#include "HiddenProcessScanner.h"

#include "HandleTableScanner.h"
#include "McpJson.h"
#include "UserModeHunter.h"

#include <Windows.h>
#include <TlHelp32.h>

#include <cstring>
#include <cstddef>
#include <limits>
#include <map>
#include <new>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

namespace
{
    constexpr uint64_t kKernelSpaceMin = 0xffff800000000000ull;
    constexpr ULONG kSystemProcessInformation = 5;
    constexpr uint32_t kMaxProcesses = 8192;
    constexpr uint32_t kMaxInfoBytes = 32u * 1024u * 1024u;
    constexpr size_t kSystemProcessInfoPrefix = 0x100;
    constexpr size_t kSystemThreadInformationSize = 0x50;

    typedef LONG NTSTATUS_LOCAL;
    typedef NTSTATUS_LOCAL (NTAPI* PfnNtQuerySystemInformation)(
        ULONG SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength);

    struct UnicodeStringLocal
    {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR Buffer;
    };

    struct SystemProcessInfoHeader
    {
        ULONG NextEntryOffset;
        ULONG NumberOfThreads;
        BYTE Reserved1[48];
        UnicodeStringLocal ImageName;
        LONG BasePriority;
        HANDLE UniqueProcessId;
        HANDLE InheritedFromUniqueProcessId;
    };

    static_assert(
        sizeof(SystemProcessInfoHeader) <= kSystemProcessInfoPrefix,
        "SYSTEM_PROCESS_INFORMATION header must fit in the documented x64 prefix");
    static_assert(
        offsetof(SystemProcessInfoHeader, ImageName) == 0x38,
        "x64 SYSTEM_PROCESS_INFORMATION ImageName offset");
    static_assert(
        offsetof(SystemProcessInfoHeader, UniqueProcessId) == 0x50,
        "x64 SYSTEM_PROCESS_INFORMATION UniqueProcessId offset");

    struct ProcessView
    {
        uint32_t Pid = 0;
        uint64_t Eprocess = 0;
        std::wstring Image;
        bool Kernel = false;
        bool Spi = false;
        bool Toolhelp = false;
        bool HandleOwner = false;
        bool CidTable = false;
        bool UserBefore = false;
        bool UserAfter = false;
        bool Auxiliary = false;
        bool ProcessExiting = false;
        bool ProcessDelete = false;
        bool ProcessRundown = false;
        bool HasActiveThreads = false;
        bool HasExitTime = false;
        bool HasLifecycle = false;
        bool PidRevalidated = false;
        bool HasAuxiliaryResolved = false;
        uint32_t ActiveThreads = 0;
        uint64_t ExitTime = 0;
    };

    struct UserInventory
    {
        std::map<uint32_t, std::wstring> Images;
        uint32_t Count = 0;
    };

    struct HiddenProcessClassifyInput
    {
        uint32_t Pid = 0;
        bool Kernel = false;
        bool Spi = false;
        bool Toolhelp = false;
        bool HandleOwner = false;
        bool CidTable = false;
        bool UserBefore = false;
        bool UserAfter = false;
        bool KernelWalkOk = false;
        bool KernelInventoryComplete = false;
        bool UserWalkOk = false;
        bool SpiWalkOk = false;
        bool ToolhelpWalkOk = false;
        bool CidConfirmAvailable = false;
        bool RequireStableUserPresence = false;
        bool LifecycleLayoutAvailable = false;
        bool HasLifecycle = false;
        bool PidRevalidated = false;
        bool HasAuxiliaryResolved = false;
        bool HasActiveThreads = false;
        uint32_t ActiveThreads = 0;
        bool HasExitTime = false;
        uint64_t ExitTime = 0;
        bool Auxiliary = false;
        bool ProcessExiting = false;
        bool ProcessDelete = false;
        bool ProcessRundown = false;
    };

    struct HiddenProcessClassifyResult
    {
        bool Suspicious = false;
        bool Ignored = false;
        bool IgnoredAuxiliary = false;
        bool IgnoredTerminating = false;
        bool IgnoredRace = false;
        std::wstring Notes;
    };

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelSpaceMin;
    }

    bool TryAddOffset(uint64_t base, uint64_t offset, uint64_t* result)
    {
        if (result == nullptr || offset > (std::numeric_limits<uint64_t>::max)() - base)
        {
            return false;
        }
        *result = base + offset;
        return true;
    }

    bool ReadU64(DeviceClient& device, uint64_t address, uint64_t* value)
    {
        std::vector<uint8_t> bytes;
        if (!device.ReadMemory(address, sizeof(uint64_t), &bytes, nullptr) ||
            bytes.size() != sizeof(uint64_t))
        {
            return false;
        }
        memcpy(value, bytes.data(), sizeof(uint64_t));
        return true;
    }

    bool ReadInteger(DeviceClient& device, uint64_t address, size_t width, uint64_t* value)
    {
        if (value == nullptr || width == 0 || width > sizeof(uint64_t))
        {
            return false;
        }

        std::vector<uint8_t> bytes;
        if (!device.ReadMemory(address, static_cast<uint32_t>(width), &bytes, nullptr) ||
            bytes.size() != width)
        {
            return false;
        }

        uint64_t parsed = 0;
        memcpy(&parsed, bytes.data(), width);
        *value = parsed;
        return true;
    }

    size_t FieldStorageWidth(const TypeFieldInfo& field, size_t fallback)
    {
        size_t width = fallback;
        if (field.IsBitField)
        {
            const uint64_t bitEnd = static_cast<uint64_t>(field.BitPosition) + field.Length;
            if (bitEnd <= 8)
            {
                width = 1;
            }
            else if (bitEnd <= 16)
            {
                width = 2;
            }
            else if (bitEnd <= 32)
            {
                width = 4;
            }
            else
            {
                width = 8;
            }
        }
        else if (field.Length > 0 && field.Length <= sizeof(uint64_t))
        {
            width = static_cast<size_t>(field.Length);
        }
        return width;
    }

    bool ReadFieldInteger(
        DeviceClient& device,
        uint64_t base,
        const TypeFieldInfo& field,
        size_t fallbackWidth,
        uint64_t* value)
    {
        if (value == nullptr)
        {
            return false;
        }

        uint64_t address = 0;
        if (!TryAddOffset(base, field.Offset, &address))
        {
            return false;
        }

        uint64_t raw = 0;
        if (!ReadInteger(device, address, FieldStorageWidth(field, fallbackWidth), &raw))
        {
            return false;
        }

        if (field.IsBitField)
        {
            if (field.Length == 0 ||
                field.Length > 64 ||
                field.BitPosition >= 64 ||
                field.Length > 64 - field.BitPosition)
            {
                return false;
            }
            const uint64_t mask = field.Length == 64
                ? (std::numeric_limits<uint64_t>::max)()
                : ((1ull << field.Length) - 1ull);
            raw = (raw >> field.BitPosition) & mask;
        }

        *value = raw;
        return true;
    }

    bool ReadBitFlag(
        DeviceClient& device,
        uint64_t eprocess,
        const TypeFieldInfo& field,
        bool resolved,
        bool* value)
    {
        if (!resolved || value == nullptr)
        {
            return false;
        }

        uint64_t raw = 0;
        if (!ReadFieldInteger(device, eprocess, field, sizeof(uint32_t), &raw))
        {
            return false;
        }
        *value = raw != 0;
        return true;
    }

    std::wstring AsciiToWide(const char* text, size_t maxLen)
    {
        std::wstring out;
        if (text == nullptr)
        {
            return out;
        }
        for (size_t i = 0; i < maxLen && text[i] != 0; ++i)
        {
            out.push_back(static_cast<wchar_t>(static_cast<unsigned char>(text[i])));
        }
        return out;
    }

    bool IsTerminatingView(const HiddenProcessClassifyInput& input)
    {
        if (input.HasExitTime && input.ExitTime != 0)
        {
            return true;
        }
        // ActiveThreads==0 alone is not an exit when AuxiliaryProcess was
        // resolved -- snapshot clones set that bit, and an attacker can zero
        // the thread count. If the PDB lacks AuxiliaryProcess, keep the
        // threadless fallback so clones do not light up as hidden.
        if (input.HasActiveThreads &&
            input.ActiveThreads == 0 &&
            !input.HasAuxiliaryResolved)
        {
            return true;
        }
        return input.ProcessExiting || input.ProcessDelete || input.ProcessRundown;
    }

    HiddenProcessClassifyResult ClassifyHiddenProcess(const HiddenProcessClassifyInput& input)
    {
        HiddenProcessClassifyResult result = {};
        if (input.Pid <= 4 || !input.KernelWalkOk || !input.UserWalkOk)
        {
            return result;
        }

        const uint32_t userViews =
            static_cast<uint32_t>(input.Spi) +
            static_cast<uint32_t>(input.Toolhelp);

        if (input.Kernel && userViews == 0)
        {
            if (!input.SpiWalkOk || !input.ToolhelpWalkOk)
            {
                result.Ignored = true;
                result.IgnoredRace = true;
                result.Notes =
                    L"SPI or Toolhelp inventory was incomplete; kernel-only process was not escalated";
                return result;
            }
            // Handle/CID confirmation means the object is still a live
            // process. Cheats set AuxiliaryProcess or fake ExitTime to ride
            // the clone/zombie filters.
            const bool independentlyVisible = input.HandleOwner || input.CidTable;
            if (input.Auxiliary && !independentlyVisible)
            {
                result.Ignored = true;
                result.IgnoredAuxiliary = true;
                result.Notes = L"ActiveProcessLinks auxiliary/snapshot clone omitted from SPI";
                return result;
            }
            if (IsTerminatingView(input) && !independentlyVisible)
            {
                result.Ignored = true;
                result.IgnoredTerminating = true;
                result.Notes = L"exiting process still linked in ActiveProcessLinks";
                return result;
            }
            if (!input.HasLifecycle)
            {
                if (input.LifecycleLayoutAvailable && !input.PidRevalidated)
                {
                    result.Ignored = true;
                    result.IgnoredRace = true;
                    result.Notes = L"kernel-only process disappeared before lifecycle revalidation";
                    return result;
                }
            }
            result.Suspicious = true;
            result.Notes = L"present in ActiveProcessLinks but absent from SPI and Toolhelp";
            return result;
        }

        if (!input.Kernel && userViews > 0)
        {
            if (!input.KernelInventoryComplete)
            {
                result.Ignored = true;
                result.IgnoredRace = true;
                result.Notes = L"ActiveProcessLinks walk was incomplete; API-only process was not escalated";
                return result;
            }
            if (input.RequireStableUserPresence && !(input.UserBefore && input.UserAfter))
            {
                result.Ignored = true;
                result.IgnoredRace = true;
                result.Notes = L"user-mode view appeared in only one snapshot";
                return result;
            }
            result.Suspicious = true;
            result.Notes = L"visible to user-mode enumeration but missing from ActiveProcessLinks";
            return result;
        }

        // DKOM unlink from ActiveProcessLinks hides the process from the
        // kernel walk AND from SPI/Toolhelp (both consume that list). The
        // process still owns handles and still has a CID slot.
        if (!input.Kernel && userViews == 0 && input.Pid > 4)
        {
            if (!input.KernelInventoryComplete)
            {
                result.Ignored = true;
                result.IgnoredRace = true;
                result.Notes =
                    L"ActiveProcessLinks walk was incomplete; CID/handle-only process was not escalated";
                return result;
            }
            if (!input.SpiWalkOk || !input.ToolhelpWalkOk)
            {
                result.Ignored = true;
                result.IgnoredRace = true;
                result.Notes =
                    L"SPI or Toolhelp inventory was incomplete; CID/handle-only process was not escalated";
                return result;
            }
            const bool independentlyVisible = input.HandleOwner || input.CidTable;
            if (IsTerminatingView(input) && !independentlyVisible)
            {
                result.Ignored = true;
                result.IgnoredTerminating = true;
                result.Notes = L"exiting CID/handle process omitted from lists";
                return result;
            }
            if (input.CidTable)
            {
                result.Suspicious = true;
                result.Notes =
                    L"live CID process missing from ActiveProcessLinks, SPI, and Toolhelp";
                return result;
            }
            if (input.HandleOwner)
            {
                if (input.CidConfirmAvailable && !input.CidTable)
                {
                    result.Ignored = true;
                    result.IgnoredRace = true;
                    result.Notes =
                        L"handle owner disappeared before CID revalidation";
                    return result;
                }
                result.Suspicious = true;
                result.Notes =
                    L"handle-table owner missing from ActiveProcessLinks, SPI, and Toolhelp";
                return result;
            }
        }

        return result;
    }

    HiddenProcessClassifyInput MakeClassifyInput(
        const ProcessView& view,
        bool kernelWalkOk,
        bool kernelInventoryComplete,
        bool userWalkOk,
        bool spiWalkOk,
        bool toolhelpWalkOk,
        bool cidConfirmAvailable,
        bool requireStableUserPresence,
        bool lifecycleLayoutAvailable)
    {
        HiddenProcessClassifyInput input = {};
        input.Pid = view.Pid;
        input.Kernel = view.Kernel;
        input.Spi = view.Spi;
        input.Toolhelp = view.Toolhelp;
        input.HandleOwner = view.HandleOwner;
        input.CidTable = view.CidTable;
        input.UserBefore = view.UserBefore;
        input.UserAfter = view.UserAfter;
        input.KernelWalkOk = kernelWalkOk;
        input.KernelInventoryComplete = kernelInventoryComplete;
        input.UserWalkOk = userWalkOk;
        input.SpiWalkOk = spiWalkOk;
        input.ToolhelpWalkOk = toolhelpWalkOk;
        input.CidConfirmAvailable = cidConfirmAvailable;
        input.RequireStableUserPresence = requireStableUserPresence;
        input.LifecycleLayoutAvailable = lifecycleLayoutAvailable;
        input.HasLifecycle = view.HasLifecycle;
        input.PidRevalidated = view.PidRevalidated;
        input.HasAuxiliaryResolved = view.HasAuxiliaryResolved;
        input.HasActiveThreads = view.HasActiveThreads;
        input.ActiveThreads = view.ActiveThreads;
        input.HasExitTime = view.HasExitTime;
        input.ExitTime = view.ExitTime;
        input.Auxiliary = view.Auxiliary;
        input.ProcessExiting = view.ProcessExiting;
        input.ProcessDelete = view.ProcessDelete;
        input.ProcessRundown = view.ProcessRundown;
        return input;
    }

    void MergeUserInventory(
        std::map<uint32_t, ProcessView>& views,
        const UserInventory& inventory,
        bool spi,
        bool toolhelp,
        bool before)
    {
        for (const auto& item : inventory.Images)
        {
            ProcessView& view = views[item.first];
            view.Pid = item.first;
            if (spi)
            {
                view.Spi = true;
            }
            if (toolhelp)
            {
                view.Toolhelp = true;
            }
            if (before)
            {
                view.UserBefore = true;
            }
            else
            {
                view.UserAfter = true;
            }
            if (view.Image.empty() && !item.second.empty())
            {
                view.Image = item.second;
            }
        }
    }

    void AdoptInventoryCount(uint32_t* count, uint32_t snapshotCount)
    {
        if (count != nullptr && snapshotCount > *count)
        {
            *count = snapshotCount;
        }
    }

    bool ParseSystemProcessInformationBuffer(
        const uint8_t* data,
        size_t validLength,
        UserInventory* inventory,
        std::wstring* warning)
    {
        if (inventory == nullptr)
        {
            return false;
        }
        *inventory = UserInventory{};

        if (data == nullptr || validLength < kSystemProcessInfoPrefix)
        {
            if (warning != nullptr)
            {
                *warning = L"SystemProcessInformation returned an invalid buffer length";
            }
            return false;
        }

        const uintptr_t bufferStart = reinterpret_cast<uintptr_t>(data);
        if (validLength > (std::numeric_limits<uintptr_t>::max)() - bufferStart)
        {
            if (warning != nullptr)
            {
                *warning = L"SystemProcessInformation buffer address overflow";
            }
            return false;
        }
        const uintptr_t bufferEnd = bufferStart + validLength;

        size_t offset = 0;
        uint32_t spiCount = 0;
        bool malformed = false;
        bool terminalEntrySeen = false;
        UserInventory parsed = {};
        while (offset <= validLength &&
            kSystemProcessInfoPrefix <= validLength - offset &&
            spiCount < kMaxProcesses)
        {
            const SystemProcessInfoHeader* info =
                reinterpret_cast<const SystemProcessInfoHeader*>(data + offset);
            const size_t entryLength = info->NextEntryOffset != 0
                ? static_cast<size_t>(info->NextEntryOffset)
                : validLength - offset;
            if (entryLength < kSystemProcessInfoPrefix ||
                entryLength > validLength - offset ||
                (info->NextEntryOffset != 0 &&
                    ((info->NextEntryOffset % alignof(void*)) != 0 ||
                        offset + info->NextEntryOffset < offset)) ||
                info->NumberOfThreads >
                    (entryLength - kSystemProcessInfoPrefix) / kSystemThreadInformationSize)
            {
                malformed = true;
                break;
            }

            const uintptr_t processId = reinterpret_cast<uintptr_t>(info->UniqueProcessId);
            if (processId > (std::numeric_limits<uint32_t>::max)())
            {
                malformed = true;
                break;
            }
            const uint32_t pid = static_cast<uint32_t>(processId);
            std::wstring image;
            if ((info->ImageName.Length % sizeof(wchar_t)) != 0 ||
                info->ImageName.MaximumLength < info->ImageName.Length ||
                (info->ImageName.Length != 0 && info->ImageName.Buffer == nullptr))
            {
                malformed = true;
                break;
            }
            if (info->ImageName.Buffer != nullptr && info->ImageName.Length > 0)
            {
                const uintptr_t nameStart =
                    reinterpret_cast<uintptr_t>(info->ImageName.Buffer);
                const size_t nameBytes = info->ImageName.Length;
                if (nameStart < bufferStart ||
                    nameStart > bufferEnd ||
                    nameBytes > static_cast<size_t>(bufferEnd - nameStart))
                {
                    malformed = true;
                    break;
                }
                image.assign(
                    info->ImageName.Buffer,
                    nameBytes / sizeof(wchar_t));
            }
            if (!parsed.Images.emplace(pid, std::move(image)).second)
            {
                malformed = true;
                break;
            }
            ++spiCount;

            if (info->NextEntryOffset == 0)
            {
                terminalEntrySeen = true;
                break;
            }
            offset += info->NextEntryOffset;
        }

        if (malformed || !terminalEntrySeen || spiCount == 0)
        {
            if (warning != nullptr)
            {
                *warning = malformed
                    ? L"SystemProcessInformation snapshot was malformed"
                    : L"SystemProcessInformation snapshot was incomplete";
            }
            return false;
        }

        parsed.Count = spiCount;
        *inventory = std::move(parsed);
        return true;
    }

    bool HiddenProcessSpiParseSelfTest()
    {
        bool ok = false;

        do
        {
            std::vector<uint8_t> wellFormed(kSystemProcessInfoPrefix, 0);
            const uint32_t pid = 1234;
            HANDLE pidHandle = ULongToHandle(pid);
            memcpy(
                wellFormed.data() + offsetof(SystemProcessInfoHeader, UniqueProcessId),
                &pidHandle,
                sizeof(pidHandle));
            UserInventory inventory = {};
            std::wstring warning;
            if (!ParseSystemProcessInformationBuffer(
                    wellFormed.data(),
                    wellFormed.size(),
                    &inventory,
                    &warning) ||
                inventory.Count != 1 ||
                inventory.Images.find(pid) == inventory.Images.end())
            {
                break;
            }

            std::vector<uint8_t> named(kSystemProcessInfoPrefix, 0);
            const uint32_t namedPid = 4321;
            HANDLE namedHandle = ULongToHandle(namedPid);
            memcpy(
                named.data() + offsetof(SystemProcessInfoHeader, UniqueProcessId),
                &namedHandle,
                sizeof(namedHandle));
            const wchar_t imageChars[] = { L'f', L'o', L'o', L'.', L'e', L'x', L'e' };
            const size_t imageBytes = sizeof(imageChars);
            const size_t imageOffset = 0xC0;
            memcpy(named.data() + imageOffset, imageChars, imageBytes);
            SystemProcessInfoHeader* header =
                reinterpret_cast<SystemProcessInfoHeader*>(named.data());
            header->ImageName.Length = static_cast<USHORT>(imageBytes);
            header->ImageName.MaximumLength = static_cast<USHORT>(imageBytes);
            header->ImageName.Buffer = reinterpret_cast<PWSTR>(named.data() + imageOffset);
            warning.clear();
            if (!ParseSystemProcessInformationBuffer(
                    named.data(),
                    named.size(),
                    &inventory,
                    &warning) ||
                inventory.Images[namedPid] != std::wstring(imageChars, imageChars + (imageBytes / sizeof(wchar_t))))
            {
                break;
            }

            std::vector<uint8_t> outsideName = wellFormed;
            header = reinterpret_cast<SystemProcessInfoHeader*>(outsideName.data());
            header->ImageName.Length = sizeof(wchar_t);
            header->ImageName.MaximumLength = sizeof(wchar_t);
            header->ImageName.Buffer = reinterpret_cast<PWSTR>(static_cast<uintptr_t>(0xffff800000001000ull));
            warning.clear();
            if (ParseSystemProcessInformationBuffer(
                    outsideName.data(),
                    outsideName.size(),
                    &inventory,
                    &warning))
            {
                break;
            }

            std::vector<uint8_t> maxBelowLength = named;
            header = reinterpret_cast<SystemProcessInfoHeader*>(maxBelowLength.data());
            header->ImageName.MaximumLength = 2;
            header->ImageName.Length = 8;
            warning.clear();
            if (ParseSystemProcessInformationBuffer(
                    maxBelowLength.data(),
                    maxBelowLength.size(),
                    &inventory,
                    &warning))
            {
                break;
            }

            std::vector<uint8_t> oddLength = wellFormed;
            header = reinterpret_cast<SystemProcessInfoHeader*>(oddLength.data());
            header->ImageName.Length = 1;
            header->ImageName.MaximumLength = 2;
            header->ImageName.Buffer =
                reinterpret_cast<PWSTR>(oddLength.data() + 0x60);
            warning.clear();
            if (ParseSystemProcessInformationBuffer(
                    oddLength.data(),
                    oddLength.size(),
                    &inventory,
                    &warning))
            {
                break;
            }

            std::vector<uint8_t> shortPrefix(sizeof(SystemProcessInfoHeader) + 8, 0);
            memcpy(
                shortPrefix.data() + offsetof(SystemProcessInfoHeader, UniqueProcessId),
                &pidHandle,
                sizeof(pidHandle));
            warning.clear();
            if (ParseSystemProcessInformationBuffer(
                    shortPrefix.data(),
                    shortPrefix.size(),
                    &inventory,
                    &warning))
            {
                break;
            }

            std::vector<uint8_t> shortNext = wellFormed;
            header = reinterpret_cast<SystemProcessInfoHeader*>(shortNext.data());
            header->NextEntryOffset = static_cast<ULONG>(sizeof(SystemProcessInfoHeader));
            warning.clear();
            if (ParseSystemProcessInformationBuffer(
                    shortNext.data(),
                    shortNext.size(),
                    &inventory,
                    &warning))
            {
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool CollectSystemProcessInformation(UserInventory* inventory, std::wstring* warning)
    {
        if (inventory == nullptr)
        {
            return false;
        }
        *inventory = UserInventory{};

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        auto query = ntdll == nullptr ? nullptr : reinterpret_cast<PfnNtQuerySystemInformation>(
            GetProcAddress(ntdll, "NtQuerySystemInformation"));
        if (query == nullptr)
        {
            if (warning != nullptr)
            {
                *warning = L"SystemProcessInformation query was unavailable";
            }
            return false;
        }

        size_t cap = 0x40000;
        std::vector<uint8_t> buffer(cap);
        ULONG needed = 0;
        NTSTATUS_LOCAL status = query(
            kSystemProcessInformation,
            buffer.data(),
            static_cast<ULONG>(buffer.size()),
            &needed);
        while (status < 0 && cap < kMaxInfoBytes)
        {
            if (needed > cap && needed <= kMaxInfoBytes)
            {
                cap = static_cast<size_t>(needed) + 0x10000;
            }
            else
            {
                cap *= 2;
            }
            if (cap > kMaxInfoBytes)
            {
                cap = kMaxInfoBytes;
            }
            buffer.resize(cap);
            status = query(
                kSystemProcessInformation,
                buffer.data(),
                static_cast<ULONG>(buffer.size()),
                &needed);
        }
        if (status < 0)
        {
            if (warning != nullptr)
            {
                *warning = L"SystemProcessInformation query failed";
            }
            return false;
        }
        if (needed == 0 || needed > buffer.size())
        {
            if (warning != nullptr)
            {
                *warning = L"SystemProcessInformation returned an invalid buffer length";
            }
            return false;
        }

        return ParseSystemProcessInformationBuffer(
            buffer.data(),
            static_cast<size_t>(needed),
            inventory,
            warning);
    }

    bool CollectToolhelpProcesses(UserInventory* inventory, std::wstring* warning)
    {
        if (inventory == nullptr)
        {
            return false;
        }
        *inventory = UserInventory{};

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
        {
            if (warning != nullptr)
            {
                *warning = L"CreateToolhelp32Snapshot failed";
            }
            return false;
        }

        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        UserInventory parsed = {};
        bool ok = false;
        if (Process32FirstW(snap, &entry))
        {
            BOOL more = TRUE;
            DWORD nextError = ERROR_SUCCESS;
            do
            {
                parsed.Images[entry.th32ProcessID] = entry.szExeFile;
                if (parsed.Images.size() >= kMaxProcesses)
                {
                    more = TRUE;
                    break;
                }
                entry.dwSize = sizeof(entry);
                more = Process32NextW(snap, &entry);
                if (!more)
                {
                    nextError = GetLastError();
                }
            } while (more);
            parsed.Count = static_cast<uint32_t>(parsed.Images.size());
            if (parsed.Count >= kMaxProcesses)
            {
                if (warning != nullptr)
                {
                    *warning = L"CreateToolhelp32Snapshot was truncated";
                }
            }
            else if (!more &&
                nextError != ERROR_NO_MORE_FILES &&
                nextError != ERROR_SUCCESS)
            {
                if (warning != nullptr)
                {
                    *warning = L"CreateToolhelp32Snapshot enumeration failed";
                }
            }
            else
            {
                ok = parsed.Count > 0;
            }
        }
        CloseHandle(snap);
        if (!ok)
        {
            if (warning != nullptr && warning->empty())
            {
                *warning = L"CreateToolhelp32Snapshot returned no processes";
            }
            return false;
        }

        *inventory = std::move(parsed);
        return true;
    }

    struct LifecycleLayout
    {
        TypeFieldInfo ExitTime = {};
        TypeFieldInfo ActiveThreads = {};
        TypeFieldInfo Auxiliary = {};
        TypeFieldInfo ProcessExiting = {};
        TypeFieldInfo ProcessDelete = {};
        TypeFieldInfo ProcessRundown = {};
        bool HasExitTime = false;
        bool HasActiveThreads = false;
        bool HasAuxiliary = false;
        bool HasProcessExiting = false;
        bool HasProcessDelete = false;
        bool HasProcessRundown = false;
    };

    bool ReadProcessLifecycle(
        DeviceClient& device,
        const LifecycleLayout& layout,
        ProcessView* view)
    {
        if (view == nullptr || view->Eprocess == 0)
        {
            return false;
        }

        if (layout.HasActiveThreads)
        {
            uint64_t threads = 0;
            if (ReadFieldInteger(device, view->Eprocess, layout.ActiveThreads, sizeof(uint32_t), &threads))
            {
                view->ActiveThreads = static_cast<uint32_t>(threads);
                view->HasActiveThreads = true;
            }
        }
        if (layout.HasExitTime)
        {
            uint64_t exitTime = 0;
            if (ReadFieldInteger(device, view->Eprocess, layout.ExitTime, sizeof(uint64_t), &exitTime))
            {
                view->ExitTime = exitTime;
                view->HasExitTime = true;
            }
        }

        bool flag = false;
        if (ReadBitFlag(device, view->Eprocess, layout.Auxiliary, layout.HasAuxiliary, &flag))
        {
            view->Auxiliary = flag;
            view->HasAuxiliaryResolved = true;
        }
        if (ReadBitFlag(device, view->Eprocess, layout.ProcessExiting, layout.HasProcessExiting, &flag))
        {
            view->ProcessExiting = flag;
        }
        if (ReadBitFlag(device, view->Eprocess, layout.ProcessDelete, layout.HasProcessDelete, &flag))
        {
            view->ProcessDelete = flag;
        }
        if (ReadBitFlag(device, view->Eprocess, layout.ProcessRundown, layout.HasProcessRundown, &flag))
        {
            view->ProcessRundown = flag;
        }

        // Flags alone are not proof the EPROCESS is still the same live object.
        view->HasLifecycle = view->HasActiveThreads || view->HasExitTime;
        return view->HasLifecycle;
    }

    bool ConfirmCidProcess(
        DeviceClient& device,
        uint32_t pid,
        const TypeFieldInfo& dtbField,
        const TypeFieldInfo& imageField,
        const LifecycleLayout& lifecycle,
        ProcessView* view)
    {
        bool ok = false;
        do
        {
            if (view == nullptr || pid <= 4 || dtbField.Offset == 0)
            {
                break;
            }

            ProcessAddressContext ctx = {};
            std::wstring ignored;
            if (!device.ResolveProcess(
                    pid,
                    static_cast<uint32_t>(dtbField.Offset),
                    0,
                    &ctx,
                    &ignored) ||
                ctx.Eprocess == 0)
            {
                break;
            }

            view->Pid = pid;
            if (view->Eprocess != 0 && view->Eprocess != ctx.Eprocess)
            {
                break;
            }
            if (view->Eprocess == 0)
            {
                view->Eprocess = ctx.Eprocess;
            }
            view->CidTable = true;
            if (view->Image.empty() && imageField.Offset != 0)
            {
                std::vector<uint8_t> nameBytes;
                uint32_t nameLen = 16;
                if (imageField.Length >= 1 && imageField.Length <= 16)
                {
                    nameLen = static_cast<uint32_t>(imageField.Length);
                }
                uint64_t imageAddress = 0;
                if (TryAddOffset(ctx.Eprocess, imageField.Offset, &imageAddress) &&
                    device.ReadMemory(
                        imageAddress,
                        nameLen,
                        &nameBytes,
                        nullptr) &&
                    !nameBytes.empty())
                {
                    view->Image = AsciiToWide(
                        reinterpret_cast<const char*>(nameBytes.data()),
                        strnlen(
                            reinterpret_cast<const char*>(nameBytes.data()),
                            nameBytes.size()));
                }
            }
            ReadProcessLifecycle(device, lifecycle, view);
            ok = true;
        } while (false);
        return ok;
    }
}

HiddenProcessScanner::HiddenProcessScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool HiddenProcessScanner::Scan(HiddenProcessScanResult* result, std::wstring* error)
{
    std::vector<uint32_t> none;
    return Scan(result, none, error);
}

bool HiddenProcessScanner::Scan(
    HiddenProcessScanResult* result,
    const std::vector<uint32_t>& extraCandidatePids,
    std::wstring* error)
{
    bool ok = false;

    try
    {
    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid hidden-process result output";
            }
            break;
        }

        *result = HiddenProcessScanResult{};
        std::map<uint32_t, ProcessView> views;

        UserInventory spiBefore = {};
        std::wstring spiWarning;
        const bool spiBeforeOk = CollectSystemProcessInformation(&spiBefore, &spiWarning);
        if (spiBeforeOk)
        {
            MergeUserInventory(views, spiBefore, true, false, true);
            AdoptInventoryCount(&result->SystemProcessInfoCount, spiBefore.Count);
        }
        else if (!spiWarning.empty())
        {
            result->Warnings.push_back(spiWarning);
        }

        UserInventory toolhelpBefore = {};
        std::wstring toolhelpWarning;
        const bool toolhelpBeforeOk = CollectToolhelpProcesses(&toolhelpBefore, &toolhelpWarning);
        if (toolhelpBeforeOk)
        {
            MergeUserInventory(views, toolhelpBefore, false, true, true);
            AdoptInventoryCount(&result->ToolhelpCount, toolhelpBefore.Count);
        }
        else if (!toolhelpWarning.empty())
        {
            result->Warnings.push_back(toolhelpWarning);
        }

        TypeFieldInfo linksField = {};
        TypeFieldInfo pidField = {};
        TypeFieldInfo imageField = {};
        std::wstring ignored;
        uint64_t listHead = 0;
        bool kernelInventoryComplete = false;
        if (symbols_.FindField(L"nt!_EPROCESS", L"ActiveProcessLinks", &linksField, &ignored) &&
            symbols_.FindField(L"nt!_EPROCESS", L"UniqueProcessId", &pidField, &ignored) &&
            symbols_.ResolveSymbol(L"nt!PsActiveProcessHead", &listHead, &ignored) &&
            listHead != 0)
        {
            symbols_.FindField(L"nt!_EPROCESS", L"ImageFileName", &imageField, &ignored);
            uint64_t flink = 0;
            if (ReadU64(device_, listHead, &flink))
            {
                uint32_t walked = 0;
                uint64_t current = flink;
                bool kernelWalkAborted = false;
                std::unordered_set<uint64_t> visited;
                visited.insert(listHead);
                while (current != 0 &&
                    current != listHead &&
                    IsKernelAddress(current) &&
                    walked < kMaxProcesses)
                {
                    if (!visited.insert(current).second)
                    {
                        result->Warnings.push_back(L"ActiveProcessLinks walk hit a cycle");
                        kernelWalkAborted = true;
                        break;
                    }
                    if (current < linksField.Offset)
                    {
                        result->Warnings.push_back(L"ActiveProcessLinks entry underflowed the list offset");
                        kernelWalkAborted = true;
                        break;
                    }
                    const uint64_t eprocess = current - linksField.Offset;
                    uint64_t pidValue = 0;
                    if (!ReadFieldInteger(
                            device_,
                            eprocess,
                            pidField,
                            sizeof(uint64_t),
                            &pidValue))
                    {
                        result->Warnings.push_back(L"ActiveProcessLinks UniqueProcessId read failed");
                        kernelWalkAborted = true;
                        break;
                    }
                    if (pidValue > (std::numeric_limits<uint32_t>::max)())
                    {
                        result->Warnings.push_back(L"ActiveProcessLinks UniqueProcessId was outside the 32-bit PID range");
                        kernelWalkAborted = true;
                        break;
                    }

                    const uint32_t pid = static_cast<uint32_t>(pidValue);
                    ProcessView& view = views[pid];
                    view.Pid = pid;
                    if (view.Kernel && view.Eprocess != 0 && view.Eprocess != eprocess)
                    {
                        result->Warnings.push_back(
                            L"ActiveProcessLinks contained a duplicate PID with a different EPROCESS");
                    }
                    else
                    {
                        view.Eprocess = eprocess;
                        view.Kernel = true;
                    }
                    if (view.Image.empty() && imageField.Offset != 0)
                    {
                        uint64_t imageAddress = 0;
                        std::vector<uint8_t> nameBytes;
                        uint32_t nameLen = imageField.Length > 16 ? 16 : static_cast<uint32_t>(imageField.Length);
                        if (nameLen > 0 &&
                            TryAddOffset(eprocess, imageField.Offset, &imageAddress) &&
                            device_.ReadMemory(imageAddress, nameLen, &nameBytes, nullptr) &&
                            !nameBytes.empty())
                        {
                            view.Image = AsciiToWide(
                                reinterpret_cast<const char*>(nameBytes.data()),
                                strnlen(
                                    reinterpret_cast<const char*>(nameBytes.data()),
                                    nameBytes.size()));
                        }
                    }

                    uint64_t next = 0;
                    if (!ReadU64(device_, current, &next) || next == current)
                    {
                        result->Warnings.push_back(L"ActiveProcessLinks Flink read failed");
                        kernelWalkAborted = true;
                        break;
                    }
                    ++walked;
                    current = next;
                }
                result->KernelListCount = walked;
                if (!kernelWalkAborted && current == listHead && walked > 0)
                {
                    kernelInventoryComplete = true;
                }
                else if (walked > 0 && current != listHead)
                {
                    kernelWalkAborted = true;
                }
                if (kernelWalkAborted)
                {
                    result->Warnings.push_back(L"kernel ActiveProcessLinks walk was incomplete");
                }
            }
        }
        else
        {
            result->Warnings.push_back(L"kernel ActiveProcessLinks walk was not resolved");
        }

        UserInventory spiAfter = {};
        spiWarning.clear();
        const bool spiAfterOk = CollectSystemProcessInformation(&spiAfter, &spiWarning);
        if (spiAfterOk)
        {
            MergeUserInventory(views, spiAfter, true, false, false);
            AdoptInventoryCount(&result->SystemProcessInfoCount, spiAfter.Count);
        }
        else if (!spiWarning.empty())
        {
            result->Warnings.push_back(L"second " + spiWarning);
        }

        UserInventory toolhelpAfter = {};
        toolhelpWarning.clear();
        const bool toolhelpAfterOk = CollectToolhelpProcesses(&toolhelpAfter, &toolhelpWarning);
        if (toolhelpAfterOk)
        {
            MergeUserInventory(views, toolhelpAfter, false, true, false);
            AdoptInventoryCount(&result->ToolhelpCount, toolhelpAfter.Count);
        }
        else if (!toolhelpWarning.empty())
        {
            result->Warnings.push_back(L"second " + toolhelpWarning);
        }

        HandleTableScanner handles(device_, symbols_);
        HandleTableScanOptions handleOptions = {};
        handleOptions.CollectRecords = false;
        HandleTableScanResult handleResult = {};
        std::wstring handleError;
        if (handles.Scan(handleOptions, &handleResult, &handleError))
        {
            if (handleResult.Truncated || !handleResult.CoverageComplete)
            {
                result->Warnings.push_back(L"handle-owner view used a truncated handle snapshot");
            }
            for (const std::wstring& warning : handleResult.Warnings)
            {
                result->Warnings.push_back(L"handle-owner view: " + warning);
            }
            for (uint32_t pid : handleResult.OwnerPids)
            {
                ProcessView& view = views[pid];
                view.Pid = pid;
                view.HandleOwner = true;
            }
            result->HandleOwnerCount = static_cast<uint32_t>(handleResult.OwnerPids.size());
        }
        else if (!handleError.empty())
        {
            result->Warnings.push_back(L"handle-owner view failed: " + handleError);
        }

        LifecycleLayout lifecycle = {};
        lifecycle.HasExitTime = symbols_.FindField(L"nt!_EPROCESS", L"ExitTime", &lifecycle.ExitTime, &ignored);
        lifecycle.HasActiveThreads =
            symbols_.FindField(L"nt!_EPROCESS", L"ActiveThreads", &lifecycle.ActiveThreads, &ignored);
        lifecycle.HasAuxiliary =
            symbols_.FindField(L"nt!_EPROCESS", L"AuxiliaryProcess", &lifecycle.Auxiliary, &ignored);
        lifecycle.HasProcessExiting =
            symbols_.FindField(L"nt!_EPROCESS", L"ProcessExiting", &lifecycle.ProcessExiting, &ignored);
        lifecycle.HasProcessDelete =
            symbols_.FindField(L"nt!_EPROCESS", L"ProcessDelete", &lifecycle.ProcessDelete, &ignored);
        lifecycle.HasProcessRundown =
            symbols_.FindField(L"nt!_EPROCESS", L"ProcessRundown", &lifecycle.ProcessRundown, &ignored);
        if (!lifecycle.HasExitTime || !lifecycle.HasActiveThreads)
        {
            result->Warnings.push_back(L"kernel process lifecycle fields were not fully resolved");
        }

        const bool userInventoryComplete =
            result->SystemProcessInfoCount > 0 &&
            result->ToolhelpCount > 0;

        const bool kernelWalkOk = result->KernelListCount > 0;
        const bool userWalkOk =
            result->SystemProcessInfoCount > 0 ||
            result->ToolhelpCount > 0;
        const bool userBeforeOk = spiBeforeOk || toolhelpBeforeOk;
        const bool userAfterOk = spiAfterOk || toolhelpAfterOk;
        const bool requireStableUserPresence = userBeforeOk && userAfterOk;
        const bool lifecycleLayoutAvailable =
            lifecycle.HasExitTime || lifecycle.HasActiveThreads;

        TypeFieldInfo dtbField = {};
        const bool hasDtb =
            symbols_.FindField(L"nt!_KPROCESS", L"DirectoryTableBase", &dtbField, &ignored) ||
            symbols_.FindField(L"nt!_EPROCESS", L"Pcb.DirectoryTableBase", &dtbField, &ignored) ||
            symbols_.FindField(L"nt!_EPROCESS", L"DirectoryTableBase", &dtbField, &ignored);
        if (!hasDtb)
        {
            result->Warnings.push_back(
                L"DirectoryTableBase was not resolved; CID confirmation is unavailable");
        }

        auto confirmIfMissingFromLists = [&](uint32_t pid)
        {
            if (pid <= 4 || !hasDtb)
            {
                return;
            }
            ProcessView& view = views[pid];
            view.Pid = pid;
            if (view.Kernel && view.Spi && view.Toolhelp)
            {
                return;
            }
            if (view.CidTable)
            {
                return;
            }
            if (ConfirmCidProcess(
                    device_,
                    pid,
                    dtbField,
                    imageField,
                    lifecycle,
                    &view))
            {
                ++result->CidTableCount;
            }
        };

        for (uint32_t pid : handleResult.OwnerPids)
        {
            confirmIfMissingFromLists(pid);
        }
        for (uint32_t pid : extraCandidatePids)
        {
            confirmIfMissingFromLists(pid);
        }

        std::vector<uint32_t> cidPids;
        std::wstring cidWarning;
        bool cidWalkComplete = false;
        if (EnumerateCidProcessIds(
                device_,
                symbols_,
                &cidPids,
                &cidWarning,
                &cidWalkComplete))
        {
            for (uint32_t pid : cidPids)
            {
                confirmIfMissingFromLists(pid);
            }
        }
        else
        {
            cidWalkComplete = false;
            if (!cidWarning.empty())
            {
                result->Warnings.push_back(cidWarning);
            }
        }
        if (!cidWalkComplete)
        {
            result->Warnings.push_back(
                L"PspCidTable process walk was incomplete; CID-only hidden processes may be missed");
        }

        result->CoverageComplete =
            kernelInventoryComplete &&
            userInventoryComplete &&
            cidWalkComplete;

        std::vector<uint32_t> kernelOnlyPids;
        for (const auto& pair : views)
        {
            if (pair.second.Kernel &&
                !pair.second.Spi &&
                !pair.second.Toolhelp &&
                pair.first > 4)
            {
                kernelOnlyPids.push_back(pair.first);
            }
        }
        for (uint32_t pid : kernelOnlyPids)
        {
            confirmIfMissingFromLists(pid);
        }

        for (auto& pair : views)
        {
            ProcessView& view = pair.second;
            if (view.Pid == 0)
            {
                continue;
            }

            const bool kernelOnly =
                kernelWalkOk &&
                userWalkOk &&
                view.Kernel &&
                !view.Spi &&
                !view.Toolhelp &&
                view.Pid > 4;
            if (kernelOnly)
            {
                uint64_t livePid = 0;
                if (ReadFieldInteger(
                        device_,
                        view.Eprocess,
                        pidField,
                        sizeof(uint64_t),
                        &livePid) &&
                    livePid <= (std::numeric_limits<uint32_t>::max)() &&
                    static_cast<uint32_t>(livePid) == view.Pid)
                {
                    view.PidRevalidated = true;
                    ReadProcessLifecycle(device_, lifecycle, &view);
                }
            }

            const HiddenProcessClassifyInput classifiedInput =
                MakeClassifyInput(
                    view,
                    kernelWalkOk,
                    kernelInventoryComplete,
                    userWalkOk,
                    spiBeforeOk && spiAfterOk,
                    toolhelpBeforeOk && toolhelpAfterOk,
                    hasDtb,
                    requireStableUserPresence,
                    lifecycleLayoutAvailable);
            const HiddenProcessClassifyResult classified = ClassifyHiddenProcess(classifiedInput);

            HiddenProcessRecord record = {};
            record.ProcessId = view.Pid;
            record.Eprocess = view.Eprocess;
            record.ImageName = view.Image;
            record.InKernelList = view.Kernel;
            record.InSystemProcessInfo = view.Spi;
            record.InToolhelp = view.Toolhelp;
            record.InHandleOwners = view.HandleOwner;
            record.InCidTable = view.CidTable;
            record.Auxiliary = view.Auxiliary;
            record.Terminating = IsTerminatingView(classifiedInput);
            record.HasActiveThreads = view.HasActiveThreads;
            record.HasExitTime = view.HasExitTime;
            record.ActiveThreads = view.ActiveThreads;
            record.ExitTime = view.ExitTime;
            record.Suspicious = classified.Suspicious;
            record.Notes = classified.Notes;

            if (classified.Ignored)
            {
                ++result->IgnoredCount;
                if (classified.IgnoredAuxiliary)
                {
                    ++result->IgnoredAuxiliaryCount;
                }
                if (classified.IgnoredTerminating)
                {
                    ++result->IgnoredTerminatingCount;
                }
                if (classified.IgnoredRace)
                {
                    ++result->IgnoredRaceCount;
                }
                // Keep kernel-only clones/zombies in the record list so the
                // ignore decision is auditable. One-sided API races stay out.
                if ((classified.IgnoredAuxiliary || classified.IgnoredTerminating) &&
                    view.Kernel &&
                    !view.Spi &&
                    !view.Toolhelp)
                {
                    result->Records.push_back(record);
                }
                continue;
            }

            if (record.Suspicious)
            {
                ++result->SuspiciousCount;
            }

            // Keep non-suspicious records only when they disagree across views.
            if (record.Suspicious ||
                (view.Kernel != view.Spi) ||
                (view.Kernel != view.Toolhelp) ||
                (view.HandleOwner && !view.Kernel && !view.Spi && !view.Toolhelp) ||
                (view.CidTable && !view.Kernel && !view.Spi && !view.Toolhelp))
            {
                result->Records.push_back(record);
            }
        }

        ok = true;
    } while (false);
    }
    catch (const std::bad_alloc&)
    {
        if (result != nullptr)
        {
            *result = HiddenProcessScanResult{};
        }
        if (error != nullptr)
        {
            *error = L"out of memory during hidden-process scan";
        }
        return false;
    }

    return ok;
}

std::wstring BuildHiddenProcessJson(const HiddenProcessScanResult& result)
{
    std::wstringstream json;
    json << L"{\"schema\":\"kn-live-dbg.hidden-process.v1\"";
    json << L",\"kernel_list\":" << result.KernelListCount;
    json << L",\"spi\":" << result.SystemProcessInfoCount;
    json << L",\"toolhelp\":" << result.ToolhelpCount;
    json << L",\"handle_owners\":" << result.HandleOwnerCount;
    json << L",\"cid_table\":" << result.CidTableCount;
    json << L",\"suspicious\":" << result.SuspiciousCount;
    json << L",\"ignored\":" << result.IgnoredCount;
    json << L",\"ignored_auxiliary\":" << result.IgnoredAuxiliaryCount;
    json << L",\"ignored_terminating\":" << result.IgnoredTerminatingCount;
    json << L",\"ignored_race\":" << result.IgnoredRaceCount;
    json << L",\"coverage_complete\":" << (result.CoverageComplete ? L"true" : L"false");
    json << L",\"records\":[";
    bool first = true;
    for (const HiddenProcessRecord& record : result.Records)
    {
        if (!first)
        {
            json << L",";
        }
        first = false;
        json << L"{\"pid\":" << record.ProcessId;
        json << L",\"eprocess\":\"0x" << std::hex << record.Eprocess << std::dec << L"\"";
        json << L",\"image\":\"" << mcpjson::Escape(record.ImageName) << L"\"";
        json << L",\"kernel\":" << (record.InKernelList ? L"true" : L"false");
        json << L",\"spi\":" << (record.InSystemProcessInfo ? L"true" : L"false");
        json << L",\"toolhelp\":" << (record.InToolhelp ? L"true" : L"false");
        json << L",\"handle_owner\":" << (record.InHandleOwners ? L"true" : L"false");
        json << L",\"cid_table\":" << (record.InCidTable ? L"true" : L"false");
        json << L",\"auxiliary\":" << (record.Auxiliary ? L"true" : L"false");
        json << L",\"terminating\":" << (record.Terminating ? L"true" : L"false");
        json << L",\"has_active_threads\":" << (record.HasActiveThreads ? L"true" : L"false");
        json << L",\"active_threads\":" << record.ActiveThreads;
        json << L",\"has_exit_time\":" << (record.HasExitTime ? L"true" : L"false");
        json << L",\"exit_time\":\"0x" << std::hex << record.ExitTime << std::dec << L"\"";
        json << L",\"suspicious\":" << (record.Suspicious ? L"true" : L"false");
        json << L",\"notes\":\"" << mcpjson::Escape(record.Notes) << L"\"}";
    }
    json << L"]}";
    return json.str();
}

bool HiddenProcessViewSelfTest()
{
    bool ok = false;

    do
    {
        HiddenProcessClassifyInput hidden = {};
        hidden.Pid = 1234;
        hidden.Kernel = true;
        hidden.KernelWalkOk = true;
        hidden.UserWalkOk = true;
        hidden.SpiWalkOk = true;
        hidden.ToolhelpWalkOk = true;
        hidden.HasLifecycle = true;
        hidden.HasAuxiliaryResolved = true;
        hidden.HasActiveThreads = true;
        hidden.ActiveThreads = 4;
        hidden.HasExitTime = true;
        hidden.ExitTime = 0;
        hidden.LifecycleLayoutAvailable = true;
        const HiddenProcessClassifyResult hiddenResult = ClassifyHiddenProcess(hidden);
        if (!hiddenResult.Suspicious || hiddenResult.Ignored)
        {
            break;
        }

        HiddenProcessClassifyInput clone = hidden;
        clone.Auxiliary = true;
        const HiddenProcessClassifyResult cloneResult = ClassifyHiddenProcess(clone);
        if (cloneResult.Suspicious || !cloneResult.IgnoredAuxiliary)
        {
            break;
        }

        HiddenProcessClassifyInput cloneCid = clone;
        cloneCid.CidTable = true;
        const HiddenProcessClassifyResult cloneCidResult = ClassifyHiddenProcess(cloneCid);
        if (!cloneCidResult.Suspicious || cloneCidResult.Ignored)
        {
            break;
        }

        HiddenProcessClassifyInput threadless = hidden;
        threadless.ActiveThreads = 0;
        const HiddenProcessClassifyResult threadlessResult = ClassifyHiddenProcess(threadless);
        if (!threadlessResult.Suspicious || threadlessResult.Ignored)
        {
            break;
        }

        HiddenProcessClassifyInput threadlessNoAuxField = threadless;
        threadlessNoAuxField.HasAuxiliaryResolved = false;
        const HiddenProcessClassifyResult threadlessNoAuxFieldResult =
            ClassifyHiddenProcess(threadlessNoAuxField);
        if (threadlessNoAuxFieldResult.Suspicious || !threadlessNoAuxFieldResult.IgnoredTerminating)
        {
            break;
        }

        HiddenProcessClassifyInput exiting = hidden;
        exiting.ProcessExiting = true;
        const HiddenProcessClassifyResult exitingResult = ClassifyHiddenProcess(exiting);
        if (exitingResult.Suspicious || !exitingResult.IgnoredTerminating)
        {
            break;
        }

        HiddenProcessClassifyInput vanished = hidden;
        vanished.HasLifecycle = false;
        vanished.HasActiveThreads = false;
        vanished.HasExitTime = false;
        vanished.PidRevalidated = false;
        vanished.LifecycleLayoutAvailable = true;
        const HiddenProcessClassifyResult vanishedResult = ClassifyHiddenProcess(vanished);
        if (vanishedResult.Suspicious || !vanishedResult.IgnoredRace)
        {
            break;
        }

        HiddenProcessClassifyInput liveUnread = vanished;
        liveUnread.PidRevalidated = true;
        const HiddenProcessClassifyResult liveUnreadResult = ClassifyHiddenProcess(liveUnread);
        if (!liveUnreadResult.Suspicious || liveUnreadResult.Ignored)
        {
            break;
        }

        HiddenProcessClassifyInput noLayout = vanished;
        noLayout.LifecycleLayoutAvailable = false;
        const HiddenProcessClassifyResult noLayoutResult = ClassifyHiddenProcess(noLayout);
        if (!noLayoutResult.Suspicious || noLayoutResult.Ignored)
        {
            break;
        }

        HiddenProcessClassifyInput visible = {};
        visible.Pid = 4321;
        visible.KernelWalkOk = true;
        visible.UserWalkOk = true;
        visible.Spi = true;
        visible.Toolhelp = true;
        visible.UserBefore = true;
        visible.UserAfter = true;
        visible.RequireStableUserPresence = true;
        visible.KernelInventoryComplete = true;
        const HiddenProcessClassifyResult visibleResult = ClassifyHiddenProcess(visible);
        if (!visibleResult.Suspicious || visibleResult.Ignored)
        {
            break;
        }

        HiddenProcessClassifyInput race = visible;
        race.UserAfter = false;
        const HiddenProcessClassifyResult raceResult = ClassifyHiddenProcess(race);
        if (raceResult.Suspicious || !raceResult.IgnoredRace)
        {
            break;
        }

        HiddenProcessClassifyInput singleSnapshot = race;
        singleSnapshot.RequireStableUserPresence = false;
        const HiddenProcessClassifyResult singleSnapshotResult = ClassifyHiddenProcess(singleSnapshot);
        if (!singleSnapshotResult.Suspicious || singleSnapshotResult.Ignored)
        {
            break;
        }

        HiddenProcessClassifyInput kernelNoSpi = hidden;
        kernelNoSpi.SpiWalkOk = false;
        const HiddenProcessClassifyResult kernelNoSpiResult = ClassifyHiddenProcess(kernelNoSpi);
        if (kernelNoSpiResult.Suspicious || !kernelNoSpiResult.IgnoredRace)
        {
            break;
        }

        HiddenProcessClassifyInput incompleteWalk = visible;
        incompleteWalk.KernelInventoryComplete = false;
        const HiddenProcessClassifyResult incompleteWalkResult = ClassifyHiddenProcess(incompleteWalk);
        if (incompleteWalkResult.Suspicious || !incompleteWalkResult.IgnoredRace)
        {
            break;
        }

        HiddenProcessClassifyInput incompleteCid = {};
        incompleteCid.Pid = 3333;
        incompleteCid.CidTable = true;
        incompleteCid.KernelWalkOk = true;
        incompleteCid.UserWalkOk = true;
        incompleteCid.KernelInventoryComplete = false;
        const HiddenProcessClassifyResult incompleteCidResult = ClassifyHiddenProcess(incompleteCid);
        if (incompleteCidResult.Suspicious || !incompleteCidResult.IgnoredRace)
        {
            break;
        }

        HiddenProcessClassifyInput handleOnly = {};
        handleOnly.Pid = 2222;
        handleOnly.HandleOwner = true;
        handleOnly.CidTable = true;
        handleOnly.KernelWalkOk = true;
        handleOnly.UserWalkOk = true;
        handleOnly.KernelInventoryComplete = true;
        handleOnly.SpiWalkOk = true;
        handleOnly.ToolhelpWalkOk = true;
        const HiddenProcessClassifyResult handleOnlyResult = ClassifyHiddenProcess(handleOnly);
        if (!handleOnlyResult.Suspicious || handleOnlyResult.Ignored)
        {
            break;
        }

        HiddenProcessClassifyInput handleNoCid = handleOnly;
        handleNoCid.CidTable = false;
        handleNoCid.CidConfirmAvailable = true;
        const HiddenProcessClassifyResult handleNoCidResult = ClassifyHiddenProcess(handleNoCid);
        if (handleNoCidResult.Suspicious || !handleNoCidResult.IgnoredRace)
        {
            break;
        }

        HiddenProcessClassifyInput handleAux = handleOnly;
        handleAux.Auxiliary = true;
        const HiddenProcessClassifyResult handleAuxResult = ClassifyHiddenProcess(handleAux);
        if (!handleAuxResult.Suspicious || handleAuxResult.Ignored)
        {
            break;
        }

        HiddenProcessClassifyInput cidOnly = {};
        cidOnly.Pid = 3333;
        cidOnly.CidTable = true;
        cidOnly.KernelWalkOk = true;
        cidOnly.UserWalkOk = true;
        cidOnly.KernelInventoryComplete = true;
        cidOnly.SpiWalkOk = true;
        cidOnly.ToolhelpWalkOk = true;
        const HiddenProcessClassifyResult cidOnlyResult = ClassifyHiddenProcess(cidOnly);
        if (!cidOnlyResult.Suspicious || cidOnlyResult.Ignored)
        {
            break;
        }

        HiddenProcessClassifyInput cidExiting = cidOnly;
        cidExiting.ProcessExiting = true;
        cidExiting.HasLifecycle = true;
        const HiddenProcessClassifyResult cidExitingResult = ClassifyHiddenProcess(cidExiting);
        if (!cidExitingResult.Suspicious || cidExitingResult.Ignored)
        {
            break;
        }

        HiddenProcessClassifyInput cidFakeExit = cidOnly;
        cidFakeExit.HasExitTime = true;
        cidFakeExit.ExitTime = 1;
        const HiddenProcessClassifyResult cidFakeExitResult = ClassifyHiddenProcess(cidFakeExit);
        if (!cidFakeExitResult.Suspicious || cidFakeExitResult.Ignored)
        {
            break;
        }

        if (!HiddenProcessSpiParseSelfTest())
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}
