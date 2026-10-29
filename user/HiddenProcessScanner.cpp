#include "HiddenProcessScanner.h"

#include "HandleTableScanner.h"
#include "UserModeHunter.h"

#include <Windows.h>
#include <TlHelp32.h>

#include <cstring>
#include <cstddef>
#include <limits>
#include <map>
#include <new>
#include <string>
#include <vector>

namespace
{
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

    struct UserInventory
    {
        std::map<uint32_t, std::wstring> Images;
        uint32_t Count = 0;
    };

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

    bool ToolhelpProcessWalkComplete(size_t count, bool more, DWORD terminalError)
    {
        return count > 0 && count < kMaxProcesses && !more &&
            terminalError == ERROR_NO_MORE_FILES;
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
        struct SnapshotOwner
        {
            HANDLE Value;
            ~SnapshotOwner()
            {
                CloseHandle(Value);
            }
        };
        SnapshotOwner owner{snap};
        entry.dwSize = sizeof(entry);
        UserInventory parsed = {};
        bool ok = false;
        if (Process32FirstW(snap, &entry))
        {
            BOOL more = TRUE;
            DWORD nextError = ERROR_SUCCESS;
            do
            {
                if (!parsed.Images.emplace(entry.th32ProcessID, entry.szExeFile).second)
                {
                    more = TRUE;
                    if (warning != nullptr)
                    {
                        *warning = L"CreateToolhelp32Snapshot contained a duplicate PID";
                    }
                    break;
                }
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
            else if (!ToolhelpProcessWalkComplete(parsed.Count, more != FALSE, nextError))
            {
                if (warning != nullptr)
                {
                    *warning = L"CreateToolhelp32Snapshot enumeration failed";
                }
            }
            else
            {
                ok = true;
            }
        }
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


    class DeviceProcessReader final : public HiddenProcessReader
    {
    public:
        DeviceProcessReader(DeviceClient& device, uint32_t dtbOffset) :
            Device(device), DtbOffset(dtbOffset)
        {
        }

        bool Read(uint64_t address, uint8_t bytes, uint64_t* value) override
        {
            std::vector<uint8_t> data;
            if (Stopped() || value == nullptr || bytes == 0 || bytes > 8 ||
                !Device.ReadMemory(address, bytes, &data, nullptr) || data.size() != bytes)
            {
                return false;
            }
            *value = 0;
            memcpy(value, data.data(), bytes);
            return true;
        }

        bool Resolve(uint32_t pid, uint64_t* eprocess) override
        {
            ProcessAddressContext context = {};
            if (Stopped() || eprocess == nullptr || DtbOffset == 0 ||
                !Device.ResolveProcess(pid, DtbOffset, 0, &context, nullptr) ||
                context.ProcessId != pid || context.Eprocess == 0)
            {
                return false;
            }
            *eprocess = context.Eprocess;
            return true;
        }

        bool Stopped() const override
        {
            return Deadline != 0 && GetTickCount64() >= Deadline;
        }

        uint64_t Deadline = 0;

    private:
        DeviceClient& Device;
        uint32_t DtbOffset;
    };

    HiddenProcessField ResolveProcessField(SymbolEngine& symbols, const wchar_t* name)
    {
        TypeFieldInfo field;
        HiddenProcessField result;
        if (!symbols.FindField(L"nt!_EPROCESS", name, &field, nullptr) || field.Offset > 0x10000)
        {
            return result;
        }
        result.Offset = field.Offset;
        if (field.IsBitField)
        {
            if (field.Length == 0 || field.Length > 64 || field.BitPosition >= 64 ||
                field.Length > 64 - field.BitPosition)
            {
                return result;
            }
            const uint64_t end = field.BitPosition + field.Length;
            result.Bytes = end <= 8 ? 1 : end <= 16 ? 2 : end <= 32 ? 4 : 8;
            result.BitPosition = static_cast<uint8_t>(field.BitPosition);
            result.BitCount = static_cast<uint8_t>(field.Length);
        }
        else
        {
            if (field.Length != 1 && field.Length != 2 && field.Length != 4 && field.Length != 8)
            {
                return result;
            }
            result.Bytes = static_cast<uint8_t>(field.Length);
        }
        result.Available = true;
        return result;
    }

    void MergeUserInventory(std::map<uint32_t, HiddenProcessRecord>& views,
        const UserInventory& inventory, bool spi)
    {
        for (const auto& item : inventory.Images)
        {
            auto& view = views[item.first];
            view.ProcessId = item.first;
            if (spi)
            {
                view.InSystemProcessInfo = true;
            }
            else
            {
                view.InToolhelp = true;
            }
            if (view.ImageName.empty())
            {
                view.ImageName = item.second;
            }
        }
    }

    HiddenProcessMembership DiscoveryMembership(const HiddenProcessRecord& record)
    {
        HiddenProcessMembership result;
        result.Kernel = record.InKernelList;
        result.Spi = record.InSystemProcessInfo;
        result.Toolhelp = record.InToolhelp;
        result.Cid = record.InCidTable;
        result.Handles = record.InHandleOwners;
        return result;
    }
}

HiddenProcessScanner::HiddenProcessScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device), symbols_(symbols)
{
}

bool HiddenProcessScanner::Scan(HiddenProcessScanResult* result, std::wstring* error)
{
    return Scan(result, {}, error);
}

bool HiddenProcessScanner::Scan(HiddenProcessScanResult* result,
    const std::vector<uint32_t>& extraCandidatePids, std::wstring* error)
{
    if (result == nullptr)
    {
        if (error != nullptr)
        {
            *error = L"invalid hidden-process result output";
        }
        return false;
    }
    *result = HiddenProcessScanResult{};
    try
    {
        HiddenProcessLayout layout;
        layout.Pid = ResolveProcessField(symbols_, L"UniqueProcessId");
        layout.CreateTime = ResolveProcessField(symbols_, L"CreateTime");
        layout.ActiveThreads = ResolveProcessField(symbols_, L"ActiveThreads");
        layout.ExitTime = ResolveProcessField(symbols_, L"ExitTime");
        layout.Auxiliary = ResolveProcessField(symbols_, L"AuxiliaryProcess");
        layout.ProcessExiting = ResolveProcessField(symbols_, L"ProcessExiting");
        layout.ProcessDelete = ResolveProcessField(symbols_, L"ProcessDelete");
        layout.ProcessRundown = ResolveProcessField(symbols_, L"ProcessRundown");
        TypeFieldInfo links = {};
        layout.LinksAvailable = symbols_.FindField(L"nt!_EPROCESS", L"ActiveProcessLinks", &links, nullptr) &&
            !links.IsBitField && links.Length == 16 && links.Offset <= 0x10000 &&
            symbols_.ResolveSymbol(L"nt!PsActiveProcessHead", &layout.ListHead, nullptr);
        layout.LinksOffset = links.Offset;
        TypeFieldInfo dtb = {};
        const bool hasDtb =
            (symbols_.FindField(L"nt!_KPROCESS", L"DirectoryTableBase", &dtb, nullptr) ||
                symbols_.FindField(L"nt!_EPROCESS", L"Pcb.DirectoryTableBase", &dtb, nullptr) ||
                symbols_.FindField(L"nt!_EPROCESS", L"DirectoryTableBase", &dtb, nullptr)) &&
            !dtb.IsBitField && dtb.Length == 8 && dtb.Offset > 0 && dtb.Offset <= 0x4000;
        DeviceProcessReader reader(device_, hasDtb ? dtb.Offset : 0);
        const auto addressSpace = device_.AddressSpace();
        if (!layout.CreateTime.Available || !layout.ExitTime.Available ||
            !layout.ActiveThreads.Available || !layout.Auxiliary.Available || !hasDtb ||
            !layout.ProcessExiting.Available || !layout.ProcessDelete.Available || !layout.ProcessRundown.Available)
        {
            result->Warnings.push_back(L"process identity or lifecycle layout was incomplete; affected candidates remain unverified");
        }

        std::map<uint32_t, HiddenProcessRecord> views;
        UserInventory spi;
        UserInventory toolhelp;
        std::wstring warning;
        const bool spiOk = CollectSystemProcessInformation(&spi, &warning);
        if (!spiOk)
        {
            result->Warnings.push_back(warning);
        }
        MergeUserInventory(views, spi, true);
        result->SystemProcessInfoCount = spi.Count;
        warning.clear();
        const bool toolhelpOk = CollectToolhelpProcesses(&toolhelp, &warning);
        if (!toolhelpOk)
        {
            result->Warnings.push_back(warning);
        }
        MergeUserInventory(views, toolhelp, false);
        result->ToolhelpCount = toolhelp.Count;
        const auto kernel = ReadHiddenProcessKernelView(reader, addressSpace, layout);
        result->KernelListCount = static_cast<uint32_t>(kernel.Entries.size());
        if (!kernel.Complete)
        {
            result->Warnings.push_back(kernel.Reason);
        }
        for (const auto& item : kernel.Entries)
        {
            auto& view = views[item.first];
            view.ProcessId = item.first;
            view.InKernelList = true;
            view.Eprocess = item.second.Eprocess;
        }

        HandleTableScanner handles(device_, symbols_);
        HandleTableScanOptions handleOptions;
        handleOptions.CollectRecords = false;
        HandleTableScanResult handleResult;
        warning.clear();
        const bool handlesOk = handles.Scan(handleOptions, &handleResult, &warning);
        if (!handlesOk || !handleResult.CoverageComplete || handleResult.Truncated)
        {
            result->Warnings.push_back(L"handle-owner discovery was incomplete: " + warning);
        }
        for (const auto& handleWarning : handleResult.Warnings)
        {
            result->Warnings.push_back(L"handle-owner view: " + handleWarning);
        }
        for (uint32_t pid : handleResult.OwnerPids)
        {
            auto& view = views[pid];
            view.ProcessId = pid;
            view.InHandleOwners = true;
        }
        result->HandleOwnerCount = static_cast<uint32_t>(handleResult.OwnerPids.size());

        std::vector<uint32_t> cidPids;
        bool cidComplete = false;
        warning.clear();
        EnumerateCidProcessIds(device_, symbols_, &cidPids, &warning, &cidComplete);
        if (!cidComplete)
        {
            result->Warnings.push_back(L"CID discovery was incomplete: " + warning);
        }
        for (uint32_t pid : cidPids)
        {
            auto& view = views[pid];
            view.ProcessId = pid;
            view.InCidTable = true;
        }
        for (uint32_t pid : extraCandidatePids)
        {
            uint64_t object = 0;
            if (pid > 4 && reader.Resolve(pid, &object))
            {
                auto& view = views[pid];
                view.ProcessId = pid;
                view.InCidTable = true;
                if (view.Eprocess == 0)
                {
                    view.Eprocess = object;
                }
            }
        }
        std::vector<HiddenProcessRecord*> candidates;
        for (auto& item : views)
        {
            auto& view = item.second;
            result->CidTableCount += view.InCidTable ? 1 : 0;
            if (IsHiddenProcessCandidate(view.ProcessId, DiscoveryMembership(view)))
            {
                candidates.push_back(&view);
            }
        }

        result->InventoryComplete = kernel.Complete && spiOk && toolhelpOk && cidComplete &&
            handlesOk && handleResult.CoverageComplete && !handleResult.Truncated;
        result->CoverageComplete = result->InventoryComplete;
        // Discovery is only a PID-based hint. Bind fresh observations to a
        // sampled lifetime before drawing any absence conclusion.
        constexpr size_t kMaxQualifiedCandidates = 128;
        constexpr uint64_t kQualificationBudgetMs = 5000;
        reader.Deadline = GetTickCount64() + kQualificationBudgetMs;
        for (size_t i = 0; i < candidates.size(); ++i)
        {
            auto& q = candidates[i]->Qualification;
            if (i >= kMaxQualifiedCandidates || reader.Stopped())
            {
                q.BudgetExceeded = true;
                continue;
            }
            q.Attempted = true;
            q.Before = ReadHiddenProcessLifetime(reader, addressSpace, layout, candidates[i]->ProcessId);
        }

        if (!candidates.empty() && !reader.Stopped())
        {
            result->ComparisonStartedMs = GetTickCount64();
            const auto comparisonKernel = ReadHiddenProcessKernelView(reader, addressSpace, layout);
            UserInventory comparisonSpi;
            UserInventory comparisonToolhelp;
            warning.clear();
            const bool comparisonSpiOk = !reader.Stopped() && CollectSystemProcessInformation(&comparisonSpi, &warning);
            if (!comparisonSpiOk && !warning.empty())
            {
                result->Warnings.push_back(L"comparison: " + warning);
            }
            warning.clear();
            const bool comparisonToolhelpOk = !reader.Stopped() && CollectToolhelpProcesses(&comparisonToolhelp, &warning);
            if (!comparisonToolhelpOk && !warning.empty())
            {
                result->Warnings.push_back(L"comparison: " + warning);
            }
            result->ComparisonFinishedMs = GetTickCount64();
            if (!comparisonKernel.Complete)
            {
                result->Warnings.push_back(L"comparison: " + comparisonKernel.Reason);
            }
            for (auto* candidate : candidates)
            {
                auto& q = candidate->Qualification;
                if (!q.Attempted)
                {
                    continue;
                }
                q.KernelComplete = comparisonKernel.Complete;
                q.SpiComplete = comparisonSpiOk;
                q.ToolhelpComplete = comparisonToolhelpOk;
                const auto found = comparisonKernel.Entries.find(candidate->ProcessId);
                q.Views.Kernel = found != comparisonKernel.Entries.end();
                if (q.Views.Kernel)
                {
                    q.KernelIdentity = found->second;
                }
                q.Views.Spi = comparisonSpi.Images.count(candidate->ProcessId) != 0;
                q.Views.Toolhelp = comparisonToolhelp.Images.count(candidate->ProcessId) != 0;
                q.After = ReadHiddenProcessLifetime(reader, addressSpace, layout, candidate->ProcessId);
                q.BudgetExceeded = reader.Stopped();
            }
        }
        for (auto* candidate : candidates)
        {
            if (reader.Stopped() && !candidate->Qualification.After.IdentityValid)
            {
                candidate->Qualification.BudgetExceeded = true;
            }
            AddHiddenProcessDecision(*result, std::move(*candidate));
        }
        if (result->UnverifiedCount != 0)
        {
            result->Warnings.push_back(L"unverified cross-view candidates remain; zero suspicious records is not a clean result");
        }
    }
    catch (const std::bad_alloc&)
    {
        *result = HiddenProcessScanResult{};
        if (error != nullptr)
        {
            *error = L"out of memory during hidden-process scan";
        }
        return false;
    }
    return true;
}

bool HiddenProcessViewSelfTest()
{
    return ToolhelpProcessWalkComplete(20, false, ERROR_NO_MORE_FILES) &&
        !ToolhelpProcessWalkComplete(20, false, ERROR_SUCCESS) &&
        !ToolhelpProcessWalkComplete(20, false, ERROR_ACCESS_DENIED) &&
        !ToolhelpProcessWalkComplete(20, true, ERROR_NO_MORE_FILES) &&
        !ToolhelpProcessWalkComplete(0, false, ERROR_NO_MORE_FILES) &&
        !ToolhelpProcessWalkComplete(kMaxProcesses, false, ERROR_NO_MORE_FILES) &&
        HiddenProcessSpiParseSelfTest() && HiddenProcessPolicySelfTest();
}
