#include "HiddenProcessScanner.h"

#include "HandleTableScanner.h"
#include "LayoutResolver.h"
#include "McpJson.h"

#include <Windows.h>
#include <TlHelp32.h>

#include <cstring>
#include <iomanip>
#include <map>
#include <sstream>
#include <string>
#include <unordered_set>

namespace
{
    constexpr uint64_t kKernelSpaceMin = 0xffff800000000000ull;
    constexpr ULONG kSystemProcessInformation = 5;
    constexpr uint32_t kMaxProcesses = 8192;
    constexpr uint32_t kMaxInfoBytes = 32u * 1024u * 1024u;

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

    struct ProcessView
    {
        uint32_t Pid = 0;
        uint64_t Eprocess = 0;
        std::wstring Image;
        bool Kernel = false;
        bool Spi = false;
        bool Toolhelp = false;
        bool HandleOwner = false;
    };

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelSpaceMin;
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
}

HiddenProcessScanner::HiddenProcessScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool HiddenProcessScanner::Scan(HiddenProcessScanResult* result, std::wstring* error)
{
    bool ok = false;

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

        TypeFieldInfo linksField = {};
        TypeFieldInfo pidField = {};
        TypeFieldInfo imageField = {};
        std::wstring ignored;
        uint64_t listHead = 0;
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
                while (current != 0 &&
                    current != listHead &&
                    IsKernelAddress(current) &&
                    walked < kMaxProcesses)
                {
                    ++walked;
                    uint64_t eprocess = current - linksField.Offset;
                    uint64_t pidValue = 0;
                    if (!ReadU64(device_, eprocess + pidField.Offset, &pidValue))
                    {
                        break;
                    }

                    ProcessView& view = views[static_cast<uint32_t>(pidValue)];
                    view.Pid = static_cast<uint32_t>(pidValue);
                    view.Eprocess = eprocess;
                    view.Kernel = true;
                    if (view.Image.empty() && imageField.Offset != 0)
                    {
                        std::vector<uint8_t> nameBytes;
                        uint32_t nameLen = imageField.Length > 16 ? 16 : static_cast<uint32_t>(imageField.Length);
                        if (nameLen > 0 &&
                            device_.ReadMemory(eprocess + imageField.Offset, nameLen, &nameBytes, nullptr) &&
                            !nameBytes.empty())
                        {
                            view.Image = AsciiToWide(
                                reinterpret_cast<const char*>(nameBytes.data()),
                                nameBytes.size());
                        }
                    }

                    uint64_t next = 0;
                    if (!ReadU64(device_, current, &next) || next == current)
                    {
                        break;
                    }
                    current = next;
                }
                result->KernelListCount = walked;
            }
        }
        else
        {
            result->Warnings.push_back(L"kernel ActiveProcessLinks walk was not resolved");
        }

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        auto query = ntdll == nullptr ? nullptr : reinterpret_cast<PfnNtQuerySystemInformation>(
            GetProcAddress(ntdll, "NtQuerySystemInformation"));
        if (query != nullptr)
        {
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
            if (status >= 0)
            {
                size_t offset = 0;
                uint32_t spiCount = 0;
                const uint8_t* bufStart = buffer.data();
                const uint8_t* bufEnd = buffer.data() + buffer.size();
                while (offset + sizeof(SystemProcessInfoHeader) <= buffer.size() && spiCount < kMaxProcesses)
                {
                    const SystemProcessInfoHeader* info =
                        reinterpret_cast<const SystemProcessInfoHeader*>(buffer.data() + offset);
                    uint32_t pid = static_cast<uint32_t>(reinterpret_cast<ULONG_PTR>(info->UniqueProcessId));
                    ProcessView& view = views[pid];
                    view.Pid = pid;
                    view.Spi = true;
                    ++spiCount;
                    if (view.Image.empty() &&
                        info->ImageName.Buffer != nullptr &&
                        info->ImageName.Length > 0)
                    {
                        const uint8_t* namePtr =
                            reinterpret_cast<const uint8_t*>(info->ImageName.Buffer);
                        const size_t nameBytes = info->ImageName.Length;
                        if (namePtr >= bufStart &&
                            nameBytes <= static_cast<size_t>(bufEnd - namePtr) &&
                            (nameBytes % sizeof(wchar_t)) == 0)
                        {
                            view.Image.assign(
                                info->ImageName.Buffer,
                                info->ImageName.Buffer + (nameBytes / sizeof(wchar_t)));
                        }
                    }
                    if (info->NextEntryOffset == 0)
                    {
                        break;
                    }
                    if (info->NextEntryOffset < sizeof(ULONG) * 2)
                    {
                        result->Warnings.push_back(L"SystemProcessInformation NextEntryOffset was too small");
                        break;
                    }
                    if (offset + info->NextEntryOffset < offset ||
                        offset + info->NextEntryOffset > buffer.size())
                    {
                        result->Warnings.push_back(L"SystemProcessInformation NextEntryOffset overflowed the snapshot");
                        break;
                    }
                    offset += info->NextEntryOffset;
                }
                result->SystemProcessInfoCount = spiCount;
            }
            else
            {
                result->Warnings.push_back(L"SystemProcessInformation query failed");
            }
        }

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE)
        {
            PROCESSENTRY32W entry = {};
            entry.dwSize = sizeof(entry);
            uint32_t toolCount = 0;
            if (Process32FirstW(snap, &entry))
            {
                do
                {
                    ProcessView& view = views[entry.th32ProcessID];
                    view.Pid = entry.th32ProcessID;
                    view.Toolhelp = true;
                    ++toolCount;
                    if (view.Image.empty() && entry.szExeFile[0] != 0)
                    {
                        view.Image = entry.szExeFile;
                    }
                } while (Process32NextW(snap, &entry) && toolCount < kMaxProcesses);
            }
            CloseHandle(snap);
            result->ToolhelpCount = toolCount;
        }
        else
        {
            result->Warnings.push_back(L"CreateToolhelp32Snapshot failed");
        }

        HandleTableScanner handles(device_, symbols_);
        HandleTableScanOptions handleOptions = {};
        handleOptions.CollectRecords = false;
        HandleTableScanResult handleResult = {};
        std::wstring handleError;
        if (handles.Scan(handleOptions, &handleResult, &handleError))
        {
            if (handleResult.Truncated)
            {
                result->Warnings.push_back(L"handle-owner view used a truncated handle snapshot");
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

        result->CoverageComplete =
            result->KernelListCount > 0 &&
            result->SystemProcessInfoCount > 0 &&
            result->ToolhelpCount > 0;

        for (const auto& pair : views)
        {
            const ProcessView& view = pair.second;
            if (view.Pid == 0)
            {
                continue;
            }

            HiddenProcessRecord record = {};
            record.ProcessId = view.Pid;
            record.Eprocess = view.Eprocess;
            record.ImageName = view.Image;
            record.InKernelList = view.Kernel;
            record.InSystemProcessInfo = view.Spi;
            record.InToolhelp = view.Toolhelp;
            record.InHandleOwners = view.HandleOwner;

            const uint32_t userViews =
                static_cast<uint32_t>(view.Spi) +
                static_cast<uint32_t>(view.Toolhelp);
            const bool kernelWalkOk = result->KernelListCount > 0;
            const bool userWalkOk =
                result->SystemProcessInfoCount > 0 ||
                result->ToolhelpCount > 0;
            if (kernelWalkOk &&
                userWalkOk &&
                view.Kernel &&
                userViews == 0 &&
                view.Pid > 4)
            {
                record.Suspicious = true;
                record.Notes = L"present in ActiveProcessLinks but absent from SPI and Toolhelp";
            }
            else if (kernelWalkOk &&
                userWalkOk &&
                !view.Kernel &&
                userViews > 0 &&
                view.Pid > 4)
            {
                record.Suspicious = true;
                record.Notes = L"visible to user-mode enumeration but missing from ActiveProcessLinks";
            }

            if (record.Suspicious)
            {
                ++result->SuspiciousCount;
            }

            // Keep non-suspicious records only when they disagree across views.
            if (record.Suspicious || (view.Kernel != view.Spi) || (view.Kernel != view.Toolhelp))
            {
                result->Records.push_back(record);
            }
        }

        ok = true;
    } while (false);

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
    json << L",\"suspicious\":" << result.SuspiciousCount;
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
        HiddenProcessRecord hidden = {};
        hidden.ProcessId = 1234;
        hidden.InKernelList = true;
        hidden.InSystemProcessInfo = false;
        hidden.InToolhelp = false;
        const uint32_t userViews =
            static_cast<uint32_t>(hidden.InSystemProcessInfo) +
            static_cast<uint32_t>(hidden.InToolhelp);
        if (!(hidden.InKernelList && userViews == 0 && hidden.ProcessId > 4))
        {
            break;
        }

        HiddenProcessRecord visible = {};
        visible.ProcessId = 4321;
        visible.InKernelList = false;
        visible.InSystemProcessInfo = true;
        visible.InToolhelp = true;
        if (visible.InKernelList ||
            (static_cast<uint32_t>(visible.InSystemProcessInfo) +
             static_cast<uint32_t>(visible.InToolhelp)) == 0)
        {
            break;
        }
        ok = true;
    } while (false);

    return ok;
}
