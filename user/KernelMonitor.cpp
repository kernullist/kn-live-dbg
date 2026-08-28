#include "KernelMonitor.h"

#include "HiddenProcessScanner.h"
#include "MapperRemnantScanner.h"

#include "../shared/KnLiveDbgIoctl.h"

#include <Windows.h>
#include <TlHelp32.h>

#include <algorithm>
#include <chrono>
#include <cwctype>
#include <iomanip>
#include <sstream>

namespace
{
    constexpr uint64_t kLogRotateBytes = 100ull * 1024ull * 1024ull;
    constexpr uint32_t kLogRotateCount = 5;
    constexpr size_t kPrintQueueCap = 1024;
    constexpr ULONG kProcessEnableLogging = 96;
    constexpr ULONG kProcessEnableReadWriteVmLogging = 87;

    std::wstring ToLowerCopy(std::wstring value)
    {
        for (wchar_t& ch : value)
        {
            if (ch >= L'A' && ch <= L'Z')
            {
                ch = static_cast<wchar_t>(ch + (L'a' - L'A'));
            }
        }
        return value;
    }

    std::wstring JsonEscape(const std::wstring& in)
    {
        std::wstring out;
        out.reserve(in.size() + 8);
        for (wchar_t c : in)
        {
            switch (c)
            {
                case L'"':
                    out += L"\\\"";
                    break;
                case L'\\':
                    out += L"\\\\";
                    break;
                case L'\n':
                    out += L"\\n";
                    break;
                case L'\r':
                    out += L"\\r";
                    break;
                case L'\t':
                    out += L"\\t";
                    break;
                default:
                    if (c < 0x20)
                    {
                        wchar_t esc[8] = {};
                        swprintf_s(esc, L"\\u%04x", static_cast<unsigned>(c));
                        out += esc;
                    }
                    else
                    {
                        out.push_back(c);
                    }
                    break;
            }
        }
        return out;
    }

    std::string WideToUtf8(const std::wstring& w)
    {
        if (w.empty())
        {
            return std::string();
        }
        int needed = WideCharToMultiByte(
            CP_UTF8,
            0,
            w.c_str(),
            static_cast<int>(w.size()),
            nullptr,
            0,
            nullptr,
            nullptr);
        if (needed <= 0)
        {
            return std::string();
        }
        std::string s(static_cast<size_t>(needed), '\0');
        WideCharToMultiByte(
            CP_UTF8,
            0,
            w.c_str(),
            static_cast<int>(w.size()),
            &s[0],
            needed,
            nullptr,
            nullptr);
        return s;
    }

    std::wstring TimestampUtcString(uint64_t fileTimeTicks)
    {
        FILETIME ft = {};
        ft.dwLowDateTime = static_cast<DWORD>(fileTimeTicks & 0xFFFFFFFFull);
        ft.dwHighDateTime = static_cast<DWORD>(fileTimeTicks >> 32);
        SYSTEMTIME st = {};
        if (!FileTimeToSystemTime(&ft, &st))
        {
            return L"1970-01-01T00:00:00.000Z";
        }
        wchar_t buf[64] = {};
        swprintf_s(
            buf,
            L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
            st.wYear,
            st.wMonth,
            st.wDay,
            st.wHour,
            st.wMinute,
            st.wSecond,
            st.wMilliseconds);
        return buf;
    }

    std::wstring ExeDirectory()
    {
        wchar_t buf[MAX_PATH] = {};
        DWORD len = GetModuleFileNameW(nullptr, buf, ARRAYSIZE(buf));
        if (len == 0 || len >= ARRAYSIZE(buf))
        {
            return L".";
        }
        std::wstring path(buf, len);
        size_t slash = path.find_last_of(L"\\/");
        if (slash == std::wstring::npos)
        {
            return L".";
        }
        return path.substr(0, slash);
    }

    bool WatchTokenIsWildcard(const std::wstring& item)
    {
        return item == L"*" || item == L"*.sys" || item == L"*.exe";
    }

    bool NameEqualsWatch(const std::wstring& baseLower, const std::vector<std::wstring>& watchLower)
    {
        bool matched = false;
        for (const std::wstring& item : watchLower)
        {
            if (WatchTokenIsWildcard(item))
            {
                if (!baseLower.empty())
                {
                    matched = true;
                    break;
                }
                continue;
            }
            if (!baseLower.empty() && baseLower == item)
            {
                matched = true;
                break;
            }
        }
        return matched;
    }

    std::wstring FormatKmonJsonLine(const KmonEvent& event)
    {
        std::wstringstream line;
        line << L"{\"ts\":\"" << JsonEscape(TimestampUtcString(event.Timestamp)) << L"\""
             << L",\"seq\":" << event.Sequence
             << L",\"kind\":\"" << JsonEscape(event.Kind) << L"\""
             << L",\"pid\":" << event.ProcessId
             << L",\"target_pid\":" << event.TargetProcessId
             << L",\"image\":\"" << JsonEscape(event.Image) << L"\""
             << L",\"target_image\":\"" << JsonEscape(event.TargetImage) << L"\""
             << L",\"driver\":\"" << JsonEscape(event.Driver) << L"\""
             << L",\"task\":\"" << JsonEscape(event.Task) << L"\""
             << L",\"summary\":\"" << JsonEscape(event.Summary) << L"\"";
        if (!event.Evidence.empty())
        {
            line << L",\"evidence\":{";
            bool first = true;
            for (const auto& item : event.Evidence)
            {
                if (!first)
                {
                    line << L",";
                }
                first = false;
                line << L"\"" << JsonEscape(item.first) << L"\":\""
                     << JsonEscape(item.second) << L"\"";
            }
            line << L"}";
        }
        line << L"}\n";
        return line.str();
    }

    typedef LONG NTSTATUS;
    typedef NTSTATUS(NTAPI* NtSetInformationProcessFn)(HANDLE, ULONG, PVOID, ULONG);

    bool TryEnableLoggingUsermode(uint32_t pid, uint32_t loggingFlags)
    {
        bool ok = false;
        HANDLE process = nullptr;

        do
        {
            process = OpenProcess(PROCESS_SET_INFORMATION, FALSE, pid);
            if (process == nullptr)
            {
                break;
            }

            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            if (ntdll == nullptr)
            {
                break;
            }

            auto setInfo = reinterpret_cast<NtSetInformationProcessFn>(
                GetProcAddress(ntdll, "NtSetInformationProcess"));
            if (setInfo == nullptr)
            {
                break;
            }

            ULONG flags = loggingFlags;
            NTSTATUS status = setInfo(
                process,
                kProcessEnableLogging,
                &flags,
                sizeof(flags));
            if (status < 0)
            {
                UCHAR smallFlags = static_cast<UCHAR>(loggingFlags & 0x3u);
                status = setInfo(
                    process,
                    kProcessEnableReadWriteVmLogging,
                    &smallFlags,
                    sizeof(smallFlags));
            }
            if (status >= 0)
            {
                ok = true;
            }
        } while (false);

        if (process != nullptr)
        {
            CloseHandle(process);
        }

        return ok;
    }

    void CollectToolhelpPidsByName(
        const std::vector<std::wstring>& namesLower,
        std::vector<uint32_t>* pids)
    {
        if (pids == nullptr || namesLower.empty())
        {
            return;
        }

        std::vector<std::wstring> concrete;
        concrete.reserve(namesLower.size());
        for (const std::wstring& item : namesLower)
        {
            if (!WatchTokenIsWildcard(item) && !item.empty())
            {
                concrete.push_back(item);
            }
        }
        if (concrete.empty())
        {
            return;
        }

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
        {
            return;
        }

        PROCESSENTRY32W entry = {};
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snap, &entry))
        {
            do
            {
                std::wstring base = KmonBasenameLower(entry.szExeFile);
                if (NameEqualsWatch(base, concrete) && entry.th32ProcessID > 4)
                {
                    pids->push_back(entry.th32ProcessID);
                }
            } while (Process32NextW(snap, &entry));
        }
        CloseHandle(snap);
    }
}

std::wstring KmonBasenameLower(const std::wstring& path)
{
    if (path.empty())
    {
        return path;
    }
    size_t slash = path.find_last_of(L"\\/");
    std::wstring base = (slash == std::wstring::npos) ? path : path.substr(slash + 1);
    return ToLowerCopy(std::move(base));
}

std::wstring KmonNormalizeDriverPath(const std::wstring& path)
{
    std::wstring n = ToLowerCopy(path);
    for (wchar_t& ch : n)
    {
        if (ch == L'/')
        {
            ch = L'\\';
        }
    }

    const std::wstring prefixes[] = {
        L"\\\\?\\",
        L"\\\\.\\",
        L"\\??\\",
        L"\\dosdevices\\"
    };
    bool stripped = true;
    while (stripped)
    {
        stripped = false;
        for (const std::wstring& prefix : prefixes)
        {
            if (n.size() >= prefix.size() && n.compare(0, prefix.size(), prefix) == 0)
            {
                n.erase(0, prefix.size());
                stripped = true;
                break;
            }
        }
    }

    const std::wstring systemRootSlash = L"\\systemroot\\";
    const std::wstring systemRoot = L"systemroot\\";
    if (n.size() >= systemRootSlash.size() &&
        n.compare(0, systemRootSlash.size(), systemRootSlash) == 0)
    {
        n.replace(0, systemRootSlash.size(), L"\\windows\\");
    }
    else if (n.size() >= systemRoot.size() &&
        n.compare(0, systemRoot.size(), systemRoot) == 0)
    {
        n.replace(0, systemRoot.size(), L"\\windows\\");
    }
    if (!n.empty() && n[0] != L'\\' && n.find(L":\\") != 1 &&
        n.find(L'\\') != std::wstring::npos)
    {
        n.insert(n.begin(), L'\\');
    }
    return n;
}

std::wstring KmonClassifyDriverPath(const std::wstring& path)
{
    std::wstring n = KmonNormalizeDriverPath(path);
    if (n.empty())
    {
        return L"unknown";
    }

    if (n.find(L"\\windows\\system32\\drivers\\") != std::wstring::npos ||
        n.find(L"\\windows\\system32\\driverstore\\") != std::wstring::npos ||
        n.find(L"\\windows\\winsxs\\") != std::wstring::npos ||
        n.find(L"\\windows\\system32\\codeintegrity\\") != std::wstring::npos)
    {
        return L"inbox";
    }

    if (n.find(L"\\users\\") != std::wstring::npos ||
        n.find(L"\\appdata\\") != std::wstring::npos ||
        n.find(L"\\windows\\temp\\") != std::wstring::npos ||
        n.find(L"\\programdata\\") != std::wstring::npos ||
        n.find(L"\\downloads\\") != std::wstring::npos ||
        n.find(L"$recycle.bin") != std::wstring::npos)
    {
        return L"drop";
    }

    // "\temp\" after the drop-dir checks so C:\Windows\foo.sys is not inbox,
    // but C:\Temp\x.sys still counts. Do not use a bare "\tmp\" match; it is
    // too wide.
    if (n.find(L"\\temp\\") != std::wstring::npos)
    {
        return L"drop";
    }

    // Volume-root drop: C:\cheat.sys or \cheat.sys
    size_t lastSlash = n.find_last_of(L'\\');
    if (lastSlash != std::wstring::npos)
    {
        std::wstring parent = n.substr(0, lastSlash);
        if (parent.size() == 2 && parent[1] == L':')
        {
            return L"drop";
        }
        if (parent.empty())
        {
            return L"drop";
        }
    }

    if (n.find(L"\\program files") != std::wstring::npos)
    {
        return L"third_party";
    }

    if (n.find(L"\\device\\") != std::wstring::npos &&
        n.find(L"\\windows\\") == std::wstring::npos)
    {
        if (KmonPathLooksLikeSys(n) ||
            n.find(L"harddiskvolume") != std::wstring::npos ||
            n.find(L"\\users\\") != std::wstring::npos)
        {
            return L"drop";
        }
    }

    // win32k.sys lives in System32, not drivers. Still inbox.
    if (n.find(L"\\windows\\system32\\") != std::wstring::npos)
    {
        return L"inbox";
    }

    // C:\Windows\cheat.sys is a classic masquerade drop, not inbox.
    if (n.find(L"\\windows\\") != std::wstring::npos)
    {
        return L"drop";
    }

    return L"unknown";
}

bool KmonDriverPathIsInbox(const std::wstring& path)
{
    return KmonClassifyDriverPath(path) == L"inbox";
}

bool KmonDriverPathHasFileDirectory(const std::wstring& path)
{
    std::wstring n = KmonNormalizeDriverPath(path);
    if (n.empty())
    {
        return false;
    }
    size_t slash = n.find_last_of(L'\\');
    if (slash == std::wstring::npos)
    {
        return false;
    }
    std::wstring parent = n.substr(0, slash);
    if (parent.empty())
    {
        return false;
    }
    if (parent == L"\\driver" || parent == L"\\device")
    {
        return false;
    }
    return true;
}

bool KmonPathLooksLikeSys(const std::wstring& path)
{
    std::wstring lower = ToLowerCopy(path);
    while (!lower.empty() &&
        (lower.back() == L'\0' || lower.back() == L' ' || lower.back() == L'.'))
    {
        lower.pop_back();
    }
    if (lower.size() < 4)
    {
        return false;
    }
    return lower.compare(lower.size() - 4, 4, L".sys") == 0;
}

bool KmonTaskLooksLikeDriverObjectLoad(const std::wstring& task)
{
    std::wstring lower = ToLowerCopy(task);
    return lower.find(L"driverobjectload") != std::wstring::npos ||
        lower.find(L"driver_object_load") != std::wstring::npos ||
        (lower.find(L"driverobject") != std::wstring::npos &&
            lower.find(L"unload") == std::wstring::npos &&
            lower.find(L"load") != std::wstring::npos);
}

bool KmonTaskLooksLikeDriverObjectUnload(const std::wstring& task)
{
    std::wstring lower = ToLowerCopy(task);
    return lower.find(L"driverobjectunload") != std::wstring::npos ||
        lower.find(L"driver_object_unload") != std::wstring::npos ||
        (lower.find(L"driverobject") != std::wstring::npos &&
            lower.find(L"unload") != std::wstring::npos);
}

bool KmonTaskLooksLikeDeviceObject(const std::wstring& task)
{
    std::wstring lower = ToLowerCopy(task);
    return lower.find(L"deviceobject") != std::wstring::npos ||
        lower.find(L"device_object") != std::wstring::npos;
}

bool KmonTaskLooksLikeRemoteInject(const std::wstring& task)
{
    std::wstring lower = ToLowerCopy(task);
    return lower.find(L"allocvm") != std::wstring::npos ||
        lower.find(L"protectvm") != std::wstring::npos ||
        lower.find(L"mapview") != std::wstring::npos ||
        lower.find(L"queueuserapc") != std::wstring::npos ||
        lower.find(L"setthreadcontext") != std::wstring::npos ||
        lower.find(L"writevm") != std::wstring::npos ||
        lower.find(L"readvm") != std::wstring::npos ||
        lower.find(L"suspend") != std::wstring::npos ||
        lower.find(L"resume") != std::wstring::npos;
}

std::wstring KmonExtractPayloadDriverName(const std::vector<TiPayloadField>& payload)
{
    std::wstring found;

    do
    {
        for (const TiPayloadField& field : payload)
        {
            if (field.Value.empty() || field.Value[0] == L'<')
            {
                continue;
            }

            std::wstring nameLower = ToLowerCopy(field.Name);
            std::wstring valueLower = ToLowerCopy(field.Value);
            const bool driverish =
                nameLower.find(L"driver") != std::wstring::npos ||
                nameLower.find(L"imagefilename") != std::wstring::npos ||
                nameLower.find(L"filename") != std::wstring::npos ||
                nameLower.find(L"device") != std::wstring::npos;
            const bool sysValue = KmonPathLooksLikeSys(field.Value);
            if (!driverish && !sysValue)
            {
                continue;
            }

            found = field.Value;
            if (sysValue || nameLower.find(L"driver") != std::wstring::npos)
            {
                break;
            }
        }
    } while (false);

    return found;
}

bool KmonClassifyTiEvent(const TiEventRecord& record, KmonEvent* out)
{
    bool classified = false;

    do
    {
        if (out == nullptr)
        {
            break;
        }

        *out = KmonEvent{};
        out->Timestamp = record.Timestamp;
        out->ProcessId = record.ProcessId;
        out->TargetProcessId = record.TargetProcessId;
        out->Image = record.ImagePath;
        out->TargetImage = record.TargetImageBase;
        out->Task = record.TaskName.empty()
            ? (L"Task" + std::to_wstring(record.TaskId))
            : record.TaskName;
        out->Driver = KmonExtractPayloadDriverName(record.Payload);
        const std::wstring pathClass = KmonClassifyDriverPath(out->Driver);
        if (!out->Driver.empty())
        {
            out->Evidence[L"path_class"] = pathClass;
        }

        if (KmonTaskLooksLikeDriverObjectLoad(out->Task))
        {
            if (out->Driver.empty())
            {
                out->Kind = L"driver.official_load";
                out->Evidence[L"path_class"] = L"unknown";
                out->Summary = L"DRIVER_OBJECT load with undecoded image path";
            }
            else if (pathClass == L"inbox")
            {
                out->Kind = L"driver.official_load";
                out->Summary = L"inbox DRIVER_OBJECT load " + out->Driver;
            }
            else if (pathClass == L"drop" ||
                pathClass == L"third_party" ||
                KmonDriverPathHasFileDirectory(out->Driver))
            {
                out->Kind = L"driver.drop_load";
                out->Summary = L"non-inbox DRIVER_OBJECT load " + out->Driver;
            }
            else
            {
                // Bare filename or \Driver/\Device object path. Hiding these
                // by default avoids acpi.sys / DeviceObject firehoses when
                // TDH yields a leaf name instead of a file path.
                out->Kind = L"driver.official_load";
                out->Summary = L"DRIVER_OBJECT load " + out->Driver;
            }
            classified = true;
            break;
        }

        if (KmonTaskLooksLikeDriverObjectUnload(out->Task))
        {
            out->Kind = L"driver.official_unload";
            out->Summary = L"DRIVER_OBJECT unload";
            if (!out->Driver.empty())
            {
                out->Summary += L" " + KmonBasenameLower(out->Driver);
            }
            classified = true;
            break;
        }

        if (KmonTaskLooksLikeDeviceObject(out->Task))
        {
            out->Kind = L"driver.device";
            out->Summary = L"DEVICE_OBJECT load/unload";
            if (!out->Driver.empty())
            {
                out->Summary += L" " + KmonBasenameLower(out->Driver);
            }
            classified = true;
            break;
        }

        if (KmonTaskLooksLikeRemoteInject(out->Task) &&
            record.TargetProcessId != 0 &&
            record.TargetProcessId != record.ProcessId)
        {
            out->Kind = L"inject.remote";
            out->Summary = out->Task + L" pid=" + std::to_wstring(record.ProcessId) +
                L" -> pid=" + std::to_wstring(record.TargetProcessId);
            classified = true;
            break;
        }
    } while (false);

    return classified;
}

bool KmonClassifyLiveEvent(const TimelineEvent& event, KmonEvent* out)
{
    bool classified = false;

    do
    {
        if (out == nullptr)
        {
            break;
        }

        *out = KmonEvent{};
        out->Timestamp = event.TimestampFileTime;
        out->ProcessId = event.ProcessId;
        out->TargetProcessId = event.TargetProcessId;
        out->Image = event.Entity;
        out->Task = event.Action;

        std::wstring action = ToLowerCopy(event.Action);
        if (action == L"image-load" && event.ProcessId == 0 && !event.Entity.empty())
        {
            const std::wstring pathClass = KmonClassifyDriverPath(event.Entity);
            const bool fileDrop =
                pathClass == L"drop" ||
                pathClass == L"third_party" ||
                (pathClass != L"inbox" && KmonDriverPathHasFileDirectory(event.Entity));
            if (!fileDrop &&
                pathClass != L"inbox" &&
                !KmonPathLooksLikeSys(event.Entity))
            {
                break;
            }

            out->Driver = event.Entity;
            out->Evidence[L"path_class"] = pathClass;
            out->Evidence[L"source"] = L"image_notify";
            if (fileDrop)
            {
                out->Kind = L"driver.drop_load";
                out->Summary = L"non-inbox kernel image load " + event.Entity;
                out->Evidence[L"followup"] = L"!pool pe /suspicious; !mapper; !kpage /pe";
            }
            else
            {
                out->Kind = L"driver.image_only";
                out->Summary = L"inbox kernel image load " + KmonBasenameLower(event.Entity);
            }
            classified = true;
            break;
        }

        if (action == L"process-create")
        {
            out->Kind = L"process.create";
            out->Summary = L"process create pid=" + std::to_wstring(event.ProcessId);
            classified = true;
            break;
        }
    } while (false);

    return classified;
}

bool KmonWatchMatches(const KmonEvent& event, const KmonOptions& options)
{
    bool matched = false;

    do
    {
        if (event.Kind.empty())
        {
            break;
        }

        if (event.Kind == L"gap.kernel_rw" ||
            event.Kind == L"process.hidden" ||
            event.Kind == L"process.syscall_unnamed" ||
            event.Kind == L"driver.drop_load" ||
            event.Kind == L"driver.short_lived" ||
            event.Kind == L"driver.mapped_residue")
        {
            matched = true;
            break;
        }

        std::wstring driverBase = KmonBasenameLower(event.Driver);
        const bool namedDriver =
            !event.Driver.empty() && NameEqualsWatch(driverBase, options.WatchDrivers);
        std::wstring pathClass;
        auto pathIt = event.Evidence.find(L"path_class");
        if (pathIt != event.Evidence.end())
        {
            pathClass = pathIt->second;
        }

        if (event.Kind.rfind(L"driver.", 0) == 0)
        {
            // /driver is a highlight, not an exclusive filter. Unknown
            // drop/map/unload names must still surface.
            if (namedDriver)
            {
                matched = true;
                break;
            }
            if (options.VerboseDrivers)
            {
                matched = true;
                break;
            }
            // Empty payload paths are common when TDH leaves DriverName as
            // <struct>. Do not treat those as drops or the tail becomes a
            // DeviceObject/unload firehose. /driver * must not override this.
            if (event.Driver.empty())
            {
                break;
            }
            if (pathClass == L"inbox")
            {
                break;
            }
            if (event.Kind == L"driver.official_unload")
            {
                if (pathClass == L"drop" ||
                    pathClass == L"third_party" ||
                    KmonDriverPathHasFileDirectory(event.Driver))
                {
                    matched = true;
                }
                break;
            }
            if (event.Kind == L"driver.device")
            {
                if (KmonPathLooksLikeSys(event.Driver))
                {
                    matched = true;
                }
                break;
            }
            break;
        }

        if (event.Kind == L"inject.remote")
        {
            if (options.WatchPids.empty() && options.WatchNames.empty())
            {
                break;
            }
            for (uint32_t pid : options.WatchPids)
            {
                if (pid == event.ProcessId || pid == event.TargetProcessId)
                {
                    matched = true;
                    break;
                }
            }
            if (matched)
            {
                break;
            }
            std::wstring caller = KmonBasenameLower(event.Image);
            std::wstring target = KmonBasenameLower(event.TargetImage);
            if (NameEqualsWatch(caller, options.WatchNames) ||
                NameEqualsWatch(target, options.WatchNames))
            {
                matched = true;
            }
            break;
        }

        if (event.Kind == L"process.create")
        {
            if (options.WatchNames.empty() && options.WatchPids.empty())
            {
                break;
            }
            std::wstring base = KmonBasenameLower(event.Image);
            if (NameEqualsWatch(base, options.WatchNames))
            {
                matched = true;
                break;
            }
            for (uint32_t pid : options.WatchPids)
            {
                if (pid == event.ProcessId)
                {
                    matched = true;
                    break;
                }
            }
            break;
        }
    } while (false);

    return matched;
}

KernelMonitor::KernelMonitor() = default;

KernelMonitor::~KernelMonitor()
{
    std::wstring ignored;
    Stop(&ignored);
}

bool KernelMonitor::IsActive() const
{
    return Active.load();
}

bool KernelMonitor::IsLiveOutputEnabled() const
{
    return LiveOutput.load();
}

void KernelMonitor::SetLiveOutput(bool enabled)
{
    LiveOutput.store(enabled);
}

KmonOptions KernelMonitor::CurrentOptions() const
{
    KmonOptions options;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        options = Options;
    }
    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        options.WatchPids.assign(WatchPids.begin(), WatchPids.end());
        options.WatchNames = WatchNamesLower;
        options.WatchDrivers = WatchDriversLower;
    }
    return options;
}

KmonStats KernelMonitor::SnapshotStats() const
{
    KmonStats stats;
    stats.EventsKept = EventsKept.load();
    stats.EventsDropped = EventsDropped.load();
    stats.EventsLogged = EventsLogged.load();
    stats.EventsWatchMatched = EventsWatchMatched.load();
    stats.TiIngested = TiIngested.load();
    stats.LiveIngested = LiveIngested.load();
    stats.HiddenScans = HiddenScans.load();
    stats.MapperScans = MapperScans.load();
    stats.LoggingEnabled = LoggingEnabledCount.load();
    stats.LoggingFailed = LoggingFailedCount.load();
    stats.LogBytesWritten = LogBytesWritten.load();
    stats.LogRotations = LogRotations.load();
    stats.StartTickMs = StartTickMs.load();
    stats.LastEventTickMs = LastEventTickMs.load();
    return stats;
}

bool KernelMonitor::Start(
    const KmonOptions& options,
    TiSubscriber* ti,
    TimelineStore* timeline,
    DeviceClient* device,
    SymbolEngine* symbols,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (ti == nullptr || timeline == nullptr || device == nullptr || symbols == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"kmon requires TI, timeline, device, and symbols";
            }
            break;
        }

        {
            std::lock_guard<std::mutex> lock(StateMutex);
            if (Active.load())
            {
                if (error != nullptr)
                {
                    *error = L"kmon already active";
                }
                break;
            }

            Options = options;
            if (Options.RingCapacity < 1024)
            {
                Options.RingCapacity = 65536;
            }
            if (Options.ThrottlePerSecond == 0)
            {
                Options.ThrottlePerSecond = 50;
            }
            if (Options.LogDirectory.empty())
            {
                Options.LogDirectory = ExeDirectory();
            }
            if (Options.HiddenScanIntervalMs < 1000)
            {
                Options.HiddenScanIntervalMs = 5000;
            }
            if (Options.MapperScanIntervalMs < 1000)
            {
                Options.MapperScanIntervalMs = 8000;
            }

            {
                std::vector<std::wstring> names;
                names.reserve(Options.WatchNames.size());
                for (const std::wstring& name : Options.WatchNames)
                {
                    std::wstring token = KmonBasenameLower(name);
                    if (!token.empty())
                    {
                        names.push_back(std::move(token));
                    }
                }
                Options.WatchNames = std::move(names);
            }
            {
                std::vector<std::wstring> drivers;
                drivers.reserve(Options.WatchDrivers.size());
                for (const std::wstring& name : Options.WatchDrivers)
                {
                    std::wstring token = KmonBasenameLower(name);
                    if (!token.empty())
                    {
                        drivers.push_back(std::move(token));
                    }
                }
                Options.WatchDrivers = std::move(drivers);
            }

            {
                std::lock_guard<std::mutex> watchLock(WatchMutex);
                WatchPids.clear();
                WatchNamesLower = Options.WatchNames;
                WatchDriversLower = Options.WatchDrivers;
                WatchPromotedPids.clear();
                LoggingEnabledPids.clear();
                EmittedHiddenPids.clear();
                EmittedUnnamedPids.clear();
                EmittedMapperKeys.clear();
                RecentLoads.clear();
                for (uint32_t pid : Options.WatchPids)
                {
                    WatchPids.insert(pid);
                }
            }

            Ti = ti;
            Timeline = timeline;
            Device = device;
            Symbols = symbols;
            TiCursorSequence = 0;
            LiveCursorEventId = 0;
            NextHiddenScanTickMs = 0;
            NextMapperScanTickMs = 0;

            EventsKept.store(0);
            EventsDropped.store(0);
            EventsLogged.store(0);
            EventsWatchMatched.store(0);
            TiIngested.store(0);
            LiveIngested.store(0);
            HiddenScans.store(0);
            MapperScans.store(0);
            LoggingEnabledCount.store(0);
            LoggingFailedCount.store(0);
            LogBytesWritten.store(0);
            LogRotations.store(0);
            StartTickMs.store(GetTickCount64());
            LastEventTickMs.store(0);
            ThrottleWindowStartMs.store(0);
            ThrottleWindowCount.store(0);
            ThrottleSuppressed.store(0);

            {
                std::lock_guard<std::mutex> ringLock(RingMutex);
                Ring.clear();
                NextSequence = 1;
            }
            {
                std::lock_guard<std::mutex> printLock(PrintMutex);
                PrintQueue.clear();
            }

            {
                std::lock_guard<std::mutex> logLock(LogMutex);
                CloseLogLocked();
                if (!EnsureLogOpenLocked())
                {
                    if (error != nullptr)
                    {
                        *error = L"could not open kmon log in " + Options.LogDirectory;
                    }
                    Ti = nullptr;
                    Timeline = nullptr;
                    Device = nullptr;
                    Symbols = nullptr;
                    LiveOutput.store(false);
                    break;
                }
            }

            StopRequested.store(false);
            LiveOutput.store(Options.AttachLiveTail);
            Active.store(true);
        }

        EnableLoggingForWatchTargets();

        KmonEvent gap = {};
        FILETIME now = {};
        GetSystemTimeAsFileTime(&now);
        gap.Timestamp = (static_cast<uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;
        gap.Kind = L"gap.kernel_rw";
        gap.Summary = L"kernel MmCopyVirtualMemory / DeviceIoControl is not visible on ETW-TI";
        gap.Evidence[L"followup"] = L"!callbacks; !inputstack; !driver integrity; !pool pe";
        RecordEvent(std::move(gap));

        {
            std::lock_guard<std::mutex> lock(StateMutex);
            if (!Active.load())
            {
                if (error != nullptr)
                {
                    *error = L"kmon became inactive during start";
                }
                break;
            }
            if (!Worker.joinable())
            {
                Worker = std::thread(&KernelMonitor::WorkerLoop, this);
            }
        }

        ok = true;
    } while (false);

    return ok;
}

bool KernelMonitor::Stop(std::wstring* error)
{
    std::thread worker;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        StopRequested.store(true);
        Active.store(false);
        LiveOutput.store(false);
        if (Worker.joinable())
        {
            worker = std::move(Worker);
        }
        Ti = nullptr;
        Timeline = nullptr;
        Device = nullptr;
        Symbols = nullptr;
    }

    if (worker.joinable())
    {
        worker.join();
    }

    {
        std::lock_guard<std::mutex> logLock(LogMutex);
        CloseLogLocked();
    }

    if (error != nullptr)
    {
        error->clear();
    }
    return true;
}

void KernelMonitor::WorkerLoop()
{
    while (!StopRequested.load())
    {
        IngestThreatIntel();
        IngestLiveTimeline();

        const uint64_t nowMs = GetTickCount64();
        uint32_t hiddenInterval = 5000;
        uint32_t mapperInterval = 8000;
        {
            std::lock_guard<std::mutex> lock(StateMutex);
            hiddenInterval = Options.HiddenScanIntervalMs;
            mapperInterval = Options.MapperScanIntervalMs;
        }
        if (hiddenInterval < 1000)
        {
            hiddenInterval = 5000;
        }
        if (mapperInterval < 1000)
        {
            mapperInterval = 8000;
        }

        // First tick only schedules the scans. Walking PsActiveProcessHead
        // plus mapper leftovers stalls TI ingest at the exact moment a
        // short-lived drop is most likely to appear.
        if (NextHiddenScanTickMs == 0)
        {
            NextHiddenScanTickMs = nowMs + 1000;
        }
        else if (nowMs >= NextHiddenScanTickMs)
        {
            ScanHiddenProcesses();
            NextHiddenScanTickMs = nowMs + hiddenInterval;
        }

        if (NextMapperScanTickMs == 0)
        {
            NextMapperScanTickMs = nowMs + 1000;
        }
        else if (nowMs >= NextMapperScanTickMs)
        {
            ScanMapperRemnants();
            NextMapperScanTickMs = nowMs + mapperInterval;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
}

void KernelMonitor::IngestThreatIntel()
{
    TiSubscriber* ti = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        ti = Ti;
    }
    if (ti == nullptr || !ti->IsActive())
    {
        return;
    }

    std::vector<TiEventRecord> batch = ti->RecentAfterSequence(TiCursorSequence, 512);
    for (const TiEventRecord& record : batch)
    {
        if (record.Sequence != 0)
        {
            TiCursorSequence = record.Sequence;
        }
        TiIngested.fetch_add(1);

        KmonEvent classified = {};
        if (KmonClassifyTiEvent(record, &classified))
        {
            if (classified.Kind == L"driver.drop_load" ||
                classified.Kind == L"driver.official_load")
            {
                NoteDriverLoad(classified);
            }
            if (classified.Kind == L"driver.official_unload")
            {
                MaybeEmitShortLived(classified);
            }
            RecordEvent(std::move(classified));
        }

        if (record.ProcessId > 4 && record.ImagePath.empty())
        {
            bool claimed = false;
            {
                std::lock_guard<std::mutex> watchLock(WatchMutex);
                claimed = EmittedUnnamedPids.insert(record.ProcessId).second;
            }
            if (claimed)
            {
                std::wstring kernelName;
                ResolveKernelImageName(record.ProcessId, &kernelName);
                KmonEvent unnamed = {};
                unnamed.Timestamp = record.Timestamp;
                unnamed.Kind = L"process.syscall_unnamed";
                unnamed.ProcessId = record.ProcessId;
                unnamed.Image = kernelName;
                unnamed.Task = record.TaskName;
                unnamed.Summary = L"TI pid=" + std::to_wstring(record.ProcessId) +
                    L" with empty OpenProcess image";
                if (!kernelName.empty())
                {
                    unnamed.Summary += L" kernel_name=" + kernelName;
                    unnamed.Evidence[L"kernel_image"] = kernelName;
                }
                RecordEvent(std::move(unnamed));
            }
        }
    }
}

void KernelMonitor::IngestLiveTimeline()
{
    TimelineStore* timeline = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        timeline = Timeline;
    }
    if (timeline == nullptr)
    {
        return;
    }

    // timeline clear() resets NextEventId to 1. A stale cursor then skips
    // every new live event for the rest of the session.
    if (LiveCursorEventId != 0 && timeline->PeekNextEventId() <= LiveCursorEventId)
    {
        LiveCursorEventId = 0;
    }

    std::vector<TimelineEvent> batch = timeline->RecentAfterEventId(LiveCursorEventId, 256);
    for (const TimelineEvent& event : batch)
    {
        if (event.EventId > LiveCursorEventId)
        {
            LiveCursorEventId = event.EventId;
        }
        if (ToLowerCopy(event.Source) != L"kernel-live")
        {
            continue;
        }
        LiveIngested.fetch_add(1);

        KmonEvent classified = {};
        if (!KmonClassifyLiveEvent(event, &classified))
        {
            continue;
        }

        if (classified.Kind == L"process.create")
        {
            std::wstring base = KmonBasenameLower(classified.Image);
            bool nameWatch = false;
            {
                std::lock_guard<std::mutex> watchLock(WatchMutex);
                nameWatch = NameEqualsWatch(base, WatchNamesLower);
                if (nameWatch)
                {
                    WatchPromotedPids.insert(classified.ProcessId);
                    WatchPids.insert(classified.ProcessId);
                }
            }
            if (nameWatch && classified.ProcessId > 4)
            {
                EnableLoggingForPid(classified.ProcessId);
            }
        }

        if (classified.Kind == L"driver.drop_load" ||
            classified.Kind == L"driver.official_load")
        {
            NoteDriverLoad(classified);
        }

        RecordEvent(std::move(classified));
    }
}

void KernelMonitor::ScanHiddenProcesses()
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        device = Device;
        symbols = Symbols;
    }
    if (device == nullptr || symbols == nullptr || !device->IsOpen())
    {
        return;
    }

    HiddenProcessScanner scanner(*device, *symbols);
    HiddenProcessScanResult result = {};
    std::wstring error;
    if (!scanner.Scan(&result, &error))
    {
        return;
    }
    HiddenScans.fetch_add(1);

    FILETIME now = {};
    GetSystemTimeAsFileTime(&now);
    const uint64_t ts = (static_cast<uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;

    for (const HiddenProcessRecord& record : result.Records)
    {
        if (!record.Suspicious || record.Auxiliary || record.Terminating)
        {
            continue;
        }

        bool already = false;
        {
            std::lock_guard<std::mutex> watchLock(WatchMutex);
            already = EmittedHiddenPids.count(record.ProcessId) != 0;
            if (!already)
            {
                EmittedHiddenPids.insert(record.ProcessId);
            }
        }
        if (already)
        {
            continue;
        }

        KmonEvent event = {};
        event.Timestamp = ts;
        event.Kind = L"process.hidden";
        event.ProcessId = record.ProcessId;
        event.Image = record.ImageName;
        event.Summary = L"hidden process pid=" + std::to_wstring(record.ProcessId);
        if (!record.ImageName.empty())
        {
            event.Summary += L" " + record.ImageName;
        }
        event.Evidence[L"in_kernel"] = record.InKernelList ? L"true" : L"false";
        event.Evidence[L"in_spi"] = record.InSystemProcessInfo ? L"true" : L"false";
        event.Evidence[L"in_toolhelp"] = record.InToolhelp ? L"true" : L"false";
        event.Evidence[L"notes"] = record.Notes;
        event.Evidence[L"followup"] = L"!hiddenproc; !vad " + std::to_wstring(record.ProcessId);
        RecordEvent(std::move(event));
    }
}

void KernelMonitor::NoteDriverLoad(const KmonEvent& event)
{
    std::lock_guard<std::mutex> lock(WatchMutex);
    RecentDriverLoad load = {};
    load.Base = KmonBasenameLower(event.Driver);
    load.Path = event.Driver;
    auto it = event.Evidence.find(L"path_class");
    if (it != event.Evidence.end())
    {
        load.PathClass = it->second;
    }
    load.Timestamp = event.Timestamp;
    RecentLoads.push_back(std::move(load));
    while (RecentLoads.size() > 64)
    {
        RecentLoads.pop_front();
    }
}

void KernelMonitor::MaybeEmitShortLived(const KmonEvent& unloadEvent)
{
    constexpr uint64_t kWindow = 30ull * 10000000ull; // 30s FILETIME
    std::wstring base = KmonBasenameLower(unloadEvent.Driver);
    KmonEvent shortLived = {};
    bool emit = false;

    {
        std::lock_guard<std::mutex> lock(WatchMutex);
        for (auto it = RecentLoads.rbegin(); it != RecentLoads.rend(); ++it)
        {
            if (it->Base.empty() || it->Base != base)
            {
                continue;
            }
            if (unloadEvent.Timestamp < it->Timestamp)
            {
                continue;
            }
            uint64_t delta = unloadEvent.Timestamp - it->Timestamp;
            if (delta > kWindow)
            {
                break;
            }
            if (it->PathClass == L"inbox")
            {
                break;
            }
            shortLived.Timestamp = unloadEvent.Timestamp;
            shortLived.Kind = L"driver.short_lived";
            shortLived.Driver = unloadEvent.Driver.empty() ? it->Path : unloadEvent.Driver;
            shortLived.Task = unloadEvent.Task;
            shortLived.Summary = L"driver loaded and vanished within 30s " + it->Base;
            shortLived.Evidence[L"path_class"] = it->PathClass;
            shortLived.Evidence[L"load_ts"] = std::to_wstring(it->Timestamp);
            shortLived.Evidence[L"lifetime_100ns"] = std::to_wstring(delta);
            shortLived.Evidence[L"followup"] = L"!mapper; !kpage /pe; !pool pe /suspicious";
            emit = true;
            break;
        }
    }

    if (emit)
    {
        RecordEvent(std::move(shortLived));
    }
}

void KernelMonitor::ScanMapperRemnants()
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        device = Device;
        symbols = Symbols;
    }
    if (device == nullptr || symbols == nullptr || !device->IsOpen())
    {
        return;
    }

    MapperRemnantScanner scanner(*device, *symbols);
    MapperScanOptions options;
    options.Limit = 64;
    MapperScanResult result = {};
    std::wstring error;
    if (!scanner.Scan(options, &result, &error))
    {
        return;
    }
    MapperScans.fetch_add(1);

    FILETIME now = {};
    GetSystemTimeAsFileTime(&now);
    const uint64_t ts = (static_cast<uint64_t>(now.dwHighDateTime) << 32) | now.dwLowDateTime;

    auto emitResidue = [&](const std::wstring& key,
                           const std::wstring& name,
                           const std::wstring& layer,
                           const std::wstring& notes)
    {
        bool already = false;
        {
            std::lock_guard<std::mutex> lock(WatchMutex);
            already = EmittedMapperKeys.count(key) != 0;
            if (!already)
            {
                EmittedMapperKeys.insert(key);
            }
        }
        if (already)
        {
            return;
        }

        KmonEvent event = {};
        event.Timestamp = ts;
        event.Kind = L"driver.mapped_residue";
        event.Driver = name;
        event.Summary = L"mapper leftover " + layer + L" " + name;
        event.Evidence[L"layer"] = layer;
        event.Evidence[L"notes"] = notes;
        event.Evidence[L"followup"] = L"!mapper; !kpage /pe; !pool pe /suspicious";
        RecordEvent(std::move(event));
    };

    for (const MapperUnloadedRecord& record : result.Unloaded)
    {
        if (!record.Suspicious)
        {
            continue;
        }
        emitResidue(
            L"unloaded:" + ToLowerCopy(record.Name) + L":" + std::to_wstring(record.StartAddress),
            record.Name,
            L"MmUnloadedDrivers",
            record.Notes);
    }
    for (const MapperPiddbRecord& record : result.Piddb)
    {
        if (!record.Suspicious)
        {
            continue;
        }
        emitResidue(
            L"piddb:" + ToLowerCopy(record.DriverName) + L":" + std::to_wstring(record.TimeDateStamp),
            record.DriverName,
            L"PiDDBCache",
            record.Notes);
    }
    for (const MapperHashRecord& record : result.HashEntries)
    {
        if (!record.Suspicious)
        {
            continue;
        }
        emitResidue(
            L"hash:" + ToLowerCopy(record.DriverName) + L":" + record.Notes,
            record.DriverName,
            L"ci_hash",
            record.Notes);
    }
}

void KernelMonitor::EnableLoggingForPid(uint32_t pid)
{
    if (pid <= 4)
    {
        return;
    }

    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        if (LoggingEnabledPids.count(pid) != 0)
        {
            return;
        }
        LoggingEnabledPids.insert(pid);
    }

    bool enabled = TryEnableLoggingUsermode(pid, KNDBG_PROCESS_LOG_DEFAULT);
    if (!enabled)
    {
        DeviceClient* device = nullptr;
        {
            std::lock_guard<std::mutex> lock(StateMutex);
            device = Device;
        }
        if (device != nullptr && device->IsOpen())
        {
            uint32_t applied = 0;
            uint32_t infoClass = 0;
            uint32_t ntStatus = 0;
            uint64_t eprocess = 0;
            std::wstring error;
            enabled = device->SetProcessLogging(
                pid,
                KNDBG_PROCESS_LOG_DEFAULT,
                &applied,
                &infoClass,
                &ntStatus,
                &eprocess,
                &error);
        }
    }

    if (enabled)
    {
        LoggingEnabledCount.fetch_add(1);
    }
    else
    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        LoggingEnabledPids.erase(pid);
        LoggingFailedCount.fetch_add(1);
    }
}

void KernelMonitor::EnableLoggingForWatchTargets()
{
    std::vector<uint32_t> pids;
    std::vector<std::wstring> names;
    {
        std::lock_guard<std::mutex> watchLock(WatchMutex);
        pids.assign(WatchPids.begin(), WatchPids.end());
        names = WatchNamesLower;
    }

    std::vector<uint32_t> namedPids;
    CollectToolhelpPidsByName(names, &namedPids);
    pids.insert(pids.end(), namedPids.begin(), namedPids.end());

    for (uint32_t pid : pids)
    {
        EnableLoggingForPid(pid);
    }
}

bool KernelMonitor::ResolveKernelImageName(uint32_t pid, std::wstring* name)
{
    bool ok = false;

    do
    {
        if (name == nullptr)
        {
            break;
        }
        name->clear();

        DeviceClient* device = nullptr;
        SymbolEngine* symbols = nullptr;
        {
            std::lock_guard<std::mutex> lock(StateMutex);
            device = Device;
            symbols = Symbols;
        }
        if (device == nullptr || symbols == nullptr || !device->IsOpen())
        {
            break;
        }

        if (symbols->Modules().empty())
        {
            std::wstring ignored;
            if (!symbols->LoadKernelModules(&ignored))
            {
                break;
            }
        }

        TypeFieldInfo dtbField = {};
        TypeFieldInfo imageField = {};
        std::wstring ignored;
        if (!symbols->FindField(L"nt!_KPROCESS", L"DirectoryTableBase", &dtbField, &ignored) &&
            !symbols->FindField(L"nt!_EPROCESS", L"Pcb.DirectoryTableBase", &dtbField, &ignored) &&
            !symbols->FindField(L"nt!_EPROCESS", L"DirectoryTableBase", &dtbField, &ignored))
        {
            break;
        }
        if (!symbols->FindField(L"nt!_EPROCESS", L"ImageFileName", &imageField, &ignored))
        {
            break;
        }

        ProcessAddressContext ctx = {};
        if (!device->ResolveProcess(pid, dtbField.Offset, 0, &ctx, &ignored) || ctx.Eprocess == 0)
        {
            break;
        }

        uint64_t fieldAddr = ctx.Eprocess + static_cast<uint64_t>(imageField.Offset);
        uint32_t length = 16;
        if (imageField.Length != 0 && imageField.Length <= 16)
        {
            length = static_cast<uint32_t>(imageField.Length);
        }
        std::vector<uint8_t> bytes;
        if (!device->ReadMemory(fieldAddr, length, &bytes, &ignored) || bytes.empty())
        {
            break;
        }

        std::wstring decoded;
        for (uint8_t byte : bytes)
        {
            if (byte == 0)
            {
                break;
            }
            if (byte >= 0x20 && byte < 0x7f)
            {
                decoded.push_back(static_cast<wchar_t>(byte));
            }
        }
        *name = decoded;
        ok = !decoded.empty();
    } while (false);

    return ok;
}

void KernelMonitor::RecordEvent(KmonEvent&& event)
{
    KmonOptions options;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        options = Options;
        {
            std::lock_guard<std::mutex> watchLock(WatchMutex);
            options.WatchPids.assign(WatchPids.begin(), WatchPids.end());
            options.WatchNames = WatchNamesLower;
            options.WatchDrivers = WatchDriversLower;
        }
    }

    if (!KmonWatchMatches(event, options))
    {
        return;
    }

    EventsWatchMatched.fetch_add(1);
    LastEventTickMs.store(GetTickCount64());

    {
        std::lock_guard<std::mutex> ringLock(RingMutex);
        if (event.Sequence == 0)
        {
            event.Sequence = NextSequence++;
            if (NextSequence == 0)
            {
                NextSequence = 1;
            }
        }
        if (Ring.size() >= Options.RingCapacity)
        {
            Ring.pop_front();
            EventsDropped.fetch_add(1);
        }
        Ring.push_back(event);
        EventsKept.fetch_add(1);
    }

    WriteLogLine(event);

    if (LiveOutput.load())
    {
        EnqueuePrint(std::move(event));
    }
}

bool KernelMonitor::WriteLogLine(const KmonEvent& event)
{
    bool ok = false;

    do
    {
        std::string utf8 = WideToUtf8(FormatKmonJsonLine(event));
        std::lock_guard<std::mutex> logLock(LogMutex);
        if (!EnsureLogOpenLocked())
        {
            break;
        }
        if (LogCurrentBytes + utf8.size() >= LogRotateBytes)
        {
            RotateLogLocked();
            if (!EnsureLogOpenLocked())
            {
                break;
            }
        }

        DWORD written = 0;
        if (!WriteFile(
                LogHandle,
                utf8.data(),
                static_cast<DWORD>(utf8.size()),
                &written,
                nullptr))
        {
            break;
        }
        LogCurrentBytes += written;
        LogBytesWritten.fetch_add(written);
        EventsLogged.fetch_add(1);
        ok = true;
    } while (false);

    return ok;
}

void KernelMonitor::EnqueuePrint(KmonEvent&& event)
{
    const uint32_t throttle = Options.ThrottlePerSecond;
    const uint64_t nowMs = GetTickCount64();
    const uint64_t windowStart = ThrottleWindowStartMs.load();
    if (windowStart == 0 || (nowMs - windowStart) >= 1000)
    {
        ThrottleWindowStartMs.store(nowMs);
        ThrottleWindowCount.store(0);
    }
    uint32_t inWindow = ThrottleWindowCount.fetch_add(1) + 1;
    if (inWindow > throttle)
    {
        ThrottleSuppressed.fetch_add(1);
        return;
    }

    std::lock_guard<std::mutex> printLock(PrintMutex);
    while (PrintQueue.size() >= kPrintQueueCap)
    {
        PrintQueue.pop_front();
        ThrottleSuppressed.fetch_add(1);
    }
    PrintQueue.push_back(std::move(event));
}

std::vector<KmonEvent> KernelMonitor::DrainPrintQueue(size_t maxCount)
{
    std::vector<KmonEvent> out;
    std::lock_guard<std::mutex> printLock(PrintMutex);
    while (!PrintQueue.empty() && (maxCount == 0 || out.size() < maxCount))
    {
        out.push_back(std::move(PrintQueue.front()));
        PrintQueue.pop_front();
    }
    return out;
}

uint64_t KernelMonitor::ConsumeThrottleSuppressedCount()
{
    return ThrottleSuppressed.exchange(0);
}

std::vector<KmonEvent> KernelMonitor::Recent(size_t maxCount, bool newestFirst) const
{
    std::vector<KmonEvent> out;
    std::lock_guard<std::mutex> lock(RingMutex);
    if (Ring.empty())
    {
        return out;
    }
    size_t total = (maxCount == 0 || maxCount > Ring.size()) ? Ring.size() : maxCount;
    if (newestFirst)
    {
        out.reserve(total);
        for (size_t i = 0; i < total; ++i)
        {
            out.push_back(Ring[Ring.size() - 1 - i]);
        }
    }
    else
    {
        size_t start = Ring.size() - total;
        out.reserve(total);
        for (size_t i = start; i < Ring.size(); ++i)
        {
            out.push_back(Ring[i]);
        }
    }
    return out;
}

bool KernelMonitor::SaveTo(const std::wstring& path, std::wstring* error) const
{
    bool ok = false;

    do
    {
        HANDLE handle = CreateFileW(
            path.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (handle == INVALID_HANDLE_VALUE)
        {
            if (error != nullptr)
            {
                *error = L"could not open output file";
            }
            break;
        }

        std::vector<KmonEvent> snapshot;
        {
            std::lock_guard<std::mutex> lock(RingMutex);
            snapshot.assign(Ring.begin(), Ring.end());
        }

        bool writeOk = true;
        for (const KmonEvent& event : snapshot)
        {
            std::string utf8 = WideToUtf8(FormatKmonJsonLine(event));
            DWORD written = 0;
            if (!WriteFile(handle, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr))
            {
                writeOk = false;
                break;
            }
        }
        CloseHandle(handle);
        if (!writeOk)
        {
            if (error != nullptr)
            {
                *error = L"write failed";
            }
            break;
        }
        ok = true;
    } while (false);

    return ok;
}

void KernelMonitor::Clear()
{
    {
        std::lock_guard<std::mutex> lock(RingMutex);
        Ring.clear();
    }
    {
        std::lock_guard<std::mutex> printLock(PrintMutex);
        PrintQueue.clear();
    }
}

bool KernelMonitor::AddWatchPid(uint32_t pid)
{
    bool inserted = false;

    do
    {
        if (pid == 0)
        {
            break;
        }
        {
            std::lock_guard<std::mutex> lock(WatchMutex);
            inserted = WatchPids.insert(pid).second;
        }
        if (inserted)
        {
            EnableLoggingForPid(pid);
        }
    } while (false);

    return inserted;
}

bool KernelMonitor::RemoveWatchPid(uint32_t pid)
{
    std::lock_guard<std::mutex> lock(WatchMutex);
    return WatchPids.erase(pid) != 0;
}

bool KernelMonitor::AddWatchName(const std::wstring& imageBase)
{
    bool added = false;
    std::vector<uint32_t> pids;

    do
    {
        std::wstring lower = KmonBasenameLower(imageBase);
        if (lower.empty())
        {
            break;
        }
        {
            std::lock_guard<std::mutex> lock(WatchMutex);
            bool exists = false;
            for (const std::wstring& existing : WatchNamesLower)
            {
                if (existing == lower)
                {
                    exists = true;
                    break;
                }
            }
            if (exists)
            {
                break;
            }
            WatchNamesLower.push_back(lower);
            added = true;
        }
        CollectToolhelpPidsByName({ lower }, &pids);
        for (uint32_t pid : pids)
        {
            {
                std::lock_guard<std::mutex> lock(WatchMutex);
                WatchPids.insert(pid);
            }
            EnableLoggingForPid(pid);
        }
    } while (false);

    return added;
}

bool KernelMonitor::RemoveWatchName(const std::wstring& imageBase)
{
    std::wstring lower = KmonBasenameLower(imageBase);
    std::lock_guard<std::mutex> lock(WatchMutex);
    auto it = std::remove(WatchNamesLower.begin(), WatchNamesLower.end(), lower);
    if (it == WatchNamesLower.end())
    {
        return false;
    }
    WatchNamesLower.erase(it, WatchNamesLower.end());
    return true;
}

bool KernelMonitor::AddWatchDriver(const std::wstring& driverBase)
{
    std::wstring lower = KmonBasenameLower(driverBase);
    if (lower.empty())
    {
        return false;
    }
    std::lock_guard<std::mutex> lock(WatchMutex);
    for (const std::wstring& existing : WatchDriversLower)
    {
        if (existing == lower)
        {
            return false;
        }
    }
    WatchDriversLower.push_back(lower);
    return true;
}

bool KernelMonitor::RemoveWatchDriver(const std::wstring& driverBase)
{
    std::wstring lower = KmonBasenameLower(driverBase);
    std::lock_guard<std::mutex> lock(WatchMutex);
    auto it = std::remove(WatchDriversLower.begin(), WatchDriversLower.end(), lower);
    if (it == WatchDriversLower.end())
    {
        return false;
    }
    WatchDriversLower.erase(it, WatchDriversLower.end());
    return true;
}

bool KernelMonitor::EnsureLogOpenLocked()
{
    bool ok = false;

    do
    {
        if (LogHandle != INVALID_HANDLE_VALUE)
        {
            ok = true;
            break;
        }

        CreateDirectoryW(Options.LogDirectory.c_str(), nullptr);
        LogActivePath = BuildLogFilePath(LogActiveRotation);
        LogHandle = CreateFileW(
            LogActivePath.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (LogHandle == INVALID_HANDLE_VALUE)
        {
            break;
        }
        LARGE_INTEGER size = {};
        if (GetFileSizeEx(LogHandle, &size))
        {
            LogCurrentBytes = static_cast<uint64_t>(size.QuadPart);
            SetFilePointer(LogHandle, 0, nullptr, FILE_END);
        }
        ok = true;
    } while (false);

    return ok;
}

void KernelMonitor::CloseLogLocked()
{
    if (LogHandle != INVALID_HANDLE_VALUE)
    {
        CloseHandle(LogHandle);
        LogHandle = INVALID_HANDLE_VALUE;
    }
}

void KernelMonitor::RotateLogLocked()
{
    CloseLogLocked();
    LogActiveRotation = (LogActiveRotation + 1) % static_cast<int>(LogRotateCount);
    LogCurrentBytes = 0;
    std::wstring next = BuildLogFilePath(LogActiveRotation);
    DeleteFileW(next.c_str());
    LogRotations.fetch_add(1);
}

std::wstring KernelMonitor::BuildLogFilePath(int rotationIndex) const
{
    return Options.LogDirectory + L"\\kmon-events." +
        std::to_wstring(GetCurrentProcessId()) + L"." +
        std::to_wstring(rotationIndex) + L".jsonl";
}

bool KernelMonitorSelfTest()
{
    bool ok = false;

    do
    {
        if (KmonBasenameLower(L"C:\\Windows\\cheat.SYS") != L"cheat.sys")
        {
            break;
        }
        if (!KmonPathLooksLikeSys(L"\\SystemRoot\\cheat.sys"))
        {
            break;
        }
        if (!KmonTaskLooksLikeDriverObjectLoad(L"KERNEL_THREATINT_TASK_DRIVEROBJECTLOAD"))
        {
            break;
        }
        if (!KmonTaskLooksLikeRemoteInject(L"WriteVM"))
        {
            break;
        }

        TiEventRecord driver = {};
        driver.ProcessId = 4;
        driver.TaskName = L"DriverObjectLoad";
        driver.ImagePath = L"System";
        TiPayloadField field = {};
        field.Name = L"DriverName";
        field.Value = L"\\??\\C:\\cheat.sys";
        driver.Payload.push_back(field);
        KmonEvent classified = {};
        if (!KmonClassifyTiEvent(driver, &classified) ||
            classified.Kind != L"driver.drop_load" ||
            KmonBasenameLower(classified.Driver) != L"cheat.sys" ||
            classified.Evidence[L"path_class"] != L"drop")
        {
            break;
        }

        if (KmonClassifyDriverPath(L"C:\\Windows\\System32\\drivers\\acpi.sys") != L"inbox" ||
            KmonClassifyDriverPath(L"C:\\Users\\a\\AppData\\Local\\Temp\\x.sys") != L"drop" ||
            KmonClassifyDriverPath(L"C:\\Windows\\cheat.sys") != L"drop" ||
            KmonClassifyDriverPath(L"C:\\Windows\\System32\\win32k.sys") != L"inbox" ||
            KmonClassifyDriverPath(L"C:\\Windows\\Temp\\x.sys") != L"drop")
        {
            break;
        }

        TiEventRecord unnamedLoad = {};
        unnamedLoad.ProcessId = 4;
        unnamedLoad.TaskName = L"DriverObjectLoad";
        unnamedLoad.ImagePath = L"System";
        if (!KmonClassifyTiEvent(unnamedLoad, &classified) ||
            classified.Kind != L"driver.official_load")
        {
            break;
        }
        KmonOptions emptyWatchForUnnamed;
        if (KmonWatchMatches(classified, emptyWatchForUnnamed))
        {
            break;
        }

        TiEventRecord inject = {};
        inject.ProcessId = 1000;
        inject.TargetProcessId = 2000;
        inject.TaskName = L"WriteVM";
        inject.ImagePath = L"C:\\cheat.exe";
        inject.TargetImageBase = L"game.exe";
        if (!KmonClassifyTiEvent(inject, &classified) || classified.Kind != L"inject.remote")
        {
            break;
        }

        TiEventRecord localAlloc = {};
        localAlloc.ProcessId = 1000;
        localAlloc.TargetProcessId = 1000;
        localAlloc.TaskName = L"AllocVM";
        if (KmonClassifyTiEvent(localAlloc, &classified))
        {
            break;
        }

        TimelineEvent liveInbox = {};
        liveInbox.Action = L"image-load";
        liveInbox.ProcessId = 0;
        liveInbox.Entity = L"\\SystemRoot\\System32\\drivers\\mapped.sys";
        liveInbox.Source = L"kernel-live";
        if (!KmonClassifyLiveEvent(liveInbox, &classified) || classified.Kind != L"driver.image_only")
        {
            break;
        }

        TimelineEvent liveDrop = {};
        liveDrop.Action = L"image-load";
        liveDrop.ProcessId = 0;
        liveDrop.Entity = L"\\??\\C:\\Users\\a\\AppData\\Local\\Temp\\mapped.sys";
        liveDrop.Source = L"kernel-live";
        if (!KmonClassifyLiveEvent(liveDrop, &classified) || classified.Kind != L"driver.drop_load")
        {
            break;
        }

        KmonOptions emptyWatch;
        KmonEvent injectEvent = classified;
        injectEvent.Kind = L"inject.remote";
        injectEvent.ProcessId = 1000;
        injectEvent.TargetProcessId = 2000;
        injectEvent.Image = L"cheat.exe";
        injectEvent.TargetImage = L"game.exe";
        if (KmonWatchMatches(injectEvent, emptyWatch))
        {
            break;
        }

        KmonOptions gameWatch;
        gameWatch.WatchNames.push_back(L"game.exe");
        if (!KmonWatchMatches(injectEvent, gameWatch))
        {
            break;
        }

        KmonEvent dropEvent = {};
        dropEvent.Kind = L"driver.drop_load";
        dropEvent.Driver = L"unknown-drop.sys";
        dropEvent.Evidence[L"path_class"] = L"drop";
        if (!KmonWatchMatches(dropEvent, emptyWatch))
        {
            break;
        }
        KmonOptions driverWatch;
        driverWatch.WatchDrivers.push_back(L"other.sys");
        // /driver must not hide an unknown drop name.
        if (!KmonWatchMatches(dropEvent, driverWatch))
        {
            break;
        }

        KmonEvent inboxEvent = {};
        inboxEvent.Kind = L"driver.official_load";
        inboxEvent.Driver = L"C:\\Windows\\System32\\drivers\\acpi.sys";
        inboxEvent.Evidence[L"path_class"] = L"inbox";
        if (KmonWatchMatches(inboxEvent, emptyWatch))
        {
            break;
        }
        KmonOptions verboseWatch;
        verboseWatch.VerboseDrivers = true;
        if (!KmonWatchMatches(inboxEvent, verboseWatch))
        {
            break;
        }
        driverWatch.WatchDrivers = { L"acpi.sys" };
        if (!KmonWatchMatches(inboxEvent, driverWatch))
        {
            break;
        }

        KmonEvent emptyDevice = {};
        emptyDevice.Kind = L"driver.device";
        if (KmonWatchMatches(emptyDevice, emptyWatch))
        {
            break;
        }

        KmonOptions starDriver;
        starDriver.WatchDrivers.push_back(L"*");
        if (KmonWatchMatches(emptyDevice, starDriver))
        {
            break;
        }

        if (KmonClassifyDriverPath(L"acpi.sys") != L"unknown" ||
            KmonClassifyDriverPath(L"\\Driver\\ACPI") != L"unknown" ||
            KmonClassifyDriverPath(L"D:\\cheats\\a.sys") != L"unknown" ||
            KmonClassifyDriverPath(L"C:\\cheat.sys") != L"drop")
        {
            break;
        }
        if (KmonDriverPathHasFileDirectory(L"acpi.sys") ||
            KmonDriverPathHasFileDirectory(L"\\Driver\\ACPI") ||
            !KmonDriverPathHasFileDirectory(L"D:\\cheats\\a.sys"))
        {
            break;
        }

        TiEventRecord bareInbox = {};
        bareInbox.ProcessId = 4;
        bareInbox.TaskName = L"DriverObjectLoad";
        TiPayloadField bareField = {};
        bareField.Name = L"DriverName";
        bareField.Value = L"acpi.sys";
        bareInbox.Payload.push_back(bareField);
        if (!KmonClassifyTiEvent(bareInbox, &classified) ||
            classified.Kind != L"driver.official_load" ||
            KmonWatchMatches(classified, emptyWatch))
        {
            break;
        }

        TiEventRecord otherVolume = {};
        otherVolume.ProcessId = 4;
        otherVolume.TaskName = L"DriverObjectLoad";
        TiPayloadField otherField = {};
        otherField.Name = L"DriverName";
        otherField.Value = L"D:\\cheats\\a.sys";
        otherVolume.Payload.push_back(otherField);
        if (!KmonClassifyTiEvent(otherVolume, &classified) ||
            classified.Kind != L"driver.drop_load" ||
            !KmonWatchMatches(classified, emptyWatch))
        {
            break;
        }

        KmonOptions pathWatch;
        pathWatch.WatchNames.push_back(KmonBasenameLower(L"C:\\games\\game.exe"));
        if (!KmonWatchMatches(injectEvent, pathWatch))
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}
