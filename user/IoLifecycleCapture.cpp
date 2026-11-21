#include "IoLifecycleCapture.h"
#include "CommandInput.h"
#include "SymbolArtifactCache.h"

#include <Windows.h>
#include <objbase.h>
#include <algorithm>
#include <array>
#include <iostream>
#include <optional>

namespace
{
    constexpr size_t Limit = 8;
    constexpr DWORD BufferSize = 4096;
    constexpr DWORD Filter = FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_DIR_NAME;

    std::string Hex(const void* data, size_t bytes)
    {
        const auto* p = static_cast<const BYTE*>(data);
        constexpr char digits[] = "0123456789abcdef";
        std::string out;
        out.reserve(bytes * 2);
        for (size_t i = 0; i < bytes; ++i) { out += digits[p[i] >> 4]; out += digits[p[i] & 15]; }
        return out;
    }

    void Number(std::optional<DWORD> value)
    {
        if (value) { std::cout << *value; }
        else { std::cout << "null"; }
    }

    class Journal
    {
        std::string run;
        unsigned seq = 0;
    public:
        explicit Journal(const GUID& id) : run(Hex(&id, sizeof(id))) {}
        void Begin(const char* kind, unsigned generation, ULONGLONG tick = GetTickCount64())
        {
            std::cout << "{\"schema\":\"kn.io_lifetime.v1\",\"run\":\"" << run << "\",\"seq\":" << seq++
                      << ",\"tick\":" << tick << ",\"kind\":\"" << kind << "\",\"generation\":" << generation;
        }
        void End() { std::cout << "}\n" << std::flush; }
    };

    struct NativeRequest
    {
        OVERLAPPED operation{};
        alignas(DWORD) std::array<BYTE, BufferSize> buffer{};
    };

    struct Request
    {
        HANDLE directory = INVALID_HANDLE_VALUE;
        HANDLE event = nullptr;
        std::unique_ptr<NativeRequest> native = std::make_unique<NativeRequest>();
        FILE_ID_INFO identity{};
        unsigned generation = 0;
        bool outstanding = false;

        Request() = default;
        Request(const Request&) = delete;
        Request& operator=(const Request&) = delete;
        void DeferToProcessExit() noexcept
        {
            // Private event failure leaves kernel ownership unknown. This one-shot process retains
            // at most eight buffers and handle pairs until Windows tears it down.
            (void)native.release();
            directory = INVALID_HANDLE_VALUE;
            event = nullptr;
            outstanding = false;
        }
        ~Request()
        {
            // An exception or output failure must not free storage for an in-flight request.
            if (outstanding)
            {
                CancelIoEx(directory, &native->operation);
                if (WaitForSingleObject(event, INFINITE) != WAIT_OBJECT_0) { DeferToProcessExit(); }
            }
            if (event) { CloseHandle(event); }
            if (directory != INVALID_HANDLE_VALUE) { CloseHandle(directory); }
        }
    };

    struct Admission
    {
        const char* stage;
        std::optional<DWORD> error;
    };

    Admission Open(const std::wstring& name, Request& r)
    {
        std::filesystem::path path;
        if (!symbol_artifacts::LocalRoot(name, &path)) { return {"path_policy", {}}; }
        // Hold the non-reparse ancestors through the open. Subsequent I/O uses only the retained handle.
        symbol_artifacts::Directories ancestors;
        if (!ancestors.Pin(path.parent_path(), false)) { return {"parent_unavailable", {}}; }
        r.directory = CreateFileW(path.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OVERLAPPED, nullptr);
        if (r.directory == INVALID_HANDLE_VALUE) { return {"open", GetLastError()}; }
        FILE_ATTRIBUTE_TAG_INFO info{};
        if (!GetFileInformationByHandleEx(r.directory, FileAttributeTagInfo, &info, sizeof(info)))
            { return {"attributes", GetLastError()}; }
        if (GetFileType(r.directory) != FILE_TYPE_DISK || !(info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ||
            (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) { return {"directory_policy", {}}; }
        std::wstring final(32768, L'\0');
        const DWORD n = GetFinalPathNameByHandleW(r.directory, final.data(), static_cast<DWORD>(final.size()),
            FILE_NAME_OPENED | VOLUME_NAME_GUID);
        if (!n) { return {"volume", GetLastError()}; }
        if (n >= final.size()) { return {"volume_policy", {}}; }
        final.resize(n);
        const auto end = final.find(L"}\\");
        if (final.rfind(L"\\\\?\\Volume{", 0) != 0 || end == std::wstring::npos ||
            GetDriveTypeW(final.substr(0, end + 2).c_str()) != DRIVE_FIXED) { return {"volume_policy", {}}; }
        if (!GetFileInformationByHandleEx(r.directory, FileIdInfo, &r.identity, sizeof(r.identity)))
            { return {"file_id", GetLastError()}; }
        r.event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!r.event) { return {"create_event", GetLastError()}; }
        r.native->operation.hEvent = r.event;
        return {"ready", {}};
    }

    void Release(Request& r, Journal& j)
    {
        std::optional<DWORD> quiesce, quiesceError, dirError, eventError;
        if (r.outstanding)
        {
            quiesce = WaitForSingleObject(r.event, INFINITE);
            if (*quiesce == WAIT_FAILED) { quiesceError = GetLastError(); }
        }
        const bool close = !quiesce || *quiesce == WAIT_OBJECT_0;
        if (close)
        {
            r.outstanding = false;
            if (CloseHandle(r.directory)) { r.directory = INVALID_HANDLE_VALUE; }
            else { dirError = GetLastError(); }
            if (CloseHandle(r.event)) { r.event = nullptr; }
            else { eventError = GetLastError(); }
        }
        else { r.DeferToProcessExit(); }
        j.Begin("release", r.generation);
        std::cout << ",\"quiesce_result\":";
        Number(quiesce);
        std::cout << ",\"quiesce_error\":";
        Number(quiesceError);
        std::cout << ",\"close_attempted\":" << (close ? "true" : "false") << ",\"directory_error\":";
        Number(dirError);
        std::cout << ",\"event_error\":";
        Number(eventError);
        j.End();
    }

    void GetResult(Request& r, Journal& j, bool final)
    {
        const auto start = GetTickCount64();
        DWORD bytes = 0;
        const BOOL ok = GetOverlappedResult(r.directory, &r.native->operation, &bytes, final ? TRUE : FALSE);
        const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        const DWORD signal = WaitForSingleObject(r.event, 0);
        const DWORD signalError = signal == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
        j.Begin(final ? "result" : "probe", r.generation);
        std::cout << ",\"start\":" << start << ",\"ok\":" << (ok ? "true" : "false") << ",\"error\":";
        Number(ok ? std::optional<DWORD>{} : error);
        std::cout << ",\"bytes\":";
        Number(ok ? std::optional<DWORD>(bytes) : std::nullopt);
        std::cout << ",\"event_result\":" << signal << ",\"event_error\":";
        Number(signal == WAIT_FAILED ? std::optional<DWORD>(signalError) : std::nullopt);
        j.End();
        if (final)
        {
            Release(r, j);
        }
    }

    void Submit(Request& r, const std::wstring& path, Journal& j)
    {
        const auto admitted = Open(path, r);
        const bool ready = r.event != nullptr;
        std::optional<DWORD> closeError;
        if (!ready && r.directory != INVALID_HANDLE_VALUE)
        {
            if (CloseHandle(r.directory)) { r.directory = INVALID_HANDLE_VALUE; }
            else { closeError = GetLastError(); }
        }
        j.Begin("admit", r.generation);
        std::cout << ",\"stage\":\"" << admitted.stage << "\",\"error\":";
        Number(admitted.error);
        std::cout << ",\"rejected_close_error\":";
        Number(closeError);
        std::cout << ",\"volume\":";
        if (ready) { std::cout << '"' << r.identity.VolumeSerialNumber << '"'; } else { std::cout << "null"; }
        std::cout << ",\"file_id\":";
        if (ready) { std::cout << '"' << Hex(r.identity.FileId.Identifier, sizeof(r.identity.FileId.Identifier)) << '"'; }
        else { std::cout << "null"; }
        j.End();
        if (!ready) { return; }

        j.Begin("issue", r.generation);
        j.End();
        const auto start = GetTickCount64();
        const BOOL ok = ReadDirectoryChangesW(r.directory, r.native->buffer.data(), BufferSize, FALSE, Filter,
            nullptr, &r.native->operation, nullptr);
        const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        r.outstanding = ok != FALSE;
        j.Begin("submit", r.generation);
        std::cout << ",\"start\":" << start << ",\"ok\":" << (ok ? "true" : "false") << ",\"error\":";
        Number(ok ? std::optional<DWORD>{} : error);
        j.End();
        if (ok) { GetResult(r, j, false); }
        else { Release(r, j); }
    }

    void Monitor(std::array<Request, Limit>& requests, DWORD budget, Journal& j)
    {
        const auto epoch = GetTickCount64();
        j.Begin("monitor", 0, epoch);
        j.End();
        while (std::cout)
        {
            std::array<HANDLE, Limit> events{};
            std::array<Request*, Limit> active{};
            DWORD count = 0;
            for (auto& r : requests)
            {
                if (r.outstanding) { events[count] = r.event; active[count++] = &r; }
            }
            if (!count) { break; }
            const auto start = GetTickCount64();
            const auto elapsed = start - epoch;
            const DWORD timeout = elapsed >= budget ? 0 : budget - static_cast<DWORD>(elapsed);
            const DWORD status = WaitForMultipleObjects(count, events.data(), FALSE, timeout);
            const DWORD error = status == WAIT_FAILED ? GetLastError() : ERROR_SUCCESS;
            j.Begin("wait", 0);
            std::cout << ",\"start\":" << start << ",\"timeout_ms\":" << timeout << ",\"generations\":[";
            for (DWORD i = 0; i < count; ++i) { if (i) { std::cout << ','; } std::cout << active[i]->generation; }
            std::cout << "],\"result\":" << status << ",\"error\":";
            Number(status == WAIT_FAILED ? std::optional<DWORD>(error) : std::nullopt);
            j.End();
            if (status >= WAIT_OBJECT_0 + count) { break; }
            GetResult(*active[status - WAIT_OBJECT_0], j, true);
        }
        // Request cancellation for every still-outstanding operation before waiting for any one result.
        for (auto& r : requests)
        {
            if (!r.outstanding) { continue; }
            const auto start = GetTickCount64();
            const BOOL ok = CancelIoEx(r.directory, &r.native->operation);
            const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
            j.Begin("cancel", r.generation);
            std::cout << ",\"start\":" << start << ",\"ok\":" << (ok ? "true" : "false") << ",\"error\":";
            Number(ok ? std::optional<DWORD>{} : error);
            j.End();
        }
        for (auto& r : requests) { if (r.outstanding) { GetResult(r, j, true); } }
    }

    ULONGLONG Birth(const FILETIME& time)
    {
        return (static_cast<ULONGLONG>(time.dwHighDateTime) << 32) | time.dwLowDateTime;
    }
}

int RunIoLifecycleCapture(const std::vector<std::wstring>& args)
{
    uint64_t budget = 0;
    if (args.size() < 2 || args.size() > Limit + 1 || !commandinput::ParseDigits(args[0], 10, &budget) ||
        !budget || budget > 30000)
    {
        std::cerr << "usage: --io-lifecycle <wait-ms 1..30000> <local-directory> [up to 8 directories]\n";
        return 2;
    }
    GUID run{};
    FILETIME process{}, thread{}, end{}, kernel{}, user{};
    if (FAILED(CoCreateGuid(&run)) || !GetProcessTimes(GetCurrentProcess(), &process, &end, &kernel, &user) ||
        !GetThreadTimes(GetCurrentThread(), &thread, &end, &kernel, &user) || !Birth(process) || !Birth(thread))
    { std::cerr << "I/O lifecycle collector identity unavailable\n"; return 1; }
    Journal j(run);
    j.Begin("plan", 0);
    std::cout << ",\"source\":\"win32_directory_changes\",\"clock\":\"GetTickCount64_ms\",\"pid\":" << GetCurrentProcessId()
              << ",\"process_created\":\"" << Birth(process) << "\",\"tid\":" << GetCurrentThreadId()
              << ",\"thread_created\":\"" << Birth(thread) << "\",\"requests\":" << args.size() - 1
              << ",\"wait_ms\":" << budget << ",\"buffer_bytes\":" << BufferSize << ",\"notify_filter\":" << Filter
              << ",\"subtree\":false";
    j.End();
    std::array<Request, Limit> requests;
    for (size_t i = 1; i < args.size() && std::cout; ++i)
    {
        requests[i - 1].generation = static_cast<unsigned>(i);
        Submit(requests[i - 1], args[i], j);
    }
    Monitor(requests, static_cast<DWORD>(budget), j);
    j.Begin("end", 0);
    j.End();
    return std::cout ? 0 : 1;
}
