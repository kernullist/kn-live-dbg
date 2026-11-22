#include "OperationRecords.h"
#include "../../user/ContentHash.h"
#include "../../user/EtlCaptureSettings.h"
#include <evntrace.h>
#include <iostream>
#include <string_view>
#pragma comment(lib, "advapi32.lib")

namespace
{
    using etl_profile::OperationRecord;
    struct Selection
    {
        std::vector<uint32_t> numbers;
        std::vector<OperationRecord> rows;
        size_t next = 0;
        uint32_t records = 0, buffers = 0, losses = 0, faults = 0, unsupportedFaults = 0;
        bool exceeded = false, includeFaults = false;
    };

    bool Parse(std::wstring_view list, Selection& s)
    {
        if (list.empty() || list.size() > 8 * etl_profile::MaxPageRows) { return false; }
        while (!list.empty())
        {
            const auto comma = list.find(L',');
            const auto number = list.substr(0, comma);
            if (s.numbers.size() == etl_profile::MaxPageRows || number.empty() || number.size() > 7 || number.front() == L'0') { return false; }
            uint32_t n = 0;
            for (auto c : number) { if (c < L'0' || c > L'9') { return false; } n = n*10 + static_cast<uint32_t>(c-L'0'); }
            if (n > etl_profile::MaxEventRecords || (!s.numbers.empty() && n <= s.numbers.back())) { return false; }
            s.numbers.push_back(n);
            if (comma == list.npos) { break; }
            list.remove_prefix(comma+1);
            if (list.empty()) { return false; }
        }
        s.rows.resize(s.numbers.size());
        return true;
    }

    void WINAPI Observe(PEVENT_RECORD e)
    {
        auto& s = *static_cast<Selection*>(e->UserContext);
        if (s.records == etl_profile::MaxEventRecords) { s.exceeded = true; return; }
        ++s.records;
        if (etl_profile::LossMarker(e->EventHeader)) { ++s.losses; }
        if (s.includeFaults)
        {
            const auto match = etl_profile::DecodeHardFault(*e, nullptr);
            if (match == etl_profile::Match::Decoded) { ++s.faults; }
            if (match == etl_profile::Match::Unsupported) { ++s.unsupportedFaults; }
        }
        if (s.next < s.numbers.size() && s.records == s.numbers[s.next]) { s.rows[s.next++].Read(e, s.records, s.includeFaults); }
    }

    ULONG WINAPI Buffer(PEVENT_TRACE_LOGFILEW log)
    {
        auto& s = *static_cast<Selection*>(log->Context);
        ++s.buffers;
        return !s.exceeded;
    }

    std::wstring Label(const Selection& s, size_t i, uint64_t OperationRecord::* field)
    {
        const auto& r = s.rows[i];
        if (r.*field)
        {
            for (size_t j = 0; j <= i; ++j)
            {
                const auto& p = s.rows[j];
                if (std::wcscmp(p.status, L"decoded") == 0 && p.logger == r.logger && p.width == r.width && p.*field == r.*field)
                { return std::to_wstring(p.number); }
            }
        }
        return L"null";
    }

    std::wstring Decimal(uint64_t n) { return L"\"" + std::to_wstring(n) + L"\""; }

    void WriteRows(const Selection& s)
    {
        for (size_t i = 0; i < s.rows.size(); ++i)
        {
            const auto& r = s.rows[i];
            if (i) { std::wcout << L','; }
            std::wcout << L"{\"record_ordinal\":" << s.numbers[i] << L",\"status\":\"" << r.status << L'"';
            if (r.fault && std::wcscmp(r.status, L"decoded") == 0)
            {
                std::wcout << L",\"layer\":\"hard_fault\",\"opcode\":32,\"version\":2,\"pointer_bytes\":" << unsigned(r.width)
                    << L",\"logger_id\":" << r.logger << L",\"raw_timestamp\":\"" << r.timestamp << L"\",\"file_object_label\":"
                    << Label(s, i, &OperationRecord::object) << L",\"faulting_tid\":" << r.tid << L",\"initial_qpc\":\"" << r.initial
                    << L"\",\"read_offset\":" << Decimal(r.offset) << L",\"byte_count\":" << r.requested;
            }
            else if (std::wcscmp(r.status, L"decoded") == 0)
            {
                const bool end = r.file && r.opcode == 76, transfer = r.file && (r.opcode == 67 || r.opcode == 68);
                std::wcout << L",\"layer\":\"" << (r.file ? L"file" : L"disk") << L"\",\"opcode\":" << unsigned(r.opcode)
                    << L",\"version\":3,\"pointer_bytes\":" << unsigned(r.width) << L",\"logger_id\":" << r.logger
                    << L",\"raw_timestamp\":\"" << r.timestamp << L"\",\"packet_label\":" << Label(s, i, &OperationRecord::packet)
                    << L",\"file_object_label\":" << Label(s, i, &OperationRecord::object)
                    << L",\"issuing_tid\":" << (end ? L"null" : std::to_wstring(r.tid))
                    << L",\"file_offset\":" << (transfer ? Decimal(r.offset) : L"null")
                    << L",\"requested_bytes\":" << (transfer ? Decimal(r.requested) : L"null")
                    << L",\"io_flags\":" << (transfer ? std::to_wstring(r.flags) : L"null")
                    << L",\"ntstatus\":" << (end ? std::to_wstring(r.ntstatus) : L"null")
                    << L",\"extra_info\":" << (end ? Decimal(r.extra) : L"null");
                if (s.includeFaults && !r.file && (r.opcode == 10 || r.opcode == 11))
                { std::wcout << L",\"transfer_bytes\":" << r.requested; }
            }
            std::wcout << L'}';
        }
    }

    int Run(int argc, wchar_t** argv)
    {
        Selection s;
        s.includeFaults = argc == 5 && std::wstring_view(argv[4]) == L"--include-hard-faults";
        if (argc != 4 && !s.includeFaults) { return 2; }
        if (!(s.includeFaults && std::wstring_view(argv[3]) == L"-") && !Parse(argv[3], s)) { return 2; }
        const std::wstring pin = argv[2];
        if (pin.size() != 64 || pin.find_first_not_of(L"0123456789abcdef") != std::wstring::npos) { return 2; }
        const HANDLE raw = CreateFileW(argv[1], GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (raw == INVALID_HANDLE_VALUE) { return 1; }
        const std::unique_ptr<void, decltype(&CloseHandle)> held(raw, &CloseHandle);
        FILE_ATTRIBUTE_TAG_INFO tag{};
        LARGE_INTEGER bytes{};
        if (GetFileType(raw) != FILE_TYPE_DISK || !GetFileInformationByHandleEx(raw, FileAttributeTagInfo, &tag, sizeof(tag)) ||
            (tag.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) || !GetFileSizeEx(raw, &bytes) ||
            bytes.QuadPart <= 0 || static_cast<uint64_t>(bytes.QuadPart) > etl_profile::MaxFileBytes) { return 1; }
        std::wstring path(32768, L'\0');
        const auto length = GetFinalPathNameByHandleW(raw, path.data(), static_cast<DWORD>(path.size()), VOLUME_NAME_GUID);
        if (!length || length >= path.size()) { return 1; }
        path.resize(length);
        ContentHash hash;
        std::vector<uint8_t> block(65536);
        DWORD used;
        do
        {
            if (!ReadFile(raw, block.data(), static_cast<DWORD>(block.size()), &used, nullptr) ||
                (used && !hash.Add(block.data(), used))) { return 1; }
        } while (used);
        if (hash.Finish() != pin) { return 1; }
        EVENT_TRACE_LOGFILEW log{};
        log.LogFileName = path.data();
        log.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
        log.EventRecordCallback = Observe;
        log.BufferCallback = Buffer;
        log.Context = &s;
        auto trace = OpenTraceW(&log);
        if (trace == INVALID_PROCESSTRACE_HANDLE) { return 1; }
        const auto rc = ProcessTrace(&trace, 1, nullptr, nullptr);
        CloseTrace(trace);
        if (rc != ERROR_SUCCESS || s.exceeded) { return 1; }
        const auto& h = log.LogfileHeader;
        const auto coverage = etl_profile::AccountBuffers(h.LogFileMode, h.BuffersWritten, s.buffers);
        const bool complete = coverage == etl_profile::BufferAccounting::Matched && !s.losses && !s.unsupportedFaults && !h.EventsLost && !h.BuffersLost &&
            h.ReservedFlags == 1 && h.PerfFreq.QuadPart > 0 && std::all_of(s.rows.begin(), s.rows.end(),
                [](const auto& r) { return std::wcscmp(r.status, L"decoded") == 0; });
        std::wcout << L"{\"schema\":\"" << (s.includeFaults ? L"kn.etl_fault_file_records.v1" : L"kn.etl_operation_records.v1")
            << L"\",\"status\":\"" << (complete ? L"read" : L"partial")
            << L"\",\"source_sha256\":\"" << pin << L"\",\"source_bytes\":" << bytes.QuadPart
            << (s.includeFaults ? L",\"fault_provider_guid\":\"3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c\"" : L"")
            << (s.includeFaults ? L",\"decoded_hard_faults\":" + std::to_wstring(s.faults) +
                L",\"unsupported_hard_fault_records\":" + std::to_wstring(s.unsupportedFaults) : L"")
            << L",\"file_provider_guid\":\"90cbdc39-4a3e-11d1-84f4-0000f80464e3\",\"disk_provider_guid\":\"3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c\""
            << L",\"clock\":{\"raw_type\":" << h.ReservedFlags << L",\"kind\":\"" << (h.ReservedFlags == 1 ? L"qpc" : h.ReservedFlags == 2 ? L"system_time" :
                h.ReservedFlags == 3 ? L"cpu_cycle" : L"unknown") << L"\",\"header_perf_frequency\":\"" << h.PerfFreq.QuadPart << L"\"}"
            << L",\"log_header\":{\"pointer_bytes\":" << h.PointerSize << L",\"processors\":" << h.NumberOfProcessors
            << L",\"start_filetime\":\"" << h.StartTime.QuadPart << L"\",\"end_filetime\":\"" << h.EndTime.QuadPart
            << L"\",\"log_mode\":" << h.LogFileMode << L",\"events_lost\":" << h.EventsLost << L",\"buffers_lost\":" << h.BuffersLost
            << L",\"buffers_written\":" << h.BuffersWritten << L"},\"records_seen\":" << s.records << L",\"buffers_processed\":" << s.buffers
            << L",\"buffer_comparison\":\"" << etl_profile::BufferComparisonName(coverage) << L"\",\"loss_marker_records\":" << s.losses
            << L",\"requested_operation_records\":[";
        for (const auto n : s.numbers) { if (n != s.numbers.front()) { std::wcout << L','; } std::wcout << n; }
        std::wcout << L"],\"next_after\":null,\"operation_records\":[";
        WriteRows(s);
        std::wcout << L"]}\n";
        return std::wcout.good() && complete ? 0 : 1;
    }
}

int wmain(int argc, wchar_t** argv)
{
    try { return Run(argc, argv); }
    catch (const std::bad_alloc&) { return 1; }
}
