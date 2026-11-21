#include "EtlProfile.h"
#include "EtlThreadEvidence.h"
#include "ArtifactOutput.h"
#include "RuntimeCapabilities.h"

#include <evntrace.h>
#include <array>
#include <iostream>

namespace
{
    using etl_profile::Sample;
    constexpr GUID LostEvent = {0x6a399ae0, 0x4bc6, 0x4de9, {0x87, 0x0b, 0x36, 0x57, 0xf8, 0x94, 0x7e, 0x7e}};
    constexpr uint64_t MaxBytes = 512ull << 20;
    constexpr uint32_t MaxRecords = 2'000'000;
    constexpr uint32_t MaxPage = 128;
    const wchar_t* Prefix(bool threads)
    {
        return threads ? L"{\"schema\":\"kn.etl_profile.v2\",\"status\":" : L"{\"schema\":\"kn.etl_profile.v1\",\"status\":";
    }
    using mcpjson::Quote;

    struct Options
    {
        uint32_t after = 0;
        uint32_t limit = 64;
        std::wstring digest;
        bool threads = false;
    };

    bool Decimal(const std::wstring& text, uint32_t maximum, uint32_t& value)
    {
        if (text.empty() || text.size() > 10 || (text.size() > 1 && text.front() == L'0')) { return false; }
        uint64_t number = 0;
        for (const auto c : text)
        {
            if (c < L'0' || c > L'9') { return false; }
            number = number * 10 + (c - L'0');
        }
        if (number > maximum) { return false; }
        value = static_cast<uint32_t>(number);
        return true;
    }

    bool Parse(const std::vector<std::wstring>& args, Options& options)
    {
        if (args.size() < 3 || args.size() > 8 || args[0].empty() ||
            args[1] != L"--sha256" || args[2].size() != 64 ||
            args[2].find_first_not_of(L"0123456789abcdefABCDEF") != std::wstring::npos) { return false; }
        options.digest = args[2];
        std::transform(options.digest.begin(), options.digest.end(), options.digest.begin(),
            [](wchar_t c) { return c >= L'A' && c <= L'F' ? static_cast<wchar_t>(c + L'a' - L'A') : c; });
        bool haveAfter = false, haveLimit = false;
        for (size_t i = 3; i < args.size(); ++i)
        {
            if (args[i] == L"--thread-evidence" && !options.threads) { options.threads = true; continue; }
            if (i + 1 == args.size()) { return false; }
            if (args[i] == L"--after" && !haveAfter && Decimal(args[i + 1], MaxRecords, options.after))
            { haveAfter = true; }
            else if (args[i] == L"--limit" && !haveLimit && Decimal(args[i + 1], MaxPage, options.limit) && options.limit)
            { haveLimit = true; }
            else { return false; }
            ++i;
        }
        return true;
    }

    struct Scan
    {
        Options options;
        etl_profile::ThreadIndex threadIndex;
        uint32_t records = 0, samples = 0, unsupported = 0, lossMarkers = 0;
        uint64_t processedBuffers = 0;
        bool budgetExceeded = false;
        std::array<Sample, MaxPage> page{};
        size_t used = 0;
    };

    void WINAPI OnRecord(PEVENT_RECORD event)
    {
        auto& scan = *static_cast<Scan*>(event->UserContext);
        if (scan.records == MaxRecords) { scan.budgetExceeded = true; return; }
        ++scan.records;
        if (scan.options.threads) { scan.threadIndex.Observe(*event, scan.records); }
        const auto& h = event->EventHeader;
        if (IsEqualGUID(h.ProviderId, LostEvent) && (h.Flags & EVENT_HEADER_FLAG_CLASSIC_HEADER) &&
            h.EventDescriptor.Opcode >= 32 && h.EventDescriptor.Opcode <= 34) { ++scan.lossMarkers; }
        Sample* row = scan.samples >= scan.options.after && scan.used < scan.options.limit ? &scan.page[scan.used] : nullptr;
        const auto match = etl_profile::Decode(*event, row);
        if (match == etl_profile::Match::Other) { return; }
        if (match == etl_profile::Match::Unsupported) { ++scan.unsupported; return; }
        ++scan.samples;
        if (row)
        {
            row->ordinal = scan.samples;
            row->record = scan.records;
            ++scan.used;
        }
    }

    ULONG WINAPI OnBuffer(PEVENT_TRACE_LOGFILEW log)
    {
        auto& scan = *static_cast<Scan*>(log->Context);
        ++scan.processedBuffers;
        return !scan.budgetExceeded;
    }

    struct Trace
    {
        PROCESSTRACE_HANDLE handle = INVALID_PROCESSTRACE_HANDLE;
        ~Trace() { if (handle != INVALID_PROCESSTRACE_HANDLE) { CloseTrace(handle); } }
    };

    bool OpenSource(const std::filesystem::path& path, symbol_artifacts::Directories& parents,
        SchemaArtifact& source, std::wstring& volumePath)
    {
        HANDLE raw = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_NO_RECALL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (raw == INVALID_HANDLE_VALUE) { return false; }
        const std::unique_ptr<void, decltype(&CloseHandle)> lease(raw, &CloseHandle);
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        constexpr DWORD excluded = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_OFFLINE |
            FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
        if (!GetFileInformationByHandleEx(raw, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
            (attributes.FileAttributes & excluded) || !source.OpenHandle(raw, MaxBytes) || !source.PathNamesFile())
        { return false; }
        // OpenTrace takes a name. Use the leased file's volume GUID and the
        // pinned directory hierarchy for the entire decode, including reopens.
        std::vector<wchar_t> buffer(32768);
        const auto length = GetFinalPathNameByHandleW(raw, buffer.data(), static_cast<DWORD>(buffer.size()), VOLUME_NAME_GUID);
        if (!length || length >= buffer.size()) { return false; }
        volumePath.assign(buffer.data(), length);
        if (volumePath.rfind(L"\\\\?\\Volume{", 0) != 0) { return false; }
        const auto root = volumePath.find(L"}\\");
        if (root == std::wstring::npos) { return false; }
        // A substituted drive can start below the real volume root. Hold each
        // actual ancestor against rename and reparse changes, then check the leaf.
        for (auto end = volumePath.find(L'\\', root + 2); end != std::wstring::npos; end = volumePath.find(L'\\', end + 1))
        {
            if (!parents.HoldExisting(volumePath.substr(0, end), FILE_SHARE_READ)) { return false; }
        }
        return source.PathNamesFile(volumePath);
    }

    std::wstring Hex(uint64_t value)
    {
        wchar_t text[20]{};
        swprintf_s(text, L"0x%llx", static_cast<unsigned long long>(value));
        return Quote(text);
    }

    std::wstring ThreadPointJson(const etl_profile::ThreadEvent* e)
    {
        if (!e) { return L"null"; }
        return L"{\"record_ordinal\":" + std::to_wstring(e->record) + L",\"raw_timestamp\":" + Quote(std::to_wstring(e->tick)) +
            L",\"event\":" + Quote(etl_profile::ThreadEventName(e->opcode)) + L",\"opcode\":" + std::to_wstring(e->opcode) +
            L",\"payload_pid\":" + std::to_wstring(e->pid) + L",\"payload_tid\":" + std::to_wstring(e->tid) + L"}";
    }

    std::wstring ThreadPairJson(const etl_profile::ThreadPair& pair)
    {
        return L",\"thread_evidence\":{\"relation\":" + Quote(pair.relation) + L",\"paired_record_pid\":" +
            (pair.pairedPid ? std::to_wstring(pair.before->pid) : L"null") + L",\"before\":" + ThreadPointJson(pair.before) +
            L",\"after\":" + ThreadPointJson(pair.after) + L"}";
    }

    std::wstring SampleJson(const Sample& s, const etl_profile::ThreadPair* thread)
    {
        return L"{\"sample_ordinal\":" + std::to_wstring(s.ordinal) + L",\"record_ordinal\":" + std::to_wstring(s.record) +
            L",\"raw_timestamp\":" + Quote(std::to_wstring(s.timestamp)) + L",\"cpu\":" + std::to_wstring(s.cpu) +
            L",\"cpu_field\":" + Quote((s.flags & EVENT_HEADER_FLAG_PROCESSOR_INDEX) ? L"processor_index" : L"processor_number") +
            L",\"instruction_pointer\":" + Hex(s.ip) + L",\"sampled_thread_id\":" + std::to_wstring(s.tid) +
            L",\"count_field\":" + std::to_wstring(s.count) + L",\"reserved_field\":" + std::to_wstring(s.reserved) +
            L",\"pointer_bytes\":" + std::to_wstring(s.width) + L",\"header_thread_id\":" + std::to_wstring(s.headerTid) +
            L",\"header_process_id\":" + std::to_wstring(s.headerPid) + L",\"header_flags\":" + std::to_wstring(s.flags) +
            L",\"logger_id\":" + std::to_wstring(s.loggerId) + L",\"event_keyword\":" + Hex(s.keyword) +
            L",\"event_level\":" + std::to_wstring(s.level) + L",\"event_channel\":" + std::to_wstring(s.channel) +
            L",\"event_task\":" + std::to_wstring(s.task) + L",\"extended_data_items\":" + std::to_wstring(s.extendedItems) +
            L",\"stack_extension_items\":" + std::to_wstring(s.stackItems) +
            (thread ? ThreadPairJson(*thread) : L"") + L"}";
    }

    int Failure(bool threads, const wchar_t* status, const std::wstring& digest = {}, DWORD error = 0)
    {
        const auto report = std::wstring(Prefix(threads)) + Quote(status) + L",\"source_sha256\":" +
            (digest.empty() ? L"null" : Quote(digest)) + L",\"win32_status\":" +
            (error ? std::to_wstring(error) : L"null") + L"}";
        return WriteCapabilityJson(report) ? 1 : 2;
    }

    enum class BufferAccounting { Unavailable, Matched, Fewer, More };

    BufferAccounting AccountBuffers(const Scan& scan, const TRACE_LOGFILE_HEADER& h)
    {
        // A circular logger's written count can include overwritten buffers.
        if (!h.BuffersWritten || !(h.LogFileMode & EVENT_TRACE_FILE_MODE_SEQUENTIAL) ||
            (h.LogFileMode & (EVENT_TRACE_FILE_MODE_CIRCULAR | EVENT_TRACE_FILE_MODE_NEWFILE)))
        { return BufferAccounting::Unavailable; }
        if (scan.processedBuffers < h.BuffersWritten) { return BufferAccounting::Fewer; }
        if (scan.processedBuffers > h.BuffersWritten) { return BufferAccounting::More; }
        return BufferAccounting::Matched;
    }

    bool Partial(const Scan& scan, BufferAccounting accounting)
    {
        return accounting == BufferAccounting::Fewer || accounting == BufferAccounting::More || !scan.threadIndex.Complete();
    }

    std::wstring Report(const Scan& scan, const TRACE_LOGFILE_HEADER& h, const SchemaArtifact& source, BufferAccounting accounting)
    {
        const auto clock = h.ReservedFlags == 1 ? L"qpc" : h.ReservedFlags == 2 ? L"system_time" :
            h.ReservedFlags == 3 ? L"cpu_cycle" : L"unknown";
        const bool partial = Partial(scan, accounting);
        const auto comparison = accounting == BufferAccounting::Matched ? L"matched" :
            accounting == BufferAccounting::Fewer ? L"fewer_than_declared" :
            accounting == BufferAccounting::More ? L"more_than_declared" : L"not_comparable";
        auto result = std::wstring(Prefix(scan.options.threads)) + Quote(partial ? L"partial" : L"read") + L",\"source_sha256\":" + Quote(source.Sha256) +
            L",\"source_bytes\":" + std::to_wstring(source.Bytes()) +
            L",\"provider_guid\":\"ce1dbfb4-137e-4da6-87b0-3f59aa102cbc\",\"event_id\":0,\"opcode\":46,\"version\":2" +
            L",\"clock\":{\"raw_type\":" + std::to_wstring(h.ReservedFlags) + L",\"kind\":" + Quote(clock) +
            L",\"header_perf_frequency\":" + Quote(std::to_wstring(h.PerfFreq.QuadPart)) + L"}" +
            L",\"log_header\":{\"pointer_bytes\":" + std::to_wstring(h.PointerSize) + L",\"processors\":" + std::to_wstring(h.NumberOfProcessors) +
            L",\"start_filetime\":" + Quote(std::to_wstring(h.StartTime.QuadPart)) +
            L",\"end_filetime\":" + Quote(std::to_wstring(h.EndTime.QuadPart)) +
            L",\"log_mode\":" + std::to_wstring(h.LogFileMode) + L",\"events_lost\":" + std::to_wstring(h.EventsLost) +
            L",\"buffers_lost\":" + std::to_wstring(h.BuffersLost) + L",\"buffers_written\":" + std::to_wstring(h.BuffersWritten) + L"}" +
            L",\"qualification\":{\"evidence\":\"reported_cpu_sample\",\"producer_authenticity\":\"unverified\","
            L"\"verified_level\":\"unqualified\",\"sampled_process_id\":null,\"thread_lifetime\":null,"
            L"\"address_space\":null,\"vm\":null,\"vtl\":null,\"code_version\":null,\"capture_privilege\":null,"
            L"\"capture_enable_flags\":null,\"stack_capture_policy\":null,\"sample_loss_intervals\":null}" +
            L",\"records_seen\":" + std::to_wstring(scan.records) + L",\"decoded_samples\":" + std::to_wstring(scan.samples) +
            L",\"buffers_processed\":" + std::to_wstring(scan.processedBuffers) + L",\"buffer_comparison\":" + Quote(comparison) +
            L",\"loss_marker_records\":" + std::to_wstring(scan.lossMarkers) +
            L",\"unsupported_profile_records\":" + std::to_wstring(scan.unsupported) + L",\"after\":" + std::to_wstring(scan.options.after) +
            L",\"next_after\":" + (scan.used && scan.page[scan.used - 1].ordinal < scan.samples ?
                std::to_wstring(scan.page[scan.used - 1].ordinal) : L"null");
        if (scan.options.threads)
        {
            result += L",\"thread_source\":{\"provider_guid\":\"3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c\",\"version\":3,"
                L"\"decoded_events\":" + std::to_wstring(scan.threadIndex.decoded) +
                L",\"retained_events\":" + std::to_wstring(scan.threadIndex.events.size()) +
                L",\"unsupported_events\":" + std::to_wstring(scan.threadIndex.unsupported) + L"}";
        }
        const bool comparableClock = (h.ReservedFlags == 1 && h.PerfFreq.QuadPart > 0) || h.ReservedFlags == 2;
        const bool captureGap = accounting != BufferAccounting::Matched || h.EventsLost || h.BuffersLost || scan.lossMarkers;
        result += L",\"samples\":[";
        for (size_t i = 0; i < scan.used; ++i)
        {
            if (i) { result += L','; }
            if (scan.options.threads)
            {
                const auto pair = scan.threadIndex.Lookup(scan.page[i], comparableClock, captureGap);
                result += SampleJson(scan.page[i], &pair);
            }
            else { result += SampleJson(scan.page[i], nullptr); }
        }
        return result + L"]}";
    }
}

int RunEtlProfile(const std::vector<std::wstring>& args)
{
    Scan scan;
    if (!Parse(args, scan.options))
    {
        return WriteWithDistinctInput(STD_ERROR_HANDLE, args.empty() ? L"" : args[0], [] {
            std::wcerr << L"usage: KnLiveDbg.exe --etl-profile <local.etl> --sha256 <digest> [--after N] [--limit 1..128] [--thread-evidence]\n";
            return 2;
        });
    }
    std::filesystem::path path;
    symbol_artifacts::Directories parents;
    SchemaArtifact source;
    std::wstring volumePath;
    if (!symbol_artifacts::LocalRoot(args[0], &path) || !parents.Pin(path.parent_path(), false) ||
        !OpenSource(path, parents, source, volumePath))
    {
        return WriteWithDistinctInput(STD_OUTPUT_HANDLE, args[0], [&] { return Failure(scan.options.threads, L"source_unavailable"); });
    }
    if (source.Sha256 != scan.options.digest) { return Failure(scan.options.threads, L"digest_mismatch", source.Sha256); }
    EVENT_TRACE_LOGFILEW log{};
    log.LogFileName = volumePath.data();
    log.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    log.EventRecordCallback = OnRecord;
    log.BufferCallback = OnBuffer;
    log.Context = &scan;
    Trace trace;
    trace.handle = OpenTraceW(&log);
    if (trace.handle == INVALID_PROCESSTRACE_HANDLE) { return Failure(scan.options.threads, L"open_trace_failed", source.Sha256, GetLastError()); }
    if (log.LogfileHeader.LogFileMode & EVENT_TRACE_FILE_MODE_NEWFILE) { return Failure(scan.options.threads, L"segmented_source", source.Sha256); }
    if (scan.options.threads)
    {
        try { scan.threadIndex.Prepare(); }
        catch (const std::bad_alloc&) { return Failure(true, L"thread_index_unavailable", source.Sha256); }
    }
    const auto status = ProcessTrace(&trace.handle, 1, nullptr, nullptr);
    if (!source.PathNamesFile(volumePath) || !source.Unchanged()) { return Failure(scan.options.threads, L"source_changed"); }
    if (scan.budgetExceeded) { return Failure(scan.options.threads, L"record_budget_exceeded", source.Sha256); }
    if (status != ERROR_SUCCESS) { return Failure(scan.options.threads, L"process_trace_failed", source.Sha256, status); }
    const auto accounting = AccountBuffers(scan, log.LogfileHeader);
    const bool partial = Partial(scan, accounting);
    if (scan.options.threads && scan.threadIndex.Complete()) { scan.threadIndex.Sort(); }
    if (!partial && scan.options.after > scan.samples) { return Failure(scan.options.threads, L"cursor_out_of_range", source.Sha256); }
    return WriteCapabilityJson(Report(scan, log.LogfileHeader, source, accounting)) ? (partial ? 1 : 0) : 2;
}
