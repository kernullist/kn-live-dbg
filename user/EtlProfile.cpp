#include "EtlProfile.h"
#include "EtlThreadEvidence.h"
#include "EtlImageEvidence.h"
#include "EtlSwitchRecord.h"
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
    using mcpjson::Quote;

    struct Options
    {
        uint32_t after = 0;
        uint32_t limit = 64;
        std::wstring digest;
        bool switches = false, threads = false, images = false;
        bool WithThreads() const { return threads || images; }
        const wchar_t* Prefix() const
        {
            if (switches) { return L"{\"schema\":\"kn.etl_switches.v1\",\"status\":"; }
            if (images) { return L"{\"schema\":\"kn.etl_profile.v3\",\"status\":"; }
            return threads ? L"{\"schema\":\"kn.etl_profile.v2\",\"status\":" : L"{\"schema\":\"kn.etl_profile.v1\",\"status\":";
        }
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
        if (args.size() < 3 || args.size() > 9 || args[0].empty() ||
            args[1] != L"--sha256" || args[2].size() != 64 ||
            args[2].find_first_not_of(L"0123456789abcdefABCDEF") != std::wstring::npos) { return false; }
        options.digest = args[2];
        std::transform(options.digest.begin(), options.digest.end(), options.digest.begin(),
            [](wchar_t c) { return c >= L'A' && c <= L'F' ? static_cast<wchar_t>(c + L'a' - L'A') : c; });
        bool haveAfter = false, haveLimit = false;
        for (size_t i = 3; i < args.size(); ++i)
        {
            if (args[i] == L"--thread-evidence" && !options.switches && !options.threads) { options.threads = true; continue; }
            if (args[i] == L"--image-evidence" && !options.switches && !options.images) { options.images = true; continue; }
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
        etl_profile::ImageIndex imageIndex;
        uint32_t records = 0, decoded = 0, unsupported = 0, lossMarkers = 0;
        uint64_t processedBuffers = 0;
        bool budgetExceeded = false;
        std::array<Sample, MaxPage> page{};
        std::array<etl_profile::SwitchEvent, MaxPage> switchPage{};
        size_t used = 0;
    };

    void WINAPI OnRecord(PEVENT_RECORD event)
    {
        auto& scan = *static_cast<Scan*>(event->UserContext);
        if (scan.records == MaxRecords) { scan.budgetExceeded = true; return; }
        ++scan.records;
        if (scan.options.WithThreads()) { scan.threadIndex.Observe(*event, scan.records); }
        if (scan.options.images) { scan.imageIndex.Observe(*event, scan.records); }
        const auto& h = event->EventHeader;
        if (IsEqualGUID(h.ProviderId, LostEvent) && (h.Flags & EVENT_HEADER_FLAG_CLASSIC_HEADER) &&
            h.EventDescriptor.Opcode >= 32 && h.EventDescriptor.Opcode <= 34) { ++scan.lossMarkers; }
        const bool keep = scan.decoded >= scan.options.after && scan.used < scan.options.limit;
        const auto match = scan.options.switches ?
            etl_profile::DecodeSwitch(*event, keep ? &scan.switchPage[scan.used] : nullptr) :
            etl_profile::Decode(*event, keep ? &scan.page[scan.used] : nullptr);
        if (match == etl_profile::Match::Unsupported) { ++scan.unsupported; }
        if (match != etl_profile::Match::Decoded) { return; }
        ++scan.decoded;
        if (keep)
        {
            etl_profile::RecordEnvelope& row = scan.options.switches ?
                static_cast<etl_profile::RecordEnvelope&>(scan.switchPage[scan.used]) : scan.page[scan.used];
            row.ordinal = scan.decoded;
            row.record = scan.records;
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

    std::wstring ImageEventJson(const etl_profile::ImageEvent& e, const etl_profile::ImageIndex& index)
    {
        return L"{\"record_ordinal\":" + std::to_wstring(e.record) + L",\"raw_timestamp\":" + Quote(std::to_wstring(e.tick)) +
            L",\"opcode\":" + std::to_wstring(e.opcode) + L",\"version\":" + std::to_wstring(e.version) +
            L",\"pointer_bytes\":" + std::to_wstring(e.width) + L",\"payload_pid\":" + std::to_wstring(e.pid) +
            L",\"image_base\":" + Hex(e.base) + L",\"image_size\":" + Hex(e.size) + L",\"preferred_base\":" + Hex(e.preferred) +
            L",\"image_checksum\":" + std::to_wstring(e.checksum) + L",\"pe_timestamp\":" + std::to_wstring(e.stamp) +
            L",\"signature_level\":" + (e.version == 3 ? std::to_wstring(e.signatureLevel) : L"null") +
            L",\"signature_type\":" + (e.version == 3 ? std::to_wstring(e.signatureType) : L"null") +
            L",\"recorded_file_name\":" + Quote(std::wstring(index.Name(e))) + L"}";
    }

    std::wstring ImageMatchJson(const etl_profile::ImageMatch& match, std::vector<const etl_profile::ImageEvent*>& records)
    {
        auto result = L",\"image_evidence\":{\"relation\":" + Quote(match.relation) +
            L",\"candidate_ranges\":" + std::to_wstring(match.count) + L",\"reported_rva\":" +
            (match.paired ? Hex(match.rva) : L"null") + L",\"witnesses\":[";
        for (size_t i = 0; i < (std::min)(match.count, match.witnesses.size()); ++i)
        {
            const auto& w = match.witnesses[i];
            if (i) { result += L','; }
            if (w.before) { records.push_back(w.before); }
            if (w.after) { records.push_back(w.after); }
            result += L"{\"relation\":" + Quote(w.relation) + L",\"before_record\":" +
                (w.before ? std::to_wstring(w.before->record) : L"null") + L",\"after_record\":" +
                (w.after ? std::to_wstring(w.after->record) : L"null") + L"}";
        }
        return result + L"]}";
    }

    std::wstring RecordLocationJson(const etl_profile::RecordEnvelope& s)
    {
        return L",\"record_ordinal\":" + std::to_wstring(s.record) +
            L",\"raw_timestamp\":" + Quote(std::to_wstring(s.timestamp)) + L",\"cpu\":" + std::to_wstring(s.cpu) +
            L",\"cpu_field\":" + Quote((s.flags & EVENT_HEADER_FLAG_PROCESSOR_INDEX) ? L"processor_index" : L"processor_number");
    }

    std::wstring RecordHeaderJson(const etl_profile::RecordEnvelope& s)
    {
        return L",\"pointer_bytes\":" + std::to_wstring(s.width) + L",\"header_thread_id\":" + std::to_wstring(s.headerTid) +
            L",\"header_process_id\":" + std::to_wstring(s.headerPid) + L",\"header_flags\":" + std::to_wstring(s.flags) +
            L",\"logger_id\":" + std::to_wstring(s.loggerId) + L",\"event_keyword\":" + Hex(s.keyword) +
            L",\"event_level\":" + std::to_wstring(s.level) + L",\"event_channel\":" + std::to_wstring(s.channel) +
            L",\"event_task\":" + std::to_wstring(s.task) + L",\"extended_data_items\":" + std::to_wstring(s.extendedItems) +
            L",\"stack_extension_items\":" + std::to_wstring(s.stackItems);
    }

    std::wstring SampleJson(const Sample& s, const etl_profile::ThreadPair* thread, const std::wstring& image = {})
    {
        return L"{\"sample_ordinal\":" + std::to_wstring(s.ordinal) + RecordLocationJson(s) +
            L",\"instruction_pointer\":" + Hex(s.ip) + L",\"sampled_thread_id\":" + std::to_wstring(s.tid) +
            L",\"count_field\":" + std::to_wstring(s.count) + L",\"reserved_field\":" + std::to_wstring(s.reserved) +
            RecordHeaderJson(s) +
            (thread ? ThreadPairJson(*thread) : L"") + image + L"}";
    }

    std::wstring SwitchJson(const etl_profile::SwitchEvent& s)
    {
        const auto& f = s.fields;
        return L"{\"switch_ordinal\":" + std::to_wstring(s.ordinal) + RecordLocationJson(s) +
            L",\"version\":" + std::to_wstring(s.version) + L",\"new_thread_id\":" + std::to_wstring(f.newTid) +
            L",\"old_thread_id\":" + std::to_wstring(f.oldTid) + L",\"new_priority\":" + std::to_wstring(f.newPriority) +
            L",\"old_priority\":" + std::to_wstring(f.oldPriority) + L",\"previous_c_state\":" + std::to_wstring(f.previousCState) +
            L",\"spare_byte\":" + std::to_wstring(f.spare) + L",\"old_wait_reason\":" + std::to_wstring(f.oldWaitReason) +
            L",\"old_wait_mode\":" + (s.version == 2 ? std::to_wstring(f.modeOrFlags) : L"null") +
            L",\"thread_flags\":" + (s.version >= 3 ? std::to_wstring(static_cast<uint8_t>(f.modeOrFlags)) : L"null") +
            L",\"old_state\":" + std::to_wstring(f.oldState) + L",\"old_wait_ideal_processor\":" + std::to_wstring(f.idealProcessor) +
            L",\"new_wait_time\":" + std::to_wstring(f.newWaitTime) + L",\"reserved_field\":" + std::to_wstring(f.reserved) +
            RecordHeaderJson(s) + L"}";
    }

    int Failure(const Options& options, const wchar_t* status, const std::wstring& digest = {}, DWORD error = 0)
    {
        const auto report = std::wstring(options.Prefix()) + Quote(status) + L",\"source_sha256\":" +
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
        return accounting == BufferAccounting::Fewer || accounting == BufferAccounting::More ||
            !scan.threadIndex.Complete() || !scan.imageIndex.Complete();
    }

    std::wstring Report(const Scan& scan, const TRACE_LOGFILE_HEADER& h, const SchemaArtifact& source, BufferAccounting accounting)
    {
        const auto clock = h.ReservedFlags == 1 ? L"qpc" : h.ReservedFlags == 2 ? L"system_time" :
            h.ReservedFlags == 3 ? L"cpu_cycle" : L"unknown";
        const bool partial = Partial(scan, accounting);
        const auto comparison = accounting == BufferAccounting::Matched ? L"matched" :
            accounting == BufferAccounting::Fewer ? L"fewer_than_declared" :
            accounting == BufferAccounting::More ? L"more_than_declared" : L"not_comparable";
        auto result = std::wstring(scan.options.Prefix()) + Quote(partial ? L"partial" : L"read") + L",\"source_sha256\":" + Quote(source.Sha256) +
            L",\"source_bytes\":" + std::to_wstring(source.Bytes()) +
            (scan.options.switches ?
                L",\"provider_guid\":\"3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c\",\"event_id\":0,\"opcode\":36,\"versions\":[2,3,4]" :
                L",\"provider_guid\":\"ce1dbfb4-137e-4da6-87b0-3f59aa102cbc\",\"event_id\":0,\"opcode\":46,\"version\":2") +
            L",\"clock\":{\"raw_type\":" + std::to_wstring(h.ReservedFlags) + L",\"kind\":" + Quote(clock) +
            L",\"header_perf_frequency\":" + Quote(std::to_wstring(h.PerfFreq.QuadPart)) + L"}" +
            L",\"log_header\":{\"pointer_bytes\":" + std::to_wstring(h.PointerSize) + L",\"processors\":" + std::to_wstring(h.NumberOfProcessors) +
            L",\"start_filetime\":" + Quote(std::to_wstring(h.StartTime.QuadPart)) +
            L",\"end_filetime\":" + Quote(std::to_wstring(h.EndTime.QuadPart)) +
            L",\"log_mode\":" + std::to_wstring(h.LogFileMode) + L",\"events_lost\":" + std::to_wstring(h.EventsLost) +
            L",\"buffers_lost\":" + std::to_wstring(h.BuffersLost) + L",\"buffers_written\":" + std::to_wstring(h.BuffersWritten) + L"}" +
            (scan.options.switches ?
                L",\"qualification\":{\"evidence\":\"reported_context_switch\",\"producer_authenticity\":\"unverified\","
                L"\"thread_lifetime\":null,\"process_generation\":null,\"wait_duration\":null,\"wait_time_unit\":null,"
                L"\"capture_enable_flags\":null,\"stack_capture_policy\":null,\"capture_privilege\":null}" :
                L",\"qualification\":{\"evidence\":\"reported_cpu_sample\",\"producer_authenticity\":\"unverified\","
            L"\"verified_level\":\"unqualified\",\"sampled_process_id\":null,\"thread_lifetime\":null,"
            L"\"address_space\":null,\"vm\":null,\"vtl\":null,\"code_version\":null,\"capture_privilege\":null,"
            L"\"capture_enable_flags\":null,\"stack_capture_policy\":null,\"sample_loss_intervals\":null}") +
            L",\"records_seen\":" + std::to_wstring(scan.records) + (scan.options.switches ? L",\"decoded_switches\":" : L",\"decoded_samples\":") + std::to_wstring(scan.decoded) +
            L",\"buffers_processed\":" + std::to_wstring(scan.processedBuffers) + L",\"buffer_comparison\":" + Quote(comparison) +
            L",\"loss_marker_records\":" + std::to_wstring(scan.lossMarkers) +
            (scan.options.switches ? L",\"unsupported_switch_records\":" : L",\"unsupported_profile_records\":") + std::to_wstring(scan.unsupported) + L",\"after\":" + std::to_wstring(scan.options.after) +
            L",\"next_after\":" + (scan.used && scan.options.after + scan.used < scan.decoded ?
                std::to_wstring(scan.options.after + scan.used) : L"null");
        if (scan.options.switches)
        {
            result += L",\"switches\":[";
            for (size_t i = 0; i < scan.used; ++i)
            {
                if (i) { result += L','; }
                result += SwitchJson(scan.switchPage[i]);
            }
            return result + L"]}";
        }
        if (scan.options.WithThreads())
        {
            result += L",\"thread_source\":{\"provider_guid\":\"3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c\",\"version\":3,"
                L"\"decoded_events\":" + std::to_wstring(scan.threadIndex.decoded) +
                L",\"retained_events\":" + std::to_wstring(scan.threadIndex.events.size()) +
                L",\"unsupported_events\":" + std::to_wstring(scan.threadIndex.unsupported) + L"}";
        }
        if (scan.options.images)
        {
            result += L",\"image_source\":{\"provider_guid\":\"2cb15d1d-5fc1-11d2-abe1-00a0c911f518\",\"versions\":[2,3],"
                L"\"decoded_events\":" + std::to_wstring(scan.imageIndex.decoded) +
                L",\"retained_events\":" + std::to_wstring(scan.imageIndex.events.size()) +
                L",\"unsupported_events\":" + std::to_wstring(scan.imageIndex.unsupported) +
                L",\"retention\":" + Quote(scan.imageIndex.retention) + L"}";
        }
        std::vector<const etl_profile::ImageEvent*> records;
        const bool comparableClock = (h.ReservedFlags == 1 && h.PerfFreq.QuadPart > 0) || h.ReservedFlags == 2;
        const bool captureGap = accounting != BufferAccounting::Matched || h.EventsLost || h.BuffersLost || scan.lossMarkers;
        result += L",\"samples\":[";
        for (size_t i = 0; i < scan.used; ++i)
        {
            if (i) { result += L','; }
            if (scan.options.WithThreads())
            {
                const auto pair = scan.threadIndex.Lookup(scan.page[i], comparableClock, captureGap);
                if (scan.options.images)
                {
                    const uint32_t pid = pair.pairedPid ? pair.before->pid : 0;
                    const auto image = scan.imageIndex.Lookup(scan.page[i], pid, comparableClock, captureGap);
                    result += SampleJson(scan.page[i], &pair, ImageMatchJson(image, records));
                }
                else { result += SampleJson(scan.page[i], &pair); }
            }
            else { result += SampleJson(scan.page[i], nullptr); }
        }
        if (scan.options.images)
        {
            result += L"],\"image_records\":[";
            std::sort(records.begin(), records.end(), [](const auto* a, const auto* b) { return a->record < b->record; });
            records.erase(std::unique(records.begin(), records.end()), records.end());
            for (size_t i = 0; i < records.size(); ++i)
            {
                if (i) { result += L','; }
                result += ImageEventJson(*records[i], scan.imageIndex);
            }
        }
        return result + L"]}";
    }
}

static int ReadSavedEtl(const std::vector<std::wstring>& args, bool switches)
{
    Scan scan;
    scan.options.switches = switches;
    if (!Parse(args, scan.options))
    {
        return WriteWithDistinctInput(STD_ERROR_HANDLE, args.empty() ? L"" : args[0], [switches] {
            std::wcerr << (switches ?
                L"usage: KnLiveDbg.exe --etl-switches <local.etl> --sha256 <digest> [--after N] [--limit 1..128]\n" :
                L"usage: KnLiveDbg.exe --etl-profile <local.etl> --sha256 <digest> [--after N] [--limit 1..128] [--thread-evidence] [--image-evidence]\n");
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
        return WriteWithDistinctInput(STD_OUTPUT_HANDLE, args[0], [&] { return Failure(scan.options, L"source_unavailable"); });
    }
    if (source.Sha256 != scan.options.digest) { return Failure(scan.options, L"digest_mismatch", source.Sha256); }
    EVENT_TRACE_LOGFILEW log{};
    log.LogFileName = volumePath.data();
    log.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
    log.EventRecordCallback = OnRecord;
    log.BufferCallback = OnBuffer;
    log.Context = &scan;
    Trace trace;
    trace.handle = OpenTraceW(&log);
    if (trace.handle == INVALID_PROCESSTRACE_HANDLE) { return Failure(scan.options, L"open_trace_failed", source.Sha256, GetLastError()); }
    if (log.LogfileHeader.LogFileMode & EVENT_TRACE_FILE_MODE_NEWFILE) { return Failure(scan.options, L"segmented_source", source.Sha256); }
    if (scan.options.WithThreads())
    {
        try
        {
            scan.threadIndex.Prepare();
            if (scan.options.images) { scan.imageIndex.Prepare(); }
        }
        catch (const std::bad_alloc&)
        { return Failure(scan.options, scan.options.images ? L"evidence_index_unavailable" : L"thread_index_unavailable", source.Sha256); }
    }
    const auto status = ProcessTrace(&trace.handle, 1, nullptr, nullptr);
    if (!source.PathNamesFile(volumePath) || !source.Unchanged()) { return Failure(scan.options, L"source_changed"); }
    if (scan.budgetExceeded) { return Failure(scan.options, L"record_budget_exceeded", source.Sha256); }
    if (status != ERROR_SUCCESS) { return Failure(scan.options, L"process_trace_failed", source.Sha256, status); }
    const auto accounting = AccountBuffers(scan, log.LogfileHeader);
    const bool partial = Partial(scan, accounting);
    if (scan.options.WithThreads() && scan.threadIndex.Complete()) { scan.threadIndex.Sort(); }
    if (!partial && scan.options.after > scan.decoded) { return Failure(scan.options, L"cursor_out_of_range", source.Sha256); }
    if (scan.options.images && scan.imageIndex.Complete()) { scan.imageIndex.Sort(); }
    return WriteCapabilityJson(Report(scan, log.LogfileHeader, source, accounting)) ? (partial ? 1 : 0) : 2;
}

int RunEtlProfile(const std::vector<std::wstring>& args)
{
    return ReadSavedEtl(args, false);
}

int RunEtlSwitches(const std::vector<std::wstring>& args)
{
    return ReadSavedEtl(args, true);
}
