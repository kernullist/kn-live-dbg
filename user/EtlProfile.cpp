#include "EtlProfile.h"
#include "EtlCaptureSettings.h"
#include "EtlProcessEvidence.h"
#include "EtlReferenceImage.h"
#include "ReferenceArtifact.h"
#include "EtlScheduleIntervals.h"
#include "ArtifactOutput.h"
#include "RuntimeCapabilities.h"

#include <evntrace.h>
#include <array>
#include <iostream>

namespace
{
    using etl_profile::Sample;
    constexpr uint64_t MaxBytes = 512ull << 20;
    constexpr uint32_t MaxRecords = 2'000'000;
    constexpr uint32_t MaxPage = 128;
    using mcpjson::Quote;

    struct Options
    {
        uint32_t after = 0;
        uint32_t limit = 64;
        std::wstring digest, referencePath, referenceDigest;
        bool switches = false, threads = false, images = false, processes = false;
        bool intervals = false, haveTid = false, builds = false, settings = false;
        uint32_t tid = 0;
        bool WithIntervals() const { return intervals || haveTid; }
        bool WithThreads() const { return threads || images || processes; }
        const wchar_t* Prefix() const
        {
            if (settings) { return switches ? L"{\"schema\":\"kn.etl_switches.v3\",\"status\":" : L"{\"schema\":\"kn.etl_profile.v7\",\"status\":"; }
            if (WithIntervals()) { return L"{\"schema\":\"kn.etl_switches.v2\",\"status\":"; }
            if (switches) { return L"{\"schema\":\"kn.etl_switches.v1\",\"status\":"; }
            if (builds) { return L"{\"schema\":\"kn.etl_profile.v6\",\"status\":"; }
            if (!referencePath.empty()) { return L"{\"schema\":\"kn.etl_profile.v5\",\"status\":"; }
            if (processes) { return L"{\"schema\":\"kn.etl_profile.v4\",\"status\":"; }
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

    bool Digest(const std::wstring& input, std::wstring& result)
    {
        if (input.size() != 64 || input.find_first_not_of(L"0123456789abcdefABCDEF") != std::wstring::npos) { return false; }
        result = input;
        std::transform(result.begin(), result.end(), result.begin(),
            [](wchar_t c) { return c >= L'A' && c <= L'F' ? static_cast<wchar_t>(c + L'a' - L'A') : c; });
        return true;
    }

    bool Parse(const std::vector<std::wstring>& args, Options& options)
    {
        if (args.size() < 3 || args.size() > 15 || args[0].empty() ||
            args[1] != L"--sha256" || !Digest(args[2], options.digest)) { return false; }
        bool haveAfter = false, haveLimit = false;
        for (size_t i = 3; i < args.size(); ++i)
        {
            if (args[i] == L"--capture-settings" && !options.settings) { options.settings = true; continue; }
            if (args[i] == L"--thread-evidence" && !options.switches && !options.threads) { options.threads = true; continue; }
            if (args[i] == L"--image-evidence" && !options.switches && !options.images) { options.images = true; continue; }
            if (args[i] == L"--process-evidence" && !options.switches && !options.processes) { options.processes = true; continue; }
            if (args[i] == L"--build-evidence" && !options.switches && !options.builds) { options.builds = true; continue; }
            if (args[i] == L"--reference-image" && !options.switches && options.referencePath.empty())
            {
                if (args.size() - i < 3 || args[i + 1].empty() || !Digest(args[i + 2], options.referenceDigest)) { return false; }
                options.referencePath = args[i + 1];
                i += 2;
                continue;
            }
            if (args[i] == L"--intervals" && options.switches && !options.intervals) { options.intervals = true; continue; }
            if (i + 1 == args.size()) { return false; }
            if (args[i] == L"--after" && !haveAfter && Decimal(args[i + 1], MaxRecords, options.after))
            { haveAfter = true; }
            else if (args[i] == L"--limit" && !haveLimit && Decimal(args[i + 1], MaxPage, options.limit) && options.limit)
            { haveLimit = true; }
            else if (args[i] == L"--thread-id" && options.switches && !options.haveTid && Decimal(args[i + 1], UINT32_MAX, options.tid))
            { options.haveTid = true; }
            else { return false; }
            ++i;
        }
        if (options.builds || !options.referencePath.empty()) { options.images = true; options.processes = true; }
        return true;
    }

    struct TraceCounts
    {
        uint32_t records = 0, decoded = 0, unsupported = 0, lossMarkers = 0;
        uint64_t processedBuffers = 0;
        bool budgetExceeded = false;
    };

    struct Scan : TraceCounts
    {
        Options options;
        etl_profile::ThreadIndex threadIndex;
        etl_profile::ImageIndex imageIndex;
        etl_profile::BuildIndex buildIndex;
        etl_profile::CaptureSettings settings;
        etl_profile::ProcessIndex processIndex;
        etl_profile::ScheduleHistory history;
        std::array<Sample, MaxPage> page{};
        std::array<etl_profile::SwitchEvent, MaxPage> switchPage{};
        std::array<etl_profile::IntervalWitnesses, MaxPage> witnesses{};
        uint32_t matched = 0;
        size_t used = 0, replayedRows = 0;
        bool replaying = false, replayMismatch = false;
    };

    void ReplayRecord(const EVENT_RECORD& event, Scan& scan)
    {
        if (!IsEqualGUID(event.EventHeader.ProviderId, etl_profile::ThreadProvider)) { return; }
        if (event.EventHeader.EventDescriptor.Opcode != 36)
        {
            scan.history.OtherThreadEvent(event, scan.records);
            return;
        }
        etl_profile::SwitchEvent point{};
        if (etl_profile::DecodeSwitch(event, &point) != etl_profile::Match::Decoded) { ++scan.unsupported; return; }
        point.record = scan.records;
        point.ordinal = ++scan.decoded;
        etl_profile::IntervalWitnesses* witnesses = nullptr;
        if (scan.replayedRows < scan.used && scan.switchPage[scan.replayedRows].record == point.record)
        {
            const auto& first = scan.switchPage[scan.replayedRows];
            scan.replayMismatch |= first.ordinal != point.ordinal || first.timestamp != point.timestamp ||
                first.cpu != point.cpu || first.flags != point.flags || first.loggerId != point.loggerId ||
                first.version != point.version || std::memcmp(&first.fields, &point.fields, sizeof(point.fields)) != 0;
            witnesses = &scan.witnesses[scan.replayedRows++];
        }
        scan.history.Observe(point, witnesses);
    }

    void WINAPI OnRecord(PEVENT_RECORD event)
    {
        auto& scan = *static_cast<Scan*>(event->UserContext);
        if (scan.records == MaxRecords) { scan.budgetExceeded = true; return; }
        ++scan.records;
        const auto& h = event->EventHeader;
        if (etl_profile::LossMarker(h)) { ++scan.lossMarkers; }
        if (scan.replaying) { ReplayRecord(*event, scan); return; }
        if (scan.options.settings) { scan.settings.Observe(*event, scan.records); }
        if (scan.options.WithThreads()) { scan.threadIndex.Observe(*event, scan.records); }
        if (scan.options.builds) { scan.buildIndex.Observe(*event, scan.records); }
        if (scan.options.images) { scan.imageIndex.Observe(*event, scan.records); }
        if (scan.options.processes) { scan.processIndex.Observe(*event, scan.records, scan.options.images); }
        const bool keep = scan.matched >= scan.options.after && scan.used < scan.options.limit;
        etl_profile::SwitchEvent scratch;
        auto* sw = keep ? &scan.switchPage[scan.used] : (scan.options.haveTid ? &scratch : nullptr);
        const auto match = scan.options.switches ? etl_profile::DecodeSwitch(*event, sw) :
            etl_profile::Decode(*event, keep ? &scan.page[scan.used] : nullptr);
        if (match == etl_profile::Match::Unsupported) { ++scan.unsupported; }
        if (match != etl_profile::Match::Decoded) { return; }
        ++scan.decoded;
        if (scan.options.haveTid && sw->fields.oldTid != scan.options.tid && sw->fields.newTid != scan.options.tid) { return; }
        ++scan.matched;
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
        SchemaArtifact& source, std::wstring& volumePath, uint64_t maximum = MaxBytes)
    {
        HANDLE raw = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_NO_RECALL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (raw == INVALID_HANDLE_VALUE) { return false; }
        const std::unique_ptr<void, decltype(&CloseHandle)> lease(raw, &CloseHandle);
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        constexpr DWORD excluded = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_OFFLINE |
            FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
        if (!GetFileInformationByHandleEx(raw, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
            (attributes.FileAttributes & excluded) || !source.OpenHandle(raw, maximum) || !source.PathNamesFile())
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

    std::wstring LoggerJson(uint16_t logger, bool include)
    {
        return include ? L",\"logger_id\":" + std::to_wstring(logger) : std::wstring{};
    }

    std::wstring SettingsManifestJson(const etl_profile::CaptureSettings& s, const TRACE_LOGFILE_HEADER& header)
    {
        auto out = std::wstring(L",\"capture_settings\":{\"scope\":\"saved_file_logger_records\",\"original_session_id\":null,") +
            L"\"mask_provider\":\"68fdd900-4a3e-11d1-84f4-0000f80464e3\",\"interval_provider\":\"ce1dbfb4-137e-4da6-87b0-3f59aa102cbc\"," +
            L"\"loss_provider\":\"6a399ae0-4bc6-4de9-870b-3657f8947e7e\",\"header_timer_resolution_100ns\":" +
            std::to_wstring(header.TimerResolution) + L",\"group_mask_records\":" + std::to_wstring(s.maskCount) +
            L",\"profile_interval_records\":" + std::to_wstring(s.intervalCount) + L",\"loss_indications\":" + std::to_wstring(s.lossCount) +
            L",\"unsupported_group_masks\":" + std::to_wstring(s.unsupportedMasks) +
            L",\"unsupported_profile_intervals\":" + std::to_wstring(s.unsupportedIntervals) +
            L",\"retained_records\":" + std::to_wstring(s.records.size()) + L",\"retention\":" + Quote(s.retention) + L",\"records\":[";
        for (const auto& e : s.records)
        {
            if (&e != s.records.data()) { out += L','; }
            out += L"{\"record_ordinal\":" + std::to_wstring(e.record) + L",\"raw_timestamp\":" + Quote(std::to_wstring(e.tick)) +
                L",\"logger_id\":" + std::to_wstring(e.logger) + L",\"cpu\":" + std::to_wstring(e.cpu) +
                L",\"cpu_field\":" + Quote((e.flags & EVENT_HEADER_FLAG_PROCESSOR_INDEX) ? L"processor_index" : L"processor_number") +
                L",\"header_flags\":" + std::to_wstring(e.flags) + L",\"pointer_bytes\":" + (e.width ? std::to_wstring(e.width) : L"null") +
                L",\"event_id\":" + std::to_wstring(e.eventId) + L",\"version\":" + std::to_wstring(e.version) +
                L",\"opcode\":" + std::to_wstring(e.opcode) + L",\"event_keyword\":" + Hex(e.keyword) +
                L",\"event_level\":" + std::to_wstring(e.level) + L",\"event_channel\":" + std::to_wstring(e.channel) +
                L",\"event_task\":" + std::to_wstring(e.task) + L",\"payload_bytes\":" + std::to_wstring(e.payloadBytes);
            const bool mask = e.kind == etl_profile::SettingKind::GroupMask;
            const bool loss = e.kind == etl_profile::SettingKind::Loss;
            out += L",\"kind\":" + Quote(mask ? L"group_mask" : loss ? L"loss_indication" : L"profile_interval") +
                L",\"payload_status\":" + Quote(loss ? L"envelope_only" : e.supported ? L"decoded" : L"unsupported");
            if (e.supported && mask)
            {
                out += L",\"group_masks\":[";
                for (size_t i = 0; i < e.masks.size(); ++i)
                {
                    if (i) { out += L','; }
                    out += std::to_wstring(e.masks[i]);
                }
                out += L"],\"kernel_event_version\":" + (e.version == 2 ? std::to_wstring(e.kernelVersion) : L"null");
            }
            else if (e.supported && !loss)
            {
                out += L",\"profile_source\":" + std::to_wstring(e.source) +
                    L",\"new_interval_raw\":" + std::to_wstring(e.newInterval) + L",\"old_interval_raw\":" + std::to_wstring(e.oldInterval) +
                    L",\"profile_source_name\":" + (e.version == 3 ? Quote(std::wstring(s.Name(e))) : L"null");
            }
            out += L'}';
        }
        return out + L"]}";
    }

    std::wstring SettingBracketJson(const etl_profile::SettingBracket& r, bool timer)
    {
        auto ordinal = [](const etl_profile::SettingRecord* p) { return p ? std::to_wstring(p->record) : std::wstring(L"null"); };
        auto out = L"{\"relation\":" + Quote(r.relation) + L",\"before_record\":" + ordinal(r.before) +
            L",\"after_record\":" + ordinal(r.after);
        if (timer)
        {
            out += L",\"collection_start_record\":" + ordinal(r.start) + L",\"collection_end_record\":" + ordinal(r.end) +
                L",\"reported_period_100ns\":" + (r.period ? std::to_wstring(r.period) : L"null");
        }
        return out + L"}";
    }

    std::wstring SettingsEvidenceJson(const Scan& scan, const etl_profile::RecordEnvelope& row, bool clock, bool gap)
    {
        if (!scan.options.settings) { return {}; }
        using etl_profile::SettingKind;
        auto out = std::wstring(L",\"capture_setting_evidence\":{\"group_mask_bracket\":") +
            SettingBracketJson(scan.settings.At(row, SettingKind::GroupMask, clock, gap), false);
        if (!scan.options.switches)
        {
            out += L",\"timer_bracket\":" + SettingBracketJson(scan.settings.At(row, SettingKind::ProfileInterval, clock, gap), true);
        }
        return out + L"}";
    }

    std::wstring ThreadPointJson(const etl_profile::ThreadEvent* e, bool includeLogger)
    {
        if (!e) { return L"null"; }
        return L"{\"record_ordinal\":" + std::to_wstring(e->record) + L",\"raw_timestamp\":" + Quote(std::to_wstring(e->tick)) +
            L",\"event\":" + Quote(etl_profile::ThreadEventName(e->opcode)) + L",\"opcode\":" + std::to_wstring(e->opcode) +
            L",\"payload_pid\":" + std::to_wstring(e->pid) + L",\"payload_tid\":" + std::to_wstring(e->tid) + LoggerJson(e->logger, includeLogger) + L"}";
    }

    std::wstring ThreadPairJson(const etl_profile::ThreadPair& pair, bool includeLogger)
    {
        return L",\"thread_evidence\":{\"relation\":" + Quote(pair.relation) + L",\"paired_record_pid\":" +
            (pair.pairedPid ? std::to_wstring(pair.before->pid) : L"null") + L",\"before\":" + ThreadPointJson(pair.before, includeLogger) +
            L",\"after\":" + ThreadPointJson(pair.after, includeLogger) + L"}";
    }

    std::wstring ImageEventJson(const etl_profile::ImageEvent& e, const etl_profile::ImageIndex& index, bool includeLogger)
    {
        return L"{\"record_ordinal\":" + std::to_wstring(e.record) + L",\"raw_timestamp\":" + Quote(std::to_wstring(e.tick)) +
            L",\"opcode\":" + std::to_wstring(e.opcode) + L",\"version\":" + std::to_wstring(e.version) +
            L",\"pointer_bytes\":" + std::to_wstring(e.width) + L",\"payload_pid\":" + std::to_wstring(e.pid) +
            L",\"image_base\":" + Hex(e.base) + L",\"image_size\":" + Hex(e.size) + L",\"preferred_base\":" + Hex(e.preferred) +
            L",\"image_checksum\":" + std::to_wstring(e.checksum) + L",\"pe_timestamp\":" + std::to_wstring(e.stamp) +
            L",\"signature_level\":" + (e.version == 3 ? std::to_wstring(e.signatureLevel) : L"null") +
            L",\"signature_type\":" + (e.version == 3 ? std::to_wstring(e.signatureType) : L"null") +
            L",\"recorded_file_name\":" + Quote(std::wstring(index.Name(e))) + LoggerJson(e.logger, includeLogger) + L"}";
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

    std::wstring ProcessEventJson(const etl_profile::ProcessEvent& e)
    {
        return L"{\"record_ordinal\":" + std::to_wstring(e.record) + L",\"raw_timestamp\":" + Quote(std::to_wstring(e.tick)) +
            L",\"event\":" + Quote(e.opcode == 39 ? L"defunct" : etl_profile::ThreadEventName(e.opcode)) +
            L",\"opcode\":" + std::to_wstring(e.opcode) + L",\"version\":" + std::to_wstring(e.version) +
            L",\"pointer_bytes\":" + std::to_wstring(e.width) + L",\"logger_id\":" + std::to_wstring(e.logger) +
            L",\"payload_pid\":" + std::to_wstring(e.pid) + L",\"parent_pid\":" + std::to_wstring(e.parent) +
            L",\"session_id\":" + std::to_wstring(e.session) + L",\"exit_status\":" + std::to_wstring(e.exitStatus) +
            L",\"defunct_exit_time_raw\":" + (e.version == 5 ? Quote(std::to_wstring(e.exitTime)) : L"null") + L"}";
    }

    std::wstring ProcessPairJson(const etl_profile::ProcessPair& p, std::vector<const etl_profile::ProcessEvent*>& records)
    {
        if (p.before) { records.push_back(p.before); }
        if (p.after) { records.push_back(p.after); }
        return L",\"process_evidence\":{\"relation\":" + Quote(p.relation) + L",\"candidate_pid\":" +
            (p.candidatePid ? std::to_wstring(p.candidatePid) : L"null") + L",\"before_record\":" +
            (p.before ? std::to_wstring(p.before->record) : L"null") + L",\"after_record\":" +
            (p.after ? std::to_wstring(p.after->record) : L"null") + L",\"opaque_key_comparison\":" + Quote(p.keyComparison) +
            L",\"recorded_generation\":" + (p.generation ? L"{\"payload_pid\":" + std::to_wstring(p.candidatePid) +
                L",\"start_record\":" + std::to_wstring(p.before->record) + L"}" : L"null") + L"}";
    }

    std::wstring ImageProcessJson(const etl_profile::ProcessPair& process, const etl_profile::ImageMatch& image,
        const etl_profile::ProcessImagePair& bound)
    {
        return L",\"image_process_evidence\":{\"relation\":" + Quote(bound.relation) + L",\"process_start_record\":" +
            (bound.paired ? std::to_wstring(process.before->record) : L"null") + L",\"reported_rva\":" +
            (bound.paired ? Hex(image.rva) : L"null") + L"}";
    }

    const wchar_t* FieldJson(etl_profile::FieldComparison value)
    {
        using etl_profile::FieldComparison;
        return value == FieldComparison::Unavailable ? L"null" : value == FieldComparison::Equal ? L"true" : L"false";
    }

    std::wstring BuildGuid(const GUID& id)
    {
        wchar_t out[37]{};
        swprintf_s(out, L"%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", id.Data1, id.Data2, id.Data3,
            id.Data4[0], id.Data4[1], id.Data4[2], id.Data4[3], id.Data4[4], id.Data4[5], id.Data4[6], id.Data4[7]);
        return Quote(out);
    }

    std::wstring BuildEventJson(const etl_profile::BuildEvent& e)
    {
        auto out = L"{\"record_ordinal\":" + std::to_wstring(e.record) + L",\"raw_timestamp\":" + Quote(std::to_wstring(e.tick)) +
            L",\"version\":2,\"opcode\":" + std::to_wstring(e.opcode) + L",\"pointer_bytes\":" + std::to_wstring(e.width) +
            L",\"logger_id\":" + std::to_wstring(e.logger) + L",\"header_process_id\":" + std::to_wstring(e.headerPid) +
            L",\"payload_pid\":" + std::to_wstring(e.pid) + L",\"image_base\":" + Hex(e.base);
        if (!e.opcode) { out += L",\"image_size\":" + Hex(e.size) + L",\"pe_timestamp\":" + std::to_wstring(e.stamp); }
        if (e.opcode == 36) { out += L",\"rsds_guid\":" + BuildGuid(e.guid) + L",\"pdb_age\":" + std::to_wstring(e.age); }
        return out + L"}";
    }

    std::wstring MarkerJson(const etl_profile::MarkerRange& range, std::vector<const etl_profile::BuildEvent*>& records)
    {
        auto out = L"{\"marker_count\":" + std::to_wstring(range.count) + L",\"marker_records\":[";
        for (size_t i = 0; i < (std::min)(range.count, size_t{2}); ++i)
        {
            if (i) { out += L','; }
            records.push_back(range.first + i);
            out += std::to_wstring(range.first[i].record);
        }
        return out + L"]}";
    }

    std::wstring BuildEndpointJson(const etl_profile::BuildEndpoint& e, std::vector<const etl_profile::BuildEvent*>& records)
    {
        return L",\"merge_build\":{\"relation\":" + Quote(e.relation) + L",\"loader_count\":" + std::to_wstring(e.loaders) +
            L",\"image_id\":" + MarkerJson(e.info, records) + L",\"no_debug_id\":" + MarkerJson(e.none, records) +
            L",\"native_rsds\":" + MarkerJson(e.rsds, records) + L"}";
    }

    std::wstring BuildPairJson(const etl_profile::BuildPair& pair, const etl_profile::ReferenceImage* reference)
    {
        auto out = L",\"build_evidence\":{\"relation\":" + Quote(pair.relation) + L",\"reference_comparison\":";
        if (!pair.rsds || !reference) { return out + L"null}"; }
        const auto fields = etl_profile::CompareMergeFields(*reference, pair);
        return out + L"{\"rsds_guid_equal\":" + FieldJson(fields.guid) + L",\"pdb_age_equal\":" + FieldJson(fields.age) +
            L",\"merge_timestamp_equal\":" + FieldJson(fields.stamp) + L"}}";
    }

    bool AppendReferenceEvidence(std::wstring& report, const etl_profile::ReferenceImage& reference,
        const etl_profile::ImageIndex& index, const etl_profile::ImageMatch& image, const etl_profile::ProcessImagePair& bound,
        const etl_profile::BuildPair* build)
    {
        const auto* point = bound.paired ? image.witnesses[0].before : nullptr;
        const auto result = etl_profile::CompareReference(reference, point, point ? index.Name(*point) : std::wstring_view{}, image.rva, build);
        report += L",\"reference_evidence\":{\"relation\":" + Quote(result.relation) + L",\"loader_fields\":";
        if (point)
        {
            report += std::wstring(L"{\"file_name\":") + FieldJson(result.name) + L",\"image_size\":" + FieldJson(result.size) +
                L",\"pe_timestamp\":" + FieldJson(result.stamp) + L",\"image_checksum\":" + FieldJson(result.checksum) +
                L",\"default_base_relation\":" + Quote(result.defaultBase) + L"}";
        }
        else { report += L"null"; }
        report += L",\"file_location\":" + Quote(result.location) + L",\"reference_window\":";
        if (!result.length) { report += L"null}"; return true; }
        const auto digest = etl_profile::ReferenceWindowHash(reference, result);
        if (digest.empty()) { return false; }
        report += L"{\"file_offset\":" + std::to_wstring(result.offset) + L",\"byte_count\":" + std::to_wstring(result.length) +
            L",\"sha256\":" + Quote(digest) + L"}}";
        return true;
    }

    template<typename Event, typename Format>
    void AppendRecords(std::wstring& result, const wchar_t* name, std::vector<const Event*>& records, Format format)
    {
        result += L"],\"";
        result += name;
        result += L"\":[";
        std::sort(records.begin(), records.end(), [](const Event* a, const Event* b) { return a->record < b->record; });
        records.erase(std::unique(records.begin(), records.end()), records.end());
        for (size_t i = 0; i < records.size(); ++i)
        {
            if (i) { result += L','; }
            result += format(*records[i]);
        }
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

    std::wstring SampleJson(const Sample& s, const etl_profile::ThreadPair* thread,
        const std::wstring& evidence = {}, bool includeLogger = false)
    {
        return L"{\"sample_ordinal\":" + std::to_wstring(s.ordinal) + RecordLocationJson(s) +
            L",\"instruction_pointer\":" + Hex(s.ip) + L",\"sampled_thread_id\":" + std::to_wstring(s.tid) +
            L",\"count_field\":" + std::to_wstring(s.count) + L",\"reserved_field\":" + std::to_wstring(s.reserved) +
            RecordHeaderJson(s) +
            (thread ? ThreadPairJson(*thread, includeLogger) : L"") + evidence + L"}";
    }

    std::wstring ScheduleRefJson(const etl_profile::ScheduleRef& ref)
    {
        return L"\"record_ordinal\":" + std::to_wstring(ref.record) + L",\"raw_timestamp\":" + Quote(std::to_wstring(ref.tick)) +
            L",\"cpu\":" + std::to_wstring(ref.cpu) + L",\"cpu_field\":" + Quote(ref.indexed ? L"processor_index" : L"processor_number") +
            L",\"logger_id\":" + std::to_wstring(ref.logger);
    }

    std::wstring EdgeJson(const etl_profile::ScheduleEdge& edge)
    {
        using etl_profile::EdgeKind;
        if (!edge.at.record) { return L"null"; }
        const bool boundary = edge.kind == EdgeKind::Boundary;
        const auto kind = boundary ? etl_profile::ThreadEventName(edge.opcode) : edge.kind == EdgeKind::In ? L"switch_in" : L"switch_out";
        auto json = L"{" + ScheduleRefJson(edge.at) + L",\"kind\":" + Quote(kind) + L",\"payload_tid\":" + std::to_wstring(edge.tid) +
            L",\"version\":" + std::to_wstring(edge.version) + L",\"opcode\":" + std::to_wstring(edge.opcode);
        if (boundary) { json += L",\"payload_pid\":" + std::to_wstring(edge.pid); }
        else { json += L",\"switch_ordinal\":" + std::to_wstring(edge.switchOrdinal); }
        if (edge.kind == EdgeKind::Out)
        { json += L",\"old_state\":" + std::to_wstring(edge.state) + L",\"old_wait_reason\":" + std::to_wstring(edge.reason); }
        return json + L"}";
    }

    std::wstring ReadyJson(const etl_profile::ReadyPoint& p)
    {
        if (!p.at.record) { return L"null"; }
        return L"{" + ScheduleRefJson(p.at) + L",\"payload_tid\":" + std::to_wstring(p.tid) +
            L",\"adjust_reason\":" + std::to_wstring(p.reason) + L",\"adjust_increment\":" + std::to_wstring(p.increment) +
            L",\"ready_flags\":" + std::to_wstring(p.flags) + L",\"reserved_field\":" + std::to_wstring(p.reserved) + L"}";
    }

    std::wstring Elapsed(bool measured, int64_t begin, int64_t end)
    {
        return measured ? Quote(std::to_wstring(etl_profile::TickDistance(begin, end))) : L"null";
    }

    std::wstring IntervalsJson(const Scan& scan, size_t index, bool clock, bool gap)
    {
        const auto& e = scan.switchPage[index];
        const auto& w = scan.witnesses[index];
        const auto& out = w.previousIncomingThread;
        const auto run = etl_profile::AssessSpan(scan.history, e, w, true, clock, gap);
        const auto off = etl_profile::AssessSpan(scan.history, e, w, false, clock, gap);
        const auto ready = etl_profile::AssessReady(w.ready, out, e, off.measured, scan.history.unsupportedReady);
        return L",\"match_ordinal\":" + std::to_wstring(scan.options.after + index + 1) +
            L",\"on_cpu\":{\"relation\":" + Quote(run.relation) + L",\"elapsed_ticks\":" +
            Elapsed(run.measured, w.previousCpu.at.tick, e.timestamp) + L",\"previous_switch\":" + EdgeJson(w.previousCpu) +
            L",\"other_thread_event\":" + (etl_profile::SameTransition(w.previousOutgoingThread, w.previousCpu) ? L"null" : EdgeJson(w.previousOutgoingThread)) +
            L"},\"off_cpu\":{\"relation\":" + Quote(off.relation) + L",\"elapsed_ticks\":" + Elapsed(off.measured, out.at.tick, e.timestamp) +
            L",\"previous_thread_event\":" + EdgeJson(out) + L",\"readiness\":{\"relation\":" + Quote(ready.relation) +
            L",\"ready_records\":" + std::to_wstring(w.ready.count) + L",\"dispatchable_records\":" + std::to_wstring(w.ready.dispatchable) +
            L",\"first_ready\":" + ReadyJson(w.ready.first) + L",\"last_ready\":" + (w.ready.count > 1 ? ReadyJson(w.ready.last) : L"null") +
            L",\"switch_out_to_ready_ticks\":" + Elapsed(ready.measured, out.at.tick, w.ready.last.at.tick) +
            L",\"ready_to_switch_in_ticks\":" + Elapsed(ready.measured, w.ready.last.at.tick, e.timestamp) + L"}}";
    }

    std::wstring SwitchJson(const etl_profile::SwitchEvent& s, const std::wstring& intervals)
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
            RecordHeaderJson(s) + intervals + L"}";
    }

    int Failure(const Options& options, const wchar_t* status, const std::wstring& digest = {}, DWORD error = 0, const std::wstring& referenceDigest = {})
    {
        const auto report = std::wstring(options.Prefix()) + Quote(status) + L",\"source_sha256\":" +
            (digest.empty() ? L"null" : Quote(digest)) + L",\"win32_status\":" +
            (error ? std::to_wstring(error) : L"null") + (options.referencePath.empty() ? L"" :
                L",\"reference_sha256\":" + (referenceDigest.empty() ? L"null" : Quote(referenceDigest))) + L"}";
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
            !scan.threadIndex.Complete() || !scan.imageIndex.Complete() || !scan.processIndex.Complete() || !scan.buildIndex.Complete() || !scan.settings.Complete();
    }

    std::wstring Report(const Scan& scan, const TRACE_LOGFILE_HEADER& h, const SchemaArtifact& source, BufferAccounting accounting,
        const etl_profile::ReferenceImage* reference)
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
            (scan.options.WithIntervals() ?
                L",\"qualification\":{\"evidence\":\"reported_scheduler_intervals\",\"producer_authenticity\":\"unverified\","
                L"\"thread_lifetime\":null,\"process_generation\":null,\"wait_object\":null,\"wait_cause\":null,\"wait_time_unit\":null,"
                L"\"capture_enable_flags\":null,\"stack_capture_policy\":null,\"capture_privilege\":null}" : scan.options.switches ?
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
            L",\"next_after\":" + (scan.used && scan.options.after + scan.used < scan.matched ?
                std::to_wstring(scan.options.after + scan.used) : L"null");
        const bool comparableClock = (h.ReservedFlags == 1 && h.PerfFreq.QuadPart > 0) || h.ReservedFlags == 2;
        const bool captureGap = accounting != BufferAccounting::Matched || h.EventsLost || h.BuffersLost || scan.lossMarkers;
        if (scan.options.settings) { result += SettingsManifestJson(scan.settings, h); }
        if (scan.options.switches)
        {
            if (scan.options.WithIntervals())
            {
                const auto& history = scan.history;
                const auto hz = h.ReservedFlags == 2 ? 10'000'000ll : h.PerfFreq.QuadPart;
                result += L",\"interval_source\":{\"thread_filter\":" + (scan.options.haveTid ? std::to_wstring(scan.options.tid) : L"null") +
                    L",\"matched_switches\":" + std::to_wstring(scan.matched) + L",\"ticks_per_second\":" +
                    (comparableClock ? Quote(std::to_wstring(hz)) : L"null") + L",\"ready_opcode\":50,\"ready_version\":2,\"ready_records\":" +
                    std::to_wstring(history.readyCount) + L",\"unsupported_ready_records\":" + std::to_wstring(history.unsupportedReady) +
                    L",\"boundary_version\":3,\"thread_boundaries\":" + std::to_wstring(history.boundaries) +
                    L",\"unsupported_thread_boundaries\":" + std::to_wstring(history.unsupportedBoundaries) +
                    L",\"cpu_scope\":" + Quote(history.ambiguousScope ? L"unqualified" : history.seenSwitch ? L"comparable" : L"unobserved") +
                    L",\"cpus_with_tid_conflict\":" + std::to_wstring(history.cpuConflicts) +
                    L",\"cpus_with_clock_conflict\":" + std::to_wstring(history.cpuClockConflicts) +
                    L",\"unknown_switch_tid\":" + (history.unknownSwitchTid ? L"true" : L"false") +
                    L",\"scheduler_clock_reversed\":" + (history.reversedClock ? L"true}" : L"false}");
            }
            result += L",\"switches\":[";
            for (size_t i = 0; i < scan.used; ++i)
            {
                if (i) { result += L','; }
                const auto intervals = scan.options.WithIntervals() ?
                    IntervalsJson(scan, i, comparableClock, captureGap || scan.unsupported) : std::wstring{};
                result += SwitchJson(scan.switchPage[i], intervals + SettingsEvidenceJson(scan, scan.switchPage[i], comparableClock, captureGap));
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
        if (scan.options.processes)
        {
            const auto& index = scan.processIndex;
            result += L",\"process_source\":{\"provider_guid\":\"3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c\","
                L"\"event_id\":0,\"lifecycle_opcodes\":[1,2,3,4],\"lifecycle_versions\":[2,3,4],"
                L"\"defunct_opcode\":39,\"defunct_versions\":[2,3,4,5],\"decoded_events\":" + std::to_wstring(index.decoded) +
                L",\"retained_events\":" + std::to_wstring(index.events.size()) + L",\"unsupported_events\":" +
                std::to_wstring(index.unsupported) + L",\"defunct_events\":" + std::to_wstring(index.defunct) +
                L",\"source_clock_reversed\":" + (index.processClock.reversed ? L"true" : L"false") +
                L",\"image_binding_clock_reversed\":" + (scan.options.images ? (index.imageClock.reversed ? L"true" : L"false") : L"null") +
                L",\"generation_scope\":\"source_sha256_and_start_record\",\"creation_filetime\":null}";
        }
        const bool buildCoverage = comparableClock && !captureGap && scan.imageIndex.Complete() && !scan.imageIndex.unsupported;
        if (scan.options.builds)
        {
            const auto& index = scan.buildIndex;
            result += L",\"build_source\":{\"provider_guid\":\"b3e675d7-2554-4f18-830b-2762732560de\",\"event_id\":0,"
                L"\"version\":2,\"opcodes\":[0,32,36],\"origin\":\"merge_metadata\",\"producer_authenticity\":\"unverified\","
                L"\"runtime_bytes_observed\":false,\"decoded_events\":" + std::to_wstring(index.decoded) +
                L",\"retained_events\":" + std::to_wstring(index.events.size()) + L",\"unsupported_events\":" +
                std::to_wstring(index.unsupported) + L",\"other_opcodes\":" + std::to_wstring(index.other) +
                L",\"header_pid_conflicts\":" + std::to_wstring(index.pidConflicts) + L"}";
        }
        if (reference)
        {
            const auto& pe = reference->pe;
            result += L",\"reference_image\":{\"file_sha256\":" + Quote(reference->file.Sha256) +
                L",\"file_bytes\":" + std::to_wstring(reference->file.Bytes()) + L",\"file_name\":" + Quote(reference->leaf) +
                L",\"machine\":" + std::to_wstring(pe.Machine) + L",\"optional_magic\":" + std::to_wstring(pe.OptionalMagic) +
                L",\"image_size\":" + Hex(pe.SizeOfImage) + L",\"pe_timestamp\":" + std::to_wstring(pe.TimeDateStamp) +
                L",\"image_checksum\":" + std::to_wstring(pe.CheckSum) + L",\"preferred_base\":" + Hex(pe.ImageBase) +
                L",\"max_window_bytes\":" + std::to_wstring(etl_profile::MaxReferenceWindow) + L",\"runtime_bytes_observed\":false}";
        }
        if (reference && scan.options.builds)
        {
            const auto& b = reference->build;
            result += L",\"reference_build\":{\"status\":" + Quote(b.status) + L",\"rsds_guid\":" +
                (b.valid ? BuildGuid(b.guid) : L"null") + L",\"pdb_age\":" + (b.valid ? std::to_wstring(b.age) : L"null") + L"}";
        }
        std::vector<const etl_profile::BuildEvent*> buildRecords;
        std::vector<const etl_profile::ImageEvent*> records;
        std::vector<const etl_profile::ProcessEvent*> processRecords;
        result += L",\"samples\":[";
        for (size_t i = 0; i < scan.used; ++i)
        {
            if (i) { result += L','; }
            if (scan.options.WithThreads())
            {
                const auto pair = scan.threadIndex.Lookup(scan.page[i], comparableClock, captureGap);
                std::wstring evidence;
                etl_profile::ProcessPair process;
                if (scan.options.processes)
                {
                    process = scan.processIndex.Lookup(scan.page[i], pair, comparableClock, captureGap || scan.unsupported);
                    evidence = ProcessPairJson(process, processRecords);
                }
                if (scan.options.images)
                {
                    const uint32_t pid = pair.pairedPid ? pair.before->pid : 0;
                    const auto image = scan.imageIndex.Lookup(scan.page[i], pid, comparableClock, captureGap);
                    evidence += ImageMatchJson(image, records);
                    if (scan.options.processes)
                    {
                        const auto bound = etl_profile::ImageInProcess(process, image, scan.processIndex.imageClock.reversed);
                        evidence += ImageProcessJson(process, image, bound);
                        etl_profile::BuildPair build;
                        if (scan.options.builds)
                        {
                            if (bound.paired)
                            {
                                const auto& witness = image.witnesses[0];
                                build = etl_profile::MatchBuildPair(scan.buildIndex.At(*witness.before, buildCoverage),
                                    scan.buildIndex.At(*witness.after, buildCoverage));
                            }
                            evidence += BuildPairJson(build, reference);
                        }
                        if (reference && !AppendReferenceEvidence(evidence, *reference, scan.imageIndex, image, bound,
                            scan.options.builds ? &build : nullptr)) { return {}; }
                    }
                }
                evidence += SettingsEvidenceJson(scan, scan.page[i], comparableClock, captureGap);
                result += SampleJson(scan.page[i], &pair, evidence, scan.options.processes);
            }
            else { result += SampleJson(scan.page[i], nullptr, SettingsEvidenceJson(scan, scan.page[i], comparableClock, captureGap)); }
        }
        if (scan.options.images)
        {
            AppendRecords(result, L"image_records", records, [&](const auto& e) {
                auto row = ImageEventJson(e, scan.imageIndex, scan.options.processes);
                if (scan.options.builds)
                {
                    row.pop_back();
                    row += BuildEndpointJson(scan.buildIndex.At(e, buildCoverage), buildRecords) + L"}";
                }
                return row;
            });
        }
        if (scan.options.builds) { AppendRecords(result, L"build_records", buildRecords, BuildEventJson); }
        if (scan.options.processes) { AppendRecords(result, L"process_records", processRecords, ProcessEventJson); }
        return result + L"]}";
    }

    EVENT_TRACE_LOGFILEW ConfigureLog(std::wstring& volumePath, Scan& scan)
    {
        EVENT_TRACE_LOGFILEW log{};
        log.LogFileName = volumePath.data();
        log.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
        log.EventRecordCallback = OnRecord;
        log.BufferCallback = OnBuffer;
        log.Context = &scan;
        return log;
    }

    ULONG ReplayIntervals(Scan& scan, std::wstring& path, const TRACE_LOGFILE_HEADER& original)
    {
        const TraceCounts first = scan;
        static_cast<TraceCounts&>(scan) = {};
        scan.replaying = true;
        auto log = ConfigureLog(path, scan);
        Trace replay;
        replay.handle = OpenTraceW(&log);
        if (replay.handle == INVALID_PROCESSTRACE_HANDLE) { return GetLastError(); }
        const auto status = ProcessTrace(&replay.handle, 1, nullptr, nullptr);
        if (status != ERROR_SUCCESS) { return status; }
        const auto& h = log.LogfileHeader;
        if (scan.replayMismatch || scan.replayedRows != scan.used || scan.budgetExceeded ||
            scan.records != first.records || scan.decoded != first.decoded || scan.unsupported != first.unsupported ||
            scan.processedBuffers != first.processedBuffers || scan.lossMarkers != first.lossMarkers ||
            h.StartTime.QuadPart != original.StartTime.QuadPart || h.EndTime.QuadPart != original.EndTime.QuadPart ||
            h.BootTime.QuadPart != original.BootTime.QuadPart || h.ReservedFlags != original.ReservedFlags ||
            h.PerfFreq.QuadPart != original.PerfFreq.QuadPart || h.NumberOfProcessors != original.NumberOfProcessors ||
            h.PointerSize != original.PointerSize || h.LogFileMode != original.LogFileMode ||
            h.BuffersWritten != original.BuffersWritten || h.BuffersLost != original.BuffersLost || h.EventsLost != original.EventsLost)
        { return ERROR_INVALID_DATA; }
        return ERROR_SUCCESS;
    }

}

static int ReadValidatedEtl(const std::vector<std::wstring>& args, Scan& scan)
{
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
    symbol_artifacts::Directories referenceParents;
    etl_profile::ReferenceImage reference;
    std::wstring referenceVolumePath;
    if (!scan.options.referencePath.empty())
    {
        std::filesystem::path referencePath;
        if (!symbol_artifacts::LocalRoot(scan.options.referencePath, &referencePath) ||
            !referenceParents.Pin(referencePath.parent_path(), false) ||
            !OpenSource(referencePath, referenceParents, reference.file, referenceVolumePath, ReferenceArtifactMaxBytes))
        { return Failure(scan.options, L"reference_unavailable", source.Sha256); }
        if (source.PathNamesFile(referenceVolumePath))
        { return Failure(scan.options, L"reference_is_trace", source.Sha256, 0, reference.file.Sha256); }
        if (reference.file.Sha256 != scan.options.referenceDigest)
        { return Failure(scan.options, L"reference_digest_mismatch", source.Sha256, 0, reference.file.Sha256); }
        if (!executable_image::ReadDiskPeIdentityHandle(reference.file.Handle(), &reference.pe, nullptr))
        { return Failure(scan.options, L"reference_invalid_pe", source.Sha256, 0, reference.file.Sha256); }
        if (scan.options.builds) { reference.build = etl_profile::ReadReferenceBuild(reference.file, reference.pe); }
        reference.leaf = referencePath.filename().wstring();
    }
    auto log = ConfigureLog(volumePath, scan);
    Trace trace;
    trace.handle = OpenTraceW(&log);
    if (trace.handle == INVALID_PROCESSTRACE_HANDLE) { return Failure(scan.options, L"open_trace_failed", source.Sha256, GetLastError()); }
    if (log.LogfileHeader.LogFileMode & EVENT_TRACE_FILE_MODE_NEWFILE) { return Failure(scan.options, L"segmented_source", source.Sha256); }
    if (scan.options.settings)
    {
        try { scan.settings.Prepare(); }
        catch (const std::bad_alloc&) { return Failure(scan.options, L"settings_index_unavailable", source.Sha256); }
    }
    if (scan.options.WithThreads())
    {
        try
        {
            scan.threadIndex.Prepare();
            if (scan.options.builds) { scan.buildIndex.Prepare(); }
            if (scan.options.images) { scan.imageIndex.Prepare(); }
            if (scan.options.processes) { scan.processIndex.Prepare(); }
        }
        catch (const std::bad_alloc&)
        { return Failure(scan.options, (scan.options.images || scan.options.processes) ? L"evidence_index_unavailable" : L"thread_index_unavailable", source.Sha256); }
    }
    const auto status = ProcessTrace(&trace.handle, 1, nullptr, nullptr);
    if (!source.PathNamesFile(volumePath) || !source.Unchanged()) { return Failure(scan.options, L"source_changed"); }
    if (scan.budgetExceeded) { return Failure(scan.options, L"record_budget_exceeded", source.Sha256); }
    if (status != ERROR_SUCCESS) { return Failure(scan.options, L"process_trace_failed", source.Sha256, status); }
    const auto accounting = AccountBuffers(scan, log.LogfileHeader);
    const bool partial = Partial(scan, accounting);
    if (scan.options.WithThreads() && scan.threadIndex.Complete()) { scan.threadIndex.Sort(); }
    if (!partial && scan.options.after > scan.matched) { return Failure(scan.options, L"cursor_out_of_range", source.Sha256); }
    if (scan.options.WithIntervals())
    {
        try { scan.history.Prepare(log.LogfileHeader.NumberOfProcessors, scan.switchPage.data(), scan.used); }
        catch (const std::bad_alloc&) { return Failure(scan.options, L"interval_index_unavailable", source.Sha256); }
        const auto replay = ReplayIntervals(scan, volumePath, log.LogfileHeader);
        if (!source.PathNamesFile(volumePath) || !source.Unchanged()) { return Failure(scan.options, L"source_changed"); }
        if (replay != ERROR_SUCCESS) { return Failure(scan.options, L"interval_replay_failed", source.Sha256, replay); }
    }
    if (scan.options.images && scan.imageIndex.Complete()) { scan.imageIndex.Sort(); }
    if (scan.options.processes && scan.processIndex.Complete()) { scan.processIndex.Sort(); }
    if (scan.options.builds)
    {
        try { scan.buildIndex.Sort(scan.imageIndex); }
        catch (const std::bad_alloc&) { return Failure(scan.options, L"evidence_index_unavailable", source.Sha256); }
    }
    const bool haveReference = !scan.options.referencePath.empty();
    const auto report = Report(scan, log.LogfileHeader, source, accounting, haveReference ? &reference : nullptr);
    if (haveReference && (!reference.file.PathNamesFile(referenceVolumePath) || !reference.file.Unchanged()))
    { return Failure(scan.options, L"reference_changed", source.Sha256); }
    if (report.empty()) { return Failure(scan.options, L"reference_read_failed", source.Sha256, 0, reference.file.Sha256); }
    return WriteCapabilityJson(report) ? (partial ? 1 : 0) : 2;
}

static int ReadSavedEtl(const std::vector<std::wstring>& args, bool switches)
{
    Scan scan;
    scan.options.switches = switches;
    if (Parse(args, scan.options))
    {
        return WriteWithDistinctInput(STD_OUTPUT_HANDLE, scan.options.referencePath, [&] { return ReadValidatedEtl(args, scan); });
    }
    const auto sink = GetStdHandle(STD_ERROR_HANDLE);
    const bool disk = GetFileType(sink) == FILE_TYPE_DISK;
    const auto references = disk ? std::count(args.begin(), args.end(), L"--reference-image") : 0;
    std::vector<DistinctArtifactInput> guards(disk ? 1 + references : 0);
    if (disk && !args.empty())
    {
        if (!guards[0].Hold(sink, args[0])) { return 2; }
        size_t guard = 1;
        for (size_t i = 0; i + 1 < args.size(); ++i)
        {
            if (args[i] == L"--reference-image" && !guards[guard++].Hold(sink, args[i + 1])) { return 2; }
        }
    }
    std::wcerr << (switches ?
        L"usage: KnLiveDbg.exe --etl-switches <local.etl> --sha256 <digest> [--after N] [--limit 1..128] [--intervals] [--thread-id N] [--capture-settings]\n" :
        L"usage: KnLiveDbg.exe --etl-profile <local.etl> --sha256 <digest> [--after N] [--limit 1..128] [--thread-evidence] [--image-evidence] [--process-evidence] [--build-evidence] [--capture-settings] [--reference-image <local.pe> <pe-sha256>]\n");
    return 2;
}

int RunEtlProfile(const std::vector<std::wstring>& args)
{
    return ReadSavedEtl(args, false);
}

int RunEtlSwitches(const std::vector<std::wstring>& args)
{
    return ReadSavedEtl(args, true);
}
