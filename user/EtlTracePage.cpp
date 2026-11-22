#include "EtlTracePage.h"
#include "EtlClrEvidence.h"
#include "TraceJsonFields.h"
#include <set>

namespace
{
    using trace_json::Object;
    using mcpjson::Quote;

    bool Label(const std::wstring& raw, const wchar_t* expected)
    {
        std::wstring value;
        return trace_json::Text(raw, &value) && value == expected;
    }

    template<typename T>
    bool UInt(const std::wstring& raw, T& out)
    {
        uint64_t value = 0;
        if (!trace_json::Decimal(raw, &value) || value > static_cast<T>(-1)) { return false; }
        out = static_cast<T>(value);
        return true;
    }

    bool SignedString(const std::wstring& raw, int64_t& out)
    {
        std::wstring text;
        if (!trace_json::Text(raw, &text, 20)) { return false; }
        const bool negative = text.front() == L'-';
        uint64_t value = 0;
        if (!trace_json::Decimal(text.substr(negative ? 1 : 0), &value) || (negative && !value) ||
            value > uint64_t{INT64_MAX} + static_cast<unsigned>(negative)) { return false; }
        out = !negative ? static_cast<int64_t>(value) : -static_cast<int64_t>(value - 1) - 1;
        return true;
    }

    bool HexString(const std::wstring& raw, uint64_t& out)
    {
        std::wstring text;
        if (!trace_json::Text(raw, &text, 18) || text.size() < 3 || text.compare(0, 2, L"0x") ||
            (text.size() > 3 && text[2] == L'0')) { return false; }
        out = 0;
        for (size_t i = 2; i < text.size(); ++i)
        {
            const auto c = text[i];
            if (c >= L'0' && c <= L'9') { out = (out << 4) | (c - L'0'); }
            else if (c >= L'a' && c <= L'f') { out = (out << 4) | (c - L'a' + 10); }
            else { return false; }
        }
        return true;
    }

    bool OptionalField(const Object& obj, const wchar_t* key, bool expected, wchar_t type = L'{')
    {
        const auto it = obj.find(key);
        return it == obj.end() ? !expected : expected && it->second.front() == type;
    }

    struct EvidenceTables
    {
        bool thread, image, process, reference, build, settings, clr;

        bool Valid(const Object& root, unsigned version) const
        {
            const unsigned schema = clr ? 8 : settings ? 7 : build ? 6 : reference ? 5 : process ? 4 : image ? 3 : thread ? 2 : 1;
            return version == schema && (!clr || process) && (!(image || process) || thread) && (!(build || reference) || (image && process)) &&
                OptionalField(root, L"thread_source", thread) && OptionalField(root, L"image_source", image) &&
                OptionalField(root, L"process_source", process) && OptionalField(root, L"reference_image", reference) &&
                OptionalField(root, L"build_source", build) && OptionalField(root, L"capture_settings", settings) &&
                OptionalField(root, L"reference_build", build && reference) &&
                OptionalField(root, L"image_records", image, L'[') && OptionalField(root, L"process_records", process, L'[') &&
                OptionalField(root, L"build_records", build, L'[') && OptionalField(root, L"clr_source", clr) &&
                OptionalField(root, L"clr_records", clr, L'[');
        }

        bool Row(const Object& row) const
        {
            return OptionalField(row, L"thread_evidence", thread) && OptionalField(row, L"image_evidence", image) &&
                OptionalField(row, L"process_evidence", process) && OptionalField(row, L"image_process_evidence", image && process) &&
                OptionalField(row, L"reference_evidence", reference) && OptionalField(row, L"build_evidence", build) &&
                OptionalField(row, L"capture_setting_evidence", settings) && OptionalField(row, L"clr_evidence", clr);
        }
    };

    bool DeclaredScope(const std::wstring& raw)
    {
        Object fields;
        if (!trace_json::Members(raw, {L"evidence", L"producer_authenticity", L"verified_level", L"sampled_process_id",
            L"thread_lifetime", L"address_space", L"vm", L"vtl", L"code_version", L"capture_privilege",
            L"capture_enable_flags", L"stack_capture_policy", L"sample_loss_intervals"}, &fields)) { return false; }
        for (const auto& [key, value] : fields)
        {
            if (key == L"evidence") { if (!Label(value, L"reported_cpu_sample")) { return false; } }
            else if (key == L"producer_authenticity") { if (!Label(value, L"unverified")) { return false; } }
            else if (key == L"verified_level") { if (!Label(value, L"unqualified")) { return false; } }
            else if (value != L"null") { return false; }
        }
        return true;
    }

    bool ClockAndBuffers(const Object& root, EtlTracePage& p, bool& comparableCoverage)
    {
        Object clock, h;
        uint32_t type = 0, width = 0, cpus = 0, mode = 0, written = 0, eventsLost = 0, buffersLost = 0;
        int64_t frequency = 0, startTime = 0, endTime = 0;
        if (!trace_json::Members(root.at(L"clock"), {L"raw_type", L"kind", L"header_perf_frequency"}, &clock) ||
            !UInt(clock.at(L"raw_type"), type) || !SignedString(clock.at(L"header_perf_frequency"), frequency) ||
            !trace_json::Members(root.at(L"log_header"), {L"pointer_bytes", L"processors", L"start_filetime", L"end_filetime",
                L"log_mode", L"events_lost", L"buffers_lost", L"buffers_written"}, &h) ||
            !UInt(h.at(L"pointer_bytes"), width) || !UInt(h.at(L"processors"), cpus) ||
            !SignedString(h.at(L"start_filetime"), startTime) || !SignedString(h.at(L"end_filetime"), endTime) ||
            !UInt(h.at(L"log_mode"), mode) || !UInt(h.at(L"events_lost"), eventsLost) ||
            !UInt(h.at(L"buffers_lost"), buffersLost) || !UInt(h.at(L"buffers_written"), written)) { return false; }
        p.ClockKind = type == 1 ? L"qpc" : type == 2 ? L"system_time" : type == 3 ? L"cpu_cycle" : L"unknown";
        if (!Label(clock.at(L"kind"), p.ClockKind.c_str())) { return false; }
        if (type == 1 && frequency > 0) { p.TicksPerSecond = static_cast<uint64_t>(frequency); }
        else if (type == 2) { p.TicksPerSecond = 10'000'000; }
        const auto accounting = etl_profile::AccountBuffers(mode, written, p.BuffersProcessed);
        p.BufferComparison = etl_profile::BufferComparisonName(accounting);
        if (!Label(root.at(L"buffer_comparison"), p.BufferComparison.c_str()) || (!p.Partial &&
            etl_profile::RequiresPartialPage(mode, accounting)))
        { return false; }
        // These exact objects contain only the checked header fields. The capture FILETIMEs
        // and log-wide loss counters do not supply sample-clock bounds or a sample loss count.
        comparableCoverage = p.TicksPerSecond && accounting == etl_profile::BufferAccounting::Matched &&
            !eventsLost && !buffersLost && !p.Unsupported && !p.LossMarkers;
        p.ClockJson = root.at(L"clock");
        p.LogHeaderJson = root.at(L"log_header");
        return true;
    }

    bool ClrPointFromPage(const std::wstring& raw, etl_profile::ClrPoint& p)
    {
        Object f;
        if (!trace_json::Members(raw, {L"record_ordinal", L"raw_timestamp", L"header_process_id", L"logger_id", L"provider_guid",
            L"event_id", L"version", L"opcode", L"action", L"method_start", L"method_size", L"method_id", L"module_id",
            L"method_token", L"method_flags", L"clr_instance_id", L"rejit_id"}, &f)) { return false; }
        auto& m = p.method;
        uint64_t token = 0, flags = 0;
        if (!UInt(f[L"record_ordinal"], p.record) || !p.record || !SignedString(f[L"raw_timestamp"], p.tick) ||
            !UInt(f[L"header_process_id"], p.pid) || !p.pid || p.pid == UINT32_MAX || !UInt(f[L"logger_id"], p.logger) ||
            !UInt(f[L"event_id"], m.EventId) || !UInt(f[L"version"], m.EventVersion) || !UInt(f[L"opcode"], p.opcode) ||
            !HexString(f[L"method_start"], m.Start) || !UInt(f[L"method_size"], m.Size) || !m.Size || m.Size > UINT32_MAX ||
            m.Start < 0x10000 || m.Start > 0x00007fffffffffffULL || m.Size - 1 > 0x00007fffffffffffULL - m.Start ||
            !HexString(f[L"method_id"], m.MethodId) || !HexString(f[L"module_id"], m.ModuleId) ||
            !HexString(f[L"method_token"], token) || token > UINT32_MAX || !HexString(f[L"method_flags"], flags) || flags > UINT32_MAX)
        { return false; }
        m.MethodToken = static_cast<uint32_t>(token);
        m.MethodFlags = static_cast<uint32_t>(flags);
        m.RundownProvider = Label(f[L"provider_guid"], L"a669021c-c450-4609-a035-5af59af4df18");
        if (!m.RundownProvider && !Label(f[L"provider_guid"], L"e13c0d23-ccbc-4e12-931b-d9cc2eee27e4")) { return false; }
        EVENT_HEADER h{};
        h.ProviderId = m.RundownProvider ? kClrRundown : kClrRuntime;
        h.EventDescriptor.Id = m.EventId;
        h.EventDescriptor.Version = m.EventVersion;
        h.EventDescriptor.Opcode = p.opcode;
        h.EventDescriptor.Task = m.RundownProvider ? 1 : 9;
        m.Observation = ClassifyClrMethodEvent(h);
        if (m.Observation == ClrMethodAction::Ignore || m.Observation == ClrMethodAction::Unsupported ||
            !Label(f[L"action"], m.Observation == ClrMethodAction::Load ? L"load" :
                m.Observation == ClrMethodAction::Unload ? L"unload" : L"rundown")) { return false; }
        return (m.EventVersion >= 1 ? UInt(f[L"clr_instance_id"], m.RuntimeInstance.emplace()) : f[L"clr_instance_id"] == L"null") &&
            (m.EventVersion == 2 ? HexString(f[L"rejit_id"], m.ReJitId.emplace()) : f[L"rejit_id"] == L"null");
    }

    struct PageBoundary
    {
        uint32_t record = 0, pid = 0, tid = 0, parent = 0, session = 0;
        uint8_t version = 0, width = 0;
        uint16_t logger = 0;
        uint8_t opcode = 0;
        int64_t tick = 0;
    };

    bool Boundary(const std::wstring& raw, bool thread, PageBoundary& b)
    {
        Object f;
        return trace_json::ReadObject(raw, &f) && UInt(f[L"record_ordinal"], b.record) && b.record &&
            UInt(f[L"payload_pid"], b.pid) && UInt(f[L"opcode"], b.opcode) && UInt(f[L"logger_id"], b.logger) &&
            SignedString(f[L"raw_timestamp"], b.tick) &&
            Label(f[L"event"], b.opcode == 39 ? L"defunct" : etl_profile::ThreadEventName(b.opcode)) &&
            (thread ? UInt(f[L"payload_tid"], b.tid) : UInt(f[L"version"], b.version) && UInt(f[L"pointer_bytes"], b.width) &&
                UInt(f[L"parent_pid"], b.parent) && UInt(f[L"session_id"], b.session));
    }

    struct ClrPage
    {
        std::map<uint32_t, etl_profile::ClrPoint> methods;
        std::map<uint32_t, PageBoundary> processes;
        std::set<uint32_t> used;
        struct Claim
        {
            const etl_profile::ClrPoint* load;
            const etl_profile::ClrPoint* unload;
            uint32_t sampleRecord;
            uint64_t ip;
        };
        std::vector<Claim> claims;
        bool usable = false, indexTruncated = false;

        bool Read(const Object& root, uint32_t total, bool captureOk, bool partial)
        {
            Object source, threads, procs;
            uint32_t loads = 0, unloads = 0, inventory = 0, unsupported = 0, unknown = 0, retained = 0;
            if (!trace_json::Members(root.at(L"clr_source"), {L"load_events", L"unload_events", L"rundown_events", L"unsupported_events",
                L"unknown_pid_events", L"retained_events", L"clock_reversed", L"runtime_bytes_observed"}, &source) ||
                !UInt(source[L"load_events"], loads) || !UInt(source[L"unload_events"], unloads) ||
                !UInt(source[L"rundown_events"], inventory) || !UInt(source[L"unsupported_events"], unsupported) ||
                !UInt(source[L"unknown_pid_events"], unknown) || unknown > unsupported || !UInt(source[L"retained_events"], retained) ||
                source[L"runtime_bytes_observed"] != L"false" || (source[L"clock_reversed"] != L"false" && source[L"clock_reversed"] != L"true") ||
                !trace_json::ReadObject(root.at(L"thread_source"), &threads) || !trace_json::ReadObject(root.at(L"process_source"), &procs))
            { return false; }
            const uint64_t seen = uint64_t{loads} + unloads + inventory + unsupported;
            if (seen > total || retained != (std::min)(seen, static_cast<uint64_t>(etl_profile::MaxClrEvents))) { return false; }
            indexTruncated = seen != retained;
            if (indexTruncated && !partial) { return false; }
            const auto complete = [&](Object& family) {
                uint32_t decoded = 0, kept = 0;
                return UInt(family[L"decoded_events"], decoded) && UInt(family[L"retained_events"], kept) &&
                    decoded >= 2 && decoded <= total && decoded == kept && family[L"unsupported_events"] == L"0";
            };
            usable = captureOk && !indexTruncated && !unknown && source[L"clock_reversed"] == L"false" &&
                complete(threads) && complete(procs) && procs[L"source_clock_reversed"] == L"false" &&
                Label(threads[L"provider_guid"], L"3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c") && threads[L"version"] == L"3" &&
                Label(procs[L"provider_guid"], L"3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c");
            std::vector<std::wstring> rows;
            if (!trace_json::Array(root.at(L"clr_records"), 4 * etl_profile::MaxPageRows, &rows) || rows.size() > retained) { return false; }
            uint32_t last = 0;
            for (const auto& raw : rows)
            {
                etl_profile::ClrPoint point;
                if (!ClrPointFromPage(raw, point) || point.record <= last || point.record > total) { return false; }
                last = point.record;
                auto& count = point.method.Observation == ClrMethodAction::Load ? loads :
                    point.method.Observation == ClrMethodAction::Unload ? unloads : inventory;
                if (!count) { return false; }
                --count;
                methods.emplace(last, point);
            }
            rows.clear();
            if (!trace_json::Array(root.at(L"process_records"), 2 * etl_profile::MaxPageRows, &rows)) { return false; }
            last = 0;
            for (const auto& raw : rows)
            {
                PageBoundary b;
                if (!Boundary(raw, false, b) || b.record <= last || b.record > total || methods.count(b.record)) { return false; }
                last = b.record;
                processes.emplace(last, b);
            }
            return true;
        }

        bool ProcessContains(const Object& fields, const EtlTraceSample& s, const etl_profile::ClrPoint& load,
            const etl_profile::ClrPoint& unload, uint32_t start) const
        {
            Object process, thread, generation;
            PageBoundary t0, t1;
            uint32_t a = 0, b = 0, pid = 0, threadPid = 0, candidate = 0, generationStart = 0;
            if (!trace_json::ReadObject(fields.at(L"process_evidence"), &process) || !Label(process[L"relation"], L"start_end") ||
                !trace_json::ReadObject(process[L"recorded_generation"], &generation) ||
                !UInt(generation[L"payload_pid"], pid) || !UInt(generation[L"start_record"], generationStart) ||
                !UInt(process[L"candidate_pid"], candidate) || candidate != pid || !UInt(process[L"before_record"], a) ||
                !UInt(process[L"after_record"], b) || start != a || start != generationStart || !processes.count(a) || !processes.count(b) ||
                !trace_json::ReadObject(fields.at(L"thread_evidence"), &thread) || !UInt(thread[L"paired_record_pid"], threadPid) ||
                threadPid != pid || !Boundary(thread[L"before"], true, t0) || !Boundary(thread[L"after"], true, t1)) { return false; }
            const auto& p0 = processes.at(a);
            const auto& p1 = processes.at(b);
            return p0.opcode == 1 && p1.opcode == 2 && p0.pid == pid && p1.pid == pid && load.pid == pid && unload.pid == pid &&
                p0.parent == p1.parent && p0.session == p1.session && p0.version == p1.version && p0.version >= 2 && p0.version <= 4 &&
                p0.width == p1.width && (p0.width == 4 || p0.width == 8) &&
                (Label(process[L"opaque_key_comparison"], L"equal") || Label(process[L"opaque_key_comparison"], L"one_unreported") ||
                    Label(process[L"opaque_key_comparison"], L"unreported")) &&
                !methods.count(t0.record) && !methods.count(t1.record) && !processes.count(t0.record) && !processes.count(t1.record) &&
                t0.pid == pid && t1.pid == pid && t0.tid == s.tid && t1.tid == s.tid && s.tid && s.tid != UINT32_MAX &&
                (t0.opcode == 1 || t0.opcode == 3) && (t1.opcode == 2 || t1.opcode == 4) &&
                Label(thread[L"relation"], t0.opcode == 1 && t1.opcode == 2 ? L"start_end" : L"rundown_bracket") &&
                p0.logger == s.loggerId && p1.logger == s.loggerId && t0.logger == s.loggerId && t1.logger == s.loggerId &&
                a < load.record && unload.record < b && p0.tick < load.tick && unload.tick < p1.tick &&
                a < t0.record && t0.record < s.record && s.record < t1.record && t1.record < b &&
                p0.tick < t0.tick && t0.tick < s.timestamp && s.timestamp < t1.tick && t1.tick < p1.tick;
        }

        bool Sample(const Object& fields, EtlTraceSample& s)
        {
            Object f;
            std::wstring relation;
            uint32_t count = 0;
            if (!trace_json::Members(fields.at(L"clr_evidence"), {L"relation", L"candidate_ranges", L"process_start_record", L"method_offset", L"witnesses"}, &f) ||
                !trace_json::Text(f[L"relation"], &relation, 40) || !UInt(f[L"candidate_ranges"], count) || count > etl_profile::MaxClrEvents ||
                methods.count(s.record) || processes.count(s.record)) { return false; }
            static const wchar_t* const reasons[] = {L"load_unload", L"no_covering_declaration", L"index_limit", L"process_generation_unavailable",
                L"coverage_unqualified", L"clock_unqualified", L"logger_conflict", L"conflicting_declarations", L"overlapping_ranges",
                L"unload_only", L"preceding_declaration", L"method_identity_conflict", L"method_identity_unavailable", L"rundown_bracket"};
            if ((relation == L"index_limit") != indexTruncated || std::find(std::begin(reasons), std::end(reasons), relation) == std::end(reasons)) { return false; }
            const bool noWitness = relation == L"index_limit" || relation == L"process_generation_unavailable" ||
                relation == L"no_covering_declaration";
            if ((noWitness && count != 0) || (relation == L"overlapping_ranges" && count <= 1) ||
                (!noWitness && relation != L"overlapping_ranges" && relation != L"coverage_unqualified" && relation != L"clock_unqualified" && count != 1))
            { return false; }
            std::vector<std::wstring> witnesses;
            if (!trace_json::Array(f[L"witnesses"], 2, &witnesses) || witnesses.size() != (std::min)(count, 2u)) { return false; }
            const etl_profile::ClrPoint* before = nullptr;
            const etl_profile::ClrPoint* after = nullptr;
            for (const auto& raw : witnesses)
            {
                Object w;
                if (!trace_json::Members(raw, {L"before_record", L"after_record"}, &w)) { return false; }
                const auto ref = [&](const std::wstring& field, bool prior, const etl_profile::ClrPoint*& value) {
                    value = nullptr;
                    if (field == L"null") { return true; }
                    uint32_t ordinal = 0;
                    if (!UInt(field, ordinal) || !methods.count(ordinal) || (prior ? ordinal >= s.record : ordinal <= s.record)) { return false; }
                    value = &methods.at(ordinal);
                    used.insert(ordinal);
                    return true;
                };
                if (!ref(w[L"before_record"], true, before) || !ref(w[L"after_record"], false, after) || (!before && !after)) { return false; }
            }
            s.ReportedClrFields = L",\"reported_clr_relation\":" + Quote(relation) + L",\"reported_clr_method\":";
            if (relation != L"load_unload")
            {
                s.ReportedClrFields += L"null";
                return f[L"method_offset"] == L"null" && f[L"process_start_record"] == L"null";
            }
            uint64_t offset = 0;
            uint32_t start = 0;
            if (!usable || count != 1 || !before || !after || before->method.Observation != ClrMethodAction::Load ||
                after->method.Observation != ClrMethodAction::Unload || !SameClrMethodRange(before->method, after->method) ||
                !before->method.MethodId || !before->method.ModuleId || !etl_profile::ClrCovers(before, s.ip) ||
                before->logger != s.loggerId || after->logger != s.loggerId || before->tick >= s.timestamp || after->tick <= s.timestamp ||
                !HexString(f[L"method_offset"], offset) || offset != s.ip - before->method.Start ||
                !UInt(f[L"process_start_record"], start) || !ProcessContains(fields, s, *before, *after, start)) { return false; }
            // A page contains only cited points. Reject contradictions visible
            // within this bracket without inferring any missing ETL records.
            for (auto it = methods.upper_bound(before->record); it != methods.end() && it->first < after->record; ++it)
            {
                const auto& point = it->second;
                if (point.pid == before->pid && point.method.Start == before->method.Start &&
                    (point.method.Observation != ClrMethodAction::Rundown || !SameClrMethodRange(before->method, point.method)))
                { return false; }
            }
            // Two rows may cite the same lifetime. Distinct claimed lifetimes for
            // the same PID cannot both cover either attributed IP at its sample.
            for (const auto& c : claims)
            {
                if (c.load->pid != before->pid || (c.load == before && c.unload == after)) { continue; }
                if ((c.load->record < s.record && s.record < c.unload->record && etl_profile::ClrCovers(c.load, s.ip)) ||
                    (before->record < c.sampleRecord && c.sampleRecord < after->record && etl_profile::ClrCovers(before, c.ip)))
                { return false; }
            }
            claims.push_back({before, after, s.record, s.ip});
            const auto& m = before->method;
            s.ReportedClrFields += L"{\"process_start_record\":" + std::to_wstring(start) + L",\"pid\":" + std::to_wstring(before->pid) +
                L",\"load_record\":" + std::to_wstring(before->record) + L",\"unload_record\":" + std::to_wstring(after->record) +
                L",\"method_id\":" + Quote(std::to_wstring(m.MethodId)) + L",\"module_id\":" + Quote(std::to_wstring(m.ModuleId)) +
                L",\"method_start\":" + Quote(std::to_wstring(m.Start)) + L",\"method_size\":" + std::to_wstring(m.Size) +
                L",\"method_offset\":" + Quote(std::to_wstring(offset)) + L",\"method_token\":" + std::to_wstring(m.MethodToken) +
                L",\"method_flags\":" + std::to_wstring(m.MethodFlags) + L",\"clr_instance_id\":" +
                (m.RuntimeInstance ? std::to_wstring(*m.RuntimeInstance) : L"null") + L",\"rejit_id\":" +
                (m.ReJitId ? Quote(std::to_wstring(*m.ReJitId)) : L"null") + L",\"runtime_bytes_observed\":false}";
            return true;
        }
    };

    bool SampleRow(const std::wstring& raw, const EvidenceTables& evidence, etl_profile::Sample& s, Object& r)
    {
        if (!trace_json::ReadObject(raw, &r) || !trace_json::HasFields(r, {L"sample_ordinal", L"record_ordinal", L"raw_timestamp",
            L"cpu", L"cpu_field", L"instruction_pointer", L"sampled_thread_id", L"count_field", L"reserved_field", L"pointer_bytes",
            L"header_thread_id", L"header_process_id", L"header_flags", L"logger_id", L"event_keyword", L"event_level",
            L"event_channel", L"event_task", L"extended_data_items", L"stack_extension_items"}, {L"thread_evidence", L"image_evidence",
            L"process_evidence", L"image_process_evidence", L"reference_evidence", L"build_evidence", L"capture_setting_evidence", L"clr_evidence"}) ||
            !evidence.Row(r) || !UInt(r.at(L"sample_ordinal"), s.ordinal) || !UInt(r.at(L"record_ordinal"), s.record) ||
            !SignedString(r.at(L"raw_timestamp"), s.timestamp) || !UInt(r.at(L"cpu"), s.cpu) ||
            !HexString(r.at(L"instruction_pointer"), s.ip) || !UInt(r.at(L"sampled_thread_id"), s.tid) ||
            !UInt(r.at(L"count_field"), s.count) || !UInt(r.at(L"reserved_field"), s.reserved) ||
            !UInt(r.at(L"pointer_bytes"), s.width) || !UInt(r.at(L"header_thread_id"), s.headerTid) ||
            !UInt(r.at(L"header_process_id"), s.headerPid) || !UInt(r.at(L"header_flags"), s.flags) ||
            !UInt(r.at(L"logger_id"), s.loggerId) || !HexString(r.at(L"event_keyword"), s.keyword) ||
            !UInt(r.at(L"event_level"), s.level) || !UInt(r.at(L"event_channel"), s.channel) || !UInt(r.at(L"event_task"), s.task) ||
            !UInt(r.at(L"extended_data_items"), s.extendedItems) || !UInt(r.at(L"stack_extension_items"), s.stackItems))
        { return false; }
        EVENT_HEADER h{};
        h.EventDescriptor.Version = 2;
        h.Flags = s.flags;
        const bool indexed = (s.flags & EVENT_HEADER_FLAG_PROCESSOR_INDEX) != 0;
        return s.width && s.width == etl_profile::ClassicPointerWidth(h, 2) && (s.width == 8 || s.ip <= UINT32_MAX) &&
            s.stackItems <= s.extendedItems && s.cpu <= (indexed ? uint32_t{UINT16_MAX} : uint32_t{UINT8_MAX}) &&
            Label(r.at(L"cpu_field"), indexed ? L"processor_index" : L"processor_number");
    }

    std::wstring N(uint64_t n) { return Quote(std::to_wstring(n)); }
}

bool ParseEtlTracePage(const Object& root, unsigned version, EtlTracePage& p, const std::atomic<bool>* cancellation)
{
    if (!trace_json::HasFields(root, {L"schema", L"status", L"source_sha256", L"source_bytes", L"provider_guid",
        L"event_id", L"opcode", L"version", L"clock", L"log_header", L"qualification", L"records_seen", L"decoded_samples",
        L"buffers_processed", L"buffer_comparison", L"loss_marker_records", L"unsupported_profile_records", L"after",
        L"next_after", L"samples"}, {L"thread_source", L"image_source", L"process_source", L"reference_image", L"build_source",
        L"capture_settings", L"reference_build", L"image_records", L"process_records", L"build_records", L"clr_source", L"clr_records"})) { return false; }
    const EvidenceTables tables{root.count(L"thread_source") != 0, root.count(L"image_source") != 0,
        root.count(L"process_source") != 0, root.count(L"reference_image") != 0, root.count(L"build_source") != 0,
        root.count(L"capture_settings") != 0, root.count(L"clr_source") != 0};
    p.Schema = L"kn.etl_profile.v" + std::to_wstring(version);
    p.Partial = Label(root.at(L"status"), L"partial");
    bool comparableCoverage = false;
    if ((!p.Partial && !Label(root.at(L"status"), L"read")) || !Label(root.at(L"schema"), p.Schema.c_str()) || !tables.Valid(root, version) ||
        !Label(root.at(L"provider_guid"), L"ce1dbfb4-137e-4da6-87b0-3f59aa102cbc") ||
        root.at(L"event_id") != L"0" || root.at(L"opcode") != L"46" || root.at(L"version") != L"2" ||
        !trace_json::Text(root.at(L"source_sha256"), &p.EtlSha256, 64) || p.EtlSha256.size() != 64 ||
        p.EtlSha256.find_first_not_of(L"0123456789abcdef") != std::wstring::npos ||
        !UInt(root.at(L"source_bytes"), p.EtlBytes) || !p.EtlBytes || p.EtlBytes > etl_profile::MaxFileBytes ||
        !UInt(root.at(L"records_seen"), p.RecordsSeen) || p.RecordsSeen > etl_profile::MaxEventRecords ||
        !UInt(root.at(L"decoded_samples"), p.Decoded) || !UInt(root.at(L"unsupported_profile_records"), p.Unsupported) ||
        !UInt(root.at(L"loss_marker_records"), p.LossMarkers) || uint64_t{p.Decoded} + p.Unsupported + p.LossMarkers > p.RecordsSeen ||
        !UInt(root.at(L"after"), p.After) || p.After > etl_profile::MaxEventRecords || (!p.Partial && p.After > p.Decoded) ||
        !UInt(root.at(L"buffers_processed"), p.BuffersProcessed) || !ClockAndBuffers(root, p, comparableCoverage) ||
        !DeclaredScope(root.at(L"qualification"))) { return false; }
    ClrPage clr;
    if (tables.clr && !clr.Read(root, p.RecordsSeen, comparableCoverage, p.Partial)) { return false; }
    std::vector<std::wstring> rows;
    if (!trace_json::Array(root.at(L"samples"), etl_profile::MaxPageRows, &rows)) { return false; }
    for (const auto& raw : rows)
    {
        if (cancellation && cancellation->load()) { return false; }
        EtlTraceSample s{};
        Object fields;
        if (!SampleRow(raw, tables, s, fields) || s.ordinal != p.After + p.Rows.size() + 1 || s.ordinal > p.Decoded ||
            s.record < s.ordinal || s.record > p.RecordsSeen - (p.Decoded - s.ordinal)) { return false; }
        if (tables.clr && !clr.Sample(fields, s)) { return false; }
        if (!p.Rows.empty())
        {
            if (p.Rows.back().record >= s.record) { return false; }
            p.ReversedTicks |= p.Rows.back().timestamp > s.timestamp;
        }
        p.Rows.push_back(s);
    }
    if (clr.used.size() != clr.methods.size() || (p.ReversedTicks && !clr.claims.empty())) { return false; }
    const auto end = p.After + static_cast<uint32_t>(p.Rows.size());
    if (end < p.Decoded)
    {
        uint32_t next = 0;
        if (p.Rows.empty() || !UInt(root.at(L"next_after"), next) || next != end) { return false; }
        p.NextAfter = next;
    }
    else if (root.at(L"next_after") != L"null") { return false; }
    return true;
}

std::wstring EtlTraceQueryFields(const EtlTracePage& p, size_t offset, size_t end, const std::wstring& cursor)
{
    std::wstring out = L",\"source\":{\"kind\":\"cpu_sample\",\"provider_guid\":\"ce1dbfb4-137e-4da6-87b0-3f59aa102cbc\","
        L"\"event_id\":0,\"opcode\":46,\"version\":2,\"native_schema\":" + Quote(p.Schema) +
        L",\"reported_etl_sha256\":" + Quote(p.EtlSha256) + L",\"reported_etl_bytes\":" + N(p.EtlBytes) +
        L",\"etl_reopened\":false,\"producer_authenticity\":\"unverified\",\"capture_privilege\":null,"
        L"\"capture_enable_flags\":null,\"stack_capture_policy\":null,\"target_id\":null,\"boot_id\":null,\"vm_id\":null,"
        L"\"vtl\":null,\"architecture\":null,"
        L"\"clock_alignment\":\"not_established\",\"clock_domain\":" + Quote(p.ClockKind) +
        L",\"ticks_per_second\":" + (p.TicksPerSecond ? N(*p.TicksPerSecond) : L"null") +
        L",\"first_tick\":null,\"last_tick\":null,\"clock\":" + p.ClockJson + L",\"log_header\":" + p.LogHeaderJson + L"}" +
        L",\"records_lost\":null,\"sequence_gaps\":null,\"loss_intervals\":null,\"address_spaces\":[],\"code_versions\":[]" +
        L",\"source_page\":{\"status\":" + Quote(p.Partial ? L"partial" : L"read") + L",\"source_after\":" + std::to_wstring(p.After) +
        L",\"source_next_after\":" + (p.NextAfter ? std::to_wstring(*p.NextAfter) : L"null") +
        L",\"records_seen\":" + std::to_wstring(p.RecordsSeen) + L",\"decoded_samples\":" + std::to_wstring(p.Decoded) +
        L",\"unsupported_profile_records\":" + std::to_wstring(p.Unsupported) + L",\"buffers_processed\":" + std::to_wstring(p.BuffersProcessed) +
        L",\"buffer_comparison\":" + Quote(p.BufferComparison) + L",\"loss_marker_records\":" + std::to_wstring(p.LossMarkers) +
        L",\"page_clock_reversed\":" + (p.ReversedTicks ? L"true}" : L"false}") +
        L",\"samples_total\":" + std::to_wstring(p.Rows.size()) + L",\"offset\":" + std::to_wstring(offset) +
        L",\"next_cursor\":" + Quote(cursor) + L",\"query_complete\":" + (end == p.Rows.size() ? L"true" : L"false") + L",\"samples\":[";
    for (size_t i = offset; i < end; ++i)
    {
        const auto& s = p.Rows[i];
        if (i != offset) { out += L','; }
        out += L"{\"sequence\":" + N(s.ordinal) + L",\"record_ordinal\":" + std::to_wstring(s.record) +
            L",\"tick\":" + Quote(std::to_wstring(s.timestamp)) + L",\"cpu\":" + N(s.cpu) +
            L",\"tid\":" + N(s.tid) + L",\"ip\":" + N(s.ip) + L",\"space\":null,\"thread_create_time\":null,\"code_version\":null" +
            L",\"logger_id\":" + std::to_wstring(s.loggerId) + L",\"pointer_bytes\":" + std::to_wstring(s.width) +
            L",\"count_field\":" + std::to_wstring(s.count) + L",\"reserved_field\":" + std::to_wstring(s.reserved) +
            L",\"cpu_field\":" + Quote(s.flags & EVENT_HEADER_FLAG_PROCESSOR_INDEX ? L"processor_index" : L"processor_number") +
            L",\"header_flags\":" + std::to_wstring(s.flags) + L",\"header_thread_id\":" + std::to_wstring(s.headerTid) +
            L",\"header_process_id\":" + std::to_wstring(s.headerPid) + L",\"event_keyword_decimal\":" + N(s.keyword) +
            L",\"event_level\":" + std::to_wstring(s.level) + L",\"event_channel\":" + std::to_wstring(s.channel) +
            L",\"event_task\":" + std::to_wstring(s.task) + L",\"extended_data_items\":" + std::to_wstring(s.extendedItems) +
            L",\"stack_extension_items\":" + std::to_wstring(s.stackItems) + s.ReportedClrFields +
            L",\"reported_level\":\"X2\",\"qualified_reported_level\":\"unqualified\",\"verified_level\":\"unqualified\","
            L"\"qualification\":\"reported_sample_without_authenticated_context\",\"loss_interval_overlap\":null}";
    }
    return out + L"],\"live_backend_opened\":false,\"raw_decoder_used\":false}";
}
