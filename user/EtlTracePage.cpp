#include "EtlTracePage.h"
#include "TraceJsonFields.h"

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
        bool thread, image, process, reference, build, settings;

        bool Valid(const Object& root, unsigned version) const
        {
            const unsigned schema = settings ? 7 : build ? 6 : reference ? 5 : process ? 4 : image ? 3 : thread ? 2 : 1;
            return version == schema && (!(image || process) || thread) && (!(build || reference) || (image && process)) &&
                OptionalField(root, L"thread_source", thread) && OptionalField(root, L"image_source", image) &&
                OptionalField(root, L"process_source", process) && OptionalField(root, L"reference_image", reference) &&
                OptionalField(root, L"build_source", build) && OptionalField(root, L"capture_settings", settings) &&
                OptionalField(root, L"reference_build", build && reference) &&
                OptionalField(root, L"image_records", image, L'[') && OptionalField(root, L"process_records", process, L'[') &&
                OptionalField(root, L"build_records", build, L'[');
        }

        bool Row(const Object& row) const
        {
            return OptionalField(row, L"thread_evidence", thread) && OptionalField(row, L"image_evidence", image) &&
                OptionalField(row, L"process_evidence", process) && OptionalField(row, L"image_process_evidence", image && process) &&
                OptionalField(row, L"reference_evidence", reference) && OptionalField(row, L"build_evidence", build) &&
                OptionalField(row, L"capture_setting_evidence", settings);
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

    bool ClockAndBuffers(const Object& root, EtlTracePage& p)
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
            (accounting == etl_profile::BufferAccounting::More || accounting == etl_profile::BufferAccounting::Fewer)))
        { return false; }
        // These exact objects contain only the checked header fields. The capture FILETIMEs
        // and log-wide loss counters do not supply sample-clock bounds or a sample loss count.
        p.ClockJson = root.at(L"clock");
        p.LogHeaderJson = root.at(L"log_header");
        return true;
    }

    bool SampleRow(const std::wstring& raw, const EvidenceTables& evidence, etl_profile::Sample& s)
    {
        Object r;
        if (!trace_json::ReadObject(raw, &r) || !trace_json::HasFields(r, {L"sample_ordinal", L"record_ordinal", L"raw_timestamp",
            L"cpu", L"cpu_field", L"instruction_pointer", L"sampled_thread_id", L"count_field", L"reserved_field", L"pointer_bytes",
            L"header_thread_id", L"header_process_id", L"header_flags", L"logger_id", L"event_keyword", L"event_level",
            L"event_channel", L"event_task", L"extended_data_items", L"stack_extension_items"}, {L"thread_evidence", L"image_evidence",
            L"process_evidence", L"image_process_evidence", L"reference_evidence", L"build_evidence", L"capture_setting_evidence"}) ||
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
        L"capture_settings", L"reference_build", L"image_records", L"process_records", L"build_records"})) { return false; }
    const EvidenceTables tables{root.count(L"thread_source") != 0, root.count(L"image_source") != 0,
        root.count(L"process_source") != 0, root.count(L"reference_image") != 0, root.count(L"build_source") != 0,
        root.count(L"capture_settings") != 0};
    p.Schema = L"kn.etl_profile.v" + std::to_wstring(version);
    p.Partial = Label(root.at(L"status"), L"partial");
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
        !UInt(root.at(L"buffers_processed"), p.BuffersProcessed) || !ClockAndBuffers(root, p) ||
        !DeclaredScope(root.at(L"qualification"))) { return false; }
    std::vector<std::wstring> rows;
    if (!trace_json::Array(root.at(L"samples"), etl_profile::MaxPageRows, &rows)) { return false; }
    for (const auto& raw : rows)
    {
        if (cancellation && cancellation->load()) { return false; }
        etl_profile::Sample s{};
        if (!SampleRow(raw, tables, s) || s.ordinal != p.After + p.Rows.size() + 1 || s.ordinal > p.Decoded ||
            s.record < s.ordinal || s.record > p.RecordsSeen - (p.Decoded - s.ordinal)) { return false; }
        if (!p.Rows.empty())
        {
            if (p.Rows.back().record >= s.record) { return false; }
            p.ReversedTicks |= p.Rows.back().timestamp > s.timestamp;
        }
        p.Rows.push_back(s);
    }
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
            L",\"stack_extension_items\":" + std::to_wstring(s.stackItems) +
            L",\"reported_level\":\"X2\",\"qualified_reported_level\":\"unqualified\",\"verified_level\":\"unqualified\","
            L"\"qualification\":\"reported_sample_without_authenticated_context\",\"loss_interval_overlap\":null}";
    }
    return out + L"],\"live_backend_opened\":false,\"raw_decoder_used\":false}";
}
