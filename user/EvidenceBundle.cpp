#include "EvidenceBundle.h"
#include "AnalystSnapshot.h"
#include "ContentHash.h"
#include "KmonHuntingJson.h"

#include <filesystem>
#include <set>

namespace
{
    std::wstring Decimal(uint64_t value) { return mcpjson::Quote(std::to_wstring(value)); }
    bool Number(const std::wstring& json, const wchar_t* name, uint64_t* value)
    {
        std::wstring text;
        if (!mcpjson::GetString(json, name, &text) || text.empty() || text.size() > 20) { return false; }
        *value = 0;
        for (const wchar_t c : text)
        {
            if (c < L'0' || c > L'9' || *value > (UINT64_MAX - (c - L'0')) / 10) { return false; }
            *value = *value * 10 + (c - L'0');
        }
        return true;
    }
    bool Boolean(const std::wstring& json, const wchar_t* name, bool* value)
    {
        std::wstring raw;
        if (!mcpjson::FindRawValue(json, name, &raw) || (raw != L"true" && raw != L"false")) { return false; }
        *value = raw == L"true";
        return true;
    }
    std::wstring Bool(bool value) { return value ? L"true" : L"false"; }
    bool Text(const std::wstring& text, size_t maximum)
    {
        return text.size() <= maximum && text.find(L'\0') == std::wstring::npos &&
            mcpjson::SanitizeUtf16(text) == text;
    }
    std::wstring Digest(const std::wstring& text)
    {
        const auto bytes = mcpjson::WideToUtf8(text);
        ContentHash hash;
        return hash.Add(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()) ? hash.Finish() : L"";
    }
    std::wstring Hex(const std::vector<uint8_t>& bytes)
    {
        std::wstring out;
        for (uint8_t b : bytes) { out += L"0123456789abcdef"[b >> 4]; out += L"0123456789abcdef"[b & 15]; }
        return out;
    }
    bool Unhex(const std::wstring& text, std::vector<uint8_t>* bytes)
    {
        if (text.size() > 8192 || text.size() % 2 != 0) { return false; }
        bytes->clear();
        const auto digit = [](wchar_t c) { return c >= L'0' && c <= L'9' ? c - L'0' : c >= L'a' && c <= L'f' ? c - L'a' + 10 : -1; };
        for (size_t i = 0; i < text.size(); i += 2)
        {
            const int a = digit(text[i]), b = digit(text[i + 1]);
            if (a < 0 || b < 0) { return false; }
            bytes->push_back(static_cast<uint8_t>((a << 4) | b));
        }
        return true;
    }
    bool Array(const std::wstring& json, std::vector<std::wstring>* rows, size_t maximum)
    {
        rows->clear();
        size_t pos = 0;
        mcpjson::SkipWhitespace(json, &pos);
        if (pos == json.size() || json[pos++] != L'[') { return false; }
        while (pos < json.size())
        {
            mcpjson::SkipWhitespace(json, &pos);
            if (pos < json.size() && json[pos] == L']') { return pos + 1 == json.size(); }
            size_t end = 0;
            if (rows->size() == maximum || !mcpjson::ScanValue(json, pos, &end)) { return false; }
            rows->push_back(json.substr(pos, end - pos));
            pos = end;
            mcpjson::SkipWhitespace(json, &pos);
            if (pos < json.size() && json[pos] == L',') { ++pos; }
        }
        return false;
    }
    std::wstring Ranges(const std::vector<ObservationRange>& ranges)
    {
        std::wstring out = L"[";
        for (const auto& range : ranges)
        {
            if (out.size() > 1) { out += L","; }
            out += L"{\"address\":" + Decimal(range.Address) + L",\"size\":" + Decimal(range.Size) + L"}";
        }
        return out + L"]";
    }
    bool ParseRanges(const std::wstring& json, const wchar_t* name, std::vector<ObservationRange>* ranges)
    {
        std::wstring raw;
        std::vector<std::wstring> rows;
        if (!mcpjson::FindRawValue(json, name, &raw) || !Array(raw, &rows, 256)) { return false; }
        for (const auto& row : rows)
        {
            ObservationRange range;
            if (!Number(row, L"address", &range.Address) || !Number(row, L"size", &range.Size) ||
                range.Size == 0 || range.Address > UINT64_MAX - range.Size) { return false; }
            ranges->push_back(range);
        }
        return true;
    }
    std::wstring CoverageJson(const ObservationCoverage& c)
    {
        return L"{\"requested\":" + Decimal(c.RequestedBytes) + L",\"compared\":" + Decimal(c.ComparedBytes) +
            L",\"failed\":" + Decimal(c.FailedBytes) + L",\"skipped\":" + Decimal(c.SkippedBytes) +
            L",\"resume\":" + Decimal(c.ResumeAddress) + L",\"lost\":" + Decimal(c.LostEvents) +
            L",\"attempted\":" + Bool(c.Attempted) + L",\"traversal_complete\":" + Bool(c.TraversalComplete) +
            L",\"inventory_available\":" + Bool(c.InventoryAvailable) + L",\"reason\":" + mcpjson::Quote(c.Reason) +
            L",\"ranges_truncated\":" + Bool(c.RangesTruncated) + L",\"compared_ranges\":" + Ranges(c.Compared) +
            L",\"failed_ranges\":" + Ranges(c.Failed) + L",\"skipped_ranges\":" + Ranges(c.Skipped) + L"}";
    }
    bool ParseCoverage(const std::wstring& json, ObservationCoverage* c)
    {
        return Number(json, L"requested", &c->RequestedBytes) && Number(json, L"compared", &c->ComparedBytes) &&
            Number(json, L"failed", &c->FailedBytes) && Number(json, L"skipped", &c->SkippedBytes) &&
            Number(json, L"resume", &c->ResumeAddress) && Number(json, L"lost", &c->LostEvents) &&
            Boolean(json, L"attempted", &c->Attempted) && Boolean(json, L"traversal_complete", &c->TraversalComplete) &&
            Boolean(json, L"inventory_available", &c->InventoryAvailable) &&
            Boolean(json, L"ranges_truncated", &c->RangesTruncated) && mcpjson::GetString(json, L"reason", &c->Reason) &&
            ParseRanges(json, L"compared_ranges", &c->Compared) && ParseRanges(json, L"failed_ranges", &c->Failed) &&
            ParseRanges(json, L"skipped_ranges", &c->Skipped);
    }
    bool ParseReference(const std::wstring& json, KmonHuntReference* r)
    {
        auto& c = r->Context;
        auto& i = c.Identity;
        uint64_t pid = 0, session = 0;
        std::wstring ownership;
        bool execution = true;
        // Reference v1 uses both JSON numbers and quoted uint64 values. Only
        // this adapter accepts either; the bundle envelope remains canonical.
        const auto number = [&](const wchar_t* name, uint64_t* value)
        {
            std::wstring raw;
            if (!mcpjson::FindRawValue(json, name, &raw)) { return false; }
            return Number(L"{\"value\":" + (raw.front() == L'"' ? raw : mcpjson::Quote(raw)) + L"}", L"value", value);
        };
        if (!mcpjson::GetString(json, L"boot_id", &i.BootId) || !number(L"pid", &pid) || pid > UINT32_MAX ||
            !number(L"create_time", &i.CreateTime) || !number(L"eprocess", &i.Eprocess) ||
            !number(L"session_id", &session) || session > UINT32_MAX || !Boolean(json, L"session_known", &i.SessionKnown) ||
            !number(L"id", &r->Id) || !number(L"address", &r->Address) || !number(L"root", &r->Root) || !number(L"slot", &r->Slot) ||
            !number(L"mapping_generation", &c.MappingGeneration) || !number(L"observed_ms", &c.MonotonicMs) ||
            !number(L"observed_at", &c.Timestamp) || !number(L"reference_at", &r->ReferenceTimestamp) ||
            !number(L"arrival_ms", &c.ArrivalMonotonicMs) || !number(L"arrival_sequence", &c.ArrivalSequence) ||
            !number(L"pfn", &c.Pfn) || !Boolean(json, L"pfn_known", &c.PfnKnown) ||
            !Boolean(json, L"slot_stable", &r->SlotStable) || !Boolean(json, L"page_comparable", &r->PageComparable) ||
            !Boolean(json, L"page_executable_verified", &r->PageExecutableVerified) ||
            !Boolean(json, L"execution_observed", &execution) || execution ||
            !mcpjson::GetString(json, L"role", &r->Role) || !mcpjson::GetString(json, L"ownership", &ownership) ||
            !mcpjson::GetString(json, L"source", &c.Source) || !mcpjson::GetString(json, L"dependency_group", &c.DependencyGroup) ||
            !mcpjson::GetString(json, L"page_sha256", &r->PageSha256)) { return false; }
        i.ProcessId = static_cast<uint32_t>(pid);
        i.SessionId = static_cast<uint32_t>(session);
        for (auto state : {CodeOwnership::Unknown, CodeOwnership::OwnedUnverified, CodeOwnership::OwnedVerified,
            CodeOwnership::OwnedModified, CodeOwnership::UnownedExecutable, CodeOwnership::OwnedUnexpectedExecutable})
        {
            if (ownership == CodeOwnershipName(state)) { c.Ownership = state; return true; }
        }
        return false;
    }
    bool Valid(const EvidenceBundle& b)
    {
        const auto& r = b.Receipt.Reference;
        const auto& c = r.Context;
        const auto& coverage = c.Coverage;
        const std::set<std::wstring> dispositions = {L"current", L"historical_only", L"identity_conflict", L"future_event",
            L"prior_process_instance", L"current_capacity"};
        const std::set<std::wstring> acquisitions = {L"local_user_reader", L"local_kernel_reader", L"local_mixed_reader", L"synthetic_fixture"};
        if (!Text(b.CollectionId, 128) || !c.Identity.HasCanonicalKey() || !Text(c.Identity.BootId, 128) || !Text(r.Role, 64) || r.Role.empty() ||
            !Text(c.Source, 128) || !Text(c.DependencyGroup, 128) || !Text(c.ReferenceSource, 128) ||
            !Text(coverage.Reason, 128) || c.MonotonicMs == 0 || c.ArrivalSequence == 0 ||
            c.ArrivalMonotonicMs == 0 || dispositions.count(b.Receipt.Disposition) == 0 || acquisitions.count(b.Acquisition) == 0 ||
            (b.Receipt.Disposition == L"current") != (r.Id != 0) ||
            (b.Receipt.Disposition == L"future_event") != (c.MonotonicMs > c.ArrivalMonotonicMs) ||
            (b.Receipt.Disposition == L"current" && c.ArrivalMonotonicMs - c.MonotonicMs > 30000) ||
            b.CaptureStartedMs == 0 || b.CaptureEndedMs < b.CaptureStartedMs ||
            b.Spans.size() > EvidenceBundleMaxSpans || coverage.Compared.size() > 256 || coverage.Failed.size() > 256 ||
            coverage.Skipped.size() > 256 || coverage.ComparedBytes > coverage.RequestedBytes ||
            coverage.FailedBytes > coverage.RequestedBytes - coverage.ComparedBytes ||
            coverage.SkippedBytes > coverage.RequestedBytes - coverage.ComparedBytes - coverage.FailedBytes ||
            (!r.PageSha256.empty() && !KmonHuntHash(r.PageSha256)) ||
            (r.PageComparable && (r.PageSha256.empty() || c.MappingGeneration == 0))) { return false; }
        for (const auto* ranges : {&coverage.Compared, &coverage.Failed, &coverage.Skipped})
        {
            for (const auto& range : *ranges)
            {
                if (range.Size == 0 || range.Address > UINT64_MAX - range.Size) { return false; }
            }
        }
        for (const auto& span : b.Spans)
        {
            if (span.RequestedBytes == 0 || span.RequestedBytes > 4096 || span.Address > UINT64_MAX - span.RequestedBytes ||
                (span.Role != L"target_head" && span.Role != L"target_page" && span.Role != L"pointer_slot" && span.Role != L"reference_anchor") ||
                (span.State != L"valid" && span.State != L"read_failed" && span.State != L"skipped") ||
                (span.State == L"valid" ? span.Bytes.size() != span.RequestedBytes : !span.Bytes.empty())) { return false; }
        }
        return true;
    }
    std::wstring Payload(const EvidenceBundle& b)
    {
        const auto& c = b.Receipt.Reference.Context;
        std::wstring out = L"{\"schema\":\"kmon.evidence.v1\",\"acquisition\":" + mcpjson::Quote(b.Acquisition) +
            L",\"capture_started_ms\":" + Decimal(b.CaptureStartedMs) + L",\"capture_ended_ms\":" + Decimal(b.CaptureEndedMs) +
            L",\"reference_consistent\":" + Bool(b.ReferenceConsistent) + L",\"capture_truncated\":" + Bool(b.CaptureTruncated) +
            L",\"read_set_complete\":" + Bool(EvidenceReadSetComplete(b)) + L",\"receipt\":" + KmonHuntReceiptJson(b.Receipt) +
            L",\"allocation_base\":" + Decimal(c.AllocationBase) + L",\"reference_source\":" + mcpjson::Quote(c.ReferenceSource) +
            L",\"observation_coverage\":" + CoverageJson(c.Coverage) + L",\"span_count\":" + Decimal(b.Spans.size()) + L",\"spans\":[";
        bool first = true;
        for (const auto& span : b.Spans)
        {
            if (!first) { out += L","; }
            first = false;
            out += L"{\"address\":" + Decimal(span.Address) + L",\"requested\":" + Decimal(span.RequestedBytes) +
                L",\"role\":" + mcpjson::Quote(span.Role) + L",\"state\":" + mcpjson::Quote(span.State) +
                L",\"sha256\":" + mcpjson::Quote(span.Bytes.empty() ? L"" : ContentHash::Bytes(span.Bytes)) +
                L",\"bytes_hex\":" + mcpjson::Quote(Hex(span.Bytes)) + L"}";
        }
        out += L"]";
        if (!b.CollectionId.empty()) { out += L",\"collection_id\":" + mcpjson::Quote(b.CollectionId); }
        return out + L"}";
    }
    bool BundlePath(const std::wstring& path)
    {
        // Private extension also separates complete publications from pending files.
        return path.size() >= 7 && path.compare(path.size() - 7, 7, L".kncase") == 0;
    }
}

bool EvidenceReadSetComplete(const EvidenceBundle& b)
{
    if (!b.ReferenceConsistent || b.CaptureTruncated || b.Spans.empty() || b.Spans.size() > EvidenceBundleMaxSpans) { return false; }
    for (const auto& span : b.Spans)
    {
        std::vector<uint8_t> bytes;
        if (span.State != L"valid" || span.RequestedBytes == 0 || span.RequestedBytes > 4096 ||
            !EvidenceRead(b, span.Address, static_cast<size_t>(span.RequestedBytes), &bytes)) { return false; }
    }
    return true;
}

bool EvidenceRead(const EvidenceBundle& b, uint64_t address, size_t size, std::vector<uint8_t>* bytes)
{
    if (bytes == nullptr) { return false; }
    bytes->clear();
    if (size == 0 || size > 4096 || address > UINT64_MAX - size) { return false; }
    std::vector<uint8_t> result(size), present(size);
    for (const auto& span : b.Spans)
    {
        if (span.State != L"valid" || span.Bytes.size() != span.RequestedBytes ||
            span.Address > UINT64_MAX - span.RequestedBytes) { continue; }
        const auto begin = (std::max)(address, span.Address);
        const auto end = (std::min)(address + size, span.Address + span.RequestedBytes);
        for (uint64_t at = begin; at < end; ++at)
        {
            const size_t index = static_cast<size_t>(at - address);
            const auto value = span.Bytes[static_cast<size_t>(at - span.Address)];
            if (present[index] && result[index] != value) { return false; }
            result[index] = value;
            present[index] = 1;
        }
    }
    if (std::find(present.begin(), present.end(), 0) != present.end()) { return false; }
    *bytes = std::move(result);
    return true;
}

std::wstring EvidenceBundleJson(const EvidenceBundle& bundle)
{
    if (!Valid(bundle)) { return {}; }
    const auto payload = Payload(bundle);
    const auto hash = Digest(payload);
    if (hash.size() != 64 || payload.size() > EvidenceBundleMaxJsonBytes) { return {}; }
    return L"{\"schema\":\"kmon.bundle.v1\",\"payload_sha256\":" + mcpjson::Quote(hash) + L",\"payload\":" + payload + L"}";
}

bool ParseEvidenceBundle(const std::wstring& json, EvidenceBundle* bundle, std::wstring* error)
{
    if (error != nullptr) { *error = L"invalid, incomplete or corrupt evidence bundle"; }
    if (bundle == nullptr) { return false; }
    *bundle = {};
    std::wstring schema, hash, payload, receipt, reference, coverage, array;
    if (json.size() > EvidenceBundleMaxJsonBytes || !mcpjson::ValidateDocument(json) ||
        !mcpjson::GetString(json, L"schema", &schema) || schema != L"kmon.bundle.v1" ||
        !mcpjson::GetString(json, L"payload_sha256", &hash) || hash.size() != 64 ||
        !mcpjson::FindRawValue(json, L"payload", &payload) || Digest(payload) != hash) { return false; }
    EvidenceBundle parsed;
    auto& c = parsed.Receipt.Reference.Context;
    uint64_t count = 0;
    std::vector<std::wstring> spans;
    if (!mcpjson::GetString(payload, L"acquisition", &parsed.Acquisition) ||
        !Number(payload, L"capture_started_ms", &parsed.CaptureStartedMs) || !Number(payload, L"capture_ended_ms", &parsed.CaptureEndedMs) ||
        !Boolean(payload, L"reference_consistent", &parsed.ReferenceConsistent) || !Boolean(payload, L"capture_truncated", &parsed.CaptureTruncated) ||
        !mcpjson::FindRawValue(payload, L"receipt", &receipt) ||
        !mcpjson::GetString(receipt, L"current_disposition", &parsed.Receipt.Disposition) ||
        !Boolean(receipt, L"arrival_inferred", &parsed.Receipt.ArrivalInferred) ||
        !mcpjson::FindRawValue(receipt, L"reference", &reference) || !ParseReference(reference, &parsed.Receipt.Reference) ||
        !Number(payload, L"allocation_base", &c.AllocationBase) || !mcpjson::GetString(payload, L"reference_source", &c.ReferenceSource) ||
        !mcpjson::FindRawValue(payload, L"observation_coverage", &coverage) || !ParseCoverage(coverage, &c.Coverage) ||
        !Number(payload, L"span_count", &count) || count > EvidenceBundleMaxSpans ||
        !mcpjson::FindRawValue(payload, L"spans", &array) || !Array(array, &spans, EvidenceBundleMaxSpans) || spans.size() != count) { return false; }
    for (const auto& row : spans)
    {
        EvidenceSpan span;
        std::wstring hex;
        if (!Number(row, L"address", &span.Address) || !Number(row, L"requested", &span.RequestedBytes) ||
            !mcpjson::GetString(row, L"role", &span.Role) || !mcpjson::GetString(row, L"state", &span.State) ||
            !mcpjson::GetString(row, L"bytes_hex", &hex) || !Unhex(hex, &span.Bytes)) { return false; }
        parsed.Spans.push_back(std::move(span));
    }
    std::wstring collection;
    if (mcpjson::FindRawValue(payload, L"collection_id", &collection) &&
        (!mcpjson::GetString(payload, L"collection_id", &parsed.CollectionId) || parsed.CollectionId.empty())) { return false; }
    // New format: require the exact canonical form. This also validates every
    // derived checksum/count/closure claim and rejects unknown or aliased fields.
    if (!Valid(parsed) || EvidenceBundleJson(parsed) != json) { return false; }
    *bundle = std::move(parsed);
    if (error != nullptr) { error->clear(); }
    return true;
}

bool SaveEvidenceBundle(const std::wstring& path, const EvidenceBundle& bundle, std::wstring* error)
{
    const auto json = EvidenceBundleJson(bundle);
    if (!BundlePath(path) || json.empty() || mcpjson::WideToUtf8(json).size() > EvidenceBundleMaxJsonBytes)
    {
        if (error != nullptr) { *error = L"bundle must be bounded and use a new .kncase path"; }
        return false;
    }
    return SaveObservationJson(path, json, error);
}

bool LoadEvidenceBundle(const std::wstring& path, EvidenceBundle* bundle, std::wstring* error, std::wstring* digest,
    size_t maximumBytes, size_t* bytesRead)
{
    if (bytesRead != nullptr) { *bytesRead = 0; }
    if (bundle != nullptr) { *bundle = {}; }
    if (digest != nullptr) { digest->clear(); }
    std::wstring json;
    if (!BundlePath(path))
    {
        if (error != nullptr) { *error = L"only published .kncase files can be opened"; }
        return false;
    }
    if (!ReadAnalystSnapshot(path, &json, error, (std::min)(maximumBytes, EvidenceBundleMaxJsonBytes), bytesRead, true) ||
        !ParseEvidenceBundle(json, bundle, error)) { return false; }
    if (digest != nullptr) { mcpjson::GetString(json, L"payload_sha256", digest); }
    return true;
}
