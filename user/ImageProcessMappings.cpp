#include "ImageProcessMappings.h"
#include "ImageVerificationRecipe.h"
#include "BoundedObservationJson.h"
#include <set>

using namespace bounded_observation_json;
namespace
{
    bool Success(const ProcessMappingQuery& q) { return q.ReturnedBytes == ProcessMappingQueryBytes; }
    std::wstring Nullable(uint64_t n, bool known) { return known ? N(n) : L"null"; }
    std::wstring QueryJson(const ProcessMappingQuery& q)
    {
        const bool valid = Success(q), allocated = valid && q.State != MEM_FREE;
        return L"{\"address\":" + N(q.Address) + L",\"returned_bytes\":" + N(q.ReturnedBytes) +
            L",\"native_status\":" + Nullable(q.NativeStatus, q.NativeStatusKnown) +
            L",\"region_base\":" + Nullable(q.RegionBase, valid) + L",\"region_bytes\":" + Nullable(q.RegionBytes, valid) +
            L",\"state\":" + Nullable(q.State, valid) + L",\"allocation_base\":" + Nullable(q.AllocationBase, allocated) +
            L",\"allocation_protect\":" + Nullable(q.AllocationProtect, allocated) + L",\"type\":" + Nullable(q.Type, allocated) +
            L",\"protect\":" + Nullable(q.Protect, valid && q.State == MEM_COMMIT) + L"}";
    }
    std::wstring ObservationJson(const ProcessMappingObservation& o)
    {
        std::wstring json = L"{\"source_id\":" + mcpjson::Quote(o.SourceId) + L",\"address\":" + N(o.Address) +
            L",\"length\":" + N(o.Length) + L",\"started_tick\":" + N(o.StartedTick) + L",\"ended_tick\":" + N(o.EndedTick) +
            L",\"status\":" + mcpjson::Quote(o.Status) + L",\"identity_revalidated\":" + B(o.IdentityRevalidated) + L",\"queries\":[";
        for (const auto& q : o.Queries)
        {
            if (&q != &o.Queries.front()) { json += L","; }
            json += QueryJson(q);
        }
        return json + L"]}";
    }
    template<class T> bool NullableNumber(const std::wstring& json, const wchar_t* key, T* out, bool* known = nullptr)
    {
        std::wstring raw;
        if (!mcpjson::FindRawValue(json, key, &raw)) { return false; }
        if (known) { *known = raw != L"null"; }
        if (raw == L"null") { *out = 0; return true; }
        return Number(json, key, out);
    }
    bool ParseObservation(const std::wstring& json, ProcessMappingObservation* o)
    {
        if (!mcpjson::GetString(json, L"source_id", &o->SourceId) || !mcpjson::GetString(json, L"status", &o->Status) ||
            !Number(json, L"address", &o->Address) || !Number(json, L"length", &o->Length) ||
            !Number(json, L"started_tick", &o->StartedTick) || !Number(json, L"ended_tick", &o->EndedTick) ||
            !Boolean(json, L"identity_revalidated", &o->IdentityRevalidated)) { return false; }
        std::vector<std::wstring> rows;
        if (!Array(json, L"queries", 2, &rows)) { return false; }
        for (const auto& row : rows)
        {
            ProcessMappingQuery q;
            if (!Number(row, L"address", &q.Address) || !Number(row, L"returned_bytes", &q.ReturnedBytes) ||
                !NullableNumber(row, L"native_status", &q.NativeStatus, &q.NativeStatusKnown) ||
                !NullableNumber(row, L"region_base", &q.RegionBase) || !NullableNumber(row, L"region_bytes", &q.RegionBytes) ||
                !NullableNumber(row, L"allocation_base", &q.AllocationBase) || !NullableNumber(row, L"allocation_protect", &q.AllocationProtect) ||
                !NullableNumber(row, L"state", &q.State) || !NullableNumber(row, L"type", &q.Type) ||
                !NullableNumber(row, L"protect", &q.Protect) || QueryJson(q) != row) { return false; }
            o->Queries.push_back(q);
        }
        return ObservationJson(*o) == json;
    }
    bool RegionValid(const ProcessMappingQuery& q)
    {
        return Success(q) && q.RegionBytes && q.RegionBase <= q.Address && q.RegionBase <= UINT64_MAX - q.RegionBytes &&
            q.RegionBase + q.RegionBytes > q.Address &&
            (q.State == MEM_FREE || q.State == MEM_RESERVE || q.State == MEM_COMMIT) &&
            (q.State == MEM_FREE || (q.AllocationBase <= q.RegionBase &&
                (q.Type == MEM_IMAGE || q.Type == MEM_MAPPED || q.Type == MEM_PRIVATE)));
    }
    bool ValidObservation(const ProcessMappingObservation& o, const ObservationSourceCapabilities& caps)
    {
        if (o.SourceId != caps.SourceId || !o.Length || o.Length > 4096 || !ObservationRangeSupported(caps, o.Address, o.Length) ||
            o.EndedTick < o.StartedTick || o.Queries.size() > 2 ||
            (o.Status != L"complete" && o.Status != L"identity_changed" && o.Status != L"unsupported" &&
                o.Status != L"cancelled" && o.Status != L"query_failed" && o.Status != L"malformed_result")) { return false; }
        uint64_t cursor = o.Address;
        bool failure = false, malformed = false;
        for (const auto& q : o.Queries)
        {
            if (failure || malformed || cursor == o.Address + o.Length || q.Address != cursor ||
                q.NativeStatusKnown != (q.ReturnedBytes == 0) || (!q.NativeStatusKnown && q.NativeStatus) ||
                (!Success(q) && (q.RegionBase || q.RegionBytes || q.State || q.AllocationBase || q.AllocationProtect || q.Type || q.Protect)) ||
                (q.State == MEM_FREE && (q.AllocationBase || q.AllocationProtect || q.Type || q.Protect)) ||
                (q.State != MEM_COMMIT && q.Protect)) { return false; }
            failure = !q.ReturnedBytes;
            malformed = q.ReturnedBytes && !RegionValid(q);
            if (!failure && !malformed) { cursor = (std::min)(o.Address + o.Length, q.RegionBase + q.RegionBytes); }
        }
        if (o.Status == L"identity_changed") { return !o.IdentityRevalidated; }
        if (o.Status == L"unsupported") { return o.Queries.empty() && !o.IdentityRevalidated; }
        if (!o.IdentityRevalidated) { return false; }
        if (o.Status == L"query_failed") { return failure; }
        if (o.Status == L"malformed_result") { return malformed || (o.Queries.size() == 2 && cursor < o.Address + o.Length); }
        if (o.Status == L"cancelled") { return !failure && !malformed && cursor < o.Address + o.Length; }
        return !failure && !malformed && cursor == o.Address + o.Length;
    }
    bool SameAttributes(const ProcessMappingQuery& a, const ProcessMappingQuery& b)
    {
        return a.State == b.State && a.Type == b.Type && a.AllocationBase == b.AllocationBase &&
            a.AllocationProtect == b.AllocationProtect && a.Protect == b.Protect;
    }
}

std::wstring ImageProcessMappingsJson(const ImageProcessMappings& mappings)
{
    if (mappings.Reads.size() > ImageRecipeMaxReads || mappings.Final.size() > ImageRecipeMaxReads) { return {}; }
    std::wstring json = L"{\"schema\":\"kn.process_image_mappings.v1\",\"policy\":" + mcpjson::Quote(ImageProcessMappingPolicy) +
        L",\"query_contract\":\"win32_virtualqueryex.amd64.v1\",\"clock_domain\":\"collector_steady_clock_ms\",\"reads\":[";
    for (const auto& pair : mappings.Reads)
    {
        if (&pair != &mappings.Reads.front()) { json += L","; }
        json += L"{\"before\":" + ObservationJson(pair.Before) + L",\"after\":" + ObservationJson(pair.After) + L"}";
    }
    json += L"],\"final\":[";
    for (const auto& o : mappings.Final)
    {
        if (&o != &mappings.Final.front()) { json += L","; }
        json += ObservationJson(o);
    }
    return json + L"]}";
}

bool ParseImageProcessMappings(const std::wstring& json, ImageProcessMappings* mappings)
{
    if (!mappings) { return false; }
    *mappings = {};
    if (json.size() > ImageRecipeMaxBytes || !mcpjson::ValidateDocument(json)) { return false; }
    ImageProcessMappings parsed;
    std::vector<std::wstring> pairs, final;
    if (!Array(json, L"reads", ImageRecipeMaxReads, &pairs) || !Array(json, L"final", ImageRecipeMaxReads, &final)) { return false; }
    for (const auto& row : pairs)
    {
        std::wstring before, after;
        ImageReadMappings pair;
        if (!mcpjson::FindRawValue(row, L"before", &before) || !mcpjson::FindRawValue(row, L"after", &after) ||
            !ParseObservation(before, &pair.Before) || !ParseObservation(after, &pair.After)) { return false; }
        parsed.Reads.push_back(std::move(pair));
    }
    for (const auto& row : final)
    {
        ProcessMappingObservation observation;
        if (!ParseObservation(row, &observation)) { return false; }
        parsed.Final.push_back(std::move(observation));
    }
    if (ImageProcessMappingsJson(parsed) != json) { return false; }
    *mappings = std::move(parsed); return true;
}

bool ValidImageProcessMappings(const ImageVerificationRecipe& p)
{
    if (p.FormatVersion != 3) { return p.Mappings.Reads.empty() && p.Mappings.Final.empty(); }
    const auto& m = p.Mappings;
    if (p.ReadSet.Reads.empty() || p.ReadSet.Reads.size() != p.Reads.size() || m.Reads.size() != p.Reads.size() || m.Reads.size() > ImageRecipeMaxReads ||
        m.Final.empty() || m.Final.size() > ImageRecipeMaxReads) { return false; }
    const auto& caps = p.ReadSet.Reads.front().Source;
    if (!caps.UserOnly || caps.KernelOnly || caps.AddressDomain != ObservationAddressDomain::Virtual || caps.SourceId != p.SourceId)
        { return false; }
    uint64_t tick = p.ReadSet.StartedTick;
    std::set<std::pair<uint64_t, uint32_t>> seen;
    std::vector<std::pair<uint64_t, uint32_t>> ranges;
    for (size_t i = 0; i < p.Reads.size(); ++i)
    {
        const auto& r = p.Reads[i];
        const auto& before = m.Reads[i].Before;
        const auto& after = m.Reads[i].After;
        if (!ValidObservation(before, caps) || !ValidObservation(after, caps) ||
            before.Address != r.Address || before.Length != r.Length || after.Address != r.Address || after.Length != r.Length ||
            before.StartedTick < tick || before.EndedTick > r.Result.StartedTick || after.StartedTick < r.Result.EndedTick)
            { return false; }
        tick = after.EndedTick;
        if (seen.emplace(r.Address, r.Length).second) { ranges.emplace_back(r.Address, r.Length); }
    }
    if (ranges.size() != m.Final.size()) { return false; }
    for (size_t i = 0; i < ranges.size(); ++i)
    {
        const auto& o = m.Final[i];
        if (!ValidObservation(o, caps) || o.Address != ranges[i].first || o.Length != ranges[i].second || o.StartedTick < tick)
            { return false; }
        tick = o.EndedTick;
    }
    return tick <= p.ReadSet.SnapshotTick;
}

ImageProcessMappingAssessment AssessImageProcessMappings(const ImageVerificationRecipe& p)
{
    ImageProcessMappingAssessment out;
    if (p.FormatVersion != 3 || !ValidImageProcessMappings(p)) { return out; }
    struct Span { uint64_t Begin, End; ProcessMappingQuery Query; };
    std::vector<Span> spans;
    bool identityChanged = false, image = true;
    const auto observe = [&](const ProcessMappingObservation& o)
    {
        ++out.Observations; out.RequestedBytes += o.Length; out.Queries += o.Queries.size();
        if (o.Status != L"complete") { ++out.FailedObservations; }
        identityChanged |= o.Status == L"identity_changed";
        for (const auto& q : o.Queries)
        {
            if (!RegionValid(q)) { image = false; continue; }
            const auto end = (std::min)(o.Address + o.Length, q.RegionBase + q.RegionBytes);
            out.ObservedBytes += end - q.Address;
            if (q.State != MEM_COMMIT) { ++out.UncommittedQueries; }
            image &= q.State == MEM_COMMIT && q.Type == MEM_IMAGE && q.AllocationBase == p.ImageBase;
            for (const auto& previous : spans)
            {
                if (q.Address < previous.End && previous.Begin < end)
                {
                    ++out.ComparedPairs;
                    if (!SameAttributes(q, previous.Query)) { ++out.ConflictingPairs; }
                }
            }
            spans.push_back({q.Address, end, q});
        }
    };
    for (const auto& pair : p.Mappings.Reads) { observe(pair.Before); observe(pair.After); }
    for (const auto& observation : p.Mappings.Final) { observe(observation); }
    out.Status = identityChanged || out.ConflictingPairs ? L"inconsistent_capture" :
        out.FailedObservations || out.UncommittedQueries ? L"unavailable" : L"consistent_observations";
    out.NativeImageMappingObserved = image && out.Status == L"consistent_observations";
    return out;
}

std::wstring ImageProcessMappingAssessmentJson(const ImageProcessMappingAssessment& a)
{
    return L"{\"schema\":\"kn.process_image_mapping_assessment.v1\",\"policy\":" + mcpjson::Quote(ImageProcessMappingPolicy) +
        L",\"status\":" + mcpjson::Quote(a.Status) + L",\"observations\":" + N(a.Observations) + L",\"queries\":" + N(a.Queries) +
        L",\"failed_observations\":" + N(a.FailedObservations) + L",\"uncommitted_queries\":" + N(a.UncommittedQueries) +
        L",\"requested_query_bytes\":" + N(a.RequestedBytes) + L",\"observed_query_bytes\":" + N(a.ObservedBytes) +
        L",\"compared_pairs\":" + N(a.ComparedPairs) + L",\"conflicting_pairs\":" + N(a.ConflictingPairs) +
        L",\"native_image_mapping_observed\":" + B(a.NativeImageMappingObserved) +
        L",\"mapping_lifetime_bound\":false,\"aba_excluded\":false,\"physical_identity_known\":false,\"original_backing_verified\":false,"
        L"\"atomic_snapshot\":false,\"current_state_known\":false,\"execution_observed\":false,\"collector_authenticated\":false}";
}
