#include "ImageSweepManifest.h"
#include "BoundedObservationJson.h"
#include "ContentHash.h"
#include <algorithm>

using namespace bounded_observation_json;

namespace
{
    constexpr size_t MaximumBytes = 2 * 1024 * 1024;
    bool Digits(const std::wstring& text)
    {
        return !text.empty() && text.size() <= 20 && text.find_first_not_of(L"0123456789") == std::wstring::npos;
    }
    bool Hash(const std::wstring& hash, bool empty = false)
    {
        return (empty && hash.empty()) || (hash.size() == 64 && hash.find_first_not_of(L"0123456789abcdef") == std::wstring::npos);
    }
    bool ValidIdentity(const ImageSweepIdentity& s)
    {
        const auto prefix = s.CollectionId + L"-";
        return Digits(s.CollectionId) && s.SweepId.rfind(prefix, 0) == 0 && Digits(s.SweepId.substr(prefix.size())) &&
            Text(s.Image, 30000) && Text(s.TargetId, 2048) && Text(s.AddressSpaceId, 2048) && Text(s.Identity.BootId, 256) &&
            (s.Identity.ProcessId == 0 || s.Identity.CreateTime != 0) && s.ImageBase != 0 && s.StartedFileTime != 0 &&
            s.TotalRanges != 0 && s.TotalRanges <= 262144 && s.ExpectedBytes >= s.TotalRanges &&
            s.ExpectedBytes <= uint64_t(s.TotalRanges) * 4096;
    }
    bool ValidSlice(const ImageSweepIdentity& s, const ImageSweepSlice& p)
    {
        return p.Ordinal != 0 && p.Ordinal <= 262144 && p.ReadSetId != 0 &&
            p.StartRange < s.TotalRanges && p.RangeCount <= s.TotalRanges - p.StartRange && p.RangeCount <= 4096 &&
            p.StartedTick >= s.StartedTick && p.EndedTick >= p.StartedTick && p.ObservedFileTime != 0 &&
            Text(p.Reason, 256) && (!p.TraversalComplete || (p.Terminal && p.StartRange + p.RangeCount == s.TotalRanges)) &&
            Hash(p.ReferenceSha256, !p.ReferenceWritten) && Hash(p.RawPayloadSha256, !p.RawWritten) &&
            Hash(p.RecipeSha256, !p.RecipeWritten) && (p.RawWritten == !p.RawPayloadSha256.empty()) &&
            (p.RecipeWritten == !p.RecipeSha256.empty()) && (!p.RecipeWritten || p.ReferenceWritten);
    }
    std::wstring IdentityJson(const ImageSweepIdentity& s)
    {
        return L"{\"collection_id\":" + mcpjson::Quote(s.CollectionId) + L",\"sweep_id\":" + mcpjson::Quote(s.SweepId) +
            L",\"image\":" + mcpjson::Quote(s.Image) + L",\"image_base\":" + N(s.ImageBase) +
            L",\"boot_id\":" + mcpjson::Quote(s.Identity.BootId) + L",\"pid\":" + N(s.Identity.ProcessId) +
            L",\"creation_time\":" + N(s.Identity.CreateTime) + L",\"target_id\":" + mcpjson::Quote(s.TargetId) +
            L",\"address_space_id\":" + mcpjson::Quote(s.AddressSpaceId) + L",\"total_ranges\":" + N(s.TotalRanges) +
            L",\"expected_bytes\":" + N(s.ExpectedBytes) + L",\"started_tick\":" + N(s.StartedTick) +
            L",\"started_filetime\":" + N(s.StartedFileTime) + L"}";
    }
    std::wstring SliceJson(const ImageSweepSlice& p)
    {
        return L"{\"ordinal\":" + N(p.Ordinal) + L",\"read_set_id\":" + N(p.ReadSetId) +
            L",\"start_range\":" + N(p.StartRange) + L",\"range_count\":" + N(p.RangeCount) +
            L",\"started_tick\":" + N(p.StartedTick) + L",\"ended_tick\":" + N(p.EndedTick) +
            L",\"observed_filetime\":" + N(p.ObservedFileTime) + L",\"terminal\":" + B(p.Terminal) +
            L",\"traversal_complete\":" + B(p.TraversalComplete) + L",\"reason\":" + mcpjson::Quote(p.Reason) +
            L",\"reference_sha256\":" + mcpjson::Quote(p.ReferenceSha256) + L",\"reference_written\":" + B(p.ReferenceWritten) +
            L",\"raw_payload_sha256\":" + mcpjson::Quote(p.RawPayloadSha256) + L",\"raw_written\":" + B(p.RawWritten) +
            L",\"recipe_sha256\":" + mcpjson::Quote(p.RecipeSha256) + L",\"recipe_written\":" + B(p.RecipeWritten) + L"}";
    }
    bool Valid(const ImageSweepManifest& p)
    {
        if (!ValidIdentity(p.Sweep) || p.ObservedSlices == 0 || p.ObservedSlices > 262144 ||
            p.Slices.size() > 2048 || p.Slices.size() > p.ObservedSlices || p.LastEndedTick < p.Sweep.StartedTick ||
            !Text(p.EndReason, 256) || (p.TraversalComplete && !p.TerminalObserved)) { return false; }
        uint64_t ordinal = 0, tick = p.Sweep.StartedTick;
        for (const auto& row : p.Slices)
        {
            if (!ValidSlice(p.Sweep, row) || row.Ordinal <= ordinal || row.Ordinal > p.ObservedSlices ||
                row.StartedTick < tick || row.EndedTick > p.LastEndedTick ||
                (row.Terminal && (!p.TerminalObserved || row.Ordinal != p.ObservedSlices ||
                    row.TraversalComplete != p.TraversalComplete || row.Reason != p.EndReason))) { return false; }
            ordinal = row.Ordinal; tick = row.EndedTick;
        }
        if (!p.Slices.empty() && p.Slices.back().Ordinal == p.ObservedSlices &&
            (p.Slices.back().EndedTick != p.LastEndedTick || p.Slices.back().Terminal != p.TerminalObserved)) { return false; }
        return true;
    }
    std::wstring Payload(const ImageSweepManifest& p)
    {
        std::wstring rows = L"[";
        for (const auto& row : p.Slices)
        {
            if (rows.size() > 1) { rows += L","; }
            rows += SliceJson(row);
        }
        return L"{\"sweep\":" + IdentityJson(p.Sweep) + L",\"observed_slices\":" + N(p.ObservedSlices) +
            L",\"retained_entries\":" + N(p.Slices.size()) + L",\"missing_entries\":" + N(p.ObservedSlices - p.Slices.size()) +
            L",\"terminal_observed\":" + B(p.TerminalObserved) + L",\"tail_unknown\":" + B(!p.TerminalObserved) +
            L",\"traversal_complete\":" + B(p.TraversalComplete) + L",\"inconsistent\":" + B(p.Inconsistent) +
            L",\"last_ended_tick\":" + N(p.LastEndedTick) + L",\"observed_elapsed_ms\":" + N(p.LastEndedTick - p.Sweep.StartedTick) +
            L",\"end_reason\":" + mcpjson::Quote(p.EndReason) + L",\"slices\":" + rows +
            L"],\"clock_domain\":\"collector_steady_clock_ms\",\"atomic_snapshot\":false,\"collector_authenticated\":false,"
            L"\"complete_replay_established\":false,\"execution_observed\":false}";
    }
}

std::wstring ImageSweepManifestJson(const ImageSweepManifest& p)
{
    if (!Valid(p)) { return L""; }
    const auto payload = Payload(p);
    const auto bytes = mcpjson::WideToUtf8(payload);
    if (bytes.size() > MaximumBytes - 256) { return L""; }
    const auto hash = ContentHash::Bytes(std::vector<uint8_t>(bytes.begin(), bytes.end()));
    return hash.empty() ? L"" : L"{\"schema\":\"kn.image_sweep.v1\",\"manifest_sha256\":" + mcpjson::Quote(hash) +
        L",\"payload\":" + payload + L"}";
}

bool ParseImageSweepManifest(const std::wstring& json, ImageSweepManifest* out)
{
    if (out == nullptr || json.size() > MaximumBytes || !mcpjson::ValidateDocument(json)) { return false; }
    ImageSweepManifest p;
    auto& s = p.Sweep;
    std::wstring payload, sweep;
    std::vector<std::wstring> rows;
    if (!mcpjson::FindRawValue(json, L"payload", &payload) || !mcpjson::FindRawValue(payload, L"sweep", &sweep) ||
        !mcpjson::GetString(sweep, L"collection_id", &s.CollectionId) || !mcpjson::GetString(sweep, L"sweep_id", &s.SweepId) ||
        !mcpjson::GetString(sweep, L"image", &s.Image) || !Number(sweep, L"image_base", &s.ImageBase) ||
        !mcpjson::GetString(sweep, L"boot_id", &s.Identity.BootId) || !Number(sweep, L"pid", &s.Identity.ProcessId) ||
        !Number(sweep, L"creation_time", &s.Identity.CreateTime) || !mcpjson::GetString(sweep, L"target_id", &s.TargetId) ||
        !mcpjson::GetString(sweep, L"address_space_id", &s.AddressSpaceId) || !Number(sweep, L"total_ranges", &s.TotalRanges) ||
        !Number(sweep, L"expected_bytes", &s.ExpectedBytes) || !Number(sweep, L"started_tick", &s.StartedTick) ||
        !Number(sweep, L"started_filetime", &s.StartedFileTime) || !Number(payload, L"observed_slices", &p.ObservedSlices) ||
        !Number(payload, L"last_ended_tick", &p.LastEndedTick) || !Boolean(payload, L"terminal_observed", &p.TerminalObserved) ||
        !Boolean(payload, L"traversal_complete", &p.TraversalComplete) || !Boolean(payload, L"inconsistent", &p.Inconsistent) ||
        !mcpjson::GetString(payload, L"end_reason", &p.EndReason) || !Array(payload, L"slices", 2048, &rows)) { return false; }
    for (const auto& row : rows)
    {
        ImageSweepSlice entry;
        if (!Number(row, L"ordinal", &entry.Ordinal) || !Number(row, L"read_set_id", &entry.ReadSetId) ||
            !Number(row, L"start_range", &entry.StartRange) || !Number(row, L"range_count", &entry.RangeCount) ||
            !Number(row, L"started_tick", &entry.StartedTick) || !Number(row, L"ended_tick", &entry.EndedTick) ||
            !Number(row, L"observed_filetime", &entry.ObservedFileTime) || !Boolean(row, L"terminal", &entry.Terminal) ||
            !Boolean(row, L"traversal_complete", &entry.TraversalComplete) || !mcpjson::GetString(row, L"reason", &entry.Reason) ||
            !mcpjson::GetString(row, L"reference_sha256", &entry.ReferenceSha256) || !Boolean(row, L"reference_written", &entry.ReferenceWritten) ||
            !mcpjson::GetString(row, L"raw_payload_sha256", &entry.RawPayloadSha256) || !Boolean(row, L"raw_written", &entry.RawWritten) ||
            !mcpjson::GetString(row, L"recipe_sha256", &entry.RecipeSha256) || !Boolean(row, L"recipe_written", &entry.RecipeWritten)) { return false; }
        p.Slices.push_back(std::move(entry));
    }
    if (ImageSweepManifestJson(p) != json) { return false; }
    *out = std::move(p);
    return true;
}

std::optional<ImageSweepManifest> ImageSweepManifestStore::Observe(const ImageSweepContext& context)
{
    const auto& s = context.Sweep;
    const auto& row = context.Slice;
    if (!ValidIdentity(s) || !ValidSlice(s, row)) { ++AdmissionDenied; return {}; }
    auto found = Sweeps.find(s.SweepId);
    if (found == Sweeps.end())
    {
        if (Sweeps.size() >= Budget.Groups) { ++AdmissionDenied; return {}; }
        ImageSweepManifest manifest;
        manifest.Sweep = s; manifest.LastEndedTick = s.StartedTick;
        found = Sweeps.emplace(s.SweepId, std::move(manifest)).first;
    }
    auto& p = found->second;
    const bool compatible = IdentityJson(p.Sweep) == IdentityJson(s) && row.Ordinal > p.ObservedSlices &&
        row.StartedTick >= p.LastEndedTick;
    p.Inconsistent |= !compatible;
    p.ObservedSlices = (std::max)(p.ObservedSlices, row.Ordinal);
    p.LastEndedTick = (std::max)(p.LastEndedTick, row.EndedTick);
    if (compatible && Entries < Budget.Entries && p.Slices.size() < (std::min)(size_t{2048}, Budget.EntriesPerGroup))
    {
        p.Slices.push_back(row);
        ++Entries;
    }
    else { ++Dropped; }
    if (!row.Terminal) { return {}; }
    p.TerminalObserved = true;
    p.TraversalComplete = row.TraversalComplete;
    p.EndReason = row.Reason;
    Entries -= p.Slices.size();
    auto completed = std::move(p);
    Sweeps.erase(found);
    return completed;
}

std::optional<ImageSweepManifest> ImageSweepManifestStore::TakeIncomplete()
{
    if (Sweeps.empty()) { return {}; }
    auto found = Sweeps.begin();
    auto p = std::move(found->second);
    Entries -= p.Slices.size();
    Sweeps.erase(found);
    p.EndReason = L"writer_stopped_before_terminal";
    return p;
}
