#include "ImageSliceRecipe.h"
#include "ImageComparisonJson.h"
#include "ObservationReadRoutingJson.h"
#include "BoundedObservationJson.h"
#include "ContentHash.h"
#include "AnalystSnapshot.h"
#include <filesystem>

using namespace bounded_observation_json;

namespace
{
    std::wstring TraceJson(const ExecutableSliceTrace& s)
    {
        return L"{\"entered\":" + B(s.Entered) + L",\"start_range\":" + N(s.StartRange) + L",\"page_count\":" + N(s.PageCount) +
            L",\"previous_relocation_base\":" + N(s.PreviousRelocationBase) + L",\"previous_secondary\":" + B(s.PreviousSecondary) +
            L",\"secondary_needed\":" + B(s.SecondaryNeeded) + L",\"secondary_opened\":" + B(s.SecondaryOpened) +
            L",\"secondary_open_error_win32\":" + N(s.SecondaryOpenError) +
            L",\"secondary_view_base\":" + N(s.SecondaryViewBase) + L",\"relocation_base\":" + N(s.RelocationBase) +
            L",\"rejection_reason\":" + mcpjson::Quote(s.RejectionReason) + L"}";
    }

    std::wstring Normalization(const executable_image::DiskPeMetadata& metadata, const ExecutableSliceTrace& slice)
    {
        ExecutableSweep schedule;
        if (!schedule.Initialize(metadata) || slice.StartRange >= schedule.Ranges.size() ||
            slice.PageCount > schedule.Ranges.size() - slice.StartRange) { return L""; }
        std::wstring json = L"[";
        for (uint32_t i = 0; i < slice.PageCount; ++i)
        {
            const auto& range = schedule.Ranges[slice.StartRange + i];
            const auto row = ImageComparisonNormalizationJson(metadata, slice.RelocationBase,
                static_cast<uint32_t>(range.Address), static_cast<uint32_t>(range.Size), slice.SecondaryNeeded);
            if (row.empty() || json.size() + row.size() > ImageRecipeMaxBytes / 2) { return L""; }
            if (i != 0) { json += L","; }
            json += row;
        }
        return json + L"]";
    }

    std::wstring Results(const std::vector<ExecutablePageResult>& pages)
    {
        std::wstring json = L"[";
        for (const auto& page : pages)
        {
            const auto row = L"{\"secondary_basis\":" + B(page.SecondaryImageView) + L",\"comparison\":" +
                ImageComparisonResultJson(page, page.Coverage.InventoryAvailable) + L"}";
            if (json.size() + row.size() > ImageRecipeMaxBytes / 2) { return L""; }
            if (json.size() != 1) { json += L","; }
            json += row;
        }
        return json + L"]";
    }

    bool Valid(const ImageSliceRecipe& p)
    {
        const auto& s = p.Slice;
        if (p.Policy != (s.SecondaryNeeded ? ImageSliceSecondaryPolicy : ImageSliceDirectPolicy) ||
            p.ReferenceSha256.size() != 64 || p.ReferenceSha256.find_first_not_of(L"0123456789abcdef") != std::wstring::npos ||
            !Text(p.OriginalReference, 30000) || !Text(p.OriginalFileIdentity, 128) || p.CapturedFileTime == 0 || p.ImageBase == 0 ||
            !s.Entered || s.StartRange >= 262144 || s.PageCount > 4096 || !Text(s.RejectionReason, 256, true) ||
            (!s.SecondaryNeeded && (s.SecondaryOpened || s.SecondaryViewBase != 0 || s.SecondaryOpenError != 0)) ||
            (s.SecondaryOpened && s.SecondaryOpenError != 0) ||
            (s.SecondaryOpened && (s.SecondaryViewBase == 0 || (s.SecondaryViewBase & 0xFFFF) != 0)) ||
            p.Normalization.empty() || p.Normalization.size() > ImageRecipeMaxBytes / 2 || p.Normalization.front() != L'[' ||
            p.RecordedResult.empty() || p.RecordedResult.size() > ImageRecipeMaxBytes / 2 || p.RecordedResult.front() != L'[' ||
            !mcpjson::ValidateDocument(p.Normalization) || !mcpjson::ValidateDocument(p.RecordedResult) ||
            p.TargetReads.ParserReads.empty() || !ValidObservationRoutedReadSet(p.TargetReads)) { return false; }
        if (s.SecondaryOpened)
        {
            if (!ValidObservationRoutedReadSet(s.SecondaryReads) || s.SecondaryReads.ParserReads.empty() ||
                s.SecondaryReads.Attempts.StartedTick < p.TargetReads.Attempts.StartedTick ||
                s.SecondaryReads.Attempts.SnapshotTick > p.TargetReads.Attempts.SnapshotTick ||
                s.SecondaryReads.Attempts.TargetId != L"reference:" + p.ReferenceSha256 ||
                s.SecondaryReads.Attempts.AddressSpaceId != L"reference_view:" + p.ReferenceSha256 + L":" + std::to_wstring(s.SecondaryViewBase) ||
                s.SecondaryReads.Attempts.Budget.MaximumBytes > 4 * 1024 * 1024 ||
                s.SecondaryReads.Attempts.Budget.MaximumSourceCalls > 1024 || s.SecondaryReads.Attempts.Budget.MaximumReceipts > 1024) { return false; }
            for (const auto& receipt : s.SecondaryReads.Attempts.Reads)
            {
                if (receipt.Source.SourceId != s.SecondaryReads.Attempts.AddressSpaceId ||
                    receipt.Source.Consistency != L"file_bound_sec_image_no_execute" || !receipt.Source.UserOnly ||
                    receipt.Source.KernelOnly || !receipt.Source.MayChangeResidency || receipt.Request.FallbackFromReceipt != 0) { return false; }
            }
        }
        else if (!s.SecondaryReads.ParserReads.empty() || !s.SecondaryReads.Attempts.OperationId.empty() ||
            !s.SecondaryReads.Attempts.Reads.empty() || s.SecondaryReads.UnrecordedParserCalls != 0) { return false; }
        return true;
    }

    std::wstring Payload(const ImageSliceRecipe& p)
    {
        return L"{\"policy\":" + mcpjson::Quote(p.Policy) + L",\"reference_sha256\":" + mcpjson::Quote(p.ReferenceSha256) +
            L",\"original_reference\":" + mcpjson::Quote(p.OriginalReference) + L",\"original_file_identity\":" + mcpjson::Quote(p.OriginalFileIdentity) +
            L",\"captured_filetime\":" + N(p.CapturedFileTime) + L",\"image_base\":" + N(p.ImageBase) +
            L",\"slice\":" + TraceJson(p.Slice) + L",\"normalization\":" + p.Normalization + L",\"recorded_result\":" + p.RecordedResult +
            L",\"target_reads\":" + ObservationRoutedReadSetJson(p.TargetReads) + L",\"secondary_reads\":" +
            (p.Slice.SecondaryOpened ? ObservationRoutedReadSetJson(p.Slice.SecondaryReads) : L"null") +
            L",\"reference_content_rechecked\":true,\"reference_content_stable\":true,\"reference_level\":\"R-retained\","
            L"\"collector_authenticated\":false,\"approved_reference\":false,\"atomic_snapshot\":false,\"execution_observed\":false}";
    }

    class RecordedParser
    {
    public:
        RecordedParser(const ObservationRoutedReadSet& reads, uint64_t& lastTick) : Reads(reads), LastTick(lastTick) {}
        bool Read(uint64_t address, size_t length, std::vector<uint8_t>* bytes)
        {
            bytes->clear();
            if (Cursor == Reads.ParserReads.size() || Reads.ParserReads[Cursor].Address != address || Reads.ParserReads[Cursor].Length != length)
            {
                Mismatch = true;
                return false;
            }
            const auto& call = Reads.ParserReads[Cursor++];
            if (call.PrimaryReceipt != 0)
            {
                const auto& first = Reads.Attempts.Reads[static_cast<size_t>(call.PrimaryReceipt - 1)];
                const auto& last = Reads.Attempts.Reads[static_cast<size_t>(call.ReturnedReceipt - 1)];
                if (first.Result.StartedTick < LastTick) { Mismatch = true; return false; }
                LastTick = last.Result.EndedTick;
                if (call.Accepted)
                {
                    for (const auto& span : last.Result.Spans) { bytes->insert(bytes->end(), span.Bytes.begin(), span.Bytes.end()); }
                }
            }
            return call.Accepted && bytes->size() == length;
        }
        bool Complete() const { return !Mismatch && Cursor == Reads.ParserReads.size(); }
    private:
        const ObservationRoutedReadSet& Reads;
        uint64_t& LastTick;
        size_t Cursor = 0;
        bool Mismatch = false;
    };

    std::wstring Proof(const ImageSliceRecipe& p, const std::vector<ExecutablePageResult>& pages, const std::wstring& digest)
    {
        uint64_t requested = 0, compared = 0, skipped = 0, failed = 0, changed = 0;
        bool qualified = !pages.empty() && p.Slice.RejectionReason.empty();
        std::wstring matches = L"[", differs = L"[";
        const auto add = [](std::wstring& json, uint64_t address, uint64_t length)
        {
            if (json.size() > 1) { json += L","; }
            json += L"{\"address\":" + N(address) + L",\"length\":" + N(length) + L"}";
        };
        for (const auto& page : pages)
        {
            const auto& c = page.Coverage;
            if (c.RequestedBytes == 0 || c.RequestedBytes > 4096 || c.RangesTruncated ||
                p.ImageBase > UINT64_MAX - page.Rva || p.ImageBase + page.Rva > UINT64_MAX - c.RequestedBytes ||
                c.ComparedBytes + c.SkippedBytes + c.FailedBytes != c.RequestedBytes) { return L""; }
            const auto start = p.ImageBase + page.Rva;
            std::vector<uint8_t> classes(static_cast<size_t>(c.RequestedBytes), 0);
            const auto mark = [&](const std::vector<ObservationRange>& ranges, uint8_t kind, bool relative)
            {
                for (const auto& range : ranges)
                {
                    if (relative && p.ImageBase > UINT64_MAX - range.Address) { return false; }
                    const auto address = range.Address + (relative ? p.ImageBase : 0);
                    if (range.Size == 0 || address < start || address - start >= classes.size() ||
                        range.Size > classes.size() - (address - start)) { return false; }
                    for (uint64_t i = address - start; i < address - start + range.Size; ++i)
                    {
                        auto& entry = classes[static_cast<size_t>(i)];
                        if ((kind == 8 && entry != 1) || (kind != 8 && entry != 0)) { return false; }
                        entry |= kind;
                    }
                }
                return true;
            };
            const auto count = [&](uint8_t kind) { return static_cast<uint64_t>(std::count(classes.begin(), classes.end(), kind)); };
            if (!mark(c.Compared, 1, false) || !mark(c.Skipped, 2, false) || !mark(c.Failed, 4, false) || !mark(page.Changes, 8, true) ||
                count(1) + count(9) != c.ComparedBytes || count(2) != c.SkippedBytes || count(4) != c.FailedBytes) { return L""; }
            qualified &= c.InventoryAvailable;
            requested += c.RequestedBytes; compared += c.ComparedBytes; skipped += c.SkippedBytes; failed += c.FailedBytes;
            for (const auto& range : page.Changes) { changed += range.Size; add(differs, p.ImageBase + range.Address, range.Size); }
            uint64_t run = 0;
            for (size_t i = 0; i <= classes.size(); ++i)
            {
                if (i < classes.size() && classes[i] == 1) { ++run; }
                else if (run != 0) { add(matches, start + i - run, run); run = 0; }
            }
        }
        return L"{\"schema\":\"kn.image_slice_proof.v1\",\"recipe_sha256\":" + mcpjson::Quote(digest) +
            L",\"reference_level\":\"R-retained\",\"policy\":" + mcpjson::Quote(p.Policy) +
            L",\"scope\":\"executed_slice_ranges\",\"whole_sweep_complete\":false,\"slice_rejection_reason\":" +
            mcpjson::Quote(p.Slice.RejectionReason) + L",\"target_reference_qualified\":" + B(qualified) + L",\"matches\":" + matches +
            L"],\"differs\":" + differs + L"],\"requested_bytes\":" + N(requested) + L",\"compared_bytes\":" + N(compared) +
            L",\"excluded_bytes\":" + N(skipped) + L",\"unreadable_bytes\":" + N(failed) + L",\"changed_bytes\":" + N(changed) +
            L",\"target_read_requested_bytes\":" + N(p.TargetReads.Attempts.ChargedBytes) +
            L",\"secondary_read_requested_bytes\":" + N(p.Slice.SecondaryReads.Attempts.ChargedBytes) +
            L",\"unfulfilled_requirements\":[" + (qualified ? std::wstring() : L"\"stable_target_reference_qualification\",") +
            L"\"approved_reference_provenance\",\"atomic_mapping_lifetime\",\"execution_observation\"],"
            L"\"collector_authenticated\":false,\"atomic_snapshot\":false,\"execution_observed\":false}";
    }
}

std::wstring ImageSliceRecipeJson(const ImageSliceRecipe& p)
{
    if (!Valid(p)) { return L""; }
    const auto payload = Payload(p);
    const auto utf8 = mcpjson::WideToUtf8(payload);
    if (utf8.size() > ImageRecipeMaxBytes - 256) { return L""; }
    const auto hash = ContentHash::Bytes(std::vector<uint8_t>(utf8.begin(), utf8.end()));
    return hash.empty() ? L"" : L"{\"schema\":" + mcpjson::Quote(p.Slice.SecondaryNeeded ? L"kn.image_slice.v2" : L"kn.image_slice.v1") +
        L",\"recipe_sha256\":" + mcpjson::Quote(hash) + L",\"payload\":" + payload + L"}";
}

std::wstring ImageSliceInputsJson(const ExecutableSliceTrace& slice)
{
    const auto json = L"{\"schema\":\"kn.image_slice_inputs.v1\",\"slice\":" + TraceJson(slice) +
        L",\"secondary_reads\":" + (slice.SecondaryOpened ? ObservationRoutedReadSetJson(slice.SecondaryReads) : L"null") +
        L",\"image_verification_replayed\":false,\"collector_authenticated\":false}";
    return mcpjson::WideToUtf8(json).size() <= ImageRecipeMaxBytes ? json : L"";
}

bool ParseImageSliceRecipe(const std::wstring& json, ImageSliceRecipe* out)
{
    if (out == nullptr || json.size() > ImageRecipeMaxBytes || !mcpjson::ValidateDocument(json)) { return false; }
    ImageSliceRecipe p;
    std::wstring payload, slice, target, secondary;
    auto& s = p.Slice;
    if (!mcpjson::FindRawValue(json, L"payload", &payload) || !mcpjson::GetString(payload, L"policy", &p.Policy) ||
        !mcpjson::GetString(payload, L"reference_sha256", &p.ReferenceSha256) || !mcpjson::GetString(payload, L"original_reference", &p.OriginalReference) ||
        !mcpjson::GetString(payload, L"original_file_identity", &p.OriginalFileIdentity) || !Number(payload, L"captured_filetime", &p.CapturedFileTime) ||
        !Number(payload, L"image_base", &p.ImageBase) || !mcpjson::FindRawValue(payload, L"slice", &slice) ||
        !Boolean(slice, L"entered", &s.Entered) || !Number(slice, L"start_range", &s.StartRange) || !Number(slice, L"page_count", &s.PageCount) ||
        !Number(slice, L"previous_relocation_base", &s.PreviousRelocationBase) || !Boolean(slice, L"previous_secondary", &s.PreviousSecondary) ||
        !Boolean(slice, L"secondary_needed", &s.SecondaryNeeded) || !Boolean(slice, L"secondary_opened", &s.SecondaryOpened) ||
        !Number(slice, L"secondary_open_error_win32", &s.SecondaryOpenError) ||
        !Number(slice, L"secondary_view_base", &s.SecondaryViewBase) || !Number(slice, L"relocation_base", &s.RelocationBase) ||
        !mcpjson::GetString(slice, L"rejection_reason", &s.RejectionReason) || !mcpjson::FindRawValue(payload, L"normalization", &p.Normalization) ||
        !mcpjson::FindRawValue(payload, L"recorded_result", &p.RecordedResult) || !mcpjson::FindRawValue(payload, L"target_reads", &target) ||
        !ParseObservationRoutedReadSet(target, &p.TargetReads) || !mcpjson::FindRawValue(payload, L"secondary_reads", &secondary) ||
        (s.SecondaryOpened ? !ParseObservationRoutedReadSet(secondary, &s.SecondaryReads) : secondary != L"null") ||
        ImageSliceRecipeJson(p) != json) { return false; }
    *out = std::move(p);
    return true;
}

std::wstring CaptureImageSliceRecipeJson(const executable_image::DiskPeMetadata& metadata, uint64_t imageBase,
    const ExecutableSweepReference& reference, const ExecutableSliceTrace& slice,
    const ObservationRoutedReadSet& reads, const std::vector<ExecutablePageResult>& pages)
{
    if (metadata.Machine != IMAGE_FILE_MACHINE_AMD64 || metadata.OptionalMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        reference.Artifact == nullptr || !reference.ContentRechecked || !reference.ContentStable || pages.size() != slice.PageCount) { return L""; }
    ImageSliceRecipe p;
    p.Policy = slice.SecondaryNeeded ? ImageSliceSecondaryPolicy : ImageSliceDirectPolicy;
    p.ReferenceSha256 = reference.Artifact->Sha256;
    p.OriginalReference = reference.Artifact->OriginalPath;
    p.OriginalFileIdentity = reference.Artifact->OriginalFileIdentity;
    FILETIME time{}; GetSystemTimeAsFileTime(&time);
    p.CapturedFileTime = (uint64_t(time.dwHighDateTime) << 32) | time.dwLowDateTime;
    p.ImageBase = imageBase;
    p.Slice = slice;
    p.TargetReads = reads;
    p.Normalization = Normalization(metadata, slice);
    p.RecordedResult = Results(pages);
    return ImageSliceRecipeJson(p);
}

ImageRecipeReplay ReplayImageSliceRecipe(const std::wstring& path, std::wstring* error)
{
    ImageRecipeReplay result;
    result.Schema = L"kn.image_slice_replay.v1";
    result.Mode = L"original_policy";
    result.CurrentPolicy.clear();
    if (error != nullptr) { *error = L"slice recipe or original inputs could not be verified"; }
    std::wstring json;
    ImageSliceRecipe p;
    if (!ReadAnalystSnapshot(path, &json, error, ImageRecipeMaxBytes, nullptr, true) || !ParseImageSliceRecipe(json, &p))
    {
        result.Status = L"recipe_unavailable_or_corrupt";
        return result;
    }
    result.RecordedPolicy = p.Policy;
    result.CurrentPolicy = p.Policy;
    result.RecordedResult = p.RecordedResult;
    mcpjson::GetString(json, L"recipe_sha256", &result.RecipeSha256);
    const auto store = std::filesystem::path(path).parent_path().parent_path() / L"image-references";
    ReferenceArtifact artifact;
    if (!artifact.Open((store / (p.ReferenceSha256 + L".knblob")).wstring(), error))
    {
        result.Status = L"reference_missing_or_unreadable";
        return result;
    }
    if (artifact.Sha256() != p.ReferenceSha256) { result.Status = L"reference_corrupt"; return result; }
    executable_image::DiskPeMetadata metadata;
    if (!executable_image::ReadDiskPeMetadata(artifact.Path(), &metadata, error) || metadata.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        result.Status = L"reference_parse_failed";
        return result;
    }
    if (Normalization(metadata, p.Slice) != p.Normalization) { result.Status = L"normalization_mismatch"; return result; }
    uint64_t lastTick = 0;
    RecordedParser target(p.TargetReads, lastTick), secondary(p.Slice.SecondaryReads, lastTick);
    ExecutableSliceTrace reproduced;
    const auto pages = ReplayExecutableSlice(artifact.Path(), metadata, p.ImageBase,
        [&](uint64_t address, size_t length, std::vector<uint8_t>* bytes) { return target.Read(address, length, bytes); },
        [&](uint64_t address, size_t length, std::vector<uint8_t>* bytes) { return secondary.Read(address, length, bytes); }, p.Slice, &reproduced);
    if (!artifact.Unchanged()) { result.Status = L"reference_changed_during_replay"; return result; }
    if (!target.Complete() || !secondary.Complete()) { result.Status = L"recorded_read_set_mismatch"; return result; }
    result.CurrentResult = Results(pages);
    if (TraceJson(reproduced) != TraceJson(p.Slice) || result.CurrentResult.empty() || result.CurrentResult != p.RecordedResult)
    {
        result.Status = L"recorded_result_mismatch";
        return result;
    }
    result.Proof = Proof(p, pages, result.RecipeSha256);
    if (result.Proof.empty()) { result.Status = L"comparison_accounting_failed"; return result; }
    result.Status = L"replayed";
    if (error != nullptr) { error->clear(); }
    return result;
}
