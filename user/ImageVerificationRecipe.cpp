#include "ImageVerificationRecipe.h"
#include "AnalystSnapshot.h"
#include "ContentHash.h"
#include "ImageProof.h"
#include "McpJson.h"
#include "ReferenceArtifact.h"
#include "ImageComparisonJson.h"
#include "ImageSliceRecipe.h"
#include <filesystem>

namespace
{
    std::wstring N(uint64_t value)
    {
        return mcpjson::Quote(std::to_wstring(value));
    }
    std::wstring B(bool value)
    {
        return value ? L"true" : L"false";
    }
    std::wstring Hex(const uint8_t* bytes, size_t length)
    {
        std::wstring text;
        for (size_t i = 0; i < length; ++i)
        {
            text += L"0123456789abcdef"[bytes[i] >> 4];
            text += L"0123456789abcdef"[bytes[i] & 15];
        }
        return text;
    }
    std::wstring Ranges(const std::vector<ObservationRange>& ranges)
    {
        std::wstring json = L"[";
        for (const auto& range : ranges)
        {
            if (json.size() > 1)
            {
                json += L",";
            }
            json += L"[" + N(range.Address) + L"," + N(range.Size) + L"]";
        }
        return json + L"]";
    }

    std::wstring ResultJson(const ExecutablePageResult& p, bool qualified)
    {
        const auto& c = p.Coverage;
        return L"{\"reference_qualified\":" + B(qualified) + L",\"ownership\":" + mcpjson::Quote(CodeOwnershipName(p.Ownership)) +
            L",\"reason\":" + mcpjson::Quote(c.Reason) + L",\"rva\":" + N(p.Rva) + L",\"relocation_base\":" + N(p.RelocationBase) +
            L",\"requested_bytes\":" + N(c.RequestedBytes) + L",\"compared_bytes\":" + N(c.ComparedBytes) +
            L",\"skipped_bytes\":" + N(c.SkippedBytes) + L",\"failed_bytes\":" + N(c.FailedBytes) +
            L",\"attempted\":" + B(c.Attempted) + L",\"inventory_available\":" + B(c.InventoryAvailable) +
            L",\"traversal_complete\":" + B(c.TraversalComplete) + L",\"ranges_truncated\":" + B(c.RangesTruncated) +
            L",\"rel32_validated_bytes\":" + N(p.Rel32ValidatedBytes) + L",\"compared\":" + Ranges(c.Compared) +
            L",\"skipped\":" + Ranges(c.Skipped) + L",\"failed\":" + Ranges(c.Failed) + L",\"changes\":" + Ranges(p.Changes) +
            L",\"expected_hex\":" + mcpjson::Quote(Hex(p.Expected.data(), p.Expected.size())) +
            L",\"observed_hex\":" + mcpjson::Quote(Hex(p.Observed.data(), p.Observed.size())) + L"}";
    }

    std::wstring Normalization(const executable_image::DiskPeMetadata& m, uint64_t base, uint32_t rva, uint32_t size, bool secondary = false)
    {
        if (m.Sections.size() > 96)
        {
            return L"";
        }
        const auto overlaps = [&](uint32_t start, uint32_t count)
        {
            return count != 0 && uint64_t(start) < uint64_t(rva) + size && rva < uint64_t(start) + count;
        };
        std::wstring json = L"{\"schema\":" + mcpjson::Quote(secondary ? L"kn.image_normalization.secondary.v1" : L"kn.image_normalization.direct.v1") + L",\"machine\":" + N(m.Machine) +
            L",\"optional_magic\":" + N(m.OptionalMagic) + L",\"image_size\":" + N(m.SizeOfImage) +
            L",\"headers_size\":" + N(m.SizeOfHeaders) + L",\"image_base\":" + N(m.ImageBase) + L",\"relocation_base\":" + N(base) +
            L",\"timestamp\":" + N(m.TimeDateStamp) + L",\"checksum\":" + N(m.CheckSum) + L",\"entrypoint\":" + N(m.EntryPointRva) +
            L",\"pdb_present\":" + B(m.HasPdbIdentity) + L",\"pdb_guid_bytes\":" + mcpjson::Quote(Hex(reinterpret_cast<const uint8_t*>(&m.PdbGuid), sizeof(m.PdbGuid))) +
            L",\"pdb_age\":" + N(m.PdbAge) + L",\"pdb_rva\":" + N(m.PdbRva) +
            L",\"relocations_present\":" + B(m.BaseRelocationTablePresent) + L",\"relocations_complete\":" + B(m.BaseRelocationTableComplete) +
            L",\"dynamic_present\":" + B(m.DynamicRelocationTablePresent) + L",\"dynamic_complete\":" + B(m.DynamicRelocationTableComplete) +
            L",\"secondary_basis\":" + B(secondary) + L",\"sections\":[";
        bool first = true;
        for (const auto& s : m.Sections)
        {
            if (!first)
            {
                json += L",";
            }
            first = false;
            json += L"[" + N(s.VirtualAddress) + L"," + N(s.VirtualSize) + L"," + N(s.PointerToRawData) + L"," +
                N(s.SizeOfRawData) + L"," + N(s.Characteristics) + L"]";
        }
        json += L"],\"relocations\":[";
        first = true;
        for (const auto& relocation : m.BaseRelocations)
        {
            if (overlaps(relocation.Rva, relocation.Width))
            {
                if (!first)
                {
                    json += L",";
                }
                first = false;
                json += L"[" + N(relocation.Rva) + L"," + N(relocation.Width) + L"]";
            }
        }
        const auto exclusions = [&](const std::vector<executable_image::DiskPeMutableRange>& ranges)
        {
            std::wstring values = L"[";
            for (const auto& range : ranges)
            {
                if (overlaps(range.Rva, range.Size))
                {
                    if (values.size() > 1)
                    {
                        values += L",";
                    }
                    values += L"[" + N(range.Rva) + L"," + N(range.Size) + L"]";
                }
            }
            return values + L"]";
        };
        json += L"],\"loader_exclusions\":" + exclusions(m.LoaderMutableRanges) +
            L",\"dynamic_exclusions\":" + exclusions(m.DynamicRelocationRanges) + L",\"rel32_overrides\":[";
        first = true;
        for (const auto& fixup : m.Rel32Overrides)
        {
            if (!overlaps(fixup.Rva, 4))
            {
                continue;
            }
            if (!first)
            {
                json += L",";
            }
            first = false;
            json += L"{\"rva\":" + N(fixup.Rva) + L",\"original_rva\":" + N(fixup.OriginalRva) + L",\"targets\":[";
            for (size_t i = 0; i < fixup.Targets.size(); ++i)
            {
                if (i != 0)
                {
                    json += L",";
                }
                json += N(fixup.Targets[i]);
            }
            json += L"]}";
        }
        json += L"]}";
        return json.size() <= 512 * 1024 ? json : L"";
    }

    std::wstring Execute(const ReferenceArtifact& artifact, const executable_image::DiskPeMetadata& metadata,
        const ImageVerificationRecipe& recipe, const ObservationReader& reader,
        ExecutablePageResult* comparison = nullptr, bool* referenceQualified = nullptr)
    {
        ExecutablePageResult result;
        result.Rva = recipe.Rva;
        std::wstring reason;
        uint64_t beforeBase = 0, afterBase = 0;
        bool qualified = QualifyExecutableReference(metadata, recipe.ImageBase, reader, &reason, &beforeBase);
        if (qualified)
        {
            result = CompareExecutableRange(artifact.Path(), metadata, recipe.ImageBase, recipe.Rva, recipe.Length, reader);
            qualified = QualifyExecutableReference(metadata, recipe.ImageBase, reader, &reason, &afterBase);
            if (qualified && beforeBase != afterBase)
            {
                qualified = false;
                reason = L"image_identity_changed_during_compare";
            }
        }
        if (!qualified)
        {
            result.Ownership = CodeOwnership::OwnedUnverified;
            result.Changes.clear();
            result.Rel32ValidatedBytes = 0;
            result.Coverage = {};
            result.Coverage.Attempted = true;
            result.Coverage.RequestedBytes = recipe.Length;
            result.Coverage.FailedBytes = recipe.Length;
            result.Coverage.Failed.push_back({recipe.ImageBase + recipe.Rva, recipe.Length});
            result.Coverage.Reason = reason;
        }
        const auto json = ResultJson(result, qualified);
        if (comparison != nullptr)
        {
            *comparison = std::move(result);
        }
        if (referenceQualified != nullptr)
        {
            *referenceQualified = qualified;
        }
        return json;
    }

    bool ExactBytes(const ImageRecipeRead& read, std::vector<uint8_t>* bytes)
    {
        bytes->clear();
        if (read.Result.State != ObservationReadState::Complete || read.Result.CancellationObserved || read.Result.OperationDeadlineExceeded)
        {
            return false;
        }
        for (const auto& span : read.Result.Spans)
        {
            bytes->insert(bytes->end(), span.Bytes.begin(), span.Bytes.end());
        }
        return bytes->size() == read.Length;
    }

    bool ReanalysisRead(const ImageVerificationRecipe& recipe, uint64_t address, size_t length, std::vector<uint8_t>* bytes)
    {
        if (length == 0 || length > 4096 || address > UINT64_MAX - length)
        {
            return false;
        }
        std::vector<uint8_t> values(length), present(length, 0);
        for (const auto& read : recipe.Reads)
        {
            if (read.Address >= address + length || read.Address + read.Length <= address)
            {
                continue;
            }
            if (read.Result.CancellationObserved || read.Result.Spans.empty())
            {
                return false;
            }
            for (const auto& span : read.Result.Spans)
            {
                const auto begin = (std::max)(address, span.Address);
                const auto end = (std::min)(address + length, span.Address + span.RequestedBytes);
                if (begin >= end)
                {
                    continue;
                }
                if (span.State != ObservationReadState::Complete)
                {
                    return false;
                }
                for (uint64_t current = begin; current < end; ++current)
                {
                    const size_t index = static_cast<size_t>(current - address);
                    const uint8_t value = span.Bytes[static_cast<size_t>(current - span.Address)];
                    if (present[index] != 0 && values[index] != value)
                    {
                        return false;
                    }
                    values[index] = value;
                    present[index] = 1;
                }
            }
        }
        if (std::find(present.begin(), present.end(), 0) != present.end())
        {
            return false;
        }
        *bytes = std::move(values);
        return true;
    }
}

std::wstring ImageComparisonResultJson(const ExecutablePageResult& result, bool qualified)
{
    return ResultJson(result, qualified);
}

std::wstring ImageComparisonNormalizationJson(const executable_image::DiskPeMetadata& metadata,
    uint64_t base, uint32_t rva, uint32_t length, bool secondary)
{
    return Normalization(metadata, base, rva, length, secondary);
}

static bool CaptureImageRecipeImpl(const std::wstring& image, IObservationSource& source, uint64_t imageBase,
    uint32_t rva, uint32_t length, const std::wstring& newDirectory, ImageVerificationRecipe* recipe,
    std::wstring* error, const std::atomic<bool>* cancellation, const ImageRecipeCaptureOptions* options)
{
    if (error != nullptr)
    {
        *error = L"image capture requires a bounded source, an exact reference and a new local directory";
    }
    const auto caps = source.Capabilities();
    if (options != nullptr)
    {
        const auto& b = options->Budget;
        const auto text = [](const std::wstring& value)
        {
            return !value.empty() && value.size() <= 2048 && value.find(L'\0') == std::wstring::npos &&
                mcpjson::SanitizeUtf16(value) == value;
        };
        if (!text(options->TargetId) || !text(options->AddressSpaceId) || b.MaximumBytes > ImageRecipeReadBudget ||
            b.MaximumSourceCalls > ImageRecipeMaxReads || b.MaximumReceipts == 0 || b.MaximumReceipts > ImageRecipeMaxReads ||
            b.MaximumStoredSpans > 65536 || b.MaximumElapsedMs == 0 || b.MaximumElapsedMs > 60000) { return false; }
    }
    if (recipe == nullptr || imageBase == 0 || imageBase > UINT64_MAX - rva || imageBase + rva > UINT64_MAX - length ||
        length == 0 || length > 4096 || caps.AddressDomain != ObservationAddressDomain::Virtual ||
        !caps.AddressSpace.Valid() || caps.SourceId.empty() ||
        newDirectory.empty() || newDirectory.size() > 29000 || newDirectory.find(L'\0') != std::wstring::npos ||
        newDirectory.rfind(L"\\\\", 0) == 0 || newDirectory.rfind(L"\\??\\", 0) == 0)
    {
        return false;
    }
    if ((!caps.AddressSpace.UserRange(imageBase, 1) && !caps.AddressSpace.KernelRange(imageBase, 1)) ||
        (!caps.AddressSpace.UserRange(imageBase + rva, length) && !caps.AddressSpace.KernelRange(imageBase + rva, length)))
    {
        return false;
    }
    ReferenceArtifact original;
    if (!original.Open(image, error))
    {
        return false;
    }
    std::error_code ec;
    const auto directory = std::filesystem::absolute(newDirectory, ec);
    const auto path = directory.wstring();
    if (ec || path.size() < 3 || path[1] != L':' || path.find(L':', 2) != std::wstring::npos ||
        !std::filesystem::create_directory(directory, ec) || ec)
    {
        return false;
    }
    const auto blob = directory / (original.Sha256() + L".knblob");
    if (!PublishReferenceArtifact(blob.wstring(), original.Bytes(), error) || !original.Unchanged())
    {
        return false;
    }
    ReferenceArtifact retained;
    executable_image::DiskPeMetadata metadata;
    if (!retained.Open(blob.wstring(), error) || retained.Sha256() != original.Sha256() ||
        !executable_image::ReadDiskPeMetadata(retained.Path(), &metadata, error) || metadata.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        return false;
    }
    ImageVerificationRecipe p;
    p.FormatVersion = options == nullptr ? 1 : 2;
    p.ReferenceSha256 = original.Sha256();
    p.OriginalReference = original.Path();
    p.OriginalFileIdentity = original.FileIdentity();
    p.SourceId = caps.SourceId;
    p.SourceConsistency = caps.Consistency;
    p.VirtualAddressBits = caps.AddressSpace.VirtualAddressBits;
    p.ImageBase = imageBase;
    p.Rva = rva;
    p.Length = length;
    FILETIME now{};
    GetSystemTimeAsFileTime(&now);
    p.CapturedFileTime = (uint64_t(now.dwHighDateTime) << 32) | now.dwLowDateTime;
    p.Normalization = Normalization(metadata, imageBase, rva, length);
    std::shared_ptr<ObservationReadOperation> operation;
    std::unique_ptr<RecordingObservationSource> recorded;
    if (options != nullptr)
    {
        static std::atomic<uint64_t> sequence{0};
        const auto id = L"image:" + std::to_wstring(GetCurrentProcessId()) + L":" +
            std::to_wstring(p.CapturedFileTime) + L":" + std::to_wstring(++sequence);
        operation = std::make_shared<ObservationReadOperation>(id, options->TargetId, options->AddressSpaceId, options->Budget);
        recorded = std::make_unique<RecordingObservationSource>(source, operation);
    }
    uint64_t remaining = ImageRecipeReadBudget;
    bool exhausted = false;
    bool sourceChanged = false;
    const ObservationReader recording = [&](uint64_t address, size_t size, std::vector<uint8_t>* bytes)
    {
        bytes->clear();
        if (exhausted || sourceChanged) { return false; }
        if (!SameObservationSourceContract(caps, source.Capabilities()))
        {
            sourceChanged = true;
            return false;
        }
        if (size == 0 || size > 4096 || size > remaining || p.Reads.size() == ImageRecipeMaxReads)
        {
            exhausted = true;
            return false;
        }
        ObservationReadRequest request;
        request.SourceId = p.SourceId;
        request.Address = address;
        request.Length = static_cast<uint32_t>(size);
        request.ByteBudget = remaining;
        request.Cancellation = cancellation;
        request.AllowResidencyChanges = options != nullptr && options->AllowResidencyChanges;
        ImageRecipeRead read;
        read.Address = address;
        read.Length = request.Length;
        read.Result = (recorded == nullptr ? source : *recorded).Read(request);
        sourceChanged = sourceChanged || !SameObservationSourceContract(caps, source.Capabilities());
        exhausted = exhausted || read.Result.OperationDeadlineExceeded;
        remaining -= size;
        p.Reads.push_back(std::move(read));
        return !sourceChanged && ExactBytes(p.Reads.back(), bytes);
    };
    p.RecordedResult = Execute(retained, metadata, p, recording);
    if (operation != nullptr) { p.ReadSet = operation->Snapshot(); }
    if (exhausted || sourceChanged || !retained.Unchanged() || !original.Unchanged())
    {
        return false;
    }
    const auto json = ImageRecipeJson(p);
    if (json.empty() || !SaveObservationJson((directory / L"recipe.knverify").wstring(), json, error))
    {
        return false;
    }
    *recipe = std::move(p);
    if (error != nullptr)
    {
        error->clear();
    }
    return true;
}

bool CaptureImageRecipe(const std::wstring& image, IObservationSource& source, uint64_t imageBase,
    uint32_t rva, uint32_t length, const std::wstring& newDirectory, ImageVerificationRecipe* recipe,
    std::wstring* error, const std::atomic<bool>* cancellation)
{
    return CaptureImageRecipeImpl(image, source, imageBase, rva, length, newDirectory, recipe, error, cancellation, nullptr);
}

bool CaptureObservedImageRecipe(const std::wstring& image, IObservationSource& source, uint64_t imageBase,
    uint32_t rva, uint32_t length, const std::wstring& newDirectory, const ImageRecipeCaptureOptions& options,
    ImageVerificationRecipe* recipe, std::wstring* error, const std::atomic<bool>* cancellation)
{
    return CaptureImageRecipeImpl(image, source, imageBase, rva, length, newDirectory, recipe, error, cancellation, &options);
}

ImageRecipeReplay ReplayImageRecipe(const std::wstring& directory, bool currentReanalysis, std::wstring* error)
{
    auto extension = std::filesystem::path(directory).extension().wstring();
    std::transform(extension.begin(), extension.end(), extension.begin(), towlower);
    if (extension == L".knslice")
    {
        if (!currentReanalysis) { return ReplayImageSliceRecipe(directory, error); }
        ImageRecipeReplay unsupported;
        unsupported.Schema = L"kn.image_slice_replay.v1";
        unsupported.Mode = L"current_reanalysis";
        unsupported.CurrentPolicy.clear();
        unsupported.Status = L"slice_current_reanalysis_unavailable";
        if (error != nullptr) { *error = L"slice recipes support original-policy replay only"; }
        return unsupported;
    }
    ImageRecipeReplay result;
    result.Mode = currentReanalysis ? L"current_reanalysis" : L"original_policy";
    ImageVerificationRecipe p;
    std::wstring json;
    const auto root = std::filesystem::path(directory);
    if (!ReadAnalystSnapshot((root / L"recipe.knverify").wstring(), &json, error, ImageRecipeMaxBytes, nullptr, true) ||
        !ParseImageRecipe(json, &p, error))
    {
        result.Status = L"recipe_unavailable_or_corrupt";
        return result;
    }
    mcpjson::GetString(json, L"recipe_sha256", &result.RecipeSha256);
    result.RecordedResult = p.RecordedResult;
    result.RecordedPolicy = p.Policy;
    if (!currentReanalysis && p.Policy != ImageRecipePolicy)
    {
        result.Status = L"original_policy_unavailable";
        return result;
    }
    ReferenceArtifact artifact;
    if (!artifact.Open((root / (p.ReferenceSha256 + L".knblob")).wstring(), error))
    {
        result.Status = L"reference_missing_or_unreadable";
        return result;
    }
    if (artifact.Sha256() != p.ReferenceSha256)
    {
        result.Status = L"reference_corrupt";
        return result;
    }
    executable_image::DiskPeMetadata metadata;
    if (!executable_image::ReadDiskPeMetadata(artifact.Path(), &metadata, error) || metadata.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        result.Status = L"reference_parse_failed";
        return result;
    }
    if (!currentReanalysis && Normalization(metadata, p.ImageBase, p.Rva, p.Length) != p.Normalization)
    {
        result.Status = L"normalization_mismatch";
        return result;
    }
    size_t cursor = 0;
    bool mismatch = false;
    const ObservationReader reader = [&](uint64_t address, size_t length, std::vector<uint8_t>* bytes)
    {
        bytes->clear();
        if (currentReanalysis)
        {
            return ReanalysisRead(p, address, length, bytes);
        }
        if (cursor == p.Reads.size() || p.Reads[cursor].Address != address || p.Reads[cursor].Length != length)
        {
            mismatch = true;
            return false;
        }
        return ExactBytes(p.Reads[cursor++], bytes);
    };
    ExecutablePageResult comparison;
    bool referenceQualified = false;
    result.CurrentResult = Execute(artifact, metadata, p, reader, &comparison, &referenceQualified);
    if (!artifact.Unchanged())
    {
        result.CurrentResult.clear();
        result.Status = L"reference_changed_during_replay";
    }
    else if (!currentReanalysis && (mismatch || cursor != p.Reads.size()))
    {
        result.CurrentResult.clear();
        result.Status = L"recorded_read_set_mismatch";
    }
    else if (!currentReanalysis && result.CurrentResult != p.RecordedResult)
    {
        result.Status = L"recorded_result_mismatch";
    }
    else
    {
        result.Status = currentReanalysis ? L"reanalyzed" : L"replayed";
        result.Proof = ImageProofJson(p, AssessImageProof(p, comparison, referenceQualified, currentReanalysis));
        if (error != nullptr)
        {
            error->clear();
        }
    }
    return result;
}
