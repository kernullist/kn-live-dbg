#include "PendingIrpBinding.h"
#include "PendingIrpReport.h"
#include "SchemaArtifact.h"
#include "ExecutableImageVerifier.h"
#include "ObservationReadRoutingJson.h"
#include "BoundedObservationJson.h"

namespace
{
    using namespace bounded_observation_json;
    using pending_irp::IrpLayout;

    std::wstring GuidText(const GUID& guid)
    {
        wchar_t text[33]{};
        swprintf_s(text, L"%08lx%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x", guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
        return text;
    }

    bool SameArtifacts(const TypeSchemaPackage& a, const TypeSchemaPackage& b)
    {
        return a.ImageSha256 == b.ImageSha256 && a.PdbSha256 == b.PdbSha256 && a.PdbGuid == b.PdbGuid &&
            a.PdbAge == b.PdbAge && a.Machine == b.Machine && a.ImageSize == b.ImageSize &&
            a.ProviderSha256 == b.ProviderSha256 && a.ProviderVersion == b.ProviderVersion;
    }

    bool PathMatches(const std::vector<std::wstring>& actual, const std::vector<std::wstring>& wanted)
    {
        size_t part = 0, anonymous = 0;
        for (const auto& name : actual)
        {
            if (part < wanted.size() && name == wanted[part]) { ++part; anonymous = 0; }
            else if (part < wanted.size() && (name.empty() || name.rfind(L"<unnamed", 0) == 0) && anonymous < 3)
            { ++anonymous; }
            else { return false; }
        }
        return part == wanted.size();
    }

    bool Field(const TypeSchemaPackage& schema, std::vector<std::wstring> path, uint32_t bytes, uint32_t* offset)
    {
        const TypeSchemaField* match = nullptr;
        for (const auto& field : schema.Fields)
        {
            if (!PathMatches(field.Path, path)) { continue; }
            // Ambiguity is a gap even if the competing field has a different
            // size/type. Choosing the first matching union arm is not proof.
            if (match != nullptr) { return false; }
            match = &field;
        }
        if (match == nullptr || match->BitWidth != 0 || match->StorageBytes != bytes ||
            match->Offset > schema.TypeBytes || bytes > schema.TypeBytes - match->Offset) { return false; }
        *offset = static_cast<uint32_t>(match->Offset);
        return true;
    }

    std::wstring CursorJson(const PendingIrpCursor& c)
    {
        return L"{\"thread\":" + N(c.ThreadObject) + L",\"created\":" + N(c.ThreadCreateTime) + L",\"irp\":" + N(c.IrpAddress) +
            L",\"head\":" + N(c.List.Head) + L",\"entry\":" + N(c.List.Entry) + L",\"forward\":" + N(c.List.Forward) +
            L",\"backward\":" + N(c.List.Backward) + L"}";
    }

    std::shared_ptr<const PendingIrpEvidenceArtifact> Evidence(const PendingIrpSchemaBinding& binding,
        const executable_image::DiskPeMetadata& m, const std::vector<PendingIrpThreadInput>& threads,
        const PendingIrpScanOptions& options, const PendingIrpScanResult& result, const ObservationRoutedReadSet& reads,
        const std::wstring& before, const std::wstring& after, bool stable)
    {
        std::wstring json = L"{\"schema\":\"kn.irp_capture.v1\",\"policy\":\"schema-image-repeated-snapshot-v1\","
            L"\"collector_authenticated\":false,\"reference_image_preserved\":false,\"pdb_file_preserved\":false,"
            L"\"whole_image_integrity\":false,\"referenced_lifetime\":false,\"atomic_snapshot\":false,"
            L"\"execution_observed\":false,\"source_initialization_recorded\":false,\"schemas\":[";
        for (size_t i = 0; i < binding.Schemas.size(); ++i)
        { if (i != 0) { json += L","; } json += TypeSchemaJson(*binding.Schemas[i]); }
        json += L"],\"image_base\":" + N(binding.ImageBase) + L",\"reference_identity\":{\"image_base\":" + N(m.ImageBase) +
            L",\"machine\":" + N(m.Machine) + L",\"optional_magic\":" + N(m.OptionalMagic) + L",\"image_size\":" + N(m.SizeOfImage) +
            L",\"timestamp\":" + N(m.TimeDateStamp) + L",\"checksum\":" + N(m.CheckSum) + L",\"entry_point\":" + N(m.EntryPointRva) +
            L",\"section_count\":" + N(m.Sections.size()) + L",\"pdb_rva\":" + N(m.PdbRva) + L",\"pdb_guid\":" + mcpjson::Quote(GuidText(m.PdbGuid)) +
            L",\"pdb_age\":" + N(m.PdbAge) + L"},\"image_before\":" + mcpjson::Quote(before) + L",\"image_after\":" + mcpjson::Quote(after) +
            L",\"reference_content_rechecked\":true,\"reference_content_stable\":" + B(stable) +
            L",\"readset_complete\":" + B(ValidObservationRoutedReadSet(reads)) + L",\"runtime_qualified\":" + B(result.RuntimeQualified) +
            L",\"qualification_reason\":" + mcpjson::Quote(result.QualificationReason) +
            L",\"invariants\":[\"schema_artifact_identity_and_field_bounds\",\"loaded_pe_rsds_before_after\","
            L"\"thread_pid_tid_create_time_before_after\",\"reciprocal_irp_list\",\"irp_type_size_owner_stack_ranges\","
            L"\"equal_irp_reads\"],\"thread_inputs\":[";
        for (size_t i = 0; i < threads.size(); ++i)
        {
            if (i != 0) { json += L","; }
            json += L"{\"thread\":" + N(threads[i].ThreadObject) + L",\"pid\":" + N(threads[i].ProcessId) + L",\"tid\":" + N(threads[i].ThreadId) + L"}";
        }
        json += L"],\"options\":{\"max_threads\":" + N(options.MaxThreads) + L",\"max_irps\":" + N(options.MaxIrps) +
            L",\"max_walk_nodes\":" + N(options.MaxWalkNodes) + L",\"inventory_complete\":" + B(options.ThreadInventoryComplete) +
            L",\"cursor\":" + CursorJson(options.Cursor) + L"},\"next_cursor\":" + CursorJson(result.NextCursor) +
            L",\"threads_visited\":" + N(result.ThreadsVisited) + L",\"irps_inspected\":" + N(result.IrpsInspected) +
            L",\"walk_nodes\":" + N(result.WalkNodes) + L",\"unstable_observations\":" + N(result.UnstableObservations) +
            L",\"enumeration_complete\":" + B(result.CoverageComplete) + L",\"requests\":[";
        for (size_t i = 0; i < result.Requests.size(); ++i)
        { if (i != 0) { json += L","; } json += PendingIrpObservationJson(result.Requests[i], result, false); }
        json += L"],\"reads\":" + ObservationRoutedReadSetJson(reads) + L"}";
        const auto utf8 = mcpjson::WideToUtf8(json);
        if (utf8.empty() || utf8.size() > PendingIrpEvidenceMaximumBytes) { return {}; }
        auto artifact = std::make_shared<PendingIrpEvidenceArtifact>();
        artifact->Bytes.assign(utf8.begin(), utf8.end());
        artifact->Sha256 = ContentHash::Bytes(artifact->Bytes);
        return artifact->Sha256.empty() ? nullptr : artifact;
    }
}

bool BuildPendingIrpLayout(const PendingIrpSchemaBinding& binding, pending_irp::IrpLayout* out, std::wstring* error)
{
    if (error) { *error = L"missing_or_incompatible_irp_schemas"; }
    if (!out) { return false; }
    *out = {};
    const wchar_t* names[] = {L"ethread", L"irp", L"io_stack_location"};
    for (size_t i = 0; i < binding.Schemas.size(); ++i)
    {
        const auto& s = binding.Schemas[i];
        if (!s || !s->ParserIsolated || !ValidateTypeSchema(*s, nullptr) || TypeSchemaJson(*s).empty() ||
            NormalizeSchemaTypeAlias(s->TypeName) != names[i] || s->Machine != IMAGE_FILE_MACHINE_AMD64 ||
            !SameArtifacts(*binding.Schemas[0], *s)) { return false; }
    }
    const auto& t = *binding.Schemas[0]; const auto& i = *binding.Schemas[1]; const auto& s = *binding.Schemas[2];
    if (t.TypeBytes == 0 || t.TypeBytes > 0x4000 || i.TypeBytes == 0 || i.TypeBytes > 0x1000 ||
        s.TypeBytes == 0 || s.TypeBytes > 0x1000) { return false; }
    IrpLayout layout;
    layout.ThreadSize = static_cast<uint32_t>(t.TypeBytes);
    layout.IrpSize = static_cast<uint32_t>(i.TypeBytes);
    layout.StackSize = static_cast<uint32_t>(s.TypeBytes);
    Field(i, {L"Cancel"}, 1, &layout.Cancel);
    Field(i, {L"PendingReturned"}, 1, &layout.PendingReturned);
    Field(i, {L"IoStatus", L"Status"}, 4, &layout.IoStatus);
    Field(s, {L"DeviceObject"}, 8, &layout.DeviceObject);
    Field(s, {L"FileObject"}, 8, &layout.FileObject);
    if (!Field(t, {L"IrpList"}, 16, &layout.ThreadIrpList) ||
        !Field(t, {L"Cid", L"UniqueProcess"}, 8, &layout.ThreadPid) ||
        !Field(t, {L"Cid", L"UniqueThread"}, 8, &layout.ThreadTid) ||
        !Field(t, {L"CreateTime"}, 8, &layout.ThreadCreateTime) ||
        !Field(i, {L"Type"}, 2, &layout.IrpType) || !Field(i, {L"Size"}, 2, &layout.PacketSize) ||
        !Field(i, {L"ThreadListEntry"}, 16, &layout.ThreadListEntry) ||
        !Field(i, {L"StackCount"}, 1, &layout.StackCount) || !Field(i, {L"CurrentLocation"}, 1, &layout.CurrentLocation) ||
        !Field(i, {L"Tail", L"Overlay", L"CurrentStackLocation"}, 8, &layout.CurrentStack) ||
        !Field(i, {L"Tail", L"Overlay", L"Thread"}, 8, &layout.OwningThread) ||
        !Field(s, {L"MajorFunction"}, 1, &layout.MajorFunction) || !Field(s, {L"MinorFunction"}, 1, &layout.MinorFunction) ||
        !Field(s, {L"Control"}, 1, &layout.Control) || !Field(s, {L"CompletionRoutine"}, 8, &layout.Completion) ||
        !Field(s, {L"Context"}, 8, &layout.Context))
    { if (error) { *error = L"required_irp_field_missing_or_ambiguous"; } return false; }
    *out = layout;
    if (error) { error->clear(); }
    return true;
}

bool CaptureBoundPendingIrps(IObservationSource& source, const PendingIrpSchemaBinding& binding,
    const std::vector<PendingIrpThreadInput>& threads, const PendingIrpScanOptions& options,
    PendingIrpScanResult* result, std::wstring* error, const std::atomic<bool>* cancellation)
{
    if (!result) { return false; }
    *result = {};
    result->ScanStartedTickMs = GetTickCount64();
    const auto caps = source.Capabilities();
    result->AddressSpace = caps.AddressSpace;
    const auto fail = [&](const std::wstring& reason)
    {
        result->QualificationReason = reason;
        result->ScanFinishedTickMs = GetTickCount64();
        if (error) { *error = reason; }
        return false;
    };
    IrpLayout layout;
    std::wstring reason;
    if (!BuildPendingIrpLayout(binding, &layout, &reason)) { return fail(reason); }
    result->LayoutFromPdb = true;
    const auto& schema = *binding.Schemas[0];
    if (threads.size() > 16384 || caps.SourceId.empty() || !caps.KernelOnly || caps.UserOnly ||
        caps.AddressDomain != ObservationAddressDomain::Virtual || caps.MaximumReadBytes == 0 ||
        caps.MaximumReadBytes > 4096 || !caps.AddressSpace.KernelRange(binding.ImageBase, static_cast<size_t>(schema.ImageSize)))
    { return fail(L"unsupported_irp_source_or_input_bounds"); }
    SchemaArtifact image;
    executable_image::DiskPeMetadata metadata;
    if (!image.Open(binding.ImagePath, 512ull * 1024 * 1024) || image.Sha256 != schema.ImageSha256 ||
        !executable_image::ReadDiskPeIdentityHandle(image.Handle(), &metadata, nullptr) || !metadata.HasPdbIdentity ||
        metadata.OptionalMagic != IMAGE_NT_OPTIONAL_HDR64_MAGIC || metadata.Machine != schema.Machine ||
        metadata.SizeOfImage != schema.ImageSize || GuidText(metadata.PdbGuid) != schema.PdbGuid || metadata.PdbAge != schema.PdbAge)
    { return fail(L"schema_reference_image_identity_mismatch_or_unavailable"); }
    static std::atomic<uint64_t> next{1};
    const auto id = L"irp-" + std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(next.fetch_add(1));
    ObservationOperationBudget budget;
    budget.MaximumBytes = 256 * 1024;
    budget.MaximumSourceCalls = 2048;
    budget.MaximumReceipts = 4096;
    auto operation = std::make_shared<ObservationReadOperation>(id, caps.SourceId, L"kernel_virtual", budget);
    ObservationReadRouting routing;
    routing.Primary = &source; routing.TargetId = caps.SourceId; routing.AddressSpaceId = L"kernel_virtual";
    routing.AllowResidencyChanges = true;
    ObservationReadRouter router(std::move(routing), operation, cancellation);
    const auto read = [&](uint64_t address, size_t count, std::vector<uint8_t>* bytes)
    {
        bytes->clear();
        if (count == 0 || count > 0x20000 || !caps.AddressSpace.KernelRange(address, count)) { return false; }
        for (size_t offset = 0; offset < count;)
        {
            const auto chunk = (std::min)(count - offset, static_cast<size_t>(caps.MaximumReadBytes));
            std::vector<uint8_t> part;
            if (!router.ReadExact(address + offset, chunk, &part)) { bytes->clear(); return false; }
            bytes->insert(bytes->end(), part.begin(), part.end());
            offset += chunk;
        }
        return true;
    };
    std::wstring before, after = L"not_attempted";
    const bool first = QualifyExecutableReference(metadata, binding.ImageBase, read, &before);
    if (first) { pending_irp::CollectPendingIrps(read, layout, threads, options, result, caps.AddressSpace); }
    const bool last = first && QualifyExecutableReference(metadata, binding.ImageBase, read, &after);
    const bool stable = image.Unchanged();
    const auto reads = router.Snapshot();
    result->RuntimeQualified = first && last && stable && ValidObservationRoutedReadSet(reads) &&
        !reads.Attempts.Cancelled && !reads.Attempts.DeadlineExceeded &&
        (cancellation == nullptr || !cancellation->load()) && SameObservationSourceContract(caps, source.Capabilities());
    result->QualificationReason = !first ? before : !last ? after : !stable ? L"reference_image_changed" :
        result->RuntimeQualified ? L"schema_image_and_object_invariants_checked" : L"readset_incomplete_or_operation_interrupted";
    result->CoverageComplete = result->CoverageComplete && result->RuntimeQualified;
    result->ScanFinishedTickMs = GetTickCount64();
    result->Evidence = Evidence(binding, metadata, threads, options, *result, reads, before, after, stable);
    if (!result->Evidence)
    {
        result->RuntimeQualified = false;
        result->CoverageComplete = false;
        result->QualificationReason = L"irp_evidence_encoding_exceeded_bound_or_failed";
    }
    if (error) { *error = result->RuntimeQualified ? L"" : result->QualificationReason; }
    // A failed final identity check preserves decoded candidates and reads;
    // callers must require RuntimeQualified before admitting callback targets.
    return first;
}
