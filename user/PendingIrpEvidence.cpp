#include "PendingIrpEvidence.h"
#include "PendingIrpReport.h"
#include "SchemaArtifact.h"
#include "ReferenceArtifact.h"
#include "ExecutableImageVerifier.h"
#include "ObservationReadRoutingJson.h"
#include "BoundedObservationJson.h"
#include "ContentHash.h"
#include <algorithm>
#include <filesystem>

using namespace bounded_observation_json;
namespace
{
    std::wstring GuidText(const GUID& guid)
    {
        wchar_t text[33]{};
        swprintf_s(text, L"%08lx%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x", guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
        return text;
    }

    std::wstring CursorJson(const PendingIrpCursor& c)
    {
        return L"{\"thread\":" + N(c.ThreadObject) + L",\"created\":" + N(c.ThreadCreateTime) + L",\"irp\":" + N(c.IrpAddress) +
            L",\"head\":" + N(c.List.Head) + L",\"entry\":" + N(c.List.Entry) + L",\"forward\":" + N(c.List.Forward) +
            L",\"backward\":" + N(c.List.Backward) + L"}";
    }

    std::wstring SourceJson(const ObservationSourceCapabilities& s)
    {
        const auto& a = s.AddressSpace;
        return L"{\"id\":" + mcpjson::Quote(s.SourceId) + L",\"consistency\":" + mcpjson::Quote(s.Consistency) +
            L",\"maximum_read_bytes\":" + N(s.MaximumReadBytes) + L",\"kernel_only\":" + B(s.KernelOnly) +
            L",\"user_only\":" + B(s.UserOnly) + L",\"may_change_residency\":" + B(s.MayChangeResidency) +
            L",\"domain\":\"virtual\",\"virtual_bits\":" + N(a.VirtualAddressBits) + L",\"pointer_bytes\":" + N(a.PointerBytes) +
            L",\"physical_bits\":" + N(a.PhysicalAddressBits) + L",\"legacy_assumed\":" + B(a.LegacyAssumed) +
            L",\"user_maximum\":" + N(a.UserMaximum) + L",\"kernel_minimum\":" + N(a.KernelMinimum) + L"}";
    }
}

IrpRetentionRequest PendingIrpRetentionRequest(const PendingIrpSchemaBinding& binding,
    const PendingIrpScanResult& result, const PendingIrpCaptureContext& context) noexcept
{
    IrpRetentionRequest request;
    if (!result.RuntimeQualified || !context.ReferenceStable || !context.FinalSourceSame || context.FinalCancelled ||
        context.ReferenceBytes == 0 || context.ReferenceBytes > ReferenceArtifactMaxBytes) { return request; }
    request.UnkeyedState = !result.Requests.empty();
    try
    {
        if (!result.AddressSpace.Valid() || !context.Source.AddressSpace.Valid() || context.Source.SourceId.empty() ||
            context.Source.SourceId.size() > 1024 || context.Source.AddressDomain != ObservationAddressDomain::Virtual ||
            result.Requests.size() > 256) { return request; }
        const auto add = [](ContentHash& hash, const std::wstring& json)
        {
            const auto bytes = mcpjson::WideToUtf8(json);
            return !bytes.empty() && hash.Add(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size());
        };
        ContentHash scope;
        if (!add(scope, L"{\"policy\":\"kn.irp_state_signature.v1\",\"source\":" + SourceJson(context.Source) +
            L",\"image_base\":" + N(binding.ImageBase) + L",\"schemas\":[")) { return request; }
        for (size_t i = 0; i < binding.Schemas.size(); ++i)
        {
            if (!binding.Schemas[i]) { return request; }
            const auto json = TypeSchemaJson(*binding.Schemas[i]);
            if (json.empty() || !add(scope, (i ? L"," : L"") + json)) { return request; }
        }
        if (!add(scope, L"]}")) { return request; }
        const auto scopeDigest = scope.Finish();
        if (scopeDigest.empty()) { return request; }
        std::vector<std::wstring> keys;
        for (const auto& observed : result.Requests)
        {
            if (observed.ThreadCreateTime == 0 || !result.AddressSpace.KernelRange(observed.Thread.ThreadObject, 1) ||
                !result.AddressSpace.KernelRange(observed.Irp, 1) || observed.Stacks.size() > 64) { return request; }
            const auto pointer = [](const std::optional<uint64_t>& value) { return value ? N(*value) : L"null"; };
            const auto flag = [](const std::optional<bool>& value) { return value ? B(*value) : L"null"; };
            std::wstring json = L"{\"scope_sha256\":" + mcpjson::Quote(scopeDigest) + L",\"thread\":" + N(observed.Thread.ThreadObject) +
                L",\"pid\":" + N(observed.Thread.ProcessId) + L",\"tid\":" + N(observed.Thread.ThreadId) + L",\"created\":" + N(observed.ThreadCreateTime) +
                L",\"irp\":" + N(observed.Irp) + L",\"stack_count\":" + N(observed.StackCount) + L",\"current_location\":" + N(observed.CurrentLocation) +
                L",\"cancel\":" + flag(observed.CancelFlag) + L",\"pending_returned\":" + flag(observed.PendingReturned) +
                L",\"io_status\":" + (observed.IoStatus ? mcpjson::Quote(std::to_wstring(*observed.IoStatus)) : L"null") + L",\"stacks\":[";
            for (size_t i = 0; i < observed.Stacks.size(); ++i)
            {
                const auto& stack = observed.Stacks[i];
                if (i) { json += L","; }
                json += L"{\"index\":" + N(stack.Index) + L",\"address\":" + N(stack.Address) + L",\"major\":" + N(stack.MajorFunction) +
                    L",\"minor\":" + N(stack.MinorFunction) + L",\"control\":" + N(stack.Control) + L",\"completion\":" + N(stack.CompletionRoutine) +
                    L",\"context\":" + N(stack.Context) + L",\"device\":" + pointer(stack.DeviceObject) + L",\"file\":" + pointer(stack.FileObject) + L"}";
            }
            ContentHash hash;
            if (!add(hash, json + L"]}")) { return request; }
            const auto key = hash.Finish();
            if (key.empty()) { return request; }
            keys.push_back(key);
        }
        std::sort(keys.begin(), keys.end()); keys.erase(std::unique(keys.begin(), keys.end()), keys.end());
        request.StateKeys = std::move(keys); request.UnkeyedState = false;
        request.Gap = !result.CoverageComplete || result.UnstableObservations != 0;
    }
    catch (...) {} // Preserve the capture with explicit unkeyed/gap admission.
    return request;
}

std::wstring PendingIrpCaptureJson(const PendingIrpSchemaBinding& binding,
    const executable_image::DiskPeMetadata& m, const std::vector<PendingIrpThreadInput>& threads,
    const PendingIrpScanOptions& options, const PendingIrpScanResult& result, const ObservationRoutedReadSet& reads,
    const std::wstring& before, const std::wstring& after, const PendingIrpCaptureContext& context)
{
    std::wstring json = L"{\"schema\":\"kn.irp_capture.v2\",\"policy\":\"schema-image-repeated-snapshot-v1\","
        L"\"collector_authenticated\":false,\"reference_image_preserved\":false,\"pdb_file_preserved\":false,"
        L"\"whole_image_integrity\":false,\"referenced_lifetime\":false,\"atomic_snapshot\":false,"
        L"\"execution_observed\":false,\"source_initialization_recorded\":false,";
    json += L"\"source_contract\":" + SourceJson(context.Source) +
        L",\"scan_started_tick_ms\":" + N(result.ScanStartedTickMs) + L",\"scan_finished_tick_ms\":" + N(result.ScanFinishedTickMs) +
        L",\"final_cancelled\":" + B(context.FinalCancelled) + L",\"final_source_contract_same\":" + B(context.FinalSourceSame) +
        L",\"reference_captured_bytes\":" + N(context.ReferenceBytes) + L",\"schemas\":[";
    for (size_t i = 0; i < binding.Schemas.size(); ++i)
    { if (i != 0) { json += L","; } json += TypeSchemaJson(*binding.Schemas[i]); }
    json += L"],\"image_base\":" + N(binding.ImageBase) + L",\"reference_identity\":{\"image_base\":" + N(m.ImageBase) +
        L",\"machine\":" + N(m.Machine) + L",\"optional_magic\":" + N(m.OptionalMagic) + L",\"image_size\":" + N(m.SizeOfImage) +
        L",\"timestamp\":" + N(m.TimeDateStamp) + L",\"checksum\":" + N(m.CheckSum) + L",\"entry_point\":" + N(m.EntryPointRva) +
        L",\"section_count\":" + N(m.Sections.size()) + L",\"pdb_rva\":" + N(m.PdbRva) + L",\"pdb_guid\":" + mcpjson::Quote(GuidText(m.PdbGuid)) +
        L",\"pdb_age\":" + N(m.PdbAge) + L"},\"image_before\":" + mcpjson::Quote(before) + L",\"image_after\":" + mcpjson::Quote(after) +
        L",\"reference_content_rechecked\":true,\"reference_content_stable\":" + B(context.ReferenceStable) +
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
    return json;
}

namespace
{
    bool ParseSource(const std::wstring& json, ObservationSourceCapabilities* s)
    {
        auto& a = s->AddressSpace;
        return mcpjson::GetString(json, L"id", &s->SourceId) && Text(s->SourceId, 1024) &&
            mcpjson::GetString(json, L"consistency", &s->Consistency) && Text(s->Consistency, 128) &&
            Number(json, L"maximum_read_bytes", &s->MaximumReadBytes) && s->MaximumReadBytes > 0 && s->MaximumReadBytes <= 4096 &&
            Boolean(json, L"kernel_only", &s->KernelOnly) && s->KernelOnly &&
            Boolean(json, L"user_only", &s->UserOnly) && !s->UserOnly &&
            Boolean(json, L"may_change_residency", &s->MayChangeResidency) &&
            Number(json, L"virtual_bits", &a.VirtualAddressBits) && Number(json, L"pointer_bytes", &a.PointerBytes) &&
            Number(json, L"physical_bits", &a.PhysicalAddressBits) && Boolean(json, L"legacy_assumed", &a.LegacyAssumed) &&
            Number(json, L"user_maximum", &a.UserMaximum) && Number(json, L"kernel_minimum", &a.KernelMinimum) &&
            a.Valid() && SourceJson(*s) == json;
    }

    bool ParseCursor(const std::wstring& json, PendingIrpCursor* c)
    {
        return Number(json, L"thread", &c->ThreadObject) && Number(json, L"created", &c->ThreadCreateTime) &&
            Number(json, L"irp", &c->IrpAddress) && Number(json, L"head", &c->List.Head) &&
            Number(json, L"entry", &c->List.Entry) && Number(json, L"forward", &c->List.Forward) &&
            Number(json, L"backward", &c->List.Backward) && CursorJson(*c) == json;
    }

    bool ParseIdentity(const std::wstring& json, executable_image::DiskPeMetadata* m)
    {
        std::wstring guid;
        uint32_t sections = 0;
        if (!Number(json, L"image_base", &m->ImageBase) || !Number(json, L"machine", &m->Machine) ||
            !Number(json, L"optional_magic", &m->OptionalMagic) || !Number(json, L"image_size", &m->SizeOfImage) ||
            !Number(json, L"timestamp", &m->TimeDateStamp) || !Number(json, L"checksum", &m->CheckSum) ||
            !Number(json, L"entry_point", &m->EntryPointRva) || !Number(json, L"section_count", &sections) || sections == 0 || sections > 96 ||
            !Number(json, L"pdb_rva", &m->PdbRva) || !Number(json, L"pdb_age", &m->PdbAge) ||
            !mcpjson::GetString(json, L"pdb_guid", &guid) || guid.size() != 32 ||
            guid.find_first_not_of(L"0123456789abcdef") != std::wstring::npos) { return false; }
        const auto hex = [&](size_t offset, size_t length) { return wcstoul(guid.substr(offset, length).c_str(), nullptr, 16); };
        m->PdbGuid.Data1 = hex(0, 8); m->PdbGuid.Data2 = static_cast<WORD>(hex(8, 4)); m->PdbGuid.Data3 = static_cast<WORD>(hex(12, 4));
        for (size_t i = 0; i < 8; ++i) { m->PdbGuid.Data4[i] = static_cast<BYTE>(hex(16 + 2 * i, 2)); }
        m->HasPdbIdentity = true;
        m->Sections.resize(sections);
        return m->Machine == IMAGE_FILE_MACHINE_AMD64 && m->OptionalMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
            m->SizeOfImage > 0 && m->PdbRva <= m->SizeOfImage && 24 <= m->SizeOfImage - m->PdbRva;
    }

    bool SameIdentity(const executable_image::DiskPeMetadata& a, const executable_image::DiskPeMetadata& b)
    {
        return a.HasPdbIdentity && b.HasPdbIdentity && a.ImageBase == b.ImageBase && a.Machine == b.Machine &&
            a.OptionalMagic == b.OptionalMagic && a.SizeOfImage == b.SizeOfImage && a.TimeDateStamp == b.TimeDateStamp &&
            a.CheckSum == b.CheckSum && a.EntryPointRva == b.EntryPointRva && a.Sections.size() == b.Sections.size() &&
            a.PdbRva == b.PdbRva && GuidText(a.PdbGuid) == GuidText(b.PdbGuid) && a.PdbAge == b.PdbAge;
    }

    // The generic read-set validator supports other routers. This policy has
    // exactly one kernel source, no guards or fallback, and fixed shared budgets.
    bool IrpReadPolicy(const ObservationRoutedReadSet& reads, const PendingIrpCaptureContext& context)
    {
        const auto& a = reads.Attempts;
        const auto& b = a.Budget;
        if (a.TargetId != context.Source.SourceId || a.AddressSpaceId != L"kernel_virtual" ||
            b.MaximumBytes != 256 * 1024 || b.MaximumSourceCalls != 2048 || b.MaximumReceipts != 4096 ||
            b.MaximumStoredSpans != 65536 || b.MaximumElapsedMs != 5000) { return false; }
        for (const auto& receipt : a.Reads)
        {
            if (!SameObservationSourceContract(receipt.Source, context.Source) ||
                receipt.Request.ByteBudget != receipt.Request.Length || !receipt.Request.AllowResidencyChanges) { return false; }
        }
        for (const auto& call : reads.ParserReads)
        {
            if (call.BeforeGuard != L"not_requested" || call.AfterGuard != L"not_requested" ||
                call.PrimaryReceipt != call.ReturnedReceipt) { return false; }
            if (call.PrimaryReceipt == 0)
            {
                if (call.Reason != L"primary_contract_changed") { return false; }
                continue;
            }
            const auto& r = a.Reads[static_cast<size_t>(call.PrimaryReceipt - 1)].Result;
            const bool complete = r.State == ObservationReadState::Complete && !r.CancellationObserved && !r.OperationDeadlineExceeded;
            if (call.Reason == L"operation_interrupted_after_read")
            {
                if (call.Accepted || !complete || (!a.Cancelled && !a.DeadlineExceeded && !context.FinalCancelled)) { return false; }
            }
            else if (call.Reason != L"primary_result" || call.Accepted != complete) { return false; }
        }
        return true;
    }

    class RecordedIrpReads
    {
    public:
        RecordedIrpReads(const ObservationRoutedReadSet& reads, const ObservationSourceCapabilities& caps) : Reads(reads), Caps(caps) {}
        bool Read(uint64_t address, size_t length, std::vector<uint8_t>* bytes)
        {
            bytes->clear();
            if (length == 0 || length > 0x20000 || !Caps.AddressSpace.KernelRange(address, length)) { return false; }
            for (size_t offset = 0; offset < length;)
            {
                const auto chunk = (std::min)(length - offset, static_cast<size_t>(Caps.MaximumReadBytes));
                if (Cursor == Reads.ParserReads.size()) { Mismatch = true; bytes->clear(); return false; }
                const auto& call = Reads.ParserReads[Cursor++];
                if (call.Address != address + offset || call.Length != chunk) { Mismatch = true; bytes->clear(); return false; }
                if (!call.Accepted) { bytes->clear(); return false; }
                const auto& receipt = Reads.Attempts.Reads[static_cast<size_t>(call.ReturnedReceipt - 1)];
                for (const auto& span : receipt.Result.Spans) { bytes->insert(bytes->end(), span.Bytes.begin(), span.Bytes.end()); }
                offset += chunk;
            }
            return bytes->size() == length;
        }
        bool Complete() const { return !Mismatch && Cursor == Reads.ParserReads.size(); }
    private:
        const ObservationRoutedReadSet& Reads;
        const ObservationSourceCapabilities& Caps;
        size_t Cursor = 0;
        bool Mismatch = false;
    };
}

PendingIrpReplay ReplayPendingIrpCapture(const std::wstring& path)
{
    PendingIrpReplay replay;
    const auto fail = [&](const wchar_t* issue) { replay.Issue = issue; replay.QualifiedObservation = false; return replay; };
    try
    {
        SchemaArtifact capture;
        std::vector<uint8_t> bytes;
        if (!capture.Open(path, PendingIrpEvidenceMaximumBytes) ||
            !executable_image::ReadFileBytesAt(capture.Handle(), 0, static_cast<uint32_t>(capture.Bytes()), &bytes))
        { return fail(L"capture_missing_or_unreadable"); }
        replay.CaptureSha256 = capture.Sha256;
        const std::string utf8(bytes.begin(), bytes.end());
        const auto json = mcpjson::Utf8ToWide(utf8);
        std::wstring schema, source, identity, opts, cursor, rawReads;
        IndexedObject object;
        if (mcpjson::WideToUtf8(json) != utf8 || !object.Parse(json))
        { return fail(L"invalid_capture_encoding"); }
        const auto metadataInputs = object.Metadata({L"schemas", L"thread_inputs", L"requests", L"reads"});
        if (!mcpjson::GetString(metadataInputs, L"schema", &schema)) { return fail(L"invalid_capture_metadata"); }
        if (schema == L"kn.irp_capture.v1") { return fail(L"legacy_capture_missing_source_and_final_state"); }
        if (schema != L"kn.irp_capture.v2") { return fail(L"unsupported_capture_schema"); }
        PendingIrpSchemaBinding binding;
        PendingIrpCaptureContext context;
        PendingIrpScanOptions options;
        auto& result = replay.Recomputed;
        executable_image::DiskPeMetadata metadata;
        ObservationRoutedReadSet reads;
        std::vector<std::wstring> packages, inputs;
        if (!object.Rows(L"schemas", 3, &packages) || packages.size() != 3 ||
            !object.Rows(L"thread_inputs", 16384, &inputs) || !Number(metadataInputs, L"image_base", &binding.ImageBase) ||
            !mcpjson::FindRawValue(metadataInputs, L"source_contract", &source) || !ParseSource(source, &context.Source) ||
            !mcpjson::FindRawValue(metadataInputs, L"reference_identity", &identity) || !ParseIdentity(identity, &metadata) ||
            !Number(metadataInputs, L"scan_started_tick_ms", &result.ScanStartedTickMs) || !Number(metadataInputs, L"scan_finished_tick_ms", &result.ScanFinishedTickMs) ||
            result.ScanFinishedTickMs < result.ScanStartedTickMs || !Boolean(metadataInputs, L"final_cancelled", &context.FinalCancelled) ||
            !Boolean(metadataInputs, L"final_source_contract_same", &context.FinalSourceSame) ||
            !Boolean(metadataInputs, L"reference_content_stable", &context.ReferenceStable) ||
            !Number(metadataInputs, L"reference_captured_bytes", &context.ReferenceBytes) || context.ReferenceBytes > ReferenceArtifactMaxBytes ||
            !mcpjson::FindRawValue(metadataInputs, L"options", &opts) || !Number(opts, L"max_threads", &options.MaxThreads) ||
            !Number(opts, L"max_irps", &options.MaxIrps) || !Number(opts, L"max_walk_nodes", &options.MaxWalkNodes) ||
            !Boolean(opts, L"inventory_complete", &options.ThreadInventoryComplete) ||
            !mcpjson::FindRawValue(opts, L"cursor", &cursor) || !ParseCursor(cursor, &options.Cursor))
        { return fail(L"invalid_or_missing_capture_inputs"); }
        for (size_t i = 0; i < packages.size(); ++i)
        {
            auto package = std::make_shared<TypeSchemaPackage>();
            if (!ParseTypeSchema(packages[i], package.get(), nullptr)) { return fail(L"invalid_schema_package"); }
            binding.Schemas[i] = std::move(package);
        }
        pending_irp::IrpLayout layout;
        if (!BuildPendingIrpLayout(binding, &layout, nullptr) ||
            !context.Source.AddressSpace.KernelRange(binding.ImageBase, metadata.SizeOfImage) ||
            metadata.SizeOfImage != binding.Schemas[0]->ImageSize || GuidText(metadata.PdbGuid) != binding.Schemas[0]->PdbGuid ||
            metadata.PdbAge != binding.Schemas[0]->PdbAge) { return fail(L"schema_or_reference_identity_mismatch"); }
        std::vector<PendingIrpThreadInput> threads;
        for (const auto& row : inputs)
        {
            PendingIrpThreadInput t;
            if (!Number(row, L"thread", &t.ThreadObject) || !Number(row, L"pid", &t.ProcessId) || !Number(row, L"tid", &t.ThreadId))
            { return fail(L"invalid_thread_input"); }
            threads.push_back(t);
        }
        if (!object.Raw(L"reads", &rawReads) ||
            !ParseObservationRoutedReadSet(rawReads, &reads, PendingIrpEvidenceMaximumBytes) || !IrpReadPolicy(reads, context))
        { return fail(L"readset_incomplete_or_policy_mismatch"); }
        SchemaArtifact reference;
        if (context.ReferenceBytes != 0)
        {
            // The document cannot choose a path or cause a symbol download.
            const auto referencePath = std::filesystem::path(path).parent_path() /
                (L"irp-reference-" + binding.Schemas[0]->ImageSha256 + L".knblob");
            executable_image::DiskPeMetadata actual;
            if (!reference.Open(referencePath.wstring(), ReferenceArtifactMaxBytes)) { replay.ReferenceStatus = L"missing_or_unreadable"; }
            else if (reference.Bytes() != context.ReferenceBytes || reference.Sha256 != binding.Schemas[0]->ImageSha256 ||
                !executable_image::ReadDiskPeIdentityHandle(reference.Handle(), &actual, nullptr) || !SameIdentity(actual, metadata))
            { replay.ReferenceStatus = L"mismatch"; return fail(L"reference_image_mismatch"); }
            else { replay.ReferenceStatus = L"verified"; }
        }
        else { replay.ReferenceStatus = L"not_captured"; }
        result.AddressSpace = context.Source.AddressSpace;
        result.LayoutFromPdb = true;
        RecordedIrpReads reader(reads, context.Source);
        const auto read = [&](uint64_t address, size_t count, std::vector<uint8_t>* out) { return reader.Read(address, count, out); };
        std::wstring before, after = L"not_attempted";
        const bool first = QualifyExecutableReference(metadata, binding.ImageBase, read, &before);
        if (first) { pending_irp::CollectPendingIrps(read, layout, threads, options, &result, context.Source.AddressSpace); }
        const bool last = first && QualifyExecutableReference(metadata, binding.ImageBase, read, &after);
        if (!reader.Complete()) { return fail(L"ordered_parser_calls_not_reproduced"); }
        result.RuntimeQualified = first && last && context.ReferenceStable && !reads.Attempts.Cancelled &&
            !reads.Attempts.DeadlineExceeded && !context.FinalCancelled && context.FinalSourceSame;
        result.QualificationReason = !first ? before : !last ? after : !context.ReferenceStable ? L"reference_image_changed" :
            result.RuntimeQualified ? L"schema_image_and_object_invariants_checked" : L"readset_incomplete_or_operation_interrupted";
        result.CoverageComplete = result.CoverageComplete && result.RuntimeQualified;
        // Compare the entire canonical encoding, including graph, optional
        // fields, pagination, counters, invariant names, and every negative flag.
        if (PendingIrpCaptureJson(binding, metadata, threads, options, result, reads, before, after, context) != json)
        { return fail(L"recomputed_capture_differs"); }
        if (!capture.Unchanged() || (replay.ReferenceStatus == L"verified" && !reference.Unchanged()))
        { return fail(L"artifact_changed_during_replay"); }
        replay.SummaryMatched = true;
        replay.QualifiedObservation = result.RuntimeQualified && replay.ReferenceStatus == L"verified";
        replay.Status = L"replayed";
        return replay;
    }
    catch (const std::exception&) { return fail(L"bounded_replay_failed"); }
}

std::wstring PendingIrpReplayJson(const PendingIrpReplay& replay)
{
    const auto& r = replay.Recomputed;
    // Do not expose partly recomputed requests as established results on failure.
    std::wstring json = L"{\"schema\":\"kn.irp_replay.v1\",\"policy\":\"schema-image-repeated-snapshot-v1\",\"status\":" +
        mcpjson::Quote(replay.Status) + L",\"issue\":" + mcpjson::Quote(replay.Issue) + L",\"capture_sha256\":" + mcpjson::Quote(replay.CaptureSha256) +
        L",\"summary_matched\":" + B(replay.SummaryMatched) + L",\"reference_status\":" + mcpjson::Quote(replay.ReferenceStatus) +
        L",\"qualified_observation_reproduced\":" + B(replay.QualifiedObservation) +
        L",\"collector_authenticated\":false,\"external_final_state_authenticated\":false,\"pdb_file_verified\":false,"
        L"\"whole_image_integrity\":false,\"referenced_lifetime\":false,\"execution_observed\":false,\"atomic_snapshot\":false,"
        L"\"build_approval\":\"not_established\",\"source_initialization_replayed\":false,\"result\":";
    if (!replay.SummaryMatched) { return json + L"null}"; }
    json += L"{\"policy_runtime_qualified\":" + B(r.RuntimeQualified) + L",\"qualification_reason\":" + mcpjson::Quote(r.QualificationReason) +
        L",\"scope\":\"declared_inputs_and_ordered_original_reads\",\"threads_visited\":" + N(r.ThreadsVisited) +
        L",\"irps_inspected\":" + N(r.IrpsInspected) + L",\"unstable_observations\":" + N(r.UnstableObservations) +
        L",\"enumeration_complete\":" + B(r.CoverageComplete) + L",\"next_cursor\":" + CursorJson(r.NextCursor) + L",\"requests\":[";
    // Request qualification has the same reference requirement as the replay.
    auto projected = r;
    projected.RuntimeQualified = replay.QualifiedObservation;
    projected.CoverageComplete &= replay.QualifiedObservation;
    if (!projected.RuntimeQualified && r.RuntimeQualified) { projected.QualificationReason = L"reference_image_not_verified"; }
    for (size_t i = 0; i < r.Requests.size(); ++i)
    { if (i != 0) { json += L","; } json += PendingIrpObservationJson(r.Requests[i], projected, false); }
    return json + L"]}}";
}
