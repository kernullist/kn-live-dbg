#include "SavedDumpCapability.h"
#include "ArtifactOutput.h"
#include "ContentHash.h"
#include "DumpReadObservationJson.h"
#include "SourceCapabilities.h"

#include <iostream>

namespace
{
    using mcpjson::Quote;

    struct Options
    {
        std::wstring ExpectedHeader, ExpectedSample;
        std::optional<uint64_t> Address;
        uint32_t Length = 16;
    };

    bool Digest(const std::wstring& text, std::wstring& value)
    {
        if (text.size() != 64 || text.find_first_not_of(L"0123456789abcdefABCDEF") != text.npos) { return false; }
        value = text;
        for (auto& c : value) { if (c >= L'A' && c <= L'F') { c += L'a' - L'A'; } }
        return true;
    }

    bool ParseRange(const std::wstring& address, const std::wstring& length, Options& options)
    {
        const size_t start = address.size() >= 2 && address[0] == L'0' && (address[1] == L'x' || address[1] == L'X') ? 2 : 0;
        if (address.size() <= start || address.size() - start > 16 ||
            address.find_first_not_of(L"0123456789abcdefABCDEF", start) != address.npos ||
            length.empty() || length.size() > 4 || length.front() == L'0' ||
            length.find_first_not_of(L"0123456789") != length.npos) { return false; }
        options.Address = wcstoull(address.c_str() + start, nullptr, 16);
        options.Length = wcstoul(length.c_str(), nullptr, 10);
        return options.Length <= 4096;
    }

    bool SavedSelector(const std::wstring& arg)
    {
        return _wcsicmp(arg.c_str(), capability_probes::SavedDump.Selector) == 0 || _wcsicmp(arg.c_str(), capability_probes::SavedEtl.Selector) == 0;
    }

    bool Parse(const std::vector<std::wstring>& args, Options& options)
    {
        if (args.size() < 4 || _wcsicmp(args[0].c_str(), capability_probes::SavedDump.Selector) || args[1].empty() ||
            std::count_if(args.begin(), args.end(), SavedSelector) != 1 || args[2] != L"--header-sha256" || !Digest(args[3], options.ExpectedHeader)) { return false; }
        size_t i = 4;
        if (i < args.size() && args[i] == L"--range")
        {
            if (args.size() - i < 3 || !ParseRange(args[i + 1], args[i + 2], options)) { return false; }
            i += 3;
        }
        if (i < args.size() && args[i] == L"--expect-sha256")
        {
            if (args.size() - i != 2 || !Digest(args[i + 1], options.ExpectedSample)) { return false; }
            i += 2;
        }
        return i == args.size();
    }

    std::wstring Nullable(const std::wstring& value) { return value.empty() ? L"null" : Quote(value); }
    const wchar_t* Boolean(bool value) { return value ? L"true" : L"false"; }

    struct SavedDumpProbe
    {
        static constexpr auto Scope = L"saved_dump_probe";
        static constexpr auto AvailabilityScope = capability_probes::SavedDump.AvailabilityScope;
        Options Request;
        DumpInitializationObservation Init;
        const wchar_t* Status = L"source_unavailable";
        const wchar_t* SampleStage = L"not_probed";
        const wchar_t* SemanticStage = L"not_probed";
        const wchar_t* ContentCheck = L"not_requested";
        std::optional<bool> SampleIdentity;
        std::optional<uint32_t> IdentityStatus;
        std::wstring RangeEvidence = L"null";

        static bool Covers(std::wstring_view domain, std::wstring_view operation, std::wstring_view backend)
        {
            return capability_probes::For(domain, operation, backend) == &capability_probes::SavedDump;
        }

        const wchar_t* Availability(std::wstring_view) const
        {
            if (!Init.SelectedLevels) { return L"unavailable"; }
            return std::wstring_view(Status) == L"read" ? L"available" : L"partial";
        }

        std::wstring StagesJson(std::wstring_view) const
        {
            const auto opened = !Init.OpenStatus ? L"not_probed" : *Init.OpenStatus ? L"failed" : L"passed";
            const auto* header = Init.CompleteHeaderSha256();
            const auto layout = Init.SelectedLevels ? L"passed" : header && *header == Request.ExpectedHeader ? L"failed" : L"not_probed";
            return L"{\"source_opened\":" + Quote(opened) + L",\"sample_read\":" + Quote(SampleStage) +
                L",\"layout_qualified\":" + Quote(layout) + L",\"semantic_validation\":" + Quote(SemanticStage) +
                L",\"environment_regression\":\"not_performed\"}";
        }

        std::wstring EvidenceJson(std::wstring_view) const { return L",\"range_evidence\":" + RangeEvidence; }

        std::wstring Json() const
        {
            const auto& request = Request;
            const auto* header = Init.CompleteHeaderSha256();
            return L"{\"schema\":\"kn.dump_capability_probe.v1\",\"status\":" + Quote(Status) +
                L",\"expected_header_sha256\":" + Quote(request.ExpectedHeader) +
                L",\"header_sha256\":" + (header ? Quote(*header) : L"null") +
                L",\"digest_scope\":\"first_8192_bytes\",\"producer_authenticity\":\"unverified\",\"range_selection\":" +
                Quote(request.Address ? L"explicit_virtual_range" : L"header_module_list_head") +
                L",\"requested_virtual_address\":" + (request.Address ? Quote(std::to_wstring(*request.Address)) : L"null") +
                L",\"requested_bytes\":" + std::to_wstring(request.Length) +
                L",\"expected_sample_sha256\":" + Nullable(request.ExpectedSample) +
                L",\"sample_digest_comparison\":" + Quote(ContentCheck) + L",\"sample_identity_revalidated\":" +
                (SampleIdentity ? Boolean(*SampleIdentity) : L"null") + L",\"sample_identity_win32_status\":" +
                (IdentityStatus ? std::to_wstring(*IdentityStatus) : L"null") + L",\"initialization\":" + DumpInitializationJson(Init) + L"}";
        }
    };

    std::wstring IncompleteReads(const ObservationReadSet& set)
    {
        std::wstring rows = L"[";
        for (const auto& row : set.Reads)
        {
            const auto& read = row.Result;
            if (row.Completed && !row.Abandoned && !row.DeadlineExceeded && read.State == ObservationReadState::Complete) { continue; }
            if (rows.size() > 1) { rows += L','; }
            rows += L"{\"physical_read_sequence\":" + std::to_wstring(row.Sequence) + L",\"state\":" + Quote(ObservationReadStateName(read.State)) +
                L",\"native_status_domain\":" + Quote(read.NativeStatusDomain) + L",\"win32_status\":" +
                (read.NativeStatusDomain == L"win32" ? std::to_wstring(read.NativeStatus) : L"null") +
                L",\"transferred_bytes\":" + (read.TransferredBytesKnown ? std::to_wstring(read.TransferredBytes) : L"null") + L"}";
        }
        return rows + L"]";
    }

    std::wstring WalksJson(const DumpReadObservation& observation)
    {
        std::wstring walks = L"[";
        for (const auto& walk : observation.Translations)
        {
            if (walks.size() > 1) { walks += L','; }
            walks += L"{\"range_offset\":" + std::to_wstring(walk.VirtualAddress - observation.Request.Address) +
                L",\"requested_bytes\":" + std::to_wstring(walk.RequestedBytes) +
                L",\"translation_state\":" + Quote(ObservationReadStateName(walk.State)) +
                L",\"translation_reason\":" + Quote(walk.Reason) + L",\"entries_revalidated\":" + Boolean(walk.EntriesRevalidated) + L"}";
        }
        return walks + L"]";
    }

    const wchar_t* CheckListHead(const DumpInitializationObservation& init, const std::vector<uint8_t>& bytes)
    {
        const std::wstring_view reason = *init.SelectedLevels == 4 ? init.Probe4 : init.Probe5;
        if (reason != L"matched")
        {
            return reason == L"link_range_rejected" || reason == L"first_backlink_mismatch" ||
                reason == L"last_forward_link_mismatch" ? L"failed" : L"inconclusive";
        }
        for (const auto& check : init.ProbeReads)
        {
            if (check.CandidateLevels != *init.SelectedLevels || std::wstring_view(check.Purpose) != L"list_head" ||
                !check.ParserAccepted || check.Address != *init.HeaderModuleList) { continue; }
            std::vector<uint8_t> head;
            for (const auto& span : check.Original.Spans) { head.insert(head.end(), span.Bytes.begin(), span.Bytes.end()); }
            return head == bytes ? L"passed" : L"failed";
        }
        return L"inconclusive";
    }

    void DescribeSample(SavedDumpProbe& probe, const DumpReadObservation& observation)
    {
        const auto& result = observation.Result;
        const auto& reads = observation.PhysicalReads;
        std::wstring spans = L"[";
        std::vector<uint8_t> captured;
        bool digestsReady = true;
        for (const auto& span : result.Spans)
        {
            const std::wstring digest = span.Bytes.empty() ? L"" : ContentHash::Bytes(span.Bytes);
            if (!span.Bytes.empty() && digest.empty()) { digestsReady = false; }
            captured.insert(captured.end(), span.Bytes.begin(), span.Bytes.end());
            if (spans.size() > 1) { spans += L','; }
            spans += L"{\"range_offset\":" + std::to_wstring(span.Address - observation.Request.Address) +
                L",\"requested_bytes\":" + std::to_wstring(span.RequestedBytes) + L",\"captured_bytes\":" + std::to_wstring(span.Bytes.size()) +
                L",\"state\":" + Quote(ObservationReadStateName(span.State)) + L",\"span_sha256\":" + Nullable(digest) + L"}";
        }
        const bool complete = result.State == ObservationReadState::Complete && captured.size() == observation.Request.Length;
        const bool recorded = reads.UnrecordedAttempts == 0 && reads.TotalAttempts == reads.Reads.size() &&
            std::all_of(reads.Reads.begin(), reads.Reads.end(), [](const auto& row) { return row.Completed && !row.Abandoned; });
        const bool walksQualified = !observation.Translations.empty() && std::all_of(observation.Translations.begin(),
            observation.Translations.end(), [](const auto& walk) { return walk.HasMapping && walk.RootRevalidated && walk.EntriesRevalidated; });
        const bool attested = complete && probe.SampleIdentity.value_or(false) && recorded && walksQualified && !reads.DeadlineExceeded &&
            !reads.Cancelled && !result.CancellationObserved && !result.OperationDeadlineExceeded;
        const auto digest = attested ? ContentHash::Bytes(captured) : std::wstring{};
        const bool accepted = attested && digestsReady && !digest.empty();
        probe.SampleStage = accepted ? L"passed" : !reads.ChargedSourceCalls ? L"not_probed" : captured.empty() ? L"failed" : L"partial";
        if (accepted && !probe.Request.ExpectedSample.empty())
        {
            probe.ContentCheck = probe.Request.ExpectedSample == digest ? L"matched" : L"mismatched";
        }
        if (accepted && !probe.Request.Address) { probe.SemanticStage = CheckListHead(probe.Init, captured); }
        if (!probe.SampleIdentity.value_or(false)) { probe.Status = L"source_identity_unqualified"; }
        else if (!complete) { probe.Status = ObservationReadStateName(result.State); }
        else if (!accepted) { probe.Status = L"sample_evidence_incomplete"; }
        else if (std::wstring_view(probe.ContentCheck) == L"mismatched") { probe.Status = L"sample_digest_mismatch"; }
        else if (!probe.Request.Address && std::wstring_view(probe.SemanticStage) != L"passed") { probe.Status = L"list_control_unqualified"; }
        else { probe.Status = L"read"; }
        probe.RangeEvidence = L"{\"operation_id\":" + Quote(reads.OperationId) + L",\"virtual_address\":" + Quote(std::to_wstring(observation.Request.Address)) +
            L",\"virtual_address_bits\":" + std::to_wstring(observation.Source.AddressSpace.VirtualAddressBits) +
            L",\"range_state\":" + Quote(ObservationReadStateName(result.State)) + L",\"captured_bytes\":" + std::to_wstring(captured.size()) +
            L",\"unobserved_bytes\":" + std::to_wstring(observation.Request.Length - captured.size()) +
            L",\"sample_sha256\":" + Nullable(digest) + L",\"translation_count\":" + std::to_wstring(observation.Translations.size()) +
            L",\"translations\":" + WalksJson(observation) + L",\"charged_physical_reads\":" + std::to_wstring(reads.ChargedSourceCalls) + L",\"charged_physical_bytes\":" + std::to_wstring(reads.ChargedBytes) +
            L",\"physical_recording_complete\":" + std::wstring(Boolean(recorded)) + L",\"unrecorded_attempts\":" + std::to_wstring(reads.UnrecordedAttempts) + L",\"incomplete_physical_reads\":" + IncompleteReads(reads) +
            L",\"spans\":" + spans + L"]}";
    }

    void Probe(const std::wstring& name, SavedDumpProbe& probe)
    {
        if (!probe.Request.ExpectedSample.empty()) { probe.ContentCheck = L"not_compared"; }
        std::filesystem::path path;
        symbol_artifacts::Directories directories;
        if (!symbol_artifacts::LocalRoot(name, &path) || !directories.Pin(path.parent_path(), false, FILE_SHARE_READ))
        {
            probe.Init.Decision = probe.Status = L"path_rejected";
            return;
        }
        auto source = OpenDumpObservationSource(path.wstring(), nullptr, &probe.Init, probe.Request.ExpectedHeader);
        if (!source) { probe.Status = probe.Init.Decision; return; }
        const auto address = probe.Request.Address.value_or(probe.Init.HeaderModuleList.value_or(0));
        if (!probe.Request.Address && ((address & 7) || !source->Capabilities().AddressSpace.KernelRange(address, 16)))
        {
            probe.Status = L"default_range_unavailable";
            return;
        }
        ObservationReadRequest request;
        request.SourceId = source->Capabilities().SourceId;
        request.Address = address;
        request.Length = probe.Request.Length;
        request.ByteBudget = request.Length;
        const auto sample = source->ReadWithReceipts(request);
        uint32_t identityStatus = 0;
        probe.SampleIdentity = source->RevalidateFileIdentity(identityStatus);
        if (probe.SampleIdentity.has_value()) { probe.IdentityStatus = identityStatus; }
        DescribeSample(probe, sample);
    }
}

int RunDumpCapabilityProbe(const std::vector<std::wstring>& args, const std::wstring& binaryVersion)
{
    SavedDumpProbe probe;
    if (!Parse(args, probe.Request))
    {
        return WriteWithDistinctSelectedInputs(STD_ERROR_HANDLE, args, SavedSelector, [] {
            std::wcerr << L"usage: KnLiveDbg.exe " << capability_probes::Invocation(capability_probes::SavedDump) << L"\n";
            return 2;
        });
    }
    return WriteWithDistinctInput(STD_OUTPUT_HANDLE, args[1], [&] {
        Probe(args[1], probe);
        if (!WriteCapabilityJson(RenderSourceCapabilities(binaryVersion, nullptr, &probe))) { return 2; }
        return std::wstring_view(probe.Status) == L"read" ? 0 : 1;
    });
}
