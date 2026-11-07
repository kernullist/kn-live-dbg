#include "PendingIrpClaims.h"
#include "PendingIrpEvidence.h"
#include "ObservationReadRoutingJson.h"
#include "BoundedObservationJson.h"
#include "ClaimPolicy.h"
#include "ReferenceArtifact.h"
#include <array>

using namespace bounded_observation_json;
using namespace claim_policy;
namespace
{
    enum Kind : size_t { Membership, Owner, Registration, Completion, Cancellation, Execution, DeviceOwner };
    const std::array<Policy, 7>& Registry()
    {
        static const auto policies = []
        {
            const std::vector<Requirement> gates = {
                {L"original_capture", L"retain_original_capture_and_ordered_reads", L"collect", true},
                {L"source_scope", L"capture_under_one_stable_source_contract", L"collect", true},
                {L"schema_image_binding", L"retain_exact_reference_and_requalify_schema_image", L"collect", true},
                {L"request_invariants", L"repeat_packet_owner_and_reciprocal_list_checks", L"collect", true}};
            std::array<Policy, 7> out;
            const wchar_t* names[] = {L"irp_thread_list_member_observed", L"irp_packet_owner_matches_thread_observed",
                L"irp_completion_registration_observed", L"irp_request_completion_observed", L"irp_request_cancellation_observed",
                L"irp_completion_execution_observed", L"irp_device_driver_ownership_observed"};
            for (size_t i = 0; i < out.size(); ++i) { out[i].Id = names[i]; out[i].Requires = gates; }
            out[Membership].Requires.push_back({L"list_path_rechecked", L"capture_and_recheck_reciprocal_thread_list_path", L"collect"});
            out[Owner].Requires.push_back({L"owner_field_matches_thread", L"capture_IRP_Tail_Thread_and_thread_generation", L"collect"});
            out[Registration].Requires.insert(out[Registration].Requires.end(), {
                {L"typed_completion_slot", L"capture_exact_IO_STACK_LOCATION_fields", L"collect", true},
                {L"completion_enabled", L"observe_completion_control_bits_in_same_packet", L"collect"},
                {L"completion_target_present", L"observe_nonzero_kernel_completion_target", L"collect"}});
            for (auto kind : {Completion, Cancellation, Execution})
            { out[kind].Requires.push_back({L"request_generation", L"obtain_provider_bound_request_allocation_generation", L"owned_lab_or_supported_provider"}); }
            out[Completion].Requires.push_back({L"completion_event_and_outcome", L"capture_generation_bound_completion_event_and_outcome", L"owned_lab_or_supported_provider"});
            out[Cancellation].Requires.push_back({L"cancellation_event_and_outcome", L"capture_generation_bound_cancel_completion_and_outcome", L"owned_lab_or_supported_provider"});
            out[Execution].Requires.insert(out[Execution].Requires.end(), {
                {L"execution_event", L"capture_qualified_completion_execution_event", L"owned_lab_or_supported_provider"},
                {L"code_version_binding", L"bind_execution_event_to_observed_code_version", L"collect"}});
            out[DeviceOwner].Requires.insert(out[DeviceOwner].Requires.end(), {
                {L"device_pointer_read", L"capture_typed_DeviceObject_field", L"collect"},
                {L"device_and_driver_lifetimes", L"obtain_referenced_device_and_driver_generations", L"owned_lab_or_supported_provider"},
                {L"device_driver_owner_relation", L"capture_and_recheck_typed_device_driver_owner_fields", L"collect"}});
            return out;
        }();
        return policies;
    }
    std::wstring Ref(const Evidence& ref)
    { return L"{\"capture_sha256\":" + mcpjson::Quote(ref.Sha256) + L",\"json_pointer\":" + mcpjson::Quote(ref.Pointer) + L"}"; }
    std::wstring Policies()
    {
        std::wstring out = L"[";
        for (const auto& policy : Registry())
        {
            if (out.size() != 1) { out += L","; }
            out += L"{\"claim\":" + mcpjson::Quote(policy.Id) + L",\"requires\":[";
            for (size_t i = 0; i < policy.Requires.size(); ++i)
            {
                const auto& r = policy.Requires[i];
                if (i) { out += L","; }
                out += L"{\"id\":" + mcpjson::Quote(r.Id) + L",\"scope_gate\":" + B(r.Gate) +
                    L",\"next_observation\":" + mcpjson::Quote(r.NextObservation) + L",\"mode\":" + mcpjson::Quote(r.Mode) + L"}";
            }
            out += L"]}";
        }
        return out + L"]";
    }
    std::wstring Facts(const std::vector<Fact>& facts)
    {
        std::wstring out = L"[";
        for (size_t i = 0; i < facts.size(); ++i)
        {
            if (i) { out += L","; }
            out += L"{\"requirement\":" + mcpjson::Quote(facts[i].RequirementId) + L",\"evidence\":" + Ref(facts[i].Origin) + L"}";
        }
        return out + L"]";
    }
    std::wstring Assessment(const Policy& policy, const Result& result, size_t request, const std::optional<size_t>& stack)
    {
        std::wstring out = L"{\"claim\":" + mcpjson::Quote(policy.Id) + L",\"policy\":\"kn.irp_claim_policy.v1\",\"request_index\":" + N(request) +
            L",\"stack_index\":" + (stack ? N(*stack) : L"null") + L",\"status\":" + mcpjson::Quote(Name(result.Status)) +
            L",\"issue\":" + mcpjson::Quote(result.Issue) + L",\"supports\":" + Facts(result.Supports) + L",\"contradicts\":" + Facts(result.Contradicts) +
            L",\"unfulfilled_requirements\":[";
        for (size_t i = 0; i < result.Missing.size(); ++i)
        { if (i) { out += L","; } out += mcpjson::Quote(result.Missing[i].Id); }
        out += L"],\"not_applicable_basis\":" + (result.NotApplicableBasis.Valid() ? Ref(result.NotApplicableBasis) : L"null") + L",\"next_best_observation\":";
        if (result.Status == State::Unfulfilled && !result.Missing.empty())
        {
            const auto& next = result.Missing.front();
            out += L"{\"resolves_requirement\":" + mcpjson::Quote(next.Id) + L",\"observation\":" + mcpjson::Quote(next.NextObservation) +
                L",\"mode\":" + mcpjson::Quote(next.Mode) + L",\"budget\":\"source_policy_bounded\",\"authorization_required\":true,\"automatic_execution\":false}";
        }
        else { out += L"null"; }
        return out + L"}";
    }
    using Interval = std::pair<uint64_t, uint64_t>;
    uint64_t UnionBytes(std::vector<Interval> ranges)
    {
        std::sort(ranges.begin(), ranges.end());
        uint64_t bytes = 0, end = 0;
        for (const auto& range : ranges)
        {
            if (range.second > end) { bytes += range.second - (std::max)(end, range.first); end = range.second; }
        }
        return bytes;
    }
}

std::wstring PendingIrpClaimAssessmentJson(const PendingIrpSchemaBinding& binding,
    const std::vector<PendingIrpThreadInput>& threads, const PendingIrpScanOptions& options,
    const PendingIrpScanResult& result, const ObservationRoutedReadSet& reads,
    const PendingIrpCaptureContext& context, const std::wstring& captureSha256,
    PendingIrpClaimMode mode, bool referenceAvailable) noexcept
{
    try
    {
        if (!Evidence{captureSha256, L"/reads"}.Valid() || threads.size() > 16384 || result.Requests.size() > 256 ||
            reads.ParserReads.size() > 4096 || !Text(context.Source.SourceId, 1024) || result.ScanFinishedTickMs < result.ScanStartedTickMs)
        { return {}; }
        const bool recorded = ValidObservationRoutedReadSet(reads);
        auto same = context.Source; same.AddressSpace = result.AddressSpace;
        const bool source = SameObservationSourceContract(same, context.Source) && context.Source.AddressSpace.Valid() &&
            context.Source.AddressDomain == ObservationAddressDomain::Virtual && context.FinalSourceSame && !context.FinalCancelled;
        pending_irp::IrpLayout layout;
        const bool bindingKnown = BuildPendingIrpLayout(binding, &layout, nullptr) && referenceAvailable && context.ReferenceBytes != 0 &&
            context.ReferenceBytes <= ReferenceArtifactMaxBytes && context.ReferenceStable && result.RuntimeQualified;
        std::vector<Interval> requested, accepted;
        uint64_t traffic = 0, rejectedCalls = 0;
        bool rangesKnown = reads.UnrecordedParserCalls == 0;
        for (const auto& read : reads.ParserReads)
        {
            if (read.Length == 0 || read.Address > UINT64_MAX - read.Length) { rangesKnown = false; continue; }
            requested.push_back({read.Address, read.Address + read.Length}); traffic += read.Length;
            if (read.Accepted) { accepted.push_back(requested.back()); } else { ++rejectedCalls; }
        }
        const auto requestedBytes = UnionBytes(requested), acceptedBytes = UnionBytes(accepted);
        uint64_t possible = 0;
        for (const auto& request : result.Requests)
        {
            if (request.Stacks.size() > 64) { return {}; }
            possible += 4 + 3 * request.Stacks.size();
        }
        std::wstring claims;
        uint64_t emitted = 0;
        bool full = false;
        std::array<uint64_t, 4> states{};
        const auto append = [&](Kind kind, size_t requestIndex, std::optional<size_t> stackIndex,
            const std::vector<Fact>& common, std::vector<Fact> extra, const Evidence& notApplicable = Evidence{})
        {
            if (full || emitted == PendingIrpClaimLimit) { return; }
            extra.insert(extra.begin(), common.begin(), common.end());
            const auto evaluated = Evaluate(Registry()[kind], extra, notApplicable);
            const auto row = Assessment(Registry()[kind], evaluated, requestIndex, stackIndex);
            // Leave room for all ledgers. Omission is explicit, never complete.
            if (row.size() + (claims.empty() ? 0 : 1) > PendingIrpClaimMaximumCharacters - 16384 - claims.size())
            { full = true; return; }
            if (!claims.empty()) { claims += L","; }
            claims += row; ++emitted; ++states[static_cast<size_t>(evaluated.Status)];
        };
        for (size_t i = 0; i < result.Requests.size(); ++i)
        {
            const auto& request = result.Requests[i];
            const auto path = L"/requests/" + std::to_wstring(i);
            const bool qualified = result.RuntimeQualified && request.ThreadCreateTime != 0 &&
                result.AddressSpace.KernelRange(request.Thread.ThreadObject, 1) && result.AddressSpace.KernelRange(request.Irp, 1);
            const auto fact = [&](const wchar_t* id, bool met, const std::wstring& pointer)
            { return Fact{id, met ? Observation::Met : Observation::Missing, {captureSha256, pointer}}; };
            const std::vector<Fact> common = {
                fact(L"original_capture", recorded, L"/reads"), fact(L"source_scope", source, L"/source_contract"),
                fact(L"schema_image_binding", bindingKnown, L"/schemas"), fact(L"request_invariants", qualified, path)};
            append(Membership, i, {}, common, {fact(L"list_path_rechecked", qualified, L"/reads")});
            append(Owner, i, {}, common, {fact(L"owner_field_matches_thread", qualified, L"/reads")});
            append(Completion, i, {}, common, {});
            append(Cancellation, i, {}, common, {});
            for (size_t j = 0; j < request.Stacks.size(); ++j)
            {
                const auto& stack = request.Stacks[j];
                const auto stackPath = path + L"/stacks/" + std::to_wstring(j);
                const bool enabled = (stack.Control & 0xe0) != 0, target = stack.CompletionRoutine != 0;
                const auto observed = [&](const wchar_t* id, bool value, const wchar_t* field)
                { return Fact{id, value ? Observation::Met : Observation::Contrary, {captureSha256, stackPath + field}}; };
                append(Registration, i, j, common, {fact(L"typed_completion_slot", qualified, stackPath),
                    observed(L"completion_enabled", enabled, L"/control"), observed(L"completion_target_present", target, L"/completion")});
                const Evidence absent = !enabled || !target ? Evidence{captureSha256, stackPath} : Evidence{};
                append(Execution, i, j, common, {}, absent);
                const auto device = fact(L"device_pointer_read", stack.DeviceObject.has_value(), stackPath + L"/device");
                const Evidence nullDevice = stack.DeviceObject && *stack.DeviceObject == 0 ? Evidence{captureSha256, stackPath + L"/device"} : Evidence{};
                append(DeviceOwner, i, j, common, {device}, nullDevice);
            }
        }
        const bool replay = mode == PendingIrpClaimMode::Replay;
        std::wstring out = L"{\"schema\":\"kn.irp_claim_report.v1\",\"registry\":\"kn.claim_registry.v1\",\"policy\":\"kn.irp_claim_policy.v1\",\"evaluation_mode\":" +
            mcpjson::Quote(replay ? L"current_policy_on_replayed_observations" : L"capture_time_policy") +
            L",\"scope\":\"captured_recorded_policy_invariants\",\"capture_sha256\":" + mcpjson::Quote(captureSha256) +
            L",\"source_id\":" + mcpjson::Quote(context.Source.SourceId) + L",\"claims_possible\":" + N(possible) +
            L",\"claims_emitted\":" + N(emitted) + L",\"claims_omitted\":" + N(possible - emitted) + L",\"claim_limit\":" + N(PendingIrpClaimLimit) +
            L",\"report_complete\":" + B(emitted == possible) + L",\"counts\":{\"supported\":" + N(states[0]) + L",\"contradicted\":" + N(states[1]) +
            L",\"unfulfilled\":" + N(states[2]) + L",\"not_applicable\":" + N(states[3]) + L"},\"ledgers\":{\"discovery\":{\"scope\":\"supplied_ETHREAD_inventory\","
            L"\"supplied_threads\":" + N(threads.size()) + L",\"threads_visited\":" + N(result.ThreadsVisited) + L",\"irps_inspected\":" + N(result.IrpsInspected) +
            L",\"requests_retained\":" + N(result.Requests.size()) + L",\"unstable_observations\":" + N(result.UnstableObservations) +
            L",\"max_threads\":" + N(options.MaxThreads) + L",\"max_irps\":" + N(options.MaxIrps) + L",\"max_walk_nodes\":" + N(options.MaxWalkNodes) +
            L",\"complete_for_supplied_inventory\":" + B(result.CoverageComplete && referenceAvailable) + L",\"global_inventory\":false,\"cursor_evidence\":" + Ref({captureSha256, L"/next_cursor"}) +
            L"},\"address\":{\"scope\":\"recorded_parser_call_ranges_only\",\"requested_union_bytes\":" + N(requestedBytes) +
            L",\"accepted_union_bytes\":" + N(acceptedBytes) + L",\"failed_only_union_bytes\":" + N(requestedBytes - acceptedBytes) +
            L",\"requested_traffic_bytes\":" + N(traffic) + L",\"rejected_parser_calls\":" + N(rejectedCalls) +
            L",\"exact_recorded_denominator\":" + B(rangesKnown && recorded) + L",\"compared_bytes\":\"0\",\"unvisited_outside_recorded_calls\":null,"
            L"\"range_evidence\":" + Ref({captureSha256, L"/reads/parser_reads"}) +
            L"},\"temporal\":{\"clock\":\"collector_boot_tick_ms\",\"started\":" + N(result.ScanStartedTickMs) + L",\"finished\":" + N(result.ScanFinishedTickMs) +
            L",\"atomic_snapshot\":false,\"continuous_observation\":false,\"event_loss_intervals\":null,\"revisit_gaps\":null},"
            L"\"semantic\":{\"schema_image_bound\":" + B(bindingKnown) + L",\"request_lifetime_bound\":false,\"build_approval\":\"not_established\"},"
            L"\"persistence\":{\"capture\":" + mcpjson::Quote(replay ? L"file_hash_verified" : L"encoded_in_memory") +
            L",\"reference\":" + mcpjson::Quote(referenceAvailable ? (replay ? L"file_hash_verified" : L"captured_in_memory") : L"unavailable") +
            L",\"journal_membership\":\"not_checked\",\"claim_report_persistence\":\"not_established\"},"
            L"\"replay\":{\"original_capture_policy\":\"schema-image-repeated-snapshot-v1\",\"ordered_read_replay\":" +
            mcpjson::Quote(replay ? L"canonical_result_matched" : L"not_attempted") + L",\"original_claim_policy_reproduced\":false},"
            L"\"trust\":{\"collector_authenticated\":false,\"external_final_state_authenticated\":false,\"source_scope\":\"declared_collector_contract\","
            L"\"checksum_is_authentication\":false}},\"never_implies\":[\"execution_observed\",\"writer_attributed\",\"maliciousness_established\","
            L"\"whole_host_clean\",\"referenced_request_lifetime\",\"deadlock_established\"],\"policy_registry\":" + Policies() + L",\"claims\":[" + claims + L"]}";
        return out.size() <= PendingIrpClaimMaximumCharacters ? out : L"";
    }
    catch (...) { return {}; }
}
