#pragma once

#include "../user/BundleObservationSource.h"
#include "../user/CodeTargetResolver.h"
#include <functional>

namespace observation_source_test
{
    class ControlledSource final : public IObservationSource
    {
    public:
        ObservationSourceCapabilities Caps;
        std::function<ObservationReadResult(const ObservationReadRequest&)> Operation;
        unsigned Calls = 0;

        ControlledSource()
        {
            Caps.SourceId = L"controlled_fixture";
            Caps.Consistency = L"single_read";
            Operation = [](const ObservationReadRequest& request)
            {
                ObservationReadResult result;
                result.Spans.push_back({request.Address, request.Length, ObservationReadState::Complete,
                    std::vector<uint8_t>(request.Length, 0xc3)});
                return result;
            };
        }

        const ObservationSourceCapabilities& Capabilities() const override
        {
            return Caps;
        }

    protected:
        ObservationReadResult ReadSpans(const ObservationReadRequest& request) override
        {
            ++Calls;
            return Operation(request);
        }
    };

    template<typename Check>
    void Run(Check check, const EvidenceBundle& fixture)
    {
        ControlledSource controlled;
        ObservationReadRequest request;
        request.SourceId = controlled.Caps.SourceId;
        request.Address = 0x11000;
        request.Length = 32;
        request.ByteBudget = 32;
        const auto complete = controlled.Read(request);
        check(complete.State == ObservationReadState::Complete && complete.Spans[0].Bytes.size() == 32 &&
            complete.StartedTick <= complete.EndedTick && !complete.IdentityRevalidated &&
            complete.NativeStatusDomain == L"unavailable", "bounded source records scope without inventing identity proof or native status");
        const auto calls = controlled.Calls;
        request.SourceId = L"other_source";
        check(controlled.Read(request).State == ObservationReadState::IdentityChanged,
            "mismatched source rejected before collection");
        request.SourceId = controlled.Caps.SourceId;
        request.ByteBudget = 31;
        check(controlled.Read(request).State == ObservationReadState::BudgetDeferred, "byte budget checked before collection");
        request.ByteBudget = 32;
        controlled.Caps.MayChangeResidency = true;
        check(controlled.Read(request).State == ObservationReadState::PolicyDenied, "page-in-capable source requires collection policy");
        std::atomic<bool> cancelled{true};
        request.Cancellation = &cancelled;
        check(controlled.Read(request).State == ObservationReadState::Cancelled && controlled.Calls == calls,
            "denied and cancelled requests perform no collection");
        cancelled.store(false);
        request.AllowResidencyChanges = true;
        check(controlled.Read(request).SideEffectsPossible, "explicit collection retains potential side effects");
        request.Address = UINT64_MAX - 31;
        check(controlled.Read(request).State == ObservationReadState::Unsupported, "exclusive end overflow rejected");
        request.Address = 0x0000800000000000ull;
        check(controlled.Read(request).State == ObservationReadState::Unsupported, "noncanonical source request rejected");
        request.Address = 0x11000;
        request.Cancellation = nullptr;
        controlled.Caps.KernelOnly = true;
        check(controlled.Read(request).State == ObservationReadState::Unsupported, "kernel source cannot read a collector user VA");
        controlled.Caps.KernelOnly = false;
        std::vector<uint8_t> bytes{1};
        controlled.Caps.UserOnly = true;
        request.Address = 0xffff800000001000ull;
        const auto beforeUserOnly = controlled.Calls;
        check(controlled.Read(request).State == ObservationReadState::Unsupported &&
            !ReadObservationRange(controlled, request.Address, 64, &bytes, 64, true) && bytes.empty() &&
            controlled.Calls == beforeUserOnly, "user source rejects kernel ranges before provider invocation");
        controlled.Caps.UserOnly = false;
        request.Address = 0x11000;
        const auto beforeLarge = controlled.Calls;
        check(ReadObservationRange(controlled, 0x11000, 8193, &bytes, 8193, true) &&
            bytes.size() == 8193 && controlled.Calls == beforeLarge + 3, "IRP-sized reads use bounded chunks without losing coverage");
        const auto afterLarge = controlled.Calls;
        check(!ReadObservationRange(controlled, 0x11000, 8193, &bytes, 8192, true) && bytes.empty() &&
            controlled.Calls == afterLarge, "range budget applies to the entire read set before collection");
        controlled.Operation = [&](const ObservationReadRequest& item)
        {
            ObservationReadResult result;
            const bool first = item.Address == 0x11000;
            result.Spans.push_back({item.Address, item.Length, first ? ObservationReadState::Complete : ObservationReadState::Failed,
                first ? std::vector<uint8_t>(item.Length, 0xc3) : std::vector<uint8_t>{}});
            return result;
        };
        check(!ReadObservationRange(controlled, 0x11000, 8193, &bytes, 8193, true) && bytes.empty(),
            "failed later chunk discards all assembled parser input");
        controlled.Operation = [&](const ObservationReadRequest& item)
        {
            ObservationReadResult result;
            result.Spans.push_back({item.Address, item.Length, ObservationReadState::Complete,
                std::vector<uint8_t>(item.Length, 0xc3)});
            controlled.Caps.SourceId = L"replacement_connection";
            return result;
        };
        check(controlled.Read(request).State == ObservationReadState::IdentityChanged,
            "connection replacement during read cannot publish stale bytes");
        request.SourceId = controlled.Caps.SourceId;
        for (unsigned mode = 0; mode < 4; ++mode)
        {
            controlled.Operation = [mode](const ObservationReadRequest& item)
            {
                ObservationReadResult result;
                result.Spans.push_back({item.Address, item.Length, ObservationReadState::Complete,
                    std::vector<uint8_t>(item.Length, 0xc3)});
                if (mode == 0)
                {
                    result.Spans[0].Bytes.pop_back();
                }
                else if (mode == 1)
                {
                    ++result.Spans[0].Address;
                }
                else if (mode == 2)
                {
                    result.Spans[0].State = static_cast<ObservationReadState>(999);
                    result.Spans[0].Bytes.clear();
                }
                else
                {
                    result.Spans[0].State = ObservationReadState::Failed;
                }
                return result;
            };
            const auto invalid = controlled.Read(request);
            check(invalid.State == ObservationReadState::Failed && invalid.Spans.empty(), "malformed backend result is never parser input");
        }
        controlled.Operation = [&](const ObservationReadRequest& item)
        {
            cancelled.store(true);
            ObservationReadResult result;
            result.Spans.push_back({item.Address, item.Length, ObservationReadState::Complete,
                std::vector<uint8_t>(item.Length, 0xc3)});
            return result;
        };
        check(!ReadObservationExact(controlled, 0x11000, 32, &bytes, true, &cancelled) && bytes.empty(),
            "cancellation observed after synchronous read stops parser consumption");

        auto sparse = fixture;
        sparse.Spans = {{0x11000, 4, L"target_head", L"valid", {0xc3, 0x90, 0x90, 0x90}},
            {0x11004, 4, L"target_head", L"read_failed", {}}, {0x11008, 4, L"target_head", L"skipped", {}}};
        BundleObservationSource bundle(sparse);
        request.SourceId = bundle.Capabilities().SourceId;
        request.Length = 16;
        request.ByteBudget = 16;
        const auto parts = bundle.Read(request);
        check(parts.State == ObservationReadState::Partial && parts.Spans.size() == 4 &&
            parts.Spans[0].State == ObservationReadState::Complete && parts.Spans[1].State == ObservationReadState::Failed &&
            parts.Spans[2].State == ObservationReadState::Skipped && parts.Spans[3].State == ObservationReadState::NotCaptured,
            "sparse source distinguishes present failed skipped and never captured bytes");
        check(!ReadObservationExact(bundle, 0x11000, 16, &bytes) && bytes.empty(), "sparse gaps are never zero filled");
        sparse.Spans[0].Bytes[0] = 0x90;
        check(ReadObservationExact(bundle, 0x11000, 4, &bytes) && bytes[0] == 0xc3, "bundle source owns immutable captured bytes");
        BundleObservationSource changed(sparse);
        check(changed.Capabilities().SourceId != bundle.Capabilities().SourceId, "same collection and sequence cannot alias different evidence");
        sparse.Spans.push_back({0x11004, 4, L"target_head", L"skipped", {}});
        BundleObservationSource ordered(sparse);
        request.SourceId = ordered.Capabilities().SourceId;
        check(ordered.Read(request).Spans[1].State == ObservationReadState::Failed, "failed observation is not hidden by later skipped attempt");
        sparse.Spans.push_back({0x11000, 4, L"target_head", L"valid", {0xc3, 0x90, 0x90, 0x90}});
        BundleObservationSource conflict(sparse);
        request.SourceId = conflict.Capabilities().SourceId;
        check(conflict.Read(request).Spans[0].State == ObservationReadState::Conflict &&
            !ReadObservationExact(conflict, 0x11000, 4, &bytes), "conflicting captured values cannot become exact bytes");
        sparse.Spans.resize(EvidenceBundleMaxSpans + 1, sparse.Spans[0]);
        BundleObservationSource oversized(sparse);
        check(oversized.Capabilities().SourceId.empty(), "unbounded direct bundle cannot acquire a source identity");

        // Use real reads of owned user memory as an independent byte oracle.
        // This does not exercise the kernel driver or a hostile target.
        std::vector<uint8_t> owned(8192, 0x90);
        const auto root = reinterpret_cast<uint64_t>(owned.data());
        const uint64_t slot = root + 4096;
        owned[0] = 0xe9;
        const int32_t delta = 64 - 5;
        std::memcpy(owned.data() + 1, &delta, sizeof(delta));
        owned[64] = 0xc3;
        std::memcpy(owned.data() + 4096, &root, sizeof(root));
        ControlledSource live;
        live.Caps.MayChangeResidency = true;
        live.Operation = [&](const ObservationReadRequest& item)
        {
            ObservationReadResult result;
            ObservationReadSpan span{item.Address, item.Length, ObservationReadState::Failed, {}};
            SIZE_T read = 0;
            if (item.Address >= root && item.Address - root <= owned.size() &&
                item.Length <= owned.size() - static_cast<size_t>(item.Address - root))
            {
                span.Bytes.resize(item.Length);
                if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(item.Address),
                    span.Bytes.data(), item.Length, &read) && read == item.Length)
                {
                    span.State = ObservationReadState::Complete;
                }
                else
                {
                    span.Bytes.clear();
                }
            }
            result.Spans.push_back(std::move(span));
            return result;
        };
        auto captured = fixture;
        auto& reference = captured.Receipt.Reference;
        reference.Address = reference.Root = root;
        reference.Slot = slot;
        reference.Context.Coverage.Compared = {{root, 32}};
        captured.Spans = {{root, 96, L"target_head", L"valid", {owned.begin(), owned.begin() + 96}},
            {slot, 8, L"pointer_slot", L"valid", {owned.begin() + 4096, owned.begin() + 4104}}};
        BundleObservationSource replay(captured);
        const ObservationReader liveRead = [&](uint64_t at, size_t count, std::vector<uint8_t>* out)
        {
            return ReadObservationExact(live, at, count, out, true);
        };
        const ObservationReader replayRead = [&](uint64_t at, size_t count, std::vector<uint8_t>* out)
        {
            return ReadObservationExact(replay, at, count, out);
        };
        const auto actual = ResolveReferencedCodeTarget(root, slot, liveRead, {});
        const auto restored = ResolveReferencedCodeTarget(root, slot, replayRead, {});
        check(actual.ReferenceStable && restored.ReferenceStable && actual.Hops.size() == 2 && restored.Hops.size() == 2 &&
            actual.Termination == restored.Termination && actual.Hops[0].Bytes == restored.Hops[0].Bytes &&
            actual.Hops[1].Address == restored.Hops[1].Address && actual.Hops[1].Bytes == restored.Hops[1].Bytes,
            "one target parser reproduces owned live reads through immutable bundle source");
        owned[64] = 0xcc;
        const auto liveChanged = ResolveReferencedCodeTarget(root, slot, liveRead, {});
        check(liveChanged.Termination != restored.Termination &&
            ResolveReferencedCodeTarget(root, slot, replayRead, {}).Termination == restored.Termination,
            "live mutation changes live parse without rewriting recorded replay");
    }
}
