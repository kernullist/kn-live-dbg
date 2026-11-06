#include "../user/TranslationReceiptJson.h"
#include <iostream>
#include <map>

namespace
{
    unsigned Checks = 0, Failures = 0;
    void Check(bool value, const char* reason)
    {
        ++Checks;
        if (!value) { ++Failures; std::cerr << "FAIL " << reason << "\n"; }
    }

    class Memory final : public IObservationSource
    {
    public:
        Memory()
        {
            Caps.SourceId = L"synthetic:physical";
            Caps.Consistency = L"controlled_memory";
            Caps.AddressDomain = ObservationAddressDomain::Physical;
            Caps.AddressSpace.PhysicalAddressBits = 52;
        }
        ObservationSourceCapabilities Caps;
        std::map<uint64_t, uint64_t> Words;
        unsigned Calls = 0;
        std::function<void(const ObservationReadRequest&, ObservationReadResult&)> AfterRead;
        const ObservationSourceCapabilities& Capabilities() const override { return Caps; }
    protected:
        ObservationReadResult ReadSpans(const ObservationReadRequest& request) override
        {
            ++Calls;
            ObservationReadResult read;
            ObservationReadSpan span{request.Address, request.Length, ObservationReadState::NotCaptured, {}};
            const auto found = Words.find(request.Address);
            if (request.Length == 8 && found != Words.end())
            {
                span.State = ObservationReadState::Complete;
                for (unsigned i = 0; i < 8; ++i) { span.Bytes.push_back(static_cast<uint8_t>(found->second >> (8 * i))); }
            }
            read.Spans.push_back(std::move(span));
            if (AfterRead) { AfterRead(request, read); }
            return read;
        }
    };

    // A provider may publish a new contract when a read scope completes.
    // Each individual read is valid, but a range must not combine the domains.
    class ContractSwitchSource final : public IObservationSource
    {
    public:
        ContractSwitchSource()
        {
            Caps.SourceId = L"synthetic:contract-switch";
            Caps.AddressSpace.PhysicalAddressBits = 52;
        }
        const ObservationSourceCapabilities& Capabilities() const override { return Caps; }
        unsigned Calls = 0;
    protected:
        class Scope final : public ObservationReadScope
        {
        public:
            explicit Scope(ObservationSourceCapabilities& caps) : Caps(caps) {}
            bool Admit(ObservationReadResult*) override { return true; }
            void Complete(ObservationReadResult*) override { Caps.AddressDomain = ObservationAddressDomain::Physical; }
        private:
            ObservationSourceCapabilities& Caps;
        };
        std::unique_ptr<ObservationReadScope> BeginReadScope(const ObservationReadRequest&, const ObservationSourceCapabilities&) override
        {
            return std::make_unique<Scope>(Caps);
        }
        ObservationReadResult ReadSpans(const ObservationReadRequest& request) override
        {
            ++Calls;
            ObservationReadResult read;
            read.Spans = {{request.Address, request.Length, ObservationReadState::Complete, std::vector<uint8_t>(request.Length, 0x42)}};
            return read;
        }
    private:
        ObservationSourceCapabilities Caps;
    };

    struct Fixture
    {
        Memory Source;
        TranslationRootIdentity Root;
        uint64_t Address;
        uint64_t Base;
        uint64_t PageBytes;
        std::vector<uint64_t> EntryAddresses;
        Fixture(uint32_t levels = 4, uint32_t leaf = 1, uint64_t tableBase = 0x1000)
        {
            Address = levels == 4 ? 0x0000123456789abcull : 0x0012123456789abcull;
            Base = leaf == 3 ? 0x80000000 : leaf == 2 ? 0x400000 : 0x9000;
            PageBytes = uint64_t{1} << (12 + 9 * (leaf - 1));
            Root.SourceId = Source.Caps.SourceId;
            Root.TargetId = L"synthetic:target";
            Root.AddressSpaceId = L"synthetic:address-space";
            Root.RootId = L"synthetic:root";
            Root.Binding = L"owned_synthetic_generation";
            Root.Root = tableBase | 0x123; // PCID bits do not become an entry address.
            Root.Epoch = 9;
            Root.Space = AddressSpaceDescriptor::FromPagingLevels(levels);
            Root.Space.PhysicalAddressBits = 52;
            Root.NxEnabled = PagingFeatureState::Enabled;
            Root.Pages1G = PagingFeatureState::Enabled;
            uint64_t table = tableBase;
            for (uint32_t level = levels; level >= leaf; --level)
            {
                const auto location = table + ((Address >> (12 + 9 * (level - 1))) & 511) * 8;
                EntryAddresses.push_back(location);
                Source.Words[location] = (level == leaf ? Base | (leaf == 1 ? 0 : 0x80) : table + 4096) | 7;
                table += 4096;
            }
        }
    };

    struct Observed { TranslationReceipt Translation; ObservationReadSet Reads; };
    Observed Run(Fixture& fixture, ObservationOperationBudget budget = {}, const std::atomic<bool>* cancel = nullptr,
        ObservationReadOperation::Clock clock = []() { return uint64_t{100}; })
    {
        const auto initial = fixture.Root;
        auto operation = std::make_shared<ObservationReadOperation>(L"synthetic:translation", initial.TargetId, initial.AddressSpaceId, budget, clock);
        RecordingObservationSource physical(fixture.Source, operation);
        auto translated = TranslateObservedAddress(physical, initial, [&]() { return fixture.Root; }, fixture.Address, 32, cancel);
        return {std::move(translated), operation->Snapshot()};
    }

    void Emit(const std::wstring& name, const Observed& observed)
    {
        std::cout << mcpjson::WideToUtf8(L"{\"name\":" + mcpjson::Quote(name) + L",\"translation\":" +
            TranslationReceiptJson(observed.Translation) + L",\"read_set\":" + ObservationReadSetJson(observed.Reads) + L"}") << "\n";
    }
}

int main()
{
    for (uint32_t levels : {4u, 5u})
    {
        for (uint32_t leaf : {1u, 2u, 3u})
        {
            Fixture fixture(levels, leaf);
            // Restrictions at the highest table must apply even with permissive leaves.
            fixture.Source.Words[fixture.EntryAddresses[0]] &= ~uint64_t{6};
            fixture.Source.Words[fixture.EntryAddresses[0]] |= uint64_t{1} << 63;
            const auto observed = Run(fixture);
            const auto& t = observed.Translation;
            Check(t.State == ObservationReadState::Complete && t.HasMapping && t.RootRevalidated && t.EntriesRevalidated,
                "complete-path-and-recheck");
            Check(t.PhysicalAddress == fixture.Base + (fixture.Address & (fixture.PageBytes - 1)) && t.PageBytes == fixture.PageBytes &&
                t.TranslatedBytes == 32, "independent-large-page-address");
            Check(t.PagingPermissionsKnown && !t.Writable && !t.UserAccessible && !t.Executable, "upper-level-permissions-reduced");
            Check(observed.Reads.ChargedBytes == 16 * fixture.EntryAddresses.size() &&
                observed.Reads.ChargedSourceCalls == 2 * fixture.EntryAddresses.size(), "every-intermediate-and-recheck-read-budgeted");
            Emit(L"la" + std::to_wstring(levels == 4 ? 48 : 57) + L"-leaf" + std::to_wstring(leaf), observed);
        }
    }
    Fixture high(4, 1, 0x0000800000000000ull);
    Check(Run(high).Translation.HasMapping, "physical-table-address-in-virtual-canonical-hole-is-admitted");
    for (unsigned kind = 0; kind < 8; ++kind)
    {
        Fixture fixture;
        if (kind == 0) { fixture.Root.Root |= uint64_t{1} << 60; }
        if (kind == 1) { fixture.Root.Space.PhysicalAddressBits = 36; fixture.Source.Words[fixture.EntryAddresses[0]] |= uint64_t{1} << 40; }
        if (kind == 2) { fixture.Source.Words[fixture.EntryAddresses[0]] |= 0x80; }
        if (kind == 3) { fixture.Root.NxEnabled = PagingFeatureState::Disabled; fixture.Source.Words[fixture.EntryAddresses[0]] |= uint64_t{1} << 63; }
        if (kind == 4) { fixture.Root.Epoch = 0; }
        if (kind == 5) { fixture.Address = 0x0000800000000000ull; }
        if (kind == 6) { fixture.Source.Caps.AddressDomain = ObservationAddressDomain::Virtual; }
        if (kind == 7) { fixture.Root.Space.LegacyAssumed = true; }
        const auto observed = Run(fixture);
        Check(observed.Translation.State == ObservationReadState::Unsupported && !observed.Translation.HasMapping &&
            !observed.Translation.PagingPermissionsKnown, "unsupported-context-or-reserved-entry-has-no-mapping-or-permissions");
    }
    for (uint32_t leaf : {2u, 3u})
    {
        Fixture invalid(4, leaf);
        invalid.Source.Words[invalid.EntryAddresses.back()] |= 0x2000;
        Check(Run(invalid).Translation.State == ObservationReadState::Unsupported, "large-leaf-reserved-alignment-rejected");
        Fixture pat(4, leaf);
        pat.Source.Words[pat.EntryAddresses.back()] |= 0x1000;
        Check(Run(pat).Translation.HasMapping, "large-leaf-pat-is-not-a-base-address-bit");
    }
    Fixture disabled(4, 3);
    disabled.Root.Pages1G = PagingFeatureState::Disabled;
    Check(!Run(disabled).Translation.HasMapping, "known-disabled-one-gib-page-denied");
    Fixture unknownLarge(4, 3);
    unknownLarge.Root.Pages1G = PagingFeatureState::Unknown;
    const auto largeUnknown = Run(unknownLarge);
    Check(largeUnknown.Translation.HasMapping && !largeUnknown.Translation.PagingPermissionsKnown,
        "unknown-one-gib-support-cannot-qualify-permissions");
    Fixture unknown;
    unknown.Root.Space.PhysicalAddressBits = 0;
    unknown.Root.NxEnabled = PagingFeatureState::Unknown;
    auto observed = Run(unknown);
    Check(observed.Translation.HasMapping && !observed.Translation.PagingPermissionsKnown, "unknown-architecture-is-not-permission-evidence");
    Emit(L"unknown-architecture", observed);

    for (unsigned failingLevel = 0; failingLevel < 4; ++failingLevel)
    {
        Fixture partial;
        partial.Source.AfterRead = [&](const auto& request, auto& read)
        {
            if (partial.Source.Calls != failingLevel + 1) { return; }
            auto prefix = read.Spans[0].Bytes;
            prefix.resize(5);
            read.Spans = {{request.Address, 5, ObservationReadState::Complete, prefix},
                {request.Address + 5, 3, ObservationReadState::Failed, {}}};
            read.NativeStatusDomain = L"ntstatus";
            read.NativeStatus = 0x8000000d;
        };
        observed = Run(partial);
        Check(!observed.Translation.HasMapping && !observed.Translation.PagingPermissionsKnown &&
            observed.Reads.Reads.back().Result.NativeStatus == 0x8000000d && partial.Source.Calls == failingLevel + 1,
            "partial-entry-failure-keeps-status-and-never-uses-prefix");
        if (failingLevel == 1) { Emit(L"partial-entry", observed); }
    }
    Fixture absent;
    absent.Source.Words[absent.EntryAddresses[1]] = 0;
    observed = Run(absent);
    Check(observed.Translation.State == ObservationReadState::NotPresent && absent.Source.Calls == 2, "nonpresent-is-distinct-from-read-failure");
    Emit(L"not-present", observed);
    for (unsigned changeAt : {1u, 5u})
    {
      for (bool changeEpoch : {false, true})
      {
        Fixture changed;
        changed.Source.AfterRead = [&](const auto&, auto&)
        {
            if (changed.Source.Calls != changeAt) { return; }
            if (changeEpoch) { ++changed.Root.Epoch; } else { changed.Root.Root += 4096; }
        };
        observed = Run(changed);
        Check(observed.Translation.State == ObservationReadState::IdentityChanged && !observed.Translation.HasMapping &&
            observed.Reads.Reads.size() == changeAt && observed.Reads.Reads[0].Result.Spans[0].Bytes.size() == 8,
            "root-or-epoch-change-keeps-original-read-but-rejects-mapping");
        if (changeEpoch && changeAt == 1) { Emit(L"root-changed", observed); }
      }
    }
    Fixture changedEntry;
    changedEntry.Source.AfterRead = [&](const auto&, auto&)
    {
        if (changedEntry.Source.Calls == 4) { changedEntry.Source.Words[changedEntry.EntryAddresses[0]] ^= 2; }
    };
    observed = Run(changedEntry);
    Check(observed.Translation.State == ObservationReadState::Conflict && !observed.Translation.HasMapping && observed.Reads.ChargedBytes == 40,
        "recheck-conflict-retains-both-versions");
    Emit(L"entry-changed", observed);

    for (bool domainChange : {false, true})
    {
        Fixture changed;
        changed.Source.AfterRead = [&](const auto&, auto&)
        {
            if (domainChange) { changed.Source.Caps.AddressDomain = ObservationAddressDomain::Virtual; }
            else { changed.Source.Caps.AddressSpace.PhysicalAddressBits = 48; }
        };
        observed = Run(changed);
        Check(observed.Translation.State == ObservationReadState::IdentityChanged && !observed.Translation.HasMapping &&
            observed.Reads.Reads[0].Result.State == ObservationReadState::IdentityChanged,
            "address-contract-change-with-same-source-label-invalidates-read");
    }
    Fixture wrongOperation;
    auto wrong = std::make_shared<ObservationReadOperation>(L"wrong-operation", L"wrong-target", wrongOperation.Root.AddressSpaceId);
    RecordingObservationSource wrongRecorded(wrongOperation.Source, wrong);
    Check(!TranslateObservedAddress(wrongRecorded, wrongOperation.Root, [&]() { return wrongOperation.Root; },
        wrongOperation.Address, 32).HasMapping && wrongOperation.Source.Calls == 0,
        "translation-root-must-match-operation-target");
    Fixture missingReceipt;
    ObservationOperationBudget receiptBudget;
    receiptBudget.MaximumReceipts = 1;
    observed = Run(missingReceipt, receiptBudget);
    Check(!observed.Translation.HasMapping && observed.Translation.State == ObservationReadState::BudgetDeferred &&
        observed.Reads.UnrecordedAttempts == 1 && observed.Reads.ChargedSourceCalls == 1,
        "receipt-exhaustion-stops-walk-with-explicit-missing-denominator");

    for (bool duringRecheck : {false, true})
    {
        Fixture limited;
        ObservationOperationBudget budget;
        budget.MaximumBytes = duringRecheck ? 40 : 16;
        observed = Run(limited, budget);
        Check(observed.Translation.State == ObservationReadState::BudgetDeferred && !observed.Translation.HasMapping &&
            observed.Reads.ChargedBytes == budget.MaximumBytes && !observed.Reads.Reads.back().SourceInvoked,
            "operation-budget-bounds-walk-and-recheck");
        if (duringRecheck) { Emit(L"budget-deferred", observed); }
    }
    Fixture deadline;
    uint64_t now = 100;
    deadline.Source.AfterRead = [&](const auto&, auto&) { now += 5; };
    ObservationOperationBudget budget;
    budget.MaximumElapsedMs = 4;
    observed = Run(deadline, budget, nullptr, [&]() { return now; });
    Check(observed.Translation.State == ObservationReadState::BudgetDeferred && observed.Reads.Reads[0].Result.OperationDeadlineExceeded &&
        observed.Reads.Reads[0].Result.Spans[0].Bytes.size() == 8 && !observed.Translation.HasMapping,
        "overrun-keeps-original-bytes-without-using-them-for-translation");
    Emit(L"deadline", observed);
    for (unsigned cancelAt : {1u, 5u})
    {
        Fixture cancelled;
        std::atomic<bool> cancel{false};
        cancelled.Source.AfterRead = [&](const auto&, auto&) { if (cancelled.Source.Calls == cancelAt) { cancel = true; } };
        observed = Run(cancelled, {}, &cancel);
        Check(observed.Translation.State == ObservationReadState::Cancelled && cancelled.Source.Calls == cancelAt && !observed.Translation.HasMapping,
            "cancellation-observed-after-source-call");
    }

    Memory physical;
    physical.Words[0] = 42;
    std::vector<uint8_t> bytes;
    Check(ReadObservationExact(physical, 0, 8, &bytes), "physical-zero-is-valid-regular-address-shape");
    Check(!ReadObservationExact(physical, (uint64_t{1} << 52) - 4, 8, &bytes), "physical-width-overflow-denied");
    auto operation = std::make_shared<ObservationReadOperation>(L"domain-check", L"target", L"as");
    RecordingObservationSource first(physical, operation);
    ObservationReadRequest request{physical.Caps.SourceId, 0x11000, 8, 8};
    const auto prior = first.Read(request);
    Memory virtualMemory;
    virtualMemory.Caps.SourceId = L"synthetic:virtual";
    virtualMemory.Caps.AddressDomain = ObservationAddressDomain::Virtual;
    RecordingObservationSource second(virtualMemory, operation);
    request.SourceId = virtualMemory.Caps.SourceId;
    request.FallbackFromReceipt = prior.ReadReceiptId;
    request.FallbackReason = L"same-number-different-domain";
    request.AllowFallback = true;
    Check(second.Read(request).State == ObservationReadState::PolicyDenied && virtualMemory.Calls == 0,
        "numeric-address-equality-does-not-permit-physical-virtual-fallback");

    now = 100;
    physical.AfterRead = [&](const auto&, auto&) { now += 5; };
    operation = std::make_shared<ObservationReadOperation>(L"parser-overrun", L"target", L"as", budget, [&]() { return now; });
    RecordingObservationSource slow(physical, operation);
    Check(!ReadObservationExact(slow, 0, 8, &bytes) && bytes.empty() && operation->Snapshot().Reads[0].Result.Spans[0].Bytes.size() == 8,
        "parser-rejects-deadline-overrun-without-erasing-evidence");
    now = 100;
    physical.AfterRead = [&](const auto& item, auto& read)
    {
        now += 5;
        read.Spans = {{item.Address, item.Length, ObservationReadState::Failed, {}}};
    };
    operation = std::make_shared<ObservationReadOperation>(L"fallback-overrun", L"target", L"as", budget, [&]() { return now; });
    RecordingObservationSource expired(physical, operation);
    request = {physical.Caps.SourceId, 0, 8, 8};
    const auto expiredRead = expired.Read(request);
    Memory alternate;
    alternate.Caps.SourceId = L"synthetic:alternate-physical";
    RecordingObservationSource retry(alternate, operation);
    request.SourceId = alternate.Caps.SourceId;
    request.FallbackFromReceipt = expiredRead.ReadReceiptId;
    request.FallbackReason = L"explicit_after_overrun";
    request.AllowFallback = true;
    Check(retry.Read(request).State == ObservationReadState::PolicyDenied && alternate.Calls == 0 &&
        !operation->Snapshot().Reads.back().FallbackPermitted,
        "deadline-overrun-failure-cannot-authorize-fallback");
    ContractSwitchSource switched;
    Check(!ReadObservationRange(switched, 0x11000, 8192, &bytes, 8192) && bytes.empty() && switched.Calls == 1,
        "range-read-cannot-combine-valid-chunks-from-different-address-contracts");
    std::cerr << "translation receipt controls: " << Checks << " checks, " << Failures << " failures\n";
    return Failures == 0 ? 0 : 1;
}
