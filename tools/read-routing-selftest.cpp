#include "../user/ObservationReadRoutingJson.h"
#include <iostream>

namespace
{
    unsigned Checks = 0, Failures = 0;
    void Check(bool value, const char* name)
    {
        ++Checks;
        if (!value) { ++Failures; std::cerr << "FAIL " << name << "\n"; }
    }
    class Source final : public IObservationSource
    {
    public:
        ObservationSourceCapabilities Caps;
        unsigned Calls = 0;
        std::function<ObservationReadResult(const ObservationReadRequest&)> Action;
        explicit Source(const wchar_t* id = L"synthetic:primary")
        {
            Caps.SourceId = id;
            Caps.Consistency = L"synthetic_non_atomic";
            Caps.AddressSpace = AddressSpaceDescriptor::FromPagingLevels(4);
            Caps.UserOnly = true;
            Action = [](const auto& request)
            {
                ObservationReadResult result;
                result.NativeStatusDomain = L"win32";
                result.Spans = {{request.Address, request.Length, ObservationReadState::Complete,
                    std::vector<uint8_t>(request.Length, 0x51)}};
                return result;
            };
        }
        const ObservationSourceCapabilities& Capabilities() const override { return Caps; }
        void Fail(ObservationReadState state = ObservationReadState::Failed)
        {
            Action = [state](const auto& request)
            {
                ObservationReadResult result;
                result.NativeStatusDomain = L"win32";
                result.NativeStatus = 299;
                result.Spans = {{request.Address, request.Length, state, {}}};
                return result;
            };
        }
    protected:
        ObservationReadResult ReadSpans(const ObservationReadRequest& request) override { ++Calls; return Action(request); }
    };
    struct Fixture
    {
        Source Primary, Secondary{L"synthetic:secondary"};
        ObservationReadRouting Route;
        ObservationOperationBudget Budget;
        std::atomic<bool> Cancel{false};
        unsigned Factories = 0;
        uint64_t Tick = 1;
        std::vector<uint8_t> Bytes{1};
        Fixture()
        {
            Route.Primary = &Primary;
            Route.TargetId = L"synthetic:target";
            Route.AddressSpaceId = L"synthetic:as";
            Route.AllowFallback = true;
            Route.Fallback = [&]() -> IObservationSource* { ++Factories; return &Secondary; };
        }
        std::shared_ptr<ObservationReadOperation> Operation(const wchar_t* id)
        {
            return std::make_shared<ObservationReadOperation>(id, Route.TargetId, Route.AddressSpaceId, Budget, [&] { return Tick; });
        }
        bool Read(ObservationReadRouter& router) { return router.ReadExact(0x11000, 32, &Bytes); }
        void Emit(const ObservationReadRouter& router) const
        {
            std::cout << mcpjson::WideToUtf8(ObservationRoutedReadSetJson(router.Snapshot())) << "\n";
        }
    };
}

int main()
{
    {
        Fixture f;
        ObservationReadRouter router(f.Route, f.Operation(L"primary"));
        Check(f.Read(router) && f.Bytes == std::vector<uint8_t>(32, 0x51), "complete-primary-parser-bytes");
        Check(f.Factories == 0 && f.Secondary.Calls == 0, "success-does-not-initialize-fallback");
        f.Emit(router);
    }
    {
        Fixture f;
        f.Primary.Action = [](const auto& request)
        {
            ObservationReadResult result;
            result.NativeStatusDomain = L"ntstatus";
            result.NativeStatus = 0x8000000d;
            result.Spans = {{request.Address, 16, ObservationReadState::Complete, std::vector<uint8_t>(16, 0x41)},
                {request.Address + 16, 16, ObservationReadState::Failed, {}}};
            return result;
        };
        ObservationReadRouter router(f.Route, f.Operation(L"partial-fallback"));
        Check(f.Read(router) && f.Bytes == std::vector<uint8_t>(32, 0x51), "fallback-whole-read-without-byte-merge");
        const auto set = router.Snapshot();
        Check(set.Attempts.Reads.size() == 2 && set.Attempts.Reads[0].Result.Spans[0].Bytes.size() == 16 &&
            set.ParserReads[0].PrimaryReceipt == 1 && set.ParserReads[0].ReturnedReceipt == 2 &&
            set.Attempts.Reads[1].Request.FallbackFromReceipt == 1 && set.Attempts.Reads[1].FallbackPermitted,
            "failed-raw-prefix-linked-to-selected-fallback");
        f.Emit(router);
    }
    for (const auto state : {ObservationReadState::IdentityChanged, ObservationReadState::PolicyDenied,
        ObservationReadState::Conflict, ObservationReadState::Cancelled, ObservationReadState::BudgetDeferred})
    {
        Fixture f; f.Primary.Fail(state);
        const auto id = L"no-fallback-" + std::to_wstring(static_cast<unsigned>(state));
        ObservationReadRouter router(f.Route, f.Operation(id.c_str()));
        Check(!f.Read(router) && f.Bytes.empty() && f.Factories == 0, "identity-policy-conflict-cancel-budget-cannot-fallback");
        f.Emit(router);
    }
    {
        Fixture f; f.Primary.Fail(); f.Secondary.Fail();
        ObservationReadRouter router(f.Route, f.Operation(L"both-failed"));
        Check(!f.Read(router) && f.Bytes.empty() && router.Snapshot().Attempts.Reads.size() == 2, "both-failures-retained");
        f.Emit(router);
    }
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        Fixture f; f.Primary.Fail();
        if (mode == 0) { f.Budget.MaximumBytes = 32; }
        if (mode == 1) { f.Budget.MaximumSourceCalls = 1; }
        if (mode == 2) { f.Budget.MaximumReceipts = 1; }
        const auto id = L"shared-budget-" + std::to_wstring(mode);
        ObservationReadRouter router(f.Route, f.Operation(id.c_str()));
        Check(!f.Read(router) && f.Bytes.empty() && f.Secondary.Calls == 0, "fallback-cannot-renew-shared-budget");
        Check(router.Snapshot().Attempts.ChargedBytes == 32, "failed-primary-charged");
        f.Emit(router);
    }
    for (unsigned mode = 0; mode < 4; ++mode)
    {
        Fixture f; f.Primary.Fail();
        if (mode == 0) { f.Secondary.Caps.SourceId = f.Primary.Caps.SourceId; }
        if (mode == 1) { f.Secondary.Caps.AddressDomain = ObservationAddressDomain::Physical; }
        if (mode == 2) { f.Secondary.Caps.AddressSpace = AddressSpaceDescriptor::FromPagingLevels(5); }
        if (mode == 3) { f.Secondary.Caps.UserOnly = false; }
        const auto id = L"incompatible-" + std::to_wstring(mode);
        ObservationReadRouter router(f.Route, f.Operation(id.c_str()));
        Check(!f.Read(router) && f.Secondary.Calls == 0 &&
            router.Snapshot().ParserReads[0].Reason == L"fallback_contract_mismatch", "fallback-domain-descriptor-policy-binding");
        f.Emit(router);
    }
    {
        Fixture f;
        ObservationReadRouter router(f.Route, f.Operation(L"source-changed"));
        f.Primary.Caps.SourceId += L":changed";
        Check(!f.Read(router) && f.Primary.Calls == 0 && f.Factories == 0, "changed-primary-contract-denied");
        f.Emit(router);
    }
    for (unsigned mode = 0; mode < 4; ++mode)
    {
        Fixture f;
        if (mode == 0) { f.Route.BeforeRead = [](auto, auto) { return false; }; }
        if (mode == 1) { f.Route.AfterRead = [](auto, auto) { return false; }; }
        if (mode == 2) { f.Route.AfterRead = [&](auto, auto) { f.Cancel.store(true); return true; }; }
        if (mode == 3) { f.Route.AfterRead = [&](auto, auto) { f.Tick += 5000; return true; }; }
        const auto id = L"guard-" + std::to_wstring(mode);
        ObservationReadRouter router(f.Route, f.Operation(id.c_str()), &f.Cancel);
        Check(!f.Read(router) && f.Bytes.empty() && f.Primary.Calls == (mode == 0 ? 0u : 1u), "guard-cancel-deadline-reject-parser-bytes");
        const auto set = router.Snapshot();
        if (mode != 0) { Check(set.Attempts.Reads[0].Result.State == ObservationReadState::Complete, "raw-complete-read-survives-parser-guard-failure"); }
        f.Emit(router);
    }
    {
        Fixture f; f.Primary.Caps.MayChangeResidency = true;
        ObservationReadRouter router(f.Route, f.Operation(L"residency"));
        Check(!f.Read(router) && f.Primary.Calls == 0 && f.Factories == 0, "residency-denial-cannot-fallback");
        f.Emit(router);
    }
    for (unsigned mode = 0; mode < 2; ++mode)
    {
        Fixture f;
        unsigned guards = 0;
        f.Route.BeforeRead = [&](auto, auto) { ++guards; return true; };
        if (mode == 0) { f.Cancel.store(true); }
        else { f.Budget.MaximumElapsedMs = 0; }
        const auto id = L"guard-not-started-" + std::to_wstring(mode);
        ObservationReadRouter router(f.Route, f.Operation(id.c_str()), &f.Cancel);
        Check(!f.Read(router) && guards == 0 && f.Primary.Calls == 0 && f.Factories == 0,
            "known-cancel-deadline-does-not-start-identity-guard");
        f.Emit(router);
    }
    {
        Fixture f; f.Cancel.store(true);
        ObservationReadRouter router(f.Route, f.Operation(L"cancel-before"), &f.Cancel);
        Check(!f.Read(router) && f.Primary.Calls == 0 && f.Factories == 0, "cancel-before-backend");
        f.Emit(router);
    }
    {
        Fixture f; auto caps = f.Primary.Caps;
        UnavailableObservationSource unavailable(caps); f.Route.Primary = &unavailable;
        ObservationReadRouter router(f.Route, f.Operation(L"unavailable"));
        Check(f.Read(router) && f.Secondary.Calls == 1 && f.Primary.Calls == 0, "missing-primary-is-recorded-before-qualified-fallback");
        f.Emit(router);
    }
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        Fixture f; f.Primary.Fail();
        if (mode == 0) { f.Route.AllowFallback = false; }
        if (mode == 1) { f.Route.Fallback = []() -> IObservationSource* { return nullptr; }; }
        if (mode == 2) { f.Route.Fallback = []() -> IObservationSource* { throw std::runtime_error("fixture"); }; }
        const auto id = L"factory-" + std::to_wstring(mode);
        ObservationReadRouter router(f.Route, f.Operation(id.c_str()));
        Check(!f.Read(router) && f.Bytes.empty() && router.Snapshot().Attempts.Reads.size() == 1, "fallback-policy-unavailable-exception-preserve-primary");
        f.Emit(router);
    }
    {
        Fixture f; f.Budget.MaximumReceipts = 2;
        ObservationReadRouter router(f.Route, f.Operation(L"parser-capacity"));
        Check(f.Read(router) && f.Read(router) && !f.Read(router) && f.Bytes.empty() && f.Primary.Calls == 2,
            "parser-capacity-stops-source-calls");
        Check(router.Snapshot().UnrecordedParserCalls == 1, "parser-call-loss-explicit");
        f.Emit(router);
    }
    {
        Fixture f;
        ObservationReadRouter router(f.Route, f.Operation(L"invalid-range"));
        Check(!router.ReadExact(1, 0, &f.Bytes) && !router.ReadExact(1, 4097, &f.Bytes) &&
            !router.ReadExact(UINT64_MAX - 10, 32, &f.Bytes) && f.Primary.Calls == 0, "invalid-parser-ranges-never-call-source");
        f.Emit(router);
    }
    {
        Fixture f; f.Primary.Action = [](const auto&) -> ObservationReadResult { throw std::runtime_error("fixture"); };
        ObservationReadRouter router(f.Route, f.Operation(L"abandoned"));
        bool caught = false;
        try { f.Read(router); } catch (const std::exception&) { caught = true; }
        const auto set = router.Snapshot();
        Check(caught && set.Attempts.Reads.size() == 1 && set.Attempts.Reads[0].Abandoned &&
            !set.ParserReads[0].Accepted && set.ParserReads[0].Reason == L"primary_incomplete", "exception-keeps-abandoned-attempt");
        f.Emit(router);
    }
    std::cerr << "Read routing checks=" << Checks << " failed=" << Failures << "\n";
    return Failures ? 1 : 0;
}
