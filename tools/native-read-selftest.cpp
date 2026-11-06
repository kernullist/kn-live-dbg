#include "../user/NativeObservationSource.h"
#include "../user/ReadReceiptJson.h"
#include <iostream>

namespace
{
    unsigned Checks = 0, Failures = 0;
    void Check(bool value, const char* reason)
    {
        ++Checks;
        if (!value) { ++Failures; std::cerr << "FAIL " << reason << "\n"; }
    }

    KNDBG_OBSERVATION_READ_REQUEST Request(uint32_t kind = KNDBG_READ_OBSERVATION_KERNEL)
    {
        KNDBG_OBSERVATION_READ_REQUEST r{};
        r.Size = sizeof(r);
        r.Version = KNDBG_READ_OBSERVATION_VERSION;
        r.Kind = kind;
        r.Flags = kind == KNDBG_READ_OBSERVATION_PHYSICAL ? 0 : KNDBG_READ_OBSERVATION_ALLOW_RESIDENCY;
        r.Address = kind == KNDBG_READ_OBSERVATION_KERNEL ? 0xffff800000011000ull : 0x11000;
        r.Length = 32;
        r.SourceEpoch = 42;
        if (kind == KNDBG_READ_OBSERVATION_PROCESS)
        {
            r.ProcessId = 100;
            r.ExpectedEprocess = 0xffff800000012000ull;
            r.ExpectedCreateTime = 123456;
        }
        return r;
    }

    struct Responder
    {
        unsigned Calls = 0;
        DWORD LastCode = 0;
        uint32_t Copied = 32;
        uint32_t Status = 0;
        DWORD Failure = 0;
        std::function<void(KNDBG_OBSERVATION_READ_RESPONSE&)> Change;
        int ReturnedDelta = 0;

        bool operator()(DWORD code, void* buffer, DWORD input, DWORD output, DWORD* returned, DWORD* error)
        {
            ++Calls;
            LastCode = code;
            *error = Failure;
            if (Failure != 0) { *returned = output; return false; }
            const auto header = static_cast<DWORD>(offsetof(KNDBG_OBSERVATION_READ_RESPONSE, Data));
            if (code == IOCTL_KNDBG_READ_OBSERVATION)
            {
                KNDBG_OBSERVATION_READ_REQUEST request{};
                Check(input == sizeof(request), "versioned-input-size");
                std::memcpy(&request, buffer, sizeof(request));
                KNDBG_OBSERVATION_READ_RESPONSE response{};
                response.Size = header;
                response.Version = KNDBG_READ_OBSERVATION_VERSION;
                response.StatusDomain = KNDBG_STATUS_DOMAIN_NTSTATUS;
                response.RawStatus = Status;
                response.Transferred = Copied;
                response.DriverAbi = KNDBG_ABI_VERSION;
                response.Request = request;
                response.ResultFlags = KNDBG_READ_OBSERVATION_COPY_ATTEMPTED;
                if (request.Kind == KNDBG_READ_OBSERVATION_PROCESS) { response.ResultFlags |= KNDBG_READ_OBSERVATION_IDENTITY_VALIDATED; }
                if (Change) { Change(response); }
                std::memcpy(buffer, &response, header);
                std::memset(static_cast<uint8_t*>(buffer) + header, 0x5a, output - header);
                *returned = static_cast<DWORD>(header + Copied + ReturnedDelta);
            }
            else if (code == IOCTL_KNDBG_READ_PROCESS_VIRTUAL)
            {
                KNDBG_PROCESS_VIRTUAL_READ_REQUEST response{};
                std::memcpy(&response, buffer, input);
                response.Size = output;
                response.Length = Copied;
                std::memcpy(buffer, &response, input);
                std::memset(static_cast<uint8_t*>(buffer) + input, 0x5a, output - input);
                *returned = input + Copied;
            }
            else
            {
                Check(code == IOCTL_KNDBG_READ_VIRTUAL || code == IOCTL_KNDBG_READ_PHYSICAL, "legacy-read-code-only");
                KNDBG_READ_REQUEST response{};
                std::memcpy(&response, buffer, input);
                Check(response.Flags == 0, "legacy-mdl-fallback-never-requested");
                response.Size = output;
                response.Length = Copied;
                std::memcpy(buffer, &response, input);
                std::memset(static_cast<uint8_t*>(buffer) + input, 0x5a, output - input);
                *returned = input + Copied;
            }
            return true;
        }
    };

    class Source final : public IObservationSource
    {
    public:
        explicit Source(NativeReadObservation native, const KNDBG_OBSERVATION_READ_REQUEST& request)
            : Native(std::move(native)), Input(request)
        {
            Caps.SourceId = L"synthetic_native:" + std::to_wstring(request.Kind);
            Caps.Consistency = L"single_read";
        }
        const ObservationSourceCapabilities& Capabilities() const override { return Caps; }
    protected:
        ObservationReadResult ReadSpans(const ObservationReadRequest& r) override
        {
            return NativeObservationReadResult(r.Address, r.Length, Native);
        }
    private:
        NativeReadObservation Native;
        KNDBG_OBSERVATION_READ_REQUEST Input;
        ObservationSourceCapabilities Caps;
    };

    void Emit(const wchar_t* name, const NativeReadObservation& native, const KNDBG_OBSERVATION_READ_REQUEST& request, bool parserSuccess)
    {
        Source source(native, request);
        auto operation = std::make_shared<ObservationReadOperation>(name, L"synthetic:target", L"synthetic:as");
        RecordingObservationSource recorder(source, operation);
        std::vector<uint8_t> bytes{1};
        Check(ReadObservationExact(recorder, request.Address, request.Length, &bytes) == parserSuccess,
            "native-result-parser-admission");
        Check(parserSuccess ? bytes == std::vector<uint8_t>(request.Length, 0x5a) : bytes.empty(), "parser-byte-view");
        std::cout << mcpjson::WideToUtf8(ObservationReadSetJson(operation->Snapshot())) << "\n";
    }
}

int main()
{
    static_assert(KNDBG_ABI_VERSION == 17 && offsetof(KNDBG_READ_REQUEST, Data) == 24 &&
        offsetof(KNDBG_PROCESS_VIRTUAL_READ_REQUEST, Data) == 48, "legacy ABI preserved");
    auto request = Request();
    const std::vector<std::function<void(KNDBG_OBSERVATION_READ_REQUEST&)>> badRequests = {
        [](auto& r) { ++r.Size; }, [](auto& r) { ++r.Version; }, [](auto& r) { r.Length = 0; },
        [](auto& r) { r.Length = 4097; }, [](auto& r) { r.Address = UINT64_MAX - 16; },
        [](auto& r) { r.SourceEpoch = 0; }, [](auto& r) { r.Reserved = 1; }, [](auto& r) { r.Reserved2 = 1; },
        [](auto& r) { r.Kind = 0; }, [](auto& r) { r.Kind = 4; }, [](auto& r) { r.Flags = 2; },
        [](auto& r) { r.ProcessId = 1; }, [](auto& r) { r.ExpectedEprocess = 1; }, [](auto& r) { r.ExpectedCreateTime = 1; }};
    for (const auto& change : badRequests)
    {
        auto bad = request;
        change(bad);
        Responder transport;
        Check(!KnDbgObservationReadShapeValid(bad) && !ReadNativeObservation(bad, true, std::ref(transport)).Rejection.empty() &&
            transport.Calls == 0, "invalid-request-rejected-before-transport");
    }
    for (uint32_t kind : {KNDBG_READ_OBSERVATION_KERNEL, KNDBG_READ_OBSERVATION_PROCESS, KNDBG_READ_OBSERVATION_PHYSICAL})
    {
        request = Request(kind);
        Responder transport;
        const auto complete = ReadNativeObservation(request, true, std::ref(transport));
        Check(complete.Rejection.empty() && complete.ResponseValidated && complete.RawStatus == 0 && complete.StatusDomain == L"ntstatus" &&
            complete.Transferred == 32 && complete.SourceEpoch == 42 && complete.DriverAbi == 17 &&
            complete.IdentityValidated == (kind == KNDBG_READ_OBSERVATION_PROCESS), "versioned-complete-bound-response");
        Check(NativeObservationReadResult(request.Address, request.Length, complete).State == ObservationReadState::Complete,
            "native-conversion-has-accurate-state-before-wrapper-validation");
        Emit(kind == 1 ? L"kernel" : kind == 2 ? L"process" : L"physical", complete, request, true);
    }
    request = Request(KNDBG_READ_OBSERVATION_PROCESS);
    Responder partial;
    partial.Status = 0x8000000d;
    partial.Copied = 7;
    auto result = ReadNativeObservation(request, true, std::ref(partial));
    Check(result.Rejection.empty() && result.Transferred == 7 && result.Bytes == std::vector<uint8_t>(7, 0x5a) &&
        result.RawStatus == 0x8000000d, "partial-native-status-and-count-survive-transport-success");
    Emit(L"partial", result, request, false);
    partial.Copied = 0;
    partial.Status = 0xc0000005;
    result = ReadNativeObservation(request, true, std::ref(partial));
    Check(result.TransferredKnown && result.Transferred == 0 && result.RawStatus == 0xc0000005, "zero-byte-native-failure-still-has-status");
    Emit(L"failed", result, request, false);

    const std::vector<std::function<void(KNDBG_OBSERVATION_READ_RESPONSE&)>> badResponses = {
        [](auto& r) { ++r.Size; }, [](auto& r) { ++r.Version; }, [](auto& r) { ++r.DriverAbi; },
        [](auto& r) { r.StatusDomain = 0; }, [](auto& r) { r.ResultFlags = 0x80000000; }, [](auto& r) { r.Reserved = 1; },
        [](auto& r) { ++r.Request.Size; }, [](auto& r) { ++r.Request.Version; }, [](auto& r) { ++r.Request.Kind; },
        [](auto& r) { ++r.Request.Address; }, [](auto& r) { ++r.Request.Length; }, [](auto& r) { ++r.Request.SourceEpoch; },
        [](auto& r) { ++r.Request.ProcessId; }, [](auto& r) { ++r.Request.ExpectedEprocess; },
        [](auto& r) { ++r.Request.ExpectedCreateTime; }, [](auto& r) { r.Request.Reserved = 1; },
        [](auto& r) { r.Request.Reserved2 = 1; }, [](auto& r) { r.Request.Flags = 0; },
        [](auto& r) { r.Transferred = 33; }, [](auto& r) { r.ResultFlags = KNDBG_READ_OBSERVATION_COPY_ATTEMPTED; },
        [](auto& r) { r.ResultFlags = KNDBG_READ_OBSERVATION_IDENTITY_VALIDATED; }};
    for (const auto& change : badResponses)
    {
        Responder transport;
        transport.Change = change;
        result = ReadNativeObservation(request, true, std::ref(transport));
        Check(result.Rejection == L"invalid_native_read_response" && result.Bytes.empty() && !result.TransferredKnown &&
            result.StatusDomain == L"unavailable" && transport.Calls == 1, "malformed-or-mismatched-response-rejected-without-retry");
    }
    for (int delta : {-100, -1, 1})
    {
        Responder transport;
        transport.ReturnedDelta = delta;
        Check(ReadNativeObservation(request, true, std::ref(transport)).Rejection == L"invalid_native_read_response", "short-or-extra-transport-data");
    }
    for (bool mismatch : {false, true})
    {
        Responder denied;
        denied.Copied = 0;
        denied.Status = mismatch ? 0xc0000225 : 0xc0000022;
        denied.Change = [mismatch](auto& r)
        {
            r.ResultFlags = mismatch ? KNDBG_READ_OBSERVATION_IDENTITY_MISMATCH : KNDBG_READ_OBSERVATION_POLICY_DENIED;
        };
        const auto deniedRead = ReadNativeObservation(request, true, std::ref(denied));
        const auto converted = NativeObservationReadResult(request.Address, request.Length, deniedRead);
        Check(converted.State == (mismatch ? ObservationReadState::IdentityChanged : ObservationReadState::PolicyDenied) &&
            converted.NativeStatus == denied.Status && converted.BackendCopyAttemptKnown && !converted.BackendCopyAttempted,
            "native-admission-kind-survives-without-generic-read-failure");
        Emit(mismatch ? L"identity-mismatch" : L"policy-denied", deniedRead, request, false);
        Source blocked(deniedRead, request);
        auto operation = std::make_shared<ObservationReadOperation>(L"deny-fallback", L"synthetic:target", L"synthetic:as");
        RecordingObservationSource recorded(blocked, operation);
        ObservationReadRequest readRequest;
        readRequest.SourceId = blocked.Capabilities().SourceId;
        readRequest.Address = request.Address;
        readRequest.Length = request.Length;
        readRequest.ByteBudget = request.Length;
        const auto prior = recorded.Read(readRequest);
        Responder good;
        auto otherRequest = Request(KNDBG_READ_OBSERVATION_KERNEL);
        otherRequest.Address = request.Address;
        Source other(ReadNativeObservation(otherRequest, true, std::ref(good)), otherRequest);
        RecordingObservationSource alternate(other, operation);
        readRequest.SourceId = other.Capabilities().SourceId;
        readRequest.FallbackFromReceipt = prior.ReadReceiptId;
        readRequest.FallbackReason = L"synthetic_explicit_fallback";
        readRequest.AllowFallback = true;
        Check(alternate.Read(readRequest).State == ObservationReadState::PolicyDenied &&
            !operation->Snapshot().Reads[1].SourceInvoked, "native-identity-or-policy-denial-cannot-authorize-fallback");
        denied.Copied = 1;
        Check(ReadNativeObservation(request, true, std::ref(denied)).Rejection == L"invalid_native_read_response",
            "denial-cannot-carry-claimed-bytes");
        denied.Copied = 0;
        denied.Status = 0;
        Check(ReadNativeObservation(request, true, std::ref(denied)).Rejection == L"invalid_native_read_response",
            "denial-cannot-carry-success-status");
    }
    Responder inconsistent;
    inconsistent.Copied = 4;
    result = ReadNativeObservation(request, true, std::ref(inconsistent));
    Check(result.RawStatus == 0 && result.TransferredKnown && result.Transferred == 4 &&
        result.Rejection == L"native_status_length_mismatch", "short-success-retains-raw-status-but-is-not-parser-input");
    Emit(L"short-success", result, request, false);
    inconsistent.Copied = 32;
    inconsistent.Status = 0xc0000005;
    result = ReadNativeObservation(request, true, std::ref(inconsistent));
    Emit(L"full-error", result, request, false);

    Responder failed;
    failed.Failure = ERROR_INVALID_FUNCTION;
    result = ReadNativeObservation(request, true, std::ref(failed));
    Check(failed.Calls == 1 && failed.LastCode == IOCTL_KNDBG_READ_OBSERVATION && !result.Legacy &&
        result.StatusDomain == L"win32" && result.RawStatus == ERROR_INVALID_FUNCTION && !result.TransferredKnown,
        "advertised-extension-error-is-not-silently-downgraded");
    Emit(L"transport-failed", result, request, false);

    for (uint32_t kind : {KNDBG_READ_OBSERVATION_KERNEL, KNDBG_READ_OBSERVATION_PROCESS, KNDBG_READ_OBSERVATION_PHYSICAL})
    {
        request = Request(kind);
        Responder legacy;
        legacy.Copied = kind == KNDBG_READ_OBSERVATION_PROCESS ? 32 : 5;
        result = ReadNativeObservation(request, false, std::ref(legacy));
        Check(result.ResponseValidated && result.Legacy && result.StatusDomain == L"unavailable" && result.Rejection.empty(),
            "legacy-success-does-not-invent-native-status");
        Emit(kind == 1 ? L"legacy-kernel" : kind == 2 ? L"legacy-process" : L"legacy-physical", result, request, kind == 2);
    }
    request = Request(KNDBG_READ_OBSERVATION_PROCESS);
    failed = {};
    failed.Failure = ERROR_PARTIAL_COPY;
    result = ReadNativeObservation(request, false, std::ref(failed));
    Check(result.Bytes.empty() && !result.TransferredKnown && result.RawStatus == ERROR_PARTIAL_COPY,
        "legacy-failure-count-remains-unknown");
    Emit(L"legacy-failed", result, request, false);
    request.Flags = 0;
    Responder noConsent;
    Check(ReadNativeObservation(request, true, std::ref(noConsent)).Rejection == L"residency_consent_required" && noConsent.Calls == 0,
        "residency-consent-required-before-call");
    request = Request(KNDBG_READ_OBSERVATION_PHYSICAL);
    request.Flags = 1;
    Check(!KnDbgObservationReadShapeValid(request), "physical-has-no-virtual-or-mdl-flags");

    DeviceClient device;
    Check(!device.HasReadObservationContract() && device.ReadObservation(Request()).Rejection == L"native_source_not_qualified",
        "closed-device-has-no-qualified-contract");
    const auto closed = NativeObservationReadResult(Request().Address, 32, device.ReadObservation(Request()));
    Check(closed.BackendContract == L"unavailable" && !closed.BackendCopyAttemptKnown && !closed.TransportAttempted,
        "unqualified-source-does-not-claim-negotiated-contract-or-no-backend-work");
    std::wstring error;
    Check(device.Open(L"NUL", &error), "owned-harmless-device-handle");
    Check(!device.QueryVersion(&error) && !device.HasReadObservationContract() && !device.AddressSpace().Valid(),
        "failed-version-query-clears-contract");
    auto unqualified = Request();
    unqualified.SourceEpoch = device.ObservationEpoch();
    Check(device.ReadObservation(unqualified).Rejection == L"native_source_not_qualified", "open-alone-does-not-authorize-legacy-fallback");
    device.Close();
    Check(device.ObservationEpoch() == 0 && !device.HasReadObservationContract(), "close-revokes-source-epoch-and-contract");
    std::cerr << "native read controls: " << Checks << " checks, " << Failures << " failures\n";
    return Failures == 0 ? 0 : 1;
}
