#include "../user/ProcessObservationSource.h"
#include "../user/ObservationSourceJson.h"
#include <iostream>

namespace
{
    unsigned Checks = 0;
    unsigned Failures = 0;

    void Check(bool success, const char* name)
    {
        ++Checks;
        if (!success)
        {
            ++Failures;
            std::cerr << "FAIL " << name << "\n";
        }
    }

    struct FreePages
    {
        void operator()(uint8_t* address) const
        {
            VirtualFree(address, 0, MEM_RELEASE);
        }
    };

    void Emit(ProcessObservationSource& source, const ObservationReadRequest& request)
    {
        std::cout << mcpjson::WideToUtf8(ObservationReadJson(source.Capabilities(), request, source.Read(request))) << "\n";
    }
}

int main()
{
    FILETIME created{}, exited{}, kernel{}, user{};
    if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
    {
        return 1;
    }
    const uint64_t creation = (uint64_t{created.dwHighDateTime} << 32) | created.dwLowDateTime;
    const auto pid = GetCurrentProcessId();
    const AddressSpaceDescriptor space;
    std::unique_ptr<uint8_t, FreePages> pages(static_cast<uint8_t*>(VirtualAlloc(nullptr, 8192,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)));
    if (!pages)
    {
        return 1;
    }
    memset(pages.get(), 0x5a, 8192);
    HANDLE original = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    Check(original != nullptr, "owned-process-handle");
    ProcessObservationSource source(original, pid, creation, space);
    if (original != nullptr)
    {
        CloseHandle(original);
    }
    Check(!source.Capabilities().SourceId.empty(), "source-admitted-with-owned-duplicate");
    ObservationReadRequest request;
    request.SourceId = source.Capabilities().SourceId;
    request.Address = reinterpret_cast<uint64_t>(pages.get());
    request.Length = 64;
    request.ByteBudget = 64;
    const auto denied = source.Read(request);
    Check(denied.State == ObservationReadState::PolicyDenied && !denied.SideEffectsPossible,
        "residency-consent-required");
    Emit(source, request);
    request.AllowResidencyChanges = true;
    const auto read = source.Read(request);
    Check(read.State == ObservationReadState::Complete && read.IdentityRevalidated && read.NativeStatus == ERROR_SUCCESS &&
        read.Spans.size() == 1 && read.Spans[0].Bytes == std::vector<uint8_t>(64, 0x5a), "read-after-caller-closes-original");
    Emit(source, request);
    std::vector<uint8_t> bytes;
    Check(ReadObservationRange(source, request.Address, 8192, &bytes, 8192, true) && bytes == std::vector<uint8_t>(8192, 0x5a),
        "multi-chunk-owned-read");
    std::atomic<bool> cancelled{true};
    request.Cancellation = &cancelled;
    const auto cancellation = source.Read(request);
    Check(cancellation.State == ObservationReadState::Cancelled && !cancellation.SideEffectsPossible, "pre-cancelled-no-read");
    Emit(source, request);
    request.Cancellation = nullptr;
    request.ByteBudget = 63;
    Check(source.Read(request).State == ObservationReadState::BudgetDeferred, "byte-budget-admission");
    request.ByteBudget = 64;
    request.SourceId += L":other";
    Check(source.Read(request).State == ObservationReadState::IdentityChanged, "source-id-binding");
    request.SourceId = source.Capabilities().SourceId;
    const auto userAddress = request.Address;
    request.Address = 0xffff800000001000ull;
    const auto unsupported = source.Read(request);
    Check(unsupported.State == ObservationReadState::Unsupported && !unsupported.SideEffectsPossible, "kernel-va-rejected-before-provider");
    Check(!ReadObservationRange(source, request.Address, 32, &bytes, 32, true) && bytes.empty(), "range-helper-rejects-kernel-va");
    Emit(source, request);
    request.Address = userAddress;
    request.Length = 4097;
    request.ByteBudget = 4097;
    Check(source.Read(request).State == ObservationReadState::Unsupported, "single-read-limit");
    request.Length = 64;
    request.ByteBudget = 64;

    DWORD oldProtection = 0;
    Check(VirtualProtect(pages.get() + 4096, 4096, PAGE_NOACCESS, &oldProtection) != FALSE, "owned-hole-created");
    request.Address = userAddress + 4096;
    uint8_t scratch[64] = {};
    SIZE_T copied = 0;
    const BOOL directRead = ReadProcessMemory(GetCurrentProcess(), pages.get() + 4096, scratch, sizeof(scratch), &copied);
    const auto directError = GetLastError();
    const auto failed = source.Read(request);
    Check(!directRead && failed.State == ObservationReadState::Failed && failed.IdentityRevalidated &&
        failed.NativeStatusDomain == L"win32" && failed.NativeStatus == directError && failed.Spans[0].Bytes.empty(),
        "failed-read-keeps-native-status-without-bytes");
    Emit(source, request);
    Check(!ReadObservationRange(source, userAddress, 8192, &bytes, 8192, true) && bytes.empty(), "later-hole-discards-earlier-chunk");
    Check(!ReadObservationExact(source, userAddress + 2048, 4096, &bytes, true) && bytes.empty(), "cross-hole-discards-partial-copy");
    DWORD ignored = 0;
    Check(VirtualProtect(pages.get() + 4096, 4096, oldProtection, &ignored) != FALSE, "owned-protection-restored");
    Check(ReadObservationExact(source, userAddress + 4096, 64, &bytes, true) && bytes == std::vector<uint8_t>(64, 0x5a),
        "read-recovers-after-hole-removal");

    ProcessObservationSource wrongCreation(GetCurrentProcess(), pid, creation + 1, space);
    ProcessObservationSource wrongPid(GetCurrentProcess(), pid + 1, creation, space);
    ProcessObservationSource absent(nullptr, pid, creation, space);
    ProcessObservationSource unknownShape(GetCurrentProcess(), pid, creation, AddressSpaceDescriptor::FromPagingLevels(0));
    Check(wrongCreation.Capabilities().SourceId.empty() && wrongPid.Capabilities().SourceId.empty() &&
        absent.Capabilities().SourceId.empty() && unknownShape.Capabilities().SourceId.empty(), "unqualified-identities-cannot-admit");
    request.SourceId = wrongCreation.Capabilities().SourceId;
    Check(wrongCreation.Read(request).State == ObservationReadState::IdentityChanged, "wrong-generation-read-denied");
    Emit(wrongCreation, request);
    HANDLE queryOnly = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    Check(queryOnly != nullptr, "query-only-handle");
    ProcessObservationSource deniedAccess(queryOnly, pid, creation, space);
    if (queryOnly != nullptr)
    {
        CloseHandle(queryOnly);
    }
    request.SourceId = deniedAccess.Capabilities().SourceId;
    const auto access = deniedAccess.Read(request);
    Check(access.State == ObservationReadState::Failed && access.NativeStatus == ERROR_ACCESS_DENIED,
        "duplicate-does-not-upgrade-read-access");
    DWORD before = 0;
    DWORD after = 0;
    Check(GetProcessHandleCount(GetCurrentProcess(), &before) != FALSE, "handle-count-before");
    for (unsigned index = 0; index < 512; ++index)
    {
        ProcessObservationSource temporary(GetCurrentProcess(), pid, creation, space);
        ProcessObservationSource invalid(GetCurrentProcess(), pid, creation + 1, space);
    }
    Check(GetProcessHandleCount(GetCurrentProcess(), &after) && before == after, "success-and-rejected-sources-close-owned-handles");
    std::cerr << "process source controls: " << Checks << " checks, " << Failures << " failures\n";
    return Failures == 0 ? 0 : 1;
}
