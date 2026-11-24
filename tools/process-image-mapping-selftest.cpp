#include "../user/ProcessObservationSource.h"
#include "../user/ImageProcessMappings.h"
#include "../user/ImageVerificationRecipe.h"
#include "../user/ImageProof.h"
#include "../user/McpJson.h"
#include <filesystem>
#include <functional>
#include <iostream>

namespace
{
    void Require(bool value, const char* text)
    { if (!value) { throw std::runtime_error(text); } }

    uint64_t Creation(HANDLE process)
    {
        FILETIME c{}, e{}, k{}, u{};
        Require(GetProcessTimes(process, &c, &e, &k, &u) != FALSE, "process creation time");
        return (uint64_t(c.dwHighDateTime) << 32) | c.dwLowDateTime;
    }

    struct Handle
    {
        HANDLE Value = nullptr;
        ~Handle() { if (Value) { CloseHandle(Value); } }
    };

    struct Child
    {
        PROCESS_INFORMATION Process{};
        ~Child()
        {
            if (Process.hProcess)
            {
                if (WaitForSingleObject(Process.hProcess, 0) != WAIT_OBJECT_0)
                    { TerminateProcess(Process.hProcess, 91); WaitForSingleObject(Process.hProcess, 10000); }
                CloseHandle(Process.hProcess); CloseHandle(Process.hThread);
            }
        }
        void Start()
        {
            std::wstring path(32768, L'\0');
            const auto length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
            Require(length && length < path.size(), "owned child executable path");
            path.resize(length);
            auto command = L"\"" + path + L"\" --mapping-exit";
            STARTUPINFOW startup{}; startup.cb = sizeof(startup);
            Require(CreateProcessW(path.c_str(), command.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW | CREATE_SUSPENDED,
                nullptr, nullptr, &startup, &Process) != FALSE, "owned suspended child created");
        }
        void Finish()
        {
            Require(ResumeThread(Process.hThread) != static_cast<DWORD>(-1) &&
                WaitForSingleObject(Process.hProcess, 10000) == WAIT_OBJECT_0, "owned child exited after explicit release");
            DWORD code = 1;
            Require(GetExitCodeProcess(Process.hProcess, &code) && code == 0, "owned child completed cleanly");
        }
    };

    struct Memory
    {
        uint8_t* Bytes = nullptr;
        bool Mapped = false;
        static constexpr size_t Size = 0x5000;
        Memory()
        {
            Bytes = static_cast<uint8_t*>(VirtualAlloc(nullptr, Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
            Require(Bytes != nullptr, "allocate owned nonexecuting buffer");
        }
        ~Memory()
        {
            if (Bytes)
                { if (Mapped) { UnmapViewOfFile(Bytes); } else { VirtualFree(Bytes, 0, MEM_RELEASE); } }
        }
        uint64_t Base() const { return reinterpret_cast<uint64_t>(Bytes); }
        void Release()
        {
            if (Bytes)
            {
                Require((Mapped ? UnmapViewOfFile(Bytes) : VirtualFree(Bytes, 0, MEM_RELEASE)) != FALSE, "release owned mapping");
                Bytes = nullptr;
            }
        }
        void Protect(size_t offset, DWORD protection)
        {
            DWORD old = 0;
            Require(VirtualProtect(Bytes + offset, 4096, protection, &old) != FALSE, "owned protection transition completed");
        }
        void Replace(bool mapped)
        {
            std::vector<uint8_t> original(Bytes, Bytes + Size);
            auto* address = Bytes;
            Handle section;
            if (mapped)
            {
                section.Value = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
                    static_cast<DWORD>(Size), nullptr);
                Require(section.Value != nullptr, "owned pagefile section");
            }
            Release();
            Bytes = mapped ? static_cast<uint8_t*>(MapViewOfFileEx(section.Value, FILE_MAP_READ | FILE_MAP_WRITE,
                0, 0, Size, address)) : static_cast<uint8_t*>(VirtualAlloc(address, Size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE));
            Mapped = mapped;
            Require(Bytes != nullptr && Bytes == address, "observed same-address remapping");
            std::memcpy(Bytes, original.data(), Size);
        }
    };

    class Observer final : public IProcessMappingObserver
    {
    public:
        explicit Observer(ProcessObservationSource& source) : Source(source) {}
        std::function<void(size_t)> Before, After;
        size_t Calls = 0;
        ProcessMappingObservation ObserveMapping(uint64_t address, uint32_t length,
            const std::atomic<bool>* cancellation) override
        {
            const auto call = ++Calls;
            if (Before) { Before(call); }
            auto result = Source.ObserveMapping(address, length, cancellation);
            if (After) { After(call); }
            return result;
        }
    private:
        ProcessObservationSource& Source;
    };

    class CancelOnReadReturn final : public IObservationSource
    {
    public:
        CancelOnReadReturn(ProcessObservationSource& source, std::atomic<bool>& stop) : Source(source), Stop(stop) {}
        const ObservationSourceCapabilities& Capabilities() const override { return Source.Capabilities(); }
    protected:
        ObservationReadResult ReadSpans(const ObservationReadRequest& request) override
        {
            auto result = Source.Read(request);
            Stop.store(true);
            return result;
        }
    private:
        ProcessObservationSource& Source;
        std::atomic<bool>& Stop;
    };
}

bool TestProcessImageMappings(const std::filesystem::path& root, const std::filesystem::path& image,
    const std::vector<uint8_t>& initial)
{
    unsigned passed = 0;
    const auto check = [&](bool value, const char* message) { Require(value, message); ++passed; };
    try
    {
        const auto reference = root / L"mapping-reference.exe";
        std::filesystem::copy_file(image, reference);
        SYSTEM_INFO info{};
        GetNativeSystemInfo(&info);
        AddressSpaceDescriptor space;
        space.UserMaximum = reinterpret_cast<uint64_t>(info.lpMaximumApplicationAddress);
        ProcessObservationSource source(GetCurrentProcess(), GetCurrentProcessId(), Creation(GetCurrentProcess()), space);
        check(!source.Capabilities().SourceId.empty(), "owned handle source");
        size_t finalCall = 0, lastCall = 0;
        std::vector<std::filesystem::path> retained;
        for (const std::wstring mode : {L"stable", L"modified", L"modified-conflict", L"protect", L"final", L"free", L"remap", L"aba", L"neighbor", L"exited", L"cancel", L"cancel-on-return", L"cancel-after-read", L"cancel-final", L"cancel-late", L"cross"})
        {
            Memory memory;
            Require(initial.size() == 0x4000, "known bounded fixture");
            std::memcpy(memory.Bytes, initial.data(), initial.size());
            const auto base = memory.Base();
            const uint64_t relocated = base + 0x1111;
            std::memcpy(memory.Bytes + 0x1ffc, &relocated, sizeof(relocated));
            if (mode == L"modified" || mode == L"modified-conflict") { memory.Bytes[0x2150] ^= 1; }
            if (mode == L"cross") { memory.Protect(0x2000, PAGE_READONLY); }
            Handle limited;
            Child child;
            if (mode == L"exited")
            {
                child.Start();
                limited.Value = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, child.Process.dwProcessId);
                Require(limited.Value != nullptr, "limited handle");
            }
            ProcessObservationSource limitedSource(limited.Value, child.Process.dwProcessId,
                child.Process.hProcess ? Creation(child.Process.hProcess) : 0, space);
            if (mode == L"exited") { child.Finish(); }
            auto& selected = mode == L"exited" ? limitedSource : source;
            Observer observer(selected);
            bool changed = false;
            std::atomic<bool> cancellation{mode == L"cancel"};
            CancelOnReadReturn returning(selected, cancellation);
            IObservationSource& reader = mode == L"cancel-on-return" ? static_cast<IObservationSource&>(returning) : selected;
            // Mutation runs synchronously at an observed query boundary. No sleep
            // or assumed actor scheduling establishes these orderings.
            observer.After = [&](size_t call)
            {
                if (mode == L"cancel-late" && call == lastCall) { cancellation.store(true); }
                if (call != 1) { return; }
                if (mode == L"protect" || mode == L"modified-conflict") { memory.Protect(0, PAGE_READONLY); changed = true; }
                if (mode == L"neighbor") { memory.Protect(0x4000, PAGE_READONLY); changed = true; }
                if (mode == L"remap" || mode == L"aba") { memory.Replace(mode == L"remap"); changed = true; }
            };
            observer.Before = [&](size_t call)
            {
                if (mode == L"cancel-after-read" && call == 2) { cancellation.store(true); }
                if (call != finalCall) { return; }
                if (mode == L"cancel-final") { cancellation.store(true); }
                if (mode == L"final") { memory.Protect(0x2000, PAGE_READONLY); changed = true; }
                if (mode == L"free") { memory.Release(); changed = true; }
            };
            ImageRecipeCaptureOptions options;
            options.TargetId = L"owned-process-mapping-fixture";
            options.AddressSpaceId = L"owned-process-mapping-fixture:user";
            options.AllowResidencyChanges = true;
            options.MappingObserver = &observer;
            ImageVerificationRecipe recipe;
            std::wstring error;
            const auto directory = root / (L"mapping-" + mode);
            if (!CaptureObservedImageRecipe(reference.wstring(), reader, base, mode == L"cross" ? 0x1ffc : 0x2000,
                mode == L"cross" ? 8 : 4096, directory.wstring(),
                options, &recipe, &error, &cancellation))
                { std::wcerr << L"mapping capture " << mode << L": " << error << L"\n"; return false; }
            retained.push_back(directory);
            check(recipe.FormatVersion == 3 && !ImageRecipeJson(recipe).empty(), "v3 bounded original mapping capture");
            const auto assessment = AssessImageProcessMappings(recipe);
            const bool conflict = mode == L"protect" || mode == L"modified-conflict" || mode == L"final" || mode == L"free" || mode == L"remap";
            const bool interrupted = mode == L"cancel" || mode == L"cancel-on-return" || mode == L"cancel-after-read" || mode == L"cancel-final";
            const bool unavailable = mode == L"exited" || interrupted;
            check(assessment.Status == (conflict ? L"inconsistent_capture" : unavailable ? L"unavailable" : L"consistent_observations"),
                "observed mapping transition selects expected status");
            check(!assessment.NativeImageMappingObserved, "private or mapped buffers are never native image observations");
            if (mode == L"stable") { finalCall = 2 * recipe.Reads.size() + 1; lastCall = observer.Calls; }
            check(recipe.ReadSet.Cancelled == interrupted, "only a recorded interruption marks the acquisition");
            if (mode == L"cancel-late") { check(cancellation.load(), "stop requested after the last completed observation"); }
            if (conflict || mode == L"aba" || mode == L"neighbor") { check(changed, "mutation actually completed"); }
            if (mode == L"exited")
            {
                check(assessment.FailedObservations == assessment.Observations && assessment.Queries == assessment.Observations,
                    "exited process retains every failed native query");
                for (const auto& pair : recipe.Mappings.Reads)
                    { check(pair.Before.Queries.front().NativeStatusKnown && pair.Before.Queries.front().NativeStatus != 0, "original Win32 query failure"); }
                ProcessObservationSource exited(child.Process.hProcess, child.Process.dwProcessId, Creation(child.Process.hProcess), space);
                const auto afterExit = exited.ObserveMapping(base, 1);
                check(afterExit.IdentityRevalidated && afterExit.Status == L"query_failed" && afterExit.Queries.front().NativeStatusKnown,
                    "owned handle pins process identity after exit but cannot preserve address-space queries");
            }
            if (mode == L"cancel") { check(assessment.Queries == 0, "cancelled query performs no native call"); }
            DirectImageReplayEvidence evidence;
            const auto replay = ReplayImageRecipe(directory.wstring(), false, &error, &evidence);
            check(replay.Status == L"replayed" && replay.CurrentResult == recipe.RecordedResult, "offline result exactly reproduces mapping gate");
            check(evidence.ReferenceQualified == !(conflict || unavailable), "typed evidence cannot retain qualification after failed mapping fence");
            if (conflict || unavailable)
            {
                check(evidence.Comparison.Coverage.ComparedBytes == 0 && evidence.Comparison.Coverage.FailedBytes == recipe.Length &&
                    evidence.Comparison.Changes.empty(), "all requested bytes are failed, never authorized or matching");
            }
            else
            {
                check(evidence.Comparison.Coverage.ComparedBytes == recipe.Length, "stable mapped observations retain byte comparison");
            }
            if (mode == L"stable")
            {
                auto corrupt = recipe;
                corrupt.Mappings.Reads.front().After.Queries.front().Protect = PAGE_READONLY;
                const auto proof = AssessImageProof(corrupt, evidence.Comparison, true, false);
                check(!proof.ReferenceQualified && proof.Matches.Status != L"supported",
                    "independent proof gate cannot accept a supplied qualified result across mapping conflict");
            }
        }
        Memory memory;
        Handle noQuery;
        noQuery.Value = OpenProcess(PROCESS_VM_READ, FALSE, GetCurrentProcessId());
        Require(noQuery.Value != nullptr, "read-only process handle");
        MEMORY_BASIC_INFORMATION denied{};
        check(VirtualQueryEx(noQuery.Value, memory.Bytes, &denied, sizeof(denied)) == 0 && GetLastError() == ERROR_ACCESS_DENIED,
            "handle without either query right receives native access denial");
        ProcessObservationSource noIdentity(noQuery.Value, GetCurrentProcessId(), Creation(GetCurrentProcess()), space);
        check(noIdentity.Capabilities().SourceId.empty() && noIdentity.ObserveMapping(memory.Base(), 1).Queries.empty(),
            "handle without identity query rights never becomes a qualified observation source");
        memory.Protect(0x1000, PAGE_READONLY);
        auto observed = source.ObserveMapping(memory.Base() + 4095, 2);
        check(observed.Status == L"complete" && observed.Queries.size() == 2 &&
            observed.Queries[0].Protect == PAGE_READWRITE && observed.Queries[1].Protect == PAGE_READONLY,
            "unaligned cross-page request preserves two distinct native regions");
        const auto base = memory.Base();
        Require(VirtualFree(memory.Bytes + 0x2000, 4096, MEM_DECOMMIT) != FALSE, "decommit owned page");
        observed = source.ObserveMapping(base + 0x2000, 1);
        check(observed.Status == L"complete" && observed.Queries.front().State == MEM_RESERVE && observed.Queries.front().Protect == 0,
            "reserved region has no invented current protection");
        memory.Release();
        observed = source.ObserveMapping(base, 1);
        check(observed.Status == L"complete" && observed.Queries.front().State == MEM_FREE &&
            observed.Queries.front().AllocationBase == 0 && observed.Queries.front().Type == 0,
            "free region retains only defined native fields");
        check(source.ObserveMapping(UINT64_MAX, 1).Status == L"unsupported" &&
            source.ObserveMapping(base, 4097).Queries.empty(), "invalid range cannot issue native mapping query");
        std::filesystem::remove(reference);
        for (const auto& directory : retained)
        {
            const auto replay = ReplayImageRecipe(directory.wstring(), false, nullptr);
            const auto current = ReplayImageRecipe(directory.wstring(), true, nullptr);
            check(replay.Status == L"replayed" && current.Status == L"reanalyzed" && replay.CurrentResult == current.CurrentResult,
                "source mapping and original reference removal leave historical and current replay intact");
        }
        std::cout << "[image.mapping] passed=" << passed << " failed=0 native_query=true controlled_mapping_transitions=true\n";
        return true;
    }
    catch (const std::exception& error)
    {
        std::cerr << "[image.mapping] passed=" << passed << " failed=1 error=" << error.what() << "\n";
        return false;
    }
}
