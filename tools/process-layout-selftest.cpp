#include "../user/ProcessLayoutCore.h"
#include "../user/ProcessLayoutMonitor.h"
#include "../user/AnalystSnapshot.h"
#include "../user/ExecutableImageVerifier.h"
#include "../user/McpJson.h"

#include <iostream>
#include <random>
#include <thread>
#include <filesystem>

namespace
{
    bool WindowsFixture();
    void ImageIdentityFixture();
}

namespace
{
    unsigned Checks = 0;
    unsigned Failures = 0;
    std::wstring EvidenceDirectory;

    void Check(bool condition, const char* name)
    {
        ++Checks;
        if (!condition)
        {
            ++Failures;
            std::cerr << "FAIL " << name << '\n';
        }
    }

    process_layout::Snapshot Make()
    {
        process_layout::Snapshot snapshot;
        snapshot.Identity.BootId = L"test-boot";
        snapshot.Identity.ProcessId = 100;
        snapshot.Identity.CreateTime = 1234;
        snapshot.StartedMs = 1;
        snapshot.FinishedMs = 2;
        snapshot.Limit = 0x100000;
        snapshot.Cursor = snapshot.Limit;
        snapshot.Complete = true;
        return snapshot;
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc > 1 && std::wstring(argv[1]) == L"--layout-child")
    {
        Sleep(8000);
        return 0;
    }
    using namespace process_layout;
    if (argc > 1)
    {
        EvidenceDirectory = argv[1];
    }
    auto first = Make();
    first.Regions.push_back({0x10000, 0x3000, 0x10000, Commit, 4, 4, Private});
    auto next = first;
    next.StartedMs = 3;
    next.FinishedMs = 4;
    Check(Compare(first, next).ChangedRanges == 0, "unchanged");
    next.Regions = {{0x10000, 0x1000, 0x10000, Commit, 4, 4, Private},
        {0x11000, 0x2000, 0x10000, Commit, 4, 4, Private}};
    Check(Compare(first, next).ChangedRanges == 0, "equivalent split");
    next.Regions[1].Protect = 0x20;
    auto diff = Compare(first, next);
    Check(diff.ChangedRanges == 1 && diff.CandidateRanges == 1 && diff.Changes[0].Base == 0x11000 &&
        diff.Changes[0].Size == 0x2000 && (diff.Changes[0].Flags & BecameExecutable) != 0, "RW to RX");
    auto masked = next;
    masked.StartedMs = 5;
    masked.FinishedMs = 6;
    masked.Regions[1].Protect = 4;
    const auto maskedDelta = Compare(next, masked);
    Check(maskedDelta.CandidateRanges == 1 && (maskedDelta.Changes[0].Flags & LostExecutable) != 0,
        "RX to RW masking lead");
    masked.Regions.erase(masked.Regions.begin() + 1);
    Check(Compare(next, masked).CandidateRanges == 0, "plain executable release is not masking");
    first.Regions[0].Type = Image;
    Check((Compare(first, next).Changes[0].Flags & ImageReplaced) != 0, "image to private");
    next = first;
    next.StartedMs = 3;
    next.FinishedMs = 4;
    first.ImageNames[0x10000] = L"first";
    next.ImageNames[0x10000] = L"second";
    Check(Compare(first, next).CandidateRanges == 1, "changed image name");
    next.ImageNames.clear();
    Check(Compare(first, next).ChangedRanges == 0, "unknown image name");
    next.Regions.clear();
    Check((Compare(first, next).Changes[0].Flags & Removed) != 0, "complete removal");
    next.Complete = false;
    Check(!Compare(first, next).Comparable, "partial removal rejected");
    History history;
    Check(history.Accept(std::make_shared<Snapshot>(first)), "initial accepted");
    Check(!history.Accept(std::make_shared<Snapshot>(next)) && history.Completed == 1 &&
        history.Current == history.Initial, "failed snapshot preserves baseline");
    next = first;
    next.StartedMs = 3;
    next.FinishedMs = 4;
    next.Identity.CreateTime++;
    Check(!history.Accept(std::make_shared<Snapshot>(next)), "PID reuse rejected");
    next.Identity = first.Identity;
    next.Identity.BootId = L"other";
    Check(!Compare(first, next).Comparable, "boot identity mismatch");
    next = first;
    next.Regions.push_back(first.Regions[0]);
    Check(!next.Valid(), "overlapping ranges rejected");
    next = first;
    next.Regions[0].Size = UINT64_MAX;
    Check(!next.Valid(), "overflow rejected");
    next = first;
    next.Limit++;
    next.Cursor++;
    Check(!Compare(first, next).Comparable, "different domain rejected");

    Snapshot sweep = Make();
    sweep.Complete = false;
    sweep.Cursor = 0;
    Check(Append(sweep, {0, 0x10000, 0, Free, 123, 456, 789}), "implicit free");
    Check(sweep.Regions.empty(), "free fields ignored");
    Check(!Append(sweep, {0, 0x20000, 0, Free}), "concurrent merge rejected");
    Check(!Append(sweep, {0x10000, 0, 0x10000, Commit}), "zero size rejected");
    Check(!Append(sweep, {0x10000, 0x1000, 0x10000, Commit}, 0), "region cap");
    Check(sweep.Cursor == 0x10000, "failed append preserves cursor");
    Check(Append(sweep, {0x10000, 0x1000, 0x10000, Reserve, 123, 4, Private}) &&
        sweep.Regions[0].Protect == 0, "undefined reserved protection normalized");
    Check(Append(sweep, {0x11000, 0x200000, 0, Free}) && sweep.Cursor == sweep.Limit, "domain clipping");

    // Differential oracle: independently compare attributes at every page.
    std::mt19937 random(23092026);
    for (unsigned iteration = 0; iteration < 3000; ++iteration)
    {
        auto a = Make();
        auto b = Make();
        b.StartedMs = 3;
        b.FinishedMs = 4;
        std::vector<Region> left(32);
        std::vector<Region> right(32);
        for (size_t page = 0; page < 32; ++page)
        {
            const auto generate = [&](std::vector<Region>& flat, Snapshot& snapshot)
            {
                const auto value = random() % 5;
                Region row{page * 4096, 4096, 0, Commit, value == 1 ? 0x20u : 4u, 4, Private};
                row.State = value == 0 ? Free : (value == 2 ? Reserve : Commit);
                if (row.State == Reserve)
                {
                    row.Protect = 0;
                }
                if (row.State == Free)
                {
                    row = {};
                }
                flat[page] = row;
                if (row.State != Free)
                {
                    if (!snapshot.Regions.empty() && snapshot.Regions.back().SameAttributes(row) &&
                        snapshot.Regions.back().Base + snapshot.Regions.back().Size == row.Base)
                    {
                        snapshot.Regions.back().Size += 4096;
                    }
                    else
                    {
                        snapshot.Regions.push_back(row);
                    }
                }
            };
            generate(left, a);
            generate(right, b);
        }
        const auto changes = Compare(a, b);
        Check(changes.Comparable, "fuzz comparable");
        for (size_t page = 0; page < left.size(); ++page)
        {
            const uint64_t address = page * 4096;
            const bool found = std::any_of(changes.Changes.begin(), changes.Changes.end(), [&](const Change& item)
            {
                return address >= item.Base && address - item.Base < item.Size;
            });
            Check(found == !left[page].SameAttributes(right[page]), "page oracle");
        }
        Check(Compare(a, b, 1).Changes.size() <= 1, "bounded delta");
        Check(Compare(a, b, 0).Changes.empty(), "zero delta capacity");
    }
    Check(WindowsFixture(), "Windows layout fixture");
    ImageIdentityFixture();
    std::cout << "[layout.core] checks=" << Checks << " failures=" << Failures << '\n';
    return Failures == 0 ? 0 : 1;
}

namespace
{
    void ImageIdentityFixture()
    {
        wchar_t path[32768]{};
        GetModuleFileNameW(nullptr, path, 32768);
        executable_image::DiskPeMetadata metadata;
        std::wstring reason;
        Check(executable_image::ReadDiskPeMetadata(path, &metadata, &reason), "owned image file metadata");
        HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        HANDLE section = file == INVALID_HANDLE_VALUE ? nullptr :
            CreateFileMappingW(file, nullptr, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, nullptr);
        void* view = section == nullptr ? nullptr : MapViewOfFile(section, FILE_MAP_READ, 0, 0, 0);
        Check(view != nullptr, "owned nonexecuting image mapping");
        if (view != nullptr)
        {
            const auto base = reinterpret_cast<uint64_t>(view);
            const ObservationReader reader = [&](uint64_t address, size_t size, std::vector<uint8_t>* bytes)
            {
                bytes->resize(size);
                SIZE_T count = 0;
                return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<void*>(address), bytes->data(), size, &count) && count == size;
            };
            Check(QualifyExecutableReference(metadata, base, reader, &reason), "unmodified mapped image identity");
            MEMORY_BASIC_INFORMATION before{}, after{};
            VirtualQuery(view, &before, sizeof(before));
            DWORD previous = 0;
            const bool writable = VirtualProtect(view, 4096, PAGE_READWRITE, &previous) != FALSE;
            Check(writable, "owned image copy-on-write header");
            if (writable)
            {
                auto dos = static_cast<IMAGE_DOS_HEADER*>(view);
                auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(static_cast<char*>(view) + dos->e_lfanew);
                nt->FileHeader.TimeDateStamp ^= 1;
                DWORD ignored = 0;
                Check(VirtualProtect(view, 4096, previous, &ignored) != FALSE, "owned image protection restored");
                VirtualQuery(view, &after, sizeof(after));
                Check(before.Type == MEM_IMAGE && after.Type == MEM_IMAGE && before.Protect == after.Protect &&
                    before.RegionSize == after.RegionSize, "tampering can preserve the image layout");
                Check(!QualifyExecutableReference(metadata, base, reader, &reason) && reason == L"live_image_identity_mismatch",
                    "unchanged layout image identity mismatch detected");
            }
            UnmapViewOfFile(view);
        }
        if (section != nullptr)
        {
            CloseHandle(section);
        }
        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }
    }

    bool WindowsFixture()
    {
        using namespace process_layout;
        ProcessLayoutScope scope;
        scope.All = false;
        scope.Pids.insert(GetCurrentProcessId());
        Check(!scope.Matches(999, L"else.exe"), "explicit scope");
        scope.Names.push_back(L"TEST.EXE");
        Check(scope.Matches(999, L"test.exe"), "case insensitive name scope");
        scope.Names.clear();
        scope.Names.push_back(L"*.exe");
        Check(scope.Matches(999, L"other.EXE") && !scope.Matches(999, L"other.dll"), "wildcard scope");
        scope.Names.clear();
        Check(ProcessLayoutScope{}.Matches(999, L"any.exe"), "default all process scope");
        Check(ProcessLayoutReferencePath(L"\\Device\\HarddiskVolume7\\CaseSensitive\\File.exe") ==
            L"\\\\?\\GLOBALROOT\\Device\\HarddiskVolume7\\CaseSensitive\\File.exe", "mapped file volume and case preserved");
        ProcessLayoutMonitor monitor;
        monitor.Reset(1000);
        std::atomic<bool> stop{false};
        std::vector<ProcessLayoutNotice> notices;
        std::vector<ProcessLayoutCandidate> candidates;
        const auto notice = [&](ProcessLayoutNotice item)
        {
            notices.push_back(std::move(item));
        };
        const auto candidate = [&](ProcessLayoutCandidate item)
        {
            candidates.push_back(std::move(item));
        };
        const auto waitCycle = [&](uint64_t cycle)
        {
            const auto begin = GetTickCount64();
            while (monitor.Stats().Completed < cycle && GetTickCount64() - begin < 10000)
            {
                monitor.Tick(scope, stop, notice, candidate);
                Sleep(10);
            }
            return monitor.Stats().Completed >= cycle;
        };
        void* memory = VirtualAlloc(nullptr, 12288, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        Check(memory != nullptr, "owned allocation");
        if (memory == nullptr)
        {
            return false;
        }
        const auto address = reinterpret_cast<uint64_t>(memory);
        const bool initial = waitCycle(1);
        Check(initial, "native full address traversal");
        if (!initial)
        {
            std::wcerr << monitor.Text();
        }
        const auto before = monitor.Json(GetCurrentProcessId(), true);
        Check(before.find(L"\"snapshot_available\":true") != std::wstring::npos, "initial snapshot export");
        Check(mcpjson::ValidateDocument(before), "valid initial JSON");
        if (!EvidenceDirectory.empty())
        {
            std::wstring error;
            const auto path = (std::filesystem::path(EvidenceDirectory) / L"initial.json").wstring();
            Check(SaveObservationJson(path, before, &error), "atomic layout export");
            Check(!SaveObservationJson(path, L"{\"replacement\":true}", &error), "export cannot overwrite");
            std::wstring loaded;
            Check(ReadAnalystSnapshot(path, &loaded, &error) && loaded == before, "layout export roundtrip");
            Check(!SaveObservationJson(path + L".bad", L"{", &error), "invalid export rejected");
            const auto after = monitor.Json(GetCurrentProcessId());
            AnalystSnapshotDiff diff;
            Check(!CompareAnalystSnapshots(before, after, &diff, &error), "layout schema not silently treated as case diff");
        }
        DWORD old = 0;
        Check(VirtualProtect(static_cast<char*>(memory) + 4096, 4096, PAGE_EXECUTE_READ, &old) != FALSE,
            "owned nonexecuted RX page");
        Check(waitCycle(2), "periodic traversal");
        if (!EvidenceDirectory.empty())
        {
            std::wstring error;
            Check(SaveObservationJson((std::filesystem::path(EvidenceDirectory) / L"changed.json").wstring(),
                monitor.Json(GetCurrentProcessId()), &error), "changed layout export");
        }
        bool changed = false;
        for (const auto& item : notices)
        {
            for (const auto& delta : item.Changes)
            {
                changed = changed || (delta.Base == address + 4096 && delta.Size == 4096 &&
                    (delta.Flags & BecameExecutable) != 0);
            }
        }
        Check(changed, "real split protection delta");
        Check(std::any_of(candidates.begin(), candidates.end(), [&](const ProcessLayoutCandidate& item)
        {
            return item.Region.Base == address + 4096 && item.Role == L"layout_change";
        }), "changed range verification queue");
        MEMORY_BASIC_INFORMATION mbi{};
        Check(VirtualQuery(memory, &mbi, sizeof(mbi)) == sizeof(mbi), "owned mapping query");
        Region expected{address, 4096, address, MEM_COMMIT, PAGE_READWRITE, PAGE_READWRITE, MEM_PRIVATE};
        Check(ProcessLayoutRegionMatches(expected, mbi), "mapping revalidation");
        expected.Protect = PAGE_EXECUTE_READ;
        Check(!ProcessLayoutRegionMatches(expected, mbi), "stale mapping rejected");
        VirtualFree(memory, 0, MEM_RELEASE);
        Check(waitCycle(3), "freed allocation traversal");
        changed = false;
        for (const auto& item : notices)
        {
            for (const auto& delta : item.Changes)
            {
                changed = changed || (delta.Base == address && (delta.Flags & Removed) != 0);
            }
        }
        Check(changed, "owned release delta");
        Check(monitor.Json(GetCurrentProcessId(), true).find(L"\"base\":\"" + std::to_wstring(address) + L"\"") !=
            std::wstring::npos, "initial baseline retained");

        wchar_t executable[32768]{};
        GetModuleFileNameW(nullptr, executable, 32768);
        std::wstring command = L"\"" + std::wstring(executable) + L"\" --layout-child";
        STARTUPINFOW startup{};
        startup.cb = sizeof(startup);
        PROCESS_INFORMATION process{};
        const bool launched = CreateProcessW(executable, command.data(), nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &startup, &process) != FALSE;
        Check(launched, "owned child launch");
        if (launched)
        {
            scope.All = true;
            const auto begin = GetTickCount64();
            bool discovered = false;
            while (!discovered && GetTickCount64() - begin < 5000)
            {
                monitor.Tick(scope, stop, notice, candidate);
                const auto json = monitor.Json(process.dwProcessId);
                discovered = json.find(L"\"snapshot_available\":true") != std::wstring::npos;
                Sleep(20);
            }
            Check(discovered, "newly started child discovered and snapshotted");
            Check(monitor.Stats().Tracked > 1 && monitor.Stats().AllProcesses, "unscoped inventory includes other processes");
            WaitForSingleObject(process.hProcess, 10000);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
            const auto end = GetTickCount64();
            while (GetTickCount64() - end < 1300)
            {
                monitor.Tick(scope, stop, notice, candidate);
                Sleep(20);
            }
            Check(monitor.Json(process.dwProcessId).find(L"\"processes\":[]") != std::wstring::npos,
                "exited child retired");
        }

        // Concurrent readers exercise immutable history publication during scans.
        std::atomic<bool> done{false};
        std::thread reader([&]()
        {
            while (!done.load())
            {
                monitor.Json(GetCurrentProcessId());
                monitor.Stats();
            }
        });
        for (unsigned i = 0; i < 30; ++i)
        {
            monitor.Tick(scope, stop, notice, candidate);
            Sleep(5);
        }
        done.store(true);
        reader.join();
        Check(ExecutableImageVerifierSelfTest(), "image verifier regression");
        executable_image::DiskPeMetadata metadata;
        std::wstring reason;
        const ObservationReader unreadable = [](uint64_t, size_t, std::vector<uint8_t>*)
        {
            return false;
        };
        Check(!QualifyExecutableReference(metadata, 0x10000, unreadable, &reason) &&
            reason == L"live_image_identity_unreadable", "read failure is not mismatch");
        const ObservationReader zeroHeader = [](uint64_t, size_t size, std::vector<uint8_t>* bytes)
        {
            bytes->assign(size, 0);
            return true;
        };
        Check(!QualifyExecutableReference(metadata, 0x10000, zeroHeader, &reason) &&
            reason == L"live_image_identity_mismatch", "readable invalid identity is distinct");
        return initial;
    }
}
