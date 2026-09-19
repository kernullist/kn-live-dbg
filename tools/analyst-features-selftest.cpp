#include "../user/ExecutionSurfaceScanner.h"
#include "../user/AnalystSnapshot.h"
#include "../user/KmonHuntingJson.h"
#include "../user/ObservationWindows.h"

#include <filesystem>
#include <iostream>
#include <random>

static volatile LONG TlsNotifications = 0;

static void NTAPI BenignTls(PVOID, DWORD, PVOID)
{
    InterlockedIncrement(&TlsNotifications);
}

#pragma section(".CRT$XLB", read)
extern "C"
{
    __declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK AnalystFixtureTls = BenignTls;
}
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:AnalystFixtureTls")

namespace
{
    size_t Passed = 0;
    size_t Failed = 0;

    void Check(bool ok, const char* name)
    {
        if (ok)
        {
            ++Passed;
        }
        else
        {
            ++Failed;
            std::cerr << "[analyst.selftest] FAIL " << name << "\n";
        }
    }

    template<typename T>
    void Put(std::vector<uint8_t>* bytes, size_t offset, T value)
    {
        if (offset <= bytes->size() && sizeof(value) <= bytes->size() - offset)
        {
            std::memcpy(bytes->data() + offset, &value, sizeof(value));
        }
    }

    std::vector<uint8_t> Image(bool x86 = false)
    {
        std::vector<uint8_t> bytes(0x4000, 0);
        Put<uint16_t>(&bytes, 0, IMAGE_DOS_SIGNATURE);
        Put<uint32_t>(&bytes, 0x3C, 0x80);
        Put<uint32_t>(&bytes, 0x80, IMAGE_NT_SIGNATURE);
        Put<uint16_t>(&bytes, 0x84, x86 ? IMAGE_FILE_MACHINE_I386 : IMAGE_FILE_MACHINE_AMD64);
        Put<uint16_t>(&bytes, 0x94, x86 ? sizeof(IMAGE_OPTIONAL_HEADER32) : sizeof(IMAGE_OPTIONAL_HEADER64));
        Put<uint16_t>(&bytes, 0x98, x86 ? IMAGE_NT_OPTIONAL_HDR32_MAGIC : IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        Put<uint32_t>(&bytes, 0x98 + 56, 0x4000);
        const size_t directories = 0x98 + (x86 ? 96 : 112);
        Put<uint32_t>(&bytes, directories - 4, 16);
        Put<uint32_t>(&bytes, directories + 9 * 8, 0x2000);
        Put<uint32_t>(&bytes, directories + 9 * 8 + 4, x86 ? 24 : 40);
        if (x86)
        {
            Put<uint32_t>(&bytes, 0x2000 + 12, 0x10002100);
            Put<uint32_t>(&bytes, 0x2100, 0x10001100);
            Put<uint32_t>(&bytes, 0x2104, 0x10001200);
        }
        else
        {
            Put<uint64_t>(&bytes, 0x2000 + 24, 0x10002100);
            Put<uint64_t>(&bytes, 0x2100, 0x10001100);
            Put<uint64_t>(&bytes, 0x2108, 0x10001200);
        }
        return bytes;
    }

    ObservationReader Reader(const std::vector<uint8_t>& bytes)
    {
        return [&bytes](uint64_t address, size_t size, std::vector<uint8_t>* out)
        {
            if (address < 0x10000000 || address - 0x10000000 >= bytes.size() ||
                size > bytes.size() - (address - 0x10000000) || size > 4096)
            {
                return false;
            }
            const auto start = static_cast<size_t>(address - 0x10000000);
            out->assign(bytes.begin() + start, bytes.begin() + start + size);
            return true;
        };
    }

    void CoreTests()
    {
        for (bool x86 : {false, true})
        {
            auto bytes = Image(x86);
            auto reader = Reader(bytes);
            auto table = execution_surface::Tls(0x10000000, 0x4000, reader);
            Check(table.Complete && table.Stable && table.Present && table.Entries.size() == 2 &&
                table.PointerSize == (x86 ? 4u : 8u) && table.Entries[1].Target == 0x10001200, "TLS architecture and VA interpretation");
            Check(std::wstring(execution_surface::CompareTls(table, table)) == L"match", "TLS stable baseline");
            Check(ObservationAnchorsMatch(table.Anchors, reader), "TLS PE/directory anchor validation");
            Put<uint32_t>(&bytes, 0x2100, 0);
            Check(!ObservationAnchorsMatch(table.Anchors, reader), "TLS earlier terminator invalidates later stable slots");
            Put<uint32_t>(&bytes, 0x2100, 0x10001100);
            Put<uint32_t>(&bytes, x86 ? 0x2108 : 0x2110, 0x10001300);
            Check(!ObservationAnchorsMatch(table.Anchors, reader), "TLS removed terminator invalidates captured extent");
            Put<uint32_t>(&bytes, x86 ? 0x2108 : 0x2110, 0);
            Put<uint32_t>(&bytes, x86 ? 0x2104 : 0x2108, 0x10001300);
            auto changed = execution_surface::Tls(0x10000000, 0x4000, reader);
            Check(std::wstring(execution_surface::CompareTls(table, changed)) == L"mismatch", "TLS callback target change");
            Put<uint64_t>(&bytes, 0x98 + (x86 ? 96 : 112) + 9 * 8, 0);
            auto removed = execution_surface::Tls(0x10000000, 0x4000, reader);
            Check(removed.Complete && removed.Stable && !removed.Present &&
                std::wstring(execution_surface::CompareTls(table, removed)) == L"mismatch", "TLS directory removal");
            Check(!ObservationAnchorsMatch(table.Anchors, reader), "TLS stale PE directory anchor rejected");
        }
        auto bytes = Image();
        auto reader = Reader(bytes);
        Put<uint64_t>(&bytes, 0x2018, 0);
        auto table = execution_surface::Tls(0x10000000, 0x4000, reader);
        Check(table.Complete && table.Entries.empty() && table.Status == L"empty", "TLS null callbacks");
        bytes = Image();
        Put<uint64_t>(&bytes, 0x2018, UINT64_MAX - 7);
        table = execution_surface::Tls(0x10000000, 0x4000, reader);
        Check(!table.Complete && table.Entries.empty(), "TLS invalid high callback array rejected");
        bytes = Image();
        for (size_t i = 0; i < 70; ++i)
        {
            Put<uint64_t>(&bytes, 0x2100 + i * 8, 0x10001100 + i);
        }
        table = execution_surface::Tls(0x10000000, 0x4000, reader);
        Check(!table.Complete && table.Entries.size() == 64, "TLS nonterminated table is partial");
        Put<uint64_t>(&bytes, 0x2100 + 64 * 8, 0);
        table = execution_surface::Tls(0x10000000, 0x4000, reader);
        Check(table.Complete && table.Entries.size() == 64, "TLS terminator at exact budget");
        Check(!execution_surface::Tls(0x10000000, 0x4000, reader, 0).Complete &&
            !execution_surface::Tls(0x10000000, 0x4000, reader, 257).Complete, "TLS invalid budgets");
        bytes = Image();
        size_t slotReads = 0;
        const ObservationReader race = [&](uint64_t address, size_t size, std::vector<uint8_t>* out)
        {
            const bool read = reader(address, size, out);
            if (read && address == 0x10002100 && ++slotReads > 1)
            {
                (*out)[0] ^= 1;
            }
            return read;
        };
        table = execution_surface::Tls(0x10000000, 0x4000, race);
        Check(!table.Stable && std::wstring(execution_surface::CompareTls(table, table)) == L"unverified", "TLS changing slot rejected");
        Put<uint64_t>(&bytes, 0x1000, 0x10002100);
        auto kct = execution_surface::KernelCallbacks(0x10001000, reader);
        Check(kct.Stable && !kct.Complete && kct.Entries.size() == 64 && kct.Entries[2].Target == 0,
            "KCT prefix is not null terminated or complete");
        Put<uint64_t>(&bytes, 0x1000, 0x10002200);
        Check(!ObservationAnchorsMatch(kct.Anchors, reader), "KCT replaced root invalidates old stable slots");
        Put<uint64_t>(&bytes, 0x1000, 0);
        kct = execution_surface::KernelCallbacks(0x10001000, reader);
        Check(kct.Stable && kct.Complete && !kct.Present, "KCT null root");
        Check(!execution_surface::KernelCallbacks(UINT64_MAX - 3, reader).Stable, "KCT overflow root");
        bytes = Image();
        Put<uint32_t>(&bytes, 0x98 + 108, UINT32_MAX);
        Check(!execution_surface::Tls(0x10000000, 0x4000, reader).Complete, "oversized directory count rejected");
        std::mt19937 random(0x20260920);
        for (size_t i = 0; i < 6000; ++i)
        {
            bytes = Image((i & 1) != 0);
            for (size_t j = 0; j < 4; ++j)
            {
                const size_t at = random() % bytes.size();
                bytes[at] = static_cast<uint8_t>(random());
            }
            const auto sample = execution_surface::Tls(0x10000000, 0x4000, reader);
            Check(sample.Entries.size() <= 64 && sample.Anchors.size() <= 5, "mutated PE remains bounded");
        }
    }

    KmonHuntReference Reference(uint32_t pid)
    {
        KmonHuntReference reference;
        reference.Context.Identity.BootId = L"boot-a";
        reference.Context.Identity.ProcessId = pid;
        reference.Context.Identity.CreateTime = pid == 0 ? 0 : 133000000000000001ull;
        reference.Context.Ownership = CodeOwnership::UnownedExecutable;
        reference.Context.Source = L"fixture";
        reference.Context.DependencyGroup = L"fixture";
        reference.Context.MonotonicMs = 100;
        reference.Context.MappingGeneration = 2;
        reference.Context.PfnKnown = true;
        reference.Context.Pfn = 9007199254740993ull;
        reference.Role = pid == 0 ? L"firmware_table_handler" : L"tls_callback";
        reference.Address = pid == 0 ? 0xFFFFF80112345000ull : 0x12345000ull;
        reference.Root = reference.Address;
        reference.Slot = pid == 0 ? 0xFFFFF80122345000ull : 0x22345000ull;
        reference.PageSha256 = std::wstring(64, L'a');
        reference.SlotStable = true;
        reference.PageComparable = true;
        return reference;
    }

    void SnapshotTests(const std::wstring& directory)
    {
        KmonHuntCase item{L"cross_domain_content", ObservationRelation::Content, Reference(0), Reference(55), true};
        auto a = KmonHuntCasesJson({item}, 100, 0, 0);
        item.Primary.Id = 500;
        item.Primary.Context.MonotonicMs = 1000;
        item.Primary.Context.Timestamp = 133000000000000001ull;
        auto b = KmonHuntCasesJson({item}, 1000, 0, 0);
        AnalystSnapshotDiff result;
        std::wstring error;
        Check(CompareAnalystSnapshots(a, b, &result, &error) && result.Unchanged == 1 && result.Changed == 0,
            "refresh times and IDs do not change a lead");
        auto equivalent = a;
        const auto pfnAt = equivalent.find(L"9007199254740993");
        equivalent.replace(pfnAt, 16, L"09007199254740993");
        Check(CompareAnalystSnapshots(a, equivalent, &result, &error) && result.Unchanged == 1,
            "numeric string spelling is normalized");
        item.Related.Context.Pfn += 1;
        b = KmonHuntCasesJson({item}, 1000, 0, 0);
        Check(CompareAnalystSnapshots(a, b, &result, &error) && result.Changed == 1, "64-bit PFN differences preserved");
        item.Related.Context.Identity.CreateTime += 1;
        b = KmonHuntCasesJson({item}, 1000, 0, 0);
        Check(CompareAnalystSnapshots(a, b, &result, &error) && result.Changed == 0 &&
            result.Added == 1 && result.NoLongerObserved == 1, "PID reuse does not join identities");
        b = KmonHuntCasesJson({}, 1000, 0, 0);
        Check(CompareAnalystSnapshots(a, b, &result, &error) && result.NoLongerObserved == 1 &&
            AnalystSnapshotDiffJson(result).find(L"\"absence_is_resolution\":false") != std::wstring::npos,
            "missing evidence is not remediation");
        Check(FilterAnalystCases({item}, {true, 55, L"tls_callback"}).size() == 1 &&
            FilterAnalystCases({item}, {true, 55, L"firmware_table_handler"}).empty(), "combined filters match one endpoint");
        auto duplicate = KmonHuntCasesJson({item, item}, 1000, 0, 0);
        Check(!CompareAnalystSnapshots(duplicate, a, &result, &error), "duplicate identities rejected");
        for (const auto& bad : {L"{}", L"{\"schema\":1,\"schema\":2}", L"[]", L"null"})
        {
            Check(!CompareAnalystSnapshots(bad, a, &result, &error), "invalid schema rejected");
        }
        auto malformed = a;
        const auto offset = malformed.find(L"133000000000000001");
        malformed.replace(offset, 18, L"18446744073709551616");
        Check(!CompareAnalystSnapshots(malformed, a, &result, &error), "uint64 overflow rejected");
        malformed = a;
        const auto flag = malformed.find(L"\"communication_proven\":false");
        malformed.replace(flag, std::wstring(L"\"communication_proven\":false").size(), L"\"communication_proven\":true");
        Check(!CompareAnalystSnapshots(malformed, a, &result, &error), "inflated input claim rejected");
        std::mt19937 random(123);
        for (size_t i = 0; i < 300; ++i)
        {
            malformed = a.substr(0, random() % a.size());
            Check(!CompareAnalystSnapshots(malformed, a, &result, &error), "truncated JSON rejected");
        }
        const auto path = directory + L"\\case-" + std::to_wstring(GetCurrentProcessId()) + L".json";
        Check(!SaveAnalystSnapshot(L"NUL.json", a, &error) && !SaveAnalystSnapshot(L"COM1.json", a, &error),
            "snapshot output rejects DOS device names");
        Check(SaveAnalystSnapshot(path, a, &error), "atomic snapshot save");
        Check(!SaveAnalystSnapshot(path, b, &error), "existing snapshot is not overwritten");
        std::wstring read;
        Check(ReadAnalystSnapshot(path, &read, &error) && read == a, "snapshot round trip");
        Check(!ReadAnalystSnapshot(L"CON", &read, &error) &&
            !ReadAnalystSnapshot(path + std::wstring(1, L'\0') + L"ignored", &read, &error), "snapshot input rejects devices and embedded NUL");
        Check(SaveAnalystSnapshot(directory + L"\\case-next-" + std::to_wstring(GetCurrentProcessId()) + L".json", b, &error), "empty snapshot save");
    }

    void CALLBACK BenignWork(PTP_CALLBACK_INSTANCE, PVOID context, PTP_WORK)
    {
        SetEvent(static_cast<HANDLE>(context));
    }

    void LiveFixture(const std::wstring& directory)
    {
        uint64_t peb = 0;
        Check(QueryExecutionSurfacePeb(GetCurrentProcess(), GetCurrentProcessId(), &peb) && peb != 0,
            "retained process PEB identity query");
        Check(!QueryExecutionSurfacePeb(GetCurrentProcess(), GetCurrentProcessId() ^ 4, &peb) && peb == 0,
            "PEB query rejects mismatched process ID");
        HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        PTP_WORK work = CreateThreadpoolWork(BenignWork, event, nullptr);
        Check(event != nullptr && work != nullptr, "owned thread pool fixture created");
        if (event == nullptr || work == nullptr)
        {
            if (work != nullptr)
            {
                CloseThreadpoolWork(work);
            }
            if (event != nullptr)
            {
                CloseHandle(event);
            }
            return;
        }
        SubmitThreadpoolWork(work);
        Check(WaitForSingleObject(event, 5000) == WAIT_OBJECT_0, "owned thread pool callback completed");
        WaitForThreadpoolWorkCallbacks(work, FALSE);
        ExecutionSurfaceOptions options;
        options.TimeBudgetMs = 10000;
        void* candidate = VirtualAlloc(nullptr, 0x4000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        Check(candidate != nullptr, "owned read-only inspection candidate allocated");
        if (candidate != nullptr)
        {
            auto data = Image();
            const auto base = reinterpret_cast<uintptr_t>(candidate);
            Put<uint64_t>(&data, 0x2018, base + 0x2100);
            Put<uint64_t>(&data, 0x2100, reinterpret_cast<uintptr_t>(&BenignTls));
            Put<uint64_t>(&data, 0x2108, 0);
            std::memcpy(candidate, data.data(), data.size());
            options.ImageCandidates.push_back({base, 0x4000});
        }
        auto result = ScanExecutionSurfaces(GetCurrentProcessId(), options);
        size_t workers = 0;
        size_t tls = 0;
        size_t mismatches = 0;
        bool ownBaseline = false;
        bool candidateObserved = false;
        const auto imageBase = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
        for (const auto& row : result.Rows)
        {
            workers += row.Kind == L"worker_factory_start" && row.Stable && row.Executable && !row.Owner.empty();
            tls += row.Kind == L"tls_callback" && row.Stable;
            mismatches += row.Baseline == L"mismatch";
            ownBaseline = ownBaseline || (row.Kind == L"tls_callback_table" && row.ModuleBase == imageBase && row.Baseline == L"match");
            candidateObserved = candidateObserved || (row.Kind == L"tls_callback" && row.ModuleBase == reinterpret_cast<uintptr_t>(candidate) &&
                row.Target == reinterpret_cast<uintptr_t>(&BenignTls) && row.Stable && row.Baseline == L"unverified");
        }
        Check(result.IdentityStable && result.ModuleInventoryComplete, "owned process identity and inventory");
        Check(workers != 0, "owned WorkerFactory start routine observed");
        Check(tls != 0 && ownBaseline, "owned TLS callbacks and relocated disk baseline");
        Check(candidateObserved, "image candidate outside loader list contributes TLS references");
        Check(mismatches == 0, "clean owned fixture has no TLS baseline mismatches");
        std::wstring error;
        const auto json = ExecutionSurfacesJson(result);
        const auto path = directory + L"\\surface-" + std::to_wstring(GetCurrentProcessId()) + L".json";
        Check(SaveAnalystSnapshot(path, json, &error), "surface snapshot persistence");
        AnalystSnapshotDiff diff;
        Check(CompareAnalystSnapshots(json, json, &diff, &error) && diff.Unchanged == result.Rows.size(), "surface self comparison");
        auto resumed = result;
        resumed.NextModule += 1;
        Check(CompareAnalystSnapshots(json, ExecutionSurfacesJson(resumed), &diff, &error) && diff.CoverageChanged &&
            diff.Unchanged == result.Rows.size(), "module resume boundary changes coverage");
        resumed = result;
        resumed.NextHandle += 4;
        Check(CompareAnalystSnapshots(json, ExecutionSurfacesJson(resumed), &diff, &error) && diff.CoverageChanged &&
            diff.Unchanged == result.Rows.size(), "handle resume boundary changes coverage");
        if (!result.Rows.empty())
        {
            result.Rows[0].Target ^= 0x1000;
            Check(CompareAnalystSnapshots(json, ExecutionSurfacesJson(result), &diff, &error) && diff.Changed == 1,
                "surface target change retains slot identity");
            result.Identity.CreateTime += 1;
            Check(CompareAnalystSnapshots(json, ExecutionSurfacesJson(result), &diff, &error) && diff.Changed == 0 &&
                diff.Added == result.Rows.size(), "surface process reuse is separate identity");
            result.Identity.BootId = L"other-boot";
            Check(CompareAnalystSnapshots(json, ExecutionSurfacesJson(result), &diff, &error) && diff.BootRelation == L"different" &&
                diff.Changed == 0, "surface reboot does not join addresses");
        }
        const auto unavailable = ExecutionSurfacesJson(ScanExecutionSurfaces(4));
        Check(CompareAnalystSnapshots(unavailable, unavailable, &diff, &error) && diff.Unchanged == 0,
            "unavailable empty snapshots retain unknown coverage");
        std::wcout << L"[analyst.fixture] workers=" << workers << L" tls=" << tls << L" mismatches=" << mismatches
            << L" own_baseline=" << ownBaseline << L" rows=" << result.Rows.size() << L"\n";
        for (const auto& coverage : result.Coverage)
        {
            std::wcout << L"[analyst.coverage] " << coverage.first << L"=" << coverage.second << L"\n";
        }
        CloseThreadpoolWork(work);
        CloseHandle(event);
        if (candidate != nullptr)
        {
            VirtualFree(candidate, 0, MEM_RELEASE);
        }
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc != 2)
    {
        return 2;
    }
    const std::wstring directory = argv[1];
    CoreTests();
    SnapshotTests(directory);
    LiveFixture(directory);
    std::cout << "[analyst.selftest] passed=" << Passed << " failed=" << Failed << "\n";
    return Failed == 0 ? 0 : 1;
}
