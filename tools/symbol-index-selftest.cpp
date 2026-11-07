#include "../user/SymbolIndexBroker.h"
#include "../user/TypeSchema.h"
#include "../user/SchemaArtifact.h"
#include "../user/ExecutableImage.h"
#include "../user/SymbolEngine.h"
#include "../user/BrokeredSymbolIndexes.h"
#include "symbol-index-fixture.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <algorithm>
#include <chrono>

struct SymbolEngineTestAccess
{
    static void Modules(SymbolEngine& engine, std::vector<KernelModuleInfo> modules)
    {
        std::lock_guard<std::recursive_mutex> lock(engine.symbolMutex_);
        std::lock_guard<std::mutex> modulesLock(engine.modulesMutex_);
        engine.ClearMetadata(); engine.modules_ = std::move(modules);
    }
    static size_t Failures(const SymbolEngine& engine) { return engine.indexFailures_.size(); }
    static void SaturateAdmissionHistory(SymbolEngine& engine, uint64_t base)
    {
        // Simulate 512 previously attempted module identities without launching
        // 512 equivalent fixture parsers. The tested reacquisition is real.
        for (size_t i = 0; i < 512; ++i) { engine.admittedModules_.insert(base + i * 0x100000); }
        engine.symbolIndexes_->Clear();
    }
};

namespace
{
    unsigned Passed = 0, Failed = 0;
    HMODULE InitialDbghelp = nullptr;
    void Check(bool value, const char* name)
    { if (value) { ++Passed; } else { ++Failed; std::cerr << "[symbol.index] FAIL " << name << '\n'; } }
    std::wstring Executable()
    {
        std::vector<wchar_t> path(32768);
        const auto count = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        return count != 0 && count < path.size() ? std::wstring(path.data(), count) : L"";
    }
    void ApiControls(const std::filesystem::path& root, const SymbolIndex& index)
    {
        const uint64_t base = 0x180000000ull;
        SymbolEngine engine; std::wstring error, name; uint64_t address = 123, displacement = 123;
        Check(engine.Initialize(root.wstring(), &error), "data-only symbol initialization");
        const KernelModuleInfo module{base, index.ImageSize, (root / L"fixture-a.exe").wstring(), L"fixture-a.exe"};
        SymbolEngineTestAccess::Modules(engine, {module});
        Check(!engine.ResolveSymbol(L"SymbolFixtureAdd", &address, &error) && address == 0,
            "unqualified lookup never triggers deferred module parsing");
        const auto find = [&](const wchar_t* query) -> uint32_t
        {
            const auto at = std::find_if(index.Symbols.begin(), index.Symbols.end(), [&](const auto& row) { return row.Name == query; });
            return at == index.Symbols.end() ? UINT32_MAX : at->Rva;
        };
        Check(engine.ResolveSymbol(L"fixture-a!SymbolFixtureAdd", &address, &error) && address == base + find(L"SymbolFixtureAdd"),
            "qualified SymbolEngine lookup uses verified index RVA");
        Check(engine.ResolveSymbol(L"PrivateSymbolFunction", &address, &error) && address == base + find(L"PrivateSymbolFunction"),
            "unqualified lookup works after module index is accepted");
        Check(engine.FindNearestSymbol(address + 2, &name, &displacement, &error) && name == L"PrivateSymbolFunction" && displacement == 2,
            "private nearest-symbol name and displacement");
        Check(!engine.ResolveSymbol(L"fixture-a!SymbolFixtureScope::Overload", &address, &error) && address == 0 && error.find(L"ambiguous") != error.npos,
            "overloaded undecorated name cannot choose an arbitrary address");
        uint64_t first = 0, second = 0;
        Check(engine.ResolveSymbol(L"fixture-a!?Overload@SymbolFixtureScope@@YAHH@Z", &first, &error) &&
            engine.ResolveSymbol(L"fixture-a!?Overload@SymbolFixtureScope@@YAHN@Z", &second, &error) && first != second,
            "exact decorated overload names disambiguate");
        std::vector<SymbolMatchInfo> symbols;
        Check(engine.EnumerateSymbols(L"fixture-a!SymbolFixture*", 32, &symbols, &error) && error.empty() && symbols.size() == 4 &&
            std::all_of(symbols.begin(), symbols.end(), [](const auto& s) { return s.SymbolIndexSha256.size() == 64; }),
            "symbol enumeration deduplicates aliases and preserves index identity");
        Check(engine.EnumerateSymbols(L"fixture-a!*", 1, &symbols, &error) && symbols.size() == 1 && !error.empty(),
            "result cap remains an explicit incomplete enumeration");
        std::vector<TypeMatchInfo> types;
        Check(engine.EnumerateTypes(L"fixture-a!pdbidentity*", 10, &types, &error) && types.size() == 1 && types.front().SizeKnown &&
            types.front().Size == sizeof(PdbIdentityFixture) && types.front().SymbolIndexSha256.size() == 64,
            "type enumeration preserves case-fold compatibility, compiler size and index identity");
        TypeLayoutInfo layout;
        Check(engine.GetTypeLayout(L"fixture-a!PdbIdentityFixture", &layout, &error) && layout.Size == sizeof(PdbIdentityFixture),
            "separate isolated layout cache still works after index acquisition");
        Check(!types.empty() && !engine.GetTypeLayoutById(base, types.front().TypeId, types.front().Name, &layout, &error),
            "enumerated provider ID is not a layout capability");
        Check(!engine.FindNearestSymbol(base + index.ImageSize, &name, &displacement, &error) && name.empty() && displacement == 0,
            "nearest lookup never crosses module end");
        const auto pdb = root / L"fixture-a.pdb", moved = root / L"fixture-a.pdb.saved";
        std::filesystem::rename(pdb, moved);
        Check(engine.ResolveSymbol(L"fixture-a!SymbolFixtureAdd", &address, &error), "accepted in-memory index needs no per-query PDB parsing");
        engine.SetSymbolPath(root.wstring());
        Check(!engine.ResolveSymbol(L"fixture-a!SymbolFixtureAdd", &address, &error) && SymbolEngineTestAccess::Failures(engine) == 1,
            "symbol-path refresh invalidates cached index and records acquisition failure");
        std::filesystem::rename(moved, pdb);
        Check(!engine.ResolveSymbol(L"fixture-a!SymbolFixtureAdd", &address, &error) && SymbolEngineTestAccess::Failures(engine) == 1,
            "scanner retries reuse generation failure instead of launching another parser");
        engine.SetSymbolPath(root.wstring());
        Check(engine.ResolveSymbol(L"fixture-a!SymbolFixtureAdd", &address, &error), "explicit refresh retries a repaired artifact");
        auto secondModule = module; secondModule.Base += 0x100000; secondModule.ImageName = L"fixture-b.exe";
        SymbolEngineTestAccess::Modules(engine, {module, secondModule});
        Check(engine.ResolveSymbol(L"fixture-a!SymbolFixtureAdd", &address, &error) && engine.ResolveSymbol(L"fixture-b!SymbolFixtureAdd", &address, &error) &&
            !engine.ResolveSymbol(L"SymbolFixtureAdd", &address, &error) && address == 0,
            "unqualified name ambiguous across indexed modules fails closed");
        secondModule.Base = base + 1;
        SymbolEngineTestAccess::Modules(engine, {module, secondModule});
        Check(!engine.FindNearestSymbol(base + 0x1000, &name, &displacement, &error) && name.empty(), "overlapping module ranges cannot select an owner");
        SymbolEngineTestAccess::Modules(engine, {{base, index.ImageSize + 1, module.ImagePath, module.ImageName}});
        Check(!engine.ResolveSymbol(L"fixture-a!SymbolFixtureAdd", &address, &error), "module size change cannot reuse prior index");
        auto good = module, missing = module;
        good.ImageName = L"ntoskrnl.exe"; missing.ImageName = L"ntkrnlmp.exe";
        missing.Base += 0x100000; ++missing.Size;
        SymbolEngineTestAccess::Modules(engine, {good, missing});
        Check(engine.EnumerateSymbols(L"nt!SymbolFixtureAdd", 8, &symbols, &error) && symbols.size() == 1 &&
            error.find(L"unavailable modules=1") != error.npos, "partial symbol results expose failed module coverage");
        Check(engine.EnumerateTypes(L"nt!PdbIdentityFixture", 8, &types, &error) && types.size() == 1 &&
            error.find(L"unavailable modules=1") != error.npos, "partial type results expose failed module coverage");
        Check(!engine.ResolveSymbol(L"nt!SymbolFixtureAdd", &address, &error) && address == 0,
            "exact lookup cannot establish uniqueness across an unavailable matching module");
        auto fresh = module; fresh.Base += 512 * 0x100000ull; fresh.ImageName = L"fresh.exe";
        SymbolEngineTestAccess::Modules(engine, {module, fresh});
        const bool admitted = engine.ResolveSymbol(L"fixture-a!SymbolFixtureAdd", &address, &error);
        SymbolEngineTestAccess::SaturateAdmissionHistory(engine, base);
        Check(admitted && engine.ResolveSymbol(L"fixture-a!SymbolFixtureAdd", &address, &error),
            "full admission ledger permits reacquisition of an evicted existing module");
        Check(!engine.ResolveSymbol(L"fresh!SymbolFixtureAdd", &address, &error) && address == 0 && error.find(L"budget") != error.npos,
            "full admission ledger still rejects a new module identity");
        Check(GetModuleHandleW(L"msdia140.dll") == nullptr && GetModuleHandleW(L"dbghelp.dll") == InitialDbghelp,
            "parent SymbolEngine APIs do not load DIA or change the initial DbgHelp state");
    }
    void CacheControls(const SymbolIndex& index)
    {
        BrokeredSymbolIndexes cache(128 * 1024 * 1024, 2);
        Check(cache.Insert(0x100000, index) != nullptr && cache.Insert(0x200000, index) != nullptr, "bounded module cache accepts validated entries");
        const auto held = cache.Find(0x100000);
        Check(cache.Insert(0x300000, index) != nullptr && cache.Contains(0x100000) && !cache.Contains(0x200000) && cache.Size() == 2,
            "LRU eviction preserves recently queried module");
        const auto bytes = cache.AccountedBytes(); auto malformed = index; malformed.ImageSize = 0;
        Check(!cache.Insert(0x100000, malformed) && cache.AccountedBytes() == bytes && cache.Contains(0x100000),
            "rejected replacement preserves valid cached metadata");
        BrokeredSymbolIndexes small(1, 2);
        Check(!small.Insert(0x100000, index) && small.Size() == 0 && !cache.Insert(UINT64_MAX - 1, index),
            "retained byte budget and rebased address overflow fail closed");
        cache.Clear();
        Check(cache.Size() == 0 && cache.AccountedBytes() == 0 && held && !held->Index.Symbols.empty(),
            "cache reset releases ownership while an active reader remains valid");
    }
    void Controls(const std::filesystem::path& root)
    {
        SymbolIndex index; std::wstring error;
        const auto image = root / L"fixture-a.exe", pdb = root / L"fixture-a.pdb";
        const bool ready = GenerateBrokeredSymbolIndex(Executable(), image.wstring(), pdb.wstring(), &index, &error);
        if (!ready) { std::wcerr << error << L'\n'; }
        Check(ready && index.IndexSha256.size() == 64, "actual restricted worker returned a verified index");
        if (!ready) { return; }
        std::cout << "[symbol.index] symbols=" << index.Symbols.size() << " types=" << index.Types.size() << '\n';
        for (const auto name : {L"SymbolFixtureAdd", L"SymbolFixture", L"PrivateSymbolFunction", L"PrivateSymbolState", L"SymbolFixtureScope::Overload"})
        {
            const auto found = std::find_if(index.Symbols.begin(), index.Symbols.end(), [&](const auto& s) { return s.Name == name; });
            Check(found != index.Symbols.end(), "exported, private or undecorated fixture symbol retained");
        }
        const auto type = std::find_if(index.Types.begin(), index.Types.end(), [](const auto& t) { return t.Name == L"PdbIdentityFixture"; });
        Check(type != index.Types.end() && type->SizeKnown && type->Bytes == sizeof(PdbIdentityFixture), "type index size equals compiler layout");
        for (const auto& expected : {std::make_pair(L"SymbolFixtureMode", sizeof(SymbolFixtureMode)),
            std::make_pair(L"SymbolFixtureCount", sizeof(SymbolFixtureCount))})
        {
            const auto entry = std::find_if(index.Types.begin(), index.Types.end(), [&](const auto& t) { return t.Name == expected.first; });
            Check(entry != index.Types.end() && entry->SizeKnown && entry->Bytes == expected.second,
                "enum and typedef discovery retain compiler-reported sizes");
        }
        Check(GetModuleHandleW(L"msdia140.dll") == nullptr, "index broker does not load parent DIA");
        std::string wire;
        Check(EncodeSymbolIndex(index, &wire), "bounded binary index encoding");
        std::ofstream saved(root / L"fixture.knsymidx", std::ios::binary); saved.write(wire.data(), static_cast<std::streamsize>(wire.size())); saved.close();
        SymbolIndex parsed;
        Check(DecodeSymbolIndex(wire, &parsed) && parsed.IndexSha256 == index.IndexSha256, "canonical round trip keeps digest");
        std::string again; Check(EncodeSymbolIndex(parsed, &again) && again == wire, "canonical re-encoding is byte exact");
        for (size_t length : {size_t{0}, size_t{7}, size_t{255}, wire.size() - 1})
        { Check(!DecodeSymbolIndex(wire.substr(0, length), &parsed) && parsed.Symbols.empty(), "truncated frame denied without stale output"); }
        Check(!DecodeSymbolIndex(wire + "x", &parsed), "trailing bytes denied");
        auto bad = wire; bad[8] = 2; Check(!DecodeSymbolIndex(bad, &parsed), "unsupported wire version denied");
        bad = wire; bad[24] = bad[25] = bad[26] = bad[27] = static_cast<char>(255);
        Check(!DecodeSymbolIndex(bad, &parsed), "hostile count rejected before allocation");
        bad = wire; bad[32] = 'z'; Check(!DecodeSymbolIndex(bad, &parsed), "noncanonical artifact digest denied");
        bad = wire; bad[264] = 2; Check(!DecodeSymbolIndex(bad, &parsed), "nonboolean size-known flag denied");
        bad = wire; bad[260] = 12; Check(!DecodeSymbolIndex(bad, &parsed), "non-address symbol tag denied");
        bad = wire; bad[280] = 0; Check(!DecodeSymbolIndex(bad, &parsed), "embedded NUL display name denied");
        bad = wire; bad[280] = static_cast<char>(255); Check(!DecodeSymbolIndex(bad, &parsed), "invalid UTF-8 name denied");
        bad = wire; bad[276] = bad[277] = bad[278] = bad[279] = static_cast<char>(255);
        Check(!DecodeSymbolIndex(bad, &parsed), "oversize string rejected before decoding");
        auto mismatch = index; mismatch.ImageSha256 = std::wstring(64, L'a');
        Check(!AcceptSymbolIndexWorkerOutput(wire, mismatch, &parsed), "wrong expected image denied");
        mismatch = index; ++mismatch.PdbAge;
        Check(!AcceptSymbolIndexWorkerOutput(wire, mismatch, &parsed), "wrong expected PDB age denied");
        mismatch = index; mismatch.PdbSha256 = std::wstring(64, L'a');
        Check(!AcceptSymbolIndexWorkerOutput(wire, mismatch, &parsed), "wrong expected PDB bytes denied");
        mismatch = index; mismatch.ProviderSha256 = std::wstring(64, L'a');
        Check(!AcceptSymbolIndexWorkerOutput(wire, mismatch, &parsed), "wrong installed provider bytes denied");
        mismatch = index; mismatch.PdbGuid = std::wstring(32, L'a');
        Check(!AcceptSymbolIndexWorkerOutput(wire, mismatch, &parsed), "wrong PE RSDS GUID denied");
        mismatch = index; ++mismatch.ImageSize;
        Check(!AcceptSymbolIndexWorkerOutput(wire, mismatch, &parsed), "wrong image extent denied");
        mismatch = index; mismatch.Symbols.front().Rva = mismatch.ImageSize;
        Check(!EncodeSymbolIndex(mismatch, &again), "symbol outside image denied");
        mismatch = index; mismatch.Symbols.front().Bytes = UINT64_MAX; mismatch.Symbols.front().SizeKnown = true;
        Check(!EncodeSymbolIndex(mismatch, &again), "symbol extent overflow denied");
        mismatch = index; mismatch.Symbols.front().Name = L"bad\x1b[31m";
        Check(!EncodeSymbolIndex(mismatch, &again), "terminal-control names denied");
        mismatch = index; mismatch.Symbols.clear(); mismatch.Types.clear();
        IndexedSymbol control;
        control.Tag = 10; control.LinkageName = L"\x7fIMPORT_DESCRIPTOR"; control.Name = EscapeSymbolIndexName(control.LinkageName);
        mismatch.Symbols.push_back(control);
        Check(control.Name == L"\\u007fIMPORT_DESCRIPTOR" && EncodeSymbolIndex(mismatch, &again) && DecodeSymbolIndex(again, &parsed) &&
            parsed.Symbols.front().LinkageName == control.LinkageName && parsed.Symbols.front().Name == control.Name,
            "raw linker control prefix retained behind escaped display name");
        mismatch = index; mismatch.Symbols.insert(mismatch.Symbols.begin(), mismatch.Symbols.front());
        Check(!EncodeSymbolIndex(mismatch, &again), "duplicate canonical row denied");
        Check(!GenerateBrokeredSymbolIndex(Executable(), image.wstring(), (root / L"fixture-b.pdb").wstring(), &parsed, &error) && parsed.Symbols.empty(),
            "wrong PDB rejected without stale rows");
        CacheControls(index);
        ApiControls(root, index);
    }
}
int wmain(int argc, wchar_t** argv)
{
    if (argc > 1 && std::wstring(argv[1]) == L"--symbol-index-worker") { return RunSymbolIndexWorkerCommand(argc, argv); }
    if (argc > 1 && (std::wstring(argv[1]) == L"--schema-worker" || std::wstring(argv[1]) == L"--schema-live-worker"))
    { return RunTypeSchemaWorkerCommand(argc, argv); }
    if (argc == 4 && std::wstring(argv[1]) == L"--kernel-index")
    {
        SchemaArtifact image; executable_image::DiskPeMetadata metadata; SymbolIndex index; std::wstring error;
        const auto started = GetTickCount64();
        const bool ok = image.Open(argv[2], 512ull * 1024 * 1024) &&
            executable_image::ReadDiskPeIdentityHandle(image.Handle(), &metadata, nullptr) &&
            ResolveBrokeredSymbolIndex(Executable(), argv[2], metadata.SizeOfImage, argv[3], &index, &error);
        std::wcout << L"[symbol.index.kernel] available=" << ok << L" symbols=" << index.Symbols.size() << L" types=" << index.Types.size()
            << L" elapsed_ms=" << GetTickCount64() - started << L" error=" << error << L'\n';
        if (!ok) { return 1; }
        SymbolEngine engine; uint64_t address = 0, displacement = 0; std::wstring name;
        engine.Initialize(argv[3], &error);
        SymbolEngineTestAccess::Modules(engine, {{0x180000000ull, metadata.SizeOfImage, argv[2], L"ntoskrnl.exe"}});
        size_t loaded = 0;
        Check(engine.PreloadKernelSymbols(&loaded, &error) && loaded == 1, "real kernel index via startup preload API");
        Check(engine.ResolveSymbol(L"nt!KeBugCheckEx", &address, &error) && address != 0, "real kernel qualified symbol resolves");
        Check(engine.FindNearestSymbol(address + 1, &name, &displacement, &error) && name == L"KeBugCheckEx" && displacement == 1,
            "real kernel nearest-symbol query matches exact public function");
        std::vector<TypeMatchInfo> types;
        Check(engine.EnumerateTypes(L"nt!*EPROCESS", 64, &types, &error) && !types.empty(), "real kernel UDT enumeration");
        const auto hotStarted = std::chrono::steady_clock::now(); bool hot = true;
        for (size_t i = 0; i < 10000; ++i) { if (!engine.ResolveSymbol(L"nt!KeBugCheckEx", &address, &error)) { hot = false; break; } }
        Check(hot, "ten thousand kernel lookups reuse bounded parent metadata");
        Check(GetModuleHandleW(L"msdia140.dll") == nullptr, "real kernel queries do not load parent DIA");
        std::wcout << L"[symbol.index.kernel] hot_lookups_us=" << std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - hotStarted).count()
            << L" passed=" << Passed << L" failed=" << Failed << L'\n';
        if (!error.empty()) { std::wcerr << error << L'\n'; }
        return Failed == 0 ? 0 : 1;
    }
    if (argc == 4 && std::wstring(argv[1]) == L"--worker-executable")
    {
        const auto root = std::filesystem::path(argv[3]); SymbolIndex index; std::wstring error;
        Check(GenerateBrokeredSymbolIndex(argv[2], (root / L"fixture-a.exe").wstring(), (root / L"fixture-a.pdb").wstring(), &index, &error) &&
            !index.Symbols.empty(), "actual Release symbol worker dispatcher");
        if (!error.empty()) { std::wcerr << error << L'\n'; }
        Check(!GenerateBrokeredSymbolIndex(argv[2], (root / L"fixture-a.exe").wstring(), (root / L"fixture-b.pdb").wstring(), &index, &error) &&
            index.Symbols.empty(), "actual Release symbol worker rejects mismatched PDB");
        std::cout << "[symbol.index.release-worker] passed=" << Passed << " failed=" << Failed << '\n';
        return Failed == 0 ? 0 : 1;
    }
    if (argc != 2) { return 2; }
    InitialDbghelp = GetModuleHandleW(L"dbghelp.dll");
    std::cout << "[symbol.index.runtime] dbghelp_preloaded=" << (InitialDbghelp != nullptr) << '\n';
    Controls(std::filesystem::absolute(argv[1]));
    std::cout << "[symbol.index] passed=" << Passed << " failed=" << Failed << '\n';
    return Failed == 0 ? 0 : 1;
}
