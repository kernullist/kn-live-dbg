#include "../user/PdbIdentity.h"
#include "../user/ExecutableImage.h"
#include <wrl/client.h>
#include <filesystem>
#include <fstream>
#include <iostream>

using Microsoft::WRL::ComPtr;

namespace
{
    unsigned Passed = 0, Failed = 0;
    void Check(bool ok, const char* name)
    {
        if (ok)
        {
            ++Passed;
        }
        else
        {
            ++Failed;
            std::cerr << "[pdb.identity] FAIL " << name << "\n";
        }
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc != 3)
    {
        return 2;
    }
    const std::filesystem::path root(argv[2]);
    const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(initialized))
    {
        return 2;
    }
    HMODULE provider = LoadLibraryExW(argv[1], nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    using GetFactory = HRESULT(WINAPI*)(REFCLSID, REFIID, void**);
    const auto getFactory = provider == nullptr ? nullptr : reinterpret_cast<GetFactory>(GetProcAddress(provider, "DllGetClassObject"));
    ComPtr<IClassFactory> factory;
    if (getFactory == nullptr || getFactory(__uuidof(DiaSource), IID_PPV_ARGS(&factory)) != S_OK)
    {
        if (provider != nullptr)
        {
            FreeLibrary(provider);
        }
        CoUninitialize();
        return 2;
    }
    const auto fresh = [&]()
    {
        ComPtr<IDiaDataSource> source;
        Check(factory->CreateInstance(nullptr, IID_PPV_ARGS(&source)) == S_OK && source,
            "fresh DIA source created");
        return source;
    };
    const auto aImage = root / L"fixture-a.exe", bImage = root / L"fixture-b.exe";
    const auto aPdb = root / L"fixture-a.pdb", bPdb = root / L"fixture-b.pdb";
    executable_image::DiskPeMetadata a, b;
    std::wstring error;
    Check(executable_image::ReadDiskPeMetadata(aImage.wstring(), &a, &error) && a.HasPdbIdentity,
        "image A provides expected CodeView identity");
    Check(executable_image::ReadDiskPeMetadata(bImage.wstring(), &b, &error) && b.HasPdbIdentity,
        "image B provides independent CodeView identity");
    const symbol_identity::PdbIdentity expectedA{a.PdbGuid, 0, a.PdbAge};
    const symbol_identity::PdbIdentity expectedB{b.PdbGuid, 0, b.PdbAge};
    Check(expectedA.Valid() && expectedB.Valid() && !expectedA.Matches(expectedB), "fixture PDB identities differ");
    {
        auto source = fresh();
        Check(symbol_identity::LoadMatchingPdb(source.Get(), aPdb.wstring(), expectedA) == S_OK,
            "matching image/PDB identity loads successfully");
    }
    {
        auto source = fresh();
        Check(source && source->loadDataFromPdb(bPdb.c_str()) == S_OK &&
            !symbol_identity::VerifyDiaIdentity(source.Get(), expectedA),
            "unvalidated legacy path accepts an unrelated PDB, reproducing the boundary defect");
    }
    {
        auto source = fresh();
        Check(FAILED(symbol_identity::LoadMatchingPdb(source.Get(), bPdb.wstring(), expectedA)),
            "wrong PDB signature cannot supply target type data");
    }
    {
        auto source = fresh();
        auto wrongAge = expectedA;
        ++wrongAge.Age;
        Check(FAILED(symbol_identity::LoadMatchingPdb(source.Get(), aPdb.wstring(), wrongAge)),
            "wrong PDB age is rejected");
    }
    {
        auto source = fresh();
        Check(source && source->loadDataForExe(aImage.c_str(), root.c_str(), nullptr) == S_OK &&
            symbol_identity::VerifyDiaIdentity(source.Get(), expectedA) &&
            !symbol_identity::VerifyDiaIdentity(source.Get(), expectedB),
            "image-based fallback must also match the previously expected signature");
    }
    const auto replaced = root / L"replaced.pdb";
    Check(CopyFileW(aPdb.c_str(), replaced.c_str(), TRUE) != FALSE, "owned mutable cache path created");
    {
        auto source = fresh();
        Check(symbol_identity::LoadMatchingPdb(source.Get(), replaced.wstring(), expectedA) == S_OK,
            "initial cached PDB matches captured identity");
    }
    Check(CopyFileW(bPdb.c_str(), replaced.c_str(), FALSE) != FALSE, "owned cache entry replaced after the first load");
    {
        auto source = fresh();
        Check(FAILED(symbol_identity::LoadMatchingPdb(source.Get(), replaced.wstring(), expectedA)),
            "replaced cache path cannot reuse previous validation");
    }
    {
        auto source = fresh();
        Check(symbol_identity::LoadMatchingPdb(source.Get(), replaced.wstring(), expectedB) == S_OK,
            "replacement is valid only for its own declared image identity");
    }
    {
        auto source = fresh();
        Check(symbol_identity::LoadMatchingPdb(source.Get(), aPdb.wstring(), {}) == E_INVALIDARG &&
            symbol_identity::LoadMatchingPdb(source.Get(), aPdb.wstring() + std::wstring(1, L'\0') + L"suffix", expectedA) == E_INVALIDARG,
            "missing identity and embedded NUL are rejected before loading");
    }
    IMAGEHLP_MODULEW64 record{};
    record.SymType = SymPdb;
    record.PdbSig70 = expectedA.Guid;
    record.PdbAge = expectedA.Age;
    Check(symbol_identity::FromMatchedModule(record).Matches(expectedA), "matched DbgHelp identity retained");
    record.PdbUnmatched = TRUE;
    Check(!symbol_identity::FromMatchedModule(record).Valid(), "unmatched DbgHelp PDB cannot qualify a DIA load");
    record.PdbUnmatched = FALSE;
    record.DbgUnmatched = TRUE;
    Check(!symbol_identity::FromMatchedModule(record).Valid(), "unmatched DBG cannot qualify a DIA load");
    record.DbgUnmatched = FALSE;
    record.SymType = SymDeferred;
    Check(!symbol_identity::FromMatchedModule(record).Valid(), "deferred metadata is not a validated PDB");
    record.BaseOfImage = 0x140000000;
    record.ImageSize = 0x1000;
    Check(symbol_identity::ModuleRecordMatches(record, 0x140000000, 0x1000) &&
        !symbol_identity::ModuleRecordMatches(record, 0x140010000, 0x1000) &&
        !symbol_identity::ModuleRecordMatches(record, 0x140000000, 0x2000),
        "module base and known image size cannot silently reuse a stale symbol record");
    factory.Reset();
    FreeLibrary(provider);
    CoUninitialize();
    std::cout << "[pdb.identity] passed=" << Passed << " failed=" << Failed << " corpus=synthetic\n";
    return Failed == 0 ? 0 : 1;
}
