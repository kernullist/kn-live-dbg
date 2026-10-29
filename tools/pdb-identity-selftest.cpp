#include "../user/PdbIdentity.h"
#include "../user/ExecutableImage.h"
#include "../user/DiaTypeLayout.h"
#include "../user/TypeSchema.h"
#include "pdb-identity-fixture.h"
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
        ComPtr<IDiaSession> session;
        ComPtr<IDiaSymbol> global;
        ComPtr<IDiaEnumSymbols> types;
        ComPtr<IDiaSymbol> type;
        ULONG fetched = 0;
        Check(source && source->openSession(&session) == S_OK && session &&
            session->get_globalScope(&global) == S_OK && global &&
            global->findChildren(SymTagUDT, L"PdbIdentityFixture", nsCaseSensitive, &types) == S_OK && types &&
            types->Next(1, &type, &fetched) == S_OK && fetched == 1 && type,
            "owned fixture type is available");
        TypeLayoutInfo layout;
        Check(dia_layout::ReadLayout(type.Get(), &layout) && layout.Size == sizeof(PdbIdentityFixture) &&
            layout.FieldsComplete && layout.UnavailableFields == 0, "DIA type size matches compiler layout");
        const auto field = [&](const wchar_t* name) -> const TypeFieldInfo*
        {
            for (const auto& item : layout.Fields)
            {
                if (item.Name == name)
                {
                    return &item;
                }
            }
            return nullptr;
        };
        const auto value = field(L"Value"), flags = field(L"Flags"), reserved = field(L"Reserved");
        const auto nested = field(L"Nested"), pointer = field(L"Next");
        Check(value && !value->IsBitField && value->Offset == offsetof(PdbIdentityFixture, Value) &&
            value->Length == sizeof(PdbIdentityFixture::Value), "ordinary member offset and byte width are exact");
        Check(flags && flags->IsBitField && flags->Length == 3 && flags->BitPosition == 0 &&
            flags->StorageLength == sizeof(unsigned int) && reserved && reserved->IsBitField &&
            reserved->Length == 5 && reserved->BitPosition == 3, "bit widths are distinct from storage byte widths");
        Check(nested && !nested->IsBitField && nested->Length == sizeof(PdbNestedFixture) &&
            nested->Offset == offsetof(PdbIdentityFixture, Nested) && pointer && !pointer->IsBitField &&
            pointer->Length == sizeof(void*) && field(L"StaticValue") == nullptr,
            "embedded types and pointer widths are exact and static data is excluded");
        ComPtr<IDiaEnumSymbols> values;
        ComPtr<IDiaSymbol> rawValue;
        DWORD unavailablePosition = 0;
        fetched = 0;
        Check(type && type->findChildren(SymTagData, L"Value", nsCaseSensitive, &values) == S_OK && values &&
            values->Next(1, &rawValue, &fetched) == S_OK && fetched == 1 && rawValue &&
            rawValue->get_bitPosition(&unavailablePosition) == S_FALSE && SUCCEEDED(S_FALSE),
            "old SUCCEEDED bit-position test accepts an unavailable property");
        TypeFieldInfo rejected;
        Check(dia_layout::ReadMember(rawValue.Get(), 1, &rejected) == dia_layout::MemberState::Unavailable,
            "out-of-bounds member cannot become a typed field");
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
    TypeSchemaPackage package;
    Check(GenerateTypeSchema(aImage.wstring(), aPdb.wstring(), L"PdbIdentityFixture", argv[1], &package, &error),
        "standalone package binds exact input and provider content");
    Check(package.TypeBytes == sizeof(PdbIdentityFixture) && package.PdbAge == a.PdbAge && package.Gaps.empty(),
        "package uses compiler size and does not invent missing fields");
    const TypeSchemaField* nestedCounter = nullptr;
    bool followedPointer = false;
    for (const auto& f : package.Fields)
    {
        if (f.Path == std::vector<std::wstring>{L"Nested", L"Counter"})
        {
            nestedCounter = &f;
        }
        followedPointer = followedPointer || (f.Path.size() > 1 && f.Path.front() == L"Next");
    }
    Check(nestedCounter && nestedCounter->Offset == offsetof(PdbIdentityFixture, Nested) + offsetof(PdbNestedFixture, Counter) &&
        nestedCounter->StorageBytes == sizeof(PdbNestedFixture::Counter) && !followedPointer,
        "nested paths have compiler offsets while pointers remain values");
    const auto json = TypeSchemaJson(package);
    TypeSchemaPackage loaded;
    Check(!json.empty() && ParseTypeSchema(json, &loaded, &error) && TypeSchemaJson(loaded) == json,
        "canonical package survives a DTO round trip");
    const auto saved = root / L"fixture.knschema";
    Check(SaveTypeSchema(saved.wstring(), package, &error) && !SaveTypeSchema(saved.wstring(), package, &error) &&
        LoadTypeSchema(saved.wstring(), &loaded, &error) && TypeSchemaJson(loaded) == json,
        "atomic publication refuses collisions and retains original package");
    auto invalid = package;
    invalid.Fields.front().StorageBytes = UINT64_MAX;
    Check(!ValidateTypeSchema(invalid, nullptr) && TypeSchemaJson(invalid).empty(), "overflowing field extent rejected");
    invalid = package;
    invalid.Fields.push_back(invalid.Fields.front());
    Check(!ValidateTypeSchema(invalid, nullptr), "duplicate field path rejected");
    invalid = package;
    invalid.Fields.front().BitPosition = invalid.Fields.front().StorageBytes * 8;
    invalid.Fields.front().BitWidth = 1;
    Check(!ValidateTypeSchema(invalid, nullptr), "bitfield outside storage rejected");
    invalid = package;
    for (auto& f : invalid.Fields)
    {
        if (f.Path == std::vector<std::wstring>{L"Nested", L"Counter"})
        {
            f.Offset = 0;
        }
    }
    Check(!ValidateTypeSchema(invalid, nullptr), "child outside embedded parent rejected");
    std::wstring changed = json;
    const auto digestStart = changed.find(L"package_sha256\":\"");
    if (digestStart != std::wstring::npos)
    {
        changed[digestStart + 17] = changed[digestStart + 17] == L'a' ? L'b' : L'a';
    }
    Check(!ParseTypeSchema(changed, &loaded, &error), "changed envelope digest rejected");
    Check(!ParseTypeSchema(json + L" ", &loaded, &error) &&
        !ParseTypeSchema(L"{\"unknown\":true," + json.substr(1), &loaded, &error),
        "canonical reader rejects trailing bytes and unknown fields");
    Check(!GenerateTypeSchema(aImage.wstring(), bPdb.wstring(), L"PdbIdentityFixture", argv[1], &loaded, &error),
        "wrong-build PDB cannot generate a schema package");
    Check(!GenerateTypeSchema(aImage.wstring(), aPdb.wstring(), L"MissingType", argv[1], &loaded, &error),
        "missing type cannot generate an empty success package");
    Check(!GenerateTypeSchema(aImage.wstring(), aPdb.wstring(), L"pdbidentityfixture", argv[1], &loaded, &error),
        "type selection preserves exact case");
    Check(!GenerateTypeSchema(aImage.wstring(), aPdb.wstring() + std::wstring(1, L'\0') + L"suffix",
        L"PdbIdentityFixture", argv[1], &loaded, &error), "embedded NUL input path rejected");
    Check(GenerateTypeSchema(aImage.wstring(), aPdb.wstring(), L"PdbDerivedFixture", argv[1], &loaded, &error) &&
        loaded.Fields.size() == 1 && loaded.Fields.front().Offset == sizeof(PdbNestedFixture) &&
        loaded.Gaps.size() == 1 && loaded.Gaps.front().Reason == L"base_classes_not_expanded",
        "inherited layout is explicitly partial, not silently complete");
    Check(GenerateTypeSchema(aImage.wstring(), aPdb.wstring(), L"PdbDepthFixture<10>", argv[1], &loaded, &error) &&
        loaded.Fields.size() == TypeSchemaMaxDepth && loaded.Gaps.size() == 1 &&
        loaded.Gaps.front().Reason == L"depth_limit", "nested value expansion stops at the declared depth cap");
    factory.Reset();
    FreeLibrary(provider);
    CoUninitialize();
    std::cout << "[pdb.identity] passed=" << Passed << " failed=" << Failed << " corpus=synthetic\n";
    return Failed == 0 ? 0 : 1;
}
