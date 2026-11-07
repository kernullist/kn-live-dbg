#include "../user/SymbolEngine.h"
#include "../user/BrokeredTypeLayouts.h"
#include "../user/SymbolArtifactResolver.h"
#include "../user/SymbolArtifactCache.h"
#include "../user/TypeSchemaBroker.h"
#include "../user/ExecutableImage.h"
#include "../user/McpJson.h"
#include "live-type-fixture.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>

struct SymbolEngineTestAccess
{
    static void Module(SymbolEngine& engine, const KernelModuleInfo& module)
    {
        std::lock_guard<std::recursive_mutex> lock(engine.dbghelpMutex_);
        std::lock_guard<std::mutex> modulesLock(engine.modulesMutex_);
        engine.typeLayouts_->Clear();
        engine.modules_ = {module};
    }
};
namespace
{
    unsigned Passed = 0, Failed = 0;
    void Check(bool condition, const char* description)
    {
        if (condition) { ++Passed; }
        else { ++Failed; std::cerr << "[live.type] FAIL " << description << '\n'; }
    }
    std::wstring Executable()
    {
        std::vector<wchar_t> value(32768);
        const auto count = GetModuleFileNameW(nullptr, value.data(), static_cast<DWORD>(value.size()));
        return count != 0 && count < value.size() ? std::wstring(value.data(), count) : L"";
    }
    bool Metadata(const std::filesystem::path& image, executable_image::DiskPeMetadata* metadata)
    {
        SchemaArtifact file;
        return file.Open(image.wstring(), 512ull * 1024 * 1024) &&
            executable_image::ReadDiskPeIdentityHandle(file.Handle(), metadata, nullptr);
    }
    void CacheControls(const std::filesystem::path& root, const std::filesystem::path& pdb, const TypeSchemaPackage& schema)
    {
        const GUID indexed{0x1234abcd, 0x789a, 0xbcde, {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}};
        Check(symbol_artifacts::Index(indexed, 26) == L"1234ABCD789ABCDE0123456789ABCDEF1a", "SymStore GUID and hexadecimal multi-digit age");
        std::filesystem::path path;
        Check(symbol_artifacts::LocalRoot(root.wstring(), &path) && path == root, "local cache root accepted");
        for (const auto text : {L"\\\\server\\symbols", L"//server/symbols", L"\\\\?\\C:\\symbols", L"\\??\\C:\\symbols",
            L"C:relative", L"C:\\symbols:ads", L"C:\\symbols.\\x", L"C:\\symbols \\x", L"C:\\CON.pdb", L"C:\\LPT1\\x", L"C:\\a?b"})
        { Check(!symbol_artifacts::LocalRoot(text, &path) && path.empty(), "unsafe root rejected before probing"); }
        const auto directory = root / L"published";
        const auto destination = directory / L"copy.pdb";
        SchemaArtifact approved;
        Check(approved.Open(pdb.wstring(), 1024ull * 1024 * 1024), "source file lease");
        Check(symbol_artifacts::Publish(approved, destination), "verified lease copied create-new");
        SchemaArtifact published;
        Check(published.Open(destination.wstring(), 1024ull * 1024 * 1024) && published.Sha256 == approved.Sha256,
            "published bytes equal independent source digest");
        Check(!symbol_artifacts::Publish(approved, destination) && published.Unchanged(), "collision preserves existing destination");
        SchemaArtifact missing;
        Check(!symbol_artifacts::Publish(missing, directory / L"failed.pdb") && !std::filesystem::exists(directory / L"failed.pdb"),
            "failed copy deletes only its new object");
        {
            symbol_artifacts::Directories pin;
            Check(pin.Pin(directory, false), "cache ancestors pinned");
            Check(!MoveFileExW(directory.c_str(), (root / L"moved").c_str(), 0), "ancestor rename denied during lease");
        }
        if (std::filesystem::exists(root / L"junction"))
        {
            symbol_artifacts::Directories pin;
            Check(!pin.Pin(root / L"junction", false), "reparse cache ancestor denied");
        }
        const auto empty = root / L"empty-cache";
        {
            symbol_artifacts::Directories pin;
            Check(pin.Pin(empty, true), "empty cache directory created and pinned");
            Check(!MoveFileExW(empty.c_str(), (root / L"moved-empty-cache").c_str(), 0),
                "directory itself denies rename before any child file exists");
        }
        const auto temporary = directory / L"temporary.pdb";
        {
            symbol_artifacts::TemporaryFile file;
            Check(file.Create(temporary.wstring()), "temporary file create-new");
            DWORD written = 0;
            Check(WriteFile(file.File, "owned", 5, &written, nullptr) && written == 5, "temporary bytes written");
            file.Close();
            Check(MoveFileExW(temporary.c_str(), (directory / L"old-owned.pdb").c_str(), 0) != FALSE, "owned temporary replaced in adversarial fixture");
            std::ofstream other(temporary, std::ios::binary); other << "other";
        }
        std::ifstream other(temporary, std::ios::binary);
        const std::string content((std::istreambuf_iterator<char>(other)), {});
        Check(content == "other", "temporary cleanup does not delete replacement");
        const auto removable = directory / L"removable.pdb";
        { symbol_artifacts::TemporaryFile file; Check(file.Create(removable.wstring()), "cleanup fixture created"); }
        Check(!std::filesystem::exists(removable), "owned temporary cleaned");

        BrokeredTypeLayouts cache;
        TypeLayoutInfo layout, byId;
        Check(cache.Insert(1, L"fixture!PdbIdentityFixture", schema, &layout, nullptr), "accepted schema materialized");
        const auto originalId = layout.TypeId;
        Check(layout.Size == sizeof(PdbIdentityFixture) && layout.SchemaPackageSha256.size() == 64, "root compiler size and digest");
        Check(!cache.FindById(2, originalId, L"", &byId), "cross-module ID denied");
        Check(!cache.FindById(1, originalId, L"another", &byId), "mismatched ID name denied");
        for (uint64_t module = 2; module <= 33; ++module)
        { Check(cache.Insert(module, L"fixture!PdbIdentityFixture", schema, &layout, nullptr), "bounded cache insert"); }
        Check(!cache.FindById(1, originalId, L"", &byId), "evicted ID denied");
        const auto laterId = layout.TypeId;
        cache.Clear();
        Check(!cache.FindById(33, laterId, L"", &byId), "cleared ID denied");
        BrokeredTypeLayouts recreated;
        Check(recreated.Insert(33, L"fixture!PdbIdentityFixture", schema, &layout, nullptr) && layout.TypeId > laterId,
            "ID not reused across cache instances");
        auto malformed = schema;
        malformed.Fields.front().StorageBytes = UINT64_MAX;
        Check(!cache.Insert(1, L"fixture!PdbIdentityFixture", malformed, &layout, nullptr) && layout.TypeId == 0,
            "hostile schema bounds do not create a layout");
        malformed = schema; malformed.ParserIsolated = false;
        Check(!cache.Insert(1, L"fixture!PdbIdentityFixture", malformed, &layout, nullptr), "nonisolated provenance rejected");
        TypeSchemaBinding binding{schema.ImageSha256, schema.PdbSha256, schema.ProviderSha256, schema.PdbGuid,
            schema.PdbAge, schema.Machine, schema.ImageSize, L"pdbidentityfixture"};
        TypeSchemaPackage accepted;
        const auto output = mcpjson::WideToUtf8(TypeSchemaJson(schema));
        Check(!AcceptTypeSchemaWorkerOutput(output, binding, &accepted, nullptr), "parent exact-mode type binding");
        binding.AllowTypeAliases = true;
        Check(AcceptTypeSchemaWorkerOutput(output, binding, &accepted, nullptr), "parent live-mode alias binding");
        binding.TypeName = L"DifferentType";
        Check(!AcceptTypeSchemaWorkerOutput(output, binding, &accepted, nullptr) && accepted.TypeName.empty(), "parent rejects unrelated live type");
    }

    void ApiControls(const std::filesystem::path& root)
    {
        const auto image = root / L"fixture-a.exe", pdb = root / L"fixture-a.pdb";
        executable_image::DiskPeMetadata metadata;
        Check(Metadata(image, &metadata), "fixture PE identity");
        SymbolEngine engine;
        std::wstring error;
        Check(engine.Initialize(root.wstring(), &error), "SymbolEngine initialized without image loading");
        constexpr uint64_t base = 0x180000000ull;
        SymbolEngineTestAccess::Module(engine, {base, metadata.SizeOfImage, image.wstring(), L"fixture-a.exe"});
        TypeLayoutInfo layout;
        const bool loaded = engine.GetTypeLayout(L"fixture-a!PdbIdentityFixture", &layout, &error);
        if (!loaded) { std::wcerr << L"[live.type] lookup error=" << error << L'\n'; }
        Check(loaded && layout.Size == sizeof(PdbIdentityFixture), "actual live API matches compiler sizeof");
        if (!loaded) { return; }
        Check(layout.TypeId >= 0x80000000 && layout.SchemaPackageSha256.size() == 64 && layout.FieldsComplete,
            "broker layout carries opaque ID, provenance and coverage");
        const auto originalId = layout.TypeId;
        TypeFieldInfo field;
        Check(engine.FindField(L"fixture-a!PdbIdentityFixture", L"Value", &field, &error) && field.Offset == offsetof(PdbIdentityFixture, Value) &&
            field.StorageLength == sizeof(PdbIdentityFixture::Value), "scalar offset and storage match compiler");
        Check(engine.FindField(L"fixture-a!PdbIdentityFixture", L"nested.counter", &field, &error) &&
            field.Offset == offsetof(PdbIdentityFixture, Nested) + offsetof(PdbNestedFixture, Counter), "nested case-fold path matches compiler");
        PdbIdentityFixture object{}; object.Nested.Counter = 0xfedcba9876543210ull;
        unsigned long long read = 0; SIZE_T bytes = 0;
        Check(ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const uint8_t*>(&object) + field.Offset, &read, sizeof(read), &bytes) &&
            bytes == sizeof(read) && read == object.Nested.Counter, "actual owned memory read through resolved nested offset");
        Check(engine.FindField(L"fixture-a!PdbIdentityFixture", L"Flags", &field, &error) && field.IsBitField && field.Length == 3 &&
            field.BitPosition == 0 && field.StorageLength == sizeof(unsigned int), "bit width is distinct from storage bytes");
        object.Flags = 5;
        unsigned int bits = 0;
        Check(ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const uint8_t*>(&object) + field.Offset, &bits, sizeof(bits), &bytes) &&
            ((bits >> field.BitPosition) & ((1u << field.Length) - 1)) == object.Flags, "actual compiler bitfield read");
        Check(engine.FindField(L"fixture-a!PdbIdentityFixture", L"Nested", &field, &error) && field.ChildTypeId != 0 &&
            engine.GetTypeLayoutById(base, field.ChildTypeId, field.TypeName, &layout, &error) && layout.Size == sizeof(PdbNestedFixture),
            "embedded child resolves without native DIA ID");
        Check(!engine.GetTypeLayoutById(base + 1, field.ChildTypeId, field.TypeName, &layout, &error) && layout.TypeId == 0,
            "actual API denies wrong module ID");
        Check(!engine.FindField(L"fixture-a!PdbIdentityFixture", L"Next.Nested", &field, &error) && field.Name.empty(), "pointer descent denied and output cleared");
        Check(!engine.FindField(L"fixture-a!PdbIdentityFixture", L"Nested..Counter", &field, &error), "empty nested segment denied");
        Check(!engine.FindField(L"fixture-a!PdbIdentityFixture", L"StaticValue", &field, &error), "static member excluded");
        Check(engine.GetTypeLayout(L"fixture-a!livealias", &layout, &error) && layout.Size == sizeof(_LiveAlias), "unique case and underscore type alias");
        Check(engine.FindField(L"fixture-a!livealias", L"Exact", &field, &error) && field.Offset == offsetof(_LiveAlias, Exact), "exact field spelling wins");
        Check(engine.FindField(L"fixture-a!livealias", L"exact", &field, &error) && field.Offset == offsetof(_LiveAlias, exact), "distinct lowercase exact field");
        Check(!engine.FindField(L"fixture-a!livealias", L"EXACT", &field, &error), "ambiguous case-fold field rejected");
        Check(!engine.GetTypeLayout(L"fixture-a!livecollision", &layout, &error), "ambiguous underscore alias rejected");
        Check(engine.GetTypeLayout(L"fixture-a!_LiveCollision", &layout, &error) && layout.Size == sizeof(_LiveCollision), "exact underscored type still resolves");
        Check(engine.GetTypeLayout(L"fixture-a!LiveCollision", &layout, &error) && layout.Size == sizeof(LiveCollision), "exact plain type still resolves");
        Check(engine.GetTypeLayout(L"fixture-a!LiveArray", &layout, &error) && !engine.FindField(L"fixture-a!LiveArray", L"Items.Counter", &field, &error),
            "array elements not treated as embedded objects");
        Check(engine.GetTypeLayout(L"fixture-a!PdbDerivedFixture", &layout, &error) && !layout.FieldsComplete && !layout.UnavailableFieldCountKnown,
            "unexpanded inheritance remains explicit unknown coverage");
        Check(engine.GetTypeLayout(L"fixture-a!PdbDepthFixture<10>", &layout, &error) &&
            !engine.FindField(L"fixture-a!PdbDepthFixture<10>", L"Child.Child.Child.Child.Child.Child.Child.Child.Child", &field, &error),
            "depth bound cannot silently fall back to DIA");
        std::vector<TypeFieldInfo> fields(1); ULONG64 size = 123;
        Check(!engine.GetTypeFields(L"fixture-a!Absent", &fields, &size, &error) && fields.empty() && size == 0, "failed field API clears stale results");
        Check(engine.GetTypeFields(L"fixture-a!PdbIdentityFixture", &fields, &size, &error) && size == sizeof(PdbIdentityFixture) && !fields.empty(),
            "field API compatibility");
        IMAGEHLP_MODULEW64 module{}; module.SizeOfStruct = sizeof(module);
        Check(!SymGetModuleInfoW64(GetCurrentProcess(), base, &module), "type APIs never registered fixture with parent DbgHelp");
        Check(GetModuleHandleW(L"msdia140.dll") == nullptr, "type APIs never loaded DIA into parent");
        engine.SetSymbolPath(root.wstring());
        Check(!engine.GetTypeLayoutById(base, originalId, L"", &layout, &error), "symbol-path reset invalidates IDs");
        Check(engine.GetTypeLayout(L"fixture-a!PdbIdentityFixture", &layout, &error) && layout.TypeId > originalId, "reset requery gets a new ID");
        std::atomic<bool> concurrent{true};
        std::thread reader([&]()
        {
            for (unsigned i = 0; i < 6; ++i)
            {
                TypeFieldInfo result;
                if (!engine.FindField(L"fixture-a!PdbIdentityFixture", L"Nested.Counter", &result, nullptr) ||
                    result.Offset != offsetof(PdbIdentityFixture, Nested) + offsetof(PdbNestedFixture, Counter)) { concurrent = false; }
            }
        });
        std::thread reset([&]() { for (unsigned i = 0; i < 6; ++i) { engine.SetSymbolPath(root.wstring()); } });
        reader.join(); reset.join();
        Check(concurrent, "complete nested API call serializes with cache invalidation");
        const auto savedId = layout.TypeId;
        SymbolEngineTestAccess::Module(engine, {base, metadata.SizeOfImage + 1, image.wstring(), L"fixture-a.exe"});
        Check(!engine.GetTypeLayout(L"fixture-a!PdbIdentityFixture", &layout, &error), "module image size mismatch denied");
        Check(!engine.GetTypeLayoutById(base, savedId, L"", &layout, &error), "module refresh invalidates old IDs");
        SymbolEngineTestAccess::Module(engine, {base, metadata.SizeOfImage, image.wstring(), L"ntoskrnl.exe"});
        Check(engine.GetTypeLayout(L"PdbIdentityFixture", &layout, &error), "unqualified kernel type without parent symbol loading");
        const auto wrong = root / L"wrong-pair";
        std::filesystem::create_directory(wrong);
        std::filesystem::copy_file(image, wrong / L"fixture-a.exe");
        std::filesystem::copy_file(root / L"fixture-b.pdb", wrong / L"fixture-a.pdb");
        engine.SetSymbolPath(wrong.wstring());
        SymbolEngineTestAccess::Module(engine, {base, metadata.SizeOfImage, (wrong / L"fixture-a.exe").wstring(), L"fixture-a.exe"});
        Check(!engine.GetTypeLayout(L"fixture-a!PdbIdentityFixture", &layout, &error) && layout.TypeId == 0, "wrong cached PDB cannot fall back to in-process parsing");
        engine.SetSymbolPath(root.wstring());
        SymbolEngineTestAccess::Module(engine, {base, metadata.SizeOfImage, image.wstring(), L"fixture-a.exe"});
        const auto provider = root / L"msdia140.dll", held = root / L"msdia140-held.dll";
        struct RenameBack
        {
            std::filesystem::path From, To;
            ~RenameBack() { std::error_code ec; std::filesystem::rename(From, To, ec); }
        };
        std::filesystem::rename(provider, held);
        {
            RenameBack restore{held, provider};
            Check(!engine.GetTypeLayout(L"fixture-a!PdbIdentityFixture", &layout, &error) && layout.TypeId == 0,
                "missing installed worker provider does not use parent DIA fallback");
        }
        Check(GetModuleHandleW(L"msdia140.dll") == nullptr, "failed type queries still do not load parent DIA");
        engine.Shutdown();
        TypeSchemaPackage schema;
        Check(GenerateBrokeredTypeSchema(Executable(), image.wstring(), pdb.wstring(), L"PdbIdentityFixture", &schema, &error), "direct broker comparison package");
        if (!schema.Fields.empty()) { CacheControls(root, pdb, schema); }
        Check(!GenerateBrokeredTypeSchema(Executable(), image.wstring(), pdb.wstring(), L"pdbidentityfixture", &schema, &error),
            "offline schema mode retains exact type spelling");
    }

    int KernelLayouts(const wchar_t* image, const wchar_t* cache)
    {
        executable_image::DiskPeMetadata metadata;
        if (!Metadata(image, &metadata)) { return 2; }
        SymbolEngine engine; std::wstring error;
        if (!engine.Initialize(cache, &error)) { return 2; }
        SymbolEngineTestAccess::Module(engine, {0x180000000ull, metadata.SizeOfImage, image, L"ntoskrnl.exe"});
        for (const auto type : {L"nt!_LIST_ENTRY", L"nt!_EPROCESS", L"nt!_ETHREAD", L"nt!_IRP", L"nt!_IO_STACK_LOCATION", L"nt!_DRIVER_OBJECT", L"nt!_DEVICE_OBJECT"})
        {
            TypeLayoutInfo layout;
            const auto ok = engine.GetTypeLayout(type, &layout, &error);
            Check(ok && layout.SchemaPackageSha256.size() == 64, "real cached kernel PDB layout available through isolated API");
            std::wcout << type << L" available=" << ok << L" size=" << layout.Size << L" fields=" << layout.Fields.size()
                << L" complete=" << layout.FieldsComplete << L" error=" << error << L'\n';
        }
        TypeFieldInfo field;
        Check(engine.FindField(L"nt!_LIST_ENTRY", L"Blink", &field, &error) && field.Offset == offsetof(LIST_ENTRY, Blink),
            "kernel LIST_ENTRY matches SDK compiler layout");
        Check(engine.FindField(L"nt!_EPROCESS", L"Pcb.DirectoryTableBase", &field, &error), "kernel embedded process field available");
        Check(GetModuleHandleW(L"msdia140.dll") == nullptr, "real kernel type APIs leave parent DIA unloaded");
        std::cout << "[live.type.kernel] passed=" << Passed << " failed=" << Failed << '\n';
        return Failed == 0 ? 0 : 1;
    }
}
int wmain(int argc, wchar_t** argv)
{
    if (argc > 1 && (std::wstring(argv[1]) == L"--schema-worker" || std::wstring(argv[1]) == L"--schema-live-worker"))
    { return RunTypeSchemaWorkerCommand(argc, argv); }
    if (argc == 4 && std::wstring(argv[1]) == L"--fetch-kernel")
    {
        executable_image::DiskPeMetadata metadata;
        TypeSchemaPackage package; std::wstring error;
        if (!Metadata(argv[2], &metadata) || !ResolveBrokeredTypeSchema(Executable(), argv[2], metadata.SizeOfImage,
            L"SRV*" + std::wstring(argv[3]) + L"*https://msdl.microsoft.com/download/symbols", L"_LIST_ENTRY", &package, &error))
        { std::wcerr << error << L'\n'; return 1; }
        std::cout << mcpjson::WideToUtf8(TypeSchemaJson(package));
        return 0;
    }
    if (argc == 4 && std::wstring(argv[1]) == L"--kernel-layouts") { return KernelLayouts(argv[2], argv[3]); }
    if (argc == 4 && std::wstring(argv[1]) == L"--worker-executable")
    {
        const auto root = std::filesystem::path(argv[3]);
        const auto binary = root / L"KnLiveDbg.exe";
        const auto fixture = std::filesystem::path(argv[2]);
        TypeSchemaPackage package; std::wstring error;
        Check(GenerateBrokeredTypeSchema(binary.wstring(), (fixture / L"fixture-a.exe").wstring(),
            (fixture / L"fixture-a.pdb").wstring(), L"pdbidentityfixture", &package, &error, 60000, nullptr, true) &&
            package.TypeName == L"PdbIdentityFixture" && package.TypeBytes == sizeof(PdbIdentityFixture), "actual Release live worker dispatcher and alias mode");
        if (!error.empty()) { std::wcerr << error << L'\n'; }
        Check(!GenerateBrokeredTypeSchema(binary.wstring(), (fixture / L"fixture-a.exe").wstring(),
            (fixture / L"fixture-b.pdb").wstring(), L"PdbIdentityFixture", &package, &error, 60000, nullptr, true) && package.Fields.empty(),
            "actual Release live worker rejects mismatched PDB");
        std::cout << "[live.type.release-worker] passed=" << Passed << " failed=" << Failed << '\n';
        return Failed == 0 ? 0 : 1;
    }
    if (argc != 2) { return 2; }
    ApiControls(std::filesystem::absolute(argv[1]));
    std::cout << "[live.type] passed=" << Passed << " failed=" << Failed << '\n';
    return Failed == 0 ? 0 : 1;
}
