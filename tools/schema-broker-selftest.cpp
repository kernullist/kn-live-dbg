#include "../user/TypeSchemaBroker.h"
#include "../user/SchemaArtifact.h"
#include "../user/SchemaReadStream.h"
#include "../user/ExecutableImage.h"
#include "../user/McpJson.h"
#include "../user/ParserWorkerProcess.h"
#include "pdb-identity-fixture.h"
#include <wrl/client.h>
#include <filesystem>
#include <iostream>
#include <thread>

using Microsoft::WRL::ComPtr;
namespace
{
    unsigned Passed = 0, Failed = 0;
    void Check(bool value, const char* description)
    {
        if (value) { ++Passed; }
        else { ++Failed; std::cerr << "[schema.broker] FAIL " << description << "\n"; }
    }
    std::string Bytes(const TypeSchemaPackage& p) { return mcpjson::WideToUtf8(TypeSchemaJson(p)); }
    TypeSchemaBinding Binding(const TypeSchemaPackage& p)
    {
        return {p.ImageSha256, p.PdbSha256, p.ProviderSha256, p.PdbGuid, p.PdbAge, p.Machine, p.ImageSize, p.TypeName};
    }
    bool Write(const std::string& output)
    {
        DWORD count = 0;
        return WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), output.data(), static_cast<DWORD>(output.size()), &count, nullptr) &&
            count == output.size();
    }
    int Worker(int argc, wchar_t** argv)
    {
        if (argc != 6 || !IsRestrictedParserWorker()) { return 91; }
        const std::wstring type = argv[2];
        if (type.rfind(L"__broker_", 0) != 0) { return RunTypeSchemaWorkerCommand(argc, argv); }
        if (type == L"__broker_hang") { Sleep(INFINITE); return 92; }
        if (type == L"__broker_exit") { Write("partial"); return 17; }
        if (type == L"__broker_flood")
        {
            const std::string block(8192, 'x');
            while (Write(block)) {}
            return 93;
        }
        HANDLE files[3]{};
        for (size_t i = 0; i < 3; ++i) { files[i] = reinterpret_cast<HANDLE>(_wcstoui64(argv[3 + i], nullptr, 10)); }
        TypeSchemaPackage p;
        if (!GenerateTypeSchemaFromHandles(files[0], files[1], files[2], L"PdbIdentityFixture", &p, nullptr)) { return 94; }
        p.ParserIsolated = true;
        p.TypeName = type;
        if (type == L"__broker_hash") { p.ImageSha256 = std::wstring(64, L'a'); }
        else if (type == L"__broker_pdb") { p.PdbSha256 = std::wstring(64, L'b'); }
        else if (type == L"__broker_provider") { p.ProviderSha256 = std::wstring(64, L'c'); }
        else if (type == L"__broker_guid") { p.PdbGuid = std::wstring(32, L'd'); }
        else if (type == L"__broker_age") { ++p.PdbAge; }
        else if (type == L"__broker_size") { ++p.ImageSize; }
        else if (type == L"__broker_type") { p.TypeName = L"AnotherType"; }
        else if (type == L"__broker_isolation") { p.ParserIsolated = false; }
        else if (type == L"__broker_readonly")
        {
            for (const auto file : files)
            {
                DWORD written = 0;
                if (WriteFile(file, "x", 1, &written, nullptr) || written != 0) { return 95; }
                HANDLE writer = ReOpenFile(file, GENERIC_WRITE, FILE_SHARE_READ, 0);
                if (writer != INVALID_HANDLE_VALUE) { CloseHandle(writer); return 96; }
            }
        }
        else { return 97; }
        return Write(Bytes(p)) ? 0 : 98;
    }

    void StreamControls(const std::filesystem::path& image)
    {
        SchemaArtifact file;
        Check(file.Open(image.wstring(), 512ull * 1024 * 1024), "approved image lease");
        LARGE_INTEGER initial{};
        initial.QuadPart = 17;
        Check(SetFilePointerEx(file.Handle(), initial, nullptr, FILE_BEGIN) != FALSE, "parent cursor sentinel");
        ComPtr<IStream> stream, clone;
        Check(SchemaReadStream::Create(file.Handle(), &stream) == S_OK && stream, "stream from approved file object");
        if (!stream) { return; }
        char signature[2]{};
        ULONG read = 0;
        Check(stream->Read(signature, 2, &read) == S_OK && read == 2 && signature[0] == 'M' && signature[1] == 'Z',
            "independent PE header oracle");
        LARGE_INTEGER zero{}, position{};
        Check(SetFilePointerEx(file.Handle(), zero, &position, FILE_CURRENT) && position.QuadPart == 17,
            "DIA stream does not move parent cursor");
        Check(stream->Clone(&clone) == S_OK && clone, "clone preserves logical cursor");
        Check(stream->Seek(zero, STREAM_SEEK_SET, nullptr) == S_OK, "seek beginning");
        ULARGE_INTEGER current{};
        Check(clone && clone->Seek(zero, STREAM_SEEK_CUR, &current) == S_OK && current.QuadPart == 2,
            "clone cursor is independent");
        LARGE_INTEGER negative{};
        negative.QuadPart = INT64_MIN;
        Check(stream->Seek(negative, STREAM_SEEK_CUR, nullptr) == STG_E_INVALIDFUNCTION, "minimum signed seek denied");
        LARGE_INTEGER maximum{};
        maximum.QuadPart = INT64_MAX;
        Check(stream->Seek(maximum, STREAM_SEEK_SET, nullptr) == S_OK, "maximum positive cursor representable");
        LARGE_INTEGER one{};
        one.QuadPart = 1;
        Check(stream->Seek(one, STREAM_SEEK_CUR, nullptr) == STG_E_INVALIDFUNCTION, "seek overflow denied");
        Check(stream->Read(signature, 2, &read) == S_FALSE && read == 0, "EOF read is empty");
        Check(stream->Read(nullptr, 0, &read) == S_OK && read == 0, "zero-byte read");
        Check(stream->Read(nullptr, 1, &read) == STG_E_INVALIDPOINTER, "null nonempty read denied");
        Check(stream->Seek(zero, 99, nullptr) == STG_E_INVALIDFUNCTION, "unknown seek origin denied");
        Check(stream->Write(signature, 2, &read) == STG_E_ACCESSDENIED && read == 0 &&
            stream->SetSize({}) == STG_E_ACCESSDENIED, "write and truncate denied");
        STATSTG stat{};
        Check(stream->Stat(&stat, STATFLAG_NONAME) == S_OK && stat.cbSize.QuadPart == file.Bytes() &&
            stat.grfMode == STGM_READ && stat.pwcsName == nullptr, "stat retains bounded size without path");
        std::atomic<bool> same{true};
        const auto reader = [&](IStream* value)
        {
            for (unsigned i = 0; i < 100; ++i)
            {
                char magic[2]{};
                ULONG count = 0;
                if (value->Seek(zero, STREAM_SEEK_SET, nullptr) != S_OK || value->Read(magic, 2, &count) != S_OK ||
                    count != 2 || magic[0] != 'M' || magic[1] != 'Z') { same = false; }
            }
        };
        if (clone)
        {
            std::thread a(reader, stream.Get()), b(reader, clone.Get());
            a.join(); b.join();
            Check(same, "concurrent clones preserve independent bytes");
        }
        executable_image::DiskPeMetadata metadata, byPath;
        Check(executable_image::ReadDiskPeMetadataHandle(file.Handle(), &metadata, nullptr) &&
            executable_image::ReadDiskPeMetadata(image.wstring(), &byPath, nullptr) && metadata.PdbAge == byPath.PdbAge &&
            std::memcmp(&metadata.PdbGuid, &byPath.PdbGuid, sizeof(GUID)) == 0 && metadata.SizeOfImage == byPath.SizeOfImage,
            "handle PE parser matches legacy path metadata");
        executable_image::DiskPeMetadata identity;
        Check(executable_image::ReadDiskPeIdentityHandle(file.Handle(), &identity, nullptr) &&
            identity.PdbAge == byPath.PdbAge && identity.HasPdbIdentity && identity.Machine == byPath.Machine &&
            std::memcmp(&identity.PdbGuid, &byPath.PdbGuid, sizeof(GUID)) == 0 && identity.SizeOfImage == byPath.SizeOfImage &&
            identity.BaserelocRva == 0 && identity.BaserelocSize == 0 && identity.DynamicRelocationRanges.empty() &&
            !identity.BaseRelocationTableComplete && !identity.DynamicRelocationTableComplete,
            "parent identity decoder stops before relocation facts");
        HANDLE writer = CreateFileW(image.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        Check(writer == INVALID_HANDLE_VALUE, "broker lease excludes concurrent writers");
        if (writer != INVALID_HANDLE_VALUE) { CloseHandle(writer); }
        Check(!DeleteFileW(image.c_str()), "broker lease excludes deletion");
        Check(file.Unchanged(), "original image survives controls");
        const auto directory = image.parent_path() / (L"owned-pin-" + std::to_wstring(GetCurrentProcessId()));
        const auto destination = image.parent_path() / (L"owned-pin-moved-" + std::to_wstring(GetCurrentProcessId()));
        const bool created = std::filesystem::create_directory(directory);
        Check(created && directory.parent_path() == image.parent_path() && destination.parent_path() == image.parent_path(),
            "pathname control owns both fixture-local directory paths");
        if (created)
        {
            const auto copy = directory / L"owned-image.exe";
            const bool copied = CopyFileW(image.c_str(), copy.c_str(), TRUE) != FALSE;
            SchemaArtifact pinned;
            const bool locked = copied && pinned.Open(copy.wstring(), 512ull * 1024 * 1024) && pinned.PinPath();
            Check(locked, "provider-style pathname can be pinned");
            if (locked)
            {
                Check(!MoveFileExW(directory.c_str(), destination.c_str(), 0), "pinned provider ancestor cannot be renamed");
                Check(pinned.Unchanged(), "pathname control preserves original file");
            }
        }
    }

    void OutputControls(const TypeSchemaPackage& original)
    {
        const auto expected = Binding(original);
        TypeSchemaPackage accepted;
        std::wstring error;
        Check(AcceptTypeSchemaWorkerOutput(Bytes(original), expected, &accepted, &error), "exact broker result accepted");
        for (unsigned i = 0; i < 9; ++i)
        {
            auto changed = expected;
            if (i == 0) { changed.ImageSha256 = std::wstring(64, L'a'); }
            if (i == 1) { changed.PdbSha256 = std::wstring(64, L'b'); }
            if (i == 2) { changed.ProviderSha256 = std::wstring(64, L'c'); }
            if (i == 3) { changed.PdbGuid = std::wstring(32, L'd'); }
            if (i == 4) { ++changed.PdbAge; }
            if (i == 5) { changed.Machine = IMAGE_FILE_MACHINE_I386; }
            if (i == 6) { ++changed.ImageSize; }
            if (i == 7) { changed.TypeName = L"another"; }
            if (i == 8) { changed.PdbGuid.clear(); }
            accepted = original;
            Check(!AcceptTypeSchemaWorkerOutput(Bytes(original), changed, &accepted, &error) &&
                accepted.TypeName.empty() && !error.empty(), "identity mismatch removes stale result");
        }
        for (const auto& text : {std::string(), std::string("{}"), Bytes(original) + " ",
            Bytes(original) + std::string("\xff"), std::string(TypeSchemaMaxBytes + 1, 'x')})
        {
            Check(!AcceptTypeSchemaWorkerOutput(text, expected, &accepted, &error), "malformed worker DTO denied");
        }
        auto changed = original;
        changed.ParserIsolated = false;
        Check(!AcceptTypeSchemaWorkerOutput(Bytes(changed), expected, &accepted, &error), "unisolated result denied");
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc >= 2 && std::wstring(argv[1]) == L"--schema-worker") { return Worker(argc, argv); }
    if (argc != 2) { return 2; }
    const std::filesystem::path root = argv[1];
    const auto image = root / L"fixture-a.exe", pdb = root / L"fixture-a.pdb";
    const auto executable = std::filesystem::absolute(argv[0]).wstring();
    TypeSchemaPackage package;
    std::wstring error;
    const bool generated = GenerateBrokeredTypeSchema(executable, image.wstring(), pdb.wstring(), L"PdbIdentityFixture", &package, &error);
    if (!generated) { std::wcerr << L"[schema.broker] " << error << L"\n"; }
    Check(generated, "actual handle worker generates owned fixture schema");
    if (!generated) { return 1; }
    Check(package.TypeBytes == sizeof(PdbIdentityFixture), "compiler sizeof independently matches root size");
    const auto offset = [&](const std::vector<std::wstring>& path, size_t expected, size_t size)
    {
        const auto f = std::find_if(package.Fields.begin(), package.Fields.end(), [&](const auto& row) { return row.Path == path; });
        Check(f != package.Fields.end() && f->Offset == expected && f->StorageBytes == size, "compiler offsetof and sizeof match field");
    };
    offset({L"Value"}, offsetof(PdbIdentityFixture, Value), sizeof(PdbIdentityFixture::Value));
    offset({L"Nested", L"Counter"}, offsetof(PdbIdentityFixture, Nested) + offsetof(PdbNestedFixture, Counter), sizeof(PdbNestedFixture::Counter));
    offset({L"Next"}, offsetof(PdbIdentityFixture, Next), sizeof(PdbIdentityFixture::Next));
    PdbIdentityFixture owned{};
    owned.Value = 0x1122334455667788ull;
    const auto field = std::find_if(package.Fields.begin(), package.Fields.end(), [](const auto& f) { return f.Path == std::vector<std::wstring>{L"Value"}; });
    uint64_t readValue = 0;
    SIZE_T read = 0;
    Check(field != package.Fields.end() && ReadProcessMemory(GetCurrentProcess(),
        reinterpret_cast<const uint8_t*>(&owned) + field->Offset, &readValue, sizeof(readValue), &read) &&
        read == sizeof(readValue) && readValue == owned.Value, "owned object read agrees with compiler value");
    OutputControls(package);
    StreamControls(image);
    for (const auto* type : {L"__broker_hash", L"__broker_pdb", L"__broker_provider", L"__broker_guid", L"__broker_age",
        L"__broker_size", L"__broker_type", L"__broker_isolation", L"__broker_exit", L"__broker_flood", L"MissingType"})
    {
        TypeSchemaPackage rejected = package;
        Check(!GenerateBrokeredTypeSchema(executable, image.wstring(), pdb.wstring(), type, &rejected, &error) &&
            rejected.TypeName.empty() && !error.empty(), "actual hostile worker cannot return a usable schema");
    }
    TypeSchemaPackage rejected;
    Check(!GenerateBrokeredTypeSchema(executable, image.wstring(), (root / L"fixture-b.pdb").wstring(),
        L"PdbIdentityFixture", &rejected, &error), "wrong-build PDB denied through stream identity check");
    Check(!GenerateBrokeredTypeSchema(executable, image.wstring(), pdb.wstring(), L"__broker_hang", &rejected, &error, 500) &&
        error.find(L"timeout") != std::wstring::npos, "hanging child returns no schema");
    Check(GenerateBrokeredTypeSchema(executable, image.wstring(), pdb.wstring(), L"__broker_readonly", &rejected, &error),
        "all inherited artifact handles deny writes and writable reopens");
    std::atomic<bool> cancelled{true};
    Check(!GenerateBrokeredTypeSchema(executable, image.wstring(), pdb.wstring(), L"PdbIdentityFixture", &rejected, &error,
        60000, &cancelled) && rejected.TypeName.empty(), "pre-cancelled broker cannot reuse stale result");
    Check(!GenerateBrokeredTypeSchema(executable, image.wstring(), pdb.wstring(), L"PdbIdentityFixture", &rejected, &error, 0),
        "zero worker budget denied");
    Check(!GenerateBrokeredTypeSchema(executable, image.wstring() + L":alternate", pdb.wstring(), L"PdbIdentityFixture", &rejected, &error),
        "alternate stream input denied");
    ParserWorkerRequest invalid;
    invalid.Executable = executable;
    invalid.Arguments = {L"--schema-worker", L"PdbIdentityFixture"};
    for (const auto handle : {static_cast<HANDLE>(nullptr), INVALID_HANDLE_VALUE, GetCurrentProcess()})
    {
        invalid.ReadOnlyFiles = {handle};
        const auto result = RunParserWorker(invalid);
        Check(result.Status == L"invalid_request" && result.ProcessId == 0 && result.Output.empty(),
            "invalid or non-file artifact handle cannot spawn a worker");
    }
    invalid.ReadOnlyFiles = {nullptr, nullptr, nullptr, nullptr};
    Check(RunParserWorker(invalid).Status == L"invalid_request", "artifact handle count bounded");
    HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    invalid.ReadOnlyFiles = {event};
    const auto notFile = RunParserWorker(invalid);
    Check(event != nullptr && notFile.Status == L"invalid_request" && notFile.ProcessId == 0,
        "valid non-file handle cannot enter artifact allowlist");
    if (event != nullptr) { CloseHandle(event); }
    SchemaArtifact undersized;
    Check(!undersized.Open(image.wstring(), 1), "broker rejects a file exceeding its approved byte budget");
    SchemaArtifact afterImage, afterPdb;
    Check(afterImage.Open(image.wstring(), 512ull * 1024 * 1024) && afterPdb.Open(pdb.wstring(), 1024ull * 1024 * 1024) &&
        afterImage.Sha256 == package.ImageSha256 && afterPdb.Sha256 == package.PdbSha256, "all failure controls preserve original files");
    std::cout << "[schema.broker] passed=" << Passed << " failed=" << Failed << "\n";
    return Failed == 0 ? 0 : 1;
}
