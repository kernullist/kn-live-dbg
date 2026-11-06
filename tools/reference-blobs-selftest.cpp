#include "../user/ReferenceArtifact.h"
#include "../user/ContentHash.h"
#include "../user/McpJson.h"
#include <filesystem>
#include <fstream>
#include <iostream>

namespace
{
    unsigned Checks = 0, Failures = 0;
    void Check(bool pass, const char* label)
    {
        ++Checks;
        if (!pass) { ++Failures; std::cerr << "FAIL " << label << "\n"; }
    }
    bool Write(const std::filesystem::path& path, const std::vector<uint8_t>& data)
    {
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
        out.close();
        return !out.fail();
    }
    bool WriteDenied(const std::filesystem::path& path)
    {
        HANDLE writer = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, 0, nullptr);
        const auto error = GetLastError();
        if (writer != INVALID_HANDLE_VALUE) { CloseHandle(writer); }
        return writer == INVALID_HANDLE_VALUE && error == ERROR_SHARING_VIOLATION;
    }
    auto Owner(HANDLE file)
    {
        return std::unique_ptr<void, decltype(&CloseHandle)>(file == INVALID_HANDLE_VALUE ? nullptr : file, &CloseHandle);
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc != 2) { return 2; }
    std::error_code ec;
    const auto root = std::filesystem::absolute(argv[1], ec);
    if (ec || !std::filesystem::create_directory(root, ec) || ec) { return 2; }
    try
    {
        const std::vector<uint8_t> original(512, 0x51), replacement(512, 0x42);
        const auto path = root / L"original.bin", moved = root / L"renamed.bin";
        Check(Write(path, original), "write-owned-original");
        auto source = Owner(CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, nullptr));
        Check(source != nullptr, "open-original-object");
        LARGE_INTEGER offset{}; offset.QuadPart = 17;
        Check(SetFilePointerEx(source.get(), offset, nullptr, FILE_BEGIN) != FALSE, "set-caller-read-position");
        Check(MoveFileExW(path.c_str(), moved.c_str(), 0) && Write(path, replacement), "replace-old-path-with-another-object");
        std::shared_ptr<const RetainedReferenceArtifact> snapshot;
        {
            ReferenceArtifact pinned;
            Check(pinned.OpenHandle(source.get(), nullptr), "reopen-exact-object-without-old-path-resolution");
            Check(pinned.Bytes() == original && pinned.Sha256() == ContentHash::Bytes(original) &&
                pinned.Path() == moved.wstring() && pinned.Unchanged(), "captured-reference-is-original-object");
            LARGE_INTEGER zero{}, position{};
            Check(SetFilePointerEx(source.get(), zero, &position, FILE_CURRENT) && position.QuadPart == 17,
                "artifact-acquisition-does-not-change-caller-file-pointer");
            Check(WriteDenied(moved), "source-object-write-lease-enforced");
            snapshot = pinned.Snapshot();
            Check(snapshot != nullptr && &snapshot->Bytes == &pinned.Bytes() && !snapshot->OriginalFileIdentity.empty(),
                "snapshot-shares-immutable-bytes-without-copy");
        }
        source.reset();
        Check(DeleteFileW(moved.c_str()) && snapshot != nullptr && snapshot->Bytes == original,
            "snapshot-survives-source-deletion-without-source-handle");
        if (snapshot == nullptr) { throw std::runtime_error("missing snapshot"); }
        std::unique_ptr<ReferenceArtifact> stored;
        bool created = false;
        std::wstring error;
        const auto store = root / L"cas";
        Check(PublishReferenceBlob(store.wstring(), *snapshot, original.size(), &stored, &created, &error) && created &&
            stored != nullptr && stored->Bytes() == original, "publish-exact-retained-object");
        const auto blob = store / (snapshot->Sha256 + L".knblob");
        Check(WriteDenied(blob), "verified-blob-lease-pins-referring-publication");
        stored.reset();
        Check(PublishReferenceBlob(store.wstring(), *snapshot, 0, &stored, &created, &error) && !created && stored != nullptr,
            "verified-existing-blob-reused-at-zero-new-byte-budget");
        stored.reset();
        Check(!PublishReferenceBlob((root / L"budget").wstring(), *snapshot, 0, &stored, &created, &error) && !created &&
            error == L"reference_store_byte_budget" && !std::filesystem::exists(root / L"budget"), "new-blob-budget-no-publication");
        auto forged = *snapshot;
        forged.Sha256[0] = forged.Sha256[0] == L'a' ? L'b' : L'a';
        Check(!PublishReferenceBlob(store.wstring(), forged, UINT64_MAX, &stored, &created, &error) && !stored && !created,
            "declared-hash-is-not-trusted");
        Check(Write(blob, replacement), "replace-owned-blob-with-corrupt-control");
        Check(!PublishReferenceBlob(store.wstring(), *snapshot, UINT64_MAX, &stored, &created, &error) && !stored && !created &&
            error == L"reference_store_existing_blob_unverified" && ContentHash::File(blob.wstring()) == ContentHash::Bytes(replacement),
            "corrupt-existing-blob-is-rejected-and-preserved");
        {
            ReferenceArtifact bounded;
            Check(!bounded.Open(path.wstring(), nullptr, original.size() - 1) && bounded.Snapshot() == nullptr,
                "oversize-reference-has-no-partial-snapshot");
        }
        auto writer = Owner(CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, 0, nullptr));
        ReferenceArtifact incompatible;
        Check(writer != nullptr && !incompatible.OpenHandle(writer.get(), nullptr) && incompatible.Snapshot() == nullptr,
            "existing-writer-prevents-stability-lease");
        writer.reset();
        auto nullDevice = Owner(CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr));
        ReferenceArtifact device, invalid;
        Check(nullDevice != nullptr && !device.OpenHandle(nullDevice.get(), nullptr) && !invalid.OpenHandle(INVALID_HANDLE_VALUE, nullptr),
            "non-file-and-invalid-handles-denied");
        {
            auto writable = Owner(CreateFileW(path.c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, 0, nullptr));
            auto section = Owner(writable ? CreateFileMappingW(writable.get(), nullptr, PAGE_READWRITE, 0, 0, nullptr) : nullptr);
            void* view = section ? MapViewOfFile(section.get(), FILE_MAP_WRITE, 0, 0, 0) : nullptr;
            const std::unique_ptr<void, decltype(&UnmapViewOfFile)> mapping(view, &UnmapViewOfFile);
            writable.reset();
            Check(mapping != nullptr, "owned-existing-mapped-writer-control");
            ReferenceArtifact captured;
            const bool ready = mapping && captured.Open(path.wstring(), nullptr);
            const auto leaseError = GetLastError();
            Check(mapping != nullptr && !ready && leaseError == ERROR_SHARING_VIOLATION && captured.Snapshot() == nullptr,
                "existing-writable-view-denies-stability-lease-before-capture");
        }
        std::cout << "{\"original_sha256\":" << mcpjson::WideToUtf8(mcpjson::Quote(snapshot->Sha256)) <<
            ",\"retained_bytes\":" << snapshot->Bytes.size() << ",\"retained_byte\":" << unsigned(snapshot->Bytes[0]) <<
            ",\"replacement_sha256\":" << mcpjson::WideToUtf8(mcpjson::Quote(ContentHash::Bytes(replacement))) << "}\n";
    }
    catch (const std::exception&) { Check(false, "reference-store-fixture-exception"); }
    // Only this invocation's exclusively created absolute directory is removed.
    std::filesystem::remove_all(root, ec);
    Check(!ec && !std::filesystem::exists(root), "owned-files-handles-and-temporaries-cleaned");
    std::cerr << "Reference blob checks=" << Checks << " failed=" << Failures << "\n";
    return Failures ? 1 : 0;
}
