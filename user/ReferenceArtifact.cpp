#include "ReferenceArtifact.h"
#include "ContentHash.h"
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <memory>
#include <winternl.h>

namespace
{
    constexpr DWORD ResidentFileAccess = FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE;

    template<typename Function>
    Function NativeFileFunction(const char* name)
    {
        const auto entry = GetProcAddress(GetModuleHandleW(L"ntdll.dll"), name);
        Function function = nullptr;
        static_assert(sizeof(function) == sizeof(entry));
        std::memcpy(&function, &entry, sizeof(function));
        return function;
    }

    std::wstring LocalPath(const std::wstring& path)
    {
        if (path.empty() || path.size() > 30000 || path.find(L'\0') != std::wstring::npos ||
            path.rfind(L"\\\\", 0) == 0 || path.rfind(L"\\??\\", 0) == 0)
        {
            return L"";
        }
        std::error_code error;
        auto absolute = std::filesystem::absolute(path, error).wstring();
        return !error && absolute.size() > 3 && absolute.size() <= 30000 && absolute[1] == L':' &&
            absolute.find(L':', 2) == std::wstring::npos ? absolute : L"";
    }

    bool OnLocalDevice(HANDLE file)
    {
        using QueryFile = NTSTATUS (NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
        const auto queryFile = NativeFileFunction<QueryFile>("NtQueryInformationFile");
        constexpr ULONG fileIsRemoteDeviceInformation = 51; // WDK FILE_INFORMATION_CLASS, answered by the I/O manager.
        IO_STATUS_BLOCK result{};
        BOOLEAN remote = TRUE;
        return queryFile && queryFile(file, &result, &remote, sizeof(remote), fileIsRemoteDeviceInformation) == 0 &&
            result.Information == sizeof(remote) && !remote;
    }

    bool ResidentLocalDiskFile(HANDLE file)
    {
        if (file == nullptr || file == INVALID_HANDLE_VALUE) { return false; }
        // Reopening under the process token must not upgrade an inherited
        // metadata-only handle. Reject remote devices before filesystem queries.
        const auto query = NativeFileFunction<decltype(&NtQueryObject)>("NtQueryObject");
        PUBLIC_OBJECT_BASIC_INFORMATION access{};
        if (!query || query(file, ObjectBasicInformation, &access, sizeof(access), nullptr) != 0 ||
            (access.GrantedAccess & ResidentFileAccess) != ResidentFileAccess) { return false; }
        if (!OnLocalDevice(file) || GetFileType(file) != FILE_TYPE_DISK) { return false; }
        std::wstring path(32768, L'\0');
        const DWORD size = GetFinalPathNameByHandleW(file, path.data(), static_cast<DWORD>(path.size()),
            FILE_NAME_OPENED | VOLUME_NAME_GUID);
        if (size == 0 || size >= path.size()) { return false; }
        path.resize(size);
        const auto volumeEnd = path.find(L"}\\");
        if (path.rfind(L"\\\\?\\Volume{", 0) != 0 || volumeEnd == std::wstring::npos ||
            volumeEnd + 2 >= path.size() || path.find(L':') != std::wstring::npos ||
            GetDriveTypeW(path.substr(0, volumeEnd + 2).c_str()) != DRIVE_FIXED) { return false; }
        FILE_ATTRIBUTE_TAG_INFO tag{};
        constexpr DWORD excluded = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT |
            FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
        return GetFileInformationByHandleEx(file, FileAttributeTagInfo, &tag, sizeof(tag)) &&
            (tag.FileAttributes & excluded) == 0;
    }

    std::wstring Hex(const uint8_t* bytes, size_t size)
    {
        std::wstring text;
        for (size_t i = 0; i < size; ++i)
        {
            text += L"0123456789abcdef"[bytes[i] >> 4];
            text += L"0123456789abcdef"[bytes[i] & 15];
        }
        return text;
    }

    bool Read(HANDLE file, std::vector<uint8_t>* bytes, size_t maximumBytes, const std::atomic<bool>* stop = nullptr)
    {
        if (stop != nullptr && stop->load()) { SetLastError(ERROR_OPERATION_ABORTED); return false; }
        LARGE_INTEGER size{}, zero{};
        if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 ||
            static_cast<uint64_t>(size.QuadPart) > (std::min)(maximumBytes, ReferenceArtifactMaxBytes) ||
            !SetFilePointerEx(file, zero, nullptr, FILE_BEGIN))
        {
            return false;
        }
        bytes->resize(static_cast<size_t>(size.QuadPart));
        size_t offset = 0;
        const uint64_t started = GetTickCount64();
        while (offset < bytes->size())
        {
            if (stop != nullptr && stop->load())
            { bytes->clear(); SetLastError(ERROR_OPERATION_ABORTED); return false; }
            DWORD received = 0;
            const DWORD count = static_cast<DWORD>((std::min)(bytes->size() - offset, size_t{65536}));
            if (GetTickCount64() - started > 30000 || !ReadFile(file, bytes->data() + offset, count, &received, nullptr) ||
                received != count)
            {
                bytes->clear();
                return false;
            }
            offset += received;
        }
        LARGE_INTEGER finalSize{};
        return GetFileSizeEx(file, &finalSize) && finalSize.QuadPart == size.QuadPart;
    }
}

bool DistinctLocalFileHandles(HANDLE input, HANDLE output)
{
    FILE_ID_INFO sourceId{}, sinkId{};
    return OnLocalDevice(input) && OnLocalDevice(output) &&
        GetFileInformationByHandleEx(input, FileIdInfo, &sourceId, sizeof(sourceId)) &&
        GetFileInformationByHandleEx(output, FileIdInfo, &sinkId, sizeof(sinkId)) &&
        std::memcmp(&sourceId, &sinkId, sizeof(sourceId)) != 0;
}

ReferenceArtifact::~ReferenceArtifact()
{
    if (File != INVALID_HANDLE_VALUE)
    {
        CloseHandle(File);
    }
}

bool ReferenceArtifact::Open(const std::wstring& path, std::wstring* error, size_t maximumBytes)
{
    if (error != nullptr)
    {
        *error = L"reference must be a stable local regular file within the byte limit";
    }
    const auto absolute = LocalPath(path);
    if (File != INVALID_HANDLE_VALUE || absolute.empty())
    {
        return false;
    }
    File = CreateFileW(absolute.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    return Initialize(error, maximumBytes);
}

bool ReferenceArtifact::OpenHandle(HANDLE file, std::wstring* error, size_t maximumBytes)
{
    return OpenHandleImpl(file, error, maximumBytes, nullptr);
}

bool ReferenceArtifact::OpenResidentLocalHandle(HANDLE file, std::wstring* error, size_t maximumBytes)
{
    if (error != nullptr) { *error = L"standard input must be a resident regular file on a fixed local volume within the byte limit"; }
    if (File != INVALID_HANDLE_VALUE || !ResidentLocalDiskFile(file)) { return false; }
    // Empty relative name reopens the supplied object with its own cursor.
    // The Win32 ReOpenFile flag set does not support no-recall.
    const auto open = NativeFileFunction<decltype(&NtOpenFile)>("NtOpenFile");
    UNICODE_STRING empty{};
    OBJECT_ATTRIBUTES attributes{};
    InitializeObjectAttributes(&attributes, &empty, 0, file, nullptr);
    IO_STATUS_BLOCK result{};
    HANDLE lease = nullptr;
    if (!open || open(&lease, ResidentFileAccess, &attributes, &result, FILE_SHARE_READ,
        FILE_OPEN_NO_RECALL | FILE_OPEN_REPARSE_POINT | FILE_NON_DIRECTORY_FILE |
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_SEQUENTIAL_ONLY) != 0) { return false; }
    File = lease;
    return ResidentLocalDiskFile(File) && Initialize(error, maximumBytes);
}

bool ReferenceArtifact::OpenHandleCancelable(HANDLE file, std::wstring* error, const std::atomic<bool>& stop, size_t maximumBytes)
{
    return OpenHandleImpl(file, error, maximumBytes, &stop);
}

bool ReferenceArtifact::OpenHandleImpl(HANDLE file, std::wstring* error, size_t maximumBytes, const std::atomic<bool>* stop)
{
    if (error != nullptr) { *error = L"reference handle must identify a stable local regular file within the byte limit"; }
    if (stop != nullptr && stop->load()) { SetLastError(ERROR_OPERATION_ABORTED); return false; }
    if (File != INVALID_HANDLE_VALUE || file == nullptr || file == INVALID_HANDLE_VALUE || GetFileType(file) != FILE_TYPE_DISK)
    {
        return false;
    }
    File = ReOpenFile(file, GENERIC_READ, FILE_SHARE_READ, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN);
    return Initialize(error, maximumBytes, stop);
}

bool ReferenceArtifact::Initialize(std::wstring* error, size_t maximumBytes, const std::atomic<bool>* stop)
{
    auto content = std::make_shared<RetainedReferenceArtifact>();
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (File == INVALID_HANDLE_VALUE || GetFileType(File) != FILE_TYPE_DISK ||
        !GetFileInformationByHandleEx(File, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        !GetFileInformationByHandleEx(File, FileIdInfo, &Identity, sizeof(Identity)) || !Read(File, &content->Bytes, maximumBytes, stop))
    {
        return false;
    }
    std::vector<wchar_t> pathBuffer(32768);
    const DWORD length = GetFinalPathNameByHandleW(File, pathBuffer.data(), static_cast<DWORD>(pathBuffer.size()), 0);
    if (length < 7 || length >= pathBuffer.size())
    {
        return false;
    }
    content->OriginalPath.assign(pathBuffer.data(), length);
    // Keep a local DOS path for callers that reject device namespaces.
    if (content->OriginalPath.rfind(L"\\\\?\\", 0) != 0 || content->OriginalPath[5] != L':')
    {
        return false;
    }
    content->OriginalPath.erase(0, 4);
    ContentHash hash;
    for (size_t offset = 0; offset < content->Bytes.size();)
    {
        if (stop != nullptr && stop->load()) { SetLastError(ERROR_OPERATION_ABORTED); return false; }
        const auto count = (std::min)(content->Bytes.size() - offset, size_t{65536});
        if (!hash.Add(content->Bytes.data() + offset, count)) { return false; }
        offset += count;
    }
    content->Sha256 = hash.Finish();
    if (stop != nullptr && stop->load()) { SetLastError(ERROR_OPERATION_ABORTED); return false; }
    if (content->Sha256.empty())
    {
        return false;
    }
    content->OriginalFileIdentity = std::to_wstring(Identity.VolumeSerialNumber) + L":" +
        Hex(Identity.FileId.Identifier, sizeof(Identity.FileId.Identifier));
    Content = std::move(content);
    if (error != nullptr)
    {
        error->clear();
    }
    return true;
}

std::shared_ptr<const RetainedReferenceArtifact> ReferenceArtifact::Snapshot() const
{
    return Content;
}

bool ReferenceArtifact::Unchanged()
{
    if (Content == nullptr)
    {
        return false;
    }
    HANDLE reopened = CreateFileW(Content->OriginalPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    const std::unique_ptr<void, decltype(&CloseHandle)> owner(reopened == INVALID_HANDLE_VALUE ? nullptr : reopened, &CloseHandle);
    FILE_ID_INFO identity{};
    std::vector<uint8_t> current;
    return owner && GetFileInformationByHandleEx(reopened, FileIdInfo, &identity, sizeof(identity)) &&
        std::memcmp(&identity, &Identity, sizeof(identity)) == 0 && Read(File, &current, Content->Bytes.size()) && current == Content->Bytes;
}

const std::wstring& ReferenceArtifact::Path() const
{
    static const std::wstring empty;
    return Content == nullptr ? empty : Content->OriginalPath;
}

const std::wstring& ReferenceArtifact::Sha256() const
{
    static const std::wstring empty;
    return Content == nullptr ? empty : Content->Sha256;
}

const std::vector<uint8_t>& ReferenceArtifact::Bytes() const
{
    static const std::vector<uint8_t> empty;
    return Content == nullptr ? empty : Content->Bytes;
}

std::wstring ReferenceArtifact::FileIdentity() const
{
    return Content == nullptr ? L"" : Content->OriginalFileIdentity;
}

bool PublishReferenceArtifact(const std::wstring& path, const std::vector<uint8_t>& bytes, std::wstring* error,
    const std::function<bool(HANDLE)>& admitOutput)
{
    const auto absolute = LocalPath(path);
    if (error != nullptr)
    {
        *error = L"reference blob publication failed; an existing file is never replaced";
    }
    if (absolute.empty() || bytes.empty() || bytes.size() > ReferenceArtifactMaxBytes)
    {
        return false;
    }
    static LONG serial = 0;
    const auto temporary = absolute + L".pending-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
        std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(InterlockedIncrement(&serial));
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE | DELETE | (admitOutput ? READ_CONTROL | FILE_READ_ATTRIBUTES : 0),
        0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    const std::unique_ptr<void, decltype(&CloseHandle)> owner(file, &CloseHandle);
    DWORD written = 0;
    bool ok = false;
    try
    {
        // Policy admission sees the actual CREATE_NEW handle before any raw
        // bytes are written. Failure/exception disposes only this owned file.
        if (GetFileType(file) == FILE_TYPE_DISK && (!admitOutput || admitOutput(file)) &&
            WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) &&
            written == bytes.size() && FlushFileBuffers(file))
        {
            std::vector<uint8_t> storage(offsetof(FILE_RENAME_INFO, FileName) + (absolute.size() + 1) * sizeof(wchar_t), 0);
            auto rename = reinterpret_cast<FILE_RENAME_INFO*>(storage.data());
            rename->FileNameLength = static_cast<DWORD>(absolute.size() * sizeof(wchar_t));
            std::memcpy(rename->FileName, absolute.data(), rename->FileNameLength);
            ok = SetFileInformationByHandle(file, FileRenameInfo, rename, static_cast<DWORD>(storage.size())) != FALSE;
        }
    }
    catch (...) { ok = false; }
    if (!ok)
    {
        FILE_DISPOSITION_INFO remove{TRUE};
        SetFileInformationByHandle(file, FileDispositionInfo, &remove, sizeof(remove));
    }
    else if (error != nullptr)
    {
        error->clear();
    }
    return ok;
}

bool PublishReferenceBlob(const std::wstring& directory, const RetainedReferenceArtifact& artifact,
    uint64_t maximumNewBytes, std::unique_ptr<ReferenceArtifact>* lease, bool* created, std::wstring* error)
{
    if (lease != nullptr) { lease->reset(); }
    if (created != nullptr) { *created = false; }
    if (error != nullptr) { *error = L"invalid_retained_reference"; }
    if (lease == nullptr || created == nullptr || artifact.Bytes.empty() || artifact.Bytes.size() > ReferenceArtifactMaxBytes ||
        artifact.Sha256.size() != 64 || artifact.Sha256 != ContentHash::Bytes(artifact.Bytes)) { return false; }
    const auto root = LocalPath(directory);
    if (root.empty()) { return false; }
    const auto path = (std::filesystem::path(root) / (artifact.Sha256 + L".knblob")).wstring();
    const auto acquire = [&]()
    {
        auto candidate = std::make_unique<ReferenceArtifact>();
        if (!candidate->Open(path, nullptr) || candidate->Sha256() != artifact.Sha256 || candidate->Bytes() != artifact.Bytes)
        {
            return false;
        }
        *lease = std::move(candidate);
        if (error != nullptr) { error->clear(); }
        return true;
    };
    if (acquire()) { return true; }
    if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES)
    {
        if (error != nullptr) { *error = L"reference_store_existing_blob_unverified"; }
        return false;
    }
    if (artifact.Bytes.size() > maximumNewBytes)
    {
        if (error != nullptr) { *error = L"reference_store_byte_budget"; }
        return false;
    }
    std::error_code ec;
    std::filesystem::create_directories(root, ec);
    if (ec)
    {
        if (error != nullptr) { *error = L"reference_store_directory_unavailable"; }
        return false;
    }
    *created = PublishReferenceArtifact(path, artifact.Bytes, error);
    // A simultaneous publisher may have won CREATE_NEW. Reuse only after
    // opening and comparing the actual existing content; never replace it.
    if (acquire()) { return true; }
    if (error != nullptr) { *error = L"reference_store_publication_or_verification_failed"; }
    return false;
}
