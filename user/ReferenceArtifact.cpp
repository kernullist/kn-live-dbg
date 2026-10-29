#include "ReferenceArtifact.h"
#include "ContentHash.h"
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <memory>

namespace
{
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

    bool Read(HANDLE file, std::vector<uint8_t>* bytes)
    {
        LARGE_INTEGER size{}, zero{};
        if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || static_cast<uint64_t>(size.QuadPart) > ReferenceArtifactMaxBytes ||
            !SetFilePointerEx(file, zero, nullptr, FILE_BEGIN))
        {
            return false;
        }
        bytes->resize(static_cast<size_t>(size.QuadPart));
        size_t offset = 0;
        const uint64_t started = GetTickCount64();
        while (offset < bytes->size())
        {
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

ReferenceArtifact::~ReferenceArtifact()
{
    if (File != INVALID_HANDLE_VALUE)
    {
        CloseHandle(File);
    }
}

bool ReferenceArtifact::Open(const std::wstring& path, std::wstring* error)
{
    if (error != nullptr)
    {
        *error = L"reference must be a stable local regular file of 1..64 MiB";
    }
    const auto absolute = LocalPath(path);
    if (File != INVALID_HANDLE_VALUE || absolute.empty())
    {
        return false;
    }
    File = CreateFileW(absolute.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    FILE_ATTRIBUTE_TAG_INFO attributes{};
    if (File == INVALID_HANDLE_VALUE || GetFileType(File) != FILE_TYPE_DISK ||
        !GetFileInformationByHandleEx(File, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
        (attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
        !GetFileInformationByHandleEx(File, FileIdInfo, &Identity, sizeof(Identity)) || !Read(File, &Data))
    {
        return false;
    }
    std::vector<wchar_t> pathBuffer(32768);
    const DWORD length = GetFinalPathNameByHandleW(File, pathBuffer.data(), static_cast<DWORD>(pathBuffer.size()), 0);
    if (length < 7 || length >= pathBuffer.size())
    {
        return false;
    }
    FinalPath.assign(pathBuffer.data(), length);
    // Keep a local DOS path for callers that reject device namespaces.
    if (FinalPath.rfind(L"\\\\?\\", 0) != 0 || FinalPath[5] != L':')
    {
        return false;
    }
    FinalPath.erase(0, 4);
    Hash = ContentHash::Bytes(Data);
    if (Hash.empty())
    {
        return false;
    }
    if (error != nullptr)
    {
        error->clear();
    }
    return true;
}

bool ReferenceArtifact::Unchanged()
{
    if (Hash.empty())
    {
        return false;
    }
    HANDLE reopened = CreateFileW(FinalPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
        FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
    const std::unique_ptr<void, decltype(&CloseHandle)> owner(reopened == INVALID_HANDLE_VALUE ? nullptr : reopened, &CloseHandle);
    FILE_ID_INFO identity{};
    std::vector<uint8_t> current;
    return owner && GetFileInformationByHandleEx(reopened, FileIdInfo, &identity, sizeof(identity)) &&
        std::memcmp(&identity, &Identity, sizeof(identity)) == 0 && Read(File, &current) && current == Data;
}

const std::wstring& ReferenceArtifact::Path() const
{
    return FinalPath;
}

const std::wstring& ReferenceArtifact::Sha256() const
{
    return Hash;
}

const std::vector<uint8_t>& ReferenceArtifact::Bytes() const
{
    return Data;
}

std::wstring ReferenceArtifact::FileIdentity() const
{
    return std::to_wstring(Identity.VolumeSerialNumber) + L":" + Hex(Identity.FileId.Identifier, sizeof(Identity.FileId.Identifier));
}

bool PublishReferenceArtifact(const std::wstring& path, const std::vector<uint8_t>& bytes, std::wstring* error)
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
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE | DELETE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    const std::unique_ptr<void, decltype(&CloseHandle)> owner(file, &CloseHandle);
    DWORD written = 0;
    bool ok = false;
    if (GetFileType(file) == FILE_TYPE_DISK && WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) &&
        written == bytes.size() && FlushFileBuffers(file))
    {
        std::vector<uint8_t> storage(offsetof(FILE_RENAME_INFO, FileName) + (absolute.size() + 1) * sizeof(wchar_t), 0);
        auto rename = reinterpret_cast<FILE_RENAME_INFO*>(storage.data());
        rename->FileNameLength = static_cast<DWORD>(absolute.size() * sizeof(wchar_t));
        std::memcpy(rename->FileName, absolute.data(), rename->FileNameLength);
        ok = SetFileInformationByHandle(file, FileRenameInfo, rename, static_cast<DWORD>(storage.size())) != FALSE;
    }
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
