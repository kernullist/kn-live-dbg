#pragma once

#include "SchemaArtifact.h"
#include <cwctype>

namespace symbol_artifacts
{
    inline std::wstring Index(const GUID& g, uint32_t age)
    {
        wchar_t text[48]{};
        // SymStore uses uppercase GUID digits followed by the hexadecimal age.
        swprintf_s(text, L"%08lX%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X%x", g.Data1, g.Data2, g.Data3,
            g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7], age);
        return text;
    }
    // Check spelling before any filesystem probe. UNC/device/drive-relative
    // roots, ADS, reserved names and Win32 path aliases are not cache roots.
    inline bool LocalRoot(std::wstring value, std::filesystem::path* output)
    {
        if (output == nullptr) { return false; }
        output->clear();
        if (value.empty() || value.size() > 29000 || value.find(L'\0') != std::wstring::npos) { return false; }
        std::replace(value.begin(), value.end(), L'/', L'\\');
        if (value[0] == L'\\' || value.find_first_of(L"<>\"|?*") != std::wstring::npos ||
            std::any_of(value.begin(), value.end(), [](wchar_t c) { return c < 32; })) { return false; }
        const auto colon = value.find(L':');
        if (colon != std::wstring::npos && (colon != 1 || value.size() < 3 || value[2] != L'\\' ||
            !((value[0] >= L'A' && value[0] <= L'Z') || (value[0] >= L'a' && value[0] <= L'z')) ||
            value.find(L':', 2) != std::wstring::npos)) { return false; }
        for (const auto& part : std::filesystem::path(value).relative_path())
        {
            auto name = part.wstring();
            if (name.empty() || name == L"." || name == L"..") { continue; }
            if (name.back() == L'.' || name.back() == L' ') { return false; }
            name = name.substr(0, name.find(L'.'));
            std::transform(name.begin(), name.end(), name.begin(), [](wchar_t c) { return static_cast<wchar_t>(towupper(c)); });
            if (name == L"CON" || name == L"PRN" || name == L"AUX" || name == L"NUL" || name == L"CONIN$" || name == L"CONOUT$" ||
                (name.size() == 4 && (name.substr(0, 3) == L"COM" || name.substr(0, 3) == L"LPT") &&
                    ((name[3] >= L'1' && name[3] <= L'9') || name[3] == L'\u00b9' || name[3] == L'\u00b2' || name[3] == L'\u00b3')))
            { return false; }
        }
        std::error_code ec;
        const auto path = std::filesystem::absolute(value, ec).lexically_normal();
        const auto text = path.wstring();
        if (ec || text.size() < 3 || text.size() > 29000 || text[1] != L':' || text[2] != L'\\' ||
            GetDriveTypeW(text.substr(0, 3).c_str()) != DRIVE_FIXED) { return false; }
        *output = path;
        return true;
    }

    struct Directories
    {
        std::vector<HANDLE> Values;
        ~Directories() { for (const auto h : Values) { CloseHandle(h); } }
        bool Pin(const std::filesystem::path& target, bool create)
        {
            std::filesystem::path approved;
            if (!LocalRoot(target.wstring(), &approved)) { return false; }
            const auto path = approved.wstring();
            for (size_t start = 3; start < path.size();)
            {
                const auto slash = path.find(L'\\', start);
                const auto directory = path.substr(0, slash);
                if (create && !CreateDirectoryW(directory.c_str(), nullptr) && GetLastError() != ERROR_ALREADY_EXISTS) { return false; }
                // Metadata-only access does not participate in Windows share
                // checks. Include directory read access before creating children.
                HANDLE h = CreateFileW(directory.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
                if (h == INVALID_HANDLE_VALUE) { return false; }
                try { Values.push_back(h); }
                catch (...) { CloseHandle(h); throw; }
                FILE_ATTRIBUTE_TAG_INFO info{};
                if (!GetFileInformationByHandleEx(h, FileAttributeTagInfo, &info, sizeof(info)) ||
                    (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
                    (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) { return false; }
                if (slash == std::wstring::npos) { break; }
                start = slash + 1;
            }
            return true;
        }
    };

    struct TemporaryFile
    {
        std::wstring Path;
        HANDLE File = INVALID_HANDLE_VALUE;
        FILE_ID_INFO Identity{};
        bool Owned = false;
        ~TemporaryFile()
        {
            Close();
            if (!Owned) { return; }
            HANDLE file = CreateFileW(Path.c_str(), DELETE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            FILE_ID_INFO current{};
            if (file != INVALID_HANDLE_VALUE)
            {
                if (GetFileInformationByHandleEx(file, FileIdInfo, &current, sizeof(current)) &&
                    std::memcmp(&Identity, &current, sizeof(current)) == 0)
                { FILE_DISPOSITION_INFO disposition{TRUE}; SetFileInformationByHandle(file, FileDispositionInfo, &disposition, sizeof(disposition)); }
                CloseHandle(file);
            }
        }
        bool Create(const std::wstring& path)
        {
            if (Owned || File != INVALID_HANDLE_VALUE) { return false; }
            Path = path;
            File = CreateFileW(Path.c_str(), GENERIC_WRITE | DELETE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY, nullptr);
            if (File == INVALID_HANDLE_VALUE) { return false; }
            Owned = GetFileInformationByHandleEx(File, FileIdInfo, &Identity, sizeof(Identity)) != FALSE;
            if (!Owned)
            { FILE_DISPOSITION_INFO disposition{TRUE}; SetFileInformationByHandle(File, FileDispositionInfo, &disposition, sizeof(disposition)); }
            return Owned;
        }
        bool Same(HANDLE file) const
        {
            FILE_ID_INFO current{};
            return Owned && GetFileInformationByHandleEx(file, FileIdInfo, &current, sizeof(current)) &&
                std::memcmp(&Identity, &current, sizeof(current)) == 0;
        }
        void Close() { if (File != INVALID_HANDLE_VALUE) { CloseHandle(File); File = INVALID_HANDLE_VALUE; } }
    };

    // Keep the approved source lease while copying. The create-new destination
    // is exclusive until flush/close; a failure deletes that exact open object.
    // A crash can leave an incomplete entry, which a later broker must reject.
    inline bool Publish(SchemaArtifact& source, const std::filesystem::path& destination)
    {
        Directories pinned;
        if (!pinned.Pin(destination.parent_path(), true)) { return false; }
        std::filesystem::path approved;
        if (!LocalRoot(destination.wstring(), &approved) || approved != destination.lexically_normal()) { return false; }
        HANDLE file = CreateFileW(approved.c_str(), GENERIC_WRITE | DELETE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE) { return false; }
        struct Output
        {
            HANDLE File;
            bool Complete = false;
            ~Output()
            {
                if (!Complete) { FILE_DISPOSITION_INFO disposition{TRUE}; SetFileInformationByHandle(File, FileDispositionInfo, &disposition, sizeof(disposition)); }
                CloseHandle(File);
            }
        } output{file};
        LARGE_INTEGER zero{};
        if (!SetFilePointerEx(source.Handle(), zero, nullptr, FILE_BEGIN)) { return false; }
        std::vector<uint8_t> buffer(65536);
        auto remaining = source.Bytes();
        const auto started = GetTickCount64();
        while (remaining != 0)
        {
            DWORD read = 0, written = 0;
            const auto count = static_cast<DWORD>((std::min)(remaining, static_cast<uint64_t>(buffer.size())));
            if (GetTickCount64() - started >= 30000 || !ReadFile(source.Handle(), buffer.data(), count, &read, nullptr) || read != count ||
                !WriteFile(file, buffer.data(), read, &written, nullptr) || written != read) { return false; }
            remaining -= read;
        }
        if (!FlushFileBuffers(file) || !source.Unchanged()) { return false; }
        output.Complete = true;
        return true;
    }
}
