#pragma once

#include "SchemaArtifact.h"
#include <aclapi.h>
#include <networkisolation.h>
#include <sddl.h>
#include <shlobj.h>
#include <userenv.h>
#include <memory>
#include <cwctype>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "userenv.lib")

namespace parser_sandbox
{
    inline bool FailWin32(DWORD error) { SetLastError(error); return false; }

    inline bool SecurityMatches(HANDLE file, const std::wstring& userSid, bool root, bool allowApps)
    {
        PSID owner = nullptr; PACL acl = nullptr; PSECURITY_DESCRIPTOR descriptor = nullptr;
        const auto result = GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &owner, nullptr, &acl, nullptr, &descriptor);
        struct Local { HLOCAL Value = nullptr; ~Local() { LocalFree(Value); } } memory{descriptor}, user;
        uint8_t system[SECURITY_MAX_SID_SIZE]{}, apps[SECURITY_MAX_SID_SIZE]{};
        DWORD systemSize = sizeof(system), appsSize = sizeof(apps);
        SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
        const size_t expectedCount = allowApps ? 3 : 2;
        if (result != ERROR_SUCCESS || acl == nullptr || acl->AceCount != expectedCount ||
            !ConvertStringSidToSidW(userSid.c_str(), reinterpret_cast<PSID*>(&user.Value)) ||
            owner == nullptr || !EqualSid(owner, user.Value) ||
            !CreateWellKnownSid(WinLocalSystemSid, nullptr, system, &systemSize) ||
            !CreateWellKnownSid(WinBuiltinAnyPackageSid, nullptr, apps, &appsSize) ||
            !GetSecurityDescriptorControl(descriptor, &control, &revision) ||
            (root && (control & SE_DACL_PROTECTED) == 0)) { return false; }
        PSID expected[] = {user.Value, system, apps};
        DWORD masks[] = {FILE_ALL_ACCESS, FILE_ALL_ACCESS, FILE_GENERIC_READ | FILE_GENERIC_EXECUTE};
        bool seen[3]{};
        for (DWORD i = 0; i < acl->AceCount; ++i)
        {
            void* raw = nullptr;
            if (!GetAce(acl, i, &raw)) { return false; }
            const auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
            if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
                (ace->Header.AceFlags & ~(OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERITED_ACE)) != 0) { return false; }
            bool matched = false;
            for (size_t j = 0; j < expectedCount; ++j)
            {
                if (!seen[j] && ace->Mask == masks[j] && EqualSid(const_cast<DWORD*>(&ace->SidStart), expected[j]))
                { seen[j] = true; matched = true; break; }
            }
            if (!matched) { return false; }
        }
        return true;
    }

    inline uint64_t CreationTime(const FILETIME& time)
    { return (static_cast<uint64_t>(time.dwHighDateTime) << 32) | time.dwLowDateTime; }

    inline std::wstring OwnerKey()
    {
        GUID guid{}; wchar_t text[40]{}, prefix[32]{}; FILETIME created{}, exited{}, kernel{}, user{};
        if (FAILED(CoCreateGuid(&guid)) || !StringFromGUID2(guid, text, 40) ||
            !GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user)) { return {}; }
        swprintf_s(prefix, L"KnP1-%08lx-%016llx-", GetCurrentProcessId(), CreationTime(created));
        std::wstring nonce;
        for (const auto c : text) { if (iswxdigit(c)) { nonce += c; } }
        return nonce.size() == 32 ? std::wstring(prefix) + nonce : L"";
    }

    inline bool OwnerGone(const std::wstring& name)
    {
        if (name.size() != 63 || _wcsnicmp(name.c_str(), L"KnP1-", 5) != 0 || name[13] != L'-' || name[30] != L'-') { return false; }
        uint64_t pid = 0, created = 0;
        for (size_t i = 5; i < name.size(); ++i)
        {
            if (i == 13 || i == 30) { continue; }
            const auto c = name[i];
            const int value = c >= L'0' && c <= L'9' ? c - L'0' : c >= L'a' && c <= L'f' ? c - L'a' + 10 :
                c >= L'A' && c <= L'F' ? c - L'A' + 10 : -1;
            if (value < 0) { return false; }
            if (i < 13) { pid = pid * 16 + value; }
            else if (i < 30) { created = created * 16 + value; }
        }
        if (pid == 0 || created == 0) { return false; }
        const auto process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, static_cast<DWORD>(pid));
        if (process == nullptr) { return GetLastError() == ERROR_INVALID_PARAMETER; }
        FILETIME start{}, exit{}, kernel{}, user{};
        const bool gone = WaitForSingleObject(process, 0) == WAIT_OBJECT_0 ||
            (GetProcessTimes(process, &start, &exit, &kernel, &user) && CreationTime(start) != created);
        CloseHandle(process); return gone;
    }

    class Profile
    {
        HANDLE RootLease = INVALID_HANDLE_VALUE;
        HANDLE Receipt = INVALID_HANDLE_VALUE;
        std::filesystem::path Root;
        std::wstring UserSid;
        bool Published = false;
        bool RegistrationCollision = false;
        bool Fail(HRESULT error) { Error = error; return false; }
        static std::wstring ReceiptText(const std::wstring& name) { return L"KnLiveDbg parser profile v1\n" + name + L"\n"; }
        static HRESULT DeleteProfile(const std::wstring& name)
        {
            const auto error = DeleteAppContainerProfile(name.c_str());
            return error == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) || error == HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND) ? S_OK : error;
        }
        bool InitializeRoot(const std::wstring& userSid)
        {
            UserSid = userSid; PWSTR local = nullptr;
            const auto located = SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DONT_VERIFY, nullptr, &local);
            if (FAILED(located)) { return Fail(located); }
            Root = std::filesystem::path(local) / L"KnLiveDbgParserProfiles-v1"; CoTaskMemFree(local);
            PSECURITY_DESCRIPTOR descriptor = nullptr;
            const auto sddl = L"O:" + userSid + L"D:P(A;OICI;FA;;;" + userSid + L")(A;OICI;FA;;;SY)";
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr))
            { return Fail(HRESULT_FROM_WIN32(GetLastError())); }
            SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
            const bool created = CreateDirectoryW(Root.c_str(), &security) || GetLastError() == ERROR_ALREADY_EXISTS;
            const auto createError = GetLastError(); LocalFree(descriptor);
            if (!created) { return Fail(HRESULT_FROM_WIN32(createError)); }
            RootLease = CreateFileW(Root.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            FILE_ATTRIBUTE_TAG_INFO attributes{};
            if (RootLease == INVALID_HANDLE_VALUE || !GetFileInformationByHandleEx(RootLease, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
                (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                !SecurityMatches(RootLease, userSid, true, false)) { return Fail(HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED)); }
            return true;
        }
        bool Recover()
        {
            WIN32_FIND_DATAW entry{};
            const auto listing = FindFirstFileW((Root / L"*").c_str(), &entry);
            if (listing == INVALID_HANDLE_VALUE)
            { return GetLastError() == ERROR_FILE_NOT_FOUND || Fail(HRESULT_FROM_WIN32(GetLastError())); }
            std::vector<std::wstring> names; bool bounded = true;
            do
            {
                const std::wstring name = entry.cFileName;
                const bool lease = name.size() == 69 && name.substr(63) == L".lease";
                const bool pending = name.size() == 71 && name.substr(63) == L".pending";
                if ((!lease && !pending) || !OwnerGone(name.substr(0, 63))) { continue; }
                if ((entry.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 || names.size() >= 4096)
                { bounded = false; break; }
                names.push_back(name);
            } while (FindNextFileW(listing, &entry));
            const auto listingError = GetLastError(); FindClose(listing);
            if (!bounded || listingError != ERROR_NO_MORE_FILES) { return Fail(HRESULT_FROM_WIN32(ERROR_INVALID_DATA)); }
            for (const auto& filename : names)
            {
                const auto name = filename.substr(0, 63);
                const bool published = filename.substr(63) == L".lease";
                HANDLE file = CreateFileW((Root / filename).c_str(), GENERIC_READ | DELETE, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                    FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
                if (file == INVALID_HANDLE_VALUE)
                {
                    if (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_SHARING_VIOLATION) { continue; }
                    return Fail(HRESULT_FROM_WIN32(GetLastError()));
                }
                const auto expected = ReceiptText(name); std::wstring text(expected.size(), L'\0');
                FILE_ATTRIBUTE_TAG_INFO attributes{}; LARGE_INTEGER size{}; DWORD read = 0;
                const bool regular = GetFileInformationByHandleEx(file, FileAttributeTagInfo, &attributes, sizeof(attributes)) &&
                    (attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0 &&
                    SecurityMatches(file, UserSid, false, false) && GetFileSizeEx(file, &size) && size.QuadPart >= 0 &&
                    size.QuadPart <= static_cast<LONGLONG>(expected.size() * sizeof(wchar_t));
                const bool valid = regular && (!published || (size.QuadPart == static_cast<LONGLONG>(expected.size() * sizeof(wchar_t)) &&
                    approved_file::ReadAt(file, 0, text.data(), static_cast<DWORD>(text.size() * sizeof(wchar_t)), &read) &&
                    read == text.size() * sizeof(wchar_t) && text == expected));
                HRESULT deleted = valid ? (published ? DeleteProfile(name) : S_OK) : HRESULT_FROM_WIN32(ERROR_INVALID_DATA);
                FILE_DISPOSITION_INFO disposition{TRUE};
                if (SUCCEEDED(deleted) && !SetFileInformationByHandle(file, FileDispositionInfo, &disposition, sizeof(disposition)))
                { deleted = HRESULT_FROM_WIN32(GetLastError()); }
                CloseHandle(file);
                if (FAILED(deleted)) { return Fail(deleted); }
                ++RecoveredCount;
            }
            return true;
        }
    public:
        PSID Sid = nullptr;
        std::wstring Name;
        std::wstring Folder;
        HRESULT Error = S_OK;
        size_t RecoveredCount = 0;
        ~Profile()
        {
            Remove();
            if (Receipt != INVALID_HANDLE_VALUE) { CloseHandle(Receipt); }
            if (RootLease != INVALID_HANDLE_VALUE) { CloseHandle(RootLease); }
            if (Sid != nullptr) { FreeSid(Sid); }
        }
        Profile() = default;
        Profile(const Profile&) = delete;
        Profile& operator=(const Profile&) = delete;
        bool Create(const std::wstring& userSid)
        {
            if (!InitializeRoot(userSid) || !Recover()) { return false; }
            Name = OwnerKey(); if (Name.empty()) { return Fail(E_FAIL); }
            const auto pending = Root / (Name + L".pending"), final = Root / (Name + L".lease");
            Receipt = CreateFileW(pending.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ,
                nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (Receipt == INVALID_HANDLE_VALUE) { Name.clear(); return Fail(HRESULT_FROM_WIN32(GetLastError())); }
            const auto text = ReceiptText(Name); DWORD written = 0;
            if (!WriteFile(Receipt, text.data(), static_cast<DWORD>(text.size() * sizeof(wchar_t)), &written, nullptr) ||
                written != text.size() * sizeof(wchar_t) || !FlushFileBuffers(Receipt)) { return Fail(HRESULT_FROM_WIN32(ERROR_WRITE_FAULT)); }
            CloseHandle(Receipt); Receipt = INVALID_HANDLE_VALUE;
            if (!MoveFileExW(pending.c_str(), final.c_str(), MOVEFILE_WRITE_THROUGH)) { return Fail(HRESULT_FROM_WIN32(GetLastError())); }
            Published = true;
            Receipt = CreateFileW(final.c_str(), GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            if (Receipt == INVALID_HANDLE_VALUE) { return Fail(HRESULT_FROM_WIN32(GetLastError())); }
            const auto created = CreateAppContainerProfile(Name.c_str(), L"KnLiveDbg parser", L"Temporary parser identity", nullptr, 0, &Sid);
            if (created == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS))
            {
                // A collided registration is not ours to delete. Invalidate the
                // recovery claim before removing it, so a failed receipt delete
                // cannot authorize a later reaper to delete that registration.
                RegistrationCollision = true;
                const wchar_t invalid = L'!'; DWORD revoked = 0;
                if (!WriteFile(Receipt, &invalid, sizeof(invalid), &revoked, nullptr) || revoked != sizeof(invalid) || !FlushFileBuffers(Receipt))
                { return Fail(HRESULT_FROM_WIN32(ERROR_WRITE_FAULT)); }
                if (!Remove()) { return false; }
                return Fail(created);
            }
            if (FAILED(created)) { return Fail(created); }
            LPWSTR sidText = nullptr, folder = nullptr;
            const auto located = ConvertSidToStringSidW(Sid, &sidText) ? GetAppContainerFolderPath(sidText, &folder) : HRESULT_FROM_WIN32(GetLastError());
            if (SUCCEEDED(located)) { Folder = folder; }
            LocalFree(sidText); CoTaskMemFree(folder);
            return SUCCEEDED(located) || Fail(located);
        }
        bool Remove()
        {
            if (Name.empty()) { return true; }
            const auto result = Published && !RegistrationCollision ? DeleteProfile(Name) : S_OK;
            if (FAILED(result)) { return Fail(result); }
            if (Receipt == INVALID_HANDLE_VALUE)
            {
                Receipt = CreateFileW((Root / (Name + (Published ? L".lease" : L".pending"))).c_str(), GENERIC_READ | DELETE,
                    FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
                if (Receipt == INVALID_HANDLE_VALUE && GetLastError() != ERROR_FILE_NOT_FOUND) { return Fail(HRESULT_FROM_WIN32(GetLastError())); }
            }
            if (Receipt != INVALID_HANDLE_VALUE)
            {
                FILE_DISPOSITION_INFO disposition{TRUE};
                if (!SetFileInformationByHandle(Receipt, FileDispositionInfo, &disposition, sizeof(disposition)))
                { return Fail(HRESULT_FROM_WIN32(GetLastError())); }
                CloseHandle(Receipt); Receipt = INVALID_HANDLE_VALUE;
            }
            Name.clear(); return true;
        }
    };

    inline bool NetworkPolicyAllowsIsolation(PSID sid)
    {
        // Read-only policy checks. Never install firewall rules or exemptions.
        if (sid == nullptr || !IsValidSid(sid)) { return FailWin32(ERROR_INVALID_SID); }
        const auto manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
        if (manager == nullptr) { return false; }
        DWORD serviceError = ERROR_SUCCESS;
        for (const auto* name : {L"BFE", L"MpsSvc"})
        {
            const auto service = OpenServiceW(manager, name, SERVICE_QUERY_STATUS);
            SERVICE_STATUS_PROCESS status{}; DWORD bytes = 0;
            if (service == nullptr || !QueryServiceStatusEx(service, SC_STATUS_PROCESS_INFO,
                reinterpret_cast<BYTE*>(&status), sizeof(status), &bytes)) { serviceError = GetLastError(); }
            else if (status.dwCurrentState != SERVICE_RUNNING) { serviceError = ERROR_SERVICE_NOT_ACTIVE; }
            if (service != nullptr) { CloseServiceHandle(service); }
            if (serviceError != ERROR_SUCCESS) { break; }
        }
        CloseServiceHandle(manager);
        if (serviceError != ERROR_SUCCESS) { return FailWin32(serviceError); }
        DWORD count = 0; PSID_AND_ATTRIBUTES entries = nullptr;
        const auto module = LoadLibraryExW(L"FirewallAPI.dll", nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (module == nullptr) { return false; }
        const auto query = reinterpret_cast<decltype(&NetworkIsolationGetAppContainerConfig)>(
            GetProcAddress(module, "NetworkIsolationGetAppContainerConfig"));
        if (query == nullptr) { const auto error = GetLastError(); FreeLibrary(module); return FailWin32(error); }
        const auto error = query(&count, &entries);
        bool allowed = error == ERROR_SUCCESS && (count == 0 || entries != nullptr);
        if (entries != nullptr)
        {
            for (DWORD i = 0; i < count; ++i)
            {
                if (entries[i].Sid == nullptr || !IsValidSid(entries[i].Sid) || EqualSid(sid, entries[i].Sid)) { allowed = false; }
                HeapFree(GetProcessHeap(), 0, entries[i].Sid);
            }
            HeapFree(GetProcessHeap(), 0, entries);
        }
        FreeLibrary(module);
        if (!allowed) { SetLastError(error == ERROR_SUCCESS ? ERROR_ACCESS_DENIED : error); }
        return allowed;
    }

    inline bool TokenHasNoCapabilities(HANDLE token, PSID expected = nullptr)
    {
        DWORD app = 0, bytes = 0;
        if (!GetTokenInformation(token, TokenIsAppContainer, &app, sizeof(app), &bytes)) { return false; }
        if (app != 1) { return FailWin32(ERROR_ACCESS_DENIED); }
        std::vector<uint8_t> capabilities(4096), identity(4096);
        if (!GetTokenInformation(token, TokenCapabilities, capabilities.data(), static_cast<DWORD>(capabilities.size()), &bytes)) { return false; }
        if (bytes < sizeof(DWORD)) { return FailWin32(ERROR_INVALID_DATA); }
        if (reinterpret_cast<TOKEN_GROUPS*>(capabilities.data())->GroupCount != 0) { return FailWin32(ERROR_ACCESS_DENIED); }
        if (!GetTokenInformation(token, TokenAppContainerSid, identity.data(), static_cast<DWORD>(identity.size()), &bytes)) { return false; }
        if (bytes < sizeof(TOKEN_APPCONTAINER_INFORMATION)) { return FailWin32(ERROR_INVALID_DATA); }
        const auto actual = reinterpret_cast<TOKEN_APPCONTAINER_INFORMATION*>(identity.data())->TokenAppContainer;
        return (actual != nullptr && IsValidSid(actual) && (expected == nullptr || (IsValidSid(expected) && EqualSid(actual, expected)))) ||
            FailWin32(ERROR_ACCESS_DENIED);
    }

    // The cache contains approved executable code only, never image/PDB inputs.
    // All Application Packages can read/execute it; only the owner and SYSTEM
    // can change it. Every use rechecks ACL, content hash and pinned pathname.
    class Runtime
    {
        struct LocalOwner { HLOCAL Value = nullptr; ~LocalOwner() { LocalFree(Value); } };
        struct FileOwner
        {
            HANDLE Value = INVALID_HANDLE_VALUE;
            ~FileOwner() { if (Value != INVALID_HANDLE_VALUE) { CloseHandle(Value); } }
        };
        std::vector<std::unique_ptr<SchemaArtifact>> Sources;
        std::vector<std::unique_ptr<SchemaArtifact>> Copies;
        std::vector<std::wstring> Names;
        std::wstring OwnerSid;

        bool SecurityMatches(HANDLE file, bool root) const
        {
            return parser_sandbox::SecurityMatches(file, OwnerSid, root, true);
        }
        bool RecoverPreparations(const std::filesystem::path& root)
        {
            WIN32_FIND_DATAW entry{};
            const auto listing = FindFirstFileW((root / L"prepare-*").c_str(), &entry);
            if (listing == INVALID_HANDLE_VALUE) { return GetLastError() == ERROR_FILE_NOT_FOUND; }
            std::vector<std::wstring> names; bool valid = true;
            do
            {
                const std::wstring name = entry.cFileName;
                if (name.size() != 71 || !OwnerGone(name.substr(8))) { continue; }
                if ((entry.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || (entry.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 || names.size() >= 128)
                { valid = false; break; }
                names.push_back(name);
            } while (FindNextFileW(listing, &entry));
            const auto listingError = GetLastError(); FindClose(listing);
            if (!valid || listingError != ERROR_NO_MORE_FILES) { SetLastError(ERROR_INVALID_DATA); return false; }
            for (const auto& name : names)
            {
                const auto path = root / name;
                // DELETE access without delete sharing elects one reaper and
                // keeps this directory object stable through its final removal.
                FileOwner directory{CreateFileW(path.c_str(), DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL,
                    FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
                if (directory.Value == INVALID_HANDLE_VALUE)
                {
                    const auto error = GetLastError();
                    if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND || error == ERROR_SHARING_VIOLATION) { continue; }
                    return false;
                }
                FILE_ATTRIBUTE_TAG_INFO attributes{};
                if (!GetFileInformationByHandleEx(directory.Value, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
                    (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || (attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                    !SecurityMatches(directory.Value, true)) { SetLastError(ERROR_INVALID_DATA); return false; }
                const auto children = FindFirstFileW((path / L"*").c_str(), &entry);
                if (children == INVALID_HANDLE_VALUE) { return false; }
                std::vector<std::wstring> files;
                do
                {
                    const std::wstring file = entry.cFileName;
                    if (file == L"." || file == L"..") { continue; }
                    if ((entry.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 || files.size() >= 3 ||
                        (file != L"worker.exe" && file != L"msdia140.dll" && file != L"clang_rt.asan_dynamic-x86_64.dll"))
                    { valid = false; break; }
                    files.push_back(file);
                } while (FindNextFileW(children, &entry));
                const auto error = GetLastError(); FindClose(children);
                if (!valid || error != ERROR_NO_MORE_FILES) { SetLastError(ERROR_INVALID_DATA); return false; }
                FILE_DISPOSITION_INFO disposition{TRUE};
                for (const auto& filename : files)
                {
                    FileOwner file{CreateFileW((path / filename).c_str(), DELETE | FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ,
                        nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
                    if (file.Value == INVALID_HANDLE_VALUE || !GetFileInformationByHandleEx(file.Value, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
                    (attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 || !SecurityMatches(file.Value, false))
                    { return FailWin32(ERROR_INVALID_DATA); }
                    if (!SetFileInformationByHandle(file.Value, FileDispositionInfo, &disposition, sizeof(disposition))) { return false; }
                }
                if (!SetFileInformationByHandle(directory.Value, FileDispositionInfo, &disposition, sizeof(disposition))) { return false; }
            }
            return true;
        }
        bool Copy(size_t index, const std::filesystem::path& path, SECURITY_ATTRIBUTES* security)
        {
            FileOwner output{CreateFileW(path.c_str(), GENERIC_WRITE, 0, security, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr)};
            if (output.Value == INVALID_HANDLE_VALUE) { return false; }
            std::vector<uint8_t> buffer(65536); ContentHash hash;
            uint64_t offset = 0;
            while (offset < Sources[index]->Bytes())
            {
                const auto count = static_cast<DWORD>((std::min)(Sources[index]->Bytes() - offset, static_cast<uint64_t>(buffer.size())));
                DWORD read = 0, written = 0;
                if (!approved_file::ReadAt(Sources[index]->Handle(), offset, buffer.data(), count, &read) ||
                    !WriteFile(output.Value, buffer.data(), read, &written, nullptr)) { return false; }
                if (read != count || written != count || !hash.Add(buffer.data(), count)) { return FailWin32(ERROR_INVALID_DATA); }
                offset += count;
            }
            if (!FlushFileBuffers(output.Value)) { return false; }
            return hash.Finish() == Sources[index]->Sha256 || FailWin32(ERROR_INVALID_DATA);
        }
    public:
        std::wstring Executable;
        HANDLE Provider = INVALID_HANDLE_VALUE;
        bool Prepare(const std::wstring& executable, HANDLE provider, const std::wstring& userSid)
        {
            OwnerSid = userSid;
            Sources.push_back(std::make_unique<SchemaArtifact>()); Names.push_back(L"worker.exe");
            if (!Sources.back()->Open(executable, 512ull * 1024 * 1024) || !Sources.back()->PinPath()) { return FailWin32(ERROR_INVALID_DATA); }
            if (provider != INVALID_HANDLE_VALUE)
            {
                Sources.push_back(std::make_unique<SchemaArtifact>()); Names.push_back(L"msdia140.dll");
                if (!Sources.back()->OpenHandle(provider, 64ull * 1024 * 1024) || !Sources.back()->PinPath()) { return FailWin32(ERROR_INVALID_DATA); }
            }
            const auto asan = std::filesystem::path(executable).parent_path() / L"clang_rt.asan_dynamic-x86_64.dll";
            const auto attributes = GetFileAttributesW(asan.c_str());
            if (attributes != INVALID_FILE_ATTRIBUTES)
            {
                Sources.push_back(std::make_unique<SchemaArtifact>()); Names.push_back(asan.filename().wstring());
                if (!Sources.back()->Open(asan.wstring(), 64ull * 1024 * 1024) || !Sources.back()->PinPath()) { return FailWin32(ERROR_INVALID_DATA); }
            }
            else if (GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND) { return false; }
            ContentHash key;
            for (size_t i = 0; i < Sources.size(); ++i)
            {
                const auto item = Names[i] + L":" + Sources[i]->Sha256 + L"\n";
                if (!key.Add(reinterpret_cast<const uint8_t*>(item.data()), item.size() * sizeof(wchar_t))) { return FailWin32(ERROR_INVALID_DATA); }
            }
            const auto digest = key.Finish(); if (digest.empty()) { return FailWin32(ERROR_INVALID_DATA); }
            PWSTR local = nullptr;
            const auto located = SHGetKnownFolderPath(FOLDERID_LocalAppData, KF_FLAG_DONT_VERIFY, nullptr, &local);
            if (FAILED(located)) { return FailWin32(HRESULT_FACILITY(located) == FACILITY_WIN32 ? HRESULT_CODE(located) : ERROR_GEN_FAILURE); }
            const auto root = std::filesystem::path(local) / L"KnLiveDbgParserRuntime-v1";
            CoTaskMemFree(local);
            LocalOwner descriptor;
            const auto sddl = L"O:" + userSid + L"D:P(A;OICI;FA;;;" + userSid + L")(A;OICI;FA;;;SY)(A;OICI;0x1200a9;;;AC)";
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1,
                reinterpret_cast<PSECURITY_DESCRIPTOR*>(&descriptor.Value), nullptr)) { return false; }
            SECURITY_ATTRIBUTES security{sizeof(security), descriptor.Value, FALSE};
            if (!CreateDirectoryW(root.c_str(), &security) && GetLastError() != ERROR_ALREADY_EXISTS) { return false; }
            FileOwner directory{CreateFileW(root.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
            FILE_ATTRIBUTE_TAG_INFO info{};
            if (directory.Value == INVALID_HANDLE_VALUE || !GetFileInformationByHandleEx(directory.Value, FileAttributeTagInfo, &info, sizeof(info)) ||
                (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                !SecurityMatches(directory.Value, true)) { return FailWin32(ERROR_INVALID_DATA); }
            if (!RecoverPreparations(root)) { return false; }
            const auto target = root / digest;
            if (GetFileAttributesW(target.c_str()) == INVALID_FILE_ATTRIBUTES)
            {
                if (GetLastError() != ERROR_FILE_NOT_FOUND && GetLastError() != ERROR_PATH_NOT_FOUND) { return false; }
                const auto owner = OwnerKey(); if (owner.empty()) { return FailWin32(ERROR_GEN_FAILURE); }
                const auto temporary = root / (L"prepare-" + owner);
                if (!CreateDirectoryW(temporary.c_str(), &security)) { return false; }
                bool copied = true;
                for (size_t i = 0; copied && i < Sources.size(); ++i) { copied = Copy(i, temporary / Names[i], &security); }
                const bool published = copied && MoveFileExW(temporary.c_str(), target.c_str(), MOVEFILE_WRITE_THROUGH);
                const auto moveError = GetLastError();
                if (!published)
                {
                    // Only this invocation's exact create-new files are removed.
                    for (const auto& name : Names) { DeleteFileW((temporary / name).c_str()); }
                    RemoveDirectoryW(temporary.c_str());
                    if (!copied || (moveError != ERROR_ALREADY_EXISTS && moveError != ERROR_FILE_EXISTS)) { return FailWin32(moveError); }
                }
            }
            FileOwner targetDirectory{CreateFileW(target.c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
            if (targetDirectory.Value == INVALID_HANDLE_VALUE ||
                !GetFileInformationByHandleEx(targetDirectory.Value, FileAttributeTagInfo, &info, sizeof(info)) ||
                (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 || (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
                !SecurityMatches(targetDirectory.Value, true)) { return FailWin32(ERROR_INVALID_DATA); }
            WIN32_FIND_DATAW entry{};
            const auto listing = FindFirstFileW((target / L"*").c_str(), &entry);
            if (listing == INVALID_HANDLE_VALUE) { return false; }
            size_t listed = 0; bool namesMatch = true;
            do
            {
                const std::wstring name = entry.cFileName;
                if (name == L"." || name == L"..") { continue; }
                if ((entry.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 ||
                    std::find(Names.begin(), Names.end(), name) == Names.end()) { namesMatch = false; break; }
                ++listed;
            } while (FindNextFileW(listing, &entry));
            const auto listingError = GetLastError(); FindClose(listing);
            if (!namesMatch || listed != Names.size() || listingError != ERROR_NO_MORE_FILES) { return FailWin32(ERROR_INVALID_DATA); }
            for (size_t i = 0; i < Sources.size(); ++i)
            {
                auto copy = std::make_unique<SchemaArtifact>();
                if (!copy->Open((target / Names[i]).wstring(), 512ull * 1024 * 1024) ||
                    !SecurityMatches(copy->Handle(), false) || !copy->PinPath() || copy->Sha256 != Sources[i]->Sha256) { return FailWin32(ERROR_INVALID_DATA); }
                if (Names[i] == L"worker.exe") { Executable = copy->Path; }
                if (Names[i] == L"msdia140.dll") { Provider = copy->Handle(); }
                Copies.push_back(std::move(copy));
            }
            return !Executable.empty() || FailWin32(ERROR_INVALID_DATA);
        }
    };
}
