#include "EvidencePrivacy.h"
#include "AnalystSnapshot.h"
#include "ContentHash.h"
#include "McpJson.h"
#include <aclapi.h>
#include <sddl.h>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <vector>

#pragma comment(lib, "advapi32.lib")
namespace fs = std::filesystem;
namespace
{
    using Handle = std::unique_ptr<void, decltype(&CloseHandle)>;
    using Local = std::unique_ptr<void, decltype(&LocalFree)>;
    Handle Own(HANDLE value) { return {value == INVALID_HANDLE_VALUE ? nullptr : value, &CloseHandle}; }
    std::wstring Native(const fs::path& path) { auto p = path; p.make_preferred(); return L"\\\\?\\" + p.wstring(); }
    bool Resolve(const std::wstring& input, fs::path* output)
    {
        if (input.empty() || input.size() > 30000 || input.find(L'\0') != std::wstring::npos || mcpjson::SanitizeUtf16(input) != input) { return false; }
        // Check spelling before absolute(): Windows can remove trailing dots or
        // spaces there, making a rejected name alias an otherwise valid root.
        for (const auto& part : fs::path(input).relative_path())
        {
            auto name = part.wstring();
            if (name.empty() || name == L"." || name == L"..") { continue; }
            if (name.back() == L'.' || name.back() == L' ' || name.find_first_of(L"<>:\"|?*") != std::wstring::npos) { return false; }
            name.resize(name.find(L'.') == std::wstring::npos ? name.size() : name.find(L'.'));
            for (auto& ch : name) { if (ch >= L'a' && ch <= L'z') { ch -= L'a' - L'A'; } }
            if (name == L"CON" || name == L"PRN" || name == L"AUX" || name == L"NUL" || name == L"CONIN$" || name == L"CONOUT$") { return false; }
            if (name.size() == 4 && (name.compare(0, 3, L"COM") == 0 || name.compare(0, 3, L"LPT") == 0) &&
                ((name[3] >= L'1' && name[3] <= L'9') || name[3] == L'\u00b9' || name[3] == L'\u00b2' || name[3] == L'\u00b3')) { return false; }
        }
        std::error_code ec;
        *output = fs::absolute(input, ec).lexically_normal();
        if (output->has_relative_path() && output->filename().empty()) { *output = output->parent_path(); }
        const auto value = output->wstring();
        if (ec || value.size() < 4 || value.size() > 30000 || value[1] != L':' ||
            (value[2] != L'\\' && value[2] != L'/') || value.find(L':', 2) != std::wstring::npos || *output == output->root_path()) { return false; }
        const auto drive = GetDriveTypeW(output->root_path().c_str());
        if (drive != DRIVE_FIXED && drive != DRIVE_REMOVABLE && drive != DRIVE_RAMDISK) { return false; }
        for (const auto& part : output->relative_path())
        {
            const auto name = part.wstring();
            if (name.empty() || name.back() == L'.' || name.back() == L' ') { return false; }
        }
        return true;
    }
    bool CurrentSid(std::wstring* text)
    {
        HANDLE raw = nullptr;
        if (!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &raw) &&
            (GetLastError() != ERROR_NO_TOKEN || !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw))) { return false; }
        auto token = Own(raw);
        DWORD size = 0;
        GetTokenInformation(token.get(), TokenUser, nullptr, 0, &size);
        if (size == 0 || size > 65536) { return false; }
        std::vector<uint8_t> bytes(size);
        if (!GetTokenInformation(token.get(), TokenUser, bytes.data(), size, &size)) { return false; }
        LPWSTR value = nullptr;
        if (!ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER*>(bytes.data())->User.Sid, &value)) { return false; }
        Local owner(value, &LocalFree); *text = value; return true;
    }
    Handle OpenObject(const fs::path& path, DWORD extra = 0, bool pinDirectory = false)
    {
        // Metadata-only handles do not participate in Windows share-access
        // exclusion. FILE_LIST_DIRECTORY / FILE_READ_DATA makes the pin effective.
        return Own(CreateFileW(Native(path).c_str(), FILE_READ_ATTRIBUTES | READ_CONTROL | extra | (pinDirectory ? FILE_READ_DATA : 0),
            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, nullptr));
    }
    bool Attributes(HANDLE file, bool directory, bool efs)
    {
        BY_HANDLE_FILE_INFORMATION info{};
        return file != nullptr && GetFileType(file) == FILE_TYPE_DISK && GetFileInformationByHandle(file, &info) &&
            (info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
            ((info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) == directory &&
            (!efs || (info.dwFileAttributes & FILE_ATTRIBUTE_ENCRYPTED) != 0) && (directory || info.nNumberOfLinks == 1);
    }
    bool Pin(const fs::path& path, std::vector<Handle>* handles)
    {
        auto current = path.root_path();
        auto root = OpenObject(current, 0, true);
        if (!Attributes(root.get(), true, false)) { return false; }
        handles->push_back(std::move(root));
        size_t depth = 0;
        for (const auto& part : path.relative_path())
        {
            if (++depth > 128) { return false; }
            current /= part;
            auto directory = OpenObject(current, 0, true);
            if (!Attributes(directory.get(), true, false)) { return false; }
            handles->push_back(std::move(directory));
        }
        return true;
    }
    bool Identity(HANDLE file, std::wstring* value)
    {
        FILE_ID_INFO id{}; FILETIME created{}, accessed{}, written{};
        if (!GetFileInformationByHandleEx(file, FileIdInfo, &id, sizeof(id)) || !GetFileTime(file, &created, &accessed, &written)) { return false; }
        const auto birth = (uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        std::wstring hex; bool nonzero = false;
        for (auto byte : id.FileId.Identifier)
        {
            nonzero |= byte != 0; hex += L"0123456789abcdef"[byte >> 4]; hex += L"0123456789abcdef"[byte & 15];
        }
        if (!birth || !nonzero) { return false; }
        *value = std::to_wstring(id.VolumeSerialNumber) + L":" + hex + L":" + std::to_wstring(birth); return true;
    }
    bool PrivateAcl(HANDLE file, const std::wstring& principal, bool root, bool directory = false)
    {
        PSID user = nullptr;
        if (!ConvertStringSidToSidW(principal.c_str(), &user)) { return false; }
        Local userOwner(user, &LocalFree);
        PSID owner = nullptr; PACL acl = nullptr; PSECURITY_DESCRIPTOR sd = nullptr;
        if (GetSecurityInfo(file, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &owner, nullptr, &acl, nullptr, &sd) != ERROR_SUCCESS) { return false; }
        Local sdOwner(sd, &LocalFree);
        SECURITY_DESCRIPTOR_CONTROL control = 0; DWORD revision = 0;
        if (!sd || !acl || !IsValidAcl(acl) || !owner || !IsValidSid(owner) ||
            !GetSecurityDescriptorControl(sd, &control, &revision) || (root && (control & SE_DACL_PROTECTED) == 0)) { return false; }
        // Elevated Windows creators may assign Administrators as a child's owner.
        // Administrators/SYSTEM are inside this OS access-control trust boundary.
        if (!EqualSid(owner, user) && (root || (!IsWellKnownSid(owner, WinBuiltinAdministratorsSid) && !IsWellKnownSid(owner, WinLocalSystemSid)))) { return false; }
        bool haveUser = false, haveSystem = false;
        if (acl->AceCount == 0 || acl->AceCount > 2) { return false; }
        for (DWORD i = 0; i < acl->AceCount; ++i)
        {
            void* raw = nullptr;
            if (!GetAce(acl, i, &raw)) { return false; }
            auto ace = reinterpret_cast<ACCESS_ALLOWED_ACE*>(raw);
            if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace->Mask != FILE_ALL_ACCESS ||
                ace->Header.AceSize < offsetof(ACCESS_ALLOWED_ACE, SidStart) + 8 ||
                (ace->Header.AceFlags & (INHERIT_ONLY_ACE | NO_PROPAGATE_INHERIT_ACE)) != 0) { return false; }
            auto sid = reinterpret_cast<PSID>(&ace->SidStart);
            if (!IsValidSid(sid) || GetLengthSid(sid) > ace->Header.AceSize - offsetof(ACCESS_ALLOWED_ACE, SidStart)) { return false; }
            const bool allowedUser = EqualSid(sid, user) != FALSE, allowedSystem = IsWellKnownSid(sid, WinLocalSystemSid) != FALSE;
            if (!allowedUser && !allowedSystem) { return false; }
            if ((root || directory) && (ace->Header.AceFlags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)) != (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)) { return false; }
            haveUser |= allowedUser; haveSystem |= allowedSystem;
        }
        return haveUser && haveSystem;
    }
    std::wstring PolicyJson(const EvidencePrivacyReport& r)
    {
        return L"{\"schema\":\"kn.evidence_private_store.v1\",\"policy\":" + mcpjson::Quote(r.Policy) +
            L",\"owner_sid\":" + mcpjson::Quote(r.OwnerSid) + L",\"root_identity\":" + mcpjson::Quote(r.RootIdentity) + L"}";
    }
    bool ReadPolicy(HANDLE file, std::wstring* json, std::wstring* hash)
    {
        LARGE_INTEGER size{};
        if (!GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > 4096) { return false; }
        std::vector<uint8_t> bytes(static_cast<size_t>(size.QuadPart)); DWORD read = 0;
        if (!ReadFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) || read != bytes.size()) { return false; }
        const std::string text(bytes.begin(), bytes.end()); *json = mcpjson::Utf8ToWide(text); *hash = ContentHash::Bytes(bytes);
        return !hash->empty() && mcpjson::WideToUtf8(*json) == text && mcpjson::ValidateDocument(*json);
    }
    bool Audit(const fs::path& root, EvidencePrivacyReport* report)
    {
        const auto start = GetTickCount64();
        // Depth-first traversal holds every active directory through enumeration,
        // excluding name deletion/rename. The owning principal remains trusted;
        // this is not an atomic descriptor or reparse-metadata snapshot.
        const auto visit = [&](const auto& self, const fs::path& path, unsigned depth) -> bool
        {
            if (depth > 128) { report->Issue = L"privacy_audit_depth_exhausted"; return false; }
            std::error_code ec;
            for (fs::directory_iterator it(Native(path), ec), end; !ec && it != end; it.increment(ec))
            {
                if (report->CheckedEntries >= 65536 || GetTickCount64() - start > 120000)
                    { report->Issue = L"privacy_audit_budget_exhausted"; return false; }
                // Iterator names are joined to the validated local path, not
                // interpreted as independent roots or followed through reparse points.
                const auto child = path / it->path().filename();
                auto object = OpenObject(child, 0, true);
                FILE_ATTRIBUTE_TAG_INFO tag{};
                if (!object || !GetFileInformationByHandleEx(object.get(), FileAttributeTagInfo, &tag, sizeof(tag)))
                    { report->Issue = L"privacy_object_unavailable"; return false; }
                const bool directory = (tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;
                if (!Attributes(object.get(), directory, report->EfsRequired) || !PrivateAcl(object.get(), report->OwnerSid, false, directory))
                    { report->Issue = L"privacy_object_policy_mismatch"; return false; }
                ++report->CheckedEntries;
                if (directory && !self(self, child, depth + 1)) { return false; }
            }
            if (ec) { report->Issue = L"privacy_audit_enumeration_failed"; return false; }
            return true;
        };
        if (!visit(visit, root, 0)) { return false; }
        report->AuditComplete = true; return true;
    }
}

struct EvidencePrivacyGuard::Impl
{
    std::vector<Handle> Directories;
    Handle Policy{nullptr, &CloseHandle};
    std::wstring OwnerSid;
    bool EfsRequired = false;
};
EvidencePrivacyGuard::EvidencePrivacyGuard() : Data(std::make_unique<Impl>()) {}
EvidencePrivacyGuard::~EvidencePrivacyGuard() = default;
bool EvidencePrivacyGuard::Open(const std::wstring& root, bool audit, EvidencePrivacyReport* report)
{
    EvidencePrivacyReport out;
    const auto fail = [&](const wchar_t* issue)
    {
        out.Status = L"denied"; out.Issue = issue; Data->Policy.reset(); Data->Directories.clear();
        if (report) { *report = out; } return false;
    };
    if (Data->Policy)
    {
        out.Status = L"denied"; out.Issue = L"privacy_guard_already_open";
        if (report) { *report = out; } return false; // Preserve the original guard.
    }
    try
    {
        fs::path path;
        if (!Resolve(root, &path) || !Pin(path, &Data->Directories)) { return fail(L"privacy_requires_pinned_local_root"); }
        out.RootPath = path.wstring();
        if (!CurrentSid(&out.OwnerSid) || !Identity(Data->Directories.back().get(), &out.RootIdentity)) { return fail(L"privacy_principal_or_identity_unavailable"); }
        const auto policyPath = path / L"store.knprivacy";
        Data->Policy = Own(CreateFileW(Native(policyPath).c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        std::wstring json;
        if (!Data->Policy || !ReadPolicy(Data->Policy.get(), &json, &out.PolicySha256) || !mcpjson::GetString(json, L"policy", &out.Policy))
            { return fail(L"private_store_policy_unavailable"); }
        out.EfsRequired = out.Policy == L"kn.current_principal_efs.v1";
        if ((!out.EfsRequired && out.Policy != L"kn.current_principal_acl.v1") || PolicyJson(out) != json)
            { return fail(L"private_store_policy_principal_or_identity_mismatch"); }
        if (!Attributes(Data->Directories.back().get(), true, out.EfsRequired) ||
            !PrivateAcl(Data->Directories.back().get(), out.OwnerSid, true) ||
            !Attributes(Data->Policy.get(), false, out.EfsRequired) || !PrivateAcl(Data->Policy.get(), out.OwnerSid, false))
            { return fail(L"private_store_root_or_policy_protection_mismatch"); }
        out.RootAclVerified = true; out.CheckedEntries = audit ? 0 : 1;
        if (audit && !Audit(path, &out)) { const auto issue = out.Issue; return fail(issue.c_str()); }
        Data->OwnerSid = out.OwnerSid; Data->EfsRequired = out.EfsRequired;
        out.Status = L"ready"; if (report) { *report = out; } return true;
    }
    catch (...) { return fail(L"privacy_validation_exception"); }
}
bool EvidencePrivacyGuard::CheckFile(HANDLE file) const
{
    return Data->Policy && Attributes(file, false, Data->EfsRequired) && PrivateAcl(file, Data->OwnerSid, false);
}

EvidencePrivacyReport InitializeEvidencePrivateStore(const std::wstring& root, bool efs, const std::function<void(const wchar_t*)>& observer)
{
    EvidencePrivacyReport out; out.EfsRequired = efs;
    out.Policy = efs ? L"kn.current_principal_efs.v1" : L"kn.current_principal_acl.v1";
    try
    {
        fs::path target; std::vector<Handle> ancestors;
        if (!Resolve(root, &target) || !Pin(target.parent_path(), &ancestors) || !CurrentSid(&out.OwnerSid))
            { out.Issue = L"privacy_requires_existing_local_parent_and_principal"; return out; }
        out.RootPath = target.wstring();
        const auto attributes = GetFileAttributesW(Native(target).c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES || GetLastError() != ERROR_FILE_NOT_FOUND)
            { out.Issue = L"private_store_output_exists_or_unavailable"; return out; }
        PSECURITY_DESCRIPTOR raw = nullptr;
        const auto sddl = L"O:" + out.OwnerSid + L"D:P(A;OICI;FA;;;" + out.OwnerSid + L")" +
            (out.OwnerSid == L"S-1-5-18" ? L"" : L"(A;OICI;FA;;;SY)");
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &raw, nullptr))
            { out.Issue = L"private_store_descriptor_unavailable"; return out; }
        Local descriptor(raw, &LocalFree); SECURITY_ATTRIBUTES sa{sizeof(sa), raw, FALSE};
        uint8_t random[16]{};
        if (BCryptGenRandom(nullptr, random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
            { out.Issue = L"private_store_name_unavailable"; return out; }
        std::wstring name = L".kn-private-";
        for (auto byte : random) { name += L"0123456789abcdef"[byte >> 4]; name += L"0123456789abcdef"[byte & 15]; }
        const auto temporary = target.parent_path() / name;
        if (!CreateDirectoryW(Native(temporary).c_str(), &sa)) { out.Issue = L"private_store_creation_failed"; return out; }
        out.TemporaryDirectory = temporary.wstring();
        auto directory = OpenObject(temporary, DELETE);
        if (!Attributes(directory.get(), true, false) || !PrivateAcl(directory.get(), out.OwnerSid, true) || !Identity(directory.get(), &out.RootIdentity))
            { out.Issue = L"private_store_initial_protection_failed"; return out; }
        if (observer) { observer(L"private_root_created"); }
        directory.reset(); // EncryptFile requires exclusive access; no evidence is present yet.
        if (efs && !EncryptFileW(Native(temporary).c_str()))
            { out.Issue = L"efs_initialization_failed_" + std::to_wstring(GetLastError()); return out; }
        directory = OpenObject(temporary, DELETE);
        std::wstring identity;
        if (!Attributes(directory.get(), true, efs) || !PrivateAcl(directory.get(), out.OwnerSid, true) ||
            !Identity(directory.get(), &identity) || identity != out.RootIdentity)
            { out.Issue = L"private_store_identity_or_encryption_changed"; return out; }
        if (observer) { observer(L"private_root_protected"); }
        const auto policy = temporary / L"store.knprivacy";
        if (!SaveObservationJson(Native(policy), PolicyJson(out), nullptr)) { out.Issue = L"private_store_policy_publication_failed"; return out; }
        {
            auto file = Own(CreateFileW(Native(policy).c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr,
                OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
            std::wstring verified;
            if (!Attributes(file.get(), false, efs) || !PrivateAcl(file.get(), out.OwnerSid, false) ||
                !ReadPolicy(file.get(), &verified, &out.PolicySha256) || verified != PolicyJson(out))
                { out.Issue = L"private_store_policy_verification_failed"; return out; }
        }
        if (observer) { observer(L"private_policy_committed"); }
        const auto targetName = Native(target);
        const auto size = offsetof(FILE_RENAME_INFO, FileName) + (targetName.size() + 1) * sizeof(wchar_t);
        std::vector<uint8_t> storage(size, 0);
        auto rename = reinterpret_cast<FILE_RENAME_INFO*>(storage.data());
        rename->FileNameLength = static_cast<DWORD>(targetName.size() * sizeof(wchar_t));
        std::memcpy(rename->FileName, targetName.data(), rename->FileNameLength);
        if (!SetFileInformationByHandle(directory.get(), FileRenameInfo, rename, static_cast<DWORD>(size)))
            { out.Issue = L"private_store_publication_failed_" + std::to_wstring(GetLastError()); return out; }
        out.TemporaryDirectory.clear(); out.RootAclVerified = true; out.AuditComplete = true;
        out.CheckedEntries = 1; out.Initialized = true; out.Status = L"ready";
        if (observer) { observer(L"private_root_published"); }
    }
    catch (...) { out.Status = L"incomplete"; out.Issue = L"private_store_initialization_exception"; }
    return out;
}
EvidencePrivacyReport InspectEvidencePrivacy(const std::wstring& root, bool audit)
{
    EvidencePrivacyGuard guard; EvidencePrivacyReport out; guard.Open(root, audit, &out); return out;
}
std::wstring EvidencePrivacyJson(const EvidencePrivacyReport& r)
{
    return L"{\"schema\":\"kn.evidence_privacy.v1\",\"status\":" + mcpjson::Quote(r.Status) + L",\"issue\":" + mcpjson::Quote(r.Issue) +
        L",\"policy\":" + mcpjson::Quote(r.Policy) + L",\"owner_sid\":" + mcpjson::Quote(r.OwnerSid) + L",\"root_identity\":" + mcpjson::Quote(r.RootIdentity) +
        L",\"policy_sha256\":" + mcpjson::Quote(r.PolicySha256) + L",\"temporary_directory\":" + mcpjson::Quote(r.TemporaryDirectory) +
        L",\"root\":" + mcpjson::Quote(r.RootPath) +
        L",\"initialized\":" + (r.Initialized ? L"true" : L"false") + L",\"efs_required\":" + (r.EfsRequired ? L"true" : L"false") +
        L",\"root_acl_verified\":" + (r.RootAclVerified ? L"true" : L"false") + L",\"audit_complete\":" + (r.AuditComplete ? L"true" : L"false") +
        L",\"checked_entries\":" + mcpjson::Quote(std::to_wstring(r.CheckedEntries)) +
        L",\"scope\":\"local_current_principal_and_system\",\"atomic_security_snapshot\":false,\"administrator_or_recovery_agent_excluded\":false,"
        L"\"collector_authenticated\":false,\"external_transfer_authorized\":false,\"power_loss_durability_established\":false}";
}
