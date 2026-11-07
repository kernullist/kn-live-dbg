#pragma once

#include "parser-worker-profile.h"

namespace worker_runtime
{
    inline void WriteDenial(const std::wstring& executable, void(*check)(bool, const char*))
    {
        // Hold parent-derived runtime pins so even a failed negative control
        // cleans only this worker's exact create-new filename in its own cache.
        parser_sandbox::Runtime runtime;
        if (!runtime.Prepare(executable, INVALID_HANDLE_VALUE, worker_profile::UserSid()))
        { check(false, "owned runtime prepared for create-only access control"); return; }
        ParserWorkerRequest request; request.Executable = executable; request.Arguments = {L"--child", L"runtime-write"};
        const auto result = RunParserWorker(request);
        check(result.Status == L"exited" && result.SandboxVerified && result.Output == "runtime_write_denied",
            "worker cannot create a DLL when requesting write access alone");
        bool clean = result.ProcessId != 0;
        if (result.ProcessId != 0)
        {
            const auto extra = std::filesystem::path(runtime.Executable).parent_path() /
                (L"unapproved-" + std::to_wstring(result.ProcessId) + L".dll");
            worker_profile::Handle file{CreateFileW(extra.c_str(), DELETE | FILE_READ_ATTRIBUTES, FILE_SHARE_READ, nullptr,
                OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
            if (file.Value == INVALID_HANDLE_VALUE) { clean = GetLastError() == ERROR_FILE_NOT_FOUND; }
            else
            {
                FILE_ATTRIBUTE_TAG_INFO attributes{}; FILE_DISPOSITION_INFO disposition{TRUE};
                clean = GetFileInformationByHandleEx(file.Value, FileAttributeTagInfo, &attributes, sizeof(attributes)) &&
                    (attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0 &&
                    SetFileInformationByHandle(file.Value, FileDispositionInfo, &disposition, sizeof(disposition));
            }
        }
        check(clean, "owned create-only access control leaves no extra runtime file");
    }

    class AclChange
    {
        std::wstring Path;
        PSECURITY_DESCRIPTOR Original = nullptr;
        PACL OriginalAcl = nullptr;
        PACL Modified = nullptr;
        SECURITY_INFORMATION RestoreFlags = DACL_SECURITY_INFORMATION;
        bool Changed = false;
    public:
        ~AclChange() { Restore(); LocalFree(Modified); LocalFree(Original); }
        bool Weaken(const std::wstring& path)
        {
            Path = path;
            if (GetNamedSecurityInfoW(Path.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, &OriginalAcl,
                nullptr, &Original) != ERROR_SUCCESS) { return false; }
            SECURITY_DESCRIPTOR_CONTROL control{}; DWORD revision = 0;
            if (!GetSecurityDescriptorControl(Original, &control, &revision)) { return false; }
            RestoreFlags |= (control & SE_DACL_PROTECTED) != 0 ? PROTECTED_DACL_SECURITY_INFORMATION : UNPROTECTED_DACL_SECURITY_INFORMATION;
            uint8_t apps[SECURITY_MAX_SID_SIZE]{}; DWORD size = sizeof(apps);
            if (!CreateWellKnownSid(WinBuiltinAnyPackageSid, nullptr, apps, &size)) { return false; }
            EXPLICIT_ACCESSW entry{}; entry.grfAccessMode = GRANT_ACCESS; entry.grfAccessPermissions = FILE_GENERIC_WRITE;
            entry.Trustee.TrusteeForm = TRUSTEE_IS_SID; entry.Trustee.ptstrName = reinterpret_cast<LPWSTR>(apps);
            Changed = SetEntriesInAclW(1, &entry, OriginalAcl, &Modified) == ERROR_SUCCESS &&
                SetNamedSecurityInfoW(Path.data(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    nullptr, nullptr, Modified, nullptr) == ERROR_SUCCESS;
            return Changed;
        }
        bool Restore()
        {
            if (!Changed) { return true; }
            if (SetNamedSecurityInfoW(Path.data(), SE_FILE_OBJECT, RestoreFlags, nullptr, nullptr, OriginalAcl, nullptr) != ERROR_SUCCESS) { return false; }
            Changed = false; return true;
        }
    };
    inline void Run(const std::wstring& executable, void(*check)(bool, const char*))
    {
        std::wstring code;
        {
            parser_sandbox::Runtime runtime;
            if (!runtime.Prepare(executable, INVALID_HANDLE_VALUE, worker_profile::UserSid()))
            { check(false, "owned runtime prepared for integrity controls"); return; }
            code = runtime.Executable;
        }
        bool distinct = false;
        {
            worker_profile::Handle original{CreateFileW(executable.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
            worker_profile::Handle copy{CreateFileW(code.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr)};
            FILE_ID_INFO first{}, second{};
            distinct = original.Value != INVALID_HANDLE_VALUE && copy.Value != INVALID_HANDLE_VALUE &&
                GetFileInformationByHandleEx(original.Value, FileIdInfo, &first, sizeof(first)) &&
                GetFileInformationByHandleEx(copy.Value, FileIdInfo, &second, sizeof(second)) && std::memcmp(&first, &second, sizeof(first)) != 0;
        }
        const auto originalHash = ContentHash::File(executable);
        const bool ownedCopy = distinct && !originalHash.empty() && ContentHash::File(code) == originalHash;
        check(ownedCopy, "runtime bytes match the source in a distinct file object");
        if (!ownedCopy) { return; }
        ParserWorkerRequest request; request.Executable = executable;
        request.Arguments = {L"--child", L"ok", L"space and \"quote\" trailing\\", L""};
        const auto rejected = [&]() {
            const auto result = RunParserWorker(request);
            return result.Status == L"runtime_configuration_failed" && result.Error == ERROR_INVALID_DATA &&
                result.ProcessId == 0 && result.Output.empty() && !result.SandboxVerified;
        };
        worker_profile::ByteRestore byte{code};
        const bool read = worker_profile::ReceiptByte(code, &byte.Original, false);
        uint8_t altered = byte.Original ^ 1;
        byte.Changed = read && worker_profile::ReceiptByte(code, &altered, true);
        check(byte.Changed && rejected(), "runtime content substitution fails before process creation");
        check(byte.Restore(), "owned runtime byte restored");
        {
            const auto extra = std::filesystem::path(code).parent_path() / L"unapproved.dll";
            worker_profile::Handle file{CreateFileW(extra.c_str(), GENERIC_WRITE | DELETE, FILE_SHARE_READ, nullptr, CREATE_NEW,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, nullptr)};
            check(file.Value != INVALID_HANDLE_VALUE && rejected(), "extra DLL is rejected before process creation");
        }
        for (const auto& path : {std::filesystem::path(code), std::filesystem::path(code).parent_path()})
        {
            AclChange acl;
            check(acl.Weaken(path.wstring()) && rejected(), "writable runtime file or directory fails before process creation");
            check(acl.Restore(), "owned runtime ACL restored");
        }
        const auto result = RunParserWorker(request);
        check(result.Status == L"exited" && result.SandboxVerified && result.Output == "owned_worker_ok" &&
            ContentHash::File(code) == originalHash && ContentHash::File(executable) == originalHash,
            "restored runtime executes and original executable remains unchanged");
    }
}
