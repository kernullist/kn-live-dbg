#pragma once

#include <Windows.h>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

struct EvidencePrivacyReport
{
    std::wstring Status = L"unavailable", Issue, Policy, OwnerSid, RootIdentity, PolicySha256;
    std::wstring TemporaryDirectory;
    std::wstring RootPath;
    uint64_t CheckedEntries = 0;
    bool Initialized = false, EfsRequired = false, RootAclVerified = false, AuditComplete = false;
};

// Keeps the local root/ancestors and immutable policy pinned. Audit describes
// observed metadata, not an atomic security snapshot or a hostile-owner boundary.
class EvidencePrivacyGuard
{
public:
    EvidencePrivacyGuard();
    ~EvidencePrivacyGuard();
    EvidencePrivacyGuard(const EvidencePrivacyGuard&) = delete;
    EvidencePrivacyGuard& operator=(const EvidencePrivacyGuard&) = delete;
    bool Open(const std::wstring& root, bool audit, EvidencePrivacyReport* report);
    bool CheckFile(HANDLE file) const;
private:
    struct Impl;
    std::unique_ptr<Impl> Data;
};

// Creates a new root only. Encryption is required by default, never silently
// downgraded. Failure may retain a private temporary directory for inspection.
EvidencePrivacyReport InitializeEvidencePrivateStore(const std::wstring& root, bool efs = true,
    const std::function<void(const wchar_t*)>& observer = {});
EvidencePrivacyReport InspectEvidencePrivacy(const std::wstring& root, bool audit = false);
std::wstring EvidencePrivacyJson(const EvidencePrivacyReport& report);
