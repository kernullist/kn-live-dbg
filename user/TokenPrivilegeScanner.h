#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "DeviceClient.h"
#include "SymbolEngine.h"

struct TokenPrivilegeBit
{
    uint32_t LuidLow = 0;
    std::wstring Name;
    bool Present = false;
    bool Enabled = false;
    bool EnabledByDefault = false;
    bool HighRisk = false;
};

struct TokenPrivilegeRecord
{
    uint32_t ProcessId = 0;
    uint64_t Eprocess = 0;
    uint64_t TokenObject = 0;
    uint64_t TokenRaw = 0;
    std::wstring ImageName;
    std::wstring ImagePath;
    uint64_t PresentMask = 0;
    uint64_t EnabledMask = 0;
    uint64_t EnabledByDefaultMask = 0;
    std::vector<TokenPrivilegeBit> Privileges;
    std::vector<std::wstring> HighRiskEnabled;
    std::vector<std::wstring> Notes;
    bool TokenResolved = false;
    bool PrivilegesResolved = false;
    bool StructuralInconsistency = false;
    bool Suspicious = false;
    bool SystemProfile = false;
    bool IdentityResolved = false;
    bool CoverageIncomplete = false;
    std::wstring PrivilegeFingerprint;
    uint32_t TokenType = 0;
    uint32_t ImpersonationLevel = 0;
    uint32_t SessionId = 0;
    uint32_t IntegrityLevel = 0;
    uint64_t TokenId = 0;
    uint64_t AuthenticationId = 0;
    bool TokenObjectFieldsResolved = false;
    bool PrimaryToken = false;
    bool IntegrityResolved = false;
    std::wstring IntegrityText;
};

struct TokenPrivilegeScanResult
{
    std::vector<TokenPrivilegeRecord> Records;
    std::vector<std::wstring> Warnings;
    bool LayoutFromPdb = false;
    bool ProcessLayoutFromPdb = false;
    bool ProcessWalkComplete = false;
    bool CoverageComplete = false;
    uint32_t SuspiciousCount = 0;
    bool AnySuspicious = false;
};

// Read-only token privilege triage from _EPROCESS.Token / _SEP_TOKEN_PRIVILEGES.
class TokenPrivilegeScanner
{
public:
    struct Options
    {
        uint32_t ProcessId = 0;
        bool HasProcessId = false;
        uint64_t Eprocess = 0;
        bool HasEprocess = false;
        std::wstring ImageFilter;
        bool ScanAll = false;
        uint32_t Limit = 0;
        bool IncludeSystemProfile = false;
        // When false, common admin privileges (SeDebug/SeSecurity/SeTakeOwnership/
        // SeSystemEnvironment) are annotated but do not alone mark Suspicious.
        // Hunt/snapshot use false to avoid clean-host and admin-desktop false
        // positives; interactive !token keeps the default true.
        bool TreatCommonAdminPrivilegesAsSuspicious = true;
        // When true, all privilege-based suspicion, including mask invariants,
        // requires a fully PDB-resolved privilege layout.
        bool RequirePdbLayoutForPrivilegeFindings = false;
    };

    TokenPrivilegeScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(const Options& options, TokenPrivilegeScanResult* result, std::wstring* error);

    // Pure helpers for self-tests / hunt integration.
    static bool IsHighRiskPrivilegeName(const std::wstring& name);
    static bool IsSystemProfileImage(
        const std::wstring& imageName,
        uint32_t pid,
        const std::wstring& imagePath = std::wstring());
    static std::wstring PrivilegeNameFromBit(uint32_t bitIndex);
    static std::wstring BuildPrivilegeFingerprint(uint64_t present, uint64_t enabled);
    static bool HasStructuralMaskInconsistency(
        uint64_t present,
        uint64_t enabled);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildTokenPrivilegeJson(const TokenPrivilegeScanResult& result);
bool TokenPrivilegeMaskInvariantSelfTest();
bool TokenPrivilegeSystemProfileSelfTest();
