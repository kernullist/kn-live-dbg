#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace etl_profile
{
    constexpr size_t MaxStatementBytes = 8192;

    struct StatementAuthority
    {
        std::vector<uint8_t> PublicPoint;
        std::wstring Sha256, Role;
    };

    struct CaptureStatement
    {
        const wchar_t* Status = L"not_checked";
        std::wstring FileSha256, ClaimedEtlSha256, Claims;
        std::optional<bool> SignatureValid, RoleMatches, EtlMatches;
        std::optional<uint64_t> ClaimedBytes;
        bool CaptureController = false;

        bool Bound() const
        {
            return SignatureValid.value_or(false) && RoleMatches.value_or(false) && EtlMatches.value_or(false);
        }
        std::wstring Json(const StatementAuthority& key, bool pageMatches) const;
    };

    // The caller supplies the trusted uncompressed SEC 1 point, independently of the JWS.
    bool ParseStatementAuthority(const std::wstring& role, const std::wstring& hex, StatementAuthority& result);
    CaptureStatement VerifyCaptureStatement(const std::vector<uint8_t>& file, const StatementAuthority& key,
        const std::wstring& etlSha256, uint64_t etlBytes);
}
