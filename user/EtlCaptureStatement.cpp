#include "EtlCaptureStatement.h"
#include "ContentHash.h"
#include "EtlProfileRecord.h"
#include "P256Signature.h"
#include "TraceJsonFields.h"

#include <string_view>

namespace etl_profile
{
    namespace
    {
        using trace_json::Object;
        using mcpjson::Quote;

        int HexDigit(wchar_t ch)
        {
            if (ch >= L'0' && ch <= L'9') { return ch - L'0'; }
            if (ch >= L'a' && ch <= L'f') { return ch - L'a' + 10; }
            if (ch >= L'A' && ch <= L'F') { return ch - L'A' + 10; }
            return -1;
        }

        bool Decode64(std::string_view text, size_t maximum, std::vector<uint8_t>& out)
        {
            if (text.empty() || text.size() % 4 == 1 || text.size() * 6 / 8 > maximum) { return false; }
            unsigned value = 0, bits = 0;
            for (const char c : text)
            {
                unsigned digit = 0;
                if (c >= 'A' && c <= 'Z') { digit = c - 'A'; }
                else if (c >= 'a' && c <= 'z') { digit = c - 'a' + 26; }
                else if (c >= '0' && c <= '9') { digit = c - '0' + 52; }
                else if (c == '-') { digit = 62; }
                else if (c == '_') { digit = 63; }
                else { return false; }
                value = (value << 6) | digit;
                bits += 6;
                if (bits >= 8)
                {
                    bits -= 8;
                    out.push_back(static_cast<uint8_t>(value >> bits));
                    value &= (1u << bits) - 1;
                }
            }
            return value == 0;
        }

        bool JsonObject(const std::vector<uint8_t>& bytes, Object& fields)
        {
            if (bytes.empty() || bytes.front() != '{') { return false; }
            const std::string utf8(bytes.begin(), bytes.end());
            const auto text = mcpjson::Utf8ToWide(utf8);
            return mcpjson::WideToUtf8(text) == utf8 && trace_json::ReadObject(text, &fields);
        }

        bool Label(const std::wstring& raw, const wchar_t* expected)
        {
            std::wstring text;
            return trace_json::Text(raw, &text) && text == expected;
        }

        bool Id(const std::wstring& raw, std::wstring& json)
        {
            if (raw == L"null") { json = raw; return true; }
            std::wstring value;
            if (!trace_json::Text(raw, &value, 36) || value.size() != 36) { return false; }
            bool nonzero = false;
            for (size_t i = 0; i < value.size(); ++i)
            {
                const auto c = value[i];
                if (i == 8 || i == 13 || i == 18 || i == 23) { if (c != L'-') { return false; } }
                else
                {
                    if (std::wstring_view(L"0123456789abcdef").find(c) == std::wstring_view::npos) { return false; }
                    nonzero |= c != L'0';
                }
            }
            json = Quote(value);
            return nonzero;
        }

        bool Claims(const std::vector<uint8_t>& bytes, CaptureStatement& out)
        {
            Object f;
            if (!JsonObject(bytes, f) || !trace_json::HasFields(f, {L"schema", L"role", L"etl_sha256", L"etl_bytes",
                L"session_id", L"target_id", L"boot_id", L"se_system_profile_privilege_enabled", L"system_trace_enable_flags",
                L"sampled_profile_stack_requested", L"context_switch_stack_requested"}) ||
                !Label(f.at(L"schema"), L"kn.etl_capture_statement.v1")) { return false; }
            const bool controller = Label(f.at(L"role"), L"capture_controller");
            if (!controller && !Label(f.at(L"role"), L"archive_witness")) { return false; }
            std::wstring digest, session, target, boot;
            uint64_t size = 0, flags = 0;
            if (!trace_json::Text(f.at(L"etl_sha256"), &digest, 64) || digest.size() != 64 ||
                digest.find_first_not_of(L"0123456789abcdef") != std::wstring::npos ||
                !trace_json::Number(f.at(L"etl_bytes"), &size) || !size || size > MaxFileBytes ||
                !Id(f.at(L"session_id"), session) || !Id(f.at(L"target_id"), target) || !Id(f.at(L"boot_id"), boot) ||
                controller != (session != L"null") || (!controller && (target != L"null" || boot != L"null"))) { return false; }
            const auto& mask = f.at(L"system_trace_enable_flags");
            if (mask != L"null" && (!controller || !trace_json::Decimal(mask, &flags) || flags > UINT32_MAX)) { return false; }
            for (const auto* k : {L"se_system_profile_privilege_enabled", L"sampled_profile_stack_requested", L"context_switch_stack_requested"})
            {
                const auto& value = f.at(k);
                if (value != L"null" && (!controller || (value != L"true" && value != L"false"))) { return false; }
            }
            out.ClaimedEtlSha256 = digest;
            out.ClaimedBytes = size;
            out.CaptureController = controller;
            out.Claims = L"{\"role\":" + Quote(controller ? L"capture_controller" : L"archive_witness") +
                L",\"session_id\":" + session + L",\"target_id\":" + target + L",\"boot_id\":" + boot +
                L",\"system_trace_enable_flags\":" + mask + L",\"se_system_profile_privilege_enabled\":" +
                f.at(L"se_system_profile_privilege_enabled") + L",\"sampled_profile_stack_requested\":" +
                f.at(L"sampled_profile_stack_requested") + L",\"context_switch_stack_requested\":" +
                f.at(L"context_switch_stack_requested") + L"}";
            return true;
        }

        const wchar_t* Boolean(std::optional<bool> value)
        {
            return !value ? L"null" : *value ? L"true" : L"false";
        }
    }

    bool ParseStatementAuthority(const std::wstring& role, const std::wstring& hex, StatementAuthority& result)
    {
        result = {};
        if (role != L"capture_controller" && role != L"archive_witness") { return false; }
        if (hex.size() != 130 || hex.compare(0, 2, L"04")) { return false; }
        std::vector<uint8_t> key;
        for (size_t i = 0; i < hex.size(); i += 2)
        {
            const int high = HexDigit(hex[i]), low = HexDigit(hex[i + 1]);
            if (high < 0 || low < 0) { return false; }
            key.push_back(static_cast<uint8_t>((high << 4) | low));
        }
        result.Role = role;
        result.Sha256 = ContentHash::Bytes(key);
        result.PublicPoint = std::move(key);
        return !result.Sha256.empty();
    }

    CaptureStatement VerifyCaptureStatement(const std::vector<uint8_t>& file, const StatementAuthority& key,
        const std::wstring& etlSha256, uint64_t etlBytes)
    {
        CaptureStatement out;
        out.Status = L"invalid_jws";
        if (file.empty() || file.size() > MaxStatementBytes || key.PublicPoint.size() != 65) { return out; }
        std::string_view token(reinterpret_cast<const char*>(file.data()), file.size());
        if (token.back() == '\n')
        {
            token.remove_suffix(1);
            if (!token.empty() && token.back() == '\r') { token.remove_suffix(1); }
        }
        const auto first = token.find('.');
        if (first == token.npos) { return out; }
        const auto last = token.find('.', first + 1);
        if (last == token.npos) { return out; }
        std::vector<uint8_t> protectedHeader, payload, signature;
        Object header;
        if (!Decode64(token.substr(0, first), 512, protectedHeader) || !JsonObject(protectedHeader, header) ||
            !trace_json::HasFields(header, {L"alg", L"typ"}) || !Label(header.at(L"alg"), L"ES256") ||
            !Label(header.at(L"typ"), L"kn.etl_capture_statement.v1+jws") ||
            !Decode64(token.substr(first + 1, last - first - 1), 4096, payload) ||
            !Decode64(token.substr(last + 1), 64, signature) || signature.size() != 64) { return out; }

        BCRYPT_ECCKEY_BLOB publicHeader{BCRYPT_ECDSA_PUBLIC_P256_MAGIC, 32};
        std::vector<uint8_t> blob(sizeof(publicHeader));
        std::memcpy(blob.data(), &publicHeader, sizeof(publicHeader));
        blob.insert(blob.end(), key.PublicPoint.begin() + 1, key.PublicPoint.end());
        std::vector<uint8_t> digest;
        out.Status = L"hash_unavailable";
        if (!p256_signature::Sha256(file.data(), last, &digest)) { return out; }
        out.SignatureValid = p256_signature::VerifyP256Signature(blob, digest, signature);
        if (!*out.SignatureValid) { out.Status = L"signature_rejected"; return out; }
        if (!Claims(payload, out)) { out.Status = L"invalid_claims"; return out; }
        out.RoleMatches = out.CaptureController == (key.Role == L"capture_controller");
        out.EtlMatches = out.ClaimedEtlSha256 == etlSha256 && *out.ClaimedBytes == etlBytes;
        out.Status = !*out.RoleMatches ? L"signer_role_mismatch" : *out.EtlMatches ? L"bound" : L"etl_identity_mismatch";
        return out;
    }

    std::wstring CaptureStatement::Json(const StatementAuthority& key, bool pageMatches) const
    {
        const bool bound = pageMatches && Bound();
        return L"{\"status\":" + mcpjson::Quote(Status) + L",\"trusted_key_sha256\":" + mcpjson::Quote(key.Sha256) +
            L",\"expected_role\":" + mcpjson::Quote(key.Role) + L",\"role_matches\":" + Boolean(RoleMatches) +
            L",\"signed_role\":" + (RoleMatches.has_value() ? mcpjson::Quote(CaptureController ? L"capture_controller" : L"archive_witness") : L"null") +
            L",\"statement_file_sha256\":" + (FileSha256.empty() ? L"null" : mcpjson::Quote(FileSha256)) +
            L",\"signature_verified\":" + Boolean(SignatureValid) + L",\"etl_identity_matches\":" + Boolean(EtlMatches) +
            L",\"claimed_etl_sha256\":" + (ClaimedEtlSha256.empty() ? L"null" : mcpjson::Quote(ClaimedEtlSha256)) +
            L",\"claimed_etl_bytes\":" + (ClaimedBytes ? mcpjson::Quote(std::to_wstring(*ClaimedBytes)) : L"null") +
            L",\"bound_to_replayed_page\":" + Boolean(bound) + L",\"capture_controller_statement_authenticated\":" +
            Boolean(bound && CaptureController) + L",\"claims\":" + (bound ? Claims : L"null") + L"}";
    }
}
