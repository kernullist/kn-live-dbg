#pragma once

#include "ContentHash.h"
#include "McpJson.h"
#include <ncrypt.h>
#include <array>

#pragma comment(lib, "ncrypt.lib")

namespace inventory_verification
{
    constexpr size_t MaxReceiptBytes = 12 * 1024;
    constexpr wchar_t KeyName[] = L"KnLiveDbg.InventoryVerification.v1";

    // Keep the verification key outside the directory that supplies the untrusted index.
    // The software KSP resolves this name in the current user's key store.
    class Signer
    {
    public:
        Signer() = default;
        Signer(const Signer&) = delete;
        Signer& operator=(const Signer&) = delete;
        ~Signer()
        {
            if (Key) { NCryptFreeObject(Key); }
            if (Provider) { NCryptFreeObject(Provider); }
        }

        std::wstring Seal(const std::wstring& chain, size_t through, const std::wstring& witnesses)
        {
            Digest digest{};
            Signature signature{};
            DWORD size = 0;
            if (!OpenKey(true) || !Frame(chain, through, witnesses, digest) ||
                NCryptSignHash(Key, nullptr, digest.data(), static_cast<DWORD>(digest.size()), signature.data(),
                    static_cast<DWORD>(signature.size()), &size, NCRYPT_SILENT_FLAG) != ERROR_SUCCESS ||
                size != signature.size()) { return {}; }
            std::wstring hex;
            for (const BYTE byte : signature)
            {
                hex += L"0123456789abcdef"[byte >> 4];
                hex += L"0123456789abcdef"[byte & 15];
            }
            return Document(through, witnesses, hex);
        }

        bool Open(const std::wstring& document, const std::wstring& chain, size_t through,
            size_t expectedWitnesses, std::wstring& witnesses)
        {
            std::wstring prefix, hex;
            Signature signature{};
            if (!mcpjson::GetString(document, L"verification_seal", &hex) || hex.size() != 2 * signature.size() ||
                !mcpjson::GetString(document, L"raw_witness_prefix", &prefix) || document != Document(through, prefix, hex))
            { return false; }
            const std::wstring digits = L"0123456789abcdef";
            for (size_t i = 0; i < signature.size(); ++i)
            {
                const auto hi = digits.find(hex[2 * i]), lo = digits.find(hex[2 * i + 1]);
                if (hi == digits.npos || lo == digits.npos) { return false; }
                signature[i] = static_cast<BYTE>(hi * 16 + lo);
            }
            size_t at = 0;
            for (size_t i = 0; i < expectedWitnesses; ++i)
            {
                const auto end = prefix.find(L'\n', at);
                if (end == prefix.npos || (end != at && (end - at != 64 || prefix.find_first_not_of(digits, at) != end)))
                { return false; }
                at = end + 1;
            }
            Digest digest{};
            if (at != prefix.size() || !OpenKey(false) || !Frame(chain, through, prefix, digest) ||
                NCryptVerifySignature(Key, nullptr, digest.data(), static_cast<DWORD>(digest.size()), signature.data(),
                    static_cast<DWORD>(signature.size()), 0) != ERROR_SUCCESS) { return false; }
            witnesses = std::move(prefix);
            return true;
        }

    private:
        using Digest = std::array<BYTE, 32>;
        using Signature = std::array<BYTE, 64>;

        bool OpenKey(bool create)
        {
            if (Key) { return true; }
            if (!Provider && NCryptOpenStorageProvider(&Provider, MS_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) { return false; }
            const auto open = [&]() { return NCryptOpenKey(Provider, &Key, KeyName, 0, NCRYPT_SILENT_FLAG); };
            auto status = open();
            if (status == ERROR_SUCCESS) { return true; }
            if (!create || (status != NTE_BAD_KEYSET && status != NTE_NOT_FOUND)) { return false; }
            // Never overwrite a key, including when two independent builds initialize the profile at once.
            NCRYPT_KEY_HANDLE fresh = 0;
            status = NCryptCreatePersistedKey(Provider, &fresh, NCRYPT_ECDSA_P256_ALGORITHM, KeyName, 0, 0);
            if (status == NTE_EXISTS) { return open() == ERROR_SUCCESS; }
            if (status != ERROR_SUCCESS) { return false; }
            DWORD usage = NCRYPT_ALLOW_SIGNING_FLAG, exports = 0;
            status = NCryptSetProperty(fresh, NCRYPT_KEY_USAGE_PROPERTY, reinterpret_cast<PBYTE>(&usage), sizeof(usage), 0);
            if (status == ERROR_SUCCESS)
            { status = NCryptSetProperty(fresh, NCRYPT_EXPORT_POLICY_PROPERTY, reinterpret_cast<PBYTE>(&exports), sizeof(exports), 0); }
            if (status == ERROR_SUCCESS) { status = NCryptFinalizeKey(fresh, NCRYPT_SILENT_FLAG); }
            if (status == ERROR_SUCCESS) { Key = fresh; return true; }
            NCryptFreeObject(fresh);
            return status == NTE_EXISTS && open() == ERROR_SUCCESS;
        }

        static std::wstring Document(size_t through, const std::wstring& witnesses, const std::wstring& hex)
        {
            return L"{\"schema\":\"kn.evidence_inventory_verification.v1\",\"verified_through\":\"" +
                std::to_wstring(through) + L"\",\"raw_witness_prefix\":" + mcpjson::Quote(witnesses) +
                L",\"verification_seal\":\"" + hex + L"\"}";
        }

        bool Frame(const std::wstring& chain, size_t through, const std::wstring& witnesses, Digest& digest)
        {
            if (Image.empty())
            {
                std::wstring path(32768, L'\0');
                const auto length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
                if (!length || length == path.size()) { return false; }
                path.resize(length);
                Image = ContentHash::File(path);
                if (Image.size() != 64) { return false; }
            }
            const auto frame = "KnLiveDbg.inventory.verification.v1\n" + mcpjson::WideToUtf8(Image) + "\n" +
                mcpjson::WideToUtf8(chain) + "\n" + std::to_string(through) + "\n" + mcpjson::WideToUtf8(witnesses);
            return BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, reinterpret_cast<PUCHAR>(const_cast<char*>(frame.data())),
                static_cast<ULONG>(frame.size()), digest.data(), static_cast<ULONG>(digest.size())) >= 0;
        }

        NCRYPT_PROV_HANDLE Provider = 0;
        NCRYPT_KEY_HANDLE Key = 0;
        std::wstring Image;
    };
}
