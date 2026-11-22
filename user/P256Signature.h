#pragma once

#include <Windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <cstring>
#include <limits>
#include <utility>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

namespace p256_signature
{
    struct AlgorithmOwner
    {
        BCRYPT_ALG_HANDLE Handle = nullptr;
        ~AlgorithmOwner()
        {
            if (Handle != nullptr)
            {
                BCryptCloseAlgorithmProvider(Handle, 0);
            }
        }
    };

    struct KeyOwner
    {
        BCRYPT_KEY_HANDLE Handle = nullptr;
        ~KeyOwner()
        {
            if (Handle != nullptr)
            {
                BCryptDestroyKey(Handle);
            }
        }
    };

    inline bool Sha256(const uint8_t* bytes, size_t length, std::vector<uint8_t>* digest)
    {
        bool ok = false;
        AlgorithmOwner algorithm;
        do
        {
            if (digest == nullptr || length > (std::numeric_limits<ULONG>::max)() ||
                (length != 0 && bytes == nullptr))
            {
                break;
            }
            digest->clear();
            if (BCryptOpenAlgorithmProvider(&algorithm.Handle, BCRYPT_SHA256_ALGORITHM,
                nullptr, 0) < 0)
            {
                break;
            }
            std::vector<uint8_t> output(32);
            if (BCryptHash(algorithm.Handle, nullptr, 0, const_cast<PUCHAR>(bytes),
                static_cast<ULONG>(length), output.data(), static_cast<ULONG>(output.size())) < 0)
            {
                break;
            }
            *digest = std::move(output);
            ok = true;
        } while (false);
        return ok;
    }

    inline bool Sha256(const std::vector<uint8_t>& bytes, std::vector<uint8_t>* digest)
    {
        return Sha256(bytes.data(), bytes.size(), digest);
    }

    inline bool VerifyP256Signature(const std::vector<uint8_t>& publicBlob,
        const std::vector<uint8_t>& digest, const std::vector<uint8_t>& signature)
    {
        bool ok = false;
        AlgorithmOwner algorithm;
        KeyOwner key;
        do
        {
            if (publicBlob.size() != sizeof(BCRYPT_ECCKEY_BLOB) + 64 ||
                digest.size() != 32 || signature.size() != 64)
            {
                break;
            }
            BCRYPT_ECCKEY_BLOB header = {};
            memcpy(&header, publicBlob.data(), sizeof(header));
            if (header.dwMagic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || header.cbKey != 32 ||
                BCryptOpenAlgorithmProvider(&algorithm.Handle, BCRYPT_ECDSA_P256_ALGORITHM,
                    nullptr, 0) < 0 ||
                BCryptImportKeyPair(algorithm.Handle, nullptr, BCRYPT_ECCPUBLIC_BLOB,
                    &key.Handle, const_cast<PUCHAR>(publicBlob.data()),
                    static_cast<ULONG>(publicBlob.size()), 0) < 0)
            {
                break;
            }
            ok = BCryptVerifySignature(key.Handle, nullptr,
                const_cast<PUCHAR>(digest.data()), static_cast<ULONG>(digest.size()),
                const_cast<PUCHAR>(signature.data()), static_cast<ULONG>(signature.size()), 0) >= 0;
        } while (false);
        return ok;
    }
}
