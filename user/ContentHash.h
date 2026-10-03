#pragma once

#include <Windows.h>
#include <bcrypt.h>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#pragma comment(lib, "bcrypt.lib")

class ContentHash
{
public:
    ContentHash()
    {
        DWORD length = 0;
        DWORD read = 0;
        if (BCryptOpenAlgorithmProvider(&Algorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0) >= 0 &&
            BCryptGetProperty(Algorithm, BCRYPT_OBJECT_LENGTH, reinterpret_cast<PUCHAR>(&length),
                sizeof(length), &read, 0) >= 0)
        {
            try
            {
                Object.resize(length);
                BCryptCreateHash(Algorithm, &Hash, Object.data(), length, nullptr, 0, 0);
            }
            catch (...)
            {
                BCryptCloseAlgorithmProvider(Algorithm, 0);
                Algorithm = nullptr;
                throw;
            }
        }
    }

    ~ContentHash()
    {
        if (Hash != nullptr)
        {
            BCryptDestroyHash(Hash);
        }
        if (Algorithm != nullptr)
        {
            BCryptCloseAlgorithmProvider(Algorithm, 0);
        }
    }

    ContentHash(const ContentHash&) = delete;
    ContentHash& operator=(const ContentHash&) = delete;

    bool Add(const uint8_t* bytes, size_t size)
    {
        return Hash != nullptr && size <= UINT32_MAX &&
            BCryptHashData(Hash, const_cast<PUCHAR>(bytes), static_cast<ULONG>(size), 0) >= 0;
    }

    std::wstring Finish()
    {
        uint8_t digest[32] = {};
        std::wstring result;
        if (Hash != nullptr && BCryptFinishHash(Hash, digest, sizeof(digest), 0) >= 0)
        {
            for (uint8_t value : digest)
            {
                result.push_back(L"0123456789abcdef"[value >> 4]);
                result.push_back(L"0123456789abcdef"[value & 15]);
            }
        }
        return result;
    }

    static std::wstring Bytes(const std::vector<uint8_t>& bytes)
    {
        ContentHash hash;
        return hash.Add(bytes.data(), bytes.size()) ? hash.Finish() : std::wstring();
    }

    static std::wstring File(const std::wstring& path)
    {
        std::wstring result;
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        const std::unique_ptr<void, decltype(&CloseHandle)> fileOwner(
            file == INVALID_HANDLE_VALUE ? nullptr : file, &CloseHandle);
        if (file != INVALID_HANDLE_VALUE)
        {
            ContentHash hash;
            std::vector<uint8_t> buffer(65536);
            DWORD read = 0;
            while (ReadFile(file, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr))
            {
                if (read == 0)
                {
                    result = hash.Finish();
                    break;
                }
                if (!hash.Add(buffer.data(), read))
                {
                    break;
                }
            }
        }
        return result;
    }

private:
    BCRYPT_ALG_HANDLE Algorithm = nullptr;
    BCRYPT_HASH_HANDLE Hash = nullptr;
    std::vector<uint8_t> Object;
};
