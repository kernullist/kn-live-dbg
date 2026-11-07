#pragma once

#include "ContentHash.h"

// A publisher-issued namespace, not a host identifier or an authentication key.
// A capture ID labels one local read session; it is not an object lifetime.
struct EvidenceOrigin
{
    std::wstring CollectorScope, CaptureId, LocalBootId;
    uint64_t NativeEpoch = 0;

    bool Empty() const
    {
        return CollectorScope.empty() && CaptureId.empty() && LocalBootId.empty() && NativeEpoch == 0;
    }
    static bool Id(const std::wstring& value)
    {
        return value.size() == 32 && value.find_first_not_of(L"0123456789abcdef") == std::wstring::npos;
    }
    bool Valid() const
    {
        return Id(CollectorScope) && Id(CaptureId) && Id(LocalBootId);
    }
};

inline std::wstring NewEvidenceScope()
{
    uint8_t bytes[16]{};
    if (BCryptGenRandom(nullptr, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) { return {}; }
    constexpr wchar_t hex[] = L"0123456789abcdef";
    std::wstring result;
    for (const auto value : bytes) { result += hex[value >> 4]; result += hex[value & 15]; }
    return result;
}
