#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>

inline bool KmonFileQueryKnown(DWORD attributes, DWORD error)
{
    return attributes != INVALID_FILE_ATTRIBUTES || error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}

// Repeat observations confirm only identical evidence inside one bounded window.
struct KmonRepeatObservation
{
    std::wstring Fingerprint;
    uint64_t LastMs = 0;
    uint32_t Count = 0;

    uint32_t Observe(const std::wstring& fingerprint, uint64_t nowMs, uint64_t maxGapMs)
    {
        if (fingerprint.empty())
        {
            *this = {};
        }
        else
        {
            if (Fingerprint != fingerprint || nowMs < LastMs || nowMs - LastMs > maxGapMs)
            {
                Count = 0;
            }
            Fingerprint = fingerprint;
            LastMs = nowMs;
            if (Count < UINT32_MAX)
            {
                ++Count;
            }
        }
        return Count;
    }
};

// Event kinds are stable routing identifiers, not maliciousness verdicts.
inline const wchar_t* KmonEventCategory(const std::wstring& kind)
{
    if (kind.rfind(L"sensor.", 0) == 0)
    {
        return L"sensor";
    }
    if (kind.rfind(L"coverage.", 0) == 0 || kind.rfind(L"gap.", 0) == 0)
    {
        return L"coverage";
    }
    if (kind == L"driver.official_load" || kind == L"driver.official_unload" ||
        kind == L"driver.drop_load" || kind == L"driver.image_only" ||
        kind == L"driver.device" || kind == L"driver.handle" || kind == L"driver.ioctl" ||
        kind == L"hook.window" || kind == L"process.create" || kind == L"loader.activity" ||
        kind == L"mapper.watch" || kind == L"finding.layout_change" ||
        kind == L"finding.code_modified" || kind == L"finding.tls_metadata" ||
        kind == L"finding.layout_image_identity" || kind == L"finding.executable_memory" ||
        kind == L"finding.executable_permission")
    {
        return L"observation";
    }
    return L"lead";
}
