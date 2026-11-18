#pragma once

#include <algorithm>
#include <string>
#include <vector>

// The local operator supplies the SHA-256 fingerprint of the client's bearer.
// Only the transport attaches a grant to an engine request.
struct McpObserveGrant
{
    std::wstring Fingerprint;
    std::wstring Source;

    bool operator==(const McpObserveGrant& other) const
    {
        return Fingerprint == other.Fingerprint && Source == other.Source;
    }
};

inline bool ValidMcpObserveGrants(const std::vector<McpObserveGrant>& grants)
{
    if (grants.size() > 16) { return false; }
    const std::wstring letters = L"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (auto at = grants.begin(); at != grants.end(); ++at)
    {
        if (at->Fingerprint.size() != 64 || at->Fingerprint.find_first_not_of(L"0123456789abcdef") != std::wstring::npos ||
            at->Source.empty() || at->Source.size() > 64 || letters.find(at->Source.front()) == std::wstring::npos ||
            at->Source.find_first_not_of(letters + L"._-") != std::wstring::npos ||
            std::any_of(grants.begin(), at, [&](const auto& prior) { return prior.Fingerprint == at->Fingerprint; }))
        {
            return false;
        }
    }
    return true;
}
