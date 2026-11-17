#pragma once

#include <cstdint>
#include <functional>
#include <string>

struct ImageChangeAssessment
{
    bool Assessed = false;
    std::wstring Json;
};

// The separate digest is the caller's trust anchor, not a manifest assertion.
// Evaluation changes no evidence and does not authenticate an issuer/collector.
// A nonzero evaluation time is for explicit offline callers; the CLI uses the
// host clock. No network, signing policy, or implicit trust-store lookup occurs.
ImageChangeAssessment AssessAuthorizedImageChanges(const std::wstring& capture,
    const std::wstring& manifest, const std::wstring& approvalPolicy, const std::wstring& policySha256,
    uint64_t evaluationFileTime = 0, const std::function<void(const wchar_t*)>& observer = {});
