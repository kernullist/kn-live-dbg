#pragma once

#include <filesystem>
#include <map>
#include <string>

// A caller may resolve an original logical input to a separately retained,
// leased artifact. Missing entries never fall back to the surrounding directory.
// Original replay still verifies the same hashes, policies and membership.
struct ImageScopeReplayPaths
{
    bool Sweep = false;
    std::map<std::wstring, std::wstring> Files;
};

inline std::filesystem::path ResolveImageScopeReplayPath(const std::filesystem::path& root,
    const std::wstring& relative, const ImageScopeReplayPaths* paths)
{
    if (!paths) { return root / relative; }
    const auto found = paths->Files.find(relative);
    return found == paths->Files.end() ? std::filesystem::path{} : std::filesystem::path(found->second);
}
