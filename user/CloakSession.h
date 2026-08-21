#pragma once

#include <string>
#include <vector>

enum class CloakMode
{
    None = 0,
    Launch,
    Resume,
    Cleanup
};

struct CloakArgs
{
    CloakMode Mode = CloakMode::None;
    std::wstring SessionPath;
};

struct CloakSession
{
    std::wstring Id;
    std::wstring ServiceName;
    std::wstring DisplayName;
    std::wstring DeviceNtName;
    std::wstring SymbolicLinkName;
    std::wstring UserDeviceName;
    std::wstring WorkDirectory;
    std::wstring CopiedExePath;
    std::wstring CopiedSysPath;
    std::wstring OriginalExePath;
    std::wstring SessionFilePath;
    std::vector<std::wstring> CopiedSidecarFiles;
};

bool ParseCloakArgs(int argc, const wchar_t* const* argv, CloakArgs* args);
bool IsValidCloakLeafName(const std::wstring& name);
bool CloakCopiesRuntimeSidecar(const std::wstring& fileName);
std::wstring GenerateCloakLeafName();
bool BuildCloakSession(CloakSession* session, std::wstring* error);
bool SaveCloakSession(const CloakSession& session, std::wstring* error);
bool LoadCloakSession(const std::wstring& path, CloakSession* session, std::wstring* error);
bool WriteCloakServiceParameters(const CloakSession& session, std::wstring* error);
bool LaunchCloakChild(const CloakSession& session, int argc, const wchar_t* const* argv, std::wstring* error);
bool CleanupCloakArtifacts(const CloakSession& session, bool runningFromCopy, std::wstring* error);
int RunCloakCleanup(const std::wstring& sessionPath);
