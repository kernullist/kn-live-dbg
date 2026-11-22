#pragma once

#include <string>
#include <vector>

int RunEtlCapabilityProbe(const std::vector<std::wstring>& args, const std::wstring& binaryVersion);
int RunEtlProfile(const std::vector<std::wstring>& args);
int RunEtlRotationSet(const std::vector<std::wstring>& args);
int RunEtlDiskIo(const std::vector<std::wstring>& args);
int RunEtlSwitches(const std::vector<std::wstring>& args);
