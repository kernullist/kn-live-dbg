#pragma once

#include <Windows.h>
#include <atomic>
#include <string>
#include <vector>

int RunProcessImageCaptureCommand(const std::vector<std::wstring>& args, const std::atomic<bool>* cancellation = nullptr);
class DistinctArtifactInput;
bool HoldImageCommandOperand(HANDLE sink, const std::wstring& name, std::vector<DistinctArtifactInput>& leases);
