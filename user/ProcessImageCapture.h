#pragma once

#include <atomic>
#include <string>
#include <vector>

int RunProcessImageCaptureCommand(const std::vector<std::wstring>& args, const std::atomic<bool>* cancellation = nullptr);
int RunReplayImageSourceCommand(const std::vector<std::wstring>& args, bool directJsonOutput);
