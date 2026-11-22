#pragma once

#include <atomic>
#include <string>
#include <vector>

// Explicit V8 log mode of the existing offline execution trace query.
int RunV8ProfileQuery(const std::vector<std::wstring>& args, const std::atomic<bool>* stop, bool inherited);
