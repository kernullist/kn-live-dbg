#pragma once
#include <string>

// The original JSON starts with "{\n". An optional first member binds the
// exact source text to Windows protection for this user and installation.
bool AttachSnapshotBootReceipt(std::wstring& json);
bool VerifySnapshotBootReceipt(const std::wstring& json);
