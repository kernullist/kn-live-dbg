#pragma once

#include "SnapshotModel.h"

#include <string>

inline constexpr uint64_t SnapshotMaxTextFileBytes = 64ull << 20;

std::wstring BuildSnapshotJson(const SnapshotDocument& document);
bool WriteSnapshotTextFile(const std::wstring& path, const std::wstring& text, std::wstring* error);
bool ReadSnapshotTextFile(const std::wstring& path, std::wstring* text, std::wstring* error);
bool WriteSnapshotJsonFile(const std::wstring& path, const SnapshotDocument& document, std::wstring* error, bool* bootReceiptWritten = nullptr);
bool ReadSnapshotJsonFile(const std::wstring& path, SnapshotDocument* document, std::wstring* error);
bool EnsureSnapshotDirectoryForFile(const std::wstring& path, std::wstring* error);
std::wstring SnapshotJsonEscape(const std::wstring& value);
bool SnapshotJsonStrictParsingSelfTest();
