#pragma once

#include "KmonHunting.h"

// One immutable receipt and its bounded read set. Files are local, private
// captures; checksums establish consistency, not collector authenticity.
struct EvidenceSpan
{
    uint64_t Address = 0;
    uint64_t RequestedBytes = 0;
    std::wstring Role;
    std::wstring State = L"read_failed";
    std::vector<uint8_t> Bytes;
};

struct EvidenceBundle
{
    KmonHuntReceipt Receipt;
    std::wstring CollectionId;
    std::wstring Acquisition = L"unspecified";
    uint64_t CaptureStartedMs = 0;
    uint64_t CaptureEndedMs = 0;
    bool ReferenceConsistent = false;
    bool CaptureTruncated = false;
    std::vector<EvidenceSpan> Spans;
};

constexpr size_t EvidenceBundleMaxSpans = 128;
constexpr size_t EvidenceBundleMaxJsonBytes = 2 * 1024 * 1024;
bool EvidenceReadSetComplete(const EvidenceBundle& bundle);
bool EvidenceRead(const EvidenceBundle& bundle, uint64_t address, size_t size, std::vector<uint8_t>* bytes);
std::wstring EvidenceBundleJson(const EvidenceBundle& bundle);
bool ParseEvidenceBundle(const std::wstring& json, EvidenceBundle* bundle, std::wstring* error);
bool SaveEvidenceBundle(const std::wstring& path, const EvidenceBundle& bundle, std::wstring* error);
bool LoadEvidenceBundle(const std::wstring& path, EvidenceBundle* bundle, std::wstring* error, std::wstring* digest = nullptr,
    size_t maximumBytes = EvidenceBundleMaxJsonBytes, size_t* bytesRead = nullptr);
