#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

struct SnapshotProcessRecord
{
    uint32_t ProcessId = 0;
    uint64_t Eprocess = 0;
    uint64_t DirectoryTableBase = 0;
    uint64_t UserDirectoryTableBase = 0;
    uint64_t Peb = 0;
    uint64_t CreateTime = 0;
    uint64_t ExitTime = 0;
    uint32_t ActiveThreads = 0;
    bool HasCreateTime = false;
    bool HasExitTime = false;
    bool HasActiveThreads = false;
    bool HasPeb = false;
    std::wstring ImageName;
    std::wstring Identity;
};

struct SnapshotRecord
{
    std::wstring Domain;
    std::wstring Identity;
    std::wstring Display;
    std::wstring Risk;
    bool Volatile = false;
    std::vector<std::wstring> Tags;
    std::map<std::wstring, std::wstring> Evidence;
};

struct SnapshotDocument
{
    std::wstring Schema;
    std::wstring Label;
    std::wstring TimestampUtc;
    std::wstring JsonPath;
    std::wstring ReportPath;
    std::wstring BootId;
    bool SameBootOnly = true;
    std::map<std::wstring, std::wstring> Metadata;
    std::map<std::wstring, std::vector<std::wstring>> DomainWarnings;
    std::vector<SnapshotProcessRecord> Processes;
    std::vector<SnapshotRecord> Records;
};

struct SnapshotDomainCount
{
    std::wstring Domain;
    uint64_t Records = 0;
    uint64_t High = 0;
    uint64_t Medium = 0;
    uint64_t Low = 0;
    uint64_t Info = 0;
};

std::wstring SnapshotToLower(const std::wstring& value);
std::wstring SnapshotHex(uint64_t value, uint32_t width = 0);
std::wstring SnapshotCurrentUtcTimestamp();
std::wstring SnapshotCurrentBootId();
std::wstring SnapshotSafeFileComponent(const std::wstring& value);
std::wstring SnapshotRiskNormalize(const std::wstring& risk);
uint32_t SnapshotRiskRank(const std::wstring& risk);
std::wstring BuildSnapshotProcessIdentity(const SnapshotProcessRecord& process, std::vector<std::wstring>* warnings);
bool SnapshotRecordHasTag(const SnapshotRecord& record, const std::wstring& tag);
std::vector<SnapshotDomainCount> BuildSnapshotDomainCounts(const SnapshotDocument& document);
