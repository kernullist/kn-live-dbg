#pragma once

#include "SymbolEngine.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

struct ByovdCatalogEntry
{
    std::wstring Source;
    std::wstring Category;
    std::wstring MatchType;
    std::wstring Value;
    std::wstring Name;
    std::wstring MinimumVersion;
    std::wstring MaximumVersion;
    std::wstring Description;
};

struct ByovdMatch
{
    ByovdCatalogEntry Entry;
    std::wstring Confidence;
    std::wstring Reason;
};

struct ByovdModuleRecord
{
    std::wstring ImageName;
    std::wstring ImagePath;
    std::wstring DiskPath;
    std::wstring FileVersion;
    std::wstring FileCompanyName;
    std::wstring FileProductName;
    std::wstring FileOriginalName;
    std::wstring Md5;
    std::wstring Sha1;
    std::wstring Sha256;
    std::wstring Error;
    std::wstring YaraError;
    uint64_t Base = 0;
    uint32_t Size = 0;
    bool FileHashed = false;
    bool VersionRead = false;
    bool YaraScanned = false;
    bool YaraTimedOut = false;
    std::vector<ByovdMatch> Matches;
};

struct ByovdScanOptions
{
    bool AutoUpdate = true;
    bool ForceUpdate = false;
    bool ExactOnly = false;
    bool EnableYara = false;
    bool Verbose = false;
    bool SummaryOnly = false;
    uint32_t Limit = 0;
    uint32_t YaraTimeoutSeconds = 30;
    std::wstring YaraExecutable;
};

struct ByovdScanResult
{
    std::vector<ByovdModuleRecord> Records;
    std::vector<std::wstring> Messages;
    std::vector<std::wstring> Warnings;
    uint64_t ModulesScanned = 0;
    uint64_t FilesHashed = 0;
    uint64_t FileReadFailures = 0;
    uint64_t MatchedModules = 0;
    uint64_t ExactMatches = 0;
    uint64_t HintMatches = 0;
    uint64_t YaraScans = 0;
    uint64_t YaraMatches = 0;
    uint64_t YaraFailures = 0;
    uint64_t YaraTimeouts = 0;
    bool CatalogUpdated = false;
    bool CatalogUpdateAttempted = false;
    bool Truncated = false;
    std::wstring YaraExecutable;
    std::vector<std::wstring> YaraRuleFiles;
};

struct ByovdCatalogStatus
{
    std::wstring DataDirectory;
    std::wstring CatalogPath;
    std::wstring ManifestPath;
    std::wstring YaraDirectory;
    uint64_t EntryCount = 0;
    uint64_t YaraRuleFileCount = 0;
    uint64_t AgeSeconds = 0;
    bool HasCatalog = false;
    bool HasYaraRules = false;
    bool Stale = false;
    std::map<std::wstring, uint64_t> SourceCounts;
    std::map<std::wstring, uint64_t> MatchTypeCounts;
};

class ByovdScanner
{
public:
    ByovdScanner(SymbolEngine& symbols, const std::wstring& executableDirectory);

    bool Scan(const ByovdScanOptions& options, ByovdScanResult* result, std::wstring* error);
    bool UpdateCatalog(bool force, std::vector<std::wstring>* messages, std::wstring* error);
    bool QueryCatalogStatus(ByovdCatalogStatus* status, std::wstring* error);

    const std::wstring& DataDirectory() const;
    const std::wstring& CatalogPath() const;
    const std::wstring& ManifestPath() const;

private:
    SymbolEngine& symbols_;
    std::wstring executableDirectory_;
    std::wstring dataDirectory_;
    std::wstring catalogPath_;
    std::wstring manifestPath_;

    bool LoadCatalog(std::vector<ByovdCatalogEntry>* entries, std::wstring* error) const;
    bool CatalogIsStale(uint64_t maxAgeSeconds, bool* stale, uint64_t* ageSeconds, std::wstring* error) const;
    bool RunUpdaterScript(bool force, std::vector<std::wstring>* messages, std::wstring* error) const;
};

std::wstring BuildByovdScanJson(const ByovdScanResult& result);
