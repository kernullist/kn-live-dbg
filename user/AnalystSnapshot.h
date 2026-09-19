#pragma once

#include "KmonHunting.h"

struct AnalystCaseFilter
{
    bool HasPid = false;
    uint32_t ProcessId = 0;
    std::wstring Role;
};

std::vector<KmonHuntCase> FilterAnalystCases(const std::vector<KmonHuntCase>& cases, const AnalystCaseFilter& filter);
bool SaveAnalystSnapshot(const std::wstring& path, const std::wstring& json, std::wstring* error);
bool ReadAnalystSnapshot(const std::wstring& path, std::wstring* json, std::wstring* error);

struct AnalystSnapshotChange
{
    std::wstring Kind;
    std::wstring Identity;
    std::wstring Before;
    std::wstring After;
};

struct AnalystSnapshotDiff
{
    std::wstring Schema;
    std::wstring BootRelation;
    uint64_t Added = 0;
    uint64_t Changed = 0;
    uint64_t NoLongerObserved = 0;
    uint64_t Unchanged = 0;
    bool CoverageChanged = false;
    std::vector<AnalystSnapshotChange> Changes;
};

bool CompareAnalystSnapshots(const std::wstring& before, const std::wstring& after,
    AnalystSnapshotDiff* result, std::wstring* error);
std::wstring AnalystSnapshotDiffJson(const AnalystSnapshotDiff& result);
