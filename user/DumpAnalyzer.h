#pragma once

#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct DumpPhysicalRun
{
    uint32_t Index = 0;
    uint64_t BasePage = 0;
    uint64_t PageCount = 0;
    uint64_t BaseAddress = 0;
    uint64_t ByteCount = 0;
    uint64_t FileOffset = 0;
};

struct DumpLoadedModuleRecord
{
    uint32_t Index = 0;
    uint64_t EntryAddress = 0;
    uint64_t DllBase = 0;
    uint32_t SizeOfImage = 0;
    std::wstring BaseName;
    std::wstring FullName;
};

struct DumpAnalyzeResult
{
    std::wstring Path;
    std::wstring Signature;
    std::wstring ValidDump;
    uint32_t MajorVersion = 0;
    uint32_t MinorVersion = 0;
    uint32_t MachineImageType = 0;
    uint32_t NumberProcessors = 0;
    uint32_t BugCheckCode = 0;
    uint32_t DumpType = 0;
    uint64_t DirectoryTableBase = 0;
    uint64_t PfnDataBase = 0;
    uint64_t PsLoadedModuleList = 0;
    uint64_t PsActiveProcessHead = 0;
    uint64_t KdDebuggerDataBlock = 0;
    uint64_t BugCheckParameter1 = 0;
    uint64_t BugCheckParameter2 = 0;
    uint64_t BugCheckParameter3 = 0;
    uint64_t BugCheckParameter4 = 0;
    uint64_t NumberOfPages = 0;
    uint64_t FileSize = 0;
    uint64_t Cr4 = 0;
    uint32_t PagingLevels = 4;
    std::wstring Comment;
    std::vector<DumpPhysicalRun> Runs;
    std::vector<DumpLoadedModuleRecord> Modules;
    std::vector<std::wstring> Warnings;
    bool HeaderValid = false;
    bool ModulesWalked = false;
    bool CoverageComplete = false;
    bool Cr4Valid = false;
    bool La57Active = false;
};

class DumpAnalyzer
{
public:
    explicit DumpAnalyzer(SymbolEngine* symbols);

    bool Analyze(const std::wstring& path, DumpAnalyzeResult* result, std::wstring* error);

private:
    SymbolEngine* symbols_;
};

std::wstring BuildDumpAnalyzeJson(const DumpAnalyzeResult& result);
bool DumpHeaderSignatureSelfTest();
bool DumpPagingWalkSelfTest();
