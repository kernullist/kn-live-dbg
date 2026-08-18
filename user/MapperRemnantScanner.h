#pragma once

#include "DeviceClient.h"
#include "LeftoverCommon.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct MapperUnloadedRecord
{
    uint32_t Index = 0;
    uint64_t EntryAddress = 0;
    uint64_t StartAddress = 0;
    uint64_t EndAddress = 0;
    uint64_t TimeStamp = 0;
    std::wstring Name;
    std::wstring Notes;
    bool StillPresent = false;
    bool StillExecutable = false;
    bool OverlapsLoadedModule = false;
    bool RangeReused = false;
    bool SameImageReload = false;
    bool Suspicious = false;
    uint32_t RepeatCount = 1;
};

struct MapperPiddbRecord
{
    uint32_t Index = 0;
    uint64_t NodeAddress = 0;
    uint64_t EntryAddress = 0;
    uint32_t TimeDateStamp = 0;
    uint32_t LoadStatus = 0;
    std::wstring DriverName;
    std::wstring Notes;
    bool InLoadedModules = false;
    bool Expected = false;
    bool Suspicious = false;
};

struct MapperHashRecord
{
    uint32_t Index = 0;
    uint64_t EntryAddress = 0;
    uint64_t Next = 0;
    std::wstring DriverName;
    std::wstring Notes;
    bool InLoadedModules = false;
    bool Expected = false;
    bool Suspicious = false;
};

struct MapperScanOptions
{
    bool IncludeUnloaded = true;
    bool IncludePiddb = true;
    bool IncludeHash = true;
    uint32_t Limit = 0;
};

struct MapperScanResult
{
    std::vector<MapperUnloadedRecord> Unloaded;
    std::vector<MapperPiddbRecord> Piddb;
    std::vector<MapperHashRecord> HashEntries;
    std::vector<std::wstring> Warnings;
    std::vector<std::wstring> CoverageNotes;
    uint64_t MmUnloadedDrivers = 0;
    uint64_t MmUnloadedArray = 0;
    uint32_t MmLastUnloadedDriver = 0;
    uint32_t UnloadedSlotCount = 0;
    uint64_t PiDDBCacheTable = 0;
    uint32_t PiddbElementCount = 0;
    uint64_t HashListSymbol = 0;
    std::wstring HashListSymbolName;
    std::wstring HashWalkMode;
    std::wstring PiddbWalkMode;
    bool UnloadedResolved = false;
    bool UnloadedComplete = false;
    bool PiddbResolved = false;
    bool PiddbComplete = false;
    bool HashResolved = false;
    bool HashComplete = false;
    bool AnySuspicious = false;
};

class MapperRemnantScanner
{
public:
    MapperRemnantScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(const MapperScanOptions& options, MapperScanResult* result, std::wstring* error);

private:
    bool ScanUnloaded(MapperScanResult* result, std::wstring* error);
    bool ScanPiddb(MapperScanResult* result, std::wstring* error);
    bool ScanHash(MapperScanResult* result, std::wstring* error);
    bool NameInLoadedModules(const std::wstring& name) const;

    DeviceClient& device_;
    SymbolEngine& symbols_;
    std::vector<LeftoverModuleRange> modules_;
};

std::wstring BuildMapperJson(const MapperScanResult& result);
bool MapperRemnantSelfTest();
