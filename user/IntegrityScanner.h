#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct ModuleIntegritySectionRecord
{
    std::wstring Name;
    uint32_t VirtualAddress = 0;
    uint32_t VirtualSize = 0;
    uint32_t RawSize = 0;
    uint32_t Characteristics = 0;
    bool Executable = false;
    bool Writable = false;
    bool Readable = false;
    bool RangeValid = true;
    bool OverlapsPrevious = false;
    bool FirstPageQueried = false;
    bool FirstPageQueryFailed = false;
    bool FirstPageReadable = false;
    bool FirstPageWritable = false;
    bool FirstPageExecutable = false;
    bool FirstPageLargePage = false;
    uint32_t FirstPagePagingLevels = 0;
    bool LastPageQueried = false;
    bool LastPageQueryFailed = false;
    bool LastPageReadable = false;
    bool LastPageWritable = false;
    bool LastPageExecutable = false;
    bool LastPageLargePage = false;
    uint32_t LastPagePagingLevels = 0;
    bool PageAttributesQueried = false;
    bool PageAttributeQueryFailed = false;
    bool EffectiveReadable = false;
    bool EffectiveWritable = false;
    bool EffectiveExecutable = false;
    bool Suspicious = false;
    bool WxEvidence = false;
    bool MismatchEvidence = false;
    std::wstring PageAttributeError;
    std::wstring Notes;
    std::vector<std::wstring> ReasonCodes;
};

struct ModuleIntegrityRecord
{
    std::wstring ImageName;
    std::wstring ImagePath;
    uint64_t Base = 0;
    uint32_t Size = 0;
    uint32_t SizeOfImage = 0;
    uint32_t SizeOfHeaders = 0;
    uint32_t SectionAlignment = 0;
    uint32_t FileAlignment = 0;
    uint32_t NumberOfRvaAndSizes = 0;
    uint64_t PreferredImageBase = 0;
    uint16_t Machine = 0;
    uint16_t OptionalHeaderMagic = 0;
    uint16_t NumberOfSections = 0;
    bool HeaderRead = false;
    bool MzOk = false;
    bool PeOk = false;
    bool OptionalHeaderOk = false;
    bool SectionTableOk = false;
    bool SizeMismatch = false;
    bool ImageBaseMismatch = false;
    bool Suspicious = false;
    bool WxEvidence = false;
    bool MismatchEvidence = false;
    std::wstring Notes;
    std::vector<std::wstring> ReasonCodes;
    std::vector<std::wstring> InfoCodes;
    std::vector<ModuleIntegritySectionRecord> Sections;
};

struct ModuleIntegrityOptions
{
    std::wstring ModuleFilter;
    uint32_t Limit = 0;
    bool SummaryOnly = false;
    bool Verbose = false;
    bool IncludeHeaders = false;
    bool IncludeSections = false;
    bool WxOnly = false;
    bool MismatchOnly = false;
};

struct ModuleIntegrityResult
{
    std::vector<ModuleIntegrityRecord> Records;
    std::vector<std::wstring> Warnings;
    uint64_t ModulesScanned = 0;
    uint64_t MatchingModules = 0;
    uint64_t ReportedModules = 0;
    uint64_t SuspiciousModules = 0;
    uint64_t WxModules = 0;
    uint64_t MismatchModules = 0;
    bool Truncated = false;
};

struct DriverDispatchRecord
{
    uint32_t Index = 0;
    std::wstring Name;
    uint64_t Function = 0;
    std::wstring ModuleName;
    std::wstring SymbolName;
    bool InLoadedModule = false;
    bool InOwningImage = false;
    bool Suspicious = false;
    std::wstring Notes;
};

struct DriverIntegrityRecord
{
    std::wstring Name;
    std::wstring DirectoryPath;
    uint64_t DriverObject = 0;
    uint64_t DriverStart = 0;
    uint64_t DriverSize = 0;
    uint64_t DriverSection = 0;
    uint64_t DeviceObject = 0;
    uint64_t FastIoDispatch = 0;
    uint64_t DriverUnload = 0;
    std::wstring OwningModule;
    std::wstring Notes;
    bool HasDriverStart = false;
    bool Suspicious = false;
    uint32_t SuspiciousDispatchCount = 0;
    std::vector<DriverDispatchRecord> Dispatch;
};

struct DriverIntegrityOptions
{
    std::wstring DriverFilter;
    uint32_t Limit = 0;
};

struct DriverIntegrityResult
{
    std::vector<DriverIntegrityRecord> Records;
    std::vector<std::wstring> Warnings;
    uint64_t DriversScanned = 0;
    uint64_t MatchingDrivers = 0;
    uint64_t SuspiciousDrivers = 0;
    bool Truncated = false;
};

class IntegrityScanner
{
public:
    IntegrityScanner(DeviceClient& device, SymbolEngine& symbols);

    bool ScanModules(const ModuleIntegrityOptions& options, ModuleIntegrityResult* result, std::wstring* error);
    bool ScanDrivers(const DriverIntegrityOptions& options, DriverIntegrityResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildModuleIntegrityJson(const ModuleIntegrityResult& result);
std::wstring BuildDriverIntegrityJson(const DriverIntegrityResult& result);
