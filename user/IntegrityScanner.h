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
    uint32_t PointerToRawData = 0;
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
    bool DiskCompareAttempted = false;
    bool DiskCompareMatched = false;
    bool DiskCompareMismatch = false;
    bool DiskCompareFailed = false;
    bool LastPageQueried = false;
    bool LastPageQueryFailed = false;
    bool LastPageReadable = false;
    bool LastPageWritable = false;
    bool LastPageExecutable = false;
    bool LastPageLargePage = false;
    uint32_t LastPagePagingLevels = 0;
    // Interior executable-page samples (between first and last) so mid-section
    // W+X hooks are not invisible when only endpoints are clean.
    uint32_t MidPagesQueried = 0;
    uint32_t MidPagesQueryFailed = 0;
    uint32_t MidPagesWx = 0;
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

struct ModuleIatRecord
{
    std::wstring ImportDll;
    std::wstring FunctionName;
    uint32_t Ordinal = 0;
    uint64_t ThunkAddress = 0;
    uint64_t Target = 0;
    std::wstring TargetModule;
    std::wstring TargetSymbol;
    bool ByOrdinal = false;
    bool Suspicious = false;
    std::wstring Notes;
};

struct ModulePrologueFinding
{
    uint64_t Address = 0;
    std::wstring Mnemonic;
    std::wstring Reason;
    uint64_t Target = 0;
    std::wstring TargetModule;
    bool HasTarget = false;
    bool Suspicious = false;
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
    uint32_t AddressOfEntryPoint = 0;
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
    bool IatEvidence = false;
    bool PrologueEvidence = false;
    std::wstring Notes;
    std::vector<std::wstring> ReasonCodes;
    std::vector<std::wstring> InfoCodes;
    std::vector<ModuleIntegritySectionRecord> Sections;
    std::vector<ModuleIatRecord> IatEntries;
    std::vector<ModulePrologueFinding> PrologueFindings;
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
    // Compare live executable pages against on-disk PE section raw data.
    // Additive: never disables existing W+X / header checks.
    bool CompareDiskPages = false;
    uint32_t DiskPagesPerSection = 2; // first + one interior sample by default
    // Walk IMAGE_DIRECTORY_ENTRY_IMPORT and flag IAT thunks whose live
    // targets sit outside loaded modules or unexpected owners.
    bool ScanIat = false;
    // Disassemble AddressOfEntryPoint and flag trampoline / debug-trap heads.
    bool ScanPrologue = false;
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
    uint64_t IatModules = 0;
    uint64_t PrologueModules = 0;
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
    bool DelegatedToLoadedModule = false;
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

struct DeviceObjectRecord
{
    uint64_t DeviceObject = 0;
    uint64_t DriverObject = 0;
    uint64_t NextDevice = 0;
    uint64_t AttachedDevice = 0;
    uint64_t AttachedTo = 0;
    uint64_t DeviceExtension = 0;
    uint64_t DeviceObjectExtension = 0;
    uint32_t DeviceType = 0;
    uint32_t Characteristics = 0;
    uint32_t Flags = 0;
    int32_t StackSize = 0;
    std::wstring DriverName;
    std::wstring DriverModule;
    std::wstring DeviceName;
    std::wstring Notes;
    bool Suspicious = false;
};

struct DeviceStackResult
{
    uint64_t StartDevice = 0;
    uint64_t TopDevice = 0;
    std::vector<DeviceObjectRecord> Stack;
    std::vector<std::wstring> Warnings;
    bool CoverageComplete = false;
    bool CycleDetected = false;
};

struct DriverObjectInspectResult
{
    std::vector<DriverIntegrityRecord> Drivers;
    std::vector<DeviceObjectRecord> Devices;
    std::vector<DeviceStackResult> Stacks;
    std::vector<std::wstring> Warnings;
    bool Found = false;
};

class IntegrityScanner
{
public:
    IntegrityScanner(DeviceClient& device, SymbolEngine& symbols);

    bool ScanModules(const ModuleIntegrityOptions& options, ModuleIntegrityResult* result, std::wstring* error);
    bool ScanDrivers(const DriverIntegrityOptions& options, DriverIntegrityResult* result, std::wstring* error);
    bool InspectDriverObject(
        const std::wstring& filter,
        bool includeDispatch,
        bool includeDevices,
        DriverObjectInspectResult* result,
        std::wstring* error);
    bool InspectDeviceStack(uint64_t deviceObject, DeviceStackResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildModuleIntegrityJson(const ModuleIntegrityResult& result);
std::wstring BuildDriverIntegrityJson(const DriverIntegrityResult& result);
std::wstring BuildDriverObjectJson(const DriverObjectInspectResult& result);
std::wstring BuildDeviceStackJson(const DeviceStackResult& result);
bool IntegrityIatOwnerSelfTest();
bool IntegrityProloguePatternSelfTest();
bool DeviceStackWalkSelfTest();
