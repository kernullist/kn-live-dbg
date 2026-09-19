#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <set>
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
    // Known zero values are distinct from unreadable identity fields.
    bool IdentityFieldsKnown = false;
    bool Suspicious = false;
    uint32_t SuspiciousDispatchCount = 0;
    std::vector<DriverDispatchRecord> Dispatch;
};

// P0: a DRIVER_OBJECT that owns a \Device object but is absent from the
// \Driver object-directory enumeration has had its directory link cut. That
// is the classic driver-object hiding shape, and no \Driver-rooted walk can
// reach it, so it is collected through a \Device back-reference instead.
struct AnonymousDriverBackrefRecord
{
    uint64_t DriverObject = 0;
    uint64_t DriverStart = 0;
    uint64_t DriverSize = 0;
    uint64_t DeviceObject = 0;
    uint32_t DeviceType = 0;
    std::wstring DeviceName;
    std::wstring DriverName;
    std::wstring ModuleName;
    bool HasDriverStart = false;
};

struct DeviceBackrefResult
{
    std::vector<AnonymousDriverBackrefRecord> AnonymousDrivers;
    std::vector<std::wstring> Warnings;
    // Every DRIVER_OBJECT the \Device walk reached, whether or not it is also
    // in the \Driver directory. The driver object type-list sweep uses this to
    // tell an object the device view already explains from one that no view
    // explains at all.
    std::set<uint64_t> DeviceDriverObjects;
    uint64_t DevicesScanned = 0;
    uint64_t DevicesWithKnownDriver = 0;
    uint64_t DevicesWithoutDriver = 0;
    uint64_t DriverObjectsKnown = 0;
    bool DirectoryFound = false;
    bool Truncated = false;
    bool Complete = false;
};

// P0 follow-up: a DRIVER_OBJECT reachable from neither the \Driver directory
// nor a \Device back-reference. The object is still allocated and still owns
// its dispatch table, so the driver object type's own list of objects
// (_OBJECT_TYPE.TypeList) is the only view left that holds it.
struct AnonymousTypeListDriverRecord
{
    uint64_t DriverObject = 0;
    uint64_t DriverStart = 0;
    uint64_t DriverSize = 0;
    uint64_t DriverSection = 0;
    uint64_t DeviceObject = 0;
    uint64_t BackedDispatch = 0;
    uint64_t UnbackedDispatch = 0;
    std::wstring DriverName;
    std::wstring ModuleName;
    bool HasDriverStart = false;
};

struct DriverTypeListResult
{
    std::vector<AnonymousTypeListDriverRecord> AnonymousDrivers;
    std::vector<std::wstring> Warnings;
    uint64_t TypeListEntries = 0;
    uint64_t CandidatesScanned = 0;
    uint64_t CalibrationMatches = 0;
    uint64_t DriversInDirectory = 0;
    uint64_t DriversInDeviceView = 0;
    uint64_t UnnamedCandidates = 0;
    uint64_t AnonymousFound = 0;
    uint64_t AnonymousDropped = 0;
    uint64_t DriverObjectsKnown = 0;
    uint64_t DeviceObjectsKnown = 0;
    bool Truncated = false;
    bool Complete = false;
};

struct DriverIntegrityOptions
{
    std::wstring DriverFilter;
    uint32_t Limit = 0;
    bool ExactName = false;
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
        std::wstring* error,
        bool exactName = false);
    bool InspectDeviceStack(uint64_t deviceObject, DeviceStackResult* result, std::wstring* error);
    // P0: walk \Device and collect DRIVER_OBJECTs that are not part of the
    // knownDriverObjects set the \Driver enumeration produced.
    bool ScanDeviceDriverBackrefs(
        const std::set<uint64_t>& knownDriverObjects,
        DeviceBackrefResult* result,
        std::wstring* error);
    // P0 follow-up: bounded sweep of the driver object type list for
    // DRIVER_OBJECTs that neither the \Driver directory nor a \Device
    // back-reference reaches. The type-list link offset is calibrated against
    // the \Driver set and needs two independent confirmations; anything less
    // fails closed with an error instead of guessing.
    bool ScanTypeListDriverObjects(
        const std::set<uint64_t>& knownDriverObjects,
        const std::set<uint64_t>& deviceDriverObjects,
        DriverTypeListResult* result,
        std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildModuleIntegrityJson(const ModuleIntegrityResult& result);
std::wstring BuildDriverIntegrityJson(const DriverIntegrityResult& result);
std::wstring BuildDriverObjectJson(const DriverObjectInspectResult& result);
std::wstring BuildDeviceStackJson(const DeviceStackResult& result);
bool IntegrityIatOwnerSelfTest();
bool IntegrityDiscardedSectionSelfTest();
bool IntegrityProloguePatternSelfTest();
bool DeviceStackWalkSelfTest();
// P0 follow-up: deterministic regression for the driver object type-list
// sweep. Drives the link-offset calibration and the candidate shape predicate
// from synthetic node lists, so the sweep semantics are covered without a live
// kernel.
bool DriverTypeListSweepSelfTest();
