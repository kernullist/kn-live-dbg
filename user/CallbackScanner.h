#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct KernelCallbackRecord
{
    std::wstring Kind;
    std::wstring Target;
    std::wstring Altitude;
    std::wstring FunctionModule;
    std::wstring FunctionSymbol;
    std::wstring PostFunctionModule;
    std::wstring PostFunctionSymbol;
    std::wstring ContextModule;
    std::wstring ContextSymbol;
    std::wstring ObjectTypeSource;
    std::wstring RootSource;
    std::wstring CallbackName;
    std::wstring FilterName;
    std::wstring Notes;
    uint32_t Slot = 0;
    uint32_t Operations = 0;
    uint32_t ObjectTypeIndex = 0xffffffffu;
    uint32_t MajorFunction = 0xffffffffu;
    uint32_t CallbackFlags = 0;
    uint32_t FilterFlags = 0;
    uint32_t FrameId = 0xffffffffu;
    uint64_t ObjectType = 0;
    uint64_t RootAddress = 0;
    uint64_t Frame = 0;
    uint64_t Filter = 0;
    uint64_t DriverObject = 0;
    uint64_t ListEntry = 0;
    uint64_t Entry = 0;
    uint64_t CallbackBlock = 0;
    uint64_t CallbackEntry = 0;
    uint64_t Function = 0;
    uint64_t PostFunction = 0;
    uint64_t FunctionSlot = 0;
    uint64_t PostFunctionSlot = 0;
    uint64_t Context = 0;
    uint64_t Cookie = 0;
    uint64_t RawValue = 0;
    bool Poisoned = false;
    bool SessionDisabled = false;
};

enum class KernelCallbackSetAction
{
    Disable,
    Enable
};

struct KernelCallbackPointerChange
{
    std::wstring Kind;
    std::wstring Target;
    std::wstring Which;
    std::wstring Module;
    uint64_t SlotAddress = 0;
    uint64_t Before = 0;
    uint64_t After = 0;
    bool Changed = false;
    bool UsedBackup = false;
    bool Skipped = false;
    std::wstring Notes;
};

struct KernelCallbackSetResult
{
    std::wstring Action;
    std::wstring Scope;
    std::wstring Module;
    uint32_t Attempted = 0;
    uint32_t Changed = 0;
    uint32_t Skipped = 0;
    uint32_t Failed = 0;
    uint32_t MinifilterLiveNodesChanged = 0;
    uint32_t MinifilterLiveNodesFailed = 0;
    std::vector<KernelCallbackPointerChange> Changes;
    std::vector<std::wstring> Failures;
    std::vector<std::wstring> Warnings;
};

struct KernelCallbackScanResult
{
    std::vector<KernelCallbackRecord> Records;
    std::vector<std::wstring> Warnings;
    // True when at least one list/table walk was partial (poisoned entries,
    // unreadable links, entry cap). Empty Records with Incomplete=false means
    // "no callbacks observed"; Incomplete=true means "coverage is not clean".
    bool Incomplete = false;
    // Count of object-callback items kept as poisoned/invalid evidence.
    uint32_t PoisonedEntryCount = 0;
};

class KernelCallbackScanner
{
public:
    KernelCallbackScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(const std::wstring& scope, KernelCallbackScanResult* result, std::wstring* error);
    bool SetModuleCallbacks(
        const std::wstring& scope,
        const std::wstring& moduleFilter,
        KernelCallbackSetAction action,
        KernelCallbackSetResult* result,
        std::wstring* error);

private:
    bool ScanProcessCallbacks(KernelCallbackScanResult* result, std::wstring* error);
    bool ScanThreadCallbacks(KernelCallbackScanResult* result, std::wstring* error);
    bool ScanImageLoadCallbacks(KernelCallbackScanResult* result, std::wstring* error);
    bool ScanRegistryCallbacks(KernelCallbackScanResult* result, std::wstring* error);
    bool ScanObjectCallbacks(KernelCallbackScanResult* result, std::wstring* error);
    bool ScanMinifilterCallbacks(KernelCallbackScanResult* result, std::wstring* error);
    bool ScanObjectTypeCallbacks(
        const std::wstring& target,
        uint64_t objectTypeAddress,
        uint32_t objectTypeIndex,
        const std::wstring& objectTypeSource,
        KernelCallbackScanResult* result,
        std::wstring* error);

    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildCallbacksJson(const KernelCallbackScanResult& result);
std::wstring BuildCallbackSetJson(const KernelCallbackSetResult& result);
bool KernelCallbackRecordMatchesModule(const KernelCallbackRecord& record, const std::wstring& moduleFilter);
bool KernelCallbackRecordMatchesModuleForWrite(const KernelCallbackRecord& record, const std::wstring& moduleFilter);
bool KernelCallbackRecordHasSessionBackup(const KernelCallbackRecord& record, const std::wstring& moduleFilter);
void OverlayCallbackSessionDisabled(KernelCallbackScanResult* result);
bool IsCallbackWriteAction(const std::wstring& text);
bool KernelCallbackScannerSelfTest();
