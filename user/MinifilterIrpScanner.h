#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

enum class MinifilterIrpAction
{
    Status,
    Disable,
    Enable
};

enum class MinifilterIrpWhich
{
    Both,
    Pre,
    Post
};

struct MinifilterIrpSlot
{
    uint32_t Index = 0;
    uint32_t MajorFunction = 0;
    uint32_t Flags = 0;
    uint64_t Entry = 0;
    uint64_t Pre = 0;
    uint64_t Post = 0;
    std::wstring MajorName;
    std::wstring PreModule;
    std::wstring PreSymbol;
    std::wstring PostModule;
    std::wstring PostSymbol;
    bool PreActive = false;
    bool PostActive = false;
    bool Disabled = false;
};

struct MinifilterFilterRecord
{
    uint32_t FrameId = 0xffffffffu;
    uint32_t Flags = 0;
    uint32_t OperationCount = 0;
    uint32_t ActiveOperationCount = 0;
    uint32_t InstanceCount = 0;
    uint32_t LiveCallbackCount = 0;
    uint64_t Frame = 0;
    uint64_t Filter = 0;
    uint64_t DriverObject = 0;
    uint64_t DriverStart = 0;
    uint64_t Operations = 0;
    std::wstring Name;
    std::wstring Altitude;
    std::wstring DriverModule;
    std::wstring Notes;
    bool WellKnownInbox = false;
    bool LiveLayoutAvailable = false;
    std::vector<MinifilterIrpSlot> OperationsTable;
};

struct MinifilterIrpChange
{
    MinifilterIrpSlot Before;
    MinifilterIrpSlot After;
    std::wstring FilterName;
    uint64_t Filter = 0;
    bool PreChanged = false;
    bool PostChanged = false;
    bool UsedBackup = false;
    bool WellKnownInbox = false;
    uint32_t LiveNodesChanged = 0;
    uint32_t LiveNodesFailed = 0;
};

struct MinifilterIrpBatchResult
{
    std::vector<MinifilterIrpChange> Changes;
    std::vector<std::wstring> Failures;
    std::wstring FilterName;
    uint64_t Filter = 0;
    uint32_t Attempted = 0;
    uint32_t Changed = 0;
    uint32_t Skipped = 0;
    uint32_t Failed = 0;
    uint32_t LiveNodesChanged = 0;
    uint32_t LiveNodesFailed = 0;
    bool WellKnownInbox = false;
};

struct MinifilterIrpScanResult
{
    std::vector<MinifilterFilterRecord> Filters;
    std::vector<std::wstring> Warnings;
    std::vector<std::wstring> CoverageNotes;
    uint64_t FltGlobals = 0;
    std::wstring FltGlobalsSymbol;
    bool LayoutFromPdb = false;
    bool CoverageComplete = false;
};

class MinifilterIrpScanner
{
public:
    MinifilterIrpScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(MinifilterIrpScanResult* result, std::wstring* error);
    bool Show(
        const std::wstring& specifier,
        MinifilterFilterRecord* filter,
        MinifilterIrpScanResult* result,
        std::wstring* error);
    bool SetIrp(
        const std::wstring& specifier,
        uint32_t majorFunction,
        MinifilterIrpAction action,
        MinifilterIrpWhich which,
        MinifilterIrpChange* change,
        MinifilterIrpScanResult* result,
        std::wstring* error);
    bool SetAllIrps(
        const std::wstring& specifier,
        MinifilterIrpAction action,
        MinifilterIrpWhich which,
        MinifilterIrpBatchResult* batch,
        MinifilterIrpScanResult* result,
        std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

bool ParseMinifilterIrpMajor(const std::wstring& text, uint32_t* majorFunction, std::wstring* error);
bool IsMinifilterIrpAllToken(const std::wstring& text);
bool IsMinifilterWriteAction(const std::wstring& text);
std::wstring MinifilterIrpMajorName(uint32_t majorFunction);
bool MinifilterIrpNameLooksInbox(const std::wstring& name);
std::wstring BuildMinifilterIrpJson(const MinifilterIrpScanResult& result);
std::wstring BuildMinifilterIrpChangeJson(const MinifilterIrpChange& change);
std::wstring BuildMinifilterIrpBatchJson(const MinifilterIrpBatchResult& batch);
bool MinifilterIrpScannerSelfTest();
uint32_t MinifilterCallbackIndexFromMajor(uint32_t majorFunction);
