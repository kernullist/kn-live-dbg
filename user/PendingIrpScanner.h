#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"
#include "ScannerListWindow.h"

#include <cstdint>
#include <string>
#include <vector>

struct PendingIrpThreadInput
{
    uint64_t ThreadObject = 0;
    uint32_t ProcessId = 0;
    uint32_t ThreadId = 0;
};

struct PendingIrpCursor
{
    uint64_t ThreadObject = 0;
    uint64_t ThreadCreateTime = 0;
    uint64_t IrpAddress = 0;
    ScannerListCursor List;
};

struct PendingIrpCompletionRecord
{
    uint64_t ThreadObject = 0;
    uint64_t ThreadCreateTime = 0;
    uint64_t Irp = 0;
    uint64_t StackLocation = 0;
    uint64_t CompletionRoutine = 0;
    uint64_t CompletionSlot = 0;
    uint64_t Context = 0;
    uint32_t ProcessId = 0;
    uint32_t ThreadId = 0;
    uint32_t StackIndex = 0;
    uint8_t MajorFunction = 0;
    uint8_t MinorFunction = 0;
    uint8_t Control = 0;
    std::wstring Module;
    std::wstring Symbol;
    bool Suspicious = false;
    bool StableObservation = false;
};

struct PendingIrpScanOptions
{
    PendingIrpCursor Cursor;
    uint32_t MaxThreads = 32;
    uint32_t MaxIrps = 64;
    uint32_t MaxWalkNodes = 4096;
    bool ThreadInventoryComplete = false;
};

struct PendingIrpScanResult
{
    std::vector<PendingIrpCompletionRecord> Records;
    std::vector<std::wstring> Warnings;
    PendingIrpCursor NextCursor;
    uint32_t ThreadsVisited = 0;
    uint32_t IrpsInspected = 0;
    uint32_t WalkNodes = 0;
    uint32_t UnstableObservations = 0;
    bool LayoutFromPdb = false;
    bool CoverageComplete = false;
    // Repeated equal reads cannot establish a referenced IRP lifetime or exclude ABA reuse.
    bool ReferencedLifetime = false;
    std::wstring CoverageScope = L"outstanding IRPs linked to supplied ETHREADs; observational snapshot only";
};

class PendingIrpScanner
{
public:
    PendingIrpScanner(DeviceClient& device, SymbolEngine& symbols);
    bool Scan(const std::vector<PendingIrpThreadInput>& threads,
        const PendingIrpScanOptions& options, PendingIrpScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

bool PendingIrpScannerSelfTest();
