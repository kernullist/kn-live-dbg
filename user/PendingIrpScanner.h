#pragma once

#include "AddressSpaceDescriptor.h"
#include "ScannerListWindow.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

class DeviceClient;
class SymbolEngine;

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

struct PendingIrpStackObservation
{
    uint32_t Index = 0;
    uint64_t Address = 0;
    uint8_t MajorFunction = 0;
    uint8_t MinorFunction = 0;
    uint8_t Control = 0;
    uint64_t CompletionRoutine = 0;
    uint64_t Context = 0;
    std::optional<uint64_t> DeviceObject;
    std::optional<uint64_t> FileObject;
};

struct PendingIrpRequestObservation
{
    PendingIrpThreadInput Thread;
    uint64_t ThreadCreateTime = 0;
    uint64_t Irp = 0;
    uint8_t StackCount = 0;
    uint8_t CurrentLocation = 0;
    std::optional<bool> CancelFlag;
    std::optional<bool> PendingReturned;
    std::optional<int32_t> IoStatus;
    std::vector<PendingIrpStackObservation> Stacks;
};

struct PendingIrpScanResult
{
    AddressSpaceDescriptor AddressSpace;
    std::vector<PendingIrpCompletionRecord> Records;
    std::vector<PendingIrpRequestObservation> Requests;
    std::vector<std::wstring> Warnings;
    PendingIrpCursor NextCursor;
    uint32_t ThreadsVisited = 0;
    uint32_t IrpsInspected = 0;
    uint32_t WalkNodes = 0;
    uint32_t UnstableObservations = 0;
    uint64_t ScanStartedTickMs = 0;
    uint64_t ScanFinishedTickMs = 0;
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

bool PendingIrpScannerSelfTest(uint32_t* checks = nullptr, PendingIrpScanResult* fixture = nullptr);
bool PendingIrpObservationSelfTest(uint32_t* checks = nullptr, PendingIrpScanResult* fixture = nullptr);
