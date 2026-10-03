#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "DeviceClient.h"
#include "SymbolEngine.h"
#include "ScannerListWindow.h"

struct DeferredQueueCursor
{
    uint64_t RootAddress = 0;
    uint32_t QueueIndex = 0;
    ScannerListCursor List;
};

struct DpcRoutineRecord
{
    uint32_t Index = 0;
    uint32_t Processor = 0;
    std::wstring Source;
    uint64_t ObjectAddress = 0;
    uint64_t Routine = 0;
    std::wstring Module;
    std::wstring Symbol;
    bool Suspicious = false;
    std::wstring Notes;
};

struct TimerRoutineRecord
{
    uint32_t Index = 0;
    uint32_t Processor = 0;
    uint64_t TimerAddress = 0;
    uint64_t DpcAddress = 0;
    uint64_t Routine = 0;
    std::wstring Module;
    std::wstring Symbol;
    bool Suspicious = false;
    std::wstring Notes;
};

struct WorkItemRecord
{
    uint32_t Index = 0;
    uint64_t EntryAddress = 0;
    uint64_t Routine = 0;
    uint64_t Parameter = 0;
    uint64_t QueueAddress = 0;
    std::wstring Module;
    std::wstring Symbol;
    bool Suspicious = false;
    std::wstring Notes;
};

struct DpcTimerScanResult
{
    std::vector<DpcRoutineRecord> Dpcs;
    std::vector<TimerRoutineRecord> Timers;
    std::vector<WorkItemRecord> WorkItems;
    std::vector<std::wstring> Warnings;
    bool DpcCoverageComplete = false;
    bool TimerCoverageComplete = false;
    bool WorkItemCoverageComplete = false;
    bool WorkItemAttempted = false;
    bool WorkItemLayoutFromPdb = false;
    uint32_t WorkItemQueuesVisited = 0;
    uint32_t WorkItemNodesVisited = 0;
    std::wstring WorkItemCoverageScope;
    DeferredQueueCursor NextWorkItemCursor;
    DeferredQueueCursor NextDpcCursor;
    DeferredQueueCursor NextTimerCursor;
    uint32_t SuspiciousDpcCount = 0;
    uint32_t SuspiciousTimerCount = 0;
    uint32_t SuspiciousWorkItemCount = 0;
    bool AnySuspicious = false;
    uint32_t ProcessorsSampled = 0;
};

// Enumerates deferred execution callbacks (DPC / timer / best-effort work-item).
// High risk is reserved for non-image routines; loaded-driver DPCs are normal.
class DpcTimerScanner
{
public:
    enum class Scope
    {
        Dpc,
        Timer,
        WorkItem,
        All
    };

    struct Options
    {
        Scope Target = Scope::All;
        bool Verbose = false;
        uint32_t Limit = 0;
        uint32_t MaxProcessors = 0;
        DeferredQueueCursor WorkItemCursor;
        DeferredQueueCursor DpcCursor;
        DeferredQueueCursor TimerCursor;
    };

    DpcTimerScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(const Options& options, DpcTimerScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildDpcJson(const DpcTimerScanResult& result);
std::wstring BuildTimerJson(const DpcTimerScanResult& result);
std::wstring BuildWorkItemJson(const DpcTimerScanResult& result);
bool DpcTimerScannerSelfTest();
bool WorkItemScannerSelfTest();
