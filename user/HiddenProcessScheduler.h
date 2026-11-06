#pragma once

#include "HiddenProcessReport.h"

#include <list>
#include <map>
#include <mutex>
#include <set>

struct HiddenProcessComparison
{
    HiddenProcessKernelView Kernel;
    std::set<uint32_t> Spi;
    std::set<uint32_t> Toolhelp;
    bool SpiComplete = false;
    bool ToolhelpComplete = false;
    uint64_t StartedMs = 0;
    uint64_t FinishedMs = 0;
    std::vector<std::wstring> Warnings;
};

// Both native acquisition and the owned controls run the same batch orchestrator.
// Deadlines are cooperative: a source need not interrupt an in-flight API call.
class HiddenProcessQualificationSource
{
public:
    virtual ~HiddenProcessQualificationSource() = default;
    virtual uint64_t NowMs() const = 0;
    virtual uint64_t Epoch() const = 0;
    virtual bool Cancelled() const = 0;
    virtual HiddenProcessLifetime ReadLifetime(uint32_t pid, uint64_t deadline) = 0;
    virtual HiddenProcessComparison Compare(uint64_t deadline) = 0;
};

class HiddenProcessScheduler
{
public:
    void Qualify(HiddenProcessQualificationSource& source,
        const std::vector<HiddenProcessRecord*>& candidates,
        HiddenProcessScanResult& result, uint64_t budgetMs = 5000);

private:
    struct Pending
    {
        std::list<uint32_t>::iterator Position;
        uint64_t SinceMs = 0;
        bool NewPriority = false;
    };

    // Queue membership is only a scheduling hint, never a process identity or a
    // lifetime sample. Memory is bounded by the current discovery candidate set.
    std::mutex Mutex;
    uint64_t SourceEpoch = 0;
    std::list<uint32_t> Order;
    std::map<uint32_t, Pending> Entries;
    uint64_t LifetimeCostMs = 1;
    uint64_t InventoryCostMs = 2000;
};

bool HiddenProcessSchedulerSelfTest(uint32_t* checks = nullptr);
std::wstring BuildHiddenProcessSchedulingFixture();
