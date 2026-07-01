#pragma once

#include "TimelineModel.h"

#include <string>
#include <vector>

struct TimelineDashboardDocument
{
    TimelineStats Stats;
    TimelineAnalysisResult Analysis;
    std::vector<TimelineEvent> Events;
    std::wstring GeneratedUtc;
    bool Truncated = false;
    uint64_t TotalStored = 0;
    size_t MaxEvents = 0;
    bool HasLiveStatus = false;
    uint32_t LiveFlags = 0;
    uint32_t LiveCapacity = 0;
    uint32_t LiveQueued = 0;
    uint64_t LiveDropped = 0;
    uint64_t LiveNextSequence = 0;
    bool AutoDrainRunning = false;
    uint64_t AutoDrainBatches = 0;
    uint64_t AutoDrainEvents = 0;
    uint64_t AutoDrainAdded = 0;
    uint64_t AutoDrainErrors = 0;
    std::wstring AutoDrainLastUtc;
    std::wstring AutoDrainLastError;
};

std::wstring BuildTimelineDashboardHtml(const TimelineDashboardDocument& document);
