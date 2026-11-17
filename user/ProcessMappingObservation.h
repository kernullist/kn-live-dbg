#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

inline constexpr uint64_t ProcessMappingQueryBytes = 48;

// VirtualQueryEx observations describe queried ranges at particular times.
// They do not hold a mapping reference, identify a physical page or exclude ABA.
struct ProcessMappingQuery
{
    uint64_t Address = 0, ReturnedBytes = 0;
    uint64_t RegionBase = 0, RegionBytes = 0, AllocationBase = 0;
    uint32_t State = 0, Type = 0, Protect = 0, AllocationProtect = 0;
    uint32_t NativeStatus = 0;
    bool NativeStatusKnown = false;
};

struct ProcessMappingObservation
{
    std::wstring SourceId;
    std::wstring Status = L"unavailable";
    uint64_t Address = 0, StartedTick = 0, EndedTick = 0;
    uint32_t Length = 0;
    bool IdentityRevalidated = false;
    std::vector<ProcessMappingQuery> Queries;
};

inline uint64_t ProcessMappingTick()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

class IProcessMappingObserver
{
public:
    virtual ~IProcessMappingObserver() = default;
    virtual ProcessMappingObservation ObserveMapping(uint64_t address, uint32_t length,
        const std::atomic<bool>* cancellation = nullptr) = 0;
};

struct ImageReadMappings
{
    ProcessMappingObservation Before, After;
};

struct ImageProcessMappings
{
    std::vector<ImageReadMappings> Reads;
    std::vector<ProcessMappingObservation> Final;
};
