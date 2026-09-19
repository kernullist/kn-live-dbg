#pragma once

#include "ProcessLayoutCore.h"
#include "ObservationWindows.h"

#include <atomic>
#include <functional>
#include <mutex>
#include <set>

struct ProcessLayoutScope
{
    bool All = true;
    std::set<uint32_t> Pids;
    std::vector<std::wstring> Names;

    bool Matches(uint32_t pid, const std::wstring& name) const;
};

struct ProcessLayoutStats
{
    uint64_t Inventories = 0;
    uint64_t InventoryFailures = 0;
    uint64_t Discovered = 0;
    uint64_t Retired = 0;
    uint64_t ProcessCap = 0;
    uint64_t Completed = 0;
    uint64_t Failed = 0;
    uint64_t Tracked = 0;
    uint64_t Pending = 0;
    uint64_t Unavailable = 0;
    uint64_t StoredRows = 0;
    uint64_t OldestAgeMs = 0;
    uint64_t LastInventoryMs = 0;
    bool InventoryComplete = false;
    bool AllProcesses = true;
    uint32_t IntervalMs = 5000;
};

struct ProcessLayoutNotice
{
    ObservationIdentity Identity;
    std::wstring Name;
    std::wstring Status;
    uint64_t Cycle = 0;
    uint64_t StartedMs = 0;
    uint64_t FinishedMs = 0;
    uint64_t ObservedAt = 0;
    uint64_t ChangedRanges = 0;
    uint64_t CandidateRanges = 0;
    uint64_t Rows = 0;
    uint64_t ImageNameFailures = 0;
    std::vector<process_layout::Change> Changes;
};

struct ProcessLayoutCandidate
{
    ObservationIdentity Identity;
    process_layout::Region Region;
    uint64_t ObservedAt = 0;
    uint64_t ObservedMs = 0;
    std::wstring Role;
    std::wstring ImageName;
};

// Tick has a single caller. Readers copy immutable snapshots under Mutex.
// OS collection is read-only and never uses the driver's shared device handle.
class ProcessLayoutMonitor
{
public:
    using NoticeSink = std::function<void(ProcessLayoutNotice)>;
    using CandidateSink = std::function<void(ProcessLayoutCandidate)>;

    void Reset(uint32_t intervalMs = 5000);
    void Tick(const ProcessLayoutScope& scope, const std::atomic<bool>& stop,
        const NoticeSink& notice, const CandidateSink& candidate);
    ProcessLayoutStats Stats() const;
    std::wstring Json(uint32_t pid = 0, bool initial = false) const;
    std::wstring Text(uint32_t pid = 0, bool initial = false) const;
    void NoteException();
    void RequestDiscovery();

private:
    struct Entry
    {
        uint32_t Pid = 0;
        std::wstring Name;
        ObservationIdentity Identity;
        process_layout::History History;
        std::shared_ptr<process_layout::Snapshot> Pending;
        uint64_t FirstSeenMs = 0;
        uint64_t NextScanMs = 0;
        uint64_t LastAttemptMs = 0;
        uint64_t VerificationCursor = 0;
        uint64_t ExportCursor = 0;
        std::wstring Status = L"pending";
        uint32_t Error = 0;
    };

    void Discover(const ProcessLayoutScope& scope, uint64_t now);
    void Advance(Entry& entry, const std::atomic<bool>& stop, const NoticeSink& notice, const CandidateSink& candidate);
    void Fail(Entry& entry, const wchar_t* reason, uint32_t error, const NoticeSink& notice);
    size_t StoredRows() const;
    size_t StoredNames() const;
    mutable std::mutex Mutex;
    std::map<uint32_t, Entry> Entries;
    ProcessLayoutStats Counters;
    uint32_t CursorPid = 0;
    uint64_t NextInventoryMs = 0;
    uint64_t AddressLimit = 0;
    std::atomic<bool> RefreshRequested{false};
};

bool ProcessLayoutRegionMatches(const process_layout::Region& expected, const MEMORY_BASIC_INFORMATION& current);
std::wstring ProcessLayoutReferencePath(const std::wstring& mappedName);
