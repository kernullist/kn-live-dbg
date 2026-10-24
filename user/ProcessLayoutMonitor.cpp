#include "ProcessLayoutMonitor.h"
#include "McpJson.h"

#include <TlHelp32.h>
#include <Psapi.h>
#include <cwctype>
#include <sstream>

#pragma comment(lib, "Psapi.lib")

namespace
{
    constexpr size_t MaxProcesses = 4096;
    // Initial, current and in-progress snapshots coexist. The old budget
    // exhausted on ordinary full-host inventories before a new sweep fit.
    constexpr size_t MaxStoredRows = 524288;
    constexpr size_t MaxStoredNames = 65536;
    // Preserve the old worst-case 32 MiB string payload while allowing the
    // many short, repeated mapping names in first/current/pending snapshots.
    constexpr size_t MaxStoredNameCharacters = 16 * 1024 * 1024;

    template<typename Query>
    bool ReadImageNameQuery(Query query, std::wstring& name, DWORD& error)
    {
        name.clear();
        for (const DWORD capacity : {1024u, 32768u})
        {
            std::vector<wchar_t> path(capacity);
            const DWORD length = query(path.data(), capacity);
            error = length == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER;
            if (length != 0 && length < capacity)
            {
                name.assign(path.data(), length);
                error = ERROR_SUCCESS;
                return true;
            }
            if (length == 0 && error != ERROR_INSUFFICIENT_BUFFER) { return false; }
        }
        return false;
    }

    bool ReadImageName(HANDLE process, uint64_t address, std::wstring& name, DWORD& error)
    {
        return ReadImageNameQuery([&](wchar_t* path, DWORD capacity)
        {
            return GetMappedFileNameW(process, reinterpret_cast<void*>(address), path, capacity);
        }, name, error);
    }

    struct Handle
    {
        HANDLE Value = nullptr;
        ~Handle()
        {
            if (Value != nullptr && Value != INVALID_HANDLE_VALUE)
            {
                CloseHandle(Value);
            }
        }
    };

    std::wstring Lower(std::wstring value)
    {
        std::transform(value.begin(), value.end(), value.begin(), towlower);
        return value;
    }

    bool Alive(HANDLE process)
    {
        FILETIME created{}, exited{}, kernel{}, user{};
        return GetProcessTimes(process, &created, &exited, &kernel, &user) &&
            exited.dwHighDateTime == 0 && exited.dwLowDateTime == 0;
    }

    process_layout::Region Convert(const MEMORY_BASIC_INFORMATION& mbi)
    {
        return {reinterpret_cast<uint64_t>(mbi.BaseAddress), mbi.RegionSize,
            reinterpret_cast<uint64_t>(mbi.AllocationBase), mbi.State, mbi.Protect, mbi.AllocationProtect, mbi.Type};
    }

    std::wstring RegionJson(const process_layout::Region& row)
    {
        return L"{\"base\":" + mcpjson::Quote(std::to_wstring(row.Base)) +
            L",\"size\":" + std::to_wstring(row.Size) +
            L",\"allocation_base\":" + mcpjson::Quote(std::to_wstring(row.AllocationBase)) +
            L",\"state\":" + std::to_wstring(row.State) + L",\"protect\":" + std::to_wstring(row.Protect) +
            L",\"allocation_protect\":" + std::to_wstring(row.AllocationProtect) +
            L",\"type\":" + std::to_wstring(row.Type) + L"}";
    }
}

bool ProcessLayoutScope::Matches(uint32_t pid, const std::wstring& name) const
{
    bool match = All || Pids.count(pid) != 0;
    const auto leaf = Lower(name.substr(name.find_last_of(L"\\/") + 1));
    for (const auto& target : Names)
    {
        const auto pattern = Lower(target.substr(target.find_last_of(L"\\/") + 1));
        match = match || pattern == L"*" || pattern == leaf ||
            ((pattern == L"*.exe" || pattern == L"*.sys") && leaf.size() >= 4 &&
                leaf.compare(leaf.size() - 4, 4, pattern.substr(1)) == 0);
    }
    return match;
}

bool ProcessLayoutRegionMatches(const process_layout::Region& expected, const MEMORY_BASIC_INFORMATION& current)
{
    const auto row = Convert(current);
    return expected.Size != 0 && expected.Base <= UINT64_MAX - expected.Size && row.Size != 0 &&
        row.Base <= expected.Base && row.Base <= UINT64_MAX - row.Size &&
        expected.Base + expected.Size <= row.Base + row.Size && expected.SameAttributes(row);
}

namespace
{
    template<typename QueryMapping, typename QueryName>
    bool RetryImageName(const process_layout::Region& expected, QueryMapping queryMapping,
        QueryName queryName, std::wstring& name, process_layout::ImageNameDiagnostic& diagnostic)
    {
        name.clear();
        diagnostic.Stage = L"not_retryable";
        if (diagnostic.InitialError == ERROR_ACCESS_DENIED || diagnostic.InitialError == ERROR_INVALID_HANDLE ||
            diagnostic.InitialError == ERROR_INVALID_PARAMETER || diagnostic.InitialError == ERROR_INSUFFICIENT_BUFFER)
        { return false; }
        const auto current = [&](MEMORY_BASIC_INFORMATION& mapping)
        {
            const bool queried = queryMapping(&mapping);
            diagnostic.CurrentAllocationBase = reinterpret_cast<uint64_t>(mapping.AllocationBase);
            diagnostic.CurrentState = mapping.State;
            diagnostic.CurrentType = mapping.Type;
            return queried && ProcessLayoutRegionMatches(expected, mapping);
        };
        MEMORY_BASIC_INFORMATION before{}, after{};
        diagnostic.Stage = L"mapping_unavailable_or_changed_before_retry";
        if (!current(before)) { return false; }
        diagnostic.Retried = true;
        diagnostic.Stage = L"retry_failed";
        std::wstring recovered;
        DWORD retryError = 0;
        if (!queryName(recovered, retryError))
        {
            diagnostic.RetryError = retryError;
            return false;
        }
        diagnostic.Stage = L"mapping_unavailable_or_changed_after_retry";
        if (!current(after) || before.BaseAddress != after.BaseAddress || before.RegionSize != after.RegionSize ||
            !Convert(before).SameAttributes(Convert(after))) { return false; }
        diagnostic.Recovered = true;
        diagnostic.Stage = L"recovered";
        name = std::move(recovered);
        return true;
    }

    std::wstring ImageNameDiagnosticsJson(const process_layout::Snapshot& snapshot)
    {
        std::wstring out = L"[";
        bool first = true;
        for (const auto& item : snapshot.ImageNameDiagnostics)
        {
            if (!first) { out += L","; }
            first = false;
            out += L"{\"address\":" + mcpjson::Quote(std::to_wstring(item.Address)) +
                L",\"allocation_base\":" + mcpjson::Quote(std::to_wstring(item.AllocationBase)) +
                L",\"initial_error\":" + std::to_wstring(item.InitialError) +
                L",\"retry_error\":" + std::to_wstring(item.RetryError) +
                L",\"retried\":" + (item.Retried ? std::wstring(L"true") : std::wstring(L"false")) +
                L",\"recovered\":" + (item.Recovered ? std::wstring(L"true") : std::wstring(L"false")) +
                L",\"stage\":" + mcpjson::Quote(item.Stage) +
                L",\"current_allocation_base\":" + mcpjson::Quote(std::to_wstring(item.CurrentAllocationBase)) +
                L",\"current_state\":" + std::to_wstring(item.CurrentState) +
                L",\"current_type\":" + std::to_wstring(item.CurrentType) + L"}";
        }
        return out + L"]";
    }
}

bool ProcessLayoutCandidateCurrent(HANDLE process, const ProcessLayoutCandidate& candidate)
{
    bool current = false;
    do
    {
        MEMORY_BASIC_INFORMATION region{};
        const uint64_t now = GetTickCount64();
        if (process == nullptr || candidate.Identity.ProcessId <= 4 || now < candidate.ObservedMs ||
            now - candidate.ObservedMs > process_layout::MaxSweepMs ||
            !candidate.Identity.SameInstance(ObserveProcessIdentity(candidate.Identity.ProcessId, process)) || !Alive(process) ||
            VirtualQueryEx(process, reinterpret_cast<void*>(candidate.Region.Base), &region, sizeof(region)) != sizeof(region) ||
            !ProcessLayoutRegionMatches(candidate.Region, region))
        {
            break;
        }
        if (!candidate.ImageName.empty())
        {
            // Equal MBI attributes do not identify the section at a reused VA.
            std::wstring name;
            DWORD error = 0;
            if (candidate.Region.Type != MEM_IMAGE || !ReadImageName(process, candidate.Region.Base, name, error) ||
                candidate.ImageName != name)
            {
                break;
            }
        }
        current = true;
    }
    while (false);
    return current;
}

std::wstring ProcessLayoutReferencePath(const std::wstring& mappedName)
{
    return mappedName.size() >= 8 && _wcsnicmp(mappedName.c_str(), L"\\Device\\", 8) == 0 ?
        L"\\\\?\\GLOBALROOT" + mappedName : mappedName;
}

void ProcessLayoutMonitor::Reset(uint32_t intervalMs)
{
    std::lock_guard<std::mutex> lock(Mutex);
    Entries.clear();
    Counters = {};
    Counters.IntervalMs = (std::max)(1000u, (std::min)(intervalMs, 60000u));
    CursorPid = 0;
    NextInventoryMs = 0;
    RefreshRequested.store(false);
    SYSTEM_INFO system{};
    GetNativeSystemInfo(&system);
    AddressLimit = reinterpret_cast<uint64_t>(system.lpMaximumApplicationAddress) + 1;
    if (AddressLimit == 0 || AddressLimit > 0x800000000000ull)
    {
        AddressLimit = 0;
    }
}

void ProcessLayoutMonitor::Discover(const ProcessLayoutScope& scope, uint64_t now)
{
    Counters.AllProcesses = scope.All;
    Counters.LastInventoryMs = now;
    ++Counters.Inventories;
    Handle snapshot{CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)};
    std::map<uint32_t, std::wstring> found;
    PROCESSENTRY32W row{};
    row.dwSize = sizeof(row);
    bool complete = false;
    if (snapshot.Value != INVALID_HANDLE_VALUE && Process32FirstW(snapshot.Value, &row))
    {
        size_t count = 0;
        do
        {
            if (++count > 65536)
            {
                break;
            }
            if (row.th32ProcessID > 4 && scope.Matches(row.th32ProcessID, row.szExeFile))
            {
                found.emplace(row.th32ProcessID, row.szExeFile);
            }
            row.dwSize = sizeof(row);
            if (!Process32NextW(snapshot.Value, &row))
            {
                complete = GetLastError() == ERROR_NO_MORE_FILES;
                break;
            }
        }
        while (true);
    }
    Counters.InventoryComplete = complete;
    if (!complete)
    {
        ++Counters.InventoryFailures;
    }
    else
    {
        for (auto it = Entries.begin(); it != Entries.end();)
        {
            if (found.count(it->first) == 0)
            {
                // Keep retained evidence until admitted even after exit. The
                // consumer will explicitly reject the old process identity.
                if (it->second.PendingNotice || !it->second.PendingChanges.empty()) { ++it; continue; }
                Counters.VerificationChangesAbandoned += it->second.PendingChanges.size();
                ++Counters.Retired;
                it = Entries.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }
    Counters.ProcessCap = 0;
    for (const auto& item : found)
    {
        if (Entries.count(item.first) != 0)
        {
            continue;
        }
        if (Entries.size() >= MaxProcesses)
        {
            ++Counters.ProcessCap;
            continue;
        }
        Entry entry;
        entry.Pid = item.first;
        entry.Name = item.second;
        entry.FirstSeenMs = now;
        Entries.emplace(item.first, std::move(entry));
        ++Counters.Discovered;
    }
}

size_t ProcessLayoutMonitor::StoredRows() const
{
    size_t rows = 0;
    for (const auto& item : Entries)
    {
        rows += item.second.History.StoredRows();
        rows += item.second.Pending ? item.second.Pending->Regions.size() : 0;
    }
    return rows;
}

size_t ProcessLayoutMonitor::StoredNames() const
{
    size_t count = 0;
    for (const auto& item : Entries)
    {
        const auto& entry = item.second;
        count += entry.History.Initial ? entry.History.Initial->ImageNames.size() : 0;
        count += entry.History.Current && entry.History.Current != entry.History.Initial ? entry.History.Current->ImageNames.size() : 0;
        count += entry.Pending ? entry.Pending->ImageNames.size() : 0;
    }
    return count;
}

size_t ProcessLayoutMonitor::StoredNameCharacters() const
{
    size_t count = 0;
    for (const auto& item : Entries)
    {
        const auto& entry = item.second;
        count += entry.History.Initial ? entry.History.Initial->ImageNameCharacters : 0;
        count += entry.History.Current && entry.History.Current != entry.History.Initial ? entry.History.Current->ImageNameCharacters : 0;
        count += entry.Pending ? entry.Pending->ImageNameCharacters : 0;
    }
    return count;
}

void ProcessLayoutMonitor::CollectImageName(process_layout::Snapshot& snapshot, const process_layout::Region& row,
    HANDLE process, size_t& remainingNames, size_t& remainingCharacters)
{
    if (row.State == process_layout::Free || row.Type != process_layout::Image) { return; }
    snapshot.ImageAllocations.insert(row.AllocationBase);
    // Reserved image tails are not a reason to cache a failed name before a
    // committed region of that allocation becomes available in this sweep.
    if (row.State != process_layout::Commit || !snapshot.ImageNameAttempts.insert(row.AllocationBase).second) { return; }
    if (remainingNames == 0 || remainingCharacters == 0 || snapshot.ImageNames.size() >= 512)
    {
        ++snapshot.ImageNameCapacityFailures;
        ++snapshot.ImageNameFailures;
        return;
    }
    std::wstring name;
    DWORD error = 0;
    if (!ReadImageName(process, row.Base, name, error))
    {
        // One transient failure used to poison this allocation for the whole
        // sweep. Retry once, only while the observed mapping still matches.
        // This is fresh name evidence, never a name copied from an old sweep.
        process_layout::ImageNameDiagnostic diagnostic;
        diagnostic.Address = row.Base;
        diagnostic.AllocationBase = row.AllocationBase;
        diagnostic.InitialError = error;
        const bool recovered = RetryImageName(row,
            [&](MEMORY_BASIC_INFORMATION* mapping)
            {
                return VirtualQueryEx(process, reinterpret_cast<void*>(row.Base), mapping, sizeof(*mapping)) == sizeof(*mapping);
            },
            [&](std::wstring& value, DWORD& code) { return ReadImageName(process, row.Base, value, code); }, name, diagnostic);
        snapshot.ImageNameRetryAttempts += diagnostic.Retried ? 1 : 0;
        snapshot.ImageNameRecovered += recovered ? 1 : 0;
        if (snapshot.ImageNameDiagnostics.size() < 32) { snapshot.ImageNameDiagnostics.push_back(std::move(diagnostic)); }
        else { ++snapshot.ImageNameDiagnosticsOmitted; }
        if (!recovered)
        {
            if (error == ERROR_INSUFFICIENT_BUFFER) { ++snapshot.ImageNameTruncated; }
            else { ++snapshot.ImageNameQueryFailures; }
            ++snapshot.ImageNameErrors[error];
            ++snapshot.ImageNameFailures;
            return;
        }
    }
    const size_t characters = name.size() + 1;
    if (characters > remainingCharacters)
    {
        ++snapshot.ImageNameCapacityFailures;
        ++snapshot.ImageNameFailures;
        return;
    }
    snapshot.ImageNames.emplace(row.AllocationBase, std::move(name));
    snapshot.ImageNameCharacters += characters;
    remainingCharacters -= characters;
    --remainingNames;
}

void ProcessLayoutMonitor::Fail(Entry& entry, const wchar_t* reason, uint32_t error, const NoticeSink& notice)
{
    ++Counters.Failed;
    entry.Pending.reset();
    entry.NextScanMs = GetTickCount64() + Counters.IntervalMs;
    if (entry.Status != reason || entry.Error != error)
    {
        ProcessLayoutNotice event;
        event.Identity = entry.Identity;
        event.Identity.ProcessId = entry.Pid;
        event.Name = entry.Name;
        event.Status = reason;
        event.FinishedMs = GetTickCount64();
        if (!notice(event))
        {
            entry.PendingNotice = std::move(event);
            ++Counters.NoticesDeferred;
        }
    }
    entry.Status = reason;
    entry.Error = error;
}

void ProcessLayoutMonitor::Advance(Entry& entry, const ProcessLayoutScope& scope, const std::atomic<bool>& stop,
    const NoticeSink& notice, const CandidateSink& candidate)
{
    using namespace process_layout;
    const auto begin = GetTickCount64();
    entry.LastAttemptMs = begin;
    Handle process{OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, entry.Pid)};
    if (process.Value == nullptr)
    {
        process.Value = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, entry.Pid);
    }
    if (process.Value == nullptr)
    {
        Fail(entry, L"process_query_unavailable", GetLastError(), notice);
        return;
    }
    const auto identity = ObserveProcessIdentity(entry.Pid, process.Value);
    if (identity.CreateTime == 0 || identity.BootId.empty() || !Alive(process.Value))
    {
        Fail(entry, L"process_identity_unavailable_or_exited", 0, notice);
        return;
    }
    const bool newInstance = entry.Identity.CreateTime == 0 || !entry.Identity.SameInstance(identity);
    if (entry.Identity.CreateTime != 0 && newInstance)
    {
        Counters.VerificationChangesAbandoned += entry.PendingChanges.size();
        entry.PendingChanges.clear();
        entry.PeriodicDeferred = false;
        entry.History = {};
        entry.Pending.reset();
        entry.FirstSeenMs = begin;
        entry.VerificationCursor = 0;
        ++Counters.Retired;
        ++Counters.Discovered;
    }
    if (newInstance)
    {
        wchar_t image[32768]{};
        DWORD length = 32768;
        if (QueryFullProcessImageNameW(process.Value, 0, image, &length) && length != 0 && length < 32768)
        {
            const std::wstring path(image, length);
            entry.Name = path.substr(path.find_last_of(L"\\/") + 1);
        }
        else
        {
            entry.Name = L"<name_unavailable>";
        }
    }
    entry.Identity = identity;
    if (!scope.Matches(entry.Pid, entry.Name))
    {
        Fail(entry, L"process_outside_scope", 0, notice);
        return;
    }
    if (!entry.Pending)
    {
        entry.Pending = std::make_shared<Snapshot>();
        entry.Pending->Identity = identity;
        entry.Pending->StartedMs = begin;
        entry.Pending->Limit = AddressLimit;
    }
    auto& sweep = *entry.Pending;
    if (AddressLimit == 0 || begin - sweep.StartedMs > MaxSweepMs)
    {
        Fail(entry, L"address_domain_unavailable_or_sweep_expired", 0, notice);
        return;
    }
    size_t remainingRows = MaxStoredRows - (std::min)(MaxStoredRows, StoredRows());
    size_t remainingNames = MaxStoredNames - (std::min)(MaxStoredNames, StoredNames());
    size_t remainingNameCharacters = MaxStoredNameCharacters - (std::min)(MaxStoredNameCharacters, StoredNameCharacters());
    for (size_t queries = 0; queries < 256 && sweep.Cursor < AddressLimit &&
        !stop.load() && GetTickCount64() - begin < 10; ++queries)
    {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQueryEx(process.Value, reinterpret_cast<void*>(sweep.Cursor), &mbi, sizeof(mbi)) != sizeof(mbi))
        {
            Fail(entry, L"virtual_query_failed", GetLastError(), notice);
            return;
        }
        const auto row = Convert(mbi);
        const size_t prior = sweep.Regions.size();
        if (!Append(sweep, row, (std::min)(MaxRegions, prior + remainingRows)))
        {
            Fail(entry, remainingRows == 0 || prior >= MaxRegions ? L"region_capacity" : L"unstable_or_invalid_boundary", 0, notice);
            return;
        }
        remainingRows -= sweep.Regions.size() - prior;
        CollectImageName(sweep, row, process.Value, remainingNames, remainingNameCharacters);
    }
    if (!entry.Identity.SameInstance(ObserveProcessIdentity(entry.Pid, process.Value)) || !Alive(process.Value))
    {
        Fail(entry, L"process_changed_or_exited", 0, notice);
        return;
    }
    entry.Status = L"collecting";
    entry.Error = 0;
    if (sweep.Cursor != AddressLimit)
    {
        return;
    }
    sweep.Complete = true;
    sweep.ImageNameUnqueryable = sweep.ImageAllocations.size() - sweep.ImageNameAttempts.size();
    sweep.ImageNameFailures += sweep.ImageNameUnqueryable;
    sweep.FinishedMs = GetTickCount64();
    sweep.ObservedAt = ObservationFileTime();
    if (sweep.FinishedMs - sweep.StartedMs > MaxSweepMs)
    {
        Fail(entry, L"sweep_expired", 0, notice);
        return;
    }
    if (!entry.History.Accept(entry.Pending))
    {
        Fail(entry, L"snapshot_rejected", 0, notice);
        return;
    }
    const auto snapshot = entry.Pending;
    entry.Pending.reset();
    entry.VerificationBudget = 8;
    entry.VerificationRowsRemaining = snapshot->Regions.size();
    entry.VerificationEmitted.clear();
    entry.NextScanMs = snapshot->FinishedMs + Counters.IntervalMs;
    entry.Status = L"complete";
    ++Counters.Completed;
    const auto& delta = entry.History.LastDelta;
    ProcessLayoutNotice event;
    event.Identity = identity;
    event.Name = entry.Name;
    event.Status = entry.History.Completed == 1 ? L"initial_observation" : L"complete";
    event.Cycle = entry.History.Completed;
    event.StartedMs = snapshot->StartedMs;
    event.FinishedMs = snapshot->FinishedMs;
    event.ObservedAt = snapshot->ObservedAt;
    event.Rows = snapshot->Regions.size();
    event.ImageNameFailures = snapshot->ImageNameFailures;
    event.ImageAllocations = snapshot->ImageAllocations.size();
    event.ImageNamesKnown = snapshot->ImageNames.size();
    event.ImageNameCapacityFailures = snapshot->ImageNameCapacityFailures;
    event.ImageNameQueryFailures = snapshot->ImageNameQueryFailures;
    event.ImageNameTruncated = snapshot->ImageNameTruncated;
    event.ImageNameUnqueryable = snapshot->ImageNameUnqueryable;
    event.ImageNameRetryAttempts = snapshot->ImageNameRetryAttempts;
    event.ImageNameRecovered = snapshot->ImageNameRecovered;
    event.ImageNameDiagnosticsOmitted = snapshot->ImageNameDiagnosticsOmitted;
    event.ImageNameDiagnostics = ImageNameDiagnosticsJson(*snapshot);
    event.ChangedRanges = delta.ChangedRanges;
    event.CandidateRanges = delta.CandidateRanges;
    event.Changes = delta.Changes;
    if (!notice(event))
    {
        entry.PendingNotice = std::move(event);
        ++Counters.NoticesDeferred;
    }

    // Retain changed ranges until admitted; a new snapshot must not overwrite
    // them under backpressure. Periodic work remains a cursor into the latest
    // complete snapshot, not thousands of redundant queued copies.
    std::set<uint64_t> emitted;
    for (bool executable : {true, false})
    {
        // Preserve the original priority for executable transitions. New NX
        // follow-ups use the remaining budget, never displace executable work.
        for (const auto& change : delta.Changes)
        {
            const auto& row = change.After;
            if (!change.Candidate() || row.State == Free || row.Executable() != executable ||
                entry.PendingChanges.size() >= 4 || !emitted.insert(row.Base).second) { continue; }
            ProcessLayoutCandidate work;
            work.Identity = identity;
            work.Region = row;
            work.ObservedMs = snapshot->FinishedMs;
            work.ObservedAt = snapshot->ObservedAt;
            work.Role = L"layout_change";
            const auto path = snapshot->ImageNames.find(row.AllocationBase);
            if (path != snapshot->ImageNames.end()) { work.ImageName = path->second; }
            entry.PendingChanges.push_back(std::move(work));
        }
    }
    PublishCandidates(entry, candidate, true);
}

void ProcessLayoutMonitor::PublishCandidates(Entry& entry, const CandidateSink& candidate, bool periodic)
{
    // A retry continues the same cycle's quota; it must not create eight new
    // admissions every time the queue briefly has room.
    auto& budget = entry.VerificationBudget;
    if (budget == 0) { entry.PeriodicDeferred = false; return; }
    auto& emitted = entry.VerificationEmitted;
    while (!entry.PendingChanges.empty() && budget != 0)
    {
        if (!candidate(entry.PendingChanges.front()))
        {
            ++Counters.VerificationDeferred;
            return;
        }
        emitted.insert(entry.PendingChanges.front().Region.Base);
        entry.PendingChanges.pop_front();
        ++Counters.VerificationSubmitted;
        --budget;
    }
    if (!periodic || !entry.History.Current) { return; }
    const auto& snapshot = entry.History.Current;
    const uint64_t now = GetTickCount64();
    if (now < snapshot->FinishedMs || now - snapshot->FinishedMs > process_layout::MaxSweepMs)
    {
        // Recollect instead of refreshing the timestamp of an old observation.
        entry.PeriodicDeferred = false;
        entry.NextScanMs = 0;
        return;
    }
    entry.PeriodicDeferred = false;
    const auto& regions = snapshot->Regions;
    auto position = std::lower_bound(regions.begin(), regions.end(), entry.VerificationCursor,
        [](const process_layout::Region& row, uint64_t address)
        {
            return row.Base < address;
        });
    size_t index = position == regions.end() ? 0 : static_cast<size_t>(position - regions.begin());
    while (entry.VerificationRowsRemaining != 0 && !regions.empty() && budget != 0)
    {
        const auto& row = regions[index];
        if (row.Executable() && emitted.count(row.Base) == 0)
        {
            ProcessLayoutCandidate work;
            work.Identity = snapshot->Identity;
            work.Region = row;
            work.ObservedMs = snapshot->FinishedMs;
            work.ObservedAt = snapshot->ObservedAt;
            work.Role = entry.History.Completed == 1 ? L"layout_initial" : L"layout_periodic";
            const auto path = snapshot->ImageNames.find(row.AllocationBase);
            if (path != snapshot->ImageNames.end()) { work.ImageName = path->second; }
            if (!candidate(std::move(work)))
            {
                ++Counters.VerificationDeferred;
                entry.VerificationCursor = row.Base;
                entry.PeriodicDeferred = true;
                return;
            }
            emitted.insert(row.Base);
            ++Counters.VerificationSubmitted;
            --budget;
        }
        --entry.VerificationRowsRemaining;
        index = (index + 1) % regions.size();
    }
    entry.VerificationCursor = regions.empty() ? 0 : regions[index].Base;
}

void ProcessLayoutMonitor::FlushCandidates(const CandidateSink& candidate)
{
    std::lock_guard<std::mutex> lock(Mutex);
    for (auto& item : Entries) { PublishCandidates(item.second, candidate, false); }
}

void ProcessLayoutMonitor::FlushNotices(const NoticeSink& notice)
{
    std::lock_guard<std::mutex> lock(Mutex);
    for (auto& item : Entries)
    {
        if (item.second.PendingNotice && notice(*item.second.PendingNotice)) { item.second.PendingNotice.reset(); }
    }
}

void ProcessLayoutMonitor::Tick(const ProcessLayoutScope& scope, const std::atomic<bool>& stop,
    const NoticeSink& notice, const CandidateSink& candidate)
{
    std::lock_guard<std::mutex> lock(Mutex);
    const uint64_t begin = GetTickCount64();
    if (begin >= NextInventoryMs || (RefreshRequested.load() && begin - Counters.LastInventoryMs >= 200))
    {
        RefreshRequested.store(false);
        Discover(scope, begin);
        NextInventoryMs = GetTickCount64() + 1000;
    }
    size_t visited = 0;
    auto next = Entries.upper_bound(CursorPid);
    while (visited < Entries.size() && !stop.load() && GetTickCount64() - begin < 50)
    {
        if (next == Entries.end())
        {
            next = Entries.begin();
        }
        auto& entry = next->second;
        CursorPid = next->first;
        ++next;
        ++visited;
        if (entry.PendingNotice)
        {
            if (!notice(*entry.PendingNotice)) { ++Counters.NoticesDeferred; continue; }
            entry.PendingNotice.reset();
        }
        if (!entry.PendingChanges.empty())
        {
            PublishCandidates(entry, candidate, false);
            if (!entry.PendingChanges.empty()) { continue; }
        }
        if (GetTickCount64() >= entry.NextScanMs)
        {
            Advance(entry, scope, stop, notice, candidate);
        }
        else if (entry.PeriodicDeferred)
        {
            PublishCandidates(entry, candidate, true);
        }
    }
}

void ProcessLayoutMonitor::NoteException()
{
    std::lock_guard<std::mutex> lock(Mutex);
    ++Counters.Failed;
}

void ProcessLayoutMonitor::RequestDiscovery()
{
    RefreshRequested.store(true);
}

ProcessLayoutStats ProcessLayoutMonitor::Stats() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    auto stats = Counters;
    stats.Tracked = Entries.size();
    stats.StoredRows = StoredRows();
    stats.StoredNames = StoredNames();
    stats.StoredNameCharacters = StoredNameCharacters();
    const auto now = GetTickCount64();
    for (const auto& item : Entries)
    {
        const auto& entry = item.second;
        stats.VerificationChangesPending += entry.PendingChanges.size();
        stats.NoticesPending += entry.PendingNotice ? 1 : 0;
        stats.Pending += entry.Pending != nullptr || !entry.History.Current ? 1 : 0;
        stats.Unavailable += entry.Status != L"complete" && entry.Status != L"collecting" && entry.Status != L"pending" ? 1 : 0;
        const uint64_t last = entry.History.Current ? entry.History.Current->FinishedMs : entry.FirstSeenMs;
        stats.OldestAgeMs = (std::max)(stats.OldestAgeMs, now - (std::min)(now, last));
    }
    return stats;
}

std::wstring ProcessLayoutMonitor::Json(uint32_t pid, bool initial) const
{
    std::map<uint32_t, Entry> entries;
    ProcessLayoutStats stats;
    {
        std::lock_guard<std::mutex> lock(Mutex);
        stats = Counters;
        stats.StoredNames = StoredNames();
        stats.StoredNameCharacters = StoredNameCharacters();
        if (pid == 0)
        {
            entries = Entries;
        }
        else
        {
            const auto found = Entries.find(pid);
            if (found != Entries.end())
            {
                entries.emplace(*found);
            }
        }
        for (auto& item : entries)
        {
            stats.VerificationChangesPending += item.second.PendingChanges.size();
            stats.NoticesPending += item.second.PendingNotice ? 1 : 0;
            item.second.ExportCursor = item.second.Pending ? item.second.Pending->Cursor : 0;
            item.second.Pending.reset();
        }
    }
    std::wstring out = L"{\"schema\":\"kmon.layouts.v1\",\"claim\":\"non_atomic_observations\",\"baseline_trusted\":false";
    out += L",\"execution_proven\":false,\"generated_ms\":" + std::to_wstring(GetTickCount64());
    out += L",\"scope\":" + mcpjson::Quote(stats.AllProcesses ? L"all_processes" : L"selected_processes");
    out += L",\"inventory_complete\":" + std::wstring(stats.InventoryComplete ? L"true" : L"false");
    out += L",\"inventory_ms\":" + std::to_wstring(stats.LastInventoryMs);
    out += L",\"processes_over_cap\":" + std::to_wstring(stats.ProcessCap);
    out += L",\"interval_ms\":" + std::to_wstring(stats.IntervalMs);
    out += L",\"stored_row_limit\":" + std::to_wstring(MaxStoredRows);
    out += L",\"stored_name_limit\":" + std::to_wstring(MaxStoredNames);
    out += L",\"stored_name_character_limit\":" + std::to_wstring(MaxStoredNameCharacters);
    out += L",\"stored_names\":" + std::to_wstring(stats.StoredNames);
    out += L",\"stored_name_characters\":" + std::to_wstring(stats.StoredNameCharacters);
    out += L",\"verification_deferred\":" + std::to_wstring(stats.VerificationDeferred);
    out += L",\"verification_submitted\":" + std::to_wstring(stats.VerificationSubmitted);
    out += L",\"verification_changes_pending\":" + std::to_wstring(stats.VerificationChangesPending);
    out += L",\"verification_changes_abandoned\":" + std::to_wstring(stats.VerificationChangesAbandoned);
    out += L",\"notices_deferred\":" + std::to_wstring(stats.NoticesDeferred);
    out += L",\"notices_pending\":" + std::to_wstring(stats.NoticesPending);
    out += L",\"view\":" + mcpjson::Quote(initial ? L"initial" : L"current");
    out += L",\"filter_pid\":" + std::to_wstring(pid) + L",\"processes\":[";
    bool first = true;
    for (const auto& item : entries)
    {
        const auto& entry = item.second;
        const auto snapshot = initial ? entry.History.Initial : entry.History.Current;
        if (!first)
        {
            out += L",";
        }
        first = false;
        out += L"{\"pid\":" + std::to_wstring(entry.Pid) + L",\"name\":" + mcpjson::Quote(entry.Name);
        out += L",\"boot_id\":" + mcpjson::Quote(entry.Identity.BootId);
        out += L",\"create_time\":" + mcpjson::Quote(std::to_wstring(entry.Identity.CreateTime));
        out += L",\"status\":" + mcpjson::Quote(entry.Status) + L",\"error\":" + std::to_wstring(entry.Error);
        out += L",\"cycles\":" + std::to_wstring(entry.History.Completed);
        out += L",\"verification_cursor\":" + mcpjson::Quote(std::to_wstring(entry.VerificationCursor));
        out += L",\"verification_budget_remaining\":" + std::to_wstring(entry.VerificationBudget);
        out += L",\"verification_periodic_deferred\":" + std::wstring(entry.PeriodicDeferred ? L"true" : L"false");
        out += L",\"verification_coverage\":\"bounded_rotating_candidates; not_full_code_coverage\"";
        out += L",\"last_attempt_ms\":" + std::to_wstring(entry.LastAttemptMs);
        out += L",\"pending_cursor\":" + mcpjson::Quote(std::to_wstring(entry.ExportCursor));
        out += L",\"snapshot_available\":" + std::wstring(snapshot ? L"true" : L"false");
        if (snapshot)
        {
            out += L",\"started_ms\":" + std::to_wstring(snapshot->StartedMs);
            out += L",\"finished_ms\":" + std::to_wstring(snapshot->FinishedMs);
            out += L",\"observed_at\":" + mcpjson::Quote(std::to_wstring(snapshot->ObservedAt));
            out += L",\"address_limit\":" + mcpjson::Quote(std::to_wstring(snapshot->Limit));
            out += L",\"region_count\":" + std::to_wstring(snapshot->Regions.size());
            out += L",\"image_name_failures\":" + std::to_wstring(snapshot->ImageNameFailures);
            out += L",\"image_allocations\":" + std::to_wstring(snapshot->ImageAllocations.size());
            out += L",\"image_names_known\":" + std::to_wstring(snapshot->ImageNames.size());
            out += L",\"image_name_capacity_failures\":" + std::to_wstring(snapshot->ImageNameCapacityFailures);
            out += L",\"image_name_query_failures\":" + std::to_wstring(snapshot->ImageNameQueryFailures);
            out += L",\"image_name_truncated\":" + std::to_wstring(snapshot->ImageNameTruncated);
            out += L",\"image_name_unqueryable\":" + std::to_wstring(snapshot->ImageNameUnqueryable);
            out += L",\"image_name_retry_attempts\":" + std::to_wstring(snapshot->ImageNameRetryAttempts);
            out += L",\"image_name_recovered\":" + std::to_wstring(snapshot->ImageNameRecovered);
            out += L",\"image_name_diagnostics_omitted\":" + std::to_wstring(snapshot->ImageNameDiagnosticsOmitted);
            out += L",\"image_name_diagnostics\":" + ImageNameDiagnosticsJson(*snapshot);
            out += L",\"image_name_errors\":{";
            bool firstError = true;
            for (const auto& error : snapshot->ImageNameErrors)
            {
                if (!firstError) { out += L","; }
                firstError = false;
                out += mcpjson::Quote(std::to_wstring(error.first)) + L":" + std::to_wstring(error.second);
            }
            out += L"}";
            if (pid != 0)
            {
                out += L",\"regions\":[";
                bool firstRegion = true;
                for (const auto& row : snapshot->Regions)
                {
                    if (!firstRegion)
                    {
                        out += L",";
                    }
                    firstRegion = false;
                    out += RegionJson(row);
                }
                out += L"],\"image_names\":[";
                bool firstName = true;
                for (const auto& name : snapshot->ImageNames)
                {
                    if (!firstName)
                    {
                        out += L",";
                    }
                    firstName = false;
                    out += L"{\"allocation_base\":" + mcpjson::Quote(std::to_wstring(name.first)) +
                        L",\"name\":" + mcpjson::Quote(name.second) + L"}";
                }
                out += L"]";
            }
        }
        const auto& delta = entry.History.LastDelta;
        out += L",\"delta_basis\":\"previous_to_current\"";
        out += L",\"delta_before_ms\":" + std::to_wstring(delta.BeforeMs);
        out += L",\"delta_after_ms\":" + std::to_wstring(delta.AfterMs);
        out += L",\"changed_ranges\":" + std::to_wstring(delta.ChangedRanges);
        out += L",\"candidate_ranges\":" + std::to_wstring(delta.CandidateRanges);
        if (pid != 0)
        {
            out += L",\"changes\":[";
            bool firstChange = true;
            for (const auto& change : delta.Changes)
            {
                if (!firstChange)
                {
                    out += L",";
                }
                firstChange = false;
                out += L"{\"base\":" + mcpjson::Quote(std::to_wstring(change.Base)) +
                    L",\"size\":" + std::to_wstring(change.Size) + L",\"flags\":" + std::to_wstring(change.Flags) +
                    L",\"before\":" + RegionJson(change.Before) + L",\"after\":" + RegionJson(change.After) + L"}";
            }
            out += L"]";
        }
        out += L",\"delta_truncated\":" + std::wstring(delta.ChangedRanges > delta.Changes.size() ? L"true" : L"false") + L"}";
    }
    out += L"]}";
    return out;
}

std::wstring ProcessLayoutMonitor::Text(uint32_t pid, bool initial) const
{
    std::lock_guard<std::mutex> lock(Mutex);
    std::wostringstream out;
    out << L"[kmon.layouts] scope=" << (Counters.AllProcesses ? L"all_processes" : L"selected_processes")
        << L" interval_ms=" << Counters.IntervalMs << L" inventory_complete=" << Counters.InventoryComplete
        << L" over_cap=" << Counters.ProcessCap << L" view=" << (initial ? L"initial" : L"current") << L"\n";
    for (const auto& item : Entries)
    {
        if (pid != 0 && pid != item.first)
        {
            continue;
        }
        const auto& entry = item.second;
        const auto snapshot = initial ? entry.History.Initial : entry.History.Current;
        out << L"  pid=" << item.first << L" create=" << entry.Identity.CreateTime << L" " << entry.Name
            << L" status=" << entry.Status << L" error=" << entry.Error << L" cycles=" << entry.History.Completed;
        if (snapshot)
        {
            out << L" regions=" << snapshot->Regions.size() << L" age_ms="
                << GetTickCount64() - snapshot->FinishedMs << L" changes=" << entry.History.LastDelta.ChangedRanges
                << L" candidates=" << entry.History.LastDelta.CandidateRanges;
        }
        out << L"\n";
        if (pid != 0 && snapshot)
        {
            out << L"  snapshot_window_ms=" << snapshot->StartedMs << L".." << snapshot->FinishedMs << L"\n";
            size_t printed = 0;
            for (const auto& row : snapshot->Regions)
            {
                if (printed++ == 64)
                {
                    out << L"  more regions in /json or /save\n";
                    break;
                }
                out << L"    base=0x" << std::hex << row.Base << L" size=0x" << row.Size
                    << L" allocation=0x" << row.AllocationBase << L" state=0x" << row.State
                    << L" protect=0x" << row.Protect << L" type=0x" << row.Type << std::dec << L"\n";
            }
            out << L"  latest_delta_ms=" << entry.History.LastDelta.BeforeMs << L".." << entry.History.LastDelta.AfterMs << L"\n";
            printed = 0;
            for (const auto& change : entry.History.LastDelta.Changes)
            {
                if (printed++ == 16)
                {
                    out << L"  more deltas in /json or /save\n";
                    break;
                }
                out << L"    change=0x" << std::hex << change.Base << L" size=0x" << change.Size
                    << L" flags=0x" << change.Flags << std::dec << L"\n";
            }
        }
    }
    out << L"  first_observed_is_not_clean; non_atomic; deltas_are_leads; polling_gaps_possible\n";
    return out.str();
}

bool ProcessLayoutMonitorSelfTest()
{
    ProcessLayoutMonitor monitor;
    monitor.Reset();
    ProcessLayoutMonitor::Entry entry;
    entry.Pid = GetCurrentProcessId();
    entry.Name = L"previous-instance-only.exe";
    entry.Identity = ObserveProcessIdentity(entry.Pid);
    if (entry.Identity.CreateTime == 0)
    {
        return false;
    }
    --entry.Identity.CreateTime;
    ProcessLayoutScope scope;
    scope.All = false;
    scope.Names.push_back(entry.Name);
    std::atomic<bool> stop{false};
    const auto notice = [](ProcessLayoutNotice)
    {
        return true;
    };
    const auto candidate = [](ProcessLayoutCandidate)
    {
        return true;
    };
    {
        ProcessLayoutMonitor::Entry bounded;
        auto snapshot = std::make_shared<process_layout::Snapshot>();
        snapshot->Identity = ObserveProcessIdentity(entry.Pid);
        snapshot->FinishedMs = GetTickCount64();
        snapshot->ObservedAt = ObservationFileTime();
        for (size_t i = 0; i < 6; ++i)
        {
            const uint64_t base = 0x10000 + i * 0x1000;
            snapshot->Regions.push_back({base, 4096, base, MEM_COMMIT, PAGE_EXECUTE_READ, PAGE_READWRITE, MEM_PRIVATE});
        }
        bounded.History.Current = snapshot;
        bounded.History.Completed = 1;
        bounded.VerificationBudget = 8;
        bounded.VerificationRowsRemaining = snapshot->Regions.size();
        std::vector<uint64_t> admitted;
        size_t room = 0;
        const auto limited = [&](ProcessLayoutCandidate item)
        {
            if (room == 0) { return false; }
            --room;
            admitted.push_back(item.Region.Base);
            return true;
        };
        for (size_t retry = 0; retry < 100; ++retry) { monitor.PublishCandidates(bounded, limited, true); }
        if (bounded.VerificationCursor != 0x10000 || !bounded.PeriodicDeferred || !admitted.empty()) { return false; }
        for (size_t pass = 0; pass < 3; ++pass)
        {
            room = 2;
            monitor.PublishCandidates(bounded, limited, true);
        }
        if (admitted.size() != 6) { return false; }
        for (size_t i = 0; i < admitted.size(); ++i)
        {
            if (admitted[i] != snapshot->Regions[i].Base) { return false; }
        }
        room = 100;
        monitor.PublishCandidates(bounded, limited, true);
        monitor.PublishCandidates(bounded, limited, true);
        if (admitted.size() != 6 || bounded.VerificationBudget != 2 || bounded.VerificationRowsRemaining != 0) { return false; }
        for (size_t i = 6; i < 10; ++i)
        {
            const uint64_t base = 0x10000 + i * 0x1000;
            snapshot->Regions.push_back({base, 4096, base, MEM_COMMIT, PAGE_EXECUTE_READ, PAGE_READWRITE, MEM_PRIVATE});
        }
        bounded.VerificationBudget = 8;
        bounded.VerificationRowsRemaining = snapshot->Regions.size();
        bounded.VerificationEmitted.clear();
        admitted.clear();
        monitor.PublishCandidates(bounded, limited, true);
        monitor.PublishCandidates(bounded, limited, true);
        if (admitted.size() != 8 || bounded.VerificationBudget != 0) { return false; }
        bounded.VerificationBudget = 1; // A separate retained changed-range batch.
        ProcessLayoutCandidate change;
        change.Identity = snapshot->Identity;
        change.Region = snapshot->Regions[2];
        change.Region.Protect = PAGE_READWRITE;
        change.Role = L"layout_change";
        bounded.PendingChanges.push_back(change);
        const auto cursor = bounded.VerificationCursor;
        room = 0;
        monitor.Entries.emplace(entry.Pid, std::move(bounded));
        monitor.FlushCandidates(limited);
        if (monitor.Stats().VerificationChangesPending != 1 ||
            monitor.Entries.at(entry.Pid).VerificationCursor != cursor) { return false; }
        room = 1;
        monitor.FlushCandidates(limited);
        if (monitor.Stats().VerificationChangesPending != 0 || admitted.back() != change.Region.Base ||
            monitor.Entries.at(entry.Pid).VerificationCursor != cursor) { return false; }
        auto& held = monitor.Entries.at(entry.Pid);
        held.PendingNotice = ProcessLayoutNotice{};
        held.PendingNotice->Cycle = 123;
        monitor.FlushNotices([](const ProcessLayoutNotice&) { return false; });
        if (monitor.Stats().NoticesPending != 1 || held.PendingNotice->Cycle != 123) { return false; }
        size_t notices = 0;
        monitor.FlushNotices([&](const ProcessLayoutNotice& item) { if (item.Cycle == 123) { ++notices; } return true; });
        if (notices != 1 || monitor.Stats().NoticesPending != 0) { return false; }
        monitor.Reset();
        ProcessLayoutMonitor::Entry retired;
        retired.Pid = UINT32_MAX;
        retired.VerificationBudget = 1;
        retired.PendingChanges.push_back(change);
        monitor.Entries.emplace(retired.Pid, std::move(retired));
        ProcessLayoutScope emptyScope;
        emptyScope.All = false;
        monitor.Discover(emptyScope, GetTickCount64());
        if (monitor.Entries.count(UINT32_MAX) != 1 || monitor.Counters.VerificationChangesAbandoned != 0) { return false; }
        room = 1;
        monitor.FlushCandidates(limited);
        monitor.Discover(emptyScope, GetTickCount64());
        if (monitor.Entries.count(UINT32_MAX) != 0 || monitor.Counters.VerificationChangesAbandoned != 0) { return false; }
        monitor.Reset();
    }
    {
        MEMORY_BASIC_INFORMATION mapping{};
        const auto base = reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
        if (VirtualQuery(reinterpret_cast<void*>(base), &mapping, sizeof(mapping)) != sizeof(mapping)) { return false; }
        const auto row = Convert(mapping);
        process_layout::Snapshot capped;
        size_t slots = 0, characters = 10000;
        for (size_t i = 0; i < 100; ++i) { monitor.CollectImageName(capped, row, GetCurrentProcess(), slots, characters); }
        if (capped.ImageNameFailures != 1 || capped.ImageNameCapacityFailures != 1 || capped.ImageNameAttempts.size() != 1) { return false; }
        process_layout::Snapshot reserved;
        auto reserve = row;
        reserve.State = process_layout::Reserve;
        slots = 10;
        monitor.CollectImageName(reserved, reserve, GetCurrentProcess(), slots, characters);
        if (reserved.ImageAllocations.size() != 1 || !reserved.ImageNameAttempts.empty() || reserved.ImageNameFailures != 0) { return false; }
        monitor.CollectImageName(reserved, row, GetCurrentProcess(), slots, characters);
        if (reserved.ImageNames.size() != 1 || reserved.ImageNameFailures != 0 || slots != 9 || reserved.ImageNameCharacters == 0) { return false; }
        process_layout::Snapshot characterCap;
        characters = 1;
        monitor.CollectImageName(characterCap, row, GetCurrentProcess(), slots, characters);
        if (characterCap.ImageNameCapacityFailures != 1 || !characterCap.ImageNames.empty() || slots != 9 || characters != 1) { return false; }
        process_layout::Snapshot unavailable;
        characters = 10000;
        monitor.CollectImageName(unavailable, row, nullptr, slots, characters);
        if (unavailable.ImageNameQueryFailures != 1 || unavailable.ImageNameErrors.empty() || !unavailable.ImageNames.empty()) { return false; }
        std::wstring longName(1500, L'x'), readName;
        DWORD error = 0;
        size_t queries = 0;
        if (!ReadImageNameQuery([&](wchar_t* output, DWORD capacity)
            {
                ++queries;
                if (capacity <= longName.size()) { return capacity; }
                std::copy(longName.begin(), longName.end(), output);
                return static_cast<DWORD>(longName.size());
            }, readName, error) || queries != 2 || readName != longName || error != 0) { return false; }
        if (ReadImageNameQuery([](wchar_t*, DWORD capacity) { return capacity; }, readName, error) ||
            !readName.empty() || error != ERROR_INSUFFICIENT_BUFFER) { return false; }
        // Reproduce error 59 deterministically at the API boundary. Recovery
        // needs the same mapping on both sides; persistent errors and races
        // must remain gaps. This does not pretend to reproduce the OS cause.
        for (size_t scenario = 0; scenario < 6; ++scenario)
        {
            process_layout::ImageNameDiagnostic diagnostic;
            diagnostic.InitialError = scenario == 5 ? ERROR_ACCESS_DENIED : ERROR_UNEXP_NET_ERR;
            size_t mappingQueries = 0, nameQueries = 0;
            std::wstring recovered = L"stale";
            const bool success = RetryImageName(row, [&](MEMORY_BASIC_INFORMATION* current)
            {
                ++mappingQueries;
                *current = mapping;
                if (scenario == 1 || (scenario == 2 && mappingQueries == 2)) { current->State = MEM_FREE; }
                if (scenario == 4) { current->AllocationBase = reinterpret_cast<void*>(base + 4096); }
                return true;
            }, [&](std::wstring& value, DWORD& code)
            {
                ++nameQueries;
                if (scenario == 3) { code = ERROR_UNEXP_NET_ERR; return false; }
                value = L"fresh-name"; code = 0; return true;
            }, recovered, diagnostic);
            if (success != (scenario == 0) || diagnostic.Recovered != success ||
                recovered != (success ? L"fresh-name" : L"") || nameQueries > 1) { return false; }
            if (scenario == 0 && (mappingQueries != 2 || nameQueries != 1)) { return false; }
            if ((scenario == 1 || scenario == 4 || scenario == 5) && diagnostic.Retried) { return false; }
            if (scenario == 2 && (!diagnostic.Retried || mappingQueries != 2)) { return false; }
            if (scenario == 3 && diagnostic.RetryError != ERROR_UNEXP_NET_ERR) { return false; }
            if (scenario == 5 && mappingQueries != 0) { return false; }
        }
        process_layout::Snapshot boundedDiagnostics;
        for (size_t i = 0; i < 40; ++i)
        {
            auto unique = row;
            unique.AllocationBase = i * 4096;
            monitor.CollectImageName(boundedDiagnostics, unique, nullptr, slots, characters);
        }
        if (boundedDiagnostics.ImageNameQueryFailures != 40 || boundedDiagnostics.ImageNameDiagnostics.size() != 32 ||
            boundedDiagnostics.ImageNameDiagnosticsOmitted != 8 || boundedDiagnostics.ImageNameRetryAttempts != 0 ||
            boundedDiagnostics.ImageNameRecovered != 0) { return false; }
    }
    monitor.Advance(entry, scope, stop, notice, candidate);
    const bool rejected = entry.Status == L"process_outside_scope" && !entry.Pending && !entry.History.Current;
    scope.Pids.insert(entry.Pid);
    monitor.Advance(entry, scope, stop, notice, candidate);
    return rejected && entry.Status != L"process_outside_scope";
}
