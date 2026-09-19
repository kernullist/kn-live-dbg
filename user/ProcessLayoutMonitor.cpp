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
    constexpr size_t MaxStoredRows = 262144;
    constexpr size_t MaxStoredNames = 8192;
    constexpr uint64_t MaxSweepMs = 30000;

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
        notice(std::move(event));
    }
    entry.Status = reason;
    entry.Error = error;
}

void ProcessLayoutMonitor::Advance(Entry& entry, const std::atomic<bool>& stop,
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
        if (row.State != Free && row.Type == Image && sweep.ImageNames.count(row.AllocationBase) == 0)
        {
            if (remainingNames == 0 || sweep.ImageNames.size() >= 512)
            {
                ++sweep.ImageNameFailures;
            }
            else
            {
                wchar_t path[1024]{};
                const DWORD length = GetMappedFileNameW(process.Value, reinterpret_cast<void*>(row.Base), path, 1024);
                const bool known = length != 0 && length < 1024;
                sweep.ImageNames.emplace(row.AllocationBase, known ? std::wstring(path, length) : L"");
                --remainingNames;
                if (!known)
                {
                    ++sweep.ImageNameFailures;
                }
            }
        }
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
    sweep.FinishedMs = GetTickCount64();
    sweep.ObservedAt = ObservationFileTime();
    if (!entry.History.Accept(entry.Pending))
    {
        Fail(entry, L"snapshot_rejected", 0, notice);
        return;
    }
    const auto snapshot = entry.Pending;
    entry.Pending.reset();
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
    event.ChangedRanges = delta.ChangedRanges;
    event.CandidateRanges = delta.CandidateRanges;
    event.Changes = delta.Changes;
    notice(std::move(event));

    // Changes go first, then rotate unchanged executable regions every cycle.
    // Disk/code sweeps remain necessary when bytes change without a layout delta.
    size_t budget = 4;
    std::set<uint64_t> emitted;
    const auto emit = [&](const Region& row, const wchar_t* role)
    {
        if (!row.Executable() || budget == 0 || !emitted.insert(row.Base).second)
        {
            return;
        }
        ProcessLayoutCandidate work;
        work.Identity = identity;
        work.Region = row;
        work.ObservedMs = snapshot->FinishedMs;
        work.ObservedAt = snapshot->ObservedAt;
        work.Role = role;
        const auto path = snapshot->ImageNames.find(row.AllocationBase);
        if (path != snapshot->ImageNames.end())
        {
            work.ImageName = path->second;
        }
        candidate(std::move(work));
        --budget;
    };
    for (const auto& change : delta.Changes)
    {
        if (change.Candidate())
        {
            emit(change.After, L"layout_change");
        }
    }
    budget += 4;
    const auto& regions = snapshot->Regions;
    auto position = std::lower_bound(regions.begin(), regions.end(), entry.VerificationCursor,
        [](const Region& row, uint64_t address)
        {
            return row.Base < address;
        });
    size_t index = position == regions.end() ? 0 : static_cast<size_t>(position - regions.begin());
    for (size_t visited = 0; visited < regions.size() && budget != 0; ++visited)
    {
        emit(regions[index], entry.History.Completed == 1 ? L"layout_initial" : L"layout_periodic");
        index = (index + 1) % regions.size();
    }
    entry.VerificationCursor = regions.empty() ? 0 : regions[index].Base;
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
        if (GetTickCount64() >= entry.NextScanMs)
        {
            Advance(entry, stop, notice, candidate);
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
    const auto now = GetTickCount64();
    for (const auto& item : Entries)
    {
        const auto& entry = item.second;
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
