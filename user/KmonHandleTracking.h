#pragma once

#include "NativeHandleSnapshot.h"

#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <utility>

using KmonMemoryReader = std::function<bool(uint64_t, size_t, void*)>;

struct KmonChannelLayout
{
    uint32_t FileType = 0;
    uint32_t FileDevice = 0;
    uint32_t DeviceTypeTag = 0;
    uint32_t DeviceDriver = 0;
    uint32_t DeviceAttached = 0;
    uint32_t DeviceType = 0;
    uint32_t DriverType = 0;
    uint32_t DriverStart = 0;
    bool Valid = false;
};

struct KmonDeviceLink
{
    uint64_t Device = 0;
    uint64_t Driver = 0;
    uint64_t Image = 0;
    uint32_t DeviceType = 0;
};

struct KmonChannel
{
    uint64_t FileObject = 0;
    std::vector<KmonDeviceLink> Stack;
    std::wstring Class = L"unknown";
    std::wstring Status = L"layout_unavailable";
    bool Complete = false;
};

inline bool KmonKernelObjectAddress(uint64_t address)
{
    return address >= 0xFFFF800000000000ull && (address & 7) == 0;
}

inline KmonChannel ResolveKmonChannel(
    uint64_t fileObject,
    const KmonChannelLayout& layout,
    const KmonMemoryReader& read)
{
    KmonChannel result;
    result.FileObject = fileObject;
    do
    {
        if (!layout.Valid || !read)
        {
            break;
        }
        const auto field = [&read](uint64_t base, uint32_t offset, void* value, size_t size)
        {
            return KmonKernelObjectAddress(base) && offset <= 0x10000 &&
                base <= UINT64_MAX - offset - size && read(base + offset, size, value);
        };
        uint16_t tag = 0;
        uint64_t device = 0;
        result.Status = L"file_unreadable_or_reused";
        if (!field(fileObject, layout.FileType, &tag, sizeof(tag)) || tag != 5 ||
            !field(fileObject, layout.FileDevice, &device, sizeof(device)))
        {
            break;
        }
        std::set<uint64_t> seen;
        result.Status = L"device_stack_incomplete";
        while (device != 0 && result.Stack.size() < 16)
        {
            if (!seen.insert(device).second)
            {
                result.Status = L"device_stack_cycle";
                break;
            }
            KmonDeviceLink link;
            link.Device = device;
            uint64_t attached = 0;
            if (!field(device, layout.DeviceTypeTag, &tag, sizeof(tag)) || tag != 3 ||
                !field(device, layout.DeviceDriver, &link.Driver, sizeof(link.Driver)) ||
                !field(device, layout.DeviceType, &link.DeviceType, sizeof(link.DeviceType)) ||
                !field(device, layout.DeviceAttached, &attached, sizeof(attached)))
            {
                break;
            }
            if (!field(link.Driver, layout.DriverType, &tag, sizeof(tag)) || tag != 4 ||
                !field(link.Driver, layout.DriverStart, &link.Image, sizeof(link.Image)))
            {
                result.Stack.push_back(link);
                break;
            }
            result.Stack.push_back(link);
            device = attached;
        }
        if (!result.Stack.empty())
        {
            const uint32_t type = result.Stack.front().DeviceType;
            switch (type)
            {
            case 0x03: // CD_ROM_FILE_SYSTEM
            case 0x08: // DISK_FILE_SYSTEM
            case 0x14: // NETWORK_FILE_SYSTEM
            case 0x20: // TAPE_FILE_SYSTEM
            case 0x28: // FILE_SYSTEM
            case 0x35: // DFS_FILE_SYSTEM
                result.Class = L"filesystem";
                break;
            case 0x02: // CD_ROM
            case 0x07: // DISK
            case 0x1F: // TAPE
            case 0x2D: // MASS_STORAGE
                result.Class = L"storage";
                break;
            case 0:
                break;
            default:
                result.Class = L"device_channel";
                break;
            }
        }
        if (device == 0 && !result.Stack.empty())
        {
            result.Complete = true;
            result.Status = L"observed";
        }
        // Revalidate the root association after walking a live, mutable stack.
        uint64_t checkDevice = 0;
        if (!field(fileObject, layout.FileType, &tag, sizeof(tag)) || tag != 5 ||
            !field(fileObject, layout.FileDevice, &checkDevice, sizeof(checkDevice)) ||
            result.Stack.empty() || checkDevice != result.Stack.front().Device)
        {
            result.Complete = false;
            result.Class = L"unknown";
            result.Status = L"file_association_changed";
        }
    } while (false);
    return result;
}

// Upper-bound rotation remains fair when watched PIDs are inserted or removed.
inline std::vector<uint32_t> KmonNextPids(
    std::vector<uint32_t> pids, size_t budget, uint32_t* lastPid)
{
    std::vector<uint32_t> selected;
    if (lastPid != nullptr && !pids.empty())
    {
        std::sort(pids.begin(), pids.end());
        pids.erase(std::unique(pids.begin(), pids.end()), pids.end());
        auto it = std::upper_bound(pids.begin(), pids.end(), *lastPid);
        for (size_t n = 0; n < (std::min)(budget, pids.size()); ++n)
        {
            if (it == pids.end())
            {
                it = pids.begin();
            }
            selected.push_back(*it++);
        }
        if (!selected.empty())
        {
            *lastPid = selected.back();
        }
    }
    return selected;
}

using KmonHandleKey = std::pair<uint64_t, uint64_t>;

inline void KmonRequestUserLayoutLead(uint32_t pid, uint64_t created, uint64_t now, bool watched,
    const std::map<std::pair<uint32_t, uint64_t>, uint64_t>& lastScan,
    std::map<std::pair<uint32_t, uint64_t>, uint64_t>* leads, bool changed = false)
{
    if (!watched || pid <= 4 || created == 0 || leads == nullptr) { return; }
    const auto key = std::make_pair(pid, created);
    const auto last = lastScan.find(key);
    // Periodic rediscovery must not make unchanged JIT/private mappings take
    // urgent slots forever. New processes and actual layout changes qualify.
    // Retain changes during cooldown; selection waits until they are due.
    if (last != lastScan.end() && !changed) { return; }
    if (leads->count(key) != 0 || leads->size() < 4096) { leads->emplace(key, now); }
}

inline bool KmonUserLayoutLeadReady(uint32_t pid, uint64_t created, uint64_t now,
    const std::map<std::pair<uint32_t, uint64_t>, uint64_t>& lastScan)
{
    const auto last = lastScan.find({pid, created});
    return last == lastScan.end() || (now >= last->second && now - last->second >= 30000);
}

inline std::vector<uint32_t> KmonSelectUserPids(
    const std::vector<uint32_t>& watched,
    const std::vector<uint32_t>& priority,
    const std::vector<uint32_t>& background,
    uint32_t* watchedCursor,
    uint32_t* priorityCursor,
    uint32_t* backgroundCursor,
    const std::vector<uint32_t>& urgent = {},
    uint32_t* urgentCursor = nullptr)
{
    // Layout leads use at most half the watched quota. The remaining watches
    // and both other tiers keep independent rotation within eight targets.
    std::vector<uint32_t> eligible;
    for (const auto pid : urgent)
    {
        if (std::find(watched.begin(), watched.end(), pid) != watched.end()) { eligible.push_back(pid); }
    }
    std::vector<uint32_t> selected = KmonNextPids(eligible, 2, urgentCursor);
    std::vector<uint32_t> ordinary;
    for (const auto pid : watched)
    {
        if (std::find(selected.begin(), selected.end(), pid) == selected.end()) { ordinary.push_back(pid); }
    }
    const auto watches = KmonNextPids(ordinary, 4 - selected.size(), watchedCursor);
    selected.insert(selected.end(), watches.begin(), watches.end());
    const auto otherPriority = KmonNextPids(priority, 6 - selected.size(), priorityCursor);
    const auto otherBackground = KmonNextPids(background, 2, backgroundCursor);
    selected.insert(selected.end(), otherPriority.begin(), otherPriority.end());
    selected.insert(selected.end(), otherBackground.begin(), otherBackground.end());
    // Preserve the previous per-tier workload even when a tier is empty.
    // Extra deep scans lengthen the pass and delay background image sweeps.
    return selected;
}

struct KmonHandleChange
{
    NativeHandleEntry Entry = {};
    std::wstring State;
    uint64_t Generation = 0;
};

struct KmonHandleHistory
{
    uint64_t CreateTime = 0;
    uint64_t Generation = 0;
    uint64_t LastCompleteMs = 0;
    bool Initialized = false;
    std::map<KmonHandleKey, NativeHandleEntry> Previous;
    std::set<KmonHandleKey> Retired;
    std::vector<KmonHandleChange> Pending;
    size_t Cursor = 0;

    void Update(uint64_t created, const std::vector<NativeHandleEntry>& entries, bool complete)
    {
        if (created == 0 || !complete)
        {
            return;
        }
        if (CreateTime != created)
        {
            *this = {};
            CreateTime = created;
        }
        ++Generation;
        Pending.clear();
        Cursor = 0;
        std::map<KmonHandleKey, NativeHandleEntry> current;
        for (const auto& entry : entries)
        {
            const KmonHandleKey key(entry.HandleValue, reinterpret_cast<uint64_t>(entry.Object));
            current.emplace(key, entry);
            if (Previous.find(key) == Previous.end())
            {
                KmonHandleChange change;
                change.Entry = entry;
                change.Generation = Generation;
                change.State = !Initialized ? L"present_at_attach" :
                    (Retired.count(key) != 0 ? L"reappeared" : L"opened");
                Pending.push_back(std::move(change));
                Retired.erase(key);
            }
        }
        for (const auto& previous : Previous)
        {
            if (current.count(previous.first) == 0)
            {
                KmonHandleChange change;
                change.Entry = previous.second;
                change.Generation = Generation;
                change.State = L"closed";
                Pending.push_back(std::move(change));
                Retired.insert(previous.first);
            }
        }
        while (Retired.size() > 16384)
        {
            Retired.erase(Retired.begin());
        }
        Previous = std::move(current);
        Initialized = true;
    }
};

inline bool KmonHandleTrackingSelfTest()
{
    bool ok = NativeHandleSnapshotSelfTest();
    std::map<std::pair<uint32_t, uint64_t>, uint64_t> scanTimes{{{10, 1}, 10000}}, leads;
    KmonRequestUserLayoutLead(10, 1, 39999, true, scanTimes, &leads);
    KmonRequestUserLayoutLead(10, 0, 40000, true, scanTimes, &leads);
    KmonRequestUserLayoutLead(11, 1, 40000, false, scanTimes, &leads);
    ok = ok && leads.empty();
    KmonRequestUserLayoutLead(10, 1, 10001, true, scanTimes, &leads, true);
    KmonRequestUserLayoutLead(10, 1, 50000, true, scanTimes, &leads, true);
    KmonRequestUserLayoutLead(10, 2, 10001, true, scanTimes, &leads);
    ok = ok && leads.size() == 2 && leads.at({10, 1}) == 10001 && leads.at({10, 2}) == 10001 &&
        !KmonUserLayoutLeadReady(10, 1, 39999, scanTimes) && KmonUserLayoutLeadReady(10, 1, 40000, scanTimes) &&
        KmonUserLayoutLeadReady(10, 2, 10001, scanTimes);
    leads.clear();
    KmonRequestUserLayoutLead(10, 1, 100000, true, scanTimes, &leads);
    ok = ok && leads.empty();
    uint32_t last = 0;
    std::vector<uint32_t> pids;
    std::set<uint32_t> visited;
    for (uint32_t pid = 10; pid < 35; ++pid)
    {
        pids.push_back(pid);
    }
    for (size_t i = 0; i < 4; ++i)
    {
        for (uint32_t pid : KmonNextPids(pids, 8, &last))
        {
            visited.insert(pid);
        }
    }
    ok = ok && visited.size() == pids.size();
    uint32_t watchedCursor = 0, priorityCursor = 0, backgroundCursor = 0;
    std::set<uint32_t> scheduled;
    for (size_t sweep = 0; sweep < 8; ++sweep)
    {
        const auto selected = KmonSelectUserPids({1000}, pids, {2000, 2001, 2002},
            &watchedCursor, &priorityCursor, &backgroundCursor);
        ok = ok && selected.size() == 8 && selected.front() == 1000 &&
            std::set<uint32_t>(selected.begin(), selected.end()).size() == selected.size();
        scheduled.insert(selected.begin(), selected.end());
    }
    ok = ok && scheduled.size() == pids.size() + 4;
    // A sustained lead flood cannot consume the ordinary watched/priority/
    // background rotations. Empty priority slots do not add deep scans.
    uint32_t urgentCursor = 0;
    watchedCursor = priorityCursor = backgroundCursor = 0;
    scheduled.clear();
    std::set<uint32_t> urgentVisited;
    for (size_t sweep = 0; sweep < 20; ++sweep)
    {
        const auto selected = KmonSelectUserPids(pids, {1000, 1001}, {2000, 2001},
            &watchedCursor, &priorityCursor, &backgroundCursor, {30, 31, 32, 33, 34, 9999}, &urgentCursor);
        ok = ok && selected.size() == 8 && selected[0] >= 30 && selected[0] <= 34 &&
            selected[1] >= 30 && selected[1] <= 34 &&
            std::set<uint32_t>(selected.begin(), selected.end()).size() == 8 &&
            std::find(selected.begin(), selected.end(), 9999u) == selected.end();
        urgentVisited.insert(selected[0]); urgentVisited.insert(selected[1]);
        scheduled.insert(selected.begin(), selected.end());
    }
    ok = ok && scheduled.size() == pids.size() + 4 && urgentVisited.size() == 5;
    watchedCursor = priorityCursor = backgroundCursor = urgentCursor = 0;
    scheduled.clear();
    for (size_t sweep = 0; sweep < 7; ++sweep)
    {
        const auto selected = KmonSelectUserPids(pids, {}, {2000, 2001},
            &watchedCursor, &priorityCursor, &backgroundCursor, {}, &urgentCursor);
        ok = ok && selected.size() == 6 && std::set<uint32_t>(selected.begin(), selected.end()).size() == 6;
        scheduled.insert(selected.begin(), selected.end());
    }
    ok = ok && scheduled.size() == pids.size() + 2;
    scheduled.clear();
    for (size_t sweep = 0; sweep < 8; ++sweep)
    {
        const auto selected = KmonSelectUserPids(pids, {1000, 1001}, {2000, 2001},
            &watchedCursor, &priorityCursor, &backgroundCursor);
        ok = ok && selected.size() == 8 && selected.front() < 35;
        scheduled.insert(selected.begin(), selected.end());
    }
    ok = ok && scheduled.size() == pids.size() + 4;
    NativeHandleEntry entry = {};
    entry.HandleValue = 0x100000004ull;
    entry.Object = reinterpret_cast<void*>(0xFFFF900000001000ull);
    KmonHandleHistory history;
    history.Update(1, {entry}, true);
    ok = ok && history.Pending.size() == 1 && history.Pending[0].State == L"present_at_attach";
    history.Update(1, {}, false);
    ok = ok && history.Previous.size() == 1;
    history.Update(1, {}, true);
    ok = ok && history.Pending.size() == 1 && history.Pending[0].State == L"closed";
    history.Update(1, {entry}, true);
    ok = ok && history.Pending.size() == 1 && history.Pending[0].State == L"reappeared";
    history.Update(2, {entry}, true);
    ok = ok && history.Pending.size() == 1 && history.Pending[0].State == L"present_at_attach";

    const uint64_t file = 0xFFFF900000001000ull;
    const uint64_t device = file + 0x1000;
    const uint64_t driver = device + 0x1000;
    std::map<uint64_t, uint64_t> memory =
    {
        {file, 5}, {file + 8, device}, {device, 3}, {device + 8, driver},
        {device + 16, 0}, {device + 24, 8}, {driver, 4}, {driver + 8, driver + 0x1000}
    };
    const KmonMemoryReader read = [&memory](uint64_t address, size_t size, void* out)
    {
        const auto it = memory.find(address);
        if (it == memory.end() || size > sizeof(it->second))
        {
            return false;
        }
        std::memcpy(out, &it->second, size);
        return true;
    };
    KmonChannelLayout layout;
    layout.FileDevice = 8;
    layout.DeviceDriver = 8;
    layout.DeviceAttached = 16;
    layout.DeviceType = 24;
    layout.DriverStart = 8;
    layout.Valid = true;
    auto channel = ResolveKmonChannel(file, layout, read);
    ok = ok && channel.Complete && channel.Class == L"filesystem" && channel.Stack[0].Driver == driver;
    memory[device + 24] = 0x22;
    channel = ResolveKmonChannel(file, layout, read);
    ok = ok && channel.Complete && channel.Class == L"device_channel";
    memory[device + 16] = device;
    channel = ResolveKmonChannel(file, layout, read);
    ok = ok && !channel.Complete && channel.Status == L"device_stack_cycle";
    memory.erase(file + 8);
    channel = ResolveKmonChannel(file, layout, read);
    ok = ok && !channel.Complete && channel.Class == L"unknown";
    return ok;
}
