#include "KmonTemporalEvidence.h"
#include "ProcessTriageScanner.h"

#include <algorithm>
#include <vector>

namespace
{
    std::wstring Lower(std::wstring value)
    {
        for (wchar_t& ch : value)
        {
            if (ch >= L'A' && ch <= L'Z')
            {
                ch += L'a' - L'A';
            }
        }
        return value;
    }

    bool ParseUnsigned(const std::wstring& text, uint64_t* output)
    {
        size_t index = 0;
        uint64_t value = 0;
        const uint32_t radix = text.size() >= 2 && text[0] == L'0' && (text[1] == L'x' || text[1] == L'X') ? 16 : 10;
        if (radix == 16)
        {
            index = 2;
        }
        if (index == text.size())
        {
            return false;
        }
        for (; index < text.size(); ++index)
        {
            const wchar_t ch = text[index];
            const uint32_t digit = ch >= L'0' && ch <= L'9' ? ch - L'0' :
                ch >= L'a' && ch <= L'f' ? ch - L'a' + 10 : ch >= L'A' && ch <= L'F' ? ch - L'A' + 10 : 16;
            if (digit >= radix || value > (UINT64_MAX - digit) / radix)
            {
                return false;
            }
            value = value * radix + digit;
        }
        *output = value;
        return true;
    }

    template<typename RegionMap>
    bool TrimOldestRegions(RegionMap* regions, size_t capacity, uint64_t* comparisons = nullptr)
    {
        if (regions->size() <= capacity)
        {
            return false;
        }
        std::vector<typename RegionMap::iterator> ordered;
        ordered.reserve(regions->size());
        for (auto it = regions->begin(); it != regions->end(); ++it)
        {
            ordered.push_back(it);
        }
        std::sort(ordered.begin(), ordered.end(), [&](const auto& a, const auto& b)
        {
            if (comparisons != nullptr)
            {
                ++*comparisons;
            }
            const uint64_t first = a->second.Observation.ReceiveTickMs;
            const uint64_t second = b->second.Observation.ReceiveTickMs;
            return first < second || (first == second && a->first < b->first);
        });
        const size_t excess = regions->size() - capacity;
        for (size_t index = 0; index < excess; ++index)
        {
            regions->erase(ordered[index]);
        }
        return true;
    }
}

bool KmonDecodeRegionEvent(const TiEventRecord& event, KmonRegionObservation* observation)
{
    if (observation == nullptr)
    {
        return false;
    }
    *observation = {};
    const std::wstring task = Lower(event.TaskName);
    if (task.find(L"unmapview") != std::wstring::npos || task.find(L"freevm") != std::wstring::npos)
    {
        observation->Action = KmonRegionAction::Release;
    }
    else if (task.find(L"protectvm") != std::wstring::npos)
    {
        observation->Action = KmonRegionAction::Protect;
    }
    else if (task.find(L"allocvm") != std::wstring::npos || task.find(L"mapview") != std::wstring::npos)
    {
        observation->Action = KmonRegionAction::Allocate;
    }
    else
    {
        return false;
    }
    uint64_t status = 0;
    uint64_t protection = 0;
    bool haveBase = false, haveSize = false, haveStatus = false, haveProtection = false;
    bool malformed = false;
    for (const TiPayloadField& field : event.Payload)
    {
        const std::wstring name = Lower(field.Name);
        uint64_t* destination = nullptr;
        bool* present = nullptr;
        if (name == L"baseaddress" || name == L"targetbaseaddress" || name == L"allocationbase")
        {
            destination = &observation->Base;
            present = &haveBase;
        }
        else if (name == L"regionsize" || name == L"viewsize" || name == L"size")
        {
            destination = &observation->Size;
            present = &haveSize;
        }
        else if (name == L"protectionmask" || name == L"newprotection" || name == L"newprotect" || name == L"protection")
        {
            destination = &protection;
            present = &haveProtection;
        }
        else if (name == L"status" || name == L"ntstatus")
        {
            destination = &status;
            present = &haveStatus;
        }
        if (destination != nullptr)
        {
            uint64_t parsed = 0;
            if (!ParseUnsigned(field.Value, &parsed) || (*present && *destination != parsed))
            {
                malformed = true;
            }
            else
            {
                *destination = parsed;
                *present = true;
            }
        }
    }
    if (malformed || (haveStatus && (status > UINT32_MAX || (status & 0x80000000u) != 0)) ||
        (haveProtection && protection > UINT32_MAX))
    {
        return false;
    }
    observation->ProcessId = event.TargetProcessId != 0 ? event.TargetProcessId : event.ProcessId;
    observation->Timestamp = event.Timestamp;
    observation->ProtectionKnown = haveStatus && haveProtection;
    observation->Protection = haveProtection ? static_cast<uint32_t>(protection) : 0;
    const uint32_t base = observation->Protection & 0xFFu;
    observation->Executable = base == PAGE_EXECUTE || base == PAGE_EXECUTE_READ ||
        base == PAGE_EXECUTE_READWRITE || base == PAGE_EXECUTE_WRITECOPY;
    return haveBase && observation->Base != 0 &&
        ((haveSize && observation->Size != 0) || observation->Action == KmonRegionAction::Release);
}

bool BuildKmonRegionSnapshot(uint32_t processId, uint64_t createTime,
    const ProcessVadProtectionRange& range, uint64_t receiveTickMs, KmonRegionObservation* observation)
{
    bool ok = false;
    if (observation != nullptr)
    {
        *observation = {};
        if (range.Committed && range.EndAddress >= range.StartAddress && range.EndAddress != UINT64_MAX)
        {
            observation->ProcessId = processId;
            observation->CreateTime = createTime;
            observation->Base = range.StartAddress;
            observation->Size = range.EndAddress - range.StartAddress + 1;
            observation->Timestamp = range.CollectionEndTimestamp;
            observation->CollectionStartTimestamp = range.CollectionStartTimestamp;
            observation->CollectionEndTimestamp = range.CollectionEndTimestamp;
            observation->ReceiveTickMs = receiveTickMs;
            observation->Protection = range.Protection;
            observation->ProtectionKnown = true;
            observation->Executable = range.Executable;
            observation->Action = KmonRegionAction::Snapshot;
            ok = true;
        }
    }
    return ok;
}

void KmonRegionHistory::ApplyLifetimeBoundary(const KmonRegionObservation& observation)
{
    const uint64_t end = observation.Base + observation.Size;
    auto first = Regions.lower_bound(Key(observation.ProcessId, observation.CreateTime, true, observation.Base));
    if (first != Regions.begin())
    {
        const auto prior = std::prev(first);
        if (std::get<0>(prior->first) == observation.ProcessId &&
            std::get<1>(prior->first) == observation.CreateTime && std::get<2>(prior->first) &&
            prior->second.Observation.Base + prior->second.Observation.Size > observation.Base)
        {
            first = prior;
        }
    }
    std::vector<StoredRegion> replacements;
    const auto appendBoundary = [&](uint64_t base, uint64_t rangeEnd)
    {
        StoredRegion record;
        record.Observation = observation;
        record.Observation.Base = base;
        record.Observation.Size = rangeEnd - base;
        record.Observation.Action = KmonRegionAction::Release;
        record.Observation.ProtectionKnown = false;
        record.Observation.Executable = false;
        record.Observation.CollectionStartTimestamp = observation.Timestamp;
        record.Observation.CollectionEndTimestamp = observation.Timestamp;
        record.LifetimeBoundaryTimestamp = observation.Timestamp;
        replacements.push_back(record);
    };
    uint64_t coveredUntil = observation.Base;
    auto last = first;
    for (; last != Regions.end() && std::get<0>(last->first) == observation.ProcessId &&
        std::get<1>(last->first) == observation.CreateTime && std::get<2>(last->first) &&
        last->second.Observation.Base < end; ++last)
    {
        const StoredRegion& previous = last->second;
        const uint64_t previousEnd = previous.Observation.Base + previous.Observation.Size;
        const uint64_t overlapBase = (std::max)(observation.Base, previous.Observation.Base);
        const uint64_t overlapEnd = (std::min)(end, previousEnd);
        if (previous.Observation.Base < observation.Base)
        {
            StoredRegion left = previous;
            left.Observation.Size = observation.Base - previous.Observation.Base;
            replacements.push_back(left);
        }
        if (coveredUntil < overlapBase)
        {
            appendBoundary(coveredUntil, overlapBase);
        }
        StoredRegion overlap = previous;
        overlap.Observation.Base = overlapBase;
        overlap.Observation.Size = overlapEnd - overlapBase;
        overlap.LifetimeBoundaryTimestamp = (std::max)(previous.LifetimeBoundaryTimestamp, observation.Timestamp);
        overlap.Observation.ReceiveTickMs = (std::max)(previous.Observation.ReceiveTickMs, observation.ReceiveTickMs);
        if (overlap.Observation.CollectionStartTimestamp <= overlap.LifetimeBoundaryTimestamp)
        {
            overlap.Observation.Action = KmonRegionAction::Release;
            overlap.Observation.ProtectionKnown = false;
            overlap.Observation.Executable = false;
            overlap.Observation.Timestamp = overlap.LifetimeBoundaryTimestamp;
            overlap.Observation.CollectionStartTimestamp = overlap.LifetimeBoundaryTimestamp;
            overlap.Observation.CollectionEndTimestamp = overlap.LifetimeBoundaryTimestamp;
        }
        replacements.push_back(overlap);
        coveredUntil = overlapEnd;
        if (previousEnd > end)
        {
            StoredRegion right = previous;
            right.Observation.Base = end;
            right.Observation.Size = previousEnd - end;
            replacements.push_back(right);
        }
    }
    if (coveredUntil < end)
    {
        appendBoundary(coveredUntil, end);
    }
    Regions.erase(first, last);
    for (const auto& replacement : replacements)
    {
        Regions[Key(observation.ProcessId, observation.CreateTime, true, replacement.Observation.Base)] = replacement;
    }
}

bool KmonRegionHistory::TrimCapacity()
{
    return TrimOldestRegions(&Regions, 8192);
}

KmonRegionTransition KmonRegionHistory::Observe(const KmonRegionObservation& observation)
{
    KmonRegionTransition result;
    const bool snapshot = observation.Action == KmonRegionAction::Snapshot;
    if (observation.ProcessId <= 4 || observation.CreateTime == 0 || observation.Base < 0x10000 ||
        observation.Base >= 0x0000800000000000ull ||
        (observation.Size == 0 && observation.Action != KmonRegionAction::Release) ||
        observation.Size > 0x0000800000000000ull - observation.Base)
    {
        return result;
    }
    if (snapshot && (observation.CollectionStartTimestamp < observation.CreateTime ||
            observation.CollectionEndTimestamp < observation.CollectionStartTimestamp ||
            observation.Timestamp != observation.CollectionEndTimestamp))
    {
        result.ObservationTimeUnknown = true;
        return result;
    }
    if (observation.Timestamp < observation.CreateTime)
    {
        return result;
    }
    const auto lastGeneration = Generations.find(observation.ProcessId);
    if (lastGeneration != Generations.end() && lastGeneration->second > observation.CreateTime)
    {
        result.OutOfOrder = true;
        return result;
    }
    if (lastGeneration != Generations.end() && lastGeneration->second != observation.CreateTime)
    {
        auto it = Regions.lower_bound(Key(observation.ProcessId, 0, false, 0));
        while (it != Regions.end() && std::get<0>(it->first) == observation.ProcessId)
        {
            it = Regions.erase(it);
        }
    }
    Generations[observation.ProcessId] = observation.CreateTime;
    if (observation.ReceiveTickMs - LastPruneTickMs >= 1000 || Generations.size() > 8192)
    {
        LastPruneTickMs = observation.ReceiveTickMs;
        Generations.clear();
        for (auto it = Regions.begin(); it != Regions.end();)
        {
            const bool expired = observation.ReceiveTickMs >= it->second.Observation.ReceiveTickMs &&
                observation.ReceiveTickMs - it->second.Observation.ReceiveTickMs > 120000;
            if (expired)
            {
                it = Regions.erase(it);
            }
            else
            {
                Generations[std::get<0>(it->first)] = std::get<1>(it->first);
                ++it;
            }
        }
        Generations[observation.ProcessId] = observation.CreateTime;
    }
    KmonRegionObservation current = observation;
    if (current.Size == 0)
    {
        // An unknown release extent breaks continuity across the process.
        current.Base = 0x10000;
        current.Size = 0x0000800000000000ull - current.Base;
        result.RangeUnknown = true;
    }
    if (current.Action == KmonRegionAction::Allocate || current.Action == KmonRegionAction::Release)
    {
        // Record lifetime boundaries even if a newer Protect event was already
        // received. Protection events cannot remove the snapshot lifetime fence.
        ApplyLifetimeBoundary(current);
        result.CapacityEvicted = TrimCapacity();
    }
    const uint64_t end = current.Base + current.Size;
    const Key key(current.ProcessId, current.CreateTime, snapshot, current.Base);
    auto first = Regions.lower_bound(key);
    if (first != Regions.begin())
    {
        const auto prior = std::prev(first);
        if (std::get<0>(prior->first) == current.ProcessId && std::get<1>(prior->first) == current.CreateTime &&
            std::get<2>(prior->first) == snapshot &&
            prior->second.Observation.Base + prior->second.Observation.Size > current.Base)
        {
            first = prior;
        }
    }
    auto last = first;
    uint64_t coveredUntil = current.Base;
    uint64_t previousTimestamp = 0;
    uint64_t previousIntervalStart = UINT64_MAX;
    uint64_t lifetimeBoundary = 0;
    bool comparable = !result.RangeUnknown;
    bool havePrevious = false;
    bool previousExecutable = false;
    std::vector<StoredRegion> survivors;
    for (; last != Regions.end() && std::get<0>(last->first) == current.ProcessId &&
        std::get<1>(last->first) == current.CreateTime && std::get<2>(last->first) == snapshot &&
        last->second.Observation.Base < end; ++last)
    {
        const KmonRegionObservation& previous = last->second.Observation;
        lifetimeBoundary = (std::max)(lifetimeBoundary, last->second.LifetimeBoundaryTimestamp);
        if (snapshot && current.CollectionStartTimestamp <= last->second.LifetimeBoundaryTimestamp)
        {
            result.LifetimeDiscontinuity = true;
            result.OutOfOrder = current.CollectionEndTimestamp <= last->second.LifetimeBoundaryTimestamp;
            return result;
        }
        if ((!snapshot && previous.Timestamp > current.Timestamp) ||
            (snapshot && previous.CollectionStartTimestamp > current.CollectionEndTimestamp))
        {
            result.OutOfOrder = true;
            return result;
        }
        comparable = comparable && previous.Base <= coveredUntil && previous.ProtectionKnown &&
            previous.Action != KmonRegionAction::Release && (!havePrevious || previous.Executable == previousExecutable);
        if (!snapshot && previous.Timestamp == current.Timestamp)
        {
            // Equal wall-clock timestamps do not order events from different threads.
            comparable = false;
            current.ProtectionKnown = false;
            result.ObservationTimeUnknown = true;
        }
        if (snapshot && previous.CollectionEndTimestamp >= current.CollectionStartTimestamp)
        {
            comparable = false;
            result.CollectionIntervalsOverlap = true;
        }
        previousExecutable = previous.Executable;
        previousTimestamp = (std::max)(previousTimestamp, previous.Timestamp);
        previousIntervalStart = (std::min)(previousIntervalStart,
            snapshot ? previous.CollectionStartTimestamp : previous.Timestamp);
        havePrevious = true;
        coveredUntil = (std::max)(coveredUntil, previous.Base + previous.Size);
        if (previous.Base < current.Base)
        {
            StoredRegion left = last->second;
            left.Observation.Size = current.Base - previous.Base;
            survivors.push_back(left);
        }
        if (previous.Base + previous.Size > end)
        {
            StoredRegion right = last->second;
            right.Observation.Base = end;
            right.Observation.Size = previous.Base + previous.Size - end;
            survivors.push_back(right);
        }
    }
    result.PreviousKnown = comparable && havePrevious && coveredUntil >= end &&
        current.Action != KmonRegionAction::Allocate;
    if (result.PreviousKnown)
    {
        result.PreviousExecutable = previousExecutable;
        result.ObservedIntervalMin100ns =
            (snapshot ? current.CollectionStartTimestamp : current.Timestamp) - previousTimestamp;
        result.ObservedIntervalMax100ns = current.Timestamp - previousIntervalStart;
        if (result.ObservedIntervalMin100ns == result.ObservedIntervalMax100ns)
        {
            result.ObservedInterval100ns = result.ObservedIntervalMin100ns;
        }
        const bool applied = current.ProtectionKnown && current.Action != KmonRegionAction::Release;
        result.NxToRx = applied && !previousExecutable && current.Executable;
        result.RxToNx = applied && previousExecutable && !current.Executable;
    }
    Regions.erase(first, last);
    for (const auto& survivor : survivors)
    {
        Regions[Key(current.ProcessId, current.CreateTime, snapshot, survivor.Observation.Base)] = survivor;
    }
    Regions[key] = {current, lifetimeBoundary};
    result.CapacityEvicted = TrimCapacity() || result.CapacityEvicted;
    result.Accepted = true;
    return result;
}

bool KmonRegionNeedsFollowup(const KmonRegionObservation& observation, const KmonRegionTransition& transition)
{
    return transition.Accepted && observation.Action != KmonRegionAction::Snapshot &&
        ((observation.Executable && observation.Action != KmonRegionAction::Release) ||
        transition.RxToNx || (observation.Action == KmonRegionAction::Release &&
        (transition.RangeUnknown || (transition.PreviousKnown && transition.PreviousExecutable))));
}

void KmonRegionHistory::Clear()
{
    Regions.clear();
    Generations.clear();
    LastPruneTickMs = 0;
}

bool KmonTemporalEvidenceSelfTest()
{
    {
        KmonRegionHistory fragmented;
        KmonRegionObservation sample;
        sample.ProcessId = 10;
        sample.CreateTime = 100;
        sample.Size = 0x1000;
        sample.Timestamp = 1000;
        sample.CollectionStartTimestamp = 1000;
        sample.CollectionEndTimestamp = 1000;
        sample.ReceiveTickMs = 10;
        sample.ProtectionKnown = true;
        for (uint64_t index = 0; index < 8192; ++index)
        {
            sample.Base = 0x100000 + index * 0x2000;
            if (!fragmented.Observe(sample).Accepted)
            {
                return false;
            }
        }
        sample.Action = KmonRegionAction::Release;
        sample.Timestamp = 2000;
        sample.ReceiveTickMs = 20;
        sample.Size = 0;
        const auto released = fragmented.Observe(sample);
        if (!released.Accepted || !released.RangeUnknown || !released.CapacityEvicted)
        {
            return false;
        }
        struct Record
        {
            KmonRegionObservation Observation;
        };
        std::map<uint64_t, Record> candidates;
        for (uint64_t index = 0; index < 16385; ++index)
        {
            candidates[index].Observation.ReceiveTickMs = index / 2;
        }
        uint64_t comparisons = 0;
        if (!TrimOldestRegions(&candidates, 8192, &comparisons) || candidates.size() != 8192 ||
            candidates.begin()->first != 8193 || comparisons > 2000000 ||
            TrimOldestRegions(&candidates, 8192))
        {
            return false;
        }
    }
    TiEventRecord event;
    event.TaskName = L"PROTECTVM_LOCAL";
    event.ProcessId = 10;
    event.Payload = {{L"BaseAddress", L"0x100000"}, {L"RegionSize", L"4096"},
        {L"ProtectionMask", L"0x20"}, {L"Status", L"0"}};
    KmonRegionObservation decoded;
    if (!KmonDecodeRegionEvent(event, &decoded) || decoded.Size != 4096 || !decoded.ProtectionKnown || !decoded.Executable)
    {
        return false;
    }
    event.Payload.back().Value = L"0xC0000022";
    if (KmonDecodeRegionEvent(event, &decoded))
    {
        return false;
    }
    event.Payload.pop_back();
    if (!KmonDecodeRegionEvent(event, &decoded) || decoded.ProtectionKnown)
    {
        return false;
    }
    KmonRegionTransition followupCandidate;
    followupCandidate.Accepted = true;
    if (!KmonRegionNeedsFollowup(decoded, followupCandidate))
    {
        return false;
    }
    event.Payload[0].Value = L"0x100000junk";
    if (KmonDecodeRegionEvent(event, &decoded))
    {
        return false;
    }
    KmonRegionHistory history;
    KmonRegionObservation observation;
    observation.ProcessId = 10;
    observation.CreateTime = 100;
    observation.Base = 0x100000;
    observation.Size = 0x1000;
    observation.Timestamp = 1000000;
    observation.ReceiveTickMs = 10;
    observation.ProtectionKnown = true;
    observation.Action = KmonRegionAction::Allocate;
    if (!history.Observe(observation).Accepted)
    {
        return false;
    }
    observation.Action = KmonRegionAction::Protect;
    observation.Executable = true;
    observation.Timestamp += 100;
    if (!history.Observe(observation).NxToRx)
    {
        return false;
    }
    {
        KmonRegionHistory equalTimeHistory;
        KmonRegionObservation equalTime = observation;
        equalTime.Action = KmonRegionAction::Protect;
        equalTime.Executable = false;
        equalTimeHistory.Observe(equalTime);
        equalTime.Executable = true;
        const auto ambiguous = equalTimeHistory.Observe(equalTime);
        if (!ambiguous.Accepted || !ambiguous.ObservationTimeUnknown || ambiguous.PreviousKnown ||
            ambiguous.NxToRx || ambiguous.RxToNx)
        {
            return false;
        }
        ++equalTime.Timestamp;
        equalTime.Executable = false;
        const auto afterAmbiguous = equalTimeHistory.Observe(equalTime);
        if (!afterAmbiguous.Accepted || afterAmbiguous.PreviousKnown || afterAmbiguous.RxToNx)
        {
            return false;
        }
        ++equalTime.Timestamp;
        equalTime.Executable = true;
        if (!equalTimeHistory.Observe(equalTime).NxToRx)
        {
            return false;
        }
    }
    observation.Timestamp -= 50;
    observation.Executable = false;
    if (!history.Observe(observation).OutOfOrder)
    {
        return false;
    }
    observation.Timestamp += 100;
    if (!history.Observe(observation).RxToNx)
    {
        return false;
    }
    ++observation.CreateTime;
    observation.Executable = true;
    if (history.Observe(observation).PreviousKnown)
    {
        return false;
    }
    observation.Action = KmonRegionAction::Release;
    ++observation.Timestamp;
    const auto released = history.Observe(observation);
    if (!released.PreviousKnown || released.NxToRx || released.RxToNx)
    {
        return false;
    }
    observation.Action = KmonRegionAction::Allocate;
    observation.Executable = false;
    ++observation.Timestamp;
    if (history.Observe(observation).PreviousKnown)
    {
        return false;
    }
    observation.ProtectionKnown = false;
    observation.Executable = true;
    ++observation.Timestamp;
    if (history.Observe(observation).NxToRx)
    {
        return false;
    }
    observation.Size = UINT64_MAX;
    if (history.Observe(observation).Accepted)
    {
        return false;
    }
    event.TaskName = L"FREEVM_LOCAL";
    event.Payload = {{L"BaseAddress", L"0x100000"}, {L"RegionSize", L"0"}, {L"Status", L"0"}};
    if (!KmonDecodeRegionEvent(event, &decoded) || decoded.Action != KmonRegionAction::Release)
    {
        return false;
    }
    event.Payload.push_back({L"TargetBaseAddress", L"0x200000"});
    if (KmonDecodeRegionEvent(event, &decoded))
    {
        return false;
    }
    history.Clear();
    observation = {};
    observation.ProcessId = 10;
    observation.CreateTime = 100;
    observation.Base = 0x100000;
    observation.Size = 0x3000;
    observation.Timestamp = 1000;
    observation.ReceiveTickMs = 10;
    observation.ProtectionKnown = true;
    observation.Action = KmonRegionAction::Allocate;
    history.Observe(observation);
    observation.Base += 0x1000;
    observation.Size = 0x1000;
    observation.Action = KmonRegionAction::Protect;
    observation.Executable = true;
    ++observation.Timestamp;
    const auto interior = history.Observe(observation);
    if (!interior.NxToRx || !KmonRegionNeedsFollowup(observation, interior))
    {
        return false;
    }
    observation.Action = KmonRegionAction::Release;
    ++observation.Timestamp;
    if (!KmonRegionNeedsFollowup(observation, history.Observe(observation)))
    {
        return false;
    }
    observation.Base -= 0x1000;
    observation.Size = 0x3000;
    observation.Action = KmonRegionAction::Snapshot;
    ++observation.Timestamp;
    observation.CollectionStartTimestamp = observation.Timestamp;
    observation.CollectionEndTimestamp = observation.Timestamp;
    if (history.Observe(observation).PreviousKnown)
    {
        return false;
    }
    observation.Action = KmonRegionAction::Allocate;
    observation.Executable = false;
    ++observation.Timestamp;
    const auto reallocated = history.Observe(observation);
    if (reallocated.PreviousKnown || reallocated.RxToNx)
    {
        return false;
    }
    observation.Action = KmonRegionAction::Release;
    observation.Size = 0;
    ++observation.Timestamp;
    if (!history.Observe(observation).RangeUnknown)
    {
        return false;
    }
    observation.Action = KmonRegionAction::Protect;
    observation.Size = 0x1000;
    --observation.Timestamp;
    if (!history.Observe(observation).OutOfOrder)
    {
        return false;
    }
    observation.Timestamp += 2;
    ++observation.CreateTime;
    history.Observe(observation);
    --observation.CreateTime;
    ++observation.Timestamp;
    if (!history.Observe(observation).OutOfOrder)
    {
        return false;
    }
    history.Clear();
    ProcessVadProtectionRange sampled;
    sampled.StartAddress = 0x100000;
    sampled.EndAddress = 0x100FFF;
    sampled.Committed = true;
    sampled.Protection = PAGE_READWRITE;
    sampled.CollectionStartTimestamp = 1000;
    sampled.CollectionEndTimestamp = 1010;
    KmonRegionObservation snapshot;
    if (!BuildKmonRegionSnapshot(10, 100, sampled, 5000, &snapshot) ||
        snapshot.Timestamp != 1010 || !history.Observe(snapshot).Accepted)
    {
        return false;
    }
    KmonRegionObservation ti = snapshot;
    ti.Action = KmonRegionAction::Allocate;
    ti.Timestamp = 900;
    ti.CollectionStartTimestamp = 0;
    ti.CollectionEndTimestamp = 0;
    if (!history.Observe(ti).Accepted)
    {
        return false;
    }
    ti.Action = KmonRegionAction::Protect;
    ti.Timestamp = 1005;
    ti.Executable = true;
    const auto delayedTi = history.Observe(ti);
    if (!delayedTi.NxToRx || delayedTi.OutOfOrder || !KmonRegionNeedsFollowup(ti, delayedTi))
    {
        return false;
    }
    sampled.CollectionStartTimestamp = 1020;
    sampled.CollectionEndTimestamp = 1030;
    if (!BuildKmonRegionSnapshot(10, 100, sampled, 6000, &snapshot))
    {
        return false;
    }
    const auto delayedSnapshot = history.Observe(snapshot);
    if (!delayedSnapshot.Accepted || !delayedSnapshot.PreviousKnown || delayedSnapshot.RxToNx ||
        delayedSnapshot.NxToRx || delayedSnapshot.OutOfOrder)
    {
        return false;
    }
    ti.Timestamp = 1040;
    ti.Executable = false;
    if (!history.Observe(ti).RxToNx)
    {
        return false;
    }
    sampled.CollectionStartTimestamp = 1025;
    sampled.CollectionEndTimestamp = 1035;
    sampled.Executable = true;
    sampled.Protection = PAGE_EXECUTE_READ;
    BuildKmonRegionSnapshot(10, 100, sampled, 7000, &snapshot);
    const auto overlappingSnapshot = history.Observe(snapshot);
    if (!overlappingSnapshot.Accepted || !overlappingSnapshot.CollectionIntervalsOverlap ||
        overlappingSnapshot.PreviousKnown || overlappingSnapshot.NxToRx || overlappingSnapshot.RxToNx)
    {
        return false;
    }
    sampled.CollectionStartTimestamp = 1040;
    sampled.CollectionEndTimestamp = 1045;
    sampled.Executable = false;
    sampled.Protection = PAGE_READWRITE;
    BuildKmonRegionSnapshot(10, 100, sampled, 8000, &snapshot);
    const auto orderedSnapshot = history.Observe(snapshot);
    if (!orderedSnapshot.RxToNx || orderedSnapshot.ObservedInterval100ns != 0 ||
        orderedSnapshot.ObservedIntervalMin100ns != 5 || orderedSnapshot.ObservedIntervalMax100ns != 20)
    {
        return false;
    }
    sampled.CollectionStartTimestamp = 1000;
    sampled.CollectionEndTimestamp = 1005;
    BuildKmonRegionSnapshot(10, 100, sampled, 9000, &snapshot);
    if (!history.Observe(snapshot).OutOfOrder)
    {
        return false;
    }
    sampled.CollectionStartTimestamp = 0;
    sampled.CollectionEndTimestamp = 0;
    BuildKmonRegionSnapshot(10, 100, sampled, 10000, &snapshot);
    const auto untimedSnapshot = history.Observe(snapshot);
    if (untimedSnapshot.Accepted || !untimedSnapshot.ObservationTimeUnknown ||
        untimedSnapshot.PreviousKnown || untimedSnapshot.NxToRx || untimedSnapshot.RxToNx)
    {
        return false;
    }
    ti.Timestamp = 1050;
    ti.Executable = true;
    if (!history.Observe(ti).NxToRx)
    {
        return false;
    }
    ti.Timestamp = 1060;
    ti.Action = KmonRegionAction::Release;
    ti.Size = 0;
    if (!history.Observe(ti).RangeUnknown)
    {
        return false;
    }
    sampled.CollectionStartTimestamp = 1055;
    sampled.CollectionEndTimestamp = 1059;
    BuildKmonRegionSnapshot(10, 100, sampled, 10500, &snapshot);
    const auto beforeRelease = history.Observe(snapshot);
    if (beforeRelease.Accepted || !beforeRelease.OutOfOrder || !beforeRelease.LifetimeDiscontinuity)
    {
        return false;
    }
    sampled.CollectionEndTimestamp = 1065;
    BuildKmonRegionSnapshot(10, 100, sampled, 10600, &snapshot);
    const auto acrossRelease = history.Observe(snapshot);
    if (acrossRelease.Accepted || !acrossRelease.LifetimeDiscontinuity || acrossRelease.PreviousKnown)
    {
        return false;
    }
    ti.Timestamp = 1065;
    ti.Action = KmonRegionAction::Protect;
    ti.Size = 0x1000;
    const auto afterReleaseProtect = history.Observe(ti);
    if (!afterReleaseProtect.Accepted || afterReleaseProtect.PreviousKnown)
    {
        return false;
    }
    sampled.CollectionEndTimestamp = 1059;
    BuildKmonRegionSnapshot(10, 100, sampled, 10700, &snapshot);
    const auto delayedBeforeRelease = history.Observe(snapshot);
    if (delayedBeforeRelease.Accepted || !delayedBeforeRelease.LifetimeDiscontinuity)
    {
        return false;
    }
    sampled.CollectionStartTimestamp = 1070;
    sampled.CollectionEndTimestamp = 1080;
    sampled.Executable = true;
    sampled.Protection = PAGE_EXECUTE_READ;
    BuildKmonRegionSnapshot(10, 100, sampled, 11000, &snapshot);
    const auto newLifetimeBaseline = history.Observe(snapshot);
    if (!newLifetimeBaseline.Accepted || newLifetimeBaseline.PreviousKnown || newLifetimeBaseline.NxToRx)
    {
        return false;
    }
    sampled.CollectionStartTimestamp = 1090;
    sampled.CollectionEndTimestamp = 1100;
    sampled.Executable = false;
    BuildKmonRegionSnapshot(10, 100, sampled, 11100, &snapshot);
    if (!history.Observe(snapshot).RxToNx)
    {
        return false;
    }
    history.Clear();
    sampled.CollectionStartTimestamp = 2000;
    sampled.CollectionEndTimestamp = 2010;
    BuildKmonRegionSnapshot(10, 100, sampled, 12000, &snapshot);
    history.Observe(snapshot);
    ti.Timestamp = 2040;
    history.Observe(ti);
    ti.Timestamp = 2020;
    ti.Action = KmonRegionAction::Release;
    if (!history.Observe(ti).OutOfOrder)
    {
        return false;
    }
    sampled.CollectionStartTimestamp = 2015;
    sampled.CollectionEndTimestamp = 2019;
    BuildKmonRegionSnapshot(10, 100, sampled, 12100, &snapshot);
    if (!history.Observe(snapshot).LifetimeDiscontinuity)
    {
        return false;
    }
    sampled.CollectionStartTimestamp = 2050;
    sampled.CollectionEndTimestamp = 2060;
    sampled.Executable = true;
    BuildKmonRegionSnapshot(10, 100, sampled, 12200, &snapshot);
    const auto delayedReleaseBaseline = history.Observe(snapshot);
    if (!delayedReleaseBaseline.Accepted || delayedReleaseBaseline.PreviousKnown || delayedReleaseBaseline.NxToRx)
    {
        return false;
    }
    ti.Timestamp = 2070;
    ti.Action = KmonRegionAction::Allocate;
    ti.Executable = false;
    history.Observe(ti);
    sampled.CollectionStartTimestamp = 2080;
    sampled.CollectionEndTimestamp = 2090;
    sampled.Executable = false;
    BuildKmonRegionSnapshot(10, 100, sampled, 12300, &snapshot);
    const auto reallocationBaseline = history.Observe(snapshot);
    if (!reallocationBaseline.Accepted || reallocationBaseline.PreviousKnown || reallocationBaseline.RxToNx)
    {
        return false;
    }
    history.Clear();
    sampled.StartAddress = 0x100000;
    sampled.EndAddress = 0x102FFF;
    sampled.CollectionStartTimestamp = 3000;
    sampled.CollectionEndTimestamp = 3010;
    BuildKmonRegionSnapshot(10, 100, sampled, 13000, &snapshot);
    history.Observe(snapshot);
    ti.Base = 0x101000;
    ti.Timestamp = 3020;
    ti.Action = KmonRegionAction::Release;
    history.Observe(ti);
    sampled.EndAddress = 0x100FFF;
    sampled.CollectionStartTimestamp = 3030;
    sampled.CollectionEndTimestamp = 3040;
    sampled.Executable = true;
    BuildKmonRegionSnapshot(10, 100, sampled, 13100, &snapshot);
    if (!history.Observe(snapshot).NxToRx)
    {
        return false;
    }
    sampled.StartAddress = 0x101000;
    sampled.EndAddress = 0x101FFF;
    BuildKmonRegionSnapshot(10, 100, sampled, 13200, &snapshot);
    const auto partialReleaseBaseline = history.Observe(snapshot);
    if (!partialReleaseBaseline.Accepted || partialReleaseBaseline.PreviousKnown || partialReleaseBaseline.NxToRx)
    {
        return false;
    }
    struct Cursor
    {
        uint64_t LastObservedMs = 0;
    };
    std::map<std::pair<uint32_t, uint64_t>, Cursor> cursors;
    std::map<std::pair<uint32_t, uint64_t>, int> identities;
    for (uint32_t pid = 10; pid < 4106; ++pid)
    {
        cursors[{pid, 100}] = {1};
        identities[{pid, 100}] = 1;
    }
    KmonPruneExecutionHistory({5000, 123}, 120001, &cursors, &identities);
    if (cursors.size() != 4096 || identities.size() != 4096)
    {
        return false;
    }
    KmonPruneExecutionHistory({5000, 123}, 120002, &cursors, &identities);
    if (!cursors.empty() || !identities.empty())
    {
        return false;
    }
    cursors[{5000, 123}] = {120002};
    identities[{5000, 123}] = 1;
    KmonPruneExecutionHistory({5000, 124}, 120003, &cursors, &identities);
    if (!cursors.empty() || !identities.empty())
    {
        return false;
    }
    cursors[{5000, 124}] = {120003};
    identities[{5000, 124}] = 1;
    KmonPruneExecutionHistory({5000, 123}, 120004, &cursors, &identities);
    if (cursors.size() != 1 || identities.size() != 1)
    {
        return false;
    }
    for (uint64_t tick = 240004; tick < 1000000; tick += 120001)
    {
        KmonRefreshExecutionHistory(std::map<uint32_t, uint64_t>{{5000, tick % 2 == 0 ? 124 : 0}}, tick, &cursors);
        KmonPruneExecutionHistory({6000, 200}, tick, &cursors, &identities);
        if (cursors.size() != 1 || identities.size() != 1 || cursors.begin()->second.LastObservedMs != tick)
        {
            return false;
        }
    }
    return true;
}
