#pragma once

#include "PendingIrpScanner.h"
#include "McpJson.h"
#include <algorithm>
#include <array>
#include <deque>
#include <map>
#include <mutex>

enum class IrpRetentionClass : size_t { FirstState, ObservationGap, Routine };
enum class IrpRetentionStream : size_t { Capture, Reference };
inline const wchar_t* IrpRetentionName(IrpRetentionClass value)
{
    static const wchar_t* names[] = {L"first_observed_state", L"observation_gap", L"repeat_or_empty"};
    return names[static_cast<size_t>(value)];
}
struct IrpRetentionLimits
{
    uint64_t Slots, MemoryBytes;
    std::array<uint64_t, 2> FileBytes;
};

// Separate session budgets prevent repeated observations from exhausting first
// state or gap admission. Equal signatures do not exclude IRP address reuse.
class IrpRetentionPolicy
{
    struct Lane
    {
        uint64_t Attempted = 0, Admitted = 0, SlotDenied = 0, MemoryDenied = 0, KeyDenied = 0;
        uint64_t PreparationDenied = 0, Unavailable = 0, Invalid = 0;
        uint64_t Finished = 0, Complete = 0, Abandoned = 0, InFlight = 0, Peak = 0, Held = 0;
        std::array<uint64_t, 2> Bytes{};
    };
    struct KeyState { uint64_t Pending = 0; bool Saved = false; };
    struct State
    {
        std::mutex Mutex;
        std::array<Lane, 3> Lanes;
        std::array<IrpRetentionLimits, 3> Limits;
        std::map<std::wstring, KeyState> Keys;
        size_t KeyLimit = 8192;
    };
public:
    static constexpr uint64_t MiB = 1024 * 1024;
    static constexpr size_t MaximumKeys = 256;
    static std::array<IrpRetentionLimits, 3> DefaultLimits()
    {
        // Each lane can admit one maximum 16 MiB capture + 64 MiB reference.
        return {{{2, 80 * MiB, {64 * MiB, 64 * MiB}},
            {1, 80 * MiB, {32 * MiB, 64 * MiB}}, {1, 80 * MiB, {32 * MiB, 64 * MiB}}}};
    }
    class Ticket
    {
        friend class IrpRetentionPolicy;
        std::shared_ptr<State> Owner;
        std::vector<std::wstring> Keys;
        IrpRetentionClass Kind = IrpRetentionClass::Routine;
        uint64_t MemoryBytes = 0;
        bool Armed = false, Finished = false, Unkeyed = false, Gap = false;
    public:
        Ticket() = default;
        Ticket(const Ticket&) = delete;
        Ticket& operator=(const Ticket&) = delete;
        ~Ticket()
        {
            if (!Armed) { return; }
            std::lock_guard<std::mutex> lock(Owner->Mutex);
            auto& lane = Owner->Lanes[static_cast<size_t>(Kind)];
            --lane.InFlight; lane.Held -= MemoryBytes;
            if (!Finished) { ++lane.Abandoned; }
            for (const auto& key : Keys)
            {
                const auto found = Owner->Keys.find(key);
                if (--found->second.Pending == 0 && !found->second.Saved) { Owner->Keys.erase(found); }
            }
        }
        IrpRetentionClass Class() const { return Kind; }
        bool Valid() const { return Armed; }
        bool HasState() const { return Unkeyed || !Keys.empty(); }
        // First-state keys are saved only after capture + retained reference
        // belong to a committed journal batch, not on queue/file admission.
        void Finish(bool complete)
        {
            if (!Armed) { return; }
            std::lock_guard<std::mutex> lock(Owner->Mutex);
            if (Finished) { return; }
            Finished = true;
            auto& lane = Owner->Lanes[static_cast<size_t>(Kind)];
            ++lane.Finished;
            if (complete)
            {
                ++lane.Complete;
                for (const auto& key : Keys) { Owner->Keys.find(key)->second.Saved = true; }
            }
        }
        std::wstring Json() const
        {
            return L"{\"policy\":\"kn.irp_retention_partition.v1\",\"class\":" + mcpjson::Quote(IrpRetentionName(Kind)) +
                L",\"state_keys\":" + mcpjson::Quote(std::to_wstring(Keys.size())) +
                L",\"unkeyed_state\":" + (Unkeyed ? L"true" : L"false") + L",\"observation_gap\":" + (Gap ? L"true" : L"false") +
                L",\"identity_scope\":\"recorded_state_signature_only\",\"referenced_lifetime\":false,\"maliciousness_established\":false}";
        }
    };
    explicit IrpRetentionPolicy(std::array<IrpRetentionLimits, 3> limits = DefaultLimits(), size_t keyLimit = 8192)
        : Data(std::make_shared<State>()) { Data->Limits = limits; Data->KeyLimit = keyLimit; }

    // Missing/invalid encoded input still contributes to the failure denominator,
    // independently of raw-file budget and queue availability.
    void RecordUnavailable(bool invalid = false)
    {
        std::lock_guard<std::mutex> lock(Data->Mutex);
        auto& lane = Data->Lanes[static_cast<size_t>(IrpRetentionClass::ObservationGap)];
        ++lane.Attempted;
        if (invalid) { ++lane.Invalid; } else { ++lane.Unavailable; }
    }
    std::shared_ptr<Ticket> Acquire(IrpRetentionRequest request, uint64_t memoryBytes)
    {
        if (request.StateKeys.size() > MaximumKeys ||
            std::any_of(request.StateKeys.begin(), request.StateKeys.end(), [](const auto& key)
                { return key.size() != 64 || key.find_first_not_of(L"0123456789abcdef") != std::wstring::npos; }))
        {
            std::lock_guard<std::mutex> lock(Data->Mutex);
            const auto kind = request.UnkeyedState || !request.StateKeys.empty() ? IrpRetentionClass::FirstState :
                request.Gap ? IrpRetentionClass::ObservationGap : IrpRetentionClass::Routine;
            auto& lane = Data->Lanes[static_cast<size_t>(kind)];
            ++lane.Attempted; ++lane.KeyDenied; return {};
        }
        std::sort(request.StateKeys.begin(), request.StateKeys.end());
        request.StateKeys.erase(std::unique(request.StateKeys.begin(), request.StateKeys.end()), request.StateKeys.end());
        std::lock_guard<std::mutex> lock(Data->Mutex);
        bool first = request.UnkeyedState;
        size_t missing = 0;
        for (const auto& key : request.StateKeys)
        {
            const auto found = Data->Keys.find(key);
            if (found == Data->Keys.end()) { ++missing; first = true; }
            else { first |= !found->second.Saved && found->second.Pending == 0; }
        }
        const auto kind = first ? IrpRetentionClass::FirstState : request.Gap ? IrpRetentionClass::ObservationGap : IrpRetentionClass::Routine;
        const auto index = static_cast<size_t>(kind);
        auto& lane = Data->Lanes[index]; const auto& limit = Data->Limits[index];
        ++lane.Attempted;
        if (missing > Data->KeyLimit - Data->Keys.size())
            { ++lane.KeyDenied; return {}; }
        if (lane.InFlight >= limit.Slots) { ++lane.SlotDenied; return {}; }
        if (memoryBytes > limit.MemoryBytes - lane.Held) { ++lane.MemoryDenied; return {}; }
        std::shared_ptr<Ticket> ticket;
        std::vector<decltype(Data->Keys)::iterator> inserted;
        try
        {
            ticket = std::make_shared<Ticket>(); ticket->Owner = Data; ticket->Kind = kind;
            ticket->Keys = std::move(request.StateKeys); ticket->Gap = request.Gap; ticket->Unkeyed = request.UnkeyedState;
            inserted.reserve(missing);
            for (const auto& key : ticket->Keys)
            {
                const auto result = Data->Keys.emplace(key, KeyState{});
                if (result.second) { inserted.push_back(result.first); }
            }
        }
        catch (...)
        {
            for (auto it : inserted) { Data->Keys.erase(it); }
            ++lane.PreparationDenied; return {};
        }
        for (const auto& key : ticket->Keys) { ++Data->Keys.find(key)->second.Pending; }
        ++lane.Admitted; ++lane.InFlight; lane.Peak = (std::max)(lane.Peak, lane.InFlight); lane.Held += memoryBytes;
        ticket->MemoryBytes = memoryBytes; ticket->Armed = true;
        return ticket;
    }
    uint64_t Remaining(IrpRetentionClass kind, IrpRetentionStream stream) const
    {
        std::lock_guard<std::mutex> lock(Data->Mutex);
        const auto i = static_cast<size_t>(kind), s = static_cast<size_t>(stream);
        return Data->Limits[i].FileBytes[s] - Data->Lanes[i].Bytes[s];
    }
    // Only the capture writer consumes file budgets. Existing exact references
    // cost zero; newly published bytes are charged even if later checks fail.
    bool Consume(IrpRetentionClass kind, IrpRetentionStream stream, uint64_t bytes)
    {
        std::lock_guard<std::mutex> lock(Data->Mutex);
        const auto i = static_cast<size_t>(kind), s = static_cast<size_t>(stream);
        auto& used = Data->Lanes[i].Bytes[s];
        if (bytes > Data->Limits[i].FileBytes[s] - used) { return false; }
        used += bytes; return true;
    }
    uint64_t MemoryHeld() const
    {
        std::lock_guard<std::mutex> lock(Data->Mutex);
        uint64_t bytes = 0;
        for (const auto& lane : Data->Lanes) { bytes += lane.Held; }
        return bytes;
    }
    std::wstring Json() const
    {
        std::lock_guard<std::mutex> lock(Data->Mutex);
        const auto n = [](uint64_t value) { return mcpjson::Quote(std::to_wstring(value)); };
        std::wstring json = L"{\"schema\":\"kn.irp_retention.v1\",\"policy\":\"kn.irp_retention_partition.v1\",\"scope\":\"recording_session\","
            L"\"key_limit\":" + n(Data->KeyLimit) + L",\"tracked_keys\":" + n(Data->Keys.size()) + L",\"classes\":[";
        for (size_t i = 0; i < 3; ++i)
        {
            const auto& l = Data->Lanes[i]; const auto& limit = Data->Limits[i];
            if (i) { json += L","; }
            json += L"{\"class\":" + mcpjson::Quote(IrpRetentionName(static_cast<IrpRetentionClass>(i))) +
                L",\"slot_limit\":" + n(limit.Slots) + L",\"memory_limit\":" + n(limit.MemoryBytes) +
                L",\"capture_bytes_limit\":" + n(limit.FileBytes[0]) + L",\"reference_bytes_limit\":" + n(limit.FileBytes[1]) +
                L",\"attempted\":" + n(l.Attempted) + L",\"admitted\":" + n(l.Admitted) + L",\"slot_denied\":" + n(l.SlotDenied) +
                L",\"memory_denied\":" + n(l.MemoryDenied) + L",\"key_denied\":" + n(l.KeyDenied) + L",\"preparation_denied\":" + n(l.PreparationDenied) +
                L",\"unavailable\":" + n(l.Unavailable) + L",\"invalid\":" + n(l.Invalid) + L",\"finished\":" + n(l.Finished) +
                L",\"complete\":" + n(l.Complete) + L",\"abandoned\":" + n(l.Abandoned) + L",\"in_flight\":" + n(l.InFlight) +
                L",\"peak\":" + n(l.Peak) + L",\"held_bytes\":" + n(l.Held) + L",\"capture_bytes\":" + n(l.Bytes[0]) +
                L",\"reference_bytes\":" + n(l.Bytes[1]) + L"}";
        }
        return json + L"],\"first_retained_requires_reference_and_journal\":true,\"cross_session_dedup_established\":false,"
            L"\"referenced_lifetime\":false,\"maliciousness_established\":false,\"disk_space_reserved\":false}";
    }
private:
    std::shared_ptr<State> Data;
};

template<typename T> class IrpRetentionQueue
{
public:
    bool Push(T item)
    {
        if (!item.Retention || !item.Retention->Valid()) { return false; }
        std::lock_guard<std::mutex> lock(Mutex);
        const auto i = static_cast<size_t>(item.Retention->Class());
        if (Items[i].size() >= IrpRetentionPolicy::DefaultLimits()[i].Slots) { return false; }
        Items[i].push_back(std::move(item)); return true;
    }
    bool Pop(T* item)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        for (size_t n = 0; n < 3; ++n)
        {
            const auto i = (Next + n) % 3;
            if (Items[i].empty()) { continue; }
            *item = std::move(Items[i].front()); Items[i].pop_front(); Next = (i + 1) % 3; return true;
        }
        return false;
    }
    size_t Size() const
    {
        std::lock_guard<std::mutex> lock(Mutex);
        return Items[0].size() + Items[1].size() + Items[2].size();
    }
    void Reset()
    {
        std::lock_guard<std::mutex> lock(Mutex);
        for (auto& lane : Items) { lane.clear(); }
        Next = 0;
    }
private:
    mutable std::mutex Mutex;
    std::array<std::deque<T>, 3> Items;
    size_t Next = 0;
};
