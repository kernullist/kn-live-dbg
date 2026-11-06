#pragma once

#include "McpJson.h"
#include <algorithm>
#include <array>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

// Admission and named-file budgets for one recording session. These classes
// neither establish maliciousness nor join target lifetimes across sessions.
enum class ImageRetentionClass : size_t { FirstDifference, ObservationGap, Routine };
enum class ImageRetentionStream : size_t { Reads, Reference, Recipe };
inline const wchar_t* ImageRetentionName(ImageRetentionClass value)
{
    static const wchar_t* names[] = {L"first_difference", L"observation_gap", L"repeat_or_clean"};
    return names[static_cast<size_t>(value)];
}
struct ImageRetentionRequest
{
    std::vector<std::wstring> DifferenceKeys;
    bool Gap = false, UnkeyedDifference = false;
};
struct ImageRetentionLimits
{
    uint64_t Slots, ReferenceMemoryBytes;
    std::array<uint64_t, 3> FileBytes;
};
class ImageRetentionPolicy
{
    struct Lane
    {
        uint64_t Attempted = 0, Admitted = 0, SlotDenied = 0, ReferenceDenied = 0, KeyDenied = 0, PreparationDenied = 0;
        uint64_t Finished = 0, Complete = 0, Abandoned = 0, InFlight = 0, Peak = 0, ReferenceHeld = 0;
        std::array<uint64_t, 3> Bytes{};
    };
    struct KeyState { uint64_t Pending = 0; bool Saved = false; };
    struct State
    {
        std::mutex Mutex;
        std::array<Lane, 3> Lanes;
        std::array<ImageRetentionLimits, 3> Limits;
        std::map<std::wstring, KeyState> Keys;
        size_t KeyLimit = 8192;
    };
public:
    static constexpr uint64_t MiB = 1024 * 1024;
    static constexpr size_t MaximumKeysPerReadSet = 256;
    static std::array<ImageRetentionLimits, 3> DefaultLimits()
    {
        return {{{4, 64 * MiB, {64 * MiB, 64 * MiB, 64 * MiB}},
            {2, 64 * MiB, {32 * MiB, 64 * MiB, 32 * MiB}}, {2, 64 * MiB, {32 * MiB, 64 * MiB, 32 * MiB}}}};
    }
    class Ticket
    {
        friend class ImageRetentionPolicy;
        std::shared_ptr<State> Owner;
        std::vector<std::wstring> Keys;
        uint64_t ReferenceBytes = 0;
        bool Armed = false, Finished = false;
    public:
        ImageRetentionClass Class = ImageRetentionClass::Routine;
        bool UnkeyedDifference = false;
        Ticket() = default;
        Ticket(const Ticket&) = delete;
        Ticket& operator=(const Ticket&) = delete;
        ~Ticket()
        {
            if (!Armed) { return; }
            std::lock_guard<std::mutex> lock(Owner->Mutex);
            auto& lane = Owner->Lanes[static_cast<size_t>(Class)];
            --lane.InFlight; lane.ReferenceHeld -= ReferenceBytes;
            if (!Finished) { ++lane.Abandoned; }
            for (const auto& key : Keys)
            {
                const auto found = Owner->Keys.find(key);
                if (--found->second.Pending == 0 && !found->second.Saved) { Owner->Keys.erase(found); }
            }
        }
        // Only a complete original/read/reference/recipe journal publication
        // earns a saved key. Failed publication releases first-attempt priority.
        void Finish(bool complete)
        {
            std::lock_guard<std::mutex> lock(Owner->Mutex);
            if (Finished) { return; }
            Finished = true;
            auto& lane = Owner->Lanes[static_cast<size_t>(Class)];
            ++lane.Finished;
            if (complete)
            {
                ++lane.Complete;
                for (const auto& key : Keys) { Owner->Keys.find(key)->second.Saved = true; }
            }
        }
        std::wstring Json() const
        {
            return L"{\"policy\":\"kn.image_retention_partition.v1\",\"class\":" + mcpjson::Quote(ImageRetentionName(Class)) +
                L",\"difference_keys\":" + mcpjson::Quote(std::to_wstring(Keys.size())) +
                L",\"unkeyed_difference\":" + (UnkeyedDifference ? L"true" : L"false") +
                L",\"scope\":\"recording_session\",\"maliciousness_established\":false}";
        }
        bool HasDifference() const { return UnkeyedDifference || !Keys.empty(); }
    };
    explicit ImageRetentionPolicy(std::array<ImageRetentionLimits, 3> limits = DefaultLimits(), size_t keyLimit = 8192)
        : Data(std::make_shared<State>()) { Data->Limits = limits; Data->KeyLimit = keyLimit; }

    std::shared_ptr<Ticket> Acquire(ImageRetentionRequest request, uint64_t referenceBytes)
    {
        std::sort(request.DifferenceKeys.begin(), request.DifferenceKeys.end());
        request.DifferenceKeys.erase(std::unique(request.DifferenceKeys.begin(), request.DifferenceKeys.end()), request.DifferenceKeys.end());
        std::lock_guard<std::mutex> lock(Data->Mutex);
        bool first = request.UnkeyedDifference;
        size_t missing = 0;
        for (const auto& key : request.DifferenceKeys)
        {
            const auto found = Data->Keys.find(key);
            if (found == Data->Keys.end()) { ++missing; first = true; }
            else { first |= !found->second.Saved && found->second.Pending == 0; }
        }
        const auto kind = first ? ImageRetentionClass::FirstDifference : request.Gap ? ImageRetentionClass::ObservationGap : ImageRetentionClass::Routine;
        const auto index = static_cast<size_t>(kind);
        auto& lane = Data->Lanes[index];
        const auto& limit = Data->Limits[index];
        ++lane.Attempted;
        if (request.DifferenceKeys.size() > MaximumKeysPerReadSet || missing > Data->KeyLimit - Data->Keys.size() ||
            std::any_of(request.DifferenceKeys.begin(), request.DifferenceKeys.end(), [](const std::wstring& key)
                { return key.size() != 64 || key.find_first_not_of(L"0123456789abcdef") != std::wstring::npos; }))
            { ++lane.KeyDenied; return {}; }
        if (lane.InFlight >= limit.Slots) { ++lane.SlotDenied; return {}; }
        if (referenceBytes > limit.ReferenceMemoryBytes - lane.ReferenceHeld) { ++lane.ReferenceDenied; return {}; }
        std::shared_ptr<Ticket> ticket;
        std::vector<decltype(Data->Keys)::iterator> inserted;
        try
        {
            ticket = std::make_shared<Ticket>();
            ticket->Owner = Data; ticket->Class = kind; ticket->UnkeyedDifference = request.UnkeyedDifference;
            ticket->Keys = std::move(request.DifferenceKeys);
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
            ++lane.PreparationDenied;
            return {};
        }
        for (const auto& key : ticket->Keys) { ++Data->Keys.find(key)->second.Pending; }
        ++lane.Admitted; ++lane.InFlight;
        lane.Peak = (std::max)(lane.Peak, lane.InFlight);
        lane.ReferenceHeld += referenceBytes;
        ticket->ReferenceBytes = referenceBytes; ticket->Armed = true;
        return ticket;
    }
    uint64_t Remaining(ImageRetentionClass lane, ImageRetentionStream stream) const
    {
        std::lock_guard<std::mutex> lock(Data->Mutex);
        const auto i = static_cast<size_t>(lane);
        return Data->Limits[i].FileBytes[static_cast<size_t>(stream)] - Data->Lanes[i].Bytes[static_cast<size_t>(stream)];
    }
    // Capture writer is the sole file-budget consumer; only successful physical
    // publications charge bytes. Reused content-addressed references cost zero.
    bool Consume(ImageRetentionClass lane, ImageRetentionStream stream, uint64_t bytes)
    {
        std::lock_guard<std::mutex> lock(Data->Mutex);
        const auto i = static_cast<size_t>(lane);
        auto& used = Data->Lanes[i].Bytes[static_cast<size_t>(stream)];
        if (bytes > Data->Limits[i].FileBytes[static_cast<size_t>(stream)] - used) { return false; }
        used += bytes; return true;
    }
    uint64_t ReferenceHeld() const
    {
        std::lock_guard<std::mutex> lock(Data->Mutex);
        uint64_t total = 0;
        for (const auto& lane : Data->Lanes) { total += lane.ReferenceHeld; }
        return total;
    }
    std::wstring Json() const
    {
        std::lock_guard<std::mutex> lock(Data->Mutex);
        const auto n = [](uint64_t value) { return mcpjson::Quote(std::to_wstring(value)); };
        std::wstring json = L"{\"schema\":\"kn.image_retention.v1\",\"policy\":\"kn.image_retention_partition.v1\",\"scope\":\"recording_session\",\"key_limit\":" +
            n(Data->KeyLimit) + L",\"tracked_keys\":" + n(Data->Keys.size()) + L",\"classes\":[";
        for (size_t i = 0; i < 3; ++i)
        {
            const auto& l = Data->Lanes[i]; const auto& limit = Data->Limits[i];
            if (i != 0) { json += L","; }
            json += L"{\"class\":" + mcpjson::Quote(ImageRetentionName(static_cast<ImageRetentionClass>(i))) +
                L",\"slot_limit\":" + n(limit.Slots) + L",\"reference_memory_limit\":" + n(limit.ReferenceMemoryBytes) +
                L",\"read_bytes_limit\":" + n(limit.FileBytes[0]) + L",\"reference_bytes_limit\":" + n(limit.FileBytes[1]) +
                L",\"recipe_bytes_limit\":" + n(limit.FileBytes[2]) + L",\"attempted\":" + n(l.Attempted) +
                L",\"admitted\":" + n(l.Admitted) + L",\"slot_denied\":" + n(l.SlotDenied) + L",\"reference_denied\":" + n(l.ReferenceDenied) +
                L",\"key_denied\":" + n(l.KeyDenied) + L",\"finished\":" + n(l.Finished) + L",\"complete\":" + n(l.Complete) +
                L",\"preparation_denied\":" + n(l.PreparationDenied) +
                L",\"abandoned\":" + n(l.Abandoned) + L",\"in_flight\":" + n(l.InFlight) + L",\"peak\":" + n(l.Peak) +
                L",\"reference_held\":" + n(l.ReferenceHeld) + L",\"read_bytes\":" + n(l.Bytes[0]) +
                L",\"reference_bytes\":" + n(l.Bytes[1]) + L",\"recipe_bytes\":" + n(l.Bytes[2]) + L"}";
        }
        return json + L"],\"first_retained_requires_complete_journal_batch\":true,\"cross_session_dedup_established\":false,"
            L"\"maliciousness_established\":false,\"disk_space_reserved\":false}";
    }
private:
    std::shared_ptr<State> Data;
};

template<typename T> class ImageRetentionQueue
{
public:
    bool Push(T item)
    {
        if (!item.Retention) { return false; }
        std::lock_guard<std::mutex> lock(Mutex);
        const auto i = static_cast<size_t>(item.Retention->Class);
        if (Items[i].size() >= ImageRetentionPolicy::DefaultLimits()[i].Slots) { return false; }
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
