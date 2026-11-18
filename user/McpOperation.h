#pragma once

#include "McpJson.h"
#include <functional>
#include <map>
#include <mutex>
#include <optional>

enum class McpBudgetLimit { None, Calls, RequestedEvents, ExaminedEvents, QueryExaminedEvents, PayloadBytes, ResultPayloadBytes };

inline const wchar_t* McpBudgetDimension(McpBudgetLimit limit)
{
    switch (limit)
    {
    case McpBudgetLimit::Calls: return L"admitted_calls";
    case McpBudgetLimit::RequestedEvents: return L"requested_events";
    case McpBudgetLimit::ExaminedEvents: return L"examined_events";
    case McpBudgetLimit::QueryExaminedEvents: return L"per_query_examined_events";
    case McpBudgetLimit::PayloadBytes: return L"payload_utf8_bytes";
    case McpBudgetLimit::ResultPayloadBytes: return L"per_result_payload_utf8_bytes";
    default: return L"none";
    }
}

struct McpObserveSettlement
{
    uint32_t ExaminedEvents = 0;
    uint32_t PayloadBytes = 0;
    McpBudgetLimit DeniedBy = McpBudgetLimit::None;
    bool AtPublication = false;
};

struct McpJournalIdentity
{
    std::wstring PrincipalId, TargetGeneration, RequestHmac;
    uint64_t AdmittedUtc = 0, DispatchedUtc = 0, ReturnedUtc = 0;
    std::wstring ControllerGeneration{};
    std::wstring ApprovedAccess{}; // absent in shared-password and historical receipts
    bool Tls = false;
};

inline const wchar_t* McpScopedJournalName(bool tls, bool target)
{
    if (tls) { return target ? L"https_observe_target" : L"https_observe_source"; }
    return target ? L"loopback_observe_target" : L"loopback_observe_source";
}

inline uint64_t McpUtcFileTime()
{
    FILETIME time{};
    GetSystemTimePreciseAsFileTime(&time);
    return (uint64_t(time.dwHighDateTime) << 32) | time.dwLowDateTime;
}

struct McpOperationSnapshot
{
    std::wstring Id;
    std::wstring Name;
    std::wstring OwnerFingerprint; // Live admission only. Never serialized into a receipt.
    std::wstring State = L"queued";
    uint64_t Order = 0;
    uint64_t QueuedMs = 0;
    uint64_t StartedMs = 0;
    uint64_t FinishedMs = 0;
    bool Dispatched = false;
    bool Finished = false;
    std::optional<uint32_t> ObserveRequestedEvents;
    McpObserveSettlement Settlement;
    std::optional<McpJournalIdentity> Journal;
};

inline bool IsMcpOperationId(const std::wstring& id)
{
    return id.size() == 32 && id.find_first_not_of(L"0123456789abcdef") == std::wstring::npos;
}

class McpOperationLedger
{
public:
    static constexpr size_t Capacity = 256;

    bool Begin(const std::wstring& id, const std::wstring& name, uint64_t now,
        std::optional<uint32_t> observeRequestedEvents = std::nullopt,
        std::optional<McpJournalIdentity> journal = std::nullopt, const std::wstring& ownerFingerprint = {})
    {
        std::lock_guard<std::mutex> lock(Mutex);
        if (!IsMcpOperationId(id) || name.empty() || name.size() > 512 || Records.count(id) != 0 || Order == UINT64_MAX)
        {
            return false;
        }
        auto oldest = Records.end();
        if (Records.size() == Capacity)
        {
            for (auto at = Records.begin(); at != Records.end(); ++at)
            {
                if (at->second.Finished && (oldest == Records.end() || at->second.Order < oldest->second.Order))
                {
                    oldest = at;
                }
            }
            if (oldest == Records.end())
            {
                return false;
            }
        }
        McpOperationSnapshot record;
        record.Id = id;
        record.Name = name;
        record.OwnerFingerprint = ownerFingerprint;
        record.Order = Order + 1;
        record.QueuedMs = now;
        record.ObserveRequestedEvents = observeRequestedEvents;
        record.Journal = std::move(journal);
        const auto inserted = Records.emplace(id, std::move(record)).first;
        if (!Save(inserted->second)) { Records.erase(inserted); return false; }
        if (oldest != Records.end()) { Records.erase(oldest); }
        ++Order;
        return true;
    }

    bool Start(const std::wstring& id, uint64_t now)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        const auto at = Records.find(id);
        if (at == Records.end() || at->second.Dispatched || at->second.Finished)
        {
            return false;
        }
        auto next = at->second;
        next.Dispatched = true;
        next.StartedMs = now;
        next.State = L"running";
        if (next.Journal) { next.Journal->DispatchedUtc = McpUtcFileTime(); }
        if (!Save(next)) { return false; }
        at->second = std::move(next);
        return true;
    }

    bool CancelQueued(const std::wstring& id, uint64_t now)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        const auto at = Records.find(id);
        if (at == Records.end() || at->second.Dispatched || at->second.Finished)
        {
            return false;
        }
        auto next = at->second;
        next.State = L"cancelled_before_execution";
        next.Finished = true;
        next.FinishedMs = now;
        if (!Save(next)) { return false; }
        at->second = std::move(next);
        return true;
    }

    void WaitEnded(const std::wstring& id)
    {
        std::lock_guard<std::mutex> lock(Mutex);
        const auto at = Records.find(id);
        if (at != Records.end() && at->second.Dispatched && !at->second.Finished)
        {
            at->second.State = L"unknown_outcome";
        }
    }

    bool Complete(const std::wstring& id, bool failed, bool unknown, uint64_t now, const McpObserveSettlement& settlement = {})
    {
        std::lock_guard<std::mutex> lock(Mutex);
        const auto at = Records.find(id);
        if (at == Records.end() || !at->second.Dispatched || at->second.Finished)
        {
            return false;
        }
        auto next = at->second;
        next.State = unknown ? L"unknown_outcome" : failed ? L"failed" : L"succeeded";
        next.Settlement = settlement;
        next.Finished = true;
        next.FinishedMs = now;
        if (next.Journal) { next.Journal->ReturnedUtc = McpUtcFileTime(); }
        if (!Save(next)) { return false; }
        at->second = std::move(next);
        return true;
    }

    bool Get(const std::wstring& id, McpOperationSnapshot* snapshot) const
    {
        std::lock_guard<std::mutex> lock(Mutex);
        const auto at = Records.find(id);
        if (at == Records.end() || snapshot == nullptr)
        {
            return false;
        }
        *snapshot = at->second;
        return true;
    }

    using Persist = std::function<bool(const McpOperationSnapshot&)>;
    void Reset(Persist persist = {})
    {
        std::lock_guard<std::mutex> lock(Mutex);
        Records.clear();
        Order = 0;
        PersistRecord = std::move(persist);
    }

private:
    bool Save(const McpOperationSnapshot& record) const noexcept
    {
        try { return !PersistRecord || PersistRecord(record); }
        catch (...) { return false; }
    }
    Persist PersistRecord;
    mutable std::mutex Mutex;
    std::map<std::wstring, McpOperationSnapshot> Records;
    uint64_t Order = 0;
};

inline std::wstring McpOperationJson(const McpOperationSnapshot& operation, bool recovered = false)
{
    const bool interrupted = recovered && !operation.Finished;
    const bool cancelledOnRecovery = interrupted && !operation.Dispatched;
    const bool settled = operation.Finished || cancelledOnRecovery;
    const auto state = interrupted ? (operation.Dispatched ? L"unknown_outcome" : L"cancelled_before_execution") : operation.State;
    std::wstring out = L"{\"schema\":\"kn.mcp_operation.v1\",\"operation_id\":" + mcpjson::Quote(operation.Id);
    out += L",\"name\":" + mcpjson::Quote(operation.Name) + L",\"state\":" + mcpjson::Quote(state);
    out += L",\"engine_dispatched\":" + std::wstring(operation.Dispatched ? L"true" : L"false");
    out += L",\"operation_finished\":" + std::wstring(settled ? L"true" : L"false");
    out += L",\"engine_finished\":" + std::wstring(operation.Dispatched && operation.Finished ? L"true" : L"false");
    out += L",\"queued_tick_ms\":" + mcpjson::Quote(std::to_wstring(operation.QueuedMs));
    out += L",\"started_tick_ms\":" + (operation.Dispatched ? mcpjson::Quote(std::to_wstring(operation.StartedMs)) : L"null");
    out += L",\"finished_tick_ms\":" + (operation.Finished ? mcpjson::Quote(std::to_wstring(operation.FinishedMs)) : L"null");
    out += L",\"clock\":\"collector_boot_tick_ms\",\"retention\":" + mcpjson::Quote(
        operation.Journal ? L"bounded_private_journal" : L"bounded_server_lifetime") + L",\"capacity\":256";
    if (operation.Journal)
    {
        const auto& j = *operation.Journal;
        const auto utc = [](uint64_t time) { return time ? mcpjson::Quote(std::to_wstring(time)) : std::wstring(L"null"); };
        const wchar_t* scope = operation.OwnerFingerprint.empty() ? L"loopback_observe" :
            McpScopedJournalName(j.Tls, !j.ControllerGeneration.empty());
        out += L",\"journal\":{\"schema\":\"kn.mcp_observe_journal.v1\",\"approved_scope\":" + mcpjson::Quote(scope);
        out += L",\"principal_id\":" + mcpjson::Quote(j.PrincipalId) + L",\"target_generation\":" + mcpjson::Quote(j.TargetGeneration);
        if (!j.ControllerGeneration.empty()) { out += L",\"controller_generation\":" + mcpjson::Quote(j.ControllerGeneration); }
        if (!j.ApprovedAccess.empty()) { out += L",\"approved_access\":" + mcpjson::Quote(j.ApprovedAccess); }
        out += L",\"request_hmac_sha256\":" + mcpjson::Quote(j.RequestHmac) + L",\"utc_clock\":\"windows_filetime_100ns\"";
        out += L",\"admitted_utc\":" + utc(j.AdmittedUtc) + L",\"dispatched_utc\":" + utc(j.DispatchedUtc);
        out += L",\"engine_returned_utc\":" + utc(j.ReturnedUtc) + L",\"effect_verified_utc\":null,\"recovered\":";
        out += recovered ? L"true" : L"false";
        out += L",\"last_recorded_phase\":" + mcpjson::Quote(operation.Finished ?
            (operation.Dispatched ? L"engine_returned" : L"cancelled") : (operation.Dispatched ? L"dispatch_authorized" : L"admitted")) + L"}";
    }
    if (operation.ObserveRequestedEvents.has_value())
    {
        const auto& cost = operation.Settlement;
        out += L",\"observe_charge\":{\"admitted_calls\":1,\"requested_events\":" + std::to_wstring(*operation.ObserveRequestedEvents);
        out += L",\"examined_events\":" + (settled ? std::to_wstring(cost.ExaminedEvents) : L"null");
        out += L",\"payload_utf8_bytes\":" + (settled ? std::to_wstring(cost.PayloadBytes) : L"null");
        if (cost.DeniedBy != McpBudgetLimit::None)
        {
            out += L",\"budget_denial\":{\"dimension\":" + mcpjson::Quote(McpBudgetDimension(cost.DeniedBy)) +
                L",\"stage\":" + mcpjson::Quote(cost.AtPublication ? L"publication" : L"dispatch") + L"}";
        }
        out += L"}";
    }
    out += L",\"result_payload_retained\":false,\"effects_verified\":false,\"rollback_performed\":false,\"automatic_retry\":false}";
    return out;
}
