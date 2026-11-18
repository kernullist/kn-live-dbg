#pragma once

#include "McpJson.h"
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

struct McpOperationSnapshot
{
    std::wstring Id;
    std::wstring Name;
    std::wstring State = L"queued";
    uint64_t Order = 0;
    uint64_t QueuedMs = 0;
    uint64_t StartedMs = 0;
    uint64_t FinishedMs = 0;
    bool Dispatched = false;
    bool Finished = false;
    std::optional<uint32_t> ObserveRequestedEvents;
    McpObserveSettlement Settlement;
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
        std::optional<uint32_t> observeRequestedEvents = std::nullopt)
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
        record.Order = Order + 1;
        record.QueuedMs = now;
        record.ObserveRequestedEvents = observeRequestedEvents;
        Records.emplace(id, std::move(record));
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
        at->second.Dispatched = true;
        at->second.StartedMs = now;
        at->second.State = L"running";
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
        at->second.State = L"cancelled_before_execution";
        at->second.Finished = true;
        at->second.FinishedMs = now;
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
        at->second.State = unknown ? L"unknown_outcome" : failed ? L"failed" : L"succeeded";
        at->second.Settlement = settlement;
        at->second.Finished = true;
        at->second.FinishedMs = now;
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

    void Reset()
    {
        std::lock_guard<std::mutex> lock(Mutex);
        Records.clear();
        Order = 0;
    }

private:
    mutable std::mutex Mutex;
    std::map<std::wstring, McpOperationSnapshot> Records;
    uint64_t Order = 0;
};

inline std::wstring McpOperationJson(const McpOperationSnapshot& operation)
{
    std::wstring out = L"{\"schema\":\"kn.mcp_operation.v1\",\"operation_id\":" + mcpjson::Quote(operation.Id);
    out += L",\"name\":" + mcpjson::Quote(operation.Name) + L",\"state\":" + mcpjson::Quote(operation.State);
    out += L",\"engine_dispatched\":" + std::wstring(operation.Dispatched ? L"true" : L"false");
    out += L",\"operation_finished\":" + std::wstring(operation.Finished ? L"true" : L"false");
    out += L",\"engine_finished\":" + std::wstring(operation.Dispatched && operation.Finished ? L"true" : L"false");
    out += L",\"queued_tick_ms\":" + mcpjson::Quote(std::to_wstring(operation.QueuedMs));
    out += L",\"started_tick_ms\":" + (operation.Dispatched ? mcpjson::Quote(std::to_wstring(operation.StartedMs)) : L"null");
    out += L",\"finished_tick_ms\":" + (operation.Finished ? mcpjson::Quote(std::to_wstring(operation.FinishedMs)) : L"null");
    out += L",\"clock\":\"collector_boot_tick_ms\",\"retention\":\"bounded_server_lifetime\",\"capacity\":256";
    if (operation.ObserveRequestedEvents.has_value())
    {
        const auto& cost = operation.Settlement;
        out += L",\"observe_charge\":{\"admitted_calls\":1,\"requested_events\":" + std::to_wstring(*operation.ObserveRequestedEvents);
        out += L",\"examined_events\":" + (operation.Finished ? std::to_wstring(cost.ExaminedEvents) : L"null");
        out += L",\"payload_utf8_bytes\":" + (operation.Finished ? std::to_wstring(cost.PayloadBytes) : L"null");
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
