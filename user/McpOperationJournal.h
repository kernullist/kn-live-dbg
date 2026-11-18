#pragma once

#include "McpOperation.h"
#include <memory>

struct McpEngineRequest;
struct McpObserveGrant;

// The server serializes access with its queue lock and holds the store lease
// until the listener stops. Only recovery views of metadata enter the file.
class McpOperationJournal
{
public:
    McpOperationJournal();
    ~McpOperationJournal();
    bool Open(const std::wstring& directory, const std::wstring& password, std::wstring* error, bool scoped = false);
    std::optional<McpJournalIdentity> Identify(const McpEngineRequest& request) const;
    bool Persist(const McpOperationSnapshot& operation) noexcept;
    bool Healthy() const;
    bool Lookup(const std::wstring& id, const McpObserveGrant& grant, std::wstring* receipt) const;

private:
    struct Impl;
    std::unique_ptr<Impl> Data;
};
