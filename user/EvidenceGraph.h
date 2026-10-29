#pragma once

#include "EvidenceInvestigation.h"
#include <atomic>

struct EvidenceGraphNode
{
    std::wstring Id;
    std::wstring Kind;
    std::wstring State;
    std::wstring Role;
    std::wstring BytesSha256;
    uint64_t Address = 0;
    uint64_t Size = 0;
    bool HasAddress = false;
    size_t SpanIndex = SIZE_MAX;
};

struct EvidenceGraphEdge
{
    std::wstring Id;
    std::wstring From;
    std::wstring To;
    std::wstring Kind;
    std::wstring Basis;
    std::vector<size_t> SpanIndices;
};

struct EvidenceGraph
{
    std::wstring Status = L"unavailable";
    std::wstring Digest;
    std::wstring SourceDigest;
    std::wstring Root;
    std::wstring Acquisition;
    std::wstring RecordedCoverageJson;
    bool ReferenceConsistent = false;
    bool CaptureTruncated = false;
    bool ReadSetComplete = false;
    uint64_t CaptureStartedMs = 0;
    uint64_t CaptureEndedMs = 0;
    KmonHuntReceipt Receipt;
    std::vector<EvidenceGraphNode> Nodes;
    std::vector<EvidenceGraphEdge> Edges;
    std::vector<std::wstring> Gaps;
};

struct EvidenceGraphQuery
{
    std::wstring Node;
    std::wstring Cursor;
    size_t Depth = 2;
    size_t Limit = 64;
    uint64_t TimeBudgetMs = 1000;
    const std::atomic<bool>* Cancellation = nullptr;
};

struct EvidenceGraphPage
{
    std::wstring Status = L"unavailable";
    std::wstring QueryDigest;
    std::wstring NextCursor;
    size_t Offset = 0;
    size_t TotalRecords = 0;
    std::vector<EvidenceGraphNode> Nodes;
    std::vector<EvidenceGraphEdge> Edges;
};

// sourceDigest must come from the successful bounded LoadEvidenceBundle call.
EvidenceGraph BuildEvidenceGraph(const EvidenceBundle& bundle, const std::wstring& sourceDigest);
EvidenceGraphPage QueryEvidenceGraph(const EvidenceGraph& graph, const EvidenceGraphQuery& query);
std::wstring EvidenceGraphJson(const EvidenceGraph& graph, const EvidenceGraphQuery& query, const EvidenceGraphPage& page);
