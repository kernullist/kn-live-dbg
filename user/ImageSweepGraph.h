#pragma once

#include "EvidenceGraph.h"
#include <map>

struct ImageSweepGraph
{
    EvidenceGraph Facts;
    std::wstring Context, Assessment;
    std::map<std::wstring, std::wstring> NodeDetails, NodeProvenance, EdgeProvenance;
};

// Replay the original policies before publishing any graph. The graph is scoped
// to one retained temporal sweep and establishes no cross-bundle lifetime joins.
ImageSweepGraph BuildImageSweepGraph(const std::wstring& path);
std::wstring ImageSweepGraphJson(const ImageSweepGraph& graph, const EvidenceGraphQuery& query,
    const EvidenceGraphPage& page);
