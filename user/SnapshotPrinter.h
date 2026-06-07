#pragma once

#include "SnapshotDiff.h"
#include "SnapshotModel.h"

#include <string>

void PrintSnapshotSummary(const SnapshotDocument& document, bool domains, bool warnings);
void PrintSnapshotDiff(const SnapshotDiffResult& diff, const SnapshotDiffOptions& options);
std::wstring BuildSnapshotBaselineMarkdown(const SnapshotDocument& document);
std::wstring BuildSnapshotDiffMarkdown(const SnapshotDiffResult& diff, const SnapshotDiffOptions& options);
