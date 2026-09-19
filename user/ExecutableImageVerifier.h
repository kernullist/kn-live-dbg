#pragma once

#include "ExecutableImage.h"
#include "ObservationModel.h"

#include <functional>
#include <map>

using ObservationReader = std::function<bool(uint64_t, size_t, std::vector<uint8_t>*)>;

struct ExecutablePageResult
{
    uint32_t Rva = 0;
    CodeOwnership Ownership = CodeOwnership::OwnedUnverified;
    ObservationCoverage Coverage;
    std::vector<uint8_t> Expected;
    std::vector<uint8_t> Observed;
    std::vector<ObservationRange> Changes;
};

struct ExecutableSweep
{
    size_t NextRange = 0;
    uint64_t Cycle = 1;
    uint64_t LastCompleteMs = 0;
    ObservationCoverage Coverage;
    std::vector<ObservationRange> Ranges;
    std::map<uint32_t, CodeOwnership> Pages;

    bool Initialize(const executable_image::DiskPeMetadata& metadata);
};

bool QualifyExecutableReference(
    const executable_image::DiskPeMetadata& metadata,
    uint64_t imageBase,
    const ObservationReader& reader,
    std::wstring* reason);

ExecutablePageResult CompareExecutableRange(
    const std::wstring& path,
    const executable_image::DiskPeMetadata& metadata,
    uint64_t imageBase,
    uint32_t rva,
    uint32_t size,
    const ObservationReader& reader);

std::vector<ExecutablePageResult> AdvanceExecutableSweep(
    const std::wstring& path,
    const executable_image::DiskPeMetadata& metadata,
    uint64_t imageBase,
    const ObservationReader& reader,
    size_t pageBudget,
    uint64_t nowMs,
    ExecutableSweep* sweep);

bool ExecutableImageVerifierSelfTest();
