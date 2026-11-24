#pragma once
#include "ProcessHandleObservation.h"
#include <memory>
#include <string>

// One direct acquisition owns its journal. Identity on an acquisition is
// queried on the acquired handle. A close refers back to that acquisition.
struct ProcessImageSourceReceipt
{
    DWORD RequestedPid = 0;
    uint64_t RequestedCreation = 0, UserMaximum = 0;
    ProcessHandleIdentity CollectorQuery;
    std::wstring SourceId;
    std::vector<ProcessHandleAction> Actions;
};

std::wstring ProcessImageSourceReceiptJson(const ProcessImageSourceReceipt& receipt);
struct ProcessImageCaptureReport
{
    std::wstring ReceiptJson, CaptureStatus, SourceStatus, SourceId, TargetId;
    std::wstring OperationId, ReferenceSha256, RecipeSha256, Policy, Consistency, Result;
    bool Published() const { return CaptureStatus == L"recorded" || CaptureStatus == L"interrupted"; }
};

// Returns the original replay diagnostic on failure. No target or file access.
const wchar_t* ParseProcessImageCaptureReport(const std::wstring& page, ProcessImageCaptureReport& report);
struct RetainedReferenceArtifact;
struct ProcessImageSourceFiles
{
    std::shared_ptr<const RetainedReferenceArtifact> Report, Claim, Reference;
    std::wstring CaptureStatus, SourceStatus;
};

bool ReplayProcessImageSource(const std::wstring& reportPath, const std::wstring& reportSha256,
    const std::wstring& imageCase, std::wstring& output, ProcessImageSourceFiles* retained = nullptr);
