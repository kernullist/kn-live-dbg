#pragma once
#include "ProcessHandleObservation.h"
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
bool ReplayProcessImageSource(const std::wstring& reportPath, const std::wstring& reportSha256,
    const std::wstring& imageCase, std::wstring& output);
