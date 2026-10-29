#pragma once

#include "AddressSpaceDescriptor.h"

#include <cstdint>
#include <map>
#include <string>

struct HiddenProcessField
{
    uint64_t Offset = 0;
    uint8_t Bytes = 0;
    uint8_t BitPosition = 0;
    uint8_t BitCount = 0;
    bool Available = false;
};

struct HiddenProcessLayout
{
    HiddenProcessField Pid;
    HiddenProcessField CreateTime;
    HiddenProcessField ActiveThreads;
    HiddenProcessField ExitTime;
    HiddenProcessField Auxiliary;
    HiddenProcessField ProcessExiting;
    HiddenProcessField ProcessDelete;
    HiddenProcessField ProcessRundown;
    uint64_t LinksOffset = 0;
    uint64_t ListHead = 0;
    bool LinksAvailable = false;
};

class HiddenProcessReader
{
public:
    virtual ~HiddenProcessReader() = default;
    virtual bool Read(uint64_t address, uint8_t bytes, uint64_t* value) = 0;
    virtual bool Resolve(uint32_t pid, uint64_t* eprocess) = 0;
    virtual bool Stopped() const = 0;
};

struct HiddenProcessLifetime
{
    uint32_t Pid = 0;
    uint64_t Eprocess = 0;
    uint64_t CreateTime = 0;
    uint64_t ExitTime = 0;
    uint32_t ActiveThreads = 0;
    bool IdentityValid = false;
    bool HasExitTime = false;
    bool HasActiveThreads = false;
    bool HasAuxiliary = false;
    bool Auxiliary = false;
    bool HasStateFlags = false;
    bool StateTransition = false;
};

struct HiddenProcessKernelEntry
{
    uint64_t Eprocess = 0;
    uint64_t CreateTime = 0;
    bool HasCreateTime = false;
};

struct HiddenProcessKernelView
{
    std::map<uint32_t, HiddenProcessKernelEntry> Entries;
    bool Complete = false;
    std::wstring Reason;
};

struct HiddenProcessMembership
{
    bool Kernel = false;
    bool Spi = false;
    bool Toolhelp = false;
    bool Cid = false;
    bool Handles = false;
};

struct HiddenProcessQualification
{
    bool Attempted = false;
    bool KernelComplete = false;
    bool SpiComplete = false;
    bool ToolhelpComplete = false;
    bool BudgetExceeded = false;
    HiddenProcessMembership Views;
    HiddenProcessKernelEntry KernelIdentity;
    HiddenProcessLifetime Before;
    HiddenProcessLifetime After;
};

enum class HiddenProcessDisposition
{
    None,
    Unverified,
    CrossViewDiscrepancy,
    Auxiliary,
    Terminating,
    Reconciled
};

struct HiddenProcessDecision
{
    HiddenProcessDisposition Disposition = HiddenProcessDisposition::None;
    const wchar_t* Reason = L"not_candidate";
    const wchar_t* Notes = L"";
    bool StableLifetime = false;
};

bool IsHiddenProcessCandidate(uint32_t pid, const HiddenProcessMembership& discovery);
HiddenProcessLifetime ReadHiddenProcessLifetime(
    HiddenProcessReader& reader,
    const AddressSpaceDescriptor& addressSpace,
    const HiddenProcessLayout& layout,
    uint32_t pid);
HiddenProcessKernelView ReadHiddenProcessKernelView(
    HiddenProcessReader& reader,
    const AddressSpaceDescriptor& addressSpace,
    const HiddenProcessLayout& layout,
    uint32_t limit = 8192);
HiddenProcessDecision QualifyHiddenProcess(
    uint32_t pid,
    const HiddenProcessMembership& discovery,
    const HiddenProcessQualification& qualification);
const wchar_t* HiddenProcessDispositionName(HiddenProcessDisposition disposition);
bool HiddenProcessPolicySelfTest(uint32_t* checks = nullptr);
