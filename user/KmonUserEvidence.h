#pragma once

#include "ProcessTriageScanner.h"

#include <array>
#include <memory>
#include <string>
#include <vector>

struct KmonEvidenceCoverage
{
    bool Available = false;
    bool Complete = false;
    bool Truncated = false;
    uint32_t Failures = 0;
    std::wstring Detail;
};

struct KmonThreadContextRecord
{
    uint32_t ThreadId = 0;
    uint64_t CreateTime = 0;
    uint64_t CaptureTime = 0;
    uint64_t InstructionPointer = 0;
    uint64_t StackPointer = 0;
    std::array<uint64_t, 4> DebugAddress = {};
    uint64_t DebugControl = 0;
    bool Wow64 = false;
    bool ControlValid = false;
    bool DebugValid = false;
};

struct KmonThreadSnapshot
{
    std::vector<KmonThreadContextRecord> Threads;
    KmonEvidenceCoverage Coverage;
    uint64_t ProcessCreateTime = 0;
    uint32_t NextThreadCursor = 0;
    bool Wow64 = false;
};

bool CaptureKmonThreadSnapshot(
    uint32_t processId,
    uint64_t expectedCreateTime,
    uint32_t maxThreads,
    uint32_t afterThreadId,
    KmonThreadSnapshot* result,
    std::wstring* error);

struct KmonFileIdentity
{
    uint64_t VolumeSerial = 0;
    std::array<uint8_t, 16> FileId = {};
    uint64_t CreationTime = 0;
    uint64_t LastWriteTime = 0;
    uint64_t ChangeTime = 0;
    uint64_t Size = 0;
    uint32_t Links = 0;
    uint32_t Attributes = 0;
    uint32_t ReparseTag = 0;
    uint32_t PathAttributes = 0;
    uint32_t PathReparseTag = 0;
    std::wstring RequestedPath;
    std::wstring FinalPath;
    bool Stable = false;
    bool PathMetadataKnown = false;
};

bool QueryKmonFileIdentity(
    const std::wstring& path,
    KmonFileIdentity* result,
    std::wstring* error);
bool KmonSameFileObject(const KmonFileIdentity& left, const KmonFileIdentity& right);
bool KmonSameFileGeneration(const KmonFileIdentity& left, const KmonFileIdentity& right);

struct KmonRuntimeCodeRange
{
    uint64_t Start = 0;
    uint64_t Size = 0;
    uint64_t MethodId = 0;
    uint64_t ModuleId = 0;
    uint64_t Timestamp = 0;
    uint16_t RuntimeInstance = 0;
    uint32_t MethodFlags = 0;
};

class KmonUserRuntimeTracker
{
public:
    KmonUserRuntimeTracker();
    ~KmonUserRuntimeTracker();
    KmonUserRuntimeTracker(const KmonUserRuntimeTracker&) = delete;
    KmonUserRuntimeTracker& operator=(const KmonUserRuntimeTracker&) = delete;

    bool Start(std::wstring* error);
    void Stop();
    bool WatchProcess(uint32_t processId, uint64_t createTime);
    void Snapshot(
        uint32_t processId,
        uint64_t createTime,
        std::vector<KmonRuntimeCodeRange>* ranges,
        KmonEvidenceCoverage* coverage);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

enum class KmonUserEvidenceKind
{
    SnapshotInstructionPointer,
    HardwareBreakpoint,
    SavedTrapInstructionPointer,
    UserApcRoutine,
    TlsCallback,
    VectoredExceptionHandler,
    VectoredContinueHandler,
    UserApcArgumentCandidate
};

// These layouts must come from an exact image/PDB match. No build-number or
// prologue guessing is accepted. Encoded handlers require DecodeRemotePointer.
struct KmonVectoredHandlerLayout
{
    uint64_t ModuleBase = 0;
    uint32_t ImageSize = 0;
    uint32_t TimeDateStamp = 0;
    GUID PdbGuid = {};
    uint32_t PdbAge = 0;
    uint32_t ListHeadRva = 0;
    uint32_t EntryLinkOffset = 0;
    uint32_t HandlerOffset = 0;
    uint32_t EntrySize = 0;
    uint32_t PointerSize = 0;
    bool Encoded = false;
    bool ContinueHandler = false;
    std::wstring SymbolProvenance;
};

struct KmonUserAddressEvidence
{
    KmonUserEvidenceKind Kind = KmonUserEvidenceKind::SnapshotInstructionPointer;
    uint64_t Address = 0;
    uint64_t RecordAddress = 0;
    uint64_t ModuleBase = 0;
    uint64_t AllocationBase = 0;
    uint32_t ThreadId = 0;
    uint32_t Protection = 0;
    uint32_t MemoryType = 0;
    uint32_t DebugRegister = 0;
    uint32_t DebugCondition = 0;
    bool OwnershipKnown = false;
    bool InLoaderModule = false;
    bool PrivateExecutable = false;
    bool GuardPage = false;
    bool RuntimeRangeObserved = false;
    std::wstring Provenance;
};

struct KmonUserCallbackCursor
{
    KmonUserEvidenceKind Kind = KmonUserEvidenceKind::TlsCallback;
    uint64_t ModuleBase = 0;
    uint64_t TableAddress = 0;
    uint64_t AfterRecord = 0;
};

struct KmonUserCallbackContinuation
{
    uint32_t ProcessId = 0;
    uint64_t CreateTime = 0;
    std::vector<KmonUserCallbackCursor> Cursors;
    bool Evicted = false;
};

struct KmonUserEvidenceOptions
{
    ProcessTriageTarget Target;
    std::vector<ProcessUserModuleRange> UserModules;
    bool UserModulesComplete = false;
    std::vector<ProcessVadRecord> VadRecords;
    bool VadCoverageComplete = false;
    std::wstring ImagePath;
    uint32_t MaxThreads = 64;
    uint32_t MaxModules = 16;
    uint32_t MaxCallbacks = 32;
    uint32_t ThreadCursor = 0;
    uint32_t KernelThreadCursor = 0;
    uint64_t ModuleCursor = 0;
    bool CaptureContexts = true;
    bool CollectKernelExecution = true;
    bool ResolveHandlerSymbols = true;
    std::vector<KmonVectoredHandlerLayout> HandlerLayouts;
    KmonUserRuntimeTracker* RuntimeTracker = nullptr;
    KmonUserCallbackContinuation* CallbackContinuation = nullptr;
};

struct KmonUserEvidenceResult
{
    uint32_t ProcessId = 0;
    uint64_t ProcessCreateTime = 0;
    uint32_t NextThreadCursor = 0;
    uint32_t NextKernelThreadCursor = 0;
    uint64_t NextModuleCursor = 0;
    KmonThreadSnapshot Snapshot;
    std::vector<KmonUserAddressEvidence> Addresses;
    std::vector<KmonRuntimeCodeRange> RuntimeRanges;
    KmonFileIdentity ImageIdentity;
    KmonEvidenceCoverage ApcCoverage;
    KmonEvidenceCoverage SavedContextCoverage;
    KmonEvidenceCoverage TlsCoverage;
    KmonEvidenceCoverage HandlerCoverage;
    KmonEvidenceCoverage FileCoverage;
    KmonEvidenceCoverage RuntimeCoverage;
    bool IdentityStable = false;
    bool CallbackCursorEvicted = false;
};

bool CollectKmonUserEvidence(
    DeviceClient& device,
    SymbolEngine& symbols,
    const KmonUserEvidenceOptions& options,
    KmonUserEvidenceResult* result,
    std::wstring* error);

bool KmonUserEvidenceSelfTest();
