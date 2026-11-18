#pragma once

#include <Windows.h>
#include <array>
#include <cstdint>
#include <vector>

enum class ProcessHandleSite
{
    SelfProbe, IdentityLookup, ObservationSource, TiImageLookup, KmonUserInventory, HuntPublicDetails, HuntPackageIdentity,
    LayoutCollection, LayoutVerification, ImageSweep, ReferenceVerification, PageCapture, DiagnosticIdentity
};
enum class ProcessHandleCall { Open, Duplicate, Close };

struct ProcessHandleIdentity
{
    DWORD Pid = 0, Error = 0;
    uint64_t Created = 0;
};

inline uint64_t ProcessHandleFileTime(FILETIME value)
{
    return (uint64_t{value.dwHighDateTime} << 32) | value.dwLowDateTime;
}

inline ProcessHandleIdentity ReadProcessHandleIdentity(HANDLE handle, DWORD expectedPid = 0)
{
    ProcessHandleIdentity result;
    result.Pid = GetProcessId(handle);
    if (!result.Pid) { result.Error = GetLastError(); return result; }
    if (expectedPid && result.Pid != expectedPid) { return result; }
    FILETIME created{}, exited{}, kernel{}, user{};
    if (GetProcessTimes(handle, &created, &exited, &kernel, &user)) { result.Created = ProcessHandleFileTime(created); }
    else { result.Error = GetLastError(); }
    return result;
}

struct ProcessHandleAction
{
    uint64_t Sequence = 0, AcquisitionId = 0, ParentAcquisitionId = 0;
    uint64_t RequestedUtc = 0, ReturnedUtc = 0, RequestedCreation = 0;
    DWORD RequestedPid = 0, DesiredAccess = 0, Status = 0;
    ProcessHandleSite Site{};
    ProcessHandleCall Call{};
    bool Succeeded = false;
    ProcessHandleIdentity Bound;
};

struct ProcessHandleSnapshot
{
    uint64_t Total = 0, Acquired = 0, Closed = 0, ControllerCreateTime = 0;
    DWORD ControllerPid = 0;
    std::vector<ProcessHandleAction> Actions;
};

class ProcessHandleJournal
{
public:
    ProcessHandleJournal() = default;
    ProcessHandleJournal(const ProcessHandleJournal&) = delete;
    ProcessHandleJournal& operator=(const ProcessHandleJournal&) = delete;

    void Record(ProcessHandleAction& action) noexcept
    {
        AcquireSRWLockExclusive(&Lock);
        action.Sequence = ++Total;
        if (action.Succeeded)
        {
            if (action.Call == ProcessHandleCall::Close) { ++Closed; }
            else { action.AcquisitionId = action.Sequence; ++Acquired; }
        }
        Rows[(action.Sequence - 1) % Rows.size()] = action;
        ReleaseSRWLockExclusive(&Lock);
    }

    ProcessHandleSnapshot Snapshot() const
    {
        ProcessHandleSnapshot snapshot;
        decltype(Rows) retained;
        AcquireSRWLockShared(&Lock);
        snapshot.Total = Total;
        snapshot.Acquired = Acquired;
        snapshot.Closed = Closed;
        const size_t count = static_cast<size_t>(Total < Rows.size() ? Total : Rows.size());
        for (size_t i = 0; i < count; ++i) { retained[i] = Rows[(Total - count + i) % Rows.size()]; }
        ReleaseSRWLockShared(&Lock);
        if (count)
        {
            snapshot.Actions.assign(retained.begin(), retained.begin() + count);
            snapshot.ControllerPid = GetCurrentProcessId();
            snapshot.ControllerCreateTime = ReadProcessHandleIdentity(GetCurrentProcess()).Created;
        }
        return snapshot;
    }

private:
    mutable SRWLOCK Lock = SRWLOCK_INIT;
    std::array<ProcessHandleAction, 64> Rows{};
    uint64_t Total = 0, Acquired = 0, Closed = 0;
};

inline ProcessHandleJournal& ControllerProcessHandles()
{
    static ProcessHandleJournal journal;
    return journal;
}

// Retain the acquisition ID and the identity reported by the handle.
// The journal never stores the Windows handle value.
class ObservedProcessHandle
{
public:
    ObservedProcessHandle(ProcessHandleJournal& journal, ProcessHandleSite site, DWORD pid, uint64_t creation = 0)
        : Journal(journal)
    {
        Acquired.Site = site;
        Acquired.RequestedPid = pid;
        Acquired.RequestedCreation = creation;
    }
    ObservedProcessHandle(const ObservedProcessHandle&) = delete;
    ObservedProcessHandle& operator=(const ObservedProcessHandle&) = delete;

    ~ObservedProcessHandle()
    {
        if (!Value) { return; }
        auto close = Acquired;
        close.Call = ProcessHandleCall::Close;
        const DWORD prior = GetLastError();
        close.RequestedUtc = Now();
        SetLastError(prior);
        close.Succeeded = CloseHandle(Value) != FALSE;
        const DWORD last = GetLastError();
        close.ReturnedUtc = Now();
        close.Status = close.Succeeded ? ERROR_SUCCESS : last;
        Journal.Record(close);
        SetLastError(last);
    }

    bool Open(DWORD desiredAccess)
    {
        return Acquire(ProcessHandleCall::Open, desiredAccess, 0, [&] {
            Value = OpenProcess(desiredAccess, FALSE, Acquired.RequestedPid);
            return Value != nullptr;
        });
    }
    HANDLE OpenForVmReadOrLimitedQuery(DWORD* readOpenError = nullptr)
    {
        if (readOpenError) { *readOpenError = ERROR_SUCCESS; }
        if (!Acquired.RequestedPid) { return nullptr; }
        if (!Open(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ))
        {
            if (readOpenError) { *readOpenError = GetLastError(); }
            if (!Open(PROCESS_QUERY_LIMITED_INFORMATION)) { return nullptr; }
        }
        return Value;
    }
    bool ConflictsWithRequestedIdentity() const
    {
        return (Acquired.Bound.Pid && Acquired.Bound.Pid != Acquired.RequestedPid) ||
            (Acquired.RequestedCreation && Acquired.Bound.Created && Acquired.RequestedCreation != Acquired.Bound.Created);
    }
    bool Duplicate(HANDLE source, uint64_t parentAcquisition = 0)
    {
        return Acquire(ProcessHandleCall::Duplicate, 0, parentAcquisition, [&] {
            return DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), &Value, 0, FALSE, DUPLICATE_SAME_ACCESS) != FALSE;
        });
    }
    HANDLE get() const { return Value; }
    const ProcessHandleAction& Acquisition() const { return Acquired; }

private:
    static uint64_t Now()
    {
        FILETIME value{};
        GetSystemTimePreciseAsFileTime(&value);
        return ProcessHandleFileTime(value);
    }
    template <typename Call>
    bool Acquire(ProcessHandleCall kind, DWORD desiredAccess, uint64_t parent, Call call)
    {
        if (Value) { SetLastError(ERROR_ALREADY_INITIALIZED); return false; }
        const DWORD prior = GetLastError();
        Acquired.Call = kind;
        Acquired.DesiredAccess = desiredAccess;
        Acquired.ParentAcquisitionId = parent;
        Acquired.RequestedUtc = Now();
        SetLastError(prior);
        Acquired.Succeeded = call();
        const DWORD last = GetLastError();
        Acquired.ReturnedUtc = Now();
        Acquired.Status = Acquired.Succeeded ? ERROR_SUCCESS : last;
        if (Acquired.Succeeded) { Acquired.Bound = ReadProcessHandleIdentity(Value, Acquired.RequestedPid); }
        else { Value = nullptr; }
        Journal.Record(Acquired);
        SetLastError(last);
        return Acquired.Succeeded;
    }
    ProcessHandleJournal& Journal;
    ProcessHandleAction Acquired{};
    HANDLE Value = nullptr;
};
