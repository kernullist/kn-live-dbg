#pragma once
#include "KmonUserModuleDebt.h"
#include <TlHelp32.h>
#include <atomic>
#include <limits>
#include <memory>

inline bool IsUserModeImageBase(uint64_t address)
{
    return address >= 0x10000ull && address <= 0x00007FFFFFFEFFFFull;
}

inline bool KmonUserModuleRangeValid(uint64_t base, uint64_t size)
{
    return IsUserModeImageBase(base) && size != 0 &&
        size - 1 <= (std::numeric_limits<uint64_t>::max)() - base &&
        IsUserModeImageBase(base + size - 1);
}

inline bool KmonUserModuleWalkComplete(
    size_t count,
    bool more,
    bool rangesValid,
    DWORD terminalError)
{
    return count != 0 && !more && rangesValid && terminalError == ERROR_NO_MORE_FILES;
}

inline bool KmonUserSnapshotGenerationMatches(
    uint64_t inventoryGeneration,
    uint64_t beforeSnapshot,
    uint64_t afterSnapshot,
    bool processPinned)
{
    return processPinned && beforeSnapshot != 0 &&
        afterSnapshot == beforeSnapshot &&
        (inventoryGeneration == 0 || inventoryGeneration == beforeSnapshot);
}

struct KmonNativeModuleAttempt
{
    KmonUserModuleDebt& Debt;
    KmonUserModuleDebt::Attempt Visit;
    KmonNativeModuleAttempt(KmonUserModuleDebt& debt, KmonUserModuleDebt::Key target, bool loan)
        : Debt(debt), Visit(debt.Begin(target, GetTickCount64(), loan)) {}
    ~KmonNativeModuleAttempt() { if (!Visit.Closed) { Fail(KmonModuleResult::Fault); } }
    void Fail(KmonModuleResult reason, DWORD error = 0) { Debt.Fail(Visit, reason, GetTickCount64(), error); }
};

constexpr size_t kMaxToolhelpModuleRows = 1024;
struct KmonUserModuleView
{
    uint64_t Base = 0, AfterGeneration = 0;
    size_t Rows = 0;
    DWORD Error = ERROR_SUCCESS;
    bool Complete = false, Stable = false, Stopped = false;
    std::vector<std::wstring> Paths;
    std::vector<std::pair<uint64_t, uint32_t>> Ranges;
};

template<class ReadGeneration, class MatchesImage>
KmonUserModuleView KmonReadFencedUserModules(KmonNativeModuleAttempt& attempt,
    const KmonUserTarget& target, uint64_t before, HANDLE process, const std::atomic<bool>& stop,
    ReadGeneration readGeneration, MatchesImage matchesImage)
{
    KmonUserModuleView view;
    view.Stopped = stop.load();
    const HANDLE handle = view.Stopped ? INVALID_HANDLE_VALUE :
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, target.Pid);
    if (handle == INVALID_HANDLE_VALUE) { view.Error = view.Stopped ? ERROR_CANCELLED : GetLastError(); }
    else
    {
        const std::unique_ptr<void, decltype(&CloseHandle)> owner(handle, &CloseHandle);
        MODULEENTRY32W row{}; row.dwSize = sizeof(row);
        BOOL more = Module32FirstW(handle, &row);
        bool rangesValid = true;
        while (more)
        {
            if (stop.load()) { view.Stopped = true; view.Error = ERROR_CANCELLED; break; }
            if (view.Rows == kMaxToolhelpModuleRows) { view.Error = ERROR_MORE_DATA; break; }
            ++view.Rows;
            const auto base = reinterpret_cast<uint64_t>(row.modBaseAddr);
            if (!KmonUserModuleRangeValid(base, row.modBaseSize))
            { rangesValid = false; view.Error = ERROR_INVALID_DATA; break; }
            if (!view.Base && matchesImage(row))
            { view.Base = base; }
            view.Paths.emplace_back(row.szExePath);
            view.Ranges.emplace_back(base, row.modBaseSize);
            row.dwSize = sizeof(row);
            more = Module32NextW(handle, &row);
        }
        if (!more) { view.Error = GetLastError(); }
        view.Complete = KmonUserModuleWalkComplete(view.Rows, more != FALSE, rangesValid, view.Error);
    }
    view.AfterGeneration = readGeneration(process, target.Pid);
    view.Stable = KmonUserSnapshotGenerationMatches(target.CreateTime, before, view.AfterGeneration, process != nullptr);
    view.Stopped = view.Stopped || stop.load();
    if (!view.Stable)
    {
        attempt.Fail(view.AfterGeneration && before && process ? KmonModuleResult::GenerationChanged :
            KmonModuleResult::IdentityUnavailable);
    }
    else
    {
        attempt.Debt.ConcludeWalk(attempt.Visit, view.AfterGeneration, view.Complete, view.Error, view.Stopped, GetTickCount64());
    }
    return view;
}
