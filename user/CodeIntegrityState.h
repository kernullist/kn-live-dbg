#pragma once

#include <Windows.h>
#include <winternl.h>

#include <cstdint>

namespace codeintegrity
{
    inline constexpr wchar_t kSource[] = L"NtQuerySystemInformation(SystemCodeIntegrityInformation=103)";
    inline constexpr uint32_t kKnownOptions = 0x3fffu;

    struct State
    {
        uint32_t Raw = 0;
        uint32_t UnknownOptions = 0;
        uint32_t NtStatus = 0xc000007au; // STATUS_PROCEDURE_NOT_FOUND until queried.
        uint32_t ReturnedLength = 0;
        bool QueryAvailable = false;
        bool Resolved = false;
        bool CodeIntegrityEnabled = false;
        bool TestSign = false;
        bool UmciEnabled = false;
        bool UmciAuditMode = false;
        bool UmciExclusionPaths = false;
        bool TestBuild = false;
        bool PreproductionBuild = false;
        bool DebugMode = false;
        bool FlightBuild = false;
        bool FlightingEnabled = false;
        bool HvciEnabled = false;
        bool HvciAuditMode = false;
        bool HvciStrictMode = false;
        bool HvciIumEnabled = false;
    };

    using QueryFunction = NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

    // These are the public SYSTEM_CODEINTEGRITY_INFORMATION flags. Private
    // ci!g_CiOptions/nt!CiOptions values are a different contract, not a fallback.
    inline State Query(QueryFunction query)
    {
        State state;
        if (query == nullptr)
        {
            return state;
        }
        state.QueryAvailable = true;
        SYSTEM_CODEINTEGRITY_INFORMATION information = {};
        information.Length = sizeof(information);
        ULONG returned = 0;
        const NTSTATUS status = query(static_cast<SYSTEM_INFORMATION_CLASS>(103),
            &information, sizeof(information), &returned);
        state.NtStatus = static_cast<uint32_t>(status);
        state.ReturnedLength = returned;
        if (status < 0 || returned != sizeof(information) || information.Length != sizeof(information))
        {
            return state;
        }

        const ULONG flags = information.CodeIntegrityOptions;
        state.Raw = flags;
        state.UnknownOptions = flags & ~kKnownOptions;
        state.Resolved = true;
        state.CodeIntegrityEnabled = (flags & CODEINTEGRITY_OPTION_ENABLED) != 0;
        state.TestSign = (flags & CODEINTEGRITY_OPTION_TESTSIGN) != 0;
        state.UmciEnabled = (flags & CODEINTEGRITY_OPTION_UMCI_ENABLED) != 0;
        state.UmciAuditMode = (flags & CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED) != 0;
        state.UmciExclusionPaths = (flags & CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED) != 0;
        state.TestBuild = (flags & CODEINTEGRITY_OPTION_TEST_BUILD) != 0;
        state.PreproductionBuild = (flags & CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD) != 0;
        state.DebugMode = (flags & CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED) != 0;
        state.FlightBuild = (flags & CODEINTEGRITY_OPTION_FLIGHT_BUILD) != 0;
        state.FlightingEnabled = (flags & CODEINTEGRITY_OPTION_FLIGHTING_ENABLED) != 0;
        state.HvciEnabled = (flags & CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED) != 0;
        state.HvciAuditMode = (flags & CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED) != 0;
        state.HvciStrictMode = (flags & CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED) != 0;
        state.HvciIumEnabled = (flags & CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED) != 0;
        return state;
    }

    inline State Query()
    {
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        const auto query = ntdll == nullptr ? nullptr : reinterpret_cast<QueryFunction>(
            GetProcAddress(ntdll, "NtQuerySystemInformation"));
        return Query(query);
    }
}
