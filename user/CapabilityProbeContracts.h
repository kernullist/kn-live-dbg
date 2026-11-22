#pragma once

#include <string>
#include <string_view>

namespace capability_probes
{
    struct Contract
    {
        const wchar_t* Id;
        const wchar_t* Selector;
        const wchar_t* Arguments;
        const wchar_t* AvailabilityScope;
        const wchar_t* Observation;
    };

    inline constexpr auto LiveSelector = L"--probe";
    inline constexpr Contract OwnedRead{L"owned_read", LiveSelector, L"", L"owned_control_range_only",
        L"Reads and compares a known 32-byte range in the collector process."};
    inline constexpr Contract NativeConnection{L"native_connection", LiveSelector, L"", L"connection_contract_only",
        L"Checks the existing device connection, ABI and session. Native operations require separate evidence."};
    inline constexpr Contract SavedEtl{L"saved_etl_family", L"--probe-etl", L"<local.etl> --sha256 <digest>", L"supplied_etl_record_family",
        L"Checks the decoded layout and records of one event family in a pinned ETL."};
    inline constexpr Contract SavedDump{L"saved_dump_range", L"--probe-dump",
        L"<local.dmp> --header-sha256 <digest> [--range <hex-va> <1..4096>] [--expect-sha256 <digest>]", L"supplied_dump_virtual_range",
        L"Reads one virtual range in a header-pinned full dump. The default module list head also checks reciprocal links."};
    inline constexpr const Contract* All[] = {&OwnedRead, &NativeConnection, &SavedEtl, &SavedDump};

    inline const Contract* For(std::wstring_view domain, std::wstring_view operation, std::wstring_view backend)
    {
        if (backend == L"native") { return &NativeConnection; }
        if (domain == L"memory" && operation == L"read_virtual")
        {
            if (backend == L"process_handle") { return &OwnedRead; }
            if (backend == L"dump") { return &SavedDump; }
        }
        if (backend == L"etl" && domain == L"execution" && (operation == L"cpu_profile" || operation == L"context_switch")) { return &SavedEtl; }
        return nullptr;
    }

    inline std::wstring Invocation(const Contract& contract)
    {
        auto result = std::wstring(L"--capabilities ") + contract.Selector;
        if (*contract.Arguments) { result += L' '; result += contract.Arguments; }
        return result;
    }
}
