#pragma once

#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <string>
#include <vector>

struct ParserWorkerRequest
{
    std::wstring Executable;
    std::vector<std::wstring> Arguments;
    // At most three approved regular files. The runner reopens each read-only,
    // inherits only those copies, and appends their decimal handles to argv.
    // Caller retains the source leases until this synchronous call returns.
    std::vector<HANDLE> ReadOnlyFiles;
    uint64_t TimeoutMs = 60000;
    // Schema requests retain the 2 MiB default. Full symbol indexes explicitly
    // opt into a larger bounded frame, never more than 32 MiB.
    size_t OutputLimit = 2 * 1024 * 1024;
    const std::atomic<bool>* Cancellation = nullptr;
};

struct ParserWorkerResult
{
    std::wstring Status = L"unavailable";
    std::string Output;
    DWORD Error = ERROR_SUCCESS;
    DWORD ExitCode = STILL_ACTIVE;
    DWORD ProcessId = 0;
    uint64_t ElapsedMs = 0;
};

// Resource and privilege containment, not a filesystem or network sandbox.
ParserWorkerResult RunParserWorker(const ParserWorkerRequest& request);
bool IsRestrictedParserWorker();
