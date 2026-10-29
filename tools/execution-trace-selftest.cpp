#include "../user/ExecutionTrace.h"

#include <iostream>

int wmain(int argc, wchar_t** argv)
{
    if (argc == 2 && std::wstring(argv[1]) == L"--cancel-check")
    {
        std::atomic<bool> stop{true};
        ExecutionTrace trace;
        trace.SourceId = L"stale";
        std::wstring error;
        if (ParseExecutionTrace(L"{}", &trace, &error, &stop) || !trace.SourceId.empty() ||
            error.find(L"cancelled") == std::wstring::npos)
        {
            return 1;
        }
        return 0;
    }
    if (argc < 4 || std::wstring(argv[1]) != L"--offline" || std::wstring(argv[2]) != L"!kmon" ||
        std::wstring(argv[3]) != L"trace")
    {
        return 2;
    }
    return RunExecutionTraceCommand(std::vector<std::wstring>(argv + 4, argv + argc));
}
