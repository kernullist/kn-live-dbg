#include "../user/HiddenProcessReport.h"

#include <iostream>
#include <string>

int wmain(int argc, wchar_t** argv)
{
    uint32_t checks = 0;
    if (!HiddenProcessPolicySelfTest(&checks))
    {
        std::wcerr << L"hidden-process policy controls failed\n";
        return 1;
    }
    if (argc == 1)
    {
        std::wcout << L"hidden-process policy controls passed: " << checks << L"\n";
        return 0;
    }
    if (argc != 2 || std::wstring(argv[1]) != L"--json")
    {
        return 2;
    }
    HiddenProcessScanResult result;
    result.InventoryComplete = true;
    result.CoverageComplete = true;
    result.Warnings.push_back(L"synthetic \"warning\"\nwith newline");
    for (uint32_t i = 0; i < 7; ++i)
    {
        HiddenProcessRecord record;
        record.ProcessId = 100 + i;
        record.ImageName = L"fixture.exe";
        record.InCidTable = true;
        auto& q = record.Qualification;
        q.Attempted = true;
        q.KernelComplete = true;
        q.SpiComplete = true;
        q.ToolhelpComplete = true;
        q.Before.Pid = record.ProcessId;
        q.Before.Eprocess = 0xffff800000010000ull + i * 0x1000;
        q.Before.CreateTime = 123456 + i;
        q.Before.IdentityValid = true;
        q.Before.HasActiveThreads = true;
        q.Before.ActiveThreads = 4;
        q.Before.HasExitTime = true;
        q.Before.HasAuxiliary = true;
        q.Before.HasStateFlags = true;
        q.After = q.Before;
        if (i == 1)
        {
            q.After.HasExitTime = false;
        }
        else if (i == 2)
        {
            ++q.After.CreateTime;
        }
        else if (i == 3)
        {
            q.After.ExitTime = 999;
        }
        else if (i == 4)
        {
            q.Views.Kernel = true;
            q.Views.Spi = true;
            q.KernelIdentity = {q.Before.Eprocess, q.Before.CreateTime, true};
        }
        else if (i == 5)
        {
            q.Views.Kernel = true;
            q.KernelIdentity = {q.Before.Eprocess, q.Before.CreateTime, true};
            q.Before.Auxiliary = q.After.Auxiliary = true;
        }
        else if (i == 6)
        {
            q.BudgetExceeded = true;
            q.After.IdentityValid = false;
        }
        AddHiddenProcessDecision(result, std::move(record));
    }
    std::wcout << BuildHiddenProcessJson(result) << L"\n";
    return 0;
}
