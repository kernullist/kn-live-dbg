#include "../user/PendingIrpReport.h"

#include <iostream>

int wmain(int argc, wchar_t** argv)
{
    if (argc > 2 || (argc == 2 && std::wstring(argv[1]) != L"--json"))
    {
        return 2;
    }
    uint32_t checks = 0;
    PendingIrpScanResult fixture;
    if (!PendingIrpScannerSelfTest(&checks, &fixture))
    {
        std::wcerr << L"pending IRP controls failed\n";
        return 1;
    }
    if (argc == 1)
    {
        std::wcout << L"pending IRP snapshot controls passed: " << checks <<
            L"; existing pagination, churn and owner-generation controls passed\n";
        return 0;
    }
    auto empty = fixture.Requests.front();
    empty.Stacks.clear();
    fixture.Requests.push_back(empty);
    auto capped = fixture.Requests.front();
    capped.Stacks.resize(65, capped.Stacks.front());
    fixture.Requests.push_back(capped);
    std::wcout << L"[";
    for (size_t i = 0; i < fixture.Requests.size(); ++i)
    {
        if (i != 0)
        {
            std::wcout << L",";
        }
        std::wcout << PendingIrpObservationJson(fixture.Requests[i], fixture);
    }
    std::wcout << L"]\n";
    return 0;
}
