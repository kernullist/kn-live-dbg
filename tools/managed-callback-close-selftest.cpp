#include "../user/DeviceClient.h"
#include <fltUser.h>
#include <atomic>
#include <iostream>
#include <thread>

// Component race test using the real provider port and a harmless NUL device
// handle. Full controller/KnLiveDbg.sys lifecycle is tested by the Python E2E.
int wmain()
{
    HANDLE observer = INVALID_HANDLE_VALUE;
    if (FAILED(FilterConnectCommunicationPort(KNDBG_MANAGED_CALLBACK_PORT, 0,
            nullptr, 0, nullptr, &observer)))
    {
        std::cerr << "the owned test provider must be loaded\n";
        return 1;
    }
    const auto query = [&](KNDBG_MANAGED_CALLBACK_STATUS* status)
    {
        KNDBG_MANAGED_CALLBACK_REQUEST request = {};
        request.Magic = KNDBG_MANAGED_CALLBACK_MAGIC;
        request.Version = KNDBG_MANAGED_CALLBACK_VERSION;
        request.Size = sizeof(request);
        DWORD returned = 0;
        return SUCCEEDED(FilterSendMessage(observer, &request, sizeof(request),
            status, sizeof(*status), &returned)) && returned == sizeof(*status);
    };
    unsigned passed = 0;
    for (unsigned cycle = 0; cycle < 100; ++cycle)
    {
        KNDBG_MANAGED_CALLBACK_STATUS baseline = {};
        if (!query(&baseline) || baseline.OwnerPid != 0 || baseline.EnabledMask != 3) break;
        DeviceClient client;
        std::wstring error;
        KNDBG_MANAGED_CALLBACK_STATUS state = {};
        if (!client.Open(L"NUL", &error) ||
            !client.ControlManagedCallbacks(KNDBG_MANAGED_DISABLE, 3, baseline.Filter, &state, &error)) break;
        std::atomic<unsigned> started{0}, bad{0};
        std::atomic<bool> closed{false};
        std::thread readers[4];
        for (auto& reader : readers)
        {
            reader = std::thread([&]()
            {
                ++started;
                for (unsigned index = 0; index < 200; ++index)
                {
                    const bool afterClose = closed.load();
                    KNDBG_MANAGED_CALLBACK_STATUS observed = {};
                    if (client.ControlManagedCallbacks(KNDBG_MANAGED_QUERY, 0, 0, &observed, nullptr) && afterClose)
                        ++bad;
                }
            });
        }
        while (started.load() != 4) SwitchToThread();
        client.Close();
        closed.store(true);
        for (auto& reader : readers) reader.join();
        if (bad.load() != 0 || client.IsOpen() || !query(&state) ||
            state.Connections != baseline.Connections || state.OwnerPid != 0 || state.EnabledMask != 3)
        {
            std::cerr << "close left a reopened port, active lease, or successful late request\n";
            break;
        }
        ++passed;
    }
    CloseHandle(observer);
    std::cout << "[managed-close.selftest] passed=" << passed << " expected=100\n";
    return passed == 100 ? 0 : 1;
}
