#include "RemoteFirewall.h"

#include <Windows.h>
#include <netfw.h>
#include <oleauto.h>
#include <thread>

namespace
{
    const wchar_t kRuleName[] = L"knlivedbg-remote";

    void ReleaseFw(IUnknown* object)
    {
        if (object != nullptr)
        {
            object->Release();
        }
    }

    HRESULT ConfigureFirewallRule(INetFwRule* rule, BSTR name, BSTR ports, BSTR remote, BSTR description)
    {
        HRESULT status = rule->put_Name(name);
        if (SUCCEEDED(status))
        {
            status = rule->put_Description(description);
        }
        if (SUCCEEDED(status))
        {
            status = rule->put_Protocol(NET_FW_IP_PROTOCOL_TCP);
        }
        if (SUCCEEDED(status))
        {
            status = rule->put_LocalPorts(ports);
        }
        if (SUCCEEDED(status))
        {
            status = rule->put_RemoteAddresses(remote);
        }
        if (SUCCEEDED(status))
        {
            status = rule->put_Direction(NET_FW_RULE_DIR_IN);
        }
        if (SUCCEEDED(status))
        {
            status = rule->put_Action(NET_FW_ACTION_ALLOW);
        }
        if (SUCCEEDED(status))
        {
            status = rule->put_Enabled(VARIANT_TRUE);
        }
        if (SUCCEEDED(status))
        {
            status = rule->put_Profiles(NET_FW_PROFILE2_DOMAIN | NET_FW_PROFILE2_PRIVATE | NET_FW_PROFILE2_PUBLIC);
        }
        return status;
    }
}

bool AddRemoteFirewallRule(
    uint16_t port,
    const std::wstring& remoteAddress,
    std::wstring* error)
{
    bool ok = false;
    HRESULT hrInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    INetFwPolicy2* policy = nullptr;
    INetFwRules* rules = nullptr;
    INetFwRule* existing = nullptr;
    INetFwRule* rule = nullptr;

    do
    {
        if (port == 0)
        {
            if (error != nullptr)
            {
                *error = L"invalid firewall port";
            }
            break;
        }

        HRESULT hr = CoCreateInstance(
            __uuidof(NetFwPolicy2),
            nullptr,
            CLSCTX_INPROC_SERVER,
            __uuidof(INetFwPolicy2),
            reinterpret_cast<void**>(&policy));
        if (FAILED(hr) || policy == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"CoCreateInstance NetFwPolicy2 failed";
            }
            break;
        }

        hr = policy->get_Rules(&rules);
        if (FAILED(hr) || rules == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"INetFwPolicy2.get_Rules failed";
            }
            break;
        }

        BSTR name = SysAllocString(kRuleName);
        if (name == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"SysAllocString failed";
            }
            break;
        }

        hr = CoCreateInstance(
            __uuidof(NetFwRule),
            nullptr,
            CLSCTX_INPROC_SERVER,
            __uuidof(INetFwRule),
            reinterpret_cast<void**>(&rule));
        if (FAILED(hr) || rule == nullptr)
        {
            SysFreeString(name);
            if (error != nullptr)
            {
                *error = L"CoCreateInstance NetFwRule failed";
            }
            break;
        }

        BSTR ports = SysAllocString(std::to_wstring(port).c_str());
        BSTR remote = SysAllocString(
            remoteAddress.empty() ? L"*" : remoteAddress.c_str());
        BSTR desc = SysAllocString(L"KnLiveDbg remote operator session");
        if (ports == nullptr || remote == nullptr || desc == nullptr)
        {
            SysFreeString(name);
            SysFreeString(ports);
            SysFreeString(remote);
            SysFreeString(desc);
            if (error != nullptr)
            {
                *error = L"SysAllocString failed";
            }
            break;
        }

        hr = ConfigureFirewallRule(rule, name, ports, remote, desc);
        if (SUCCEEDED(hr))
        {
            const HRESULT found = rules->Item(name, &existing);
            if (SUCCEEDED(found) && existing != nullptr)
            {
                hr = rules->Remove(name);
            }
        }
        if (SUCCEEDED(hr))
        {
            hr = rules->Add(rule);
        }
        SysFreeString(name);
        SysFreeString(ports);
        SysFreeString(remote);
        SysFreeString(desc);
        if (FAILED(hr))
        {
            if (error != nullptr)
            {
                *error = L"firewall rule configuration or publication failed";
            }
            break;
        }

        ok = true;
    } while (false);

    ReleaseFw(rule);
    ReleaseFw(existing);
    ReleaseFw(rules);
    ReleaseFw(policy);
    if (SUCCEEDED(hrInit))
    {
        CoUninitialize();
    }
    return ok;
}

void RemoveRemoteFirewallRule()
{
    HRESULT hrInit = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    INetFwPolicy2* policy = nullptr;
    INetFwRules* rules = nullptr;

    do
    {
        HRESULT hr = CoCreateInstance(
            __uuidof(NetFwPolicy2),
            nullptr,
            CLSCTX_INPROC_SERVER,
            __uuidof(INetFwPolicy2),
            reinterpret_cast<void**>(&policy));
        if (FAILED(hr) || policy == nullptr)
        {
            break;
        }
        hr = policy->get_Rules(&rules);
        if (FAILED(hr) || rules == nullptr)
        {
            break;
        }
        BSTR name = SysAllocString(kRuleName);
        if (name == nullptr)
        {
            break;
        }
        rules->Remove(name);
        SysFreeString(name);
    } while (false);

    ReleaseFw(rules);
    ReleaseFw(policy);
    if (SUCCEEDED(hrInit))
    {
        CoUninitialize();
    }
}

bool RemoteFirewallSelfTest()
{
    bool passed = false;
    std::thread isolated([&]()
    {
        const HRESULT first = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
        if (FAILED(first))
        {
            return;
        }
        std::wstring error;
        // Port zero fails before policy access and must balance S_FALSE too.
        const bool invalidRejected = !AddRemoteFirewallRule(0, L"", &error);
        CoUninitialize();
        const HRESULT second = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(second))
        {
            CoUninitialize();
            return;
        }
        INetFwRule* rule = nullptr;
        const HRESULT created = CoCreateInstance(__uuidof(NetFwRule), nullptr, CLSCTX_INPROC_SERVER,
            __uuidof(INetFwRule), reinterpret_cast<void**>(&rule));
        BSTR name = SysAllocString(L"KnLiveDbg self-test unpublished rule");
        BSTR ports = SysAllocString(L"51767");
        BSTR remote = SysAllocString(L"invalid[address");
        BSTR description = SysAllocString(L"Unpublished fixture");
        if (invalidRejected && SUCCEEDED(created) && rule != nullptr && name != nullptr &&
            ports != nullptr && remote != nullptr && description != nullptr)
        {
            // This object is never passed to INetFwRules::Add.
            passed = FAILED(ConfigureFirewallRule(rule, name, ports, remote, description));
        }
        SysFreeString(name);
        SysFreeString(ports);
        SysFreeString(remote);
        SysFreeString(description);
        ReleaseFw(rule);
        CoUninitialize();
    });
    isolated.join();
    return passed;
}
