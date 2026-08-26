#include "RemoteFirewall.h"

#include <Windows.h>
#include <netfw.h>
#include <oleauto.h>

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

        hr = rules->Item(name, &existing);
        if (SUCCEEDED(hr) && existing != nullptr)
        {
            rules->Remove(name);
            existing->Release();
            existing = nullptr;
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

        rule->put_Name(name);
        rule->put_Description(desc);
        rule->put_Protocol(NET_FW_IP_PROTOCOL_TCP);
        rule->put_LocalPorts(ports);
        rule->put_RemoteAddresses(remote);
        rule->put_Direction(NET_FW_RULE_DIR_IN);
        rule->put_Action(NET_FW_ACTION_ALLOW);
        rule->put_Enabled(VARIANT_TRUE);
        rule->put_Profiles(
            NET_FW_PROFILE2_DOMAIN | NET_FW_PROFILE2_PRIVATE | NET_FW_PROFILE2_PUBLIC);

        hr = rules->Add(rule);
        SysFreeString(name);
        SysFreeString(ports);
        SysFreeString(remote);
        SysFreeString(desc);
        if (FAILED(hr))
        {
            if (error != nullptr)
            {
                *error = L"INetFwRules.Add failed";
            }
            break;
        }

        ok = true;
    } while (false);

    ReleaseFw(rule);
    ReleaseFw(existing);
    ReleaseFw(rules);
    ReleaseFw(policy);
    if (hrInit == S_OK)
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
    if (hrInit == S_OK)
    {
        CoUninitialize();
    }
}
