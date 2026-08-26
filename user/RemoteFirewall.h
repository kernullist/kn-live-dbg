#pragma once

#include <string>
#include <cstdint>

bool AddRemoteFirewallRule(
    uint16_t port,
    const std::wstring& remoteAddress,
    std::wstring* error);

void RemoveRemoteFirewallRule();
