#pragma once

#include <Windows.h>
#include <evntprov.h>

namespace handoff_events
{
    inline constexpr GUID Provider{0x4dc673b7, 0xfb3f, 0x4099, {0x95, 0x2a, 0x37, 0xda, 0xc2, 0x7c, 0xf1, 0x94}};
    constexpr size_t MaxPayload = 1024;
    constexpr DWORD MaxViews = 8;
    constexpr DWORD ViewSpacingMs = 5;

    inline bool SchedulingPayload(const GUID& provider, const EVENT_DESCRIPTOR& d)
    {
        if (!IsEqualGUID(provider, Provider) || d.Version != 2 || d.Opcode != 2 || d.Channel) { return false; }
        return (d.Id == 8 && d.Task == 4) || (d.Id == 10 && d.Task == 5) ||
               (d.Id == 19 && d.Task == 8) || (d.Id == 21 && d.Task == 9);
    }
}
