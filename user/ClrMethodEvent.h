#pragma once

#include <windows.h>
#include <evntcons.h>

#include <cstdint>
#include <cstring>
#include <optional>

inline constexpr GUID kClrRuntime = {0xe13c0d23, 0xccbc, 0x4e12, {0x93, 0x1b, 0xd9, 0xcc, 0x2e, 0xee, 0x27, 0xe4}};
inline constexpr GUID kClrRundown = {0xa669021c, 0xc450, 0x4609, {0xa0, 0x35, 0x5a, 0xf5, 0x9a, 0xf4, 0xdf, 0x18}};

enum class ClrMethodAction
{
    Ignore,
    Unsupported,
    Load,
    Unload,
    Rundown
};

struct KmonRuntimeCodeRange
{
    uint64_t Start = 0;
    uint64_t Size = 0;
    uint64_t MethodId = 0;
    uint64_t ModuleId = 0;
    uint64_t Timestamp = 0;
    std::optional<uint16_t> RuntimeInstance;
    uint32_t MethodFlags = 0;
    uint32_t MethodToken = 0;
    std::optional<uint64_t> ReJitId;
    uint16_t EventId = 0;
    uint8_t EventVersion = 0;
    bool RundownProvider = false;
    ClrMethodAction Observation = ClrMethodAction::Ignore;
};

inline bool SameClrMethodRange(const KmonRuntimeCodeRange& a, const KmonRuntimeCodeRange& b)
{
    return a.Start == b.Start && a.Size == b.Size && a.MethodId == b.MethodId && a.ModuleId == b.ModuleId &&
        a.MethodToken == b.MethodToken && a.MethodFlags == b.MethodFlags &&
        a.RuntimeInstance == b.RuntimeInstance && a.ReJitId == b.ReJitId;
}

inline ClrMethodAction ClassifyClrMethodEvent(const EVENT_HEADER& header)
{
    const auto& descriptor = header.EventDescriptor;
    const bool rundown = IsEqualGUID(header.ProviderId, kClrRundown) != FALSE;
    if (!rundown && !IsEqualGUID(header.ProviderId, kClrRuntime))
    {
        return ClrMethodAction::Ignore;
    }
    const auto id = descriptor.Id;
    if (id < (rundown ? 141 : 137) || id > 144)
    {
        return ClrMethodAction::Ignore;
    }

    // The runtime's legacy DC events exist only in v0. Both ends of a DC
    // enumeration describe present methods, including the end rundown.
    constexpr uint8_t runtimeOpcodes[] = {35, 36, 39, 40, 33, 34, 37, 38};
    constexpr uint8_t rundownOpcodes[] = {35, 36, 39, 40};
    const uint8_t expectedOpcode = rundown ? rundownOpcodes[id - 141] : runtimeOpcodes[id - 137];
    if (descriptor.Version > (id < 141 ? 0 : 2) || descriptor.Task != (rundown ? 1 : 9) ||
        descriptor.Opcode != expectedOpcode ||
        (header.Flags & (EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_TRACE_MESSAGE | EVENT_HEADER_FLAG_STRING_ONLY)) != 0)
    {
        return ClrMethodAction::Unsupported;
    }
    if (rundown || id < 141)
    {
        return ClrMethodAction::Rundown;
    }
    return (id == 141 || id == 143) ? ClrMethodAction::Load : ClrMethodAction::Unload;
}

// ClrEtwAll.man uses fixed-width integer fields on both x86 and x64.
// Verbose records insert exactly three terminated UTF-16 strings before
// the optional version suffix. Names are unnecessary for range identity.
inline ClrMethodAction ReadClrMethodRange(const EVENT_RECORD& event, KmonRuntimeCodeRange& result)
{
    const auto action = ClassifyClrMethodEvent(event.EventHeader);
    if (action == ClrMethodAction::Ignore || action == ClrMethodAction::Unsupported)
    {
        return action;
    }
    if (event.UserData == nullptr || event.UserDataLength < 36)
    {
        return ClrMethodAction::Unsupported;
    }
    const auto& descriptor = event.EventHeader.EventDescriptor;
    const auto* data = static_cast<const uint8_t*>(event.UserData);
    const size_t length = event.UserDataLength;
    const size_t suffix = descriptor.Version == 2 ? 10 : descriptor.Version == 1 ? 2 : 0;
    if (length < 36 + suffix)
    {
        return ClrMethodAction::Unsupported;
    }
    const size_t stringsEnd = length - suffix;
    size_t offset = 36;
    if (descriptor.Id == 139 || descriptor.Id == 140 || descriptor.Id == 143 || descriptor.Id == 144)
    {
        for (unsigned field = 0; field < 3; ++field)
        {
            while (stringsEnd - offset >= 2 && (data[offset] != 0 || data[offset + 1] != 0))
            {
                offset += 2;
            }
            if (stringsEnd - offset < 2)
            {
                return ClrMethodAction::Unsupported;
            }
            offset += 2;
        }
    }
    if (offset != stringsEnd)
    {
        return ClrMethodAction::Unsupported;
    }

    KmonRuntimeCodeRange record;
    uint32_t size = 0;
    std::memcpy(&record.MethodId, data, 8);
    std::memcpy(&record.ModuleId, data + 8, 8);
    std::memcpy(&record.Start, data + 16, 8);
    std::memcpy(&size, data + 24, 4);
    std::memcpy(&record.MethodToken, data + 28, 4);
    std::memcpy(&record.MethodFlags, data + 32, 4);
    record.Size = size;
    if (descriptor.Version >= 1)
    {
        std::memcpy(&record.RuntimeInstance.emplace(), data + offset, 2);
        offset += 2;
    }
    if (descriptor.Version == 2)
    {
        std::memcpy(&record.ReJitId.emplace(), data + offset, 8);
    }
    record.Timestamp = static_cast<uint64_t>(event.EventHeader.TimeStamp.QuadPart);
    record.EventId = descriptor.Id;
    record.EventVersion = descriptor.Version;
    record.RundownProvider = IsEqualGUID(event.EventHeader.ProviderId, kClrRundown) != FALSE;
    record.Observation = action;
    result = record;
    return action;
}
