#pragma once

#include "EtlProfileRecord.h"
#include <cstddef>

namespace etl_profile
{
    // Classic Thread/CSwitch versions 2, 3 and 4 share this pointer-free layout.
    // Byte 13 is the old wait mode in version 2 and ThreadFlags in versions 3/4.
    struct SwitchFields
    {
        uint32_t newTid, oldTid;
        int8_t newPriority, oldPriority;
        uint8_t previousCState;
        int8_t spare, oldWaitReason, modeOrFlags, oldState, idealProcessor;
        uint32_t newWaitTime, reserved;
    };

    static_assert(sizeof(SwitchFields) == 24 && offsetof(SwitchFields, modeOrFlags) == 13 &&
        offsetof(SwitchFields, newWaitTime) == 16);

    struct SwitchEvent : RecordEnvelope
    {
        SwitchFields fields;
        uint8_t version;
    };

    inline Match DecodeSwitch(const EVENT_RECORD& event, SwitchEvent* output)
    {
        const auto& h = event.EventHeader;
        const auto& d = h.EventDescriptor;
        if (!IsEqualGUID(h.ProviderId, ThreadProvider) || d.Opcode != 36) { return Match::Other; }
        if (d.Version < 2 || d.Version > 4) { return Match::Unsupported; }
        const auto width = ClassicPointerWidth(h, d.Version);
        if (!width || !event.UserData || event.UserDataLength != sizeof(SwitchFields) ||
            (event.ExtendedDataCount && !event.ExtendedData)) { return Match::Unsupported; }
        if (output)
        {
            *output = {};
            ReadEnvelope(event, width, *output);
            output->version = d.Version;
            std::memcpy(&output->fields, event.UserData, sizeof(SwitchFields));
        }
        return Match::Decoded;
    }
}
