#pragma once

#include "../user/SessionWritePolicy.h"

inline bool SessionWritePolicySelfTest()
{
    for (bool wanted : {false, true})
    {
        KNDBG_WRITE_MODE_REQUEST reply{};
        reply.Size = sizeof(reply);
        reply.EnableWrite = wanted ? 1u : 0u;
        reply.Acknowledge = KNDBG_WRITE_ACK_MAGIC;
        if (!SessionWriteReplyMatches(reply, sizeof(reply), wanted) ||
            SessionWriteReplyMatches(reply, sizeof(reply) - 1, wanted) ||
            SessionWriteReplyMatches(reply, sizeof(reply), !wanted))
        {
            return false;
        }
        reply.EnableWrite = 2;
        if (SessionWriteReplyMatches(reply, sizeof(reply), wanted))
        {
            return false;
        }
        reply.EnableWrite = wanted ? 1u : 0u;
        reply.Size = 0;
        if (SessionWriteReplyMatches(reply, sizeof(reply), wanted))
        {
            return false;
        }
        reply.Size = sizeof(reply);
        reply.Acknowledge = 0;
        if (SessionWriteReplyMatches(reply, sizeof(reply), wanted))
        {
            return false;
        }

        // Exercise acknowledgment loss and stale state after a transport success.
        // Neither case may be reported as a confirmed engine admission.
        for (unsigned fault = 0; fault < 4; ++fault)
        {
            bool gate = !wanted;
            unsigned writes = 0, queries = 0;
            std::wstring error;
            const bool confirmed = ConfirmSessionWritePolicy(wanted, [&](bool value)
            {
                ++writes;
                gate = value;
                return fault != 1;
            }, [&](bool* actual)
            {
                ++queries;
                *actual = fault == 3 ? !gate : gate;
                return fault != 2;
            }, &error);
            if (confirmed != (fault == 0) || writes != 1 || queries != (fault == 1 ? 0u : 1u) ||
                (fault != 0 && error.find(L"unconfirmed") == std::wstring::npos))
            {
                return false;
            }
        }
    }
    return true;
}
