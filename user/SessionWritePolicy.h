#pragma once

#include "../shared/KnLiveDbgIoctl.h"
#include <cstddef>
#include <string>

inline bool SessionWriteReplyMatches(const KNDBG_WRITE_MODE_REQUEST& reply, size_t returned, bool enabled)
{
    return returned == sizeof(reply) && reply.Size == sizeof(reply) &&
        reply.EnableWrite == (enabled ? 1u : 0u) && reply.Acknowledge == KNDBG_WRITE_ACK_MAGIC;
}

// Transport acceptance is insufficient: a separate status read must confirm
// the requested gate. A failed transition never authorizes engine dispatch.
template<typename Setter, typename Query>
bool ConfirmSessionWritePolicy(bool enabled, Setter set, Query query, std::wstring* error)
{
    bool actual = !enabled;
    const bool confirmed = set(enabled) && query(&actual) && actual == enabled;
    if (!confirmed && error != nullptr)
    {
        if (!error->empty())
        {
            *error += L"; ";
        }
        *error += L"kernel write state is unconfirmed";
    }
    return confirmed;
}
