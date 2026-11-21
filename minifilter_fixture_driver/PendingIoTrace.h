#pragma once
#include "../shared/KnLiveDbgIoTrace.h"

namespace KnIoTrace
{
    constexpr U32 ReadMajor = 3;
    struct Transfer { U32 Flags; U64 Bytes; };

    template<class ReadInformation>
    Transfer PostTransfer(U32 major, U32 status, U32 length, ReadInformation readInformation)
    {
        // Reparse information can encode a pointer. Consult Information only
        // for a successful READ and retain a count within the submitted length.
        if (major == ReadMajor && status == 0)
        {
            const U64 bytes = readInformation();
            if (bytes <= length) return {HasStatus | HasBytes, bytes};
        }
        return {HasStatus, 0};
    }

    // All calls in the driver hold the fixture spin lock. The client owns the
    // ring. Operations retain only scalar generation numbers across callbacks.
    struct Ring
    {
        Epoch Capture;
        U64 Frequency, Last, NextRequest, LossFlags;
        Event Events[Capacity];

        U64 BeginRequest()
        {
            if (NextRequest != ~U64{0}) return ++NextRequest;
            LossFlags |= LostRequest;
            return 0;
        }

        void Record(Event event)
        {
            if (event.Instance == 0) LossFlags |= LostInstance;
            if (event.Request == 0 || event.Instance == 0) return;
            if (Last == ~U64{0})
            {
                LossFlags |= LostSequence;
                return;
            }
            event.Sequence = ++Last;
            Events[(event.Sequence - 1) % Capacity] = event;
        }

        bool Read(const Query& query, Page& page) const
        {
            if (query.Magic != Magic || query.Version != Version || query.Size != sizeof(Query) ||
                query.Reserved != 0 || query.After > Last) return false;
            bool same = true, empty = true;
            for (U32 i = 0; i < 4; ++i)
            {
                if (query.Capture.Words[i] != Capture.Words[i]) same = false;
                if (query.Capture.Words[i] != 0) empty = false;
            }
            if (!same && !(empty && query.After == 0)) return false;
            page = {};
            page.Magic = Magic;
            page.Version = Version;
            page.Size = sizeof(Page);
            page.Capture = Capture;
            page.Frequency = Frequency;
            page.After = query.After;
            page.Last = Last;
            page.First = Last == 0 ? 0 : (Last <= Capacity ? 1 : Last - Capacity + 1);
            page.LossFlags = LossFlags;
            U64 cursor = query.After;
            if (page.First && cursor < page.First - 1) cursor = page.First - 1;
            while (page.Count < PageSize && cursor < Last)
            {
                page.Events[page.Count++] = Events[cursor % Capacity];
                ++cursor;
            }
            return true;
        }
    };
}
