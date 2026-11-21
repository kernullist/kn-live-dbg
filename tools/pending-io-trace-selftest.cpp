#include "../minifilter_fixture_driver/PendingIoTrace.h"
#include "../shared/KnLiveDbgPendingIo.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <io.h>
#include <initializer_list>

namespace
{
    using namespace KnIoTrace;

    void Check(bool value, const char* message)
    {
        if (!value)
        {
            std::fprintf(stderr, "%s\n", message);
            std::exit(1);
        }
    }

    Query Discovery()
    {
        Query request = {Magic, Version, sizeof(Query), 0, {}, 0};
        return request;
    }

    void Mark(Ring& ring, U64 request, Layer layer, Kind kind, U32 status = 0)
    {
        Event e = {};
        e.Request = request;
        e.Topology = 7;
        e.Instance = layer == Upper ? 5 : 6;
        e.Qpc = (ring.Last + 1) * 10;
        e.Kind = kind;
        e.Major = 3;
        e.Layer = layer;
        e.ReadLength = 4096;
        if (kind == PostObserved || kind == PreCompleteSelected)
        {
            e.Flags = HasStatus;
            e.Status = status;
            if (kind == PostObserved && status == 0)
            {
                e.Flags |= HasBytes;
                e.Bytes = 4096;
            }
        }
        ring.Record(e);
    }

    void CheckPostTransfer()
    {
        U32 reads = 0;
        U64 value = 4096;
        const auto information = [&]() { ++reads; return value; };
        auto item = PostTransfer(ReadMajor, 0, 4096, information);
        Check(item.Flags == (HasStatus | HasBytes) && item.Bytes == 4096 && reads == 1, "successful read count");
        value = ~U64{0};
        item = PostTransfer(ReadMajor, 0, 4096, information);
        Check(item.Flags == HasStatus && !item.Bytes && reads == 2, "oversized information");
        item = PostTransfer(ReadMajor, 0x104, 4096, information);
        Check(item.Flags == HasStatus && !item.Bytes && reads == 2, "reparse information skipped");
        item = PostTransfer(0, 0, 0, information);
        Check(item.Flags == HasStatus && !item.Bytes && reads == 2, "create information skipped");
        value = 0;
        item = PostTransfer(ReadMajor, 0, 0, information);
        Check(item.Flags == (HasStatus | HasBytes) && !item.Bytes && reads == 3, "observed zero byte count");
    }

    void CheckBoundaries()
    {
        Ring ring = {};
        ring.Capture.Words[0] = 3;
        ring.Frequency = 10000000;
        Query q = Discovery();
        Page p;
        std::memset(&p, 0xCC, sizeof(p));
        Check(ring.Read(q, p) && !p.First && !p.Last && !p.Count, "empty capture");
        const Event blank = {};
        for (const auto& event : p.Events) Check(!std::memcmp(&event, &blank, sizeof(event)), "page initialization");
        q.Reserved = 1;
        Check(!ring.Read(q, p), "reserved flags");
        q = Discovery();
        q.Version = 2;
        Check(!ring.Read(q, p), "version");
        q = Discovery();
        q.Size -= 1;
        Check(!ring.Read(q, p), "query size");
        q = Discovery();
        q.Magic = 0;
        Check(!ring.Read(q, p), "magic");
        q = Discovery();
        q.Capture.Words[1] = 1;
        Check(!ring.Read(q, p), "foreign capture");
        q = Discovery();
        for (U32 i = 0; i < Capacity + 3; ++i) Mark(ring, ring.BeginRequest(), Upper, DispatchObserved);
        Check(ring.Read(q, p) && p.First == 4 && p.Events[0].Request == 4 && p.Count == PageSize, "overwrite");
        q.After = 1;
        Check(!ring.Read(q, p), "unbound cursor");
        q.Capture = ring.Capture;
        q.After = ring.Last + 1;
        Check(!ring.Read(q, p), "future cursor");
        q.After = ring.Last - 1;
        Check(ring.Read(q, p) && p.Count == 1 && p.Events[0].Sequence == ring.Last, "last page");
        const Page previous = p;
        Check(ring.Read(q, p) && std::memcmp(&p, &previous, sizeof(p)) == 0, "retry stability");
        for (U32 i = 1; i < PageSize; ++i) Check(!std::memcmp(&p.Events[i], &blank, sizeof(blank)), "unused slots");
        ring.NextRequest = ~U64{0} - 1;
        Check(ring.BeginRequest() == ~U64{0} && ring.BeginRequest() == 0, "generation exhaustion");
        Event missing = {};
        missing.Request = 1;
        ring.Record(missing);
        ring.Last = ~U64{0} - 1;
        Mark(ring, 1, Upper, Retired);
        Mark(ring, 1, Upper, Retired);
        q.After = ~U64{0} - 1;
        Check(ring.Read(q, p) && p.Count == 1 && p.Events[0].Sequence == ~U64{0} &&
              p.LossFlags == (LostSequence | LostRequest | LostInstance), "sequence exhaustion and loss");
        q.After = ~U64{0};
        Check(ring.Read(q, p) && p.Count == 0, "terminal cursor");
    }

    void EmitCapture()
    {
        Ring ring = {};
        ring.Capture = {{0x11223344, 0x55667788, 0x99AABBCC, 0xDDEEFF00}};
        ring.Frequency = 10000000;
        const auto first = ring.BeginRequest(), second = ring.BeginRequest();
        for (auto request : {first, second})
        {
            Mark(ring, request, Upper, DispatchObserved);
            Mark(ring, request, Upper, PreForwardSelected);
            Mark(ring, request, Lower, DispatchObserved);
            Mark(ring, request, Lower, PrePending);
        }
        Mark(ring, second, Lower, PreForwardSelected);
        Mark(ring, second, Lower, PostObserved);
        Mark(ring, second, Lower, Retired);
        Mark(ring, second, Upper, PostObserved);
        Mark(ring, second, Upper, Retired);
        Mark(ring, first, Lower, CancelObserved);
        Mark(ring, first, Lower, PreCompleteSelected, 0xC0000120);
        // FltCompletePendedPreOperation may deliver the upper post before it returns.
        Mark(ring, first, Upper, PostObserved, 0xC0000120);
        Mark(ring, first, Upper, Retired);
        Mark(ring, first, Lower, Retired);
        Query q = Discovery();
        Page page;
        do
        {
            Check(ring.Read(q, page), "sample read");
            Check(std::fwrite(&page, sizeof(page), 1, stdout) == 1, "sample write");
            q.Capture = page.Capture;
            q.After = page.Events[page.Count - 1].Sequence;
        } while (q.After < ring.Last);
    }
}

int main()
{
    Check(_setmode(_fileno(stdout), _O_BINARY) != -1, "binary stdout");
    CheckPostTransfer();
    CheckBoundaries();
    EmitCapture();
    return std::fflush(stdout) == 0 ? 0 : 1;
}
