#pragma once

// Little-endian records from the cooperative pending-I/O fixture. The existing
// status/control connection keeps its independent v7 ABI.
namespace KnIoTrace
{
    using U32 = unsigned int;
    using U64 = unsigned __int64;
    constexpr U32 Magic = 0x54494E4Bu; // KNIT
    constexpr U32 Version = 1;
    constexpr U32 PageSize = 8;
    constexpr U32 Capacity = 128;
    constexpr U32 HasStatus = 1, HasBytes = 2;
    constexpr U32 LostSequence = 1, LostRequest = 2, LostInstance = 4;

    enum Kind : U32
    {
        DispatchObserved = 1, PrePending, PreForwardSelected, PreCompleteSelected,
        PostObserved, PostPending, PostResumeSelected, Draining, Retired, ContextUnavailable,
        CancelObserved
    };
    enum Layer : U32 { Upper = 1, Lower = 2 };

    struct Epoch { U32 Words[4]; };
    struct Connect { U32 Magic, Version, Size, Reserved; };
    struct Query
    {
        U32 Magic, Version, Size, Reserved;
        Epoch Capture;
        U64 After;
    };
    struct Event
    {
        U64 Sequence, Request, Topology, Instance, Qpc, Bytes;
        U32 Kind, Major, Layer, Flags, Status, ReadLength;
    };
    struct Page
    {
        U32 Magic, Version, Size, Count;
        Epoch Capture;
        U64 Frequency, After, First, Last, LossFlags;
        Event Events[PageSize];
    };

    static_assert(sizeof(Connect) == 16 && sizeof(Query) == 40, "I/O trace request ABI");
    static_assert(sizeof(Event) == 72 && sizeof(Page) == 648, "I/O trace reply ABI");
}
