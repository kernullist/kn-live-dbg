#pragma once

#include <cstddef>
#include <cstdint>

// One x64 game-owned registry slot. A serialized writer brackets changes to the
// member, object and its lifetime with an odd/even sequence using full barriers.
// A completed publication has a nonzero even sequence. Neither the sequence nor
// the allocation generation may be recycled within the process generation.
enum class KnGameObjectPhase : uint64_t
{
    Vacant = 0,
    Constructing = 1,
    Live = 2,
    Destroying = 3,
    Collecting = 4
};

struct alignas(8) KnGameObjectSlotV1
{
    uint64_t Sequence;
    uint64_t Generation;
    uint64_t ContainerId;
    uint64_t MemberAddress;
    uint64_t Phase;
};

static_assert(sizeof(KnGameObjectSlotV1) == 40 && alignof(KnGameObjectSlotV1) == 8);
static_assert(offsetof(KnGameObjectSlotV1, Sequence) == 0 && offsetof(KnGameObjectSlotV1, Generation) == 8 &&
    offsetof(KnGameObjectSlotV1, ContainerId) == 16 && offsetof(KnGameObjectSlotV1, MemberAddress) == 24 &&
    offsetof(KnGameObjectSlotV1, Phase) == 32);
