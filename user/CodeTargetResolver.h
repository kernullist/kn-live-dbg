#pragma once

#include "ExecutableImageVerifier.h"
#include <string>
#include <vector>

// Entry shapes the decoder recognises. Ordinary prologue bytes (push, sub rsp,
// mov, call __chkstk) stay Plain, so a normal entry can never be a verdict.
enum class KmonInlinePatchShape
{
    Plain = 0,
    Trap,
    NearJump,
    RipIndirect,
    RegisterImmediate,
    PushRet,
    RegisterIndirect,
};

// Pure byte-level decode of one entry prologue. RipIndirect carries the slot
// address instead of a target because the destination is the qword in the slot
// and needs one more read; RegisterIndirect has no static destination at all.
// Pure, so the self-test can drive every accepted form.
struct KmonInlinePatchDecode
{
    KmonInlinePatchShape Shape = KmonInlinePatchShape::Plain;
    bool TargetKnown = false;
    uint64_t Target = 0;
    uint64_t SlotAddress = 0;
};

KmonInlinePatchDecode KmonDecodeInlinePatchHead(
    const uint8_t* bytes,
    size_t size,
    uint64_t address);

struct CodeTargetHop
{
    uint64_t Address = 0;
    uint64_t Slot = 0;
    uint64_t Target = 0;
    CodeOwnership Ownership = CodeOwnership::Unknown;
    std::vector<uint8_t> Bytes;
};

struct CodeTargetChain
{
    std::vector<CodeTargetHop> Hops;
    std::wstring Termination = L"unresolved";
    bool HasModifiedCode = false;
    bool HasUnownedExecutable = false;
    bool HasUnexpectedExecutable = false;
    bool ReferenceChecked = false;
    bool ReferenceStable = false;
};

using CodeTargetInspector = std::function<CodeOwnership(uint64_t, const std::vector<uint8_t>&)>;
bool CodeTargetSlotMatches(uint64_t address, uint64_t slot, const ObservationReader& reader);
bool CodeTargetChainMatches(const CodeTargetChain& chain, const ObservationReader& reader);
CodeTargetChain ResolveCodeTarget(uint64_t address, const ObservationReader& reader,
    const CodeTargetInspector& inspect, size_t depthLimit = 8);
CodeTargetChain ResolveReferencedCodeTarget(uint64_t address, uint64_t slot,
    const ObservationReader& reader, const CodeTargetInspector& inspect, size_t depthLimit = 8);
bool CodeTargetResolverSelfTest();
