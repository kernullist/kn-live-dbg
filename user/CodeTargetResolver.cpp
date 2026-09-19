#include "CodeTargetResolver.h"

#include <algorithm>
#include <cstring>
#include <set>

namespace
{
    bool RelativeTarget(uint64_t address, uint64_t length, int64_t displacement, uint64_t* target)
    {
        if (address > UINT64_MAX - length)
        {
            return false;
        }
        const uint64_t next = address + length;
        if (displacement < 0)
        {
            const uint64_t magnitude = static_cast<uint64_t>(-displacement);
            if (magnitude > next)
            {
                return false;
            }
            *target = next - magnitude;
        }
        else
        {
            if (static_cast<uint64_t>(displacement) > UINT64_MAX - next)
            {
                return false;
            }
            *target = next + static_cast<uint64_t>(displacement);
        }
        return true;
    }
}

KmonInlinePatchDecode KmonDecodeInlinePatchHead(
    const uint8_t* bytes,
    size_t size,
    uint64_t address)
{
    KmonInlinePatchDecode decode = {};
    if (bytes == nullptr || address == 0 || size == 0)
    {
        return decode;
    }
    // Only the forms a hook can plant are decoded. The ordinary prologue bytes
    // (push, sub rsp, mov, call __chkstk) stay Plain, so a normal entry cannot
    // become a transfer verdict.
    if (bytes[0] == 0xCC)
    {
        decode.Shape = KmonInlinePatchShape::Trap;
        return decode;
    }
    if (size >= 5 && bytes[0] == 0xE9)
    {
        int32_t relative = 0;
        std::memcpy(&relative, bytes + 1, sizeof(relative));
        decode.Shape = KmonInlinePatchShape::NearJump;
        decode.TargetKnown = RelativeTarget(address, 5, relative, &decode.Target);
        return decode;
    }
    if (size >= 2 && bytes[0] == 0xEB)
    {
        decode.Shape = KmonInlinePatchShape::NearJump;
        decode.TargetKnown = RelativeTarget(address, 2, static_cast<int8_t>(bytes[1]), &decode.Target);
        return decode;
    }
    if (size >= 6 && bytes[0] == 0xFF && bytes[1] == 0x25)
    {
        int32_t relative = 0;
        std::memcpy(&relative, bytes + 2, sizeof(relative));
        decode.Shape = KmonInlinePatchShape::RipIndirect;
        RelativeTarget(address, 6, relative, &decode.SlotAddress);
        return decode;
    }
    // mov reg,imm64 followed by jmp reg: the ModRM r/m field has to name the
    // same register the mov loaded, because the immediate is only the target
    // when that register is the one the jump consumes. A jump through any other
    // register has no statically known destination, so it must not be reported
    // with this immediate as its target.
    if (size >= 12 && bytes[0] == 0x48 && bytes[1] >= 0xB8 && bytes[1] <= 0xBF &&
        bytes[10] == 0xFF && (bytes[11] & 0xF8) == 0xE0 &&
        (bytes[11] & 0x07) == (bytes[1] - 0xB8))
    {
        uint64_t immediate = 0;
        std::memcpy(&immediate, bytes + 2, sizeof(immediate));
        decode.Shape = KmonInlinePatchShape::RegisterImmediate;
        decode.Target = immediate;
        decode.TargetKnown = true;
        return decode;
    }
    // push imm32; ret: the ret sign-extends the pushed value, so this form only
    // reaches kernel code for the top window of the kernel half (0xFFFFFFFF8..
    // upwards, the only canonical kernel range a 32-bit immediate can express).
    // The decode reports the sign-extended value as-is, and the classifier is
    // what refuses a value below the canonical kernel floor.
    if (size >= 6 && bytes[0] == 0x68 && bytes[5] == 0xC3)
    {
        int32_t immediate = 0;
        std::memcpy(&immediate, bytes + 1, sizeof(immediate));
        decode.Shape = KmonInlinePatchShape::PushRet;
        decode.Target = static_cast<uint64_t>(static_cast<int64_t>(immediate));
        decode.TargetKnown = true;
        return decode;
    }
    if (size >= 2 && bytes[0] == 0xFF && (bytes[1] & 0xF8) == 0xE0)
    {
        decode.Shape = KmonInlinePatchShape::RegisterIndirect;
        return decode;
    }
    return decode;
}

CodeTargetChain ResolveCodeTarget(uint64_t address, const ObservationReader& reader,
    const CodeTargetInspector& inspect, size_t depthLimit)
{
    CodeTargetChain result;
    std::set<uint64_t> seen;
    for (size_t depth = 0; depth < (std::min<size_t>)(depthLimit, 16); ++depth)
    {
        if (address == 0 || !seen.insert(address).second)
        {
            result.Termination = address == 0 ? L"null_target" : L"cycle";
            return result;
        }
        CodeTargetHop hop;
        hop.Address = address;
        const size_t count = (std::min<uint64_t>)(32, 4096 - (address & 4095));
        if (!reader || !reader(address, count, &hop.Bytes) || hop.Bytes.size() != count)
        {
            result.Hops.push_back(std::move(hop));
            result.Termination = L"unreadable";
            return result;
        }
        hop.Ownership = inspect ? inspect(address, hop.Bytes) : CodeOwnership::Unknown;
        result.HasModifiedCode = result.HasModifiedCode || hop.Ownership == CodeOwnership::OwnedModified;
        result.HasUnownedExecutable = result.HasUnownedExecutable || hop.Ownership == CodeOwnership::UnownedExecutable;
        result.HasUnexpectedExecutable = result.HasUnexpectedExecutable || hop.Ownership == CodeOwnership::OwnedUnexpectedExecutable;
        size_t prefix = 0;
        if (hop.Bytes.size() >= 4 && std::memcmp(hop.Bytes.data(), "\xF3\x0F\x1E\xFA", 4) == 0)
        {
            prefix = 4;
        }
        while (prefix < hop.Bytes.size() && prefix < 8 && hop.Bytes[prefix] == 0x90)
        {
            ++prefix;
        }
        const auto decode = KmonDecodeInlinePatchHead(hop.Bytes.data() + prefix,
            hop.Bytes.size() - prefix, address + prefix);
        hop.Target = decode.Target;
        hop.Slot = decode.SlotAddress;
        bool known = decode.TargetKnown;
        if (decode.Shape == KmonInlinePatchShape::RipIndirect)
        {
            std::vector<uint8_t> slot;
            known = hop.Slot != 0 && reader(hop.Slot, sizeof(uint64_t), &slot) && slot.size() == sizeof(uint64_t);
            if (known)
            {
                std::memcpy(&hop.Target, slot.data(), sizeof(hop.Target));
            }
        }
        address = hop.Target;
        result.Hops.push_back(std::move(hop));
        if (!known)
        {
            result.Termination = decode.Shape == KmonInlinePatchShape::Plain ?
                (count < 32 ? L"head_truncated_at_page_boundary" : L"no_supported_head_transfer") :
                (decode.Shape == KmonInlinePatchShape::Trap ? L"trap" : L"unresolved_indirect");
            return result;
        }
    }
    result.Termination = L"depth_budget";
    return result;
}

bool CodeTargetSlotMatches(uint64_t address, uint64_t slot, const ObservationReader& reader)
{
    std::vector<uint8_t> bytes;
    uint64_t target = 0;
    if (!reader || slot == 0 || slot > UINT64_MAX - sizeof(target) ||
        !reader(slot, sizeof(target), &bytes) || bytes.size() != sizeof(target))
    {
        return false;
    }
    std::memcpy(&target, bytes.data(), sizeof(target));
    return target == address;
}

CodeTargetChain ResolveReferencedCodeTarget(uint64_t address, uint64_t slot,
    const ObservationReader& reader, const CodeTargetInspector& inspect, size_t depthLimit)
{
    CodeTargetChain result;
    if (CodeTargetSlotMatches(address, slot, reader))
    {
        result = ResolveCodeTarget(address, reader, inspect, depthLimit);
        result.ReferenceStable = CodeTargetSlotMatches(address, slot, reader);
    }
    result.ReferenceChecked = true;
    if (!result.ReferenceStable)
    {
        result.HasModifiedCode = false;
        result.HasUnownedExecutable = false;
        result.HasUnexpectedExecutable = false;
        result.Termination = L"reference_changed_or_unreadable";
    }
    return result;
}

bool CodeTargetResolverSelfTest()
{
    std::map<uint64_t, std::vector<uint8_t>> memory;
    memory[0x1000] = std::vector<uint8_t>(32, 0x90);
    memory[0x1100] = std::vector<uint8_t>(32, 0x90);
    memory[0x3000] = std::vector<uint8_t>(32, 0xCC);
    const auto jump = [&memory](uint64_t from, uint64_t to)
    {
        auto& bytes = memory[from];
        bytes[0] = 0xE9;
        const int32_t delta = static_cast<int32_t>(to - from - 5);
        std::memcpy(bytes.data() + 1, &delta, sizeof(delta));
    };
    jump(0x1000, 0x1100);
    jump(0x1100, 0x3000);
    const ObservationReader reader = [&memory](uint64_t address, size_t size, std::vector<uint8_t>* bytes)
    {
        const auto it = memory.find(address);
        if (it == memory.end() || size > it->second.size())
        {
            return false;
        }
        bytes->assign(it->second.begin(), it->second.begin() + size);
        return true;
    };
    const CodeTargetInspector inspect = [](uint64_t address, const std::vector<uint8_t>&)
    {
        return address < 0x2000 ? CodeOwnership::OwnedModified : CodeOwnership::UnownedExecutable;
    };
    auto chain = ResolveCodeTarget(0x1000, reader, inspect);
    bool ok = chain.Hops.size() == 3 && chain.HasModifiedCode && chain.HasUnownedExecutable;
    jump(0x1100, 0x1000);
    chain = ResolveCodeTarget(0x1000, reader, inspect);
    ok = ok && chain.Termination == L"cycle";
    memory[0x1100][0] = 0xFF;
    memory[0x1100][1] = 0xE0;
    chain = ResolveCodeTarget(0x1000, reader, inspect);
    ok = ok && chain.Termination == L"unresolved_indirect" && chain.Hops.back().Target == 0;
    chain = ResolveCodeTarget(0x1000, reader, inspect, 1);
    ok = ok && chain.Termination == L"depth_budget";
    memory.erase(0x1100);
    chain = ResolveCodeTarget(0x1000, reader, inspect);
    ok = ok && chain.Termination == L"unreadable";
    memory[0x1FFF] = {0xE9};
    chain = ResolveCodeTarget(0x1FFF, reader, inspect);
    ok = ok && chain.Termination == L"head_truncated_at_page_boundary";
    const uint8_t overflow[] = {0xE9, 0x7F, 0, 0, 0};
    const uint8_t underflow[] = {0xE9, 0, 0, 0, 0x80};
    ok = ok && !KmonDecodeInlinePatchHead(overflow, sizeof(overflow), UINT64_MAX - 4).TargetKnown &&
        !KmonDecodeInlinePatchHead(underflow, sizeof(underflow), 1).TargetKnown;
    memory[0x9000].resize(8);
    const uint64_t target = 0x3000;
    std::memcpy(memory[0x9000].data(), &target, sizeof(target));
    chain = ResolveReferencedCodeTarget(target, 0x9000, reader, inspect);
    ok = ok && chain.ReferenceStable && chain.HasUnownedExecutable;
    chain = ResolveReferencedCodeTarget(0x1000, 0x9000, reader, inspect);
    ok = ok && chain.ReferenceChecked && !chain.ReferenceStable && chain.Hops.empty();
    const CodeTargetInspector changing = [&](uint64_t address, const std::vector<uint8_t>& bytes)
    {
        memory[0x9000][0] ^= 1;
        return inspect(address, bytes);
    };
    chain = ResolveReferencedCodeTarget(target, 0x9000, reader, changing);
    ok = ok && !chain.ReferenceStable && !chain.HasUnownedExecutable &&
        chain.Termination == L"reference_changed_or_unreadable";
    std::memcpy(memory[0x9000].data(), &target, sizeof(target));
    const CodeTargetInspector unexpected = [](uint64_t, const std::vector<uint8_t>&)
    {
        return CodeOwnership::OwnedUnexpectedExecutable;
    };
    chain = ResolveReferencedCodeTarget(target, 0x9000, reader, unexpected);
    ok = ok && chain.ReferenceStable && chain.HasUnexpectedExecutable && !chain.HasModifiedCode;
    memory[0x9000][0] ^= 1;
    ok = ok && !CodeTargetSlotMatches(target, 0x9000, reader);
    std::memcpy(memory[0x9000].data(), &target, sizeof(target));
    const CodeTargetInspector changingPermission = [&](uint64_t address, const std::vector<uint8_t>& bytes)
    {
        memory[0x9000][0] ^= 1;
        return unexpected(address, bytes);
    };
    chain = ResolveReferencedCodeTarget(target, 0x9000, reader, changingPermission);
    ok = ok && !chain.ReferenceStable && !chain.HasUnexpectedExecutable;
    return ok;
}
