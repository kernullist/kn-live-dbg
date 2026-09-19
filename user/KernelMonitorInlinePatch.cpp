#include "KernelMonitor.h"

#include <cstring>
#include <limits>
#include <set>
#include <string>
#include <vector>

// Entry-shape alerts retain their historical location-based noise filters.
// Every resolved entry is also queued into the common byte/branch verifier
// before those filters: same-module and inbox destinations are inspected there.
// A shape exclusion is not an integrity verdict. Unknown register targets,
// cycles and failed reads remain explicit coverage states in that verifier.

namespace
{
    constexpr size_t kPrologueBytes = 16;
    constexpr size_t kStubBytes = 16;
    constexpr uint32_t kEmitCap = 16;
    constexpr uint32_t kStrikeThreshold = 2;
    constexpr size_t kMaxTargets = 32;
    constexpr size_t kMaxStrikeEntries = 4096;
    constexpr size_t kMaxModuleEntries = 2048;
    constexpr uint64_t kKernelVaFloor = 0xFFFF800000000000ull;
    const wchar_t* const kLayer = L"inline_patch";

    struct PatchTargetEntry
    {
        const wchar_t* Label;
        const wchar_t* Primary;
        const wchar_t* Secondary;
    };

    // The entry points a mapper or BYOVD driver rewrites to hide a process, to
    // read a game, or to blind a syscall query. win32k moved the NtUser*
    // implementations between win32k.sys, win32kbase.sys, and win32kfull.sys
    // across builds, so a row may carry both names a build can use.
    const PatchTargetEntry kTargets[] =
    {
        { L"NtQuerySystemInformation", L"nt!NtQuerySystemInformation", nullptr },
        { L"NtQueryInformationProcess", L"nt!NtQueryInformationProcess", nullptr },
        { L"NtReadVirtualMemory", L"nt!NtReadVirtualMemory", nullptr },
        { L"NtWriteVirtualMemory", L"nt!NtWriteVirtualMemory", nullptr },
        { L"NtProtectVirtualMemory", L"nt!NtProtectVirtualMemory", nullptr },
        { L"NtAllocateVirtualMemory", L"nt!NtAllocateVirtualMemory", nullptr },
        { L"NtOpenProcess", L"nt!NtOpenProcess", nullptr },
        { L"NtCreateThreadEx", L"nt!NtCreateThreadEx", nullptr },
        { L"NtQueryVirtualMemory", L"nt!NtQueryVirtualMemory", nullptr },
        { L"NtMapViewOfSection", L"nt!NtMapViewOfSection", nullptr },
        { L"NtDeviceIoControlFile", L"nt!NtDeviceIoControlFile", nullptr },
        { L"MmCopyVirtualMemory", L"nt!MmCopyVirtualMemory", nullptr },
        { L"NtUserGetAsyncKeyState", L"win32kfull!NtUserGetAsyncKeyState", L"win32kbase!NtUserGetAsyncKeyState" },
        { L"NtUserGetKeyState", L"win32kfull!NtUserGetKeyState", L"win32kbase!NtUserGetKeyState" },
        { L"NtUserGetRawInputData", L"win32kfull!NtUserGetRawInputData", L"win32kbase!NtUserGetRawInputData" },
        { L"NtUserSetWindowsHookEx", L"win32kfull!NtUserSetWindowsHookEx", L"win32kbase!NtUserSetWindowsHookEx" },
        { L"NtUserGetForegroundWindow", L"win32kfull!NtUserGetForegroundWindow", L"win32kbase!NtUserGetForegroundWindow" },
        { L"NtGdiBitBlt", L"win32kfull!NtGdiBitBlt", L"win32kbase!NtGdiBitBlt" },
    };

    constexpr size_t kTargetCount = sizeof(kTargets) / sizeof(kTargets[0]);

    struct PatchModule
    {
        uint64_t Base = 0;
        uint64_t End = 0;
        std::wstring Leaf;
        bool NonInbox = false;
    };

    std::wstring PatchHex(uint64_t value)
    {
        wchar_t buf[32] = {};
        swprintf_s(buf, L"0x%llx", static_cast<unsigned long long>(value));
        return buf;
    }

    // Same canonical-address and size guard the kernel helpers apply: a bogus
    // size or a user-mode address cannot become a speculative read.
    bool ReadKernelBytes(
        DeviceClient* device,
        uint64_t address,
        size_t size,
        std::vector<uint8_t>* out)
    {
        if (device == nullptr || out == nullptr || size == 0 || address == 0 ||
            address < kKernelVaFloor)
        {
            return false;
        }
        if (size > 0x1000)
        {
            size = 0x1000;
        }
        out->clear();
        std::wstring ignored;
        if (!device->ReadMemory(address, static_cast<uint32_t>(size), out, &ignored))
        {
            return false;
        }
        return !out->empty();
    }

    bool ReadKernelU64(DeviceClient* device, uint64_t address, uint64_t* value)
    {
        if (value == nullptr)
        {
            return false;
        }
        std::vector<uint8_t> bytes;
        if (!ReadKernelBytes(device, address, sizeof(uint64_t), &bytes) ||
            bytes.size() < sizeof(uint64_t))
        {
            return false;
        }
        std::memcpy(value, bytes.data(), sizeof(*value));
        return true;
    }

    // The module inventory plus the path class of each range, so the ownership
    // test and the inbox test come from one snapshot. A module whose size is
    // unknown is skipped: a range that cannot be trusted cannot back a verdict.
    void BuildPatchModules(SymbolEngine* symbols, std::vector<PatchModule>* modules)
    {
        modules->clear();
        if (symbols == nullptr)
        {
            return;
        }
        const std::vector<KernelModuleInfo> inventory = symbols->CopyModules();
        for (const KernelModuleInfo& module : inventory)
        {
            if (modules->size() >= kMaxModuleEntries)
            {
                break;
            }
            if (module.Base == 0 || module.Size == 0)
            {
                continue;
            }
            const uint64_t size = static_cast<uint64_t>(module.Size);
            if (module.Base > (std::numeric_limits<uint64_t>::max)() - size)
            {
                continue;
            }
            PatchModule entry = {};
            entry.Base = module.Base;
            entry.End = module.Base + size;
            if (entry.End <= entry.Base)
            {
                continue;
            }
            const std::wstring source = module.ImageName.empty()
                ? module.ImagePath
                : module.ImageName;
            entry.Leaf = KmonBasenameLower(source);
            entry.NonInbox = KmonClassifyDriverPath(
                module.ImagePath.empty() ? source : module.ImagePath) != L"inbox";
            modules->push_back(std::move(entry));
        }
    }

    const PatchModule* FindPatchModule(
        const std::vector<PatchModule>& modules,
        uint64_t address)
    {
        if (address == 0)
        {
            return nullptr;
        }
        for (const PatchModule& module : modules)
        {
            if (address >= module.Base && address < module.End)
            {
                return &module;
            }
        }
        return nullptr;
    }

    bool EnsurePatchModules(SymbolEngine* symbols)
    {
        if (symbols == nullptr)
        {
            return false;
        }
        if (!symbols->CopyModules().empty())
        {
            return true;
        }
        std::wstring ignored;
        if (!symbols->LoadKernelModules(&ignored) || symbols->CopyModules().empty())
        {
            return false;
        }
        return true;
    }

    // A head transfer lands in kernel code, so a destination below the
    // canonical kernel floor is not an address this layer may call a transfer
    // target: the 32-bit immediate of a push/ret head sign-extends into the
    // user half, and a thunk slot or an r/m the decoder read can hold anything.
    // The mapper/pool stub counter drops the same values from its slots
    // (KernelMonitorMapperPool.cpp, IsKernelDestination), so a value that is
    // data there cannot be a hook destination here.
    bool InlineTargetIsKernelCode(uint64_t target)
    {
        return target >= kKernelVaFloor;
    }

    const wchar_t* ShapeName(KmonInlinePatchShape shape)
    {
        switch (shape)
        {
        case KmonInlinePatchShape::Trap:
            return L"int3";
        case KmonInlinePatchShape::NearJump:
            return L"jmp rel32";
        case KmonInlinePatchShape::RipIndirect:
            return L"jmp [rip]";
        case KmonInlinePatchShape::RegisterImmediate:
            return L"mov reg,imm64;jmp reg";
        case KmonInlinePatchShape::PushRet:
            return L"push imm32;ret";
        case KmonInlinePatchShape::RegisterIndirect:
            return L"jmp reg";
        default:
            return L"plain";
        }
    }
}

bool KmonDecodeInlinePatchStub(
    const uint8_t* bytes,
    size_t size,
    uint64_t address,
    uint64_t* destination)
{
    if (destination == nullptr)
    {
        return false;
    }
    const KmonInlinePatchDecode decode = KmonDecodeInlinePatchHead(bytes, size, address);
    // Only a statically known continuation is a trampoline stub. The rip-slot
    // form needs one more read that this decoder does not do, so it stays a
    // plain unbacked head transfer.
    switch (decode.Shape)
    {
    case KmonInlinePatchShape::NearJump:
    case KmonInlinePatchShape::RegisterImmediate:
    case KmonInlinePatchShape::PushRet:
        if (!decode.TargetKnown)
        {
            return false;
        }
        *destination = decode.Target;
        return true;
    default:
        return false;
    }
}

KmonInlinePatchKind KmonClassifyInlinePatch(const KmonInlinePatchInput& input)
{
    // Fail-closed: an unreadable prologue is never a verdict.
    if (!input.PrologueKnown)
    {
        return KmonInlinePatchKind::None;
    }
    // An int3 at the entry needs no other view: the trap is the first
    // instruction itself. Breakpoint hooking is used by cheat drivers and by
    // some security products, and both are worth reporting on a hot entry.
    if (input.HeadIsTrap)
    {
        return KmonInlinePatchKind::Int3Breakpoint;
    }
    // A register transfer has no statically known destination, and an ordinary
    // prologue does not transfer at all.
    if (!input.HeadIsTransfer || !input.TransferTargetKnown)
    {
        return KmonInlinePatchKind::None;
    }
    // A destination that is not kernel code is not what this layer reports as a
    // head transfer: a push/ret head pushes a sign-extended 32-bit value, so an
    // immediate below the kernel floor lands in the user half, and a thunk slot
    // or an r/m the decoder read can hold anything. Reporting such a value as
    // the transfer destination would name an address control flow cannot reach.
    if (!InlineTargetIsKernelCode(input.TransferTarget))
    {
        return KmonInlinePatchKind::None;
    }
    // Without the owner range and a usable module view an in-image hotpatch
    // cannot be ruled out, so the verdict is withheld.
    if (!input.OwnerRangeKnown || input.OwnerEnd <= input.OwnerBase ||
        !input.ModuleViewKnown)
    {
        return KmonInlinePatchKind::None;
    }
    if (input.TransferTarget >= input.OwnerBase &&
        input.TransferTarget < input.OwnerEnd)
    {
        return KmonInlinePatchKind::None;
    }
    if (input.TargetInLoadedModule)
    {
        // win32k.sys forwards NtUser* into win32kbase/win32kfull and other
        // inbox images chain their own entries, so only a non-inbox
        // destination is reported.
        return input.TargetModuleNonInbox
            ? KmonInlinePatchKind::ForeignModuleHeadTransfer
            : KmonInlinePatchKind::None;
    }
    // The transfer leaves every loaded module. When the bytes there are
    // themselves a stub with a known continuation, the pool trampoline is
    // reported instead of the plain head transfer.
    // The stub continuation has to be kernel code too, for the same reason: a
    // stub body that pushes a 32-bit value continues into the user half, and
    // naming that value as the trampoline destination would be wrong. The head
    // transfer into the unbacked stub stays a verdict either way.
    if (input.StubKnown && input.StubIsTransfer && input.StubDestinationKnown &&
        InlineTargetIsKernelCode(input.StubDestination))
    {
        return KmonInlinePatchKind::TrampolineStub;
    }
    return KmonInlinePatchKind::UnbackedHeadTransfer;
}

const wchar_t* KmonInlinePatchKindName(KmonInlinePatchKind kind)
{
    switch (kind)
    {
    case KmonInlinePatchKind::UnbackedHeadTransfer:
        return L"unbacked_head_transfer";
    case KmonInlinePatchKind::TrampolineStub:
        return L"trampoline_stub";
    case KmonInlinePatchKind::ForeignModuleHeadTransfer:
        return L"foreign_module_head_transfer";
    case KmonInlinePatchKind::Int3Breakpoint:
        return L"int3_breakpoint";
    default:
        return L"";
    }
}

void KernelMonitor::ScanKernelInlinePatches()
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        device = Device;
        symbols = Symbols;
    }
    if (device == nullptr || symbols == nullptr || !device->IsOpen())
    {
        EmitUnique(
            L"hook.scan",
            L"scan_failed:patch:device",
            std::wstring(),
            kLayer,
            L"inline patch scan skipped; kernel device is not open",
            L"Device is null or closed");
        return;
    }
    ClearEmittedKey(L"scan_failed:patch:device");
    if (!EnsurePatchModules(symbols))
    {
        EmitUnique(
            L"hook.scan",
            L"scan_failed:patch:inventory",
            std::wstring(),
            kLayer,
            L"inline patch scan skipped; kernel module inventory unavailable",
            L"SymbolEngine::LoadKernelModules returned no module");
        return;
    }
    ClearEmittedKey(L"scan_failed:patch:inventory");

    std::vector<PatchModule> modules;
    BuildPatchModules(symbols, &modules);
    if (modules.empty())
    {
        // An empty module view cannot tell an in-image hotpatch from a hook,
        // so it is a deferral, the same rule AddressOwnedByLoadedModule uses
        // for pointers.
        EmitUnique(
            L"hook.scan",
            L"scan_failed:patch:modules",
            std::wstring(),
            kLayer,
            L"inline patch scan skipped; no kernel module range with a known size was available",
            L"SymbolEngine::CopyModules returned no sized module");
        return;
    }
    ClearEmittedKey(L"scan_failed:patch:modules");

    struct ResolvedTarget
    {
        const PatchTargetEntry* Entry = nullptr;
        const wchar_t* Symbol = nullptr;
        uint64_t Address = 0;
        const PatchModule* Owner = nullptr;
    };

    std::vector<ResolvedTarget> resolved;
    size_t unresolved = 0;
    for (const PatchTargetEntry& target : kTargets)
    {
        if (resolved.size() >= kMaxTargets)
        {
            break;
        }
        const wchar_t* names[2] = { target.Primary, target.Secondary };
        bool found = false;
        for (const wchar_t* name : names)
        {
            if (name == nullptr)
            {
                continue;
            }
            uint64_t address = 0;
            std::wstring ignored;
            if (!symbols->ResolveSymbol(name, &address, &ignored) || address == 0)
            {
                continue;
            }
            const PatchModule* owner = FindPatchModule(modules, address);
            if (owner == nullptr)
            {
                // Resolved outside every sized module: the owner range is
                // unknown, so this entry cannot be judged. Coverage gap.
                break;
            }
            ResolvedTarget entry = {};
            entry.Entry = &target;
            entry.Symbol = name;
            entry.Address = address;
            entry.Owner = owner;
            resolved.push_back(entry);
            found = true;
            break;
        }
        if (!found)
        {
            ++unresolved;
        }
    }

    if (resolved.empty())
    {
        EmitUnique(
            L"hook.scan",
            L"scan_failed:patch:symbols",
            std::wstring(),
            kLayer,
            L"inline patch scan skipped; no hot kernel entry point symbol was resolvable",
            L"resolved=0 targets=" + std::to_wstring(kTargetCount) +
                L" unresolved=" + std::to_wstring(unresolved) +
                L" (entry points come from the symbol engine, so a missing PDB is a deferral)");
        return;
    }
    ClearEmittedKey(L"scan_failed:patch:symbols");

    if (unresolved != 0)
    {
        EmitUnique(
            L"hook.scan",
            L"coverage:patch:targets",
            std::wstring(),
            kLayer,
            L"inline patch scan covers " + std::to_wstring(resolved.size()) + L" of " +
                std::to_wstring(kTargetCount) +
                L" hot kernel entry points; the rest are not resolvable in this build",
            L"unresolved=" + std::to_wstring(unresolved) +
                L" names are resolved through the symbol engine, so an unresolvable row is a coverage gap");
    }
    else
    {
        ClearEmittedKey(L"coverage:patch:targets");
    }

    uint32_t emitted = 0;
    bool capped = false;
    size_t readable = 0;
    size_t skipped = 0;
    std::set<std::wstring> candidates;

    for (const ResolvedTarget& target : resolved)
    {
        QueueExecutionReference(target.Address, 0, L"entrypoint");
        if (StopRequested.load())
        {
            break;
        }

        KmonInlinePatchInput input = {};
        input.OwnerRangeKnown = true;
        input.OwnerBase = target.Owner->Base;
        input.OwnerEnd = target.Owner->End;
        input.ModuleViewKnown = true;

        std::vector<uint8_t> prologue;
        if (!ReadKernelBytes(device, target.Address, kPrologueBytes, &prologue) ||
            prologue.size() < 6)
        {
            // A prologue that cannot be read proves nothing: the entry is a
            // deferral for this pass and the scan continues with the rest.
            ++skipped;
            continue;
        }
        ++readable;

        const KmonInlinePatchDecode decode =
            KmonDecodeInlinePatchHead(prologue.data(), prologue.size(), target.Address);
        if (decode.Shape == KmonInlinePatchShape::Trap)
        {
            input.HeadIsTrap = true;
        }
        else if (decode.Shape == KmonInlinePatchShape::RipIndirect)
        {
            // FF 25 jmp qword ptr [rip+disp]: the destination is the qword in
            // the slot, so one more read decides it.
            uint64_t slotValue = 0;
            const bool slotRead = ReadKernelU64(device, decode.SlotAddress, &slotValue) && slotValue != 0;
            if (!slotRead)
            {
                // An unreadable thunk slot is a deferral and is counted as one,
                // so the pass coverage shows the entry was not judged.
                ++skipped;
            }
            if (slotRead)
            {
                input.HeadIsTransfer = true;
                input.TransferTargetKnown = true;
                input.TransferTarget = slotValue;
            }
        }
        else if (decode.Shape != KmonInlinePatchShape::RegisterIndirect &&
                 decode.TargetKnown)
        {
            input.HeadIsTransfer = true;
            input.TransferTargetKnown = true;
            input.TransferTarget = decode.Target;
        }

        if (input.TransferTargetKnown)
        {
            const PatchModule* destination =
                FindPatchModule(modules, input.TransferTarget);
            input.TargetInLoadedModule = destination != nullptr;
            input.TargetModuleNonInbox =
                destination != nullptr && destination->NonInbox;
            if (destination == nullptr)
            {
                std::vector<uint8_t> stub;
                if (ReadKernelBytes(
                        device,
                        input.TransferTarget,
                        kStubBytes,
                        &stub) &&
                    stub.size() >= 6)
                {
                    input.StubKnown = true;
                    uint64_t destinationAddress = 0;
                    if (KmonDecodeInlinePatchStub(
                            stub.data(),
                            stub.size(),
                            input.TransferTarget,
                            &destinationAddress))
                    {
                        input.StubIsTransfer = true;
                        input.StubDestinationKnown = true;
                        input.StubDestination = destinationAddress;
                    }
                }
            }
        }

        const KmonInlinePatchKind kind = KmonClassifyInlinePatch(input);
        if (kind == KmonInlinePatchKind::None)
        {
            continue;
        }

        // Two-scan confirmation: a page-in or a hotpatch transition lands in
        // the first pass only, and a single pass must not print a verdict.
        const std::wstring strikeKey =
            std::wstring(target.Symbol) + L":" + KmonInlinePatchKindName(kind);
        candidates.insert(strikeKey);
        uint32_t strikes = 0;
        {
            std::lock_guard<std::mutex> lock(WatchMutex);
            if (InlinePatchStrikes.size() > kMaxStrikeEntries)
            {
                InlinePatchStrikes.clear();
            }
            strikes = ++InlinePatchStrikes[strikeKey];
        }
        if (strikes < kStrikeThreshold)
        {
            continue;
        }
        if (emitted >= kEmitCap)
        {
            capped = true;
            continue;
        }

        const std::wstring function = std::wstring(target.Symbol);
        const std::wstring label = std::wstring(target.Entry->Label);
        std::wstring notes = L"function=" + function + L" shape=" +
            ShapeName(decode.Shape) + L" entry=" + PatchHex(target.Address);
        if (input.TransferTargetKnown)
        {
            notes += L" target=" + PatchHex(input.TransferTarget);
        }
        if (input.StubDestinationKnown)
        {
            notes += L" stub_destination=" + PatchHex(input.StubDestination);
        }
        notes += L" strikes=" + std::to_wstring(kStrikeThreshold);
        if (!target.Owner->Leaf.empty())
        {
            notes += L" owner=" + target.Owner->Leaf;
        }

        std::wstring summary;
        std::wstring kindName;
        if (kind == KmonInlinePatchKind::Int3Breakpoint)
        {
            kindName = L"hook.breakpoint";
            summary = label + L" (" + function +
                L") starts with an int3 trap at " + PatchHex(target.Address) +
                L"; the real prologue is not reachable";
        }
        else if (kind == KmonInlinePatchKind::TrampolineStub)
        {
            kindName = L"hook.inline";
            summary = label + L" (" + function +
                L") was rewritten to a head transfer into an unbacked trampoline stub at " +
                PatchHex(input.TransferTarget) + L" that continues to " +
                PatchHex(input.StubDestination);
        }
        else if (kind == KmonInlinePatchKind::UnbackedHeadTransfer)
        {
            kindName = L"hook.inline";
            summary = label + L" (" + function +
                L") was rewritten to a head transfer at " + PatchHex(target.Address) +
                L" into code no loaded module owns (" +
                PatchHex(input.TransferTarget) + L")";
        }
        else
        {
            kindName = L"hook.inline";
            const PatchModule* destination =
                FindPatchModule(modules, input.TransferTarget);
            const std::wstring destinationLeaf = destination != nullptr
                ? destination->Leaf
                : std::wstring(L"<unknown>");
            summary = label + L" (" + function +
                L") was rewritten to a head transfer into non-inbox module " +
                destinationLeaf + L" (" + PatchHex(input.TransferTarget) + L")";
        }

        EmitUnique(
            kindName,
            std::wstring(L"inline_patch:") + KmonInlinePatchKindName(kind) + L":" + function,
            target.Owner->Leaf,
            kLayer,
            summary,
            notes);
        emitted += 1;
    }

    {
        std::lock_guard<std::mutex> lock(WatchMutex);
        for (auto it = InlinePatchStrikes.begin(); it != InlinePatchStrikes.end();)
        {
            if (candidates.count(it->first) == 0)
            {
                it = InlinePatchStrikes.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }

    if (capped)
    {
        EmitUnique(
            L"hook.scan",
            L"reportcap:patch",
            std::wstring(),
            kLayer,
            L"inline patch scan capped at " + std::to_wstring(kEmitCap) +
                L" findings; more patched entries exist in this pass",
            L"reattach after the mapper watch window or raise the pass budget");
    }
    else
    {
        ClearEmittedKey(L"reportcap:patch");
    }

    if (readable == 0)
    {
        // No entry could be judged this pass, so a coverage note from an
        // earlier pass would describe a state that no longer holds.
        ClearEmittedKey(L"coverage:patch:prologue");
        EmitUnique(
            L"hook.scan",
            L"scan_failed:patch:prologue",
            std::wstring(),
            kLayer,
            L"inline patch scan read no entry point prologue; no patch verdict was possible",
            L"resolved=" + std::to_wstring(resolved.size()) +
                L" unreadable=" + std::to_wstring(skipped));
        return;
    }
    ClearEmittedKey(L"scan_failed:patch:prologue");
    if (skipped != 0)
    {
        EmitUnique(
            L"hook.scan",
            L"coverage:patch:prologue",
            std::wstring(),
            kLayer,
            L"inline patch scan could not judge " + std::to_wstring(skipped) + L" of " +
                std::to_wstring(resolved.size()) +
                L" hot kernel entry points this pass; those entries were not judged",
            L"an unreadable prologue or thunk slot is a deferral, not a verdict");
    }
    else
    {
        ClearEmittedKey(L"coverage:patch:prologue");
    }
}

bool KernelMonitorInlinePatchSelfTest()
{
    bool ok = false;

    do
    {
        // The byte decoder: every accepted hook shape, plus the ordinary
        // prologue bytes that must never be read as a transfer.
        uint8_t jump[16] = {};
        jump[0] = 0xE9;
        const int32_t jumpRelative = 0x100;
        std::memcpy(jump + 1, &jumpRelative, sizeof(jumpRelative));
        KmonInlinePatchDecode decode =
            KmonDecodeInlinePatchHead(jump, sizeof(jump), 0x2000);
        if (decode.Shape != KmonInlinePatchShape::NearJump ||
            !decode.TargetKnown ||
            decode.Target != 0x2000 + 5 + 0x100)
        {
            break;
        }

        uint8_t backwards[16] = {};
        backwards[0] = 0xE9;
        const int32_t backwardsRelative = -0x40;
        std::memcpy(backwards + 1, &backwardsRelative, sizeof(backwardsRelative));
        decode = KmonDecodeInlinePatchHead(backwards, sizeof(backwards), 0x2000);
        if (decode.Shape != KmonInlinePatchShape::NearJump ||
            decode.Target != 0x2000 + 5 - 0x40)
        {
            break;
        }

        uint8_t rip[16] = {};
        rip[0] = 0xFF;
        rip[1] = 0x25;
        const int32_t ripRelative = 0x30;
        std::memcpy(rip + 2, &ripRelative, sizeof(ripRelative));
        decode = KmonDecodeInlinePatchHead(rip, sizeof(rip), 0x2000);
        if (decode.Shape != KmonInlinePatchShape::RipIndirect ||
            decode.TargetKnown ||
            decode.SlotAddress != 0x2000 + 6 + 0x30)
        {
            break;
        }

        uint8_t absolute[16] = {};
        absolute[0] = 0x48;
        absolute[1] = 0xB8;
        const uint64_t absoluteTarget = 0xFFFFF80200001000ull;
        std::memcpy(absolute + 2, &absoluteTarget, sizeof(absoluteTarget));
        absolute[10] = 0xFF;
        absolute[11] = 0xE0;
        decode = KmonDecodeInlinePatchHead(absolute, sizeof(absolute), 0x2000);
        if (decode.Shape != KmonInlinePatchShape::RegisterImmediate ||
            decode.Target != absoluteTarget)
        {
            break;
        }

        uint8_t pushRet[16] = {};
        pushRet[0] = 0x68;
        const int32_t pushImmediate = 0x40;
        std::memcpy(pushRet + 1, &pushImmediate, sizeof(pushImmediate));
        pushRet[5] = 0xC3;
        decode = KmonDecodeInlinePatchHead(pushRet, sizeof(pushRet), 0x2000);
        if (decode.Shape != KmonInlinePatchShape::PushRet || decode.Target != 0x40)
        {
            break;
        }

        // The same shape with an immediate that sign-extends into the kernel
        // half still decodes to a destination, so the guard below cannot be
        // satisfied by rejecting the push/ret form itself.
        uint8_t pushRetKernel[16] = {};
        pushRetKernel[0] = 0x68;
        const int32_t pushKernelImmediate = (std::numeric_limits<int32_t>::min)();
        std::memcpy(pushRetKernel + 1, &pushKernelImmediate, sizeof(pushKernelImmediate));
        pushRetKernel[5] = 0xC3;
        const KmonInlinePatchDecode pushRetKernelDecode =
            KmonDecodeInlinePatchHead(pushRetKernel, sizeof(pushRetKernel), 0x2000);
        if (pushRetKernelDecode.Shape != KmonInlinePatchShape::PushRet ||
            !pushRetKernelDecode.TargetKnown ||
            pushRetKernelDecode.Target != 0xFFFFFFFF80000000ull)
        {
            break;
        }

        // A transfer destination has to be kernel code: the user half, the bare
        // 32-bit immediate, and a zero read are all data, while a kernel address
        // and the sign-extended top window are destinations.
        if (InlineTargetIsKernelCode(0) ||
            InlineTargetIsKernelCode(0x40) ||
            InlineTargetIsKernelCode(0x00007FF600001000ull) ||
            !InlineTargetIsKernelCode(0xFFFFF88000034000ull) ||
            !InlineTargetIsKernelCode(0xFFFFFFFF80000000ull))
        {
            break;
        }

        uint8_t trap[16] = {};
        trap[0] = 0xCC;
        decode = KmonDecodeInlinePatchHead(trap, sizeof(trap), 0x2000);
        if (decode.Shape != KmonInlinePatchShape::Trap)
        {
            break;
        }

        uint8_t registerJump[16] = {};
        registerJump[0] = 0xFF;
        registerJump[1] = 0xE0;
        decode = KmonDecodeInlinePatchHead(registerJump, sizeof(registerJump), 0x2000);
        if (decode.Shape != KmonInlinePatchShape::RegisterIndirect ||
            decode.TargetKnown)
        {
            break;
        }

        // A normal prologue and a mov reg,imm64 that is not a jump stay Plain.
        uint8_t plain[16] = { 0x48, 0x83, 0xEC, 0x28, 0x48, 0x89, 0x4C, 0x24,
                              0x30, 0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00 };
        decode = KmonDecodeInlinePatchHead(plain, sizeof(plain), 0x2000);
        if (decode.Shape != KmonInlinePatchShape::Plain || decode.TargetKnown)
        {
            break;
        }
        uint8_t loadOnly[16] = { 0x48, 0xB8, 0x00, 0x10, 0x00, 0x00, 0x02, 0xF8,
                                 0xFF, 0xFF, 0x48, 0x89, 0x05, 0x00, 0x00, 0x00 };
        decode = KmonDecodeInlinePatchHead(loadOnly, sizeof(loadOnly), 0x2000);
        if (decode.Shape != KmonInlinePatchShape::Plain || decode.TargetKnown)
        {
            break;
        }
        if (KmonDecodeInlinePatchHead(nullptr, 16, 0x2000).Shape !=
            KmonInlinePatchShape::Plain)
        {
            break;
        }

        // The stub decoder: a statically known continuation counts, a plain
        // body and the rip-slot form do not.
        uint64_t stubDestination = 0;
        if (!KmonDecodeInlinePatchStub(
                absolute,
                sizeof(absolute),
                0x3000,
                &stubDestination) ||
            stubDestination != absoluteTarget)
        {
            break;
        }
        if (KmonDecodeInlinePatchStub(plain, sizeof(plain), 0x3000, &stubDestination) ||
            KmonDecodeInlinePatchStub(rip, sizeof(rip), 0x3000, &stubDestination) ||
            KmonDecodeInlinePatchStub(absolute, sizeof(absolute), 0x3000, nullptr))
        {
            break;
        }

        // mov rax,imm64 followed by a jump through another register: the
        // immediate is not what that jump consumes, so it must be neither the
        // head's target nor a stub continuation.
        uint8_t mismatchedRegister[16] = {};
        mismatchedRegister[0] = 0x48;
        mismatchedRegister[1] = 0xB8;
        std::memcpy(mismatchedRegister + 2, &absoluteTarget, sizeof(absoluteTarget));
        mismatchedRegister[10] = 0xFF;
        mismatchedRegister[11] = 0xE1;
        decode = KmonDecodeInlinePatchHead(
            mismatchedRegister, sizeof(mismatchedRegister), 0x2000);
        if (decode.Shape != KmonInlinePatchShape::Plain || decode.TargetKnown)
        {
            break;
        }
        stubDestination = 0;
        if (KmonDecodeInlinePatchStub(
                mismatchedRegister,
                sizeof(mismatchedRegister),
                0x3000,
                &stubDestination))
        {
            break;
        }
        // The matching-register form still decodes, so the guard above cannot
        // be satisfied by rejecting every mov reg,imm64 head.
        decode = KmonDecodeInlinePatchHead(absolute, sizeof(absolute), 0x2000);
        if (decode.Shape != KmonInlinePatchShape::RegisterImmediate ||
            !decode.TargetKnown || decode.Target != absoluteTarget)
        {
            break;
        }

        const uint64_t ownerBase = 0xFFFFF80200000000ull;
        const uint64_t ownerEnd = 0xFFFFF80200100000ull;
        KmonInlinePatchInput normal = {};
        normal.PrologueKnown = true;
        normal.OwnerRangeKnown = true;
        normal.OwnerBase = ownerBase;
        normal.OwnerEnd = ownerEnd;
        normal.ModuleViewKnown = true;
        if (KmonClassifyInlinePatch(normal) != KmonInlinePatchKind::None)
        {
            break;
        }

        // An unreadable prologue is never a verdict, even with a trap flag.
        KmonInlinePatchInput unread = normal;
        unread.PrologueKnown = false;
        unread.HeadIsTrap = true;
        if (KmonClassifyInlinePatch(unread) != KmonInlinePatchKind::None)
        {
            break;
        }

        // int3 at the entry, with every other view missing.
        KmonInlinePatchInput trapEntry = normal;
        trapEntry.HeadIsTrap = true;
        trapEntry.OwnerRangeKnown = false;
        if (KmonClassifyInlinePatch(trapEntry) != KmonInlinePatchKind::Int3Breakpoint)
        {
            break;
        }

        // A head transfer into code no module owns is the mapper hook.
        KmonInlinePatchInput head = normal;
        head.HeadIsTransfer = true;
        head.TransferTargetKnown = true;
        head.TransferTarget = 0xFFFFF88000034000ull;
        if (KmonClassifyInlinePatch(head) != KmonInlinePatchKind::UnbackedHeadTransfer)
        {
            break;
        }

        // A decoded destination below the canonical kernel floor is not a head
        // transfer: the user half and the bare push immediate are data, so the
        // entry stays quiet instead of naming a value the jump cannot reach.
        KmonInlinePatchInput userTarget = head;
        userTarget.TransferTarget = 0x00007FF600001000ull;
        if (KmonClassifyInlinePatch(userTarget) != KmonInlinePatchKind::None)
        {
            break;
        }
        KmonInlinePatchInput shortImmediateTarget = head;
        shortImmediateTarget.TransferTarget = 0x40ull;
        if (KmonClassifyInlinePatch(shortImmediateTarget) != KmonInlinePatchKind::None)
        {
            break;
        }
        // The sign-extended top window is a kernel address, so the same shape
        // with that destination is still the verdict.
        KmonInlinePatchInput kernelImmediateTarget = head;
        kernelImmediateTarget.TransferTarget = 0xFFFFFFFF80000000ull;
        if (KmonClassifyInlinePatch(kernelImmediateTarget) !=
            KmonInlinePatchKind::UnbackedHeadTransfer)
        {
            break;
        }

        // The same transfer whose target bytes are a stub with a known
        // continuation is the pool trampoline.
        KmonInlinePatchInput trampoline = head;
        trampoline.StubKnown = true;
        trampoline.StubIsTransfer = true;
        trampoline.StubDestinationKnown = true;
        trampoline.StubDestination = ownerBase + 0x1234;
        if (KmonClassifyInlinePatch(trampoline) != KmonInlinePatchKind::TrampolineStub)
        {
            break;
        }

        // A stub whose own continuation is not kernel code is not a trampoline
        // into that value, while the head transfer into the unbacked stub still
        // is: the verdict degrades instead of disappearing.
        KmonInlinePatchInput userStub = trampoline;
        userStub.StubDestination = 0x40ull;
        if (KmonClassifyInlinePatch(userStub) != KmonInlinePatchKind::UnbackedHeadTransfer)
        {
            break;
        }

        // A transfer into another loaded module is reported only when that
        // module is not an inbox Windows image.
        KmonInlinePatchInput foreign = head;
        foreign.TargetInLoadedModule = true;
        foreign.TargetModuleNonInbox = true;
        if (KmonClassifyInlinePatch(foreign) !=
            KmonInlinePatchKind::ForeignModuleHeadTransfer)
        {
            break;
        }
        KmonInlinePatchInput forwarder = foreign;
        forwarder.TargetModuleNonInbox = false;
        if (KmonClassifyInlinePatch(forwarder) != KmonInlinePatchKind::None)
        {
            break;
        }

        // An in-image transfer is the normal kernel hotpatch.
        KmonInlinePatchInput hotpatch = head;
        hotpatch.TransferTarget = ownerBase + 0x8000;
        if (KmonClassifyInlinePatch(hotpatch) != KmonInlinePatchKind::None)
        {
            break;
        }

        // Fail-closed: an undecoded target, an unknown owner range, an invalid
        // owner range, and an unusable module view all withhold the verdict.
        KmonInlinePatchInput unknownTarget = head;
        unknownTarget.TransferTargetKnown = false;
        if (KmonClassifyInlinePatch(unknownTarget) != KmonInlinePatchKind::None)
        {
            break;
        }
        KmonInlinePatchInput noOwner = head;
        noOwner.OwnerRangeKnown = false;
        if (KmonClassifyInlinePatch(noOwner) != KmonInlinePatchKind::None)
        {
            break;
        }
        KmonInlinePatchInput emptyOwner = head;
        emptyOwner.OwnerEnd = emptyOwner.OwnerBase;
        if (KmonClassifyInlinePatch(emptyOwner) != KmonInlinePatchKind::None)
        {
            break;
        }
        KmonInlinePatchInput noModules = head;
        noModules.ModuleViewKnown = false;
        if (KmonClassifyInlinePatch(noModules) != KmonInlinePatchKind::None)
        {
            break;
        }

        if (KmonInlinePatchKindName(KmonInlinePatchKind::None)[0] != L'\0' ||
            std::wstring(KmonInlinePatchKindName(
                KmonInlinePatchKind::UnbackedHeadTransfer)) !=
                L"unbacked_head_transfer" ||
            std::wstring(KmonInlinePatchKindName(KmonInlinePatchKind::TrampolineStub)) !=
                L"trampoline_stub" ||
            std::wstring(KmonInlinePatchKindName(
                KmonInlinePatchKind::ForeignModuleHeadTransfer)) !=
                L"foreign_module_head_transfer" ||
            std::wstring(KmonInlinePatchKindName(KmonInlinePatchKind::Int3Breakpoint)) !=
                L"int3_breakpoint")
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}
