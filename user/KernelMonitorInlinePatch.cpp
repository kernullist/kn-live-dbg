#include "KernelMonitor.h"
#include "CallbackScanner.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <map>
#include <new>
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
    constexpr size_t kPrologueBytes = 32;
    constexpr size_t kStubBytes = 32;
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
            address < kKernelVaFloor || address > ~0ull - size)
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
    bool BuildPatchModules(SymbolEngine* symbols, std::vector<PatchModule>* modules)
    {
        bool complete = true;
        modules->clear();
        if (symbols == nullptr)
        {
            return false;
        }
        const std::vector<KernelModuleInfo> inventory = symbols->CopyModules();
        for (const KernelModuleInfo& module : inventory)
        {
            if (modules->size() >= kMaxModuleEntries)
            {
                complete = false;
                break;
            }
            if (module.Base < kKernelVaFloor || module.Size == 0)
            {
                complete = false;
                continue;
            }
            const uint64_t size = static_cast<uint64_t>(module.Size);
            if (module.Base > (std::numeric_limits<uint64_t>::max)() - size)
            {
                complete = false;
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
        return complete && !modules->empty();
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
        return KmonEnsureKernelModuleView(symbols);
    }

    using PatchConfirmations = std::map<std::wstring, KmonRepeatObservation>;

    struct CallbackProbeBatch
    {
        std::vector<size_t> Indices;
        bool Repeated = false;
    };

    CallbackProbeBatch SelectCallbackProbeBatch(
        const std::vector<uint64_t>& candidates,
        size_t budget,
        uint64_t* cursor,
        std::vector<uint64_t>* pending)
    {
        CallbackProbeBatch batch;
        if (!pending->empty())
        {
            batch.Repeated = true;
            const uint64_t endAnchor = pending->back();
            for (uint64_t address : *pending)
            {
                const auto found = std::lower_bound(candidates.begin(), candidates.end(), address);
                if (found != candidates.end() && *found == address && batch.Indices.size() < budget)
                {
                    batch.Indices.push_back(static_cast<size_t>(found - candidates.begin()));
                }
            }
            // Registration churn must not restart the entire batch. Confirm
            // survivors, then advance past its original last address even if
            // that address or every pending registration has disappeared.
            *cursor = endAnchor;
            pending->clear();
        }
        else
        {
            if (!candidates.empty())
            {
                // Resolve the address anchor only against this fresh view.
                // An ordinal from the repeat view can point behind the old
                // anchor when registrations change again before this pass.
                const auto next = std::upper_bound(candidates.begin(), candidates.end(), *cursor);
                const size_t start = next != candidates.end()
                    ? static_cast<size_t>(next - candidates.begin()) : 0;
                const size_t count = (std::min)(budget, candidates.size());
                for (size_t index = 0; index < count; ++index)
                {
                    const size_t selected = (start + index) % candidates.size();
                    batch.Indices.push_back(selected);
                    pending->push_back(candidates[selected]);
                }
            }
        }
        return batch;
    }

    bool ReserveCallbackConfirmationBatch(
        PatchConfirmations* confirmations,
        const std::set<std::wstring>& batchEntries,
        std::vector<std::wstring>* expired)
    {
        size_t outsideBatch = 0;
        for (const auto& entry : *confirmations)
        {
            const size_t separator = entry.first.find(L':');
            if (batchEntries.count(entry.first.substr(0, separator)) == 0)
            {
                ++outsideBatch;
            }
        }
        const bool reset = outsideBatch + batchEntries.size() > kMaxStrikeEntries;
        if (reset)
        {
            for (const auto& entry : *confirmations)
            {
                expired->push_back(entry.first);
            }
            confirmations->clear();
        }
        return reset;
    }

    PatchConfirmations TakePatchConfirmations(PatchConfirmations* current)
    {
        PatchConfirmations previous;
        if (current != nullptr)
        {
            previous.swap(*current);
        }
        return previous;
    }

    void EraseConfirmationEventKeys(
        std::unordered_set<std::wstring>* emitted,
        const wchar_t* prefix,
        size_t prefixLength) noexcept
    {
        if (emitted != nullptr)
        {
            for (auto item = emitted->begin(); item != emitted->end();)
            {
                if (item->compare(0, prefixLength, prefix) == 0)
                {
                    item = emitted->erase(item);
                }
                else
                {
                    ++item;
                }
            }
        }
    }

    void ResetCallbackConfirmations(
        PatchConfirmations* current,
        std::vector<uint64_t>* batch,
        std::unordered_set<std::wstring>* emitted) noexcept
    {
        current->clear();
        batch->clear();
        constexpr wchar_t prefix[] = L"callback_redirect:";
        EraseConfirmationEventKeys(emitted, prefix, sizeof(prefix) / sizeof(prefix[0]) - 1);
    }

    uint32_t ConfirmPatchObservation(
        const PatchConfirmations& previous,
        PatchConfirmations* current,
        const std::wstring& key)
    {
        uint32_t strikes = 0;
        if (current != nullptr)
        {
            const auto found = previous.find(key);
            KmonRepeatObservation observation = found != previous.end() ? found->second : KmonRepeatObservation{};
            strikes = observation.Observe(key, GetTickCount64(), 60000);
            (*current)[key] = std::move(observation);
        }
        return strikes;
    }

    bool CallbackProbeSchedulingSelfTest()
    {
        bool ok = false;
        do
        {
            constexpr uint64_t base = 0xFFFFF80040000000ull;
            std::vector<uint64_t> candidates;
            for (size_t index = 0; index < 8192; ++index)
            {
                candidates.push_back(base + index * 0x100);
            }
            PatchConfirmations confirmations;
            std::vector<uint64_t> pendingBatch;
            std::set<uint64_t> confirmed;
            uint64_t cursor = 0;
            bool valid = true;
            bool capacityObserved = false;
            for (size_t pass = 0; pass < 256 && valid; ++pass)
            {
                const CallbackProbeBatch batch = SelectCallbackProbeBatch(
                    candidates, 64, &cursor, &pendingBatch);
                std::set<std::wstring> entries;
                for (size_t index : batch.Indices)
                {
                    entries.insert(PatchHex(candidates[index]));
                }
                std::vector<std::wstring> expired;
                const bool reset = ReserveCallbackConfirmationBatch(&confirmations, entries, &expired);
                capacityObserved = capacityObserved || reset;
                if (batch.Indices.size() != 64 || batch.Repeated != ((pass & 1) != 0) ||
                    (batch.Repeated && reset))
                {
                    valid = false;
                    break;
                }
                for (size_t index : batch.Indices)
                {
                    const std::wstring key = PatchHex(candidates[index]) + L":target";
                    if (ConfirmPatchObservation(confirmations, &confirmations, key) >= kStrikeThreshold)
                    {
                        confirmed.insert(candidates[index]);
                    }
                }
                valid = confirmations.size() <= kMaxStrikeEntries;
            }
            if (!valid || !capacityObserved || confirmed.size() != candidates.size() ||
                cursor != candidates.back() || !pendingBatch.empty())
            {
                break;
            }

            // Replacing the lowest registration on every pass must not pin
            // the cursor ahead of stable routines in later batches.
            confirmations.clear();
            pendingBatch.clear();
            confirmed.clear();
            cursor = 0;
            for (size_t pass = 0; pass < 256 && valid; ++pass)
            {
                std::vector<uint64_t> live;
                live.push_back(base - ((pass & 1) != 0 ? 0x100 : 0x200));
                live.insert(live.end(), candidates.begin(), candidates.end() - 1);
                const CallbackProbeBatch batch = SelectCallbackProbeBatch(live, 64, &cursor, &pendingBatch);
                std::set<std::wstring> entries;
                for (size_t index : batch.Indices)
                {
                    entries.insert(PatchHex(live[index]));
                }
                std::vector<std::wstring> expired;
                const bool reset = ReserveCallbackConfirmationBatch(&confirmations, entries, &expired);
                if (batch.Indices.size() > 64 || batch.Repeated != ((pass & 1) != 0) ||
                    (batch.Repeated && reset) || (pass == 1 && batch.Indices.size() != 63))
                {
                    valid = false;
                    break;
                }
                for (size_t index : batch.Indices)
                {
                    const uint64_t address = live[index];
                    const std::wstring key = PatchHex(address) + L":target";
                    if (ConfirmPatchObservation(confirmations, &confirmations, key) >= kStrikeThreshold &&
                        address >= base)
                    {
                        confirmed.insert(address);
                    }
                }
                valid = confirmations.size() <= kMaxStrikeEntries;
            }
            if (!valid || confirmed.size() != 8191 || cursor != candidates[8190] || !pendingBatch.empty())
            {
                break;
            }

            // Alternating entire prefixes must not turn an address anchor
            // into an ordinal that restarts at zero in the next fresh view.
            confirmations.clear();
            pendingBatch.clear();
            cursor = 0;
            bool stableConfirmed = false;
            const uint64_t stableAddress = base + 1000 * 0x100;
            for (size_t pass = 0; pass < 256; ++pass)
            {
                std::vector<uint64_t> live;
                for (size_t index = 0; index < 64; ++index)
                {
                    live.push_back(base + (index + ((pass & 1) != 0 ? 64 : 0)) * 0x100);
                }
                live.push_back(stableAddress);
                const CallbackProbeBatch batch = SelectCallbackProbeBatch(live, 64, &cursor, &pendingBatch);
                for (size_t index : batch.Indices)
                {
                    if (live[index] == stableAddress &&
                        ConfirmPatchObservation(confirmations, &confirmations, L"stable") >= kStrikeThreshold)
                    {
                        stableConfirmed = true;
                    }
                }
            }
            if (!stableConfirmed)
            {
                break;
            }

            // Neither an exact fit nor a boundary in the middle of a batch
            // may clear its first observations on the second visit.
            for (size_t priorCount : {size_t(4032), size_t(4070)})
            {
                confirmations.clear();
                pendingBatch.clear();
                cursor = 0;
                for (size_t index = 0; index < priorCount; ++index)
                {
                    const std::wstring key = PatchHex(base - 0x1000000 + index * 0x100) + L":old";
                    confirmations[key] = {key, GetTickCount64(), 2};
                }
                for (size_t pass = 0; pass < 2 && valid; ++pass)
                {
                    const CallbackProbeBatch batch = SelectCallbackProbeBatch(
                        candidates, 64, &cursor, &pendingBatch);
                    std::set<std::wstring> entries;
                    for (size_t index : batch.Indices)
                    {
                        entries.insert(PatchHex(candidates[index]));
                    }
                    std::vector<std::wstring> expired;
                    const bool reset = ReserveCallbackConfirmationBatch(&confirmations, entries, &expired);
                    const bool expectedReset = priorCount == 4070 && pass == 0;
                    if (reset != expectedReset || expired.size() != (expectedReset ? priorCount : 0))
                    {
                        valid = false;
                        break;
                    }
                    for (size_t index : batch.Indices)
                    {
                        const std::wstring key = PatchHex(candidates[index]) + L":target";
                        if (ConfirmPatchObservation(confirmations, &confirmations, key) != pass + 1)
                        {
                            valid = false;
                            break;
                        }
                    }
                    valid = valid && confirmations.size() <= kMaxStrikeEntries;
                }
            }
            if (!valid)
            {
                break;
            }

            // An outer failure starts the current batch again and discards
            // both confirmation and its associated deduplication identity.
            confirmations.clear();
            pendingBatch.clear();
            cursor = 0;
            const std::wstring key = PatchHex(candidates.front()) + L":target";
            CallbackProbeBatch batch = SelectCallbackProbeBatch(candidates, 64, &cursor, &pendingBatch);
            if (batch.Repeated || cursor != 0 || pendingBatch.size() != 64 ||
                ConfirmPatchObservation(confirmations, &confirmations, key) != 1)
            {
                break;
            }
            ResetCallbackConfirmations(&confirmations, &pendingBatch, nullptr);
            if (!confirmations.empty() || !pendingBatch.empty())
            {
                break;
            }
            batch = SelectCallbackProbeBatch(candidates, 64, &cursor, &pendingBatch);
            if (batch.Repeated || ConfirmPatchObservation(confirmations, &confirmations, key) != 1)
            {
                break;
            }
            batch = SelectCallbackProbeBatch(candidates, 64, &cursor, &pendingBatch);
            if (!batch.Repeated || ConfirmPatchObservation(confirmations, &confirmations, key) != 2)
            {
                break;
            }

            // New registrations do not replace routines awaiting confirmation.
            // Removal confirms survivors and advances using the old end anchor.
            std::vector<uint64_t> changing = {base, base + 0x100, base + 0x200};
            pendingBatch.clear();
            cursor = 0;
            SelectCallbackProbeBatch(changing, 2, &cursor, &pendingBatch);
            changing.insert(changing.begin(), base - 0x100);
            batch = SelectCallbackProbeBatch(changing, 2, &cursor, &pendingBatch);
            if (!batch.Repeated || batch.Indices != std::vector<size_t>({1, 2}) || cursor != base + 0x100)
            {
                break;
            }
            SelectCallbackProbeBatch(changing, 2, &cursor, &pendingBatch);
            changing.pop_back();
            batch = SelectCallbackProbeBatch(changing, 2, &cursor, &pendingBatch);
            if (!batch.Repeated || batch.Indices != std::vector<size_t>({0}) ||
                !pendingBatch.empty() || cursor != base - 0x100)
            {
                break;
            }
            changing = {base, base + 0x100, base + 0x200, base + 0x300};
            cursor = 0;
            SelectCallbackProbeBatch(changing, 2, &cursor, &pendingBatch);
            changing = {base + 0x80, base + 0x200};
            batch = SelectCallbackProbeBatch(changing, 2, &cursor, &pendingBatch);
            if (!batch.Repeated || !batch.Indices.empty() || cursor != base + 0x100 || !pendingBatch.empty())
            {
                break;
            }
            changing = {base, base + 0x100, base + 0x200, base + 0x300};
            cursor = base + 0x200;
            SelectCallbackProbeBatch(changing, 2, &cursor, &pendingBatch);
            changing = {base - 0x80, base + 0x80, base + 0x100, base + 0x200, base + 0x300};
            batch = SelectCallbackProbeBatch(changing, 2, &cursor, &pendingBatch);
            if (!batch.Repeated || batch.Indices != std::vector<size_t>({4}) ||
                cursor != base || !pendingBatch.empty())
            {
                break;
            }
            cursor = 0;
            SelectCallbackProbeBatch(changing, 2, &cursor, &pendingBatch);
            batch = SelectCallbackProbeBatch({}, 64, &cursor, &pendingBatch);
            if (!batch.Repeated || !batch.Indices.empty() || !pendingBatch.empty() || cursor != base + 0x80)
            {
                break;
            }
            batch = SelectCallbackProbeBatch(changing, 2, &cursor, &pendingBatch);
            if (batch.Repeated || batch.Indices != std::vector<size_t>({2, 3}))
            {
                break;
            }
            ok = true;
        } while (false);
        return ok;
    }

    void RetireInlineObservationKeys(
        const PatchConfirmations& current,
        std::unordered_set<std::wstring>* emitted) noexcept
    {
        constexpr wchar_t prefix[] = L"inline_patch:";
        constexpr size_t prefixLength = sizeof(prefix) / sizeof(prefix[0]) - 1;
        for (auto item = emitted->begin(); item != emitted->end();)
        {
            bool retained = item->compare(0, prefixLength, prefix) != 0;
            if (!retained)
            {
                for (const auto& entry : current)
                {
                    if (item->size() - prefixLength == entry.first.size() &&
                        item->compare(prefixLength, entry.first.size(), entry.first) == 0)
                    {
                        retained = true;
                        break;
                    }
                }
            }
            if (retained)
            {
                ++item;
            }
            else
            {
                item = emitted->erase(item);
            }
        }
    }

    std::wstring PatchObservationEventKey(const std::wstring& observation)
    {
        return L"inline_patch:" + observation;
    }

    bool PatchSampleCoverageComplete(const std::vector<uint8_t>& sample, size_t requested)
    {
        return sample.size() == requested;
    }

    template<typename Emitter>
    void EmitPatchCandidate(uint32_t* emitted, bool* capped, Emitter emit)
    {
        if (*emitted >= kEmitCap)
        {
            *capped = true;
        }
        else if (emit())
        {
            ++(*emitted);
        }
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

    KmonInlinePatchDecode PrepareInlinePatchInput(
        const std::vector<uint8_t>& bytes,
        uint64_t address,
        KmonInlinePatchInput* input)
    {
        KmonInlinePatchDecode decode = {};
        if (input != nullptr && address != 0 && !bytes.empty())
        {
            decode = KmonDecodeInlinePatchHead(bytes.data(), bytes.size(), address);
            input->PrologueKnown = true;
            input->HeadIsTrap = decode.Shape == KmonInlinePatchShape::Trap;
            input->HeadIsTransfer = decode.TargetKnown ||
                decode.Shape == KmonInlinePatchShape::RipIndirect ||
                decode.Shape == KmonInlinePatchShape::RegisterIndirect;
            input->TransferTargetKnown = decode.TargetKnown;
            input->TransferTarget = decode.Target;
        }
        return decode;
    }

    struct CallbackHeadObservation
    {
        uint64_t Target = 0;
        bool Complete = false;
    };

    template<typename Reader>
    CallbackHeadObservation ProbeCallbackRedirect(
        Reader& read,
        const std::vector<PatchModule>& modules,
        uint64_t entry)
    {
        CallbackHeadObservation observation = {};
        std::set<uint64_t> visited;
        uint64_t current = entry;
        for (size_t hop = 0; hop < 4; ++hop)
        {
            if (!InlineTargetIsKernelCode(current) ||
                FindPatchModule(modules, current) == nullptr ||
                !visited.insert(current).second)
            {
                break;
            }
            std::vector<uint8_t> bytes;
            if (!read(current, kPrologueBytes, &bytes) || bytes.size() != kPrologueBytes)
            {
                break;
            }
            KmonInlinePatchInput input = {};
            const KmonInlinePatchDecode decode = PrepareInlinePatchInput(bytes, current, &input);
            if (decode.Shape == KmonInlinePatchShape::Plain ||
                decode.Shape == KmonInlinePatchShape::Trap)
            {
                observation.Complete = true;
                break;
            }
            uint64_t target = decode.Target;
            if (decode.Shape == KmonInlinePatchShape::RipIndirect)
            {
                std::vector<uint8_t> slot;
                if (!InlineTargetIsKernelCode(decode.SlotAddress) ||
                    !read(decode.SlotAddress, sizeof(uint64_t), &slot) ||
                    slot.size() != sizeof(uint64_t))
                {
                    break;
                }
                std::memcpy(&target, slot.data(), sizeof(target));
            }
            else if (!decode.TargetKnown)
            {
                break;
            }
            if (!InlineTargetIsKernelCode(target))
            {
                break;
            }
            if (FindPatchModule(modules, target) == nullptr)
            {
                observation.Target = target;
                observation.Complete = true;
                break;
            }
            current = target;
        }
        return observation;
    }

    const wchar_t* ShapeName(KmonInlinePatchShape shape)
    {
        switch (shape)
        {
        case KmonInlinePatchShape::Trap:
            return L"int3";
        case KmonInlinePatchShape::NearJump:
            return L"jmp relative";
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
    InlineConfirmationAttempt attempt(this);
    PatchConfirmations previous;
    {
        std::lock_guard<std::mutex> lock(WatchMutex);
        // Every attempted scan breaks confirmation unless it observes the
        // same candidate again. Early failures must not retain an old strike.
        previous = TakePatchConfirmations(&InlinePatchStrikes);
    }
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
    if (!BuildPatchModules(symbols, &modules))
    {
        // An empty module view cannot tell an in-image hotpatch from a hook,
        // so it is a deferral, the same rule AddressOwnedByLoadedModule uses
        // for pointers.
        EmitUnique(
            L"hook.scan",
            L"scan_failed:patch:modules",
            std::wstring(),
            kLayer,
            L"inline patch scan skipped; kernel module range snapshot was incomplete",
            L"empty, invalid or truncated module ranges cannot establish an unbacked target");
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
            prologue.size() != kPrologueBytes)
        {
            // A prologue that cannot be read proves nothing: the entry is a
            // deferral for this pass and the scan continues with the rest.
            ++skipped;
            continue;
        }
        ++readable;
        const bool partialPrologue = !PatchSampleCoverageComplete(prologue, kPrologueBytes);
        if (partialPrologue)
        {
            ++skipped;
        }

        const KmonInlinePatchDecode decode =
            PrepareInlinePatchInput(prologue, target.Address, &input);
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
                if (!partialPrologue)
                {
                    ++skipped;
                }
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
                std::vector<uint8_t> confirmedStub;
                if (ReadKernelBytes(
                        device,
                        input.TransferTarget,
                        kStubBytes,
                        &stub) &&
                    stub.size() == kStubBytes &&
                    ReadKernelBytes(device, input.TransferTarget, kStubBytes, &confirmedStub) &&
                    stub == confirmedStub)
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

        std::vector<uint8_t> confirmedPrologue;
        uint64_t confirmedSlot = 0;
        if (!ReadKernelBytes(device, target.Address, kPrologueBytes, &confirmedPrologue) ||
            confirmedPrologue != prologue ||
            (decode.Shape == KmonInlinePatchShape::RipIndirect &&
                (!ReadKernelU64(device, decode.SlotAddress, &confirmedSlot) || confirmedSlot != input.TransferTarget)))
        {
            ++skipped;
            continue;
        }
        // Different addresses, bytes or targets must not accumulate confirmation.
        std::wstring strikeKey = std::wstring(target.Symbol) + L":" + KmonInlinePatchKindName(kind) +
            L":" + PatchHex(target.Address) + L":" + PatchHex(input.TransferTarget) +
            L":" + PatchHex(input.StubDestination) + L":" + PatchHex(target.Owner->Base) +
            L":" + PatchHex(target.Owner->End);
        for (uint8_t byte : prologue)
        {
            strikeKey += L":" + std::to_wstring(byte);
        }
        candidates.insert(strikeKey);
        uint32_t strikes = 0;
        {
            std::lock_guard<std::mutex> lock(WatchMutex);
            if (InlinePatchStrikes.size() > kMaxStrikeEntries)
            {
                InlinePatchStrikes.clear();
            }
            strikes = ConfirmPatchObservation(previous, &InlinePatchStrikes, strikeKey);
        }
        if (strikes < kStrikeThreshold)
        {
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
        notes += L" strikes=" + std::to_wstring(kStrikeThreshold) +
            L" evidence=entry_shape original_bytes=unknown execution=not_established";
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
                L"; breakpoint ownership and purpose are unknown";
        }
        else if (kind == KmonInlinePatchKind::TrampolineStub)
        {
            kindName = L"hook.inline";
            summary = label + L" (" + function +
                L") has a head transfer into an unowned trampoline-shaped stub at " +
                PatchHex(input.TransferTarget) + L" that continues to " +
                PatchHex(input.StubDestination);
        }
        else if (kind == KmonInlinePatchKind::UnbackedHeadTransfer)
        {
            kindName = L"hook.inline";
            summary = label + L" (" + function +
                L") has a head transfer at " + PatchHex(target.Address) +
                L" into an address no loaded module owns (" +
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
                L") has a head transfer into non-inbox module " +
                destinationLeaf + L" (" + PatchHex(input.TransferTarget) + L")";
        }

        EmitPatchCandidate(&emitted, &capped, [&]()
        {
            return EmitUnique(
                kindName,
                PatchObservationEventKey(strikeKey),
                target.Owner->Leaf,
                kLayer,
                summary,
                notes);
        });
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
                L" leads; more entry-shape candidates exist in this pass",
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
            L"unreadable or partial prologue/thunk samples leave coverage incomplete");
    }
    else
    {
        ClearEmittedKey(L"coverage:patch:prologue");
    }
    {
        std::lock_guard<std::mutex> lock(WatchMutex);
        RetireInlineObservationKeys(InlinePatchStrikes, &EmittedMapperKeys);
    }
    attempt.Complete();
}

KernelMonitor::InlineConfirmationAttempt::~InlineConfirmationAttempt() noexcept
{
    if (!Completed)
    {
        Owner->InvalidateInlinePatchConfirmations();
    }
}

void KernelMonitor::InvalidateInlinePatchConfirmations() noexcept
{
    std::lock_guard<std::mutex> lock(WatchMutex);
    InlinePatchStrikes.clear();
    constexpr wchar_t prefix[] = L"inline_patch:";
    EraseConfirmationEventKeys(&EmittedMapperKeys, prefix, sizeof(prefix) / sizeof(prefix[0]) - 1);
}

KernelMonitor::CallbackConfirmationAttempt::~CallbackConfirmationAttempt() noexcept
{
    if (!Completed)
    {
        Owner->InvalidateCallbackRedirectConfirmations();
    }
}

void KernelMonitor::InvalidateCallbackRedirectConfirmations() noexcept
{
    std::lock_guard<std::mutex> lock(WatchMutex);
    ResetCallbackConfirmations(&CallbackRedirectStrikes, &CallbackRedirectBatch, &EmittedMapperKeys);
}

bool KernelMonitor::ScanCallbackInlineTargets(const std::vector<KernelCallbackRecord>& records)
{
    CallbackConfirmationAttempt attempt(this);
    constexpr size_t kCallbackBudget = 64;
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    {
        std::lock_guard<std::mutex> lock(StateMutex);
        device = Device;
        symbols = Symbols;
    }
    std::vector<PatchModule> modules;
    if (device == nullptr || !device->IsOpen() || !EnsurePatchModules(symbols) ||
        !BuildPatchModules(symbols, &modules))
    {
        EmitUnique(L"hook.scan", L"scan_failed:callback_redirect:inventory", std::wstring(),
            L"callback_redirect", L"callback entry scan lacks a complete kernel module view",
            L"pending callback redirect confirmations were cleared");
        return false;
    }
    ClearEmittedKey(L"scan_failed:callback_redirect:inventory");

    struct CallbackTarget
    {
        uint64_t Address = 0;
        std::wstring Label;
        std::wstring Module;
    };
    std::vector<CallbackTarget> candidates;
    std::set<uint64_t> seen;
    std::set<std::wstring> liveEntries;
    for (const KernelCallbackRecord& record : records)
    {
        if (record.Poisoned)
        {
            continue;
        }
        const uint64_t functions[] = {record.Function, record.PostFunction};
        for (uint64_t function : functions)
        {
            const PatchModule* owner = FindPatchModule(modules, function);
            if (owner == nullptr || !seen.insert(function).second)
            {
                continue;
            }
            CallbackTarget candidate = {};
            candidate.Address = function;
            candidate.Label = record.Kind + L":" + record.Target;
            candidate.Module = owner->Leaf;
            candidates.push_back(std::move(candidate));
            liveEntries.insert(PatchHex(function));
        }
    }
    std::sort(candidates.begin(), candidates.end(), [](const CallbackTarget& left, const CallbackTarget& right)
    {
        return left.Address < right.Address;
    });
    std::vector<uint64_t> addresses;
    addresses.reserve(candidates.size());
    for (const CallbackTarget& candidate : candidates)
    {
        addresses.push_back(candidate.Address);
    }
    std::vector<std::wstring> expired;
    CallbackProbeBatch batch;
    bool confirmationsReset = false;
    {
        std::lock_guard<std::mutex> lock(WatchMutex);
        for (auto it = CallbackRedirectStrikes.begin(); it != CallbackRedirectStrikes.end();)
        {
            const size_t separator = it->first.find(L':');
            if (liveEntries.count(it->first.substr(0, separator)) == 0)
            {
                expired.push_back(it->first);
                it = CallbackRedirectStrikes.erase(it);
            }
            else
            {
                ++it;
            }
        }
        batch = SelectCallbackProbeBatch(
            addresses, kCallbackBudget, &CallbackRedirectCursor, &CallbackRedirectBatch);
        std::set<std::wstring> batchEntries;
        for (size_t index : batch.Indices)
        {
            batchEntries.insert(PatchHex(candidates[index].Address));
        }
        // Reserve for the whole batch before any observation. Its second
        // visit reuses these slots, so a capacity boundary cannot split it.
        confirmationsReset = ReserveCallbackConfirmationBatch(
            &CallbackRedirectStrikes, batchEntries, &expired);
    }
    for (const std::wstring& key : expired)
    {
        ClearEmittedKey(L"callback_redirect:" + key);
    }
    if (confirmationsReset)
    {
        EmitUnique(L"hook.scan", L"coverage:callback_redirect:state", std::wstring(),
            L"callback_redirect", L"callback confirmation cache reached capacity; a full batch was reserved",
            L"older confirmation history and deduplication were retired; capacity=" +
                std::to_wstring(kMaxStrikeEntries));
    }
    else
    {
        ClearEmittedKey(L"coverage:callback_redirect:state");
    }

    size_t incomplete = 0;
    const size_t count = batch.Indices.size();
    auto read = [&](uint64_t address, size_t size, std::vector<uint8_t>* bytes)
    {
        return ReadKernelBytes(device, address, size, bytes);
    };
    for (size_t index = 0; index < count; ++index)
    {
        if (StopRequested.load())
        {
            return false;
        }
        const CallbackTarget& candidate = candidates[batch.Indices[index]];
        const CallbackHeadObservation observation = ProbeCallbackRedirect(read, modules, candidate.Address);
        if (!observation.Complete)
        {
            ++incomplete;
        }
        const std::wstring entryPrefix = PatchHex(candidate.Address) + L":";
        const std::wstring strikeKey = entryPrefix + PatchHex(observation.Target);
        uint32_t strikes = 0;
        expired.clear();
        {
            std::lock_guard<std::mutex> lock(WatchMutex);
            for (auto it = CallbackRedirectStrikes.begin(); it != CallbackRedirectStrikes.end();)
            {
                if (it->first.compare(0, entryPrefix.size(), entryPrefix) == 0 &&
                    (!observation.Complete || observation.Target == 0 || it->first != strikeKey))
                {
                    expired.push_back(it->first);
                    it = CallbackRedirectStrikes.erase(it);
                }
                else
                {
                    ++it;
                }
            }
            if (observation.Complete && observation.Target != 0)
            {
                strikes = ConfirmPatchObservation(
                    CallbackRedirectStrikes, &CallbackRedirectStrikes, strikeKey);
            }
        }
        for (const std::wstring& key : expired)
        {
            ClearEmittedKey(L"callback_redirect:" + key);
        }
        if (strikes >= kStrikeThreshold)
        {
            EmitUnique(L"hook.inline", L"callback_redirect:" + strikeKey,
                candidate.Module, L"callback_redirect",
                candidate.Label + L" recently observed execution entry " + PatchHex(candidate.Address) +
                    L" redirects outside loaded kernel modules to " + PatchHex(observation.Target),
                L"entry=" + PatchHex(candidate.Address) + L" target=" + PatchHex(observation.Target) +
                    L" confirmed_observations=2 max_transfer_hops=4 registration_lifetime=not_proven");
        }
    }
    if (incomplete != 0)
    {
        EmitUnique(L"hook.scan", L"coverage:callback_redirect:read", std::wstring(),
            L"callback_redirect", L"some callback entry transfers could not be resolved",
            L"incomplete=" + std::to_wstring(incomplete) + L" sampled=" + std::to_wstring(count) +
                L"; unreadable, register-indirect, cyclic or over-budget chains clear pending confirmation");
    }
    else
    {
        ClearEmittedKey(L"coverage:callback_redirect:read");
    }
    if (candidates.size() > count)
    {
        EmitUnique(L"hook.scan", L"coverage:callback_redirect:budget", std::wstring(),
            L"callback_redirect", L"callback entry scan repeats each bounded sample before rotating registered routines",
            L"per_pass=" + std::to_wstring(count) + L" candidates=" + std::to_wstring(candidates.size()));
    }
    else
    {
        ClearEmittedKey(L"coverage:callback_redirect:budget");
    }
    attempt.Complete();
    return true;
}

bool KernelMonitorInlinePatchSelfTest()
{
    bool ok = false;

    do
    {
        if (!CallbackProbeSchedulingSelfTest())
        {
            break;
        }
        KernelMonitor attempts;
        bool attemptValid = true;
        for (uint32_t scenario = 0; scenario < 6 && attemptValid; ++scenario)
        {
            const bool callback = scenario < 3;
            const uint32_t outcome = scenario % 3;
            attempts.CallbackRedirectStrikes.clear();
            attempts.CallbackRedirectStrikes[L"pending"] = {L"pending", GetTickCount64(), 1};
            attempts.InlinePatchStrikes.clear();
            attempts.InlinePatchStrikes[L"pending"] = {L"pending", GetTickCount64(), 1};
            attempts.CallbackRedirectBatch.clear();
            attempts.CallbackRedirectBatch.push_back(0xFFFF800010000000ull);
            attempts.CallbackRedirectCursor = 321;
            attempts.EmittedMapperKeys.clear();
            attempts.EmittedMapperKeys.insert(L"callback_redirect:pending");
            attempts.EmittedMapperKeys.insert(L"inline_patch:pending");
            attempts.EmittedMapperKeys.insert(L"other:keep");
            bool completed = false;
            bool threw = false;
            try
            {
                auto runAttempt = [&](auto& attempt)
                {
                    if (outcome == 0)
                    {
                        return false;
                    }
                    if (outcome == 1)
                    {
                        throw std::bad_alloc();
                    }
                    attempt.Complete();
                    return true;
                };
                if (callback)
                {
                    KernelMonitor::CallbackConfirmationAttempt attempt(&attempts);
                    completed = runAttempt(attempt);
                }
                else
                {
                    KernelMonitor::InlineConfirmationAttempt attempt(&attempts);
                    completed = runAttempt(attempt);
                }
            }
            catch (const std::bad_alloc&)
            {
                threw = true;
            }
            const bool retained = outcome == 2;
            const size_t expected = retained ? 1 : 0;
            attemptValid = completed == retained && threw == (outcome == 1) &&
                attempts.CallbackRedirectStrikes.size() == (callback ? expected : 1) &&
                attempts.InlinePatchStrikes.size() == (callback ? 1 : expected) &&
                attempts.CallbackRedirectBatch.size() == (callback ? expected : 1) &&
                attempts.EmittedMapperKeys.count(L"callback_redirect:pending") == (callback ? expected : 1) &&
                attempts.EmittedMapperKeys.count(L"inline_patch:pending") == (callback ? 1 : expected) &&
                attempts.EmittedMapperKeys.count(L"other:keep") == 1 &&
                attempts.CallbackRedirectCursor == 321;
            PatchConfirmations& observations = callback
                ? attempts.CallbackRedirectStrikes : attempts.InlinePatchStrikes;
            if (ConfirmPatchObservation(observations, &observations, L"pending") != (retained ? 2u : 1u))
            {
                attemptValid = false;
            }
        }
        if (!attemptValid)
        {
            break;
        }
        PatchConfirmations pending;
        const std::wstring candidateKey = L"entry:target";
        PatchConfirmations previous = TakePatchConfirmations(&pending);
        if (ConfirmPatchObservation(previous, &pending, candidateKey) != 1)
        {
            break;
        }
        // An attempted scan that returns before observing candidates must
        // sever confirmation across that failed attempt.
        previous = TakePatchConfirmations(&pending);
        previous = TakePatchConfirmations(&pending);
        if (ConfirmPatchObservation(previous, &pending, candidateKey) != 1)
        {
            break;
        }
        previous = TakePatchConfirmations(&pending);
        if (ConfirmPatchObservation(previous, &pending, candidateKey) != 2)
        {
            break;
        }
        // Callback rotation retains unvisited entries, but a failed outer
        // callback scan uses the same invalidation before a later visit.
        TakePatchConfirmations(&pending);
        if (ConfirmPatchObservation(pending, &pending, candidateKey) != 1 ||
            ConfirmPatchObservation(pending, &pending, candidateKey) != 2)
        {
            break;
        }
        std::set<size_t> reported;
        bool budgetValid = true;
        for (size_t pass = 0; pass < 2; ++pass)
        {
            uint32_t emitted = 0;
            bool capped = false;
            for (size_t index = 0; index < 18; ++index)
            {
                EmitPatchCandidate(&emitted, &capped, [&]()
                {
                    return reported.insert(index).second;
                });
            }
            if (emitted > kEmitCap || (pass == 0 && (!capped || emitted != 16)))
            {
                budgetValid = false;
            }
        }
        if (!budgetValid || reported.size() != 18)
        {
            break;
        }
        PatchConfirmations emittedIdentity;
        emittedIdentity[L"symbol:kind:entry:target-a"] = {L"symbol:kind:entry:target-a", GetTickCount64(), 2};
        PatchConfirmations changedIdentity;
        changedIdentity[L"symbol:kind:entry:target-b"] = {L"symbol:kind:entry:target-b", GetTickCount64(), 2};
        std::unordered_set<std::wstring> identityKeys;
        const std::wstring oldIdentityKey = PatchObservationEventKey(emittedIdentity.begin()->first);
        const std::wstring newIdentityKey = PatchObservationEventKey(changedIdentity.begin()->first);
        identityKeys.insert(oldIdentityKey);
        identityKeys.insert(newIdentityKey);
        identityKeys.insert(L"callback_redirect:keep");
        RetireInlineObservationKeys(changedIdentity, &identityKeys);
        if (oldIdentityKey == newIdentityKey || identityKeys.count(oldIdentityKey) != 0 ||
            identityKeys.count(newIdentityKey) != 1 || identityKeys.count(L"callback_redirect:keep") != 1)
        {
            break;
        }
        changedIdentity.clear();
        RetireInlineObservationKeys(changedIdentity, &identityKeys);
        if (identityKeys.size() != 1 || identityKeys.count(L"callback_redirect:keep") != 1)
        {
            break;
        }
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
        // Exercise the same byte-to-input path used by the live scan. Merely
        // setting PrologueKnown in classifier fixtures missed a runtime bug.
        KmonInlinePatchInput liveInput = {};
        liveInput.OwnerRangeKnown = true;
        liveInput.OwnerBase = ownerBase;
        liveInput.OwnerEnd = ownerEnd;
        liveInput.ModuleViewKnown = true;
        std::vector<uint8_t> liveBytes(absolute, absolute + sizeof(absolute));
        const uint64_t outsideTarget = 0xFFFFF88000034000ull;
        std::memcpy(liveBytes.data() + 2, &outsideTarget, sizeof(outsideTarget));
        PrepareInlinePatchInput(liveBytes, ownerBase + 0x1000, &liveInput);
        if (KmonClassifyInlinePatch(liveInput) !=
                KmonInlinePatchKind::UnbackedHeadTransfer ||
            PatchSampleCoverageComplete(liveBytes, kPrologueBytes))
        {
            break;
        }
        std::vector<uint8_t> shortPrologue(liveBytes.begin(), liveBytes.begin() + 8);
        KmonInlinePatchInput shortInput = {};
        PrepareInlinePatchInput(shortPrologue, ownerBase + 0x1000, &shortInput);
        if (PatchSampleCoverageComplete(shortPrologue, kPrologueBytes) ||
            shortInput.TransferTargetKnown)
        {
            break;
        }
        liveBytes.assign(trap, trap + sizeof(trap));
        PrepareInlinePatchInput(liveBytes, ownerBase + 0x1000, &liveInput);
        if (KmonClassifyInlinePatch(liveInput) != KmonInlinePatchKind::Int3Breakpoint)
        {
            break;
        }

        uint8_t extendedRegister[32] = {0xF3, 0x0F, 0x1E, 0xFA, 0x90, 0x49, 0xBB};
        std::memcpy(extendedRegister + 7, &outsideTarget, sizeof(outsideTarget));
        extendedRegister[15] = 0x41;
        extendedRegister[16] = 0xFF;
        extendedRegister[17] = 0xE3;
        decode = KmonDecodeInlinePatchHead(
            extendedRegister, sizeof(extendedRegister), ownerBase);
        if (decode.Shape != KmonInlinePatchShape::RegisterImmediate ||
            !decode.TargetKnown || decode.Target != outsideTarget)
        {
            break;
        }
        extendedRegister[17] = 0xE2;
        if (KmonDecodeInlinePatchHead(
                extendedRegister, sizeof(extendedRegister), ownerBase).TargetKnown ||
            KmonDecodeInlinePatchHead(extendedRegister, 17, ownerBase).TargetKnown)
        {
            break;
        }
        const uint8_t shortJump[] = {0x90, 0xEB, 0xFC};
        decode = KmonDecodeInlinePatchHead(shortJump, sizeof(shortJump), ownerBase + 0x1000);
        if (decode.Shape != KmonInlinePatchShape::NearJump ||
            !decode.TargetKnown || decode.Target != ownerBase + 0xFFF)
        {
            break;
        }

        std::vector<PatchModule> callbackModules;
        PatchModule callbackOwner = {};
        callbackOwner.Base = ownerBase;
        callbackOwner.End = ownerEnd;
        callbackModules.push_back(callbackOwner);
        PatchModule delegatedOwner = {};
        delegatedOwner.Base = ownerEnd + 0x100000;
        delegatedOwner.End = delegatedOwner.Base + 0x100000;
        callbackModules.push_back(delegatedOwner);
        std::map<uint64_t, std::vector<uint8_t>> callbackMemory;
        auto callbackRead = [&](uint64_t address, size_t size, std::vector<uint8_t>* output)
        {
            const auto found = callbackMemory.find(address);
            if (found == callbackMemory.end() || found->second.size() != size)
            {
                return false;
            }
            *output = found->second;
            return true;
        };
        auto putAbsoluteJump = [&](uint64_t entry, uint64_t destination)
        {
            std::vector<uint8_t> bytes(kPrologueBytes, 0);
            bytes[0] = 0x49;
            bytes[1] = 0xBB;
            std::memcpy(bytes.data() + 2, &destination, sizeof(destination));
            bytes[10] = 0x41;
            bytes[11] = 0xFF;
            bytes[12] = 0xE3;
            callbackMemory[entry] = bytes;
        };
        const uint64_t callbackEntry = ownerBase + 0x2000;
        const uint64_t callbackCave = ownerBase + 0x4000;
        putAbsoluteJump(callbackEntry, callbackCave);
        putAbsoluteJump(callbackCave, outsideTarget);
        CallbackHeadObservation callbackObservation =
            ProbeCallbackRedirect(callbackRead, callbackModules, callbackEntry);
        if (!callbackObservation.Complete || callbackObservation.Target != outsideTarget)
        {
            break;
        }
        // A supported framework tail call into another image remains normal.
        putAbsoluteJump(callbackCave, delegatedOwner.Base);
        callbackMemory[delegatedOwner.Base] = std::vector<uint8_t>(kPrologueBytes, 0);
        callbackMemory[delegatedOwner.Base][0] = 0x55;
        callbackObservation = ProbeCallbackRedirect(callbackRead, callbackModules, callbackEntry);
        if (!callbackObservation.Complete || callbackObservation.Target != 0)
        {
            break;
        }
        // Unreadable and cyclic intermediate thunks do not become clean.
        callbackMemory.erase(callbackCave);
        if (ProbeCallbackRedirect(callbackRead, callbackModules, callbackEntry).Complete)
        {
            break;
        }
        putAbsoluteJump(callbackCave, callbackEntry);
        if (ProbeCallbackRedirect(callbackRead, callbackModules, callbackEntry).Complete)
        {
            break;
        }
        std::vector<uint8_t> indirect(kPrologueBytes, 0);
        indirect[0] = 0xFF;
        indirect[1] = 0x25;
        callbackMemory[callbackEntry] = indirect;
        callbackMemory[callbackEntry + 6] = std::vector<uint8_t>(sizeof(uint64_t), 0);
        std::memcpy(callbackMemory[callbackEntry + 6].data(), &outsideTarget, sizeof(outsideTarget));
        callbackObservation = ProbeCallbackRedirect(callbackRead, callbackModules, callbackEntry);
        if (!callbackObservation.Complete || callbackObservation.Target != outsideTarget)
        {
            break;
        }
        callbackMemory.erase(callbackEntry + 6);
        if (ProbeCallbackRedirect(callbackRead, callbackModules, callbackEntry).Complete)
        {
            break;
        }

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
