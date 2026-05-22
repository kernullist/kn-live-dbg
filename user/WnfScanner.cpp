#include "WnfScanner.h"

#include <Zydis.h>

#include <algorithm>
#include <cwctype>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#include <utility>

namespace
{
    constexpr uint64_t kKernelSpaceMin       = 0xffff800000000000ull;
    constexpr uint32_t kMaxRawBytesPerRead   = 0x1000;
    constexpr uint32_t kMaxAvlNodes          = 0x4000;
    constexpr uint32_t kMaxAvlDepth          = 64;
    constexpr uint64_t kRtlBalancedLinksSize = 0x20;
    constexpr uint64_t kAvlBalancedRootLeft  = 0x08;
    constexpr uint64_t kAvlBalancedRootRight = 0x10;

    bool IsKernelAddress(uint64_t v)
    {
        return v >= kKernelSpaceMin;
    }

    bool TryAdd(uint64_t a, uint64_t b, uint64_t* out)
    {
        if (out == nullptr)
        {
            return false;
        }
        if (a > (~0ull - b))
        {
            return false;
        }
        *out = a + b;
        return true;
    }

    std::wstring HexAddressLocal(uint64_t address)
    {
        wchar_t buf[24];
        swprintf_s(buf, L"0x%016llx", static_cast<unsigned long long>(address));
        return buf;
    }

    bool ReadKernelBytes(
        DeviceClient& device,
        uint64_t addr,
        uint32_t len,
        std::vector<uint8_t>* bytes,
        std::wstring* err)
    {
        if (bytes == nullptr || len == 0 || len > kMaxRawBytesPerRead)
        {
            if (err != nullptr)
            {
                *err = L"invalid read request";
            }
            return false;
        }
        if (!device.ReadMemory(addr, len, bytes, err))
        {
            return false;
        }
        if (bytes->size() != len)
        {
            if (err != nullptr)
            {
                *err = L"short kernel read";
            }
            return false;
        }
        return true;
    }

    bool ReadU32(DeviceClient& device, uint64_t addr, uint32_t* val, std::wstring* err)
    {
        std::vector<uint8_t> bytes;
        if (!ReadKernelBytes(device, addr, sizeof(uint32_t), &bytes, err))
        {
            return false;
        }
        memcpy(val, bytes.data(), sizeof(uint32_t));
        return true;
    }

    bool ReadU64(DeviceClient& device, uint64_t addr, uint64_t* val, std::wstring* err)
    {
        std::vector<uint8_t> bytes;
        if (!ReadKernelBytes(device, addr, sizeof(uint64_t), &bytes, err))
        {
            return false;
        }
        memcpy(val, bytes.data(), sizeof(uint64_t));
        return true;
    }

    bool TryFindField(
        SymbolEngine& symbols,
        const std::wstring& typeName,
        const std::wstring& fieldName,
        TypeFieldInfo* out)
    {
        std::wstring ignored;
        return symbols.FindField(typeName, fieldName, out, &ignored);
    }

    bool TryFindFieldAcrossTypes(
        SymbolEngine& symbols,
        std::initializer_list<const wchar_t*> typeNames,
        const std::wstring& fieldName,
        TypeFieldInfo* out,
        std::wstring* matchedType)
    {
        for (const wchar_t* typeName : typeNames)
        {
            if (TryFindField(symbols, typeName, fieldName, out))
            {
                if (matchedType != nullptr)
                {
                    *matchedType = typeName;
                }
                return true;
            }
        }
        return false;
    }

    bool ResolveFirstSymbol(
        SymbolEngine& symbols,
        std::initializer_list<const wchar_t*> candidates,
        uint64_t* address,
        std::wstring* matchedSymbol)
    {
        for (const wchar_t* name : candidates)
        {
            uint64_t addr = 0;
            std::wstring ignored;
            if (symbols.ResolveSymbol(name, &addr, &ignored))
            {
                if (address != nullptr)
                {
                    *address = addr;
                }
                if (matchedSymbol != nullptr)
                {
                    *matchedSymbol = name;
                }
                return true;
            }
        }
        return false;
    }

    // Decode up to 64 instructions starting at funcAddr and collect every
    // distinct kernel-canonical absolute target referenced by RIP-relative
    // memory operands (lea reg,[rip+disp32] and mov reg,[rip+disp32] both
    // resolve through this path). When followDepth > 0, also follow each
    // direct call/jmp rel32 once and recursively collect from the callee --
    // this matters because modern syscall stubs delegate to an internal
    // helper before touching any global.
    bool ExtractAnchorGlobals(
        DeviceClient& device,
        uint64_t funcAddr,
        uint32_t followDepth,
        std::unordered_set<uint64_t>* visitedFunctions,
        std::vector<uint64_t>* targets,
        std::unordered_set<uint64_t>* seenTargets)
    {
        if (targets == nullptr || seenTargets == nullptr || visitedFunctions == nullptr)
        {
            return false;
        }
        if (!visitedFunctions->insert(funcAddr).second)
        {
            return true;
        }

        std::vector<uint8_t> code;
        if (!ReadKernelBytes(device, funcAddr, 0x200, &code, nullptr))
        {
            return false;
        }

        size_t offset = 0;
        uint64_t pc = funcAddr;

        for (uint32_t i = 0; i < 64 && offset < code.size(); ++i)
        {
            ZydisDisassembledInstruction inst = {};
            ZyanStatus status = ZydisDisassembleIntel(
                ZYDIS_MACHINE_MODE_LONG_64,
                pc,
                code.data() + offset,
                code.size() - offset,
                &inst);
            if (!ZYAN_SUCCESS(status))
            {
                break;
            }
            if (inst.info.length == 0 || inst.info.length > 15)
            {
                break;
            }

            for (uint8_t op = 0; op < inst.info.operand_count; ++op)
            {
                const ZydisDecodedOperand& operand = inst.operands[op];
                if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    operand.mem.base == ZYDIS_REGISTER_RIP &&
                    operand.mem.disp.has_displacement)
                {
                    int64_t disp = operand.mem.disp.value;
                    uint64_t target = pc + inst.info.length + static_cast<uint64_t>(disp);
                    if (IsKernelAddress(target) && seenTargets->insert(target).second)
                    {
                        targets->push_back(target);
                    }
                }
            }

            if (followDepth > 0 &&
                (inst.info.mnemonic == ZYDIS_MNEMONIC_CALL ||
                 inst.info.mnemonic == ZYDIS_MNEMONIC_JMP) &&
                inst.info.operand_count > 0 &&
                inst.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                inst.operands[0].imm.is_relative != 0)
            {
                int64_t disp = inst.operands[0].imm.is_signed
                    ? static_cast<int64_t>(inst.operands[0].imm.value.s)
                    : static_cast<int64_t>(inst.operands[0].imm.value.u);
                uint64_t callTarget = pc + inst.info.length + static_cast<uint64_t>(disp);
                if (IsKernelAddress(callTarget))
                {
                    ExtractAnchorGlobals(
                        device,
                        callTarget,
                        followDepth - 1,
                        visitedFunctions,
                        targets,
                        seenTargets);
                }
            }

            offset += inst.info.length;
            pc += inst.info.length;

            if (inst.info.mnemonic == ZYDIS_MNEMONIC_RET)
            {
                break;
            }
        }

        return true;
    }

    // Weak plausibility gate: a kernel canonical address whose first
    // dereference yields anything. The strong validation is performed by
    // scanning for an embedded RTL_AVL_TABLE inside the candidate.
    bool CandidateSiloLooksPlausible(DeviceClient& device, uint64_t siloAddr)
    {
        if (siloAddr == 0 || !IsKernelAddress(siloAddr))
        {
            return false;
        }
        uint64_t probe = 0;
        return ReadU64(device, siloAddr, &probe, nullptr);
    }

    // Validate that a candidate state-name value plausibly decodes as a real
    // WNF state name -- known lifetimes/scopes/versions are limited ranges.
    bool LooksLikeStateName(uint64_t raw)
    {
        WnfStateNameDecoded decoded = DecodeWnfStateName(raw);
        if (decoded.Version > 7)
        {
            return false;
        }
        if (decoded.Lifetime > 3)
        {
            return false;
        }
        if (decoded.DataScope > 5)
        {
            return false;
        }
        // Pure zero would mean the slot is empty -- treat as not a name
        if (decoded.Decoded == 0)
        {
            return false;
        }
        return true;
    }

    // RTL_AVL_TABLE field offsets on x64.
    constexpr uint64_t kRtlAvlTableCompareRoutine  = 0x30;
    constexpr uint64_t kRtlAvlTableAllocateRoutine = 0x38;
    constexpr uint64_t kRtlAvlTableFreeRoutine     = 0x40;
    constexpr uint64_t kRtlAvlTableNumberOfElements = 0x2c;

    // Validate that the candidate looks like a real RTL_AVL_TABLE: at least
    // two of the three routine slots (Compare/Allocate/Free) must be kernel
    // canonical function pointers landing inside a loaded kernel module, and
    // NumberOfElements must be in a sane range. This rejects offsets where
    // the bytes happen to look like a root pointer but the rest of the
    // structure is garbage.
    bool LooksLikeAvlTable(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t tableAddr)
    {
        uint64_t routineAddrs[3] = {
            tableAddr + kRtlAvlTableCompareRoutine,
            tableAddr + kRtlAvlTableAllocateRoutine,
            tableAddr + kRtlAvlTableFreeRoutine
        };

        uint32_t goodRoutines = 0;
        for (uint64_t addr : routineAddrs)
        {
            uint64_t value = 0;
            if (!ReadU64(device, addr, &value, nullptr))
            {
                continue;
            }
            if (value == 0 || !IsKernelAddress(value))
            {
                continue;
            }
            bool inModule = false;
            for (const KernelModuleInfo& module : symbols.Modules())
            {
                uint64_t end = module.Base + module.Size;
                if (end < module.Base)
                {
                    continue;
                }
                if (value >= module.Base && value < end)
                {
                    inModule = true;
                    break;
                }
            }
            if (inModule)
            {
                ++goodRoutines;
            }
        }

        if (goodRoutines < 2)
        {
            return false;
        }

        uint32_t numberOfElements = 0;
        uint64_t nelAddr = tableAddr + kRtlAvlTableNumberOfElements;
        if (!ReadU32(device, nelAddr, &numberOfElements, nullptr))
        {
            return false;
        }
        if (numberOfElements == 0 || numberOfElements > 0x100000)
        {
            return false;
        }

        // Strong structural validation: the sentinel's RightChild is the
        // real root. It must be a non-NULL kernel canonical pointer when
        // NumberOfElements > 0, and the root's Parent (root+0x00) must
        // point back to the sentinel head (i.e., to tableAddr itself).
        uint64_t rootAddr = 0;
        if (!ReadU64(device, tableAddr + kAvlBalancedRootRight, &rootAddr, nullptr))
        {
            return false;
        }
        if (rootAddr == 0 || !IsKernelAddress(rootAddr))
        {
            return false;
        }

        uint64_t rootParent = 0;
        if (!ReadU64(device, rootAddr, &rootParent, nullptr))
        {
            return false;
        }
        if (rootParent != tableAddr)
        {
            return false;
        }

        return true;
    }

    // Heuristic AVL-table offset scan: for each 8-byte aligned offset inside
    // the silo state, treat the slot as an RTL_AVL_TABLE header. Reject any
    // candidate whose Compare/Allocate/FreeRoutine fields don't point at
    // real kernel functions or whose NumberOfElements is out of range. Then
    // verify the root subtree resolves to a node whose user data decodes as
    // a plausible state-name at the supplied offset.
    bool AutoDetectAvlTableOffset(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t siloAddr,
        uint64_t stateNameOffsetWithinUserData,
        uint64_t* avlOffsetOut)
    {
        if (avlOffsetOut == nullptr)
        {
            return false;
        }

        for (uint64_t off = 0; off <= 0x2000; off += sizeof(uint64_t))
        {
            uint64_t tableAddr = 0;
            if (!TryAdd(siloAddr, off, &tableAddr))
            {
                break;
            }

            if (!LooksLikeAvlTable(device, symbols, tableAddr))
            {
                continue;
            }

            uint64_t rightAddr = 0;
            if (!TryAdd(tableAddr, kAvlBalancedRootRight, &rightAddr))
            {
                continue;
            }

            uint64_t root = 0;
            if (!ReadU64(device, rightAddr, &root, nullptr) ||
                root == 0 || !IsKernelAddress(root))
            {
                continue;
            }

            uint64_t userData = 0;
            if (!TryAdd(root, kRtlBalancedLinksSize, &userData))
            {
                continue;
            }

            uint64_t stateNameAddr = 0;
            if (!TryAdd(userData, stateNameOffsetWithinUserData, &stateNameAddr))
            {
                continue;
            }

            uint64_t stateName = 0;
            if (!ReadU64(device, stateNameAddr, &stateName, nullptr))
            {
                continue;
            }

            if (LooksLikeStateName(stateName))
            {
                *avlOffsetOut = off;
                return true;
            }
        }

        return false;
    }

    // Look up CompareRoutine for the AVL table; if its nearest symbol name
    // contains "wnf" (case-insensitive), this AVL is almost certainly part
    // of the WNF subsystem.
    bool IsWnfRelatedAvlTable(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t tableAddr)
    {
        uint64_t compareRoutine = 0;
        uint64_t fieldAddr = tableAddr + kRtlAvlTableCompareRoutine;
        if (!ReadU64(device, fieldAddr, &compareRoutine, nullptr))
        {
            return false;
        }
        if (compareRoutine == 0 || !IsKernelAddress(compareRoutine))
        {
            return false;
        }
        std::wstring symbolName;
        uint64_t displacement = 0;
        std::wstring ignored;
        if (!symbols.FindNearestSymbol(compareRoutine, &symbolName, &displacement, &ignored))
        {
            return false;
        }
        std::wstring lowered;
        lowered.reserve(symbolName.size());
        for (wchar_t ch : symbolName)
        {
            lowered.push_back(static_cast<wchar_t>(std::towlower(ch)));
        }
        return lowered.find(L"wnf") != std::wstring::npos;
    }

    struct AvlOffsetCandidate
    {
        uint64_t Offset = 0;
        bool WnfRelated = false;
        std::wstring CompareSymbol;
    };

    // Enumerate every RTL_AVL_TABLE-shaped header inside the candidate silo
    // and rank those whose CompareRoutine resolves to a Wnf-named function
    // ahead of generic AVL tables.
    bool FindAllAvlTablesInSilo(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t siloAddr,
        std::vector<AvlOffsetCandidate>* offsetsOut)
    {
        if (offsetsOut == nullptr)
        {
            return false;
        }
        offsetsOut->clear();

        for (uint64_t off = 0; off <= 0x2000; off += sizeof(uint64_t))
        {
            uint64_t tableAddr = 0;
            if (!TryAdd(siloAddr, off, &tableAddr))
            {
                break;
            }
            if (!LooksLikeAvlTable(device, symbols, tableAddr))
            {
                continue;
            }

            AvlOffsetCandidate cand = {};
            cand.Offset = off;
            cand.WnfRelated = IsWnfRelatedAvlTable(device, symbols, tableAddr);
            if (cand.WnfRelated)
            {
                uint64_t compareRoutine = 0;
                if (ReadU64(device, tableAddr + kRtlAvlTableCompareRoutine, &compareRoutine, nullptr))
                {
                    std::wstring nearest;
                    uint64_t displacement = 0;
                    std::wstring ignored;
                    if (symbols.FindNearestSymbol(compareRoutine, &nearest, &displacement, &ignored))
                    {
                        cand.CompareSymbol = nearest;
                    }
                }
            }
            offsetsOut->push_back(std::move(cand));
        }

        std::stable_sort(offsetsOut->begin(), offsetsOut->end(),
            [](const AvlOffsetCandidate& a, const AvlOffsetCandidate& b)
            {
                return a.WnfRelated && !b.WnfRelated;
            });

        return !offsetsOut->empty();
    }

    // Detect a doubly-linked LIST_ENTRY head at headAddr. Treats two cases:
    //   empty list: Flink == Blink == headAddr (self-sentinel)
    //   non-empty:  Flink != headAddr; we additionally verify Flink's Blink
    //               points back to headAddr (true for a proper LIST_ENTRY chain)
    bool DetectListEntryHead(DeviceClient& device, uint64_t headAddr, uint64_t* flinkOut, uint64_t* blinkOut, bool* isEmptyOut)
    {
        std::vector<uint8_t> bytes;
        if (!ReadKernelBytes(device, headAddr, 16, &bytes, nullptr))
        {
            return false;
        }

        uint64_t flink = 0;
        uint64_t blink = 0;
        memcpy(&flink, bytes.data(), sizeof(uint64_t));
        memcpy(&blink, bytes.data() + sizeof(uint64_t), sizeof(uint64_t));

        if (flink == 0 || !IsKernelAddress(flink))
        {
            return false;
        }
        if (blink == 0 || !IsKernelAddress(blink))
        {
            return false;
        }

        if (flink == headAddr && blink == headAddr)
        {
            if (flinkOut) *flinkOut = flink;
            if (blinkOut) *blinkOut = blink;
            if (isEmptyOut) *isEmptyOut = true;
            return true;
        }

        // Non-empty: verify Flink's Blink points back to headAddr
        uint64_t flinkBlinkAddr = 0;
        if (!TryAdd(flink, sizeof(uint64_t), &flinkBlinkAddr))
        {
            return false;
        }
        uint64_t flinkBlink = 0;
        if (!ReadU64(device, flinkBlinkAddr, &flinkBlink, nullptr))
        {
            return false;
        }
        if (flinkBlink != headAddr)
        {
            return false;
        }

        if (flinkOut) *flinkOut = flink;
        if (blinkOut) *blinkOut = blink;
        if (isEmptyOut) *isEmptyOut = false;
        return true;
    }

    // Scan a silo candidate for LIST_ENTRY heads and walk every non-empty
    // chain. For each entry, also probe a small range of byte offsets for a
    // value that decodes as a plausible WNF state name -- that hint helps
    // operators recognise the entry kind without per-build offset tables.
    void CollectListHeadsFromSilo(
        DeviceClient& device,
        uint64_t siloAddr,
        std::vector<WnfListHeadFinding>* findings)
    {
        if (findings == nullptr)
        {
            return;
        }

        constexpr uint64_t kScanRange = 0x800;
        constexpr uint32_t kMaxEntriesPerList = 0x80;
        // Capture deep enough to fit a full _WNF_NAME_INSTANCE plus a
        // possible trailing _WNF_NAME_INFO. Modern Win11 layouts may
        // store the full encoded state name (0x41C6XXXX_XXXXXXXX pattern)
        // beyond the first 0x80 bytes, so we read 0x200 to give the probe
        // a fair chance to find it.
        constexpr uint32_t kEntryBytesCaptured = 0x200;

        for (uint64_t off = 0; off <= kScanRange; off += sizeof(uint64_t))
        {
            uint64_t headAddr = 0;
            if (!TryAdd(siloAddr, off, &headAddr))
            {
                break;
            }

            uint64_t flink = 0;
            uint64_t blink = 0;
            bool isEmpty = false;
            if (!DetectListEntryHead(device, headAddr, &flink, &blink, &isEmpty))
            {
                continue;
            }

            WnfListHeadFinding finding = {};
            finding.SiloAddress = siloAddr;
            finding.HeadOffset = off;
            finding.HeadAddress = headAddr;
            finding.Flink = flink;
            finding.Blink = blink;
            finding.IsEmpty = isEmpty;

            if (!isEmpty)
            {
                uint64_t current = flink;
                uint32_t visited = 0;
                std::unordered_set<uint64_t> seen;
                while (current != headAddr && visited < kMaxEntriesPerList)
                {
                    if (!IsKernelAddress(current))
                    {
                        break;
                    }
                    if (!seen.insert(current).second)
                    {
                        break;
                    }

                    std::vector<uint8_t> entryBytes;
                    if (!ReadKernelBytes(device, current, kEntryBytesCaptured, &entryBytes, nullptr))
                    {
                        break;
                    }

                    WnfListEntryWalkRecord rec = {};
                    rec.EntryAddress = current;
                    rec.EntryBytes = entryBytes;

                    // Probe candidate state-name offsets within the entry.
                    // Skip the first 0x10 bytes (LIST_ENTRY itself).
                    for (size_t snOff = 0x10; snOff + 8 <= entryBytes.size() && snOff <= 0x40; snOff += sizeof(uint64_t))
                    {
                        uint64_t value = 0;
                        memcpy(&value, entryBytes.data() + snOff, sizeof(uint64_t));
                        if (LooksLikeStateName(value))
                        {
                            rec.HasStateName = true;
                            rec.StateNameOffsetWithinEntry = snOff;
                            rec.StateNameCandidate = value;
                            rec.DecodedStateName = DecodeWnfStateName(value);
                            break;
                        }
                    }

                    finding.Entries.push_back(std::move(rec));

                    uint64_t nextAddr = 0;
                    if (!ReadU64(device, current, &nextAddr, nullptr))
                    {
                        break;
                    }
                    current = nextAddr;
                    ++visited;
                }
            }

            findings->push_back(std::move(finding));
        }
    }

    // Backwards-compatible wrapper that returns just the first/best offset.
    bool FindAnyAvlTableInSilo(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t siloAddr,
        uint64_t* avlOffsetOut)
    {
        std::vector<AvlOffsetCandidate> candidates;
        if (!FindAllAvlTablesInSilo(device, symbols, siloAddr, &candidates))
        {
            return false;
        }
        if (avlOffsetOut != nullptr)
        {
            *avlOffsetOut = candidates.front().Offset;
        }
        return true;
    }

    // Heuristic StateName-within-_WNF_NAME_INSTANCE offset scan: for each
    // candidate offset within the user data, read as 64-bit and decode. If
    // multiple distinct candidates from a walked subtree consistently look
    // like state-name encoded values, accept this offset.
    bool AutoDetectStateNameOffset(
        DeviceClient& device,
        uint64_t siloAddr,
        uint64_t avlTableOffset,
        uint64_t* stateNameOffsetOut)
    {
        if (stateNameOffsetOut == nullptr)
        {
            return false;
        }

        uint64_t tableAddr = 0;
        if (!TryAdd(siloAddr, avlTableOffset, &tableAddr))
        {
            return false;
        }

        uint64_t rightAddr = 0;
        if (!TryAdd(tableAddr, kAvlBalancedRootRight, &rightAddr))
        {
            return false;
        }

        uint64_t root = 0;
        if (!ReadU64(device, rightAddr, &root, nullptr) ||
            root == 0 || !IsKernelAddress(root))
        {
            return false;
        }

        // Walk a small set of nodes (root + left + right + grandchildren) and
        // score each candidate offset by how many distinct plausible state
        // names we observe at that offset across nodes.
        std::vector<uint64_t> sampleNodes;
        sampleNodes.push_back(root);
        for (uint64_t side : {kAvlBalancedRootLeft, kAvlBalancedRootRight})
        {
            uint64_t childAddr = 0;
            uint64_t child = 0;
            if (TryAdd(root, side, &childAddr) &&
                ReadU64(device, childAddr, &child, nullptr) &&
                child != 0 && IsKernelAddress(child))
            {
                sampleNodes.push_back(child);
            }
        }

        for (uint64_t off = 0; off <= 0x80; off += sizeof(uint64_t))
        {
            uint32_t plausibleCount = 0;
            for (uint64_t node : sampleNodes)
            {
                uint64_t userData = 0;
                if (!TryAdd(node, kRtlBalancedLinksSize, &userData))
                {
                    continue;
                }
                uint64_t fieldAddr = 0;
                if (!TryAdd(userData, off, &fieldAddr))
                {
                    continue;
                }
                uint64_t value = 0;
                if (!ReadU64(device, fieldAddr, &value, nullptr))
                {
                    continue;
                }
                if (LooksLikeStateName(value))
                {
                    ++plausibleCount;
                }
            }
            if (plausibleCount >= 2 || (plausibleCount == 1 && sampleNodes.size() == 1))
            {
                *stateNameOffsetOut = off;
                return true;
            }
        }

        return false;
    }

    struct NameInstanceLayout
    {
        uint64_t StateNameOffset = 0;
        uint64_t ChangeStampOffset = 0;
        uint32_t ChangeStampLength = sizeof(uint32_t);
        uint64_t DataSizeOffset = 0;
        uint64_t LastDataBlockOffset = 0;
        std::wstring TypeName;
        std::wstring Source;
        bool HasStateName = false;
        bool HasChangeStamp = false;
        bool HasDataSize = false;
        bool HasLastDataBlock = false;
    };

    bool ResolveNameInstanceLayoutFromPdb(SymbolEngine& symbols, NameInstanceLayout* layout)
    {
        if (layout == nullptr)
        {
            return false;
        }

        const wchar_t* typeNames[] =
        {
            L"nt!_WNF_NAME_INSTANCE",
            L"nt!_WNF_NAME_INSTANCE_HEADER"
        };

        for (const wchar_t* typeName : typeNames)
        {
            TypeFieldInfo stateName = {};
            if (!TryFindField(symbols, typeName, L"StateName", &stateName))
            {
                continue;
            }

            layout->TypeName = typeName;
            layout->StateNameOffset = stateName.Offset;
            layout->HasStateName = true;
            layout->Source = L"pdb:" + std::wstring(typeName);

            TypeFieldInfo field = {};
            if (TryFindField(symbols, typeName, L"ChangeStamp", &field))
            {
                layout->ChangeStampOffset = field.Offset;
                layout->ChangeStampLength = static_cast<uint32_t>(field.Length);
                layout->HasChangeStamp = true;
            }
            if (TryFindField(symbols, typeName, L"DataSize", &field))
            {
                layout->DataSizeOffset = field.Offset;
                layout->HasDataSize = true;
            }
            if (TryFindField(symbols, typeName, L"LastDataBlock", &field) ||
                TryFindField(symbols, typeName, L"StateData", &field) ||
                TryFindField(symbols, typeName, L"DataBlock", &field))
            {
                layout->LastDataBlockOffset = field.Offset;
                layout->HasLastDataBlock = true;
            }

            return true;
        }

        return false;
    }

    struct TableLocator
    {
        std::wstring TypeName;
        std::wstring FieldName;
        TypeFieldInfo Field = {};
        bool Resolved = false;
    };

    bool LocateNameSetTable(SymbolEngine& symbols, TableLocator* locator)
    {
        if (locator == nullptr)
        {
            return false;
        }

        const wchar_t* containerTypes[] =
        {
            L"nt!_WNF_SUBSCRIPTION_TABLE",
            L"nt!_WNF_SILODRIVERSTATE",
            L"nt!_WNF_PROCESS_CONTEXT"
        };

        const wchar_t* candidateFields[] =
        {
            L"NameSet",
            L"NameSubscriptionTable",
            L"SubscriptionTable",
            L"NameInstanceTable",
            L"NameInstances"
        };

        for (const wchar_t* typeName : containerTypes)
        {
            for (const wchar_t* fieldName : candidateFields)
            {
                if (TryFindField(symbols, typeName, fieldName, &locator->Field))
                {
                    locator->TypeName = typeName;
                    locator->FieldName = fieldName;
                    locator->Resolved = true;
                    return true;
                }
            }
        }

        return false;
    }

    // ---------------- LIST_ENTRY-based instance walker (modern Win11) ----------------
    //
    // Background: on builds that have migrated WNF subscription tracking away
    // from RTL_AVL_TABLE, the kernel keeps instances in LIST_ENTRY chains
    // hanging off the silo state struct. Per-entry layout varies (state name
    // may sit at +0x10, +0x18, +0x20, +0x28, +0x30, or +0x38 depending on
    // sub-type), so we probe a small offset window per entry instead of
    // assuming a fixed layout. A list is treated as a WNF instance list if
    // at least 50% of its entries yield a plausible state name -- random
    // kernel data rarely meets that bar.
    // Scan the captured entry bytes for a full-form encoded WNF state name.
    //
    // Encoded WNF state names ALWAYS have high 16 bits == 0x41C6 because
    // the XOR mask is 0x41C64E6DA3BC0074 and the decoded sequence high
    // bits are bounded (cannot flip 0x41C6 back to zero except via XOR
    // with another 0x41C6-prefixed value, which would also be a valid
    // encoded state name). Scanning for that fingerprint reveals whether
    // each _WNF_NAME_INSTANCE actually carries a full encoded state name
    // somewhere in its body, vs. only the compact bit-field form we are
    // currently extracting at +0x10..+0x38.
    //
    // The scan walks every byte alignment so unaligned fields are caught.
    // A candidate must also XOR-decode to plausible Lifetime/DataScope.
    bool ProbeFullEncodedStateName(
        const WnfListEntryWalkRecord& entry,
        uint64_t* outFullEncoded,
        uint64_t* outOffset)
    {
        if (entry.EntryBytes.size() < sizeof(uint64_t))
        {
            return false;
        }
        for (size_t off = 0; off + sizeof(uint64_t) <= entry.EntryBytes.size(); ++off)
        {
            uint64_t value = 0;
            memcpy(&value, entry.EntryBytes.data() + off, sizeof(uint64_t));
            if ((value & 0xFFFF000000000000ull) != 0x41C6000000000000ull)
            {
                continue;
            }
            WnfStateNameDecoded d = DecodeWnfStateName(value);
            if (d.Lifetime > 3)
            {
                continue;
            }
            if (d.DataScope > 5)
            {
                continue;
            }
            if (outFullEncoded != nullptr)
            {
                *outFullEncoded = value;
            }
            if (outOffset != nullptr)
            {
                *outOffset = off;
            }
            return true;
        }
        return false;
    }

    bool ExtractStateNameFromEntry(
        const WnfListEntryWalkRecord& entry,
        uint64_t* outRaw,
        uint64_t* outOffset,
        WnfStateNameDecoded* outDecoded)
    {
        // Primary path: modern Win11 stores _WNF_NAME_INSTANCE.StateName
        // in DECODED form at +0x10 (or near it), with high 32 bits set to
        // the 0x00000103 schema marker. This matches the format used by
        // public WNF state-name databases (Ionescu wnfdump, Win11 RE
        // tables). We accept any low-32-bit content because the bit-field
        // layout (Version/Lifetime/DataScope) drifts between builds, but
        // the schema marker is stable and lets us positively identify the
        // canonical state-name slot.
        //
        // Note: a stable 0x41C6XXXX_XXXXXXXX pattern at +0x1E0 looks like
        // a state name but actually decodes to (high=0, low=tiny seq) for
        // every entry -- it is a tagged internal field (subscription
        // token or schema marker), NOT the canonical state name.
        for (uint64_t off = 0x10; off <= 0x38; off += sizeof(uint64_t))
        {
            if (entry.EntryBytes.size() < off + sizeof(uint64_t))
            {
                continue;
            }
            uint64_t value = 0;
            memcpy(&value, entry.EntryBytes.data() + off, sizeof(uint64_t));
            if ((value & 0xFFFFFFFF00000000ull) == 0x0000010300000000ull)
            {
                if (outRaw != nullptr)
                {
                    *outRaw = value;
                }
                if (outOffset != nullptr)
                {
                    *outOffset = off;
                }
                if (outDecoded != nullptr)
                {
                    *outDecoded = DecodeWnfStateName(value);
                }
                return true;
            }
        }

        // Fallback path: legacy heuristic for entries on Win10 / early
        // Win11 builds that store the state name in fully encoded form
        // somewhere in +0x10..+0x38. Used when the 0x103 schema marker is
        // not present.
        for (uint64_t off = 0x10; off <= 0x38; off += sizeof(uint64_t))
        {
            if (entry.EntryBytes.size() < off + sizeof(uint64_t))
            {
                continue;
            }
            uint64_t value = 0;
            memcpy(&value, entry.EntryBytes.data() + off, sizeof(uint64_t));
            if (value == 0)
            {
                continue;
            }
            if (IsKernelAddress(value))
            {
                continue;
            }
            if (!LooksLikeStateName(value))
            {
                continue;
            }
            if (outRaw != nullptr)
            {
                *outRaw = value;
            }
            if (outOffset != nullptr)
            {
                *outOffset = off;
            }
            if (outDecoded != nullptr)
            {
                *outDecoded = DecodeWnfStateName(value);
            }
            return true;
        }
        return false;
    }

    // -------- LIST_ENTRY mode _WNF_DATA_BLOCK probe ----------------------
    //
    // Locate a published WNF data descriptor referenced from an entry
    // address. Walks the first 0x200 bytes of the entry looking for any
    // kernel-canonical pointer that dereferences to a structure whose
    // first 16 bytes match the documented _WNF_DATA_BLOCK header layout
    // (Ionescu reverse-engineered, confirmed against live Win11 layout
    // by census of entry-resident pointers):
    //
    //   +0x00 DataSize        (UINT32, <= AllocatedSize)
    //   +0x04 AllocatedSize   (UINT32, > 0, <= 0x1000; stored as the
    //                          user-requested size, NOT rounded up to
    //                          pool granularity, so do not assume any
    //                          specific alignment)
    //   +0x08 ChangeStamp     (UINT64, may be 0 if never published)
    //   +0x10 Buffer          (variable size)
    //
    // ChangeStamp is intentionally NOT gated -- a freshly-created state
    // name with no producer ever publishing returns ChangeStamp == 0,
    // and we still want to surface that fact to the operator.
    //
    // Caller-supplied out pointers receive metadata for the FIRST match;
    // any subsequent kernel pointer that also passes validation is
    // ignored (in practice the canonical LastDataBlock slot is the only
    // entry-resident kernel pointer with a 4 KB-bounded size header).
    bool ProbeWnfDataBlock(
        DeviceClient& device,
        uint64_t entryAddress,
        uint64_t* outBlockAddr,
        uint32_t* outAllocatedSize,
        uint32_t* outDataSize,
        uint64_t* outChangeStamp,
        uint64_t* outFoundAtEntryOffset,
        std::vector<uint8_t>* outEntryDumpForDiag)
    {
        // Read the full canonical entry window. The Win11 _WNF_NAME_INSTANCE
        // is ~0x1E8 bytes (we discovered the encoded-name slot at +0x1E0);
        // a LastDataBlock pointer can sit anywhere within that range, not
        // just in the first 0x80. Reading 0x200 covers the entire entry
        // without straying into the next allocation.
        std::vector<uint8_t> entryBytes;
        if (!ReadKernelBytes(device, entryAddress, 0x200, &entryBytes, nullptr))
        {
            return false;
        }
        if (entryBytes.size() < 0x18)
        {
            return false;
        }
        if (outEntryDumpForDiag != nullptr)
        {
            *outEntryDumpForDiag = entryBytes;
        }

        for (size_t off = 0x10;
             off + sizeof(uint64_t) <= entryBytes.size();
             off += sizeof(uint64_t))
        {
            uint64_t ptr = 0;
            memcpy(&ptr, entryBytes.data() + off, sizeof(uint64_t));
            if (!IsKernelAddress(ptr))
            {
                continue;
            }

            std::vector<uint8_t> hdr;
            if (!ReadKernelBytes(device, ptr, 16, &hdr, nullptr))
            {
                continue;
            }
            if (hdr.size() != 16)
            {
                continue;
            }

            // _WNF_DATA_BLOCK header layout (Ionescu):
            //   +0x00 DataSize
            //   +0x04 AllocatedSize
            //   +0x08 ChangeStamp (UINT64)
            uint32_t dataSz = 0;
            uint32_t alloc = 0;
            uint64_t stamp = 0;
            memcpy(&dataSz, hdr.data() + 0, sizeof(uint32_t));
            memcpy(&alloc,  hdr.data() + 4, sizeof(uint32_t));
            memcpy(&stamp,  hdr.data() + 8, sizeof(uint64_t));

            if (alloc == 0 || alloc > 0x1000)
            {
                continue;
            }
            if (dataSz > alloc)
            {
                continue;
            }

            if (outBlockAddr != nullptr)
            {
                *outBlockAddr = ptr;
            }
            if (outAllocatedSize != nullptr)
            {
                *outAllocatedSize = alloc;
            }
            if (outDataSize != nullptr)
            {
                *outDataSize = dataSz;
            }
            if (outChangeStamp != nullptr)
            {
                *outChangeStamp = stamp;
            }
            if (outFoundAtEntryOffset != nullptr)
            {
                *outFoundAtEntryOffset = off;
            }
            return true;
        }
        return false;
    }

    // -------- LIST_ENTRY mode subscriber walker --------------------------
    //
    // Each _WNF_NAME_INSTANCE has one or more LIST_ENTRY heads embedded
    // inside it that thread together subscription records (one node per
    // active subscription). The candidate slots discovered by census are
    // at +0x48, +0xE0, +0x178, +0x1D0 -- some entries leave some of these
    // chains empty (self-sentinel) while populating others. We detect
    // non-empty pairs (consecutive 8-byte slots holding the same kernel
    // pointer to the chain head, OR a pair where Flink points away from
    // the head) and walk each one.
    //
    // For each subscription node we capture its first 0x40 bytes and try
    // to resolve an _EPROCESS pointer within them. _EPROCESS is detected
    // by checking that the dispatcher header byte at offset +0x00 of the
    // dereferenced pointer is 0x03 (KOBJECTS::ProcessObject); PID and
    // ImageFileName are then read via PDB-resolved field offsets so the
    // walker tolerates per-build _EPROCESS layout drift.
    struct EprocessFields
    {
        TypeFieldInfo UniqueProcessId = {};
        TypeFieldInfo ImageFileName = {};
        bool HasPid = false;
        bool HasImage = false;
        bool Loaded = false;
    };

    void EnsureEprocessFields(SymbolEngine& symbols, EprocessFields* fields)
    {
        if (fields == nullptr || fields->Loaded)
        {
            return;
        }
        fields->HasPid = TryFindField(symbols, L"nt!_EPROCESS", L"UniqueProcessId", &fields->UniqueProcessId);
        fields->HasImage = TryFindField(symbols, L"nt!_EPROCESS", L"ImageFileName", &fields->ImageFileName);
        fields->Loaded = true;
    }

    // PID-shape validator: real Windows PIDs are non-zero, 4-byte-aligned,
    // and well under 0x100000 (1M) in practice -- the kernel keeps a 32-bit
    // upper guardrail at 0x10000000 but no production system carries
    // anywhere near that. Tighten to 0x100000 to reject obviously-junky
    // values like 0x013FFFE0 / 0x04B4F800 seen in field testing.
    bool LooksLikePid(uint64_t value)
    {
        if (value == 0)
        {
            return false;
        }
        if (value > 0x100000ull)
        {
            return false;
        }
        if ((value & 0x3) != 0)
        {
            return false;
        }
        return true;
    }

    // ImageFileName-shape validator: kernel keeps a short ASCII string
    // padded with NULs; first byte must be a printable ASCII letter or
    // digit so we reject random binary blobs. Minimum length is 3 chars
    // -- shortest real process name is "dwm" (3 chars); 1-2 char values
    // are almost always coincidental byte sequences (e.g. "b", "l", "n"
    // observed in field testing as false positives).
    bool LooksLikeImageName(const std::vector<uint8_t>& bytes, std::wstring* outImage)
    {
        if (bytes.empty())
        {
            return false;
        }
        const uint8_t first = bytes[0];
        const bool firstPrintable =
            (first >= 'A' && first <= 'Z') ||
            (first >= 'a' && first <= 'z') ||
            (first >= '0' && first <= '9');
        if (!firstPrintable)
        {
            return false;
        }

        std::wstring imageName;
        for (uint8_t b : bytes)
        {
            if (b == 0)
            {
                break;
            }
            if (b >= 0x20 && b < 0x7F)
            {
                imageName.push_back(static_cast<wchar_t>(b));
            }
            else
            {
                // Non-printable mid-string -- not an ASCII ImageFileName.
                return false;
            }
        }
        if (imageName.size() < 3)
        {
            return false;
        }
        if (outImage != nullptr)
        {
            *outImage = std::move(imageName);
        }
        return true;
    }

    bool ResolveEprocess(
        DeviceClient& device,
        const EprocessFields& fields,
        uint64_t candidate,
        uint64_t* outPid,
        std::wstring* outImage)
    {
        if (!IsKernelAddress(candidate))
        {
            return false;
        }

        // Fast-path signature: classical _DISPATCHER_HEADER.Type byte at
        // offset 0 equals KOBJECTS::ProcessObject (0x03). Holds on most
        // Win10/Win11 builds but is not load-bearing -- when it fails we
        // fall back to shape-only validation of PDB-resolved fields.
        std::vector<uint8_t> probe;
        if (!ReadKernelBytes(device, candidate, 1, &probe, nullptr))
        {
            return false;
        }
        const bool sigByteMatched = (!probe.empty() && probe[0] == 0x03);

        // Read PID candidate from PDB-resolved offset (when available).
        bool pidValid = false;
        uint64_t pid = 0;
        if (fields.HasPid)
        {
            uint64_t pidAddr = 0;
            if (TryAdd(candidate, fields.UniqueProcessId.Offset, &pidAddr))
            {
                uint64_t raw = 0;
                if (ReadU64(device, pidAddr, &raw, nullptr))
                {
                    if (LooksLikePid(raw))
                    {
                        pid = raw;
                        pidValid = true;
                    }
                }
            }
        }

        // Read ImageFileName candidate from PDB-resolved offset.
        bool imageValid = false;
        std::wstring image;
        if (fields.HasImage)
        {
            uint64_t imgAddr = 0;
            if (TryAdd(candidate, fields.ImageFileName.Offset, &imgAddr))
            {
                size_t imgLen = static_cast<size_t>(fields.ImageFileName.Length);
                if (imgLen == 0 || imgLen > 64)
                {
                    imgLen = 16;
                }
                std::vector<uint8_t> imgBytes;
                if (ReadKernelBytes(device, imgAddr, static_cast<uint32_t>(imgLen), &imgBytes, nullptr))
                {
                    if (LooksLikeImageName(imgBytes, &image))
                    {
                        imageValid = true;
                    }
                }
            }
        }

        // Acceptance policy:
        //   1) Signature byte 0x03 matches            -> accept (legacy fast-path)
        //   2) Both PID-shape and ImageName-shape OK  -> accept (shape-only)
        //   3) Otherwise                              -> reject
        //
        // The two-of-two rule on the shape path is deliberately strict:
        // each individual shape (small aligned integer / printable ASCII
        // run) is too easy to alias by accident, but their simultaneous
        // co-occurrence at the documented offsets is highly specific to
        // _EPROCESS.
        const bool accept = sigByteMatched || (pidValid && imageValid);
        if (!accept)
        {
            return false;
        }

        bool gotAnything = false;
        if (pidValid)
        {
            if (outPid != nullptr)
            {
                *outPid = pid;
            }
            gotAnything = true;
        }
        if (imageValid)
        {
            if (outImage != nullptr)
            {
                *outImage = std::move(image);
            }
            gotAnything = true;
        }
        // If the signature byte matched but neither shape resolved, we
        // still treat the resolve as successful at the EPROCESS-pointer
        // level (HasProcess remains true in the caller). gotAnything is
        // the "filled any field" signal, not the "found EPROCESS" signal.
        if (!gotAnything && sigByteMatched)
        {
            return true;
        }
        return gotAnything;
    }

    // Walk a single LIST_ENTRY chain inside a _WNF_NAME_INSTANCE entry,
    // collecting each external node as a subscriber record. Cycle
    // detection caps the walk; the head sentinel itself is not emitted.
    void WalkSingleSubscriberChain(
        DeviceClient& device,
        SymbolEngine& symbols,
        EprocessFields& eprocessFields,
        uint64_t entryAddress,
        uint64_t headEntryOffset,
        uint64_t flink,
        std::vector<WnfSubscriberRecord>* out)
    {
        constexpr uint32_t kMaxNodes = 0x40;
        const uint64_t headAbsAddr = entryAddress + headEntryOffset;

        std::unordered_set<uint64_t> seen;
        uint64_t current = flink;
        uint32_t visited = 0;
        while (current != headAbsAddr && visited < kMaxNodes)
        {
            if (!IsKernelAddress(current))
            {
                break;
            }
            if (!seen.insert(current).second)
            {
                break;
            }

            std::vector<uint8_t> nodeBytes;
            // Capture 0x80 bytes per node. _WNF_SUBSCRIPTION-style records
            // hold the OwningProcess/ProcessContext pointer past the
            // chain-link LIST_ENTRY pair, and a 0x40 window proved too
            // shallow on Win11 builds observed in the field.
            if (!ReadKernelBytes(device, current, 0x80, &nodeBytes, nullptr))
            {
                break;
            }
            if (nodeBytes.size() < sizeof(uint64_t))
            {
                break;
            }

            WnfSubscriberRecord rec = {};
            rec.NodeAddress = current;
            rec.ListHeadEntryOffset = headEntryOffset;
            rec.RawBytes = nodeBytes;

            // Hunt for the POOL_HEADER that identifies this node's
            // kernel object type. Empirically (raw dump evidence) the
            // tag sits inside the node body at +0x14 in the POOL_HEADER
            // shape "00 00 BS BS T1 T2 T3 T4" -- i.e. nodeBytes[0x10..]
            // is a POOL_HEADER and its 4-byte ASCII tag lives at +0x04
            // of that header (nodeBytes[0x14..0x18]).
            //
            // We also capture the 0x40 bytes preceding the node into
            // PrefixBytes (used by ResolveOwningProcessForEntry which
            // reads the stable EPROCESS pointer at node-0x30), and as
            // a secondary lookup we scan the prefix for a tag in case
            // some node variants carry their header earlier.
            do
            {
                if (current < 0x40ull)
                {
                    break;
                }
                std::vector<uint8_t> prefix;
                if (!ReadKernelBytes(device, current - 0x40, 0x40, &prefix, nullptr))
                {
                    break;
                }
                if (prefix.size() != 0x40)
                {
                    break;
                }
                rec.PrefixBytes = prefix;
            } while (false);

            // Helper: validate a 4-byte ASCII pool tag at `bytes[tagBase]`.
            auto try_extract_tag =
                [&rec](const std::vector<uint8_t>& bytes, size_t tagBase) -> bool
            {
                if (tagBase + 4 > bytes.size())
                {
                    return false;
                }
                for (size_t i = 0; i < 4; ++i)
                {
                    const uint8_t b = bytes[tagBase + i];
                    const bool ok =
                        (b >= 'A' && b <= 'Z') ||
                        (b >= 'a' && b <= 'z') ||
                        (b >= '0' && b <= '9') ||
                        b == ' ';
                    if (!ok)
                    {
                        return false;
                    }
                }
                std::wstring tag;
                for (size_t i = 0; i < 4; ++i)
                {
                    tag.push_back(static_cast<wchar_t>(bytes[tagBase + i]));
                }
                rec.OwnPoolTag = tag;
                rec.HasOwnPoolTag = true;
                if (tag == L"Ntfc" || tag == L"Wnf " || tag == L"WnfN")
                {
                    rec.IsProcessCandidateTag = true;
                }
                return true;
            };

            // Primary: tag in node body at +0x14 (POOL_HEADER at +0x10,
            // tag at +0x04 of that header).
            if (!rec.HasOwnPoolTag)
            {
                try_extract_tag(rec.RawBytes, 0x14);
            }

            // Fallback: scan the prefix at candidate POOL_HEADER
            // positions in case some node variants carry their header
            // before the node start instead.
            if (!rec.HasOwnPoolTag && !rec.PrefixBytes.empty())
            {
                static const size_t kPrefixCandidates[] = { 0x30, 0x20, 0x10, 0x00 };
                for (size_t candOff : kPrefixCandidates)
                {
                    if (try_extract_tag(rec.PrefixBytes, candOff + 4))
                    {
                        break;
                    }
                }
            }

            EnsureEprocessFields(symbols, &eprocessFields);
            for (size_t off = 0; off + sizeof(uint64_t) <= nodeBytes.size(); off += sizeof(uint64_t))
            {
                uint64_t ptr = 0;
                memcpy(&ptr, nodeBytes.data() + off, sizeof(uint64_t));

                // Reject EPROCESS candidates that sit suspiciously
                // close to the node itself. Real EPROCESS objects live
                // in their own pool chunks; if the "candidate" is
                // within 0x200 bytes of the node it is almost certainly
                // another field of the same record or an adjacent
                // allocation, not a process object. This catches
                // shape-only false positives like
                //   node=0xffffd387e7bac8e0 process=0xffffd387e7bac890
                // observed in field testing.
                uint64_t distance = (ptr > current) ? (ptr - current) : (current - ptr);
                if (distance < 0x200)
                {
                    continue;
                }

                uint64_t pid = 0;
                std::wstring img;
                if (ResolveEprocess(device, eprocessFields, ptr, &pid, &img))
                {
                    rec.OwningProcessAddress = ptr;
                    rec.HasProcess = true;
                    if (pid != 0)
                    {
                        rec.Pid = pid;
                        rec.HasPid = true;
                    }
                    if (!img.empty())
                    {
                        rec.ImageName = std::move(img);
                        rec.HasImageName = true;
                    }
                    break;
                }
            }

            out->push_back(std::move(rec));

            // Advance to next node via this node's Flink (offset +0x00).
            uint64_t nextFlink = 0;
            memcpy(&nextFlink, nodeBytes.data() + 0, sizeof(uint64_t));
            current = nextFlink;
            ++visited;
        }
    }

    // Entry-level owning/host process resolution. Field testing showed
    // that every subscription record on a given entry has the same
    // EPROCESS pointer at node-0x30, and that pointer matches the
    // entry's own process slot (entry-0x540 in the observed builds).
    // We treat it as the "host process that owns this WNF state".
    void ResolveOwningProcessForEntry(
        DeviceClient& device,
        SymbolEngine& symbols,
        WnfInstanceRecord* match)
    {
        if (match == nullptr || match->Subscribers.empty())
        {
            return;
        }
        const std::vector<uint8_t>& prefix = match->Subscribers[0].PrefixBytes;
        if (prefix.size() < 0x18)
        {
            return;
        }
        uint64_t ownerPtr = 0;
        memcpy(&ownerPtr, prefix.data() + 0x10, sizeof(uint64_t));
        if (!IsKernelAddress(ownerPtr))
        {
            return;
        }

        EprocessFields eprocessFields = {};
        EnsureEprocessFields(symbols, &eprocessFields);

        uint64_t pid = 0;
        std::wstring img;
        if (!ResolveEprocess(device, eprocessFields, ownerPtr, &pid, &img))
        {
            return;
        }

        match->OwningProcessAddress = ownerPtr;
        match->HasOwningProcess = true;
        if (pid != 0)
        {
            match->OwningPid = pid;
            match->HasOwningPid = true;
        }
        if (!img.empty())
        {
            match->OwningImageName = std::move(img);
            match->HasOwningImageName = true;
        }
    }

    // Detect every subscription LIST_ENTRY chain in the entry and walk
    // each one. Heuristic: a slot at offset O is a list head when entry
    // bytes at +O (Flink) and +O+8 (Blink) are both kernel-canonical AND
    // ((Flink == entry+O) OR (the Flink target's first 16 bytes link
    // back into the +O / +O+8 region)). The walker emits subscribers
    // from every detected chain.
    void WalkSubscribersForEntry(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t entryAddress,
        std::vector<WnfSubscriberRecord>* out)
    {
        if (out == nullptr)
        {
            return;
        }
        std::vector<uint8_t> entryBytes;
        if (!ReadKernelBytes(device, entryAddress, 0x200, &entryBytes, nullptr))
        {
            return;
        }

        EprocessFields eprocessFields = {};

        // Start scanning after the parent LIST_ENTRY at +0x00 (which
        // chains the entry into its silo-level list and is not a
        // subscriber chain). Skip 8 bytes at a time and consider each
        // (slot, slot+8) pair as a possible LIST_ENTRY head.
        for (uint64_t off = 0x10;
             off + 2 * sizeof(uint64_t) <= entryBytes.size();
             off += sizeof(uint64_t))
        {
            uint64_t flink = 0;
            uint64_t blink = 0;
            memcpy(&flink, entryBytes.data() + off, sizeof(uint64_t));
            memcpy(&blink, entryBytes.data() + off + sizeof(uint64_t), sizeof(uint64_t));
            if (!IsKernelAddress(flink) || !IsKernelAddress(blink))
            {
                continue;
            }

            const uint64_t headAbs = entryAddress + off;

            // Self-sentinel (empty list) -- skip but still confirms this
            // slot IS a list head, so skip the next 8-byte slot too
            // (the Blink half).
            if (flink == headAbs && blink == headAbs)
            {
                ++off;  // skip blink half too (loop increments by sizeof too)
                continue;
            }

            // Non-empty candidate: validate that the target's Flink
            // and/or Blink link back into the head region. This rejects
            // arbitrary kernel pointers that happen to occupy two
            // consecutive slots.
            std::vector<uint8_t> first;
            if (!ReadKernelBytes(device, flink, 16, &first, nullptr))
            {
                continue;
            }
            if (first.size() != 16)
            {
                continue;
            }
            uint64_t nodeFlink = 0;
            uint64_t nodeBlink = 0;
            memcpy(&nodeFlink, first.data() + 0, sizeof(uint64_t));
            memcpy(&nodeBlink, first.data() + 8, sizeof(uint64_t));

            // Accept if either link references the head we're probing
            // (could be the only-node case where Blink == head, or any
            // intermediate node where Blink points back along the chain).
            const bool linksHead =
                (nodeBlink == headAbs) || (nodeFlink == headAbs) ||
                (nodeBlink >= entryAddress && nodeBlink < entryAddress + 0x200) ||
                (nodeFlink >= entryAddress && nodeFlink < entryAddress + 0x200);
            if (!linksHead)
            {
                continue;
            }

            WalkSingleSubscriberChain(device, symbols, eprocessFields,
                                       entryAddress, off, flink, out);

            // Skip the blink half so we don't re-detect the same head
            // from the +0x08 offset on the next iteration.
            ++off;
        }
    }

    bool WalkInstancesViaListEntry(
        const std::vector<WnfListHeadFinding>& findings,
        const WnfScanner::Options& options,
        WnfScanResult* result)
    {
        if (result == nullptr)
        {
            return false;
        }

        const bool hasHashFilter =
            (options.Target == WnfScanner::Scope::Instance ||
             options.Target == WnfScanner::Scope::Data) && options.HasTargetHash;
        const uint64_t hashFilter = options.TargetHash;

        // Score each finding by the count of UNIQUE state-name values its
        // entries yield. This is the discriminator that separates a real
        // WNF instance list (broad distribution of unique names) from a
        // sentinel/allocator-tracking list whose entries all share a
        // single tag value that happens to decode as plausible.
        struct Scored
        {
            const WnfListHeadFinding* Head;
            size_t SuccessCount;
            size_t UniqueCount;
        };
        std::vector<Scored> ranked;
        ranked.reserve(findings.size());

        for (const WnfListHeadFinding& finding : findings)
        {
            if (finding.IsEmpty || finding.Entries.empty())
            {
                continue;
            }
            size_t success = 0;
            std::unordered_set<uint64_t> uniqueNames;
            for (const WnfListEntryWalkRecord& e : finding.Entries)
            {
                uint64_t raw = 0;
                if (ExtractStateNameFromEntry(e, &raw, nullptr, nullptr))
                {
                    ++success;
                    uniqueNames.insert(raw);
                }
            }
            // Require: at least 4 successes, >= 50% hit rate, AND at least
            // 4 distinct state-name values across the list.
            if (success < 4)
            {
                continue;
            }
            if (success * 2 < finding.Entries.size())
            {
                continue;
            }
            if (uniqueNames.size() < 4)
            {
                continue;
            }
            ranked.push_back({&finding, success, uniqueNames.size()});
        }

        if (ranked.empty())
        {
            return false;
        }

        // Sort by UniqueCount descending (richer distribution wins). Tie
        // breaker on SuccessCount.
        std::sort(ranked.begin(), ranked.end(),
                  [](const Scored& a, const Scored& b)
                  {
                      if (a.UniqueCount != b.UniqueCount)
                      {
                          return a.UniqueCount > b.UniqueCount;
                      }
                      return a.SuccessCount > b.SuccessCount;
                  });

        // Walk ONLY the top-ranked list. Unioning multiple lists previously
        // produced 1000+ entries with heavy sentinel pollution. The single
        // most-diverse list is the authoritative WNF name-instance chain
        // on this build; everything else is allocator/object bookkeeping.
        const Scored& top = ranked.front();
        uint32_t totalExtracted = 0;
        for (const WnfListEntryWalkRecord& e : top.Head->Entries)
        {
            uint64_t raw = 0;
            uint64_t off = 0;
            WnfStateNameDecoded decoded = {};
            if (!ExtractStateNameFromEntry(e, &raw, &off, &decoded))
            {
                continue;
            }
            // Filter accepts EITHER state-name match OR entry-address match.
            // Operators often paste the entry address shown by !wnf instances
            // directly into !wnf instance <hash>; accepting both makes that
            // workflow ergonomic without forcing them to re-decode.
            if (hasHashFilter && raw != hashFilter && e.EntryAddress != hashFilter)
            {
                continue;
            }

            WnfInstanceRecord rec = {};
            rec.Address = e.EntryAddress;
            rec.StateName = raw;
            rec.Decoded = decoded;
            result->Instances.push_back(rec);
            ++totalExtracted;
        }

        // We identified a candidate WNF list. Return success even when the
        // hash filter excluded every entry -- that's an honest "no match"
        // not a "walker failed" condition, and falling through to the AVL
        // path on a system that has no AVL table would mislead the operator.
        result->TableTypeName = L"WNF instance list (list-entry heuristic)";
        result->TableFieldName = L"silo+head LIST_ENTRY chain";
        result->TableAddress = top.Head->HeadAddress;
        result->TableResolved = true;

        std::wstringstream ss;
        ss << L"list-entry walk: ranked_heads=" << std::dec << ranked.size()
           << L" top_head=0x" << std::hex << top.Head->HeadAddress
           << L" top_silo=0x" << top.Head->SiloAddress
           << L" top_unique=" << std::dec << top.UniqueCount
           << L" top_hits=" << top.SuccessCount
           << L"/" << top.Head->Entries.size()
           << L" extracted=" << totalExtracted;
        result->Diagnostics.push_back(ss.str());

        // Verification probe: scan the top list for the FULL encoded WNF
        // state name pattern (0x41C6XXXX_XXXXXXXX). If most entries carry
        // one, we have been reading the wrong offset all along and the
        // probe tells us where the real state name lives.
        {
            uint32_t fullStateHits = 0;
            std::unordered_map<uint64_t, uint32_t> offsetHistogram;
            uint64_t firstHitOffset = 0;
            uint64_t firstHitValue = 0;
            uint64_t firstHitEntry = 0;
            for (const WnfListEntryWalkRecord& e : top.Head->Entries)
            {
                uint64_t full = 0;
                uint64_t off = 0;
                if (ProbeFullEncodedStateName(e, &full, &off))
                {
                    ++fullStateHits;
                    ++offsetHistogram[off];
                    if (firstHitOffset == 0 && fullStateHits == 1)
                    {
                        firstHitOffset = off;
                        firstHitValue = full;
                        firstHitEntry = e.EntryAddress;
                    }
                }
            }

            std::wstringstream ps;
            ps << L"full-state-name probe (0x41C6XXXX pattern, top list): hits="
               << std::dec << fullStateHits << L"/" << top.Head->Entries.size();
            if (fullStateHits > 0)
            {
                ps << L" first_hit_entry=0x" << std::hex << firstHitEntry
                   << L" first_hit_value=0x" << firstHitValue
                   << L" first_hit_offset=0x" << firstHitOffset;
            }
            result->Diagnostics.push_back(ps.str());

            if (!offsetHistogram.empty())
            {
                std::vector<std::pair<uint64_t, uint32_t>> sorted(
                    offsetHistogram.begin(), offsetHistogram.end());
                std::sort(sorted.begin(), sorted.end(),
                          [](const auto& a, const auto& b)
                          {
                              return a.second > b.second;
                          });

                std::wstringstream hs;
                hs << L"full-state-name offset histogram:";
                const size_t maxShow = sorted.size() < 8 ? sorted.size() : 8;
                for (size_t i = 0; i < maxShow; ++i)
                {
                    hs << L" +0x" << std::hex << sorted[i].first
                       << L"=" << std::dec << sorted[i].second;
                }
                result->Diagnostics.push_back(hs.str());
            }
        }

        // List the runners-up so the operator can re-run with manual
        // targeting if needed (e.g. when a per-build split moves the real
        // instance chain into a smaller secondary head).
        for (size_t i = 1; i < ranked.size() && i < 6; ++i)
        {
            std::wstringstream rs;
            rs << L"list-entry runner-up #" << std::dec << i
               << L": head=0x" << std::hex << ranked[i].Head->HeadAddress
               << L" silo=0x" << ranked[i].Head->SiloAddress
               << L" unique=" << std::dec << ranked[i].UniqueCount
               << L" hits=" << ranked[i].SuccessCount
               << L"/" << ranked[i].Head->Entries.size();
            result->Diagnostics.push_back(rs.str());
        }

        return true;
    }

    struct AvlWalkContext
    {
        DeviceClient* Device = nullptr;
        SymbolEngine* Symbols = nullptr;
        NameInstanceLayout* Layout = nullptr;
        std::vector<WnfInstanceRecord>* Records = nullptr;
        uint32_t NodesVisited = 0;
        uint64_t HashFilter = 0;
        bool HasHashFilter = false;
        bool Aborted = false;
    };

    bool ReadInstanceRecord(
        DeviceClient& device,
        const NameInstanceLayout& layout,
        uint64_t instanceAddress,
        WnfInstanceRecord* record)
    {
        if (record == nullptr || !layout.HasStateName)
        {
            return false;
        }

        record->Address = instanceAddress;

        uint64_t fieldAddress = 0;
        if (!TryAdd(instanceAddress, layout.StateNameOffset, &fieldAddress))
        {
            return false;
        }

        uint64_t stateName = 0;
        if (!ReadU64(device, fieldAddress, &stateName, nullptr))
        {
            return false;
        }

        record->StateName = stateName;
        record->Decoded = DecodeWnfStateName(stateName);

        if (layout.HasChangeStamp)
        {
            uint64_t changeStampAddr = 0;
            if (TryAdd(instanceAddress, layout.ChangeStampOffset, &changeStampAddr))
            {
                if (layout.ChangeStampLength == sizeof(uint64_t))
                {
                    uint64_t stamp = 0;
                    if (ReadU64(device, changeStampAddr, &stamp, nullptr))
                    {
                        record->ChangeStamp = stamp;
                        record->HasChangeStamp = true;
                    }
                }
                else
                {
                    uint32_t stamp32 = 0;
                    if (ReadU32(device, changeStampAddr, &stamp32, nullptr))
                    {
                        record->ChangeStamp = stamp32;
                        record->HasChangeStamp = true;
                    }
                }
            }
        }

        if (layout.HasDataSize)
        {
            uint64_t dataSizeAddr = 0;
            if (TryAdd(instanceAddress, layout.DataSizeOffset, &dataSizeAddr))
            {
                uint32_t size = 0;
                if (ReadU32(device, dataSizeAddr, &size, nullptr))
                {
                    record->DataSize = size;
                    record->HasDataSize = true;
                }
            }
        }

        if (layout.HasLastDataBlock)
        {
            uint64_t dataBlockAddr = 0;
            if (TryAdd(instanceAddress, layout.LastDataBlockOffset, &dataBlockAddr))
            {
                uint64_t block = 0;
                if (ReadU64(device, dataBlockAddr, &block, nullptr))
                {
                    if (block == 0 || IsKernelAddress(block))
                    {
                        record->LastDataBlock = block;
                        record->HasLastDataBlock = true;
                    }
                }
            }
        }

        return true;
    }

    void WalkAvlTreeIterative(uint64_t treeAddress, AvlWalkContext* ctx, WnfScanResult* result)
    {
        if (ctx == nullptr || result == nullptr || ctx->Device == nullptr || ctx->Layout == nullptr)
        {
            return;
        }

        // treeAddress is the address of an RTL_AVL_TABLE. The actual root link is
        // its BalancedRoot member (the table's RightChild of a sentinel head). On
        // x64 ntoskrnl RTL_AVL_TABLE starts with the sentinel _RTL_BALANCED_LINKS
        // at offset 0, so the real subtree root pointer lives at +RightChild.
        uint64_t rootRightAddr = 0;
        if (!TryAdd(treeAddress, kAvlBalancedRootRight, &rootRightAddr))
        {
            return;
        }

        uint64_t root = 0;
        if (!ReadU64(*ctx->Device, rootRightAddr, &root, nullptr) ||
            root == 0 || !IsKernelAddress(root))
        {
            return;
        }

        struct Frame
        {
            uint64_t Node;
            bool VisitedLeft;
        };

        std::vector<Frame> stack;
        stack.reserve(kMaxAvlDepth);
        stack.push_back({root, false});

        while (!stack.empty() && ctx->NodesVisited < kMaxAvlNodes)
        {
            Frame& top = stack.back();
            if (!top.VisitedLeft)
            {
                top.VisitedLeft = true;

                uint64_t leftAddr = 0;
                uint64_t leftChild = 0;
                if (TryAdd(top.Node, kAvlBalancedRootLeft, &leftAddr) &&
                    ReadU64(*ctx->Device, leftAddr, &leftChild, nullptr) &&
                    leftChild != 0 && IsKernelAddress(leftChild))
                {
                    if (stack.size() >= kMaxAvlDepth)
                    {
                        if (ctx->NodesVisited == 0)
                        {
                            result->Warnings.push_back(
                                L"AVL left-chain exceeded depth 64 before any node was processed; "
                                L"the located AVL table is likely not the WNF subscription tree");
                            ctx->Aborted = true;
                        }
                        else
                        {
                            result->Warnings.push_back(L"AVL traversal depth limit reached");
                        }
                        break;
                    }
                    stack.push_back({leftChild, false});
                    continue;
                }
            }

            // Process this node
            uint64_t nodeAddress = top.Node;
            uint64_t instanceAddress = 0;
            if (TryAdd(nodeAddress, kRtlBalancedLinksSize, &instanceAddress))
            {
                WnfInstanceRecord record = {};
                if (ReadInstanceRecord(*ctx->Device, *ctx->Layout, instanceAddress, &record))
                {
                    // First-node sanity check: if the leftmost leaf's state
                    // name doesn't look like a real WNF name, we walked into
                    // a non-tree structure (auto-detect picked a wrong AVL
                    // offset). Abort the walk and surface the failure.
                    if (ctx->NodesVisited == 0 && !LooksLikeStateName(record.StateName))
                    {
                        result->Warnings.push_back(
                            L"first processed node's StateName does not decode as a plausible WNF name; "
                            L"the located AVL table is likely not the WNF subscription tree");
                        ctx->Aborted = true;
                        break;
                    }

                    bool keep = true;
                    if (ctx->HasHashFilter)
                    {
                        keep = (record.StateName == ctx->HashFilter);
                    }
                    if (keep)
                    {
                        ctx->Records->push_back(std::move(record));
                    }
                }
            }

            ++ctx->NodesVisited;

            uint64_t rightAddr = 0;
            uint64_t rightChild = 0;
            bool hasRight = TryAdd(nodeAddress, kAvlBalancedRootRight, &rightAddr) &&
                            ReadU64(*ctx->Device, rightAddr, &rightChild, nullptr) &&
                            rightChild != 0 && IsKernelAddress(rightChild);

            stack.pop_back();

            if (hasRight)
            {
                if (stack.size() >= kMaxAvlDepth)
                {
                    result->Warnings.push_back(L"AVL traversal depth limit reached");
                    break;
                }
                stack.push_back({rightChild, false});
            }
        }

        result->NodesVisited += ctx->NodesVisited;

        if (!ctx->Aborted && ctx->NodesVisited >= kMaxAvlNodes)
        {
            result->Warnings.push_back(L"AVL traversal node cap reached");
        }
    }
}

WnfStateNameDecoded DecodeWnfStateName(uint64_t raw)
{
    WnfStateNameDecoded r{};
    r.Raw = raw;
    r.Decoded = raw ^ kWnfStateNameXorKey;

    r.Version = static_cast<uint32_t>(r.Decoded & 0xfull);
    r.Lifetime = static_cast<uint32_t>((r.Decoded >> 4) & 0x3ull);
    r.DataScope = static_cast<uint32_t>((r.Decoded >> 6) & 0xfull);
    r.IsPermanent = ((r.Decoded >> 10) & 0x1ull) != 0;
    // The unique field occupies the upper 53 bits (positions 11..63). For
    // WellKnown lifetime, the upper 32 bits of that field are a 4-char ASCII
    // OwnerTag and the lower 21 bits are a local sequence id; for the other
    // lifetimes the whole 53 bits are a unique sequence.
    r.Sequence = (r.Decoded >> 11) & 0x1fffffffffffffull;
    r.OwnerTag = (r.Decoded >> 32) & 0xffffffffull;

    switch (r.Lifetime)
    {
    case 0:
        r.LifetimeText = L"WellKnown";
        break;
    case 1:
        r.LifetimeText = L"Permanent";
        break;
    case 2:
        r.LifetimeText = L"Persistent";
        break;
    case 3:
        r.LifetimeText = L"Temporary";
        break;
    default:
        r.LifetimeText = L"<unknown>";
        break;
    }

    switch (r.DataScope)
    {
    case 0:
        r.DataScopeText = L"System";
        break;
    case 1:
        r.DataScopeText = L"Session";
        break;
    case 2:
        r.DataScopeText = L"User";
        break;
    case 3:
        r.DataScopeText = L"Process";
        break;
    case 4:
        r.DataScopeText = L"Machine";
        break;
    case 5:
        r.DataScopeText = L"PhysicalMachine";
        break;
    default:
        r.DataScopeText = L"<unknown>";
        break;
    }

    if (r.Lifetime == 0 && r.OwnerTag != 0)
    {
        // WellKnown owner tag: 4 ASCII bytes in little-endian order from the 32-bit
        // OwnerTag field (decoded bits 32..63).
        wchar_t buf[5] = {0, 0, 0, 0, 0};
        uint32_t tag = static_cast<uint32_t>(r.OwnerTag);
        bool printable = true;
        bool anyNonZero = false;
        for (int i = 0; i < 4; ++i)
        {
            unsigned char ch = static_cast<unsigned char>((tag >> (i * 8)) & 0xffu);
            if (ch == 0)
            {
                buf[i] = L' ';
                continue;
            }
            if (ch < 0x20 || ch >= 0x7f)
            {
                printable = false;
                break;
            }
            anyNonZero = true;
            buf[i] = static_cast<wchar_t>(ch);
        }
        if (printable && anyNonZero)
        {
            r.OwnerTagText = buf;
            // Trim trailing spaces from padding zeros
            while (!r.OwnerTagText.empty() && r.OwnerTagText.back() == L' ')
            {
                r.OwnerTagText.pop_back();
            }
        }
    }

    return r;
}

WnfScanner::WnfScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool WnfScanner::Scan(const Options& options, WnfScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid scan result output";
            }
            break;
        }

        *result = WnfScanResult{};

        if (options.Target == Scope::Decode)
        {
            if (!options.HasTargetHash)
            {
                if (error != nullptr)
                {
                    *error = L"!wnf decode requires a 64-bit state-name hash";
                }
                break;
            }
            result->DecodedHash = DecodeWnfStateName(options.TargetHash);
            ok = true;
            break;
        }

        // Candidates scope shares anchor collection with the live walk but
        // stops after recording each candidate's first 256 bytes for manual
        // inspection. This is the diagnostic gateway for builds where the
        // subscription table data structure has moved away from RTL_AVL_TABLE.

        // Step 1: resolve silo state global -- try the well-known names first,
        // then anchor-disassemble nt!NtQueryWnfStateData / nt!NtPublishWnfStateData
        // and try every kernel-canonical pointer they reference.
        struct SiloCandidate
        {
            uint64_t PointerAddress;
            uint64_t SiloAddress;
            std::wstring Symbol;
        };
        std::vector<SiloCandidate> siloCandidates;

        {
            uint64_t namedPtr = 0;
            std::wstring namedSymbol;
            if (ResolveFirstSymbol(
                    symbols_,
                    {L"nt!ExpWnfSiloState",
                     L"nt!ExpWnfSiloDriverState",
                     L"nt!ExpWnfDriverState",
                     L"nt!ExpWnfState",
                     L"nt!ExpWnfProcess",
                     L"nt!ExpWnfDriverGlobals",
                     L"nt!ExpWnfGlobalState",
                     L"nt!WnfSiloState"},
                    &namedPtr,
                    &namedSymbol))
            {
                uint64_t siloAddr = 0;
                if (ReadU64(device_, namedPtr, &siloAddr, nullptr) &&
                    siloAddr != 0 && IsKernelAddress(siloAddr))
                {
                    siloCandidates.push_back({namedPtr, siloAddr, namedSymbol});
                }
            }
        }

        {
            const wchar_t* anchorFunctions[] =
            {
                L"nt!NtQueryWnfStateData",
                L"nt!NtPublishWnfStateData",
                L"nt!NtSubscribeWnfStateChange",
                L"nt!NtUnsubscribeWnfStateChange",
                L"nt!NtQueryWnfStateNameInformation",
                L"nt!NtCreateWnfStateName",
                L"nt!NtDeleteWnfStateName",
                L"nt!ExpWnfQueryStateData",
                L"nt!ExpWnfPublishStateData",
                L"nt!ExpWnfCreateNameInstance",
                L"nt!ExpWnfDeleteNameInstance",
                L"nt!ExpWnfSubscribeStateChange"
            };
            std::unordered_set<uint64_t> seenTargets;
            std::unordered_set<uint64_t> seenAnchorCandidates;

            for (const wchar_t* anchor : anchorFunctions)
            {
                uint64_t funcAddr = 0;
                std::wstring ignored;
                if (!symbols_.ResolveSymbol(anchor, &funcAddr, &ignored))
                {
                    continue;
                }
                std::vector<uint64_t> targets;
                std::unordered_set<uint64_t> visitedFunctions;
                ExtractAnchorGlobals(device_, funcAddr, 2, &visitedFunctions, &targets, &seenTargets);

                for (uint64_t targetAddr : targets)
                {
                    if (!seenAnchorCandidates.insert(targetAddr).second)
                    {
                        continue;
                    }

                    // Modern WNF can be reached two different ways from a
                    // disassembled anchor: the function might use a pointer-
                    // to-struct global (mov reg,[rip+SiloPtr], dereference
                    // gives the silo address) or an inline struct global
                    // (lea reg,[rip+SiloStruct], the target IS the struct).
                    // We add both interpretations as silo candidates and
                    // rely on the embedded-AVL filter to reject the wrong
                    // shape.

                    // Interpretation 1: target is a pointer variable
                    uint64_t derefValue = 0;
                    if (ReadU64(device_, targetAddr, &derefValue, nullptr) &&
                        derefValue != 0 && IsKernelAddress(derefValue) &&
                        CandidateSiloLooksPlausible(device_, derefValue))
                    {
                        SiloCandidate cand = {};
                        cand.PointerAddress = targetAddr;
                        cand.SiloAddress = derefValue;
                        wchar_t buf[80];
                        swprintf_s(buf, L"<anchor:%ls+disp deref>", anchor);
                        cand.Symbol = buf;
                        siloCandidates.push_back(cand);
                    }

                    // Interpretation 2: target is itself the struct
                    if (CandidateSiloLooksPlausible(device_, targetAddr))
                    {
                        SiloCandidate cand = {};
                        cand.PointerAddress = targetAddr;
                        cand.SiloAddress = targetAddr;
                        wchar_t buf[80];
                        swprintf_s(buf, L"<anchor:%ls+disp inline>", anchor);
                        cand.Symbol = buf;
                        siloCandidates.push_back(cand);
                    }
                }
                // Continue collecting across all anchors so we have a wider
                // candidate set when none of the named symbols resolved.
            }
        }

        result->SiloCandidatesCollected = static_cast<uint32_t>(siloCandidates.size());

        if (options.Target == Scope::Lists)
        {
            for (const SiloCandidate& cand : siloCandidates)
            {
                CollectListHeadsFromSilo(device_, cand.SiloAddress, &result->ListHeads);
            }
            ok = true;
            break;
        }

        if (options.Target == Scope::Candidates)
        {
            for (const SiloCandidate& cand : siloCandidates)
            {
                WnfSiloCandidateDump dump = {};
                dump.PointerAddress = cand.PointerAddress;
                dump.SiloAddress = cand.SiloAddress;
                dump.AnchorSymbol = cand.Symbol;

                std::vector<uint8_t> head;
                if (ReadKernelBytes(device_, cand.SiloAddress, 0x100, &head, nullptr))
                {
                    dump.HeadBytes = std::move(head);

                    // Tally weak signals: kernel pointer slots and embedded
                    // state-name-looking 64-bit values within the dumped head.
                    for (size_t off = 0; off + 8 <= dump.HeadBytes.size(); off += sizeof(uint64_t))
                    {
                        uint64_t value = 0;
                        memcpy(&value, dump.HeadBytes.data() + off, sizeof(uint64_t));
                        if (value != 0 && IsKernelAddress(value))
                        {
                            ++dump.KernelPointerSlots;
                        }
                        if (LooksLikeStateName(value))
                        {
                            ++dump.EmbeddedStateNameHits;
                        }
                    }
                }

                std::wstring nearest;
                uint64_t displacement = 0;
                std::wstring ignored;
                if (symbols_.FindNearestSymbol(cand.SiloAddress, &nearest, &displacement, &ignored))
                {
                    std::wstringstream stream;
                    stream << nearest;
                    if (displacement != 0)
                    {
                        stream << L"+0x" << std::hex << displacement;
                    }
                    dump.NearestSymbol = stream.str();
                }
                for (const KernelModuleInfo& module : symbols_.Modules())
                {
                    uint64_t end = module.Base + module.Size;
                    if (end < module.Base)
                    {
                        continue;
                    }
                    if (cand.SiloAddress >= module.Base && cand.SiloAddress < end)
                    {
                        dump.NearestModule = module.ImageName;
                        break;
                    }
                }

                result->Candidates.push_back(std::move(dump));
            }
            ok = true;
            break;
        }

        // Modern Win11 fast path: enumerate LIST_ENTRY chains hanging off
        // each silo candidate and walk them as _WNF_NAME_INSTANCE (mode B)
        // or _WNF_NAME_SUBSCRIPTION (mode A) before falling back to the
        // RTL_AVL_TABLE legacy walker. The list-entry walker bypasses
        // PDB layout discovery entirely, which is essential on builds
        // where ExpWnfSiloState/ExpWnfState are private symbols.
        if (options.Target == Scope::Instances ||
            options.Target == Scope::Instance ||
            options.Target == Scope::Data)
        {
            std::vector<WnfListHeadFinding> listHeads;
            for (const SiloCandidate& cand : siloCandidates)
            {
                CollectListHeadsFromSilo(device_, cand.SiloAddress, &listHeads);
            }

            const bool produced = WalkInstancesViaListEntry(listHeads, options, result);

            if (produced)
            {
                // Enrich every matched record with subscriber chain
                // enumeration. Done for all instance-producing scopes
                // (Instances listing, single Instance lookup, and Data
                // lookup) so the operator can correlate state -> owner
                // in one pass without re-running !wnf instance per entry.
                // For the listing path we emit a single aggregate
                // diagnostic instead of N per-entry lines.
                if ((options.Target == Scope::Instances ||
                     options.Target == Scope::Instance ||
                     options.Target == Scope::Data) && !result->Instances.empty())
                {
                    size_t totalSubs = 0;
                    size_t entriesWithSubs = 0;
                    for (WnfInstanceRecord& subMatch : result->Instances)
                    {
                        if (subMatch.Subscribers.empty())
                        {
                            WalkSubscribersForEntry(device_, symbols_,
                                                    subMatch.Address,
                                                    &subMatch.Subscribers);
                        }
                        if (!subMatch.Subscribers.empty())
                        {
                            totalSubs += subMatch.Subscribers.size();
                            ++entriesWithSubs;
                        }
                        // Entry-level owning process from the first
                        // subscriber's prefix slot at node-0x30. Safe
                        // to call when the subscriber list is empty
                        // (it returns immediately).
                        if (!subMatch.HasOwningProcess)
                        {
                            ResolveOwningProcessForEntry(device_, symbols_, &subMatch);
                        }
                    }

                    if (options.Target == Scope::Instances)
                    {
                        std::wstringstream ss;
                        ss << L"subscriber walk (listing): entries=" << std::dec
                           << result->Instances.size()
                           << L" entries_with_subs=" << entriesWithSubs
                           << L" total_subs=" << totalSubs;
                        result->Diagnostics.push_back(ss.str());
                    }
                    else
                    {
                        const WnfInstanceRecord& only = result->Instances.front();
                        std::wstringstream ss;
                        ss << L"subscriber walk: entry=0x" << std::hex << only.Address
                           << L" subscribers=" << std::dec << only.Subscribers.size();
                        result->Diagnostics.push_back(ss.str());
                    }
                }

                // For Data scope, fill in the dump from the matched record.
                // (Only fires when Instances is non-empty -- empty means the
                // hash filter excluded every entry, which is "not found",
                // not "walker failed".)
                if (options.Target == Scope::Data && !result->Instances.empty())
                {
                    WnfInstanceRecord& match = result->Instances.front();

                    // Probe the matched _WNF_NAME_INSTANCE entry for a
                    // _WNF_DATA_BLOCK pointer. The legacy AVL walker
                    // resolves this via PDB-named offsets, but in
                    // LIST_ENTRY mode we run without symbols and must
                    // discover it heuristically. Skipped if a previous
                    // walker stage already populated the data-block
                    // fields.
                    if (!match.HasLastDataBlock)
                    {
                        uint64_t blockAddr = 0;
                        uint32_t allocSize = 0;
                        uint32_t dataSize = 0;
                        uint64_t changeStamp = 0;
                        uint64_t entryOff = 0;
                        std::vector<uint8_t> entryDump;
                        if (ProbeWnfDataBlock(device_, match.Address,
                                              &blockAddr, &allocSize,
                                              &dataSize, &changeStamp,
                                              &entryOff, &entryDump))
                        {
                            match.HasLastDataBlock = true;
                            match.LastDataBlock = blockAddr;
                            match.HasDataSize = true;
                            match.DataSize = dataSize;
                            match.HasChangeStamp = true;
                            match.ChangeStamp = changeStamp;

                            std::wstringstream ds;
                            ds << L"data-block probe: entry=0x" << std::hex << match.Address
                               << L" block=0x" << blockAddr
                               << L" alloc=" << std::dec << allocSize
                               << L" data_size=" << dataSize
                               << L" change_stamp=0x" << std::hex << changeStamp
                               << L" found_at_entry_offset=0x" << entryOff;
                            result->Diagnostics.push_back(ds.str());
                        }
                        else
                        {
                            result->Diagnostics.push_back(
                                L"data-block probe: no _WNF_DATA_BLOCK pointer found in entry first 0x200 bytes");

                            // When probe fails, surface a kernel-pointer
                            // census of the entry so the operator can see
                            // which slot might actually carry the data
                            // block reference on this build. We list each
                            // kernel-canonical pointer + the first 16
                            // bytes at the pointed-to address; that header
                            // shape is what discriminates _WNF_DATA_BLOCK
                            // from other referenced structures.
                            for (size_t off = 0x10;
                                 off + sizeof(uint64_t) <= entryDump.size();
                                 off += sizeof(uint64_t))
                            {
                                uint64_t ptr = 0;
                                memcpy(&ptr, entryDump.data() + off, sizeof(uint64_t));
                                if (!IsKernelAddress(ptr))
                                {
                                    continue;
                                }
                                std::vector<uint8_t> hdr;
                                if (!ReadKernelBytes(device_, ptr, 16, &hdr, nullptr))
                                {
                                    continue;
                                }
                                if (hdr.size() != 16)
                                {
                                    continue;
                                }
                                uint32_t a = 0;
                                uint32_t b = 0;
                                uint32_t c = 0;
                                uint32_t d = 0;
                                memcpy(&a, hdr.data() +  0, sizeof(uint32_t));
                                memcpy(&b, hdr.data() +  4, sizeof(uint32_t));
                                memcpy(&c, hdr.data() +  8, sizeof(uint32_t));
                                memcpy(&d, hdr.data() + 12, sizeof(uint32_t));
                                std::wstringstream cs;
                                cs << L"  entry+0x" << std::hex << off
                                   << L" -> 0x" << ptr
                                   << L"  hdr=[0x" << a
                                   << L" 0x" << b
                                   << L" 0x" << c
                                   << L" 0x" << d << L"]";
                                result->Diagnostics.push_back(cs.str());
                            }
                        }
                    }

                    result->Data.StateName = match.StateName;
                    result->Data.Decoded = match.Decoded;
                    result->Data.InstanceAddress = match.Address;
                    result->Data.InstanceResolved = true;

                    if (match.HasLastDataBlock && match.LastDataBlock != 0)
                    {
                        result->Data.DataBlockAddress = match.LastDataBlock;

                        uint32_t copySize = match.HasDataSize ? match.DataSize : 0;
                        if (copySize == 0)
                        {
                            copySize = 0x40;
                        }
                        if (copySize > 0x100)
                        {
                            copySize = 0x100;
                        }

                        // Try several buffer-offset candidates within the
                        // _WNF_DATA_BLOCK. +0x10 is the canonical layout
                        // (AllocatedSize/DataSize/ChangeStamp/pad then
                        // buffer). +0x18, +0x20 cover header variants
                        // observed in newer builds; +0x00 is the
                        // pre-header-stripped form some debuggers expose.
                        const uint64_t bufferOffsetCandidates[] = { 0x10, 0x18, 0x20, 0x00 };
                        for (uint64_t bufOff : bufferOffsetCandidates)
                        {
                            uint64_t bufferAddr = 0;
                            if (!TryAdd(match.LastDataBlock, bufOff, &bufferAddr))
                            {
                                continue;
                            }
                            std::vector<uint8_t> bytes;
                            if (ReadKernelBytes(device_, bufferAddr, copySize, &bytes, nullptr))
                            {
                                result->Data.DataBytes = std::move(bytes);
                                result->Data.DataSize = copySize;
                                result->Data.DataResolved = true;

                                std::wstringstream bs;
                                bs << L"data-block buffer read: address=0x" << std::hex << bufferAddr
                                   << L" (block_base=0x" << match.LastDataBlock
                                   << L" +0x" << bufOff << L")"
                                   << L" bytes=" << std::dec << copySize;
                                result->Diagnostics.push_back(bs.str());
                                break;
                            }
                        }
                    }
                }

                // Honest exit: a candidate WNF list was identified. If the
                // filter excluded every entry, the operator gets a clean
                // "0 instances" plus the diagnostics showing the top list
                // and runner-ups, which is the correct signal -- not the
                // misleading "walker failed, falling back to AVL" message.
                ok = true;
                break;
            }

            // Only fall through to the legacy AVL path when no LIST_ENTRY
            // candidate list was identified at all (Win10 / early Win11
            // builds that still use RTL_AVL_TABLE).
            result->Diagnostics.push_back(
                L"list-entry walk identified no candidate WNF list; trying legacy RTL_AVL_TABLE path");
        }

        // Secondary filter: drop silo candidates that don't contain any
        // RTL_AVL_TABLE-shaped header within the first 0x800 bytes. Real WNF
        // silo state structs hold at least one such table. We REPLACE the
        // candidate list regardless of whether the filtered list is empty
        // -- keeping the unfiltered list when nothing passes just leads us
        // to the same failure with no diagnostic value.
        {
            std::vector<SiloCandidate> filtered;
            filtered.reserve(siloCandidates.size());
            for (const SiloCandidate& cand : siloCandidates)
            {
                std::vector<AvlOffsetCandidate> avlList;
                if (FindAllAvlTablesInSilo(device_, symbols_, cand.SiloAddress, &avlList) &&
                    !avlList.empty())
                {
                    filtered.push_back(cand);
                    result->TotalAvlTablesObserved += static_cast<uint32_t>(avlList.size());
                    for (const AvlOffsetCandidate& a : avlList)
                    {
                        if (a.WnfRelated)
                        {
                            ++result->WnfRelatedAvlsObserved;
                            std::wstringstream stream;
                            stream << L"silo=" << HexAddressLocal(cand.SiloAddress)
                                   << L" avl=+0x" << std::hex << a.Offset << std::dec
                                   << L" compare=" << a.CompareSymbol;
                            result->Diagnostics.push_back(stream.str());
                        }
                    }
                }
            }
            siloCandidates = std::move(filtered);
        }

        result->SiloCandidatesAfterFilter = static_cast<uint32_t>(siloCandidates.size());

        if (siloCandidates.empty())
        {
            if (error != nullptr)
            {
                *error = L"resolved candidate WNF silo pointers but none contained a recognizable RTL_AVL_TABLE structure within the first 0x2000 bytes (Parent-pointer validation included). "
                         L"Modern Windows builds may have migrated WNF subscription tracking away from RTL_AVL_TABLE into a different data structure, or moved it into per-process _WNF_PROCESS_CONTEXT. "
                         L"Live walking on this build requires a per-build offset table or WNF-specific reverse engineering (Tier 1 backlog item). "
                         L"The standalone !wnf decode <hash> subcommand still works for translating obfuscated 64-bit state names into Version/Lifetime/DataScope/PermanentData/Sequence/OwnerTag fields.";
            }
            break;
        }

        if (siloCandidates.empty())
        {
            if (error != nullptr)
            {
                *error = L"could not resolve a WNF silo pointer (tried named symbols and anchor disassembly of NtQueryWnfStateData/NtPublishWnfStateData). !wnf decode <hash> still works.";
            }
            break;
        }

        // Step 2: try to resolve the AVL table address and NameInstance layout
        // for each candidate silo. The candidate that successfully validates
        // wins. PDB resolution is preferred; otherwise heuristic offset scans
        // run against the same candidate silo.
        NameInstanceLayout layout = {};
        bool layoutFromPdb = ResolveNameInstanceLayoutFromPdb(symbols_, &layout);

        TableLocator pdbLocator = {};
        bool tableFromPdb = LocateNameSetTable(symbols_, &pdbLocator);

        SiloCandidate chosen = {};
        uint64_t chosenTableAddress = 0;
        std::wstring chosenTableSource;
        NameInstanceLayout chosenLayout = {};
        bool chosenLayoutFromPdb = false;
        bool chosen_ok = false;

        for (const SiloCandidate& cand : siloCandidates)
        {
            // Build the AVL offset candidate list for this silo. When PDB
            // provided the field name, that is the only candidate; otherwise
            // we enumerate every RTL_AVL_TABLE-shaped header inside the silo
            // and rank Wnf-named CompareRoutine entries first.
            std::vector<AvlOffsetCandidate> avlCandidates;
            if (tableFromPdb)
            {
                uint64_t tableAddr = 0;
                if (!TryAdd(cand.SiloAddress, pdbLocator.Field.Offset, &tableAddr))
                {
                    continue;
                }
                if (!LooksLikeAvlTable(device_, symbols_, tableAddr))
                {
                    continue;
                }
                AvlOffsetCandidate pdbAvl = {};
                pdbAvl.Offset = pdbLocator.Field.Offset;
                pdbAvl.WnfRelated = IsWnfRelatedAvlTable(device_, symbols_, tableAddr);
                avlCandidates.push_back(pdbAvl);
            }
            else
            {
                if (!FindAllAvlTablesInSilo(device_, symbols_, cand.SiloAddress, &avlCandidates))
                {
                    continue;
                }
            }

            bool perCandidateOk = false;
            for (const AvlOffsetCandidate& avlCand : avlCandidates)
            {
                NameInstanceLayout candidateLayout = layout;
                uint64_t tableAddress = 0;
                if (!TryAdd(cand.SiloAddress, avlCand.Offset, &tableAddress))
                {
                    continue;
                }

                std::wstring tableSource;
                if (tableFromPdb)
                {
                    tableSource = L"pdb:" + pdbLocator.TypeName + L"::" + pdbLocator.FieldName;
                }
                else
                {
                    wchar_t buf[96];
                    if (avlCand.WnfRelated && !avlCand.CompareSymbol.empty())
                    {
                        swprintf_s(buf, L"auto:silo+0x%llx(compare=%ls)",
                            static_cast<unsigned long long>(avlCand.Offset),
                            avlCand.CompareSymbol.c_str());
                    }
                    else
                    {
                        swprintf_s(buf, L"auto:silo+0x%llx",
                            static_cast<unsigned long long>(avlCand.Offset));
                    }
                    tableSource = buf;
                }

                if (!candidateLayout.HasStateName)
                {
                    uint64_t autoStateNameOffset = 0;
                    if (AutoDetectStateNameOffset(device_, cand.SiloAddress, avlCand.Offset, &autoStateNameOffset))
                    {
                        candidateLayout = NameInstanceLayout{};
                        candidateLayout.StateNameOffset = autoStateNameOffset;
                        candidateLayout.HasStateName = true;
                        candidateLayout.Source = L"auto-detect";
                    }
                }

                if (!candidateLayout.HasStateName)
                {
                    continue;
                }

                chosen = cand;
                chosenTableAddress = tableAddress;
                chosenTableSource = tableSource;
                chosenLayout = candidateLayout;
                chosenLayoutFromPdb = layoutFromPdb;
                perCandidateOk = true;
                break;
            }

            if (perCandidateOk)
            {
                chosen_ok = true;
                break;
            }
        }

        if (!chosen_ok)
        {
            if (error != nullptr)
            {
                *error = L"located a WNF silo pointer but could not resolve the AVL subscription table or _WNF_NAME_INSTANCE.StateName layout (PDB private types and offset auto-detect both unavailable).";
            }
            result->SiloStateAddress = siloCandidates.front().SiloAddress;
            result->SiloStateSymbol = siloCandidates.front().Symbol;
            result->SiloStateResolved = true;
            result->Warnings.push_back(L"!wnf decode <hash> works without kernel walking");
            break;
        }

        result->SiloStateAddress = chosen.SiloAddress;
        result->SiloStateSymbol = chosen.Symbol;
        result->SiloStateResolved = true;
        result->TableAddress = chosenTableAddress;
        result->TableTypeName = chosenTableSource;
        result->TableFieldName = chosenLayout.Source.empty() ? L"<auto>" : chosenLayout.Source;
        result->TableResolved = true;
        result->NameInstanceLayoutResolved = true;

        uint64_t tableAddress = chosenTableAddress;
        NameInstanceLayout& walkLayout = chosenLayout;
        (void)layout;
        (void)layoutFromPdb;
        (void)chosenLayoutFromPdb;

        // Step 4: walk the AVL tree
        AvlWalkContext walkCtx = {};
        walkCtx.Device = &device_;
        walkCtx.Symbols = &symbols_;
        walkCtx.Layout = &walkLayout;
        walkCtx.Records = &result->Instances;
        if (options.Target == Scope::Instance || options.Target == Scope::Data)
        {
            walkCtx.HasHashFilter = options.HasTargetHash;
            walkCtx.HashFilter = options.TargetHash;
        }

        WalkAvlTreeIterative(tableAddress, &walkCtx, result);

        // For Data scope, populate the data dump from the matched instance
        if (options.Target == Scope::Data)
        {
            if (result->Instances.empty())
            {
                if (error != nullptr)
                {
                    *error = L"no live WNF name instance matched the requested hash";
                }
                break;
            }

            const WnfInstanceRecord& match = result->Instances.front();
            result->Data.StateName = match.StateName;
            result->Data.Decoded = match.Decoded;
            result->Data.InstanceAddress = match.Address;
            result->Data.InstanceResolved = true;

            if (match.HasLastDataBlock && match.LastDataBlock != 0)
            {
                result->Data.DataBlockAddress = match.LastDataBlock;

                uint32_t copySize = match.HasDataSize ? match.DataSize : 0;
                if (copySize == 0)
                {
                    copySize = 0x40;
                }
                if (copySize > 0x100)
                {
                    copySize = 0x100;
                }

                // WNF_STATE_DATA buffer typically follows a header. Try common offsets.
                const uint64_t bufferOffsetCandidates[] = {0x10, 0x18, 0x20, 0x00};
                for (uint64_t bufferOffset : bufferOffsetCandidates)
                {
                    uint64_t bufferAddr = 0;
                    if (!TryAdd(match.LastDataBlock, bufferOffset, &bufferAddr))
                    {
                        continue;
                    }

                    std::vector<uint8_t> bytes;
                    if (ReadKernelBytes(device_, bufferAddr, copySize, &bytes, nullptr))
                    {
                        result->Data.DataBytes = std::move(bytes);
                        result->Data.DataSize = copySize;
                        result->Data.DataResolved = true;
                        break;
                    }
                }

                if (!result->Data.DataResolved)
                {
                    result->Warnings.push_back(
                        L"located WNF_STATE_DATA descriptor but could not read its payload at any standard buffer offset");
                }
            }
            else
            {
                result->Warnings.push_back(
                    L"_WNF_NAME_INSTANCE.LastDataBlock/StateData not exposed in PDB; cannot follow data pointer");
            }
        }

        ok = true;
    } while (false);

    return ok;
}
