#include "PendingIrpScanner.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <set>

namespace
{
    constexpr uint64_t kKernelMinimum = 0xffff800000000000ull;
    constexpr uint32_t kMaximumStackCount = 64;

    struct IrpLayout
    {
        uint32_t ThreadSize = 0;
        uint32_t ThreadIrpList = 0;
        uint32_t ThreadPid = 0;
        uint32_t ThreadTid = 0;
        uint32_t ThreadCreateTime = 0;
        uint32_t IrpSize = 0;
        uint32_t IrpType = 0;
        uint32_t PacketSize = 0;
        uint32_t ThreadListEntry = 0;
        uint32_t StackCount = 0;
        uint32_t CurrentLocation = 0;
        uint32_t CurrentStack = 0;
        uint32_t OwningThread = 0;
        uint32_t StackSize = 0;
        uint32_t MajorFunction = 0;
        uint32_t MinorFunction = 0;
        uint32_t Control = 0;
        uint32_t Completion = 0;
        uint32_t Context = 0;
    };

    bool KernelRange(uint64_t address, size_t bytes)
    {
        return address >= kKernelMinimum && bytes != 0 && address <= ~0ull - bytes;
    }

    bool ResolveNestedField(SymbolEngine& symbols, const TypeLayoutInfo& layout,
        const std::vector<std::wstring>& path, size_t part, uint32_t accumulated,
        uint32_t expectedSize, uint32_t* offset, uint32_t anonymousDepth = 0)
    {
        if (part >= path.size() || layout.Size == 0 || layout.Size > 0x4000)
        {
            return false;
        }
        for (const TypeFieldInfo& field : layout.Fields)
        {
            if (field.IsBitField || field.Offset > layout.Size || field.Length > layout.Size - field.Offset)
            {
                continue;
            }
            const bool named = field.Name == path[part];
            const bool anonymous = field.Name.empty() || field.Name.find(L"<unnamed") != std::wstring::npos;
            if (!named && (!anonymous || anonymousDepth >= 3))
            {
                continue;
            }
            const uint32_t nextOffset = accumulated + field.Offset;
            if (named && part + 1 == path.size())
            {
                if (field.Length == expectedSize)
                {
                    *offset = nextOffset;
                    return true;
                }
                continue;
            }
            if (field.ChildTag != KNDBG_SYMTAG_UDT || field.ChildTypeId == 0)
            {
                continue;
            }
            TypeLayoutInfo child = {};
            if (symbols.GetTypeLayoutById(field.ModuleBase, field.ChildTypeId, field.TypeName, &child, nullptr) &&
                child.Size == field.Length &&
                ResolveNestedField(symbols, child, path, named ? part + 1 : part,
                    nextOffset, expectedSize, offset, named ? 0 : anonymousDepth + 1))
            {
                return true;
            }
        }
        return false;
    }

    bool BuildIrpLayout(SymbolEngine& symbols, IrpLayout* out)
    {
        TypeLayoutInfo thread = {};
        TypeLayoutInfo irp = {};
        TypeLayoutInfo stack = {};
        if (!symbols.GetTypeLayout(L"nt!_ETHREAD", &thread, nullptr) ||
            !symbols.GetTypeLayout(L"nt!_IRP", &irp, nullptr) ||
            !symbols.GetTypeLayout(L"nt!_IO_STACK_LOCATION", &stack, nullptr) ||
            thread.Size == 0 || thread.Size > 0x4000 || irp.Size == 0 || irp.Size > 0x1000 ||
            stack.Size == 0 || stack.Size > 0x1000)
        {
            return false;
        }
        out->ThreadSize = static_cast<uint32_t>(thread.Size);
        out->IrpSize = static_cast<uint32_t>(irp.Size);
        out->StackSize = static_cast<uint32_t>(stack.Size);
        const auto field = [&](const TypeLayoutInfo& type, std::vector<std::wstring> path, uint32_t size, uint32_t* offset)
        {
            return ResolveNestedField(symbols, type, path, 0, 0, size, offset);
        };
        return field(thread, {L"IrpList"}, 16, &out->ThreadIrpList) &&
            field(thread, {L"Cid", L"UniqueProcess"}, 8, &out->ThreadPid) &&
            field(thread, {L"Cid", L"UniqueThread"}, 8, &out->ThreadTid) &&
            field(thread, {L"CreateTime"}, 8, &out->ThreadCreateTime) &&
            field(irp, {L"Type"}, 2, &out->IrpType) && field(irp, {L"Size"}, 2, &out->PacketSize) &&
            field(irp, {L"ThreadListEntry"}, 16, &out->ThreadListEntry) &&
            field(irp, {L"StackCount"}, 1, &out->StackCount) &&
            field(irp, {L"CurrentLocation"}, 1, &out->CurrentLocation) &&
            field(irp, {L"Tail", L"Overlay", L"CurrentStackLocation"}, 8, &out->CurrentStack) &&
            field(irp, {L"Tail", L"Overlay", L"Thread"}, 8, &out->OwningThread) &&
            field(stack, {L"MajorFunction"}, 1, &out->MajorFunction) &&
            field(stack, {L"MinorFunction"}, 1, &out->MinorFunction) &&
            field(stack, {L"Control"}, 1, &out->Control) &&
            field(stack, {L"CompletionRoutine"}, 8, &out->Completion) &&
            field(stack, {L"Context"}, 8, &out->Context);
    }

    template<typename T>
    bool Extract(const std::vector<uint8_t>& bytes, size_t offset, T* value)
    {
        if (offset > bytes.size() || sizeof(T) > bytes.size() - offset)
        {
            return false;
        }
        memcpy(value, bytes.data() + offset, sizeof(T));
        return true;
    }

    template<typename Reader>
    bool ReadScalar(Reader& read, uint64_t base, uint32_t offset, uint64_t* value)
    {
        std::vector<uint8_t> bytes;
        return KernelRange(base, static_cast<size_t>(offset) + 8) &&
            read(base + offset, 8, &bytes) && bytes.size() == 8 && Extract(bytes, 0, value);
    }

    template<typename Reader>
    bool WalkIrpList(Reader& read, uint64_t head, size_t maximum, std::vector<uint64_t>* nodes)
    {
        nodes->clear();
        uint64_t first = 0;
        uint64_t last = 0;
        if (!ReadScalar(read, head, 0, &first) || !ReadScalar(read, head, 8, &last))
        {
            return false;
        }
        uint64_t current = first;
        uint64_t previous = head;
        std::set<uint64_t> visited;
        while (current != head)
        {
            uint64_t next = 0;
            uint64_t back = 0;
            if ((current & 7) != 0 || nodes->size() >= maximum || !visited.insert(current).second ||
                !ReadScalar(read, current, 0, &next) || !ReadScalar(read, current, 8, &back) || back != previous)
            {
                return false;
            }
            nodes->push_back(current);
            previous = current;
            current = next;
        }
        uint64_t firstAfter = 0;
        uint64_t lastAfter = 0;
        return previous == last && ReadScalar(read, head, 0, &firstAfter) && ReadScalar(read, head, 8, &lastAfter) &&
            first == firstAfter && last == lastAfter;
    }

    template<typename Reader>
    bool CaptureIrp(Reader& read, const IrpLayout& layout, uint64_t irp,
        const PendingIrpThreadInput& thread, uint64_t createTime, std::vector<PendingIrpCompletionRecord>* records)
    {
        std::vector<uint8_t> header;
        if (!KernelRange(irp, layout.IrpSize) || !read(irp, layout.IrpSize, &header) || header.size() != layout.IrpSize)
        {
            return false;
        }
        uint16_t type = 0;
        uint16_t packetSize = 0;
        uint8_t stackCount = 0;
        uint8_t currentLocation = 0;
        uint64_t currentStack = 0;
        uint64_t owner = 0;
        if (!Extract(header, layout.IrpType, &type) || type != 6 ||
            !Extract(header, layout.PacketSize, &packetSize) ||
            !Extract(header, layout.StackCount, &stackCount) || stackCount == 0 || stackCount > kMaximumStackCount ||
            !Extract(header, layout.CurrentLocation, &currentLocation) || currentLocation == 0 || currentLocation > stackCount + 1 ||
            !Extract(header, layout.CurrentStack, &currentStack) ||
            !Extract(header, layout.OwningThread, &owner) || owner != thread.ThreadObject)
        {
            return false;
        }
        const size_t required = layout.IrpSize + static_cast<size_t>(stackCount) * layout.StackSize;
        if (required > packetSize || !KernelRange(irp, required) ||
            currentStack != irp + layout.IrpSize + static_cast<uint64_t>(currentLocation - 1) * layout.StackSize)
        {
            return false;
        }
        std::vector<uint8_t> first;
        std::vector<uint8_t> second;
        if (!read(irp, static_cast<uint32_t>(required), &first) || first.size() != required ||
            memcmp(first.data(), header.data(), header.size()) != 0 ||
            !read(irp, static_cast<uint32_t>(required), &second) || first != second)
        {
            return false;
        }
        std::vector<PendingIrpCompletionRecord> local;
        for (uint32_t index = currentLocation - 1; index < stackCount; ++index)
        {
            const size_t base = layout.IrpSize + static_cast<size_t>(index) * layout.StackSize;
            PendingIrpCompletionRecord record;
            if (!Extract(second, base + layout.Control, &record.Control) ||
                !Extract(second, base + layout.MajorFunction, &record.MajorFunction) ||
                !Extract(second, base + layout.MinorFunction, &record.MinorFunction) ||
                !Extract(second, base + layout.Completion, &record.CompletionRoutine) ||
                !Extract(second, base + layout.Context, &record.Context) || record.MajorFunction > 0x1b)
            {
                return false;
            }
            if ((record.Control & 0xe0) == 0 || record.CompletionRoutine == 0)
            {
                continue;
            }
            record.ThreadObject = thread.ThreadObject;
            record.ThreadCreateTime = createTime;
            record.ProcessId = thread.ProcessId;
            record.ThreadId = thread.ThreadId;
            record.Irp = irp;
            record.StackIndex = index;
            record.StackLocation = irp + base;
            record.CompletionSlot = record.StackLocation + layout.Completion;
            record.StableObservation = true;
            local.push_back(std::move(record));
        }
        records->insert(records->end(), local.begin(), local.end());
        return true;
    }

    template<typename Reader>
    void CollectPendingIrps(Reader& read, const IrpLayout& layout,
        std::vector<PendingIrpThreadInput> threads, const PendingIrpScanOptions& options, PendingIrpScanResult* result)
    {
        std::sort(threads.begin(), threads.end(), [](const PendingIrpThreadInput& left, const PendingIrpThreadInput& right)
        {
            return left.ThreadObject < right.ThreadObject;
        });
        const size_t threadLimit = (std::min)(options.MaxThreads == 0 ? 32u : options.MaxThreads, 128u);
        const size_t irpLimit = (std::min)(options.MaxIrps == 0 ? 64u : options.MaxIrps, 256u);
        const size_t walkLimit = (std::min)(options.MaxWalkNodes == 0 ? 4096u : options.MaxWalkNodes, 4096u);
        bool complete = options.ThreadInventoryComplete && options.Cursor.IrpAddress == 0 && threads.size() <= threadLimit;
        size_t begin = 0;
        while (begin < threads.size() && (threads[begin].ThreadObject < options.Cursor.ThreadObject ||
            (threads[begin].ThreadObject == options.Cursor.ThreadObject && options.Cursor.IrpAddress == 0)))
        {
            ++begin;
        }
        if (begin == threads.size())
        {
            begin = 0;
        }
        std::set<uint64_t> visitedThreads;
        for (size_t step = 0; step < (std::min)(threadLimit, threads.size()); ++step)
        {
            const PendingIrpThreadInput& thread = threads[(begin + step) % threads.size()];
            ++result->ThreadsVisited;
            result->NextCursor = PendingIrpCursor{thread.ThreadObject, 0, 0};
            uint64_t pid = 0;
            uint64_t tid = 0;
            uint64_t createTime = 0;
            if (thread.ProcessId == 0 || thread.ThreadId == 0 || !visitedThreads.insert(thread.ThreadObject).second ||
                !ReadScalar(read, thread.ThreadObject, layout.ThreadPid, &pid) || pid != thread.ProcessId ||
                !ReadScalar(read, thread.ThreadObject, layout.ThreadTid, &tid) || tid != thread.ThreadId ||
                !ReadScalar(read, thread.ThreadObject, layout.ThreadCreateTime, &createTime) || createTime == 0 ||
                !KernelRange(thread.ThreadObject, layout.ThreadIrpList + 16))
            {
                ++result->UnstableObservations;
                complete = false;
                continue;
            }
            result->NextCursor.ThreadCreateTime = createTime;
            const uint64_t head = thread.ThreadObject + layout.ThreadIrpList;
            auto readLink = [&](uint64_t address, uint64_t* value)
            {
                return ReadScalar(read, address, 0, value);
            };
            ScannerListCursor cursor;
            if (thread.ThreadObject == options.Cursor.ThreadObject && createTime == options.Cursor.ThreadCreateTime)
            {
                cursor = options.Cursor.List;
            }
            const size_t budget = (std::min)(walkLimit - result->WalkNodes, irpLimit - result->IrpsInspected);
            ScannerListWindow window;
            if (!ReadScannerListWindow(readLink, head, head + 8, false, budget, cursor, &window))
            {
                result->WalkNodes += static_cast<uint32_t>(window.NodesVisited);
                ++result->UnstableObservations;
                complete = false;
                if (result->WalkNodes >= walkLimit)
                {
                    break;
                }
                continue;
            }
            result->WalkNodes += static_cast<uint32_t>(window.Nodes.size());
            complete = complete && window.Complete;
            std::vector<PendingIrpCompletionRecord> local;
            for (const ScannerListNode& node : window.Nodes)
            {
                if (node.Address < layout.ThreadListEntry ||
                    !KernelRange(node.Address - layout.ThreadListEntry, layout.IrpSize))
                {
                    complete = false;
                    continue;
                }
                const uint64_t irp = node.Address - layout.ThreadListEntry;
                ++result->IrpsInspected;
                if (!CaptureIrp(read, layout, irp, thread, createTime, &local))
                {
                    ++result->UnstableObservations;
                    complete = false;
                }
            }
            uint64_t pidAfter = 0;
            uint64_t tidAfter = 0;
            uint64_t createAfter = 0;
            if (!ReadScalar(read, thread.ThreadObject, layout.ThreadPid, &pidAfter) || pidAfter != pid ||
                !ReadScalar(read, thread.ThreadObject, layout.ThreadTid, &tidAfter) || tidAfter != tid ||
                !ReadScalar(read, thread.ThreadObject, layout.ThreadCreateTime, &createAfter) || createAfter != createTime ||
                !ValidateScannerListWindow(readLink, window))
            {
                ++result->UnstableObservations;
                complete = false;
            }
            else
            {
                result->Records.insert(result->Records.end(), local.begin(), local.end());
                const bool replacedOwner = options.Cursor.IrpAddress != 0 &&
                    thread.ThreadObject == options.Cursor.ThreadObject && createTime != options.Cursor.ThreadCreateTime;
                if ((!window.Restarted && !replacedOwner) || threads.size() == 1)
                {
                    result->NextCursor.List = window.Next;
                    result->NextCursor.IrpAddress = window.Next.Entry == 0 ? 0 : window.Next.Entry - layout.ThreadListEntry;
                }
            }
            if (!window.ReachedEnd)
            {
                complete = false;
                break;
            }
            if (result->IrpsInspected >= irpLimit || result->WalkNodes >= walkLimit)
            {
                complete = complete && step + 1 == threads.size();
                break;
            }
        }
        result->CoverageComplete = complete && result->ThreadsVisited == threads.size();
    }
}

PendingIrpScanner::PendingIrpScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device), symbols_(symbols)
{
}

bool PendingIrpScanner::Scan(const std::vector<PendingIrpThreadInput>& threads,
    const PendingIrpScanOptions& options, PendingIrpScanResult* result, std::wstring* error)
{
    if (result == nullptr)
    {
        return false;
    }
    *result = PendingIrpScanResult{};
    IrpLayout layout;
    if (!BuildIrpLayout(symbols_, &layout))
    {
        if (error != nullptr)
        {
            *error = L"exact ETHREAD/IRP/IO_STACK_LOCATION PDB layout unavailable";
        }
        return false;
    }
    result->LayoutFromPdb = true;
    auto read = [&](uint64_t address, uint32_t size, std::vector<uint8_t>* bytes)
    {
        return KernelRange(address, size) && size <= 0x20000 &&
            device_.ReadMemory(address, size, bytes, nullptr) && bytes->size() == size;
    };
    CollectPendingIrps(read, layout, threads, options, result);
    const std::vector<KernelModuleInfo> modules = symbols_.Modules();
    for (PendingIrpCompletionRecord& record : result->Records)
    {
        for (const KernelModuleInfo& module : modules)
        {
            if (module.Size != 0 && record.CompletionRoutine >= module.Base &&
                record.CompletionRoutine - module.Base < module.Size)
            {
                record.Module = module.ImageName;
                break;
            }
        }
        record.Suspicious = record.Module.empty();
        uint64_t displacement = 0;
        symbols_.FindNearestSymbol(record.CompletionRoutine, &record.Symbol, &displacement, nullptr);
    }
    result->Warnings.push_back(L"equal snapshots do not reference IRP lifetime or exclude address reuse; corroboration is required");
    if (!result->CoverageComplete)
    {
        result->Warnings.push_back(L"pending IRP snapshot is partial, changed, or bounded; unobserved completion paths remain unknown");
    }
    return true;
}

bool PendingIrpScannerSelfTest()
{
    IrpLayout layout;
    layout.ThreadSize = 0x80;
    layout.ThreadPid = 0;
    layout.ThreadTid = 8;
    layout.ThreadCreateTime = 16;
    layout.ThreadIrpList = 32;
    layout.IrpSize = 0x60;
    layout.IrpType = 0;
    layout.PacketSize = 2;
    layout.StackCount = 4;
    layout.CurrentLocation = 5;
    layout.CurrentStack = 8;
    layout.OwningThread = 16;
    layout.ThreadListEntry = 32;
    layout.StackSize = 0x20;
    layout.MajorFunction = 0;
    layout.MinorFunction = 1;
    layout.Control = 2;
    layout.Completion = 8;
    layout.Context = 16;
    std::map<uint64_t, uint8_t> memory;
    const auto put = [&](uint64_t address, auto value)
    {
        const auto* data = reinterpret_cast<const uint8_t*>(&value);
        for (size_t i = 0; i < sizeof(value); ++i)
        {
            memory[address + i] = data[i];
        }
    };
    auto read = [&](uint64_t address, uint32_t size, std::vector<uint8_t>* bytes)
    {
        bytes->clear();
        for (uint32_t i = 0; i < size; ++i)
        {
            const auto found = memory.find(address + i);
            if (found == memory.end())
            {
                return false;
            }
            bytes->push_back(found->second);
        }
        return true;
    };
    const uint64_t base = 0xffff800000010000ull;
    std::vector<PendingIrpThreadInput> threads = {{base, 4, 40}, {base + 0x1000, 4, 44}};
    uint64_t lastIrp = 0;
    for (size_t threadIndex = 0; threadIndex < threads.size(); ++threadIndex)
    {
        const auto& thread = threads[threadIndex];
        put(thread.ThreadObject, static_cast<uint64_t>(thread.ProcessId));
        put(thread.ThreadObject + 8, static_cast<uint64_t>(thread.ThreadId));
        put(thread.ThreadObject + 16, static_cast<uint64_t>(100 + threadIndex));
        const uint64_t head = thread.ThreadObject + 32;
        const size_t count = threadIndex == 0 ? 4097 : 1;
        const uint64_t firstIrp = base + 0x10000 + threadIndex * 0x200000;
        put(head, firstIrp + 32);
        put(head + 8, firstIrp + (count - 1) * 0x100 + 32);
        for (size_t i = 0; i < count; ++i)
        {
            const uint64_t irp = firstIrp + i * 0x100;
            for (uint32_t byte = 0; byte < 0x80; ++byte)
            {
                memory[irp + byte] = 0;
            }
            put(irp, static_cast<uint16_t>(6));
            put(irp + 2, static_cast<uint16_t>(0x80));
            put(irp + 4, static_cast<uint8_t>(1));
            put(irp + 5, static_cast<uint8_t>(1));
            put(irp + 8, irp + 0x60);
            put(irp + 16, thread.ThreadObject);
            put(irp + 32, i + 1 == count ? head : irp + 0x120);
            put(irp + 40, i == 0 ? head : irp - 0x100 + 32);
            put(irp + 0x62, static_cast<uint8_t>(0x40));
            put(irp + 0x68, base + 0x100000);
            lastIrp = irp;
        }
    }
    PendingIrpScanOptions options;
    options.ThreadInventoryComplete = true;
    PendingIrpScanResult first;
    CollectPendingIrps(read, layout, threads, options, &first);
    if (first.Records.size() != 64 || first.CoverageComplete || first.NextCursor.ThreadObject != base ||
        first.NextCursor.IrpAddress == 0)
    {
        return false;
    }
    PendingIrpScanResult second;
    std::set<uint64_t> observed;
    for (const auto& record : first.Records)
    {
        observed.insert(record.Irp);
    }
    options.Cursor = first.NextCursor;
    for (size_t pass = 0; pass < 65; ++pass)
    {
        second = {};
        CollectPendingIrps(read, layout, threads, options, &second);
        if (second.UnstableObservations != 0 || second.WalkNodes > options.MaxIrps || second.IrpsInspected > options.MaxIrps)
        {
            return false;
        }
        for (const auto& record : second.Records)
        {
            observed.insert(record.Irp);
        }
        options.Cursor = second.NextCursor;
        if (observed.size() == 4098)
        {
            break;
        }
    }
    if (observed.size() != 4098 || observed.find(lastIrp) == observed.end())
    {
        return false;
    }
    auto scalarRead = [&](uint64_t address, uint64_t* value)
    {
        return ReadScalar(read, address, 0, value);
    };
    auto scalarWrite = [&](uint64_t address, uint64_t value)
    {
        put(address, value);
    };
    if (!ScannerListWindowFixture(scalarRead, scalarWrite, base + 0x400000))
    {
        return false;
    }
    // Repeated unlink of the first owner's inner anchor must leave later threads reachable.
    PendingIrpScanOptions churnOptions;
    churnOptions.ThreadInventoryComplete = true;
    size_t laterOwnerObservations = 0;
    for (size_t pass = 0; pass < 9; ++pass)
    {
        const bool removed = churnOptions.Cursor.ThreadObject == base && churnOptions.Cursor.List.Entry != 0;
        if (removed)
        {
            const uint64_t anchor = churnOptions.Cursor.List.Entry;
            uint64_t next = 0;
            uint64_t previous = 0;
            if (!scalarRead(anchor, &next) || !scalarRead(anchor + 8, &previous))
            {
                return false;
            }
            put(previous, next);
            put(next + 8, previous);
            put(anchor, anchor);
            put(anchor + 8, anchor);
        }
        PendingIrpScanResult churn;
        CollectPendingIrps(read, layout, threads, churnOptions, &churn);
        if (churn.CoverageComplete || churn.WalkNodes > churnOptions.MaxIrps ||
            churn.IrpsInspected > churnOptions.MaxIrps ||
            (removed && (churn.NextCursor.ThreadObject != base || churn.NextCursor.IrpAddress != 0 ||
                churn.NextCursor.List.Entry != 0)))
        {
            return false;
        }
        for (const PendingIrpCompletionRecord& record : churn.Records)
        {
            laterOwnerObservations += record.ThreadObject == threads[1].ThreadObject ? 1 : 0;
        }
        churnOptions.Cursor = churn.NextCursor;
    }
    if (laterOwnerObservations < 4)
    {
        return false;
    }
    // A reused ETHREAD invalidates its saved internal list cursor.
    options.Cursor = first.NextCursor;
    put(base + 16, static_cast<uint64_t>(999));
    PendingIrpScanResult replacement;
    CollectPendingIrps(read, layout, threads, options, &replacement);
    if (replacement.Records.empty() || replacement.Records.front().Irp != first.Records.front().Irp ||
        replacement.Records.front().ThreadCreateTime != 999 || replacement.NextCursor.IrpAddress != 0 ||
        replacement.NextCursor.List.Entry != 0)
    {
        return false;
    }
    PendingIrpScanOptions afterReplacementOptions = options;
    afterReplacementOptions.Cursor = replacement.NextCursor;
    PendingIrpScanResult afterReplacement;
    CollectPendingIrps(read, layout, threads, afterReplacementOptions, &afterReplacement);
    if (afterReplacement.Records.empty() || afterReplacement.Records.front().ThreadObject != threads[1].ThreadObject)
    {
        return false;
    }
    put(base + 16, static_cast<uint64_t>(100));
    std::vector<PendingIrpCompletionRecord> records;
    put(lastIrp + 5, static_cast<uint8_t>(0));
    if (CaptureIrp(read, layout, lastIrp, threads[1], 101, &records))
    {
        return false;
    }
    put(lastIrp + 5, static_cast<uint8_t>(1));
    put(lastIrp + 8, lastIrp + 0x68);
    if (CaptureIrp(read, layout, lastIrp, threads[1], 101, &records))
    {
        return false;
    }
    put(lastIrp + 8, lastIrp + 0x60);
    size_t reads = 0;
    auto changing = [&](uint64_t address, uint32_t size, std::vector<uint8_t>* bytes)
    {
        if (!read(address, size, bytes))
        {
            return false;
        }
        if (address == lastIrp && ++reads == 3)
        {
            (*bytes)[0x68] ^= 1;
        }
        return true;
    };
    return !CaptureIrp(changing, layout, lastIrp, threads[1], 101, &records) && records.empty();
}
