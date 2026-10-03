#include "DpcTimerScanner.h"

#include "McpJson.h"

#include <Windows.h>
#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <sstream>

namespace
{
    constexpr uint64_t kKernelSpaceMin = 0xffff800000000000ull;
    constexpr uint32_t kMaxDpcRecords = 4096;
    constexpr uint32_t kMaxTimerRecords = 8192;
    constexpr uint32_t kMaxListWalk = 512;
    constexpr uint32_t kMaxTimerBuckets = 512;

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelSpaceMin;
    }

    bool ReadU64(DeviceClient& device, uint64_t address, uint64_t* value)
    {
        if (value == nullptr || !IsKernelAddress(address) || address > ~0ull - sizeof(uint64_t))
        {
            return false;
        }
        std::vector<uint8_t> bytes;
        if (!device.ReadMemory(address, sizeof(uint64_t), &bytes, nullptr) ||
            bytes.size() != sizeof(uint64_t))
        {
            return false;
        }
        memcpy(value, bytes.data(), sizeof(uint64_t));
        return true;
    }

    std::wstring FindOwningModule(SymbolEngine& symbols, uint64_t address)
    {
        for (const KernelModuleInfo& module : symbols.Modules())
        {
            uint64_t end = module.Base + module.Size;
            if (end < module.Base)
            {
                continue;
            }
            if (address >= module.Base && address < end)
            {
                return module.ImageName;
            }
        }
        return std::wstring();
    }

    std::wstring NearestSymbolText(SymbolEngine& symbols, uint64_t address)
    {
        std::wstring nearest;
        uint64_t displacement = 0;
        std::wstring ignored;
        if (!symbols.FindNearestSymbol(address, &nearest, &displacement, &ignored))
        {
            return std::wstring();
        }
        std::wstringstream stream;
        stream << nearest;
        if (displacement != 0)
        {
            stream << L"+0x" << std::hex << displacement;
        }
        return stream.str();
    }

    std::wstring JsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }

    void ClassifyRoutine(
        SymbolEngine& symbols,
        uint64_t routine,
        std::wstring* module,
        std::wstring* symbol,
        bool* suspicious,
        std::wstring* notes)
    {
        if (module != nullptr)
        {
            *module = FindOwningModule(symbols, routine);
        }
        if (symbol != nullptr)
        {
            *symbol = NearestSymbolText(symbols, routine);
        }
        if (suspicious != nullptr)
        {
            *suspicious = false;
        }
        if (notes != nullptr)
        {
            notes->clear();
        }

        if (routine == 0)
        {
            return;
        }
        if (!IsKernelAddress(routine) || (module != nullptr && module->empty()))
        {
            if (suspicious != nullptr)
            {
                *suspicious = true;
            }
            if (notes != nullptr)
            {
                *notes = L"callback routine outside loaded kernel modules";
            }
        }
    }

    bool ResolvePrcbArray(SymbolEngine& symbols, uint64_t* arrayBase, uint32_t* count, std::wstring* symbolName)
    {
        const std::wstring candidates[] =
        {
            L"nt!KiProcessorBlock",
            L"nt!KeProcessorBlock",
            L"nt!KiProcessorBlocks"
        };

        for (const std::wstring& name : candidates)
        {
            uint64_t base = 0;
            if (symbols.ResolveSymbol(name, &base, nullptr) && base != 0 && IsKernelAddress(base))
            {
                *arrayBase = base;
                *symbolName = name;
                // Active processor count from usermode as a soft bound.
                DWORD active = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
                if (active == 0)
                {
                    active = 1;
                }
                *count = active;
                return true;
            }
        }
        return false;
    }

    bool FieldFits(const TypeFieldInfo& field, uint64_t containerSize, uint64_t size)
    {
        return size != 0 && field.Length >= size &&
            field.Offset <= containerSize && size <= containerSize - field.Offset;
    }

    struct DeferredPointerRecord
    {
        uint64_t Object = 0;
        uint64_t Dpc = 0;
        uint64_t Function = 0;
    };

    template<typename Reader>
    bool CollectDeferredListWindow(Reader& read, uint64_t head, uint64_t tail, bool singlyLinked,
        uint32_t listOffset, uint32_t routineOffset, bool timer, uint32_t timerDpcOffset,
        size_t budget, const ScannerListCursor& cursor, ScannerListWindow* window,
        std::vector<DeferredPointerRecord>* records, bool* fieldsComplete)
    {
        records->clear();
        *fieldsComplete = true;
        if (!ReadScannerListWindow(read, head, tail, singlyLinked, budget, cursor, window))
        {
            return false;
        }
        for (const ScannerListNode& node : window->Nodes)
        {
            DeferredPointerRecord record;
            if (node.Address < listOffset || !IsKernelAddress(node.Address - listOffset))
            {
                *fieldsComplete = false;
                continue;
            }
            record.Object = node.Address - listOffset;
            record.Dpc = record.Object;
            if (timer && (record.Object > ~0ull - timerDpcOffset ||
                !read(record.Object + timerDpcOffset, &record.Dpc)))
            {
                *fieldsComplete = false;
                continue;
            }
            if (record.Dpc == 0)
            {
                continue;
            }
            uint64_t functionAfter = 0;
            uint64_t dpcAfter = record.Dpc;
            if (!IsKernelAddress(record.Dpc) || record.Dpc > ~0ull - routineOffset ||
                !read(record.Dpc + routineOffset, &record.Function) ||
                !read(record.Dpc + routineOffset, &functionAfter) || functionAfter != record.Function ||
                (timer && (!read(record.Object + timerDpcOffset, &dpcAfter) || dpcAfter != record.Dpc)))
            {
                *fieldsComplete = false;
                continue;
            }
            if (record.Function != 0)
            {
                records->push_back(record);
            }
        }
        if (!ValidateScannerListWindow(read, *window))
        {
            records->clear();
            return false;
        }
        return true;
    }

    DeferredQueueCursor AdvanceDeferredQueue(uint64_t root, uint32_t index, uint32_t count,
        const ScannerListWindow* window)
    {
        DeferredQueueCursor next;
        next.RootAddress = root;
        const bool resume = window != nullptr && !window->ReachedEnd && (!window->Restarted || count == 1);
        next.QueueIndex = resume ? index : (index + 1) % count;
        if (resume)
        {
            next.List = window->Next;
        }
        return next;
    }

    struct WorkItemQueueDescriptor
    {
        uint64_t QueueAddress = 0;
        uint64_t HeadAddress = 0;
    };

    template<typename Reader>
    bool CollectWorkItemListWindow(
        Reader& read,
        const WorkItemQueueDescriptor& queue,
        uint32_t listOffset,
        uint32_t routineOffset,
        uint32_t parameterOffset,
        size_t limit,
        const ScannerListCursor& cursor,
        ScannerListWindow* window,
        std::vector<WorkItemRecord>* records,
        bool* fieldsComplete)
    {
        records->clear();
        *fieldsComplete = true;
        if (!ReadScannerListWindow(read, queue.HeadAddress, queue.HeadAddress + 8,
                false, limit, cursor, window))
        {
            return false;
        }
        for (const ScannerListNode& node : window->Nodes)
        {
            WorkItemRecord record;
            if (node.Address < listOffset || !IsKernelAddress(node.Address - listOffset))
            {
                *fieldsComplete = false;
                continue;
            }
            record.EntryAddress = node.Address - listOffset;
            record.QueueAddress = queue.QueueAddress;
            uint64_t routineAfter = 0;
            uint64_t parameterAfter = 0;
            if (record.EntryAddress > ~0ull - routineOffset ||
                record.EntryAddress > ~0ull - parameterOffset ||
                !read(record.EntryAddress + routineOffset, &record.Routine) ||
                !read(record.EntryAddress + parameterOffset, &record.Parameter) ||
                !read(record.EntryAddress + routineOffset, &routineAfter) ||
                !read(record.EntryAddress + parameterOffset, &parameterAfter) ||
                routineAfter != record.Routine || parameterAfter != record.Parameter || record.Routine == 0)
            {
                *fieldsComplete = false;
                continue;
            }
            records->push_back(std::move(record));
        }
        if (!ValidateScannerListWindow(read, *window))
        {
            records->clear();
            return false;
        }
        return true;
    }

    template<typename Reader>
    void CollectWorkItemWindows(
        Reader& read,
        std::vector<WorkItemQueueDescriptor> queues,
        uint32_t listOffset,
        uint32_t routineOffset,
        uint32_t parameterOffset,
        size_t limit,
        bool inventoryComplete,
        const DeferredQueueCursor& cursor,
        DpcTimerScanResult* result)
    {
        std::sort(queues.begin(), queues.end(), [](const auto& left, const auto& right)
        {
            return left.HeadAddress < right.HeadAddress;
        });
        queues.erase(std::unique(queues.begin(), queues.end(), [](const auto& left, const auto& right)
        {
            return left.HeadAddress == right.HeadAddress;
        }), queues.end());
        if (queues.empty() || limit == 0)
        {
            return;
        }

        // RootAddress names the next queue head, not an index in a changing array.
        // A removed head resumes at its successor in the current root inventory.
        auto firstQueue = std::lower_bound(queues.begin(), queues.end(), cursor.RootAddress,
            [](const WorkItemQueueDescriptor& queue, uint64_t head)
        {
            return queue.HeadAddress < head;
        });
        if (firstQueue == queues.end())
        {
            firstQueue = queues.begin();
        }
        const size_t first = static_cast<size_t>(firstQueue - queues.begin());
        const size_t queueBudget = (std::min)(queues.size(), size_t(32));
        size_t remaining = (std::min)(limit, size_t(kMaxDpcRecords));
        bool complete = inventoryComplete && cursor.List.Entry == 0 && queueBudget == queues.size();
        for (size_t offset = 0; offset < queueBudget && remaining != 0; ++offset)
        {
            const size_t index = (first + offset) % queues.size();
            const WorkItemQueueDescriptor& queue = queues[index];
            result->NextWorkItemCursor = {queues[(index + 1) % queues.size()].HeadAddress, 0, {}};
            ++result->WorkItemQueuesVisited;
            const ScannerListCursor listCursor = offset == 0 && cursor.RootAddress == queue.HeadAddress ?
                cursor.List : ScannerListCursor{};
            ScannerListWindow window;
            std::vector<WorkItemRecord> records;
            bool fieldsComplete = false;
            const bool stable = CollectWorkItemListWindow(read, queue, listOffset, routineOffset,
                parameterOffset, remaining, listCursor, &window, &records, &fieldsComplete);
            const size_t consumed = (std::min)(remaining, window.NodesVisited);
            remaining -= consumed;
            result->WorkItemNodesVisited += static_cast<uint32_t>(consumed);
            complete = complete && stable && fieldsComplete && window.Complete;
            if (!stable)
            {
                continue;
            }
            for (WorkItemRecord& record : records)
            {
                record.Index = static_cast<uint32_t>(result->WorkItems.size());
                result->WorkItems.push_back(std::move(record));
            }
            if (!window.ReachedEnd)
            {
                // A repeatedly removed anchor must not pin every pass to this queue.
                if (!window.Restarted || queues.size() == 1)
                {
                    result->NextWorkItemCursor = {queue.HeadAddress, 0, window.Next};
                }
                break;
            }
        }
        result->WorkItemCoverageComplete = complete && result->WorkItemQueuesVisited == queues.size();
    }

    void CollectWorkItems(
        DeviceClient& device,
        SymbolEngine& symbols,
        const DpcTimerScanner::Options& options,
        DpcTimerScanResult* result)
    {
        result->WorkItemAttempted = true;
        TypeLayoutInfo queueLayout = {};
        TypeLayoutInfo kqueueLayout = {};
        TypeLayoutInfo itemLayout = {};
        TypeFieldInfo queueField = {};
        TypeFieldInfo headField = {};
        TypeFieldInfo listField = {};
        TypeFieldInfo routineField = {};
        TypeFieldInfo parameterField = {};
        const auto exactField = [](const TypeFieldInfo& field, uint64_t size, uint64_t bytes)
        {
            return !field.IsBitField && field.Length == bytes && FieldFits(field, size, bytes);
        };
        if (!symbols.GetTypeLayout(L"nt!_EX_WORK_QUEUE", &queueLayout, nullptr) ||
            !symbols.GetTypeLayout(L"nt!_KQUEUE", &kqueueLayout, nullptr) ||
            !symbols.GetTypeLayout(L"nt!_WORK_QUEUE_ITEM", &itemLayout, nullptr) ||
            queueLayout.Size == 0 || queueLayout.Size > 0x1000 ||
            kqueueLayout.Size == 0 || kqueueLayout.Size > 0x1000 ||
            itemLayout.Size == 0 || itemLayout.Size > 0x1000 ||
            !symbols.FindField(L"nt!_EX_WORK_QUEUE", L"Queue", &queueField, nullptr) ||
            !symbols.FindField(L"nt!_KQUEUE", L"EntryListHead", &headField, nullptr) ||
            !symbols.FindField(L"nt!_WORK_QUEUE_ITEM", L"List", &listField, nullptr) ||
            !symbols.FindField(L"nt!_WORK_QUEUE_ITEM", L"WorkerRoutine", &routineField, nullptr) ||
            !symbols.FindField(L"nt!_WORK_QUEUE_ITEM", L"Parameter", &parameterField, nullptr) ||
            !exactField(queueField, queueLayout.Size, kqueueLayout.Size) ||
            !exactField(headField, kqueueLayout.Size, 16) ||
            !exactField(listField, itemLayout.Size, 16) ||
            !exactField(routineField, itemLayout.Size, 8) ||
            !exactField(parameterField, itemLayout.Size, 8))
        {
            result->Warnings.push_back(L"exact PDB executive work-queue layout unavailable");
            return;
        }
        result->WorkItemLayoutFromPdb = true;
        std::vector<SymbolMatchInfo> roots;
        const wchar_t* rootNames[] = {L"nt!ExWorkerQueue", L"nt!ExWorkerQueues"};
        for (const wchar_t* name : rootNames)
        {
            std::vector<SymbolMatchInfo> matches;
            if (symbols.EnumerateSymbols(name, 2, &matches, nullptr))
            {
                roots.insert(roots.end(), matches.begin(), matches.end());
            }
        }
        std::set<uint64_t> visitedRoots;
        std::vector<WorkItemQueueDescriptor> queues;
        bool complete = true;
        for (const SymbolMatchInfo& root : roots)
        {
            if (!IsKernelAddress(root.Address) || root.Size == 0 ||
                root.Size % queueLayout.Size != 0 || root.Size / queueLayout.Size > 16 ||
                root.Address > ~0ull - root.Size)
            {
                complete = false;
                continue;
            }
            if (!visitedRoots.insert(root.Address).second)
            {
                continue;
            }
            if (!result->WorkItemCoverageScope.empty())
            {
                result->WorkItemCoverageScope += L",";
            }
            result->WorkItemCoverageScope += root.Name;
            for (uint64_t offset = 0; offset < root.Size; offset += queueLayout.Size)
            {
                const uint64_t queue = root.Address + offset;
                const uint64_t head = queue + queueField.Offset + headField.Offset;
                queues.push_back({queue, head});
            }
        }
        auto read = [&](uint64_t address, uint64_t* value)
        {
            return ReadU64(device, address, value);
        };
        const size_t limit = options.Limit == 0 ? kMaxDpcRecords : (std::min)(options.Limit, kMaxDpcRecords);
        CollectWorkItemWindows(read, std::move(queues), listField.Offset, routineField.Offset,
            parameterField.Offset, limit, complete, options.WorkItemCursor, result);
        if (!result->WorkItemCoverageComplete)
        {
            result->Warnings.push_back(L"executive work-queue inventory unavailable, changed, or bounded; coverage incomplete");
        }
        result->Warnings.push_back(L"work-item coverage is limited to named PDB executive queues; running workers and other pools are not enumerated");
        result->Warnings.push_back(L"work-item queue windows are repeated observations, not a referenced object snapshot; interior splice/ABA remains possible");
        for (WorkItemRecord& record : result->WorkItems)
        {
            ClassifyRoutine(symbols, record.Routine, &record.Module, &record.Symbol,
                &record.Suspicious, &record.Notes);
            if (record.Suspicious)
            {
                ++result->SuspiciousWorkItemCount;
                result->AnySuspicious = true;
            }
        }
    }

    template<typename Reader, typename Visitor>
    bool WalkSingleDpcQueue(
        Reader& read,
        Visitor& visit,
        uint64_t headAddress,
        uint64_t tailAddress,
        uint32_t entryOffset,
        uint32_t routineOffset,
        uint32_t limit)
    {
        bool complete = false;
        do
        {
            uint64_t first = 0;
            uint64_t last = 0;
            if (!read(headAddress, &first) || !read(tailAddress, &last))
            {
                break;
            }
            if (first == 0)
            {
                complete = last == headAddress;
                break;
            }
            std::set<uint64_t> visited;
            uint64_t current = first;
            uint64_t previous = headAddress;
            while (current != 0 && visited.size() < (std::min)(limit, kMaxListWalk))
            {
                if (!IsKernelAddress(current) || current < entryOffset ||
                    !visited.insert(current).second)
                {
                    break;
                }
                const uint64_t objectAddress = current - entryOffset;
                if (objectAddress > ~0ull - routineOffset)
                {
                    break;
                }
                uint64_t next = 0;
                uint64_t routine = 0;
                if (!read(current, &next) ||
                    !read(objectAddress + routineOffset, &routine))
                {
                    break;
                }
                if (next != 0 && !IsKernelAddress(next))
                {
                    break;
                }
                visit(objectAddress, routine);
                previous = current;
                current = next;
            }
            if (current != 0 || previous != last)
            {
                break;
            }
            // This is a lock-free observation. A changed head or tail is a
            // coverage gap, never evidence that a callback was removed.
            uint64_t firstAfter = 0;
            uint64_t lastAfter = 0;
            complete = read(headAddress, &firstAfter) &&
                read(tailAddress, &lastAfter) && firstAfter == first && lastAfter == last;
        } while (false);
        return complete;
    }

    bool WalkModernDpcRoutines(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t headAddress,
        uint64_t tailAddress,
        uint32_t processor,
        const std::wstring& source,
        uint32_t routineOffset,
        uint32_t entryOffset,
        uint32_t limit,
        DpcTimerScanResult* result)
    {
        if (result == nullptr || result->Dpcs.size() >= limit)
        {
            return false;
        }
        auto read = [&](uint64_t address, uint64_t* value)
        {
            return ReadU64(device, address, value);
        };
        auto visit = [&](uint64_t objectAddress, uint64_t routine)
        {
            DpcRoutineRecord record = {};
            record.Index = static_cast<uint32_t>(result->Dpcs.size());
            record.Processor = processor;
            record.Source = source;
            record.ObjectAddress = objectAddress;
            record.Routine = routine;
            ClassifyRoutine(symbols, routine, &record.Module, &record.Symbol,
                &record.Suspicious, &record.Notes);
            if (record.Suspicious)
            {
                ++result->SuspiciousDpcCount;
                result->AnySuspicious = true;
            }
            result->Dpcs.push_back(record);
        };
        return WalkSingleDpcQueue(read, visit, headAddress, tailAddress,
            entryOffset, routineOffset, limit - static_cast<uint32_t>(result->Dpcs.size()));
    }

    bool WalkListForDpcRoutines(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t listHead,
        uint32_t processor,
        const std::wstring& source,
        uint32_t deferredRoutineOffset,
        uint32_t dpcObjectOffsetFromList,
        uint32_t limit,
        DpcTimerScanResult* result)
    {
        if (result == nullptr ||
            listHead == 0 ||
            !IsKernelAddress(listHead) ||
            result->Dpcs.size() >= limit)
        {
            return false;
        }

        uint64_t flink = 0;
        uint64_t blink = 0;
        if (!ReadU64(device, listHead, &flink) ||
            !ReadU64(device, listHead + sizeof(uint64_t), &blink) ||
            flink == 0 ||
            blink == 0)
        {
            return false;
        }
        if (flink == listHead)
        {
            return blink == listHead;
        }

        std::set<uint64_t> visited;
        uint64_t entry = flink;
        uint64_t previous = listHead;
        uint32_t walked = 0;
        while (entry != 0 && entry != listHead && walked < kMaxListWalk)
        {
            if (visited.find(entry) != visited.end())
            {
                return false;
            }
            visited.insert(entry);
            if (!IsKernelAddress(entry))
            {
                return false;
            }

            uint64_t next = 0;
            uint64_t previousLink = 0;
            if (!ReadU64(device, entry, &next) ||
                !ReadU64(device, entry + sizeof(uint64_t), &previousLink) ||
                previousLink != previous ||
                next == 0 ||
                (next != listHead && !IsKernelAddress(next)))
            {
                return false;
            }
            uint64_t nextBacklink = 0;
            if (!ReadU64(
                    device,
                    next + sizeof(uint64_t),
                    &nextBacklink) ||
                nextBacklink != entry)
            {
                return false;
            }

            uint64_t objectAddress = entry;
            if (dpcObjectOffsetFromList != 0 && entry >= dpcObjectOffsetFromList)
            {
                objectAddress = entry - dpcObjectOffsetFromList;
            }

            uint64_t routine = 0;
            if (!ReadU64(device, objectAddress + deferredRoutineOffset, &routine))
            {
                return false;
            }
            if (routine != 0)
            {
                DpcRoutineRecord record = {};
                record.Index = static_cast<uint32_t>(result->Dpcs.size());
                record.Processor = processor;
                record.Source = source;
                record.ObjectAddress = objectAddress;
                record.Routine = routine;
                ClassifyRoutine(
                    symbols,
                    routine,
                    &record.Module,
                    &record.Symbol,
                    &record.Suspicious,
                    &record.Notes);
                if (record.Suspicious)
                {
                    ++result->SuspiciousDpcCount;
                    result->AnySuspicious = true;
                }
                result->Dpcs.push_back(record);
                if (result->Dpcs.size() >= limit)
                {
                    return next == listHead;
                }
            }

            previous = entry;
            entry = next;
            ++walked;
        }

        return entry == listHead;
    }

    bool ResolveExactSymbolSize(
        SymbolEngine& symbols,
        const std::wstring& name,
        uint64_t address,
        uint32_t* size)
    {
        if (size == nullptr)
        {
            return false;
        }
        *size = 0;

        std::vector<SymbolMatchInfo> matches;
        if (!symbols.EnumerateSymbols(name, 8, &matches, nullptr))
        {
            return false;
        }
        for (const SymbolMatchInfo& match : matches)
        {
            if (match.Address == address && match.Size != 0)
            {
                *size = match.Size;
                return true;
            }
        }
        return false;
    }
}

DpcTimerScanner::DpcTimerScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool DpcTimerScanner::Scan(const Options& options, DpcTimerScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid dpc/timer scan result output";
            }
            break;
        }

        *result = DpcTimerScanResult{};

        if (symbols_.Modules().empty())
        {
            std::wstring loadError;
            if (!symbols_.LoadKernelModules(&loadError))
            {
                if (error != nullptr)
                {
                    *error = L"could not load kernel modules: " + loadError;
                }
                break;
            }
        }

        TypeFieldInfo deferredRoutine = {};
        TypeFieldInfo dpcListEntry = {};
        TypeFieldInfo timerDpc = {};
        TypeFieldInfo timerListEntry = {};
        TypeLayoutInfo dpcObjectLayout = {};
        TypeLayoutInfo timerObjectLayout = {};
        std::wstring ignored;
        const bool dpcObjectLayoutFromPdb =
            symbols_.GetTypeLayout(L"nt!_KDPC", &dpcObjectLayout, &ignored) &&
            dpcObjectLayout.Size != 0 && dpcObjectLayout.Size <= 0x1000 &&
            symbols_.FindField(
                L"nt!_KDPC",
                L"DeferredRoutine",
                &deferredRoutine,
                &ignored) &&
            symbols_.FindField(
                L"nt!_KDPC",
                L"DpcListEntry",
                &dpcListEntry,
                &ignored) &&
            !deferredRoutine.IsBitField && deferredRoutine.Length == 8 &&
            FieldFits(deferredRoutine, dpcObjectLayout.Size, 8) && !dpcListEntry.IsBitField &&
            (dpcListEntry.Length == 8 || dpcListEntry.Length == 16) &&
            FieldFits(dpcListEntry, dpcObjectLayout.Size, dpcListEntry.Length);
        const bool timerObjectLayoutFromPdb =
            symbols_.GetTypeLayout(L"nt!_KTIMER", &timerObjectLayout, &ignored) &&
            timerObjectLayout.Size != 0 && timerObjectLayout.Size <= 0x1000 &&
            symbols_.FindField(L"nt!_KTIMER", L"Dpc", &timerDpc, &ignored) &&
            symbols_.FindField(
                L"nt!_KTIMER",
                L"TimerListEntry",
                &timerListEntry,
                &ignored) && !timerDpc.IsBitField && timerDpc.Length == 8 &&
            FieldFits(timerDpc, timerObjectLayout.Size, 8) && !timerListEntry.IsBitField &&
            timerListEntry.Length == 16 && FieldFits(timerListEntry, timerObjectLayout.Size, 16);

        const uint32_t dpcLimit = options.Limit == 0
            ? kMaxDpcRecords
            : (std::min)(options.Limit, kMaxDpcRecords);
        const uint32_t timerLimit = options.Limit == 0
            ? kMaxTimerRecords
            : (std::min)(options.Limit, kMaxTimerRecords);

        // ---- DPC path: per-PRCB list heads when available ----
        if (options.Target == Scope::Dpc || options.Target == Scope::All)
        {
            uint64_t prcbArray = 0;
            uint32_t processorCount = 0;
            std::wstring prcbSymbol;
            TypeFieldInfo dpcDataField = {};
            TypeFieldInfo dpcListHeadField = {};
            TypeFieldInfo dpcListField = {};
            TypeFieldInfo dpcLastEntryField = {};
            TypeLayoutInfo dpcDataLayout = {};
            TypeLayoutInfo dpcListLayout = {};
            const bool dpcDataLayoutFromPdb =
                dpcObjectLayoutFromPdb &&
                symbols_.FindField(
                    L"nt!_KPRCB",
                    L"DpcData",
                    &dpcDataField,
                    &ignored) &&
                symbols_.GetTypeLayout(
                    L"nt!_KDPC_DATA",
                    &dpcDataLayout,
                    &ignored) &&
                dpcDataLayout.Size >= sizeof(uint64_t) * 2 &&
                dpcDataLayout.Size <= 0x1000;
            const bool modernDpcList = dpcDataLayoutFromPdb &&
                symbols_.FindField(L"nt!_KDPC_DATA", L"DpcList", &dpcListField, &ignored) &&
                symbols_.GetTypeLayout(L"nt!_KDPC_LIST", &dpcListLayout, &ignored) &&
                symbols_.FindField(L"nt!_KDPC_LIST", L"ListHead", &dpcListHeadField, &ignored) &&
                symbols_.FindField(L"nt!_KDPC_LIST", L"LastEntry", &dpcLastEntryField, &ignored) &&
                FieldFits(dpcListField, dpcDataLayout.Size, dpcListLayout.Size) &&
                FieldFits(dpcListHeadField, dpcListLayout.Size, sizeof(uint64_t)) &&
                FieldFits(dpcLastEntryField, dpcListLayout.Size, sizeof(uint64_t)) &&
                dpcListEntry.Length == sizeof(uint64_t);
            const bool legacyDpcList = !modernDpcList && dpcDataLayoutFromPdb &&
                symbols_.FindField(L"nt!_KDPC_DATA", L"DpcListHead", &dpcListHeadField, &ignored) &&
                FieldFits(dpcListHeadField, dpcDataLayout.Size, sizeof(uint64_t) * 2) &&
                dpcListEntry.Length == sizeof(uint64_t) * 2;
            const bool dpcQueueLayoutFromPdb = modernDpcList || legacyDpcList;

            uint32_t dpcDataCount = 0;
            if (dpcQueueLayoutFromPdb)
            {
                dpcDataCount = static_cast<uint32_t>(
                    dpcDataField.Length / dpcDataLayout.Size);
                if (dpcDataCount == 0 || dpcDataCount > 4 ||
                    dpcDataField.Length % dpcDataLayout.Size != 0)
                {
                    dpcDataCount = 0;
                }
            }

            if (!dpcQueueLayoutFromPdb || dpcDataCount == 0)
            {
                result->Warnings.push_back(
                    L"PDB DPC queue layout unavailable; heuristic PRCB probing disabled");
                result->DpcCoverageComplete = false;
            }
            else if (!ResolvePrcbArray(
                         symbols_,
                         &prcbArray,
                         &processorCount,
                         &prcbSymbol))
            {
                result->Warnings.push_back(
                    L"KiProcessorBlock not resolved; DPC per-CPU queues unavailable");
                result->DpcCoverageComplete = false;
            }
            else
            {
                bool coverageComplete = true;
                if (processorCount > 256)
                {
                    processorCount = 256;
                    coverageComplete = false;
                    result->Warnings.push_back(L"processor safety limit truncated DPC coverage");
                }
                if (options.MaxProcessors != 0 && processorCount > options.MaxProcessors)
                {
                    processorCount = options.MaxProcessors;
                    coverageComplete = false;
                    result->Warnings.push_back(
                        L"processor limit truncated DPC coverage");
                }
                result->Warnings.push_back(L"PRCB array via " + prcbSymbol);

                const uint32_t queueCount = processorCount * dpcDataCount;
                const uint32_t firstQueue = options.DpcCursor.RootAddress == prcbArray
                    ? options.DpcCursor.QueueIndex % queueCount : 0;
                const uint32_t queueBudget = (std::min)(queueCount, 32u);
                size_t nodesRemaining = (std::min)(dpcLimit, 4096u);
                coverageComplete = coverageComplete && options.DpcCursor.List.Entry == 0 && queueBudget == queueCount;
                auto read = [&](uint64_t address, uint64_t* value)
                {
                    return ReadU64(device_, address, value);
                };
                for (uint32_t step = 0; step < queueBudget && nodesRemaining != 0; ++step)
                {
                    const uint32_t queue = (firstQueue + step) % queueCount;
                    const uint32_t cpu = queue / dpcDataCount;
                    const uint32_t dataIndex = queue % dpcDataCount;
                    result->NextDpcCursor = AdvanceDeferredQueue(prcbArray, queue, queueCount, nullptr);
                    uint64_t prcbPtr = 0;
                    if (!ReadU64(device_, prcbArray + static_cast<uint64_t>(cpu) * 8, &prcbPtr) ||
                        !IsKernelAddress(prcbPtr) || prcbPtr > ~0ull - dpcDataField.Offset - dpcDataField.Length)
                    {
                        coverageComplete = false;
                        continue;
                    }
                    ++result->ProcessorsSampled;
                    const uint64_t dataAddress = prcbPtr + dpcDataField.Offset +
                        static_cast<uint64_t>(dataIndex) * dpcDataLayout.Size;
                    const uint64_t listHead = dataAddress + (modernDpcList ? dpcListField.Offset : 0) + dpcListHeadField.Offset;
                    const uint64_t tail = modernDpcList
                        ? dataAddress + dpcListField.Offset + dpcLastEntryField.Offset : listHead + 8;
                    const ScannerListCursor cursor = step == 0 && options.DpcCursor.RootAddress == prcbArray
                        ? options.DpcCursor.List : ScannerListCursor{};
                    ScannerListWindow window;
                    std::vector<DeferredPointerRecord> records;
                    bool fieldsComplete = false;
                    if (!CollectDeferredListWindow(read, listHead, tail, modernDpcList,
                            dpcListEntry.Offset, deferredRoutine.Offset, false, 0, nodesRemaining,
                            cursor, &window, &records, &fieldsComplete))
                    {
                        nodesRemaining -= (std::min)(nodesRemaining, window.NodesVisited);
                        coverageComplete = false;
                        continue;
                    }
                    nodesRemaining -= window.Nodes.size();
                    result->NextDpcCursor = AdvanceDeferredQueue(prcbArray, queue, queueCount, &window);
                    coverageComplete = coverageComplete && fieldsComplete && window.Complete;
                    for (const DeferredPointerRecord& observed : records)
                    {
                        DpcRoutineRecord record;
                        record.Index = static_cast<uint32_t>(result->Dpcs.size());
                        record.Processor = cpu;
                        record.Source = L"prcb.dpcdata[" + std::to_wstring(dataIndex) + L"].window";
                        record.ObjectAddress = observed.Object;
                        record.Routine = observed.Function;
                        ClassifyRoutine(symbols_, record.Routine, &record.Module, &record.Symbol,
                            &record.Suspicious, &record.Notes);
                        result->SuspiciousDpcCount += record.Suspicious ? 1 : 0;
                        result->AnySuspicious = result->AnySuspicious || record.Suspicious;
                        result->Dpcs.push_back(std::move(record));
                    }
                    if (!window.ReachedEnd || (nodesRemaining == 0 && step + 1 != queueCount))
                    {
                        coverageComplete = false;
                        break;
                    }
                }

                result->DpcCoverageComplete = coverageComplete;
            }
        }

        // ---- Timer path: KiTimerTable when present ----
        if (options.Target == Scope::Timer || options.Target == Scope::All)
        {
            uint64_t timerTable = 0;
            uint32_t timerTableSize = 0;
            const std::wstring timerSymbol = L"nt!KiTimerTableListHead";
            TypeLayoutInfo timerTableEntryLayout = {};
            TypeFieldInfo timerTableListField = {};
            bool timerTableListFieldFromPdb = symbols_.FindField(
                L"nt!_KTIMER_TABLE_ENTRY",
                L"Entry",
                &timerTableListField,
                &ignored);
            if (!timerTableListFieldFromPdb)
            {
                timerTableListFieldFromPdb = symbols_.FindField(
                    L"nt!_KTIMER_TABLE_ENTRY",
                    L"ListHead",
                    &timerTableListField,
                    &ignored);
            }
            const bool foundTimerRoot =
                dpcObjectLayoutFromPdb &&
                timerObjectLayoutFromPdb &&
                timerTableListFieldFromPdb &&
                symbols_.GetTypeLayout(
                    L"nt!_KTIMER_TABLE_ENTRY",
                    &timerTableEntryLayout,
                    &ignored) &&
                timerTableEntryLayout.Size >= sizeof(uint64_t) * 2 &&
                timerTableEntryLayout.Size <= 0x100 &&
                static_cast<uint64_t>(timerTableListField.Offset) +
                        sizeof(uint64_t) * 2 <=
                    timerTableEntryLayout.Size &&
                symbols_.ResolveSymbol(timerSymbol, &timerTable, nullptr) &&
                IsKernelAddress(timerTable) &&
                ResolveExactSymbolSize(
                    symbols_,
                    timerSymbol,
                    timerTable,
                    &timerTableSize) &&
                timerTableSize % timerTableEntryLayout.Size == 0;
            const uint32_t bucketCount = foundTimerRoot
                ? static_cast<uint32_t>(
                      timerTableSize / timerTableEntryLayout.Size)
                : 0;

            if (!foundTimerRoot ||
                bucketCount == 0 ||
                bucketCount > kMaxTimerBuckets)
            {
                result->Warnings.push_back(
                    L"PDB-bounded KiTimerTableListHead unavailable; heuristic timer "
                    L"table probing disabled");
                result->TimerCoverageComplete = false;
            }
            else
            {
                bool coverageComplete = true;
                result->Warnings.push_back(
                    L"timer root via PDB-bounded " + timerSymbol);

                const uint32_t firstBucket = options.TimerCursor.RootAddress == timerTable
                    ? options.TimerCursor.QueueIndex % bucketCount : 0;
                const uint32_t bucketBudget = (std::min)(bucketCount, 32u);
                size_t nodesRemaining = (std::min)(timerLimit, 4096u);
                coverageComplete = options.TimerCursor.List.Entry == 0 && bucketBudget == bucketCount;
                auto read = [&](uint64_t address, uint64_t* value)
                {
                    return ReadU64(device_, address, value);
                };
                for (uint32_t step = 0; step < bucketBudget && nodesRemaining != 0; ++step)
                {
                    const uint32_t bucket = (firstBucket + step) % bucketCount;
                    result->NextTimerCursor = AdvanceDeferredQueue(timerTable, bucket, bucketCount, nullptr);
                    const uint64_t listHead = timerTable + static_cast<uint64_t>(bucket) * timerTableEntryLayout.Size +
                        timerTableListField.Offset;
                    const ScannerListCursor cursor = step == 0 && options.TimerCursor.RootAddress == timerTable
                        ? options.TimerCursor.List : ScannerListCursor{};
                    ScannerListWindow window;
                    std::vector<DeferredPointerRecord> records;
                    bool fieldsComplete = false;
                    if (!CollectDeferredListWindow(read, listHead, listHead + 8, false,
                            timerListEntry.Offset, deferredRoutine.Offset, true, timerDpc.Offset,
                            nodesRemaining, cursor, &window, &records, &fieldsComplete))
                    {
                        nodesRemaining -= (std::min)(nodesRemaining, window.NodesVisited);
                        coverageComplete = false;
                        continue;
                    }
                    nodesRemaining -= window.Nodes.size();
                    result->NextTimerCursor = AdvanceDeferredQueue(timerTable, bucket, bucketCount, &window);
                    coverageComplete = coverageComplete && fieldsComplete && window.Complete;
                    for (const DeferredPointerRecord& observed : records)
                    {
                        TimerRoutineRecord record;
                        record.Index = static_cast<uint32_t>(result->Timers.size());
                        record.TimerAddress = observed.Object;
                        record.DpcAddress = observed.Dpc;
                        record.Routine = observed.Function;
                        ClassifyRoutine(symbols_, record.Routine, &record.Module, &record.Symbol,
                            &record.Suspicious, &record.Notes);
                        result->SuspiciousTimerCount += record.Suspicious ? 1 : 0;
                        result->AnySuspicious = result->AnySuspicious || record.Suspicious;
                        result->Timers.push_back(std::move(record));
                    }
                    if (!window.ReachedEnd || (nodesRemaining == 0 && step + 1 != bucketCount))
                    {
                        coverageComplete = false;
                        break;
                    }
                }

                result->TimerCoverageComplete = coverageComplete;
            }
        }

        // Only PDB-validated executive queue arrays are interpreted as work items.
        if (options.Target == Scope::WorkItem || options.Target == Scope::All)
        {
            CollectWorkItems(device_, symbols_, options, result);
        }

        // Success even when some coverage is incomplete - incomplete is explicit.
        if (options.Target == Scope::Dpc &&
            result->Dpcs.empty() &&
            !result->DpcCoverageComplete &&
            result->ProcessorsSampled == 0)
        {
            // still ok: return empty with warnings
        }

        ok = true;
    } while (false);

    return ok;
}

namespace
{
    std::wstring BuildSharedHeader(const DpcTimerScanResult& result, const wchar_t* schema)
    {
        std::wstring out = L"{\"schema\":";
        out += mcpjson::Quote(schema);
        out += L",\"anySuspicious\":";
        out += result.AnySuspicious ? L"true" : L"false";
        out += L",\"processorsSampled\":" + std::to_wstring(result.ProcessorsSampled);
        out += L",\"dpcCoverageComplete\":";
        out += result.DpcCoverageComplete ? L"true" : L"false";
        out += L",\"timerCoverageComplete\":";
        out += result.TimerCoverageComplete ? L"true" : L"false";
        out += L",\"workItemCoverageComplete\":";
        out += result.WorkItemCoverageComplete ? L"true" : L"false";
        out += L",\"warnings\":[";
        for (size_t i = 0; i < result.Warnings.size(); ++i)
        {
            if (i > 0)
            {
                out += L",";
            }
            out += mcpjson::Quote(result.Warnings[i]);
        }
        out += L"]";
        return out;
    }
}

std::wstring BuildDpcJson(const DpcTimerScanResult& result)
{
    std::wstring out = BuildSharedHeader(result, L"kn-live-dbg.dpc.v1");
    out += L",\"suspiciousCount\":" + std::to_wstring(result.SuspiciousDpcCount);
    out += L",\"dpcCount\":" + std::to_wstring(result.Dpcs.size());
    out += L",\"dpcs\":[";
    for (size_t i = 0; i < result.Dpcs.size(); ++i)
    {
        const DpcRoutineRecord& record = result.Dpcs[i];
        if (i > 0)
        {
            out += L",";
        }
        out += L"{\"index\":" + std::to_wstring(record.Index);
        out += L",\"processor\":" + std::to_wstring(record.Processor);
        out += L",\"source\":" + mcpjson::Quote(record.Source);
        out += L",\"object\":" + mcpjson::Quote(JsonHex(record.ObjectAddress));
        out += L",\"routine\":" + mcpjson::Quote(JsonHex(record.Routine));
        out += L",\"module\":" + mcpjson::Quote(record.Module);
        out += L",\"symbol\":" + mcpjson::Quote(record.Symbol);
        out += L",\"suspicious\":";
        out += record.Suspicious ? L"true" : L"false";
        out += L",\"notes\":" + mcpjson::Quote(record.Notes);
        out += L"}";
    }
    out += L"]}";
    return out;
}

std::wstring BuildTimerJson(const DpcTimerScanResult& result)
{
    std::wstring out = BuildSharedHeader(result, L"kn-live-dbg.timer.v1");
    out += L",\"suspiciousCount\":" + std::to_wstring(result.SuspiciousTimerCount);
    out += L",\"timerCount\":" + std::to_wstring(result.Timers.size());
    out += L",\"timers\":[";
    for (size_t i = 0; i < result.Timers.size(); ++i)
    {
        const TimerRoutineRecord& record = result.Timers[i];
        if (i > 0)
        {
            out += L",";
        }
        out += L"{\"index\":" + std::to_wstring(record.Index);
        out += L",\"timer\":" + mcpjson::Quote(JsonHex(record.TimerAddress));
        out += L",\"dpc\":" + mcpjson::Quote(JsonHex(record.DpcAddress));
        out += L",\"routine\":" + mcpjson::Quote(JsonHex(record.Routine));
        out += L",\"module\":" + mcpjson::Quote(record.Module);
        out += L",\"symbol\":" + mcpjson::Quote(record.Symbol);
        out += L",\"suspicious\":";
        out += record.Suspicious ? L"true" : L"false";
        out += L",\"notes\":" + mcpjson::Quote(record.Notes);
        out += L"}";
    }
    out += L"]}";
    return out;
}

std::wstring BuildWorkItemJson(const DpcTimerScanResult& result)
{
    std::wstring out = BuildSharedHeader(result, L"kn-live-dbg.workitem.v1");
    out += L",\"attempted\":";
    out += result.WorkItemAttempted ? L"true" : L"false";
    out += L",\"layoutFromPdb\":";
    out += result.WorkItemLayoutFromPdb ? L"true" : L"false";
    out += L",\"coverageScope\":" + mcpjson::Quote(result.WorkItemCoverageScope);
    out += L",\"queuesVisited\":" + std::to_wstring(result.WorkItemQueuesVisited);
    out += L",\"nodesVisited\":" + std::to_wstring(result.WorkItemNodesVisited);
    out += L",\"nextCursor\":" + mcpjson::Quote(JsonHex(result.NextWorkItemCursor.List.Entry));
    out += L",\"nextQueueHead\":" + mcpjson::Quote(JsonHex(result.NextWorkItemCursor.RootAddress));
    out += L",\"cursorHead\":" + mcpjson::Quote(JsonHex(result.NextWorkItemCursor.List.Head));
    out += L",\"cursorForward\":" + mcpjson::Quote(JsonHex(result.NextWorkItemCursor.List.Forward));
    out += L",\"cursorBackward\":" + mcpjson::Quote(JsonHex(result.NextWorkItemCursor.List.Backward));
    out += L",\"suspiciousCount\":" + std::to_wstring(result.SuspiciousWorkItemCount);
    out += L",\"workItemCount\":" + std::to_wstring(result.WorkItems.size());
    out += L",\"workItems\":[";
    for (size_t i = 0; i < result.WorkItems.size(); ++i)
    {
        const WorkItemRecord& record = result.WorkItems[i];
        if (i > 0)
        {
            out += L",";
        }
        out += L"{\"index\":" + std::to_wstring(record.Index);
        out += L",\"entry\":" + mcpjson::Quote(JsonHex(record.EntryAddress));
        out += L",\"queue\":" + mcpjson::Quote(JsonHex(record.QueueAddress));
        out += L",\"parameter\":" + mcpjson::Quote(JsonHex(record.Parameter));
        out += L",\"routine\":" + mcpjson::Quote(JsonHex(record.Routine));
        out += L",\"module\":" + mcpjson::Quote(record.Module);
        out += L",\"symbol\":" + mcpjson::Quote(record.Symbol);
        out += L",\"suspicious\":";
        out += record.Suspicious ? L"true" : L"false";
        out += L",\"notes\":" + mcpjson::Quote(record.Notes);
        out += L"}";
    }
    out += L"]}";
    return out;
}

bool WorkItemScannerSelfTest()
{
    const uint64_t head = 0xffff800000001000ull;
    const uint64_t otherHead = head + 0x1000;
    const uint64_t firstNode = head + 0x100000;
    const uint64_t otherNode = head + 0x400000;
    const uint64_t callback = head + 0x800000;
    constexpr uint32_t listOffset = 8;
    constexpr uint32_t routineOffset = 0x20;
    constexpr uint32_t parameterOffset = 0x28;
    std::map<uint64_t, uint64_t> memory;
    auto read = [&](uint64_t address, uint64_t* value)
    {
        const auto found = memory.find(address);
        if (found == memory.end())
        {
            return false;
        }
        *value = found->second;
        return true;
    };
    auto populate = [&](uint64_t queueHead, uint64_t nodes, size_t count)
    {
        memory[queueHead] = count == 0 ? queueHead : nodes;
        memory[queueHead + 8] = count == 0 ? queueHead : nodes + (count - 1) * 0x40;
        for (size_t index = 0; index < count; ++index)
        {
            const uint64_t node = nodes + index * 0x40;
            memory[node] = index + 1 == count ? queueHead : node + 0x40;
            memory[node + 8] = index == 0 ? queueHead : node - 0x40;
            memory[node - listOffset + routineOffset] = callback;
            memory[node - listOffset + parameterOffset] = 0;
        }
    };
    const std::vector<WorkItemQueueDescriptor> queues =
    {
        {otherHead - 0x20, otherHead},
        {head - 0x20, head},
        {head - 0x20, head}
    };

    // This uses the production collector, not pagination of a prebuilt output.
    populate(head, firstNode, 4097);
    populate(otherHead, otherNode, 1);
    for (size_t limit : {size_t(32), size_t(4096), size_t(8192)})
    {
        DeferredQueueCursor cursor;
        std::set<uint64_t> observed;
        for (size_t pass = 0; pass < 130 && observed.size() != 4098; ++pass)
        {
            DpcTimerScanResult result;
            CollectWorkItemWindows(read, queues, listOffset, routineOffset, parameterOffset,
                limit, true, cursor, &result);
            const size_t budget = (std::min)(limit, size_t(4096));
            if (result.WorkItemCoverageComplete || result.WorkItems.empty() ||
                result.WorkItemNodesVisited > budget || result.WorkItems.size() > budget ||
                result.WorkItemQueuesVisited > 32)
            {
                return false;
            }
            if (pass == 0 && (result.WorkItems.size() != budget ||
                result.NextWorkItemCursor.RootAddress != head ||
                result.NextWorkItemCursor.List.Entry != firstNode + (budget - 1) * 0x40))
            {
                return false;
            }
            for (const WorkItemRecord& record : result.WorkItems)
            {
                if (record.Routine != callback || record.Parameter != 0 ||
                    (record.QueueAddress != head - 0x20 && record.QueueAddress != otherHead - 0x20))
                {
                    return false;
                }
                observed.insert(record.EntryAddress);
            }
            cursor = result.NextWorkItemCursor;
        }
        if (observed.size() != 4098 || observed.count(otherNode - listOffset) != 1)
        {
            return false;
        }
    }

    // Empty known queues are a complete negative; an incomplete root inventory is not.
    memory.clear();
    populate(head, firstNode, 0);
    populate(otherHead, otherNode, 0);
    DpcTimerScanResult empty;
    CollectWorkItemWindows(read, queues, listOffset, routineOffset, parameterOffset,
        32, true, {}, &empty);
    if (!empty.WorkItemCoverageComplete || !empty.WorkItems.empty() ||
        empty.WorkItemQueuesVisited != 2 || empty.WorkItemNodesVisited != 0)
    {
        return false;
    }
    DpcTimerScanResult unknown;
    CollectWorkItemWindows(read, queues, listOffset, routineOffset, parameterOffset,
        32, false, {}, &unknown);
    if (unknown.WorkItemCoverageComplete)
    {
        return false;
    }

    // A field read failure consumes the node budget without publishing an unknown routine.
    populate(head, firstNode, 1);
    populate(otherHead, otherNode, 1);
    memory.erase(firstNode - listOffset + parameterOffset);
    DpcTimerScanResult fieldFailure;
    CollectWorkItemWindows(read, queues, listOffset, routineOffset, parameterOffset,
        32, true, {}, &fieldFailure);
    if (fieldFailure.WorkItemCoverageComplete || fieldFailure.WorkItemNodesVisited != 2 ||
        fieldFailure.WorkItems.size() != 1 || fieldFailure.WorkItems.front().EntryAddress != otherNode - listOffset)
    {
        return false;
    }
    memory[firstNode - listOffset + parameterOffset] = 0;
    size_t parameterReads = 0;
    auto changedParameter = [&](uint64_t address, uint64_t* value)
    {
        if (address == firstNode - listOffset + parameterOffset && ++parameterReads == 2)
        {
            *value = 1;
            return true;
        }
        return read(address, value);
    };
    DpcTimerScanResult changedFields;
    CollectWorkItemWindows(changedParameter, queues, listOffset, routineOffset, parameterOffset,
        32, true, {}, &changedFields);
    if (changedFields.WorkItemCoverageComplete || changedFields.WorkItems.size() != 1 ||
        changedFields.WorkItems.front().EntryAddress != otherNode - listOffset)
    {
        return false;
    }

    // A head mutation after callback reads invalidates that queue's staged records.
    size_t headReads = 0;
    auto changedHead = [&](uint64_t address, uint64_t* value)
    {
        if (address == head && ++headReads == 3)
        {
            *value = head;
            return true;
        }
        return read(address, value);
    };
    DpcTimerScanResult unstable;
    CollectWorkItemWindows(changedHead, queues, listOffset, routineOffset, parameterOffset,
        32, true, {}, &unstable);
    if (unstable.WorkItemCoverageComplete || unstable.WorkItems.size() != 1 ||
        unstable.WorkItems.front().EntryAddress != otherNode - listOffset)
    {
        return false;
    }

    // An unlinked anchor restarts the affected queue and then reaches its surviving tail.
    memory.clear();
    populate(head, firstNode, 5);
    const std::vector<WorkItemQueueDescriptor> oneQueue = {{head - 0x20, head}};
    DpcTimerScanResult first;
    CollectWorkItemWindows(read, oneQueue, listOffset, routineOffset, parameterOffset, 2, true, {}, &first);
    memory[firstNode] = firstNode + 0x80;
    memory[firstNode + 0x88] = firstNode;
    memory[firstNode + 0x40] = firstNode + 0x40;
    memory[firstNode + 0x48] = firstNode + 0x40;
    DpcTimerScanResult second;
    CollectWorkItemWindows(read, oneQueue, listOffset, routineOffset, parameterOffset,
        2, true, first.NextWorkItemCursor, &second);
    DpcTimerScanResult third;
    CollectWorkItemWindows(read, oneQueue, listOffset, routineOffset, parameterOffset,
        2, true, second.NextWorkItemCursor, &third);
    if (second.WorkItemCoverageComplete || second.WorkItems.size() != 2 ||
        second.WorkItems.front().EntryAddress != firstNode - listOffset || third.WorkItems.size() != 2 ||
        third.WorkItems.back().EntryAddress != firstNode + 0x100 - listOffset ||
        third.NextWorkItemCursor.List.Entry != 0)
    {
        return false;
    }

    // Failed walks are charged, and the next queue remains reachable on the next pass.
    memory.clear();
    populate(head, firstNode, 64);
    populate(otherHead, otherNode, 1);
    memory.erase(firstNode + 31 * 0x40);
    DpcTimerScanResult failedWalk;
    CollectWorkItemWindows(read, queues, listOffset, routineOffset, parameterOffset,
        32, true, {}, &failedWalk);
    if (failedWalk.WorkItemCoverageComplete || failedWalk.WorkItemNodesVisited != 32 ||
        failedWalk.WorkItemQueuesVisited != 1 || !failedWalk.WorkItems.empty() ||
        failedWalk.NextWorkItemCursor.RootAddress != otherHead || failedWalk.NextWorkItemCursor.List.Entry != 0)
    {
        return false;
    }
    DpcTimerScanResult nextQueue;
    CollectWorkItemWindows(read, queues, listOffset, routineOffset, parameterOffset,
        32, true, failedWalk.NextWorkItemCursor, &nextQueue);
    if (nextQueue.WorkItems.empty() || nextQueue.WorkItems.front().EntryAddress != otherNode - listOffset ||
        nextQueue.WorkItemNodesVisited > 32)
    {
        return false;
    }

    // Removed roots use an address anchor; they do not reset to the first surviving queue.
    DpcTimerScanResult removedRoot;
    CollectWorkItemWindows(read, {{otherHead - 0x20, otherHead}}, listOffset, routineOffset, parameterOffset,
        32, true, first.NextWorkItemCursor, &removedRoot);
    if (removedRoot.WorkItemCoverageComplete || removedRoot.WorkItems.size() != 1 ||
        removedRoot.WorkItems.front().EntryAddress != otherNode - listOffset)
    {
        return false;
    }

    // Repeated removal of the saved anchor cannot keep a later queue unobserved.
    memory.clear();
    populate(head, firstNode, 64);
    populate(otherHead, otherNode, 1);
    DeferredQueueCursor churnCursor;
    size_t laterQueueObservations = 0;
    for (size_t pass = 0; pass < 9; ++pass)
    {
        if (churnCursor.RootAddress == head && churnCursor.List.Entry != 0)
        {
            const uint64_t anchor = churnCursor.List.Entry;
            const uint64_t next = memory[anchor];
            const uint64_t previous = memory[anchor + 8];
            memory[previous] = next;
            memory[next + 8] = previous;
            memory[anchor] = anchor;
            memory[anchor + 8] = anchor;
        }
        DpcTimerScanResult churn;
        CollectWorkItemWindows(read, queues, listOffset, routineOffset, parameterOffset,
            32, true, churnCursor, &churn);
        if (churn.WorkItemCoverageComplete || churn.WorkItemNodesVisited > 32)
        {
            return false;
        }
        for (const WorkItemRecord& record : churn.WorkItems)
        {
            laterQueueObservations += record.EntryAddress == otherNode - listOffset ? 1 : 0;
        }
        churnCursor = churn.NextWorkItemCursor;
    }
    if (laterQueueObservations < 4)
    {
        return false;
    }

    // Queue discovery and empty queues must not bypass the per-pass queue budget.
    memory.clear();
    std::vector<WorkItemQueueDescriptor> manyQueues;
    for (size_t index = 0; index < 33; ++index)
    {
        const uint64_t queueHead = head + index * 0x100;
        manyQueues.push_back({queueHead - 0x20, queueHead});
        populate(queueHead, otherNode, index == 32 ? 1 : 0);
    }
    DpcTimerScanResult queueCap;
    CollectWorkItemWindows(read, manyQueues, listOffset, routineOffset, parameterOffset,
        32, true, {}, &queueCap);
    DpcTimerScanResult queueTail;
    CollectWorkItemWindows(read, manyQueues, listOffset, routineOffset, parameterOffset,
        32, true, queueCap.NextWorkItemCursor, &queueTail);
    if (queueCap.WorkItemCoverageComplete || queueCap.WorkItemQueuesVisited != 32 ||
        !queueCap.WorkItems.empty() || queueTail.WorkItemCoverageComplete ||
        queueTail.WorkItemQueuesVisited != 32 || queueTail.WorkItems.size() != 1 ||
        queueTail.WorkItems.front().EntryAddress != otherNode - listOffset)
    {
        return false;
    }
    DpcTimerScanResult invalidRoot;
    CollectWorkItemWindows(read, {{~0ull - 7, ~0ull - 7}}, listOffset, routineOffset, parameterOffset,
        32, true, {}, &invalidRoot);
    if (invalidRoot.WorkItemCoverageComplete || !invalidRoot.WorkItems.empty() ||
        invalidRoot.WorkItemNodesVisited != 0)
    {
        return false;
    }
    return BuildWorkItemJson(first).find(L"\"nextQueueHead\":") != std::wstring::npos &&
        BuildWorkItemJson(first).find(L"\"nodesVisited\":2") != std::wstring::npos;
}

bool DpcTimerScannerSelfTest()
{
    {
        const uint64_t head = 0xffff800030000000ull;
        const uint64_t first = head + 0x1000;
        std::map<uint64_t, uint64_t> memory;
        auto read = [&](uint64_t address, uint64_t* value)
        {
            const auto found = memory.find(address);
            if (found != memory.end())
            {
                *value = found->second;
            }
            return found != memory.end();
        };
        for (bool timer : {false, true})
        {
            memory.clear();
            memory[head] = first;
            memory[head + 8] = first + 64 * 0x100;
            for (size_t i = 0; i < 65; ++i)
            {
                const uint64_t node = first + i * 0x100;
                memory[node] = i == 64 ? (timer ? head : 0) : node + 0x100;
                memory[node + 8] = i == 0 ? head : node - 0x100;
                memory[node + 0x10] = node + 0x40;
                memory[node + 0x18] = head + 0x900000;
                memory[node + 0x58] = head + 0x900000;
            }
            DeferredQueueCursor cursor;
            std::set<uint64_t> observed;
            for (size_t pass = 0; pass < 3; ++pass)
            {
                ScannerListWindow window;
                std::vector<DeferredPointerRecord> records;
                bool complete = false;
                if (!CollectDeferredListWindow(read, head, head + 8, !timer, 0, 0x18, timer, 0x10,
                        32, cursor.List, &window, &records, &complete) || !complete || window.NodesVisited > 32)
                {
                    return false;
                }
                for (const auto& record : records)
                {
                    observed.insert(record.Object);
                }
                cursor = AdvanceDeferredQueue(head, 0, 2, &window);
            }
            if (observed.size() != 65 || cursor.QueueIndex != 1 || cursor.List.Entry != 0)
            {
                return false;
            }
            const auto wrapped = AdvanceDeferredQueue(head, 1, 2, nullptr);
            if (wrapped.QueueIndex != 0 || wrapped.List.Entry != 0)
            {
                return false;
            }
            ScannerListWindow beforeUnlink;
            std::vector<DeferredPointerRecord> beforeRecords;
            bool fieldsComplete = false;
            if (!CollectDeferredListWindow(read, head, head + 8, !timer, 0, 0x18, timer, 0x10,
                    32, {}, &beforeUnlink, &beforeRecords, &fieldsComplete) || !fieldsComplete)
            {
                return false;
            }
            const uint64_t anchor = beforeUnlink.Next.Entry;
            const uint64_t previous = memory[anchor + 8];
            const uint64_t following = memory[anchor];
            memory[previous] = following;
            memory[following + 8] = previous;
            memory[anchor] = timer ? anchor : 0;
            memory[anchor + 8] = anchor;
            ScannerListWindow restarted;
            std::vector<DeferredPointerRecord> restartedRecords;
            if (!CollectDeferredListWindow(read, head, head + 8, !timer, 0, 0x18, timer, 0x10,
                    32, beforeUnlink.Next, &restarted, &restartedRecords, &fieldsComplete) ||
                !fieldsComplete || !restarted.Restarted || restarted.ReachedEnd || restartedRecords.size() != 32)
            {
                return false;
            }
            const auto nextQueue = AdvanceDeferredQueue(head, 0, 2, &restarted);
            const auto sameQueue = AdvanceDeferredQueue(head, 0, 1, &restarted);
            if (nextQueue.QueueIndex != 1 || nextQueue.List.Entry != 0 ||
                sameQueue.QueueIndex != 0 || sameQueue.List.Entry != restarted.Next.Entry)
            {
                return false;
            }
        }
        ScannerListWindow window;
        std::vector<DeferredPointerRecord> records;
        bool complete = false;
        uint32_t callbackReads = 0;
        auto changing = [&](uint64_t address, uint64_t* value)
        {
            if (!read(address, value))
            {
                return false;
            }
            if (address == first + 0x58 && ++callbackReads == 2)
            {
                *value ^= 0x100;
            }
            return true;
        };
        if (!CollectDeferredListWindow(changing, head, head + 8, false, 0, 0x18, true, 0x10,
                1, {}, &window, &records, &complete) || complete || !records.empty())
        {
            return false;
        }
    }
    bool ok = false;
    do
    {
        const uint64_t head = 0xffff800000001000ull;
        const uint64_t tail = head + 8;
        const uint64_t first = 0xffff800000002008ull;
        const uint64_t second = 0xffff800000003008ull;
        const uint64_t routine = 0xffff800000010000ull;
        std::map<uint64_t, uint64_t> memory;
        auto read = [&](uint64_t address, uint64_t* value)
        {
            const auto found = memory.find(address);
            if (found == memory.end())
            {
                return false;
            }
            *value = found->second;
            return true;
        };
        std::vector<uint64_t> observed;
        auto visit = [&](uint64_t objectAddress, uint64_t callback)
        {
            if (callback == routine)
            {
                observed.push_back(objectAddress);
            }
        };
        memory[head] = 0;
        memory[tail] = head;
        if (!WalkSingleDpcQueue(read, visit, head, tail, 8, 0x18, 16) || !observed.empty())
        {
            break;
        }
        memory[head] = first;
        memory[tail] = second;
        memory[first] = second;
        memory[second] = 0;
        memory[first + 0x10] = routine;
        memory[second + 0x10] = routine;
        if (!WalkSingleDpcQueue(read, visit, head, tail, 8, 0x18, 16) ||
            observed != std::vector<uint64_t>{first - 8, second - 8})
        {
            break;
        }
        if (WalkSingleDpcQueue(read, visit, head, tail, 8, 0x18, 1))
        {
            break;
        }
        memory[second] = first;
        if (WalkSingleDpcQueue(read, visit, head, tail, 8, 0x18, 16))
        {
            break;
        }
        memory[second] = 0;
        memory[tail] = first;
        if (WalkSingleDpcQueue(read, visit, head, tail, 8, 0x18, 16))
        {
            break;
        }
        memory[tail] = second;
        memory.erase(second + 0x10);
        if (WalkSingleDpcQueue(read, visit, head, tail, 8, 0x18, 16))
        {
            break;
        }
        memory[second + 0x10] = routine;
        uint32_t headReads = 0;
        auto changingRead = [&](uint64_t address, uint64_t* value)
        {
            if (address == head && ++headReads == 2)
            {
                *value = second;
                return true;
            }
            return read(address, value);
        };
        if (WalkSingleDpcQueue(changingRead, visit, head, tail, 8, 0x18, 16))
        {
            break;
        }
        memory[first] = 0x1000;
        if (WalkSingleDpcQueue(read, visit, head, tail, 8, 0x18, 16))
        {
            break;
        }
        ok = true;
    } while (false);
    return ok;
}
