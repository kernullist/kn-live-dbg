#pragma once

#include "PendingIrpScanner.h"

#include <algorithm>
#include <cstring>
#include <set>

namespace pending_irp
{
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
        // Missing optional fields remain unknown; zero is a valid PDB offset.
        uint32_t Cancel = UINT32_MAX;
        uint32_t PendingReturned = UINT32_MAX;
        uint32_t IoStatus = UINT32_MAX;
        uint32_t DeviceObject = UINT32_MAX;
        uint32_t FileObject = UINT32_MAX;
    };

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
    bool ReadScalar(Reader& read, uint64_t base, uint32_t offset, uint64_t* value,
        const AddressSpaceDescriptor& space)
    {
        std::vector<uint8_t> bytes;
        return space.KernelRange(base, static_cast<size_t>(offset) + 8) &&
            read(base + offset, 8, &bytes) && bytes.size() == 8 && Extract(bytes, 0, value);
    }

    template<typename Reader>
    bool WalkIrpList(Reader& read, uint64_t head, size_t maximum, std::vector<uint64_t>* nodes,
        const AddressSpaceDescriptor& space)
    {
        nodes->clear();
        uint64_t first = 0;
        uint64_t last = 0;
        if (!ReadScalar(read, head, 0, &first, space) || !ReadScalar(read, head, 8, &last, space))
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
                !ReadScalar(read, current, 0, &next, space) || !ReadScalar(read, current, 8, &back, space) || back != previous)
            {
                return false;
            }
            nodes->push_back(current);
            previous = current;
            current = next;
        }
        uint64_t firstAfter = 0;
        uint64_t lastAfter = 0;
        return previous == last && ReadScalar(read, head, 0, &firstAfter, space) && ReadScalar(read, head, 8, &lastAfter, space) &&
            first == firstAfter && last == lastAfter;
    }

    template<typename Reader>
    bool CaptureIrp(Reader& read, const IrpLayout& layout, uint64_t irp,
        const PendingIrpThreadInput& thread, uint64_t createTime, std::vector<PendingIrpCompletionRecord>* records,
        const AddressSpaceDescriptor& space, PendingIrpRequestObservation* request = nullptr)
    {
        std::vector<uint8_t> header;
        if (!space.KernelRange(irp, layout.IrpSize) || !read(irp, layout.IrpSize, &header) || header.size() != layout.IrpSize)
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
        if (required > packetSize || !space.KernelRange(irp, required) ||
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
        PendingIrpRequestObservation observed;
        observed.Thread = thread;
        observed.ThreadCreateTime = createTime;
        observed.Irp = irp;
        observed.StackCount = stackCount;
        observed.CurrentLocation = currentLocation;
        uint8_t boolean = 0;
        int32_t status = 0;
        if (layout.Cancel != UINT32_MAX && Extract(header, layout.Cancel, &boolean) && boolean <= 1)
        {
            observed.CancelFlag = boolean != 0;
        }
        if (layout.PendingReturned != UINT32_MAX && Extract(header, layout.PendingReturned, &boolean) && boolean <= 1)
        {
            observed.PendingReturned = boolean != 0;
        }
        if (layout.IoStatus != UINT32_MAX && Extract(header, layout.IoStatus, &status))
        {
            observed.IoStatus = status;
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
            PendingIrpStackObservation stack;
            stack.Index = index;
            stack.Address = irp + base;
            stack.MajorFunction = record.MajorFunction;
            stack.MinorFunction = record.MinorFunction;
            stack.Control = record.Control;
            stack.CompletionRoutine = record.CompletionRoutine;
            stack.Context = record.Context;
            uint64_t pointer = 0;
            if (layout.DeviceObject != UINT32_MAX && layout.DeviceObject <= layout.StackSize &&
                sizeof(pointer) <= layout.StackSize - layout.DeviceObject &&
                Extract(second, base + layout.DeviceObject, &pointer))
            {
                stack.DeviceObject = pointer;
            }
            if (layout.FileObject != UINT32_MAX && layout.FileObject <= layout.StackSize &&
                sizeof(pointer) <= layout.StackSize - layout.FileObject &&
                Extract(second, base + layout.FileObject, &pointer))
            {
                stack.FileObject = pointer;
            }
            observed.Stacks.push_back(std::move(stack));
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
        if (request != nullptr)
        {
            *request = std::move(observed);
        }
        return true;
    }

    template<typename Reader>
    void CollectPendingIrps(Reader& read, const IrpLayout& layout,
        std::vector<PendingIrpThreadInput> threads, const PendingIrpScanOptions& options, PendingIrpScanResult* result,
        const AddressSpaceDescriptor& space)
    {
        result->AddressSpace = space;
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
                !ReadScalar(read, thread.ThreadObject, layout.ThreadPid, &pid, space) || pid != thread.ProcessId ||
                !ReadScalar(read, thread.ThreadObject, layout.ThreadTid, &tid, space) || tid != thread.ThreadId ||
                !ReadScalar(read, thread.ThreadObject, layout.ThreadCreateTime, &createTime, space) || createTime == 0 ||
                !space.KernelRange(thread.ThreadObject, layout.ThreadIrpList + 16))
            {
                ++result->UnstableObservations;
                complete = false;
                continue;
            }
            result->NextCursor.ThreadCreateTime = createTime;
            const uint64_t head = thread.ThreadObject + layout.ThreadIrpList;
            auto readLink = [&](uint64_t address, uint64_t* value)
            {
                return ReadScalar(read, address, 0, value, space);
            };
            ScannerListCursor cursor;
            if (thread.ThreadObject == options.Cursor.ThreadObject && createTime == options.Cursor.ThreadCreateTime)
            {
                cursor = options.Cursor.List;
            }
            const size_t budget = (std::min)(walkLimit - result->WalkNodes, irpLimit - result->IrpsInspected);
            ScannerListWindow window;
            if (!ReadScannerListWindow(readLink, head, head + 8, false, budget, cursor, &window, space))
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
            std::vector<PendingIrpRequestObservation> requests;
            for (const ScannerListNode& node : window.Nodes)
            {
                if (node.Address < layout.ThreadListEntry ||
                    !space.KernelRange(node.Address - layout.ThreadListEntry, layout.IrpSize))
                {
                    complete = false;
                    continue;
                }
                const uint64_t irp = node.Address - layout.ThreadListEntry;
                ++result->IrpsInspected;
                PendingIrpRequestObservation request;
                if (!CaptureIrp(read, layout, irp, thread, createTime, &local, space, &request))
                {
                    ++result->UnstableObservations;
                    complete = false;
                }
                else
                {
                    requests.push_back(std::move(request));
                }
            }
            uint64_t pidAfter = 0;
            uint64_t tidAfter = 0;
            uint64_t createAfter = 0;
            if (!ReadScalar(read, thread.ThreadObject, layout.ThreadPid, &pidAfter, space) || pidAfter != pid ||
                !ReadScalar(read, thread.ThreadObject, layout.ThreadTid, &tidAfter, space) || tidAfter != tid ||
                !ReadScalar(read, thread.ThreadObject, layout.ThreadCreateTime, &createAfter, space) || createAfter != createTime ||
                !ValidateScannerListWindow(readLink, window))
            {
                ++result->UnstableObservations;
                complete = false;
            }
            else
            {
                result->Records.insert(result->Records.end(), local.begin(), local.end());
                result->Requests.insert(result->Requests.end(), requests.begin(), requests.end());
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
