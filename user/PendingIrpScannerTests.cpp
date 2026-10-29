#include "PendingIrpReader.h"

#include <map>

using namespace pending_irp;

static bool PendingIrpScannerSelfTestForSpace(const AddressSpaceDescriptor& space, uint64_t base)
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
    CollectPendingIrps(read, layout, threads, options, &first, space);
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
        CollectPendingIrps(read, layout, threads, options, &second, space);
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
        return ReadScalar(read, address, 0, value, space);
    };
    auto scalarWrite = [&](uint64_t address, uint64_t value)
    {
        put(address, value);
    };
    if (!ScannerListWindowFixture(scalarRead, scalarWrite, base + 0x400000, space))
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
        CollectPendingIrps(read, layout, threads, churnOptions, &churn, space);
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
    CollectPendingIrps(read, layout, threads, options, &replacement, space);
    if (replacement.Records.empty() || replacement.Records.front().Irp != first.Records.front().Irp ||
        replacement.Records.front().ThreadCreateTime != 999 || replacement.NextCursor.IrpAddress != 0 ||
        replacement.NextCursor.List.Entry != 0)
    {
        return false;
    }
    PendingIrpScanOptions afterReplacementOptions = options;
    afterReplacementOptions.Cursor = replacement.NextCursor;
    PendingIrpScanResult afterReplacement;
    CollectPendingIrps(read, layout, threads, afterReplacementOptions, &afterReplacement, space);
    if (afterReplacement.Records.empty() || afterReplacement.Records.front().ThreadObject != threads[1].ThreadObject)
    {
        return false;
    }
    put(base + 16, static_cast<uint64_t>(100));
    std::vector<PendingIrpCompletionRecord> records;
    put(lastIrp + 5, static_cast<uint8_t>(0));
    if (CaptureIrp(read, layout, lastIrp, threads[1], 101, &records, space))
    {
        return false;
    }
    put(lastIrp + 5, static_cast<uint8_t>(1));
    put(lastIrp + 8, lastIrp + 0x68);
    if (CaptureIrp(read, layout, lastIrp, threads[1], 101, &records, space))
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
    return !CaptureIrp(changing, layout, lastIrp, threads[1], 101, &records, space) && records.empty();
}


bool PendingIrpScannerSelfTest(uint32_t* checks, PendingIrpScanResult* fixture)
{
    return PendingIrpScannerSelfTestForSpace(AddressSpaceDescriptor::FromPagingLevels(4), 0xffff800000010000ull) &&
        PendingIrpScannerSelfTestForSpace(AddressSpaceDescriptor::FromPagingLevels(5), 0xff10000000010000ull) &&
        PendingIrpObservationSelfTest(checks, fixture);
}

bool PendingIrpObservationSelfTest(uint32_t* checks, PendingIrpScanResult* fixture)
{
    uint32_t count = 0;
    uint32_t failed = 0;
    const auto check = [&](bool value)
    {
        ++count;
        if (!value)
        {
            ++failed;
        }
    };
    for (const uint32_t levels : {4u, 5u})
    {
        const auto space = AddressSpaceDescriptor::FromPagingLevels(levels);
        const uint64_t base = levels == 4 ? 0xffff800000010000ull : 0xff10000000010000ull;
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
        layout.Cancel = 6;
        layout.PendingReturned = 7;
        layout.CurrentStack = 8;
        layout.OwningThread = 16;
        layout.IoStatus = 24;
        layout.ThreadListEntry = 32;
        layout.StackSize = 0x30;
        layout.MajorFunction = 0;
        layout.MinorFunction = 1;
        layout.Control = 2;
        layout.Completion = 8;
        layout.Context = 16;
        layout.DeviceObject = 24;
        layout.FileObject = 32;
        std::vector<uint8_t> memory(0x4000, 0);
        const auto put = [&](uint64_t address, auto value)
        {
            std::memcpy(memory.data() + static_cast<size_t>(address - base), &value, sizeof(value));
        };
        auto read = [&](uint64_t address, uint32_t size, std::vector<uint8_t>* bytes)
        {
            if (address < base || address - base > memory.size() || size > memory.size() - (address - base))
            {
                return false;
            }
            const auto begin = memory.begin() + static_cast<size_t>(address - base);
            bytes->assign(begin, begin + size);
            return true;
        };
        const PendingIrpThreadInput thread = {base, 100, 104};
        put(base, uint64_t{100});
        put(base + 8, uint64_t{104});
        put(base + 16, uint64_t{1000});
        put(base + 32, base + 0x1020);
        put(base + 40, base + 0x1220);
        for (uint32_t i = 0; i < 3; ++i)
        {
            const uint64_t irp = base + 0x1000 + i * 0x100;
            put(irp, uint16_t{6});
            put(irp + 2, uint16_t{0x90});
            put(irp + 4, uint8_t{1});
            put(irp + 5, uint8_t{1});
            put(irp + 6, static_cast<uint8_t>(i == 1));
            put(irp + 7, static_cast<uint8_t>(i == 1));
            put(irp + 8, irp + 0x60);
            put(irp + 16, base);
            put(irp + 24, int32_t{0});
            put(irp + 32, i == 2 ? base + 32 : irp + 0x120);
            put(irp + 40, i == 0 ? base + 32 : irp - 0xe0);
            put(irp + 0x60, uint8_t{3});
            put(irp + 0x62, static_cast<uint8_t>(i == 0 ? 0 : 0x40));
            put(irp + 0x68, i == 0 ? uint64_t{0} : base + 0x3000);
            put(irp + 0x78, base + 0x3100);
            put(irp + 0x80, i == 2 ? uint64_t{0x1234} : base + 0x3200);
        }
        PendingIrpScanOptions options;
        options.ThreadInventoryComplete = true;
        PendingIrpScanResult result;
        CollectPendingIrps(read, layout, {thread}, options, &result, space);
        check(result.CoverageComplete && result.Requests.size() == 3 && result.Records.size() == 2);
        if (result.Requests.size() != 3)
        {
            continue;
        }
        check(result.Requests[0].Stacks.size() == 1 && result.Requests[0].Stacks[0].CompletionRoutine == 0);
        check(result.Requests[1].CancelFlag == true && result.Requests[1].PendingReturned == true && result.Requests[1].IoStatus == 0);
        check(result.Requests[2].Stacks[0].FileObject == 0x1234 && !result.ReferencedLifetime);
        if (fixture != nullptr && levels == 4)
        {
            *fixture = result;
            fixture->ScanStartedTickMs = 100;
            fixture->ScanFinishedTickMs = 110;
        }
        const auto original = memory;
        const uint64_t target = base + 0x1000;
        for (uint32_t failure = 0; failure < 6; ++failure)
        {
            memory = original;
            if (failure == 0)
            {
                put(target + 5, uint8_t{0});
            }
            else if (failure == 1)
            {
                put(target + 4, uint8_t{65});
            }
            else if (failure == 2)
            {
                put(target + 2, uint16_t{0x60});
            }
            else if (failure == 3)
            {
                put(target + 8, target + 0x68);
            }
            else if (failure == 4)
            {
                put(target + 16, base + 0x100);
            }
            else
            {
                put(target + 0x60, uint8_t{0x1c});
            }
            result = {};
            CollectPendingIrps(read, layout, {thread}, options, &result, space);
            check(!result.CoverageComplete && result.Requests.size() == 2 && result.UnstableObservations != 0);
        }
        memory = original;
        put(target + 6, uint8_t{2});
        put(target + 7, uint8_t{2});
        result = {};
        CollectPendingIrps(read, layout, {thread}, options, &result, space);
        check(result.Requests.size() == 3 && !result.Requests[0].CancelFlag.has_value() && !result.Requests[0].PendingReturned.has_value());
        memory = original;
        auto missing = layout;
        missing.Cancel = UINT32_MAX;
        missing.PendingReturned = UINT32_MAX;
        missing.IoStatus = UINT32_MAX;
        missing.DeviceObject = layout.StackSize - 1;
        missing.FileObject = UINT32_MAX;
        result = {};
        CollectPendingIrps(read, missing, {thread}, options, &result, space);
        check(result.Requests.size() == 3 && result.Records.size() == 2 &&
            !result.Requests[0].CancelFlag.has_value() && !result.Requests[0].IoStatus.has_value() &&
            !result.Requests[0].Stacks[0].DeviceObject.has_value() && !result.Requests[0].Stacks[0].FileObject.has_value());
        if (fixture != nullptr && levels == 4 && !result.Requests.empty())
        {
            fixture->Requests.push_back(result.Requests[0]);
        }
        put(target + 5, uint8_t{2});
        put(target + 8, target + 0x90);
        result = {};
        CollectPendingIrps(read, layout, {thread}, options, &result, space);
        check(result.Requests.size() == 3 && result.Requests[0].Stacks.empty());
        memory = original;
        uint32_t reads = 0;
        auto churn = [&](uint64_t address, uint32_t size, std::vector<uint8_t>* bytes)
        {
            if (!read(address, size, bytes))
            {
                return false;
            }
            if (address == target && ++reads == 3)
            {
                (*bytes)[layout.Cancel] ^= 1;
            }
            return true;
        };
        result = {};
        CollectPendingIrps(churn, layout, {thread}, options, &result, space);
        check(result.Requests.size() == 2 && !result.CoverageComplete);
        reads = 0;
        auto ownerChurn = [&](uint64_t address, uint32_t size, std::vector<uint8_t>* bytes)
        {
            if (!read(address, size, bytes))
            {
                return false;
            }
            if (address == base + 16 && ++reads == 2)
            {
                (*bytes)[0] ^= 1;
            }
            return true;
        };
        result = {};
        CollectPendingIrps(ownerChurn, layout, {thread}, options, &result, space);
        check(result.Requests.empty() && result.Records.empty() && !result.CoverageComplete);
        result = {};
        options.MaxIrps = 1;
        CollectPendingIrps(read, layout, {thread}, options, &result, space);
        check(result.Requests.size() == 1 && !result.CoverageComplete && result.NextCursor.IrpAddress != 0);
    }
    if (checks != nullptr)
    {
        *checks = count;
    }
    return failed == 0;
}
