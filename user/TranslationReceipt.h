#pragma once

#include <Windows.h>
#include "RecordingObservationSource.h"
#include "../shared/KnLiveDbgPaging.h"
#include <functional>

enum class PagingFeatureState { Unknown, Disabled, Enabled };

// A provider must retain the source and publish a new epoch on root replacement.
// Labels are evidence from that provider, not an authentication of the kernel.
struct TranslationRootIdentity
{
    std::wstring SourceId;
    std::wstring TargetId;
    std::wstring AddressSpaceId;
    std::wstring RootId;
    std::wstring Binding;
    uint64_t Root = 0;
    uint64_t Epoch = 0;
    AddressSpaceDescriptor Space;
    PagingFeatureState NxEnabled = PagingFeatureState::Unknown;
    PagingFeatureState Pages1G = PagingFeatureState::Unknown;
};

inline bool SameTranslationRoot(const TranslationRootIdentity& a, const TranslationRootIdentity& b)
{
    return a.SourceId == b.SourceId && a.TargetId == b.TargetId && a.AddressSpaceId == b.AddressSpaceId &&
        a.RootId == b.RootId && a.Binding == b.Binding && a.Root == b.Root && a.Epoch == b.Epoch &&
        a.Space.VirtualAddressBits == b.Space.VirtualAddressBits && a.Space.PointerBytes == b.Space.PointerBytes &&
        a.Space.PhysicalAddressBits == b.Space.PhysicalAddressBits && a.Space.LegacyAssumed == b.Space.LegacyAssumed &&
        a.Space.UserMaximum == b.Space.UserMaximum && a.Space.KernelMinimum == b.Space.KernelMinimum &&
        a.NxEnabled == b.NxEnabled && a.Pages1G == b.Pages1G;
}

struct TranslationWalkEntry
{
    uint32_t Level = 0;
    uint64_t Address = 0;
    bool Recheck = false;
    bool Decoded = false;
    uint64_t Value = 0;
    ObservationReadResult Read;
};

struct TranslationReceipt
{
    TranslationRootIdentity Root;
    ObservationSourceCapabilities PhysicalSource;
    uint64_t VirtualAddress = 0;
    uint32_t RequestedBytes = 0;
    ObservationReadState State = ObservationReadState::Unsupported;
    std::wstring Reason;
    std::vector<TranslationWalkEntry> Entries;
    bool HasMapping = false;
    bool RootRevalidated = false;
    bool EntriesRevalidated = false;
    bool PagingPermissionsKnown = false;
    bool Writable = false;
    bool UserAccessible = false;
    bool Executable = false;
    uint64_t PhysicalAddress = 0;
    uint64_t PageBytes = 0;
    uint32_t TranslatedBytes = 0;
};

// The root callback reads retained provider metadata; acquisition needed to
// establish that metadata belongs in the provider's own recorded operation.
// Equal before/after values are a bounded observation, not an ABA/lifetime proof.
inline TranslationReceipt TranslateObservedAddress(RecordingObservationSource& physical,
    const TranslationRootIdentity& root, const std::function<TranslationRootIdentity()>& currentRoot,
    uint64_t address, uint32_t length, const std::atomic<bool>* cancellation = nullptr)
{
    constexpr uint64_t FrameMask52 = 0x000ffffffffff000ull;
    TranslationReceipt receipt;
    receipt.Root = root;
    receipt.PhysicalSource = physical.Capabilities();
    receipt.VirtualAddress = address;
    receipt.RequestedBytes = length;
    const auto fail = [&](ObservationReadState state, const wchar_t* reason)
    {
        receipt.State = state;
        receipt.Reason = reason;
        return receipt;
    };
    const auto boundedId = [](const std::wstring& value) { return !value.empty() && value.size() <= 2048; };
    const auto validFeature = [](PagingFeatureState value)
    {
        return value >= PagingFeatureState::Unknown && value <= PagingFeatureState::Enabled;
    };
    if (!boundedId(root.SourceId) || !boundedId(root.TargetId) || !boundedId(root.AddressSpaceId) ||
        !boundedId(root.RootId) || !boundedId(root.Binding) || root.Epoch == 0 || !root.Space.Valid() ||
        root.Space.LegacyAssumed || !validFeature(root.NxEnabled) || !validFeature(root.Pages1G) ||
        !currentRoot || length == 0 || length > 4096 ||
        (!root.Space.UserRange(address, length) && !root.Space.KernelRange(address, length)) ||
        receipt.PhysicalSource.AddressDomain != ObservationAddressDomain::Physical ||
        receipt.PhysicalSource.SourceId != root.SourceId ||
        !physical.MatchesTarget(root.TargetId, root.AddressSpaceId) ||
        !ObservationRangeSupported(receipt.PhysicalSource, root.Root & FrameMask52, 4096))
    {
        return fail(ObservationReadState::Unsupported, L"invalid_translation_context");
    }
    const uint32_t physicalBits = root.Space.PhysicalAddressBits == 0 ? 52 : root.Space.PhysicalAddressBits;
    const uint64_t frameMask = ((uint64_t{1} << physicalBits) - 1) & ~uint64_t{4095};
    if ((root.Root & frameMask) == 0 || (root.Root & ~(frameMask | 0xfffull)) != 0)
    {
        return fail(ObservationReadState::Unsupported, L"invalid_translation_root");
    }
    const auto sameRoot = [&]()
    {
        return SameObservationSourceContract(physical.Capabilities(), receipt.PhysicalSource) &&
            SameTranslationRoot(root, currentRoot());
    };
    const auto readEntry = [&](uint32_t level, uint64_t entryAddress, bool recheck)
    {
        if (cancellation != nullptr && cancellation->load())
        {
            receipt.State = ObservationReadState::Cancelled;
            receipt.Reason = L"translation_cancelled";
            return false;
        }
        if (!sameRoot())
        {
            receipt.State = ObservationReadState::IdentityChanged;
            receipt.Reason = L"translation_root_changed";
            return false;
        }
        ObservationReadRequest request;
        request.SourceId = root.SourceId;
        request.Address = entryAddress;
        request.Length = 8;
        request.ByteBudget = 8;
        request.Cancellation = cancellation;
        TranslationWalkEntry entry;
        entry.Level = level;
        entry.Address = entryAddress;
        entry.Recheck = recheck;
        entry.Read = physical.Read(request);
        receipt.Entries.push_back(std::move(entry));
        auto& saved = receipt.Entries.back();
        if (!sameRoot())
        {
            receipt.State = ObservationReadState::IdentityChanged;
            receipt.Reason = L"translation_root_changed";
            return false;
        }
        if (saved.Read.CancellationObserved || saved.Read.OperationDeadlineExceeded ||
            saved.Read.State != ObservationReadState::Complete || saved.Read.ReadReceiptId == 0)
        {
            receipt.State = saved.Read.CancellationObserved ? ObservationReadState::Cancelled :
                saved.Read.OperationDeadlineExceeded || saved.Read.ReadReceiptId == 0 ? ObservationReadState::BudgetDeferred :
                saved.Read.State == ObservationReadState::Partial ? ObservationReadState::Failed : saved.Read.State;
            receipt.Reason = L"page_table_read_incomplete";
            return false;
        }
        uint32_t offset = 0;
        for (const auto& span : saved.Read.Spans)
        {
            for (const auto byte : span.Bytes)
            {
                if (offset == 8) { break; }
                saved.Value |= uint64_t{byte} << (offset++ * 8);
            }
        }
        if (offset != 8)
        {
            receipt.State = ObservationReadState::Failed;
            receipt.Reason = L"page_table_entry_not_exact";
            return false;
        }
        saved.Decoded = true;
        return true;
    };
    uint64_t table = root.Root & frameMask, pageBytes = 0, physicalAddress = 0;
    bool writable = true, userAccessible = true, executable = true, used1G = false;
    const uint32_t levels = root.Space.VirtualAddressBits == 57 ? 5 : 4;
    receipt.Entries.reserve(2 * levels);
    for (uint32_t level = levels; level != 0; --level)
    {
        const uint32_t shift = 12 + 9 * (level - 1);
        if (!readEntry(level, table + ((address >> shift) & 511) * 8, false)) { return receipt; }
        const uint64_t value = receipt.Entries.back().Value;
        if ((value & 1) == 0) { return fail(ObservationReadState::NotPresent, L"page_table_entry_not_present"); }
        if (!KnDbgPresentPagingEntryValid(value, level) || (value & FrameMask52 & ~frameMask) != 0 ||
            (root.NxEnabled == PagingFeatureState::Disabled && (value >> 63) != 0))
        {
            return fail(ObservationReadState::Unsupported, L"reserved_paging_entry_bits");
        }
        writable = writable && (value & 2) != 0;
        userAccessible = userAccessible && (value & 4) != 0;
        executable = executable && (value >> 63) == 0;
        const bool leaf = level == 1 || ((level == 2 || level == 3) && (value & 0x80) != 0);
        if (leaf)
        {
            used1G = level == 3;
            if (used1G && root.Pages1G == PagingFeatureState::Disabled)
            {
                return fail(ObservationReadState::Unsupported, L"one_gib_pages_disabled");
            }
            pageBytes = uint64_t{1} << shift;
            physicalAddress = (value & frameMask & ~(pageBytes - 1)) + (address & (pageBytes - 1));
            break;
        }
        table = value & frameMask;
    }
    const auto walked = receipt.Entries.size();
    for (size_t i = 0; i < walked; ++i)
    {
        const auto level = receipt.Entries[i].Level;
        const auto entryAddress = receipt.Entries[i].Address;
        const auto value = receipt.Entries[i].Value;
        if (!readEntry(level, entryAddress, true)) { return receipt; }
        if (receipt.Entries.back().Value != value)
        {
            return fail(ObservationReadState::Conflict, L"page_table_entry_changed");
        }
    }
    receipt.RootRevalidated = true;
    receipt.EntriesRevalidated = true;
    receipt.HasMapping = true;
    receipt.PhysicalAddress = physicalAddress;
    receipt.PageBytes = pageBytes;
    receipt.TranslatedBytes = static_cast<uint32_t>((std::min)(uint64_t{length}, pageBytes - (address & (pageBytes - 1))));
    receipt.PagingPermissionsKnown = root.Space.PhysicalAddressBits != 0 && root.NxEnabled != PagingFeatureState::Unknown &&
        (!used1G || root.Pages1G != PagingFeatureState::Unknown);
    receipt.Writable = writable;
    receipt.UserAccessible = userAccessible;
    receipt.Executable = executable;
    receipt.State = ObservationReadState::Complete;
    receipt.Reason = receipt.PagingPermissionsKnown ? L"page_table_chain_rechecked" : L"architecture_context_incomplete";
    return receipt;
}
