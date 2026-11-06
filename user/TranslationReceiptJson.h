#pragma once

#include "TranslationReceipt.h"
#include "ReadReceiptJson.h"

inline std::wstring TranslationReceiptJson(const TranslationReceipt& receipt)
{
    const auto n = [](uint64_t value) { return mcpjson::Quote(std::to_wstring(value)); };
    const auto b = [](bool value) { return value ? L"true" : L"false"; };
    const auto feature = [](PagingFeatureState value)
    {
        return value == PagingFeatureState::Unknown ? L"null" : value == PagingFeatureState::Enabled ? L"true" : L"false";
    };
    const auto& root = receipt.Root;
    std::wstring json = L"{\"schema\":\"kn.translation_receipt.v1\",\"status\":" +
        mcpjson::Quote(ObservationReadStateName(receipt.State)) + L",\"reason\":" + mcpjson::Quote(receipt.Reason) +
        L",\"virtual_address\":" + n(receipt.VirtualAddress) + L",\"requested_bytes\":" + n(receipt.RequestedBytes) +
        L",\"root\":{\"source_id\":" + mcpjson::Quote(root.SourceId) + L",\"target_id\":" + mcpjson::Quote(root.TargetId) +
        L",\"address_space_id\":" + mcpjson::Quote(root.AddressSpaceId) + L",\"root_id\":" + mcpjson::Quote(root.RootId) +
        L",\"binding\":" + mcpjson::Quote(root.Binding) + L",\"value\":" + n(root.Root) + L",\"epoch\":" + n(root.Epoch) +
        L",\"virtual_address_bits\":" + std::to_wstring(root.Space.VirtualAddressBits) + L",\"physical_address_bits\":" +
        (root.Space.PhysicalAddressBits == 0 ? std::wstring(L"null") : std::to_wstring(root.Space.PhysicalAddressBits)) +
        L",\"nx_enabled\":" + feature(root.NxEnabled) + L",\"one_gib_pages\":" + feature(root.Pages1G) +
        L"},\"root_revalidated\":" + b(receipt.RootRevalidated) + L",\"entries_revalidated\":" + b(receipt.EntriesRevalidated) +
        L",\"physical_address\":" + (receipt.HasMapping ? n(receipt.PhysicalAddress) : L"null") +
        L",\"pfn\":" + (receipt.HasMapping ? n(receipt.PhysicalAddress >> 12) : L"null") +
        L",\"page_bytes\":" + (receipt.HasMapping ? n(receipt.PageBytes) : L"null") +
        L",\"translated_bytes\":" + (receipt.HasMapping ? n(receipt.TranslatedBytes) : L"null") +
        L",\"paging_permissions_known\":" + b(receipt.PagingPermissionsKnown) +
        L",\"paging_write_allowed\":" + (receipt.PagingPermissionsKnown ? b(receipt.Writable) : L"null") +
        L",\"paging_user_allowed\":" + (receipt.PagingPermissionsKnown ? b(receipt.UserAccessible) : L"null") +
        L",\"paging_execute_allowed\":" + (receipt.PagingPermissionsKnown ? b(receipt.Executable) : L"null") +
        L",\"cpu_access_verified\":false,\"mapping_lifetime_bound\":false,\"collector_authenticated\":false,"
        L"\"consistency\":\"repeated_walk_not_atomic_snapshot\",\"entries\":[";
    for (const auto& entry : receipt.Entries)
    {
        if (&entry != &receipt.Entries.front()) { json += L","; }
        ObservationReadRequest request;
        request.SourceId = root.SourceId;
        request.Address = entry.Address;
        request.Length = 8;
        json += L"{\"level\":" + std::to_wstring(entry.Level) + L",\"entry_address\":" + n(entry.Address) +
            L",\"phase\":" + mcpjson::Quote(entry.Recheck ? L"recheck" : L"walk") +
            L",\"entry_value\":" + (entry.Decoded ? n(entry.Value) : L"null") +
            L",\"read\":" + ObservationReadJson(receipt.PhysicalSource, request, entry.Read) + L"}";
    }
    return json + L"]}";
}
