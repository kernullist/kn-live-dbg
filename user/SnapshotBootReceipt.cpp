#include "SnapshotBootReceipt.h"
#include "ContentHash.h"
#include <ncrypt.h>
#include <ncryptprotect.h>
#include <algorithm>
#include <string_view>

#pragma comment(lib, "ncrypt.lib")

namespace
{
    constexpr std::wstring_view ObjectStart = L"{\n";
    constexpr std::wstring_view ReceiptMember = L"  \"local_boot_receipt\":\"";
    constexpr std::wstring_view MemberEnd = L"\",\n";
    constexpr size_t MaxBlob = 4096;
    constexpr wchar_t Policy[] = L"LOCAL=user AND LOCAL=machine";

    struct Descriptor
    {
        NCRYPT_DESCRIPTOR_HANDLE Handle = nullptr;
        ~Descriptor() { if (Handle) { NCryptCloseProtectionDescriptor(Handle); } }
    };

    struct Buffer
    {
        BYTE* Data = nullptr;
        DWORD Size = 0;
        ~Buffer() { LocalFree(Data); }
    };

    std::string Statement(std::wstring_view remainder)
    {
        static_assert(sizeof(wchar_t) == 2);
        ContentHash hash;
        for (const auto part : {ObjectStart, remainder})
        {
            if (!hash.Add(reinterpret_cast<const uint8_t*>(part.data()), part.size() * sizeof(wchar_t))) { return {}; }
        }
        const auto digest = hash.Finish();
        if (digest.empty()) { return {}; }
        std::string message = "kn.snapshot.local-boot.v1:";
        for (wchar_t digit : digest) { message.push_back(static_cast<char>(digit)); }
        return message;
    }

    bool LocalPolicy(NCRYPT_DESCRIPTOR_HANDLE descriptor)
    {
        void* rule = nullptr;
        const auto status = NCryptGetProtectionDescriptorInfo(descriptor, nullptr,
            NCRYPT_PROTECTION_INFO_TYPE_DESCRIPTOR_STRING, &rule);
        const std::unique_ptr<void, decltype(&LocalFree)> owner(rule, LocalFree);
        if (status != ERROR_SUCCESS || !rule) { return false; }
        const auto text = static_cast<const wchar_t*>(rule);
        // Windows can return the normalized descriptor without spaces around AND.
        return !_wcsicmp(text, Policy) || !_wcsicmp(text, L"LOCAL=userANDLOCAL=machine");
    }
}

bool AttachSnapshotBootReceipt(std::wstring& json)
{
    const std::wstring_view original(json);
    if (original.substr(0, ObjectStart.size()) != ObjectStart) { return false; }
    const auto message = Statement(original.substr(ObjectStart.size()));
    Descriptor descriptor;
    Buffer sealed;
    if (message.empty() || NCryptCreateProtectionDescriptor(Policy, 0, &descriptor.Handle) != ERROR_SUCCESS ||
        NCryptProtectSecret(descriptor.Handle, NCRYPT_SILENT_FLAG, reinterpret_cast<const BYTE*>(message.data()),
            static_cast<ULONG>(message.size()), nullptr, nullptr, &sealed.Data, &sealed.Size) != ERROR_SUCCESS ||
        !sealed.Data || !sealed.Size || sealed.Size > MaxBlob) { return false; }
    constexpr wchar_t hex[] = L"0123456789abcdef";
    std::wstring member(ReceiptMember);
    for (DWORD i = 0; i < sealed.Size; ++i)
    {
        member.push_back(hex[sealed.Data[i] >> 4]);
        member.push_back(hex[sealed.Data[i] & 15]);
    }
    member.append(MemberEnd);
    json.insert(ObjectStart.size(), member);
    return true;
}

bool VerifySnapshotBootReceipt(const std::wstring& json)
{
    const std::wstring_view text(json);
    const auto start = ObjectStart.size() + ReceiptMember.size();
    if (text.substr(0, ObjectStart.size()) != ObjectStart ||
        text.substr(ObjectStart.size(), ReceiptMember.size()) != ReceiptMember) { return false; }
    const auto end = text.substr(start, MaxBlob * 2 + MemberEnd.size()).find(MemberEnd);
    if (end == std::wstring_view::npos || !end || end > MaxBlob * 2 || (end % 2)) { return false; }
    constexpr std::wstring_view hex = L"0123456789abcdef";
    std::vector<BYTE> bytes(end / 2);
    for (size_t i = 0; i < bytes.size(); ++i)
    {
        const auto hi = hex.find(text[start + i * 2]);
        const auto lo = hex.find(text[start + i * 2 + 1]);
        if (hi == hex.npos || lo == hex.npos) { return false; }
        bytes[i] = static_cast<BYTE>((hi << 4) | lo);
    }

    // Inspect the descriptor before allowing any key provider to decrypt.
    Descriptor header;
    Buffer ignored;
    const auto size = static_cast<ULONG>(bytes.size());
    if (NCryptUnprotectSecret(&header.Handle, NCRYPT_SILENT_FLAG | NCRYPT_UNPROTECT_NO_DECRYPT,
        bytes.data(), size, nullptr, nullptr, &ignored.Data, &ignored.Size) != ERROR_SUCCESS ||
        !LocalPolicy(header.Handle)) { return false; }
    Descriptor actual;
    Buffer clear;
    if (NCryptUnprotectSecret(&actual.Handle, NCRYPT_SILENT_FLAG, bytes.data(), size, nullptr, nullptr,
        &clear.Data, &clear.Size) != ERROR_SUCCESS || !LocalPolicy(actual.Handle) || !clear.Data) { return false; }
    const auto expected = Statement(text.substr(start + end + MemberEnd.size()));
    return !expected.empty() && clear.Size == expected.size() &&
        std::equal(expected.begin(), expected.end(), clear.Data);
}
