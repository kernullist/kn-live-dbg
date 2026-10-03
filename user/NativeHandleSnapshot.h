#pragma once

#include <Windows.h>
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

// SystemExtendedHandleInformation uses pointer-sized PID and handle fields.
struct NativeHandleEntry
{
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
};

struct NativeHandleHeader
{
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
};

static_assert(sizeof(void*) == 8, "The native handle ABI requires x64");
static_assert(sizeof(NativeHandleHeader) == 0x10, "Unexpected handle header");
static_assert(sizeof(NativeHandleEntry) == 0x28, "Unexpected handle entry");
static_assert(offsetof(NativeHandleEntry, HandleValue) == 0x10, "Handle ABI");
static_assert(offsetof(NativeHandleEntry, GrantedAccess) == 0x18, "Access ABI");
static_assert(offsetof(NativeHandleEntry, ObjectTypeIndex) == 0x1E, "Type ABI");
static_assert(offsetof(NativeHandleEntry, HandleAttributes) == 0x20, "Flags ABI");

inline bool ParseNativeHandleSnapshot(
    const void* data,
    size_t capacity,
    size_t returned,
    std::vector<NativeHandleEntry>* entries)
{
    bool ok = false;
    do
    {
        if (entries == nullptr)
        {
            break;
        }
        entries->clear();
        if (data == nullptr || returned > capacity || returned < sizeof(NativeHandleHeader))
        {
            break;
        }
        NativeHandleHeader header = {};
        std::memcpy(&header, data, sizeof(header));
        const size_t maxCount = (returned - sizeof(header)) / sizeof(NativeHandleEntry);
        if (header.NumberOfHandles > maxCount)
        {
            break;
        }
        entries->resize(static_cast<size_t>(header.NumberOfHandles));
        if (!entries->empty())
        {
            std::memcpy(entries->data(), static_cast<const uint8_t*>(data) + sizeof(header),
                entries->size() * sizeof(NativeHandleEntry));
        }
        ok = true;
    } while (false);
    return ok;
}

inline bool QueryNativeHandleSnapshot(
    std::vector<NativeHandleEntry>* entries,
    std::wstring* error)
{
    bool ok = false;
    do
    {
        if (entries == nullptr)
        {
            break;
        }
        entries->clear();
        using QueryFn = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        const auto query = ntdll == nullptr ? nullptr : reinterpret_cast<QueryFn>(
            GetProcAddress(ntdll, "NtQuerySystemInformation"));
        if (query == nullptr)
        {
            break;
        }
        constexpr size_t maxBytes = 64u * 1024u * 1024u;
        std::vector<uint8_t> buffer(1u << 20);
        for (size_t attempt = 0; attempt < 8; ++attempt)
        {
            ULONG returned = 0;
            const LONG status = query(64, buffer.data(), static_cast<ULONG>(buffer.size()), &returned);
            if (status >= 0)
            {
                ok = ParseNativeHandleSnapshot(buffer.data(), buffer.size(), returned, entries);
                break;
            }
            if (static_cast<ULONG>(status) != 0xC0000004u &&
                static_cast<ULONG>(status) != 0xC0000023u)
            {
                break;
            }
            const size_t next = (std::max)(buffer.size() * 2, static_cast<size_t>(returned) + 65536);
            if (next > maxBytes)
            {
                break;
            }
            buffer.resize(next);
        }
    } while (false);
    if (!ok && error != nullptr)
    {
        *error = L"native handle snapshot unavailable, over budget, or truncated";
    }
    return ok;
}

inline bool NativeHandleSnapshotSelfTest()
{
    std::vector<uint8_t> bytes(0x38, 0);
    const uint64_t count = 1;
    const uint64_t handle = 0x1234567887654321ull;
    const uint32_t access = 0x12019Fu;
    const uint16_t type = 0x42;
    std::memcpy(bytes.data(), &count, sizeof(count));
    std::memcpy(bytes.data() + 0x20, &handle, sizeof(handle));
    std::memcpy(bytes.data() + 0x28, &access, sizeof(access));
    std::memcpy(bytes.data() + 0x2E, &type, sizeof(type));
    std::vector<NativeHandleEntry> entries;
    bool ok = ParseNativeHandleSnapshot(bytes.data(), bytes.size(), bytes.size(), &entries);
    ok = ok && entries.size() == 1 && entries[0].HandleValue == handle &&
        entries[0].GrantedAccess == access && entries[0].ObjectTypeIndex == type;
    ok = ok && !ParseNativeHandleSnapshot(bytes.data(), bytes.size(), bytes.size() - 1, &entries);
    ok = ok && !ParseNativeHandleSnapshot(bytes.data(), bytes.size(), 15, &entries);
    ok = ok && !ParseNativeHandleSnapshot(bytes.data(), bytes.size(), bytes.size() + 1, &entries);
    return ok;
}
