#pragma once

#include <Windows.h>
#include <cstdint>

namespace approved_file
{
    // Reopening preserves the caller's implicit cursor. An inherited broker
    // handle can instead be duplicated without another pathname access check.
    // Duplicate readers must use explicit offsets: duplicates share a file object.
    enum class Access { Reopen, Duplicate };

    inline HANDLE Open(HANDLE source, Access access)
    {
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        if (source == nullptr || source == INVALID_HANDLE_VALUE || GetFileType(source) != FILE_TYPE_DISK ||
            !GetFileInformationByHandleEx(source, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
            (attributes.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0)
        { return INVALID_HANDLE_VALUE; }
        if (access == Access::Reopen)
        { return ReOpenFile(source, GENERIC_READ, FILE_SHARE_READ, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN); }
        if (access != Access::Duplicate) { return INVALID_HANDLE_VALUE; }
        HANDLE copy = nullptr;
        return DuplicateHandle(GetCurrentProcess(), source, GetCurrentProcess(), &copy, GENERIC_READ, FALSE, 0) ?
            copy : INVALID_HANDLE_VALUE;
    }

    // Synchronous completion for both synchronous and overlapped regular-file
    // handles. A private event keeps concurrent reads from sharing completion
    // state. Never return while this stack-owned OVERLAPPED is still pending.
    inline bool ReadAt(HANDLE file, uint64_t offset, void* buffer, DWORD requested, DWORD* received)
    {
        if (received == nullptr) { return false; }
        *received = 0;
        if (file == nullptr || file == INVALID_HANDLE_VALUE || (buffer == nullptr && requested != 0) ||
            offset > INT64_MAX || requested > static_cast<uint64_t>(INT64_MAX) - offset) { return false; }
        if (requested == 0) { return true; }
        const auto event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (event == nullptr) { return false; }
        OVERLAPPED operation{};
        operation.Offset = static_cast<DWORD>(offset);
        operation.OffsetHigh = static_cast<DWORD>(offset >> 32);
        // Do not enqueue our stack-owned OVERLAPPED in a caller-owned IOCP.
        // Windows reserves the event handle's low bit for notification suppression.
        operation.hEvent = reinterpret_cast<HANDLE>(reinterpret_cast<uintptr_t>(event) | uintptr_t{1});
        bool ok = ReadFile(file, buffer, requested, received, &operation) != FALSE;
        if (!ok && GetLastError() == ERROR_IO_PENDING)
        { ok = GetOverlappedResult(file, &operation, received, TRUE) != FALSE; }
        const auto error = ok ? ERROR_SUCCESS : GetLastError();
        CloseHandle(event);
        if (!ok) { *received = 0; SetLastError(error); }
        return ok;
    }
}
