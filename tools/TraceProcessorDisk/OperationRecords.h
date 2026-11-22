#pragma once

#include "../../user/EtlDiskIo.h"
#include <tdh.h>
#include <vector>
#pragma comment(lib, "tdh.lib")

namespace etl_profile
{
    inline constexpr GUID FileIoProvider = {0x90cbdc39, 0x4a3e, 0x11d1, {0x84, 0xf4, 0x00, 0x00, 0xf8, 0x04, 0x64, 0xe3}};

    // Windows TDH decodes the named fields of selected original records only.
    // Packet and file-object values stay in memory for comparisons within this query.
    struct OperationRecord
    {
        const wchar_t* status = L"not_observed";
        bool file = false;
        uint8_t opcode = 0, width = 0;
        uint16_t logger = 0;
        uint32_t number = 0, tid = 0, requested = 0, flags = 0, ntstatus = 0;
        int64_t timestamp = 0;
        uint64_t packet = 0, object = 0, offset = 0, extra = 0;

        static bool Property(PEVENT_RECORD e, PCWSTR name, ULONG bytes, void* out)
        {
            PROPERTY_DATA_DESCRIPTOR field{};
            field.PropertyName = reinterpret_cast<ULONGLONG>(name);
            field.ArrayIndex = ULONG_MAX;
            ULONG size = 0;
            return TdhGetPropertySize(e, 0, nullptr, 1, &field, &size) == ERROR_SUCCESS && size == bytes &&
                TdhGetProperty(e, 0, nullptr, 1, &field, bytes, static_cast<PBYTE>(out)) == ERROR_SUCCESS;
        }

        void Read(PEVENT_RECORD e, uint32_t record)
        {
            number = record;
            const auto& h = e->EventHeader;
            opcode = h.EventDescriptor.Opcode;
            file = IsEqualGUID(h.ProviderId, FileIoProvider) != 0;
            const bool disk = IsEqualGUID(h.ProviderId, DiskIoProvider) != 0;
            const bool transfer = opcode == 67 || opcode == 68;
            status = L"other_event";
            if (!(file && (transfer || opcode == 73 || opcode == 76)) && !(disk && opcode >= 10 && opcode <= 15)) { return; }
            status = L"unsupported_record";
            width = ClassicPointerWidth(h, 3);
            if (!width || !e->UserData || (e->ExtendedDataCount && !e->ExtendedData)) { return; }
            timestamp = h.TimeStamp.QuadPart;
            logger = e->BufferContext.LoggerId;
            if (!Property(e, file ? L"IrpPtr" : L"Irp", width, &packet)) { return; }
            if (file && opcode == 76)
            {
                if (!Property(e, L"ExtraInfo", width, &extra) || !Property(e, L"NtStatus", 4, &ntstatus)) { return; }
            }
            else
            {
                if (!Property(e, file ? L"TTID" : L"IssuingThreadId", 4, &tid)) { return; }
                if ((file || opcode == 10 || opcode == 11) && !Property(e, L"FileObject", width, &object)) { return; }
                if (file && transfer && (!Property(e, L"Offset", 8, &offset) || !Property(e, L"IoSize", 4, &requested) ||
                    !Property(e, L"IoFlags", 4, &flags))) { return; }
            }
            status = L"decoded";
        }
    };
}
