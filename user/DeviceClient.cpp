#include "DeviceClient.h"

#include "../shared/KnLiveDbgIoctl.h"

#include <limits>
#include <sstream>

static std::wstring DeviceErrorText(const wchar_t* prefix, DWORD error)
{
    wchar_t buffer[512] = {};
    FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        buffer,
        static_cast<DWORD>(std::size(buffer)),
        nullptr);

    std::wstringstream stream;
    stream << prefix << L": " << error << L" " << buffer;
    return stream.str();
}

DeviceClient::DeviceClient() :
    device_(INVALID_HANDLE_VALUE)
{
}

DeviceClient::~DeviceClient()
{
    Close();
}

bool DeviceClient::Open(std::wstring* error)
{
    return Open(KNDBG_USER_DEVICE_NAME, error);
}

bool DeviceClient::Open(const std::wstring& userDeviceName, std::wstring* error)
{
    bool ok = false;

    do
    {
        Close();

        if (userDeviceName.empty())
        {
            if (error != nullptr)
            {
                *error = L"device name is empty";
            }
            break;
        }

        device_ = CreateFileW(
            userDeviceName.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (device_ == INVALID_HANDLE_VALUE)
        {
            if (error != nullptr)
            {
                *error = DeviceErrorText(L"CreateFileW device failed", GetLastError());
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

void DeviceClient::Close()
{
    if (device_ != INVALID_HANDLE_VALUE)
    {
        CloseHandle(device_);
        device_ = INVALID_HANDLE_VALUE;
    }
}

bool DeviceClient::IsOpen() const
{
    return device_ != INVALID_HANDLE_VALUE;
}

bool DeviceClient::Ioctl(
    DWORD code,
    void* buffer,
    DWORD inLength,
    DWORD outLength,
    DWORD* returned,
    std::wstring* error,
    DWORD* deviceError)
{
    bool ok = false;

    do
    {
        if (deviceError != nullptr)
        {
            *deviceError = ERROR_SUCCESS;
        }

        if (device_ == INVALID_HANDLE_VALUE)
        {
            if (deviceError != nullptr)
            {
                *deviceError = ERROR_INVALID_HANDLE;
            }
            if (error != nullptr)
            {
                *error = L"Device is not open";
            }
            break;
        }

        DWORD localReturned = 0;
        if (!DeviceIoControl(device_, code, buffer, inLength, buffer, outLength, &localReturned, nullptr))
        {
            const DWORD lastError = GetLastError();
            if (deviceError != nullptr)
            {
                *deviceError = lastError;
            }
            if (error != nullptr)
            {
                *error = DeviceErrorText(L"DeviceIoControl failed", lastError);
            }
            break;
        }

        if (returned != nullptr)
        {
            *returned = localReturned;
        }

        ok = true;
    } while (false);

    return ok;
}

bool DeviceClient::QueryVersion(std::wstring* error)
{
    bool ok = false;

    do
    {
        KNDBG_VERSION_RESPONSE response = {};
        DWORD returned = 0;
        if (!Ioctl(IOCTL_KNDBG_GET_VERSION, &response, 0, sizeof(response), &returned, error))
        {
            break;
        }

        if (returned < sizeof(response) || response.AbiVersion != KNDBG_ABI_VERSION)
        {
            if (error != nullptr)
            {
                *error = L"Driver ABI version mismatch";
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool DeviceClient::QuerySessionStatus(DriverSessionStatus* status, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (status == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid session status output";
            }
            break;
        }

        KNDBG_SESSION_STATUS_RESPONSE response = {};
        DWORD returned = 0;
        if (!Ioctl(IOCTL_KNDBG_GET_SESSION_STATUS, &response, 0, sizeof(response), &returned, error))
        {
            break;
        }

        if (returned < sizeof(response))
        {
            if (error != nullptr)
            {
                *error = L"Short session status response";
            }
            break;
        }

        status->Flags = response.Flags;
        status->OwnerPid = response.OwnerPid;
        status->CurrentPid = response.CurrentPid;
        status->OpenHandleCount = response.OpenHandleCount;
        ok = true;
    } while (false);

    return ok;
}

bool DeviceClient::ReadMsr(
    uint32_t msrIndex,
    uint32_t processorNumber,
    uint64_t* value,
    uint32_t* actualProcessor,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (value == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid MSR value output";
            }
            break;
        }

        union
        {
            KNDBG_READ_MSR_REQUEST Request;
            KNDBG_READ_MSR_RESPONSE Response;
        } buffer = {};

        buffer.Request.Size = sizeof(KNDBG_READ_MSR_REQUEST);
        buffer.Request.Flags = 0;
        buffer.Request.MsrIndex = msrIndex;
        buffer.Request.ProcessorNumber = processorNumber;

        DWORD returned = 0;
        if (!Ioctl(IOCTL_KNDBG_READ_MSR, &buffer, sizeof(KNDBG_READ_MSR_REQUEST), sizeof(KNDBG_READ_MSR_RESPONSE), &returned, error))
        {
            break;
        }

        if (returned < sizeof(KNDBG_READ_MSR_RESPONSE))
        {
            if (error != nullptr)
            {
                *error = L"Short MSR read response";
            }
            break;
        }

        *value = buffer.Response.Value;
        if (actualProcessor != nullptr)
        {
            *actualProcessor = buffer.Response.ProcessorNumber;
        }
        ok = true;
    } while (false);

    return ok;
}

bool DeviceClient::ReadControlRegisters(
    uint32_t processorNumber,
    ControlRegisters* registers,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (registers == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid control register output";
            }
            break;
        }

        union
        {
            KNDBG_READ_CR_REQUEST Request;
            KNDBG_READ_CR_RESPONSE Response;
        } buffer = {};

        buffer.Request.Size = sizeof(KNDBG_READ_CR_REQUEST);
        buffer.Request.Flags = 0;
        buffer.Request.ProcessorNumber = processorNumber;

        DWORD returned = 0;
        if (!Ioctl(IOCTL_KNDBG_READ_CONTROL_REGISTERS, &buffer, sizeof(KNDBG_READ_CR_REQUEST), sizeof(KNDBG_READ_CR_RESPONSE), &returned, error))
        {
            break;
        }

        if (returned < sizeof(KNDBG_READ_CR_RESPONSE))
        {
            if (error != nullptr)
            {
                *error = L"Short control register response";
            }
            break;
        }

        registers->ProcessorNumber = buffer.Response.ProcessorNumber;
        registers->Cr0 = buffer.Response.Cr0;
        registers->Cr2 = buffer.Response.Cr2;
        registers->Cr3 = buffer.Response.Cr3;
        registers->Cr4 = buffer.Response.Cr4;
        registers->Cr8 = buffer.Response.Cr8;
        ok = true;
    } while (false);

    return ok;
}

bool DeviceClient::ReadIdt(
    uint32_t processorNumber,
    IdtInfo* info,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (info == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid IDT output";
            }
            break;
        }

        union
        {
            KNDBG_READ_IDT_REQUEST Request;
            KNDBG_READ_IDT_RESPONSE Response;
        } buffer = {};

        buffer.Request.Size = sizeof(KNDBG_READ_IDT_REQUEST);
        buffer.Request.Flags = 0;
        buffer.Request.ProcessorNumber = processorNumber;

        DWORD returned = 0;
        if (!Ioctl(IOCTL_KNDBG_READ_IDT, &buffer, sizeof(KNDBG_READ_IDT_REQUEST), sizeof(KNDBG_READ_IDT_RESPONSE), &returned, error))
        {
            break;
        }

        if (returned < sizeof(KNDBG_READ_IDT_RESPONSE))
        {
            if (error != nullptr)
            {
                *error = L"Short IDT response";
            }
            break;
        }

        info->ProcessorNumber = buffer.Response.ProcessorNumber;
        info->Base = buffer.Response.IdtBase;
        info->Limit = buffer.Response.IdtLimit;
        ok = true;
    } while (false);

    return ok;
}

bool DeviceClient::ControlTimeline(
    uint32_t action,
    uint32_t capacity,
    std::wstring* error)
{
    KNDBG_TIMELINE_CONTROL_REQUEST request = {};
    request.Size = sizeof(request);
    request.Action = action;
    request.Capacity = capacity;
    request.Acknowledge = KNDBG_WRITE_ACK_MAGIC;

    DWORD returned = 0;
    return Ioctl(
        IOCTL_KNDBG_TIMELINE_CONTROL,
        &request,
        sizeof(request),
        sizeof(request),
        &returned,
        error);
}

bool DeviceClient::QueryTimelineStatus(
    TimelineLiveStatus* status,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (status == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid timeline status output";
            }
            break;
        }

        KNDBG_TIMELINE_STATUS_RESPONSE response = {};
        DWORD returned = 0;
        if (!Ioctl(IOCTL_KNDBG_TIMELINE_STATUS, &response, 0, sizeof(response), &returned, error))
        {
            break;
        }

        if (returned < sizeof(response))
        {
            if (error != nullptr)
            {
                *error = L"Short timeline status response";
            }
            break;
        }

        status->Flags = response.Flags;
        status->Capacity = response.Capacity;
        status->Count = response.Count;
        status->Dropped = response.Dropped;
        status->NextSequence = response.NextSequence;
        ok = true;
    } while (false);

    return ok;
}

bool DeviceClient::DrainTimelineEvents(
    uint32_t maxEvents,
    std::vector<TimelineLiveEvent>* events,
    TimelineLiveStatus* status,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (events == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid timeline event output";
            }
            break;
        }

        events->clear();
        if (maxEvents == 0)
        {
            maxEvents = 256;
        }
        if (maxEvents > 1024)
        {
            maxEvents = 1024;
        }

        DWORD headerLength = FIELD_OFFSET(KNDBG_TIMELINE_DRAIN_RESPONSE, Events);
        DWORD bufferLength = headerLength + maxEvents * sizeof(KNDBG_TIMELINE_EVENT_RECORD);
        if (bufferLength > KNDBG_MAX_TRANSFER_SIZE)
        {
            if (error != nullptr)
            {
                *error = L"Timeline drain request is too large";
            }
            break;
        }

        std::vector<uint8_t> buffer(bufferLength);
        KNDBG_TIMELINE_DRAIN_REQUEST* request = reinterpret_cast<KNDBG_TIMELINE_DRAIN_REQUEST*>(buffer.data());
        request->Size = sizeof(*request);
        request->MaxEvents = maxEvents;

        DWORD returned = 0;
        if (!Ioctl(
                IOCTL_KNDBG_TIMELINE_DRAIN,
                buffer.data(),
                sizeof(*request),
                bufferLength,
                &returned,
                error))
        {
            break;
        }
        if (returned < headerLength)
        {
            if (error != nullptr)
            {
                *error = L"Short timeline drain response";
            }
            break;
        }

        KNDBG_TIMELINE_DRAIN_RESPONSE* response =
            reinterpret_cast<KNDBG_TIMELINE_DRAIN_RESPONSE*>(buffer.data());
        if (response->Count > maxEvents ||
            returned < headerLength + response->Count * sizeof(KNDBG_TIMELINE_EVENT_RECORD))
        {
            if (error != nullptr)
            {
                *error = L"Invalid timeline drain count";
            }
            break;
        }

        events->reserve(response->Count);
        for (uint32_t index = 0; index < response->Count; ++index)
        {
            const KNDBG_TIMELINE_EVENT_RECORD& item = response->Events[index];
            TimelineLiveEvent event = {};
            event.Type = item.Type;
            event.Flags = item.Flags;
            event.ProcessId = item.ProcessId;
            event.ParentProcessId = item.ParentProcessId;
            event.ThreadId = item.ThreadId;
            event.CreatorProcessId = item.CreatorProcessId;
            event.CreatorThreadId = item.CreatorThreadId;
            event.Sequence = item.Sequence;
            event.Timestamp100ns = item.Timestamp100ns;
            event.ImageBase = item.ImageBase;
            event.ImageSize = item.ImageSize;
            event.FileObject = item.FileObject;
            uint32_t chars = item.ImagePathLength;
            if (chars >= KNDBG_TIMELINE_IMAGE_PATH_CHARS)
            {
                chars = KNDBG_TIMELINE_IMAGE_PATH_CHARS - 1;
            }
            event.ImagePath.assign(item.ImagePath, item.ImagePath + chars);
            events->push_back(event);
        }

        if (status != nullptr)
        {
            status->Flags = 0;
            status->Capacity = 0;
            status->Count = response->Remaining;
            status->Dropped = response->Dropped;
            status->NextSequence = response->NextSequence;
        }
        ok = true;
    } while (false);

    return ok;
}

bool DeviceClient::ResolveProcess(
    uint32_t processId,
    uint32_t directoryTableBaseOffset,
    uint32_t userDirectoryTableBaseOffset,
    ProcessAddressContext* context,
    std::wstring* error,
    DWORD* deviceError)
{
    bool ok = false;

    do
    {
        if (deviceError != nullptr)
        {
            *deviceError = ERROR_SUCCESS;
        }

        if (context == nullptr || processId == 0 || directoryTableBaseOffset == 0)
        {
            if (deviceError != nullptr)
            {
                *deviceError = ERROR_INVALID_PARAMETER;
            }
            if (error != nullptr)
            {
                *error = L"Invalid process resolve request";
            }
            break;
        }

        union
        {
            KNDBG_PROCESS_RESOLVE_REQUEST Request;
            KNDBG_PROCESS_RESOLVE_RESPONSE Response;
        } buffer = {};

        buffer.Request.Size = sizeof(KNDBG_PROCESS_RESOLVE_REQUEST);
        buffer.Request.ProcessId = processId;
        buffer.Request.DirectoryTableBaseOffset = directoryTableBaseOffset;
        buffer.Request.UserDirectoryTableBaseOffset = userDirectoryTableBaseOffset;

        DWORD returned = 0;
        if (!Ioctl(
                IOCTL_KNDBG_RESOLVE_PROCESS,
                &buffer,
                sizeof(KNDBG_PROCESS_RESOLVE_REQUEST),
                sizeof(KNDBG_PROCESS_RESOLVE_RESPONSE),
                &returned,
                error,
                deviceError))
        {
            break;
        }

        if (returned < sizeof(KNDBG_PROCESS_RESOLVE_RESPONSE))
        {
            if (deviceError != nullptr)
            {
                *deviceError = ERROR_INSUFFICIENT_BUFFER;
            }
            if (error != nullptr)
            {
                *error = L"Short process resolve response";
            }
            break;
        }

        context->Flags = buffer.Response.Flags;
        context->ProcessId = buffer.Response.ProcessId;
        context->Eprocess = buffer.Response.Eprocess;
        context->DirectoryTableBase = buffer.Response.DirectoryTableBase;
        context->UserDirectoryTableBase = buffer.Response.UserDirectoryTableBase;
        ok = true;
    } while (false);

    return ok;
}

bool DeviceClient::SetWriteMode(bool enabled, std::wstring* error)
{
    KNDBG_WRITE_MODE_REQUEST request = {};
    request.Size = sizeof(request);
    request.EnableWrite = enabled ? 1u : 0u;
    request.Acknowledge = KNDBG_WRITE_ACK_MAGIC;

    DWORD returned = 0;
    return Ioctl(IOCTL_KNDBG_SET_WRITE_MODE, &request, sizeof(request), sizeof(request), &returned, error);
}

bool DeviceClient::ReadMemory(
    uint64_t address,
    uint32_t length,
    std::vector<uint8_t>* bytes,
    std::wstring* error,
    uint32_t flags)
{
    bool ok = false;

    do
    {
        if (bytes == nullptr || length == 0 || length > KNDBG_MAX_TRANSFER_SIZE)
        {
            if (error != nullptr)
            {
                *error = L"Invalid read length";
            }
            break;
        }

        DWORD bufferLength = FIELD_OFFSET(KNDBG_READ_REQUEST, Data) + length;
        std::vector<uint8_t> buffer(bufferLength);
        KNDBG_READ_REQUEST* request = reinterpret_cast<KNDBG_READ_REQUEST*>(buffer.data());
        request->Size = FIELD_OFFSET(KNDBG_READ_REQUEST, Data);
        request->Address = address;
        request->Length = length;
        request->Flags = flags;

        DWORD returned = 0;
        if (!Ioctl(IOCTL_KNDBG_READ_VIRTUAL, buffer.data(), FIELD_OFFSET(KNDBG_READ_REQUEST, Data), bufferLength, &returned, error))
        {
            break;
        }

        if (returned < FIELD_OFFSET(KNDBG_READ_REQUEST, Data))
        {
            if (error != nullptr)
            {
                *error = L"Short read response";
            }
            break;
        }

        uint32_t copied = reinterpret_cast<KNDBG_READ_REQUEST*>(buffer.data())->Length;
        if (copied > length)
        {
            if (error != nullptr)
            {
                *error = L"Invalid copied length";
            }
            break;
        }

        if (returned < FIELD_OFFSET(KNDBG_READ_REQUEST, Data) + copied)
        {
            if (error != nullptr)
            {
                *error = L"Short read data response";
            }
            break;
        }

        bytes->assign(buffer.begin() + FIELD_OFFSET(KNDBG_READ_REQUEST, Data), buffer.begin() + FIELD_OFFSET(KNDBG_READ_REQUEST, Data) + copied);
        ok = true;
    } while (false);

    return ok;
}

bool DeviceClient::ReadProcessVirtual(
    uint32_t processId,
    uint64_t expectedEprocess,
    uint64_t expectedCreateTime,
    uint64_t address,
    uint32_t length,
    std::vector<uint8_t>* bytes,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (bytes != nullptr)
        {
            bytes->clear();
        }
        if (bytes == nullptr ||
            processId == 0 ||
            expectedEprocess == 0 ||
            expectedCreateTime == 0 ||
            length == 0 ||
            length > KNDBG_MAX_TRANSFER_SIZE)
        {
            if (error != nullptr)
            {
                *error =
                    L"Invalid process virtual read request";
            }
            break;
        }

        const DWORD headerLength =
            FIELD_OFFSET(
                KNDBG_PROCESS_VIRTUAL_READ_REQUEST,
                Data);
        const DWORD bufferLength = headerLength + length;
        if (bufferLength < headerLength)
        {
            if (error != nullptr)
            {
                *error =
                    L"Process virtual read buffer overflow";
            }
            break;
        }

        std::vector<uint8_t> buffer(bufferLength);
        KNDBG_PROCESS_VIRTUAL_READ_REQUEST* request =
            reinterpret_cast<
                KNDBG_PROCESS_VIRTUAL_READ_REQUEST*>(
                    buffer.data());
        request->Size = headerLength;
        request->ProcessId = processId;
        request->ExpectedEprocess = expectedEprocess;
        request->ExpectedCreateTime =
            expectedCreateTime;
        request->Address = address;
        request->Length = length;

        DWORD returned = 0;
        if (!Ioctl(
                IOCTL_KNDBG_READ_PROCESS_VIRTUAL,
                buffer.data(),
                headerLength,
                bufferLength,
                &returned,
                error))
        {
            break;
        }
        if (returned < headerLength)
        {
            if (error != nullptr)
            {
                *error =
                    L"Short process virtual read response";
            }
            break;
        }

        const KNDBG_PROCESS_VIRTUAL_READ_REQUEST* response =
            reinterpret_cast<
                const KNDBG_PROCESS_VIRTUAL_READ_REQUEST*>(
                    buffer.data());
        if (response->Size != bufferLength ||
            response->Flags != 0 ||
            response->Reserved != 0 ||
            response->Reserved2 != 0 ||
            response->ProcessId != processId ||
            response->ExpectedEprocess != expectedEprocess ||
            response->ExpectedCreateTime !=
                expectedCreateTime ||
            response->Address != address ||
            response->Length != length ||
            returned < headerLength + length)
        {
            if (error != nullptr)
            {
                *error =
                    L"Invalid process virtual read response";
            }
            break;
        }

        bytes->assign(
            buffer.begin() + headerLength,
            buffer.begin() + headerLength + length);
        ok = true;
    } while (false);

    return ok;
}

bool DeviceClient::WriteMemory(uint64_t address, const std::vector<uint8_t>& bytes, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (bytes.empty() || bytes.size() > KNDBG_MAX_TRANSFER_SIZE)
        {
            if (error != nullptr)
            {
                *error = L"Invalid write length";
            }
            break;
        }

        DWORD bufferLength = static_cast<DWORD>(FIELD_OFFSET(KNDBG_WRITE_REQUEST, Data) + bytes.size());
        std::vector<uint8_t> buffer(bufferLength);
        KNDBG_WRITE_REQUEST* request = reinterpret_cast<KNDBG_WRITE_REQUEST*>(buffer.data());
        request->Size = bufferLength;
        request->Address = address;
        request->Length = static_cast<uint32_t>(bytes.size());
        request->Acknowledge = KNDBG_WRITE_ACK_MAGIC;
        memcpy(request->Data, bytes.data(), bytes.size());

        DWORD returned = 0;
        if (!Ioctl(IOCTL_KNDBG_WRITE_VIRTUAL, buffer.data(), bufferLength, bufferLength, &returned, error))
        {
            break;
        }

        if (returned < FIELD_OFFSET(KNDBG_WRITE_REQUEST, Data))
        {
            if (error != nullptr)
            {
                *error = L"Short write response header";
            }
            break;
        }

        if (request->Length != bytes.size())
        {
            if (error != nullptr)
            {
                *error = L"Short write: requested=" + std::to_wstring(bytes.size()) +
                         L" written=" + std::to_wstring(request->Length);
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool DeviceClient::QueryAddress(uint64_t address, uint32_t length, AddressQueryInfo* info, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (info == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid query output";
            }
            break;
        }

        if (length == 0 || length > KNDBG_MAX_TRANSFER_SIZE)
        {
            if (error != nullptr)
            {
                *error = L"Invalid query length";
            }
            break;
        }

        *info = AddressQueryInfo{};

        KNDBG_ADDRESS_QUERY_REQUEST request = {};
        request.Size = sizeof(request);
        request.Address = address;
        request.Length = length;

        union
        {
            KNDBG_ADDRESS_QUERY_REQUEST Request;
            KNDBG_ADDRESS_QUERY_RESPONSE Response;
        } buffer = {};

        buffer.Request = request;

        DWORD returned = 0;
        if (!Ioctl(IOCTL_KNDBG_QUERY_ADDRESS, &buffer, sizeof(request), sizeof(buffer.Response), &returned, error))
        {
            break;
        }

        if (returned < sizeof(KNDBG_ADDRESS_QUERY_RESPONSE))
        {
            if (error != nullptr)
            {
                *error = L"Short query response";
            }
            break;
        }

        info->Address = buffer.Response.Address;
        info->RequestedLength = buffer.Response.RequestedLength;
        info->ProbedLength = buffer.Response.ProbedLength;
        info->IsReadable = buffer.Response.IsReadable != 0;
        info->WriteGateEnabled =
            buffer.Response.IsWritable != 0 ||
            (buffer.Response.Reserved & KNDBG_ADDRESS_QUERY_RESERVED_WRITE_GATE) != 0;

        ok = true;
    } while (false);

    return ok;
}

bool DeviceClient::QueryAddress(uint64_t address, uint32_t length, std::wstring* summary, std::wstring* error)
{
    AddressQueryInfo info = {};
    if (!QueryAddress(address, length, &info, error))
    {
        return false;
    }

    if (summary != nullptr)
    {
        std::wstringstream stream;
        stream << L"address=0x" << std::hex << info.Address
               << L" readable=" << std::dec << (info.IsReadable ? 1 : 0)
               << L" write_gate=" << (info.WriteGateEnabled ? 1 : 0)
               << L" pte_writable=n/a"
               << L" probed=" << info.ProbedLength
               << L" requested=" << info.RequestedLength
               << L" probe_scope=current_as"
               << L" note=first_byte";
        *summary = stream.str();
    }

    return true;
}

bool DeviceClient::TranslateVirtual(
    uint64_t directoryTableBase,
    uint64_t virtualAddress,
    uint32_t length,
    PhysicalTranslationInfo* info,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (info == nullptr || length == 0 || length > KNDBG_MAX_TRANSFER_SIZE)
        {
            if (error != nullptr)
            {
                *error = L"Invalid translation request";
            }
            break;
        }

        union
        {
            KNDBG_TRANSLATE_VIRTUAL_REQUEST Request;
            KNDBG_TRANSLATE_VIRTUAL_RESPONSE Response;
        } buffer = {};

        buffer.Request.Size = sizeof(KNDBG_TRANSLATE_VIRTUAL_REQUEST);
        buffer.Request.DirectoryTableBase = directoryTableBase;
        buffer.Request.VirtualAddress = virtualAddress;
        buffer.Request.Length = length;

        DWORD returned = 0;
        if (!Ioctl(
                IOCTL_KNDBG_TRANSLATE_VIRTUAL,
                &buffer,
                sizeof(KNDBG_TRANSLATE_VIRTUAL_REQUEST),
                sizeof(KNDBG_TRANSLATE_VIRTUAL_RESPONSE),
                &returned,
                error))
        {
            break;
        }

        if (returned < sizeof(KNDBG_TRANSLATE_VIRTUAL_RESPONSE))
        {
            if (error != nullptr)
            {
                *error = L"Short translation response";
            }
            break;
        }

        info->Flags = buffer.Response.Flags;
        info->DirectoryTableBase = buffer.Response.DirectoryTableBase;
        info->VirtualAddress = buffer.Response.VirtualAddress;
        info->PhysicalAddress = buffer.Response.PhysicalAddress;
        info->PageSize = buffer.Response.PageSize;
        info->PageOffset = buffer.Response.PageOffset;
        info->PageBytes = buffer.Response.PageBytes;
        info->RequestedLength = buffer.Response.RequestedLength;
        info->TranslatedLength = buffer.Response.TranslatedLength;
        info->PagingLevels = buffer.Response.PagingLevels;
        info->Pml4e = buffer.Response.Pml4e;
        info->Pml5e = buffer.Response.Pml5e;
        info->Pdpte = buffer.Response.Pdpte;
        info->Pde = buffer.Response.Pde;
        info->Pte = buffer.Response.Pte;
        info->Pml5eAddress = buffer.Response.Pml5eAddress;
        info->Pml4eAddress = buffer.Response.Pml4eAddress;
        info->PdpteAddress = buffer.Response.PdpteAddress;
        info->PdeAddress = buffer.Response.PdeAddress;
        info->PteAddress = buffer.Response.PteAddress;

        ok = true;
    } while (false);

    return ok;
}

bool DeviceClient::FlushVirtual(uint64_t virtualAddress, uint32_t length, std::wstring* error)
{
    return FlushVirtual(virtualAddress, length, 0, 0, error);
}

bool DeviceClient::FlushVirtual(
    uint64_t virtualAddress,
    uint32_t length,
    uint32_t processId,
    uint64_t directoryTableBase,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (length == 0 || length > KNDBG_MAX_TRANSFER_SIZE)
        {
            if (error != nullptr)
            {
                *error = L"Invalid virtual flush length";
            }
            break;
        }

        KNDBG_FLUSH_VIRTUAL_REQUEST request = {};
        request.Size = sizeof(KNDBG_FLUSH_VIRTUAL_REQUEST);
        request.VirtualAddress = virtualAddress;
        request.Length = length;
        request.ProcessId = processId;
        request.Acknowledge = KNDBG_WRITE_ACK_MAGIC;
        request.DirectoryTableBase = directoryTableBase;
        if (directoryTableBase != 0)
        {
            request.Flags |= KNDBG_FLUSH_FLAG_PROCESS_DTB;
        }

        DWORD returned = 0;
        if (!Ioctl(
                IOCTL_KNDBG_FLUSH_VIRTUAL,
                &request,
                sizeof(request),
                sizeof(request),
                &returned,
                error))
        {
            break;
        }

        if (returned < sizeof(KNDBG_FLUSH_VIRTUAL_REQUEST))
        {
            if (error != nullptr)
            {
                *error = L"Short virtual flush response";
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool DeviceClient::SetProcessProtection(
    uint32_t processId,
    uint32_t protectionFieldOffset,
    uint8_t  newProtection,
    uint8_t* oldProtection,
    uint8_t* readBackProtection,
    uint64_t* eprocessAddress,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (processId == 0 || protectionFieldOffset == 0 || protectionFieldOffset > 0x2000)
        {
            if (error != nullptr)
            {
                *error = L"Invalid SetProcessProtection request";
            }
            break;
        }

        union
        {
            KNDBG_SET_PROCESS_PROTECTION_REQUEST Request;
            KNDBG_SET_PROCESS_PROTECTION_RESPONSE Response;
            unsigned char Padding[
                sizeof(KNDBG_SET_PROCESS_PROTECTION_REQUEST) >= sizeof(KNDBG_SET_PROCESS_PROTECTION_RESPONSE)
                    ? sizeof(KNDBG_SET_PROCESS_PROTECTION_REQUEST)
                    : sizeof(KNDBG_SET_PROCESS_PROTECTION_RESPONSE)];
        } buffer = {};

        buffer.Request.Size = sizeof(KNDBG_SET_PROCESS_PROTECTION_REQUEST);
        buffer.Request.ProcessId = processId;
        buffer.Request.ProtectionFieldOffset = protectionFieldOffset;
        buffer.Request.NewProtection = newProtection;
        buffer.Request.Acknowledge = KNDBG_WRITE_ACK_MAGIC;

        DWORD returned = 0;
        if (!Ioctl(
                IOCTL_KNDBG_SET_PROCESS_PROTECTION,
                &buffer,
                sizeof(KNDBG_SET_PROCESS_PROTECTION_REQUEST),
                sizeof(KNDBG_SET_PROCESS_PROTECTION_RESPONSE),
                &returned,
                error))
        {
            break;
        }

        if (returned < sizeof(KNDBG_SET_PROCESS_PROTECTION_RESPONSE))
        {
            if (error != nullptr)
            {
                *error = L"Short SetProcessProtection response";
            }
            break;
        }

        if (oldProtection != nullptr)
        {
            *oldProtection = buffer.Response.OldProtection;
        }
        if (readBackProtection != nullptr)
        {
            *readBackProtection = buffer.Response.ReadBackProtection;
        }
        if (eprocessAddress != nullptr)
        {
            *eprocessAddress = buffer.Response.EprocessAddress;
        }

        ok = true;
    } while (false);

    return ok;
}

bool DeviceClient::SetProcessLogging(
    uint32_t processId,
    uint32_t loggingFlags,
    uint32_t* appliedFlags,
    uint32_t* informationClassUsed,
    uint32_t* ntStatus,
    uint64_t* eprocessAddress,
    std::wstring* error,
    bool disable)
{
    bool ok = false;

    do
    {
        if (processId == 0)
        {
            if (error != nullptr)
            {
                *error = L"Invalid SetProcessLogging request";
            }
            break;
        }

        union
        {
            KNDBG_SET_PROCESS_LOGGING_REQUEST Request;
            KNDBG_SET_PROCESS_LOGGING_RESPONSE Response;
            unsigned char Padding[
                sizeof(KNDBG_SET_PROCESS_LOGGING_REQUEST) >= sizeof(KNDBG_SET_PROCESS_LOGGING_RESPONSE)
                    ? sizeof(KNDBG_SET_PROCESS_LOGGING_REQUEST)
                    : sizeof(KNDBG_SET_PROCESS_LOGGING_RESPONSE)];
        } buffer = {};

        buffer.Request.Size = sizeof(KNDBG_SET_PROCESS_LOGGING_REQUEST);
        buffer.Request.ProcessId = processId;
        buffer.Request.Flags = disable ? KNDBG_SET_PROCESS_LOGGING_FLAG_DISABLE : 0;
        buffer.Request.LoggingFlags = disable
            ? 0
            : ((loggingFlags == 0) ? KNDBG_PROCESS_LOG_DEFAULT : loggingFlags);
        buffer.Request.Acknowledge = KNDBG_WRITE_ACK_MAGIC;

        DWORD returned = 0;
        if (!Ioctl(
                IOCTL_KNDBG_SET_PROCESS_LOGGING,
                &buffer,
                sizeof(KNDBG_SET_PROCESS_LOGGING_REQUEST),
                sizeof(KNDBG_SET_PROCESS_LOGGING_RESPONSE),
                &returned,
                error))
        {
            break;
        }

        if (returned < sizeof(KNDBG_SET_PROCESS_LOGGING_RESPONSE))
        {
            if (error != nullptr)
            {
                *error = L"Short SetProcessLogging response";
            }
            break;
        }

        if (appliedFlags != nullptr)
        {
            *appliedFlags = buffer.Response.LoggingFlagsApplied;
        }
        if (informationClassUsed != nullptr)
        {
            *informationClassUsed = buffer.Response.InformationClassUsed;
        }
        if (ntStatus != nullptr)
        {
            *ntStatus = buffer.Response.NtStatus;
        }
        if (eprocessAddress != nullptr)
        {
            *eprocessAddress = buffer.Response.EprocessAddress;
        }

        ok = true;
    } while (false);

    return ok;
}

bool DeviceClient::ReadPhysical(uint64_t physicalAddress, uint32_t length, std::vector<uint8_t>* bytes, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (bytes == nullptr || length == 0 || length > KNDBG_MAX_TRANSFER_SIZE)
        {
            if (error != nullptr)
            {
                *error = L"Invalid physical read length";
            }
            break;
        }

        DWORD bufferLength = FIELD_OFFSET(KNDBG_PHYSICAL_READ_REQUEST, Data) + length;
        std::vector<uint8_t> buffer(bufferLength);
        KNDBG_PHYSICAL_READ_REQUEST* request = reinterpret_cast<KNDBG_PHYSICAL_READ_REQUEST*>(buffer.data());
        request->Size = FIELD_OFFSET(KNDBG_PHYSICAL_READ_REQUEST, Data);
        request->PhysicalAddress = physicalAddress;
        request->Length = length;

        DWORD returned = 0;
        if (!Ioctl(
                IOCTL_KNDBG_READ_PHYSICAL,
                buffer.data(),
                FIELD_OFFSET(KNDBG_PHYSICAL_READ_REQUEST, Data),
                bufferLength,
                &returned,
                error))
        {
            break;
        }

        if (returned < FIELD_OFFSET(KNDBG_PHYSICAL_READ_REQUEST, Data))
        {
            if (error != nullptr)
            {
                *error = L"Short physical read response";
            }
            break;
        }

        uint32_t copied = reinterpret_cast<KNDBG_PHYSICAL_READ_REQUEST*>(buffer.data())->Length;
        if (copied > length)
        {
            if (error != nullptr)
            {
                *error = L"Invalid physical copied length";
            }
            break;
        }

        if (returned < FIELD_OFFSET(KNDBG_PHYSICAL_READ_REQUEST, Data) + copied)
        {
            if (error != nullptr)
            {
                *error = L"Short physical read data response";
            }
            break;
        }

        bytes->assign(
            buffer.begin() + FIELD_OFFSET(KNDBG_PHYSICAL_READ_REQUEST, Data),
            buffer.begin() + FIELD_OFFSET(KNDBG_PHYSICAL_READ_REQUEST, Data) + copied);
        ok = true;
    } while (false);

    return ok;
}

bool DeviceClient::GetPhysicalMemoryRanges(
    std::vector<PhysicalMemoryRange>* ranges,
    uint64_t* totalBytes,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (ranges == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid physical-range output";
            }
            break;
        }

        ranges->clear();
        if (totalBytes != nullptr)
        {
            *totalBytes = 0;
        }

        KNDBG_PHYSICAL_RANGES_RESPONSE response = {};
        DWORD returned = 0;
        if (!Ioctl(
                IOCTL_KNDBG_GET_PHYSICAL_RANGES,
                &response,
                0,
                sizeof(response),
                &returned,
                error))
        {
            break;
        }

        if (returned < sizeof(response) ||
            response.RangeCount > KNDBG_MAX_PHYSICAL_RANGES)
        {
            if (error != nullptr)
            {
                *error = L"Short or invalid physical-range response";
            }
            break;
        }

        uint64_t summed = 0;
        bool overflow = false;
        ranges->reserve(response.RangeCount);
        for (uint32_t index = 0; index < response.RangeCount; ++index)
        {
            const KNDBG_PHYSICAL_RANGE& entry = response.Ranges[index];
            if (entry.ByteCount == 0)
            {
                continue;
            }

            if (summed > (std::numeric_limits<uint64_t>::max)() - entry.ByteCount)
            {
                overflow = true;
                break;
            }

            PhysicalMemoryRange range = {};
            range.BaseAddress = entry.BaseAddress;
            range.ByteCount = entry.ByteCount;
            ranges->push_back(range);
            summed += entry.ByteCount;
        }

        if (overflow)
        {
            ranges->clear();
            if (error != nullptr)
            {
                *error = L"Physical-range byte count overflow";
            }
            break;
        }

        if (totalBytes != nullptr)
        {
            *totalBytes = summed;
        }

        ok = true;
    } while (false);

    return ok;
}

bool DeviceClient::WritePhysical(uint64_t physicalAddress, const std::vector<uint8_t>& bytes, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (bytes.empty() || bytes.size() > KNDBG_MAX_TRANSFER_SIZE)
        {
            if (error != nullptr)
            {
                *error = L"Invalid physical write length";
            }
            break;
        }

        DWORD bufferLength = static_cast<DWORD>(FIELD_OFFSET(KNDBG_PHYSICAL_WRITE_REQUEST, Data) + bytes.size());
        std::vector<uint8_t> buffer(bufferLength);
        KNDBG_PHYSICAL_WRITE_REQUEST* request = reinterpret_cast<KNDBG_PHYSICAL_WRITE_REQUEST*>(buffer.data());
        request->Size = bufferLength;
        request->PhysicalAddress = physicalAddress;
        request->Length = static_cast<uint32_t>(bytes.size());
        request->Acknowledge = KNDBG_WRITE_ACK_MAGIC;
        memcpy(request->Data, bytes.data(), bytes.size());

        DWORD returned = 0;
        if (!Ioctl(IOCTL_KNDBG_WRITE_PHYSICAL, buffer.data(), bufferLength, bufferLength, &returned, error))
        {
            break;
        }

        if (returned < FIELD_OFFSET(KNDBG_PHYSICAL_WRITE_REQUEST, Data))
        {
            if (error != nullptr)
            {
                *error = L"Short physical write response header";
            }
            break;
        }

        if (request->Length != bytes.size())
        {
            if (error != nullptr)
            {
                *error = L"Short physical write: requested=" + std::to_wstring(bytes.size()) +
                         L" written=" + std::to_wstring(request->Length);
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}
