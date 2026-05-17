#include "DeviceClient.h"

#include "../shared/KnLiveDbgIoctl.h"

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
    bool ok = false;

    do
    {
        Close();

        device_ = CreateFileW(
            KNDBG_USER_DEVICE_NAME,
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

bool DeviceClient::Ioctl(DWORD code, void* buffer, DWORD inLength, DWORD outLength, DWORD* returned, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (device_ == INVALID_HANDLE_VALUE)
        {
            if (error != nullptr)
            {
                *error = L"Device is not open";
            }
            break;
        }

        DWORD localReturned = 0;
        if (!DeviceIoControl(device_, code, buffer, inLength, buffer, outLength, &localReturned, nullptr))
        {
            if (error != nullptr)
            {
                *error = DeviceErrorText(L"DeviceIoControl failed", GetLastError());
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

bool DeviceClient::SetWriteMode(bool enabled, std::wstring* error)
{
    KNDBG_WRITE_MODE_REQUEST request = {};
    request.Size = sizeof(request);
    request.EnableWrite = enabled ? 1u : 0u;
    request.Acknowledge = KNDBG_WRITE_ACK_MAGIC;

    DWORD returned = 0;
    return Ioctl(IOCTL_KNDBG_SET_WRITE_MODE, &request, sizeof(request), sizeof(request), &returned, error);
}

bool DeviceClient::ReadMemory(uint64_t address, uint32_t length, std::vector<uint8_t>* bytes, std::wstring* error)
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

        bytes->assign(buffer.begin() + FIELD_OFFSET(KNDBG_READ_REQUEST, Data), buffer.begin() + FIELD_OFFSET(KNDBG_READ_REQUEST, Data) + copied);
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

        ok = true;
    } while (false);

    return ok;
}

bool DeviceClient::QueryAddress(uint64_t address, uint32_t length, std::wstring* summary, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (length == 0 || length > KNDBG_MAX_TRANSFER_SIZE)
        {
            if (error != nullptr)
            {
                *error = L"Invalid query length";
            }
            break;
        }

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

        if (summary != nullptr)
        {
            std::wstringstream stream;
            stream << L"address=0x" << std::hex << buffer.Response.Address
                   << L" readable=" << std::dec << buffer.Response.IsReadable
                   << L" writable=" << buffer.Response.IsWritable
                   << L" probed=" << buffer.Response.ProbedLength;
            *summary = stream.str();
        }

        ok = true;
    } while (false);

    return ok;
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
        info->Pml4e = buffer.Response.Pml4e;
        info->Pdpte = buffer.Response.Pdpte;
        info->Pde = buffer.Response.Pde;
        info->Pte = buffer.Response.Pte;

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

        bytes->assign(
            buffer.begin() + FIELD_OFFSET(KNDBG_PHYSICAL_READ_REQUEST, Data),
            buffer.begin() + FIELD_OFFSET(KNDBG_PHYSICAL_READ_REQUEST, Data) + copied);
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

        ok = true;
    } while (false);

    return ok;
}
