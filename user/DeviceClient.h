#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

struct PhysicalTranslationInfo
{
    uint32_t Flags;
    uint64_t DirectoryTableBase;
    uint64_t VirtualAddress;
    uint64_t PhysicalAddress;
    uint64_t PageSize;
    uint64_t PageOffset;
    uint64_t PageBytes;
    uint32_t RequestedLength;
    uint32_t TranslatedLength;
    uint64_t Pml4e;
    uint64_t Pml5e;
    uint64_t Pdpte;
    uint64_t Pde;
    uint64_t Pte;
};

struct DriverSessionStatus
{
    uint32_t Flags;
    uint32_t OwnerPid;
    uint32_t CurrentPid;
    uint32_t OpenHandleCount;
};

struct ProcessAddressContext
{
    uint32_t Flags;
    uint32_t ProcessId;
    uint64_t Eprocess;
    uint64_t DirectoryTableBase;
    uint64_t UserDirectoryTableBase;
};

class DeviceClient
{
public:
    DeviceClient();
    ~DeviceClient();

    bool Open(std::wstring* error);
    void Close();
    bool IsOpen() const;

    bool QueryVersion(std::wstring* error);
    bool QuerySessionStatus(DriverSessionStatus* status, std::wstring* error);
    bool ResolveProcess(
        uint32_t processId,
        uint32_t directoryTableBaseOffset,
        uint32_t userDirectoryTableBaseOffset,
        ProcessAddressContext* context,
        std::wstring* error);
    bool SetWriteMode(bool enabled, std::wstring* error);
    bool ReadMemory(uint64_t address, uint32_t length, std::vector<uint8_t>* bytes, std::wstring* error);
    bool WriteMemory(uint64_t address, const std::vector<uint8_t>& bytes, std::wstring* error);
    bool QueryAddress(uint64_t address, uint32_t length, std::wstring* summary, std::wstring* error);
    bool TranslateVirtual(
        uint64_t directoryTableBase,
        uint64_t virtualAddress,
        uint32_t length,
        PhysicalTranslationInfo* info,
        std::wstring* error);
    bool ReadPhysical(uint64_t physicalAddress, uint32_t length, std::vector<uint8_t>* bytes, std::wstring* error);
    bool WritePhysical(uint64_t physicalAddress, const std::vector<uint8_t>& bytes, std::wstring* error);

private:
    bool Ioctl(DWORD code, void* buffer, DWORD inLength, DWORD outLength, DWORD* returned, std::wstring* error);

    HANDLE device_;
};
