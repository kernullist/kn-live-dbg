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
    uint32_t PagingLevels;
    uint64_t Pml4e;
    uint64_t Pml5e;
    uint64_t Pdpte;
    uint64_t Pde;
    uint64_t Pte;
    uint64_t Pml5eAddress;
    uint64_t Pml4eAddress;
    uint64_t PdpteAddress;
    uint64_t PdeAddress;
    uint64_t PteAddress;
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

struct ControlRegisters
{
    uint32_t ProcessorNumber;
    uint64_t Cr0;
    uint64_t Cr2;
    uint64_t Cr3;
    uint64_t Cr4;
    uint64_t Cr8;
};

struct IdtInfo
{
    uint32_t ProcessorNumber;
    uint64_t Base;
    uint32_t Limit;
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
    bool ReadMemory(
        uint64_t address,
        uint32_t length,
        std::vector<uint8_t>* bytes,
        std::wstring* error,
        uint32_t flags = 0);
    bool WriteMemory(uint64_t address, const std::vector<uint8_t>& bytes, std::wstring* error);
    bool QueryAddress(uint64_t address, uint32_t length, std::wstring* summary, std::wstring* error);
    bool TranslateVirtual(
        uint64_t directoryTableBase,
        uint64_t virtualAddress,
        uint32_t length,
        PhysicalTranslationInfo* info,
        std::wstring* error);
    bool FlushVirtual(uint64_t virtualAddress, uint32_t length, std::wstring* error);
    bool ReadPhysical(uint64_t physicalAddress, uint32_t length, std::vector<uint8_t>* bytes, std::wstring* error);
    bool WritePhysical(uint64_t physicalAddress, const std::vector<uint8_t>& bytes, std::wstring* error);

    // Writes a single byte to (EPROCESS + ProtectionFieldOffset) inside the
    // target process. Returns the old/new/read-back bytes plus the resolved
    // EPROCESS pointer so callers can verify the change took effect. The
    // driver requires write mode to be enabled and the standard write
    // acknowledge magic. Used to flip the calling process to PPL Antimalware
    // for ETW Microsoft-Windows-Threat-Intelligence subscription.
    bool SetProcessProtection(
        uint32_t processId,
        uint32_t protectionFieldOffset,
        uint8_t  newProtection,
        uint8_t* oldProtection,
        uint8_t* readBackProtection,
        uint64_t* eprocessAddress,
        std::wstring* error);

    // Reads one architectural MSR (must be a KNDBG_MSR_* whitelist value) on
    // the requested logical processor. Read-only; does not require write mode.
    // On success, value receives the MSR value and actualProcessor (optional)
    // receives the processor the read actually ran on.
    bool ReadMsr(
        uint32_t msrIndex,
        uint32_t processorNumber,
        uint64_t* value,
        uint32_t* actualProcessor,
        std::wstring* error);

    // Reads the x64 control registers on the requested logical processor.
    // Read-only; does not require write mode.
    bool ReadControlRegisters(
        uint32_t processorNumber,
        ControlRegisters* registers,
        std::wstring* error);

    // Reads the IDTR (base + limit) on the requested logical processor via
    // __sidt. Read-only; does not require write mode.
    bool ReadIdt(
        uint32_t processorNumber,
        IdtInfo* info,
        std::wstring* error);

private:
    bool Ioctl(DWORD code, void* buffer, DWORD inLength, DWORD outLength, DWORD* returned, std::wstring* error);

    HANDLE device_;
};
