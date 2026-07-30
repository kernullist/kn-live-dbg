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

// Current-AS first-byte probe. WriteGateEnabled is session write mode, not PTE.W.
struct AddressQueryInfo
{
    uint64_t Address = 0;
    uint32_t RequestedLength = 0;
    uint32_t ProbedLength = 0;
    bool IsReadable = false;
    bool WriteGateEnabled = false;
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

struct TimelineLiveStatus
{
    uint32_t Flags;
    uint32_t Capacity;
    uint32_t Count;
    uint64_t Dropped;
    uint64_t NextSequence;
};

struct TimelineLiveEvent
{
    uint32_t Type;
    uint32_t Flags;
    uint32_t ProcessId;
    uint32_t ParentProcessId;
    uint32_t ThreadId;
    uint32_t CreatorProcessId;
    uint32_t CreatorThreadId;
    uint64_t Sequence;
    uint64_t Timestamp100ns;
    uint64_t ImageBase;
    uint64_t ImageSize;
    uint64_t FileObject;
    std::wstring ImagePath;
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
        std::wstring* error,
        DWORD* deviceError = nullptr);
    bool SetWriteMode(bool enabled, std::wstring* error);
    bool ReadMemory(
        uint64_t address,
        uint32_t length,
        std::vector<uint8_t>* bytes,
        std::wstring* error,
        uint32_t flags = 0);
    bool ReadProcessVirtual(
        uint32_t processId,
        uint64_t expectedEprocess,
        uint64_t expectedCreateTime,
        uint64_t address,
        uint32_t length,
        std::vector<uint8_t>* bytes,
        std::wstring* error);
    bool WriteMemory(uint64_t address, const std::vector<uint8_t>& bytes, std::wstring* error);
    bool QueryAddress(uint64_t address, uint32_t length, AddressQueryInfo* info, std::wstring* error);
    bool QueryAddress(uint64_t address, uint32_t length, std::wstring* summary, std::wstring* error);
    bool TranslateVirtual(
        uint64_t directoryTableBase,
        uint64_t virtualAddress,
        uint32_t length,
        PhysicalTranslationInfo* info,
        std::wstring* error);
    // Flush VA translations. When processId/directoryTableBase are supplied the
    // driver switches each CPU to that DTB before invlpg (ABI v13+).
    bool FlushVirtual(uint64_t virtualAddress, uint32_t length, std::wstring* error);
    bool FlushVirtual(
        uint64_t virtualAddress,
        uint32_t length,
        uint32_t processId,
        uint64_t directoryTableBase,
        std::wstring* error);
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

    bool ControlTimeline(
        uint32_t action,
        uint32_t capacity,
        std::wstring* error);

    bool QueryTimelineStatus(
        TimelineLiveStatus* status,
        std::wstring* error);

    bool DrainTimelineEvents(
        uint32_t maxEvents,
        std::vector<TimelineLiveEvent>* events,
        TimelineLiveStatus* status,
        std::wstring* error);

private:
    bool Ioctl(
        DWORD code,
        void* buffer,
        DWORD inLength,
        DWORD outLength,
        DWORD* returned,
        std::wstring* error,
        DWORD* deviceError = nullptr);

    HANDLE device_;
};
