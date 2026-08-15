#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

// Shared helpers for leftover-payload, mapper-remnant, and orphan-page
// scanners. No new driver IOCTL.

constexpr uint64_t kLeftoverKernelMinLa48 = 0xFFFF800000000000ull;
constexpr uint64_t kLeftoverSessionSpaceMin = 0xFFFFF90000000000ull;
constexpr uint64_t kLeftoverSessionSpaceEnd = 0xFFFFF98000000000ull;
constexpr uint32_t kLeftoverPageShift = 12;
constexpr uint32_t kLeftoverPageSize = 0x1000;
constexpr uint32_t kLeftoverMaxUnicodeBytes = 512;

struct LeftoverModuleRange
{
    uint64_t Base = 0;
    uint64_t End = 0;
    std::wstring Name;
};

struct LeftoverBigPoolEntry
{
    uint64_t VirtualAddress = 0;
    uint64_t SizeInBytes = 0;
    uint32_t TagRaw = 0;
    bool NonPaged = false;
};

struct LeftoverBigPoolSnapshot
{
    std::vector<LeftoverBigPoolEntry> Entries;
    std::vector<std::wstring> Warnings;
    uint64_t TotalEntries = 0;
    bool Queried = false;
    bool PrivilegeEnabled = false;
};

bool LeftoverTryAdd(uint64_t left, uint64_t right, uint64_t* result);
bool LeftoverIsKernelCanonical(uint64_t address);
bool LeftoverIsLikelyUserAddress(uint64_t address);
uint64_t LeftoverSignExtendVa(uint64_t address, bool la57);
bool LeftoverIsSessionSpace(uint64_t address);
bool LeftoverIsPageTableSelfMap(uint64_t address, uint64_t pteBase, bool la57);
uint64_t LeftoverDecodeVaFromPteAddress(uint64_t pteAddress, uint64_t pteBase, bool la57);

bool LeftoverReadBytes(
    DeviceClient& device,
    uint64_t address,
    uint32_t length,
    std::vector<uint8_t>* bytes,
    std::wstring* error);
bool LeftoverReadU16(DeviceClient& device, uint64_t address, uint16_t* value, std::wstring* error);
bool LeftoverReadU32(DeviceClient& device, uint64_t address, uint32_t* value, std::wstring* error);
bool LeftoverReadU64(DeviceClient& device, uint64_t address, uint64_t* value, std::wstring* error);
bool LeftoverReadPhysicalPage(
    DeviceClient& device,
    uint64_t physicalAddress,
    std::vector<uint8_t>* page,
    std::wstring* error);

bool LeftoverLooksLikeUnicodeString(uint16_t length, uint16_t maximumLength, uint64_t buffer);
bool LeftoverReadUnicodeString(
    DeviceClient& device,
    SymbolEngine& symbols,
    uint64_t address,
    std::wstring* value,
    std::wstring* error);

void LeftoverBuildModuleRanges(
    const SymbolEngine& symbols,
    std::vector<LeftoverModuleRange>* ranges);
const LeftoverModuleRange* LeftoverFindModule(
    const std::vector<LeftoverModuleRange>& ranges,
    uint64_t address);
std::wstring LeftoverModuleBaseName(const std::wstring& pathOrName);
bool LeftoverNamesMatch(const std::wstring& left, const std::wstring& right);
bool LeftoverLooksLikeDriverName(const std::wstring& name);

bool LeftoverQueryBigPool(LeftoverBigPoolSnapshot* snapshot, std::wstring* error);
const LeftoverBigPoolEntry* LeftoverFindBigPool(
    const LeftoverBigPoolSnapshot& snapshot,
    uint64_t address);

std::wstring LeftoverFormatHex(uint64_t value, int width);
std::wstring LeftoverFormatTag(uint32_t tagRaw);
void LeftoverAppendNote(std::wstring* notes, const std::wstring& note);

// Driver-free invariants used by the console-surface self-test.
bool LeftoverCommonSelfTest();
