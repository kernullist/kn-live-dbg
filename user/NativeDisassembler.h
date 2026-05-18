#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct NativeDisassemblyResult
{
    std::wstring Text;
    uint64_t NextOffset;
    uint32_t InstructionsDecoded;
    uint32_t BytesConsumed;
};

bool DisassembleX64CodeBytes(
    uint64_t address,
    const std::vector<uint8_t>& bytes,
    uint32_t instructionCount,
    NativeDisassemblyResult* result,
    std::wstring* error);
