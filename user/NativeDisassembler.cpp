#include "NativeDisassembler.h"

#include <Zydis.h>

#include <iomanip>
#include <sstream>

static std::wstring AsciiToWide(const char* text)
{
    std::wstring result;

    do
    {
        if (text == nullptr)
        {
            break;
        }

        while (*text != 0)
        {
            result.push_back(static_cast<wchar_t>(static_cast<unsigned char>(*text)));
            ++text;
        }
    } while (false);

    return result;
}

static std::wstring FormatDisassemblyAddress(uint64_t address)
{
    std::wstringstream stream;

    stream << std::hex << std::nouppercase << std::setfill(L'0')
           << std::setw(8) << static_cast<uint32_t>(address >> 32)
           << L"`"
           << std::setw(8) << static_cast<uint32_t>(address & 0xffffffffu)
           << std::dec;

    return stream.str();
}

static std::wstring FormatInstructionBytes(const uint8_t* bytes, uint8_t length)
{
    std::wstringstream stream;

    for (uint8_t index = 0; index < length; ++index)
    {
        stream << std::hex << std::nouppercase << std::setfill(L'0')
               << std::setw(2) << static_cast<uint32_t>(bytes[index]);
    }

    return stream.str();
}

static bool IsNativeFunctionTerminal(const ZydisDisassembledInstruction& instruction)
{
    bool terminal = false;

    switch (instruction.info.meta.category)
    {
    case ZYDIS_CATEGORY_RET:
        terminal = true;
        break;
    default:
        break;
    }

    if (!terminal)
    {
        switch (instruction.info.mnemonic)
        {
        case ZYDIS_MNEMONIC_INT3:
        case ZYDIS_MNEMONIC_IRET:
        case ZYDIS_MNEMONIC_IRETD:
        case ZYDIS_MNEMONIC_IRETQ:
        case ZYDIS_MNEMONIC_SYSEXIT:
        case ZYDIS_MNEMONIC_SYSRET:
        case ZYDIS_MNEMONIC_HLT:
        case ZYDIS_MNEMONIC_UD2:
            terminal = true;
            break;
        default:
            break;
        }
    }

    return terminal;
}

static bool DisassembleX64BytesInternal(
    uint64_t address,
    const std::vector<uint8_t>& bytes,
    uint32_t instructionLimit,
    bool stopAtFunctionEnd,
    NativeDisassemblyResult* result,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr || instructionLimit == 0)
        {
            if (error != nullptr)
            {
                *error = L"Invalid native disassembly request";
            }
            break;
        }

        result->Text.clear();
        result->NextOffset = address;
        result->InstructionsDecoded = 0;
        result->BytesConsumed = 0;

        if (bytes.empty())
        {
            if (error != nullptr)
            {
                *error = L"No code bytes were read";
            }
            break;
        }

        size_t offset = 0;
        uint64_t current = address;
        std::wstringstream output;

        while (result->InstructionsDecoded < instructionLimit && offset < bytes.size())
        {
            ZydisDisassembledInstruction instruction = {};
            ZyanStatus status = ZydisDisassembleIntel(
                ZYDIS_MACHINE_MODE_LONG_64,
                current,
                bytes.data() + offset,
                bytes.size() - offset,
                &instruction);

            if (!ZYAN_SUCCESS(status))
            {
                if (result->InstructionsDecoded == 0 && error != nullptr)
                {
                    std::wstringstream stream;
                    stream << L"Zydis decode failed at "
                           << FormatDisassemblyAddress(current)
                           << L" status=0x"
                           << std::hex << static_cast<uint32_t>(status) << std::dec;
                    *error = stream.str();
                }
                break;
            }

            if (instruction.info.length == 0 ||
                instruction.info.length > 15 ||
                offset + instruction.info.length > bytes.size())
            {
                if (result->InstructionsDecoded == 0 && error != nullptr)
                {
                    *error = L"Zydis decoded an invalid instruction length";
                }
                break;
            }

            std::wstring byteText = FormatInstructionBytes(bytes.data() + offset, instruction.info.length);
            output << FormatDisassemblyAddress(current)
                   << L"  "
                   << std::left << std::setw(18) << std::setfill(L' ') << byteText
                   << L" "
                   << AsciiToWide(instruction.text)
                   << L"\n";

            offset += instruction.info.length;
            current += instruction.info.length;
            result->InstructionsDecoded += 1;
            result->BytesConsumed = static_cast<uint32_t>(offset);
            result->NextOffset = current;

            if (stopAtFunctionEnd && IsNativeFunctionTerminal(instruction))
            {
                break;
            }
        }

        if (result->InstructionsDecoded == 0)
        {
            if (error != nullptr && error->empty())
            {
                *error = L"Native disassembly produced no instructions";
            }
            break;
        }

        result->Text = output.str();
        ok = true;
    } while (false);

    return ok;
}

bool DisassembleX64CodeBytes(
    uint64_t address,
    const std::vector<uint8_t>& bytes,
    uint32_t instructionCount,
    NativeDisassemblyResult* result,
    std::wstring* error)
{
    return DisassembleX64BytesInternal(address, bytes, instructionCount, false, result, error);
}

bool DisassembleX64FunctionBytes(
    uint64_t address,
    const std::vector<uint8_t>& bytes,
    uint32_t maxInstructions,
    NativeDisassemblyResult* result,
    std::wstring* error)
{
    return DisassembleX64BytesInternal(address, bytes, maxInstructions, true, result, error);
}
