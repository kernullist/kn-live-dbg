#include "CallbackScanner.h"
#include "CommandRegistry.h"
#include "DbgEngBackend.h"
#include "DeviceClient.h"
#include "DriverService.h"
#include "SymbolEngine.h"

#include "../shared/KnLiveDbgIoctl.h"

#include <Windows.h>
#include <shellapi.h>

#include <algorithm>
#include <atomic>
#include <cwctype>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static std::atomic_bool g_StopRequested = false;

struct DebuggerState
{
    uint32_t NumberBase;
    bool Quiet;
    std::wstring LastCommand;
    std::wstring DbgEngConnectOptions;
    uint64_t LastDisassemblyAddress;
    bool HasLastDisassemblyAddress;
    enum class BackendMode
    {
        Auto,
        Native,
        DbgEng
    } Backend;
};

static BOOL WINAPI ConsoleHandler(DWORD controlType)
{
    BOOL handled = FALSE;

    switch (controlType)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
        g_StopRequested = true;
        handled = TRUE;
        break;
    default:
        handled = FALSE;
        break;
    }

    return handled;
}

static std::wstring ToLower(const std::wstring& value)
{
    std::wstring result = value;

    for (wchar_t& ch : result)
    {
        ch = static_cast<wchar_t>(std::towlower(ch));
    }

    return result;
}

static std::wstring NormalizeInputCommand(const std::wstring& value)
{
    std::wstring result;

    if (value == L"dS")
    {
        result = L"du";
    }
    else if (value == L"dW")
    {
        result = L"dw";
    }
    else if (value == L"dD")
    {
        result = L"dq";
    }
    else if (value == L"eD")
    {
        result = L"eq";
    }
    else if (value == L"gN")
    {
        result = L"gn";
    }
    else if (value == L"kP")
    {
        result = L"kp";
    }
    else
    {
        result = ToLower(value);
    }

    return result;
}

static bool IsElevated()
{
    bool elevated = false;
    HANDLE token = nullptr;

    do
    {
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        {
            break;
        }

        TOKEN_ELEVATION elevation = {};
        DWORD returned = 0;
        if (!GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &returned))
        {
            break;
        }

        elevated = elevation.TokenIsElevated != 0;
    } while (false);

    if (token != nullptr)
    {
        CloseHandle(token);
    }

    return elevated;
}

static std::wstring GetExecutableDirectory()
{
    std::wstring result;

    do
    {
        wchar_t path[MAX_PATH] = {};
        DWORD count = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
        if (count == 0 || count >= std::size(path))
        {
            break;
        }

        result = path;
        size_t slash = result.find_last_of(L"\\/");
        if (slash != std::wstring::npos)
        {
            result.resize(slash);
        }
    } while (false);

    return result;
}

static std::vector<std::wstring> Split(const std::wstring& line)
{
    std::vector<std::wstring> parts;
    std::wistringstream stream(line);
    std::wstring part;

    while (stream >> part)
    {
        parts.push_back(part);
    }

    return parts;
}

static std::wstring JoinArgs(const std::vector<std::wstring>& args, size_t first)
{
    std::wstring result;

    for (size_t index = first; index < args.size(); ++index)
    {
        if (!result.empty())
        {
            result += L" ";
        }

        result += args[index];
    }

    if (result.size() >= 2 && result.front() == L'"' && result.back() == L'"')
    {
        result = result.substr(1, result.size() - 2);
    }

    return result;
}

static void PrintHelp(bool includeDbgEng)
{
    std::wcout << L"KnLiveDbg WinDbg-compatible command surface\n";
    std::wcout << L"usage examples:\n";
    std::wcout << L"  .sympath SRV*C:\\Symbols*https://msdl.microsoft.com/download/symbols\n";
    std::wcout << L"  .reload\n";
    std::wcout << L"  lm nt\n";
    std::wcout << L"  x nt!*Process*\n";
    std::wcout << L"  ln nt!PsLoadedModuleList\n";
    std::wcout << L"  u nt!KiSystemCall64 8\n";
    std::wcout << L"  uf nt!KiSystemCall64\n";
    std::wcout << L"  dq nt!PsLoadedModuleList 8\n";
    std::wcout << L"  dt nt!_EPROCESS <address>\n";
    std::wcout << L"  callbacks all\n";
    std::wcout << L"  vtop nt!PsLoadedModuleList\n";
    std::wcout << L"  pdb <physical-address> 80\n";
    std::wcout << L"  kdinit\n";
    std::wcout << L"  backend dbgeng\n";
    std::wcout << L"  !process 0 0\n";
    std::wcout << L"  write off\n";
    std::wcout << L"  ed <address> <value>\n";
    std::wcout << L"  peq <physical-address> <value>\n";
    std::wcout << L"  drvstatus\n";
    std::wcout << L"\n";
    CommandRegistry::PrintSummary(includeDbgEng);
}

static const wchar_t* BackendModeText(DebuggerState::BackendMode mode)
{
    const wchar_t* text = L"auto";

    if (mode == DebuggerState::BackendMode::Native)
    {
        text = L"native";
    }
    else if (mode == DebuggerState::BackendMode::DbgEng)
    {
        text = L"dbgeng";
    }

    return text;
}

static bool EnsureDbgEng(DbgEngBackend& dbgeng, SymbolEngine& symbols, const DebuggerState& state, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (dbgeng.IsReady())
        {
            ok = true;
            break;
        }

        if (!dbgeng.Initialize(symbols.SymbolPath(), state.DbgEngConnectOptions, error))
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool ExecuteDbgEngCommand(
    DbgEngBackend& dbgeng,
    SymbolEngine& symbols,
    const DebuggerState& state,
    const std::wstring& commandLine,
    bool printFailure)
{
    bool ok = false;
    std::wstring output;
    std::wstring error;

    do
    {
        if (!EnsureDbgEng(dbgeng, symbols, state, &error))
        {
            if (printFailure)
            {
                std::wcerr << L"DbgEng init failed: " << error << L"\n";
            }
            break;
        }

        if (!dbgeng.Execute(commandLine, &output, &error))
        {
            if (printFailure)
            {
                std::wcerr << L"DbgEng command failed: " << error << L"\n";
            }
            break;
        }

        if (!output.empty())
        {
            std::wcout << output;
            if (output.back() != L'\n')
            {
                std::wcout << L"\n";
            }
        }

        ok = true;
    } while (false);

    return ok;
}

static bool ShouldRouteToDbgEng(const std::wstring& command)
{
    bool route = false;

    do
    {
        if (command.empty())
        {
            break;
        }

        if (command[0] == L'!' || command[0] == L'.')
        {
            route = true;
            break;
        }

        const CommandInfo* info = CommandRegistry::Find(command);
        if (info != nullptr && info->Support == CommandSupport::DbgEng)
        {
            route = true;
            break;
        }
    } while (false);

    return route;
}

static bool ParseUnsigned(const std::wstring& value, uint32_t numberBase, uint64_t* output)
{
    bool ok = false;

    do
    {
        if (output == nullptr || value.empty())
        {
            break;
        }

        std::wstring text = value;
        if (!text.empty() && (text[0] == L'L' || text[0] == L'l'))
        {
            text = text.substr(1);
        }

        int base = static_cast<int>(numberBase);
        if (text.size() > 2 && text[0] == L'0' && (text[1] == L'x' || text[1] == L'X'))
        {
            base = 16;
        }
        else if (text.size() > 2 && text[0] == L'0' && (text[1] == L'n' || text[1] == L'N'))
        {
            text = text.substr(2);
            base = 10;
        }
        else if (text.find_first_of(L"abcdefABCDEF") != std::wstring::npos)
        {
            base = 16;
        }

        wchar_t* end = nullptr;
        uint64_t parsed = wcstoull(text.c_str(), &end, base);
        if (end == nullptr || *end != L'\0')
        {
            break;
        }

        *output = parsed;
        ok = true;
    } while (false);

    return ok;
}

static bool ParseAddressOrSymbol(SymbolEngine& symbols, const DebuggerState& state, const std::wstring& value, uint64_t* address, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (address == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid address output";
            }
            break;
        }

        uint64_t parsed = 0;
        if (ParseUnsigned(value, state.NumberBase, &parsed))
        {
            *address = parsed;
            ok = true;
            break;
        }

        if (symbols.ResolveSymbol(value, address, error))
        {
            ok = true;
        }
    } while (false);

    return ok;
}

static std::vector<uint8_t> EncodeInteger(uint64_t value, size_t width)
{
    std::vector<uint8_t> bytes(width);

    for (size_t index = 0; index < width; ++index)
    {
        bytes[index] = static_cast<uint8_t>((value >> (index * 8)) & 0xff);
    }

    return bytes;
}

static uint64_t DecodeInteger(const uint8_t* bytes, size_t width)
{
    uint64_t value = 0;
    size_t effectiveWidth = width < sizeof(value) ? width : sizeof(value);

    for (size_t index = 0; index < effectiveWidth; ++index)
    {
        value |= static_cast<uint64_t>(bytes[index]) << (index * 8);
    }

    return value;
}

static void HexDump(uint64_t address, const std::vector<uint8_t>& bytes)
{
    for (size_t offset = 0; offset < bytes.size(); offset += 16)
    {
        std::wcout << std::hex << std::setw(16) << std::setfill(L'0') << (address + offset) << L"  ";

        for (size_t index = 0; index < 16; ++index)
        {
            if (offset + index < bytes.size())
            {
                std::wcout << std::setw(2) << static_cast<unsigned>(bytes[offset + index]) << L" ";
            }
            else
            {
                std::wcout << L"   ";
            }
        }

        std::wcout << L" ";
        for (size_t index = 0; index < 16 && offset + index < bytes.size(); ++index)
        {
            wchar_t ch = static_cast<wchar_t>(bytes[offset + index]);
            if (ch < 32 || ch > 126)
            {
                ch = L'.';
            }
            std::wcout << ch;
        }

        std::wcout << std::dec << L"\n";
    }
}

static void UnitDump(uint64_t address, const std::vector<uint8_t>& bytes, size_t width, SymbolEngine* symbols)
{
    for (size_t offset = 0; offset + width <= bytes.size(); offset += width)
    {
        uint64_t value = DecodeInteger(bytes.data() + offset, width);
        std::wcout << L"0x" << std::hex << std::setw(16) << std::setfill(L'0') << (address + offset)
                   << L": 0x" << std::setw(static_cast<int>(width * 2)) << value;

        if (symbols != nullptr)
        {
            std::wstring name;
            uint64_t displacement = 0;
            std::wstring ignored;
            if (symbols->FindNearestSymbol(value, &name, &displacement, &ignored))
            {
                std::wcout << L"  " << name;
                if (displacement != 0)
                {
                    std::wcout << L"+0x" << displacement;
                }
            }
        }

        std::wcout << std::dec << L"\n";
    }
}

static void PrintAsciiString(uint64_t address, const std::vector<uint8_t>& bytes)
{
    std::wcout << L"0x" << std::hex << address << L": " << std::dec;

    for (uint8_t ch : bytes)
    {
        if (ch == 0)
        {
            break;
        }

        if (ch < 32 || ch > 126)
        {
            std::wcout << L".";
        }
        else
        {
            std::wcout << static_cast<wchar_t>(ch);
        }
    }

    std::wcout << L"\n";
}

static void PrintUnicodeString(uint64_t address, const std::vector<uint8_t>& bytes)
{
    std::wcout << L"0x" << std::hex << address << L": " << std::dec;

    for (size_t offset = 0; offset + sizeof(wchar_t) <= bytes.size(); offset += sizeof(wchar_t))
    {
        wchar_t ch = 0;
        memcpy(&ch, bytes.data() + offset, sizeof(ch));
        if (ch == 0)
        {
            break;
        }

        if (ch < 32)
        {
            std::wcout << L".";
        }
        else
        {
            std::wcout << ch;
        }
    }

    std::wcout << L"\n";
}

static size_t UnitWidthForDisplayCommand(const std::wstring& command)
{
    size_t width = 1;

    if (command == L"dw")
    {
        width = 2;
    }
    else if (command == L"dd" || command == L"dc" || command == L"df" || command == L"dyd" || command == L"dds")
    {
        width = 4;
    }
    else if (command == L"dq" || command == L"dp" || command == L"dps" || command == L"dqs" ||
             command == L"dda" || command == L"ddp" || command == L"ddu" || command == L"dpa" ||
             command == L"dpp" || command == L"dpu" || command == L"dqa" || command == L"dqp" ||
             command == L"dqu")
    {
        width = 8;
    }

    return width;
}

static bool IsDisplayCommand(const std::wstring& command)
{
    return command == L"d" || command == L"db" || command == L"da" || command == L"dc" ||
        command == L"dd" || command == L"df" || command == L"dp" || command == L"dq" ||
        command == L"du" || command == L"dw" || command == L"dyb" || command == L"dyd" ||
        command == L"dda" || command == L"ddp" || command == L"ddu" || command == L"dpa" ||
        command == L"dpp" || command == L"dpu" || command == L"dqa" || command == L"dqp" ||
        command == L"dqu" || command == L"dds" || command == L"dps" || command == L"dqs" ||
        command == L"ds";
}

static bool IsEnterCommand(const std::wstring& command)
{
    return command == L"e" || command == L"ea" || command == L"eb" || command == L"ed" ||
        command == L"ef" || command == L"ep" || command == L"eq" || command == L"eu" ||
        command == L"ew" || command == L"eza" || command == L"ezu";
}

static size_t UnitWidthForPhysicalDisplayCommand(const std::wstring& command)
{
    size_t width = 1;

    if (command == L"pdw")
    {
        width = 2;
    }
    else if (command == L"pdd")
    {
        width = 4;
    }
    else if (command == L"pdq")
    {
        width = 8;
    }

    return width;
}

static bool IsPhysicalDisplayCommand(const std::wstring& command)
{
    return command == L"phys" || command == L"pdb" || command == L"pdw" ||
        command == L"pdd" || command == L"pdq";
}

static bool IsPhysicalEnterCommand(const std::wstring& command)
{
    return command == L"peb" || command == L"pew" || command == L"ped" || command == L"peq";
}

static bool GetCountArgument(const std::vector<std::wstring>& args, size_t index, uint64_t defaultCount, const DebuggerState& state, uint64_t* count)
{
    bool ok = true;

    do
    {
        if (count == nullptr)
        {
            ok = false;
            break;
        }

        *count = defaultCount;
        if (args.size() <= index)
        {
            break;
        }

        if (!ParseUnsigned(args[index], state.NumberBase, count))
        {
            ok = false;
        }
    } while (false);

    return ok;
}

static bool IsSafeTransferSize(uint64_t byteCount)
{
    return byteCount != 0 && byteCount <= KNDBG_MAX_TRANSFER_SIZE;
}

static bool TryCalculateTransferSize(uint64_t count, uint64_t unit, uint32_t* byteCount)
{
    bool ok = false;

    do
    {
        if (byteCount == nullptr || count == 0 || unit == 0)
        {
            break;
        }

        if (count > (~0ull / unit))
        {
            break;
        }

        uint64_t total = count * unit;
        if (!IsSafeTransferSize(total))
        {
            break;
        }

        *byteCount = static_cast<uint32_t>(total);
        ok = true;
    } while (false);

    return ok;
}

static bool TryAddOffset(uint64_t address, uint64_t offset, uint64_t* result)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            break;
        }

        if (address > (~0ull - offset))
        {
            break;
        }

        *result = address + offset;
        ok = true;
    } while (false);

    return ok;
}

static std::vector<uint8_t> EncodeString(const std::wstring& value, bool unicode, bool zeroTerminate)
{
    std::vector<uint8_t> bytes;

    if (unicode)
    {
        bytes.resize(value.size() * sizeof(wchar_t) + (zeroTerminate ? sizeof(wchar_t) : 0));
        memcpy(bytes.data(), value.data(), value.size() * sizeof(wchar_t));
    }
    else
    {
        for (wchar_t ch : value)
        {
            bytes.push_back(static_cast<uint8_t>(ch & 0xff));
        }

        if (zeroTerminate)
        {
            bytes.push_back(0);
        }
    }

    return bytes;
}

struct DtRequest
{
    std::wstring TypeName;
    bool HasAddress;
    uint64_t Address;
    ULONG RecursionDepth;
    bool Verbose;
    bool Bare;
    std::vector<std::wstring> FieldFilters;
};

static bool ContainsNoCase(const std::wstring& value, const std::wstring& needle)
{
    return ToLower(value).find(ToLower(needle)) != std::wstring::npos;
}

static bool FieldMatchesFilters(const TypeFieldInfo& field, const std::vector<std::wstring>& filters)
{
    bool matches = false;

    do
    {
        if (filters.empty())
        {
            matches = true;
            break;
        }

        for (const std::wstring& filter : filters)
        {
            if (ContainsNoCase(field.Name, filter) || ContainsNoCase(field.TypeName, filter))
            {
                matches = true;
                break;
            }
        }
    } while (false);

    return matches;
}

static bool ParseDtRequest(
    const std::vector<std::wstring>& args,
    const DebuggerState& state,
    SymbolEngine& symbols,
    DtRequest* request,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (request == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid dt request output";
            }
            break;
        }

        *request = {};
        request->RecursionDepth = 0;

        size_t index = 1;
        while (index < args.size() && !args[index].empty() && args[index][0] == L'-')
        {
            std::wstring option = ToLower(args[index]);
            if (option == L"-v")
            {
                request->Verbose = true;
            }
            else if (option == L"-b")
            {
                request->Bare = true;
            }
            else if (option == L"-r")
            {
                request->RecursionDepth = 1;
            }
            else if (option.rfind(L"-r", 0) == 0 && option.size() > 2)
            {
                uint64_t depth = 0;
                if (!ParseUnsigned(option.substr(2), 10, &depth))
                {
                    if (error != nullptr)
                    {
                        *error = L"Invalid dt recursion depth";
                    }
                    break;
                }
                request->RecursionDepth = static_cast<ULONG>(depth);
            }
            else
            {
                if (error != nullptr)
                {
                    *error = L"Unknown dt option: " + args[index];
                }
                break;
            }

            ++index;
        }

        if (error != nullptr && !error->empty())
        {
            break;
        }

        if (index >= args.size())
        {
            if (error != nullptr)
            {
                *error = L"usage: dt [-rN] [-v] [-b] <module!type|type> [address|symbol] [field-filter...]";
            }
            break;
        }

        request->TypeName = args[index];
        ++index;

        if (index < args.size())
        {
            uint64_t address = 0;
            std::wstring ignored;
            if (ParseAddressOrSymbol(symbols, state, args[index], &address, &ignored))
            {
                request->HasAddress = true;
                request->Address = address;
                ++index;
            }
        }

        while (index < args.size())
        {
            request->FieldFilters.push_back(args[index]);
            ++index;
        }

        ok = true;
    } while (false);

    return ok;
}

static void PrintFieldValue(DeviceClient& device, const TypeFieldInfo& field, uint64_t address)
{
    std::wstring error;
    uint32_t width = static_cast<uint32_t>(field.Length);

    if (field.ChildTag == KNDBG_SYMTAG_POINTER_TYPE)
    {
        width = sizeof(uint64_t);
    }

    if (width == 0 || width > sizeof(uint64_t))
    {
        std::wcout << L" <no scalar value>";
        return;
    }

    std::vector<uint8_t> bytes;
    uint64_t fieldAddress = 0;
    if (!TryAddOffset(address, field.Offset, &fieldAddress))
    {
        std::wcout << L" <address overflow>";
        return;
    }

    if (!device.ReadMemory(fieldAddress, width, &bytes, &error))
    {
        std::wcout << L" <read failed: " << error << L">";
        return;
    }

    uint64_t value = DecodeInteger(bytes.data(), bytes.size());
    if (field.IsBitField && field.Length > 0 && field.Length < 64)
    {
        uint64_t mask = (1ull << field.Length) - 1ull;
        value = (value >> field.BitPosition) & mask;
    }

    std::wcout << L" = 0x" << std::hex << value << std::dec;
}

static void DumpTypeLayout(
    DeviceClient& device,
    SymbolEngine& symbols,
    const TypeLayoutInfo& layout,
    const DtRequest& request,
    uint64_t address,
    ULONG indent,
    ULONG remainingDepth)
{
    std::wstring indentText(indent, L' ');

    std::wcout << indentText << layout.Name;
    if (request.HasAddress)
    {
        std::wcout << L" @ 0x" << std::hex << address;
    }
    std::wcout << L" size=0x" << std::hex << layout.Size << std::dec << L"\n";

    for (const TypeFieldInfo& field : layout.Fields)
    {
        if (!FieldMatchesFilters(field, request.FieldFilters))
        {
            continue;
        }

        std::wcout << indentText << L"   +0x" << std::hex << std::setw(3) << std::setfill(L'0') << field.Offset
                   << std::setfill(L' ') << L" " << field.Name;

        if (!request.Bare)
        {
            std::wcout << L" : " << field.TypeName;
        }

        if (field.IsBitField)
        {
            std::wcout << L" bitpos=" << field.BitPosition << L" bits=" << field.Length;
        }

        if (request.Verbose)
        {
            std::wcout << L" tag=" << field.Tag << L" childTag=" << field.ChildTag
                       << L" typeId=" << field.ChildTypeId << L" len=" << field.Length;
        }

        if (request.HasAddress)
        {
            PrintFieldValue(device, field, address);
        }

        std::wcout << L"\n";

        if (remainingDepth > 0 && field.ChildTag == KNDBG_SYMTAG_UDT && field.ChildTypeId != 0 && field.ChildTypeId != layout.TypeId)
        {
            TypeLayoutInfo childLayout = {};
            std::wstring childError;
            uint64_t childAddress = 0;
            if (TryAddOffset(address, field.Offset, &childAddress) &&
                symbols.GetTypeLayoutById(field.ModuleBase, field.ChildTypeId, field.TypeName, &childLayout, &childError))
            {
                DtRequest childRequest = request;
                childRequest.FieldFilters.clear();
                DumpTypeLayout(device, symbols, childLayout, childRequest, childAddress, indent + 4, remainingDepth - 1);
            }
        }
    }
}

static void HandleDtCommand(
    const std::vector<std::wstring>& args,
    const DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    std::wstring error;
    DtRequest request = {};

    do
    {
        if (!ParseDtRequest(args, state, symbols, &request, &error))
        {
            std::wcerr << L"dt failed: " << error << L"\n";
            break;
        }

        TypeLayoutInfo layout = {};
        if (!symbols.GetTypeLayout(request.TypeName, &layout, &error))
        {
            std::wcerr << L"dt failed: " << error << L"\n";
            break;
        }

        DumpTypeLayout(device, symbols, layout, request, request.Address, 0, request.RecursionDepth);
    } while (false);
}

static void HandleDisplayCommand(
    const std::vector<std::wstring>& args,
    const DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    std::wstring error;
    std::wstring command = NormalizeInputCommand(args[0]);

    do
    {
        if (args.size() < 2)
        {
            std::wcerr << L"usage: " << command << L" <address|symbol> [count]\n";
            break;
        }

        uint64_t address = 0;
        if (!ParseAddressOrSymbol(symbols, state, args[1], &address, &error))
        {
            std::wcerr << L"display failed: " << error << L"\n";
            break;
        }

        size_t unit = UnitWidthForDisplayCommand(command);
        uint64_t defaultCount = 128;
        if (unit != 1)
        {
            defaultCount = 16;
        }

        if (command == L"da" || command == L"du" || command == L"ds")
        {
            defaultCount = 128;
        }

        uint64_t count = 0;
        if (!GetCountArgument(args, 2, defaultCount, state, &count))
        {
            std::wcerr << L"invalid count\n";
            break;
        }

        uint64_t byteUnit = unit;
        if (command == L"da" || command == L"ds")
        {
            byteUnit = 1;
        }
        else if (command == L"du")
        {
            byteUnit = sizeof(wchar_t);
        }

        uint32_t byteCount = 0;
        if (!TryCalculateTransferSize(count, byteUnit, &byteCount))
        {
            std::wcerr << L"read size exceeds native transfer limit\n";
            break;
        }

        std::vector<uint8_t> bytes;
        if (!device.ReadMemory(address, byteCount, &bytes, &error))
        {
            std::wcerr << L"read failed: " << error << L"\n";
            break;
        }

        if (command == L"d" || command == L"db" || command == L"dyb")
        {
            HexDump(address, bytes);
        }
        else if (command == L"da" || command == L"ds")
        {
            PrintAsciiString(address, bytes);
        }
        else if (command == L"du")
        {
            PrintUnicodeString(address, bytes);
        }
        else if (command == L"dds" || command == L"dps" || command == L"dqs")
        {
            UnitDump(address, bytes, unit, &symbols);
        }
        else if (command.size() == 3 && command[0] == L'd' &&
                 (command[2] == L'a' || command[2] == L'p' || command[2] == L'u'))
        {
            for (size_t offset = 0; offset + unit <= bytes.size(); offset += unit)
            {
                uint64_t pointer = DecodeInteger(bytes.data() + offset, unit);
                std::wcout << L"0x" << std::hex << (address + offset) << L": 0x" << pointer << L" ";

                if (command[2] == L'a')
                {
                    std::vector<uint8_t> refBytes;
                    if (device.ReadMemory(pointer, 128, &refBytes, &error))
                    {
                        PrintAsciiString(pointer, refBytes);
                    }
                    else
                    {
                        std::wcout << L"<read failed>\n";
                    }
                }
                else if (command[2] == L'u')
                {
                    std::vector<uint8_t> refBytes;
                    if (device.ReadMemory(pointer, 128 * sizeof(wchar_t), &refBytes, &error))
                    {
                        PrintUnicodeString(pointer, refBytes);
                    }
                    else
                    {
                        std::wcout << L"<read failed>\n";
                    }
                }
                else
                {
                    std::wstring name;
                    uint64_t displacement = 0;
                    if (symbols.FindNearestSymbol(pointer, &name, &displacement, &error))
                    {
                        std::wcout << name;
                        if (displacement != 0)
                        {
                            std::wcout << L"+0x" << displacement;
                        }
                    }
                    std::wcout << L"\n";
                }
            }
        }
        else
        {
            UnitDump(address, bytes, unit, nullptr);
        }
    } while (false);
}

static void HandleTranslateVirtualCommand(
    const std::vector<std::wstring>& args,
    const DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    std::wstring error;
    std::wstring command = NormalizeInputCommand(args[0]);

    do
    {
        if (args.size() < 2)
        {
            std::wcerr << L"usage: vtop <address|symbol> [length]\n";
            std::wcerr << L"usage: vtop /cr3 <directory-table-base> <address|symbol> [length]\n";
            std::wcerr << L"usage: !vtop <address|symbol> [length]\n";
            std::wcerr << L"usage: !vtop <directory-table-base> <address|symbol> [length]\n";
            break;
        }

        uint64_t directoryTableBase = 0;
        uint64_t virtualAddress = 0;
        uint64_t length = 1;
        size_t index = 1;

        if (command == L"vtop" && ToLower(args[index]) == L"/cr3")
        {
            if (args.size() < 4)
            {
                std::wcerr << L"usage: vtop /cr3 <directory-table-base> <address|symbol> [length]\n";
                break;
            }

            if (!ParseUnsigned(args[2], state.NumberBase, &directoryTableBase))
            {
                std::wcerr << L"invalid directory table base\n";
                break;
            }

            if (!ParseAddressOrSymbol(symbols, state, args[3], &virtualAddress, &error))
            {
                std::wcerr << L"vtop failed: " << error << L"\n";
                break;
            }

            index = 4;
        }
        else if (command == L"!vtop" && args.size() >= 3)
        {
            if (!ParseUnsigned(args[1], state.NumberBase, &directoryTableBase))
            {
                std::wcerr << L"invalid directory table base\n";
                break;
            }

            if (!ParseAddressOrSymbol(symbols, state, args[2], &virtualAddress, &error))
            {
                std::wcerr << L"vtop failed: " << error << L"\n";
                break;
            }

            index = 3;
        }
        else
        {
            if (!ParseAddressOrSymbol(symbols, state, args[1], &virtualAddress, &error))
            {
                std::wcerr << L"vtop failed: " << error << L"\n";
                break;
            }

            index = 2;
        }

        if (args.size() > index && !ParseUnsigned(args[index], state.NumberBase, &length))
        {
            std::wcerr << L"invalid vtop length\n";
            break;
        }

        if (!IsSafeTransferSize(length))
        {
            std::wcerr << L"vtop size exceeds native transfer limit\n";
            break;
        }

        PhysicalTranslationInfo info = {};
        if (!device.TranslateVirtual(
                directoryTableBase,
                virtualAddress,
                static_cast<uint32_t>(length),
                &info,
                &error))
        {
            std::wcerr << L"vtop failed: " << error << L"\n";
            break;
        }

        std::wcout << L"va=0x" << std::hex << std::setw(16) << std::setfill(L'0') << info.VirtualAddress
                   << L" pa=0x" << std::setw(16) << info.PhysicalAddress
                   << L" cr3=0x" << std::setw(16) << info.DirectoryTableBase << std::dec << L"\n";
        std::wcout << L"page-size=0x" << std::hex << info.PageSize
                   << L" page-offset=0x" << info.PageOffset
                   << L" page-bytes=0x" << info.PageBytes
                   << L" translated=0x" << info.TranslatedLength << std::dec << L"\n";
        std::wcout << L"pml4e=0x" << std::hex << std::setw(16) << info.Pml4e
                   << L" pdpte=0x" << std::setw(16) << info.Pdpte
                   << L" pde=0x" << std::setw(16) << info.Pde
                   << L" pte=0x" << std::setw(16) << info.Pte << std::dec << L"\n";
    } while (false);
}

static void HandlePhysicalDisplayCommand(
    const std::vector<std::wstring>& args,
    const DebuggerState& state,
    DeviceClient& device)
{
    std::wstring error;
    std::wstring command = NormalizeInputCommand(args[0]);

    do
    {
        if (args.size() < 2)
        {
            std::wcerr << L"usage: " << command << L" <physical-address> [count]\n";
            break;
        }

        uint64_t physicalAddress = 0;
        if (!ParseUnsigned(args[1], state.NumberBase, &physicalAddress))
        {
            std::wcerr << L"invalid physical address\n";
            break;
        }

        size_t unit = UnitWidthForPhysicalDisplayCommand(command);
        uint64_t defaultCount = unit == 1 ? 128 : 16;
        uint64_t count = 0;
        if (!GetCountArgument(args, 2, defaultCount, state, &count))
        {
            std::wcerr << L"invalid count\n";
            break;
        }

        uint32_t byteCount = 0;
        if (!TryCalculateTransferSize(count, unit, &byteCount))
        {
            std::wcerr << L"physical read size exceeds native transfer limit\n";
            break;
        }

        std::vector<uint8_t> bytes;
        if (!device.ReadPhysical(physicalAddress, byteCount, &bytes, &error))
        {
            std::wcerr << L"physical read failed: " << error << L"\n";
            break;
        }

        if (command == L"phys" || command == L"pdb")
        {
            HexDump(physicalAddress, bytes);
        }
        else
        {
            UnitDump(physicalAddress, bytes, unit, nullptr);
        }
    } while (false);
}

static void HandlePhysicalEnterCommand(
    const std::vector<std::wstring>& args,
    const DebuggerState& state,
    DeviceClient& device)
{
    std::wstring error;
    std::wstring command = NormalizeInputCommand(args[0]);

    do
    {
        if (args.size() < 3)
        {
            std::wcerr << L"usage: " << command << L" <physical-address> <value...>\n";
            break;
        }

        uint64_t physicalAddress = 0;
        if (!ParseUnsigned(args[1], state.NumberBase, &physicalAddress))
        {
            std::wcerr << L"invalid physical address\n";
            break;
        }

        size_t width = 1;
        if (command == L"pew")
        {
            width = 2;
        }
        else if (command == L"ped")
        {
            width = 4;
        }
        else if (command == L"peq")
        {
            width = 8;
        }

        std::vector<uint8_t> bytes;
        bool valuesOk = true;
        for (size_t index = 2; index < args.size(); ++index)
        {
            uint64_t value = 0;
            if (!ParseUnsigned(args[index], state.NumberBase, &value))
            {
                std::wcerr << L"invalid value: " << args[index] << L"\n";
                valuesOk = false;
                break;
            }

            std::vector<uint8_t> encoded = EncodeInteger(value, width);
            bytes.insert(bytes.end(), encoded.begin(), encoded.end());
        }

        if (!valuesOk)
        {
            break;
        }

        if (!IsSafeTransferSize(bytes.size()))
        {
            std::wcerr << L"physical write size exceeds native transfer limit\n";
            break;
        }

        if (device.WritePhysical(physicalAddress, bytes, &error))
        {
            std::wcout << L"wrote physical " << bytes.size() << L" bytes\n";
        }
        else
        {
            std::wcerr << L"physical write failed: " << error << L"\n";
        }
    } while (false);
}

static void HandleEnterCommand(
    const std::vector<std::wstring>& args,
    const DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    std::wstring error;
    std::wstring command = NormalizeInputCommand(args[0]);

    do
    {
        if (args.size() < 3)
        {
            std::wcerr << L"usage: " << command << L" <address|symbol> <value...>\n";
            break;
        }

        uint64_t address = 0;
        if (!ParseAddressOrSymbol(symbols, state, args[1], &address, &error))
        {
            std::wcerr << L"write failed: " << error << L"\n";
            break;
        }

        std::vector<uint8_t> bytes;
        if (command == L"ea" || command == L"eza" || command == L"eu" || command == L"ezu")
        {
            bool unicode = command == L"eu" || command == L"ezu";
            bool zeroTerminate = command == L"eza" || command == L"ezu";
            bytes = EncodeString(JoinArgs(args, 2), unicode, zeroTerminate);
        }
        else
        {
            size_t width = 1;
            if (command == L"ew")
            {
                width = 2;
            }
            else if (command == L"ed" || command == L"ef")
            {
                width = 4;
            }
            else if (command == L"eq" || command == L"ep")
            {
                width = 8;
            }

            bool valuesOk = true;
            for (size_t index = 2; index < args.size(); ++index)
            {
                uint64_t value = 0;
                if (!ParseUnsigned(args[index], state.NumberBase, &value))
                {
                    std::wcerr << L"invalid value: " << args[index] << L"\n";
                    valuesOk = false;
                    break;
                }

                std::vector<uint8_t> encoded = EncodeInteger(value, width);
                bytes.insert(bytes.end(), encoded.begin(), encoded.end());
            }

            if (!valuesOk)
            {
                break;
            }
        }

        if (bytes.empty())
        {
            std::wcerr << L"no bytes to write\n";
            break;
        }

        if (!IsSafeTransferSize(bytes.size()))
        {
            std::wcerr << L"write size exceeds native transfer limit\n";
            break;
        }

        if (device.WriteMemory(address, bytes, &error))
        {
            std::wcout << L"wrote " << bytes.size() << L" bytes\n";
        }
        else
        {
            std::wcerr << L"write failed: " << error << L"\n";
        }
    } while (false);
}

static void HandleCompare(const std::vector<std::wstring>& args, const DebuggerState& state, DeviceClient& device, SymbolEngine& symbols)
{
    std::wstring error;

    do
    {
        if (args.size() < 4)
        {
            std::wcerr << L"usage: c <address1> <address2> <length>\n";
            break;
        }

        uint64_t address1 = 0;
        uint64_t address2 = 0;
        uint64_t length = 0;
        if (!ParseAddressOrSymbol(symbols, state, args[1], &address1, &error) ||
            !ParseAddressOrSymbol(symbols, state, args[2], &address2, &error) ||
            !ParseUnsigned(args[3], state.NumberBase, &length))
        {
            std::wcerr << L"compare argument parse failed\n";
            break;
        }

        if (!IsSafeTransferSize(length))
        {
            std::wcerr << L"compare size exceeds native transfer limit\n";
            break;
        }

        std::vector<uint8_t> left;
        std::vector<uint8_t> right;
        if (!device.ReadMemory(address1, static_cast<uint32_t>(length), &left, &error) ||
            !device.ReadMemory(address2, static_cast<uint32_t>(length), &right, &error))
        {
            std::wcerr << L"compare read failed: " << error << L"\n";
            break;
        }

        size_t mismatchCount = 0;
        size_t effective = left.size() < right.size() ? left.size() : right.size();
        for (size_t index = 0; index < effective; ++index)
        {
            if (left[index] != right[index])
            {
                std::wcout << L"0x" << std::hex << (address1 + index) << L" 0x"
                           << static_cast<unsigned>(left[index]) << L" != 0x"
                           << (address2 + index) << L" 0x" << static_cast<unsigned>(right[index]) << std::dec << L"\n";
                ++mismatchCount;
            }
        }

        std::wcout << L"mismatches=" << mismatchCount << L"\n";
    } while (false);
}

static void HandleFill(const std::vector<std::wstring>& args, const DebuggerState& state, DeviceClient& device, SymbolEngine& symbols)
{
    std::wstring error;
    std::wstring command = NormalizeInputCommand(args[0]);

    do
    {
        if (args.size() < 4)
        {
            std::wcerr << L"usage: f <address> <length> <value...>\n";
            break;
        }

        uint64_t address = 0;
        uint64_t length = 0;
        if (!ParseAddressOrSymbol(symbols, state, args[1], &address, &error) ||
            !ParseUnsigned(args[2], state.NumberBase, &length))
        {
            std::wcerr << L"fill argument parse failed\n";
            break;
        }

        if (!IsSafeTransferSize(length))
        {
            std::wcerr << L"fill size exceeds native transfer limit\n";
            break;
        }

        std::vector<uint8_t> pattern;
        size_t width = command == L"fp" ? sizeof(uint64_t) : 1;
        bool valuesOk = true;
        for (size_t index = 3; index < args.size(); ++index)
        {
            uint64_t value = 0;
            if (!ParseUnsigned(args[index], state.NumberBase, &value))
            {
                std::wcerr << L"invalid fill value\n";
                valuesOk = false;
                break;
            }

            if (width == 1)
            {
                pattern.push_back(static_cast<uint8_t>(value & 0xff));
            }
            else
            {
                std::vector<uint8_t> encoded = EncodeInteger(value, width);
                pattern.insert(pattern.end(), encoded.begin(), encoded.end());
            }
        }

        if (!valuesOk)
        {
            break;
        }

        if (pattern.empty())
        {
            std::wcerr << L"empty fill pattern\n";
            break;
        }

        std::vector<uint8_t> bytes(static_cast<size_t>(length));
        for (size_t index = 0; index < bytes.size(); ++index)
        {
            bytes[index] = pattern[index % pattern.size()];
        }

        if (device.WriteMemory(address, bytes, &error))
        {
            std::wcout << L"filled " << bytes.size() << L" bytes\n";
        }
        else
        {
            std::wcerr << L"fill failed: " << error << L"\n";
        }
    } while (false);
}

static void HandleMove(const std::vector<std::wstring>& args, const DebuggerState& state, DeviceClient& device, SymbolEngine& symbols)
{
    std::wstring error;

    do
    {
        if (args.size() < 4)
        {
            std::wcerr << L"usage: m <source> <destination> <length>\n";
            break;
        }

        uint64_t source = 0;
        uint64_t destination = 0;
        uint64_t length = 0;
        if (!ParseAddressOrSymbol(symbols, state, args[1], &source, &error) ||
            !ParseAddressOrSymbol(symbols, state, args[2], &destination, &error) ||
            !ParseUnsigned(args[3], state.NumberBase, &length))
        {
            std::wcerr << L"move argument parse failed\n";
            break;
        }

        if (!IsSafeTransferSize(length))
        {
            std::wcerr << L"move size exceeds native transfer limit\n";
            break;
        }

        std::vector<uint8_t> bytes;
        if (!device.ReadMemory(source, static_cast<uint32_t>(length), &bytes, &error))
        {
            std::wcerr << L"move read failed: " << error << L"\n";
            break;
        }

        if (device.WriteMemory(destination, bytes, &error))
        {
            std::wcout << L"moved " << bytes.size() << L" bytes\n";
        }
        else
        {
            std::wcerr << L"move write failed: " << error << L"\n";
        }
    } while (false);
}

static void HandleSearch(const std::vector<std::wstring>& args, const DebuggerState& state, DeviceClient& device, SymbolEngine& symbols)
{
    std::wstring error;

    do
    {
        if (args.size() < 4)
        {
            std::wcerr << L"usage: s [-b|-w|-d|-q] <address> <length> <value...>\n";
            break;
        }

        size_t argIndex = 1;
        size_t width = 1;
        if (args[argIndex] == L"-w")
        {
            width = 2;
            ++argIndex;
        }
        else if (args[argIndex] == L"-d")
        {
            width = 4;
            ++argIndex;
        }
        else if (args[argIndex] == L"-q")
        {
            width = 8;
            ++argIndex;
        }
        else if (args[argIndex] == L"-b")
        {
            width = 1;
            ++argIndex;
        }

        if (args.size() <= argIndex + 2)
        {
            std::wcerr << L"usage: s [-b|-w|-d|-q] <address> <length> <value...>\n";
            break;
        }

        uint64_t address = 0;
        uint64_t length = 0;
        if (!ParseAddressOrSymbol(symbols, state, args[argIndex], &address, &error) ||
            !ParseUnsigned(args[argIndex + 1], state.NumberBase, &length))
        {
            std::wcerr << L"search argument parse failed\n";
            break;
        }

        if (!IsSafeTransferSize(length))
        {
            std::wcerr << L"search size exceeds native transfer limit\n";
            break;
        }

        std::vector<uint8_t> pattern;
        bool valuesOk = true;
        for (size_t index = argIndex + 2; index < args.size(); ++index)
        {
            uint64_t value = 0;
            if (!ParseUnsigned(args[index], state.NumberBase, &value))
            {
                std::wcerr << L"invalid search value\n";
                valuesOk = false;
                break;
            }

            std::vector<uint8_t> encoded = EncodeInteger(value, width);
            pattern.insert(pattern.end(), encoded.begin(), encoded.end());
        }

        if (!valuesOk)
        {
            break;
        }

        std::vector<uint8_t> bytes;
        if (!device.ReadMemory(address, static_cast<uint32_t>(length), &bytes, &error))
        {
            std::wcerr << L"search read failed: " << error << L"\n";
            break;
        }

        size_t matches = 0;
        for (size_t index = 0; index + pattern.size() <= bytes.size(); ++index)
        {
            if (memcmp(bytes.data() + index, pattern.data(), pattern.size()) == 0)
            {
                std::wcout << L"0x" << std::hex << (address + index) << std::dec << L"\n";
                ++matches;
            }
        }

        std::wcout << L"matches=" << matches << L"\n";
    } while (false);
}

static void PrintVersion(DeviceClient& device)
{
    std::wstring error;

    std::wcout << L"KnLiveDbg version 0.3\n";
    if (device.QueryVersion(&error))
    {
        std::wcout << L"driver ABI ok\n";
    }
    else
    {
        std::wcerr << L"driver ABI check failed: " << error << L"\n";
    }
}

static void PrintTarget()
{
    typedef LONG NTSTATUS;
    typedef NTSTATUS (WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

    RTL_OSVERSIONINFOW version = {};
    version.dwOSVersionInfoSize = sizeof(version);

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto rtlGetVersion = ntdll != nullptr ? reinterpret_cast<RtlGetVersionPtr>(GetProcAddress(ntdll, "RtlGetVersion")) : nullptr;
    if (rtlGetVersion != nullptr && rtlGetVersion(&version) >= 0)
    {
        std::wcout << L"local live kernel target: Windows "
                   << version.dwMajorVersion << L"." << version.dwMinorVersion
                   << L" build " << version.dwBuildNumber << L"\n";
    }
    else
    {
        std::wcout << L"local live kernel target: current machine\n";
    }
}

static std::wstring ObjectOperationsText(uint32_t operations)
{
    std::wstring text;

    do
    {
        if ((operations & 0x1) != 0)
        {
            text += L"create";
        }

        if ((operations & 0x2) != 0)
        {
            if (!text.empty())
            {
                text += L"|";
            }
            text += L"duplicate";
        }

        if (text.empty())
        {
            text = L"none";
        }
    } while (false);

    return text;
}

static void PrintCallbackAddress(
    const wchar_t* label,
    uint64_t address,
    const std::wstring& moduleName,
    const std::wstring& symbolName)
{
    do
    {
        if (address == 0)
        {
            break;
        }

        std::wcout << L"  " << label << L"=0x"
                   << std::hex << std::setw(16) << std::setfill(L'0') << address << std::dec;
        if (!moduleName.empty())
        {
            std::wcout << L" module=" << moduleName;
        }
        else
        {
            std::wcout << L" module=<non-image>";
        }

        if (!symbolName.empty())
        {
            std::wcout << L" symbol=" << symbolName;
        }

        std::wcout << L"\n";
    } while (false);
}

static void HandleCallbacksCommand(
    const std::vector<std::wstring>& args,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    std::wstring error;

    do
    {
        std::wstring scope = L"all";
        if (args.size() >= 2)
        {
            scope = args[1];
        }

        if (symbols.Modules().empty())
        {
            if (!symbols.LoadKernelModules(&error))
            {
                std::wcerr << L"callback scan failed: " << error << L"\n";
                break;
            }
        }

        KernelCallbackScanner scanner(device, symbols);
        KernelCallbackScanResult result = {};
        if (!scanner.Scan(scope, &result, &error))
        {
            std::wcerr << L"callback scan failed: " << error << L"\n";
            break;
        }

        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"callback warning: " << warning << L"\n";
        }

        std::wcout << L"callback records=" << result.Records.size() << L"\n";
        for (const KernelCallbackRecord& record : result.Records)
        {
            std::wcout << L"[" << record.Kind << L"] " << record.Target;
            if (!record.Altitude.empty())
            {
                std::wcout << L" altitude=\"" << record.Altitude << L"\"";
            }

            if (!record.CallbackName.empty())
            {
                std::wcout << L" callback=" << record.CallbackName;
            }

            if (record.Kind == L"ob")
            {
                std::wcout << L" operations=0x" << std::hex << record.Operations
                           << L"(" << ObjectOperationsText(record.Operations) << L")" << std::dec;
            }

            if (record.Kind == L"minifilter")
            {
                std::wcout << L" filterFlags=0x" << std::hex << record.FilterFlags << std::dec;
                if (record.MajorFunction != 0xffffffffu)
                {
                    std::wcout << L" major=0x" << std::hex << record.MajorFunction << std::dec;
                }
                if (record.CallbackFlags != 0)
                {
                    std::wcout << L" cbFlags=0x" << std::hex << record.CallbackFlags << std::dec;
                }
            }

            std::wcout << L" slot=" << record.Slot;

            std::wcout << L"\n";

            if (record.RootAddress != 0)
            {
                std::wcout << L"  root=0x" << std::hex << std::setw(16) << std::setfill(L'0')
                           << record.RootAddress << std::dec;
                if (!record.RootSource.empty())
                {
                    std::wcout << L" source=" << record.RootSource;
                }
                std::wcout << L"\n";
            }

            if (record.Filter != 0)
            {
                std::wcout << L"  filter=0x" << std::hex << std::setw(16) << std::setfill(L'0')
                           << record.Filter << std::dec;
                if (record.Frame != 0)
                {
                    std::wcout << L" frame=0x" << std::hex << std::setw(16) << std::setfill(L'0')
                               << record.Frame << std::dec;
                }
                if (record.FrameId != 0xffffffffu)
                {
                    std::wcout << L" frameId=" << record.FrameId;
                }
                std::wcout << L"\n";
            }

            if (record.DriverObject != 0)
            {
                std::wcout << L"  driverObject=0x" << std::hex << std::setw(16) << std::setfill(L'0')
                           << record.DriverObject << std::dec << L"\n";
            }

            if (record.ObjectType != 0)
            {
                std::wcout << L"  objectType=0x" << std::hex << std::setw(16) << std::setfill(L'0')
                           << record.ObjectType << std::dec;
                if (!record.ObjectTypeSource.empty())
                {
                    std::wcout << L" source=" << record.ObjectTypeSource;
                }
                std::wcout << L"\n";
            }

            if (record.ListEntry != 0)
            {
                std::wcout << L"  list=0x" << std::hex << std::setw(16) << std::setfill(L'0')
                           << record.ListEntry << std::dec << L"\n";
            }

            if (record.Entry != 0)
            {
                std::wcout << L"  entry=0x" << std::hex << std::setw(16) << std::setfill(L'0')
                           << record.Entry << std::dec << L"\n";
            }

            if (record.CallbackBlock != 0)
            {
                std::wcout << L"  block=0x" << std::hex << std::setw(16) << std::setfill(L'0')
                           << record.CallbackBlock << L" raw=0x" << std::setw(16)
                           << record.RawValue << std::dec << L"\n";
            }

            if (record.CallbackEntry != 0)
            {
                std::wcout << L"  callbackEntry=0x" << std::hex << std::setw(16) << std::setfill(L'0')
                           << record.CallbackEntry << std::dec << L"\n";
            }

            const wchar_t* primaryLabel = L"pre";
            if (record.Kind == L"process" || (record.Kind == L"minifilter" && record.PostFunction == 0))
            {
                primaryLabel = L"function";
            }

            PrintCallbackAddress(
                primaryLabel,
                record.Function,
                record.FunctionModule,
                record.FunctionSymbol);
            PrintCallbackAddress(L"post", record.PostFunction, record.PostFunctionModule, record.PostFunctionSymbol);
            PrintCallbackAddress(L"context", record.Context, record.ContextModule, record.ContextSymbol);

            if (record.Cookie != 0)
            {
                std::wcout << L"  cookie=0x" << std::hex << std::setw(16) << std::setfill(L'0')
                           << record.Cookie << std::dec << L"\n";
            }

            if (!record.Notes.empty())
            {
                std::wcout << L"  notes=" << record.Notes << L"\n";
            }
        }
    } while (false);
}

static void HandleUnassembleCommand(
    const std::vector<std::wstring>& args,
    const std::wstring& originalLine,
    DebuggerState& state,
    DbgEngBackend& dbgeng,
    SymbolEngine& symbols)
{
    std::wstring command = NormalizeInputCommand(args[0]);
    std::wstring error;

    do
    {
        if (command == L"uf")
        {
            if (args.size() < 2)
            {
                std::wcerr << L"usage: uf <address|symbol>\n";
                break;
            }

            ExecuteDbgEngCommand(dbgeng, symbols, state, originalLine, true);
            break;
        }

        uint64_t address = 0;
        bool hasAddress = false;
        if (args.size() >= 2)
        {
            if (symbols.Modules().empty())
            {
                symbols.LoadKernelModules(nullptr);
            }

            if (ParseAddressOrSymbol(symbols, state, args[1], &address, &error))
            {
                hasAddress = true;
            }
            else
            {
                ExecuteDbgEngCommand(dbgeng, symbols, state, originalLine, true);
                break;
            }
        }
        else if (state.HasLastDisassemblyAddress)
        {
            address = state.LastDisassemblyAddress;
            hasAddress = true;
        }

        if (!hasAddress)
        {
            if (!ExecuteDbgEngCommand(dbgeng, symbols, state, originalLine, true))
            {
                std::wcerr << L"usage: u <address|symbol> [instruction-count]\n";
            }
            break;
        }

        uint64_t count = 8;
        if (args.size() >= 3 && !ParseUnsigned(args[2], state.NumberBase, &count))
        {
            std::wcerr << L"invalid instruction count\n";
            break;
        }

        if (count == 0 || count > 256)
        {
            std::wcerr << L"instruction count must be between 1 and 256\n";
            break;
        }

        if (!EnsureDbgEng(dbgeng, symbols, state, &error))
        {
            std::wcerr << L"DbgEng init failed: " << error << L"\n";
            break;
        }

        std::wstring output;
        uint64_t nextOffset = address;
        if (!dbgeng.Disassemble(address, static_cast<uint32_t>(count), &output, &nextOffset, &error))
        {
            std::wcerr << L"u failed: " << error << L"\n";
            break;
        }

        if (!output.empty())
        {
            std::wcout << output;
            if (output.back() != L'\n')
            {
                std::wcout << L"\n";
            }
        }

        state.LastDisassemblyAddress = nextOffset;
        state.HasLastDisassemblyAddress = true;
    } while (false);
}

static bool HandleCommand(
    const std::vector<std::wstring>& args,
    const std::wstring& originalLine,
    DebuggerState& state,
    DbgEngBackend& dbgeng,
    DeviceClient& device,
    DriverService& service,
    SymbolEngine& symbols)
{
    bool keepRunning = true;

    do
    {
        if (args.empty())
        {
            break;
        }

        std::wstring command = NormalizeInputCommand(args[0]);
        std::wstring error;

        if (command == L"help")
        {
            bool includeDbgEng = args.size() >= 2 && ToLower(args[1]) == L"all";
            PrintHelp(includeDbgEng);
        }
        else if (command == L"backend")
        {
            if (args.size() >= 2)
            {
                std::wstring mode = ToLower(args[1]);
                if (mode == L"auto")
                {
                    state.Backend = DebuggerState::BackendMode::Auto;
                }
                else if (mode == L"native")
                {
                    state.Backend = DebuggerState::BackendMode::Native;
                }
                else if (mode == L"dbgeng")
                {
                    if (EnsureDbgEng(dbgeng, symbols, state, &error))
                    {
                        state.Backend = DebuggerState::BackendMode::DbgEng;
                    }
                    else
                    {
                        std::wcerr << L"DbgEng init failed: " << error << L"\n";
                    }
                }
                else
                {
                    std::wcerr << L"usage: backend auto|native|dbgeng\n";
                }
            }

            std::wcout << L"backend: " << BackendModeText(state.Backend)
                       << L" dbgeng-ready=" << (dbgeng.IsReady() ? L"yes" : L"no") << L"\n";
        }
        else if (command == L"kdinit")
        {
            if (args.size() >= 2)
            {
                state.DbgEngConnectOptions = JoinArgs(args, 1);
            }

            if (EnsureDbgEng(dbgeng, symbols, state, &error))
            {
                std::wcout << L"DbgEng local-kernel backend ready\n";
            }
            else
            {
                std::wcerr << L"DbgEng init failed: " << error << L"\n";
            }
        }
        else if (command == L"kddetach")
        {
            dbgeng.Shutdown();
            if (state.Backend == DebuggerState::BackendMode::DbgEng)
            {
                state.Backend = DebuggerState::BackendMode::Auto;
            }

            std::wcout << L"DbgEng backend detached\n";
        }
        else if (command == L"kd")
        {
            if (args.size() < 2)
            {
                std::wcerr << L"usage: kd <windbg-command>\n";
                break;
            }

            ExecuteDbgEngCommand(dbgeng, symbols, state, JoinArgs(args, 1), true);
        }
        else if (command == L"u" || command == L"uf")
        {
            HandleUnassembleCommand(args, originalLine, state, dbgeng, symbols);
        }
        else if (state.Backend == DebuggerState::BackendMode::DbgEng &&
                 command != L"q" && command != L"qq" && command != L"qd" &&
                 command != L"quit" && command != L"exit" &&
                 command != L"unload" && command != L"drvstatus" &&
                 command != L"callbacks" && command != L"kcallbacks" && command != L"cb")
        {
            ExecuteDbgEngCommand(dbgeng, symbols, state, originalLine, true);
        }
        else if (command == L"?" && args.size() == 1)
        {
            PrintHelp(false);
        }
        else if ((command == L"?" || command == L"??") && args.size() >= 2)
        {
            uint64_t value = 0;
            if (ParseAddressOrSymbol(symbols, state, args[1], &value, &error))
            {
                std::wcout << L"Evaluate expression: 0x" << std::hex << value << L" = " << std::dec << value << L"\n";
            }
            else
            {
                std::wcerr << L"evaluate failed: " << error << L"\n";
            }
        }
        else if (command == L".sympath" || command == L"sympath")
        {
            if (args.size() >= 2)
            {
                symbols.SetSymbolPath(JoinArgs(args, 1));
                if (dbgeng.IsReady())
                {
                    dbgeng.SetSymbolPath(symbols.SymbolPath(), nullptr);
                }
            }

            std::wcout << L"symbol path: " << symbols.SymbolPath() << L"\n";
        }
        else if (command == L".sympath+")
        {
            if (args.size() >= 2)
            {
                symbols.SetSymbolPath(symbols.SymbolPath() + L";" + JoinArgs(args, 1));
                if (dbgeng.IsReady())
                {
                    dbgeng.SetSymbolPath(symbols.SymbolPath(), nullptr);
                }
            }

            std::wcout << L"symbol path: " << symbols.SymbolPath() << L"\n";
        }
        else if (command == L".reload" || command == L"reload" || command == L"ld")
        {
            if (symbols.LoadKernelModules(&error))
            {
                std::wcout << L"loaded module list: " << symbols.Modules().size() << L"\n";
                if (dbgeng.IsReady())
                {
                    std::wstring output;
                    dbgeng.Reload(&output, nullptr);
                    if (!output.empty())
                    {
                        std::wcout << output;
                    }
                }
            }
            else
            {
                std::wcerr << L"reload failed: " << error << L"\n";
            }
        }
        else if (command == L"lm" || command == L"modules")
        {
            std::wstring filter;
            if (args.size() >= 2)
            {
                filter = ToLower(args[1]);
            }

            for (const KernelModuleInfo& module : symbols.Modules())
            {
                std::wstring imageName = ToLower(module.ImageName);
                if (!filter.empty() && imageName.find(filter) == std::wstring::npos)
                {
                    continue;
                }

                std::wcout << L"0x" << std::hex << std::setw(16) << std::setfill(L'0') << module.Base
                           << L" size=0x" << module.Size << L" " << module.ImageName
                           << L" " << module.ImagePath << std::dec << L"\n";
            }
        }
        else if (command == L"x" && args.size() >= 2)
        {
            std::vector<SymbolMatchInfo> matches;
            if (symbols.EnumerateSymbols(args[1], 512, &matches, &error))
            {
                for (const SymbolMatchInfo& match : matches)
                {
                    std::wcout << L"0x" << std::hex << std::setw(16) << std::setfill(L'0') << match.Address
                               << L" " << match.Name << std::dec << L"\n";
                }

                std::wcout << L"symbols=" << matches.size() << L"\n";
            }
            else
            {
                std::wcerr << L"x failed: " << error << L"\n";
            }
        }
        else if ((command == L"ln" || command == L"addr") && args.size() >= 2)
        {
            uint64_t address = 0;
            if (!ParseAddressOrSymbol(symbols, state, args[1], &address, &error))
            {
                std::wcerr << L"ln failed: " << error << L"\n";
                break;
            }

            std::wstring nearest;
            uint64_t displacement = 0;
            std::wcout << args[1] << L" = 0x" << std::hex << address << std::dec << L"\n";
            if (symbols.FindNearestSymbol(address, &nearest, &displacement, &error))
            {
                std::wcout << L"nearest: " << nearest;
                if (displacement != 0)
                {
                    std::wcout << L"+0x" << std::hex << displacement << std::dec;
                }
                std::wcout << L"\n";
            }
        }
        else if (command == L"query" && args.size() >= 2)
        {
            uint64_t address = 0;
            uint64_t length = 1;
            if (!ParseAddressOrSymbol(symbols, state, args[1], &address, &error))
            {
                std::wcerr << L"query failed: " << error << L"\n";
                break;
            }

            if (args.size() >= 3)
            {
                if (!ParseUnsigned(args[2], state.NumberBase, &length))
                {
                    std::wcerr << L"invalid query length\n";
                    break;
                }
            }

            if (!IsSafeTransferSize(length))
            {
                std::wcerr << L"query size exceeds native transfer limit\n";
                break;
            }

            std::wstring summary;
            if (device.QueryAddress(address, static_cast<uint32_t>(length), &summary, &error))
            {
                std::wcout << summary << L"\n";
            }
            else
            {
                std::wcerr << L"query failed: " << error << L"\n";
            }
        }
        else if (command == L"vtop" || command == L"!vtop")
        {
            HandleTranslateVirtualCommand(args, state, device, symbols);
        }
        else if (IsPhysicalDisplayCommand(command))
        {
            HandlePhysicalDisplayCommand(args, state, device);
        }
        else if (IsDisplayCommand(command))
        {
            HandleDisplayCommand(args, state, device, symbols);
        }
        else if (command == L"dt" || command == L"dtx")
        {
            HandleDtCommand(args, state, device, symbols);
        }
        else if (command == L"callbacks" || command == L"kcallbacks" || command == L"cb")
        {
            HandleCallbacksCommand(args, device, symbols);
        }
        else if (command == L"write" && args.size() >= 2)
        {
            bool enabled = args[1] == L"on";
            if (args[1] != L"on" && args[1] != L"off")
            {
                std::wcerr << L"usage: write on|off\n";
                break;
            }

            if (device.SetWriteMode(enabled, &error))
            {
                std::wcout << L"write mode: " << (enabled ? L"on" : L"off") << L"\n";
            }
            else
            {
                std::wcerr << L"write mode failed: " << error << L"\n";
            }
        }
        else if (IsPhysicalEnterCommand(command))
        {
            HandlePhysicalEnterCommand(args, state, device);
        }
        else if (IsEnterCommand(command))
        {
            HandleEnterCommand(args, state, device, symbols);
        }
        else if (command == L"setfield" && args.size() >= 5)
        {
            uint64_t address = 0;
            uint64_t value = 0;
            if (!ParseAddressOrSymbol(symbols, state, args[2], &address, &error))
            {
                std::wcerr << L"setfield failed: " << error << L"\n";
                break;
            }

            if (!ParseUnsigned(args[4], state.NumberBase, &value))
            {
                std::wcerr << L"invalid value\n";
                break;
            }

            TypeFieldInfo field = {};
            if (!symbols.FindField(args[1], args[3], &field, &error))
            {
                std::wcerr << L"setfield failed: " << error << L"\n";
                break;
            }

            size_t width = static_cast<size_t>(field.Length);
            if (width == 0 || width > sizeof(uint64_t))
            {
                width = sizeof(uint64_t);
            }

            std::vector<uint8_t> bytes = EncodeInteger(value, width);
            uint64_t fieldAddress = 0;
            if (!TryAddOffset(address, field.Offset, &fieldAddress))
            {
                std::wcerr << L"setfield address overflow\n";
                break;
            }

            if (device.WriteMemory(fieldAddress, bytes, &error))
            {
                std::wcout << L"wrote field " << field.Name << L" at +0x" << std::hex << field.Offset << std::dec << L"\n";
            }
            else
            {
                std::wcerr << L"setfield write failed: " << error << L"\n";
            }
        }
        else if (command == L"c")
        {
            HandleCompare(args, state, device, symbols);
        }
        else if (command == L"f" || command == L"fp")
        {
            HandleFill(args, state, device, symbols);
        }
        else if (command == L"m")
        {
            HandleMove(args, state, device, symbols);
        }
        else if (command == L"s")
        {
            HandleSearch(args, state, device, symbols);
        }
        else if (command == L"n")
        {
            if (args.size() >= 2)
            {
                uint64_t newBase = 0;
                if (ParseUnsigned(args[1], 10, &newBase) && (newBase == 10 || newBase == 16))
                {
                    state.NumberBase = static_cast<uint32_t>(newBase);
                }
                else
                {
                    std::wcerr << L"supported number bases: 10, 16\n";
                }
            }

            std::wcout << L"number base: " << state.NumberBase << L"\n";
        }
        else if (command == L"sq")
        {
            if (args.size() >= 2)
            {
                std::wstring value = ToLower(args[1]);
                state.Quiet = value == L"1" || value == L"on" || value == L"true";
            }

            std::wcout << L"quiet mode: " << (state.Quiet ? L"on" : L"off") << L"\n";
        }
        else if (command == L"version")
        {
            PrintVersion(device);
        }
        else if (command == L"vertarget")
        {
            PrintTarget();
        }
        else if (command == L"vercommand")
        {
            std::wcout << L"KnLiveDbg.exe - local live-memory kernel backend\n";
        }
        else if (command == L"drvstatus")
        {
            DriverStatus status = {};
            if (service.Query(&status, &error))
            {
                std::wcout << L"driver service: " << (status.Installed ? L"installed" : L"not installed");
                if (!status.StateText.empty())
                {
                    std::wcout << L" state=" << status.StateText;
                }
                std::wcout << L"\n";
            }
            else
            {
                std::wcerr << L"driver service query failed: " << error << L"\n";
            }
        }
        else if (command == L"||" || command == L"||s")
        {
            std::wcout << L"0: kd> local live-memory system\n";
        }
        else if (command == L"|")
        {
            std::wcout << L"0 id: current process context is not pinned by native backend\n";
        }
        else if (command == L"unload")
        {
            DriverUnloadResult unloadResult = {};
            device.Close();
            if (!service.StopAndDelete(&unloadResult, &error))
            {
                std::wcerr << L"unload failed: " << error << L"\n";
            }
            else
            {
                std::wcout << L"driver service removed";
                if (!unloadResult.FinalState.empty())
                {
                    std::wcout << L": " << unloadResult.FinalState;
                }
                std::wcout << L"\n";
            }
            keepRunning = false;
        }
        else if (command == L"q" || command == L"qq" || command == L"qd" || command == L"quit" || command == L"exit")
        {
            keepRunning = false;
        }
        else if (command.size() > 0 && command[0] == L'!')
        {
            if (state.Backend != DebuggerState::BackendMode::Native)
            {
                if (!ExecuteDbgEngCommand(dbgeng, symbols, state, originalLine, true))
                {
                    CommandRegistry::PrintCommandStatus(command);
                }
            }
            else
            {
                CommandRegistry::PrintCommandStatus(command);
            }
        }
        else if (CommandRegistry::IsKnown(command))
        {
            if (state.Backend != DebuggerState::BackendMode::Native && ShouldRouteToDbgEng(command))
            {
                if (!ExecuteDbgEngCommand(dbgeng, symbols, state, originalLine, true))
                {
                    CommandRegistry::PrintCommandStatus(command);
                }
            }
            else
            {
                CommandRegistry::PrintCommandStatus(command);
            }
        }
        else
        {
            std::wcerr << L"unknown command. type help or help all\n";
        }
    } while (false);

    return keepRunning;
}

int wmain(int argc, wchar_t** argv)
{
    UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);

    int exitCode = 1;

    do
    {
        SetConsoleCtrlHandler(ConsoleHandler, TRUE);

        if (!IsElevated())
        {
            std::wcerr << L"KnLiveDbg must run elevated to install and load the driver.\n";
            break;
        }

        std::wstring exeDir = GetExecutableDirectory();
        std::wstring driverPath = exeDir + L"\\KnLiveDbg.sys";

        DriverService service;
        std::wstring error;
        if (!service.EnsureLoaded(driverPath, &error))
        {
            std::wcerr << L"driver load failed: " << error << L"\n";
            std::wcerr << L"expected driver path: " << driverPath << L"\n";
            break;
        }

        DeviceClient device;
        for (int attempt = 0; attempt < 50; ++attempt)
        {
            if (device.Open(&error))
            {
                break;
            }

            Sleep(100);
        }

        if (!device.IsOpen())
        {
            std::wcerr << L"device open failed: " << error << L"\n";
            break;
        }

        if (!device.QueryVersion(&error))
        {
            std::wcerr << L"driver ABI check failed: " << error << L"\n";
            break;
        }

        SymbolEngine symbols;
        if (!symbols.Initialize(symbols.SymbolPath(), &error))
        {
            std::wcerr << L"symbol init warning: " << error << L"\n";
        }
        else if (!symbols.LoadKernelModules(&error))
        {
            std::wcerr << L"symbol reload warning: " << error << L"\n";
        }

        DebuggerState state = {};
        state.NumberBase = 16;
        state.Quiet = false;
        state.Backend = DebuggerState::BackendMode::Auto;

        DbgEngBackend dbgeng;

        std::wcout << L"KnLiveDbg ready. backend=auto. type help or help all\n";

        while (!g_StopRequested)
        {
            std::wcout << L"knkd> ";
            std::wstring line;
            if (!std::getline(std::wcin, line))
            {
                break;
            }

            if (line.empty() && !state.LastCommand.empty())
            {
                line = state.LastCommand;
                std::wcout << line << L"\n";
            }

            std::vector<std::wstring> args = Split(line);
            if (!args.empty())
            {
                state.LastCommand = line;
            }

            if (!HandleCommand(args, line, state, dbgeng, device, service, symbols))
            {
                break;
            }
        }

        dbgeng.Shutdown();
        device.Close();
        exitCode = 0;
    } while (false);

    return exitCode;
}
