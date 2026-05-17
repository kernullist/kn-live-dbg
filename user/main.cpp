#include "AiProvider.h"
#include "CallbackScanner.h"
#include "CommandRegistry.h"
#include "DbgEngBackend.h"
#include "DeviceClient.h"
#include "DriverService.h"
#include "SymbolEngine.h"

#include "../shared/KnLiveDbgIoctl.h"
#include "../shared/KnLiveDbgProbeIoctl.h"

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

static std::wstring FormatWin32Error(const wchar_t* prefix, DWORD error)
{
    wchar_t buffer[512] = {};
    FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        error,
        0,
        buffer,
        static_cast<DWORD>(_countof(buffer)),
        nullptr);

    std::wstringstream stream;
    stream << prefix << L": " << error << L" " << buffer;
    return stream.str();
}

struct DebuggerState
{
    uint32_t NumberBase;
    bool Quiet;
    std::wstring LastCommand;
    std::wstring DbgEngConnectOptions;
    bool DbgEngRemoteKernel;
    uint64_t LastDisassemblyAddress;
    bool HasLastDisassemblyAddress;
    bool HasProcessContext;
    ProcessAddressContext ProcessContext;
    enum class BackendMode
    {
        Auto,
        Native,
        DbgEng
    } Backend;
};

struct AiCommandProposal
{
    std::wstring Command;
    std::wstring Purpose;
    std::wstring Risk;
    std::wstring Backend;
    std::wstring ExpectedOutput;
    bool RequiresConfirmation;
    bool WriteLike;
};

struct AiPlanState
{
    std::wstring Schema;
    std::wstring Title;
    std::wstring Summary;
    std::wstring RawResponse;
    std::vector<AiCommandProposal> Commands;
    std::wstring TranscriptPath;
    bool TranscriptEnabled;
    uint64_t TranscriptMaxBytes;
    bool TranscriptRedactOutput;
    uint32_t TranscriptRotationIndex;
    std::wstring WriteAuditPath;
    bool WriteAuditEnabled;
};

struct CommandExecutionResult
{
    bool KeepRunning;
    std::wstring Output;
    std::wstring Error;
};

struct AiWriteSafetyPlan
{
    std::wstring TargetKind;
    std::wstring Target;
    std::wstring ByteCountText;
    std::wstring BackupCommand;
    std::wstring RestoreCommand;
    std::wstring VerifyCommand;
    std::wstring TranslationCommand;
    std::wstring Warning;
};

static void PreserveAiSessionSettings(AiPlanState& target, const AiPlanState& source)
{
    target.TranscriptPath = source.TranscriptPath;
    target.TranscriptEnabled = source.TranscriptEnabled;
    target.TranscriptMaxBytes = source.TranscriptMaxBytes;
    target.TranscriptRedactOutput = source.TranscriptRedactOutput;
    target.TranscriptRotationIndex = source.TranscriptRotationIndex;
    target.WriteAuditPath = source.WriteAuditPath;
    target.WriteAuditEnabled = source.WriteAuditEnabled;
}

static bool WriteUtf8TextFile(const std::wstring& path, const std::wstring& text, std::wstring* error);
static std::wstring BuildCallbackScanJson(
    const std::wstring& scope,
    const KernelCallbackScanResult& result);

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

static std::wstring TrimWhitespace(const std::wstring& value)
{
    std::wstring result;

    do
    {
        size_t first = 0;
        while (first < value.size() && std::iswspace(value[first]) != 0)
        {
            ++first;
        }

        if (first >= value.size())
        {
            break;
        }

        size_t last = value.size();
        while (last > first && std::iswspace(value[last - 1]) != 0)
        {
            --last;
        }

        result = value.substr(first, last - first);
    } while (false);

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

static std::wstring GetCurrentDirectoryString()
{
    std::wstring result;

    do
    {
        DWORD required = GetCurrentDirectoryW(0, nullptr);
        if (required == 0)
        {
            break;
        }

        std::wstring buffer(required, L'\0');
        DWORD written = GetCurrentDirectoryW(required, &buffer[0]);
        if (written == 0 || written >= required)
        {
            break;
        }

        buffer.resize(written);
        result = buffer;
    } while (false);

    return result;
}

static std::wstring GetFullPathString(const std::wstring& path)
{
    std::wstring result = path;

    do
    {
        if (path.empty())
        {
            break;
        }

        DWORD required = GetFullPathNameW(path.c_str(), 0, nullptr, nullptr);
        if (required == 0)
        {
            break;
        }

        std::wstring buffer(required, L'\0');
        DWORD written = GetFullPathNameW(path.c_str(), required, &buffer[0], nullptr);
        if (written == 0 || written >= required)
        {
            break;
        }

        buffer.resize(written);
        result = buffer;
    } while (false);

    return result;
}

static void AddUniquePath(std::vector<std::wstring>& paths, const std::wstring& path)
{
    do
    {
        if (path.empty())
        {
            break;
        }

        std::wstring normalized = GetFullPathString(path);
        std::wstring lowered = ToLower(normalized);
        for (const std::wstring& existing : paths)
        {
            if (ToLower(existing) == lowered)
            {
                return;
            }
        }

        paths.push_back(normalized);
    } while (false);
}

static bool EndsWithNoCase(const std::wstring& value, const std::wstring& suffix)
{
    bool result = false;

    if (value.size() >= suffix.size())
    {
        result = ToLower(value.substr(value.size() - suffix.size())) == ToLower(suffix);
    }

    return result;
}

static std::vector<std::wstring> BuildDotEnvSearchPaths(const std::wstring& exeDir)
{
    std::vector<std::wstring> paths;

    std::wstring cwd = GetCurrentDirectoryString();
    if (!cwd.empty())
    {
        AddUniquePath(paths, cwd + L"\\.env");
    }

    if (!exeDir.empty())
    {
        AddUniquePath(paths, exeDir + L"\\.env");
        if (EndsWithNoCase(exeDir, L"\\x64\\Debug") || EndsWithNoCase(exeDir, L"\\x64\\Release"))
        {
            AddUniquePath(paths, exeDir + L"\\..\\..\\.env");
        }
    }

    return paths;
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
    std::wcout << L"  callbacks json all .\\callbacks.json\n";
    std::wcout << L"  procctx <pid>\n";
    std::wcout << L"  vtop /pid <pid> <user-address>\n";
    std::wcout << L"  db /pid <pid> <user-address> 80\n";
    std::wcout << L"  vtop nt!PsLoadedModuleList\n";
    std::wcout << L"  pdb <physical-address> 80\n";
    std::wcout << L"  probe load\n";
    std::wcout << L"  probe info\n";
    std::wcout << L"  kdinit\n";
    std::wcout << L"  backend dbgeng\n";
    std::wcout << L"  !process 0 0\n";
    std::wcout << L"  write off\n";
    std::wcout << L"  ed <address> <value>\n";
    std::wcout << L"  peq <physical-address> <value>\n";
    std::wcout << L"  ai ask explain this callback scan result\n";
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

        if (!dbgeng.Initialize(symbols.SymbolPath(), state.DbgEngConnectOptions, state.DbgEngRemoteKernel, error))
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

static std::wstring HexText(uint64_t value)
{
    std::wstringstream stream;

    stream << L"0x" << std::hex << value << std::dec;
    return stream.str();
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

static bool ResolveProcessAddressContext(
    DeviceClient& device,
    SymbolEngine& symbols,
    uint32_t processId,
    ProcessAddressContext* context,
    std::wstring* error);

static bool ReadMemoryWithProcessContext(
    DeviceClient& device,
    const DebuggerState& state,
    const ProcessAddressContext* explicitContext,
    uint64_t address,
    uint32_t length,
    std::vector<uint8_t>* bytes,
    std::wstring* error);

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
            std::wcerr << L"usage: " << command << L" [/pid <process-id>] <address|symbol> [count]\n";
            break;
        }

        size_t argIndex = 1;
        ProcessAddressContext explicitContext = {};
        bool hasExplicitContext = false;
        if (ToLower(args[argIndex]) == L"/pid" || ToLower(args[argIndex]) == L"/process")
        {
            if (args.size() < 4)
            {
                std::wcerr << L"usage: " << command << L" /pid <process-id> <address|symbol> [count]\n";
                break;
            }

            uint64_t processId = 0;
            if (!ParseUnsigned(args[argIndex + 1], state.NumberBase, &processId) || processId == 0 || processId > 0xffffffffull)
            {
                std::wcerr << L"invalid process id\n";
                break;
            }

            if (!ResolveProcessAddressContext(device, symbols, static_cast<uint32_t>(processId), &explicitContext, &error))
            {
                std::wcerr << L"process context failed: " << error << L"\n";
                break;
            }

            hasExplicitContext = true;
            argIndex += 2;
        }

        uint64_t address = 0;
        if (!ParseAddressOrSymbol(symbols, state, args[argIndex], &address, &error))
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
        if (!GetCountArgument(args, argIndex + 1, defaultCount, state, &count))
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
        const ProcessAddressContext* memoryContext = hasExplicitContext ? &explicitContext : nullptr;
        if (!ReadMemoryWithProcessContext(device, state, memoryContext, address, byteCount, &bytes, &error))
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
                    if (ReadMemoryWithProcessContext(device, state, memoryContext, pointer, 128, &refBytes, &error))
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
                    if (ReadMemoryWithProcessContext(device, state, memoryContext, pointer, 128 * sizeof(wchar_t), &refBytes, &error))
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

static bool FindFieldAny(
    SymbolEngine& symbols,
    const std::vector<std::wstring>& typeNames,
    const std::wstring& fieldName,
    TypeFieldInfo* field,
    std::wstring* error)
{
    bool ok = false;
    std::wstring lastError;

    do
    {
        if (field == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid field output";
            }
            break;
        }

        for (const std::wstring& typeName : typeNames)
        {
            std::wstring localError;
            if (symbols.FindField(typeName, fieldName, field, &localError))
            {
                ok = true;
                break;
            }

            if (!localError.empty())
            {
                lastError = localError;
            }
        }

        if (!ok && error != nullptr)
        {
            *error = lastError.empty() ? L"field not found" : lastError;
        }
    } while (false);

    return ok;
}

static bool ResolveProcessDirectoryTableBaseOffsets(
    SymbolEngine& symbols,
    uint32_t* directoryTableBaseOffset,
    uint32_t* userDirectoryTableBaseOffset,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (directoryTableBaseOffset == nullptr || userDirectoryTableBaseOffset == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid process offset output";
            }
            break;
        }

        if (symbols.Modules().empty())
        {
            if (!symbols.LoadKernelModules(error))
            {
                break;
            }
        }

        TypeFieldInfo pcbField = {};
        if (!FindFieldAny(symbols, {L"nt!_EPROCESS", L"_EPROCESS"}, L"Pcb", &pcbField, error))
        {
            break;
        }

        TypeFieldInfo dtbField = {};
        if (!FindFieldAny(symbols, {L"nt!_KPROCESS", L"_KPROCESS"}, L"DirectoryTableBase", &dtbField, error))
        {
            break;
        }

        uint64_t dtbOffset = static_cast<uint64_t>(pcbField.Offset) + dtbField.Offset;
        if (dtbOffset > 0xffffffffull)
        {
            if (error != nullptr)
            {
                *error = L"DirectoryTableBase offset is too large";
            }
            break;
        }

        *directoryTableBaseOffset = static_cast<uint32_t>(dtbOffset);
        *userDirectoryTableBaseOffset = 0;

        TypeFieldInfo userDtbField = {};
        std::wstring ignored;
        if (FindFieldAny(symbols, {L"nt!_KPROCESS", L"_KPROCESS"}, L"UserDirectoryTableBase", &userDtbField, &ignored))
        {
            uint64_t userDtbOffset = static_cast<uint64_t>(pcbField.Offset) + userDtbField.Offset;
            if (userDtbOffset <= 0xffffffffull)
            {
                *userDirectoryTableBaseOffset = static_cast<uint32_t>(userDtbOffset);
            }
        }

        ok = true;
    } while (false);

    return ok;
}

static bool ResolveProcessAddressContext(
    DeviceClient& device,
    SymbolEngine& symbols,
    uint32_t processId,
    ProcessAddressContext* context,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (context == nullptr || processId == 0)
        {
            if (error != nullptr)
            {
                *error = L"invalid process id";
            }
            break;
        }

        uint32_t dtbOffset = 0;
        uint32_t userDtbOffset = 0;
        if (!ResolveProcessDirectoryTableBaseOffsets(symbols, &dtbOffset, &userDtbOffset, error))
        {
            break;
        }

        if (!device.ResolveProcess(processId, dtbOffset, userDtbOffset, context, error))
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool IsLikelyUserVirtualAddress(uint64_t virtualAddress)
{
    return virtualAddress < 0x0000800000000000ull;
}

static uint64_t SelectProcessDirectoryTableBase(const ProcessAddressContext& context, uint64_t virtualAddress)
{
    uint64_t directoryTableBase = context.DirectoryTableBase;

    if (context.UserDirectoryTableBase != 0 && IsLikelyUserVirtualAddress(virtualAddress))
    {
        directoryTableBase = context.UserDirectoryTableBase;
    }

    return directoryTableBase;
}

static void PrintProcessAddressContext(const ProcessAddressContext& context)
{
    std::wcout << L"pid=" << context.ProcessId
               << L" eprocess=0x" << std::hex << std::setw(16) << std::setfill(L'0') << context.Eprocess
               << L" dtb=0x" << std::setw(16) << context.DirectoryTableBase;
    if (context.UserDirectoryTableBase != 0)
    {
        std::wcout << L" user-dtb=0x" << std::setw(16) << context.UserDirectoryTableBase;
    }
    std::wcout << std::dec << L"\n";
}

static bool ReadProcessVirtualMemory(
    DeviceClient& device,
    const ProcessAddressContext& context,
    uint64_t address,
    uint32_t length,
    std::vector<uint8_t>* bytes,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (bytes == nullptr || length == 0)
        {
            if (error != nullptr)
            {
                *error = L"Invalid process read request";
            }
            break;
        }

        bytes->clear();
        bytes->reserve(length);

        uint64_t current = address;
        uint32_t remaining = length;
        while (remaining != 0)
        {
            PhysicalTranslationInfo translation = {};
            uint64_t directoryTableBase = SelectProcessDirectoryTableBase(context, current);
            if (!device.TranslateVirtual(directoryTableBase, current, remaining, &translation, error))
            {
                break;
            }

            uint32_t chunk = translation.TranslatedLength;
            if (chunk == 0 || chunk > remaining)
            {
                chunk = remaining;
            }

            std::vector<uint8_t> pageBytes;
            if (!device.ReadPhysical(translation.PhysicalAddress, chunk, &pageBytes, error))
            {
                break;
            }

            if (pageBytes.size() != chunk)
            {
                if (error != nullptr)
                {
                    *error = L"Short process physical read";
                }
                break;
            }

            bytes->insert(bytes->end(), pageBytes.begin(), pageBytes.end());
            current += chunk;
            remaining -= chunk;
        }

        ok = remaining == 0;
    } while (false);

    return ok;
}

static bool WriteProcessVirtualMemory(
    DeviceClient& device,
    const ProcessAddressContext& context,
    uint64_t address,
    const std::vector<uint8_t>& bytes,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (bytes.empty())
        {
            if (error != nullptr)
            {
                *error = L"Invalid process write request";
            }
            break;
        }

        uint64_t current = address;
        size_t offset = 0;
        size_t remaining = bytes.size();
        while (remaining != 0)
        {
            PhysicalTranslationInfo translation = {};
            uint64_t directoryTableBase = SelectProcessDirectoryTableBase(context, current);
            uint32_t requestLength = static_cast<uint32_t>(std::min<size_t>(remaining, KNDBG_MAX_TRANSFER_SIZE));
            if (!device.TranslateVirtual(directoryTableBase, current, requestLength, &translation, error))
            {
                break;
            }

            uint32_t chunk = translation.TranslatedLength;
            if (chunk == 0 || chunk > requestLength)
            {
                chunk = requestLength;
            }

            std::vector<uint8_t> pageBytes(bytes.begin() + offset, bytes.begin() + offset + chunk);
            if (!device.WritePhysical(translation.PhysicalAddress, pageBytes, error))
            {
                break;
            }

            current += chunk;
            offset += chunk;
            remaining -= chunk;
        }

        ok = remaining == 0;
    } while (false);

    return ok;
}

static const ProcessAddressContext* SelectMemoryAccessContext(
    const DebuggerState& state,
    const ProcessAddressContext* explicitContext,
    uint64_t address)
{
    const ProcessAddressContext* context = explicitContext;

    if (context == nullptr && state.HasProcessContext && IsLikelyUserVirtualAddress(address))
    {
        context = &state.ProcessContext;
    }

    return context;
}

static bool ReadMemoryWithProcessContext(
    DeviceClient& device,
    const DebuggerState& state,
    const ProcessAddressContext* explicitContext,
    uint64_t address,
    uint32_t length,
    std::vector<uint8_t>* bytes,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        const ProcessAddressContext* context = SelectMemoryAccessContext(state, explicitContext, address);
        if (context != nullptr)
        {
            ok = ReadProcessVirtualMemory(device, *context, address, length, bytes, error);
        }
        else
        {
            ok = device.ReadMemory(address, length, bytes, error);
        }
    } while (false);

    return ok;
}

static bool WriteMemoryWithProcessContext(
    DeviceClient& device,
    const DebuggerState& state,
    const ProcessAddressContext* explicitContext,
    uint64_t address,
    const std::vector<uint8_t>& bytes,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        const ProcessAddressContext* context = SelectMemoryAccessContext(state, explicitContext, address);
        if (context != nullptr)
        {
            ok = WriteProcessVirtualMemory(device, *context, address, bytes, error);
        }
        else
        {
            ok = device.WriteMemory(address, bytes, error);
        }
    } while (false);

    return ok;
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
            std::wcerr << L"usage: vtop /pid <process-id> <address|symbol> [length]\n";
            std::wcerr << L"usage: !vtop <address|symbol> [length]\n";
            std::wcerr << L"usage: !vtop <directory-table-base> <address|symbol> [length]\n";
            break;
        }

        uint64_t directoryTableBase = 0;
        uint64_t virtualAddress = 0;
        uint64_t length = 1;
        size_t index = 1;
        bool hasProcessContext = false;
        ProcessAddressContext processContext = {};

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
        else if (command == L"vtop" && (ToLower(args[index]) == L"/pid" || ToLower(args[index]) == L"/process"))
        {
            if (args.size() < 4)
            {
                std::wcerr << L"usage: vtop /pid <process-id> <address|symbol> [length]\n";
                break;
            }

            uint64_t pid64 = 0;
            if (!ParseUnsigned(args[2], 10, &pid64) || pid64 == 0 || pid64 > 0xffffffffull)
            {
                std::wcerr << L"invalid process id\n";
                break;
            }

            if (!ParseAddressOrSymbol(symbols, state, args[3], &virtualAddress, &error))
            {
                std::wcerr << L"vtop failed: " << error << L"\n";
                break;
            }

            if (!ResolveProcessAddressContext(device, symbols, static_cast<uint32_t>(pid64), &processContext, &error))
            {
                std::wcerr << L"vtop process resolve failed: " << error << L"\n";
                break;
            }

            directoryTableBase = SelectProcessDirectoryTableBase(processContext, virtualAddress);
            hasProcessContext = true;
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

        if (directoryTableBase == 0 && state.HasProcessContext)
        {
            processContext = state.ProcessContext;
            directoryTableBase = SelectProcessDirectoryTableBase(processContext, virtualAddress);
            hasProcessContext = true;
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

        if (hasProcessContext)
        {
            std::wcout << L"process-context ";
            PrintProcessAddressContext(processContext);
        }

        std::wcout << L"va=0x" << std::hex << std::setw(16) << std::setfill(L'0') << info.VirtualAddress
                   << L" pa=0x" << std::setw(16) << info.PhysicalAddress
                   << L" cr3=0x" << std::setw(16) << info.DirectoryTableBase << std::dec << L"\n";
        std::wcout << L"page-size=0x" << std::hex << info.PageSize
                   << L" page-offset=0x" << info.PageOffset
                   << L" page-bytes=0x" << info.PageBytes
                   << L" translated=0x" << info.TranslatedLength << std::dec << L"\n";
        if ((info.Flags & KNDBG_TRANSLATE_FLAG_LA57_ACTIVE) != 0)
        {
            std::wcout << L"pml5e=0x" << std::hex << std::setw(16) << info.Pml5e << L"\n";
        }
        std::wcout << L"pml4e=0x" << std::hex << std::setw(16) << info.Pml4e
                   << L" pdpte=0x" << std::setw(16) << info.Pdpte
                   << L" pde=0x" << std::setw(16) << info.Pde
                   << L" pte=0x" << std::setw(16) << info.Pte << std::dec << L"\n";
    } while (false);
}

static void HandleProcessContextCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    std::wstring error;

    do
    {
        if (args.size() < 2 || ToLower(args[1]) == L"status")
        {
            if (state.HasProcessContext)
            {
                std::wcout << L"process context: ";
                PrintProcessAddressContext(state.ProcessContext);
            }
            else
            {
                std::wcout << L"process context: off\n";
            }
            break;
        }

        std::wstring action = ToLower(args[1]);
        if (action == L"off" || action == L"clear")
        {
            state.HasProcessContext = false;
            state.ProcessContext = {};
            std::wcout << L"process context: off\n";
            break;
        }

        uint64_t pid64 = 0;
        if (!ParseUnsigned(args[1], 10, &pid64) || pid64 == 0 || pid64 > 0xffffffffull)
        {
            std::wcerr << L"usage: procctx <process-id|off|status>\n";
            break;
        }

        ProcessAddressContext context = {};
        if (!ResolveProcessAddressContext(device, symbols, static_cast<uint32_t>(pid64), &context, &error))
        {
            std::wcerr << L"procctx failed: " << error << L"\n";
            break;
        }

        state.ProcessContext = context;
        state.HasProcessContext = true;
        std::wcout << L"process context: ";
        PrintProcessAddressContext(state.ProcessContext);
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
            std::wcerr << L"usage: " << command << L" [/pid <process-id>] <address|symbol> <value...>\n";
            break;
        }

        size_t argIndex = 1;
        ProcessAddressContext explicitContext = {};
        bool hasExplicitContext = false;
        if (ToLower(args[argIndex]) == L"/pid" || ToLower(args[argIndex]) == L"/process")
        {
            if (args.size() < 5)
            {
                std::wcerr << L"usage: " << command << L" /pid <process-id> <address|symbol> <value...>\n";
                break;
            }

            uint64_t processId = 0;
            if (!ParseUnsigned(args[argIndex + 1], state.NumberBase, &processId) || processId == 0 || processId > 0xffffffffull)
            {
                std::wcerr << L"invalid process id\n";
                break;
            }

            if (!ResolveProcessAddressContext(device, symbols, static_cast<uint32_t>(processId), &explicitContext, &error))
            {
                std::wcerr << L"process context failed: " << error << L"\n";
                break;
            }

            hasExplicitContext = true;
            argIndex += 2;
        }

        uint64_t address = 0;
        if (!ParseAddressOrSymbol(symbols, state, args[argIndex], &address, &error))
        {
            std::wcerr << L"write failed: " << error << L"\n";
            break;
        }

        std::vector<uint8_t> bytes;
        if (command == L"ea" || command == L"eza" || command == L"eu" || command == L"ezu")
        {
            bool unicode = command == L"eu" || command == L"ezu";
            bool zeroTerminate = command == L"eza" || command == L"ezu";
            bytes = EncodeString(JoinArgs(args, argIndex + 1), unicode, zeroTerminate);
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
            for (size_t index = argIndex + 1; index < args.size(); ++index)
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

        const ProcessAddressContext* memoryContext = hasExplicitContext ? &explicitContext : nullptr;
        if (WriteMemoryWithProcessContext(device, state, memoryContext, address, bytes, &error))
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

    std::wcout << L"KnLiveDbg version 0.4\n";
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

static HANDLE OpenProbeDevice(std::wstring* error)
{
    HANDLE device = INVALID_HANDLE_VALUE;

    do
    {
        device = CreateFileW(
            KNDBG_PROBE_USER_DEVICE_NAME,
            GENERIC_READ | GENERIC_WRITE,
            0,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);

        if (device == INVALID_HANDLE_VALUE && error != nullptr)
        {
            *error = FormatWin32Error(L"CreateFileW KnLiveDbgProbe failed", GetLastError());
        }
    } while (false);

    return device;
}

static bool QueryProbeInfo(KNDBG_PROBE_INFO_RESPONSE* response, std::wstring* error)
{
    bool ok = false;
    HANDLE device = INVALID_HANDLE_VALUE;

    do
    {
        if (response == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid probe info output";
            }
            break;
        }

        device = OpenProbeDevice(error);
        if (device == INVALID_HANDLE_VALUE)
        {
            break;
        }

        KNDBG_PROBE_INFO_RESPONSE local = {};
        DWORD returned = 0;
        if (!DeviceIoControl(
                device,
                IOCTL_KNDBG_PROBE_GET_INFO,
                nullptr,
                0,
                &local,
                sizeof(local),
                &returned,
                nullptr))
        {
            if (error != nullptr)
            {
                *error = FormatWin32Error(L"IOCTL_KNDBG_PROBE_GET_INFO failed", GetLastError());
            }
            break;
        }

        if (returned < sizeof(local) ||
            local.Size != sizeof(local) ||
            local.AbiVersion != KNDBG_PROBE_ABI_VERSION ||
            local.BufferLength != KNDBG_PROBE_BUFFER_LENGTH)
        {
            if (error != nullptr)
            {
                *error = L"Probe driver ABI response is invalid";
            }
            break;
        }

        *response = local;
        ok = true;
    } while (false);

    if (device != INVALID_HANDLE_VALUE)
    {
        CloseHandle(device);
    }

    return ok;
}

static bool ResetProbePattern(std::wstring* error)
{
    bool ok = false;
    HANDLE device = INVALID_HANDLE_VALUE;

    do
    {
        device = OpenProbeDevice(error);
        if (device == INVALID_HANDLE_VALUE)
        {
            break;
        }

        DWORD returned = 0;
        if (!DeviceIoControl(
                device,
                IOCTL_KNDBG_PROBE_RESET_PATTERN,
                nullptr,
                0,
                nullptr,
                0,
                &returned,
                nullptr))
        {
            if (error != nullptr)
            {
                *error = FormatWin32Error(L"IOCTL_KNDBG_PROBE_RESET_PATTERN failed", GetLastError());
            }
            break;
        }

        ok = true;
    } while (false);

    if (device != INVALID_HANDLE_VALUE)
    {
        CloseHandle(device);
    }

    return ok;
}

static void PrintProbeInfo(const KNDBG_PROBE_INFO_RESPONSE& info)
{
    std::wcout << L"probe abi=" << info.AbiVersion
               << L" length=0x" << std::hex << info.BufferLength
               << L" seed=0x" << info.PatternSeed << std::dec << L"\n";
    std::wcout << L"probe virtual=0x" << std::hex << std::setw(16) << std::setfill(L'0')
               << info.BufferVirtualAddress << L"\n";
    std::wcout << L"probe physical=0x" << std::setw(16) << info.BufferPhysicalAddress
               << std::setfill(L' ') << std::dec << L"\n";
    std::wcout << L"try: db 0x" << std::hex << info.BufferVirtualAddress
               << L" 40; pdb 0x" << info.BufferPhysicalAddress
               << L" 40" << std::dec << L"\n";
}

static void HandleProbeCommand(const std::vector<std::wstring>& args)
{
    std::wstring action = args.size() >= 2 ? ToLower(args[1]) : L"status";
    std::wstring error;
    DriverService probeService(KNDBG_PROBE_SERVICE_NAME, KNDBG_PROBE_DISPLAY_NAME);

    do
    {
        if (action == L"load" || action == L"install" || action == L"start")
        {
            std::wstring driverPath = args.size() >= 3 ? JoinArgs(args, 2) : GetExecutableDirectory() + L"\\KnLiveDbgProbe.sys";
            if (!probeService.EnsureLoaded(driverPath, &error))
            {
                std::wcerr << L"probe load failed: " << error << L"\n";
                std::wcerr << L"expected probe path: " << driverPath << L"\n";
                break;
            }

            std::wcout << L"probe driver loaded: " << driverPath << L"\n";
            KNDBG_PROBE_INFO_RESPONSE info = {};
            if (QueryProbeInfo(&info, &error))
            {
                PrintProbeInfo(info);
            }
            else
            {
                std::wcerr << L"probe info failed: " << error << L"\n";
            }
        }
        else if (action == L"unload" || action == L"remove" || action == L"stop")
        {
            DriverUnloadResult unloadResult = {};
            if (!probeService.StopAndDelete(&unloadResult, &error))
            {
                std::wcerr << L"probe unload failed: " << error << L"\n";
                break;
            }

            std::wcout << L"probe service removed";
            if (!unloadResult.FinalState.empty())
            {
                std::wcout << L": " << unloadResult.FinalState;
            }
            std::wcout << L"\n";
        }
        else if (action == L"status")
        {
            DriverStatus status = {};
            if (!probeService.Query(&status, &error))
            {
                std::wcerr << L"probe service query failed: " << error << L"\n";
                break;
            }

            std::wcout << L"probe service: " << (status.Installed ? L"installed" : L"not installed");
            if (!status.StateText.empty())
            {
                std::wcout << L" state=" << status.StateText;
            }
            std::wcout << L"\n";

            if (status.CurrentState == SERVICE_RUNNING)
            {
                KNDBG_PROBE_INFO_RESPONSE info = {};
                if (QueryProbeInfo(&info, &error))
                {
                    PrintProbeInfo(info);
                }
                else
                {
                    std::wcerr << L"probe info failed: " << error << L"\n";
                }
            }
        }
        else if (action == L"info")
        {
            KNDBG_PROBE_INFO_RESPONSE info = {};
            if (!QueryProbeInfo(&info, &error))
            {
                std::wcerr << L"probe info failed: " << error << L"\n";
                break;
            }

            PrintProbeInfo(info);
        }
        else if (action == L"reset")
        {
            if (!ResetProbePattern(&error))
            {
                std::wcerr << L"probe reset failed: " << error << L"\n";
                break;
            }

            std::wcout << L"probe pattern reset\n";
        }
        else
        {
            std::wcerr << L"usage: probe [status|load [sys-path]|info|reset|unload]\n";
        }
    } while (false);
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

static bool IsCallbackScopeName(const std::wstring& value)
{
    bool result = false;
    std::wstring lowered = ToLower(value);

    if (lowered == L"all" ||
        lowered == L"ob" ||
        lowered == L"object" ||
        lowered == L"object-manager" ||
        lowered == L"registry" ||
        lowered == L"reg" ||
        lowered == L"process" ||
        lowered == L"ps" ||
        lowered == L"minifilter" ||
        lowered == L"flt" ||
        lowered == L"fltmgr")
    {
        result = true;
    }

    return result;
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
        bool jsonOutput = false;
        std::wstring jsonPath;
        if (args.size() >= 2)
        {
            std::wstring first = ToLower(args[1]);
            if (first == L"json" || first == L"--json")
            {
                jsonOutput = true;
                if (args.size() >= 3)
                {
                    if (IsCallbackScopeName(args[2]))
                    {
                        scope = args[2];
                        if (args.size() >= 4)
                        {
                            jsonPath = JoinArgs(args, 3);
                        }
                    }
                    else
                    {
                        jsonPath = JoinArgs(args, 2);
                    }
                }
            }
            else
            {
                scope = args[1];
                if (args.size() >= 3)
                {
                    std::wstring second = ToLower(args[2]);
                    if (second == L"json" || second == L"--json")
                    {
                        jsonOutput = true;
                        if (args.size() >= 4)
                        {
                            jsonPath = JoinArgs(args, 3);
                        }
                    }
                }
            }
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

        if (jsonOutput)
        {
            std::wstring json = BuildCallbackScanJson(scope, result);
            if (!jsonPath.empty() && jsonPath != L"-")
            {
                if (!WriteUtf8TextFile(jsonPath, json + L"\n", &error))
                {
                    std::wcerr << L"callback json write failed: " << error << L"\n";
                    break;
                }

                std::wcout << L"callback json written: " << jsonPath << L"\n";
            }
            else
            {
                std::wcout << json << L"\n";
            }
            break;
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

static std::wstring BuildAiSystemPrompt(const DebuggerState& state, const SymbolEngine& symbols)
{
    std::wstringstream stream;

    stream << L"KnLiveDbg session context:\n";
    stream << L"- backend: " << BackendModeText(state.Backend) << L"\n";
    stream << L"- number base: " << state.NumberBase << L"\n";
    stream << L"- symbol path: " << symbols.SymbolPath() << L"\n";
    stream << L"- loaded kernel modules: " << symbols.Modules().size() << L"\n";
    stream << L"- write mode is enabled by default per device handle unless the operator ran write off\n";
    stream << L"Rules:\n";
    stream << L"- Prefer concrete KnLiveDbg commands and exact preview text.\n";
    stream << L"- Treat AI output as advisory and require operator confirmation for writes.\n";
    stream << L"- For memory writes, mention backup, restore, and readback verification commands.\n";
    stream << L"- Do not claim live state was inspected unless command output was provided in the prompt.\n";

    return stream.str();
}

static void PrintAiProviders()
{
    std::wcout << L"supported AI providers:\n";
    for (const std::wstring& provider : AiProviderRuntime::SupportedProviderNames())
    {
        std::wcout << L"  " << provider << L"\n";
    }
}

static bool ParseDecimalIndex(const std::wstring& value, size_t* output)
{
    bool ok = false;

    do
    {
        if (output == nullptr || value.empty())
        {
            break;
        }

        wchar_t* end = nullptr;
        unsigned long parsed = wcstoul(value.c_str(), &end, 10);
        if (end == nullptr || *end != L'\0' || parsed == 0)
        {
            break;
        }

        *output = static_cast<size_t>(parsed);
        ok = true;
    } while (false);

    return ok;
}

static std::wstring EscapeJsonText(const std::wstring& value)
{
    std::wstringstream stream;

    for (wchar_t ch : value)
    {
        switch (ch)
        {
        case L'\"':
            stream << L"\\\"";
            break;
        case L'\\':
            stream << L"\\\\";
            break;
        case L'\b':
            stream << L"\\b";
            break;
        case L'\f':
            stream << L"\\f";
            break;
        case L'\n':
            stream << L"\\n";
            break;
        case L'\r':
            stream << L"\\r";
            break;
        case L'\t':
            stream << L"\\t";
            break;
        default:
            if (ch < 0x20)
            {
                stream << L"\\u" << std::hex << std::setw(4) << std::setfill(L'0') << static_cast<unsigned int>(ch);
            }
            else
            {
                stream << ch;
            }
            break;
        }
    }

    return stream.str();
}

static std::string WideToUtf8ForLog(const std::wstring& value)
{
    std::string result;

    do
    {
        if (value.empty())
        {
            break;
        }

        int required = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), nullptr, 0, nullptr, nullptr);
        if (required <= 0)
        {
            break;
        }

        result.resize(required);
        WideCharToMultiByte(CP_UTF8, 0, value.c_str(), static_cast<int>(value.size()), &result[0], required, nullptr, nullptr);
    } while (false);

    return result;
}

static std::wstring CurrentUtcTimestamp()
{
    SYSTEMTIME now = {};
    wchar_t buffer[64] = {};

    GetSystemTime(&now);
    swprintf_s(
        buffer,
        L"%04u-%02u-%02uT%02u:%02u:%02u.%03uZ",
        now.wYear,
        now.wMonth,
        now.wDay,
        now.wHour,
        now.wMinute,
        now.wSecond,
        now.wMilliseconds);

    return buffer;
}

static std::wstring FixedHex32Text(uint32_t value)
{
    std::wstringstream stream;

    stream << L"0x" << std::hex << std::setw(8) << std::setfill(L'0') << value << std::dec;
    return stream.str();
}

static std::wstring FixedHex64Text(uint64_t value)
{
    std::wstringstream stream;

    stream << L"0x" << std::hex << std::setw(16) << std::setfill(L'0') << value << std::dec;
    return stream.str();
}

static void AppendJsonStringProperty(
    std::wstringstream& stream,
    const wchar_t* indent,
    const wchar_t* name,
    const std::wstring& value,
    bool comma)
{
    stream << indent << L"\"" << name << L"\":\"" << EscapeJsonText(value) << L"\"";
    if (comma)
    {
        stream << L",";
    }
    stream << L"\n";
}

static void AppendJsonUint32Property(
    std::wstringstream& stream,
    const wchar_t* indent,
    const wchar_t* name,
    uint32_t value,
    bool comma)
{
    stream << indent << L"\"" << name << L"\":" << value;
    if (comma)
    {
        stream << L",";
    }
    stream << L"\n";
}

static void AppendJsonNullableUint32Property(
    std::wstringstream& stream,
    const wchar_t* indent,
    const wchar_t* name,
    uint32_t value,
    uint32_t nullValue,
    bool comma)
{
    stream << indent << L"\"" << name << L"\":";
    if (value == nullValue)
    {
        stream << L"null";
    }
    else
    {
        stream << value;
    }

    if (comma)
    {
        stream << L",";
    }
    stream << L"\n";
}

static void AppendJsonHex32Property(
    std::wstringstream& stream,
    const wchar_t* indent,
    const wchar_t* name,
    uint32_t value,
    bool comma)
{
    stream << indent << L"\"" << name << L"\":\"" << FixedHex32Text(value) << L"\"";
    if (comma)
    {
        stream << L",";
    }
    stream << L"\n";
}

static void AppendJsonHex64Property(
    std::wstringstream& stream,
    const wchar_t* indent,
    const wchar_t* name,
    uint64_t value,
    bool comma)
{
    stream << indent << L"\"" << name << L"\":";
    if (value == 0)
    {
        stream << L"null";
    }
    else
    {
        stream << L"\"" << FixedHex64Text(value) << L"\"";
    }

    if (comma)
    {
        stream << L",";
    }
    stream << L"\n";
}

static std::wstring BuildCallbackScanJson(
    const std::wstring& scope,
    const KernelCallbackScanResult& result)
{
    std::wstringstream stream;

    stream << L"{\n";
    AppendJsonStringProperty(stream, L"  ", L"schema", L"kn-live-dbg.callbacks.v1", true);
    AppendJsonStringProperty(stream, L"  ", L"generated", CurrentUtcTimestamp(), true);
    AppendJsonStringProperty(stream, L"  ", L"scope", scope, true);
    stream << L"  \"record_count\":" << result.Records.size() << L",\n";
    stream << L"  \"warnings\":[\n";
    for (size_t index = 0; index < result.Warnings.size(); ++index)
    {
        stream << L"    \"" << EscapeJsonText(result.Warnings[index]) << L"\"";
        if (index + 1 < result.Warnings.size())
        {
            stream << L",";
        }
        stream << L"\n";
    }
    stream << L"  ],\n";
    stream << L"  \"records\":[\n";

    for (size_t index = 0; index < result.Records.size(); ++index)
    {
        const KernelCallbackRecord& record = result.Records[index];
        stream << L"    {\n";
        AppendJsonStringProperty(stream, L"      ", L"kind", record.Kind, true);
        AppendJsonStringProperty(stream, L"      ", L"target", record.Target, true);
        AppendJsonStringProperty(stream, L"      ", L"altitude", record.Altitude, true);
        AppendJsonStringProperty(stream, L"      ", L"callback_name", record.CallbackName, true);
        AppendJsonStringProperty(stream, L"      ", L"filter_name", record.FilterName, true);
        AppendJsonUint32Property(stream, L"      ", L"slot", record.Slot, true);
        AppendJsonUint32Property(stream, L"      ", L"operations", record.Operations, true);
        AppendJsonHex32Property(stream, L"      ", L"operations_hex", record.Operations, true);
        AppendJsonStringProperty(stream, L"      ", L"operations_text", ObjectOperationsText(record.Operations), true);
        AppendJsonNullableUint32Property(stream, L"      ", L"major_function", record.MajorFunction, 0xffffffffu, true);
        AppendJsonUint32Property(stream, L"      ", L"callback_flags", record.CallbackFlags, true);
        AppendJsonHex32Property(stream, L"      ", L"callback_flags_hex", record.CallbackFlags, true);
        AppendJsonUint32Property(stream, L"      ", L"filter_flags", record.FilterFlags, true);
        AppendJsonHex32Property(stream, L"      ", L"filter_flags_hex", record.FilterFlags, true);
        AppendJsonNullableUint32Property(stream, L"      ", L"frame_id", record.FrameId, 0xffffffffu, true);

        stream << L"      \"sources\":{\n";
        AppendJsonStringProperty(stream, L"        ", L"root_source", record.RootSource, true);
        AppendJsonStringProperty(stream, L"        ", L"object_type_source", record.ObjectTypeSource, false);
        stream << L"      },\n";

        stream << L"      \"symbols\":{\n";
        AppendJsonStringProperty(stream, L"        ", L"function_module", record.FunctionModule, true);
        AppendJsonStringProperty(stream, L"        ", L"function_symbol", record.FunctionSymbol, true);
        AppendJsonStringProperty(stream, L"        ", L"post_function_module", record.PostFunctionModule, true);
        AppendJsonStringProperty(stream, L"        ", L"post_function_symbol", record.PostFunctionSymbol, true);
        AppendJsonStringProperty(stream, L"        ", L"context_module", record.ContextModule, true);
        AppendJsonStringProperty(stream, L"        ", L"context_symbol", record.ContextSymbol, false);
        stream << L"      },\n";

        stream << L"      \"addresses\":{\n";
        AppendJsonHex64Property(stream, L"        ", L"object_type", record.ObjectType, true);
        AppendJsonHex64Property(stream, L"        ", L"root_address", record.RootAddress, true);
        AppendJsonHex64Property(stream, L"        ", L"frame", record.Frame, true);
        AppendJsonHex64Property(stream, L"        ", L"filter", record.Filter, true);
        AppendJsonHex64Property(stream, L"        ", L"driver_object", record.DriverObject, true);
        AppendJsonHex64Property(stream, L"        ", L"list_entry", record.ListEntry, true);
        AppendJsonHex64Property(stream, L"        ", L"entry", record.Entry, true);
        AppendJsonHex64Property(stream, L"        ", L"callback_block", record.CallbackBlock, true);
        AppendJsonHex64Property(stream, L"        ", L"callback_entry", record.CallbackEntry, true);
        AppendJsonHex64Property(stream, L"        ", L"function", record.Function, true);
        AppendJsonHex64Property(stream, L"        ", L"post_function", record.PostFunction, true);
        AppendJsonHex64Property(stream, L"        ", L"context", record.Context, true);
        AppendJsonHex64Property(stream, L"        ", L"cookie", record.Cookie, true);
        AppendJsonHex64Property(stream, L"        ", L"raw_value", record.RawValue, false);
        stream << L"      },\n";

        AppendJsonStringProperty(stream, L"      ", L"notes", record.Notes, false);
        stream << L"    }";
        if (index + 1 < result.Records.size())
        {
            stream << L",";
        }
        stream << L"\n";
    }

    stream << L"  ]\n";
    stream << L"}";

    return stream.str();
}

static std::wstring CurrentUtcFileTimestamp()
{
    SYSTEMTIME now = {};
    wchar_t buffer[64] = {};

    GetSystemTime(&now);
    swprintf_s(
        buffer,
        L"%04u%02u%02u_%02u%02u%02u_%03u",
        now.wYear,
        now.wMonth,
        now.wDay,
        now.wHour,
        now.wMinute,
        now.wSecond,
        now.wMilliseconds);

    return buffer;
}

static bool IsHexTextChar(wchar_t ch)
{
    bool result = false;

    if ((ch >= L'0' && ch <= L'9') ||
        (ch >= L'a' && ch <= L'f') ||
        (ch >= L'A' && ch <= L'F'))
    {
        result = true;
    }

    return result;
}

static bool IsSecretTokenChar(wchar_t ch)
{
    bool result = false;

    if (std::iswalnum(ch) || ch == L'-' || ch == L'_' || ch == L'.')
    {
        result = true;
    }

    return result;
}

static std::wstring RedactTranscriptText(const std::wstring& value)
{
    std::wstring result;

    for (size_t index = 0; index < value.size();)
    {
        if (index + 3 <= value.size() &&
            value[index] == L's' &&
            value[index + 1] == L'k' &&
            value[index + 2] == L'-')
        {
            result += L"sk-<redacted>";
            index += 3;
            while (index < value.size() && IsSecretTokenChar(value[index]))
            {
                ++index;
            }
        }
        else if (index + 2 < value.size() &&
                 value[index] == L'0' &&
                 (value[index + 1] == L'x' || value[index + 1] == L'X'))
        {
            size_t digitStart = index + 2;
            size_t digitEnd = digitStart;
            while (digitEnd < value.size() && IsHexTextChar(value[digitEnd]))
            {
                ++digitEnd;
            }

            if (digitEnd - digitStart >= 8)
            {
                result += L"0x<redacted>";
                index = digitEnd;
            }
            else
            {
                result.append(value, index, digitEnd - index);
                index = digitEnd;
            }
        }
        else
        {
            result.push_back(value[index]);
            ++index;
        }
    }

    return result;
}

static std::wstring MaybeRedactTranscriptText(const AiPlanState& aiState, const std::wstring& value)
{
    std::wstring result = value;

    if (aiState.TranscriptRedactOutput)
    {
        result = RedactTranscriptText(value);
    }

    return result;
}

static bool QueryFileSizeBytes(const std::wstring& path, uint64_t* size)
{
    bool ok = false;
    WIN32_FILE_ATTRIBUTE_DATA attributes = {};

    do
    {
        if (size == nullptr)
        {
            break;
        }

        *size = 0;
        if (!GetFileAttributesExW(path.c_str(), GetFileExInfoStandard, &attributes))
        {
            DWORD lastError = GetLastError();
            if (lastError == ERROR_FILE_NOT_FOUND || lastError == ERROR_PATH_NOT_FOUND)
            {
                ok = true;
            }
            break;
        }

        ULARGE_INTEGER value = {};
        value.HighPart = attributes.nFileSizeHigh;
        value.LowPart = attributes.nFileSizeLow;
        *size = value.QuadPart;
        ok = true;
    } while (false);

    return ok;
}

static bool RotateLogIfNeeded(
    const std::wstring& path,
    uint64_t maxBytes,
    size_t incomingBytes,
    uint32_t* rotationIndex,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (path.empty() || maxBytes == 0)
        {
            ok = true;
            break;
        }

        uint64_t currentSize = 0;
        if (!QueryFileSizeBytes(path, &currentSize))
        {
            if (error != nullptr)
            {
                *error = L"query log size failed";
            }
            break;
        }

        if (currentSize == 0 ||
            (incomingBytes <= maxBytes && currentSize <= maxBytes - incomingBytes))
        {
            ok = true;
            break;
        }

        uint32_t nextIndex = 1;
        if (rotationIndex != nullptr)
        {
            *rotationIndex += 1;
            nextIndex = *rotationIndex;
        }

        std::wstringstream rotatedPath;
        rotatedPath << path << L"." << CurrentUtcFileTimestamp() << L"." << nextIndex << L".old";

        if (!MoveFileExW(path.c_str(), rotatedPath.str().c_str(), MOVEFILE_REPLACE_EXISTING))
        {
            DWORD lastError = GetLastError();
            if (lastError != ERROR_FILE_NOT_FOUND && lastError != ERROR_PATH_NOT_FOUND)
            {
                if (error != nullptr)
                {
                    *error = L"rotate log failed";
                }
                break;
            }
        }

        ok = true;
    } while (false);

    return ok;
}

static bool AppendUtf8Line(const std::wstring& path, const std::wstring& line, std::wstring* error)
{
    bool ok = false;
    HANDLE file = INVALID_HANDLE_VALUE;

    do
    {
        if (path.empty())
        {
            break;
        }

        file = CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            if (error != nullptr)
            {
                *error = L"open transcript failed";
            }
            break;
        }

        std::string bytes = WideToUtf8ForLog(line + L"\n");
        DWORD written = 0;
        if (!bytes.empty() && !WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr))
        {
            if (error != nullptr)
            {
                *error = L"write transcript failed";
            }
            break;
        }

        ok = written == bytes.size();
    } while (false);

    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }

    return ok;
}

static bool AppendRotatingUtf8Line(
    const std::wstring& path,
    const std::wstring& line,
    uint64_t maxBytes,
    uint32_t* rotationIndex,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        std::string bytes = WideToUtf8ForLog(line + L"\n");
        std::wstring rotateError;
        if (!RotateLogIfNeeded(path, maxBytes, bytes.size(), rotationIndex, &rotateError))
        {
            if (error != nullptr)
            {
                *error = rotateError;
            }
        }

        if (!AppendUtf8Line(path, line, error))
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool AppendTranscriptLine(AiPlanState& aiState, const std::wstring& line, std::wstring* error)
{
    return AppendRotatingUtf8Line(
        aiState.TranscriptPath,
        line,
        aiState.TranscriptMaxBytes,
        &aiState.TranscriptRotationIndex,
        error);
}

static bool WriteUtf8TextFile(const std::wstring& path, const std::wstring& text, std::wstring* error)
{
    bool ok = false;
    HANDLE file = INVALID_HANDLE_VALUE;

    do
    {
        if (path.empty())
        {
            if (error != nullptr)
            {
                *error = L"empty output path";
            }
            break;
        }

        file = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            if (error != nullptr)
            {
                *error = L"open output file failed";
            }
            break;
        }

        std::string bytes = WideToUtf8ForLog(text);
        DWORD written = 0;
        if (!bytes.empty() && !WriteFile(file, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr))
        {
            if (error != nullptr)
            {
                *error = L"write output file failed";
            }
            break;
        }

        ok = written == bytes.size();
    } while (false);

    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }

    return ok;
}

static void WriteAiTranscriptEvent(
    AiPlanState& aiState,
    const std::wstring& event,
    const std::wstring& detail,
    const std::wstring& command)
{
    do
    {
        if (!aiState.TranscriptEnabled || aiState.TranscriptPath.empty())
        {
            break;
        }

        std::wstringstream line;
        line << L"{";
        line << L"\"ts\":\"" << EscapeJsonText(CurrentUtcTimestamp()) << L"\",";
        line << L"\"event\":\"" << EscapeJsonText(event) << L"\",";
        line << L"\"detail\":\"" << EscapeJsonText(detail) << L"\",";
        line << L"\"command\":\"" << EscapeJsonText(command) << L"\"";
        line << L"}";

        std::wstring ignored;
        AppendTranscriptLine(aiState, line.str(), &ignored);
    } while (false);
}

static std::wstring FirstNonEmptySummaryLine(const std::wstring& text, bool fromEnd)
{
    std::wstring result;
    std::wistringstream stream(text);
    std::wstring line;

    if (fromEnd)
    {
        while (std::getline(stream, line))
        {
            if (!line.empty() && line.back() == L'\r')
            {
                line.pop_back();
            }

            if (!TrimWhitespace(line).empty())
            {
                result = line;
            }
        }
    }
    else
    {
        while (std::getline(stream, line))
        {
            if (!line.empty() && line.back() == L'\r')
            {
                line.pop_back();
            }

            if (!TrimWhitespace(line).empty())
            {
                result = line;
                break;
            }
        }
    }

    if (result.size() > 180)
    {
        result.resize(180);
        result += L"...";
    }

    return result;
}

static size_t CountTextLinesForSummary(const std::wstring& text)
{
    size_t lines = 0;

    do
    {
        if (text.empty())
        {
            break;
        }

        lines = 1;
        for (wchar_t ch : text)
        {
            if (ch == L'\n')
            {
                ++lines;
            }
        }
    } while (false);

    return lines;
}

static size_t CountInterestingLinesForSummary(const std::wstring& text)
{
    size_t count = 0;
    std::wistringstream stream(text);
    std::wstring line;

    while (std::getline(stream, line))
    {
        if (ContainsNoCase(line, L"error") ||
            ContainsNoCase(line, L"failed") ||
            ContainsNoCase(line, L"warning") ||
            ContainsNoCase(line, L"invalid") ||
            ContainsNoCase(line, L"denied") ||
            ContainsNoCase(line, L"partial"))
        {
            ++count;
        }
    }

    return count;
}

static std::wstring BuildTextOutputSummary(const std::wstring& label, const std::wstring& text)
{
    std::wstringstream stream;
    size_t lineCount = CountTextLinesForSummary(text);
    size_t interesting = CountInterestingLinesForSummary(text);

    stream << label << L": chars=" << text.size() << L" lines=" << lineCount;
    if (interesting != 0)
    {
        stream << L" interesting-lines=" << interesting;
    }

    std::wstring first = FirstNonEmptySummaryLine(text, false);
    std::wstring last = FirstNonEmptySummaryLine(text, true);
    if (!first.empty())
    {
        stream << L" first=\"" << first << L"\"";
    }
    if (!last.empty() && last != first)
    {
        stream << L" last=\"" << last << L"\"";
    }

    return stream.str();
}

static std::wstring BuildCommandOutputSummary(const CommandExecutionResult& result)
{
    std::wstringstream stream;

    stream << BuildTextOutputSummary(L"stdout", result.Output) << L"\n";
    stream << BuildTextOutputSummary(L"stderr", result.Error);

    return stream.str();
}

static void WriteCommandTranscriptEvent(
    AiPlanState& aiState,
    const std::wstring& origin,
    const std::wstring& backend,
    const std::wstring& commandClass,
    bool writeLike,
    const std::wstring& command,
    const CommandExecutionResult& result)
{
    do
    {
        if (!aiState.TranscriptEnabled || aiState.TranscriptPath.empty())
        {
            break;
        }

        std::wstringstream line;
        line << L"{";
        line << L"\"ts\":\"" << EscapeJsonText(CurrentUtcTimestamp()) << L"\",";
        line << L"\"event\":\"command\",";
        line << L"\"origin\":\"" << EscapeJsonText(origin) << L"\",";
        line << L"\"backend\":\"" << EscapeJsonText(backend) << L"\",";
        line << L"\"class\":\"" << EscapeJsonText(commandClass) << L"\",";
        line << L"\"write_like\":" << (writeLike ? L"true" : L"false") << L",";
        line << L"\"command\":\"" << EscapeJsonText(command) << L"\",";
        line << L"\"keep_running\":" << (result.KeepRunning ? L"true" : L"false") << L",";
        std::wstring outputSummary = MaybeRedactTranscriptText(aiState, BuildCommandOutputSummary(result));
        line << L"\"stdout_chars\":" << result.Output.size() << L",";
        line << L"\"stderr_chars\":" << result.Error.size() << L",";
        line << L"\"output_summary\":\"" << EscapeJsonText(outputSummary) << L"\",";
        line << L"\"stdout\":\"" << EscapeJsonText(MaybeRedactTranscriptText(aiState, result.Output)) << L"\",";
        line << L"\"stderr\":\"" << EscapeJsonText(MaybeRedactTranscriptText(aiState, result.Error)) << L"\"";
        line << L"}";

        std::wstring ignored;
        AppendTranscriptLine(aiState, line.str(), &ignored);
    } while (false);
}

static void WriteCommandAuditEvent(
    AiPlanState& aiState,
    const std::wstring& origin,
    const std::wstring& backend,
    const std::wstring& commandClass,
    const std::wstring& command,
    const CommandExecutionResult& result)
{
    do
    {
        if (!aiState.WriteAuditEnabled || aiState.WriteAuditPath.empty())
        {
            break;
        }

        std::wstringstream line;
        line << L"{";
        line << L"\"ts\":\"" << EscapeJsonText(CurrentUtcTimestamp()) << L"\",";
        line << L"\"event\":\"write_command\",";
        line << L"\"origin\":\"" << EscapeJsonText(origin) << L"\",";
        line << L"\"backend\":\"" << EscapeJsonText(backend) << L"\",";
        line << L"\"class\":\"" << EscapeJsonText(commandClass) << L"\",";
        line << L"\"write_like\":true,";
        line << L"\"command\":\"" << EscapeJsonText(command) << L"\",";
        line << L"\"keep_running\":" << (result.KeepRunning ? L"true" : L"false") << L",";
        std::wstring outputSummary = MaybeRedactTranscriptText(aiState, BuildCommandOutputSummary(result));
        line << L"\"stdout_chars\":" << result.Output.size() << L",";
        line << L"\"stderr_chars\":" << result.Error.size() << L",";
        line << L"\"output_summary\":\"" << EscapeJsonText(outputSummary) << L"\",";
        line << L"\"stdout\":\"" << EscapeJsonText(MaybeRedactTranscriptText(aiState, result.Output)) << L"\",";
        line << L"\"stderr\":\"" << EscapeJsonText(MaybeRedactTranscriptText(aiState, result.Error)) << L"\"";
        line << L"}";

        std::wstring ignored;
        AppendUtf8Line(aiState.WriteAuditPath, line.str(), &ignored);
    } while (false);
}

static bool ExtractBalancedJsonObject(const std::wstring& text, std::wstring* json)
{
    bool ok = false;

    do
    {
        if (json == nullptr)
        {
            break;
        }

        size_t start = text.find(L'{');
        if (start == std::wstring::npos)
        {
            break;
        }

        int depth = 0;
        bool inString = false;
        bool escaped = false;
        for (size_t index = start; index < text.size(); ++index)
        {
            wchar_t ch = text[index];
            if (inString)
            {
                if (escaped)
                {
                    escaped = false;
                }
                else if (ch == L'\\')
                {
                    escaped = true;
                }
                else if (ch == L'\"')
                {
                    inString = false;
                }
                continue;
            }

            if (ch == L'\"')
            {
                inString = true;
            }
            else if (ch == L'{')
            {
                ++depth;
            }
            else if (ch == L'}')
            {
                --depth;
                if (depth == 0)
                {
                    *json = text.substr(start, index - start + 1);
                    ok = true;
                    break;
                }
            }
        }
    } while (false);

    return ok;
}

static bool ParseJsonStringAt(const std::wstring& text, size_t quote, std::wstring* value, size_t* next)
{
    bool ok = false;
    std::wstring result;

    do
    {
        if (value == nullptr || quote >= text.size() || text[quote] != L'\"')
        {
            break;
        }

        for (size_t index = quote + 1; index < text.size(); ++index)
        {
            wchar_t ch = text[index];
            if (ch == L'\"')
            {
                *value = result;
                if (next != nullptr)
                {
                    *next = index + 1;
                }
                ok = true;
                break;
            }

            if (ch != L'\\' || index + 1 >= text.size())
            {
                result += ch;
                continue;
            }

            wchar_t escaped = text[++index];
            switch (escaped)
            {
            case L'\"':
            case L'\\':
            case L'/':
                result += escaped;
                break;
            case L'b':
                result += L'\b';
                break;
            case L'f':
                result += L'\f';
                break;
            case L'n':
                result += L'\n';
                break;
            case L'r':
                result += L'\r';
                break;
            case L't':
                result += L'\t';
                break;
            default:
                result += escaped;
                break;
            }
        }
    } while (false);

    return ok;
}

static bool ExtractJsonStringValue(const std::wstring& json, const std::wstring& key, std::wstring* value)
{
    bool ok = false;
    std::wstring pattern = L"\"" + key + L"\"";
    size_t pos = 0;

    do
    {
        if (value == nullptr)
        {
            break;
        }

        while ((pos = json.find(pattern, pos)) != std::wstring::npos)
        {
            size_t colon = json.find(L':', pos + pattern.size());
            if (colon == std::wstring::npos)
            {
                break;
            }

            size_t quote = colon + 1;
            while (quote < json.size() && iswspace(json[quote]) != 0)
            {
                ++quote;
            }

            if (quote < json.size() && json[quote] == L'\"')
            {
                ok = ParseJsonStringAt(json, quote, value, nullptr);
                break;
            }

            pos = colon + 1;
        }
    } while (false);

    return ok;
}

static bool ExtractJsonBoolValue(const std::wstring& json, const std::wstring& key, bool* value)
{
    bool ok = false;
    std::wstring pattern = L"\"" + key + L"\"";
    size_t pos = json.find(pattern);

    do
    {
        if (value == nullptr || pos == std::wstring::npos)
        {
            break;
        }

        size_t colon = json.find(L':', pos + pattern.size());
        if (colon == std::wstring::npos)
        {
            break;
        }

        size_t item = colon + 1;
        while (item < json.size() && iswspace(json[item]) != 0)
        {
            ++item;
        }

        if (json.compare(item, 4, L"true") == 0)
        {
            *value = true;
            ok = true;
        }
        else if (json.compare(item, 5, L"false") == 0)
        {
            *value = false;
            ok = true;
        }
    } while (false);

    return ok;
}

static std::vector<std::wstring> ExtractJsonArrayObjects(const std::wstring& json, const std::wstring& key)
{
    std::vector<std::wstring> objects;
    std::wstring pattern = L"\"" + key + L"\"";
    size_t pos = json.find(pattern);

    do
    {
        if (pos == std::wstring::npos)
        {
            break;
        }

        size_t bracket = json.find(L'[', pos + pattern.size());
        if (bracket == std::wstring::npos)
        {
            break;
        }

        bool inString = false;
        bool escaped = false;
        int objectDepth = 0;
        size_t objectStart = std::wstring::npos;
        for (size_t index = bracket + 1; index < json.size(); ++index)
        {
            wchar_t ch = json[index];
            if (inString)
            {
                if (escaped)
                {
                    escaped = false;
                }
                else if (ch == L'\\')
                {
                    escaped = true;
                }
                else if (ch == L'\"')
                {
                    inString = false;
                }
                continue;
            }

            if (ch == L'\"')
            {
                inString = true;
            }
            else if (ch == L'{')
            {
                if (objectDepth == 0)
                {
                    objectStart = index;
                }
                ++objectDepth;
            }
            else if (ch == L'}')
            {
                --objectDepth;
                if (objectDepth == 0 && objectStart != std::wstring::npos)
                {
                    objects.push_back(json.substr(objectStart, index - objectStart + 1));
                    objectStart = std::wstring::npos;
                }
            }
            else if (ch == L']' && objectDepth == 0)
            {
                break;
            }
        }
    } while (false);

    return objects;
}

static bool IsShutdownOrUnloadCommand(const std::wstring& command)
{
    bool blocked = false;

    if (command == L"q" ||
        command == L"qq" ||
        command == L"qd" ||
        command == L"quit" ||
        command == L"exit" ||
        command == L"unload")
    {
        blocked = true;
    }

    return blocked;
}

static bool ContainsUnsafeAiCommandCharacters(const std::wstring& line, std::wstring* reason)
{
    bool unsafe = false;

    do
    {
        for (wchar_t ch : line)
        {
            if (ch == L';' || ch == L'\r' || ch == L'\n')
            {
                unsafe = true;
                if (reason != nullptr)
                {
                    *reason = L"command chaining and multiline commands are not allowed in AI plans";
                }
                break;
            }

            if (std::iswcntrl(ch) != 0 && ch != L'\t')
            {
                unsafe = true;
                if (reason != nullptr)
                {
                    *reason = L"control characters are not allowed in AI plan commands";
                }
                break;
            }
        }
    } while (false);

    return unsafe;
}

static std::wstring NormalizeAiRiskText(const std::wstring& risk, bool writeLike, const std::wstring& commandClass)
{
    std::wstring normalized = ToLower(TrimWhitespace(risk));

    do
    {
        if (writeLike)
        {
            normalized = L"write-like";
            break;
        }

        if (normalized.empty())
        {
            if (commandClass == L"dbgeng")
            {
                normalized = L"dbgeng";
            }
            else
            {
                normalized = L"read-only";
            }
            break;
        }

        if (normalized.find(L"write") != std::wstring::npos)
        {
            normalized = L"write-like";
            break;
        }

        if (normalized.find(L"dbgeng") != std::wstring::npos || normalized.find(L"debugger") != std::wstring::npos)
        {
            normalized = L"dbgeng";
            break;
        }

        if (normalized.find(L"unknown") != std::wstring::npos)
        {
            normalized = L"unknown";
            break;
        }

        if (normalized.find(L"read") != std::wstring::npos || normalized.find(L"low") != std::wstring::npos)
        {
            normalized = L"read-only";
            break;
        }
    } while (false);

    return normalized;
}

static std::wstring InferAiPlanBackend(const std::wstring& commandLine, const std::wstring& commandClass)
{
    std::wstring backend = L"native";
    std::vector<std::wstring> args = Split(commandLine);

    do
    {
        if (args.empty())
        {
            backend = L"unknown";
            break;
        }

        std::wstring command = NormalizeInputCommand(args[0]);
        if (command == L"kd" || commandClass == L"dbgeng" || (!command.empty() && command[0] == L'!'))
        {
            backend = L"dbgeng";
            break;
        }

        if (command == L"u" || command == L"uf")
        {
            backend = L"native+dbgeng";
            break;
        }

        if (commandClass == L"session" || commandClass == L"ai")
        {
            backend = L"tui";
            break;
        }
    } while (false);

    return backend;
}

static bool IsWriteLikeCommandLine(const std::wstring& line)
{
    bool writeLike = false;
    std::vector<std::wstring> args = Split(line);

    do
    {
        if (args.empty())
        {
            break;
        }

        std::wstring command = NormalizeInputCommand(args[0]);
        if (command == L"kd" && args.size() >= 2)
        {
            std::wstring inner = NormalizeInputCommand(args[1]);
            if (inner == L"setfield" || inner == L"write" || inner == L"f" || inner == L"fp" || inner == L"m" ||
                IsEnterCommand(inner) || IsPhysicalEnterCommand(inner))
            {
                writeLike = true;
            }
            break;
        }

        if (command == L"setfield" || command == L"write" || command == L"f" || command == L"fp" || command == L"m")
        {
            writeLike = true;
            break;
        }

        if (IsEnterCommand(command) || IsPhysicalEnterCommand(command))
        {
            writeLike = true;
            break;
        }
    } while (false);

    return writeLike;
}

static bool IsNativeMemoryDisplayCommand(const std::wstring& command)
{
    bool result = false;

    if (command == L"d" ||
        command == L"da" ||
        command == L"db" ||
        command == L"dc" ||
        command == L"dd" ||
        command == L"df" ||
        command == L"dp" ||
        command == L"dq" ||
        command == L"du" ||
        command == L"dw" ||
        command == L"dyb" ||
        command == L"dyd" ||
        command == L"dda" ||
        command == L"ddp" ||
        command == L"ddu" ||
        command == L"dpa" ||
        command == L"dpp" ||
        command == L"dpu" ||
        command == L"dqa" ||
        command == L"dqp" ||
        command == L"dqu" ||
        command == L"dds" ||
        command == L"dps" ||
        command == L"dqs" ||
        command == L"c" ||
        command == L"s")
    {
        result = true;
    }

    return result;
}

static bool IsNativePhysicalReadCommand(const std::wstring& command)
{
    bool result = false;

    if (command == L"phys" ||
        command == L"pdb" ||
        command == L"pdw" ||
        command == L"pdd" ||
        command == L"pdq")
    {
        result = true;
    }

    return result;
}

static std::wstring ClassifyCommandLine(const std::wstring& line, bool writeLike)
{
    std::wstring commandClass = L"command";
    std::vector<std::wstring> args = Split(line);

    do
    {
        if (args.empty())
        {
            commandClass = L"empty";
            break;
        }

        std::wstring command = NormalizeInputCommand(args[0]);
        if (command == L"ai")
        {
            commandClass = L"ai";
            break;
        }

        if (writeLike)
        {
            if (IsPhysicalEnterCommand(command))
            {
                commandClass = L"physical-write";
            }
            else if (IsEnterCommand(command))
            {
                commandClass = L"virtual-write";
            }
            else if (command == L"setfield")
            {
                commandClass = L"type-write";
            }
            else
            {
                commandClass = L"write";
            }
            break;
        }

        if (command == L"kd" || (!command.empty() && command[0] == L'!'))
        {
            commandClass = L"dbgeng";
            break;
        }

        if (command == L"backend" || command == L"kdinit" || command == L"kddetach" ||
            command == L"drvstatus" || command == L"unload" || command == L"q" ||
            command == L"qq" || command == L"qd" || command == L"quit" || command == L"exit" ||
            command == L"version" || command == L"vertarget" || command == L"vercommand")
        {
            commandClass = L"session";
            break;
        }

        if (command == L"dt" || command == L"dtx")
        {
            commandClass = L"type";
            break;
        }

        if (command == L"callbacks" || command == L"kcallbacks" || command == L"cb")
        {
            commandClass = L"callbacks";
            break;
        }

        if (command == L"u" || command == L"uf")
        {
            commandClass = L"disassembly";
            break;
        }

        if (command == L"vtop")
        {
            commandClass = L"address-translation";
            break;
        }

        if (command == L"lm" || command == L"ld" || command == L"ln" || command == L"x" ||
            command == L".sympath" || command == L".sympath+" || command == L".reload")
        {
            commandClass = L"symbols";
            break;
        }

        if (!command.empty() && command[0] == L'.')
        {
            commandClass = L"dbgeng";
            break;
        }

        if (IsNativePhysicalReadCommand(command))
        {
            commandClass = L"physical-read";
            break;
        }

        if (IsNativeMemoryDisplayCommand(command))
        {
            commandClass = L"memory-read";
            break;
        }

        if (ShouldRouteToDbgEng(command))
        {
            commandClass = L"dbgeng";
            break;
        }
    } while (false);

    return commandClass;
}

static bool ValidateAiPlanArgumentShape(
    const std::wstring& command,
    const std::vector<std::wstring>& args,
    std::wstring* reason);

static bool ValidateAiPlanCommand(const AiCommandProposal& item, std::wstring* reason)
{
    bool ok = false;
    std::vector<std::wstring> args = Split(item.Command);

    do
    {
        if (args.empty())
        {
            if (reason != nullptr)
            {
                *reason = L"empty command";
            }
            break;
        }

        if (ContainsUnsafeAiCommandCharacters(item.Command, reason))
        {
            break;
        }

        if (item.Command.size() > 1024)
        {
            if (reason != nullptr)
            {
                *reason = L"command is too long";
            }
            break;
        }

        if (args.size() > 64)
        {
            if (reason != nullptr)
            {
                *reason = L"command has too many arguments";
            }
            break;
        }

        if (TrimWhitespace(item.Purpose).empty())
        {
            if (reason != nullptr)
            {
                *reason = L"plan command is missing purpose";
            }
            break;
        }

        if (item.Purpose.size() > 512 || item.Risk.size() > 128 || item.ExpectedOutput.size() > 512)
        {
            if (reason != nullptr)
            {
                *reason = L"plan command metadata is too long";
            }
            break;
        }

        std::wstring command = NormalizeInputCommand(args[0]);
        if (command == L"ai")
        {
            if (reason != nullptr)
            {
                *reason = L"nested ai commands are not allowed in plans";
            }
            break;
        }

        if (IsShutdownOrUnloadCommand(command))
        {
            if (reason != nullptr)
            {
                *reason = L"shutdown and unload commands are not allowed in plans";
            }
            break;
        }

        if (command == L"backend" || command == L"kdinit" || command == L"kddetach")
        {
            if (reason != nullptr)
            {
                *reason = L"backend/session mutation commands are not allowed in AI plans";
            }
            break;
        }

        if (command == L"probe")
        {
            if (reason != nullptr)
            {
                *reason = L"probe service control is not allowed in AI plans";
            }
            break;
        }

        if (command == L"kd" && args.size() < 2)
        {
            if (reason != nullptr)
            {
                *reason = L"kd plan command requires an inner command";
            }
            break;
        }

        if (command == L"kd" && args.size() >= 2)
        {
            std::wstring inner = NormalizeInputCommand(args[1]);
            if (inner == L"ai" || IsShutdownOrUnloadCommand(inner))
            {
                if (reason != nullptr)
                {
                    *reason = L"raw kd command wraps a blocked session command";
                }
                break;
            }

            if (IsWriteLikeCommandLine(item.Command))
            {
                if (!item.RequiresConfirmation)
                {
                    if (reason != nullptr)
                    {
                        *reason = L"raw kd write-like command must require confirmation";
                    }
                    break;
                }
            }
        }

        if ((command == L"dt" || command == L"dtx" || command == L"ln" || command == L"x" ||
             command == L"vtop" || command == L"u" || command == L"uf" ||
             IsNativeMemoryDisplayCommand(command) || IsNativePhysicalReadCommand(command)) &&
            args.size() < 2)
        {
            if (reason != nullptr)
            {
                *reason = L"command is missing its required target argument";
            }
            break;
        }

        if (!ValidateAiPlanArgumentShape(command, args, reason))
        {
            break;
        }

        if (!CommandRegistry::IsKnown(command) &&
            command != L"kd" &&
            (command.empty() || (command[0] != L'!' && command[0] != L'.')))
        {
            if (reason != nullptr)
            {
                *reason = L"unknown command; use kd <command> for raw DbgEng execution";
            }
            break;
        }

        if (!item.Backend.empty())
        {
            std::wstring backend = ToLower(TrimWhitespace(item.Backend));
            if (backend != L"native" && backend != L"dbgeng" && backend != L"native+dbgeng" &&
                backend != L"tui" && backend != L"auto" && backend != L"unknown")
            {
                if (reason != nullptr)
                {
                    *reason = L"unsupported backend expectation";
                }
                break;
            }
        }

        ok = true;
    } while (false);

    return ok;
}

static bool ValidateAiPlanArgumentShape(
    const std::wstring& command,
    const std::vector<std::wstring>& args,
    std::wstring* reason)
{
    bool ok = false;

    do
    {
        if (command == L"c")
        {
            if (args.size() < 4)
            {
                if (reason != nullptr)
                {
                    *reason = L"compare command requires two addresses and a length";
                }
                break;
            }
        }
        else if (command == L"s")
        {
            bool hasWidthOption = args.size() >= 2 &&
                (ToLower(args[1]) == L"-b" || ToLower(args[1]) == L"-w" ||
                 ToLower(args[1]) == L"-d" || ToLower(args[1]) == L"-q");
            size_t minimum = hasWidthOption ? 5 : 4;
            if (args.size() < minimum)
            {
                if (reason != nullptr)
                {
                    *reason = L"search command requires address, length, and at least one value";
                }
                break;
            }
        }
        else if (command == L"f" || command == L"fp")
        {
            if (args.size() < 4)
            {
                if (reason != nullptr)
                {
                    *reason = L"fill command requires address, length, and byte pattern";
                }
                break;
            }
        }
        else if (command == L"m")
        {
            if (args.size() < 4)
            {
                if (reason != nullptr)
                {
                    *reason = L"move command requires source, destination, and length";
                }
                break;
            }
        }
        else if (IsEnterCommand(command) || IsPhysicalEnterCommand(command))
        {
            if (args.size() < 3)
            {
                if (reason != nullptr)
                {
                    *reason = L"write command requires target and at least one value";
                }
                break;
            }
        }
        else if (command == L"vtop" && args.size() >= 2)
        {
            std::wstring option = ToLower(args[1]);
            if ((option == L"/cr3" || option == L"/pid" || option == L"/process") && args.size() < 4)
            {
                if (reason != nullptr)
                {
                    *reason = L"vtop option requires context value and address";
                }
                break;
            }
        }

        ok = true;
    } while (false);

    return ok;
}

static bool IsBlockedAiRunCommand(const std::wstring& line, std::wstring* reason)
{
    bool blocked = false;
    std::vector<std::wstring> args = Split(line);

    do
    {
        if (args.empty())
        {
            blocked = true;
            if (reason != nullptr)
            {
                *reason = L"empty command";
            }
            break;
        }

        std::wstring command = NormalizeInputCommand(args[0]);
        if (command == L"ai")
        {
            blocked = true;
            if (reason != nullptr)
            {
                *reason = L"nested ai commands are not executed from plans";
            }
            break;
        }

        if (IsShutdownOrUnloadCommand(command))
        {
            blocked = true;
            if (reason != nullptr)
            {
                *reason = L"session shutdown commands are blocked";
            }
            break;
        }

        if (command == L"backend" || command == L"kdinit" || command == L"kddetach" || command == L"probe")
        {
            blocked = true;
            if (reason != nullptr)
            {
                *reason = L"session mutation commands are blocked";
            }
            break;
        }

        if (command == L"kd" && args.size() >= 2)
        {
            std::wstring inner = NormalizeInputCommand(args[1]);
            if (IsShutdownOrUnloadCommand(inner))
            {
                blocked = true;
                if (reason != nullptr)
                {
                    *reason = L"raw kd wraps a blocked session command";
                }
                break;
            }
        }

        if (IsWriteLikeCommandLine(line))
        {
            blocked = true;
            if (reason != nullptr)
            {
                *reason = L"write-like commands require manual execution";
            }
            break;
        }
    } while (false);

    return blocked;
}

static bool ParseAiPlanResponse(const std::wstring& responseText, AiPlanState* plan, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (plan == nullptr)
        {
            break;
        }

        std::wstring json;
        if (!ExtractBalancedJsonObject(responseText, &json))
        {
            if (error != nullptr)
            {
                *error = L"AI response did not contain a JSON object";
            }
            break;
        }

        AiPlanState parsed = {};
        PreserveAiSessionSettings(parsed, *plan);
        parsed.RawResponse = responseText;
        ExtractJsonStringValue(json, L"schema", &parsed.Schema);
        ExtractJsonStringValue(json, L"title", &parsed.Title);
        ExtractJsonStringValue(json, L"summary", &parsed.Summary);

        if (!parsed.Schema.empty() &&
            parsed.Schema != L"kn-live-dbg.ai-plan.v1" &&
            parsed.Schema != L"kn-live-dbg.ai-plan.v2")
        {
            if (error != nullptr)
            {
                *error = L"unsupported AI plan schema: " + parsed.Schema;
            }
            break;
        }

        std::vector<std::wstring> objects = ExtractJsonArrayObjects(json, L"commands");
        bool strictV2 = parsed.Schema == L"kn-live-dbg.ai-plan.v2";
        if (objects.size() > 32)
        {
            if (error != nullptr)
            {
                *error = L"AI plan has too many commands";
            }
            break;
        }

        bool validationFailed = false;
        for (const std::wstring& object : objects)
        {
            AiCommandProposal item = {};
            ExtractJsonStringValue(object, L"command", &item.Command);
            std::wstring rawCommand = item.Command;
            ExtractJsonStringValue(object, L"purpose", &item.Purpose);
            if (item.Purpose.empty())
            {
                ExtractJsonStringValue(object, L"reason", &item.Purpose);
            }
            ExtractJsonStringValue(object, L"risk", &item.Risk);
            ExtractJsonStringValue(object, L"backend", &item.Backend);
            ExtractJsonStringValue(object, L"expected_output", &item.ExpectedOutput);
            std::wstring rawRisk = item.Risk;
            std::wstring rawBackend = item.Backend;
            std::wstring rawExpectedOutput = item.ExpectedOutput;
            ExtractJsonBoolValue(object, L"requires_confirmation", &item.RequiresConfirmation);
            ExtractJsonBoolValue(object, L"write_like", &item.WriteLike);

            std::wstring unsafeReason;
            if (ContainsUnsafeAiCommandCharacters(rawCommand, &unsafeReason))
            {
                validationFailed = true;
                if (error != nullptr)
                {
                    *error = L"AI plan command failed validation: " + unsafeReason;
                }
                break;
            }

            item.Command = JoinArgs(Split(item.Command), 0);

            if (item.Command.empty())
            {
                validationFailed = true;
                if (error != nullptr)
                {
                    *error = L"AI plan command failed validation: empty command";
                }
                break;
            }

            if (strictV2 &&
                (TrimWhitespace(rawRisk).empty() ||
                 TrimWhitespace(rawBackend).empty() ||
                 TrimWhitespace(rawExpectedOutput).empty()))
            {
                validationFailed = true;
                if (error != nullptr)
                {
                    *error = L"AI plan command failed validation: v2 command metadata requires risk, backend, and expected_output command=" + item.Command;
                }
                break;
            }

            std::wstring commandClass = ClassifyCommandLine(item.Command, item.WriteLike || IsWriteLikeCommandLine(item.Command));
            item.WriteLike = item.WriteLike || IsWriteLikeCommandLine(item.Command);
            item.Risk = NormalizeAiRiskText(item.Risk, item.WriteLike, commandClass);
            if (item.Backend.empty())
            {
                item.Backend = InferAiPlanBackend(item.Command, commandClass);
            }
            else
            {
                item.Backend = ToLower(TrimWhitespace(item.Backend));
            }
            if (item.WriteLike)
            {
                item.RequiresConfirmation = true;
                if (item.Risk.empty())
                {
                    item.Risk = L"write-like";
                }
            }

            if (!item.Command.empty())
            {
                std::wstring validationReason;
                if (!ValidateAiPlanCommand(item, &validationReason))
                {
                    validationFailed = true;
                    if (error != nullptr)
                    {
                        *error = L"AI plan command failed validation: " + validationReason + L" command=" + item.Command;
                    }
                    break;
                }

                parsed.Commands.push_back(item);
            }
        }

        if (validationFailed)
        {
            break;
        }

        if (parsed.Commands.empty())
        {
            if (error != nullptr)
            {
                *error = L"AI plan JSON did not contain commands";
            }
            break;
        }

        *plan = parsed;
        ok = true;
    } while (false);

    return ok;
}

static std::wstring BuildAiPlanPrompt(const std::wstring& prompt)
{
    std::wstringstream stream;

    stream << L"Create a KnLiveDbg command plan for this operator request.\n";
    stream << L"Return only one JSON object, with no Markdown fences and no prose before or after it.\n";
    stream << L"Schema:\n";
    stream << L"{\"schema\":\"kn-live-dbg.ai-plan.v2\",\"title\":\"short title\",\"summary\":\"short summary\",\"commands\":[";
    stream << L"{\"command\":\"exact KnLiveDbg command\",\"purpose\":\"why this command is useful\",\"risk\":\"read-only|write-like|dbgeng|unknown\",\"backend\":\"native|dbgeng|native+dbgeng|tui|auto|unknown\",\"expected_output\":\"what evidence this should produce\",\"requires_confirmation\":true,\"write_like\":false}";
    stream << L"]}\n";
    stream << L"Rules:\n";
    stream << L"- Use exact commands supported by KnLiveDbg where possible.\n";
    stream << L"- Prefer read-only commands such as lm, ln, x, d*, dt, callbacks, vtop, pdb, u, uf, and kd for raw DbgEng.\n";
    stream << L"- Use one command per JSON item. Do not use semicolon command chaining or multiline commands.\n";
    stream << L"- Do not use backend, kdinit, kddetach, probe service control, q, quit, exit, unload, or nested ai commands in plans.\n";
    stream << L"- If a write is requested, include backup and verification commands, but mark write_like=true for the mutation command.\n";
    stream << L"- Every command must include purpose, risk, backend, and expected_output.\n";
    stream << L"Operator request:\n";
    stream << prompt << L"\n";

    return stream.str();
}

static std::wstring TruncateForAiPrompt(const std::wstring& text, size_t limit)
{
    std::wstring result = text;

    if (result.size() > limit)
    {
        result.resize(limit);
        result += L"\n[truncated]\n";
    }

    return result;
}

static void PrintAiPlan(const AiPlanState& plan)
{
    do
    {
        if (plan.Commands.empty())
        {
            std::wcout << L"no AI command plan is loaded\n";
            break;
        }

        std::wcout << L"AI command plan";
        if (!plan.Title.empty())
        {
            std::wcout << L": " << plan.Title;
        }
        std::wcout << L"\n";
        if (!plan.Summary.empty())
        {
            std::wcout << plan.Summary << L"\n";
        }

        for (size_t index = 0; index < plan.Commands.size(); ++index)
        {
            const AiCommandProposal& item = plan.Commands[index];
            std::wcout << L"[" << (index + 1) << L"] " << item.Command << L"\n";
            if (!item.Purpose.empty())
            {
                std::wcout << L"    purpose: " << item.Purpose << L"\n";
            }
            if (!item.Risk.empty() || item.WriteLike)
            {
                std::wcout << L"    risk: " << (item.Risk.empty() ? L"(unspecified)" : item.Risk);
                if (item.WriteLike)
                {
                    std::wcout << L" write-like";
                }
                std::wcout << L"\n";
            }
            if (!item.Backend.empty())
            {
                std::wcout << L"    backend: " << item.Backend << L"\n";
            }
            if (!item.ExpectedOutput.empty())
            {
                std::wcout << L"    expected: " << item.ExpectedOutput << L"\n";
            }
        }
    } while (false);
}

static std::wstring BuildAiSessionReport(
    const DebuggerState& state,
    const SymbolEngine& symbols,
    const AiProviderRuntime& ai,
    const AiPlanState& plan)
{
    std::wstringstream stream;

    stream << L"# KnLiveDbg AI Session Report\n\n";
    stream << L"- generated: " << CurrentUtcTimestamp() << L"\n";
    stream << L"- backend: " << BackendModeText(state.Backend) << L"\n";
    stream << L"- number base: " << state.NumberBase << L"\n";
    stream << L"- symbol path: `" << symbols.SymbolPath() << L"`\n";
    stream << L"- loaded kernel modules: " << symbols.Modules().size() << L"\n";
    stream << L"- ai provider: " << ai.ProviderName() << L"\n";
    stream << L"- ai model: " << (ai.Settings().Model.empty() ? L"(default)" : ai.Settings().Model) << L"\n";
    stream << L"- ai credential: " << ai.CredentialStatus() << L"\n";
    stream << L"- transcript: " << (plan.TranscriptEnabled ? L"enabled" : L"disabled");
    if (!plan.TranscriptPath.empty())
    {
        stream << L" `" << plan.TranscriptPath << L"`";
    }
    stream << L"\n";
    stream << L"- transcript rotation max bytes: ";
    if (plan.TranscriptMaxBytes == 0)
    {
        stream << L"off";
    }
    else
    {
        stream << plan.TranscriptMaxBytes;
    }
    stream << L"\n";
    stream << L"- transcript redaction: " << (plan.TranscriptRedactOutput ? L"enabled" : L"disabled") << L"\n";
    stream << L"- write audit: " << (plan.WriteAuditEnabled ? L"enabled" : L"disabled");
    if (!plan.WriteAuditPath.empty())
    {
        stream << L" `" << plan.WriteAuditPath << L"`";
    }
    stream << L"\n\n";

    stream << L"## Current AI Plan\n\n";
    if (plan.Commands.empty())
    {
        stream << L"No AI command plan is loaded.\n";
    }
    else
    {
        if (!plan.Schema.empty())
        {
            stream << L"Schema: `" << plan.Schema << L"`\n\n";
        }
        if (!plan.Title.empty())
        {
            stream << L"Title: " << plan.Title << L"\n\n";
        }
        if (!plan.Summary.empty())
        {
            stream << plan.Summary << L"\n\n";
        }
        for (size_t index = 0; index < plan.Commands.size(); ++index)
        {
            const AiCommandProposal& item = plan.Commands[index];
            stream << L"### " << (index + 1) << L". `" << item.Command << L"`\n\n";
            if (!item.Purpose.empty())
            {
                stream << L"- purpose: " << item.Purpose << L"\n";
            }
            if (!item.Risk.empty())
            {
                stream << L"- risk: " << item.Risk << L"\n";
            }
            if (!item.Backend.empty())
            {
                stream << L"- backend: " << item.Backend << L"\n";
            }
            if (!item.ExpectedOutput.empty())
            {
                stream << L"- expected output: " << item.ExpectedOutput << L"\n";
            }
            stream << L"- write-like: " << (item.WriteLike ? L"yes" : L"no") << L"\n";
            stream << L"- requires confirmation: " << (item.RequiresConfirmation ? L"yes" : L"no") << L"\n\n";
        }
    }

    if (!plan.RawResponse.empty())
    {
        stream << L"## Raw AI Plan Response\n\n";
        stream << L"```text\n";
        stream << plan.RawResponse << L"\n";
        stream << L"```\n";
    }

    return stream.str();
}

class TeeWideStreamBuffer : public std::wstreambuf
{
public:
    TeeWideStreamBuffer(std::wstreambuf* target, std::wstring* capture) :
        target_(target),
        capture_(capture)
    {
    }

protected:
    int_type overflow(int_type value) override
    {
        if (traits_type::eq_int_type(value, traits_type::eof()))
        {
            return traits_type::not_eof(value);
        }

        wchar_t ch = traits_type::to_char_type(value);
        if (capture_ != nullptr)
        {
            capture_->push_back(ch);
        }

        if (target_ != nullptr)
        {
            return target_->sputc(ch);
        }

        return value;
    }

    std::streamsize xsputn(const wchar_t* text, std::streamsize count) override
    {
        if (capture_ != nullptr && text != nullptr && count > 0)
        {
            capture_->append(text, static_cast<size_t>(count));
        }

        if (target_ != nullptr)
        {
            return target_->sputn(text, count);
        }

        return count;
    }

    int sync() override
    {
        if (target_ != nullptr)
        {
            return target_->pubsync();
        }

        return 0;
    }

private:
    std::wstreambuf* target_;
    std::wstring* capture_;
};

class ScopedWideStreamCapture
{
public:
    ScopedWideStreamCapture(std::wstring* output, std::wstring* error) :
        outBuffer_(std::wcout.rdbuf(), output),
        errBuffer_(std::wcerr.rdbuf(), error),
        oldOut_(std::wcout.rdbuf(&outBuffer_)),
        oldErr_(std::wcerr.rdbuf(&errBuffer_))
    {
    }

    ~ScopedWideStreamCapture()
    {
        std::wcout.flush();
        std::wcerr.flush();
        std::wcout.rdbuf(oldOut_);
        std::wcerr.rdbuf(oldErr_);
    }

private:
    TeeWideStreamBuffer outBuffer_;
    TeeWideStreamBuffer errBuffer_;
    std::wstreambuf* oldOut_;
    std::wstreambuf* oldErr_;
};

static bool HandleCommand(
    const std::vector<std::wstring>& args,
    const std::wstring& originalLine,
    DebuggerState& state,
    DbgEngBackend& dbgeng,
    DeviceClient& device,
    DriverService& service,
    SymbolEngine& symbols,
    AiProviderRuntime& ai,
    AiPlanState& aiState);

static CommandExecutionResult ExecuteCommandWithTranscript(
    const std::vector<std::wstring>& args,
    const std::wstring& originalLine,
    const std::wstring& origin,
    DebuggerState& state,
    DbgEngBackend& dbgeng,
    DeviceClient& device,
    DriverService& service,
    SymbolEngine& symbols,
    AiProviderRuntime& ai,
    AiPlanState& aiState);

static std::wstring ByteCountText(uint64_t byteCount)
{
    std::wstringstream stream;

    if (byteCount == 0)
    {
        stream << L"unknown";
    }
    else
    {
        stream << byteCount << L" bytes";
    }

    return stream.str();
}

static bool EstimateEnterWriteSize(const std::vector<std::wstring>& commandArgs, uint64_t* byteCount)
{
    bool ok = false;

    do
    {
        if (byteCount == nullptr || commandArgs.size() < 3)
        {
            break;
        }

        std::wstring command = NormalizeInputCommand(commandArgs[0]);
        if (command == L"ea" || command == L"eza" || command == L"eu" || command == L"ezu")
        {
            std::wstring value = JoinArgs(commandArgs, 2);
            bool unicode = command == L"eu" || command == L"ezu";
            bool zeroTerminate = command == L"eza" || command == L"ezu";
            uint64_t unit = unicode ? sizeof(wchar_t) : 1;
            uint64_t terminator = zeroTerminate ? unit : 0;
            if (value.size() <= ((~0ull - terminator) / unit))
            {
                *byteCount = value.size() * unit + terminator;
                ok = true;
            }
            break;
        }

        uint64_t width = 1;
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

        uint64_t count = static_cast<uint64_t>(commandArgs.size() - 2);
        if (count <= (~0ull / width))
        {
            *byteCount = count * width;
            ok = true;
        }
    } while (false);

    return ok;
}

static bool EstimatePhysicalEnterWriteSize(const std::vector<std::wstring>& commandArgs, uint64_t* byteCount)
{
    bool ok = false;

    do
    {
        if (byteCount == nullptr || commandArgs.size() < 3)
        {
            break;
        }

        std::wstring command = NormalizeInputCommand(commandArgs[0]);
        uint64_t width = 1;
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

        uint64_t count = static_cast<uint64_t>(commandArgs.size() - 2);
        if (count <= (~0ull / width))
        {
            *byteCount = count * width;
            ok = true;
        }
    } while (false);

    return ok;
}

static AiWriteSafetyPlan BuildWriteSafetyPlan(
    const std::wstring& commandLine,
    const DebuggerState& state,
    SymbolEngine& symbols)
{
    AiWriteSafetyPlan plan = {};
    std::vector<std::wstring> commandArgs = Split(commandLine);

    do
    {
        if (commandArgs.empty())
        {
            plan.Warning = L"empty command";
            break;
        }

        std::wstring command = NormalizeInputCommand(commandArgs[0]);
        if (command == L"kd")
        {
            plan.TargetKind = L"dbgeng-raw-write";
            plan.Target = commandLine;
            plan.ByteCountText = L"unknown";
            plan.Warning = L"raw kd write-like command: automatic backup and restore are unavailable; prefer native e*, pe*, setfield, f, or m commands when possible";
        }
        else if (IsEnterCommand(command))
        {
            if (commandArgs.size() < 3)
            {
                plan.Warning = L"cannot build write safety plan: enter command has too few arguments";
                break;
            }

            uint64_t address = 0;
            std::wstring error;
            bool resolved = ParseAddressOrSymbol(symbols, state, commandArgs[1], &address, &error);
            uint64_t byteCount = 0;
            EstimateEnterWriteSize(commandArgs, &byteCount);

            plan.TargetKind = L"virtual";
            plan.Target = resolved ? HexText(address) : commandArgs[1];
            plan.ByteCountText = ByteCountText(byteCount);
            plan.BackupCommand = L"db " + commandArgs[1] + L" " + std::to_wstring(byteCount == 0 ? 16 : byteCount);
            plan.VerifyCommand = plan.BackupCommand;
            plan.TranslationCommand = L"vtop " + commandArgs[1] + L" " + std::to_wstring(byteCount == 0 ? 1 : byteCount);
            plan.Warning = L"virtual write: verify page ownership, target module, and whether the range touches code, callbacks, list links, or reference counts";
        }
        else if (IsPhysicalEnterCommand(command))
        {
            if (commandArgs.size() < 3)
            {
                plan.Warning = L"cannot build write safety plan: physical enter command has too few arguments";
                break;
            }

            uint64_t physicalAddress = 0;
            ParseUnsigned(commandArgs[1], state.NumberBase, &physicalAddress);
            uint64_t byteCount = 0;
            EstimatePhysicalEnterWriteSize(commandArgs, &byteCount);

            plan.TargetKind = L"physical";
            plan.Target = HexText(physicalAddress);
            plan.ByteCountText = ByteCountText(byteCount);
            plan.BackupCommand = L"pdb " + commandArgs[1] + L" " + std::to_wstring(byteCount == 0 ? 16 : byteCount);
            plan.VerifyCommand = plan.BackupCommand;
            plan.Warning = L"physical write: confirm this is not page table, MMIO, firmware-owned, or device memory before confirming";
        }
        else if (command == L"setfield")
        {
            if (commandArgs.size() < 5)
            {
                plan.Warning = L"cannot build write safety plan: setfield has too few arguments";
                break;
            }

            uint64_t address = 0;
            std::wstring error;
            ParseAddressOrSymbol(symbols, state, commandArgs[2], &address, &error);

            TypeFieldInfo field = {};
            uint64_t byteCount = 0;
            if (symbols.FindField(commandArgs[1], commandArgs[3], &field, &error))
            {
                byteCount = static_cast<uint64_t>(field.Length);
                if (byteCount == 0 || byteCount > sizeof(uint64_t))
                {
                    byteCount = sizeof(uint64_t);
                }
            }

            plan.TargetKind = L"type-field";
            plan.Target = commandArgs[1] + L"." + commandArgs[3] + L" at " + commandArgs[2];
            if (address != 0 && field.Offset != 0)
            {
                plan.Target += L" field-address=" + HexText(address + field.Offset);
            }
            plan.ByteCountText = ByteCountText(byteCount);
            plan.BackupCommand = L"dt " + commandArgs[1] + L" " + commandArgs[2] + L" " + commandArgs[3];
            plan.VerifyCommand = plan.BackupCommand;
            plan.TranslationCommand = L"vtop " + commandArgs[2] + L" " + std::to_wstring(byteCount == 0 ? 1 : byteCount);
            plan.Warning = L"type field write: check field drift, bitfield width, pointer ownership, and list/refcount semantics";
        }
        else if (command == L"f" || command == L"fp")
        {
            if (commandArgs.size() < 4)
            {
                plan.Warning = L"cannot build write safety plan: fill command has too few arguments";
                break;
            }

            uint64_t length = 0;
            ParseUnsigned(commandArgs[2], state.NumberBase, &length);
            plan.TargetKind = L"virtual-fill";
            plan.Target = commandArgs[1];
            plan.ByteCountText = ByteCountText(length);
            plan.BackupCommand = L"db " + commandArgs[1] + L" " + std::to_wstring(length == 0 ? 16 : length);
            plan.VerifyCommand = plan.BackupCommand;
            plan.TranslationCommand = L"vtop " + commandArgs[1] + L" " + std::to_wstring(length == 0 ? 1 : length);
            plan.Warning = L"fill write: confirm the whole target range is intended and does not cross into adjacent structure fields";
        }
        else if (command == L"m")
        {
            if (commandArgs.size() < 4)
            {
                plan.Warning = L"cannot build write safety plan: move command has too few arguments";
                break;
            }

            uint64_t length = 0;
            ParseUnsigned(commandArgs[3], state.NumberBase, &length);
            plan.TargetKind = L"virtual-move";
            plan.Target = L"destination " + commandArgs[2] + L" from source " + commandArgs[1];
            plan.ByteCountText = ByteCountText(length);
            plan.BackupCommand = L"db " + commandArgs[2] + L" " + std::to_wstring(length == 0 ? 16 : length);
            plan.VerifyCommand = plan.BackupCommand;
            plan.TranslationCommand = L"vtop " + commandArgs[2] + L" " + std::to_wstring(length == 0 ? 1 : length);
            plan.Warning = L"move write: confirm source and destination do not overlap unexpectedly";
        }
        else
        {
            plan.Warning = L"write-like command is not recognized by the safety planner";
        }
    } while (false);

    return plan;
}

static bool ResolveWriteTargetForRestore(
    const std::wstring& commandLine,
    const DebuggerState& state,
    SymbolEngine& symbols,
    bool* physical,
    uint64_t* address,
    uint64_t* byteCount)
{
    bool ok = false;
    std::vector<std::wstring> commandArgs = Split(commandLine);

    do
    {
        if (physical == nullptr || address == nullptr || byteCount == nullptr || commandArgs.empty())
        {
            break;
        }

        *physical = false;
        *address = 0;
        *byteCount = 0;

        std::wstring command = NormalizeInputCommand(commandArgs[0]);
        std::wstring error;
        if (IsEnterCommand(command))
        {
            if (commandArgs.size() < 3 ||
                !ParseAddressOrSymbol(symbols, state, commandArgs[1], address, &error) ||
                !EstimateEnterWriteSize(commandArgs, byteCount))
            {
                break;
            }
            ok = true;
        }
        else if (IsPhysicalEnterCommand(command))
        {
            if (commandArgs.size() < 3 ||
                !ParseUnsigned(commandArgs[1], state.NumberBase, address) ||
                !EstimatePhysicalEnterWriteSize(commandArgs, byteCount))
            {
                break;
            }
            *physical = true;
            ok = true;
        }
        else if (command == L"setfield")
        {
            if (commandArgs.size() < 5)
            {
                break;
            }

            TypeFieldInfo field = {};
            if (!symbols.FindField(commandArgs[1], commandArgs[3], &field, &error) ||
                !ParseAddressOrSymbol(symbols, state, commandArgs[2], address, &error) ||
                !TryAddOffset(*address, field.Offset, address))
            {
                break;
            }

            *byteCount = static_cast<uint64_t>(field.Length);
            if (*byteCount == 0 || *byteCount > sizeof(uint64_t))
            {
                *byteCount = sizeof(uint64_t);
            }
            ok = true;
        }
        else if (command == L"f" || command == L"fp")
        {
            if (commandArgs.size() < 4 ||
                !ParseAddressOrSymbol(symbols, state, commandArgs[1], address, &error) ||
                !ParseUnsigned(commandArgs[2], state.NumberBase, byteCount))
            {
                break;
            }
            ok = true;
        }
        else if (command == L"m")
        {
            if (commandArgs.size() < 4 ||
                !ParseAddressOrSymbol(symbols, state, commandArgs[2], address, &error) ||
                !ParseUnsigned(commandArgs[3], state.NumberBase, byteCount))
            {
                break;
            }
            ok = true;
        }

        if (ok && !IsSafeTransferSize(*byteCount))
        {
            ok = false;
        }
    } while (false);

    return ok;
}

static std::wstring BuildByteRestoreCommand(const std::wstring& prefix, uint64_t address, const std::vector<uint8_t>& bytes)
{
    std::wstringstream stream;

    stream << prefix << L" " << HexText(address);
    for (uint8_t value : bytes)
    {
        stream << L" " << std::hex << std::setw(2) << std::setfill(L'0')
               << static_cast<unsigned>(value) << std::setfill(L' ') << std::dec;
    }

    return stream.str();
}

static void PopulateWriteRestoreCommand(
    AiWriteSafetyPlan* plan,
    const std::wstring& commandLine,
    const DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    do
    {
        if (plan == nullptr)
        {
            break;
        }

        bool physical = false;
        uint64_t address = 0;
        uint64_t byteCount = 0;
        if (!ResolveWriteTargetForRestore(commandLine, state, symbols, &physical, &address, &byteCount))
        {
            break;
        }

        if (byteCount == 0 || byteCount > 64)
        {
            std::wstring note = L"restore command omitted for large or unknown range; use backup/read-current output to build an explicit restore command";
            plan->Warning = plan->Warning.empty() ? note : plan->Warning + L"; " + note;
            break;
        }

        std::vector<uint8_t> bytes;
        std::wstring error;
        bool readOk = physical ?
            device.ReadPhysical(address, static_cast<uint32_t>(byteCount), &bytes, &error) :
            device.ReadMemory(address, static_cast<uint32_t>(byteCount), &bytes, &error);
        if (!readOk)
        {
            std::wstring note = L"restore read failed: " + error;
            plan->Warning = plan->Warning.empty() ? note : plan->Warning + L"; " + note;
            break;
        }

        plan->RestoreCommand = BuildByteRestoreCommand(physical ? L"peb" : L"eb", address, bytes);
    } while (false);
}

static void PrintWriteSafetyPlan(const AiWriteSafetyPlan& plan)
{
    std::wcout << L"write safety preflight\n";
    if (!plan.TargetKind.empty())
    {
        std::wcout << L"  target-kind: " << plan.TargetKind << L"\n";
    }
    if (!plan.Target.empty())
    {
        std::wcout << L"  target: " << plan.Target << L"\n";
    }
    if (!plan.ByteCountText.empty())
    {
        std::wcout << L"  size: " << plan.ByteCountText << L"\n";
    }
    if (!plan.TranslationCommand.empty())
    {
        std::wcout << L"  translation: " << plan.TranslationCommand << L"\n";
    }
    if (!plan.BackupCommand.empty())
    {
        std::wcout << L"  backup/read-current: " << plan.BackupCommand << L"\n";
    }
    if (!plan.RestoreCommand.empty())
    {
        std::wcout << L"  restore-current: " << plan.RestoreCommand << L"\n";
    }
    if (!plan.VerifyCommand.empty())
    {
        std::wcout << L"  verify-after: " << plan.VerifyCommand << L"\n";
    }
    if (!plan.Warning.empty())
    {
        std::wcout << L"  warning: " << plan.Warning << L"\n";
    }
}

static CommandExecutionResult ExecuteReadOnlySafetyCommand(
    const std::wstring& commandLine,
    const std::wstring& origin,
    DebuggerState& state,
    DbgEngBackend& dbgeng,
    DeviceClient& device,
    DriverService& service,
    SymbolEngine& symbols,
    AiProviderRuntime& ai,
    AiPlanState& aiState)
{
    CommandExecutionResult result = {};
    result.KeepRunning = true;

    do
    {
        if (commandLine.empty())
        {
            break;
        }

        if (IsWriteLikeCommandLine(commandLine))
        {
            result.Error = L"preflight command blocked because it is write-like: " + commandLine;
            std::wcerr << result.Error << L"\n";
            break;
        }

        std::wcout << L"preflight> " << commandLine << L"\n";
        result = ExecuteCommandWithTranscript(
            Split(commandLine),
            commandLine,
            origin,
            state,
            dbgeng,
            device,
            service,
            symbols,
            ai,
            aiState);
    } while (false);

    return result;
}

static std::vector<std::wstring> SplitDiffLines(const std::wstring& text)
{
    std::vector<std::wstring> lines;
    std::wistringstream stream(text);
    std::wstring line;

    while (std::getline(stream, line))
    {
        if (!line.empty() && line.back() == L'\r')
        {
            line.pop_back();
        }
        lines.push_back(line);
    }

    if (lines.empty() && !text.empty())
    {
        lines.push_back(text);
    }

    return lines;
}

static void PrintLineDiff(
    const std::wstring& label,
    const std::wstring& before,
    const std::wstring& after)
{
    do
    {
        if (before == after)
        {
            std::wcout << L"  " << label << L": no textual change\n";
            break;
        }

        std::vector<std::wstring> beforeLines = SplitDiffLines(before);
        std::vector<std::wstring> afterLines = SplitDiffLines(after);
        size_t maxCount = std::max(beforeLines.size(), afterLines.size());
        size_t emitted = 0;
        std::wcout << L"  " << label << L":\n";

        for (size_t index = 0; index < maxCount; ++index)
        {
            const std::wstring beforeLine = index < beforeLines.size() ? beforeLines[index] : L"";
            const std::wstring afterLine = index < afterLines.size() ? afterLines[index] : L"";
            if (beforeLine == afterLine)
            {
                continue;
            }

            if (emitted >= 80)
            {
                std::wcout << L"    ... diff truncated ...\n";
                break;
            }

            if (index < beforeLines.size())
            {
                std::wcout << L"    - " << beforeLine << L"\n";
            }
            if (index < afterLines.size())
            {
                std::wcout << L"    + " << afterLine << L"\n";
            }
            ++emitted;
        }
    } while (false);
}

static void PrintWriteVerificationDiff(
    const std::wstring& verifyCommand,
    const CommandExecutionResult& before,
    const CommandExecutionResult& after)
{
    do
    {
        if (verifyCommand.empty())
        {
            break;
        }

        std::wcout << L"write verification diff\n";
        std::wcout << L"  command: " << verifyCommand << L"\n";
        PrintLineDiff(L"stdout", before.Output, after.Output);
        PrintLineDiff(L"stderr", before.Error, after.Error);
    } while (false);
}

static std::wstring BuildAiEvidencePrompt(
    const std::wstring& title,
    const std::wstring& instructions,
    const std::wstring& commandLine,
    const CommandExecutionResult& result)
{
    std::wstringstream stream;

    stream << title << L"\n\n";
    stream << instructions << L"\n\n";
    stream << L"Command:\n";
    stream << commandLine << L"\n\n";
    stream << L"Deterministic output summary:\n```text\n";
    stream << BuildCommandOutputSummary(result);
    stream << L"\n```\n\n";
    stream << L"Stdout:\n```text\n";
    stream << TruncateForAiPrompt(result.Output, 60000);
    stream << L"\n```\n\n";
    stream << L"Stderr:\n```text\n";
    stream << TruncateForAiPrompt(result.Error, 12000);
    stream << L"\n```\n";

    return stream.str();
}

static void CompleteAndPrintAiRequest(
    const std::wstring& eventName,
    const AiCompletionRequest& request,
    AiProviderRuntime& ai,
    AiPlanState& aiState)
{
    do
    {
        std::wcout << L"ai request: provider=" << ai.ProviderName()
                   << L" model=" << ai.Settings().Model
                   << L" credential=" << ai.CredentialStatus() << L"\n";

        AiCompletionResponse response = {};
        std::wstring error;
        if (!ai.Complete(request, &response, &error))
        {
            std::wcerr << L"ai request failed: " << error << L"\n";
            WriteAiTranscriptEvent(aiState, eventName + L"_failed", error, L"");
            break;
        }

        WriteAiTranscriptEvent(aiState, eventName, L"request completed", L"");
        if (!response.Text.empty())
        {
            std::wcout << response.Text;
            if (response.Text.back() != L'\n')
            {
                std::wcout << L"\n";
            }
        }
    } while (false);
}

static void HandleAiEvidenceAnalysis(
    const std::wstring& eventName,
    const std::wstring& commandLine,
    const std::wstring& title,
    const std::wstring& instructions,
    DebuggerState& state,
    DbgEngBackend& dbgeng,
    DeviceClient& device,
    DriverService& service,
    SymbolEngine& symbols,
    AiProviderRuntime& ai,
    AiPlanState& aiState)
{
    do
    {
        std::wstring reason;
        if (IsBlockedAiRunCommand(commandLine, &reason))
        {
            std::wcerr << L"ai analysis command blocked: " << reason << L"\n";
            break;
        }

        std::wcout << L"ai evidence> " << commandLine << L"\n";
        CommandExecutionResult result = ExecuteCommandWithTranscript(
            Split(commandLine),
            commandLine,
            L"ai_evidence",
            state,
            dbgeng,
            device,
            service,
            symbols,
            ai,
            aiState);
        if (!result.KeepRunning)
        {
            break;
        }

        AiCompletionRequest request = {};
        request.System = BuildAiSystemPrompt(state, symbols);
        request.Prompt = BuildAiEvidencePrompt(title, instructions, commandLine, result);
        CompleteAndPrintAiRequest(eventName, request, ai, aiState);
    } while (false);
}

static AiPlanState BuildPlaybookPlan(const std::wstring& name, const std::wstring& argument, std::wstring* error)
{
    AiPlanState plan = {};
    std::wstring key = ToLower(name);
    plan.Schema = L"kn-live-dbg.ai-plan.v2";

    auto add = [&plan](const std::wstring& command, const std::wstring& purpose)
    {
        AiCommandProposal item = {};
        item.Command = command;
        item.Purpose = purpose;
        item.Risk = L"read-only";
        item.Backend = InferAiPlanBackend(command, ClassifyCommandLine(command, false));
        item.ExpectedOutput = L"operator evidence for the playbook step";
        item.RequiresConfirmation = false;
        item.WriteLike = IsWriteLikeCommandLine(command);
        plan.Commands.push_back(item);
    };

    do
    {
        if (key == L"callbacks" || key == L"callback-audit")
        {
            plan.Title = L"Callback surface audit";
            plan.Summary = L"Enumerate callback surfaces and module baseline for follow-up AI analysis.";
            add(L"callbacks all", L"enumerate object, registry, process, and minifilter callbacks");
            add(L"lm", L"capture loaded module baseline");
        }
        else if (key == L"minifilter")
        {
            plan.Title = L"Minifilter chain review";
            plan.Summary = L"Enumerate minifilter callbacks and baseline fltmgr symbols.";
            add(L"callbacks minifilter", L"enumerate registered minifilter callbacks");
            add(L"x fltmgr!*Flt*", L"list FltMgr symbols useful for manual follow-up");
        }
        else if (key == L"object" || key == L"object-callbacks")
        {
            plan.Title = L"Object callback integrity review";
            plan.Summary = L"Enumerate object-manager callback lists discovered from object type objects.";
            add(L"callbacks ob", L"enumerate object-manager filters by object type");
            add(L"dt nt!_OBJECT_TYPE", L"show object type layout for offset verification");
        }
        else if (key == L"address")
        {
            if (argument.empty())
            {
                if (error != nullptr)
                {
                    *error = L"usage: ai playbook address <address|symbol> [run|dry-run]";
                }
                break;
            }

            plan.Title = L"Address provenance";
            plan.Summary = L"Resolve ownership, translation, data view, and code view for one address.";
            add(L"ln " + argument, L"resolve nearest symbol and module ownership");
            add(L"vtop " + argument, L"translate virtual address to physical context");
            add(L"dq " + argument + L" 4", L"display qword data at the target");
            add(L"u " + argument + L" 16", L"disassemble if the target is executable code");
        }
        else if (key == L"driver" || key == L"suspect-driver")
        {
            plan.Title = L"Suspect driver surface map";
            if (argument.empty())
            {
                plan.Summary = L"Capture module list and callback registrations; pass a module name for symbol enumeration.";
                add(L"lm", L"list loaded kernel modules");
                add(L"callbacks all", L"find callback surfaces owned by loaded modules");
            }
            else
            {
                plan.Summary = L"Capture module, symbols, and callback registrations for a suspected driver.";
                add(L"lm " + argument, L"show matching loaded module");
                add(L"x " + argument + L"!*", L"list public symbols for the suspected module");
                add(L"callbacks all", L"find callback surfaces owned by the module");
            }
        }
        else
        {
            if (error != nullptr)
            {
                *error = L"unknown playbook. supported: callbacks, minifilter, object, address, driver";
            }
            break;
        }
    } while (false);

    return plan;
}

static bool RunAiPlannedCommands(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DbgEngBackend& dbgeng,
    DeviceClient& device,
    DriverService& service,
    SymbolEngine& symbols,
    AiProviderRuntime& ai,
    AiPlanState& aiState)
{
    bool keepRunning = true;

    do
    {
        if (aiState.Commands.empty())
        {
            std::wcerr << L"no AI command plan is loaded. run ai plan <prompt> first\n";
            break;
        }

        if (args.size() < 3)
        {
            std::wcerr << L"usage: ai run <index|all>\n";
            break;
        }

        std::vector<size_t> indexes;
        if (ToLower(args[2]) == L"all")
        {
            for (size_t index = 1; index <= aiState.Commands.size(); ++index)
            {
                indexes.push_back(index);
            }
        }
        else
        {
            size_t index = 0;
            if (!ParseDecimalIndex(args[2], &index) || index == 0 || index > aiState.Commands.size())
            {
                std::wcerr << L"invalid AI plan index\n";
                break;
            }
            indexes.push_back(index);
        }

        for (size_t index : indexes)
        {
            const AiCommandProposal& item = aiState.Commands[index - 1];
            std::wstring reason;
            if (IsBlockedAiRunCommand(item.Command, &reason))
            {
                std::wcerr << L"ai run blocked [" << index << L"]: " << reason << L" command=" << item.Command << L"\n";
                WriteAiTranscriptEvent(aiState, L"ai_run_blocked", reason, item.Command);
                continue;
            }

            std::wcout << L"ai run [" << index << L"]: " << item.Command << L"\n";
            WriteAiTranscriptEvent(aiState, L"ai_run", L"executing planned command", item.Command);

            std::vector<std::wstring> commandArgs = Split(item.Command);
            CommandExecutionResult result = ExecuteCommandWithTranscript(
                commandArgs,
                item.Command,
                L"ai_run",
                state,
                dbgeng,
                device,
                service,
                symbols,
                ai,
                aiState);
            if (!result.KeepRunning)
            {
                keepRunning = false;
                break;
            }
        }
    } while (false);

    return keepRunning;
}

static void HandleAiPlaybookCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DbgEngBackend& dbgeng,
    DeviceClient& device,
    DriverService& service,
    SymbolEngine& symbols,
    AiProviderRuntime& ai,
    AiPlanState& aiState)
{
    do
    {
        if (args.size() < 3)
        {
            std::wcerr << L"usage: ai playbook <callbacks|minifilter|object|address|driver> [argument] [run|dry-run]\n";
            break;
        }

        std::wstring mode = L"dry-run";
        std::wstring argument;
        if (args.size() >= 4)
        {
            std::wstring last = ToLower(args.back());
            if (last == L"run" || last == L"dry-run")
            {
                mode = last;
                if (args.size() > 4)
                {
                    std::vector<std::wstring> argumentArgs(args.begin() + 3, args.end() - 1);
                    argument = JoinArgs(argumentArgs, 0);
                }
            }
            else
            {
                argument = JoinArgs(args, 3);
            }
        }

        std::wstring error;
        AiPlanState plan = BuildPlaybookPlan(args[2], argument, &error);
        if (plan.Commands.empty())
        {
            std::wcerr << L"ai playbook failed: " << error << L"\n";
            break;
        }

        PreserveAiSessionSettings(plan, aiState);
        aiState = plan;
        WriteAiTranscriptEvent(aiState, L"ai_playbook", L"playbook loaded", args[2]);
        PrintAiPlan(aiState);

        if (mode == L"run")
        {
            std::vector<std::wstring> runArgs = {L"ai", L"run", L"all"};
            RunAiPlannedCommands(runArgs, state, dbgeng, device, service, symbols, ai, aiState);
        }
    } while (false);
}

static void HandleAiPlannedWrite(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DbgEngBackend& dbgeng,
    DeviceClient& device,
    DriverService& service,
    SymbolEngine& symbols,
    AiProviderRuntime& ai,
    AiPlanState& aiState)
{
    do
    {
        if (aiState.Commands.empty())
        {
            std::wcerr << L"no AI command plan is loaded. run ai plan <prompt> first\n";
            break;
        }

        if (args.size() < 3)
        {
            std::wcerr << L"usage: ai write <index> [confirm]\n";
            break;
        }

        size_t index = 0;
        if (!ParseDecimalIndex(args[2], &index) || index == 0 || index > aiState.Commands.size())
        {
            std::wcerr << L"invalid AI plan index\n";
            break;
        }

        const AiCommandProposal& item = aiState.Commands[index - 1];
        std::wstring reason;
        if (IsBlockedAiRunCommand(item.Command, &reason) && !IsWriteLikeCommandLine(item.Command))
        {
            std::wcerr << L"ai write blocked: " << reason << L"\n";
            WriteAiTranscriptEvent(aiState, L"ai_write_blocked", reason, item.Command);
            break;
        }

        if (!IsWriteLikeCommandLine(item.Command))
        {
            std::wcerr << L"selected command is not write-like; use ai run " << index << L"\n";
            break;
        }

        AiWriteSafetyPlan safety = BuildWriteSafetyPlan(item.Command, state, symbols);
        PopulateWriteRestoreCommand(&safety, item.Command, state, device, symbols);
        bool confirmed = args.size() >= 4 && ToLower(args[3]) == L"confirm";
        if (!confirmed)
        {
            std::wcout << L"AI write preview [" << index << L"]\n";
            std::wcout << L"command: " << item.Command << L"\n";
            if (!item.Purpose.empty())
            {
                std::wcout << L"purpose: " << item.Purpose << L"\n";
            }
            if (!item.Risk.empty())
            {
                std::wcout << L"risk: " << item.Risk << L"\n";
            }
            PrintWriteSafetyPlan(safety);
            ExecuteReadOnlySafetyCommand(safety.TranslationCommand, L"ai_write_preflight", state, dbgeng, device, service, symbols, ai, aiState);
            ExecuteReadOnlySafetyCommand(safety.BackupCommand, L"ai_write_preflight", state, dbgeng, device, service, symbols, ai, aiState);
            std::wcout << L"operator action required: inspect the command, backup/readback output, then type:\n";
            std::wcout << L"  ai write " << index << L" confirm\n";
            WriteAiTranscriptEvent(aiState, L"ai_write_preview", L"confirmation required", item.Command);
            break;
        }

        std::wcout << L"ai write confirm [" << index << L"]: " << item.Command << L"\n";
        WriteAiTranscriptEvent(aiState, L"ai_write_confirm", L"operator confirmed write-like command", item.Command);
        PrintWriteSafetyPlan(safety);
        CommandExecutionResult beforeResult = ExecuteReadOnlySafetyCommand(
            safety.BackupCommand,
            L"ai_write_prewrite",
            state,
            dbgeng,
            device,
            service,
            symbols,
            ai,
            aiState);

        std::vector<std::wstring> commandArgs = Split(item.Command);
        ExecuteCommandWithTranscript(
            commandArgs,
            item.Command,
            L"ai_write_confirm",
            state,
            dbgeng,
            device,
            service,
            symbols,
            ai,
            aiState);
        CommandExecutionResult afterResult = ExecuteReadOnlySafetyCommand(
            safety.VerifyCommand,
            L"ai_write_verify",
            state,
            dbgeng,
            device,
            service,
            symbols,
            ai,
            aiState);
        PrintWriteVerificationDiff(safety.VerifyCommand, beforeResult, afterResult);
    } while (false);
}

static void HandleAiCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DbgEngBackend& dbgeng,
    DeviceClient& device,
    DriverService& service,
    SymbolEngine& symbols,
    AiProviderRuntime& ai,
    AiPlanState& aiState)
{
    do
    {
        if (args.size() == 1 || args[1] == L"status")
        {
            std::wcout << ai.StatusText();
            break;
        }

        std::wstring action = ToLower(args[1]);
        if (action == L"help")
        {
            std::wcout << L"ai commands:\n";
            std::wcout << L"  ai status\n";
            std::wcout << L"  ai providers\n";
            std::wcout << L"  ai provider <openai-codex-cli|openai-codex-subscription|deepseek|openrouter|off>\n";
            std::wcout << L"  ai policy <allow-remote|local-only|status>\n";
            std::wcout << L"  ai model <model>\n";
            std::wcout << L"  ai baseurl <url>\n";
            std::wcout << L"  ai effort <minimal|low|medium|high|xhigh>\n";
            std::wcout << L"  ai auth\n";
            std::wcout << L"  ai preview <prompt>\n";
            std::wcout << L"  ai ask <prompt>\n";
            std::wcout << L"  ai plan <prompt>\n";
            std::wcout << L"  ai analyze callbacks [all|ob|registry|process|minifilter]\n";
            std::wcout << L"  ai explain dt <dt-args...>\n";
            std::wcout << L"  ai annotate <u|uf> <address|symbol> [count]\n";
            std::wcout << L"  ai diagnose <prompt>\n";
            std::wcout << L"  ai playbook <callbacks|minifilter|object|address|driver> [argument] [run|dry-run]\n";
            std::wcout << L"  ai show\n";
            std::wcout << L"  ai run <index|all>\n";
            std::wcout << L"  ai write <index> [confirm]\n";
            std::wcout << L"  ai transcript <path|off|status>\n";
            std::wcout << L"  ai transcript max <bytes|off>\n";
            std::wcout << L"  ai transcript redact <on|off>\n";
            std::wcout << L"  ai audit <path|off|status>\n";
            std::wcout << L"  ai report <path>\n";
        }
        else if (action == L"providers")
        {
            PrintAiProviders();
        }
        else if (action == L"provider")
        {
            if (args.size() < 3)
            {
                std::wcerr << L"usage: ai provider <name>\n";
                break;
            }

            std::wstring error;
            if (!ai.SetProvider(args[2], &error))
            {
                std::wcerr << L"ai provider failed: " << error << L"\n";
                break;
            }

            std::wcout << ai.StatusText();
        }
        else if (action == L"policy")
        {
            if (args.size() < 3 || ToLower(args[2]) == L"status")
            {
                std::wcout << L"ai remote policy: " << ai.RemotePolicyName() << L"\n";
                break;
            }

            std::wstring error;
            if (!ai.SetRemotePolicy(args[2], &error))
            {
                std::wcerr << L"ai policy failed: " << error << L"\n";
                break;
            }

            std::wcout << ai.StatusText();
        }
        else if (action == L"model")
        {
            if (args.size() < 3)
            {
                std::wcerr << L"usage: ai model <model>\n";
                break;
            }

            ai.SetModel(JoinArgs(args, 2));
            std::wcout << ai.StatusText();
        }
        else if (action == L"baseurl" || action == L"base-url")
        {
            if (args.size() < 3)
            {
                std::wcerr << L"usage: ai baseurl <url>\n";
                break;
            }

            ai.SetBaseUrl(JoinArgs(args, 2));
            std::wcout << ai.StatusText();
        }
        else if (action == L"effort")
        {
            if (args.size() < 3)
            {
                std::wcerr << L"usage: ai effort <minimal|low|medium|high|xhigh>\n";
                break;
            }

            ai.SetReasoningEffort(args[2]);
            std::wcout << ai.StatusText();
        }
        else if (action == L"auth")
        {
            std::wcout << ai.AuthHelpText();
        }
        else if (action == L"show")
        {
            PrintAiPlan(aiState);
        }
        else if (action == L"write")
        {
            HandleAiPlannedWrite(args, state, dbgeng, device, service, symbols, ai, aiState);
        }
        else if (action == L"transcript")
        {
            if (args.size() < 3 || ToLower(args[2]) == L"status")
            {
                std::wcout << L"ai transcript: " << (aiState.TranscriptEnabled ? L"on" : L"off");
                if (!aiState.TranscriptPath.empty())
                {
                    std::wcout << L" path=" << aiState.TranscriptPath;
                }
                std::wcout << L" max=";
                if (aiState.TranscriptMaxBytes == 0)
                {
                    std::wcout << L"off";
                }
                else
                {
                    std::wcout << aiState.TranscriptMaxBytes;
                }
                std::wcout << L" redact=" << (aiState.TranscriptRedactOutput ? L"on" : L"off");
                std::wcout << L"\n";
                break;
            }

            std::wstring transcriptAction = ToLower(args[2]);
            if (transcriptAction == L"max")
            {
                if (args.size() < 4)
                {
                    std::wcerr << L"usage: ai transcript max <bytes|off>\n";
                    break;
                }

                std::wstring limitText = ToLower(args[3]);
                if (limitText == L"off" || limitText == L"0")
                {
                    aiState.TranscriptMaxBytes = 0;
                    WriteAiTranscriptEvent(aiState, L"transcript_max", L"transcript rotation disabled", L"");
                    std::wcout << L"ai transcript max: off\n";
                    break;
                }

                uint64_t maxBytes = 0;
                if (!ParseUnsigned(args[3], 10, &maxBytes) || maxBytes == 0)
                {
                    std::wcerr << L"invalid transcript max bytes\n";
                    break;
                }

                aiState.TranscriptMaxBytes = maxBytes;
                WriteAiTranscriptEvent(aiState, L"transcript_max", L"transcript rotation limit updated", args[3]);
                std::wcout << L"ai transcript max: " << aiState.TranscriptMaxBytes << L"\n";
                break;
            }

            if (transcriptAction == L"redact")
            {
                if (args.size() < 4)
                {
                    std::wcerr << L"usage: ai transcript redact <on|off>\n";
                    break;
                }

                std::wstring mode = ToLower(args[3]);
                if (mode == L"on")
                {
                    aiState.TranscriptRedactOutput = true;
                }
                else if (mode == L"off")
                {
                    aiState.TranscriptRedactOutput = false;
                }
                else
                {
                    std::wcerr << L"usage: ai transcript redact <on|off>\n";
                    break;
                }

                WriteAiTranscriptEvent(aiState, L"transcript_redact", L"transcript redaction updated", mode);
                std::wcout << L"ai transcript redact: " << (aiState.TranscriptRedactOutput ? L"on" : L"off") << L"\n";
                break;
            }

            if (transcriptAction == L"off")
            {
                WriteAiTranscriptEvent(aiState, L"transcript_off", L"transcript disabled", L"");
                aiState.TranscriptEnabled = false;
                std::wcout << L"ai transcript: off\n";
                break;
            }

            aiState.TranscriptPath = JoinArgs(args, 2);
            aiState.TranscriptEnabled = true;
            WriteAiTranscriptEvent(aiState, L"transcript_on", L"transcript enabled", L"");
            std::wcout << L"ai transcript: on path=" << aiState.TranscriptPath << L"\n";
        }
        else if (action == L"audit")
        {
            if (args.size() < 3 || ToLower(args[2]) == L"status")
            {
                std::wcout << L"ai audit: " << (aiState.WriteAuditEnabled ? L"on" : L"off");
                if (!aiState.WriteAuditPath.empty())
                {
                    std::wcout << L" path=" << aiState.WriteAuditPath;
                }
                std::wcout << L"\n";
                break;
            }

            if (ToLower(args[2]) == L"off")
            {
                WriteAiTranscriptEvent(aiState, L"audit_off", L"write audit disabled", L"");
                aiState.WriteAuditEnabled = false;
                std::wcout << L"ai audit: off\n";
                break;
            }

            aiState.WriteAuditPath = JoinArgs(args, 2);
            aiState.WriteAuditEnabled = true;
            WriteAiTranscriptEvent(aiState, L"audit_on", L"write audit enabled", aiState.WriteAuditPath);
            std::wcout << L"ai audit: on path=" << aiState.WriteAuditPath << L"\n";
        }
        else if (action == L"report")
        {
            if (args.size() < 3)
            {
                std::wcerr << L"usage: ai report <path>\n";
                break;
            }

            std::wstring path = JoinArgs(args, 2);
            std::wstring error;
            if (!WriteUtf8TextFile(path, BuildAiSessionReport(state, symbols, ai, aiState), &error))
            {
                std::wcerr << L"ai report failed: " << error << L"\n";
                break;
            }

            WriteAiTranscriptEvent(aiState, L"ai_report", L"report written", path);
            std::wcout << L"ai report written: " << path << L"\n";
        }
        else if (action == L"analyze")
        {
            if (args.size() < 3 || ToLower(args[2]) != L"callbacks")
            {
                std::wcerr << L"usage: ai analyze callbacks [all|ob|registry|process|minifilter]\n";
                break;
            }

            std::wstring scope = args.size() >= 4 ? args[3] : L"all";
            HandleAiEvidenceAnalysis(
                L"ai_analyze_callbacks",
                L"callbacks json " + scope,
                L"Analyze this KnLiveDbg kernel callback scan.",
                L"Produce a callback analysis report from this structured JSON. Count records by surface, group by module, call out non-image owners, missing symbols, unusual minifilter metadata, shared module ownership across surfaces, and concrete follow-up commands. Preserve raw addresses and confidence notes.",
                state,
                dbgeng,
                device,
                service,
                symbols,
                ai,
                aiState);
        }
        else if (action == L"explain")
        {
            if (args.size() < 4 || (ToLower(args[2]) != L"dt" && ToLower(args[2]) != L"dtx"))
            {
                std::wcerr << L"usage: ai explain dt <dt-args...>\n";
                break;
            }

            std::wstring commandLine = JoinArgs(args, 2);
            HandleAiEvidenceAnalysis(
                L"ai_explain_dt",
                commandLine,
                L"Explain this KnLiveDbg dt/dtx structure output.",
                L"Explain important fields, pointer and LIST_ENTRY follow-ups, suspicious null or out-of-module values, and exact commands to inspect referenced fields. Keep raw offsets and values auditable.",
                state,
                dbgeng,
                device,
                service,
                symbols,
                ai,
                aiState);
        }
        else if (action == L"annotate")
        {
            if (args.size() < 4 || (ToLower(args[2]) != L"u" && ToLower(args[2]) != L"uf"))
            {
                std::wcerr << L"usage: ai annotate <u|uf> <address|symbol> [instruction-count]\n";
                break;
            }

            std::wstring commandLine = JoinArgs(args, 2);
            HandleAiEvidenceAnalysis(
                L"ai_annotate_disassembly",
                commandLine,
                L"Annotate this KnLiveDbg disassembly.",
                L"Summarize likely routine purpose, call targets, direct and indirect call evidence, callback/dispatch/minifilter/process classification hints, suspicious code patterns, uncertainty, and next commands such as ln, x, dt, dq, or uf.",
                state,
                dbgeng,
                device,
                service,
                symbols,
                ai,
                aiState);
        }
        else if (action == L"diagnose")
        {
            if (args.size() < 3)
            {
                std::wcerr << L"usage: ai diagnose <symbol/backend/type failure or operator note>\n";
                break;
            }

            AiCompletionRequest request = {};
            request.System = BuildAiSystemPrompt(state, symbols);
            std::wstringstream prompt;
            prompt << L"Diagnose this KnLiveDbg setup or symbol/backend issue.\n";
            prompt << L"Return likely root causes first, then concrete remediation commands.\n";
            prompt << L"Consider PDB mismatch, missing private types, field drift, DbgEng local-kernel attach limits, missing callback symbols, backend mode, elevation, and symbol path.\n\n";
            prompt << L"Operator note:\n";
            prompt << JoinArgs(args, 2) << L"\n";
            request.Prompt = prompt.str();
            CompleteAndPrintAiRequest(L"ai_diagnose", request, ai, aiState);
        }
        else if (action == L"playbook")
        {
            HandleAiPlaybookCommand(args, state, dbgeng, device, service, symbols, ai, aiState);
        }
        else if (action == L"preview" || action == L"ask")
        {
            if (args.size() < 3)
            {
                std::wcerr << L"usage: ai " << action << L" <prompt>\n";
                break;
            }

            AiCompletionRequest request = {};
            request.System = BuildAiSystemPrompt(state, symbols);
            request.Prompt = JoinArgs(args, 2);

            if (action == L"preview")
            {
                std::wcout << ai.PreviewText(request);
                break;
            }

            std::wcout << L"ai request: provider=" << ai.ProviderName()
                       << L" model=" << ai.Settings().Model
                       << L" credential=" << ai.CredentialStatus() << L"\n";
            AiCompletionResponse response = {};
            std::wstring error;
            if (!ai.Complete(request, &response, &error))
            {
                std::wcerr << L"ai request failed: " << error << L"\n";
                WriteAiTranscriptEvent(aiState, L"ai_ask_failed", error, L"");
                break;
            }

            WriteAiTranscriptEvent(aiState, L"ai_ask", L"request completed", L"");
            if (!response.Text.empty())
            {
                std::wcout << response.Text;
                if (response.Text.back() != L'\n')
                {
                    std::wcout << L"\n";
                }
            }
        }
        else if (action == L"plan")
        {
            if (args.size() < 3)
            {
                std::wcerr << L"usage: ai plan <prompt>\n";
                break;
            }

            AiCompletionRequest request = {};
            request.System = BuildAiSystemPrompt(state, symbols);
            request.Prompt = BuildAiPlanPrompt(JoinArgs(args, 2));

            std::wcout << L"ai plan request: provider=" << ai.ProviderName()
                       << L" model=" << ai.Settings().Model
                       << L" credential=" << ai.CredentialStatus() << L"\n";

            AiCompletionResponse response = {};
            std::wstring error;
            if (!ai.Complete(request, &response, &error))
            {
                std::wcerr << L"ai plan failed: " << error << L"\n";
                WriteAiTranscriptEvent(aiState, L"ai_plan_failed", error, L"");
                break;
            }

            AiPlanState parsed = {};
            PreserveAiSessionSettings(parsed, aiState);
            if (!ParseAiPlanResponse(response.Text, &parsed, &error))
            {
                aiState.RawResponse = response.Text;
                std::wcerr << L"ai plan parse failed: " << error << L"\n";
                std::wcerr << L"raw response:\n" << response.Text << L"\n";
                WriteAiTranscriptEvent(aiState, L"ai_plan_parse_failed", error, L"");
                break;
            }

            aiState = parsed;
            WriteAiTranscriptEvent(aiState, L"ai_plan", L"plan loaded", L"");
            PrintAiPlan(aiState);
        }
        else
        {
            std::wcerr << L"unknown ai command. type ai help\n";
        }
    } while (false);
}

static bool HandleCommand(
    const std::vector<std::wstring>& args,
    const std::wstring& originalLine,
    DebuggerState& state,
    DbgEngBackend& dbgeng,
    DeviceClient& device,
    DriverService& service,
    SymbolEngine& symbols,
    AiProviderRuntime& ai,
    AiPlanState& aiState)
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
                       << L" dbgeng-ready=" << (dbgeng.IsReady() ? L"yes" : L"no")
                       << L" kd-mode=" << (state.DbgEngRemoteKernel ? L"remote" : L"local") << L"\n";
        }
        else if (command == L"kdinit")
        {
            state.DbgEngRemoteKernel = false;
            if (args.size() >= 2 && (ToLower(args[1]) == L"/remote" || ToLower(args[1]) == L"remote"))
            {
                if (args.size() < 3)
                {
                    std::wcerr << L"usage: kdinit /remote <connection-options>\n";
                    break;
                }

                state.DbgEngRemoteKernel = true;
                state.DbgEngConnectOptions = JoinArgs(args, 2);
            }
            else if (args.size() >= 2 && (ToLower(args[1]) == L"/local" || ToLower(args[1]) == L"local"))
            {
                state.DbgEngConnectOptions = args.size() >= 3 ? JoinArgs(args, 2) : L"";
            }
            else if (args.size() >= 2)
            {
                state.DbgEngConnectOptions = JoinArgs(args, 1);
            }
            else
            {
                state.DbgEngConnectOptions.clear();
            }

            if (dbgeng.IsReady())
            {
                dbgeng.Shutdown();
            }

            if (EnsureDbgEng(dbgeng, symbols, state, &error))
            {
                std::wcout << L"DbgEng " << (state.DbgEngRemoteKernel ? L"remote-kernel" : L"local-kernel") << L" backend ready\n";
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
        else if (command == L"probe")
        {
            HandleProbeCommand(args);
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
        else if (command == L"ai")
        {
            if (args.size() >= 2 && ToLower(args[1]) == L"run")
            {
                keepRunning = RunAiPlannedCommands(args, state, dbgeng, device, service, symbols, ai, aiState);
            }
            else
            {
                HandleAiCommand(args, state, dbgeng, device, service, symbols, ai, aiState);
            }
        }
        else if (state.Backend == DebuggerState::BackendMode::DbgEng &&
                 command != L"q" && command != L"qq" && command != L"qd" &&
                 command != L"quit" && command != L"exit" &&
                 command != L"unload" && command != L"drvstatus" &&
                 command != L"probe" &&
                 command != L"procctx" &&
                 command != L"callbacks" && command != L"kcallbacks" && command != L"cb" &&
                 command != L"ai")
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
        else if (command == L"procctx")
        {
            HandleProcessContextCommand(args, state, device, symbols);
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

                DriverSessionStatus session = {};
                if (device.IsOpen() && device.QuerySessionStatus(&session, &error))
                {
                    std::wcout << L"driver session: owner-pid=" << session.OwnerPid
                               << L" current-pid=" << session.CurrentPid
                               << L" handles=" << session.OpenHandleCount
                               << L" write=" << ((session.Flags & KNDBG_SESSION_FLAG_WRITE_ENABLED) != 0 ? L"on" : L"off")
                               << L"\n";
                }
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

static CommandExecutionResult ExecuteCommandWithTranscript(
    const std::vector<std::wstring>& args,
    const std::wstring& originalLine,
    const std::wstring& origin,
    DebuggerState& state,
    DbgEngBackend& dbgeng,
    DeviceClient& device,
    DriverService& service,
    SymbolEngine& symbols,
    AiProviderRuntime& ai,
    AiPlanState& aiState)
{
    CommandExecutionResult result = {};
    result.KeepRunning = true;
    std::wstring backendBefore = BackendModeText(state.Backend);
    bool writeLike = IsWriteLikeCommandLine(originalLine);
    std::wstring commandClass = ClassifyCommandLine(originalLine, writeLike);

    do
    {
        ScopedWideStreamCapture capture(&result.Output, &result.Error);
        result.KeepRunning = HandleCommand(args, originalLine, state, dbgeng, device, service, symbols, ai, aiState);

        WriteCommandTranscriptEvent(
            aiState,
            origin,
            backendBefore,
            commandClass,
            writeLike,
            originalLine,
            result);
        if (writeLike)
        {
            WriteCommandAuditEvent(
                aiState,
                origin,
                backendBefore,
                commandClass,
                originalLine,
                result);
        }
    } while (false);

    return result;
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
        AiProviderRuntime ai;
        AiPlanState aiState = {};
        std::wstring loadedDotEnv;
        std::wstring dotEnvError;
        ai.LoadDotEnvFiles(BuildDotEnvSearchPaths(exeDir), &loadedDotEnv, &dotEnvError);

        std::wcout << L"KnLiveDbg ready. backend=auto. type help or help all\n";
        if (!loadedDotEnv.empty())
        {
            std::wcout << L"AI config: loaded " << loadedDotEnv << L"\n";
        }

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

            CommandExecutionResult commandResult = ExecuteCommandWithTranscript(
                args,
                line,
                L"operator",
                state,
                dbgeng,
                device,
                service,
                symbols,
                ai,
                aiState);
            if (!commandResult.KeepRunning)
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
