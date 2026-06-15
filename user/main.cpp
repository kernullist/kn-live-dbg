#include "AddressInspector.h"
#include "AiProvider.h"
#include "AlpcScanner.h"
#include "ByovdScanner.h"
#include "CallbackScanner.h"
#include "CommandRegistry.h"
#include "DbgEngBackend.h"
#include "DeviceClient.h"
#include "DriverService.h"
#include "EtwScanner.h"
#include "FirmwareTableScanner.h"
#include "IntegrityScanner.h"
#include "MemoryDumper.h"
#include "NativeDisassembler.h"
#include "PoolPeHunter.h"
#include "ProcessTriageScanner.h"
#include "SnapshotCollector.h"
#include "SnapshotDiff.h"
#include "SnapshotJson.h"
#include "SnapshotPrinter.h"
#include "ThreatIntelSubscriber.h"
#include "NmiScanner.h"
#include "MsrScanner.h"
#include "CrScanner.h"
#include "SsdtScanner.h"
#include "IdtScanner.h"
#include "PoolScanner.h"
#include "SymbolEngine.h"
#include "VbsScanner.h"
#include "WfpScanner.h"
#include "WfpCalloutScanner.h"
#include "WnfScanner.h"

#include "../shared/KnLiveDbgIoctl.h"
#include "../shared/KnLiveDbgProbeIoctl.h"

#include <Windows.h>
#include <conio.h>
#include <shellapi.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cwctype>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

static std::atomic_bool g_StopRequested = false;
static HANDLE g_MainThreadHandle = nullptr;
static HANDLE g_InstanceMutexHandle = nullptr;

// Set by the !ti handler while a subscription is active. The console control
// handler reads this on hard-exit paths (window close / logoff / system
// shutdown) and calls Stop() synchronously so the kernel ETW session never
// leaks; the normal exit path (return from wmain) is already covered by the
// singleton's destructor.
class TiSubscriber;
static std::atomic<TiSubscriber*> g_TiSubscriberForShutdown{nullptr};
static bool g_InstanceMutexOwned = false;
static std::recursive_mutex g_ConsoleOutputMutex;
static std::atomic_uint64_t g_CommandStreamOutputSerial = 0;

static constexpr WORD KNDBG_COLOR_TEXT = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
static constexpr WORD KNDBG_COLOR_DIM = FOREGROUND_BLUE | FOREGROUND_GREEN;
static constexpr WORD KNDBG_COLOR_FRAME = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
static constexpr WORD KNDBG_COLOR_TITLE = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
static constexpr WORD KNDBG_COLOR_ACCENT = FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
static constexpr WORD KNDBG_COLOR_STEP = FOREGROUND_BLUE | FOREGROUND_INTENSITY;
static constexpr WORD KNDBG_COLOR_OK = FOREGROUND_GREEN | FOREGROUND_INTENSITY;
static constexpr WORD KNDBG_COLOR_WARN = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY;
static constexpr WORD KNDBG_COLOR_FAIL = FOREGROUND_RED | FOREGROUND_INTENSITY;
static constexpr WORD KNDBG_COLOR_PROMPT = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY;

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

static std::wstring FormatHResultError(const wchar_t* prefix, HRESULT hr)
{
    std::wstringstream stream;

    stream << prefix << L": 0x" << std::hex << std::setw(8) << std::setfill(L'0')
           << static_cast<uint32_t>(hr) << std::dec;
    return stream.str();
}

class ScopedConsoleColor
{
public:
    ScopedConsoleColor(HANDLE handle, WORD foreground) :
        handle_(handle),
        lock_(g_ConsoleOutputMutex),
        oldAttributes_(0),
        active_(false)
    {
        CONSOLE_SCREEN_BUFFER_INFO info = {};

        do
        {
            if (handle_ == nullptr || handle_ == INVALID_HANDLE_VALUE)
            {
                break;
            }

            if (!GetConsoleScreenBufferInfo(handle_, &info))
            {
                break;
            }

            oldAttributes_ = info.wAttributes;
            WORD preserved = static_cast<WORD>(info.wAttributes & 0xfff0);
            WORD attributes = static_cast<WORD>(preserved | foreground);
            if (!SetConsoleTextAttribute(handle_, attributes))
            {
                break;
            }

            active_ = true;
        } while (false);
    }

    ~ScopedConsoleColor()
    {
        if (active_)
        {
            SetConsoleTextAttribute(handle_, oldAttributes_);
        }
    }

private:
    HANDLE handle_;
    std::unique_lock<std::recursive_mutex> lock_;
    WORD oldAttributes_;
    bool active_;
};

static void PrintColoredText(const std::wstring& text, WORD color)
{
    ScopedConsoleColor scopedColor(GetStdHandle(STD_OUTPUT_HANDLE), color);
    std::wcout << text;
}

static void PrintColoredText(const wchar_t* text, WORD color)
{
    if (text != nullptr)
    {
        PrintColoredText(std::wstring(text), color);
    }
}

static void PrintCommandRegistryColoredText(const std::wstring& text, CommandRegistryColor color)
{
    PrintColoredText(text, static_cast<WORD>(color));
}

static std::wstring GetExecutableDirectory();

// -------- Output logging: tee stdout to a file --------------------------
//
// "log enable" intercepts std::wcout by swapping in a wstreambuf that
// forwards every wide character to both the original console buffer
// and a UTF-8 log file. The mechanism preserves console coloring
// because PrintColoredText only manipulates CONSOLE_SCREEN_BUFFER
// attributes; the actual character stream still flows through
// std::wcout. ANSI escape sequences are never produced, so the log
// file is clean text.
//
// "log disable" restores the original wstreambuf and closes the file.
// The wmain shutdown path also calls Disable() to flush and close
// gracefully on quit/exit.
// TeeStreambuf is permanently installed as std::wcout.rdbuf() at wmain
// startup. Its file sink starts null; "log enable" attaches a file
// sink at runtime and "log disable" detaches it. The buffer must stay
// installed across ScopedWideStreamCapture lifetimes because the
// capture's destructor restores whatever rdbuf was present when it
// entered -- if that was the tee, the chain survives; if it was a
// raw console buf, the tee falls out of the chain and the file sink
// stops receiving anything after the first enable call.
class TeeStreambuf : public std::wstreambuf
{
public:
    explicit TeeStreambuf(std::wstreambuf* console) :
        console_(console),
        file_(nullptr)
    {
    }

    void SetFile(std::ofstream* file)
    {
        std::lock_guard<std::mutex> guard(file_lock_);
        file_ = file;
    }

    bool HasFile()
    {
        std::lock_guard<std::mutex> guard(file_lock_);
        return file_ != nullptr;
    }

protected:
    int_type overflow(int_type c) override
    {
        if (c == traits_type::eof())
        {
            return traits_type::not_eof(c);
        }

        wchar_t wc = static_cast<wchar_t>(c);

        if (console_ != nullptr)
        {
            (void)console_->sputc(wc);
        }

        std::lock_guard<std::mutex> guard(file_lock_);
        if (file_ != nullptr && file_->good())
        {
            char buf[8] = {};
            int len = WideCharToMultiByte(
                CP_UTF8, 0,
                &wc, 1,
                buf, static_cast<int>(sizeof(buf)),
                nullptr, nullptr);
            if (len > 0)
            {
                file_->write(buf, len);
            }
        }

        return c;
    }

    std::streamsize xsputn(const wchar_t* text, std::streamsize count) override
    {
        if (text == nullptr || count <= 0)
        {
            return 0;
        }

        if (console_ != nullptr)
        {
            console_->sputn(text, count);
        }

        std::lock_guard<std::mutex> guard(file_lock_);
        if (file_ != nullptr && file_->good())
        {
            // WideCharToMultiByte takes int; cap chunk size to INT_MAX
            // so a hypothetical INT_MAX+ streamsize cannot wrap into a
            // negative cchWideChar. In practice wcout never delivers a
            // run that large, but the cast is otherwise undefined.
            const std::streamsize kIntMax = std::numeric_limits<int>::max();
            std::streamsize remaining = count;
            const wchar_t* cursor = text;
            while (remaining > 0 && file_->good())
            {
                const int chunk = static_cast<int>(
                    remaining < kIntMax ? remaining : kIntMax);

                constexpr int kStackBytes = 1024;
                char stackBuf[kStackBytes];
                char* out = stackBuf;
                std::vector<char> heap;
                int needed = WideCharToMultiByte(
                    CP_UTF8, 0,
                    cursor, chunk,
                    nullptr, 0,
                    nullptr, nullptr);
                if (needed <= 0)
                {
                    break;
                }
                if (needed > kStackBytes)
                {
                    heap.resize(static_cast<size_t>(needed));
                    out = heap.data();
                }
                int written = WideCharToMultiByte(
                    CP_UTF8, 0,
                    cursor, chunk,
                    out, needed,
                    nullptr, nullptr);
                if (written > 0)
                {
                    file_->write(out, written);
                }

                cursor += chunk;
                remaining -= chunk;
            }
        }

        return count;
    }

    int sync() override
    {
        int rc = 0;
        if (console_ != nullptr && console_->pubsync() != 0)
        {
            rc = -1;
        }
        std::lock_guard<std::mutex> guard(file_lock_);
        if (file_ != nullptr)
        {
            file_->flush();
        }
        return rc;
    }

private:
    std::wstreambuf* console_;
    std::ofstream*   file_;
    std::mutex       file_lock_;
};

struct OutputLogState
{
    std::ofstream                 File;
    std::unique_ptr<TeeStreambuf>  Tee;
    std::wstreambuf*              OriginalCoutBuf = nullptr;
    std::wstring                  Path;
    bool                          TeeInstalled = false;
    bool                          Active = false;
    std::mutex                    Lock;
};

static OutputLogState g_OutputLog;

// Install the permanent tee buffer in front of std::wcout. Called
// once at wmain startup -- BEFORE any ScopedWideStreamCapture so
// that captures see the tee as their bottom-of-chain rdbuf and
// restore to the tee at destructor time.
static void InstallOutputTee()
{
    std::lock_guard<std::mutex> guard(g_OutputLog.Lock);
    if (g_OutputLog.TeeInstalled)
    {
        return;
    }
    g_OutputLog.OriginalCoutBuf = std::wcout.rdbuf();
    g_OutputLog.Tee.reset(new TeeStreambuf(g_OutputLog.OriginalCoutBuf));
    std::wcout.rdbuf(g_OutputLog.Tee.get());
    g_OutputLog.TeeInstalled = true;
}

static void UninstallOutputTee()
{
    std::lock_guard<std::mutex> guard(g_OutputLog.Lock);
    if (!g_OutputLog.TeeInstalled)
    {
        return;
    }
    std::wcout.flush();
    std::wcout.rdbuf(g_OutputLog.OriginalCoutBuf);
    g_OutputLog.OriginalCoutBuf = nullptr;
    g_OutputLog.Tee.reset();
    g_OutputLog.TeeInstalled = false;
}

static std::wstring BuildLogFileName()
{
    // KnLiveDbg-YYYYMMDD-HHMMSS.log -- collation-friendly and unique
    // per second. The user can launch multiple sessions and they
    // will not collide unless the same second is hit twice.
    SYSTEMTIME st = {};
    GetLocalTime(&st);

    std::wstringstream ss;
    ss << L"KnLiveDbg-"
       << std::setw(4) << std::setfill(L'0') << st.wYear
       << std::setw(2) << std::setfill(L'0') << st.wMonth
       << std::setw(2) << std::setfill(L'0') << st.wDay
       << L"-"
       << std::setw(2) << std::setfill(L'0') << st.wHour
       << std::setw(2) << std::setfill(L'0') << st.wMinute
       << std::setw(2) << std::setfill(L'0') << st.wSecond
       << L".log";
    return ss.str();
}

static bool EnableOutputLog(std::wstring* outPath, std::wstring* outError)
{
    // Tee install happens in wmain. Here we only open the file sink
    // and attach it to the already-installed tee. That way no rdbuf
    // swap happens inside ScopedWideStreamCapture and the chain
    // survives across capture lifetimes.
    if (!g_OutputLog.TeeInstalled)
    {
        if (outError != nullptr)
        {
            *outError = L"tee buffer not installed";
        }
        return false;
    }

    std::unique_lock<std::mutex> guard(g_OutputLog.Lock);

    if (g_OutputLog.Active)
    {
        if (outPath != nullptr)
        {
            *outPath = g_OutputLog.Path;
        }
        if (outError != nullptr)
        {
            *outError = L"log already enabled";
        }
        return false;
    }

    std::wstring exeDir = GetExecutableDirectory();
    if (exeDir.empty())
    {
        if (outError != nullptr)
        {
            *outError = L"failed to resolve executable directory";
        }
        return false;
    }

    std::wstring path = exeDir + L"\\" + BuildLogFileName();

    std::string narrowPath;
    {
        int needed = WideCharToMultiByte(CP_UTF8, 0, path.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (needed > 0)
        {
            narrowPath.resize(static_cast<size_t>(needed - 1));
            WideCharToMultiByte(CP_UTF8, 0, path.c_str(), -1,
                                narrowPath.data(), needed, nullptr, nullptr);
        }
    }

    g_OutputLog.File.open(narrowPath, std::ios::out | std::ios::binary | std::ios::trunc);
    if (!g_OutputLog.File.is_open())
    {
        if (outError != nullptr)
        {
            *outError = L"failed to open log file";
        }
        return false;
    }

    const unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
    g_OutputLog.File.write(reinterpret_cast<const char*>(bom), sizeof(bom));

    g_OutputLog.Path = path;
    g_OutputLog.Active = true;

    // Attach the file sink to the tee. SetFile takes its own internal
    // lock; nothing in the tee path needs g_OutputLog.Lock.
    TeeStreambuf* tee = g_OutputLog.Tee.get();
    guard.unlock();
    tee->SetFile(&g_OutputLog.File);

    if (outPath != nullptr)
    {
        *outPath = path;
    }
    return true;
}

static bool DisableOutputLog(std::wstring* outPath)
{
    if (!g_OutputLog.TeeInstalled)
    {
        return false;
    }

    std::unique_lock<std::mutex> guard(g_OutputLog.Lock);

    if (!g_OutputLog.Active)
    {
        return false;
    }

    // Detach the file sink before any flush/close so concurrent writes
    // through the tee cannot race against the close.
    TeeStreambuf* tee = g_OutputLog.Tee.get();
    guard.unlock();
    std::wcout.flush();
    tee->SetFile(nullptr);

    guard.lock();
    g_OutputLog.File.flush();
    g_OutputLog.File.close();

    if (outPath != nullptr)
    {
        *outPath = g_OutputLog.Path;
    }
    g_OutputLog.Path.clear();
    g_OutputLog.Active = false;
    return true;
}

static void HandleLogCommand(const std::vector<std::wstring>& args)
{
    std::wstring sub = (args.size() > 1) ? args[1] : L"status";
    std::transform(sub.begin(), sub.end(), sub.begin(),
                   [](wchar_t c) { return static_cast<wchar_t>(std::towlower(c)); });

    if (sub == L"enable" || sub == L"on" || sub == L"start")
    {
        std::wstring path;
        std::wstring error;
        if (EnableOutputLog(&path, &error))
        {
            std::wcout << L"log enabled: " << path << L"\n";
        }
        else
        {
            std::wcout << L"log enable failed: " << error;
            if (!path.empty())
            {
                std::wcout << L" (current=" << path << L")";
            }
            std::wcout << L"\n";
        }
    }
    else if (sub == L"disable" || sub == L"off" || sub == L"stop")
    {
        std::wstring path;
        if (DisableOutputLog(&path))
        {
            std::wcout << L"log disabled: " << path << L"\n";
        }
        else
        {
            std::wcout << L"log disabled: (was not active)\n";
        }
    }
    else if (sub == L"status" || sub == L"?" || sub == L"help")
    {
        std::lock_guard<std::mutex> guard(g_OutputLog.Lock);
        if (g_OutputLog.Active)
        {
            std::wcout << L"log status: active path=" << g_OutputLog.Path << L"\n";
        }
        else
        {
            std::wcout << L"log status: inactive\n";
        }
        std::wcout << L"usage: log [enable|disable|status]\n";
        std::wcout << L"  enable  start mirroring all console output to a new log file in the EXE directory\n";
        std::wcout << L"  disable stop logging and close the current file\n";
        std::wcout << L"  status  show current logging state (default)\n";
    }
    else
    {
        std::wcout << L"unknown log subcommand: " << sub << L"\n";
        std::wcout << L"usage: log [enable|disable|status]\n";
    }
}

struct DebuggerState
{
    uint32_t NumberBase;
    bool Quiet;
    bool MainDriverCleanupRequested;
    bool MainDriverUnloaded;
    bool ProbeDriverCleanupRequested;
    bool ProbeDriverUnloaded;
    bool ByovdFixtureCleanupRequested;
    bool ByovdFixtureUnloaded;
    std::vector<std::wstring> CommandHistory;
    std::wstring DbgEngConnectOptions;
    bool DbgEngRemoteKernel;
    uint64_t LastDisassemblyAddress;
    bool HasLastDisassemblyAddress;
    bool HasKernelProcessContext;
    ProcessAddressContext KernelProcessContext;
    bool HasProcessContext;
    ProcessAddressContext ProcessContext;
    bool HasSnapshotBaseline;
    SnapshotDocument SnapshotBaseline;
    std::wstring SnapshotBaselineJsonPath;
    std::wstring SnapshotBaselineReportPath;
    enum class BackendMode
    {
        Auto,
        Native,
        DbgEng
    } Backend;
};

static constexpr uint32_t KNDBG_SYSTEM_PROCESS_ID = 4;
static constexpr const wchar_t* KNDBG_BYOVD_FIXTURE_SERVICE_NAME = L"KnLiveDbgByovdFixture";
static constexpr const wchar_t* KNDBG_BYOVD_FIXTURE_DISPLAY_NAME = L"KnLiveDbg BYOVD Positive-Control Fixture";
static constexpr const wchar_t* KNDBG_BYOVD_FIXTURE_IMAGE_NAME = L"amdryzenmasterdriver.sys";
static constexpr uint64_t KNDBG_X64_PTE_PRESENT = 0x1ull;
static constexpr uint64_t KNDBG_X64_PTE_WRITE = 0x2ull;
static constexpr uint64_t KNDBG_X64_PTE_LARGE_PAGE = 0x80ull;
static constexpr uint64_t KNDBG_X64_PTE_4K_BASE_MASK = 0x000ffffffffff000ull;
static constexpr uint64_t KNDBG_X64_PTE_2MB_BASE_MASK = 0x000fffffffe00000ull;
static constexpr uint64_t KNDBG_X64_PTE_1GB_BASE_MASK = 0x000fffffc0000000ull;
static constexpr uint64_t KNDBG_X64_4K_PAGE_SIZE = 0x1000ull;
static constexpr uint64_t KNDBG_X64_2MB_PAGE_SIZE = 0x200000ull;
static constexpr uint64_t KNDBG_X64_1GB_PAGE_SIZE = 0x40000000ull;

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

static BOOL WINAPI ConsoleHandler(DWORD controlType)
{
    BOOL handled = FALSE;

    switch (controlType)
    {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
        // Polite interrupt: let the main loop notice the flag and tear down
        // through normal paths (which includes the TiSubscriber destructor).
        g_StopRequested = true;
        if (g_MainThreadHandle != nullptr)
        {
            CancelSynchronousIo(g_MainThreadHandle);
        }
        handled = TRUE;
        break;
    case CTRL_CLOSE_EVENT:
    case CTRL_LOGOFF_EVENT:
    case CTRL_SHUTDOWN_EVENT:
    {
        // Hard exit: Windows will terminate the process shortly after we
        // return. Static destructors typically do NOT run on these paths,
        // which means the ETW session and provider registration would leak
        // until reboot. We synchronously tear down the TI subscription
        // first; the call is bounded by IOCTL latencies and well under
        // the OS-imposed handler budget (5 s for CTRL_CLOSE_EVENT, 20 s
        // for CTRL_LOGOFF/SHUTDOWN_EVENT by default).
        TiSubscriber* sub = g_TiSubscriberForShutdown.load();
        if (sub != nullptr)
        {
            std::wstring stopError;
            sub->Stop(&stopError);
            g_TiSubscriberForShutdown.store(nullptr);
        }
        g_StopRequested = true;
        if (g_MainThreadHandle != nullptr)
        {
            CancelSynchronousIo(g_MainThreadHandle);
        }
        handled = TRUE;
        break;
    }
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

static void AddCommandHistory(DebuggerState* state, const std::wstring& line)
{
    static constexpr size_t kCommandHistoryLimit = 256;

    do
    {
        if (state == nullptr || TrimWhitespace(line).empty())
        {
            break;
        }

        if (!state->CommandHistory.empty() && state->CommandHistory.back() == line)
        {
            break;
        }

        state->CommandHistory.push_back(line);
        while (state->CommandHistory.size() > kCommandHistoryLimit)
        {
            state->CommandHistory.erase(state->CommandHistory.begin());
        }
    } while (false);
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

static bool FileExists(const std::wstring& path)
{
    bool exists = false;

    do
    {
        if (path.empty())
        {
            break;
        }

        DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES)
        {
            break;
        }

        if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
        {
            break;
        }

        exists = true;
    } while (false);

    return exists;
}

static bool EnsureSymsrvConsentFile(const std::wstring& exeDir, std::wstring* status, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (status != nullptr)
        {
            status->clear();
        }

        if (exeDir.empty())
        {
            if (error != nullptr)
            {
                *error = L"executable directory is empty";
            }
            break;
        }

        std::wstring symsrvPath = exeDir + L"\\symsrv.dll";
        if (!FileExists(symsrvPath))
        {
            if (status != nullptr)
            {
                *status = L"symsrv.dll not staged";
            }
            ok = true;
            break;
        }

        std::wstring consentPath = exeDir + L"\\symsrv.yes";
        if (FileExists(consentPath))
        {
            if (status != nullptr)
            {
                *status = L"symsrv.yes present";
            }
            ok = true;
            break;
        }

        HANDLE file = CreateFileW(
            consentPath.c_str(),
            GENERIC_WRITE,
            0,
            nullptr,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            DWORD lastError = GetLastError();
            if (lastError == ERROR_FILE_EXISTS)
            {
                if (status != nullptr)
                {
                    *status = L"symsrv.yes present";
                }
                ok = true;
                break;
            }

            if (error != nullptr)
            {
                *error = FormatWin32Error(L"CreateFileW symsrv.yes failed", lastError);
            }
            break;
        }

        BYTE marker = 0x20;
        DWORD written = 0;
        BOOL writeOk = WriteFile(file, &marker, sizeof(marker), &written, nullptr);
        DWORD writeError = writeOk ? ERROR_SUCCESS : GetLastError();
        CloseHandle(file);

        if (!writeOk || written != sizeof(marker))
        {
            DeleteFileW(consentPath.c_str());
            if (error != nullptr)
            {
                *error = writeOk ? L"WriteFile symsrv.yes wrote an unexpected byte count" :
                    FormatWin32Error(L"WriteFile symsrv.yes failed", writeError);
            }
            break;
        }

        if (status != nullptr)
        {
            *status = L"symsrv.yes created";
        }
        ok = true;
    } while (false);

    return ok;
}

typedef HRESULT (STDAPICALLTYPE* DllRegisterServerPtr)();

static bool RegisterDiaDll(const std::wstring& path, std::wstring* error)
{
    bool ok = false;
    HMODULE module = nullptr;

    do
    {
        module = LoadLibraryW(path.c_str());
        if (module == nullptr)
        {
            if (error != nullptr)
            {
                *error = FormatWin32Error(L"LoadLibraryW DIA failed", GetLastError());
            }
            break;
        }

        FARPROC proc = GetProcAddress(module, "DllRegisterServer");
        if (proc == nullptr)
        {
            if (error != nullptr)
            {
                *error = FormatWin32Error(L"GetProcAddress DllRegisterServer failed", GetLastError());
            }
            break;
        }

        auto registerServer = reinterpret_cast<DllRegisterServerPtr>(proc);
        HRESULT hr = registerServer();
        if (FAILED(hr))
        {
            if (error != nullptr)
            {
                *error = FormatHResultError(L"DllRegisterServer DIA failed", hr);
            }
            break;
        }

        ok = true;
    } while (false);

    if (module != nullptr)
    {
        FreeLibrary(module);
    }

    return ok;
}

static bool EnsureDiaRegistration(const std::wstring& exeDir, std::wstring* status, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (status != nullptr)
        {
            status->clear();
        }

        if (exeDir.empty())
        {
            if (error != nullptr)
            {
                *error = L"executable directory is empty";
            }
            break;
        }

        const std::wstring candidates[] =
        {
            exeDir + L"\\msdia140.dll",
            exeDir + L"\\msdia150.dll"
        };

        std::wstring selected;
        for (const std::wstring& candidate : candidates)
        {
            if (FileExists(candidate))
            {
                selected = candidate;
                break;
            }
        }

        if (selected.empty())
        {
            if (status != nullptr)
            {
                *status = L"msdia dll not staged";
            }
            ok = true;
            break;
        }

        std::wstring localError;
        if (!RegisterDiaDll(selected, &localError))
        {
            if (error != nullptr)
            {
                *error = selected + L": " + localError;
            }
            break;
        }

        if (status != nullptr)
        {
            size_t slash = selected.find_last_of(L"\\/");
            *status = L"registered " + (slash == std::wstring::npos ? selected : selected.substr(slash + 1));
        }
        ok = true;
    } while (false);

    return ok;
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

static std::vector<std::wstring> BuildDotEnvSearchPaths(const std::wstring& exeDir)
{
    std::vector<std::wstring> paths;

    if (!exeDir.empty())
    {
        AddUniquePath(paths, exeDir + L"\\.env");
    }

    return paths;
}

typedef struct _SYMBOL_DIRECTORY_SCAN_ITEM
{
    std::wstring Path;
    ULONG Depth;
} SYMBOL_DIRECTORY_SCAN_ITEM;

typedef struct _STARTUP_SYMBOL_PATH_INFO
{
    std::wstring Path;
    std::wstring SymbolCachePath;
    std::wstring SymbolCacheError;
    size_t LocalDirectoryCount;
    bool SymbolCacheReady;
    bool Truncated;
} STARTUP_SYMBOL_PATH_INFO;

static const wchar_t* KNDBG_MICROSOFT_SYMBOL_SERVER = L"https://msdl.microsoft.com/download/symbols";

static void AddUniqueSymbolPathEntry(std::vector<std::wstring>& entries, const std::wstring& entry)
{
    do
    {
        std::wstring trimmed = TrimWhitespace(entry);
        if (trimmed.empty())
        {
            break;
        }

        std::wstring lowered = ToLower(trimmed);
        for (const std::wstring& existing : entries)
        {
            if (ToLower(existing) == lowered)
            {
                return;
            }
        }

        entries.push_back(trimmed);
    } while (false);
}

static std::vector<std::wstring> SplitSymbolPathEntries(const std::wstring& symbolPath)
{
    std::vector<std::wstring> entries;
    size_t first = 0;

    while (first <= symbolPath.size())
    {
        size_t next = symbolPath.find(L';', first);
        std::wstring entry = symbolPath.substr(
            first,
            next == std::wstring::npos ? std::wstring::npos : next - first);
        AddUniqueSymbolPathEntry(entries, entry);

        if (next == std::wstring::npos)
        {
            break;
        }

        first = next + 1;
    }

    return entries;
}

static std::wstring JoinSymbolPathEntries(const std::vector<std::wstring>& entries)
{
    std::wstring result;

    for (const std::wstring& entry : entries)
    {
        if (entry.empty())
        {
            continue;
        }

        if (!result.empty())
        {
            result += L";";
        }

        result += entry;
    }

    return result;
}

static bool IsSkippableDirectoryName(const std::wstring& name)
{
    return name == L"." || name == L"..";
}

static std::wstring TrimTrailingSlashes(const std::wstring& value)
{
    std::wstring result = value;

    while (!result.empty() && (result.back() == L'\\' || result.back() == L'/'))
    {
        result.pop_back();
    }

    return result;
}

static bool PathIsSameOrBelow(const std::wstring& path, const std::wstring& root)
{
    bool matches = false;

    do
    {
        if (path.empty() || root.empty())
        {
            break;
        }

        std::wstring normalizedPath = ToLower(TrimTrailingSlashes(GetFullPathString(path)));
        std::wstring normalizedRoot = ToLower(TrimTrailingSlashes(GetFullPathString(root)));
        if (normalizedPath.empty() || normalizedRoot.empty())
        {
            break;
        }

        if (normalizedPath == normalizedRoot)
        {
            matches = true;
            break;
        }

        if (normalizedPath.size() > normalizedRoot.size() &&
            normalizedPath.rfind(normalizedRoot, 0) == 0 &&
            (normalizedPath[normalizedRoot.size()] == L'\\' || normalizedPath[normalizedRoot.size()] == L'/'))
        {
            matches = true;
            break;
        }
    } while (false);

    return matches;
}

static bool EnsureDirectoryExists(const std::wstring& path, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (path.empty())
        {
            if (error != nullptr)
            {
                *error = L"directory path is empty";
            }
            break;
        }

        DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES)
        {
            if ((attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                ok = true;
            }
            else if (error != nullptr)
            {
                *error = L"path exists but is not a directory: " + path;
            }
            break;
        }

        if (!CreateDirectoryW(path.c_str(), nullptr))
        {
            DWORD lastError = GetLastError();
            if (lastError == ERROR_ALREADY_EXISTS)
            {
                attributes = GetFileAttributesW(path.c_str());
                if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
                {
                    ok = true;
                    break;
                }
            }

            if (error != nullptr)
            {
                *error = FormatWin32Error(L"CreateDirectoryW failed", lastError);
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static std::wstring BuildExeSymbolCachePath(const std::wstring& exeDir)
{
    std::wstring result;

    do
    {
        if (exeDir.empty())
        {
            break;
        }

        result = GetFullPathString(exeDir + L"\\symbols");
    } while (false);

    return result;
}

static std::wstring BuildMicrosoftSymbolServerEntry(const std::wstring& cachePath)
{
    std::wstring entry;

    do
    {
        if (cachePath.empty())
        {
            break;
        }

        entry = L"SRV*" + cachePath + L"*" + KNDBG_MICROSOFT_SYMBOL_SERVER;
    } while (false);

    return entry;
}

static bool IsMicrosoftSymbolServerEntry(const std::wstring& entry)
{
    return ToLower(entry).find(ToLower(KNDBG_MICROSOFT_SYMBOL_SERVER)) != std::wstring::npos;
}

static void AddExecutableSymbolDirectories(
    std::vector<std::wstring>& entries,
    const std::wstring& exeDir,
    const std::wstring& excludedRoot,
    size_t maxDirectories,
    ULONG maxDepth,
    size_t* localDirectoryCount,
    bool* truncated)
{
    do
    {
        if (localDirectoryCount != nullptr)
        {
            *localDirectoryCount = 0;
        }

        if (truncated != nullptr)
        {
            *truncated = false;
        }

        if (exeDir.empty() || maxDirectories == 0)
        {
            break;
        }

        std::vector<SYMBOL_DIRECTORY_SCAN_ITEM> pending;
        std::vector<std::wstring> localDirectories;

        AddUniquePath(localDirectories, exeDir);

        SYMBOL_DIRECTORY_SCAN_ITEM rootItem = {};
        rootItem.Path = GetFullPathString(exeDir);
        rootItem.Depth = 0;
        pending.push_back(rootItem);

        size_t scanIndex = 0;
        while (scanIndex < pending.size())
        {
            SYMBOL_DIRECTORY_SCAN_ITEM item = pending[scanIndex];
            ++scanIndex;

            if (item.Depth >= maxDepth)
            {
                continue;
            }

            std::wstring search = item.Path + L"\\*";
            WIN32_FIND_DATAW findData = {};
            HANDLE find = FindFirstFileW(search.c_str(), &findData);
            if (find == INVALID_HANDLE_VALUE)
            {
                continue;
            }

            do
            {
                std::wstring name = findData.cFileName;
                if (IsSkippableDirectoryName(name))
                {
                    continue;
                }

                if ((findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0)
                {
                    continue;
                }

                if ((findData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                {
                    continue;
                }

                if (localDirectories.size() >= maxDirectories)
                {
                    if (truncated != nullptr)
                    {
                        *truncated = true;
                    }
                    break;
                }

                std::wstring child = item.Path + L"\\" + name;
                if (PathIsSameOrBelow(child, excludedRoot))
                {
                    continue;
                }

                AddUniquePath(localDirectories, child);

                SYMBOL_DIRECTORY_SCAN_ITEM childItem = {};
                childItem.Path = GetFullPathString(child);
                childItem.Depth = item.Depth + 1;
                pending.push_back(childItem);
            } while (FindNextFileW(find, &findData));

            FindClose(find);

            if (truncated != nullptr && *truncated)
            {
                break;
            }
        }

        for (const std::wstring& directory : localDirectories)
        {
            AddUniqueSymbolPathEntry(entries, directory);
        }

        if (localDirectoryCount != nullptr)
        {
            *localDirectoryCount = localDirectories.size();
        }
    } while (false);
}

static STARTUP_SYMBOL_PATH_INFO BuildStartupSymbolPath(const std::wstring& baseSymbolPath, const std::wstring& exeDir)
{
    STARTUP_SYMBOL_PATH_INFO info = {};
    std::vector<std::wstring> entries;

    info.SymbolCachePath = BuildExeSymbolCachePath(exeDir);
    if (!info.SymbolCachePath.empty())
    {
        info.SymbolCacheReady = EnsureDirectoryExists(info.SymbolCachePath, &info.SymbolCacheError);
    }

    AddExecutableSymbolDirectories(entries, exeDir, info.SymbolCachePath, 128, 6, &info.LocalDirectoryCount, &info.Truncated);

    std::wstring microsoftSymbolServer = BuildMicrosoftSymbolServerEntry(info.SymbolCachePath);
    if (!microsoftSymbolServer.empty())
    {
        AddUniqueSymbolPathEntry(entries, microsoftSymbolServer);
    }

    std::vector<std::wstring> baseEntries = SplitSymbolPathEntries(baseSymbolPath);
    for (const std::wstring& entry : baseEntries)
    {
        if (IsMicrosoftSymbolServerEntry(entry))
        {
            continue;
        }

        AddUniqueSymbolPathEntry(entries, entry);
    }

    info.Path = JoinSymbolPathEntries(entries);
    return info;
}

static std::vector<std::wstring> Split(const std::wstring& line)
{
    // Whitespace-delimited tokenizer with double-quote support. We only
    // recognise '"' as a quote character, matching CMD/PowerShell convention
    // -- this keeps unquoted paths containing apostrophes (e.g. C:\Users\O'
    // Brien\foo.bin) intact rather than swallowing everything from the
    // apostrophe onward. Quotes can begin and end mid-token, so the input
    // --path="C:\Program Files\foo" yields a single token
    // --path=C:\Program Files\foo. A token may mix quoted and unquoted
    // segments; the quoting only affects whether interior whitespace is
    // preserved.
    std::vector<std::wstring> parts;
    const size_t length = line.size();
    size_t i = 0;

    while (i < length)
    {
        while (i < length && std::iswspace(line[i]) != 0)
        {
            ++i;
        }

        if (i >= length)
        {
            break;
        }

        std::wstring token;
        bool tokenStarted = false;

        while (i < length)
        {
            wchar_t ch = line[i];

            if (std::iswspace(ch) != 0)
            {
                break;
            }

            if (ch == L'"')
            {
                ++i;
                while (i < length && line[i] != L'"')
                {
                    token.push_back(line[i]);
                    ++i;
                }
                if (i < length)
                {
                    ++i;
                }
                tokenStarted = true;
                continue;
            }

            token.push_back(ch);
            ++i;
            tokenStarted = true;
        }

        if (tokenStarted)
        {
            parts.push_back(token);
        }
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

static bool IsHelpToken(const std::wstring& value)
{
    std::wstring token = ToLower(value);
    return token == L"help" || token == L"?" || token == L"/?" || token == L"-?";
}

static bool HasHelpToken(const std::vector<std::wstring>& args, size_t first)
{
    bool found = false;

    for (size_t index = first; index < args.size(); ++index)
    {
        if (IsHelpToken(args[index]))
        {
            found = true;
            break;
        }
    }

    return found;
}

static void PrintHelp(bool includeDbgEng)
{
    PrintColoredText(L"KnLiveDbg command help", KNDBG_COLOR_TITLE);
    std::wcout << L"\n";
    std::wcout << L"  WinDbg-compatible live-kernel console with native memory IOCTLs, symbols, scanners, and optional DbgEng routing.\n";
    std::wcout << L"  Press Tab for completion. Up/Down recalls history. Empty Enter opens a fresh prompt.\n";
    std::wcout << L"\n";

    PrintColoredText(L"quick start", KNDBG_COLOR_ACCENT);
    std::wcout << L"\n";
    std::wcout << L"  help                     show native and TUI commands grouped by feature\n";
    std::wcout << L"  help all                 also include DbgEng-routed WinDbg commands\n";
    std::wcout << L"  help <command>           show syntax, options, notes, and examples for one family\n";
    std::wcout << L"  <command> help           same as help <command>\n";
    std::wcout << L"  ai help <subcommand>     show AI subcommand help\n";
    std::wcout << L"  cls                      clear the console screen\n";
    std::wcout << L"\n";

    PrintColoredText(L"operator rules", KNDBG_COLOR_ACCENT);
    std::wcout << L"\n";
    std::wcout << L"  <address|symbol> accepts numbers, loaded symbols, and + or - arithmetic.\n";
    std::wcout << L"  nt! is normalized to the loaded kernel image for symbol and type lookup.\n";
    std::wcout << L"  d*/e*/vtop support /process <process-id>; procctx pins a default process context.\n";
    std::wcout << L"  Virtual e* writes default to System(pid 4) context for kernel addresses.\n";
    std::wcout << L"  Sparse reads keep layout and render unreadable bytes as ??.\n";
    std::wcout << L"  ";
    PrintColoredText(L"native", KNDBG_COLOR_OK);
    std::wcout << L" means KnLiveDbg implementation; ";
    PrintColoredText(L"alias", KNDBG_COLOR_ACCENT);
    std::wcout << L" means local alias; ";
    PrintColoredText(L"dbgeng", KNDBG_COLOR_WARN);
    std::wcout << L" means routed to IDebugControl.\n";
    std::wcout << L"\n";

    PrintColoredText(L"high-value topics", KNDBG_COLOR_ACCENT);
    std::wcout << L"\n";
    std::wcout << L"  help callbacks       callback scanners and module filters\n";
    std::wcout << L"  help !vad            VAD tree triage, hidden PTE checks, PE-like private memory\n";
    std::wcout << L"  help !threads        thread list, suspicious starts, APC evidence\n";
    std::wcout << L"  help !pool           big-pool allocation triage and W+X annotation\n";
    std::wcout << L"  help !address        canonicality, page-table walk, effective permissions, owner symbol\n";
    std::wcout << L"  help dt              type layout, wildcard, and field filters\n";
    std::wcout << L"  help e               virtual memory editing and /process behavior\n";
    std::wcout << L"  help vtop            VA to PA translation and page-table details\n";
    std::wcout << L"  ai help              AI question, config, plan, explain, run, and write commands\n";
    std::wcout << L"\n";

    PrintColoredText(L"example workflows", KNDBG_COLOR_ACCENT);
    std::wcout << L"\n";
    std::wcout << L"  session       home | drvstatus | probe load | probe info | backend dbgeng | kdinit\n";
    std::wcout << L"  symbols       .sympath SRV*<exe-dir>\\symbols*https://msdl.microsoft.com/download/symbols\n";
    std::wcout << L"  symbols       .reload | lm nt | x nt!*Process* | ln nt!PsLoadedModuleList\n";
    std::wcout << L"  memory        dq nt!PsLoadedModuleList 8 | db /process <pid> <user-address> 80\n";
    std::wcout << L"  memory        procctx <pid> | vtop /process <pid> <user-address> | pdb <pa> 80\n";
    std::wcout << L"  types/code    dt nt!_EPROCESS <address> | u nt!KiSystemCall64 8 | uf nt!KiSystemCall64 512\n";
    std::wcout << L"  callbacks     callbacks all | callbacks imageload | callbacks process WdFilter.sys\n";
    std::wcout << L"  process       !dml_proc [pid|name] | !vad <pid> /exec /private | !threads <pid> /apc\n";
    std::wcout << L"  kernel        !wfp providers | !alpc ports | !fwtable providers | !wnf instances\n";
    std::wcout << L"  integrity     !vbs | !ci options | !securekernel | !etw integrity | !nmi callbacks\n";
    std::wcout << L"  cpu-state     !msrcheck (SYSCALL MSR / LSTAR hook) | !cr (CR0.WP / SMEP / SMAP)\n";
    std::wcout << L"                !ssdt (syscall table hooks) | !idt (interrupt handler hooks)\n";
    std::wcout << L"  hunting       !pool find /wx | pool-scan-pe /suspicious | !byovd scan\n";
    std::wcout << L"  dumping       dump-raw <address> <length> <path> | dump-pe <address> <path>\n";
    std::wcout << L"  writes        write off | ed <address> <value> | peq <physical-address> <value>\n";
    std::wcout << L"  ti            set-ppl-antimalware status | !ti status | !ti start /name a.exe | !ti watch\n";
    std::wcout << L"  ai            ai a.exe eprocess | ai explain callbacks all | ai plan check VBS status\n";
    std::wcout << L"\n";

    CommandRegistry::PrintSummary(includeDbgEng);
    if (!includeDbgEng)
    {
        std::wcout << L"\n";
        std::wcout << L"type ";
        PrintColoredText(L"help all", KNDBG_COLOR_ACCENT);
        std::wcout << L" to include DbgEng-routed WinDbg commands.\n";
    }
}

static void PrintCallbacksHelp()
{
    std::wcout << L"callbacks command:\n";
    std::wcout << L"  callbacks [all|object|registry|process|thread|imageload|minifilter] [module]\n";
    std::wcout << L"  callbacks [scope] /module <module>\n";
    std::wcout << L"  callbacks <scope> help\n";
    std::wcout << L"\n";
    std::wcout << L"scopes:\n";
    std::wcout << L"  all          object-manager, registry, process, thread, image-load, and minifilter callbacks\n";
    std::wcout << L"  object       object-manager filters from _OBJECT_TYPE.CallbackList\n";
    std::wcout << L"  registry     registry callbacks from CmpCallbackListHead candidates\n";
    std::wcout << L"  process      process creation callbacks from PspCreateProcessNotifyRoutine candidates\n";
    std::wcout << L"  thread       thread creation callbacks from PspCreateThreadNotifyRoutine candidates\n";
    std::wcout << L"  imageload    image load callbacks from PspLoadImageNotifyRoutine candidates\n";
    std::wcout << L"  minifilter   minifilter filters and operation callbacks from fltmgr!FltGlobals\n";
    std::wcout << L"  module       case-insensitive module name or stem, for example WdFilter or wdfilter.sys\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  The scanner locates callback roots from symbols or self-discovered kernel lists.\n";
    std::wcout << L"  Module filters match callback function owners case-insensitively by image name or stem.\n";
    std::wcout << L"  Some private callback item layouts are absent from public PDBs; fallback notes are printed per record.\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  callbacks all\n";
    std::wcout << L"  callbacks object\n";
    std::wcout << L"  callbacks registry\n";
    std::wcout << L"  callbacks process\n";
    std::wcout << L"  callbacks thread\n";
    std::wcout << L"  callbacks imageload\n";
    std::wcout << L"  callbacks minifilter\n";
    std::wcout << L"  callbacks object WdFilter.sys\n";
    std::wcout << L"  callbacks minifilter UnionFS\n";
}

static std::wstring NormalizeCallbackHelpScope(const std::wstring& value)
{
    std::wstring scope = ToLower(value);

    return scope;
}

static bool PrintCallbackScopeHelp(const std::wstring& requestedScope)
{
    bool handled = true;
    std::wstring scope = NormalizeCallbackHelpScope(requestedScope);

    if (scope == L"all")
    {
        PrintCallbacksHelp();
    }
    else if (scope == L"object")
    {
        std::wcout << L"callbacks object:\n";
        std::wcout << L"  callbacks object [module]\n";
        std::wcout << L"  callbacks object /module <module>\n";
        std::wcout << L"\n";
        std::wcout << L"what it scans:\n";
        std::wcout << L"  Object-manager pre/post filters from each _OBJECT_TYPE.CallbackList.\n";
        std::wcout << L"  Object type addresses are discovered automatically from kernel object-type roots.\n";
        std::wcout << L"\n";
        std::wcout << L"important output:\n";
        std::wcout << L"  object/typeIndex/objectType/source identify the protected object type.\n";
        std::wcout << L"  pre/post are callback routines; registrationContext is the callback entry context.\n";
        std::wcout << L"  operations decodes create and duplicate filter bits.\n";
    }
    else if (scope == L"registry")
    {
        std::wcout << L"callbacks registry:\n";
        std::wcout << L"  callbacks registry [module]\n";
        std::wcout << L"  callbacks registry /module <module>\n";
        std::wcout << L"\n";
        std::wcout << L"what it scans:\n";
        std::wcout << L"  Registry callbacks from CmpCallbackListHead-style callback-list candidates.\n";
        std::wcout << L"\n";
        std::wcout << L"important output:\n";
        std::wcout << L"  function is the Cm callback routine owner.\n";
        std::wcout << L"  callbackContext is operator-supplied registration context, not a module owner.\n";
        std::wcout << L"  cookie is printed when the kernel record exposes it.\n";
    }
    else if (scope == L"process")
    {
        std::wcout << L"callbacks process:\n";
        std::wcout << L"  callbacks process [module]\n";
        std::wcout << L"  callbacks process /module <module>\n";
        std::wcout << L"\n";
        std::wcout << L"what it scans:\n";
        std::wcout << L"  Process creation notification blocks from PspCreateProcessNotifyRoutine candidates.\n";
        std::wcout << L"\n";
        std::wcout << L"important output:\n";
        std::wcout << L"  function is the create-process notify routine.\n";
        std::wcout << L"  notifyMetadata is low-bit metadata from the encoded notify entry, not a callback context.\n";
        std::wcout << L"  raw is the encoded pointer value before routine/metadata separation.\n";
    }
    else if (scope == L"thread")
    {
        std::wcout << L"callbacks thread:\n";
        std::wcout << L"  callbacks thread [module]\n";
        std::wcout << L"  callbacks thread /module <module>\n";
        std::wcout << L"\n";
        std::wcout << L"what it scans:\n";
        std::wcout << L"  Thread creation notification blocks from PspCreateThreadNotifyRoutine candidates.\n";
        std::wcout << L"\n";
        std::wcout << L"important output:\n";
        std::wcout << L"  function is the create-thread notify routine.\n";
        std::wcout << L"  callbackContext is printed when the record layout exposes a context-like field.\n";
    }
    else if (scope == L"imageload")
    {
        std::wcout << L"callbacks imageload:\n";
        std::wcout << L"  callbacks imageload [module]\n";
        std::wcout << L"  callbacks imageload /module <module>\n";
        std::wcout << L"\n";
        std::wcout << L"what it scans:\n";
        std::wcout << L"  Image load notification blocks from PspLoadImageNotifyRoutine candidates.\n";
        std::wcout << L"\n";
        std::wcout << L"important output:\n";
        std::wcout << L"  function is the image load notify routine.\n";
        std::wcout << L"  callbackContext is printed when the record layout exposes a context-like field.\n";
        std::wcout << L"  root and block show the notify table slot and decoded callback block.\n";
    }
    else if (scope == L"minifilter")
    {
        std::wcout << L"callbacks minifilter:\n";
        std::wcout << L"  callbacks minifilter [module]\n";
        std::wcout << L"  callbacks minifilter /module <module>\n";
        std::wcout << L"\n";
        std::wcout << L"what it scans:\n";
        std::wcout << L"  Minifilter filters and operation callbacks discovered from fltmgr!FltGlobals.\n";
        std::wcout << L"\n";
        std::wcout << L"important output:\n";
        std::wcout << L"  altitude, filter, frame, driverObject, major, function, and post identify filter ownership.\n";
        std::wcout << L"  module filters match operation callback function owners case-insensitively.\n";
    }
    else
    {
        handled = false;
    }

    return handled;
}

static void PrintCallbacksHelpFromArgs(const std::vector<std::wstring>& args, size_t first)
{
    size_t index = first;
    bool printed = false;

    do
    {
        if (index < args.size() && IsHelpToken(args[index]))
        {
            ++index;
        }

        if (index < args.size() && PrintCallbackScopeHelp(args[index]))
        {
            printed = true;
            break;
        }
    } while (false);

    if (!printed)
    {
        PrintCallbacksHelp();
    }
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

static std::wstring HexTextWidth(uint64_t value, int width, bool prefix)
{
    std::wstringstream stream;

    if (prefix)
    {
        stream << L"0x";
    }

    stream << std::hex << std::setw(width) << std::setfill(L'0') << value << std::dec;
    return stream.str();
}

static bool IsNativePhysicalBangCommand(const std::wstring& command)
{
    bool result = false;

    if (command == L"!db" ||
        command == L"!dw" ||
        command == L"!dd" ||
        command == L"!dq" ||
        command == L"!eb" ||
        command == L"!ew" ||
        command == L"!ed" ||
        command == L"!eq")
    {
        result = true;
    }

    return result;
}

static bool IsNativeBangCommand(const std::wstring& command)
{
    bool result = false;

    if (IsNativePhysicalBangCommand(command) ||
        command == L"!dml_proc" ||
        command == L"!vad" ||
        command == L"!threads" ||
        command == L"!snapshot" ||
        command == L"!diff" ||
        command == L"!wfp" ||
        command == L"!alpc" ||
        command == L"!byovd" ||
        command == L"!vbs" ||
        command == L"!ci" ||
        command == L"!securekernel" ||
        command == L"!etw" ||
        command == L"!nmi" ||
        command == L"!msrcheck" ||
        command == L"!cr" ||
        command == L"!ssdt" ||
        command == L"!idt" ||
        command == L"!fwtable" ||
        command == L"!module" ||
        command == L"!driver" ||
        command == L"!pool" ||
        command == L"!wnf" ||
        command == L"!address" ||
        command == L"!ti")
    {
        result = true;
    }

    return result;
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
            if (command == L"!vtop" || IsNativeBangCommand(command))
            {
                break;
            }

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

        if (value[0] == L'+' || value[0] == L'-')
        {
            break;
        }

        std::wstring text = value;
        if (!text.empty() && (text[0] == L'L' || text[0] == L'l'))
        {
            text = text.substr(1);
        }

        if (!text.empty() && (text[0] == L'+' || text[0] == L'-'))
        {
            break;
        }

        text.erase(std::remove(text.begin(), text.end(), L'`'), text.end());
        if (text.empty())
        {
            break;
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

static bool ContainsAddressExpressionOperator(const std::wstring& value)
{
    bool contains = false;

    for (size_t index = 1; index < value.size(); ++index)
    {
        if (value[index] == L'+' || value[index] == L'-')
        {
            contains = true;
            break;
        }
    }

    return contains;
}

static size_t FindAddressExpressionOperator(const std::wstring& value, size_t start)
{
    size_t found = std::wstring::npos;

    for (size_t index = start; index < value.size(); ++index)
    {
        if (value[index] == L'+' || value[index] == L'-')
        {
            found = index;
            break;
        }
    }

    return found;
}

static bool ResolveAddressTerm(
    SymbolEngine& symbols,
    const DebuggerState& state,
    const std::wstring& term,
    uint64_t* value,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (value == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid address term output";
            }
            break;
        }

        if (term.empty())
        {
            if (error != nullptr)
            {
                *error = L"Empty address expression term";
            }
            break;
        }

        uint64_t parsed = 0;
        if (ParseUnsigned(term, state.NumberBase, &parsed))
        {
            *value = parsed;
            ok = true;
            break;
        }

        if (symbols.ResolveSymbol(term, value, error))
        {
            ok = true;
        }
    } while (false);

    return ok;
}

static bool EvaluateAddressExpression(
    SymbolEngine& symbols,
    const DebuggerState& state,
    const std::wstring& expression,
    uint64_t* address,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (address == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid address expression output";
            }
            break;
        }

        size_t termStart = 0;
        wchar_t pendingOperator = 0;
        uint64_t result = 0;
        bool hasResult = false;

        while (termStart <= expression.size())
        {
            size_t operatorIndex = FindAddressExpressionOperator(expression, termStart);
            std::wstring term = expression.substr(
                termStart,
                operatorIndex == std::wstring::npos ? std::wstring::npos : operatorIndex - termStart);

            uint64_t termValue = 0;
            if (!ResolveAddressTerm(symbols, state, term, &termValue, error))
            {
                break;
            }

            if (!hasResult)
            {
                result = termValue;
                hasResult = true;
            }
            else if (pendingOperator == L'+')
            {
                if (result > (~0ull - termValue))
                {
                    if (error != nullptr)
                    {
                        *error = L"Address expression overflow";
                    }
                    break;
                }

                result += termValue;
            }
            else if (pendingOperator == L'-')
            {
                if (result < termValue)
                {
                    if (error != nullptr)
                    {
                        *error = L"Address expression underflow";
                    }
                    break;
                }

                result -= termValue;
            }
            else
            {
                if (error != nullptr)
                {
                    *error = L"Invalid address expression operator";
                }
                break;
            }

            if (operatorIndex == std::wstring::npos)
            {
                *address = result;
                ok = true;
                break;
            }

            pendingOperator = expression[operatorIndex];
            termStart = operatorIndex + 1;
            if (termStart >= expression.size())
            {
                if (error != nullptr)
                {
                    *error = L"Address expression is missing a trailing term";
                }
                break;
            }
        }
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

        if (ContainsAddressExpressionOperator(value))
        {
            if (EvaluateAddressExpression(symbols, state, value, address, error))
            {
                ok = true;
            }
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

struct MemoryReadView
{
    std::vector<uint8_t> Bytes;
    std::vector<uint8_t> Valid;
    bool AnyValid;
};

static MemoryReadView MakeKnownMemoryReadView(const std::vector<uint8_t>& bytes)
{
    MemoryReadView view = {};

    view.Bytes = bytes;
    view.Valid.assign(bytes.size(), 1);
    view.AnyValid = !bytes.empty();

    return view;
}

static bool MemoryByteIsKnown(const MemoryReadView& view, size_t offset)
{
    bool known = false;

    if (offset < view.Bytes.size() && offset < view.Valid.size() && view.Valid[offset] != 0)
    {
        known = true;
    }

    return known;
}

static bool MemoryRangeIsKnown(const MemoryReadView& view, size_t offset, size_t width)
{
    bool known = false;

    do
    {
        if (width == 0 || offset > view.Bytes.size() || width > view.Bytes.size() - offset)
        {
            break;
        }

        known = true;
        for (size_t index = 0; index < width; ++index)
        {
            if (!MemoryByteIsKnown(view, offset + index))
            {
                known = false;
                break;
            }
        }
    } while (false);

    return known;
}

static std::wstring UnknownHexText(size_t width, bool prefix)
{
    std::wstring result;

    if (prefix)
    {
        result = L"0x";
    }

    result += std::wstring(width * 2, L'?');
    return result;
}

static void HexDump(uint64_t address, const MemoryReadView& view)
{
    for (size_t offset = 0; offset < view.Bytes.size(); offset += 16)
    {
        PrintColoredText(HexTextWidth(address + offset, 16, false), KNDBG_COLOR_ACCENT);
        std::wcout << L"  ";
        std::wcout << std::hex << std::setfill(L'0');

        for (size_t index = 0; index < 16; ++index)
        {
            if (offset + index < view.Bytes.size())
            {
                if (MemoryByteIsKnown(view, offset + index))
                {
                    std::wcout << std::setw(2) << static_cast<unsigned>(view.Bytes[offset + index]) << L" ";
                }
                else
                {
                    std::wcout << L"?? ";
                }
            }
            else
            {
                std::wcout << L"   ";
            }
        }

        std::wcout << L" ";
        for (size_t index = 0; index < 16 && offset + index < view.Bytes.size(); ++index)
        {
            wchar_t ch = L'?';
            if (MemoryByteIsKnown(view, offset + index))
            {
                ch = static_cast<wchar_t>(view.Bytes[offset + index]);
                if (ch < 32 || ch > 126)
                {
                    ch = L'.';
                }
            }
            std::wcout << ch;
        }

        std::wcout << std::setfill(L' ') << std::dec << L"\n";
    }
}

static void UnitDump(uint64_t address, const MemoryReadView& view, size_t width, SymbolEngine* symbols)
{
    for (size_t offset = 0; offset + width <= view.Bytes.size(); offset += width)
    {
        PrintColoredText(HexTextWidth(address + offset, 16, true), KNDBG_COLOR_ACCENT);
        std::wcout << L": ";

        if (!MemoryRangeIsKnown(view, offset, width))
        {
            std::wcout << UnknownHexText(width, true) << std::dec << L"\n";
            continue;
        }

        uint64_t value = DecodeInteger(view.Bytes.data() + offset, width);
        std::wcout << HexTextWidth(value, static_cast<int>(width * 2), true);

        if (symbols != nullptr)
        {
            std::wstring name;
            uint64_t displacement = 0;
            std::wstring ignored;
            if (symbols->FindNearestSymbol(value, &name, &displacement, &ignored))
            {
                std::wcout << L"  ";
                PrintColoredText(name, KNDBG_COLOR_TITLE);
                if (displacement != 0)
                {
                    std::wcout << L"+0x" << displacement;
                }
            }
        }

        std::wcout << std::dec << L"\n";
    }
}

static void PrintAsciiString(uint64_t address, const MemoryReadView& view)
{
    PrintColoredText(HexText(address), KNDBG_COLOR_ACCENT);
    std::wcout << L": ";

    for (size_t offset = 0; offset < view.Bytes.size(); ++offset)
    {
        if (!MemoryByteIsKnown(view, offset))
        {
            std::wcout << L"?";
            continue;
        }

        uint8_t ch = view.Bytes[offset];
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

static void PrintAsciiString(uint64_t address, const std::vector<uint8_t>& bytes)
{
    PrintAsciiString(address, MakeKnownMemoryReadView(bytes));
}

static void PrintUnicodeString(uint64_t address, const MemoryReadView& view)
{
    PrintColoredText(HexText(address), KNDBG_COLOR_ACCENT);
    std::wcout << L": ";

    for (size_t offset = 0; offset + sizeof(wchar_t) <= view.Bytes.size(); offset += sizeof(wchar_t))
    {
        if (!MemoryRangeIsKnown(view, offset, sizeof(wchar_t)))
        {
            std::wcout << L"?";
            continue;
        }

        wchar_t ch = 0;
        memcpy(&ch, view.Bytes.data() + offset, sizeof(ch));
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

static void PrintUnicodeString(uint64_t address, const std::vector<uint8_t>& bytes)
{
    PrintUnicodeString(address, MakeKnownMemoryReadView(bytes));
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

static bool IsProcessContextOption(const std::wstring& value)
{
    std::wstring option = ToLower(value);
    return option == L"/process";
}

static bool IsDeprecatedProcessContextOption(const std::wstring& value)
{
    std::wstring option = ToLower(value);
    return option == L"/pid";
}

static bool IsSwitchLikeToken(const std::wstring& value)
{
    bool result = false;

    if (!value.empty() && (value[0] == L'/' || value[0] == L'-'))
    {
        result = true;
    }

    return result;
}

static bool IsEnterStringCommand(const std::wstring& command)
{
    return command == L"ea" || command == L"eza" || command == L"eu" || command == L"ezu";
}

static size_t UnitWidthForEnterCommand(const std::wstring& command)
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

    return width;
}

static size_t UnitWidthForPhysicalDisplayCommand(const std::wstring& command)
{
    size_t width = 1;

    if (command == L"pdw" || command == L"!dw")
    {
        width = 2;
    }
    else if (command == L"pdd" || command == L"!dd")
    {
        width = 4;
    }
    else if (command == L"pdq" || command == L"!dq")
    {
        width = 8;
    }

    return width;
}

static size_t UnitWidthForPhysicalEnterCommand(const std::wstring& command)
{
    size_t width = 1;

    if (command == L"pew" || command == L"!ew")
    {
        width = 2;
    }
    else if (command == L"ped" || command == L"!ed")
    {
        width = 4;
    }
    else if (command == L"peq" || command == L"!eq")
    {
        width = 8;
    }

    return width;
}

static bool IsPhysicalDisplayCommand(const std::wstring& command)
{
    return command == L"phys" || command == L"pdb" || command == L"pdw" ||
        command == L"pdd" || command == L"pdq" ||
        command == L"!db" || command == L"!dw" || command == L"!dd" ||
        command == L"!dq";
}

static bool IsPhysicalEnterCommand(const std::wstring& command)
{
    return command == L"peb" || command == L"pew" || command == L"ped" ||
        command == L"peq" ||
        command == L"!eb" || command == L"!ew" || command == L"!ed" ||
        command == L"!eq";
}

static bool IsWfpScopeName(const std::wstring& value)
{
    std::wstring lowered = ToLower(value);

    return lowered == L"providers" ||
        lowered == L"sublayers" ||
        lowered == L"callouts" ||
        lowered == L"kernelcallouts" ||
        lowered == L"filters" ||
        lowered == L"layers";
}

static bool IsWfpOption(const std::wstring& value)
{
    std::wstring lowered = ToLower(value);

    return lowered == L"/module" ||
        lowered == L"/layer" ||
        lowered == L"/provider";
}

static bool ResolveWfpScope(const std::wstring& value, WfpScanner::Scope* scope)
{
    bool ok = true;
    std::wstring lowered = ToLower(value);

    if (lowered == L"providers")
    {
        *scope = WfpScanner::Scope::Providers;
    }
    else if (lowered == L"sublayers")
    {
        *scope = WfpScanner::Scope::SubLayers;
    }
    else if (lowered == L"callouts")
    {
        *scope = WfpScanner::Scope::Callouts;
    }
    else if (lowered == L"filters")
    {
        *scope = WfpScanner::Scope::Filters;
    }
    else if (lowered == L"layers")
    {
        *scope = WfpScanner::Scope::Layers;
    }
    else
    {
        ok = false;
    }

    return ok;
}

static bool IsAlpcScopeName(const std::wstring& value)
{
    std::wstring lowered = ToLower(value);

    return lowered == L"ports" ||
        lowered == L"port" ||
        lowered == L"connections" ||
        lowered == L"queues";
}

static bool IsAlpcOption(const std::wstring& value)
{
    std::wstring lowered = ToLower(value);

    return lowered == L"/name" ||
        lowered == L"/pid";
}

static bool ResolveAlpcScope(const std::wstring& value, AlpcScanner::Scope* scope)
{
    bool ok = true;
    std::wstring lowered = ToLower(value);

    if (lowered == L"ports")
    {
        *scope = AlpcScanner::Scope::Ports;
    }
    else if (lowered == L"port")
    {
        *scope = AlpcScanner::Scope::Port;
    }
    else if (lowered == L"connections")
    {
        *scope = AlpcScanner::Scope::Connections;
    }
    else if (lowered == L"queues")
    {
        *scope = AlpcScanner::Scope::Queues;
    }
    else
    {
        ok = false;
    }

    return ok;
}

static bool IsCiScopeName(const std::wstring& value)
{
    std::wstring lowered = ToLower(value);
    return lowered == L"options" || lowered == L"policy";
}

static bool IsEtwScopeName(const std::wstring& value)
{
    std::wstring lowered = ToLower(value);
    return lowered == L"loggers" || lowered == L"logger" || lowered == L"integrity";
}

static bool IsNmiScopeName(const std::wstring& value)
{
    std::wstring lowered = ToLower(value);
    return lowered == L"callbacks";
}

static bool IsFirmwareTableScopeName(const std::wstring& value)
{
    std::wstring lowered = ToLower(value);
    return lowered == L"providers" || lowered == L"provider";
}

static bool IsFirmwareTableOption(const std::wstring& value)
{
    std::wstring lowered = ToLower(value);
    return lowered == L"/module";
}

static bool IsPoolScopeName(const std::wstring& value)
{
    std::wstring lowered = ToLower(value);
    return lowered == L"big" ||
        lowered == L"bigpool" ||
        lowered == L"find" ||
        lowered == L"summary";
}

static bool IsPoolOption(const std::wstring& value)
{
    std::wstring lowered = ToLower(value);
    return lowered == L"/tag" ||
        lowered == L"/min" ||
        lowered == L"/max" ||
        lowered == L"/addr" ||
        lowered == L"/limit" ||
        lowered == L"/paged" ||
        lowered == L"/nonpaged" ||
        lowered == L"/any" ||
        lowered == L"/annotate" ||
        lowered == L"/wx";
}

static bool IsWnfScopeName(const std::wstring& value)
{
    std::wstring lowered = ToLower(value);
    return lowered == L"decode" ||
        lowered == L"instances" ||
        lowered == L"instance" ||
        lowered == L"data" ||
        lowered == L"candidates" ||
        lowered == L"lists";
}

static void AddCompletionCandidate(std::vector<std::wstring>* candidates, const wchar_t* value)
{
    do
    {
        if (candidates == nullptr || value == nullptr || value[0] == L'\0')
        {
            break;
        }

        std::wstring item = value;
        if (std::find(candidates->begin(), candidates->end(), item) == candidates->end())
        {
            candidates->push_back(item);
        }
    } while (false);
}

template <size_t Count>
static void AddCompletionCandidates(std::vector<std::wstring>* candidates, const wchar_t* const (&values)[Count])
{
    for (size_t index = 0; index < Count; ++index)
    {
        AddCompletionCandidate(candidates, values[index]);
    }
}

static void AddRegisteredCommandCompletionCandidates(std::vector<std::wstring>* candidates)
{
    do
    {
        if (candidates == nullptr)
        {
            break;
        }

        for (const CommandInfo& command : CommandRegistry::Commands())
        {
            AddCompletionCandidate(candidates, command.Name);
        }
    } while (false);
}

static void AddHelpCompletionCandidates(std::vector<std::wstring>* candidates)
{
    static const wchar_t* values[] =
    {
        L"all",
        L"callbacks"
    };

    AddCompletionCandidates(candidates, values);
    AddRegisteredCommandCompletionCandidates(candidates);
}

static void AddCallbackScopeCompletionCandidates(std::vector<std::wstring>* candidates)
{
    static const wchar_t* values[] =
    {
        L"all",
        L"object",
        L"registry",
        L"process",
        L"thread",
        L"imageload",
        L"minifilter",
        L"/module",
        L"help"
    };

    AddCompletionCandidates(candidates, values);
}

static void AddCallbackModuleOptionCompletionCandidates(std::vector<std::wstring>* candidates)
{
    static const wchar_t* values[] =
    {
        L"/module",
        L"help"
    };

    AddCompletionCandidates(candidates, values);
}

static void AddVadOptionCompletionCandidates(std::vector<std::wstring>* candidates)
{
    static const wchar_t* values[] =
    {
        L"/summary",
        L"/exec",
        L"/private",
        L"/wx",
        L"/pe",
        L"/hiddenpte",
        L"/limit",
        L"/json",
        L"help"
    };

    AddCompletionCandidates(candidates, values);
}

static void AddThreadsOptionCompletionCandidates(std::vector<std::wstring>* candidates)
{
    static const wchar_t* values[] =
    {
        L"/apc",
        L"/stacks",
        L"/limit",
        L"/json",
        L"help"
    };

    AddCompletionCandidates(candidates, values);
}

static void AddSnapshotCompletionCandidates(std::vector<std::wstring>* candidates)
{
    static const wchar_t* values[] =
    {
        L"baseline",
        L"save",
        L"show",
        L"/all",
        L"/name",
        L"/domains",
        L"/warnings",
        L"help"
    };

    AddCompletionCandidates(candidates, values);
}

static void AddDiffCompletionCandidates(std::vector<std::wstring>* candidates)
{
    static const wchar_t* values[] =
    {
        L"baseline",
        L"/summary",
        L"/details",
        L"/domain",
        L"/risk",
        L"/limit",
        L"help"
    };

    AddCompletionCandidates(candidates, values);
}

static void AddWfpScopeCompletionCandidates(std::vector<std::wstring>* candidates)
{
    static const wchar_t* values[] =
    {
        L"providers",
        L"sublayers",
        L"callouts",
        L"kernelcallouts",
        L"filters",
        L"layers",
        L"help"
    };

    AddCompletionCandidates(candidates, values);
}

static void AddWfpOptionCompletionCandidates(std::vector<std::wstring>* candidates, WfpScanner::Scope scope)
{
    if (scope == WfpScanner::Scope::Callouts)
    {
        AddCompletionCandidate(candidates, L"/module");
    }
    else if (scope == WfpScanner::Scope::Filters)
    {
        AddCompletionCandidate(candidates, L"/layer");
        AddCompletionCandidate(candidates, L"/provider");
    }

    AddCompletionCandidate(candidates, L"help");
}

static void AddAlpcScopeCompletionCandidates(std::vector<std::wstring>* candidates)
{
    static const wchar_t* values[] =
    {
        L"ports",
        L"port",
        L"connections",
        L"queues",
        L"help"
    };

    AddCompletionCandidates(candidates, values);
}

static void AddAlpcOptionCompletionCandidates(std::vector<std::wstring>* candidates, AlpcScanner::Scope scope)
{
    if (scope == AlpcScanner::Scope::Ports || scope == AlpcScanner::Scope::Connections)
    {
        AddCompletionCandidate(candidates, L"/name");
        AddCompletionCandidate(candidates, L"/pid");
    }

    AddCompletionCandidate(candidates, L"help");
}

static void AddFirmwareTableCompletionCandidates(std::vector<std::wstring>* candidates, bool afterScope)
{
    if (!afterScope)
    {
        static const wchar_t* values[] =
        {
            L"providers",
            L"provider",
            L"help"
        };

        AddCompletionCandidates(candidates, values);
    }
    else
    {
        static const wchar_t* values[] =
        {
            L"/module",
            L"help"
        };

        AddCompletionCandidates(candidates, values);
    }
}

static void AddFirmwareTableCommandCompletionCandidates(
    std::vector<std::wstring>* candidates,
    const std::vector<std::wstring>& argsBefore)
{
    do
    {
        if (argsBefore.size() <= 1)
        {
            AddFirmwareTableCompletionCandidates(candidates, false);
            break;
        }

        std::wstring scope = ToLower(argsBefore[1]);
        if (scope == L"providers")
        {
            AddFirmwareTableCompletionCandidates(candidates, true);
            break;
        }

        if (scope == L"provider")
        {
            if (argsBefore.size() <= 2)
            {
                static const wchar_t* values[] =
                {
                    L"ACPI",
                    L"FIRM",
                    L"RSMB",
                    L"help"
                };

                AddCompletionCandidates(candidates, values);
            }
            else
            {
                AddCompletionCandidate(candidates, L"help");
            }
            break;
        }

        AddFirmwareTableCompletionCandidates(candidates, false);
    } while (false);
}

static void AddAiActionCompletionCandidates(std::vector<std::wstring>* candidates)
{
    static const wchar_t* values[] =
    {
        L"status",
        L"help",
        L"config",
        L"providers",
        L"provider",
        L"policy",
        L"model",
        L"base-url",
        L"effort",
        L"auth",
        L"preview",
        L"ask",
        L"plan",
        L"run",
        L"write",
        L"explain",
        L"analyze",
        L"annotate",
        L"diagnose",
        L"playbook",
        L"transcript",
        L"audit",
        L"show",
        L"report"
    };

    AddCompletionCandidates(candidates, values);
}

static void AddAiEvidenceCommandCompletionCandidates(std::vector<std::wstring>* candidates)
{
    static const wchar_t* values[] =
    {
        L"callbacks",
        L"dt",
        L"dtx",
        L"u",
        L"uf",
        L"ln",
        L"lm",
        L"x",
        L"vtop",
        L"!dml_proc",
        L"!vad",
        L"!threads",
        L"!snapshot",
        L"!diff",
        L"!wfp",
        L"!alpc",
        L"!vbs",
        L"!ci",
        L"!securekernel",
        L"!etw",
        L"!nmi",
        L"!msrcheck",
        L"!cr",
        L"!ssdt",
        L"!idt",
        L"!fwtable",
        L"!module",
        L"!driver",
        L"!pool",
        L"!address",
        L"!wnf",
        L"help"
    };

    AddCompletionCandidates(candidates, values);
}

static void AddAiCompletionCandidates(
    const std::vector<std::wstring>& argsBefore,
    std::vector<std::wstring>* candidates)
{
    do
    {
        if (candidates == nullptr)
        {
            break;
        }

        if (argsBefore.size() <= 1)
        {
            AddAiActionCompletionCandidates(candidates);
            break;
        }

        std::wstring action = ToLower(argsBefore[1]);
        if (action == L"config")
        {
            if (argsBefore.size() == 2)
            {
                static const wchar_t* values[] =
                {
                    L"status",
                    L"providers",
                    L"provider",
                    L"policy",
                    L"model",
                    L"base-url",
                    L"effort",
                    L"auth",
                    L"test",
                    L"help"
                };

                AddCompletionCandidates(candidates, values);
            }
            else if (ToLower(argsBefore[2]) == L"provider")
            {
                for (const std::wstring& provider : AiProviderRuntime::SupportedProviderNames())
                {
                    AddCompletionCandidate(candidates, provider.c_str());
                }

                AddCompletionCandidate(candidates, L"off");
                AddCompletionCandidate(candidates, L"help");
            }
            else if (ToLower(argsBefore[2]) == L"policy")
            {
                static const wchar_t* values[] =
                {
                    L"allow-remote",
                    L"local-only",
                    L"status",
                    L"help"
                };

                AddCompletionCandidates(candidates, values);
            }
            else if (ToLower(argsBefore[2]) == L"effort")
            {
                static const wchar_t* values[] =
                {
                    L"minimal",
                    L"low",
                    L"medium",
                    L"high",
                    L"xhigh",
                    L"help"
                };

                AddCompletionCandidates(candidates, values);
            }
        }
        else if (action == L"provider")
        {
            if (argsBefore.size() == 2)
            {
                for (const std::wstring& provider : AiProviderRuntime::SupportedProviderNames())
                {
                    AddCompletionCandidate(candidates, provider.c_str());
                }

                AddCompletionCandidate(candidates, L"off");
                AddCompletionCandidate(candidates, L"help");
            }
        }
        else if (action == L"policy")
        {
            static const wchar_t* values[] =
            {
                L"allow-remote",
                L"local-only",
                L"status",
                L"help"
            };

            AddCompletionCandidates(candidates, values);
        }
        else if (action == L"effort")
        {
            static const wchar_t* values[] =
            {
                L"minimal",
                L"low",
                L"medium",
                L"high",
                L"xhigh",
                L"help"
            };

            AddCompletionCandidates(candidates, values);
        }
        else if (action == L"run")
        {
            static const wchar_t* values[] =
            {
                L"all",
                L"help"
            };

            AddCompletionCandidates(candidates, values);
        }
        else if (action == L"write")
        {
            if (argsBefore.size() >= 3)
            {
                static const wchar_t* values[] =
                {
                    L"confirm",
                    L"help"
                };

                AddCompletionCandidates(candidates, values);
            }
        }
        else if (action == L"analyze")
        {
            if (argsBefore.size() == 2)
            {
                AddAiEvidenceCommandCompletionCandidates(candidates);
            }
            else if (ToLower(argsBefore[2]) == L"callbacks")
            {
                if (argsBefore.size() == 3)
                {
                    AddCallbackScopeCompletionCandidates(candidates);
                }
                else
                {
                    AddCallbackModuleOptionCompletionCandidates(candidates);
                }
            }
        }
        else if (action == L"explain")
        {
            if (argsBefore.size() == 2)
            {
                AddAiEvidenceCommandCompletionCandidates(candidates);
            }
            else if (ToLower(argsBefore[2]) == L"callbacks")
            {
                if (argsBefore.size() == 3)
                {
                    AddCallbackScopeCompletionCandidates(candidates);
                }
                else
                {
                    AddCallbackModuleOptionCompletionCandidates(candidates);
                }
            }
        }
        else if (action == L"annotate")
        {
            static const wchar_t* values[] =
            {
                L"u",
                L"uf",
                L"help"
            };

            AddCompletionCandidates(candidates, values);
        }
        else if (action == L"playbook")
        {
            if (argsBefore.size() == 2)
            {
                static const wchar_t* values[] =
                {
                    L"callbacks",
                    L"minifilter",
                    L"object",
                    L"address",
                    L"driver",
                    L"help"
                };

                AddCompletionCandidates(candidates, values);
            }
            else
            {
                static const wchar_t* values[] =
                {
                    L"run",
                    L"dry-run",
                    L"help"
                };

                AddCompletionCandidates(candidates, values);
            }
        }
        else if (action == L"transcript")
        {
            if (argsBefore.size() == 2)
            {
                static const wchar_t* values[] =
                {
                    L"status",
                    L"off",
                    L"max",
                    L"redact",
                    L"help"
                };

                AddCompletionCandidates(candidates, values);
            }
            else if (ToLower(argsBefore[2]) == L"max")
            {
                static const wchar_t* values[] =
                {
                    L"off",
                    L"help"
                };

                AddCompletionCandidates(candidates, values);
            }
            else if (ToLower(argsBefore[2]) == L"redact")
            {
                static const wchar_t* values[] =
                {
                    L"on",
                    L"off",
                    L"help"
                };

                AddCompletionCandidates(candidates, values);
            }
        }
        else if (action == L"audit")
        {
            static const wchar_t* values[] =
            {
                L"status",
                L"off",
                L"help"
            };

            AddCompletionCandidates(candidates, values);
        }
        else if (action == L"help")
        {
            AddAiActionCompletionCandidates(candidates);
        }
    } while (false);
}

static std::wstring CompletionCanonicalCommand(const std::wstring& value)
{
    std::wstring command = NormalizeInputCommand(value);

    const CommandInfo* info = CommandRegistry::Find(value);
    if (info != nullptr && info->Canonical != nullptr)
    {
        command = NormalizeInputCommand(info->Canonical);
    }

    return command;
}

static std::vector<std::wstring> BuildInteractiveCompletionCandidates(const std::vector<std::wstring>& argsBefore)
{
    std::vector<std::wstring> candidates;

    do
    {
        if (argsBefore.empty())
        {
            AddRegisteredCommandCompletionCandidates(&candidates);
            break;
        }

        if (IsHelpToken(argsBefore.back()))
        {
            break;
        }

        std::wstring command = CompletionCanonicalCommand(argsBefore[0]);
        if (command == L"help" || command == L"?")
        {
            if (argsBefore.size() <= 1)
            {
                AddHelpCompletionCandidates(&candidates);
            }
            else
            {
                std::wstring topic = CompletionCanonicalCommand(argsBefore[1]);
                if (topic == L"ai")
                {
                    AddAiActionCompletionCandidates(&candidates);
                }
                else if (topic == L"callbacks")
                {
                    AddCallbackScopeCompletionCandidates(&candidates);
                }
                else if (topic == L"backend")
                {
                    static const wchar_t* values[] =
                    {
                        L"auto",
                        L"native",
                        L"dbgeng"
                    };

                    AddCompletionCandidates(&candidates, values);
                }
                else if (topic == L"kdinit")
                {
                    static const wchar_t* values[] =
                    {
                        L"/local",
                        L"/remote"
                    };

                    AddCompletionCandidates(&candidates, values);
                }
                else if (topic == L"probe")
                {
                    static const wchar_t* values[] =
                    {
                        L"status",
                        L"load",
                        L"info",
                        L"reset",
                        L"unload"
                    };

                    AddCompletionCandidates(&candidates, values);
                }
                else if (topic == L"procctx")
                {
                    static const wchar_t* values[] =
                    {
                        L"status",
                        L"clear"
                    };

                    AddCompletionCandidates(&candidates, values);
                }
                else if (topic == L"write")
                {
                    static const wchar_t* values[] =
                    {
                        L"on",
                        L"off"
                    };

                    AddCompletionCandidates(&candidates, values);
                }
                else if (topic == L"!wfp")
                {
                    AddWfpScopeCompletionCandidates(&candidates);
                }
                else if (topic == L"!vad")
                {
                    AddVadOptionCompletionCandidates(&candidates);
                }
                else if (topic == L"!threads")
                {
                    AddThreadsOptionCompletionCandidates(&candidates);
                }
                else if (topic == L"!alpc")
                {
                    AddAlpcScopeCompletionCandidates(&candidates);
                }
                else if (topic == L"!ci")
                {
                    static const wchar_t* values[] =
                    {
                        L"options",
                        L"policy"
                    };
                    AddCompletionCandidates(&candidates, values);
                }
                else if (topic == L"!etw")
                {
                    static const wchar_t* values[] =
                    {
                        L"loggers",
                        L"logger",
                        L"integrity"
                    };
                    AddCompletionCandidates(&candidates, values);
                }
                else if (topic == L"!nmi")
                {
                    AddCompletionCandidate(&candidates, L"callbacks");
                }
                else if (topic == L"!fwtable")
                {
                    AddFirmwareTableCompletionCandidates(&candidates, false);
                }
                else if (topic == L"!snapshot")
                {
                    AddSnapshotCompletionCandidates(&candidates);
                }
                else if (topic == L"!diff")
                {
                    AddDiffCompletionCandidates(&candidates);
                }
                else if (topic == L"!module")
                {
                    static const wchar_t* values[] =
                    {
                        L"integrity",
                        L"all",
                        L"/summary",
                        L"/verbose",
                        L"/headers",
                        L"/sections",
                        L"/wx",
                        L"/mismatch",
                        L"/limit",
                        L"/json"
                    };
                    AddCompletionCandidates(&candidates, values);
                }
                else if (topic == L"!driver")
                {
                    static const wchar_t* values[] =
                    {
                        L"integrity",
                        L"all",
                        L"/limit",
                        L"/json"
                    };
                    AddCompletionCandidates(&candidates, values);
                }
                else if (topic == L"!pool")
                {
                    static const wchar_t* values[] =
                    {
                        L"big",
                        L"find",
                        L"summary"
                    };
                    AddCompletionCandidates(&candidates, values);
                }
                else if (topic == L"pool-scan-pe")
                {
                    static const wchar_t* values[] =
                    {
                        L"/tag",
                        L"/min",
                        L"/max",
                        L"/limit",
                        L"/nonpaged",
                        L"/paged",
                        L"/any",
                        L"/suspicious",
                        L"/dump"
                    };
                    AddCompletionCandidates(&candidates, values);
                }
                else if (topic == L"dump-raw")
                {
                    AddCompletionCandidate(&candidates, L"/zerofill");
                }
                else if (topic == L"set-ppl-antimalware")
                {
                    static const wchar_t* values[] =
                    {
                        L"on",
                        L"off",
                        L"status"
                    };
                    AddCompletionCandidates(&candidates, values);
                }
                else if (topic == L"!wnf")
                {
                    static const wchar_t* values[] =
                    {
                        L"decode",
                        L"instances",
                        L"instance",
                        L"data",
                        L"candidates",
                        L"lists"
                    };
                    AddCompletionCandidates(&candidates, values);
                }
                else
                {
                    AddHelpCompletionCandidates(&candidates);
                }
            }
        }
        else if (command == L"callbacks")
        {
            if (argsBefore.size() <= 1)
            {
                AddCallbackScopeCompletionCandidates(&candidates);
            }
            else
            {
                AddCallbackModuleOptionCompletionCandidates(&candidates);
            }
        }
        else if (command == L"!wfp")
        {
            if (argsBefore.size() <= 1)
            {
                AddWfpScopeCompletionCandidates(&candidates);
            }
            else
            {
                WfpScanner::Scope scope = WfpScanner::Scope::Callouts;
                ResolveWfpScope(argsBefore[1], &scope);
                AddWfpOptionCompletionCandidates(&candidates, scope);
            }
        }
        else if (command == L"!vad")
        {
            AddVadOptionCompletionCandidates(&candidates);
        }
        else if (command == L"!threads")
        {
            AddThreadsOptionCompletionCandidates(&candidates);
        }
        else if (command == L"!snapshot")
        {
            AddSnapshotCompletionCandidates(&candidates);
        }
        else if (command == L"!diff")
        {
            AddDiffCompletionCandidates(&candidates);
        }
        else if (command == L"!alpc")
        {
            if (argsBefore.size() <= 1)
            {
                AddAlpcScopeCompletionCandidates(&candidates);
            }
            else
            {
                AlpcScanner::Scope scope = AlpcScanner::Scope::Ports;
                ResolveAlpcScope(argsBefore[1], &scope);
                AddAlpcOptionCompletionCandidates(&candidates, scope);
            }
        }
        else if (command == L"!ci")
        {
            if (argsBefore.size() <= 1)
            {
                static const wchar_t* values[] =
                {
                    L"options",
                    L"policy",
                    L"help"
                };
                AddCompletionCandidates(&candidates, values);
            }
        }
        else if (command == L"!vbs" || command == L"!securekernel")
        {
            if (argsBefore.size() <= 1)
            {
                AddCompletionCandidate(&candidates, L"help");
            }
        }
        else if (command == L"!etw")
        {
            if (argsBefore.size() <= 1)
            {
                static const wchar_t* values[] =
                {
                    L"loggers",
                    L"logger",
                    L"integrity",
                    L"help"
                };
                AddCompletionCandidates(&candidates, values);
            }
        }
        else if (command == L"!nmi")
        {
            if (argsBefore.size() <= 1)
            {
                static const wchar_t* values[] =
                {
                    L"callbacks",
                    L"help"
                };
                AddCompletionCandidates(&candidates, values);
            }
        }
        else if (command == L"!fwtable")
        {
            AddFirmwareTableCommandCompletionCandidates(&candidates, argsBefore);
        }
        else if (command == L"!module")
        {
            static const wchar_t* values[] =
            {
                L"integrity",
                L"all",
                L"/summary",
                L"/verbose",
                L"/headers",
                L"/sections",
                L"/wx",
                L"/mismatch",
                L"/limit",
                L"/json",
                L"help"
            };
            AddCompletionCandidates(&candidates, values);
        }
        else if (command == L"!driver")
        {
            static const wchar_t* values[] =
            {
                L"integrity",
                L"all",
                L"/limit",
                L"/json",
                L"help"
            };
            AddCompletionCandidates(&candidates, values);
        }
        else if (command == L"byovd" || command == L"!byovd")
        {
            if (argsBefore.size() >= 2 && ToLower(argsBefore[1]) == L"fixture")
            {
                static const wchar_t* values[] =
                {
                    L"status",
                    L"load",
                    L"unload",
                    L"path",
                    L"help"
                };
                AddCompletionCandidates(&candidates, values);
            }
            else
            {
                static const wchar_t* values[] =
                {
                    L"scan",
                    L"update",
                    L"status",
                    L"fixture",
                    L"/no-update",
                L"/force-update",
                L"/exact",
                L"/yara",
                L"/yara-path",
                L"/yara-timeout",
                L"/verbose",
                L"/summary",
                L"/limit",
                    L"/json",
                    L"help"
                };
                AddCompletionCandidates(&candidates, values);
            }
        }
        else if (command == L"pool-scan-pe")
        {
            static const wchar_t* values[] =
            {
                L"/tag",
                L"/min",
                L"/max",
                L"/limit",
                L"/nonpaged",
                L"/paged",
                L"/any",
                L"/suspicious",
                L"/dump",
                L"help"
            };
            AddCompletionCandidates(&candidates, values);
        }
        else if (command == L"dump-raw")
        {
            if (argsBefore.size() >= 4)
            {
                AddCompletionCandidate(&candidates, L"/zerofill");
            }
            AddCompletionCandidate(&candidates, L"help");
        }
        else if (command == L"dump-pe")
        {
            AddCompletionCandidate(&candidates, L"help");
        }
        else if (command == L"!address")
        {
            AddCompletionCandidate(&candidates, L"help");
        }
        else if (command == L"set-ppl-antimalware")
        {
            static const wchar_t* values[] =
            {
                L"on",
                L"off",
                L"status",
                L"help"
            };
            AddCompletionCandidates(&candidates, values);
        }
        else if (command == L"!ti")
        {
            if (argsBefore.size() <= 1)
            {
                static const wchar_t* values[] =
                {
                    L"start",
                    L"stop",
                    L"status",
                    L"add",
                    L"remove",
                    L"watch",
                    L"recent",
                    L"stats",
                    L"by",
                    L"grep",
                    L"save",
                    L"clear",
                    L"help"
                };
                AddCompletionCandidates(&candidates, values);
            }
            else
            {
                static const wchar_t* values[] =
                {
                    L"/pid",
                    L"/name",
                    L"/throttle",
                    L"/ring",
                    L"/log",
                    L"pid",
                    L"task"
                };
                AddCompletionCandidates(&candidates, values);
            }
        }
        else if (command == L"!pool")
        {
            if (argsBefore.size() <= 1)
            {
                static const wchar_t* values[] =
                {
                    L"big",
                    L"find",
                    L"summary",
                    L"help"
                };
                AddCompletionCandidates(&candidates, values);
            }
            else
            {
                static const wchar_t* values[] =
                {
                    L"/tag",
                    L"/min",
                    L"/max",
                    L"/addr",
                    L"/limit",
                    L"/nonpaged",
                    L"/paged",
                    L"/any",
                    L"/annotate",
                    L"/wx"
                };
                AddCompletionCandidates(&candidates, values);
            }
        }
        else if (command == L"!wnf")
        {
            if (argsBefore.size() <= 1)
            {
                static const wchar_t* values[] =
                {
                    L"decode",
                    L"instances",
                    L"instance",
                    L"data",
                    L"candidates",
                    L"lists",
                    L"help"
                };
                AddCompletionCandidates(&candidates, values);
            }
        }
        else if (command == L"log")
        {
            if (argsBefore.size() <= 1)
            {
                static const wchar_t* values[] =
                {
                    L"enable",
                    L"disable",
                    L"status",
                    L"help"
                };
                AddCompletionCandidates(&candidates, values);
            }
        }
        else if (command == L"ai")
        {
            AddAiCompletionCandidates(argsBefore, &candidates);
        }
        else if (command == L"backend")
        {
            if (argsBefore.size() <= 1)
            {
                static const wchar_t* values[] =
                {
                    L"auto",
                    L"native",
                    L"dbgeng",
                    L"help"
                };

                AddCompletionCandidates(&candidates, values);
            }
        }
        else if (command == L"kdinit")
        {
            if (argsBefore.size() <= 1)
            {
                static const wchar_t* values[] =
                {
                    L"/local",
                    L"/remote",
                    L"help"
                };

                AddCompletionCandidates(&candidates, values);
            }
        }
        else if (command == L"probe")
        {
            if (argsBefore.size() <= 1)
            {
                static const wchar_t* values[] =
                {
                    L"status",
                    L"load",
                    L"info",
                    L"reset",
                    L"unload",
                    L"help"
                };

                AddCompletionCandidates(&candidates, values);
            }
        }
        else if (command == L"procctx")
        {
            if (argsBefore.size() <= 1)
            {
                static const wchar_t* values[] =
                {
                    L"status",
                    L"clear",
                    L"help"
                };

                AddCompletionCandidates(&candidates, values);
            }
        }
        else if (command == L"write")
        {
            if (argsBefore.size() <= 1)
            {
                static const wchar_t* values[] =
                {
                    L"on",
                    L"off",
                    L"help"
                };

                AddCompletionCandidates(&candidates, values);
            }
        }
        else if (command == L"sq")
        {
            if (argsBefore.size() <= 1)
            {
                static const wchar_t* values[] =
                {
                    L"true",
                    L"false",
                    L"help"
                };

                AddCompletionCandidates(&candidates, values);
            }
        }
        else if (command == L"n")
        {
            if (argsBefore.size() <= 1)
            {
                static const wchar_t* values[] =
                {
                    L"10",
                    L"16",
                    L"help"
                };

                AddCompletionCandidates(&candidates, values);
            }
        }
        else if (command == L"vtop")
        {
            static const wchar_t* values[] =
            {
                L"/cr3",
                L"/process",
                L"help"
            };

            AddCompletionCandidates(&candidates, values);
        }
        else if (command == L"dt" || command == L"dtx")
        {
            static const wchar_t* values[] =
            {
                L"-r",
                L"-r1",
                L"-r2",
                L"-r3",
                L"-v",
                L"-b",
                L"help"
            };

            AddCompletionCandidates(&candidates, values);
        }
        else if (command == L"s")
        {
            static const wchar_t* values[] =
            {
                L"-b",
                L"-w",
                L"-d",
                L"-q",
                L"help"
            };

            AddCompletionCandidates(&candidates, values);
        }
        else if (command == L"setfield")
        {
            static const wchar_t* values[] =
            {
                L"help"
            };

            AddCompletionCandidates(&candidates, values);
        }
        else if (IsDisplayCommand(command) || IsEnterCommand(command))
        {
            static const wchar_t* values[] =
            {
                L"/process",
                L"help"
            };

            AddCompletionCandidates(&candidates, values);
        }
        else if (IsPhysicalDisplayCommand(command) || IsPhysicalEnterCommand(command))
        {
            static const wchar_t* values[] =
            {
                L"help"
            };

            AddCompletionCandidates(&candidates, values);
        }
    } while (false);

    std::sort(
        candidates.begin(),
        candidates.end(),
        [](const std::wstring& left, const std::wstring& right)
        {
            std::wstring lowerLeft = ToLower(left);
            std::wstring lowerRight = ToLower(right);
            if (lowerLeft == lowerRight)
            {
                return left < right;
            }

            return lowerLeft < lowerRight;
        });

    return candidates;
}

static bool StartsWithNoCase(const std::wstring& value, const std::wstring& prefix)
{
    bool matched = false;

    do
    {
        if (prefix.size() > value.size())
        {
            break;
        }

        std::wstring valuePrefix = value.substr(0, prefix.size());
        matched = ToLower(valuePrefix) == ToLower(prefix);
    } while (false);

    return matched;
}

static std::vector<std::wstring> FilterCompletionCandidates(
    const std::vector<std::wstring>& candidates,
    const std::wstring& prefix)
{
    std::vector<std::wstring> matches;

    for (const std::wstring& candidate : candidates)
    {
        if (StartsWithNoCase(candidate, prefix))
        {
            matches.push_back(candidate);
        }
    }

    return matches;
}

static std::wstring LongestCommonCompletionPrefix(const std::vector<std::wstring>& matches)
{
    std::wstring prefix;

    do
    {
        if (matches.empty())
        {
            break;
        }

        const std::wstring& first = matches[0];
        size_t length = 0;
        while (length < first.size())
        {
            wchar_t expected = static_cast<wchar_t>(std::towlower(first[length]));
            bool same = true;

            for (size_t index = 1; index < matches.size(); ++index)
            {
                if (length >= matches[index].size() ||
                    static_cast<wchar_t>(std::towlower(matches[index][length])) != expected)
                {
                    same = false;
                    break;
                }
            }

            if (!same)
            {
                break;
            }

            ++length;
        }

        prefix = first.substr(0, length);
    } while (false);

    return prefix;
}

static void PrintCompletionMatches(const std::vector<std::wstring>& matches)
{
    std::lock_guard<std::recursive_mutex> lock(g_ConsoleOutputMutex);
    const size_t columnWidth = 18;
    size_t column = 0;

    std::wcout << L"\n";
    for (const std::wstring& match : matches)
    {
        std::wcout << L"  " << match;
        size_t used = match.size() + 2;
        while (used < columnWidth)
        {
            std::wcout << L" ";
            ++used;
        }

        ++column;
        if (column == 4)
        {
            std::wcout << L"\n";
            column = 0;
        }
    }

    if (column != 0)
    {
        std::wcout << L"\n";
    }
}

struct InteractiveRenderState
{
    HANDLE Output;
    bool ConsoleOutput;
    COORD Start;
    size_t RenderedLength;
};

class ScopedConsoleCursorVisibility
{
public:
    ScopedConsoleCursorVisibility(HANDLE handle, bool visible) :
        handle_(handle),
        oldInfo_(),
        active_(false)
    {
        do
        {
            if (handle_ == nullptr || handle_ == INVALID_HANDLE_VALUE)
            {
                break;
            }

            if (!GetConsoleCursorInfo(handle_, &oldInfo_))
            {
                break;
            }

            CONSOLE_CURSOR_INFO newInfo = oldInfo_;
            newInfo.bVisible = visible ? TRUE : FALSE;
            if (!SetConsoleCursorInfo(handle_, &newInfo))
            {
                break;
            }

            active_ = true;
        } while (false);
    }

    ~ScopedConsoleCursorVisibility()
    {
        if (active_)
        {
            SetConsoleCursorInfo(handle_, &oldInfo_);
        }
    }

private:
    HANDLE handle_;
    CONSOLE_CURSOR_INFO oldInfo_;
    bool active_;
};

static bool CaptureInteractiveRenderStart(InteractiveRenderState* render)
{
    bool captured = false;

    do
    {
        if (render == nullptr)
        {
            break;
        }

        render->Output = GetStdHandle(STD_OUTPUT_HANDLE);
        render->ConsoleOutput = false;
        render->Start = {};
        render->RenderedLength = 0;

        if (render->Output == nullptr || render->Output == INVALID_HANDLE_VALUE)
        {
            break;
        }

        DWORD mode = 0;
        if (!GetConsoleMode(render->Output, &mode))
        {
            break;
        }

        CONSOLE_SCREEN_BUFFER_INFO info = {};
        if (!GetConsoleScreenBufferInfo(render->Output, &info))
        {
            break;
        }

        render->ConsoleOutput = true;
        render->Start = info.dwCursorPosition;
        captured = true;
    } while (false);

    return captured;
}

static bool GetInteractiveConsolePosition(
    const InteractiveRenderState& render,
    size_t offset,
    COORD* position)
{
    bool ok = false;

    do
    {
        if (position == nullptr || !render.ConsoleOutput)
        {
            break;
        }

        CONSOLE_SCREEN_BUFFER_INFO info = {};
        if (!GetConsoleScreenBufferInfo(render.Output, &info) || info.dwSize.X <= 0)
        {
            break;
        }

        uint64_t absolute = static_cast<uint64_t>(render.Start.X) + static_cast<uint64_t>(offset);
        uint64_t rowOffset = absolute / static_cast<uint64_t>(info.dwSize.X);
        uint64_t y = static_cast<uint64_t>(render.Start.Y) + rowOffset;
        if (y > static_cast<uint64_t>(std::numeric_limits<SHORT>::max()))
        {
            break;
        }

        position->X = static_cast<SHORT>(absolute % static_cast<uint64_t>(info.dwSize.X));
        position->Y = static_cast<SHORT>(y);
        ok = true;
    } while (false);

    return ok;
}

static bool InteractiveConsolePositionEquals(
    const COORD& left,
    const COORD& right)
{
    return left.X == right.X && left.Y == right.Y;
}

static bool SetInteractiveConsoleCursor(
    const InteractiveRenderState& render,
    const std::wstring& prompt,
    size_t cursor)
{
    bool ok = false;

    do
    {
        COORD position = {};
        if (!GetInteractiveConsolePosition(render, prompt.size() + cursor, &position))
        {
            break;
        }

        ok = SetConsoleCursorPosition(render.Output, position) != FALSE;
    } while (false);

    return ok;
}

static bool TryRenderInteractiveAppendCharacter(
    const std::wstring& prompt,
    const std::wstring& line,
    size_t cursor,
    wchar_t ch,
    InteractiveRenderState* render)
{
    bool rendered = false;

    do
    {
        if (render == nullptr || !render->ConsoleOutput || cursor == 0 || cursor != line.size())
        {
            break;
        }

        size_t visibleLength = prompt.size() + line.size();
        if (render->RenderedLength + 1 != visibleLength)
        {
            break;
        }

        COORD expected = {};
        if (!GetInteractiveConsolePosition(*render, prompt.size() + cursor - 1, &expected))
        {
            break;
        }

        CONSOLE_SCREEN_BUFFER_INFO info = {};
        if (!GetConsoleScreenBufferInfo(render->Output, &info) ||
            !InteractiveConsolePositionEquals(info.dwCursorPosition, expected))
        {
            break;
        }

        std::lock_guard<std::recursive_mutex> lock(g_ConsoleOutputMutex);
        std::wcout << ch;
        std::wcout.flush();
        render->RenderedLength = visibleLength;
        rendered = true;
    } while (false);

    return rendered;
}

static bool TryRenderInteractiveEraseLastCharacter(
    const std::wstring& prompt,
    const std::wstring& line,
    size_t cursor,
    InteractiveRenderState* render)
{
    bool rendered = false;

    do
    {
        if (render == nullptr || !render->ConsoleOutput || cursor != line.size())
        {
            break;
        }

        size_t visibleLength = prompt.size() + line.size();
        if (render->RenderedLength != visibleLength + 1)
        {
            break;
        }

        COORD currentExpected = {};
        if (!GetInteractiveConsolePosition(*render, prompt.size() + cursor + 1, &currentExpected))
        {
            break;
        }

        CONSOLE_SCREEN_BUFFER_INFO info = {};
        if (!GetConsoleScreenBufferInfo(render->Output, &info) ||
            !InteractiveConsolePositionEquals(info.dwCursorPosition, currentExpected))
        {
            break;
        }

        COORD erasePosition = {};
        if (!GetInteractiveConsolePosition(*render, prompt.size() + cursor, &erasePosition))
        {
            break;
        }

        std::lock_guard<std::recursive_mutex> lock(g_ConsoleOutputMutex);
        if (!SetConsoleCursorPosition(render->Output, erasePosition))
        {
            break;
        }

        std::wcout << L" ";
        std::wcout.flush();
        SetConsoleCursorPosition(render->Output, erasePosition);
        render->RenderedLength = visibleLength;
        rendered = true;
    } while (false);

    return rendered;
}

static int ReadInteractiveInputKey(std::vector<int>* pendingKeys)
{
    int key = 0;

    do
    {
        if (pendingKeys != nullptr && !pendingKeys->empty())
        {
            key = pendingKeys->front();
            pendingKeys->erase(pendingKeys->begin());
            break;
        }

        key = _getwch();
    } while (false);

    return key;
}

static void PushInteractiveInputKey(std::vector<int>* pendingKeys, int key)
{
    if (pendingKeys != nullptr)
    {
        pendingKeys->insert(pendingKeys->begin(), key);
    }
}

static bool TryReadInteractiveInputKey(std::vector<int>* pendingKeys, int* key)
{
    static constexpr int kInputSequenceWaitAttempts = 50;
    bool ok = false;

    do
    {
        if (key == nullptr)
        {
            break;
        }

        if (pendingKeys != nullptr && !pendingKeys->empty())
        {
            *key = pendingKeys->front();
            pendingKeys->erase(pendingKeys->begin());
            ok = true;
            break;
        }

        for (int attempt = 0; attempt < kInputSequenceWaitAttempts; ++attempt)
        {
            if (_kbhit())
            {
                *key = _getwch();
                ok = true;
                break;
            }

            Sleep(1);
        }
    } while (false);

    return ok;
}

static bool MapVirtualTerminalLetterKey(int key, int* extended)
{
    bool mapped = true;

    do
    {
        if (extended == nullptr)
        {
            mapped = false;
            break;
        }

        switch (key)
        {
        case L'A':
            *extended = 72;
            break;
        case L'B':
            *extended = 80;
            break;
        case L'C':
            *extended = 77;
            break;
        case L'D':
            *extended = 75;
            break;
        case L'H':
            *extended = 71;
            break;
        case L'F':
            *extended = 79;
            break;
        default:
            mapped = false;
            break;
        }
    } while (false);

    return mapped;
}

static bool MapVirtualTerminalTildeKey(const std::wstring& parameters, int* extended)
{
    bool mapped = false;

    do
    {
        if (extended == nullptr || parameters.empty())
        {
            break;
        }

        size_t end = parameters.find(L';');
        std::wstring first = parameters.substr(0, end);
        uint64_t value = 0;
        if (!ParseUnsigned(first, 10, &value))
        {
            break;
        }

        if (value == 1 || value == 7)
        {
            *extended = 71;
            mapped = true;
        }
        else if (value == 3)
        {
            *extended = 83;
            mapped = true;
        }
        else if (value == 4 || value == 8)
        {
            *extended = 79;
            mapped = true;
        }
    } while (false);

    return mapped;
}

static bool TryReadVirtualTerminalExtendedKey(std::vector<int>* pendingKeys, int* extended)
{
    bool mapped = false;

    do
    {
        int introducer = 0;
        if (!TryReadInteractiveInputKey(pendingKeys, &introducer))
        {
            break;
        }

        if (introducer != L'[' && introducer != L'O')
        {
            PushInteractiveInputKey(pendingKeys, introducer);
            break;
        }

        int key = 0;
        if (!TryReadInteractiveInputKey(pendingKeys, &key))
        {
            break;
        }

        if (introducer == L'O')
        {
            mapped = MapVirtualTerminalLetterKey(key, extended);
            break;
        }

        if (MapVirtualTerminalLetterKey(key, extended))
        {
            mapped = true;
            break;
        }

        std::wstring parameters;
        int current = key;
        while (parameters.size() < 16)
        {
            parameters.push_back(static_cast<wchar_t>(current));

            if (current == L'~')
            {
                parameters.pop_back();
                mapped = MapVirtualTerminalTildeKey(parameters, extended);
                break;
            }

            if ((current >= L'A' && current <= L'Z') ||
                (current >= L'a' && current <= L'z'))
            {
                mapped = MapVirtualTerminalLetterKey(current, extended);
                break;
            }

            if (!TryReadInteractiveInputKey(pendingKeys, &current))
            {
                break;
            }
        }
    } while (false);

    return mapped;
}

static void ResetInteractiveRenderStart(InteractiveRenderState* render)
{
    do
    {
        if (render == nullptr)
        {
            break;
        }

        if (!render->ConsoleOutput)
        {
            render->RenderedLength = 0;
            break;
        }

        CONSOLE_SCREEN_BUFFER_INFO info = {};
        if (GetConsoleScreenBufferInfo(render->Output, &info))
        {
            render->Start = info.dwCursorPosition;
        }

        render->RenderedLength = 0;
    } while (false);
}

static void RenderInteractiveCommandLine(
    const std::wstring& prompt,
    const std::wstring& line,
    size_t cursor,
    InteractiveRenderState* render)
{
    std::lock_guard<std::recursive_mutex> lock(g_ConsoleOutputMutex);
    size_t visibleLength = prompt.size() + line.size();

    if (render != nullptr && render->ConsoleOutput)
    {
        ScopedConsoleCursorVisibility hiddenCursor(render->Output, false);
        if (SetConsoleCursorPosition(render->Output, render->Start))
        {
            PrintColoredText(prompt, KNDBG_COLOR_PROMPT);
            std::wcout << line;

            while (render->RenderedLength > visibleLength)
            {
                std::wcout << L" ";
                --render->RenderedLength;
            }

            std::wcout.flush();
            render->RenderedLength = visibleLength;
            SetInteractiveConsoleCursor(*render, prompt, cursor);
            return;
        }
    }

    size_t* renderedLength = render != nullptr ? &render->RenderedLength : nullptr;
    std::wcout << L"\r";
    PrintColoredText(prompt, KNDBG_COLOR_PROMPT);
    std::wcout << line;

    if (renderedLength != nullptr)
    {
        while (*renderedLength > visibleLength)
        {
            std::wcout << L" ";
            --(*renderedLength);
        }
    }

    std::wcout << L"\r";
    PrintColoredText(prompt, KNDBG_COLOR_PROMPT);
    if (cursor > 0)
    {
        std::wcout << line.substr(0, cursor);
    }

    std::wcout.flush();

    if (renderedLength != nullptr)
    {
        *renderedLength = visibleLength;
    }
}

struct InteractiveCompletionContext
{
    std::vector<std::wstring> ArgsBefore;
    std::wstring Prefix;
    size_t TokenStart;
    size_t TokenEnd;
};

static InteractiveCompletionContext BuildInteractiveCompletionContext(
    const std::wstring& line,
    size_t cursor)
{
    InteractiveCompletionContext context = {};
    context.TokenStart = cursor;
    context.TokenEnd = cursor;

    while (context.TokenStart > 0 && std::iswspace(line[context.TokenStart - 1]) == 0)
    {
        --context.TokenStart;
    }

    while (context.TokenEnd < line.size() && std::iswspace(line[context.TokenEnd]) == 0)
    {
        ++context.TokenEnd;
    }

    context.Prefix = line.substr(context.TokenStart, cursor - context.TokenStart);
    context.ArgsBefore = Split(line.substr(0, context.TokenStart));
    return context;
}

static bool ApplyInteractiveTabCompletion(std::wstring* line, size_t* cursor, bool* listed)
{
    bool changed = false;

    do
    {
        if (line == nullptr || cursor == nullptr)
        {
            break;
        }

        if (listed != nullptr)
        {
            *listed = false;
        }

        InteractiveCompletionContext context = BuildInteractiveCompletionContext(*line, *cursor);
        std::vector<std::wstring> candidates = BuildInteractiveCompletionCandidates(context.ArgsBefore);
        std::vector<std::wstring> matches = FilterCompletionCandidates(candidates, context.Prefix);
        if (matches.empty())
        {
            MessageBeep(MB_OK);
            break;
        }

        std::wstring replacement;
        bool appendSpace = false;
        if (matches.size() == 1)
        {
            replacement = matches[0];
            appendSpace = true;
        }
        else
        {
            replacement = LongestCommonCompletionPrefix(matches);
            if (replacement.size() <= context.Prefix.size())
            {
                PrintCompletionMatches(matches);
                if (listed != nullptr)
                {
                    *listed = true;
                }
                break;
            }
        }

        line->replace(context.TokenStart, context.TokenEnd - context.TokenStart, replacement);
        *cursor = context.TokenStart + replacement.size();
        if (appendSpace && *cursor == line->size())
        {
            line->insert(*cursor, L" ");
            ++(*cursor);
        }

        changed = true;
    } while (false);

    return changed;
}

static bool ReadInteractiveCommandLine(
    const std::wstring& prompt,
    const std::vector<std::wstring>& history,
    std::wstring* line)
{
    bool ok = false;

    do
    {
        if (line == nullptr)
        {
            break;
        }

        line->clear();
        HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
        DWORD mode = 0;
        bool consoleInput = input != nullptr &&
            input != INVALID_HANDLE_VALUE &&
            GetConsoleMode(input, &mode);

        InteractiveRenderState render = {};
        if (consoleInput)
        {
            CaptureInteractiveRenderStart(&render);
        }

        PrintColoredText(prompt, KNDBG_COLOR_PROMPT);
        render.RenderedLength = prompt.size();
        if (!consoleInput)
        {
            ok = static_cast<bool>(std::getline(std::wcin, *line));
            break;
        }

        size_t cursor = 0;
        size_t historyIndex = history.size();
        std::wstring historyDraft;
        bool hasHistoryDraft = false;

        auto resetHistoryNavigation = [&history, &historyIndex, &historyDraft, &hasHistoryDraft]()
        {
            historyIndex = history.size();
            historyDraft.clear();
            hasHistoryDraft = false;
        };

        auto moveInteractiveCursor = [&prompt, &line, &cursor, &render]()
        {
            if (!SetInteractiveConsoleCursor(render, prompt, cursor))
            {
                RenderInteractiveCommandLine(prompt, *line, cursor, &render);
            }
        };

        auto recallHistoryLine = [&prompt, &history, line, &cursor, &render, &historyIndex, &historyDraft, &hasHistoryDraft](bool older)
        {
            bool recalled = false;

            do
            {
                if (history.empty() || line == nullptr)
                {
                    MessageBeep(MB_OK);
                    break;
                }

                if (older)
                {
                    if (historyIndex == history.size())
                    {
                        historyDraft = *line;
                        hasHistoryDraft = true;
                        historyIndex = history.size() - 1;
                    }
                    else if (historyIndex > 0)
                    {
                        --historyIndex;
                    }
                    else
                    {
                        MessageBeep(MB_OK);
                        break;
                    }

                    *line = history[historyIndex];
                }
                else
                {
                    if (historyIndex >= history.size())
                    {
                        MessageBeep(MB_OK);
                        break;
                    }

                    if (historyIndex + 1 < history.size())
                    {
                        ++historyIndex;
                        *line = history[historyIndex];
                    }
                    else
                    {
                        historyIndex = history.size();
                        *line = hasHistoryDraft ? historyDraft : L"";
                    }
                }

                cursor = line->size();
                RenderInteractiveCommandLine(prompt, *line, cursor, &render);
                recalled = true;
            } while (false);

            return recalled;
        };

        auto handleExtendedKey = [&line, &cursor, &render, &prompt, &recallHistoryLine, &moveInteractiveCursor, &resetHistoryNavigation](int extended)
        {
            if (extended == 72)
            {
                recallHistoryLine(true);
            }
            else if (extended == 80)
            {
                recallHistoryLine(false);
            }
            else if (extended == 75)
            {
                if (cursor > 0)
                {
                    --cursor;
                    moveInteractiveCursor();
                }
            }
            else if (extended == 77)
            {
                if (cursor < line->size())
                {
                    ++cursor;
                    moveInteractiveCursor();
                }
            }
            else if (extended == 71)
            {
                cursor = 0;
                moveInteractiveCursor();
            }
            else if (extended == 79)
            {
                cursor = line->size();
                moveInteractiveCursor();
            }
            else if (extended == 83)
            {
                if (cursor < line->size())
                {
                    line->erase(cursor, 1);
                    resetHistoryNavigation();
                    RenderInteractiveCommandLine(prompt, *line, cursor, &render);
                }
            }
        };

        std::vector<int> pendingInputKeys;

        while (!g_StopRequested)
        {
            int key = ReadInteractiveInputKey(&pendingInputKeys);
            if (key == 0 || key == 0xe0)
            {
                int extended = ReadInteractiveInputKey(&pendingInputKeys);
                handleExtendedKey(extended);
                continue;
            }

            if (key == 27)
            {
                int extended = 0;
                if (TryReadVirtualTerminalExtendedKey(&pendingInputKeys, &extended))
                {
                    handleExtendedKey(extended);
                }
                continue;
            }

            if (key == L'\r' || key == L'\n')
            {
                std::wcout << L"\n";
                ok = true;
                break;
            }

            if (key == 3)
            {
                g_StopRequested = true;
                std::wcout << L"^C\n";
                break;
            }

            if (key == 26)
            {
                std::wcout << L"\n";
                break;
            }

            if (key == L'\t')
            {
                bool listed = false;
                bool changed = ApplyInteractiveTabCompletion(line, &cursor, &listed);
                if (listed)
                {
                    ResetInteractiveRenderStart(&render);
                    RenderInteractiveCommandLine(prompt, *line, cursor, &render);
                }
                else if (changed)
                {
                    resetHistoryNavigation();
                    RenderInteractiveCommandLine(prompt, *line, cursor, &render);
                }
                continue;
            }

            if (key == L'\b')
            {
                if (cursor > 0)
                {
                    bool eraseLastCharacter = cursor == line->size();
                    line->erase(cursor - 1, 1);
                    --cursor;
                    resetHistoryNavigation();
                    if (!eraseLastCharacter ||
                        !TryRenderInteractiveEraseLastCharacter(prompt, *line, cursor, &render))
                    {
                        RenderInteractiveCommandLine(prompt, *line, cursor, &render);
                    }
                }
                continue;
            }

            if (key >= 32 && key != 127)
            {
                wchar_t ch = static_cast<wchar_t>(key);
                bool appendCharacter = cursor == line->size();
                line->insert(cursor, 1, ch);
                ++cursor;
                resetHistoryNavigation();
                if (!appendCharacter ||
                    !TryRenderInteractiveAppendCharacter(prompt, *line, cursor, ch, &render))
                {
                    RenderInteractiveCommandLine(prompt, *line, cursor, &render);
                }
            }
        }
    } while (false);

    return ok;
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

static bool TrySubtractOffset(uint64_t address, uint64_t offset, uint64_t* result)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            break;
        }

        if (address < offset)
        {
            break;
        }

        *result = address - offset;
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

static bool HasTypeWildcard(const std::wstring& value)
{
    return value.find(L'*') != std::wstring::npos || value.find(L'?') != std::wstring::npos;
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
                *error = L"usage: dt [-rN] [-v] [-b] <module!type|type|module!type-pattern> [address|symbol] [field-filter...]";
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

static std::wstring FormatTypeMatchName(const TypeMatchInfo& match)
{
    std::wstring name = match.Name;

    do
    {
        if (name.find(L'!') != std::wstring::npos || match.ModuleName.empty())
        {
            break;
        }

        name = match.ModuleName + L"!" + name;
    } while (false);

    return name;
}

static void PrintDtTypeMatches(const DtRequest& request, const std::vector<TypeMatchInfo>& matches, size_t limit)
{
    for (const TypeMatchInfo& match : matches)
    {
        if (request.Bare)
        {
            std::wcout << match.Name << L"\n";
            continue;
        }

        PrintColoredText(FormatTypeMatchName(match), KNDBG_COLOR_TITLE);
        std::wcout << L" size=0x" << std::hex << match.Size << std::dec;

        if (request.Verbose)
        {
            std::wcout << L" moduleBase=0x" << std::hex << std::setw(16) << std::setfill(L'0') << match.ModuleBase
                       << std::setfill(L' ') << L" typeId=" << std::dec << match.TypeId;
        }

        std::wcout << L"\n";
    }

    if (limit != 0 && matches.size() >= limit)
    {
        PrintColoredText(L"type matches shown", KNDBG_COLOR_WARN);
        std::wcout << L"=" << matches.size() << L" limit=" << limit
                   << L" (narrow the pattern for more)\n";
    }
    else
    {
        PrintColoredText(L"type matches", KNDBG_COLOR_TITLE);
        std::wcout << L"=" << matches.size() << L"\n";
    }
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

        std::wcout << indentText;
        PrintColoredText(layout.Name, KNDBG_COLOR_TITLE);
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

        std::wstringstream offsetText;
        offsetText << L"+0x" << std::hex << std::setw(3) << std::setfill(L'0') << field.Offset;
        std::wcout << indentText << L"   ";
        PrintColoredText(offsetText.str(), KNDBG_COLOR_ACCENT);
        std::wcout << L" ";
        PrintColoredText(field.Name, KNDBG_COLOR_TITLE);

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

        if (HasTypeWildcard(request.TypeName))
        {
            if (request.HasAddress || !request.FieldFilters.empty())
            {
                std::wcerr << L"dt failed: wildcard type patterns list matching types only; use an exact type name to dump fields or values\n";
                break;
            }

            constexpr size_t typeMatchLimit = 512;
            std::vector<TypeMatchInfo> matches;
            if (!symbols.EnumerateTypes(request.TypeName, typeMatchLimit, &matches, &error))
            {
                std::wcerr << L"dt failed: " << error << L"\n";
                break;
            }

            PrintDtTypeMatches(request, matches, typeMatchLimit);
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

static void MarkKnownBytes(MemoryReadView* view, size_t offset, const std::vector<uint8_t>& bytes, size_t maxLength)
{
    if (view == nullptr)
    {
        return;
    }

    size_t copyLength = std::min(bytes.size(), maxLength);
    if (offset > view->Bytes.size())
    {
        return;
    }

    copyLength = std::min(copyLength, view->Bytes.size() - offset);
    for (size_t index = 0; index < copyLength; ++index)
    {
        view->Bytes[offset + index] = bytes[index];
        view->Valid[offset + index] = 1;
        view->AnyValid = true;
    }
}

static uint32_t PageBoundedReadChunk(uint64_t address, size_t offset, uint32_t length)
{
    uint32_t chunk = 0;

    do
    {
        if (offset >= length)
        {
            break;
        }

        uint64_t current = address + offset;
        size_t pageOffset = static_cast<size_t>(current & 0xfffull);
        size_t pageLeft = 0x1000ull - pageOffset;
        size_t remaining = static_cast<size_t>(length) - offset;
        chunk = static_cast<uint32_t>(std::min(pageLeft, remaining));
    } while (false);

    return chunk;
}

static bool ReadSparseVirtualMemory(
    DeviceClient& device,
    const DebuggerState& state,
    const ProcessAddressContext* explicitContext,
    uint64_t address,
    uint32_t length,
    MemoryReadView* view,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (view == nullptr || length == 0)
        {
            if (error != nullptr)
            {
                *error = L"invalid sparse read request";
            }
            break;
        }

        if (!device.IsOpen())
        {
            if (error != nullptr)
            {
                *error = L"driver device is not open";
            }
            break;
        }

        view->Bytes.assign(length, 0);
        view->Valid.assign(length, 0);
        view->AnyValid = false;

        size_t offset = 0;
        while (offset < length)
        {
            uint32_t chunk = PageBoundedReadChunk(address, offset, length);
            if (chunk == 0)
            {
                break;
            }

            std::vector<uint8_t> chunkBytes;
            std::wstring ignored;
            if (ReadMemoryWithProcessContext(device, state, explicitContext, address + offset, chunk, &chunkBytes, &ignored))
            {
                MarkKnownBytes(view, offset, chunkBytes, chunk);
                if (chunkBytes.size() >= chunk)
                {
                    offset += chunk;
                }
                else if (!chunkBytes.empty())
                {
                    offset += chunkBytes.size();
                }
                else
                {
                    offset += chunk;
                }
                continue;
            }

            std::vector<uint8_t> firstByte;
            if (!ReadMemoryWithProcessContext(device, state, explicitContext, address + offset, 1, &firstByte, &ignored) ||
                firstByte.size() != 1)
            {
                offset += chunk;
                continue;
            }

            MarkKnownBytes(view, offset, firstByte, 1);
            for (uint32_t lineOffset = 0; lineOffset < chunk; lineOffset += 16)
            {
                uint32_t lineLength = std::min<uint32_t>(16, chunk - lineOffset);
                std::vector<uint8_t> lineBytes;
                if (ReadMemoryWithProcessContext(device, state, explicitContext, address + offset + lineOffset, lineLength, &lineBytes, &ignored))
                {
                    MarkKnownBytes(view, offset + lineOffset, lineBytes, lineLength);
                    continue;
                }

                for (uint32_t index = 0; index < lineLength; ++index)
                {
                    std::vector<uint8_t> byte;
                    if (ReadMemoryWithProcessContext(device, state, explicitContext, address + offset + lineOffset + index, 1, &byte, &ignored) &&
                        byte.size() == 1)
                    {
                        MarkKnownBytes(view, offset + lineOffset + index, byte, 1);
                    }
                }
            }

            offset += chunk;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool ReadSparsePhysicalMemory(
    DeviceClient& device,
    uint64_t physicalAddress,
    uint32_t length,
    MemoryReadView* view,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (view == nullptr || length == 0)
        {
            if (error != nullptr)
            {
                *error = L"invalid sparse physical read request";
            }
            break;
        }

        if (!device.IsOpen())
        {
            if (error != nullptr)
            {
                *error = L"driver device is not open";
            }
            break;
        }

        view->Bytes.assign(length, 0);
        view->Valid.assign(length, 0);
        view->AnyValid = false;

        size_t offset = 0;
        while (offset < length)
        {
            uint32_t chunk = PageBoundedReadChunk(physicalAddress, offset, length);
            if (chunk == 0)
            {
                break;
            }

            std::vector<uint8_t> chunkBytes;
            std::wstring ignored;
            if (device.ReadPhysical(physicalAddress + offset, chunk, &chunkBytes, &ignored))
            {
                MarkKnownBytes(view, offset, chunkBytes, chunk);
                if (chunkBytes.size() >= chunk)
                {
                    offset += chunk;
                }
                else if (!chunkBytes.empty())
                {
                    offset += chunkBytes.size();
                }
                else
                {
                    offset += chunk;
                }
                continue;
            }

            std::vector<uint8_t> firstByte;
            if (!device.ReadPhysical(physicalAddress + offset, 1, &firstByte, &ignored) ||
                firstByte.size() != 1)
            {
                offset += chunk;
                continue;
            }

            MarkKnownBytes(view, offset, firstByte, 1);
            for (uint32_t lineOffset = 0; lineOffset < chunk; lineOffset += 16)
            {
                uint32_t lineLength = std::min<uint32_t>(16, chunk - lineOffset);
                std::vector<uint8_t> lineBytes;
                if (device.ReadPhysical(physicalAddress + offset + lineOffset, lineLength, &lineBytes, &ignored))
                {
                    MarkKnownBytes(view, offset + lineOffset, lineBytes, lineLength);
                    continue;
                }

                for (uint32_t index = 0; index < lineLength; ++index)
                {
                    std::vector<uint8_t> byte;
                    if (device.ReadPhysical(physicalAddress + offset + lineOffset + index, 1, &byte, &ignored) &&
                        byte.size() == 1)
                    {
                        MarkKnownBytes(view, offset + lineOffset + index, byte, 1);
                    }
                }
            }

            offset += chunk;
        }

        ok = true;
    } while (false);

    return ok;
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
            std::wcerr << L"usage: " << command << L" [/process <process-id>] <address|symbol> [count]\n";
            break;
        }

        size_t argIndex = 1;
        ProcessAddressContext explicitContext = {};
        bool hasExplicitContext = false;
        if (IsDeprecatedProcessContextOption(args[argIndex]))
        {
            std::wcerr << L"usage: " << command << L" [/process <process-id>] <address|symbol> [count]\n";
            break;
        }

        if (IsProcessContextOption(args[argIndex]))
        {
            if (args.size() < 4)
            {
                std::wcerr << L"usage: " << command << L" /process <process-id> <address|symbol> [count]\n";
                break;
            }

            uint64_t processId = 0;
            if (!ParseUnsigned(args[argIndex + 1], 10, &processId) || processId == 0 || processId > 0xffffffffull)
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

        MemoryReadView memory;
        const ProcessAddressContext* memoryContext = hasExplicitContext ? &explicitContext : nullptr;
        if (!ReadSparseVirtualMemory(device, state, memoryContext, address, byteCount, &memory, &error))
        {
            std::wcerr << L"read failed: " << error << L"\n";
            break;
        }

        if (command == L"d" || command == L"db" || command == L"dyb")
        {
            HexDump(address, memory);
        }
        else if (command == L"da" || command == L"ds")
        {
            PrintAsciiString(address, memory);
        }
        else if (command == L"du")
        {
            PrintUnicodeString(address, memory);
        }
        else if (command == L"dds" || command == L"dps" || command == L"dqs")
        {
            UnitDump(address, memory, unit, &symbols);
        }
        else if (command.size() == 3 && command[0] == L'd' &&
                 (command[2] == L'a' || command[2] == L'p' || command[2] == L'u'))
        {
            for (size_t offset = 0; offset + unit <= memory.Bytes.size(); offset += unit)
            {
                std::wcout << L"0x" << std::hex << (address + offset) << L": ";
                if (!MemoryRangeIsKnown(memory, offset, unit))
                {
                    std::wcout << UnknownHexText(unit, true) << L" <unreadable>\n";
                    continue;
                }

                uint64_t pointer = DecodeInteger(memory.Bytes.data() + offset, unit);
                std::wcout << L"0x" << pointer << L" ";

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
            UnitDump(address, memory, unit, nullptr);
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

static bool EnsureKernelProcessAddressContext(
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    ProcessAddressContext* context,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (context == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid kernel process context output";
            }
            break;
        }

        if (state.HasKernelProcessContext)
        {
            *context = state.KernelProcessContext;
            ok = true;
            break;
        }

        ProcessAddressContext resolved = {};
        if (!ResolveProcessAddressContext(device, symbols, KNDBG_SYSTEM_PROCESS_ID, &resolved, error))
        {
            break;
        }

        state.KernelProcessContext = resolved;
        state.HasKernelProcessContext = true;
        *context = state.KernelProcessContext;
        ok = true;
    } while (false);

    return ok;
}

static bool IsLikelyUserVirtualAddress(uint64_t virtualAddress)
{
    return virtualAddress < 0x0000800000000000ull;
}

static bool IsLikelyKernelVirtualAddress(uint64_t virtualAddress)
{
    return virtualAddress >= 0xff00000000000000ull;
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
    PrintColoredText(L"pid", KNDBG_COLOR_ACCENT);
    std::wcout << L"=" << context.ProcessId << L" ";
    PrintColoredText(L"eprocess", KNDBG_COLOR_ACCENT);
    std::wcout << L"=" << HexTextWidth(context.Eprocess, 16, true) << L" ";
    PrintColoredText(L"dtb", KNDBG_COLOR_ACCENT);
    std::wcout << L"=" << HexTextWidth(context.DirectoryTableBase, 16, true);
    if (context.UserDirectoryTableBase != 0)
    {
        std::wcout << L" ";
        PrintColoredText(L"user-dtb", KNDBG_COLOR_ACCENT);
        std::wcout << L"=" << HexTextWidth(context.UserDirectoryTableBase, 16, true);
    }
    std::wcout << std::dec << L"\n";
}

struct DmlProcessLayout
{
    TypeFieldInfo ActiveProcessLinks = {};
    TypeFieldInfo UniqueProcessId = {};
    TypeFieldInfo ImageFileName = {};
    TypeFieldInfo InheritedFromUniqueProcessId = {};
    TypeFieldInfo ActiveThreads = {};
    TypeFieldInfo Peb = {};
    TypeFieldInfo CreateTime = {};
    uint32_t DirectoryTableBaseOffset = 0;
    uint32_t UserDirectoryTableBaseOffset = 0;
    bool HasInheritedFromUniqueProcessId = false;
    bool HasActiveThreads = false;
    bool HasPeb = false;
    bool HasCreateTime = false;
};

struct DmlProcessRecord
{
    uint64_t Eprocess = 0;
    uint64_t ListEntry = 0;
    uint64_t Flink = 0;
    uint64_t Blink = 0;
    uint64_t ProcessId = 0;
    uint64_t ParentProcessId = 0;
    uint64_t DirectoryTableBase = 0;
    uint64_t UserDirectoryTableBase = 0;
    uint64_t Peb = 0;
    uint64_t CreateTime = 0;
    uint32_t ActiveThreads = 0;
    std::wstring ImageName;
    bool HasParentProcessId = false;
    bool HasActiveThreads = false;
    bool HasPeb = false;
    bool HasCreateTime = false;
};

static bool ReadKernelBytes(
    DeviceClient& device,
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
                *error = L"invalid kernel read request";
            }
            break;
        }

        if (!device.ReadMemory(address, length, bytes, error))
        {
            break;
        }

        if (bytes->size() != length)
        {
            if (error != nullptr)
            {
                *error = L"short kernel read";
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool ReadKernelInteger(
    DeviceClient& device,
    uint64_t address,
    size_t width,
    uint64_t* value,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (value == nullptr || width == 0 || width > sizeof(uint64_t))
        {
            if (error != nullptr)
            {
                *error = L"invalid integer read request";
            }
            break;
        }

        std::vector<uint8_t> bytes;
        if (!ReadKernelBytes(device, address, static_cast<uint32_t>(width), &bytes, error))
        {
            break;
        }

        *value = DecodeInteger(bytes.data(), width);
        ok = true;
    } while (false);

    return ok;
}

static size_t FieldReadWidth(const TypeFieldInfo& field, size_t fallbackWidth)
{
    size_t width = fallbackWidth;

    if (field.Length > 0 && field.Length <= sizeof(uint64_t))
    {
        width = static_cast<size_t>(field.Length);
    }

    return width;
}

static bool ReadKernelFieldInteger(
    DeviceClient& device,
    uint64_t base,
    const TypeFieldInfo& field,
    size_t fallbackWidth,
    uint64_t* value,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        uint64_t fieldAddress = 0;
        if (!TryAddOffset(base, field.Offset, &fieldAddress))
        {
            if (error != nullptr)
            {
                *error = L"field address overflow";
            }
            break;
        }

        if (!ReadKernelInteger(device, fieldAddress, FieldReadWidth(field, fallbackWidth), value, error))
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool ReadKernelPointer(DeviceClient& device, uint64_t address, uint64_t* value, std::wstring* error)
{
    return ReadKernelInteger(device, address, sizeof(uint64_t), value, error);
}

static bool ResolveDmlProcessLayout(SymbolEngine& symbols, DmlProcessLayout* layout, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (layout == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid dml process layout output";
            }
            break;
        }

        *layout = DmlProcessLayout{};

        if (!FindFieldAny(symbols, {L"nt!_EPROCESS", L"_EPROCESS"}, L"ActiveProcessLinks", &layout->ActiveProcessLinks, error))
        {
            break;
        }

        if (!FindFieldAny(symbols, {L"nt!_EPROCESS", L"_EPROCESS"}, L"UniqueProcessId", &layout->UniqueProcessId, error))
        {
            break;
        }

        std::wstring ignored;
        FindFieldAny(symbols, {L"nt!_EPROCESS", L"_EPROCESS"}, L"ImageFileName", &layout->ImageFileName, &ignored);
        layout->HasInheritedFromUniqueProcessId =
            FindFieldAny(symbols, {L"nt!_EPROCESS", L"_EPROCESS"}, L"InheritedFromUniqueProcessId", &layout->InheritedFromUniqueProcessId, &ignored);
        layout->HasActiveThreads =
            FindFieldAny(symbols, {L"nt!_EPROCESS", L"_EPROCESS"}, L"ActiveThreads", &layout->ActiveThreads, &ignored);
        layout->HasPeb =
            FindFieldAny(symbols, {L"nt!_EPROCESS", L"_EPROCESS"}, L"Peb", &layout->Peb, &ignored);
        layout->HasCreateTime =
            FindFieldAny(symbols, {L"nt!_EPROCESS", L"_EPROCESS"}, L"CreateTime", &layout->CreateTime, &ignored);

        if (!ResolveProcessDirectoryTableBaseOffsets(symbols, &layout->DirectoryTableBaseOffset, &layout->UserDirectoryTableBaseOffset, error))
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static std::wstring ReadDmlProcessImageName(
    DeviceClient& device,
    uint64_t eprocess,
    const TypeFieldInfo& field)
{
    std::wstring result = L"<unknown>";

    do
    {
        if (field.Name.empty())
        {
            break;
        }

        uint64_t fieldAddress = 0;
        if (!TryAddOffset(eprocess, field.Offset, &fieldAddress))
        {
            break;
        }

        size_t length = static_cast<size_t>(field.Length);
        if (length == 0 || length > 64)
        {
            length = 16;
        }

        std::vector<uint8_t> bytes;
        std::wstring ignored;
        if (!ReadKernelBytes(device, fieldAddress, static_cast<uint32_t>(length), &bytes, &ignored))
        {
            break;
        }

        std::wstring name;
        for (uint8_t byte : bytes)
        {
            if (byte == 0)
            {
                break;
            }

            if (byte < 32 || byte > 126)
            {
                name.push_back(L'.');
            }
            else
            {
                name.push_back(static_cast<wchar_t>(byte));
            }
        }

        if (!name.empty())
        {
            result = name;
        }
    } while (false);

    return result;
}

static bool ReadDmlProcessRecord(
    DeviceClient& device,
    const DmlProcessLayout& layout,
    uint64_t eprocess,
    DmlProcessRecord* record,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (record == nullptr || eprocess == 0)
        {
            if (error != nullptr)
            {
                *error = L"invalid EPROCESS address";
            }
            break;
        }

        *record = DmlProcessRecord{};
        record->Eprocess = eprocess;

        if (!TryAddOffset(eprocess, layout.ActiveProcessLinks.Offset, &record->ListEntry))
        {
            if (error != nullptr)
            {
                *error = L"ActiveProcessLinks address overflow";
            }
            break;
        }

        if (!ReadKernelPointer(device, record->ListEntry, &record->Flink, error))
        {
            break;
        }

        uint64_t blinkAddress = 0;
        if (!TryAddOffset(record->ListEntry, sizeof(uint64_t), &blinkAddress))
        {
            if (error != nullptr)
            {
                *error = L"Blink address overflow";
            }
            break;
        }

        if (!ReadKernelPointer(device, blinkAddress, &record->Blink, error))
        {
            break;
        }

        if (!IsLikelyKernelVirtualAddress(record->Flink) ||
            !IsLikelyKernelVirtualAddress(record->Blink))
        {
            if (error != nullptr)
            {
                *error = L"ActiveProcessLinks contains a non-kernel list pointer";
            }
            break;
        }

        if (!ReadKernelFieldInteger(device, eprocess, layout.UniqueProcessId, sizeof(uint64_t), &record->ProcessId, error))
        {
            break;
        }

        if (record->ProcessId > 0xffffffffull)
        {
            if (error != nullptr)
            {
                *error = L"UniqueProcessId is outside the expected 32-bit PID range";
            }
            break;
        }

        if (layout.HasInheritedFromUniqueProcessId)
        {
            record->HasParentProcessId =
                ReadKernelFieldInteger(
                    device,
                    eprocess,
                    layout.InheritedFromUniqueProcessId,
                    sizeof(uint64_t),
                    &record->ParentProcessId,
                    nullptr);
        }

        if (layout.HasActiveThreads)
        {
            uint64_t activeThreads = 0;
            if (ReadKernelFieldInteger(device, eprocess, layout.ActiveThreads, sizeof(uint32_t), &activeThreads, nullptr))
            {
                record->ActiveThreads = static_cast<uint32_t>(activeThreads);
                record->HasActiveThreads = true;
            }
        }

        if (layout.HasPeb)
        {
            record->HasPeb =
                ReadKernelFieldInteger(device, eprocess, layout.Peb, sizeof(uint64_t), &record->Peb, nullptr);
        }

        if (layout.HasCreateTime)
        {
            record->HasCreateTime =
                ReadKernelFieldInteger(device, eprocess, layout.CreateTime, sizeof(uint64_t), &record->CreateTime, nullptr);
        }

        uint64_t directoryTableBaseAddress = 0;
        if (TryAddOffset(eprocess, layout.DirectoryTableBaseOffset, &directoryTableBaseAddress))
        {
            ReadKernelInteger(device, directoryTableBaseAddress, sizeof(uint64_t), &record->DirectoryTableBase, nullptr);
        }

        if (layout.UserDirectoryTableBaseOffset != 0)
        {
            uint64_t userDirectoryTableBaseAddress = 0;
            if (TryAddOffset(eprocess, layout.UserDirectoryTableBaseOffset, &userDirectoryTableBaseAddress))
            {
                ReadKernelInteger(device, userDirectoryTableBaseAddress, sizeof(uint64_t), &record->UserDirectoryTableBase, nullptr);
            }
        }

        record->DirectoryTableBase &= KNDBG_X64_PTE_4K_BASE_MASK;
        record->UserDirectoryTableBase &= KNDBG_X64_PTE_4K_BASE_MASK;
        record->ImageName = ReadDmlProcessImageName(device, eprocess, layout.ImageFileName);
        ok = true;
    } while (false);

    return ok;
}

static void PrintDmlProcessRecord(const DmlProcessRecord& record)
{
    PrintColoredText(HexTextWidth(record.Eprocess, 16, true), KNDBG_COLOR_ACCENT);
    std::wcout << L" ";
    std::wcout << std::setw(6) << std::dec << record.ProcessId << L" ";

    if (record.HasParentProcessId)
    {
        std::wcout << std::setw(6) << record.ParentProcessId << L" ";
    }
    else
    {
        std::wcout << std::setw(6) << L"?" << L" ";
    }

    if (record.HasActiveThreads)
    {
        std::wcout << std::setw(5) << record.ActiveThreads << L" ";
    }
    else
    {
        std::wcout << std::setw(5) << L"?" << L" ";
    }

    PrintColoredText(HexTextWidth(record.DirectoryTableBase, 16, true), KNDBG_COLOR_TITLE);
    std::wcout << L" ";
    std::wcout << std::left << std::setw(18) << record.ImageName << std::right;
    std::wcout << L" ";
    PrintColoredText(L"dt", KNDBG_COLOR_DIM);
    std::wcout << L"=dt nt!_EPROCESS " << HexTextWidth(record.Eprocess, 16, true);
    std::wcout << L"\n";
}

static void PrintDmlProcessHeader()
{
    PrintColoredText(L"EPROCESS", KNDBG_COLOR_TITLE);
    std::wcout << L"             ";
    PrintColoredText(L"PID", KNDBG_COLOR_TITLE);
    std::wcout << L"   ";
    PrintColoredText(L"PPID", KNDBG_COLOR_TITLE);
    std::wcout << L"  ";
    PrintColoredText(L"Thrd", KNDBG_COLOR_TITLE);
    std::wcout << L"  ";
    PrintColoredText(L"DirBase", KNDBG_COLOR_TITLE);
    std::wcout << L"           ";
    PrintColoredText(L"Image", KNDBG_COLOR_TITLE);
    std::wcout << L"\n";
}

static bool DmlProcessAlreadyVisited(const std::vector<uint64_t>& visited, uint64_t entry)
{
    return std::find(visited.begin(), visited.end(), entry) != visited.end();
}

static bool DmlProcessMatchesFilter(
    const DmlProcessRecord& record,
    bool hasPidFilter,
    uint64_t pidFilter,
    const std::wstring& nameFilter)
{
    if (hasPidFilter)
    {
        return record.ProcessId == pidFilter;
    }

    if (!nameFilter.empty())
    {
        // Case-insensitive substring match against the image name.
        return ToLower(record.ImageName).find(ToLower(nameFilter)) != std::wstring::npos;
    }

    return true;
}

static bool ParseDmlProcessPidFilter(const std::wstring& value, uint64_t* pid)
{
    bool ok = false;

    do
    {
        if (pid == nullptr || value.empty() || IsSwitchLikeToken(value))
        {
            break;
        }

        bool decimalOnly = true;
        for (wchar_t ch : value)
        {
            if (ch < L'0' || ch > L'9')
            {
                decimalOnly = false;
                break;
            }
        }

        if (!decimalOnly)
        {
            break;
        }

        uint64_t parsed = 0;
        if (!ParseUnsigned(value, 10, &parsed) || parsed > 0xffffffffull)
        {
            break;
        }

        *pid = parsed;
        ok = true;
    } while (false);

    return ok;
}

struct DmlProcessCollection
{
    std::vector<DmlProcessRecord> Records;
    std::vector<std::wstring> Warnings;
    size_t ScannedCount = 0;
    bool Truncated = false;
};

static bool CollectDmlProcessRecords(
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    DmlProcessCollection* output,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (output == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid process collection output";
            }
            break;
        }

        *output = DmlProcessCollection{};

        DmlProcessLayout layout = {};
        if (!ResolveDmlProcessLayout(symbols, &layout, error))
        {
            break;
        }

        ProcessAddressContext systemContext = {};
        if (!EnsureKernelProcessAddressContext(state, device, symbols, &systemContext, error))
        {
            break;
        }

        uint64_t systemListEntry = 0;
        if (!TryAddOffset(systemContext.Eprocess, layout.ActiveProcessLinks.Offset, &systemListEntry))
        {
            if (error != nullptr)
            {
                *error = L"ActiveProcessLinks address overflow";
            }
            break;
        }

        uint64_t listHead = 0;
        std::wstring ignored;
        bool hasGlobalHead = symbols.ResolveSymbol(L"nt!PsActiveProcessHead", &listHead, &ignored);

        uint64_t current = 0;
        constexpr size_t maxProcessRecords = 4096;
        std::vector<uint64_t> visited;

        if (hasGlobalHead)
        {
            if (!ReadKernelPointer(device, listHead, &current, error))
            {
                break;
            }

            visited.push_back(listHead);
        }
        else
        {
            DmlProcessRecord systemRecord = {};
            if (!ReadDmlProcessRecord(device, layout, systemContext.Eprocess, &systemRecord, error))
            {
                break;
            }

            output->Records.push_back(systemRecord);
            current = systemRecord.Flink;
            output->ScannedCount = 1;
            listHead = systemListEntry;
            visited.push_back(systemListEntry);
        }

        while (current != 0 && current != listHead && output->ScannedCount < maxProcessRecords)
        {
            if (DmlProcessAlreadyVisited(visited, current))
            {
                output->Warnings.push_back(L"loop detected at " + HexTextWidth(current, 16, true));
                break;
            }

            visited.push_back(current);

            uint64_t eprocess = 0;
            if (!TrySubtractOffset(current, layout.ActiveProcessLinks.Offset, &eprocess))
            {
                output->Warnings.push_back(L"list entry underflow at " + HexTextWidth(current, 16, true));
                break;
            }

            DmlProcessRecord record = {};
            std::wstring readError;
            if (ReadDmlProcessRecord(device, layout, eprocess, &record, &readError))
            {
                output->Records.push_back(record);
                ++output->ScannedCount;
                current = record.Flink;
            }
            else
            {
                if (!hasGlobalHead)
                {
                    uint64_t hiddenHeadFlink = 0;
                    if (ReadKernelPointer(device, current, &hiddenHeadFlink, nullptr) &&
                        IsLikelyKernelVirtualAddress(hiddenHeadFlink))
                    {
                        if (hiddenHeadFlink == systemListEntry)
                        {
                            break;
                        }

                        if (!DmlProcessAlreadyVisited(visited, hiddenHeadFlink))
                        {
                            current = hiddenHeadFlink;
                            continue;
                        }
                    }
                }

                output->Warnings.push_back(
                    L"failed to read EPROCESS " + HexTextWidth(eprocess, 16, true) + L": " + readError);
                break;
            }
        }

        if (output->ScannedCount >= maxProcessRecords)
        {
            output->Truncated = true;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool BuildSnapshotProcessInventory(
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    std::vector<SnapshotProcessRecord>* processes,
    std::vector<std::wstring>* warnings,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (processes == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid process inventory output";
            }
            break;
        }

        processes->clear();
        DmlProcessCollection collection = {};
        if (!CollectDmlProcessRecords(state, device, symbols, &collection, error))
        {
            break;
        }

        if (warnings != nullptr)
        {
            warnings->insert(warnings->end(), collection.Warnings.begin(), collection.Warnings.end());
            if (collection.Truncated)
            {
                warnings->push_back(L"process inventory was truncated");
            }
        }

        for (const DmlProcessRecord& record : collection.Records)
        {
            SnapshotProcessRecord process = {};
            process.ProcessId = static_cast<uint32_t>(record.ProcessId);
            process.Eprocess = record.Eprocess;
            process.DirectoryTableBase = record.DirectoryTableBase;
            process.UserDirectoryTableBase = record.UserDirectoryTableBase;
            process.Peb = record.Peb;
            process.HasPeb = record.HasPeb;
            process.CreateTime = record.CreateTime;
            process.HasCreateTime = record.HasCreateTime;
            process.ImageName = record.ImageName;
            process.Identity = BuildSnapshotProcessIdentity(process, warnings);
            processes->push_back(std::move(process));
        }

        ok = true;
    } while (false);

    return ok;
}

static std::wstring BuildSnapshotDefaultPath(
    const std::wstring& subdirectory,
    const std::wstring& timestamp,
    const std::wstring& label,
    const std::wstring& suffix)
{
    std::wstring safeLabel = SnapshotSafeFileComponent(label);
    std::wstring path = GetExecutableDirectory();
    path += L"\\.kn-live-dbg\\";
    path += subdirectory;
    path += L"\\";
    path += SnapshotSafeFileComponent(timestamp);
    path += L"-";
    path += safeLabel;
    path += suffix;
    return path;
}

static bool CaptureSnapshotForCommand(
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    const std::wstring& label,
    bool captureVadDkom,
    bool allowByovdAutoUpdate,
    const SnapshotDocument* baselineForVadDkom,
    SnapshotDocument* document,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (document == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid snapshot output";
            }
            break;
        }

        std::vector<SnapshotProcessRecord> processes;
        std::vector<std::wstring> processWarnings;
        if (!BuildSnapshotProcessInventory(state, device, symbols, &processes, &processWarnings, error))
        {
            break;
        }

        SnapshotCaptureOptions options = {};
        options.Label = label;
        options.ExecutableDirectory = GetExecutableDirectory();
        options.IncludeAll = true;
        options.AllowByovdAutoUpdate = allowByovdAutoUpdate;
        options.CaptureVadDkomForNewProcesses = captureVadDkom;
        options.BaselineForVadDkom = baselineForVadDkom;
        options.Processes = std::move(processes);

        SnapshotCollector collector(device, symbols);
        if (!collector.Capture(options, document, error))
        {
            break;
        }

        if (!processWarnings.empty())
        {
            document->DomainWarnings[L"process"].insert(
                document->DomainWarnings[L"process"].end(),
                processWarnings.begin(),
                processWarnings.end());
        }

        ok = true;
    } while (false);

    return ok;
}

static void PrintSnapshotHelp()
{
    std::wcout << L"!snapshot command:\n";
    std::wcout << L"  !snapshot baseline [/all] [/name <label>]\n";
    std::wcout << L"  !snapshot save <path> [/all] [/name <label>]\n";
    std::wcout << L"  !snapshot show [baseline|<path>] [/domains] [/warnings]\n";
    std::wcout << L"\n";
    std::wcout << L"description:\n";
    std::wcout << L"  Captures same-boot evidence snapshots over native scanners and stores a\n";
    std::wcout << L"  session baseline in memory plus JSON and Markdown files under .kn-live-dbg.\n";
    std::wcout << L"  Baseline captures process inventory; VAD DKOM hidden-PTE scans run during\n";
    std::wcout << L"  !diff baseline for processes newly present since the baseline.\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  !snapshot baseline /name clean-boot\n";
    std::wcout << L"  !snapshot save .\\after-game.json /name after-game\n";
    std::wcout << L"  !snapshot show baseline /warnings\n";
}

static void PrintDiffHelp()
{
    std::wcout << L"!diff command:\n";
    std::wcout << L"  !diff baseline [/summary] [/details] [/domain <name>] [/risk high|all] [/limit <n>]\n";
    std::wcout << L"  !diff <old.json> <new.json> [/summary] [/details] [/domain <name>] [/risk high|all] [/limit <n>]\n";
    std::wcout << L"\n";
    std::wcout << L"description:\n";
    std::wcout << L"  Compares snapshots with new-focused semantics: records absent from baseline\n";
    std::wcout << L"  but present now, plus high-risk escalations. !diff baseline captures a fresh\n";
    std::wcout << L"  current snapshot, scans VAD DKOM for newly live processes, writes JSON and\n";
    std::wcout << L"  a Markdown diff report, then prints compact domain summaries.\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  !diff baseline\n";
    std::wcout << L"  !diff baseline /domain pool /limit 20\n";
    std::wcout << L"  !diff .\\clean.json .\\after.json /risk high\n";
}

static bool ParseSnapshotNameOption(
    const std::vector<std::wstring>& args,
    size_t start,
    std::wstring* label,
    bool* parseError)
{
    bool ok = false;

    do
    {
        if (label == nullptr || parseError == nullptr)
        {
            break;
        }

        *parseError = false;
        size_t index = start;
        while (index < args.size())
        {
            std::wstring option = ToLower(args[index]);
            if (option == L"/all")
            {
                ++index;
                continue;
            }
            if (option == L"/name")
            {
                if (index + 1 >= args.size())
                {
                    std::wcerr << L"!snapshot: /name requires a label\n";
                    *parseError = true;
                    break;
                }
                *label = args[index + 1];
                index += 2;
                continue;
            }

            std::wcerr << L"!snapshot: unrecognised option \"" << args[index] << L"\"\n";
            *parseError = true;
            break;
        }

        ok = !*parseError;
    } while (false);

    return ok;
}

static bool FinalizeAndWriteSnapshot(
    SnapshotDocument* document,
    const std::wstring& jsonPath,
    const std::wstring& reportPath,
    bool printSummary)
{
    bool ok = false;
    std::wstring error;

    do
    {
        if (document == nullptr)
        {
            break;
        }

        document->JsonPath = jsonPath;
        document->ReportPath = reportPath;

        if (!WriteSnapshotJsonFile(jsonPath, *document, &error))
        {
            std::wcerr << L"!snapshot json failed: " << error << L"\n";
            break;
        }

        if (!WriteSnapshotTextFile(reportPath, BuildSnapshotBaselineMarkdown(*document), &error))
        {
            std::wcerr << L"!snapshot report failed: " << error << L"\n";
            break;
        }

        if (printSummary)
        {
            PrintSnapshotSummary(*document, true, false);
        }

        ok = true;
    } while (false);

    return ok;
}

static void HandleSnapshotCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    std::wstring error;

    do
    {
        if (args.size() < 2 || HasHelpToken(args, 1))
        {
            PrintSnapshotHelp();
            break;
        }

        std::wstring action = ToLower(args[1]);
        if (action == L"show")
        {
            bool domains = true;
            bool warnings = false;
            bool parseError = false;
            std::wstring target = L"baseline";
            size_t index = 2;
            if (index < args.size() && args[index][0] != L'/')
            {
                target = args[index];
                ++index;
            }
            while (index < args.size())
            {
                std::wstring option = ToLower(args[index]);
                if (option == L"/domains")
                {
                    domains = true;
                }
                else if (option == L"/warnings")
                {
                    warnings = true;
                }
                else
                {
                    std::wcerr << L"!snapshot show: unrecognised option \"" << args[index] << L"\"\n";
                    parseError = true;
                    break;
                }
                ++index;
            }
            if (parseError)
            {
                break;
            }

            if (ToLower(target) == L"baseline")
            {
                if (!state.HasSnapshotBaseline)
                {
                    std::wcerr << L"!snapshot show: no session baseline captured\n";
                    break;
                }
                PrintSnapshotSummary(state.SnapshotBaseline, domains, warnings);
            }
            else
            {
                SnapshotDocument document = {};
                if (!ReadSnapshotJsonFile(target, &document, &error))
                {
                    std::wcerr << L"!snapshot show failed: " << error << L"\n";
                    break;
                }
                PrintSnapshotSummary(document, domains, warnings);
            }
            break;
        }

        if (!device.IsOpen())
        {
            std::wcerr << L"!snapshot requires the KnLiveDbg.sys driver device to be open\n";
            break;
        }

        if (action == L"baseline")
        {
            std::wstring label = L"baseline";
            bool parseError = false;
            if (!ParseSnapshotNameOption(args, 2, &label, &parseError) || parseError)
            {
                break;
            }

            SnapshotDocument document = {};
            if (!CaptureSnapshotForCommand(state, device, symbols, label, false, true, nullptr, &document, &error))
            {
                std::wcerr << L"!snapshot baseline failed: " << error << L"\n";
                break;
            }

            std::wstring jsonPath = BuildSnapshotDefaultPath(L"snapshots", document.TimestampUtc, label, L".json");
            std::wstring reportPath = BuildSnapshotDefaultPath(L"reports", document.TimestampUtc, label + L"-baseline", L".md");
            if (!FinalizeAndWriteSnapshot(&document, jsonPath, reportPath, true))
            {
                break;
            }

            state.SnapshotBaseline = document;
            state.HasSnapshotBaseline = true;
            state.SnapshotBaselineJsonPath = jsonPath;
            state.SnapshotBaselineReportPath = reportPath;
            break;
        }

        if (action == L"save")
        {
            if (args.size() < 3)
            {
                std::wcerr << L"usage: !snapshot save <path> [/all] [/name <label>]\n";
                break;
            }

            std::wstring jsonPath = args[2];
            std::wstring label = L"snapshot";
            bool parseError = false;
            if (!ParseSnapshotNameOption(args, 3, &label, &parseError) || parseError)
            {
                break;
            }

            SnapshotDocument document = {};
            if (!CaptureSnapshotForCommand(state, device, symbols, label, false, true, nullptr, &document, &error))
            {
                std::wcerr << L"!snapshot save failed: " << error << L"\n";
                break;
            }

            std::wstring reportPath = BuildSnapshotDefaultPath(L"reports", document.TimestampUtc, label + L"-snapshot", L".md");
            if (!FinalizeAndWriteSnapshot(&document, jsonPath, reportPath, true))
            {
                break;
            }
            break;
        }

        std::wcerr << L"usage: !snapshot baseline|save|show\n";
    } while (false);
}

static bool ParseDiffOptions(
    const std::vector<std::wstring>& args,
    size_t start,
    DebuggerState& state,
    SnapshotDiffOptions* options,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (options == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid diff options output";
            }
            break;
        }

        *options = SnapshotDiffOptions{};
        size_t index = start;
        bool parseError = false;
        while (index < args.size())
        {
            std::wstring option = ToLower(args[index]);
            if (option == L"/summary")
            {
                options->SummaryOnly = true;
                ++index;
                continue;
            }
            if (option == L"/details")
            {
                options->Details = true;
                options->SummaryOnly = false;
                ++index;
                continue;
            }
            if (option == L"/domain")
            {
                if (index + 1 >= args.size())
                {
                    if (error != nullptr)
                    {
                        *error = L"/domain requires a value";
                    }
                    parseError = true;
                    break;
                }
                options->DomainFilter = args[index + 1];
                index += 2;
                continue;
            }
            if (option == L"/risk")
            {
                if (index + 1 >= args.size())
                {
                    if (error != nullptr)
                    {
                        *error = L"/risk requires high or all";
                    }
                    parseError = true;
                    break;
                }
                std::wstring risk = ToLower(args[index + 1]);
                if (risk == L"high")
                {
                    options->HighOnly = true;
                }
                else if (risk == L"all")
                {
                    options->HighOnly = false;
                }
                else
                {
                    if (error != nullptr)
                    {
                        *error = L"/risk supports high or all";
                    }
                    parseError = true;
                    break;
                }
                index += 2;
                continue;
            }
            if (option == L"/limit")
            {
                if (index + 1 >= args.size())
                {
                    if (error != nullptr)
                    {
                        *error = L"/limit requires a value";
                    }
                    parseError = true;
                    break;
                }
                uint64_t value = 0;
                if (!ParseUnsigned(args[index + 1], state.NumberBase, &value) || value > 0xffffffffull)
                {
                    if (error != nullptr)
                    {
                        *error = L"invalid /limit value";
                    }
                    parseError = true;
                    break;
                }
                options->Limit = static_cast<uint32_t>(value);
                index += 2;
                continue;
            }

            if (error != nullptr)
            {
                *error = L"unrecognised option: " + args[index];
            }
            parseError = true;
            break;
        }

        ok = !parseError;
    } while (false);

    return ok;
}

static void HandleDiffCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    std::wstring error;

    do
    {
        if (args.size() < 2 || HasHelpToken(args, 1))
        {
            PrintDiffHelp();
            break;
        }

        std::wstring target = ToLower(args[1]);
        SnapshotDocument oldSnapshot = {};
        SnapshotDocument newSnapshot = {};
        SnapshotDiffOptions options = {};
        size_t optionStart = 0;

        if (target == L"baseline")
        {
            if (!state.HasSnapshotBaseline)
            {
                std::wcerr << L"!diff baseline: no session baseline captured\n";
                break;
            }
            if (!device.IsOpen())
            {
                std::wcerr << L"!diff baseline requires the KnLiveDbg.sys driver device to be open\n";
                break;
            }

            if (!ParseDiffOptions(args, 2, state, &options, &error))
            {
                std::wcerr << L"!diff baseline failed: " << error << L"\n";
                break;
            }
            options.InMemoryBaseline = true;

            oldSnapshot = state.SnapshotBaseline;
            std::wstring label = L"current";
            if (!CaptureSnapshotForCommand(state, device, symbols, label, true, false, &state.SnapshotBaseline, &newSnapshot, &error))
            {
                std::wcerr << L"!diff baseline capture failed: " << error << L"\n";
                break;
            }

            newSnapshot.JsonPath = BuildSnapshotDefaultPath(L"snapshots", newSnapshot.TimestampUtc, label, L".json");
            newSnapshot.ReportPath = BuildSnapshotDefaultPath(L"reports", newSnapshot.TimestampUtc, label + L"-snapshot", L".md");
            if (!WriteSnapshotJsonFile(newSnapshot.JsonPath, newSnapshot, &error))
            {
                std::wcerr << L"!diff current json failed: " << error << L"\n";
                break;
            }
            if (!WriteSnapshotTextFile(newSnapshot.ReportPath, BuildSnapshotBaselineMarkdown(newSnapshot), &error))
            {
                std::wcerr << L"!diff current report failed: " << error << L"\n";
                break;
            }
        }
        else
        {
            if (args.size() < 3)
            {
                std::wcerr << L"usage: !diff <old.json> <new.json> [/summary] [/details] [/domain <name>] [/risk high|all] [/limit <n>]\n";
                break;
            }

            if (!ReadSnapshotJsonFile(args[1], &oldSnapshot, &error))
            {
                std::wcerr << L"!diff old snapshot failed: " << error << L"\n";
                break;
            }
            if (!ReadSnapshotJsonFile(args[2], &newSnapshot, &error))
            {
                std::wcerr << L"!diff new snapshot failed: " << error << L"\n";
                break;
            }
            optionStart = 3;
            if (!ParseDiffOptions(args, optionStart, state, &options, &error))
            {
                std::wcerr << L"!diff failed: " << error << L"\n";
                break;
            }
        }

        SnapshotDiffResult diff = {};
        if (!BuildSnapshotDiff(oldSnapshot, newSnapshot, options, &diff, &error))
        {
            std::wcerr << L"!diff failed: " << error << L"\n";
            break;
        }

        std::wstring reportPath = BuildSnapshotDefaultPath(L"reports", SnapshotCurrentUtcTimestamp(), newSnapshot.Label + L"-diff", L".md");
        diff.ReportPath = reportPath;
        if (!WriteSnapshotTextFile(reportPath, BuildSnapshotDiffMarkdown(diff, options), &error))
        {
            std::wcerr << L"!diff report failed: " << error << L"\n";
            break;
        }

        PrintSnapshotDiff(diff, options);
    } while (false);
}

static void PrintDmlProcHelp();

static void HandleDmlProcCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    std::wstring error;

    do
    {
        if (args.size() > 2)
        {
            std::wcerr << L"usage: !dml_proc [pid|name]\n";
            break;
        }

        bool hasPidFilter = false;
        uint64_t pidFilter = 0;
        std::wstring nameFilter;
        if (args.size() == 2)
        {
            if (HasHelpToken(args, 1))
            {
                PrintDmlProcHelp();
                break;
            }

            if (ParseDmlProcessPidFilter(args[1], &pidFilter))
            {
                hasPidFilter = true;
            }
            else if (IsSwitchLikeToken(args[1]))
            {
                std::wcerr << L"usage: !dml_proc [pid|name]\n";
                break;
            }
            else
            {
                // A non-decimal argument is a case-insensitive image-name
                // substring filter, e.g. !dml_proc lsass.
                nameFilter = args[1];
            }
        }

        DmlProcessCollection collection = {};
        if (!CollectDmlProcessRecords(state, device, symbols, &collection, &error))
        {
            std::wcerr << L"!dml_proc failed: " << error << L"\n";
            break;
        }

        size_t count = 0;

        PrintColoredText(L"!dml_proc", KNDBG_COLOR_TITLE);
        std::wcout << L"\n";
        PrintDmlProcessHeader();
        for (const DmlProcessRecord& record : collection.Records)
        {
            if (DmlProcessMatchesFilter(record, hasPidFilter, pidFilter, nameFilter))
            {
                PrintDmlProcessRecord(record);
                ++count;
            }
        }

        for (const std::wstring& warning : collection.Warnings)
        {
            std::wcerr << L"!dml_proc warning: " << warning << L"\n";
        }

        PrintColoredText(L"process records", KNDBG_COLOR_TITLE);
        std::wcout << L"=" << count;
        if (hasPidFilter)
        {
            std::wcout << L" ";
            PrintColoredText(L"pid", KNDBG_COLOR_ACCENT);
            std::wcout << L"=" << std::dec << pidFilter;
        }
        else if (!nameFilter.empty())
        {
            std::wcout << L" ";
            PrintColoredText(L"name", KNDBG_COLOR_ACCENT);
            std::wcout << L"=" << nameFilter;
        }
        if (collection.Truncated)
        {
            std::wcout << L" truncated=yes";
        }
        std::wcout << L"\n";
    } while (false);
}

struct LeafPageTableEntry
{
    uint64_t PhysicalAddress;
    uint64_t Value;
    uint64_t CompareMask;
    std::wstring Name;
};

static bool TranslationUsesPml5(const PhysicalTranslationInfo& translation)
{
    bool usesPml5 = false;

    do
    {
        if (translation.PagingLevels == 5 ||
            (translation.Flags & KNDBG_TRANSLATE_FLAG_LA57_ACTIVE) != 0)
        {
            usesPml5 = true;
        }
    } while (false);

    return usesPml5;
}

struct TemporaryWritablePageEntry
{
    bool Active;
    uint64_t VirtualAddress;
    uint32_t FlushLength;
    uint64_t PhysicalAddress;
    uint64_t OriginalValue;
    uint64_t WritableValue;
    uint64_t CompareMask;
    std::wstring Name;
};

static bool GetLeafPageTableEntry(
    const PhysicalTranslationInfo& translation,
    LeafPageTableEntry* entry,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (entry == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid leaf PTE output";
            }
            break;
        }

        *entry = LeafPageTableEntry{};

        if (translation.PageSize == KNDBG_X64_1GB_PAGE_SIZE ||
            (translation.Pdpte & KNDBG_X64_PTE_LARGE_PAGE) != 0)
        {
            if ((translation.Pml4e & KNDBG_X64_PTE_PRESENT) == 0 ||
                (translation.Pdpte & KNDBG_X64_PTE_PRESENT) == 0)
            {
                if (error != nullptr)
                {
                    *error = L"missing PDPTE leaf";
                }
                break;
            }

            entry->PhysicalAddress = translation.PdpteAddress;
            entry->Value = translation.Pdpte;
            entry->CompareMask =
                KNDBG_X64_PTE_1GB_BASE_MASK |
                KNDBG_X64_PTE_PRESENT |
                KNDBG_X64_PTE_LARGE_PAGE;
            entry->Name = L"pdpte";
            ok = true;
            break;
        }

        if (translation.PageSize == KNDBG_X64_2MB_PAGE_SIZE ||
            (translation.Pde & KNDBG_X64_PTE_LARGE_PAGE) != 0)
        {
            if ((translation.Pdpte & KNDBG_X64_PTE_PRESENT) == 0 ||
                (translation.Pde & KNDBG_X64_PTE_PRESENT) == 0)
            {
                if (error != nullptr)
                {
                    *error = L"missing PDE leaf";
                }
                break;
            }

            entry->PhysicalAddress = translation.PdeAddress;
            entry->Value = translation.Pde;
            entry->CompareMask =
                KNDBG_X64_PTE_2MB_BASE_MASK |
                KNDBG_X64_PTE_PRESENT |
                KNDBG_X64_PTE_LARGE_PAGE;
            entry->Name = L"pde";
            ok = true;
            break;
        }

        if (translation.PageSize != KNDBG_X64_4K_PAGE_SIZE ||
            (translation.Pde & KNDBG_X64_PTE_PRESENT) == 0 ||
            (translation.Pte & KNDBG_X64_PTE_PRESENT) == 0)
        {
            if (error != nullptr)
            {
                *error = L"missing PTE leaf";
            }
            break;
        }

        entry->PhysicalAddress = translation.PteAddress;
        entry->Value = translation.Pte;
        entry->CompareMask =
            KNDBG_X64_PTE_4K_BASE_MASK |
            KNDBG_X64_PTE_PRESENT;
        entry->Name = L"pte";
        if (entry->PhysicalAddress == 0)
        {
            if (error != nullptr)
            {
                *error = L"missing leaf entry physical address";
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool ReadPhysicalQword(DeviceClient& device, uint64_t physicalAddress, uint64_t* value, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (value == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid qword output";
            }
            break;
        }

        std::vector<uint8_t> bytes;
        if (!device.ReadPhysical(physicalAddress, sizeof(uint64_t), &bytes, error))
        {
            break;
        }

        if (bytes.size() != sizeof(uint64_t))
        {
            if (error != nullptr)
            {
                *error = L"short qword physical read";
            }
            break;
        }

        *value = DecodeInteger(bytes.data(), sizeof(uint64_t));
        ok = true;
    } while (false);

    return ok;
}

static bool WritePhysicalQword(DeviceClient& device, uint64_t physicalAddress, uint64_t value, std::wstring* error)
{
    std::vector<uint8_t> bytes = EncodeInteger(value, sizeof(uint64_t));
    return device.WritePhysical(physicalAddress, bytes, error);
}

static bool EndTemporaryWritablePageEntry(
    DeviceClient& device,
    TemporaryWritablePageEntry* temporary,
    std::wstring* error);

static bool BeginTemporaryWritablePageEntry(
    DeviceClient& device,
    const PhysicalTranslationInfo& translation,
    uint32_t flushLength,
    TemporaryWritablePageEntry* temporary,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (temporary == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid temporary PTE state";
            }
            break;
        }

        *temporary = TemporaryWritablePageEntry{};

        LeafPageTableEntry leaf = {};
        if (!GetLeafPageTableEntry(translation, &leaf, error))
        {
            break;
        }

        if ((leaf.Value & KNDBG_X64_PTE_WRITE) != 0)
        {
            ok = true;
            break;
        }

        // Refuse to flip the write bit on a read-only large-page leaf: the
        // PDPTE/PDE entry governs an entire 1 GB / 2 MB region shared by other
        // mappings, so temporarily enabling writes there would widen write
        // access far beyond the target. (An already-writable large page took
        // the early-out above and is safe.)
        if (leaf.Name == L"pdpte" || leaf.Name == L"pde")
        {
            if (error != nullptr)
            {
                *error = L"refusing to write through a read-only large-page (" + leaf.Name +
                    L") mapping: enabling writes would affect the whole large-page region; "
                    L"target a 4 KB-mapped address instead";
            }
            break;
        }

        uint64_t currentEntry = 0;
        if (!ReadPhysicalQword(device, leaf.PhysicalAddress, &currentEntry, error))
        {
            break;
        }

        if (currentEntry != leaf.Value)
        {
            if (error != nullptr)
            {
                *error = L"leaf page table entry changed before write";
            }
            break;
        }

        uint64_t writableEntry = currentEntry | KNDBG_X64_PTE_WRITE;
        if (!WritePhysicalQword(device, leaf.PhysicalAddress, writableEntry, error))
        {
            if (error != nullptr)
            {
                std::wstring writeError = *error;
                *error = L"temporary " + leaf.Name + L" write-enable failed entry-pa=" +
                    HexTextWidth(leaf.PhysicalAddress, 16, true) + L": " + writeError;
            }
            break;
        }

        temporary->Active = true;
        temporary->VirtualAddress = translation.VirtualAddress;
        temporary->FlushLength = flushLength == 0 ? 1 : flushLength;
        temporary->PhysicalAddress = leaf.PhysicalAddress;
        temporary->OriginalValue = currentEntry;
        temporary->WritableValue = writableEntry;
        temporary->CompareMask = leaf.CompareMask;
        temporary->Name = leaf.Name;

        if (!device.FlushVirtual(temporary->VirtualAddress, temporary->FlushLength, error))
        {
            std::wstring flushError = error != nullptr ? *error : L"unknown error";
            std::wstring restoreError;
            EndTemporaryWritablePageEntry(device, temporary, &restoreError);
            if (error != nullptr)
            {
                *error = L"temporary " + leaf.Name + L" flush failed after write-enable va=" +
                    HexTextWidth(temporary->VirtualAddress, 16, true) + L": " + flushError;
                if (!restoreError.empty())
                {
                    *error += L"; restore=" + restoreError;
                }
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool EndTemporaryWritablePageEntry(
    DeviceClient& device,
    TemporaryWritablePageEntry* temporary,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (temporary == nullptr || !temporary->Active)
        {
            ok = true;
            break;
        }

        uint64_t currentEntry = 0;
        if (!ReadPhysicalQword(device, temporary->PhysicalAddress, &currentEntry, error))
        {
            break;
        }

        if ((currentEntry & temporary->CompareMask) !=
            (temporary->WritableValue & temporary->CompareMask))
        {
            if (error != nullptr)
            {
                *error = L"leaf page table entry changed before restore";
            }
            break;
        }

        uint64_t restoredEntry = currentEntry & ~KNDBG_X64_PTE_WRITE;
        if (!WritePhysicalQword(device, temporary->PhysicalAddress, restoredEntry, error))
        {
            if (error != nullptr)
            {
                std::wstring writeError = *error;
                *error = L"temporary " + temporary->Name + L" restore write failed entry-pa=" +
                    HexTextWidth(temporary->PhysicalAddress, 16, true) + L": " + writeError;
            }
            break;
        }

        temporary->Active = false;
        if (!device.FlushVirtual(temporary->VirtualAddress, temporary->FlushLength, error))
        {
            if (error != nullptr)
            {
                std::wstring flushError = *error;
                *error = L"temporary " + temporary->Name + L" flush failed after restore va=" +
                    HexTextWidth(temporary->VirtualAddress, 16, true) + L": " + flushError;
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
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
            TemporaryWritablePageEntry temporary = {};
            if (!BeginTemporaryWritablePageEntry(device, translation, chunk, &temporary, error))
            {
                break;
            }

            std::wstring writeError;
            bool writeViaKernelVirtualAddress = !IsLikelyUserVirtualAddress(current);
            bool writeOk = false;
            std::wstring writeTargetText;
            std::wstring writeFailureText;
            if (writeViaKernelVirtualAddress)
            {
                writeTargetText = L" va=" + HexTextWidth(current, 16, true);
                writeFailureText = L"virtual data write failed";
                writeOk = device.WriteMemory(current, pageBytes, &writeError);
            }
            else
            {
                writeTargetText = L" pa=" + HexTextWidth(translation.PhysicalAddress, 16, true);
                writeFailureText = L"physical data write failed";
                writeOk = device.WritePhysical(translation.PhysicalAddress, pageBytes, &writeError);
            }

            std::wstring restoreError;
            bool restoreOk = EndTemporaryWritablePageEntry(device, &temporary, &restoreError);
            if (!writeOk || !restoreOk)
            {
                if (error != nullptr)
                {
                    if (!writeOk && !restoreOk)
                    {
                        *error = writeFailureText + writeTargetText + L": " +
                            writeError + L"; PTE restore failed: " + restoreError;
                    }
                    else if (!writeOk)
                    {
                        *error = writeFailureText + writeTargetText + L": " + writeError;
                    }
                    else
                    {
                        *error = L"PTE restore failed: " + restoreError;
                    }
                }
                break;
            }

            // Read-back verification: confirm the bytes actually landed before
            // advancing. A silent short or dropped write (e.g. a racing remap
            // or copy-on-write split) would otherwise pass unnoticed. Reads do
            // not require the write bit, so this runs after the PTE is restored.
            std::vector<uint8_t> verifyBytes;
            std::wstring verifyError;
            bool verifyRead = writeViaKernelVirtualAddress
                ? device.ReadMemory(current, chunk, &verifyBytes, &verifyError)
                : device.ReadPhysical(translation.PhysicalAddress, chunk, &verifyBytes, &verifyError);
            if (!verifyRead || verifyBytes.size() != pageBytes.size() ||
                memcmp(verifyBytes.data(), pageBytes.data(), pageBytes.size()) != 0)
            {
                if (error != nullptr)
                {
                    *error = L"write verification failed" + writeTargetText +
                        L": target did not read back the written bytes" +
                        (verifyError.empty() ? L"" : (L" (" + verifyError + L")"));
                }
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
            std::wcerr << L"usage: vtop /process <process-id> <address|symbol> [length]\n";
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
        else if (command == L"vtop" && IsDeprecatedProcessContextOption(args[index]))
        {
            std::wcerr << L"usage: vtop /process <process-id> <address|symbol> [length]\n";
            break;
        }
        else if (command == L"vtop" && IsProcessContextOption(args[index]))
        {
            if (args.size() < 4)
            {
                std::wcerr << L"usage: vtop /process <process-id> <address|symbol> [length]\n";
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
            PrintColoredText(L"process-context", KNDBG_COLOR_TITLE);
            std::wcout << L" ";
            PrintProcessAddressContext(processContext);
        }

        PrintColoredText(L"va", KNDBG_COLOR_ACCENT);
        std::wcout << L"=" << HexTextWidth(info.VirtualAddress, 16, true) << L" ";
        PrintColoredText(L"pa", KNDBG_COLOR_TITLE);
        std::wcout << L"=" << HexTextWidth(info.PhysicalAddress, 16, true) << L" ";
        PrintColoredText(L"cr3", KNDBG_COLOR_ACCENT);
        std::wcout << L"=" << HexTextWidth(info.DirectoryTableBase, 16, true) << L" ";
        PrintColoredText(L"paging", KNDBG_COLOR_ACCENT);
        std::wcout << L"=" << (TranslationUsesPml5(info) ? L"pml5" : L"pml4")
                   << L" levels=" << (info.PagingLevels == 0 ? (TranslationUsesPml5(info) ? 5 : 4) : info.PagingLevels)
                   << L"\n";
        PrintColoredText(L"page-size", KNDBG_COLOR_ACCENT);
        std::wcout << L"=" << HexText(info.PageSize) << L" ";
        PrintColoredText(L"page-offset", KNDBG_COLOR_ACCENT);
        std::wcout << L"=" << HexText(info.PageOffset) << L" ";
        PrintColoredText(L"page-bytes", KNDBG_COLOR_ACCENT);
        std::wcout << L"=" << HexText(info.PageBytes) << L" ";
        PrintColoredText(L"translated", KNDBG_COLOR_TITLE);
        std::wcout << L"=" << HexText(info.TranslatedLength) << L"\n";
        if ((info.Flags & KNDBG_TRANSLATE_FLAG_LA57_ACTIVE) != 0)
        {
            PrintColoredText(L"pml5e", KNDBG_COLOR_ACCENT);
            std::wcout << L"=" << HexTextWidth(info.Pml5e, 16, true) << L" ";
            PrintColoredText(L"pml5e-pa", KNDBG_COLOR_ACCENT);
            std::wcout << L"=" << HexTextWidth(info.Pml5eAddress, 16, true) << L"\n";
        }
        PrintColoredText(L"pml4e", KNDBG_COLOR_ACCENT);
        std::wcout << L"=" << HexTextWidth(info.Pml4e, 16, true) << L" ";
        PrintColoredText(L"pml4e-pa", KNDBG_COLOR_ACCENT);
        std::wcout << L"=" << HexTextWidth(info.Pml4eAddress, 16, true) << L"\n";
        PrintColoredText(L"pdpte", KNDBG_COLOR_ACCENT);
        std::wcout << L"=" << HexTextWidth(info.Pdpte, 16, true) << L" ";
        PrintColoredText(L"pdpte-pa", KNDBG_COLOR_ACCENT);
        std::wcout << L"=" << HexTextWidth(info.PdpteAddress, 16, true) << L"\n";
        PrintColoredText(L"pde", KNDBG_COLOR_ACCENT);
        std::wcout << L"=" << HexTextWidth(info.Pde, 16, true) << L" ";
        PrintColoredText(L"pde-pa", KNDBG_COLOR_ACCENT);
        std::wcout << L"=" << HexTextWidth(info.PdeAddress, 16, true) << L"\n";
        PrintColoredText(L"pte", KNDBG_COLOR_TITLE);
        std::wcout << L"=" << HexTextWidth(info.Pte, 16, true) << L" ";
        PrintColoredText(L"pte-pa", KNDBG_COLOR_ACCENT);
        std::wcout << L"=" << HexTextWidth(info.PteAddress, 16, true) << L"\n";

        LeafPageTableEntry leaf = {};
        if (GetLeafPageTableEntry(info, &leaf, nullptr))
        {
            PrintColoredText(L"leaf", KNDBG_COLOR_ACCENT);
            std::wcout << L"=" << leaf.Name << L" ";
            PrintColoredText(L"entry-pa", KNDBG_COLOR_ACCENT);
            std::wcout << L"=" << HexTextWidth(leaf.PhysicalAddress, 16, true) << L" ";
            PrintColoredText(L"writable", KNDBG_COLOR_ACCENT);
            std::wcout << L"=" << (((leaf.Value & KNDBG_X64_PTE_WRITE) != 0) ? L"yes" : L"no") << L"\n";
        }
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
                PrintColoredText(L"process context", KNDBG_COLOR_TITLE);
                std::wcout << L": ";
                PrintProcessAddressContext(state.ProcessContext);
            }
            else
            {
                PrintColoredText(L"process context", KNDBG_COLOR_TITLE);
                std::wcout << L": off\n";
            }
            break;
        }

        std::wstring action = ToLower(args[1]);
        if (action == L"clear")
        {
            state.HasProcessContext = false;
            state.ProcessContext = {};
            PrintColoredText(L"process context", KNDBG_COLOR_TITLE);
            std::wcout << L": off\n";
            break;
        }

        uint64_t pid64 = 0;
        if (!ParseUnsigned(args[1], 10, &pid64) || pid64 == 0 || pid64 > 0xffffffffull)
        {
            std::wcerr << L"usage: procctx <process-id|clear|status>\n";
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
        PrintColoredText(L"process context", KNDBG_COLOR_TITLE);
        std::wcout << L": ";
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

        MemoryReadView memory;
        if (!ReadSparsePhysicalMemory(device, physicalAddress, byteCount, &memory, &error))
        {
            std::wcerr << L"physical read failed: " << error << L"\n";
            break;
        }

        if (command == L"phys" || command == L"pdb" || command == L"!db")
        {
            HexDump(physicalAddress, memory);
        }
        else
        {
            UnitDump(physicalAddress, memory, unit, nullptr);
        }
    } while (false);
}

static bool PromptForPhysicalEnterBytes(
    const std::wstring& command,
    const DebuggerState& state,
    DeviceClient& device,
    uint64_t physicalAddress,
    std::vector<uint8_t>* bytes,
    bool* cancelled,
    std::wstring* error);

static void HandlePhysicalEnterCommand(
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
            std::wcerr << L"usage: " << command << L" <physical-address> [value...]\n";
            break;
        }

        uint64_t physicalAddress = 0;
        if (!ParseUnsigned(args[1], state.NumberBase, &physicalAddress))
        {
            std::wcerr << L"invalid physical address\n";
            break;
        }

        size_t width = UnitWidthForPhysicalEnterCommand(command);
        std::vector<uint8_t> bytes;
        bool interactiveEdit = args.size() < 3;
        if (interactiveEdit)
        {
            bool cancelled = false;
            if (!PromptForPhysicalEnterBytes(command, state, device, physicalAddress, &bytes, &cancelled, &error))
            {
                std::wcerr << L"edit failed: " << error << L"\n";
                break;
            }

            if (cancelled)
            {
                PrintColoredText(L"edit cancelled", KNDBG_COLOR_DIM);
                std::wcout << L"\n";
                break;
            }
        }
        else
        {
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
            std::wcerr << L"physical write size exceeds native transfer limit\n";
            break;
        }

        if (device.WritePhysical(physicalAddress, bytes, &error))
        {
            PrintColoredText(L"wrote physical", KNDBG_COLOR_OK);
            std::wcout << L" " << bytes.size() << L" bytes\n";
        }
        else
        {
            std::wcerr << L"physical write failed: " << error << L"\n";
        }
    } while (false);
}

static bool ReadEnterPromptLine(std::wstring* line, bool* cancelled, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (line == nullptr || cancelled == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid edit prompt state";
            }
            break;
        }

        *line = L"";
        *cancelled = false;
        if (!std::getline(std::wcin, *line))
        {
            if (error != nullptr)
            {
                *error = L"input stream closed";
            }
            break;
        }

        std::wstring trimmed = ToLower(TrimWhitespace(*line));
        if (trimmed.empty() || trimmed == L"q" || trimmed == L"quit" || trimmed == L".")
        {
            *cancelled = true;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool PromptForPhysicalEnterBytes(
    const std::wstring& command,
    const DebuggerState& state,
    DeviceClient& device,
    uint64_t physicalAddress,
    std::vector<uint8_t>* bytes,
    bool* cancelled,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (bytes == nullptr || cancelled == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid edit prompt output";
            }
            break;
        }

        bytes->clear();
        *cancelled = false;

        PrintColoredText(HexTextWidth(physicalAddress, 16, false), KNDBG_COLOR_ACCENT);
        std::wcout << L"  ";

        size_t width = UnitWidthForPhysicalEnterCommand(command);
        std::vector<uint8_t> currentBytes;
        std::wstring ignored;
        if (device.ReadPhysical(
                physicalAddress,
                static_cast<uint32_t>(width),
                &currentBytes,
                &ignored) &&
            currentBytes.size() == width)
        {
            uint64_t currentValue = DecodeInteger(currentBytes.data(), width);
            std::wcout << HexTextWidth(currentValue, static_cast<int>(width * 2), false);
        }
        else
        {
            std::wcout << UnknownHexText(width, false);
        }

        std::wcout << L" : ";

        std::wstring line;
        if (!ReadEnterPromptLine(&line, cancelled, error))
        {
            break;
        }

        if (*cancelled)
        {
            ok = true;
            break;
        }

        std::vector<std::wstring> values = Split(line);
        if (values.empty())
        {
            *cancelled = true;
            ok = true;
            break;
        }

        bool valuesOk = true;
        for (const std::wstring& text : values)
        {
            uint64_t value = 0;
            if (!ParseUnsigned(text, state.NumberBase, &value))
            {
                if (error != nullptr)
                {
                    *error = L"invalid value: " + text;
                }
                valuesOk = false;
                break;
            }

            std::vector<uint8_t> encoded = EncodeInteger(value, width);
            bytes->insert(bytes->end(), encoded.begin(), encoded.end());
        }

        ok = valuesOk && !bytes->empty();
    } while (false);

    return ok;
}

static bool PromptForEnterBytes(
    const std::wstring& command,
    const DebuggerState& state,
    DeviceClient& device,
    const ProcessAddressContext* memoryContext,
    uint64_t address,
    std::vector<uint8_t>* bytes,
    bool* cancelled,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (bytes == nullptr || cancelled == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid edit prompt output";
            }
            break;
        }

        bytes->clear();
        *cancelled = false;

        PrintColoredText(HexTextWidth(address, 16, false), KNDBG_COLOR_ACCENT);
        std::wcout << L"  ";

        if (IsEnterStringCommand(command))
        {
            PrintColoredText(L"string", KNDBG_COLOR_DIM);
            std::wcout << L" : ";

            std::wstring line;
            if (!ReadEnterPromptLine(&line, cancelled, error))
            {
                break;
            }

            if (*cancelled)
            {
                ok = true;
                break;
            }

            bool unicode = command == L"eu" || command == L"ezu";
            bool zeroTerminate = command == L"eza" || command == L"ezu";
            *bytes = EncodeString(line, unicode, zeroTerminate);
            ok = true;
            break;
        }

        size_t width = UnitWidthForEnterCommand(command);
        std::vector<uint8_t> currentBytes;
        if (ReadMemoryWithProcessContext(
                device,
                state,
                memoryContext,
                address,
                static_cast<uint32_t>(width),
                &currentBytes,
                error) &&
            currentBytes.size() == width)
        {
            uint64_t currentValue = DecodeInteger(currentBytes.data(), width);
            std::wcout << HexTextWidth(currentValue, static_cast<int>(width * 2), false);
        }
        else
        {
            std::wcout << UnknownHexText(width, false);
        }

        std::wcout << L" : ";

        std::wstring line;
        if (!ReadEnterPromptLine(&line, cancelled, error))
        {
            break;
        }

        if (*cancelled)
        {
            ok = true;
            break;
        }

        std::vector<std::wstring> values = Split(line);
        if (values.empty())
        {
            *cancelled = true;
            ok = true;
            break;
        }

        bool valuesOk = true;
        for (const std::wstring& text : values)
        {
            uint64_t value = 0;
            if (!ParseUnsigned(text, state.NumberBase, &value))
            {
                if (error != nullptr)
                {
                    *error = L"invalid value: " + text;
                }
                valuesOk = false;
                break;
            }

            std::vector<uint8_t> encoded = EncodeInteger(value, width);
            bytes->insert(bytes->end(), encoded.begin(), encoded.end());
        }

        ok = valuesOk && !bytes->empty();
    } while (false);

    return ok;
}

static void HandleEnterCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    std::wstring error;
    std::wstring command = NormalizeInputCommand(args[0]);

    do
    {
        if (args.size() < 2)
        {
            std::wcerr << L"usage: " << command << L" [/process <process-id>] <address|symbol> [value...]\n";
            break;
        }

        size_t argIndex = 1;
        ProcessAddressContext explicitContext = {};
        bool hasExplicitContext = false;
        if (IsDeprecatedProcessContextOption(args[argIndex]))
        {
            std::wcerr << L"usage: " << command << L" [/process <process-id>] <address|symbol> [value...]\n";
            break;
        }

        if (IsProcessContextOption(args[argIndex]))
        {
            if (args.size() < argIndex + 3)
            {
                std::wcerr << L"usage: " << command << L" /process <process-id> <address|symbol> [value...]\n";
                break;
            }

            uint64_t processId = 0;
            if (!ParseUnsigned(args[argIndex + 1], 10, &processId) || processId == 0 || processId > 0xffffffffull)
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

        if (argIndex >= args.size())
        {
            std::wcerr << L"usage: " << command << L" [/process <process-id>] <address|symbol> [value...]\n";
            break;
        }

        uint64_t address = 0;
        if (!ParseAddressOrSymbol(symbols, state, args[argIndex], &address, &error))
        {
            std::wcerr << L"write failed: " << error << L"\n";
            break;
        }

        ProcessAddressContext kernelContext = {};
        const ProcessAddressContext* memoryContext = hasExplicitContext ? &explicitContext : nullptr;
        if (!hasExplicitContext)
        {
            if (!EnsureKernelProcessAddressContext(state, device, symbols, &kernelContext, &error))
            {
                std::wcerr << L"kernel process context failed: " << error << L"\n";
                break;
            }

            memoryContext = &kernelContext;
        }

        bool interactiveEdit = argIndex + 1 >= args.size();
        std::vector<uint8_t> bytes;
        if (interactiveEdit)
        {
            bool cancelled = false;
            if (!PromptForEnterBytes(command, state, device, memoryContext, address, &bytes, &cancelled, &error))
            {
                std::wcerr << L"edit failed: " << error << L"\n";
                break;
            }

            if (cancelled)
            {
                PrintColoredText(L"edit cancelled", KNDBG_COLOR_DIM);
                std::wcout << L"\n";
                break;
            }
        }
        else if (IsEnterStringCommand(command))
        {
            bool unicode = command == L"eu" || command == L"ezu";
            bool zeroTerminate = command == L"eza" || command == L"ezu";
            bytes = EncodeString(JoinArgs(args, argIndex + 1), unicode, zeroTerminate);
        }
        else
        {
            size_t width = UnitWidthForEnterCommand(command);

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

        if (WriteMemoryWithProcessContext(device, state, memoryContext, address, bytes, &error))
        {
            PrintColoredText(L"wrote", KNDBG_COLOR_OK);
            std::wcout << L" " << bytes.size() << L" bytes";
            if (memoryContext != nullptr)
            {
                std::wcout << L" pid=" << memoryContext->ProcessId;
            }
            std::wcout << L"\n";
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
                PrintColoredText(HexText(address1 + index), KNDBG_COLOR_ACCENT);
                std::wcout << L" 0x" << std::hex << static_cast<unsigned>(left[index]) << L" != ";
                PrintColoredText(HexText(address2 + index), KNDBG_COLOR_ACCENT);
                std::wcout << L" 0x" << static_cast<unsigned>(right[index]) << std::dec << L"\n";
                ++mismatchCount;
            }
        }

        PrintColoredText(L"mismatches", mismatchCount == 0 ? KNDBG_COLOR_OK : KNDBG_COLOR_WARN);
        std::wcout << L"=" << mismatchCount << L"\n";
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
            PrintColoredText(L"filled", KNDBG_COLOR_OK);
            std::wcout << L" " << bytes.size() << L" bytes\n";
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
            PrintColoredText(L"moved", KNDBG_COLOR_OK);
            std::wcout << L" " << bytes.size() << L" bytes\n";
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
                PrintColoredText(HexText(address + index), KNDBG_COLOR_ACCENT);
                std::wcout << L"\n";
                ++matches;
            }
        }

        PrintColoredText(L"matches", KNDBG_COLOR_TITLE);
        std::wcout << L"=" << matches << L"\n";
    } while (false);
}

static void PrintVersion(DeviceClient& device)
{
    std::wstring error;

    PrintColoredText(L"KnLiveDbg", KNDBG_COLOR_TITLE);
    std::wcout << L" version 0.4\n";
    if (device.QueryVersion(&error))
    {
        PrintColoredText(L"driver ABI ok", KNDBG_COLOR_OK);
        std::wcout << L"\n";
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
        PrintColoredText(L"local live kernel target", KNDBG_COLOR_TITLE);
        std::wcout << L": Windows " << version.dwMajorVersion << L"." << version.dwMinorVersion
                   << L" build " << version.dwBuildNumber << L"\n";
    }
    else
    {
        PrintColoredText(L"local live kernel target", KNDBG_COLOR_TITLE);
        std::wcout << L": current machine\n";
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

static std::wstring ProbeFirmwareSignatureText(uint32_t signature)
{
    std::wstring text;

    do
    {
        for (uint32_t index = 0; index < 4; ++index)
        {
            uint8_t ch = static_cast<uint8_t>((signature >> ((3 - index) * 8)) & 0xffu);
            if (ch < 0x20 || ch > 0x7e)
            {
                text.clear();
                break;
            }

            text.push_back(static_cast<wchar_t>(ch));
        }
    } while (false);

    return text;
}

static void PrintProbeInfo(const KNDBG_PROBE_INFO_RESPONSE& info)
{
    PrintColoredText(L"probe", KNDBG_COLOR_TITLE);
    std::wcout << L" abi=" << info.AbiVersion
               << L" length=" << HexText(info.BufferLength)
               << L" seed=" << HexText(info.PatternSeed) << L"\n";
    PrintColoredText(L"probe virtual", KNDBG_COLOR_ACCENT);
    std::wcout << L"=" << HexTextWidth(info.BufferVirtualAddress, 16, true) << L"\n";
    PrintColoredText(L"probe physical", KNDBG_COLOR_TITLE);
    std::wcout << L"=" << HexTextWidth(info.BufferPhysicalAddress, 16, true) << L"\n";
    PrintColoredText(L"probe firmware", KNDBG_COLOR_ACCENT);
    std::wcout << L" signature=" << HexTextWidth(info.FirmwareProviderSignature, 8, true);
    std::wstring fourcc = ProbeFirmwareSignatureText(info.FirmwareProviderSignature);
    if (!fourcc.empty())
    {
        std::wcout << L" fourcc=\"" << fourcc << L"\"";
    }
    std::wcout << L" registered=" << (info.FirmwareProviderRegistered != 0 ? L"yes" : L"no")
               << L" registerStatus=" << HexTextWidth(info.FirmwareProviderRegisterStatus, 8, true)
               << L" unregisterStatus=" << HexTextWidth(info.FirmwareProviderUnregisterStatus, 8, true)
               << L" handler=" << HexTextWidth(info.FirmwareTableHandlerAddress, 16, true)
               << L"\n";
    std::wcout << L"try: db 0x" << std::hex << info.BufferVirtualAddress
               << L" 40; pdb 0x" << info.BufferPhysicalAddress
               << L" 40" << std::dec << L"\n";
    std::wcout << L"try: !fwtable provider " << fourcc << L"; !fwtable providers /module KnLiveDbgProbe.sys\n";
}

static bool LoadDriverServiceWithUx(
    DriverService& service,
    const std::wstring& title,
    const std::wstring& driverPath,
    std::wstring* error);
static bool UnloadDriverServiceWithUx(
    DriverService& service,
    const std::wstring& title,
    DriverUnloadResult* unloadResult,
    std::wstring* error);
static void PrintProbeHelp();

static void HandleProbeCommand(const std::vector<std::wstring>& args, DebuggerState& state)
{
    std::wstring action = args.size() >= 2 ? ToLower(args[1]) : L"status";
    std::wstring error;
    DriverService probeService(KNDBG_PROBE_SERVICE_NAME, KNDBG_PROBE_DISPLAY_NAME);

    do
    {
        if (HasHelpToken(args, 1))
        {
            PrintProbeHelp();
            break;
        }

        if (action == L"load")
        {
            std::wstring driverPath = args.size() >= 3 ? JoinArgs(args, 2) : GetExecutableDirectory() + L"\\KnLiveDbgProbe.sys";
            state.ProbeDriverCleanupRequested = true;
            state.ProbeDriverUnloaded = false;
            if (!LoadDriverServiceWithUx(probeService, L"Probe driver load", driverPath, &error))
            {
                break;
            }

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
        else if (action == L"unload")
        {
            DriverUnloadResult unloadResult = {};
            if (!UnloadDriverServiceWithUx(probeService, L"Probe driver unload", &unloadResult, &error))
            {
                break;
            }

            state.ProbeDriverUnloaded = true;
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

static std::wstring TuiFitText(const std::wstring& value, size_t width)
{
    std::wstring result;

    do
    {
        for (wchar_t ch : value)
        {
            if (ch == L'\r' || ch == L'\n' || ch == L'\t')
            {
                result += L' ';
            }
            else
            {
                result += ch;
            }
        }

        if (result.size() > width)
        {
            if (width <= 3)
            {
                result.resize(width);
            }
            else
            {
                result.resize(width - 3);
                result += L"...";
            }
            break;
        }

        while (result.size() < width)
        {
            result += L' ';
        }
    } while (false);

    return result;
}

static void PrintTuiRule(WORD color = KNDBG_COLOR_FRAME)
{
    ScopedConsoleColor scopedColor(GetStdHandle(STD_OUTPUT_HANDLE), color);
    std::wcout << L"+" << std::wstring(78, L'-') << L"+\n";
}

static void PrintTuiLine(const std::wstring& value, WORD color = KNDBG_COLOR_TEXT)
{
    ScopedConsoleColor scopedColor(GetStdHandle(STD_OUTPUT_HANDLE), color);
    std::wcout << L"| " << TuiFitText(value, 76) << L" |\n";
}

static void PrintTuiBlank()
{
    PrintTuiLine(L"", KNDBG_COLOR_DIM);
}

static void PrintWelcomeBanner()
{
    PrintTuiRule(KNDBG_COLOR_ACCENT);
    PrintTuiLine(L"##  ##  ##  ##  ##  ##  ##  ##  ##  ##  ##  ##  ##  ##  ##", KNDBG_COLOR_ACCENT);
    PrintTuiLine(L"", KNDBG_COLOR_ACCENT);
    PrintTuiLine(L"                    WELCOME TO KNLIVEDBG", KNDBG_COLOR_TITLE);
    PrintTuiLine(L"              Live Kernel Debugger Console", KNDBG_COLOR_ACCENT);
    PrintTuiLine(L"        Native memory IOCTLs + symbols + optional DbgEng", KNDBG_COLOR_TEXT);
    PrintTuiLine(L"", KNDBG_COLOR_ACCENT);
    PrintTuiLine(L"##  ##  ##  ##  ##  ##  ##  ##  ##  ##  ##  ##  ##  ##  ##", KNDBG_COLOR_ACCENT);
    PrintTuiRule(KNDBG_COLOR_ACCENT);
}

static std::wstring DriverStatusSummary(const DriverStatus& status)
{
    std::wstring text;

    do
    {
        if (!status.Installed)
        {
            text = L"not-installed";
            break;
        }

        text = L"installed";
        if (!status.StateText.empty())
        {
            text += L"/" + status.StateText;
        }
    } while (false);

    return text;
}

static void PrintLifecycleHeader(const std::wstring& title, const std::wstring& detail)
{
    PrintTuiRule();
    PrintTuiLine(title, KNDBG_COLOR_TITLE);
    if (!detail.empty())
    {
        PrintTuiLine(detail, KNDBG_COLOR_DIM);
    }
    PrintTuiRule();
}

static void PrintLifecycleStep(const std::wstring& label, const std::wstring& detail)
{
    std::wstring line = L"[ .. ] " + label;

    if (!detail.empty())
    {
        line += L": " + detail;
    }

    PrintTuiLine(line, KNDBG_COLOR_STEP);
}

static void PrintLifecycleOk(const std::wstring& label, const std::wstring& detail)
{
    std::wstring line = L"[ OK ] " + label;

    if (!detail.empty())
    {
        line += L": " + detail;
    }

    PrintTuiLine(line, KNDBG_COLOR_OK);
}

static void PrintLifecycleWarn(const std::wstring& label, const std::wstring& detail)
{
    std::wstring line = L"[WARN] " + label;

    if (!detail.empty())
    {
        line += L": " + detail;
    }

    PrintTuiLine(line, KNDBG_COLOR_WARN);
}

static void PrintLifecycleFail(const std::wstring& label, const std::wstring& detail)
{
    std::wstring line = L"[FAIL] " + label;

    if (!detail.empty())
    {
        line += L": " + detail;
    }

    PrintTuiLine(line, KNDBG_COLOR_FAIL);
}

static bool IsConsoleOutputHandle(HANDLE handle)
{
    bool isConsole = false;

    do
    {
        if (handle == nullptr || handle == INVALID_HANDLE_VALUE)
        {
            break;
        }

        DWORD mode = 0;
        if (!GetConsoleMode(handle, &mode))
        {
            break;
        }

        isConsole = true;
    } while (false);

    return isConsole;
}

static bool ClearConsoleScreen(std::wstring* error)
{
    bool ok = false;

    do
    {
        HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
        if (!IsConsoleOutputHandle(handle))
        {
            if (error != nullptr)
            {
                *error = L"stdout is not a console";
            }
            break;
        }

        std::lock_guard<std::recursive_mutex> lock(g_ConsoleOutputMutex);

        CONSOLE_SCREEN_BUFFER_INFO info = {};
        if (!GetConsoleScreenBufferInfo(handle, &info))
        {
            if (error != nullptr)
            {
                *error = FormatWin32Error(L"GetConsoleScreenBufferInfo failed", GetLastError());
            }
            break;
        }

        if (info.dwSize.X <= 0 || info.dwSize.Y <= 0)
        {
            if (error != nullptr)
            {
                *error = L"console buffer size is invalid";
            }
            break;
        }

        DWORD cellCount = static_cast<DWORD>(info.dwSize.X) * static_cast<DWORD>(info.dwSize.Y);
        COORD origin = {};
        DWORD written = 0;
        if (!FillConsoleOutputCharacterW(handle, L' ', cellCount, origin, &written))
        {
            if (error != nullptr)
            {
                *error = FormatWin32Error(L"FillConsoleOutputCharacterW failed", GetLastError());
            }
            break;
        }

        if (written != cellCount)
        {
            if (error != nullptr)
            {
                *error = L"FillConsoleOutputCharacterW wrote fewer cells than requested";
            }
            break;
        }

        written = 0;
        if (!FillConsoleOutputAttribute(handle, info.wAttributes, cellCount, origin, &written))
        {
            if (error != nullptr)
            {
                *error = FormatWin32Error(L"FillConsoleOutputAttribute failed", GetLastError());
            }
            break;
        }

        if (written != cellCount)
        {
            if (error != nullptr)
            {
                *error = L"FillConsoleOutputAttribute wrote fewer cells than requested";
            }
            break;
        }

        if (!SetConsoleCursorPosition(handle, origin))
        {
            if (error != nullptr)
            {
                *error = FormatWin32Error(L"SetConsoleCursorPosition failed", GetLastError());
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool WriteConsoleTuiLineDirect(
    HANDLE handle,
    const std::wstring& value,
    WORD color,
    uint64_t expectedOutputSerial = std::numeric_limits<uint64_t>::max())
{
    bool writtenOk = false;

    do
    {
        if (!IsConsoleOutputHandle(handle))
        {
            break;
        }

        std::lock_guard<std::recursive_mutex> lock(g_ConsoleOutputMutex);
        if (expectedOutputSerial != std::numeric_limits<uint64_t>::max() &&
            g_CommandStreamOutputSerial.load(std::memory_order_relaxed) != expectedOutputSerial)
        {
            break;
        }

        CONSOLE_SCREEN_BUFFER_INFO info = {};
        WORD oldAttributes = 0;
        bool hasOldAttributes = false;
        if (GetConsoleScreenBufferInfo(handle, &info))
        {
            oldAttributes = info.wAttributes;
            hasOldAttributes = true;
            WORD preserved = static_cast<WORD>(info.wAttributes & 0xfff0);
            SetConsoleTextAttribute(handle, static_cast<WORD>(preserved | color));
        }

        std::wstring line = L"| " + TuiFitText(value, 76) + L" |\n";
        DWORD written = 0;
        if (WriteConsoleW(handle, line.c_str(), static_cast<DWORD>(line.size()), &written, nullptr))
        {
            writtenOk = true;
        }

        if (hasOldAttributes)
        {
            SetConsoleTextAttribute(handle, oldAttributes);
        }
    } while (false);

    return writtenOk;
}

static std::wstring FormatElapsedSeconds(uint64_t milliseconds)
{
    std::wstring text;

    do
    {
        uint64_t seconds = milliseconds / 1000;
        uint64_t tenths = (milliseconds % 1000) / 100;

        std::wstringstream stream;
        stream << seconds << L"." << tenths << L"s";
        text = stream.str();
    } while (false);

    return text;
}

static std::wstring ShortCommandText(const std::wstring& command)
{
    std::wstring result = TrimWhitespace(command);

    do
    {
        if (result.empty())
        {
            result = L"<empty>";
            break;
        }

        for (wchar_t& ch : result)
        {
            if (ch == L'\r' || ch == L'\n' || ch == L'\t')
            {
                ch = L' ';
            }
        }

        if (result.size() > 48)
        {
            result.resize(45);
            result += L"...";
        }
    } while (false);

    return result;
}

class ScopedCommandProgress
{
public:
    ScopedCommandProgress(const std::wstring& command, const std::wstring& origin, bool enabled) :
        command_(ShortCommandText(command)),
        origin_(origin.empty() ? L"command" : origin),
        handle_(GetStdHandle(STD_OUTPUT_HANDLE)),
        startTick_(GetTickCount64()),
        initialOutputSerial_(g_CommandStreamOutputSerial.load(std::memory_order_relaxed)),
        stopRequested_(false),
        completed_(false),
        displayed_(false)
    {
        bool shouldStart = enabled && !command_.empty() && IsConsoleOutputHandle(handle_);
        if (shouldStart)
        {
            try
            {
                worker_ = std::thread(&ScopedCommandProgress::WorkerMain, this);
            }
            catch (...)
            {
                // Progress is best-effort and must never block command execution.
            }
        }
    }

    ~ScopedCommandProgress()
    {
        Complete();
    }

    void Complete()
    {
        bool expected = false;
        if (!completed_.compare_exchange_strong(expected, true))
        {
            return;
        }

        stopRequested_ = true;
        if (worker_.joinable())
        {
            worker_.join();
        }

        if (displayed_.load())
        {
            uint64_t elapsed = GetTickCount64() - startTick_;
            WriteConsoleTuiLineDirect(
                handle_,
                L"[ .. ] " + origin_ + L" finished: " + command_ + L" elapsed=" + FormatElapsedSeconds(elapsed),
                KNDBG_COLOR_DIM);
        }
    }

private:
    void WorkerMain()
    {
        static constexpr uint64_t START_DELAY_MS = 1200;
        static constexpr uint64_t UPDATE_INTERVAL_MS = 3000;
        uint64_t nextUpdate = START_DELAY_MS;

        while (!stopRequested_.load())
        {
            uint64_t elapsed = GetTickCount64() - startTick_;
            if (elapsed >= nextUpdate)
            {
                if (g_CommandStreamOutputSerial.load(std::memory_order_relaxed) != initialOutputSerial_)
                {
                    Sleep(100);
                    continue;
                }

                if (WriteConsoleTuiLineDirect(
                        handle_,
                        L"[ .. ] " + origin_ + L" still running: " + command_ + L" elapsed=" + FormatElapsedSeconds(elapsed),
                        KNDBG_COLOR_STEP,
                        initialOutputSerial_))
                {
                    displayed_ = true;
                    nextUpdate += UPDATE_INTERVAL_MS;
                }
            }

            Sleep(100);
        }
    }

    std::wstring command_;
    std::wstring origin_;
    HANDLE handle_;
    uint64_t startTick_;
    uint64_t initialOutputSerial_;
    std::atomic_bool stopRequested_;
    std::atomic_bool completed_;
    std::atomic_bool displayed_;
    std::thread worker_;
};

static bool LoadDriverServiceWithUx(
    DriverService& service,
    const std::wstring& title,
    const std::wstring& driverPath,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        PrintLifecycleHeader(title, L"image: " + driverPath);

        DriverStatus before = {};
        PrintLifecycleStep(L"query service", L"SCM status");
        if (!service.Query(&before, error))
        {
            PrintLifecycleFail(L"query service", error != nullptr ? *error : L"unknown error");
            break;
        }
        PrintLifecycleOk(L"query service", DriverStatusSummary(before));

        PrintLifecycleStep(L"install/update service", L"kernel driver demand-start entry");
        if (!service.Install(driverPath, error))
        {
            PrintLifecycleFail(L"install/update service", error != nullptr ? *error : L"unknown error");
            break;
        }
        PrintLifecycleOk(L"install/update service", L"configured");

        PrintLifecycleStep(L"load driver", L"start service");
        if (!service.Start(error))
        {
            PrintLifecycleFail(L"load driver", error != nullptr ? *error : L"unknown error");
            break;
        }
        PrintLifecycleOk(L"load driver", L"running");

        DriverStatus after = {};
        PrintLifecycleStep(L"verify final state", L"SCM status");
        if (!service.Query(&after, error))
        {
            PrintLifecycleFail(L"verify final state", error != nullptr ? *error : L"unknown error");
            break;
        }
        PrintLifecycleOk(L"verify final state", DriverStatusSummary(after));
        PrintTuiRule();
        ok = true;
    } while (false);

    return ok;
}

static bool UnloadDriverServiceWithUx(
    DriverService& service,
    const std::wstring& title,
    DriverUnloadResult* unloadResult,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        PrintLifecycleHeader(title, L"SCM stop/delete sequence");

        DriverStatus before = {};
        PrintLifecycleStep(L"query service", L"SCM status");
        if (!service.Query(&before, error))
        {
            PrintLifecycleFail(L"query service", error != nullptr ? *error : L"unknown error");
            break;
        }
        PrintLifecycleOk(L"query service", DriverStatusSummary(before));

        if (!before.Installed)
        {
            PrintLifecycleOk(L"unload service", L"already absent");
            PrintTuiRule();
            if (unloadResult != nullptr)
            {
                *unloadResult = {};
                unloadResult->Deleted = true;
                unloadResult->FinalState = L"not-installed";
            }
            ok = true;
            break;
        }

        PrintLifecycleStep(L"stop/delete service", L"release kernel driver image");
        if (!service.StopAndDelete(unloadResult, error))
        {
            PrintLifecycleFail(L"stop/delete service", error != nullptr ? *error : L"unknown error");
            break;
        }

        std::wstring finalState = unloadResult != nullptr ? unloadResult->FinalState : L"deleted";
        PrintLifecycleOk(L"stop/delete service", finalState);
        PrintTuiRule();
        ok = true;
    } while (false);

    return ok;
}

static bool CleanupMainDriverOnExit(DebuggerState& state, DeviceClient& device, DriverService& service)
{
    bool ok = false;
    std::wstring error;

    do
    {
        if (!state.MainDriverCleanupRequested)
        {
            ok = true;
            break;
        }

        if (state.MainDriverUnloaded)
        {
            ok = true;
            break;
        }

        PrintLifecycleHeader(L"KnLiveDbg shutdown", L"automatic driver unload/remove");
        PrintLifecycleStep(L"close device handle", L"release controller session");
        if (device.IsOpen())
        {
            device.Close();
            PrintLifecycleOk(L"close device handle", L"closed");
        }
        else
        {
            PrintLifecycleOk(L"close device handle", L"already closed");
        }

        DriverUnloadResult unloadResult = {};
        if (!UnloadDriverServiceWithUx(service, L"Main driver automatic unload", &unloadResult, &error))
        {
            std::wcerr << L"automatic driver unload failed: " << error << L"\n";
            break;
        }

        state.MainDriverUnloaded = true;
        ok = true;
    } while (false);

    return ok;
}

static bool CleanupProbeDriverOnExit(DebuggerState& state)
{
    bool ok = false;
    std::wstring error;

    do
    {
        if (!state.ProbeDriverCleanupRequested)
        {
            ok = true;
            break;
        }

        if (state.ProbeDriverUnloaded)
        {
            ok = true;
            break;
        }

        DriverService probeService(KNDBG_PROBE_SERVICE_NAME, KNDBG_PROBE_DISPLAY_NAME);
        DriverUnloadResult unloadResult = {};
        if (!UnloadDriverServiceWithUx(probeService, L"Probe driver automatic unload", &unloadResult, &error))
        {
            std::wcerr << L"automatic probe driver unload failed: " << error << L"\n";
            break;
        }

        state.ProbeDriverUnloaded = true;
        ok = true;
    } while (false);

    return ok;
}

static bool CleanupByovdFixtureDriverOnExit(DebuggerState& state)
{
    bool ok = false;
    std::wstring error;

    do
    {
        if (!state.ByovdFixtureCleanupRequested)
        {
            ok = true;
            break;
        }

        if (state.ByovdFixtureUnloaded)
        {
            ok = true;
            break;
        }

        DriverService fixtureService(KNDBG_BYOVD_FIXTURE_SERVICE_NAME, KNDBG_BYOVD_FIXTURE_DISPLAY_NAME);
        DriverUnloadResult unloadResult = {};
        if (!UnloadDriverServiceWithUx(fixtureService, L"BYOVD fixture automatic unload", &unloadResult, &error))
        {
            std::wcerr << L"automatic BYOVD fixture unload failed: " << error << L"\n";
            break;
        }

        state.ByovdFixtureUnloaded = true;
        ok = true;
    } while (false);

    return ok;
}

static bool AcquireSingleInstanceLock(std::wstring* error)
{
    bool ok = false;
    constexpr const wchar_t* MutexName = L"Global\\KnLiveDbg.Exe.SingleInstance";

    do
    {
        g_InstanceMutexHandle = CreateMutexW(nullptr, TRUE, MutexName);
        if (g_InstanceMutexHandle == nullptr)
        {
            DWORD lastError = GetLastError();
            if (lastError == ERROR_ACCESS_DENIED)
            {
                HANDLE existing = OpenMutexW(SYNCHRONIZE, FALSE, MutexName);
                if (existing != nullptr)
                {
                    CloseHandle(existing);
                    if (error != nullptr)
                    {
                        *error = L"another KnLiveDbg.exe instance is already running";
                    }
                    break;
                }
            }

            if (error != nullptr)
            {
                *error = FormatWin32Error(L"CreateMutexW single-instance gate failed", lastError);
            }
            break;
        }

        if (GetLastError() == ERROR_ALREADY_EXISTS)
        {
            CloseHandle(g_InstanceMutexHandle);
            g_InstanceMutexHandle = nullptr;
            if (error != nullptr)
            {
                *error = L"another KnLiveDbg.exe instance is already running";
            }
            break;
        }

        g_InstanceMutexOwned = true;
        ok = true;
    } while (false);

    return ok;
}

static void ReleaseSingleInstanceLock()
{
    if (g_InstanceMutexHandle != nullptr)
    {
        if (g_InstanceMutexOwned)
        {
            ReleaseMutex(g_InstanceMutexHandle);
            g_InstanceMutexOwned = false;
        }

        CloseHandle(g_InstanceMutexHandle);
        g_InstanceMutexHandle = nullptr;
    }
}

static std::wstring BuildDriverPanelText(DriverService& service, DeviceClient& device)
{
    std::wstring text = L"Driver: device=open";
    std::wstring error;

    do
    {
        DriverStatus status = {};
        if (service.Query(&status, &error))
        {
            text += L" service=";
            text += (status.Installed ? std::wstring(L"installed") : std::wstring(L"not-installed"));
            if (!status.StateText.empty())
            {
                text += L"/" + status.StateText;
            }
        }
        else
        {
            text += L" service=query-failed";
        }

        DriverSessionStatus session = {};
        if (device.IsOpen() && device.QuerySessionStatus(&session, &error))
        {
            text += L" write=";
            text += ((session.Flags & KNDBG_SESSION_FLAG_WRITE_ENABLED) != 0 ? std::wstring(L"on") : std::wstring(L"off"));
            text += L" handles=" + std::to_wstring(session.OpenHandleCount);
            text += L" owner-pid=" + std::to_wstring(session.OwnerPid);
        }
    } while (false);

    return text;
}

static std::wstring BuildProbePanelText()
{
    std::wstring text = L"Probe: not-loaded";
    std::wstring error;
    DriverService probeService(KNDBG_PROBE_SERVICE_NAME, KNDBG_PROBE_DISPLAY_NAME);

    do
    {
        DriverStatus status = {};
        if (!probeService.Query(&status, &error))
        {
            text = L"Probe: query-failed";
            break;
        }

        if (!status.Installed)
        {
            break;
        }

        text = L"Probe: " + status.StateText;
        if (status.CurrentState == SERVICE_RUNNING)
        {
            KNDBG_PROBE_INFO_RESPONSE info = {};
            if (QueryProbeInfo(&info, &error))
            {
                text += L" va=" + HexText(info.BufferVirtualAddress);
                text += L" pa=" + HexText(info.BufferPhysicalAddress);
                text += info.FirmwareProviderRegistered != 0 ? L" fw=KNFW" : L" fw=not-registered";
            }
        }
    } while (false);

    return text;
}

static void PrintStartupTui(
    const DebuggerState& state,
    DriverService& service,
    DeviceClient& device,
    SymbolEngine& symbols,
    const AiProviderRuntime& ai)
{
    const AiProviderSettings& aiSettings = ai.Settings();
    std::wstring model = aiSettings.Model.empty() ? L"default" : aiSettings.Model;
    std::wstring dotEnv = aiSettings.DotEnvPath.empty() ? L"none" : aiSettings.DotEnvPath;
    std::wstring dbgengMode = state.DbgEngRemoteKernel ? L"remote-kernel" : L"local-kernel";

    PrintWelcomeBanner();
    PrintTuiLine(L"KnLiveDbg live kernel debugger console", KNDBG_COLOR_TITLE);
    PrintTuiLine(L"WinDbg-style commands over native memory IOCTLs and optional DbgEng", KNDBG_COLOR_DIM);
    PrintTuiRule();
    PrintTuiLine(BuildDriverPanelText(service, device), KNDBG_COLOR_OK);
    PrintTuiLine(L"Backend: " + std::wstring(BackendModeText(state.Backend)) + L" dbgeng=lazy kd-mode=" + dbgengMode + L" base=16", KNDBG_COLOR_ACCENT);
    PrintTuiLine(L"Symbols: ready=" + std::wstring(symbols.IsReady() ? L"yes" : L"no") +
                 L" modules=" + std::to_wstring(symbols.Modules().size()), symbols.IsReady() ? KNDBG_COLOR_OK : KNDBG_COLOR_WARN);
    PrintTuiLine(L"AI: provider=" + ai.ProviderName() + L" model=" + model +
                 L" policy=" + ai.RemotePolicyName() + L" credential=" + ai.CredentialStatus(), KNDBG_COLOR_TEXT);
    PrintTuiLine(L"Env: " + dotEnv, dotEnv == L"none" ? KNDBG_COLOR_DIM : KNDBG_COLOR_OK);
    PrintTuiLine(BuildProbePanelText(), KNDBG_COLOR_TEXT);
    PrintTuiRule();
    PrintTuiLine(L"Quick actions", KNDBG_COLOR_TITLE);
    PrintTuiLine(L"  help          show native command summary", KNDBG_COLOR_TEXT);
    PrintTuiLine(L"  help all      include DbgEng-routed WinDbg commands", KNDBG_COLOR_TEXT);
    PrintTuiLine(L"  drvstatus     inspect service/session/write gate state", KNDBG_COLOR_TEXT);
    PrintTuiLine(L"  probe load    load positive-control VA/PA and fwtable provider", KNDBG_COLOR_TEXT);
    PrintTuiLine(L"  callbacks all enumerate callback surfaces including minifilters", KNDBG_COLOR_TEXT);
    PrintTuiLine(L"  ai status     inspect provider, model, policy, and credentials", KNDBG_COLOR_TEXT);
    PrintTuiBlank();
    PrintTuiLine(L"Examples", KNDBG_COLOR_TITLE);
    PrintTuiLine(L"  lm nt                    x nt!*Process*", KNDBG_COLOR_DIM);
    PrintTuiLine(L"  dt nt!_EPROCESS <addr>   dq nt!PsLoadedModuleList 8", KNDBG_COLOR_DIM);
    PrintTuiLine(L"  vtop <addr>              pdb <physical-address> 80", KNDBG_COLOR_DIM);
    PrintTuiLine(L"  u nt!KiSystemCall64 8    uf nt!KiSystemCall64", KNDBG_COLOR_DIM);
    PrintTuiLine(L"  !dml_proc [pid|name]     backend native", KNDBG_COLOR_DIM);
    PrintTuiRule();
    PrintTuiLine(L"Type home to redraw this screen. Type q, quit, or exit to unload and leave.", KNDBG_COLOR_WARN);
    PrintTuiRule();
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
        lowered == L"object" ||
        lowered == L"registry" ||
        lowered == L"process" ||
        lowered == L"thread" ||
        lowered == L"imageload" ||
        lowered == L"minifilter")
    {
        result = true;
    }

    return result;
}

static bool IsDeprecatedCallbackScopeAlias(const std::wstring& value)
{
    bool result = false;
    std::wstring lowered = ToLower(value);

    if (lowered == L"ob" ||
        lowered == L"objects" ||
        lowered == L"object-manager" ||
        lowered == L"reg" ||
        lowered == L"proc" ||
        lowered == L"processes" ||
        lowered == L"ps" ||
        lowered == L"threads" ||
        lowered == L"thr" ||
        lowered == L"th" ||
        lowered == L"image" ||
        lowered == L"loadimage" ||
        lowered == L"load-image" ||
        lowered == L"imgload" ||
        lowered == L"mini" ||
        lowered == L"minifilters" ||
        lowered == L"flt" ||
        lowered == L"fltmgr" ||
        lowered == L"filter" ||
        lowered == L"filters")
    {
        result = true;
    }

    return result;
}

static bool IsCallbackModuleOption(const std::wstring& value)
{
    std::wstring lowered = ToLower(value);
    return lowered == L"/module";
}

static bool IsDeprecatedCallbackModuleOption(const std::wstring& value)
{
    std::wstring lowered = ToLower(value);
    return lowered == L"--module" || lowered == L"-m";
}

static std::wstring CallbackComparableModuleName(const std::wstring& value, bool removeExtension)
{
    std::wstring comparable;

    do
    {
        std::wstring text = TrimWhitespace(value);
        if (text.empty())
        {
            break;
        }

        if (text.size() >= 2 &&
            ((text.front() == L'"' && text.back() == L'"') ||
             (text.front() == L'\'' && text.back() == L'\'')))
        {
            text = text.substr(1, text.size() - 2);
        }

        size_t bang = text.find(L'!');
        if (bang != std::wstring::npos)
        {
            text = text.substr(0, bang);
        }

        size_t slash = text.find_last_of(L"\\/");
        if (slash != std::wstring::npos)
        {
            text = text.substr(slash + 1);
        }

        text = ToLower(text);
        if (removeExtension)
        {
            size_t dot = text.find_last_of(L'.');
            if (dot != std::wstring::npos)
            {
                text = text.substr(0, dot);
            }
        }

        comparable = text;
    } while (false);

    return comparable;
}

static bool CallbackModuleTextMatchesFilter(const std::wstring& moduleText, const std::wstring& moduleFilter)
{
    bool matched = false;

    do
    {
        std::wstring filterBase = CallbackComparableModuleName(moduleFilter, false);
        if (filterBase.empty())
        {
            matched = true;
            break;
        }

        std::wstring moduleBase = CallbackComparableModuleName(moduleText, false);
        if (moduleBase.empty())
        {
            break;
        }

        if (moduleBase == filterBase)
        {
            matched = true;
            break;
        }

        std::wstring filterStem = CallbackComparableModuleName(moduleFilter, true);
        std::wstring moduleStem = CallbackComparableModuleName(moduleText, true);
        if (!filterStem.empty() && moduleStem == filterStem)
        {
            matched = true;
            break;
        }
    } while (false);

    return matched;
}

static bool CallbackRecordMatchesModuleFilter(
    const KernelCallbackRecord& record,
    const std::wstring& moduleFilter)
{
    bool matched = false;

    do
    {
        if (TrimWhitespace(moduleFilter).empty())
        {
            matched = true;
            break;
        }

        if (CallbackModuleTextMatchesFilter(record.FunctionModule, moduleFilter) ||
            CallbackModuleTextMatchesFilter(record.PostFunctionModule, moduleFilter))
        {
            matched = true;
            break;
        }

        if (record.Kind == L"minifilter" &&
            CallbackModuleTextMatchesFilter(record.FilterName, moduleFilter))
        {
            matched = true;
            break;
        }
    } while (false);

    return matched;
}

static void ApplyCallbackModuleFilter(
    const std::wstring& moduleFilter,
    KernelCallbackScanResult* result)
{
    do
    {
        if (result == nullptr || TrimWhitespace(moduleFilter).empty())
        {
            break;
        }

        std::vector<KernelCallbackRecord> filtered;
        filtered.reserve(result->Records.size());
        for (const KernelCallbackRecord& record : result->Records)
        {
            if (CallbackRecordMatchesModuleFilter(record, moduleFilter))
            {
                filtered.push_back(record);
            }
        }

        result->Records.swap(filtered);
    } while (false);
}

static WORD CallbackKindColor(const std::wstring& kind)
{
    WORD color = KNDBG_COLOR_ACCENT;

    if (kind == L"ob")
    {
        color = KNDBG_COLOR_TITLE;
    }
    else if (kind == L"minifilter")
    {
        color = KNDBG_COLOR_WARN;
    }
    else if (kind == L"registry")
    {
        color = KNDBG_COLOR_ACCENT;
    }
    else if (kind == L"process")
    {
        color = KNDBG_COLOR_OK;
    }
    else if (kind == L"thread")
    {
        color = KNDBG_COLOR_OK;
    }
    else if (kind == L"imageload")
    {
        color = KNDBG_COLOR_WARN;
    }

    return color;
}

static std::wstring ProcessNotifyMetadataText(uint64_t metadata)
{
    std::wstring text;

    do
    {
        if (metadata == 0)
        {
            text = L"PsSetCreateProcessNotifyRoutine";
            break;
        }

        if (metadata == 0x6)
        {
            text = L"PsSetCreateProcessNotifyRoutineEx2";
            break;
        }

        if (metadata == 0x2)
        {
            text = L"PsSetCreateProcessNotifyRoutineEx";
            break;
        }

        text = L"unknown";
    } while (false);

    return text;
}

static void PrintCallbackAddress(
    const wchar_t* label,
    uint64_t address,
    const std::wstring& moduleName,
    const std::wstring& symbolName,
    bool showNonImageModule)
{
    do
    {
        if (address == 0)
        {
            break;
        }

        std::wcout << L"  ";
        PrintColoredText(label, KNDBG_COLOR_ACCENT);
        std::wcout << L"=" << HexTextWidth(address, 16, true);
        if (!moduleName.empty())
        {
            std::wcout << L" module=";
            PrintColoredText(moduleName, KNDBG_COLOR_OK);
        }
        else if (showNonImageModule)
        {
            std::wcout << L" module=";
            PrintColoredText(L"<non-image>", KNDBG_COLOR_WARN);
        }

        if (!symbolName.empty())
        {
            std::wcout << L" symbol=";
            PrintColoredText(symbolName, KNDBG_COLOR_TITLE);
        }

        std::wcout << L"\n";
    } while (false);
}

static void PrintCallbackContext(const KernelCallbackRecord& record)
{
    do
    {
        if (record.Kind == L"process")
        {
            std::wcout << L"  ";
            PrintColoredText(L"notifyType", KNDBG_COLOR_ACCENT);
            std::wcout << L"=";
            PrintColoredText(ProcessNotifyMetadataText(record.Context), KNDBG_COLOR_TITLE);
            std::wcout << L" metadata=" << HexTextWidth(record.Context, 16, true) << L"\n";
            break;
        }

        if (record.Context == 0)
        {
            break;
        }

        const wchar_t* label = L"context";
        if (record.Kind == L"registry")
        {
            label = L"callbackContext";
        }
        else if (record.Kind == L"ob")
        {
            label = L"registrationContext";
        }
        else if (record.Kind == L"thread")
        {
            label = L"callbackContext";
        }
        else if (record.Kind == L"imageload")
        {
            label = L"callbackContext";
        }

        std::wstring symbolName;
        if (!record.ContextModule.empty())
        {
            symbolName = record.ContextSymbol;
        }

        PrintCallbackAddress(
            label,
            record.Context,
            record.ContextModule,
            symbolName,
            false);
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
        std::wstring moduleFilter;
        if (args.size() >= 2)
        {
            if (HasHelpToken(args, 1))
            {
                PrintCallbacksHelpFromArgs(args, 1);
                break;
            }

            size_t index = 1;
            if (IsCallbackScopeName(args[index]))
            {
                scope = args[index];
                ++index;
            }
            else if (IsDeprecatedCallbackModuleOption(args[index]) ||
                     IsDeprecatedCallbackScopeAlias(args[index]))
            {
                std::wcerr << L"usage: callbacks [all|object|registry|process|thread|imageload|minifilter] [module]\n";
                PrintCallbacksHelp();
                break;
            }
            else if (!IsCallbackModuleOption(args[index]))
            {
                moduleFilter = args[index];
                ++index;
            }

            while (index < args.size())
            {
                if (IsCallbackModuleOption(args[index]))
                {
                    if (index + 1 >= args.size())
                    {
                        std::wcerr << L"usage: callbacks [scope] /module <module>\n";
                        break;
                    }

                    if (!moduleFilter.empty())
                    {
                        std::wcerr << L"usage: callbacks [scope] [module]\n";
                        break;
                    }

                    moduleFilter = args[index + 1];
                    index += 2;
                    continue;
                }

                if (IsDeprecatedCallbackModuleOption(args[index]) ||
                    IsDeprecatedCallbackScopeAlias(args[index]))
                {
                    std::wcerr << L"usage: callbacks [scope] [module]\n";
                    break;
                }

                if (moduleFilter.empty())
                {
                    moduleFilter = args[index];
                    ++index;
                    continue;
                }

                std::wcerr << L"usage: callbacks [scope] [module]\n";
                break;
            }

            if (index < args.size())
            {
                break;
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

        ApplyCallbackModuleFilter(moduleFilter, &result);

        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"callback warning: " << warning << L"\n";
        }

        PrintColoredText(L"callback records", KNDBG_COLOR_TITLE);
        std::wcout << L"=" << result.Records.size();
        if (!moduleFilter.empty())
        {
            std::wcout << L" ";
            PrintColoredText(L"module", KNDBG_COLOR_ACCENT);
            std::wcout << L"=";
            PrintColoredText(moduleFilter, KNDBG_COLOR_OK);
        }
        std::wcout << L"\n";
        for (const KernelCallbackRecord& record : result.Records)
        {
            PrintColoredText(L"[" + record.Kind + L"]", CallbackKindColor(record.Kind));
            if (record.Kind == L"ob")
            {
                std::wcout << L" object=";
                PrintColoredText(record.Target.empty() ? L"<unknown>" : record.Target, KNDBG_COLOR_TITLE);
            }
            else
            {
                std::wcout << L" ";
                PrintColoredText(record.Target, CallbackKindColor(record.Kind));
            }

            if (!record.Altitude.empty())
            {
                std::wcout << L" altitude=\"" << record.Altitude << L"\"";
            }

            if (!record.CallbackName.empty())
            {
                std::wcout << L" callback=";
                PrintColoredText(record.CallbackName, KNDBG_COLOR_TITLE);
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
                std::wcout << L"  ";
                PrintColoredText(L"root", KNDBG_COLOR_ACCENT);
                std::wcout << L"=" << HexTextWidth(record.RootAddress, 16, true);
                if (!record.RootSource.empty())
                {
                    std::wcout << L" source=" << record.RootSource;
                }
                std::wcout << L"\n";
            }

            if (record.Filter != 0)
            {
                std::wcout << L"  ";
                PrintColoredText(L"filter", KNDBG_COLOR_ACCENT);
                std::wcout << L"=" << HexTextWidth(record.Filter, 16, true);
                if (record.Frame != 0)
                {
                    std::wcout << L" frame=" << HexTextWidth(record.Frame, 16, true);
                }
                if (record.FrameId != 0xffffffffu)
                {
                    std::wcout << L" frameId=" << record.FrameId;
                }
                std::wcout << L"\n";
            }

            if (record.DriverObject != 0)
            {
                std::wcout << L"  ";
                PrintColoredText(L"driverObject", KNDBG_COLOR_ACCENT);
                std::wcout << L"=" << HexTextWidth(record.DriverObject, 16, true) << L"\n";
            }

            if (record.ObjectType != 0)
            {
                std::wcout << L"  ";
                PrintColoredText(L"object", KNDBG_COLOR_ACCENT);
                std::wcout << L"=";
                PrintColoredText(record.Target.empty() ? L"<unknown>" : record.Target, KNDBG_COLOR_TITLE);
                if (record.ObjectTypeIndex != 0xffffffffu)
                {
                    std::wcout << L" typeIndex=0x" << std::hex << record.ObjectTypeIndex << std::dec;
                }

                std::wcout << L" objectType=" << HexTextWidth(record.ObjectType, 16, true);
                if (!record.ObjectTypeSource.empty())
                {
                    std::wcout << L" source=" << record.ObjectTypeSource;
                }
                std::wcout << L"\n";
            }

            if (record.ListEntry != 0)
            {
                std::wcout << L"  ";
                PrintColoredText(L"list", KNDBG_COLOR_ACCENT);
                std::wcout << L"=" << HexTextWidth(record.ListEntry, 16, true) << L"\n";
            }

            if (record.Entry != 0)
            {
                std::wcout << L"  ";
                PrintColoredText(L"entry", KNDBG_COLOR_ACCENT);
                std::wcout << L"=" << HexTextWidth(record.Entry, 16, true) << L"\n";
            }

            if (record.CallbackBlock != 0)
            {
                std::wcout << L"  ";
                PrintColoredText(L"block", KNDBG_COLOR_ACCENT);
                std::wcout << L"=" << HexTextWidth(record.CallbackBlock, 16, true)
                           << L" raw=" << HexTextWidth(record.RawValue, 16, true) << L"\n";
            }

            if (record.CallbackEntry != 0)
            {
                std::wcout << L"  ";
                PrintColoredText(L"callbackEntry", KNDBG_COLOR_ACCENT);
                std::wcout << L"=" << HexTextWidth(record.CallbackEntry, 16, true) << L"\n";
            }

            const wchar_t* primaryLabel = L"pre";
            if (record.Kind == L"process" ||
                record.Kind == L"thread" ||
                record.Kind == L"imageload" ||
                (record.Kind == L"minifilter" && record.PostFunction == 0))
            {
                primaryLabel = L"function";
            }

            PrintCallbackAddress(
                primaryLabel,
                record.Function,
                record.FunctionModule,
                record.FunctionSymbol,
                true);
            PrintCallbackAddress(
                L"post",
                record.PostFunction,
                record.PostFunctionModule,
                record.PostFunctionSymbol,
                true);
            PrintCallbackContext(record);

            if (record.Cookie != 0)
            {
                std::wcout << L"  cookie=0x" << std::hex << std::setw(16) << std::setfill(L'0')
                           << record.Cookie << std::dec << L"\n";
            }

            if (!record.Notes.empty())
            {
                std::wcout << L"  ";
                PrintColoredText(L"notes", KNDBG_COLOR_WARN);
                std::wcout << L"=" << record.Notes << L"\n";
            }
        }
    } while (false);
}

static void PrintWfpHelp()
{
    std::wcout << L"!wfp command:\n";
    std::wcout << L"  !wfp providers\n";
    std::wcout << L"  !wfp sublayers\n";
    std::wcout << L"  !wfp callouts [/module <name|GUID>]\n";
    std::wcout << L"  !wfp kernelcallouts\n";
    std::wcout << L"  !wfp filters [/layer <name|GUID>] [/provider <name|GUID>]\n";
    std::wcout << L"  !wfp layers\n";
    std::wcout << L"\n";
    std::wcout << L"scopes:\n";
    std::wcout << L"  providers       registered WFP providers (driver service identities)\n";
    std::wcout << L"  sublayers       configured WFP sublayers and weights\n";
    std::wcout << L"  callouts        registered WFP callouts with applicable layer and owning provider (user-mode BFE)\n";
    std::wcout << L"  kernelcallouts  kernel-mode classify/notify/flowDelete function pointers from the netio.sys\n";
    std::wcout << L"                  callout table, joined to callout metadata; flags classify targets outside\n";
    std::wcout << L"                  loaded kernel modules. Requires the driver device and netio.sys symbols.\n";
    std::wcout << L"  filters         installed WFP filters with layer, sublayer, provider, action, and weight\n";
    std::wcout << L"  layers          active WFP management layers with kernel/builtin/buffered flags\n";
    std::wcout << L"\n";
    std::wcout << L"options:\n";
    std::wcout << L"  /module <name|GUID>    callouts only; match owning provider service name, display name, or providerKey GUID\n";
    std::wcout << L"  /layer <name|GUID>     filters only; match layer display name (substring) or layerKey GUID\n";
    std::wcout << L"  /provider <name|GUID>  filters only; match provider service name, display name, or providerKey GUID\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  Uses the user-mode Base Filtering Engine (BFE) through fwpuclnt.dll; requires the BFE service running.\n";
    std::wcout << L"  Module ownership for callouts comes from the providerKey -> provider serviceName mapping.\n";
    std::wcout << L"  Kernel-mode callout function pointers are not exposed through fwpuclnt and are intentionally omitted.\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  !wfp providers\n";
    std::wcout << L"  !wfp callouts\n";
    std::wcout << L"  !wfp callouts /module tcpip\n";
    std::wcout << L"  !wfp filters /layer ALE_AUTH_CONNECT_V4\n";
    std::wcout << L"  !wfp filters /provider WdFilter\n";
    std::wcout << L"  !wfp layers\n";
}

static void PrintWfpRecord(const WfpRecord& record)
{
    PrintColoredText(L"[" + record.Kind + L"]", KNDBG_COLOR_TITLE);

    if (record.Kind == L"wfp.filter")
    {
        std::wcout << L" id=" << record.Id;
    }
    else if (record.Kind == L"wfp.callout" && record.HasCalloutId)
    {
        std::wcout << L" calloutId=" << record.CalloutId;
    }
    else if (record.Kind == L"wfp.layer" && record.HasLayerId)
    {
        std::wcout << L" layerId=" << record.LayerId;
    }

    std::wcout << L" name=\"" << record.Name << L"\"";
    std::wcout << L" key=";
    PrintColoredText(record.Key, KNDBG_COLOR_ACCENT);

    if (record.Kind == L"wfp.filter")
    {
        std::wcout << L" action=";
        PrintColoredText(record.ActionText, KNDBG_COLOR_OK);
        std::wcout << L"(0x" << std::hex << record.Action << L")" << std::dec;
        if (!record.ActionKey.empty())
        {
            std::wcout << L" calloutKey=" << record.ActionKey;
        }
        std::wcout << L" weight=" << record.WeightText;
        std::wcout << L" conditions=" << record.NumConditions;
    }

    if (record.Kind == L"wfp.sublayer" && record.HasSubLayerWeight)
    {
        std::wcout << L" weight=0x" << std::hex << record.SubLayerWeight << std::dec;
    }

    std::wcout << L" flags=0x" << std::hex << record.Flags << std::dec;
    if (!record.FlagsText.empty())
    {
        std::wcout << L"(" << record.FlagsText << L")";
    }

    std::wcout << L"\n";

    if ((record.Kind == L"wfp.filter" || record.Kind == L"wfp.callout") && !record.LayerKey.empty())
    {
        std::wcout << L"  ";
        PrintColoredText(L"layer", KNDBG_COLOR_ACCENT);
        std::wcout << L"=";
        if (!record.LayerName.empty())
        {
            PrintColoredText(record.LayerName, KNDBG_COLOR_OK);
            std::wcout << L" ";
        }
        std::wcout << record.LayerKey;
        if (record.HasLayerId)
        {
            std::wcout << L" layerId=" << record.LayerId;
        }
        std::wcout << L"\n";
    }

    if (record.Kind == L"wfp.filter" && !record.SubLayerKey.empty())
    {
        std::wcout << L"  ";
        PrintColoredText(L"sublayer", KNDBG_COLOR_ACCENT);
        std::wcout << L"=";
        if (!record.SubLayerName.empty())
        {
            PrintColoredText(record.SubLayerName, KNDBG_COLOR_OK);
            std::wcout << L" ";
        }
        std::wcout << record.SubLayerKey << L"\n";
    }

    if (record.HasProvider && !record.ProviderKey.empty())
    {
        std::wcout << L"  ";
        PrintColoredText(L"provider", KNDBG_COLOR_ACCENT);
        std::wcout << L"=";
        if (!record.ProviderName.empty())
        {
            PrintColoredText(record.ProviderName, KNDBG_COLOR_OK);
            std::wcout << L" ";
        }
        std::wcout << record.ProviderKey;
        if (!record.ProviderService.empty())
        {
            std::wcout << L" service=\"" << record.ProviderService << L"\"";
        }
        std::wcout << L"\n";
    }
    else if (record.Kind == L"wfp.provider" && !record.ProviderService.empty())
    {
        std::wcout << L"  ";
        PrintColoredText(L"service", KNDBG_COLOR_ACCENT);
        std::wcout << L"=\"" << record.ProviderService << L"\"\n";
    }

    if (!record.Description.empty())
    {
        std::wcout << L"  description=\"" << record.Description << L"\"\n";
    }

    if (!record.Notes.empty())
    {
        std::wcout << L"  ";
        PrintColoredText(L"notes", KNDBG_COLOR_WARN);
        std::wcout << L"=" << record.Notes << L"\n";
    }
}

static void HandleWfpKernelCalloutsCommand(
    const std::vector<std::wstring>& args,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    do
    {
        if (HasHelpToken(args, 2))
        {
            PrintWfpHelp();
            break;
        }

        if (!device.IsOpen())
        {
            std::wcerr << L"!wfp kernelcallouts requires the KnLiveDbg.sys driver device to be open\n";
            break;
        }

        if (symbols.Modules().empty())
        {
            std::wstring loadError;
            if (!symbols.LoadKernelModules(&loadError))
            {
                std::wcerr << L"!wfp kernelcallouts failed: " << loadError << L"\n";
                break;
            }
        }

        WfpCalloutScanner scanner(device, symbols);
        WfpCalloutScanResult result = {};
        std::wstring error;
        if (!scanner.Scan(&result, &error))
        {
            std::wcerr << L"!wfp kernelcallouts failed: " << error << L"\n";
            for (const std::wstring& warning : result.Warnings)
            {
                std::wcerr << L"!wfp kernelcallouts warning: " << warning << L"\n";
            }
            break;
        }

        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"!wfp kernelcallouts warning: " << warning << L"\n";
        }

        if (!result.Resolved)
        {
            std::wcout << L"wfp kernel callouts: unresolved (netio.sys layout could not be located; see warnings)\n";
            break;
        }

        PrintColoredText(L"wfp kernel callouts", KNDBG_COLOR_TITLE);
        std::wcout << L" count=" << std::dec << result.Callouts.size()
                   << L" array=" << HexTextWidth(result.ArrayAddress, 16, true)
                   << L" layout=" << result.LayoutSource;
        if (result.AnySuspicious)
        {
            std::wcout << L" ";
            PrintColoredText(L"[SUSPICIOUS]", KNDBG_COLOR_FAIL);
            std::wcout << L" hooks=" << std::dec << result.SuspiciousCount;
        }
        std::wcout << L"\n";

        // Report the resolved engine base and the offsets that validated, so a
        // fallback-scan layout can be pinned as a documented candidate.
        std::wcout << L"  gWfpGlobal=" << HexTextWidth(result.GlobalSymbol, 16, true)
                   << L" engine=" << HexTextWidth(result.EngineBase, 16, true)
                   << (result.EngineFromPointer ? L" [deref]" : L" [direct]") << L"\n";
        std::wcout << L"  offsets: count@+0x" << std::hex << result.CountOffset
                   << L" array@+0x" << result.ArrayOffset
                   << L" entry=0x" << result.EntrySize
                   << L" classify@+0x" << result.ClassifyOffset << std::dec << L"\n";

        for (const WfpKernelCallout& callout : result.Callouts)
        {
            std::wcout << L"  ";
            PrintColoredText(L"[wfp.kcallout]", callout.ClassifySuspicious ? KNDBG_COLOR_FAIL : KNDBG_COLOR_TITLE);
            std::wcout << L" id=" << std::dec << callout.CalloutId
                       << L" classify=" << HexTextWidth(callout.ClassifyFn, 16, true);
            if (!callout.ClassifyModule.empty())
            {
                std::wcout << L" module=";
                PrintColoredText(callout.ClassifyModule, callout.ClassifySuspicious ? KNDBG_COLOR_WARN : KNDBG_COLOR_OK);
            }
            if (!callout.ClassifySymbol.empty())
            {
                std::wcout << L" (" << callout.ClassifySymbol << L")";
            }
            if (callout.ClassifySuspicious)
            {
                std::wcout << L" ";
                PrintColoredText(L"[SUSPICIOUS]", KNDBG_COLOR_FAIL);
            }
            std::wcout << L"\n";

            if (callout.HasMetadata && (!callout.Name.empty() || !callout.LayerName.empty() || !callout.ProviderName.empty()))
            {
                std::wcout << L"    ";
                if (!callout.Name.empty())
                {
                    std::wcout << L"name=";
                    PrintColoredText(callout.Name, KNDBG_COLOR_ACCENT);
                    std::wcout << L" ";
                }
                if (!callout.LayerName.empty())
                {
                    std::wcout << L"layer=" << callout.LayerName << L" ";
                }
                if (!callout.ProviderName.empty())
                {
                    std::wcout << L"provider=" << callout.ProviderName;
                }
                std::wcout << L"\n";
            }

            if (!callout.Notes.empty())
            {
                std::wcout << L"    note: ";
                PrintColoredText(callout.Notes, KNDBG_COLOR_WARN);
                std::wcout << L"\n";
            }
        }
    } while (false);
}

static void HandleWfpCommand(const std::vector<std::wstring>& args)
{
    do
    {
        WfpScanner::Options options = {};
        options.Target = WfpScanner::Scope::Callouts;

        size_t index = 1;
        if (index < args.size())
        {
            if (HasHelpToken(args, 1))
            {
                PrintWfpHelp();
                break;
            }

            if (IsWfpScopeName(args[index]))
            {
                ResolveWfpScope(args[index], &options.Target);
                ++index;
            }
            else if (!IsWfpOption(args[index]))
            {
                std::wcerr << L"usage: !wfp [providers|sublayers|callouts|filters|layers] [/module|/layer|/provider <value>]\n";
                PrintWfpHelp();
                break;
            }
        }

        bool optionError = false;
        while (index < args.size())
        {
            if (IsHelpToken(args[index]))
            {
                PrintWfpHelp();
                optionError = true;
                break;
            }

            if (!IsWfpOption(args[index]))
            {
                std::wcerr << L"usage: !wfp [scope] [/module|/layer|/provider <value>]\n";
                optionError = true;
                break;
            }

            if (index + 1 >= args.size())
            {
                std::wcerr << L"usage: !wfp [scope] " << args[index] << L" <value>\n";
                optionError = true;
                break;
            }

            std::wstring optionName = ToLower(args[index]);
            std::wstring optionValue = args[index + 1];
            index += 2;

            if (optionName == L"/module")
            {
                if (options.Target != WfpScanner::Scope::Callouts)
                {
                    std::wcerr << L"!wfp /module only applies to the callouts scope\n";
                    optionError = true;
                    break;
                }
                options.ModuleFilter = optionValue;
            }
            else if (optionName == L"/layer")
            {
                if (options.Target != WfpScanner::Scope::Filters)
                {
                    std::wcerr << L"!wfp /layer only applies to the filters scope\n";
                    optionError = true;
                    break;
                }
                options.LayerFilter = optionValue;
            }
            else if (optionName == L"/provider")
            {
                if (options.Target != WfpScanner::Scope::Filters)
                {
                    std::wcerr << L"!wfp /provider only applies to the filters scope\n";
                    optionError = true;
                    break;
                }
                options.ProviderFilter = optionValue;
            }
        }

        if (optionError)
        {
            break;
        }

        WfpScanner scanner;
        WfpScanResult result = {};
        std::wstring error;
        if (!scanner.Scan(options, &result, &error))
        {
            std::wcerr << L"!wfp scan failed: " << error << L"\n";
            for (const std::wstring& warning : result.Warnings)
            {
                std::wcerr << L"!wfp warning: " << warning << L"\n";
            }
            break;
        }

        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"!wfp warning: " << warning << L"\n";
        }

        PrintColoredText(L"wfp records", KNDBG_COLOR_TITLE);
        std::wcout << L"=" << result.Records.size();
        std::wcout << L" scope=";
        PrintColoredText(result.Scope, KNDBG_COLOR_OK);
        if (!options.ModuleFilter.empty())
        {
            std::wcout << L" module=";
            PrintColoredText(options.ModuleFilter, KNDBG_COLOR_OK);
        }
        if (!options.LayerFilter.empty())
        {
            std::wcout << L" layer=";
            PrintColoredText(options.LayerFilter, KNDBG_COLOR_OK);
        }
        if (!options.ProviderFilter.empty())
        {
            std::wcout << L" provider=";
            PrintColoredText(options.ProviderFilter, KNDBG_COLOR_OK);
        }
        std::wcout << L"\n";

        for (const WfpRecord& record : result.Records)
        {
            PrintWfpRecord(record);
        }
    } while (false);
}

static void PrintAlpcHelp()
{
    std::wcout << L"!alpc command:\n";
    std::wcout << L"  !alpc ports [/name <pattern>] [/pid <pid>]\n";
    std::wcout << L"  !alpc port <address>\n";
    std::wcout << L"  !alpc connections [/pid <pid>] [/name <pattern>]\n";
    std::wcout << L"  !alpc queues <address>\n";
    std::wcout << L"\n";
    std::wcout << L"scopes:\n";
    std::wcout << L"  ports        list ALPC ports discovered via Object Manager directory walk\n";
    std::wcout << L"  port         show a single port at an explicit address\n";
    std::wcout << L"  connections  group ports by ConnectionPort to render client/server pairings\n";
    std::wcout << L"  queues       count MainQueue, PendingQueue, LargeMessageQueue, CanceledQueue, and WaitQueue entries for one port\n";
    std::wcout << L"\n";
    std::wcout << L"options:\n";
    std::wcout << L"  /name <pattern>  case-insensitive substring filter on port name or directory path\n";
    std::wcout << L"  /pid <pid>       decimal owning-process PID filter (resolved through _ALPC_PORT.OwnerProcess)\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  Discovery walks the Object Manager namespace from nt!ObpRootDirectoryObject and follows _ALPC_PORT.CommunicationInfo links to surface paired server/client ports.\n";
    std::wcout << L"  Anonymous client ports that are never reachable from a named server port are not enumerated; handle-table walking is intentionally not yet implemented.\n";
    std::wcout << L"  Queue counts are bounded list-entry walks and depend on PDB exposure of MainQueue/PendingQueue/LargeMessageQueue/CanceledQueue/WaitQueue.\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  !alpc ports\n";
    std::wcout << L"  !alpc ports /name OLE\n";
    std::wcout << L"  !alpc ports /pid 1234\n";
    std::wcout << L"  !alpc port ffff8a8400000000\n";
    std::wcout << L"  !alpc connections\n";
    std::wcout << L"  !alpc queues ffff8a8400000000\n";
}

static void PrintAlpcPortHeader(const AlpcPortRecord& record)
{
    PrintColoredText(L"[alpc.port]", KNDBG_COLOR_TITLE);
    std::wcout << L" address=";
    PrintColoredText(HexTextWidth(record.Address, 16, true), KNDBG_COLOR_ACCENT);

    if (!record.Name.empty())
    {
        std::wcout << L" name=\"";
        PrintColoredText(record.Name, KNDBG_COLOR_OK);
        std::wcout << L"\"";
    }

    if (record.IsConnectionPort)
    {
        std::wcout << L" role=connection";
    }
    else if (record.IsServerCommunicationPort)
    {
        std::wcout << L" role=server";
    }
    else if (record.IsClientCommunicationPort)
    {
        std::wcout << L" role=client";
    }
    else if (record.IsNamedDirectoryPort)
    {
        std::wcout << L" role=named";
    }

    std::wcout << L"\n";
}

static void PrintAlpcPortRecord(const AlpcPortRecord& record)
{
    PrintAlpcPortHeader(record);

    if (!record.DirectoryPath.empty())
    {
        std::wcout << L"  path=" << record.DirectoryPath << L"\n";
    }

    if (record.HasOwnerProcess)
    {
        std::wcout << L"  ";
        PrintColoredText(L"owner", KNDBG_COLOR_ACCENT);
        std::wcout << L"=" << HexTextWidth(record.OwnerProcess, 16, true);
        if (record.OwnerProcessId != 0)
        {
            std::wcout << L" pid=" << std::dec << record.OwnerProcessId;
        }
        if (!record.OwnerImageName.empty())
        {
            std::wcout << L" image=\"" << record.OwnerImageName << L"\"";
        }
        std::wcout << L"\n";
    }

    if (record.HasConnectionPort)
    {
        std::wcout << L"  ";
        PrintColoredText(L"connectionPort", KNDBG_COLOR_ACCENT);
        std::wcout << L"=" << HexTextWidth(record.ConnectionPort, 16, true) << L"\n";
    }

    if (record.HasCommunicationInfo)
    {
        std::wcout << L"  ";
        PrintColoredText(L"communicationInfo", KNDBG_COLOR_ACCENT);
        std::wcout << L"=" << HexTextWidth(record.CommunicationInfo, 16, true);
        if (record.ServerCommunicationPort != 0)
        {
            std::wcout << L" server=" << HexTextWidth(record.ServerCommunicationPort, 16, true);
        }
        if (record.ClientCommunicationPort != 0)
        {
            std::wcout << L" client=" << HexTextWidth(record.ClientCommunicationPort, 16, true);
        }
        std::wcout << L"\n";
    }

    if (record.HasQueueData)
    {
        std::wcout << L"  ";
        PrintColoredText(L"queues", KNDBG_COLOR_ACCENT);
        std::wcout << L" main=" << std::dec << record.MainQueueLength
                   << L" pending=" << record.PendingQueueLength
                   << L" large=" << record.LargeMessageQueueLength
                   << L" canceled=" << record.CanceledQueueLength
                   << L" wait=" << record.WaitQueueLength << L"\n";
    }

    if (record.Flags != 0)
    {
        std::wcout << L"  flags=0x" << std::hex << record.Flags << std::dec << L"\n";
    }

    if (!record.Notes.empty())
    {
        std::wcout << L"  ";
        PrintColoredText(L"notes", KNDBG_COLOR_WARN);
        std::wcout << L"=" << record.Notes << L"\n";
    }
}

static void PrintAlpcConnectionGroups(const std::vector<AlpcPortRecord>& records)
{
    std::map<uint64_t, std::vector<const AlpcPortRecord*>> byConnection;
    std::vector<const AlpcPortRecord*> orphans;

    for (const AlpcPortRecord& record : records)
    {
        if (record.HasConnectionPort)
        {
            byConnection[record.ConnectionPort].push_back(&record);
        }
        else
        {
            orphans.push_back(&record);
        }
    }

    PrintColoredText(L"alpc connection families", KNDBG_COLOR_TITLE);
    std::wcout << L"=" << byConnection.size() << L" orphans=" << orphans.size() << L"\n";

    for (const auto& group : byConnection)
    {
        std::wcout << L"\n";
        PrintColoredText(L"connection=", KNDBG_COLOR_ACCENT);
        std::wcout << HexTextWidth(group.first, 16, true) << L" members=" << group.second.size() << L"\n";

        for (const AlpcPortRecord* port : group.second)
        {
            std::wcout << L"  ";
            PrintColoredText(HexTextWidth(port->Address, 16, true), KNDBG_COLOR_ACCENT);

            if (port->IsConnectionPort)
            {
                std::wcout << L" [connection]";
            }
            else if (port->IsServerCommunicationPort)
            {
                std::wcout << L" [server]";
            }
            else if (port->IsClientCommunicationPort)
            {
                std::wcout << L" [client]";
            }

            if (port->HasOwnerProcess)
            {
                std::wcout << L" pid=" << std::dec << port->OwnerProcessId;
                if (!port->OwnerImageName.empty())
                {
                    std::wcout << L" image=\"" << port->OwnerImageName << L"\"";
                }
            }

            if (!port->Name.empty())
            {
                std::wcout << L" name=\"" << port->Name << L"\"";
            }

            std::wcout << L"\n";
        }
    }

    if (!orphans.empty())
    {
        std::wcout << L"\n";
        PrintColoredText(L"unpaired ports", KNDBG_COLOR_WARN);
        std::wcout << L"=" << orphans.size() << L"\n";
        for (const AlpcPortRecord* port : orphans)
        {
            std::wcout << L"  " << HexTextWidth(port->Address, 16, true);
            if (!port->Name.empty())
            {
                std::wcout << L" name=\"" << port->Name << L"\"";
            }
            std::wcout << L"\n";
        }
    }
}

static void HandleAlpcCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    do
    {
        if (!device.IsOpen())
        {
            std::wcerr << L"!alpc requires the KnLiveDbg.sys driver device to be open\n";
            break;
        }

        AlpcScanner::Options options = {};
        options.Target = AlpcScanner::Scope::Ports;

        size_t index = 1;
        if (index < args.size())
        {
            if (HasHelpToken(args, 1))
            {
                PrintAlpcHelp();
                break;
            }

            if (IsAlpcScopeName(args[index]))
            {
                ResolveAlpcScope(args[index], &options.Target);
                ++index;
            }
            else if (!IsAlpcOption(args[index]))
            {
                std::wcerr << L"usage: !alpc [ports|port|connections|queues] [options]\n";
                PrintAlpcHelp();
                break;
            }
        }

        if (options.Target == AlpcScanner::Scope::Port || options.Target == AlpcScanner::Scope::Queues)
        {
            if (index >= args.size())
            {
                std::wcerr << L"usage: !alpc " << (options.Target == AlpcScanner::Scope::Port ? L"port" : L"queues") << L" <address>\n";
                break;
            }

            uint64_t address = 0;
            std::wstring parseError;
            if (!ParseAddressOrSymbol(symbols, state, args[index], &address, &parseError))
            {
                std::wcerr << L"!alpc address parse failed: " << parseError << L"\n";
                break;
            }

            options.Address = address;
            options.HasAddress = true;
            ++index;
        }

        bool optionError = false;
        while (index < args.size())
        {
            if (IsHelpToken(args[index]))
            {
                PrintAlpcHelp();
                optionError = true;
                break;
            }

            if (!IsAlpcOption(args[index]))
            {
                std::wcerr << L"usage: !alpc [scope] [/name <pattern>] [/pid <pid>]\n";
                optionError = true;
                break;
            }

            if (index + 1 >= args.size())
            {
                std::wcerr << L"usage: !alpc [scope] " << args[index] << L" <value>\n";
                optionError = true;
                break;
            }

            std::wstring optionName = ToLower(args[index]);
            std::wstring optionValue = args[index + 1];
            index += 2;

            if (optionName == L"/name")
            {
                if (options.Target == AlpcScanner::Scope::Queues)
                {
                    std::wcerr << L"!alpc /name does not apply to the queues scope\n";
                    optionError = true;
                    break;
                }
                options.NameFilter = optionValue;
            }
            else if (optionName == L"/pid")
            {
                uint64_t pid = 0;
                if (!ParseUnsigned(optionValue, 10, &pid))
                {
                    std::wcerr << L"!alpc /pid expects a decimal process id\n";
                    optionError = true;
                    break;
                }

                options.PidFilter = pid;
                options.HasPidFilter = true;
            }
        }

        if (optionError)
        {
            break;
        }

        if (symbols.Modules().empty())
        {
            std::wstring loadError;
            if (!symbols.LoadKernelModules(&loadError))
            {
                std::wcerr << L"!alpc scan failed: " << loadError << L"\n";
                break;
            }
        }

        AlpcScanner scanner(device, symbols);
        AlpcScanResult result = {};
        std::wstring error;
        if (!scanner.Scan(options, &result, &error))
        {
            std::wcerr << L"!alpc scan failed: " << error << L"\n";
            for (const std::wstring& warning : result.Warnings)
            {
                std::wcerr << L"!alpc warning: " << warning << L"\n";
            }
            break;
        }

        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"!alpc warning: " << warning << L"\n";
        }

        PrintColoredText(L"alpc records", KNDBG_COLOR_TITLE);
        std::wcout << L"=" << result.Records.size();
        if (result.TypeIndexResolved)
        {
            std::wcout << L" typeIndex=0x" << std::hex << static_cast<uint32_t>(result.AlpcPortTypeIndex) << std::dec;
            std::wcout << L" objectType=" << HexTextWidth(result.AlpcPortTypeAddress, 16, true);
        }
        if (!options.NameFilter.empty())
        {
            std::wcout << L" name=\"" << options.NameFilter << L"\"";
        }
        if (options.HasPidFilter)
        {
            std::wcout << L" pid=" << std::dec << options.PidFilter;
        }
        std::wcout << L"\n";

        if (options.Target == AlpcScanner::Scope::Connections)
        {
            PrintAlpcConnectionGroups(result.Records);
            break;
        }

        for (const AlpcPortRecord& record : result.Records)
        {
            PrintAlpcPortRecord(record);
        }
    } while (false);
}

static void PrintVbsHelp()
{
    std::wcout << L"!vbs command:\n";
    std::wcout << L"  !vbs\n";
    std::wcout << L"\n";
    std::wcout << L"output:\n";
    std::wcout << L"  Comprehensive VBS/HVCI/MBEC/Secure Kernel/trustlet status report.\n";
    std::wcout << L"  Sources: nt!g_CiOptions, nt!HvlpVsmVtlCallVa, CPUID(0x40000000/0x40000006),\n";
    std::wcout << L"  PsLoadedModuleList (securekernel.exe/skci.dll), and PsActiveProcessHead walk.\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  CiOptions resolves through nt!g_CiOptions, ci!g_CiOptions, or nt!CiOptions in that order.\n";
    std::wcout << L"  Trustlet detection requires _EPROCESS/_KPROCESS.SecureState exposure in the loaded kernel PDB.\n";
    std::wcout << L"  When SecureState is unavailable, well-known trustlet image names (lsaiso.exe, bioiso.exe, securesystem.exe, kdcustomization.exe) are still listed as candidates.\n";
}

static void PrintCiHelp()
{
    std::wcout << L"!ci command:\n";
    std::wcout << L"  !ci\n";
    std::wcout << L"  !ci options\n";
    std::wcout << L"  !ci policy\n";
    std::wcout << L"\n";
    std::wcout << L"scopes:\n";
    std::wcout << L"  options   decode CiOptions bits (CODEINTEGRITY_OPTION_ENABLED, TESTSIGN, UMCI_ENABLED, HVCI_ENFORCED, etc.)\n";
    std::wcout << L"  policy    summarize Code Integrity policy state (CiOptions plus best-effort policy hints)\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  WDAC policy hash extraction depends on private CI internals and is reported as a follow-up source for now.\n";
}

static void PrintSecureKernelHelp()
{
    std::wcout << L"!securekernel command:\n";
    std::wcout << L"  !securekernel\n";
    std::wcout << L"\n";
    std::wcout << L"output:\n";
    std::wcout << L"  Secure Kernel and skci.dll module presence plus an IUM trustlet list walked from PsActiveProcessHead.\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  Trustlet detection prefers _EPROCESS.SecureState then _KPROCESS.SecureState bit 0 (SecureKernelInProcess).\n";
    std::wcout << L"  Without that field, fallback heuristics use well-known trustlet image names.\n";
}

static const wchar_t* FormatBoolText(bool value)
{
    return value ? L"yes" : L"no";
}

static WORD FormatBoolColor(bool value)
{
    return value ? KNDBG_COLOR_OK : KNDBG_COLOR_WARN;
}

static std::wstring FormatCiOptionsFlagText(const VbsCiOptionsInfo& info)
{
    std::wstring acc;
    auto append = [&](const wchar_t* token)
    {
        if (!acc.empty())
        {
            acc.append(L"|");
        }
        acc.append(token);
    };

    if (info.CodeIntegrityEnabled) append(L"CODEINTEGRITY_OPTION_ENABLED");
    if (info.TestSign)             append(L"TESTSIGN");
    if (info.UmciEnabled)          append(L"UMCI_ENABLED");
    if (info.UmciAuditMode)        append(L"UMCI_AUDITMODE_ENABLED");
    if (info.HvciEnforced)         append(L"HVCI_ENFORCED");
    if (info.UmciExclusionPaths)   append(L"UMCI_EXCLUSIONPATHS_ENABLED");
    if (info.TestBuild)            append(L"TEST_BUILD");
    if (info.PreproductionBuild)   append(L"PREPRODUCTION_BUILD");
    if (info.FlightBuild)          append(L"FLIGHT_BUILD");
    if (info.HvciStrictMode)       append(L"HVCI_STRICT_MODE");
    if (info.HvciDebugMode)        append(L"HVCI_DEBUG_MODE");

    return acc;
}

static void PrintCiOptionsBlock(const VbsCiOptionsInfo& info)
{
    PrintColoredText(L"[ci.options]", KNDBG_COLOR_TITLE);
    if (!info.Resolved)
    {
        std::wcout << L" status=unresolved\n";
        return;
    }

    std::wcout << L" source=" << info.SymbolSource;
    std::wcout << L" raw=0x" << std::hex << info.Raw << std::dec << L"\n";

    std::wstring flagsText = FormatCiOptionsFlagText(info);
    std::wcout << L"  flags=";
    if (flagsText.empty())
    {
        PrintColoredText(L"<none>", KNDBG_COLOR_DIM);
    }
    else
    {
        PrintColoredText(flagsText, KNDBG_COLOR_OK);
    }
    std::wcout << L"\n";

    std::wcout << L"  ci=" << FormatBoolText(info.CodeIntegrityEnabled)
               << L" testsign=" << FormatBoolText(info.TestSign)
               << L" umci=" << FormatBoolText(info.UmciEnabled)
               << L" hvci=" << FormatBoolText(info.HvciEnforced)
               << L" hvci_strict=" << FormatBoolText(info.HvciStrictMode)
               << L" hvci_debug=" << FormatBoolText(info.HvciDebugMode) << L"\n";
}

static void PrintHypervisorBlock(const VbsHypervisorInfo& info)
{
    PrintColoredText(L"[vbs.hypervisor]", KNDBG_COLOR_TITLE);
    std::wcout << L" present=";
    PrintColoredText(FormatBoolText(info.HypervisorPresent), FormatBoolColor(info.HypervisorPresent));
    if (!info.VendorSignature.empty())
    {
        std::wcout << L" vendor=\"" << info.VendorSignature << L"\"";
    }
    if (info.HvLeafBase != 0)
    {
        std::wcout << L" leaf_base=0x" << std::hex << info.HvLeafBase << std::dec;
    }
    if (info.HvFeaturesValid)
    {
        std::wcout << L" hv_hw_features=0x" << std::hex << info.HvHardwareFeatures << std::dec;
    }
    std::wcout << L"\n";
    std::wcout << L"  note: MBEC enablement requires IA32_VMX_PROCBASED_CTLS2 bit 22 (MSR read, kernel-only); inferred from HVCI enforcement instead.\n";
}

static void PrintVbsCoreBlock(const VbsScanResult& result)
{
    PrintColoredText(L"[vbs.core]", KNDBG_COLOR_TITLE);
    std::wcout << L" vbs_active=";
    PrintColoredText(FormatBoolText(result.VbsActive), FormatBoolColor(result.VbsActive));
    std::wcout << L" hvci_enforced=";
    PrintColoredText(FormatBoolText(result.CiOptions.HvciEnforced), FormatBoolColor(result.CiOptions.HvciEnforced));
    std::wcout << L" sk_loaded=";
    PrintColoredText(FormatBoolText(result.SecureKernelLoaded), FormatBoolColor(result.SecureKernelLoaded));
    std::wcout << L" skci=";
    PrintColoredText(FormatBoolText(result.SkciLoaded), FormatBoolColor(result.SkciLoaded));
    std::wcout << L"\n";

    if (result.HvlpVsmVtlCallVaResolved)
    {
        std::wcout << L"  " << result.HvlpVsmVtlCallVaSymbol << L"=" << HexTextWidth(result.HvlpVsmVtlCallVa, 16, true) << L"\n";
    }

    if (result.HvcallStubResolved)
    {
        std::wcout << L"  " << result.HvcallStubSymbol << L"=" << HexTextWidth(result.HvcallStubAddress, 16, true) << L"\n";
    }
}

static void PrintSecureKernelModules(const VbsScanResult& result)
{
    if (result.SecureKernelModules.empty())
    {
        PrintColoredText(L"[securekernel.modules]", KNDBG_COLOR_TITLE);
        std::wcout << L" count=0\n";
        return;
    }

    PrintColoredText(L"[securekernel.modules]", KNDBG_COLOR_TITLE);
    std::wcout << L" count=" << result.SecureKernelModules.size() << L"\n";
    for (const VbsModuleHit& module : result.SecureKernelModules)
    {
        std::wcout << L"  ";
        PrintColoredText(module.ImageName, KNDBG_COLOR_OK);
        std::wcout << L" base=" << HexTextWidth(module.Base, 16, true)
                   << L" size=0x" << std::hex << module.Size << std::dec << L"\n";
    }
}

static void PrintTrustletList(const VbsScanResult& result)
{
    PrintColoredText(L"[securekernel.trustlets]", KNDBG_COLOR_TITLE);
    std::wcout << L" count=" << result.Trustlets.size() << L"\n";
    for (const VbsTrustletInfo& t : result.Trustlets)
    {
        std::wcout << L"  ";
        PrintColoredText(HexTextWidth(t.Eprocess, 16, true), KNDBG_COLOR_ACCENT);
        std::wcout << L" pid=" << std::dec << t.ProcessId;
        if (!t.ImageName.empty())
        {
            std::wcout << L" image=\"";
            PrintColoredText(t.ImageName, KNDBG_COLOR_OK);
            std::wcout << L"\"";
        }
        if (t.HasSecureState)
        {
            std::wcout << L" secure_state=0x" << std::hex << t.SecureState << std::dec
                       << L" sk_in_process=" << FormatBoolText(t.SecureKernelInProcess);
        }
        else
        {
            std::wcout << L" secure_state=unknown";
        }
        std::wcout << L"\n";
    }
}

static void EmitVbsWarnings(const VbsScanResult& result)
{
    for (const std::wstring& warning : result.Warnings)
    {
        std::wcerr << L"!vbs warning: " << warning << L"\n";
    }
}

static bool PrepareVbsScan(
    VbsScanner::Options options,
    DeviceClient& device,
    SymbolEngine& symbols,
    VbsScanResult* result,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (!device.IsOpen())
        {
            if (error != nullptr)
            {
                *error = L"requires the KnLiveDbg.sys driver device to be open";
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

        VbsScanner scanner(device, symbols);
        if (!scanner.Scan(options, result, error))
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static void HandleVbsCommand(
    const std::vector<std::wstring>& args,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    do
    {
        if (args.size() >= 2 && HasHelpToken(args, 1))
        {
            PrintVbsHelp();
            break;
        }

        if (args.size() >= 2)
        {
            std::wcerr << L"usage: !vbs\n";
            PrintVbsHelp();
            break;
        }

        VbsScanner::Options options = {};
        options.Target = VbsScanner::Scope::Vbs;

        VbsScanResult result = {};
        std::wstring error;
        if (!PrepareVbsScan(options, device, symbols, &result, &error))
        {
            std::wcerr << L"!vbs failed: " << error << L"\n";
            EmitVbsWarnings(result);
            break;
        }

        EmitVbsWarnings(result);

        PrintVbsCoreBlock(result);
        PrintCiOptionsBlock(result.CiOptions);
        PrintHypervisorBlock(result.Hypervisor);
        PrintSecureKernelModules(result);
        PrintTrustletList(result);
    } while (false);
}

static void PrintCiPolicyBlock(const VbsScanResult& result)
{
    PrintColoredText(L"[ci.policy]", KNDBG_COLOR_TITLE);
    std::wcout << L" status=";
    if (result.CiOptions.Resolved && result.CiOptions.UmciEnabled)
    {
        PrintColoredText(L"UMCI-enforced", KNDBG_COLOR_OK);
    }
    else if (result.CiOptions.Resolved)
    {
        PrintColoredText(L"UMCI-disabled", KNDBG_COLOR_WARN);
    }
    else
    {
        PrintColoredText(L"unknown", KNDBG_COLOR_WARN);
    }
    if (result.CiOptions.Resolved)
    {
        std::wcout << L" testsign=" << FormatBoolText(result.CiOptions.TestSign)
                   << L" audit=" << FormatBoolText(result.CiOptions.UmciAuditMode)
                   << L" exclusion_paths=" << FormatBoolText(result.CiOptions.UmciExclusionPaths)
                   << L" hvci=" << FormatBoolText(result.CiOptions.HvciEnforced)
                   << L" hvci_strict=" << FormatBoolText(result.CiOptions.HvciStrictMode);
    }
    std::wcout << L"\n";
    std::wcout << L"  note: WDAC policy blob discovery requires private CI internals and is reserved for a follow-up milestone.\n";
}

static void HandleCiCommand(
    const std::vector<std::wstring>& args,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    do
    {
        if (args.size() >= 2 && HasHelpToken(args, 1))
        {
            PrintCiHelp();
            break;
        }

        bool printOptions = true;
        bool printPolicy = true;
        if (args.size() >= 2)
        {
            if (!IsCiScopeName(args[1]))
            {
                std::wcerr << L"usage: !ci [options|policy]\n";
                PrintCiHelp();
                break;
            }
            std::wstring scope = ToLower(args[1]);
            if (scope == L"options")
            {
                printOptions = true;
                printPolicy = false;
            }
            else if (scope == L"policy")
            {
                printOptions = true;
                printPolicy = true;
            }
        }

        VbsScanner::Options options = {};
        options.Target = VbsScanner::Scope::Ci;

        VbsScanResult result = {};
        std::wstring error;
        if (!PrepareVbsScan(options, device, symbols, &result, &error))
        {
            std::wcerr << L"!ci failed: " << error << L"\n";
            EmitVbsWarnings(result);
            break;
        }

        EmitVbsWarnings(result);

        if (printOptions)
        {
            PrintCiOptionsBlock(result.CiOptions);
            PrintHypervisorBlock(result.Hypervisor);
        }

        if (printPolicy)
        {
            PrintCiPolicyBlock(result);
        }
    } while (false);
}

static void HandleSecureKernelCommand(
    const std::vector<std::wstring>& args,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    do
    {
        if (args.size() >= 2 && HasHelpToken(args, 1))
        {
            PrintSecureKernelHelp();
            break;
        }

        if (args.size() >= 2)
        {
            std::wcerr << L"usage: !securekernel\n";
            PrintSecureKernelHelp();
            break;
        }

        VbsScanner::Options options = {};
        options.Target = VbsScanner::Scope::SecureKernel;

        VbsScanResult result = {};
        std::wstring error;
        if (!PrepareVbsScan(options, device, symbols, &result, &error))
        {
            std::wcerr << L"!securekernel failed: " << error << L"\n";
            EmitVbsWarnings(result);
            break;
        }

        EmitVbsWarnings(result);

        PrintSecureKernelModules(result);
        PrintTrustletList(result);
    } while (false);
}

static void PrintEtwHelp()
{
    std::wcout << L"!etw command:\n";
    std::wcout << L"  !etw loggers\n";
    std::wcout << L"  !etw logger <index|name-substring>\n";
    std::wcout << L"  !etw integrity\n";
    std::wcout << L"\n";
    std::wcout << L"scopes:\n";
    std::wcout << L"  loggers    list every populated WMI_LOGGER_CONTEXT slot under nt!EtwpDebuggerData with name and GetCpuClock annotation\n";
    std::wcout << L"  logger     filter by slot index (decimal) or case-insensitive name substring\n";
    std::wcout << L"  integrity  decode the first instructions of canonical ETW/PMC dispatch functions and report trampoline / cross-module branch findings (modern InfinityHook variants)\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  Resolves nt!EtwpDebuggerData, walks the silo state when present, then resolves LoggerName and GetCpuClock through _WMI_LOGGER_CONTEXT PDB fields with documented fallbacks.\n";
    std::wcout << L"  In modern Windows GetCpuClock is a UINT32 mode tag dispatched internally; mode=Custom on Circular Kernel Context Logger is normal, not a hook indicator.\n";
    std::wcout << L"  !etw integrity disassembles each target's first 16 instructions and flags first-instruction jmp/int3/ud2, mov-imm64+jmp-reg trampolines, push-imm+ret trampolines, and cross-module branches whose targets lie outside any loaded kernel module.\n";
}

static void PrintNmiHelp()
{
    std::wcout << L"!nmi command:\n";
    std::wcout << L"  !nmi\n";
    std::wcout << L"  !nmi callbacks\n";
    std::wcout << L"\n";
    std::wcout << L"output:\n";
    std::wcout << L"  Singly-linked list of KNMI_HANDLER_CALLBACK nodes from nt!KiNmiCallbackListHead, with module/symbol annotation per callback.\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  Node layout is fixed: Next at 0x00, Callback at 0x08, Context at 0x10, Handle at 0x18.\n";
    std::wcout << L"  Callback targets outside any loaded kernel module are flagged as suspicious; the walker bounds iteration and detects cycles.\n";
}

static void PrintEtwLoggerRecord(const EtwLoggerRecord& record)
{
    PrintColoredText(L"[etw.logger]", KNDBG_COLOR_TITLE);
    std::wcout << L" slot=" << std::dec << record.Slot;
    std::wcout << L" context=" << HexTextWidth(record.ContextAddress, 16, true);
    if (!record.Name.empty())
    {
        std::wcout << L" name=\"";
        PrintColoredText(record.Name, KNDBG_COLOR_OK);
        std::wcout << L"\"";
    }
    if (record.Suspicious)
    {
        std::wcout << L" ";
        PrintColoredText(L"[SUSPICIOUS]", KNDBG_COLOR_FAIL);
    }
    std::wcout << L"\n";

    if (record.HasGetCpuClockRaw)
    {
        std::wcout << L"  ";
        PrintColoredText(L"getCpuClock", KNDBG_COLOR_ACCENT);
        std::wcout << L"=" << HexTextWidth(record.GetCpuClockRaw, 16, true);
        if (record.HasGetCpuClockMode)
        {
            std::wcout << L" mode=";
            PrintColoredText(record.GetCpuClockModeText, KNDBG_COLOR_OK);
            std::wcout << L"(" << std::dec << record.GetCpuClockMode << L")";
        }
        std::wcout << L"\n";
    }

    if (record.HasGetCpuClockCallback)
    {
        std::wcout << L"  ";
        PrintColoredText(L"callback", KNDBG_COLOR_ACCENT);
        std::wcout << L"=" << HexTextWidth(record.GetCpuClockCallback, 16, true);
        if (!record.GetCpuClockCallbackSource.empty())
        {
            std::wcout << L" source=" << record.GetCpuClockCallbackSource;
        }
        if (!record.GetCpuClockModule.empty())
        {
            std::wcout << L" module=";
            PrintColoredText(record.GetCpuClockModule, KNDBG_COLOR_OK);
        }
        if (!record.GetCpuClockSymbol.empty())
        {
            std::wcout << L" symbol=";
            PrintColoredText(record.GetCpuClockSymbol, KNDBG_COLOR_OK);
        }
        std::wcout << L"\n";
    }

    if (!record.Notes.empty())
    {
        std::wcout << L"  ";
        PrintColoredText(L"notes", KNDBG_COLOR_WARN);
        std::wcout << L"=" << record.Notes << L"\n";
    }
}

static void PrintNmiCallbackRecord(const NmiCallbackRecord& record)
{
    PrintColoredText(L"[nmi.callback]", KNDBG_COLOR_TITLE);
    std::wcout << L" slot=" << std::dec << record.Slot;
    std::wcout << L" node=" << HexTextWidth(record.NodeAddress, 16, true);
    if (record.Suspicious)
    {
        std::wcout << L" ";
        PrintColoredText(L"[SUSPICIOUS]", KNDBG_COLOR_FAIL);
    }
    std::wcout << L"\n";

    std::wcout << L"  ";
    PrintColoredText(L"callback", KNDBG_COLOR_ACCENT);
    std::wcout << L"=" << HexTextWidth(record.Callback, 16, true);
    if (!record.CallbackModule.empty())
    {
        std::wcout << L" module=";
        PrintColoredText(record.CallbackModule, KNDBG_COLOR_OK);
    }
    if (!record.CallbackSymbol.empty())
    {
        std::wcout << L" symbol=";
        PrintColoredText(record.CallbackSymbol, KNDBG_COLOR_OK);
    }
    std::wcout << L"\n";

    std::wcout << L"  context=" << HexTextWidth(record.Context, 16, true)
               << L" handle=" << HexTextWidth(record.Handle, 16, true) << L"\n";

    if (!record.Notes.empty())
    {
        std::wcout << L"  ";
        PrintColoredText(L"notes", KNDBG_COLOR_WARN);
        std::wcout << L"=" << record.Notes << L"\n";
    }
}

static void PrintEtwIntegrityRecord(const EtwIntegrityRecord& record)
{
    PrintColoredText(L"[etw.integrity]", KNDBG_COLOR_TITLE);
    std::wcout << L" target=";
    PrintColoredText(record.Symbol, KNDBG_COLOR_OK);

    const wchar_t* statusText = L"clean";
    WORD statusColor = KNDBG_COLOR_OK;
    if (!record.SymbolResolved)
    {
        statusText = L"unresolved";
        statusColor = KNDBG_COLOR_WARN;
    }
    else if (!record.BytesRead)
    {
        statusText = L"read-failed";
        statusColor = KNDBG_COLOR_WARN;
    }
    else if (!record.DecodeOk)
    {
        statusText = L"decode-failed";
        statusColor = KNDBG_COLOR_WARN;
    }
    else if (!record.Findings.empty())
    {
        statusText = L"SUSPICIOUS";
        statusColor = KNDBG_COLOR_FAIL;
    }

    std::wcout << L" status=";
    PrintColoredText(statusText, statusColor);
    std::wcout << L"\n";

    if (!record.Description.empty())
    {
        std::wcout << L"  description=" << record.Description << L"\n";
    }

    if (record.SymbolResolved)
    {
        std::wcout << L"  address=" << HexTextWidth(record.Address, 16, true);
        if (!record.OwningModule.empty())
        {
            std::wcout << L" module=";
            PrintColoredText(record.OwningModule, KNDBG_COLOR_OK);
        }
        std::wcout << L"\n";

        if (!record.HeadBytesHex.empty())
        {
            std::wcout << L"  head=" << record.HeadBytesHex << L"\n";
        }

        if (record.InstructionsAnalyzed > 0)
        {
            std::wcout << L"  instructions_analyzed=" << std::dec << record.InstructionsAnalyzed
                       << L" findings=" << record.Findings.size() << L"\n";
        }

        for (size_t i = 0; i < record.Findings.size(); ++i)
        {
            const EtwIntegrityFinding& finding = record.Findings[i];
            std::wcout << L"  ";
            PrintColoredText(L"finding[", KNDBG_COLOR_WARN);
            std::wcout << std::dec << i;
            PrintColoredText(L"]", KNDBG_COLOR_WARN);
            std::wcout << L" mnemonic=" << finding.Mnemonic
                       << L" instr_index=" << finding.InstructionIndex
                       << L" offset=0x" << std::hex << finding.InstructionOffset << std::dec
                       << L"\n    reason=" << finding.Reason << L"\n";
            if (finding.HasTarget)
            {
                std::wcout << L"    target=" << HexTextWidth(finding.Target, 16, true);
                if (!finding.TargetModule.empty())
                {
                    std::wcout << L" module=";
                    PrintColoredText(finding.TargetModule, KNDBG_COLOR_OK);
                }
                else
                {
                    std::wcout << L" module=";
                    PrintColoredText(L"<outside-loaded-modules>", KNDBG_COLOR_FAIL);
                }
                if (!finding.TargetSymbol.empty())
                {
                    std::wcout << L" symbol=";
                    PrintColoredText(finding.TargetSymbol, KNDBG_COLOR_OK);
                }
                std::wcout << L"\n";
            }
        }
    }
    else
    {
        std::wcout << L"  note: symbol not present in current kernel PDB; skipping\n";
    }
}

static void HandleEtwCommand(
    const std::vector<std::wstring>& args,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    do
    {
        if (!device.IsOpen())
        {
            std::wcerr << L"!etw requires the KnLiveDbg.sys driver device to be open\n";
            break;
        }

        if (HasHelpToken(args, 1))
        {
            PrintEtwHelp();
            break;
        }

        EtwScanner::Options options = {};
        options.Target = EtwScanner::Scope::Loggers;

        size_t index = 1;
        if (index < args.size())
        {
            if (IsEtwScopeName(args[index]))
            {
                std::wstring scope = ToLower(args[index]);
                if (scope == L"loggers")
                {
                    options.Target = EtwScanner::Scope::Loggers;
                }
                else if (scope == L"logger")
                {
                    options.Target = EtwScanner::Scope::Logger;
                }
                else if (scope == L"integrity")
                {
                    options.Target = EtwScanner::Scope::Integrity;
                }
                ++index;
            }
            else
            {
                std::wcerr << L"usage: !etw [loggers|logger <index|name>|integrity]\n";
                PrintEtwHelp();
                break;
            }
        }

        if (options.Target == EtwScanner::Scope::Logger)
        {
            if (index >= args.size())
            {
                std::wcerr << L"usage: !etw logger <index|name-substring>\n";
                break;
            }

            std::wstring filterValue = args[index];
            uint64_t parsedIndex = 0;
            if (ParseUnsigned(filterValue, 10, &parsedIndex) && parsedIndex < 0x100ull)
            {
                options.HasIndexFilter = true;
                options.IndexFilter = static_cast<uint32_t>(parsedIndex);
            }
            else
            {
                options.NameFilter = filterValue;
            }
            ++index;
        }

        if (index < args.size())
        {
            std::wcerr << L"!etw: unexpected extra argument \"" << args[index] << L"\"\n";
            break;
        }

        if (symbols.Modules().empty())
        {
            std::wstring loadError;
            if (!symbols.LoadKernelModules(&loadError))
            {
                std::wcerr << L"!etw failed: " << loadError << L"\n";
                break;
            }
        }

        EtwScanner scanner(device, symbols);

        if (options.Target == EtwScanner::Scope::Integrity)
        {
            EtwIntegrityResult integrityResult = {};
            std::wstring integrityError;
            if (!scanner.ScanIntegrity(&integrityResult, &integrityError))
            {
                std::wcerr << L"!etw integrity failed: " << integrityError << L"\n";
                for (const std::wstring& warning : integrityResult.Warnings)
                {
                    std::wcerr << L"!etw warning: " << warning << L"\n";
                }
                break;
            }

            for (const std::wstring& warning : integrityResult.Warnings)
            {
                std::wcerr << L"!etw warning: " << warning << L"\n";
            }

            size_t suspiciousCount = 0;
            size_t unresolvedCount = 0;
            size_t cleanCount = 0;
            for (const EtwIntegrityRecord& record : integrityResult.Records)
            {
                if (!record.SymbolResolved)
                {
                    ++unresolvedCount;
                }
                else if (!record.Findings.empty())
                {
                    ++suspiciousCount;
                }
                else if (record.BytesRead && record.DecodeOk)
                {
                    ++cleanCount;
                }
            }

            PrintColoredText(L"etw integrity", KNDBG_COLOR_TITLE);
            std::wcout << L" targets=" << std::dec << integrityResult.Records.size()
                       << L" clean=" << cleanCount
                       << L" suspicious=";
            PrintColoredText(std::to_wstring(suspiciousCount),
                             suspiciousCount == 0 ? KNDBG_COLOR_OK : KNDBG_COLOR_FAIL);
            std::wcout << L" unresolved=" << unresolvedCount << L"\n";

            for (const EtwIntegrityRecord& record : integrityResult.Records)
            {
                PrintEtwIntegrityRecord(record);
            }
            break;
        }

        EtwScanResult result = {};
        std::wstring error;
        if (!scanner.Scan(options, &result, &error))
        {
            std::wcerr << L"!etw failed: " << error << L"\n";
            for (const std::wstring& warning : result.Warnings)
            {
                std::wcerr << L"!etw warning: " << warning << L"\n";
            }
            break;
        }

        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"!etw warning: " << warning << L"\n";
        }

        PrintColoredText(L"etw loggers", KNDBG_COLOR_TITLE);
        std::wcout << L"=" << result.Loggers.size();
        std::wcout << L" debuggerData=" << HexTextWidth(result.DebuggerDataAddress, 16, true);
        std::wcout << L" arraySource=" << result.LoggerArraySource;
        if (result.UsedSiloPath)
        {
            std::wcout << L" silo=" << HexTextWidth(result.SiloStateAddress, 16, true);
        }
        std::wcout << L" arrayBase=" << HexTextWidth(result.LoggerArrayBase, 16, true);
        std::wcout << L" layoutFromPdb=" << (result.LayoutFromPdb ? L"yes" : L"no");
        std::wcout << L" nameOffset=0x" << std::hex << result.LoggerNameOffset << std::dec;
        std::wcout << L" getCpuClockOffset=0x" << std::hex << result.GetCpuClockOffset << std::dec;
        if (result.NonCanonicalSlotCount > 0)
        {
            std::wcout << L" skippedSlots=" << std::dec << result.NonCanonicalSlotCount;
        }
        std::wcout << L"\n";

        for (const EtwLoggerRecord& record : result.Loggers)
        {
            PrintEtwLoggerRecord(record);
        }
    } while (false);
}

static void HandleNmiCommand(
    const std::vector<std::wstring>& args,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    do
    {
        if (!device.IsOpen())
        {
            std::wcerr << L"!nmi requires the KnLiveDbg.sys driver device to be open\n";
            break;
        }

        if (HasHelpToken(args, 1))
        {
            PrintNmiHelp();
            break;
        }

        size_t index = 1;
        if (index < args.size())
        {
            if (!IsNmiScopeName(args[index]))
            {
                std::wcerr << L"usage: !nmi [callbacks]\n";
                PrintNmiHelp();
                break;
            }
            ++index;
        }

        if (index < args.size())
        {
            std::wcerr << L"!nmi: unexpected extra argument \"" << args[index] << L"\"\n";
            break;
        }

        if (symbols.Modules().empty())
        {
            std::wstring loadError;
            if (!symbols.LoadKernelModules(&loadError))
            {
                std::wcerr << L"!nmi failed: " << loadError << L"\n";
                break;
            }
        }

        NmiScanner scanner(device, symbols);
        NmiScanResult result = {};
        std::wstring error;
        if (!scanner.Scan(&result, &error))
        {
            std::wcerr << L"!nmi failed: " << error << L"\n";
            for (const std::wstring& warning : result.Warnings)
            {
                std::wcerr << L"!nmi warning: " << warning << L"\n";
            }
            break;
        }

        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"!nmi warning: " << warning << L"\n";
        }

        PrintColoredText(L"nmi callbacks", KNDBG_COLOR_TITLE);
        std::wcout << L"=" << result.Callbacks.size();
        if (result.ListHeadResolved)
        {
            std::wcout << L" listHead=" << result.ListHeadSymbol;
            std::wcout << L"(" << HexTextWidth(result.ListHeadAddress, 16, true) << L")";
        }
        std::wcout << L"\n";

        for (const NmiCallbackRecord& record : result.Callbacks)
        {
            PrintNmiCallbackRecord(record);
        }
    } while (false);
}

static void PrintMsrCheckHelp()
{
    std::wcout << L"!msrcheck command:\n";
    std::wcout << L"  !msrcheck\n";
    std::wcout << L"\n";
    std::wcout << L"output:\n";
    std::wcout << L"  Reads the SYSCALL-configuration MSRs (IA32_LSTAR/CSTAR/STAR/FMASK/EFER) on every\n";
    std::wcout << L"  active processor in group 0 through the driver's read-only MSR primitive.\n";
    std::wcout << L"\n";
    std::wcout << L"checks:\n";
    std::wcout << L"  LSTAR must equal nt!KiSystemCall64; a mismatch, a per-CPU divergence, or an entry\n";
    std::wcout << L"  pointer outside the loaded kernel image is flagged as a possible SYSCALL hook.\n";
    std::wcout << L"  CSTAR is validated only when non-zero (it is unused on most Intel parts). STAR\n";
    std::wcout << L"  selectors and EFER bits are decoded for inspection.\n";
}

static void PrintMsrReadingRecord(const MsrReading& reading)
{
    PrintColoredText(L"[msr]", KNDBG_COLOR_TITLE);
    std::wcout << L" ";
    PrintColoredText(reading.MsrName, KNDBG_COLOR_ACCENT);

    if (reading.PerCpuValues.empty())
    {
        std::wcout << L" read-failed\n";
        return;
    }

    uint64_t value = reading.PerCpuValues.front();
    std::wcout << L"=" << HexTextWidth(value, 16, true);
    if (reading.Suspicious)
    {
        std::wcout << L" ";
        PrintColoredText(L"[SUSPICIOUS]", KNDBG_COLOR_FAIL);
    }
    std::wcout << L"\n";

    if (reading.IsPointer && (!reading.OwningModule.empty() || !reading.NearestSymbol.empty()))
    {
        std::wcout << L"  ";
        if (!reading.OwningModule.empty())
        {
            std::wcout << L"module=";
            PrintColoredText(reading.OwningModule, KNDBG_COLOR_OK);
            std::wcout << L" ";
        }
        if (!reading.NearestSymbol.empty())
        {
            std::wcout << L"symbol=";
            PrintColoredText(reading.NearestSymbol, KNDBG_COLOR_OK);
        }
        std::wcout << L"\n";
    }

    if (reading.MsrIndex == KNDBG_MSR_IA32_STAR)
    {
        uint32_t compatEip = static_cast<uint32_t>(value & 0xFFFFFFFFull);
        uint16_t syscallCsSs = static_cast<uint16_t>((value >> 32) & 0xFFFFull);
        uint16_t sysretCsSs = static_cast<uint16_t>((value >> 48) & 0xFFFFull);
        std::wcout << L"  syscall_cs_ss=" << HexTextWidth(syscallCsSs, 4, true)
                   << L" sysret_cs_ss=" << HexTextWidth(sysretCsSs, 4, true)
                   << L" compat_eip=" << HexTextWidth(compatEip, 8, true) << L"\n";
    }
    else if (reading.MsrIndex == KNDBG_MSR_IA32_EFER)
    {
        std::wcout << L"  SCE=" << ((value & 0x1ull) != 0 ? L"1" : L"0")
                   << L" LME=" << ((value & 0x100ull) != 0 ? L"1" : L"0")
                   << L" LMA=" << ((value & 0x400ull) != 0 ? L"1" : L"0")
                   << L" NXE=" << ((value & 0x800ull) != 0 ? L"1" : L"0") << L"\n";
    }

    if (reading.Divergent)
    {
        std::wcout << L"  per-cpu:";
        for (size_t i = 0; i < reading.PerCpuValues.size(); ++i)
        {
            std::wcout << L" cpu" << std::dec << i << L"=" << HexTextWidth(reading.PerCpuValues[i], 16, true);
        }
        std::wcout << L"\n";
    }

    if (!reading.Notes.empty())
    {
        std::wcout << L"  note: ";
        PrintColoredText(reading.Notes, KNDBG_COLOR_WARN);
        std::wcout << L"\n";
    }
}

static void HandleMsrCheckCommand(
    const std::vector<std::wstring>& args,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    do
    {
        if (!device.IsOpen())
        {
            std::wcerr << L"!msrcheck requires the KnLiveDbg.sys driver device to be open\n";
            break;
        }

        if (HasHelpToken(args, 1))
        {
            PrintMsrCheckHelp();
            break;
        }

        if (args.size() > 1)
        {
            std::wcerr << L"!msrcheck: unexpected extra argument \"" << args[1] << L"\"\n";
            PrintMsrCheckHelp();
            break;
        }

        if (symbols.Modules().empty())
        {
            std::wstring loadError;
            if (!symbols.LoadKernelModules(&loadError))
            {
                std::wcerr << L"!msrcheck failed: " << loadError << L"\n";
                break;
            }
        }

        MsrScanner scanner(device, symbols);
        MsrScanResult result = {};
        std::wstring error;
        if (!scanner.Scan(&result, &error))
        {
            std::wcerr << L"!msrcheck failed: " << error << L"\n";
            for (const std::wstring& warning : result.Warnings)
            {
                std::wcerr << L"!msrcheck warning: " << warning << L"\n";
            }
            break;
        }

        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"!msrcheck warning: " << warning << L"\n";
        }

        PrintColoredText(L"msr syscall-config", KNDBG_COLOR_TITLE);
        std::wcout << L" cpus=" << std::dec << result.ProcessorCount;
        if (result.AnySuspicious)
        {
            std::wcout << L" ";
            PrintColoredText(L"[SUSPICIOUS]", KNDBG_COLOR_FAIL);
        }
        std::wcout << L"\n";

        for (const MsrReading& reading : result.Readings)
        {
            PrintMsrReadingRecord(reading);
        }
    } while (false);
}

static void PrintCrCheckHelp()
{
    std::wcout << L"!cr command:\n";
    std::wcout << L"  !cr\n";
    std::wcout << L"\n";
    std::wcout << L"output:\n";
    std::wcout << L"  Reads CR0/CR4/CR8 on every active processor in group 0 through the driver's\n";
    std::wcout << L"  read-only control-register primitive.\n";
    std::wcout << L"\n";
    std::wcout << L"checks:\n";
    std::wcout << L"  CR0.WP must be 1 (kernel write-protect); WP=0 or any per-CPU divergence of CR0/CR4\n";
    std::wcout << L"  is flagged as suspicious. SMEP/SMAP/UMIP/LA57/CET/PKE bits in CR4 are decoded; SMEP\n";
    std::wcout << L"  or SMAP off is surfaced as a mitigation-weakened note (legacy CPUs may lack them).\n";
}

static void PrintCrReadingRecord(const CrReading& reading)
{
    PrintColoredText(L"[cr]", KNDBG_COLOR_TITLE);
    std::wcout << L" ";
    PrintColoredText(reading.Name, KNDBG_COLOR_ACCENT);

    if (reading.PerCpuValues.empty())
    {
        std::wcout << L" read-failed\n";
        return;
    }

    uint64_t value = reading.PerCpuValues.front();
    std::wcout << L"=" << HexTextWidth(value, 16, true);
    if (reading.Suspicious)
    {
        std::wcout << L" ";
        PrintColoredText(L"[SUSPICIOUS]", KNDBG_COLOR_FAIL);
    }
    std::wcout << L"\n";

    if (reading.Name == L"CR0")
    {
        std::wcout << L"  WP=" << ((value & (1ull << 16)) != 0 ? L"1" : L"0")
                   << L" PG=" << ((value & (1ull << 31)) != 0 ? L"1" : L"0")
                   << L" NE=" << ((value & (1ull << 5)) != 0 ? L"1" : L"0") << L"\n";
    }
    else if (reading.Name == L"CR4")
    {
        std::wcout << L"  SMEP=" << ((value & (1ull << 20)) != 0 ? L"1" : L"0")
                   << L" SMAP=" << ((value & (1ull << 21)) != 0 ? L"1" : L"0")
                   << L" UMIP=" << ((value & (1ull << 11)) != 0 ? L"1" : L"0")
                   << L" LA57=" << ((value & (1ull << 12)) != 0 ? L"1" : L"0")
                   << L" CET=" << ((value & (1ull << 23)) != 0 ? L"1" : L"0")
                   << L" PKE=" << ((value & (1ull << 22)) != 0 ? L"1" : L"0") << L"\n";
    }

    if (reading.Divergent)
    {
        std::wcout << L"  per-cpu:";
        for (size_t i = 0; i < reading.PerCpuValues.size(); ++i)
        {
            std::wcout << L" cpu" << std::dec << i << L"=" << HexTextWidth(reading.PerCpuValues[i], 16, true);
        }
        std::wcout << L"\n";
    }

    if (!reading.Notes.empty())
    {
        std::wcout << L"  note: ";
        PrintColoredText(reading.Notes, KNDBG_COLOR_WARN);
        std::wcout << L"\n";
    }
}

static void HandleCrCommand(
    const std::vector<std::wstring>& args,
    DeviceClient& device)
{
    do
    {
        if (!device.IsOpen())
        {
            std::wcerr << L"!cr requires the KnLiveDbg.sys driver device to be open\n";
            break;
        }

        if (HasHelpToken(args, 1))
        {
            PrintCrCheckHelp();
            break;
        }

        if (args.size() > 1)
        {
            std::wcerr << L"!cr: unexpected extra argument \"" << args[1] << L"\"\n";
            PrintCrCheckHelp();
            break;
        }

        CrScanner scanner(device);
        CrScanResult result = {};
        std::wstring error;
        if (!scanner.Scan(&result, &error))
        {
            std::wcerr << L"!cr failed: " << error << L"\n";
            for (const std::wstring& warning : result.Warnings)
            {
                std::wcerr << L"!cr warning: " << warning << L"\n";
            }
            break;
        }

        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"!cr warning: " << warning << L"\n";
        }

        PrintColoredText(L"control registers", KNDBG_COLOR_TITLE);
        std::wcout << L" cpus=" << std::dec << result.ProcessorCount;
        if (result.AnySuspicious)
        {
            std::wcout << L" ";
            PrintColoredText(L"[SUSPICIOUS]", KNDBG_COLOR_FAIL);
        }
        std::wcout << L"\n";

        for (const CrReading& reading : result.Readings)
        {
            PrintCrReadingRecord(reading);
        }
    } while (false);
}

static void PrintSsdtHelp()
{
    std::wcout << L"!ssdt command:\n";
    std::wcout << L"  !ssdt\n";
    std::wcout << L"\n";
    std::wcout << L"output:\n";
    std::wcout << L"  Walks the native SSDT (nt!KeServiceDescriptorTable -> KiServiceTable) and, when\n";
    std::wcout << L"  win32k modules are loaded, the win32k shadow table\n";
    std::wcout << L"  (nt!KeServiceDescriptorTableShadow[1]).\n";
    std::wcout << L"\n";
    std::wcout << L"checks:\n";
    std::wcout << L"  Each service routine is decoded (x64: KiServiceTable + (entry >> 4)) and validated\n";
    std::wcout << L"  to reside in the expected kernel image (ntoskrnl for the native table, win32k* for\n";
    std::wcout << L"  the shadow table). Routines outside the expected module, or outside all loaded\n";
    std::wcout << L"  modules, are flagged as syscall-hook evidence. Only hooked entries are listed; a\n";
    std::wcout << L"  clean table prints a one-line summary.\n";
}

static void PrintSsdtTable(const SsdtTable& table)
{
    PrintColoredText(L"[ssdt.table]", KNDBG_COLOR_TITLE);
    std::wcout << L" ";
    PrintColoredText(table.Name, KNDBG_COLOR_ACCENT);

    if (!table.Resolved)
    {
        std::wcout << L" unresolved";
        if (!table.Warning.empty())
        {
            std::wcout << L": " << table.Warning;
        }
        std::wcout << L"\n";
        return;
    }

    std::wcout << L" base=" << HexTextWidth(table.TableBase, 16, true)
               << L" count=" << std::dec << table.Limit
               << L" expected=" << table.ExpectedModule;
    if (table.SuspiciousCount > 0)
    {
        std::wcout << L" ";
        PrintColoredText(L"[SUSPICIOUS]", KNDBG_COLOR_FAIL);
        std::wcout << L" hooks=" << std::dec << table.SuspiciousCount;
    }
    std::wcout << L"\n";

    if (!table.Warning.empty())
    {
        std::wcout << L"  warning: " << table.Warning << L"\n";
    }

    if (table.SuspiciousCount == 0)
    {
        std::wcout << L"  all " << std::dec << table.Limit << L" service routines resolve into "
                   << table.ExpectedModule << L"\n";
        return;
    }

    for (const SsdtEntry& entry : table.Entries)
    {
        if (!entry.Suspicious)
        {
            continue;
        }

        std::wcout << L"  ";
        PrintColoredText(L"[ssdt.hook]", KNDBG_COLOR_FAIL);
        std::wcout << L" index=" << std::dec << entry.Index
                   << L" routine=" << HexTextWidth(entry.Routine, 16, true);
        if (!entry.Module.empty())
        {
            std::wcout << L" module=";
            PrintColoredText(entry.Module, KNDBG_COLOR_WARN);
        }
        if (!entry.Symbol.empty())
        {
            std::wcout << L" symbol=" << entry.Symbol;
        }
        std::wcout << L"\n";
        if (!entry.Notes.empty())
        {
            std::wcout << L"    note: ";
            PrintColoredText(entry.Notes, KNDBG_COLOR_WARN);
            std::wcout << L"\n";
        }
    }
}

static void HandleSsdtCommand(
    const std::vector<std::wstring>& args,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    do
    {
        if (!device.IsOpen())
        {
            std::wcerr << L"!ssdt requires the KnLiveDbg.sys driver device to be open\n";
            break;
        }

        if (HasHelpToken(args, 1))
        {
            PrintSsdtHelp();
            break;
        }

        if (args.size() > 1)
        {
            std::wcerr << L"!ssdt: unexpected extra argument \"" << args[1] << L"\"\n";
            PrintSsdtHelp();
            break;
        }

        if (symbols.Modules().empty())
        {
            std::wstring loadError;
            if (!symbols.LoadKernelModules(&loadError))
            {
                std::wcerr << L"!ssdt failed: " << loadError << L"\n";
                break;
            }
        }

        SsdtScanner scanner(device, symbols);
        SsdtScanResult result = {};
        std::wstring error;
        if (!scanner.Scan(&result, &error))
        {
            std::wcerr << L"!ssdt failed: " << error << L"\n";
            for (const std::wstring& warning : result.Warnings)
            {
                std::wcerr << L"!ssdt warning: " << warning << L"\n";
            }
            break;
        }

        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"!ssdt warning: " << warning << L"\n";
        }

        PrintColoredText(L"ssdt", KNDBG_COLOR_TITLE);
        std::wcout << L" tables=" << std::dec << result.Tables.size();
        if (result.AnySuspicious)
        {
            std::wcout << L" ";
            PrintColoredText(L"[SUSPICIOUS]", KNDBG_COLOR_FAIL);
            std::wcout << L" hooks=" << std::dec << result.SuspiciousCount;
        }
        std::wcout << L"\n";

        for (const SsdtTable& table : result.Tables)
        {
            PrintSsdtTable(table);
        }
    } while (false);
}

static void PrintIdtHelp()
{
    std::wcout << L"!idt command:\n";
    std::wcout << L"  !idt\n";
    std::wcout << L"\n";
    std::wcout << L"output:\n";
    std::wcout << L"  Reads the boot processor IDTR (via __sidt) through the read-only IDT primitive and\n";
    std::wcout << L"  walks the interrupt gate descriptors from live kernel memory.\n";
    std::wcout << L"\n";
    std::wcout << L"checks:\n";
    std::wcout << L"  Each present gate's handler is rebuilt (OffsetLow | Middle<<16 | High<<32) and\n";
    std::wcout << L"  validated to reside in a loaded kernel module. Handlers outside every loaded module\n";
    std::wcout << L"  are flagged as interrupt-hook evidence. Only flagged gates are listed; a clean table\n";
    std::wcout << L"  prints a one-line summary. Every active processor's IDT is cross-checked against\n";
    std::wcout << L"  the boot processor; a per-CPU handler divergence (single-core hook) is flagged.\n";
}

static void HandleIdtCommand(
    const std::vector<std::wstring>& args,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    do
    {
        if (!device.IsOpen())
        {
            std::wcerr << L"!idt requires the KnLiveDbg.sys driver device to be open\n";
            break;
        }

        if (HasHelpToken(args, 1))
        {
            PrintIdtHelp();
            break;
        }

        if (args.size() > 1)
        {
            std::wcerr << L"!idt: unexpected extra argument \"" << args[1] << L"\"\n";
            PrintIdtHelp();
            break;
        }

        if (symbols.Modules().empty())
        {
            std::wstring loadError;
            if (!symbols.LoadKernelModules(&loadError))
            {
                std::wcerr << L"!idt failed: " << loadError << L"\n";
                break;
            }
        }

        IdtScanner scanner(device, symbols);
        IdtScanResult result = {};
        std::wstring error;
        if (!scanner.Scan(&result, &error))
        {
            std::wcerr << L"!idt failed: " << error << L"\n";
            for (const std::wstring& warning : result.Warnings)
            {
                std::wcerr << L"!idt warning: " << warning << L"\n";
            }
            break;
        }

        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"!idt warning: " << warning << L"\n";
        }

        PrintColoredText(L"idt", KNDBG_COLOR_TITLE);
        std::wcout << L" cpu=" << std::dec << result.ProcessorNumber
                   << L" base=" << HexTextWidth(result.IdtBase, 16, true)
                   << L" entries=" << std::dec << result.EntryCount
                   << L" cpus-compared=" << std::dec << (result.ProcessorsCompared + 1);
        if (result.AnySuspicious)
        {
            std::wcout << L" ";
            PrintColoredText(L"[SUSPICIOUS]", KNDBG_COLOR_FAIL);
            std::wcout << L" hooks=" << std::dec << result.SuspiciousCount;
            if (result.DivergentCount > 0)
            {
                std::wcout << L" divergent=" << std::dec << result.DivergentCount;
            }
        }
        std::wcout << L"\n";

        if (!result.AnySuspicious)
        {
            std::wcout << L"  all present interrupt handlers resolve into loaded kernel modules";
            if (result.ProcessorsCompared > 0)
            {
                std::wcout << L" and match across all " << std::dec << (result.ProcessorsCompared + 1) << L" processors";
            }
            std::wcout << L"\n";
        }

        for (const IdtEntry& entry : result.Entries)
        {
            if (!entry.Suspicious)
            {
                continue;
            }

            std::wcout << L"  ";
            PrintColoredText(L"[idt.hook]", KNDBG_COLOR_FAIL);
            std::wcout << L" vector=" << std::dec << entry.Vector
                       << L" handler=" << HexTextWidth(entry.Handler, 16, true);
            if (!entry.Module.empty())
            {
                std::wcout << L" module=";
                PrintColoredText(entry.Module, KNDBG_COLOR_WARN);
            }
            if (!entry.Symbol.empty())
            {
                std::wcout << L" symbol=" << entry.Symbol;
            }
            std::wcout << L"\n";
            if (!entry.Notes.empty())
            {
                std::wcout << L"    note: ";
                PrintColoredText(entry.Notes, KNDBG_COLOR_WARN);
                std::wcout << L"\n";
            }
        }
    } while (false);
}

static void PrintFirmwareTableHelp()
{
    std::wcout << L"!fwtable command:\n";
    std::wcout << L"  !fwtable providers\n";
    std::wcout << L"  !fwtable providers /module <name>\n";
    std::wcout << L"  !fwtable provider <signature>\n";
    std::wcout << L"\n";
    std::wcout << L"output:\n";
    std::wcout << L"  Registered firmware table provider nodes from nt!ExpFirmwareTableProviderListHead with handler and DriverObject annotations.\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  Default enumeration is passive and never invokes firmware handlers.\n";
    std::wcout << L"  ACPI, FIRM, and RSMB are treated as baseline providers; custom signatures are highlighted for triage.\n";
    std::wcout << L"  Calling EnumSystemFirmwareTables or GetSystemFirmwareTable can execute a registered handler, so probing is not part of this passive scan.\n";
}

static bool ParseFirmwareProviderSignature(
    const std::wstring& value,
    uint32_t numberBase,
    uint32_t* signature)
{
    bool ok = false;

    do
    {
        if (signature == nullptr)
        {
            break;
        }

        std::wstring text = TrimWhitespace(value);
        if (text.size() == 4 && text.find_first_not_of(L"0123456789abcdefABCDEFxX") != std::wstring::npos)
        {
            uint32_t parsed = 0;
            for (wchar_t ch : text)
            {
                if (ch < 0x20 || ch > 0x7e)
                {
                    parsed = 0;
                    break;
                }
                parsed = (parsed << 8) | static_cast<uint32_t>(static_cast<uint8_t>(ch));
            }
            if (parsed != 0)
            {
                *signature = parsed;
                ok = true;
                break;
            }
        }

        if (text.size() == 4 && text.rfind(L"0x", 0) != 0 && text.rfind(L"0X", 0) != 0)
        {
            bool printable = true;
            for (wchar_t ch : text)
            {
                if (ch < 0x20 || ch > 0x7e)
                {
                    printable = false;
                    break;
                }
            }
            if (printable && text.find_first_not_of(L"0123456789") != std::wstring::npos)
            {
                uint32_t parsed = 0;
                for (wchar_t ch : text)
                {
                    parsed = (parsed << 8) | static_cast<uint32_t>(static_cast<uint8_t>(ch));
                }
                *signature = parsed;
                ok = true;
                break;
            }
        }

        uint64_t numeric = 0;
        if (ParseUnsigned(text, numberBase, &numeric) && numeric <= 0xffffffffull)
        {
            *signature = static_cast<uint32_t>(numeric);
            ok = true;
            break;
        }
    } while (false);

    return ok;
}

static bool FirmwareProviderMatchesModuleFilter(
    const FirmwareTableProviderRecord& record,
    const std::wstring& moduleFilter)
{
    bool matched = false;

    do
    {
        if (TrimWhitespace(moduleFilter).empty())
        {
            matched = true;
            break;
        }

        if (CallbackModuleTextMatchesFilter(record.HandlerModule, moduleFilter) ||
            CallbackModuleTextMatchesFilter(record.DriverModule, moduleFilter) ||
            CallbackModuleTextMatchesFilter(record.DriverName, moduleFilter))
        {
            matched = true;
            break;
        }
    } while (false);

    return matched;
}

static void ApplyFirmwareTableFilters(
    const std::wstring& moduleFilter,
    bool hasProviderFilter,
    uint32_t providerFilter,
    FirmwareTableScanResult* result)
{
    do
    {
        if (result == nullptr)
        {
            break;
        }

        if (TrimWhitespace(moduleFilter).empty() && !hasProviderFilter)
        {
            break;
        }

        std::vector<FirmwareTableProviderRecord> filtered;
        filtered.reserve(result->Records.size());
        for (const FirmwareTableProviderRecord& record : result->Records)
        {
            if (hasProviderFilter && record.ProviderSignature != providerFilter)
            {
                continue;
            }
            if (!FirmwareProviderMatchesModuleFilter(record, moduleFilter))
            {
                continue;
            }
            filtered.push_back(record);
        }

        result->Records.swap(filtered);
    } while (false);
}

static void PrintFirmwareTableProviderRecord(const FirmwareTableProviderRecord& record)
{
    PrintColoredText(L"[fwtable.provider]", record.Suspicious ? KNDBG_COLOR_WARN : KNDBG_COLOR_TITLE);
    std::wcout << L" slot=" << std::dec << record.Slot;
    std::wcout << L" sig=" << HexTextWidth(record.ProviderSignature, 8, true);
    if (!record.ProviderText.empty())
    {
        std::wcout << L" fourcc=\"";
        PrintColoredText(record.ProviderText, record.StandardProvider ? KNDBG_COLOR_OK : KNDBG_COLOR_WARN);
        std::wcout << L"\"";
    }
    if (record.Suspicious)
    {
        std::wcout << L" ";
        PrintColoredText(L"[SUSPICIOUS]", KNDBG_COLOR_FAIL);
    }
    std::wcout << L"\n";

    std::wcout << L"  node=" << HexTextWidth(record.NodeAddress, 16, true)
               << L" list=" << HexTextWidth(record.ListEntry, 16, true)
               << L" flink=" << HexTextWidth(record.Flink, 16, true)
               << L" blink=" << HexTextWidth(record.Blink, 16, true)
               << L" register=" << std::dec << static_cast<uint32_t>(record.RegisterFlag) << L"\n";

    std::wcout << L"  ";
    PrintColoredText(L"handler", KNDBG_COLOR_ACCENT);
    std::wcout << L"=" << HexTextWidth(record.FirmwareTableHandler, 16, true);
    if (!record.HandlerModule.empty())
    {
        std::wcout << L" module=";
        PrintColoredText(record.HandlerModule, KNDBG_COLOR_OK);
    }
    else
    {
        std::wcout << L" module=";
        PrintColoredText(L"<non-image>", KNDBG_COLOR_WARN);
        if (record.FirmwareTableHandler != 0)
        {
            std::wcout << L" moduleAddress=" << HexTextWidth(record.FirmwareTableHandler, 16, true);
        }
    }
    if (!record.HandlerSymbol.empty())
    {
        std::wcout << L" symbol=";
        PrintColoredText(record.HandlerSymbol, KNDBG_COLOR_TITLE);
    }
    std::wcout << L"\n";

    std::wcout << L"  ";
    PrintColoredText(L"driverObject", KNDBG_COLOR_ACCENT);
    std::wcout << L"=" << HexTextWidth(record.DriverObject, 16, true);
    if (!record.DriverName.empty())
    {
        std::wcout << L" name=\"";
        PrintColoredText(record.DriverName, KNDBG_COLOR_OK);
        std::wcout << L"\"";
    }
    else if (record.DriverObject != 0)
    {
        std::wcout << L" name=<unresolved> raw=" << HexTextWidth(record.DriverObject, 16, true);
    }
    if (record.DriverStart != 0)
    {
        std::wcout << L" start=" << HexTextWidth(record.DriverStart, 16, true)
                   << L" size=0x" << std::hex << record.DriverSize << std::dec;
    }
    if (!record.DriverModule.empty())
    {
        std::wcout << L" module=";
        PrintColoredText(record.DriverModule, KNDBG_COLOR_OK);
    }
    else if (record.DriverStart != 0)
    {
        std::wcout << L" module=";
        PrintColoredText(L"<non-image>", KNDBG_COLOR_WARN);
        std::wcout << L" moduleAddress=" << HexTextWidth(record.DriverStart, 16, true);
    }
    std::wcout << L"\n";

    if (!record.Notes.empty())
    {
        std::wcout << L"  ";
        PrintColoredText(L"notes", KNDBG_COLOR_WARN);
        std::wcout << L"=" << record.Notes << L"\n";
    }
}

static void HandleFirmwareTableCommand(
    const std::vector<std::wstring>& args,
    const DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    do
    {
        if (HasHelpToken(args, 1))
        {
            PrintFirmwareTableHelp();
            break;
        }

        if (!device.IsOpen())
        {
            std::wcerr << L"!fwtable requires the KnLiveDbg.sys driver device to be open\n";
            break;
        }

        std::wstring scope = L"providers";
        std::wstring moduleFilter;
        bool hasProviderFilter = false;
        uint32_t providerFilter = 0;

        size_t index = 1;
        if (index < args.size())
        {
            std::wstring requested = ToLower(args[index]);
            if (requested == L"providers")
            {
                ++index;
            }
            else if (requested == L"provider")
            {
                scope = L"provider";
                ++index;
                if (index >= args.size())
                {
                    std::wcerr << L"usage: !fwtable provider <signature>\n";
                    break;
                }
                if (!ParseFirmwareProviderSignature(args[index], state.NumberBase, &providerFilter))
                {
                    std::wcerr << L"!fwtable: invalid provider signature \"" << args[index] << L"\"\n";
                    break;
                }
                hasProviderFilter = true;
                ++index;
            }
            else
            {
                std::wcerr << L"usage: !fwtable [providers|provider <signature>]\n";
                std::wcerr << L"       !fwtable providers /module <name>\n";
                PrintFirmwareTableHelp();
                break;
            }
        }

        while (index < args.size())
        {
            std::wstring option = ToLower(args[index]);
            if (option == L"/module")
            {
                if (scope != L"providers")
                {
                    std::wcerr << L"!fwtable /module applies to providers scope\n";
                    break;
                }
                if (index + 1 >= args.size())
                {
                    std::wcerr << L"usage: !fwtable providers /module <name>\n";
                    break;
                }
                if (!moduleFilter.empty())
                {
                    std::wcerr << L"!fwtable accepts only one /module filter\n";
                    break;
                }
                moduleFilter = args[index + 1];
                index += 2;
                continue;
            }

            std::wcerr << L"!fwtable: unexpected argument \"" << args[index] << L"\"\n";
            break;
        }

        if (index < args.size())
        {
            break;
        }

        if (symbols.Modules().empty())
        {
            std::wstring loadError;
            if (!symbols.LoadKernelModules(&loadError))
            {
                std::wcerr << L"!fwtable failed: " << loadError << L"\n";
                break;
            }
        }

        FirmwareTableScanner scanner(device, symbols);
        FirmwareTableScanResult result = {};
        std::wstring error;
        if (!scanner.Scan(&result, &error))
        {
            std::wcerr << L"!fwtable failed: " << error << L"\n";
            for (const std::wstring& warning : result.Warnings)
            {
                std::wcerr << L"!fwtable warning: " << warning << L"\n";
            }
            break;
        }

        ApplyFirmwareTableFilters(moduleFilter, hasProviderFilter, providerFilter, &result);

        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"!fwtable warning: " << warning << L"\n";
        }

        size_t suspiciousCount = 0;
        for (const FirmwareTableProviderRecord& record : result.Records)
        {
            if (record.Suspicious)
            {
                ++suspiciousCount;
            }
        }

        PrintColoredText(L"firmware table providers", KNDBG_COLOR_TITLE);
        std::wcout << L"=" << std::dec << result.Records.size()
                   << L" suspicious=";
        PrintColoredText(std::to_wstring(suspiciousCount),
                         suspiciousCount == 0 ? KNDBG_COLOR_OK : KNDBG_COLOR_FAIL);
        std::wcout << L" listHead=" << result.ListHeadSymbol
                   << L"(" << HexTextWidth(result.ListHeadAddress, 16, true) << L")";
        std::wcout << L" layout=";
        if (!result.LayoutName.empty())
        {
            std::wcout << result.LayoutName;
        }
        else
        {
            std::wcout << (result.UsedFallbackLayout ? L"fallback" : L"pdb");
        }
        if (result.ResourceAddress != 0)
        {
            std::wcout << L" resource=" << result.ResourceSymbol
                       << L"(" << HexTextWidth(result.ResourceAddress, 16, true) << L")";
        }
        if (!moduleFilter.empty())
        {
            std::wcout << L" module=";
            PrintColoredText(moduleFilter, KNDBG_COLOR_OK);
        }
        if (hasProviderFilter)
        {
            std::wcout << L" provider=" << HexTextWidth(providerFilter, 8, true);
        }
        std::wcout << L"\n";

        for (const FirmwareTableProviderRecord& record : result.Records)
        {
            PrintFirmwareTableProviderRecord(record);
        }
    } while (false);
}

static void PrintDumpRawHelp()
{
    std::wcout << L"dump-raw command:\n";
    std::wcout << L"  dump-raw <address> <length> <path> [/zerofill]\n";
    std::wcout << L"\n";
    std::wcout << L"description:\n";
    std::wcout << L"  Reads <length> bytes starting at <address> from kernel memory through the driver\n";
    std::wcout << L"  IOCTL and writes them verbatim to <path>. The read is chunked into 256 KB IOCTL\n";
    std::wcout << L"  calls; per-chunk failures abort the dump unless /zerofill is supplied, in which\n";
    std::wcout << L"  case failed chunks are zero-filled and a per-chunk warning is recorded.\n";
    std::wcout << L"\n";
    std::wcout << L"arguments:\n";
    std::wcout << L"  <address>   start virtual address (symbol or hex/decimal value).\n";
    std::wcout << L"  <length>    number of bytes to read (hex or decimal). Capped at 1 GB.\n";
    std::wcout << L"  <path>      output file path. Existing file is overwritten.\n";
    std::wcout << L"  /zerofill   continue on read failure and zero-fill the failed chunk.\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  Requires the KnLiveDbg.sys driver device to be open. Wrap paths that contain\n";
    std::wcout << L"  whitespace in double quotes (\"C:\\Program Files\\foo.bin\"). Apostrophes in\n";
    std::wcout << L"  unquoted paths are kept literal (matches CMD/PowerShell convention).\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  dump-raw nt!KiSystemServiceUser 0x200 .\\kiSystemServiceUser.bin\n";
    std::wcout << L"  dump-raw 0xffffae8000123000 0x1000 .\\stack-page.bin\n";
    std::wcout << L"  dump-raw nt 0x100000 \"C:\\Program Files\\Dumps\\ntoskrnl-1mb.bin\" /zerofill\n";
}

static void PrintDumpPeHelp()
{
    std::wcout << L"dump-pe command:\n";
    std::wcout << L"  dump-pe <address> <path>\n";
    std::wcout << L"\n";
    std::wcout << L"description:\n";
    std::wcout << L"  Treats the memory region at <address> as an in-memory loaded PE image and rebuilds\n";
    std::wcout << L"  the on-disk PE layout from the in-memory section table. The headers are copied\n";
    std::wcout << L"  verbatim and each section's bytes are read from address+VirtualAddress and written\n";
    std::wcout << L"  to file offset PointerToRawData (SizeOfRawData bytes), reversing the loader's RVA\n";
    std::wcout << L"  expansion. Sections that fail to read (typically discarded INIT) are zero-filled\n";
    std::wcout << L"  with a warning rather than aborting the dump.\n";
    std::wcout << L"\n";
    std::wcout << L"arguments:\n";
    std::wcout << L"  <address>   PE base virtual address (symbol or hex/decimal value).\n";
    std::wcout << L"  <path>      output file path. Existing file is overwritten.\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  Requires the KnLiveDbg.sys driver device to be open. PE32 (32-bit) and PE32+\n";
    std::wcout << L"  (64-bit) are both supported.\n";
    std::wcout << L"\n";
    std::wcout << L"  Header recovery: the scanner restores wiped 'MZ' / 'PE\\0\\0' signatures and\n";
    std::wcout << L"  corrupted e_lfanew values when the surrounding FileHeader/OptionalHeader fields\n";
    std::wcout << L"  are intact enough to identify the NT header position. This covers the common\n";
    std::wcout << L"  malware/loader-stomp pattern of zeroing the magic bytes to evade signature\n";
    std::wcout << L"  scanners while leaving the rest of the structure usable. Restored fields are\n";
    std::wcout << L"  reported in the summary line under recovered=[MZ,e_lfanew,PE].\n";
    std::wcout << L"\n";
    std::wcout << L"  Caveats: the dumped image reflects the in-memory state -- relocations are applied,\n";
    std::wcout << L"  the IAT is resolved to live addresses, and any in-place patches by anti-malware or\n";
    std::wcout << L"  PatchGuard appear in the output. Use this for IDA/Ghidra inspection of the running\n";
    std::wcout << L"  image, not for repackaging.\n";
    std::wcout << L"\n";
    std::wcout << L"  Paths with spaces are accepted when wrapped in double quotes\n";
    std::wcout << L"  (\"C:\\Program Files\\Dumps\\foo.sys\"). Apostrophes in unquoted paths are\n";
    std::wcout << L"  kept literal so names like O'Brien\\foo.sys do not need quoting.\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  dump-pe nt .\\ntoskrnl-live.exe\n";
    std::wcout << L"  dump-pe Wdf01000 .\\wdf01000-live.sys\n";
    std::wcout << L"  dump-pe 0xfffff80300000000 \"C:\\Program Files\\Dumps\\unknown-driver.sys\"\n";
}

static void HandleDumpRawCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    do
    {
        if (HasHelpToken(args, 1))
        {
            PrintDumpRawHelp();
            break;
        }

        if (args.size() < 4)
        {
            std::wcerr << L"usage: dump-raw <address> <length> <path> [/zerofill]\n";
            PrintDumpRawHelp();
            break;
        }

        if (!device.IsOpen())
        {
            std::wcerr << L"dump-raw requires the KnLiveDbg.sys driver device to be open\n";
            break;
        }

        std::wstring error;
        uint64_t address = 0;
        if (!ParseAddressOrSymbol(symbols, state, args[1], &address, &error))
        {
            std::wcerr << L"dump-raw: failed to parse address \"" << args[1] << L"\": " << error << L"\n";
            break;
        }

        uint64_t length = 0;
        if (!ParseUnsigned(args[2], state.NumberBase, &length))
        {
            std::wcerr << L"dump-raw: failed to parse length \"" << args[2] << L"\"\n";
            break;
        }

        if (length == 0)
        {
            std::wcerr << L"dump-raw: length must be > 0\n";
            break;
        }

        std::wstring path = args[3];
        bool zeroFill = false;
        bool parseError = false;
        for (size_t i = 4; i < args.size(); ++i)
        {
            std::wstring opt = ToLower(args[i]);
            if (opt == L"/zerofill")
            {
                zeroFill = true;
            }
            else
            {
                std::wcerr << L"dump-raw: unrecognised argument \"" << args[i] << L"\"\n";
                PrintDumpRawHelp();
                parseError = true;
                break;
            }
        }

        if (parseError)
        {
            break;
        }

        DumpRawResult result = {};
        std::wstring dumpError;
        if (!DumpKernelRangeToFile(device, address, length, path, zeroFill, &result, &dumpError))
        {
            std::wcerr << L"dump-raw failed: " << dumpError << L"\n";
            for (const std::wstring& warning : result.Warnings)
            {
                std::wcerr << L"dump-raw warning: " << warning << L"\n";
            }
            break;
        }

        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"dump-raw warning: " << warning << L"\n";
        }

        PrintColoredText(L"[dump-raw]", KNDBG_COLOR_TITLE);
        std::wcout << L" address=" << HexTextWidth(result.StartAddress, 16, true)
                   << L" length=0x" << std::hex << result.Length << std::dec
                   << L" wrote=" << result.BytesWritten
                   << L" chunks=" << result.ChunksRead;
        if (result.ChunksFailed > 0)
        {
            std::wcout << L" ";
            PrintColoredText(L"zero-filled=" + std::to_wstring(result.ChunksFailed), KNDBG_COLOR_WARN);
        }
        std::wcout << L" path=";
        PrintColoredText(path, KNDBG_COLOR_OK);
        std::wcout << L"\n";
    } while (false);
}

static void PrintAddressHelp()
{
    std::wcout << L"!address command:\n";
    std::wcout << L"  !address <va>\n";
    std::wcout << L"\n";
    std::wcout << L"description:\n";
    std::wcout << L"  Reports detailed properties of a virtual address: canonicality, kernel vs\n";
    std::wcout << L"  user half, the page-table walk down to the leaf PTE (PML5/PML4/PDPTE/PDE/PTE\n";
    std::wcout << L"  values plus their physical addresses), the resulting physical address, the\n";
    std::wcout << L"  effective R/W/X/U permissions across every traversed level, and the owning\n";
    std::wcout << L"  kernel module + nearest symbol when known.\n";
    std::wcout << L"\n";
    std::wcout << L"arguments:\n";
    std::wcout << L"  <va>   virtual address (hex/decimal value, symbol like nt!Foo, or expression).\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  The page-table walk runs through the KnLiveDbg.sys TranslateVirtual IOCTL and\n";
    std::wcout << L"  uses the live CR3. Effective writable = AND of bit-1 across walked levels;\n";
    std::wcout << L"  effective executable = AND of (!NX) across walked levels.\n";
    std::wcout << L"  LA57 (5-level) paging is auto-detected; the kernel/user split adjusts accordingly.\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  !address 0xfffff80237890000\n";
    std::wcout << L"  !address nt!ExpWnfSiloState\n";
    std::wcout << L"  !address WdFilter+0x1234\n";
}

static void PrintAddressInspection(const AddressInspectResult& r)
{
    PrintColoredText(L"[address]", KNDBG_COLOR_TITLE);
    std::wcout << L" " << HexTextWidth(r.VirtualAddress, 16, true) << L"\n";

    std::wcout << L"  canonical=";
    PrintColoredText(r.IsCanonical ? L"yes" : L"no",
                     r.IsCanonical ? KNDBG_COLOR_OK : KNDBG_COLOR_FAIL);
    if (r.IsCanonical)
    {
        std::wcout << L" class=";
        if (r.IsZeroPage)
        {
            PrintColoredText(L"zero-page", KNDBG_COLOR_WARN);
        }
        else if (r.IsKernelSpace)
        {
            PrintColoredText(L"kernel", KNDBG_COLOR_OK);
        }
        else if (r.IsUserSpace)
        {
            PrintColoredText(L"user", KNDBG_COLOR_ACCENT);
        }
        else
        {
            PrintColoredText(L"unknown", KNDBG_COLOR_DIM);
        }
    }
    if (r.La57Active)
    {
        std::wcout << L" paging=LA57";
    }
    std::wcout << L"\n";

    if (r.HasModule)
    {
        PrintColoredText(L"  module", KNDBG_COLOR_ACCENT);
        std::wcout << L"=";
        PrintColoredText(r.ModuleName, KNDBG_COLOR_TITLE);
        std::wcout << L" base=" << HexTextWidth(r.ModuleBase, 16, true)
                   << L" size=0x" << std::hex << r.ModuleSize << std::dec
                   << L" offset=0x" << std::hex << r.OffsetInModule << std::dec << L"\n";
        if (!r.ModulePath.empty())
        {
            std::wcout << L"  image=";
            PrintColoredText(r.ModulePath, KNDBG_COLOR_DIM);
            std::wcout << L"\n";
        }
    }

    if (r.HasSymbol)
    {
        PrintColoredText(L"  symbol", KNDBG_COLOR_ACCENT);
        std::wcout << L"=";
        PrintColoredText(r.SymbolName, KNDBG_COLOR_TITLE);
        std::wcout << L"+0x" << std::hex << r.SymbolDisplacement << std::dec << L"\n";
    }

    if (r.TranslationAttempted)
    {
        if (r.TranslationSucceeded)
        {
            PrintColoredText(L"[address.translation]", KNDBG_COLOR_TITLE);
            std::wcout << L" CR3=" << HexTextWidth(r.DirectoryTableBase, 16, true)
                       << L" levels=" << std::dec << r.PagingLevels
                       << L" pageSize=0x" << std::hex << r.PageSize << std::dec;
            if (r.LargePage)
            {
                std::wcout << L" ";
                PrintColoredText(L"LargePage", KNDBG_COLOR_WARN);
            }
            std::wcout << L"\n";

            auto printLevel = [](const wchar_t* name, uint64_t addr, uint64_t value)
            {
                if (addr == 0 && value == 0)
                {
                    return;
                }
                std::wcout << L"  ";
                PrintColoredText(name, KNDBG_COLOR_ACCENT);
                std::wcout << L" @ " << HexTextWidth(addr, 16, true)
                           << L" = " << HexTextWidth(value, 16, true);
                std::wcout << L" (P=" << ((value & 1ULL) ? 1 : 0)
                           << L" W=" << ((value & 2ULL) ? 1 : 0)
                           << L" U=" << ((value & 4ULL) ? 1 : 0)
                           << L" PS=" << ((value & 0x80ULL) ? 1 : 0)
                           << L" NX=" << ((value & (1ULL << 63)) ? 1 : 0)
                           << L")\n";
            };

            if (r.La57Active)
            {
                printLevel(L"PML5E", r.Pml5eAddress, r.Pml5e);
            }
            printLevel(L"PML4E", r.Pml4eAddress, r.Pml4e);
            printLevel(L"PDPTE", r.PdpteAddress, r.Pdpte);
            printLevel(L"PDE  ", r.PdeAddress, r.Pde);
            printLevel(L"PTE  ", r.PteAddress, r.Pte);

            std::wcout << L"  effective: ";
            std::wcout << L"present=";
            PrintColoredText(r.EffectivePresent ? L"yes" : L"no",
                             r.EffectivePresent ? KNDBG_COLOR_OK : KNDBG_COLOR_FAIL);
            std::wcout << L" R=" << (r.EffectivePresent ? L"1" : L"0");
            std::wcout << L" W=";
            PrintColoredText(r.EffectiveWritable ? L"1" : L"0",
                             r.EffectiveWritable ? KNDBG_COLOR_WARN : KNDBG_COLOR_DIM);
            std::wcout << L" X=";
            PrintColoredText(r.EffectiveExecutable ? L"1" : L"0",
                             r.EffectiveExecutable ? KNDBG_COLOR_FAIL : KNDBG_COLOR_DIM);
            std::wcout << L" U=";
            PrintColoredText(r.EffectiveUserAccessible ? L"1" : L"0",
                             r.EffectiveUserAccessible ? KNDBG_COLOR_WARN : KNDBG_COLOR_DIM);
            if (r.EffectiveWritable && r.EffectiveExecutable && r.EffectivePresent)
            {
                std::wcout << L" ";
                PrintColoredText(L"[W+X]", KNDBG_COLOR_FAIL);
            }
            std::wcout << L"\n";

            PrintColoredText(L"[address.physical]", KNDBG_COLOR_TITLE);
            std::wcout << L" PA=" << HexTextWidth(r.PhysicalAddress, 16, true)
                       << L" offset=0x" << std::hex << r.PageOffset
                       << L" pageBytes=0x" << r.PageBytes << std::dec << L"\n";
        }
        else
        {
            PrintColoredText(L"[address.translation]", KNDBG_COLOR_TITLE);
            std::wcout << L" ";
            PrintColoredText(L"failed", KNDBG_COLOR_FAIL);
            std::wcout << L": " << r.TranslationError << L"\n";
        }
    }
}

static void PrintModuleIntegrityHelp()
{
    std::wcout << L"!module command:\n";
    std::wcout << L"  !module integrity [module|all] [/summary] [/verbose] [/headers] [/sections]\n";
    std::wcout << L"                    [/wx] [/mismatch] [/limit <n>] [/json <path>]\n";
    std::wcout << L"\n";
    std::wcout << L"description:\n";
    std::wcout << L"  Verifies loaded kernel module PE headers and executable sections from live\n";
    std::wcout << L"  memory. The scanner validates PE headers, section ranges, SizeOfImage drift,\n";
    std::wcout << L"  static W+X flags, and effective page permissions from page-table walks.\n";
    std::wcout << L"\n";
    std::wcout << L"options:\n";
    std::wcout << L"  [module|all]  image/path substring filter. Defaults to all.\n";
    std::wcout << L"  /summary      print only aggregate findings and warnings.\n";
    std::wcout << L"  /verbose      print all executable/.text sections, not only suspicious ones.\n";
    std::wcout << L"  /headers      print detailed PE header evidence.\n";
    std::wcout << L"  /sections     print all section-table records.\n";
    std::wcout << L"  /wx           report only modules with W+X section/page evidence.\n";
    std::wcout << L"  /mismatch     report only modules with header, size, or section anomalies.\n";
    std::wcout << L"  /limit <n>    cap reported records while still scanning matching modules.\n";
    std::wcout << L"  /json <path>  write structured kn-live-dbg.module-integrity.v1 JSON.\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  !module integrity\n";
    std::wcout << L"  !module integrity ntoskrnl\n";
    std::wcout << L"  !module integrity ntoskrnl /verbose\n";
    std::wcout << L"  !module integrity all /wx\n";
    std::wcout << L"  !module integrity WdFilter /headers /sections\n";
    std::wcout << L"  !module integrity all /json .\\module-integrity.json\n";
}

static void PrintDriverIntegrityHelp()
{
    std::wcout << L"!driver command:\n";
    std::wcout << L"  !driver integrity [driver|all] [/limit <n>] [/json <path>]\n";
    std::wcout << L"\n";
    std::wcout << L"description:\n";
    std::wcout << L"  Walks the Object Manager \\Driver directory, reads _DRIVER_OBJECT entries,\n";
    std::wcout << L"  annotates MajorFunction dispatch pointers, and flags handlers outside loaded\n";
    std::wcout << L"  modules or routed into another non-kernel module. ntoskrnl stubs are treated\n";
    std::wcout << L"  as normal because unused dispatch slots commonly point to nt!IopInvalidDeviceRequest.\n";
    std::wcout << L"\n";
    std::wcout << L"options:\n";
    std::wcout << L"  [driver|all]  driver object name/path substring filter. Defaults to all.\n";
    std::wcout << L"  /limit <n>    stop after <n> matching drivers.\n";
    std::wcout << L"  /json <path>  write structured kn-live-dbg.driver-integrity.v1 JSON.\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  !driver integrity WdFilter\n";
    std::wcout << L"  !driver integrity all /limit 25\n";
    std::wcout << L"  !driver integrity all /json .\\driver-integrity.json\n";
}

static bool ParseIntegrityLimitOption(
    const std::wstring& value,
    uint32_t numberBase,
    uint32_t* limit,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (limit == nullptr)
        {
            break;
        }

        uint64_t parsed = 0;
        if (!ParseUnsigned(value, numberBase, &parsed) || parsed > 0xffffffffull)
        {
            if (error != nullptr)
            {
                *error = L"invalid limit: " + value;
            }
            break;
        }

        *limit = static_cast<uint32_t>(parsed);
        ok = true;
    } while (false);

    return ok;
}

static std::wstring GetDefaultByovdFixturePath()
{
    return GetExecutableDirectory() + L"\\" + KNDBG_BYOVD_FIXTURE_IMAGE_NAME;
}

static void PrintByovdHelp()
{
    std::wcout << L"byovd command:\n";
    std::wcout << L"  byovd [scan] [/no-update] [/force-update] [/exact] [/yara]\n";
    std::wcout << L"               [/yara-path <exe>] [/yara-timeout <seconds>]\n";
    std::wcout << L"               [/verbose] [/summary]\n";
    std::wcout << L"               [/limit <n>] [/json <path>]\n";
    std::wcout << L"  byovd update [/force]\n";
    std::wcout << L"  byovd status\n";
    std::wcout << L"  byovd fixture [status|load [sys-path]|unload|path]\n";
    std::wcout << L"\n";
    std::wcout << L"description:\n";
    std::wcout << L"  Scans currently loaded kernel modules against a local BYOVD intelligence\n";
    std::wcout << L"  catalog built from the Microsoft vulnerable driver blocklist and LOLDrivers\n";
    std::wcout << L"  hash/YARA feeds. The scan updates the local catalog automatically when it is\n";
    std::wcout << L"  missing or older than 24 hours, then hashes each module image on disk.\n";
    std::wcout << L"\n";
    std::wcout << L"match confidence:\n";
    std::wcout << L"  HIGH    exact MD5/SHA1/SHA256 catalog match.\n";
    std::wcout << L"  MEDIUM  Microsoft file-name and file-version blocklist hint. Microsoft OS\n";
    std::wcout << L"          vendor metadata is used to suppress third-party name collisions,\n";
    std::wcout << L"          but full WDAC signer checks are still triage-only.\n";
    std::wcout << L"\n";
    std::wcout << L"options:\n";
    std::wcout << L"  /no-update     skip stale-catalog auto update for this scan.\n";
    std::wcout << L"  /force-update  update before scanning even when the catalog is fresh.\n";
    std::wcout << L"  /exact         suppress name/version hints; /yara still adds YARA hits.\n";
    std::wcout << L"  /yara          run LOLDrivers YARA rules through external yara64.exe/yara.exe.\n";
    std::wcout << L"                 YARA binaries are operator-supplied and not bundled.\n";
    std::wcout << L"  /yara-path     use a specific YARA executable path.\n";
    std::wcout << L"  /yara-timeout  per-driver per-rule timeout in seconds, default 30.\n";
    std::wcout << L"  /verbose       also print clean modules and hash/read failures.\n";
    std::wcout << L"  /summary       print only aggregate counts and warnings.\n";
    std::wcout << L"  /limit <n>     cap printed records while still scanning all modules.\n";
    std::wcout << L"  /json <path>   write structured kn-live-dbg.byovd-scan.v1 JSON.\n";
    std::wcout << L"\n";
    std::wcout << L"fixture:\n";
    std::wcout << L"  Loads a benign no-op driver named " << KNDBG_BYOVD_FIXTURE_IMAGE_NAME << L".\n";
    std::wcout << L"  It is expected to trigger a Microsoft file-name/version MEDIUM hit only.\n";
    std::wcout << L"  If Windows blocks the load, check HVCI, Secure Boot, test signing, and the\n";
    std::wcout << L"  vulnerable-driver blocklist state before debugging the scanner.\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  byovd\n";
    std::wcout << L"  byovd scan /exact\n";
    std::wcout << L"  byovd scan /yara\n";
    std::wcout << L"  byovd scan /force-update /json .\\byovd-scan.json\n";
    std::wcout << L"  byovd update\n";
    std::wcout << L"  byovd status\n";
    std::wcout << L"  byovd fixture load\n";
    std::wcout << L"  byovd scan\n";
    std::wcout << L"  byovd fixture unload\n";
}

static void PrintByovdFixtureStatus(const DriverStatus& status)
{
    std::wcout << L"byovd fixture service: " << (status.Installed ? L"installed" : L"not installed");
    if (!status.StateText.empty())
    {
        std::wcout << L" state=" << status.StateText;
    }
    std::wcout << L"\n";
    std::wcout << L"  defaultPath=" << GetDefaultByovdFixturePath() << L"\n";
    std::wcout << L"  expectedHit=MEDIUM source=microsoft_blocklist name="
               << KNDBG_BYOVD_FIXTURE_IMAGE_NAME << L" version=1.0.0.0\n";
}

static void HandleByovdFixtureCommand(
    const std::vector<std::wstring>& args,
    size_t index,
    DebuggerState& state)
{
    std::wstring action = index < args.size() ? ToLower(args[index]) : L"status";
    std::wstring error;
    DriverService fixtureService(KNDBG_BYOVD_FIXTURE_SERVICE_NAME, KNDBG_BYOVD_FIXTURE_DISPLAY_NAME);
    bool argumentError = false;

    do
    {
        if (index < args.size() && HasHelpToken(args, index))
        {
            PrintByovdHelp();
            break;
        }

        if (action == L"status" || action == L"path" || action == L"unload")
        {
            if (args.size() > index + 1)
            {
                std::wcerr << L"byovd fixture " << action
                           << L": unexpected argument \"" << args[index + 1] << L"\"\n";
                argumentError = true;
                break;
            }
        }

        if (action == L"status")
        {
            DriverStatus status = {};
            if (!fixtureService.Query(&status, &error))
            {
                std::wcerr << L"byovd fixture status failed: " << error << L"\n";
                break;
            }

            PrintByovdFixtureStatus(status);
        }
        else if (action == L"path")
        {
            std::wcout << GetDefaultByovdFixturePath() << L"\n";
        }
        else if (action == L"load")
        {
            std::wstring driverPath = (args.size() > index + 1)
                ? JoinArgs(args, index + 1)
                : GetDefaultByovdFixturePath();

            state.ByovdFixtureCleanupRequested = true;
            state.ByovdFixtureUnloaded = false;

            if (!LoadDriverServiceWithUx(fixtureService, L"BYOVD fixture driver load", driverPath, &error))
            {
                std::wcerr << L"byovd fixture load failed: " << error << L"\n";
                break;
            }

            std::wcout << L"byovd fixture loaded: " << driverPath << L"\n";
            std::wcout << L"run: byovd scan\n";
        }
        else if (action == L"unload")
        {
            DriverUnloadResult unloadResult = {};
            if (!UnloadDriverServiceWithUx(fixtureService, L"BYOVD fixture driver unload", &unloadResult, &error))
            {
                std::wcerr << L"byovd fixture unload failed: " << error << L"\n";
                break;
            }

            state.ByovdFixtureUnloaded = true;
        }
        else
        {
            std::wcerr << L"usage: byovd fixture [status|load [sys-path]|unload|path]\n";
        }
    } while (false);

    if (argumentError)
    {
        std::wcerr << L"usage: byovd fixture [status|load [sys-path]|unload|path]\n";
    }
}

static void PrintByovdStatus(const ByovdCatalogStatus& status)
{
    PrintColoredText(L"[byovd.status]", KNDBG_COLOR_TITLE);
    std::wcout << L" catalog=" << (status.HasCatalog ? L"yes" : L"no")
               << L" stale=" << (status.Stale ? L"yes" : L"no")
               << L" ageSeconds=" << status.AgeSeconds
               << L" entries=" << status.EntryCount << L"\n";

    std::wcout << L"  data=" << status.DataDirectory << L"\n";
    std::wcout << L"  catalog=" << status.CatalogPath << L"\n";
    std::wcout << L"  manifest=" << status.ManifestPath << L"\n";
    std::wcout << L"  yara=" << status.YaraDirectory
               << L" rules=" << status.YaraRuleFileCount
               << L" present=" << (status.HasYaraRules ? L"yes" : L"no") << L"\n";

    if (!status.SourceCounts.empty())
    {
        std::wcout << L"  sources:";
        for (const auto& item : status.SourceCounts)
        {
            std::wcout << L" " << item.first << L"=" << item.second;
        }
        std::wcout << L"\n";
    }

    if (!status.MatchTypeCounts.empty())
    {
        std::wcout << L"  matchTypes:";
        for (const auto& item : status.MatchTypeCounts)
        {
            std::wcout << L" " << item.first << L"=" << item.second;
        }
        std::wcout << L"\n";
    }
}

static void PrintByovdMatch(const ByovdMatch& match)
{
    std::wcout << L"  ";
    PrintColoredText(
        L"[byovd.match]",
        match.Confidence == L"HIGH" ? KNDBG_COLOR_FAIL : KNDBG_COLOR_WARN);
    std::wcout << L" confidence=";
    PrintColoredText(
        match.Confidence,
        match.Confidence == L"HIGH" ? KNDBG_COLOR_FAIL : KNDBG_COLOR_WARN);
    std::wcout << L" source=" << match.Entry.Source
               << L" category=" << match.Entry.Category
               << L" type=" << match.Entry.MatchType;

    if (!match.Entry.Value.empty())
    {
        std::wcout << L" value=" << match.Entry.Value;
    }
    if (!match.Entry.Name.empty())
    {
        std::wcout << L" name=" << match.Entry.Name;
    }
    if (!match.Entry.MinimumVersion.empty() || !match.Entry.MaximumVersion.empty())
    {
        std::wcout << L" versionRange=" << match.Entry.MinimumVersion
                   << L".." << match.Entry.MaximumVersion;
    }
    if (!match.Reason.empty())
    {
        std::wcout << L" reason=\"" << match.Reason << L"\"";
    }
    if (!match.Entry.Description.empty())
    {
        std::wcout << L" desc=\"" << match.Entry.Description << L"\"";
    }
    std::wcout << L"\n";
}

static void PrintByovdRecord(const ByovdModuleRecord& record)
{
    bool suspicious = !record.Matches.empty();
    bool high = false;
    for (const ByovdMatch& match : record.Matches)
    {
        if (match.Confidence == L"HIGH")
        {
            high = true;
            break;
        }
    }

    PrintColoredText(
        suspicious ? L"[byovd.hit]" : L"[byovd.clean]",
        suspicious ? (high ? KNDBG_COLOR_FAIL : KNDBG_COLOR_WARN) : KNDBG_COLOR_DIM);
    std::wcout << L" image=";
    PrintColoredText(record.ImageName.empty() ? L"<unknown>" : record.ImageName,
                     suspicious ? KNDBG_COLOR_WARN : KNDBG_COLOR_OK);
    std::wcout << L" base=" << HexTextWidth(record.Base, 16, true)
               << L" size=0x" << std::hex << record.Size << std::dec;

    if (record.VersionRead)
    {
        std::wcout << L" version=" << record.FileVersion;
        if (!record.FileCompanyName.empty())
        {
            std::wcout << L" company=\"" << record.FileCompanyName << L"\"";
        }
    }
    if (record.FileHashed)
    {
        std::wcout << L" sha256=" << record.Sha256;
    }
    if (!record.Error.empty())
    {
        std::wcout << L" error=\"" << record.Error << L"\"";
    }
    if (record.YaraScanned)
    {
        std::wcout << L" yara=yes";
    }
    if (record.YaraTimedOut)
    {
        std::wcout << L" yaraTimeout=yes";
    }
    if (!record.YaraError.empty())
    {
        std::wcout << L" yaraError=\"" << record.YaraError << L"\"";
    }
    std::wcout << L"\n";

    if (!record.DiskPath.empty())
    {
        std::wcout << L"  path=" << record.DiskPath << L"\n";
    }

    for (const ByovdMatch& match : record.Matches)
    {
        PrintByovdMatch(match);
    }
}

static void HandleByovdCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    SymbolEngine& symbols)
{
    do
    {
        if (HasHelpToken(args, 1))
        {
            PrintByovdHelp();
            break;
        }

        std::wstring action = L"scan";
        size_t index = 1;
        if (args.size() >= 2)
        {
            std::wstring maybeAction = ToLower(args[1]);
            if (maybeAction == L"scan" || maybeAction == L"update" || maybeAction == L"status" || maybeAction == L"fixture")
            {
                action = maybeAction;
                index = 2;
            }
        }

        ByovdScanner scanner(symbols, GetExecutableDirectory());
        std::wstring error;

        if (action == L"status")
        {
            ByovdCatalogStatus status = {};
            if (!scanner.QueryCatalogStatus(&status, &error))
            {
                std::wcerr << L"byovd status failed: " << error << L"\n";
                break;
            }

            PrintByovdStatus(status);
            break;
        }

        if (action == L"fixture")
        {
            HandleByovdFixtureCommand(args, index, state);
            break;
        }

        if (action == L"update")
        {
            bool force = true;
            bool helpRequested = false;
            bool parseError = false;
            while (index < args.size())
            {
                std::wstring opt = ToLower(args[index]);
                if (opt == L"/force")
                {
                    force = true;
                    ++index;
                    continue;
                }
                if (opt == L"help")
                {
                    PrintByovdHelp();
                    helpRequested = true;
                    break;
                }

                std::wcerr << L"byovd update: unrecognised option \"" << args[index] << L"\"\n";
                parseError = true;
                break;
            }

            if (helpRequested || parseError)
            {
                break;
            }

            std::vector<std::wstring> messages;
            if (!scanner.UpdateCatalog(force, &messages, &error))
            {
                std::wcerr << L"byovd update failed: " << error << L"\n";
                break;
            }

            for (const std::wstring& message : messages)
            {
                PrintColoredText(L"[byovd.update]", KNDBG_COLOR_TITLE);
                std::wcout << L" " << message << L"\n";
            }
            PrintColoredText(L"[byovd.update]", KNDBG_COLOR_OK);
            std::wcout << L" complete\n";
            break;
        }

        ByovdScanOptions options = {};
        std::wstring jsonPath;
        bool parseError = false;

        while (index < args.size())
        {
            std::wstring opt = ToLower(args[index]);
            if (opt == L"/no-update")
            {
                options.AutoUpdate = false;
                ++index;
                continue;
            }
            if (opt == L"/force-update")
            {
                options.ForceUpdate = true;
                ++index;
                continue;
            }
            if (opt == L"/exact")
            {
                options.ExactOnly = true;
                ++index;
                continue;
            }
            if (opt == L"/yara")
            {
                options.EnableYara = true;
                ++index;
                continue;
            }
            if (opt == L"/yara-path")
            {
                if (index + 1 >= args.size())
                {
                    std::wcerr << L"byovd scan: /yara-path requires a path\n";
                    parseError = true;
                    break;
                }
                options.EnableYara = true;
                options.YaraExecutable = args[index + 1];
                index += 2;
                continue;
            }
            if (opt == L"/yara-timeout")
            {
                if (index + 1 >= args.size())
                {
                    std::wcerr << L"byovd scan: /yara-timeout requires seconds\n";
                    parseError = true;
                    break;
                }

                uint64_t timeoutSeconds = 0;
                if (!ParseUnsigned(args[index + 1], 10, &timeoutSeconds) ||
                    timeoutSeconds == 0 ||
                    timeoutSeconds > 600)
                {
                    std::wcerr << L"byovd scan: invalid /yara-timeout, expected 1..600 seconds\n";
                    parseError = true;
                    break;
                }

                options.EnableYara = true;
                options.YaraTimeoutSeconds = static_cast<uint32_t>(timeoutSeconds);
                index += 2;
                continue;
            }
            if (opt == L"/verbose")
            {
                options.Verbose = true;
                ++index;
                continue;
            }
            if (opt == L"/summary")
            {
                options.SummaryOnly = true;
                ++index;
                continue;
            }
            if (opt == L"/limit")
            {
                if (index + 1 >= args.size())
                {
                    std::wcerr << L"byovd scan: /limit requires a value\n";
                    parseError = true;
                    break;
                }
                if (!ParseIntegrityLimitOption(args[index + 1], state.NumberBase, &options.Limit, &error))
                {
                    std::wcerr << L"byovd scan: " << error << L"\n";
                    parseError = true;
                    break;
                }
                index += 2;
                continue;
            }
            if (opt == L"/json")
            {
                if (index + 1 >= args.size())
                {
                    std::wcerr << L"byovd scan: /json requires a path\n";
                    parseError = true;
                    break;
                }
                jsonPath = args[index + 1];
                index += 2;
                continue;
            }
            if (IsSwitchLikeToken(args[index]))
            {
                std::wcerr << L"byovd scan: unrecognised option \"" << args[index] << L"\"\n";
                parseError = true;
                break;
            }

            std::wcerr << L"byovd scan: unexpected argument \"" << args[index] << L"\"\n";
            parseError = true;
            break;
        }

        if (parseError)
        {
            break;
        }

        ByovdScanResult result = {};
        if (!scanner.Scan(options, &result, &error))
        {
            std::wcerr << L"byovd scan failed: " << error << L"\n";
            for (const std::wstring& warning : result.Warnings)
            {
                std::wcerr << L"byovd warning: " << warning << L"\n";
            }
            break;
        }

        for (const std::wstring& message : result.Messages)
        {
            PrintColoredText(L"[byovd.info]", KNDBG_COLOR_DIM);
            std::wcout << L" " << message << L"\n";
        }
        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"byovd warning: " << warning << L"\n";
        }

        if (!jsonPath.empty())
        {
            if (WriteUtf8TextFile(jsonPath, BuildByovdScanJson(result), &error))
            {
                std::wcout << L"byovd json=" << jsonPath << L"\n";
            }
            else
            {
                std::wcerr << L"byovd json failed: " << error << L"\n";
            }
        }

        if (!options.SummaryOnly)
        {
            for (const ByovdModuleRecord& record : result.Records)
            {
                PrintByovdRecord(record);
            }
        }

        PrintColoredText(L"[byovd.summary]", KNDBG_COLOR_TITLE);
        std::wcout << L" scanned=" << result.ModulesScanned
                   << L" hashed=" << result.FilesHashed
                   << L" readFail=" << result.FileReadFailures
                   << L" matched=" << result.MatchedModules
                   << L" exact=" << result.ExactMatches
                   << L" hints=" << result.HintMatches
                   << L" yaraScans=" << result.YaraScans
                   << L" yaraMatches=" << result.YaraMatches
                   << L" yaraFailures=" << result.YaraFailures
                   << L" yaraTimeouts=" << result.YaraTimeouts
                   << L" updateAttempted=" << (result.CatalogUpdateAttempted ? L"yes" : L"no")
                   << L" updated=" << (result.CatalogUpdated ? L"yes" : L"no")
                   << L" truncated=" << (result.Truncated ? L"yes" : L"no") << L"\n";
    } while (false);
}

static void PrintReasonCodes(const std::vector<std::wstring>& codes)
{
    if (codes.empty())
    {
        return;
    }

    std::wcout << L" reasons=";
    for (size_t index = 0; index < codes.size(); ++index)
    {
        if (index != 0)
        {
            std::wcout << L",";
        }
        std::wcout << codes[index];
    }
}

static bool ShouldPrintModuleIntegritySection(
    const ModuleIntegritySectionRecord& section,
    const ModuleIntegrityOptions& options)
{
    bool print = false;

    do
    {
        if (options.IncludeSections)
        {
            print = true;
            break;
        }
        if (options.WxOnly)
        {
            print = section.WxEvidence;
            break;
        }
        if (options.MismatchOnly)
        {
            print = section.MismatchEvidence || section.Suspicious;
            break;
        }
        if (options.Verbose)
        {
            print = section.Executable || ToLower(section.Name) == L".text" || section.Suspicious;
            break;
        }

        print = section.Suspicious;
    } while (false);

    return print;
}

static void PrintPageProbeState(
    const wchar_t* label,
    bool queried,
    bool failed,
    bool readable,
    bool writable,
    bool executable,
    bool largePage,
    uint32_t pagingLevels)
{
    std::wcout << L" " << label << L"=";
    if (queried)
    {
        std::wcout << (readable ? L"R" : L"-")
                   << (writable ? L"W" : L"-")
                   << (executable ? L"X" : L"-");
        if (pagingLevels != 0 || largePage)
        {
            std::wcout << L"(levels=" << pagingLevels;
            if (largePage)
            {
                std::wcout << L",large";
            }
            std::wcout << L")";
        }
    }
    else if (failed)
    {
        PrintColoredText(L"query-failed", KNDBG_COLOR_WARN);
    }
    else
    {
        PrintColoredText(L"not-queried", KNDBG_COLOR_DIM);
    }
}

static void PrintModuleIntegrityRecord(
    const ModuleIntegrityRecord& record,
    const ModuleIntegrityOptions& options)
{
    PrintColoredText(
        record.Suspicious ? L"[module.integrity.suspicious]" : L"[module.integrity]",
        record.Suspicious ? KNDBG_COLOR_FAIL : KNDBG_COLOR_TITLE);
    std::wcout << L" image=";
    PrintColoredText(record.ImageName.empty() ? L"<unknown>" : record.ImageName, KNDBG_COLOR_OK);
    std::wcout << L" base=" << HexTextWidth(record.Base, 16, true)
               << L" size=0x" << std::hex << record.Size
               << L" peSize=0x" << record.SizeOfImage << std::dec
               << L" sections=" << record.NumberOfSections;
    if (record.SizeMismatch)
    {
        std::wcout << L" ";
        PrintColoredText(L"[SIZE-MISMATCH]", KNDBG_COLOR_WARN);
    }
    if (record.WxEvidence)
    {
        std::wcout << L" ";
        PrintColoredText(L"[WX]", KNDBG_COLOR_FAIL);
    }
    if (record.MismatchEvidence)
    {
        std::wcout << L" ";
        PrintColoredText(L"[MISMATCH]", KNDBG_COLOR_WARN);
    }
    PrintReasonCodes(record.ReasonCodes);
    if (!record.Notes.empty())
    {
        std::wcout << L" notes=" << record.Notes;
    }
    std::wcout << L"\n";

    if (options.IncludeHeaders)
    {
        std::wcout << L"  ";
        PrintColoredText(L"[module.header]", KNDBG_COLOR_DIM);
        std::wcout << L" mz=" << (record.MzOk ? L"ok" : L"bad")
                   << L" pe=" << (record.PeOk ? L"ok" : L"bad")
                   << L" opt=" << (record.OptionalHeaderOk ? L"ok" : L"bad")
                   << L" sectable=" << (record.SectionTableOk ? L"ok" : L"bad")
                   << L" machine=" << HexTextWidth(record.Machine, 4, true)
                   << L" magic=" << HexTextWidth(record.OptionalHeaderMagic, 4, true)
                   << L" imageBase=" << HexTextWidth(record.PreferredImageBase, 16, true)
                   << L" sizeHeaders=0x" << std::hex << record.SizeOfHeaders
                   << L" sectionAlign=0x" << record.SectionAlignment
                   << L" fileAlign=0x" << record.FileAlignment
                   << std::dec << L"\n";
    }

    for (const ModuleIntegritySectionRecord& section : record.Sections)
    {
        if (!ShouldPrintModuleIntegritySection(section, options))
        {
            continue;
        }

        std::wcout << L"  ";
        PrintColoredText(section.Suspicious ? L"[module.section.suspicious]" : L"[module.section]",
                         section.Suspicious ? KNDBG_COLOR_WARN : KNDBG_COLOR_DIM);
        std::wcout << L" name=";
        PrintColoredText(section.Name.empty() ? L"<unnamed>" : section.Name, KNDBG_COLOR_ACCENT);
        std::wcout << L" rva=" << HexTextWidth(section.VirtualAddress, 8, true)
                   << L" vsize=0x" << std::hex << section.VirtualSize
                   << L" raw=0x" << section.RawSize << std::dec
                   << L" chars=" << (section.Executable ? L"X" : L"-")
                   << (section.Writable ? L"W" : L"-")
                   << (section.Readable ? L"R" : L"-");
        PrintPageProbeState(
            L"first",
            section.FirstPageQueried,
            section.FirstPageQueryFailed,
            section.FirstPageReadable,
            section.FirstPageWritable,
            section.FirstPageExecutable,
            section.FirstPageLargePage,
            section.FirstPagePagingLevels);
        PrintPageProbeState(
            L"last",
            section.LastPageQueried,
            section.LastPageQueryFailed,
            section.LastPageReadable,
            section.LastPageWritable,
            section.LastPageExecutable,
            section.LastPageLargePage,
            section.LastPagePagingLevels);
        if (section.PageAttributesQueried)
        {
            std::wcout << L" effective="
                       << (section.EffectiveReadable ? L"R" : L"-")
                       << (section.EffectiveWritable ? L"W" : L"-")
                       << (section.EffectiveExecutable ? L"X" : L"-");
        }
        if (!section.PageAttributeError.empty())
        {
            std::wcout << L" pageError=" << section.PageAttributeError;
        }
        PrintReasonCodes(section.ReasonCodes);
        if (!section.Notes.empty())
        {
            std::wcout << L" notes=" << section.Notes;
        }
        std::wcout << L"\n";
    }
}

static void PrintDriverIntegrityRecord(const DriverIntegrityRecord& record, bool verboseDispatch)
{
    PrintColoredText(
        record.Suspicious ? L"[driver.integrity.suspicious]" : L"[driver.integrity]",
        record.Suspicious ? KNDBG_COLOR_FAIL : KNDBG_COLOR_TITLE);
    std::wcout << L" name=";
    PrintColoredText(record.Name.empty() ? L"<unnamed>" : record.Name, KNDBG_COLOR_OK);
    std::wcout << L" object=" << HexTextWidth(record.DriverObject, 16, true)
               << L" start=" << HexTextWidth(record.DriverStart, 16, true)
               << L" size=0x" << std::hex << record.DriverSize << std::dec;
    if (!record.OwningModule.empty())
    {
        std::wcout << L" owner=";
        PrintColoredText(record.OwningModule, KNDBG_COLOR_TITLE);
    }
    if (!record.Notes.empty())
    {
        std::wcout << L" notes=" << record.Notes;
    }
    std::wcout << L"\n";

    if (record.DriverUnload != 0 || record.FastIoDispatch != 0)
    {
        std::wcout << L"  unload=" << HexTextWidth(record.DriverUnload, 16, true)
                   << L" fastIo=" << HexTextWidth(record.FastIoDispatch, 16, true)
                   << L" device=" << HexTextWidth(record.DeviceObject, 16, true) << L"\n";
    }

    for (const DriverDispatchRecord& dispatch : record.Dispatch)
    {
        if (!verboseDispatch && !dispatch.Suspicious)
        {
            continue;
        }

        std::wcout << L"  ";
        PrintColoredText(dispatch.Suspicious ? L"[dispatch.suspicious]" : L"[dispatch]",
                         dispatch.Suspicious ? KNDBG_COLOR_WARN : KNDBG_COLOR_DIM);
        std::wcout << L" irp=" << dispatch.Index << L":" << dispatch.Name
                   << L" function=" << HexTextWidth(dispatch.Function, 16, true);
        if (!dispatch.ModuleName.empty())
        {
            std::wcout << L" module=";
            PrintColoredText(dispatch.ModuleName, KNDBG_COLOR_OK);
        }
        else if (dispatch.Function != 0)
        {
            std::wcout << L" module=";
            PrintColoredText(L"<outside-loaded-modules>", KNDBG_COLOR_FAIL);
        }
        if (!dispatch.SymbolName.empty())
        {
            std::wcout << L" symbol=";
            PrintColoredText(dispatch.SymbolName, KNDBG_COLOR_TITLE);
        }
        if (!dispatch.Notes.empty())
        {
            std::wcout << L" notes=" << dispatch.Notes;
        }
        std::wcout << L"\n";
    }
}

static void HandleModuleIntegrityCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    do
    {
        if (HasHelpToken(args, 1))
        {
            PrintModuleIntegrityHelp();
            break;
        }

        if (args.size() < 2 || ToLower(args[1]) != L"integrity")
        {
            std::wcerr << L"usage: !module integrity [module|all] [/summary] [/verbose] [/headers] [/sections] [/wx] [/mismatch] [/limit <n>] [/json <path>]\n";
            PrintModuleIntegrityHelp();
            break;
        }

        if (!device.IsOpen())
        {
            std::wcerr << L"!module integrity requires the KnLiveDbg.sys driver device to be open\n";
            break;
        }

        ModuleIntegrityOptions options = {};
        std::wstring jsonPath;
        std::wstring error;
        bool parseError = false;

        size_t index = 2;
        while (index < args.size())
        {
            std::wstring opt = ToLower(args[index]);
            if (opt == L"/summary")
            {
                options.SummaryOnly = true;
                ++index;
                continue;
            }
            if (opt == L"/verbose")
            {
                options.Verbose = true;
                ++index;
                continue;
            }
            if (opt == L"/headers")
            {
                options.IncludeHeaders = true;
                ++index;
                continue;
            }
            if (opt == L"/sections")
            {
                options.IncludeSections = true;
                ++index;
                continue;
            }
            if (opt == L"/wx")
            {
                options.WxOnly = true;
                ++index;
                continue;
            }
            if (opt == L"/mismatch")
            {
                options.MismatchOnly = true;
                ++index;
                continue;
            }
            if (opt == L"/limit")
            {
                if (index + 1 >= args.size())
                {
                    std::wcerr << L"!module integrity: /limit requires a value\n";
                    parseError = true;
                    break;
                }
                if (!ParseIntegrityLimitOption(args[index + 1], state.NumberBase, &options.Limit, &error))
                {
                    std::wcerr << L"!module integrity: " << error << L"\n";
                    parseError = true;
                    break;
                }
                index += 2;
                continue;
            }
            if (opt == L"/json")
            {
                if (index + 1 >= args.size())
                {
                    std::wcerr << L"!module integrity: /json requires a path\n";
                    parseError = true;
                    break;
                }
                jsonPath = args[index + 1];
                index += 2;
                continue;
            }
            if (IsSwitchLikeToken(args[index]))
            {
                std::wcerr << L"!module integrity: unrecognised option \"" << args[index] << L"\"\n";
                parseError = true;
                break;
            }
            if (!options.ModuleFilter.empty())
            {
                std::wcerr << L"!module integrity: unexpected extra target \"" << args[index] << L"\"\n";
                parseError = true;
                break;
            }
            options.ModuleFilter = args[index];
            ++index;
        }

        if (parseError)
        {
            break;
        }

        IntegrityScanner scanner(device, symbols);
        ModuleIntegrityResult result = {};
        if (!scanner.ScanModules(options, &result, &error))
        {
            std::wcerr << L"!module integrity failed: " << error << L"\n";
            for (const std::wstring& warning : result.Warnings)
            {
                std::wcerr << L"!module integrity warning: " << warning << L"\n";
            }
            break;
        }

        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"!module integrity warning: " << warning << L"\n";
        }

        if (!jsonPath.empty())
        {
            if (WriteUtf8TextFile(jsonPath, BuildModuleIntegrityJson(result), &error))
            {
                std::wcout << L"!module integrity json=" << jsonPath << L"\n";
            }
            else
            {
                std::wcerr << L"!module integrity json failed: " << error << L"\n";
            }
        }

        if (!options.SummaryOnly)
        {
            for (const ModuleIntegrityRecord& record : result.Records)
            {
                PrintModuleIntegrityRecord(record, options);
            }
        }

        PrintColoredText(L"[module.integrity.summary]", KNDBG_COLOR_TITLE);
        std::wcout << L" scanned=" << std::dec << result.ModulesScanned
                   << L" matching=" << result.MatchingModules
                   << L" reported=" << result.ReportedModules
                   << L" suspicious=" << result.SuspiciousModules
                   << L" wx=" << result.WxModules
                   << L" mismatch=" << result.MismatchModules
                   << L" truncated=" << (result.Truncated ? L"yes" : L"no") << L"\n";
    } while (false);
}

static void HandleDriverIntegrityCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    do
    {
        if (HasHelpToken(args, 1))
        {
            PrintDriverIntegrityHelp();
            break;
        }

        if (args.size() < 2 || ToLower(args[1]) != L"integrity")
        {
            std::wcerr << L"usage: !driver integrity [driver|all] [/limit <n>] [/json <path>]\n";
            PrintDriverIntegrityHelp();
            break;
        }

        if (!device.IsOpen())
        {
            std::wcerr << L"!driver integrity requires the KnLiveDbg.sys driver device to be open\n";
            break;
        }

        DriverIntegrityOptions options = {};
        std::wstring jsonPath;
        std::wstring error;
        bool parseError = false;

        size_t index = 2;
        while (index < args.size())
        {
            std::wstring opt = ToLower(args[index]);
            if (opt == L"/limit")
            {
                if (index + 1 >= args.size())
                {
                    std::wcerr << L"!driver integrity: /limit requires a value\n";
                    parseError = true;
                    break;
                }
                if (!ParseIntegrityLimitOption(args[index + 1], state.NumberBase, &options.Limit, &error))
                {
                    std::wcerr << L"!driver integrity: " << error << L"\n";
                    parseError = true;
                    break;
                }
                index += 2;
                continue;
            }
            if (opt == L"/json")
            {
                if (index + 1 >= args.size())
                {
                    std::wcerr << L"!driver integrity: /json requires a path\n";
                    parseError = true;
                    break;
                }
                jsonPath = args[index + 1];
                index += 2;
                continue;
            }
            if (IsSwitchLikeToken(args[index]))
            {
                std::wcerr << L"!driver integrity: unrecognised option \"" << args[index] << L"\"\n";
                parseError = true;
                break;
            }
            if (!options.DriverFilter.empty())
            {
                std::wcerr << L"!driver integrity: unexpected extra target \"" << args[index] << L"\"\n";
                parseError = true;
                break;
            }
            options.DriverFilter = args[index];
            ++index;
        }

        if (parseError)
        {
            break;
        }

        IntegrityScanner scanner(device, symbols);
        DriverIntegrityResult result = {};
        if (!scanner.ScanDrivers(options, &result, &error))
        {
            std::wcerr << L"!driver integrity failed: " << error << L"\n";
            for (const std::wstring& warning : result.Warnings)
            {
                std::wcerr << L"!driver integrity warning: " << warning << L"\n";
            }
            break;
        }

        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"!driver integrity warning: " << warning << L"\n";
        }

        if (!jsonPath.empty())
        {
            if (WriteUtf8TextFile(jsonPath, BuildDriverIntegrityJson(result), &error))
            {
                std::wcout << L"!driver integrity json=" << jsonPath << L"\n";
            }
            else
            {
                std::wcerr << L"!driver integrity json failed: " << error << L"\n";
            }
        }

        std::wstring filter = ToLower(TrimWhitespace(options.DriverFilter));
        bool verboseDispatch = !filter.empty() && filter != L"all";
        for (const DriverIntegrityRecord& record : result.Records)
        {
            PrintDriverIntegrityRecord(record, verboseDispatch);
        }

        PrintColoredText(L"[driver.integrity.summary]", KNDBG_COLOR_TITLE);
        std::wcout << L" scanned=" << std::dec << result.DriversScanned
                   << L" matching=" << result.MatchingDrivers
                   << L" suspicious=" << result.SuspiciousDrivers
                   << L" truncated=" << (result.Truncated ? L"yes" : L"no") << L"\n";
    } while (false);
}

static void PrintSetPplAntimalwareHelp()
{
    std::wcout << L"set-ppl-antimalware command:\n";
    std::wcout << L"  set-ppl-antimalware [on|off|status]\n";
    std::wcout << L"\n";
    std::wcout << L"description:\n";
    std::wcout << L"  Flips the calling process's _EPROCESS.Protection byte to make KnLiveDbg.exe\n";
    std::wcout << L"  run as a PPL Antimalware process (PS_PROTECTION: Type=1 PPL, Signer=3\n";
    std::wcout << L"  Antimalware -> 0x31). This is a prerequisite for subscribing to the\n";
    std::wcout << L"  Microsoft-Windows-Threat-Intelligence ETW provider, which gates its sensitive\n";
    std::wcout << L"  events on the consumer being PPL with the antimalware signer.\n";
    std::wcout << L"\n";
    std::wcout << L"subcommands:\n";
    std::wcout << L"  on       set the protection byte to 0x31 (PPL Antimalware). Default.\n";
    std::wcout << L"  off      clear the protection byte to 0x00 (unprotected).\n";
    std::wcout << L"  status   read and decode the current protection byte without writing.\n";
    std::wcout << L"\n";
    std::wcout << L"requirements:\n";
    std::wcout << L"  - The KnLiveDbg.sys driver device must be open and write mode enabled\n";
    std::wcout << L"    (run 'write on' first).\n";
    std::wcout << L"  - Kernel symbols must resolve _EPROCESS.Protection so the driver receives\n";
    std::wcout << L"    a build-correct field offset rather than a hardcoded number.\n";
    std::wcout << L"\n";
    std::wcout << L"caveats:\n";
    std::wcout << L"  - Once PPL-protected, KnLiveDbg.exe cannot be attached to by a non-PPL\n";
    std::wcout << L"    debugger; if you want to debug the tool itself, attach BEFORE running\n";
    std::wcout << L"    this command.\n";
    std::wcout << L"  - PatchGuard does not currently audit this field at runtime, but a future\n";
    std::wcout << L"    Windows kernel could. Use only in controlled lab environments.\n";
    std::wcout << L"  - PPL state is per-process and clears on exit.\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  set-ppl-antimalware\n";
    std::wcout << L"  set-ppl-antimalware on\n";
    std::wcout << L"  set-ppl-antimalware status\n";
    std::wcout << L"  set-ppl-antimalware off\n";
}

static std::wstring DescribeProtectionByte(uint8_t value)
{
    if (value == 0)
    {
        return L"None (unprotected)";
    }
    uint8_t type = value & 0x07;
    uint8_t signer = (value >> 4) & 0x0F;
    const wchar_t* typeName = L"?";
    switch (type)
    {
        case 0: typeName = L"None"; break;
        case 1: typeName = L"PPL"; break;
        case 2: typeName = L"PP"; break;
    }
    const wchar_t* signerName = L"?";
    switch (signer)
    {
        case 0: signerName = L"None"; break;
        case 1: signerName = L"Authenticode"; break;
        case 2: signerName = L"CodeGen"; break;
        case 3: signerName = L"Antimalware"; break;
        case 4: signerName = L"Lsa"; break;
        case 5: signerName = L"Windows"; break;
        case 6: signerName = L"WinTcb"; break;
        case 7: signerName = L"WinSystem"; break;
        case 8: signerName = L"App"; break;
    }
    std::wstringstream ss;
    ss << typeName << L"-" << signerName;
    return ss.str();
}

static void HandleSetPplAntimalwareCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    (void)state;

    do
    {
        if (HasHelpToken(args, 1))
        {
            PrintSetPplAntimalwareHelp();
            break;
        }

        std::wstring action = L"on";
        if (args.size() >= 2)
        {
            action = ToLower(args[1]);
        }
        if (args.size() > 2)
        {
            std::wcerr << L"set-ppl-antimalware: unexpected extra argument \"" << args[2] << L"\"\n";
            break;
        }

        if (action != L"on" && action != L"off" && action != L"status")
        {
            std::wcerr << L"set-ppl-antimalware: unknown action \"" << args[1] << L"\"\n";
            PrintSetPplAntimalwareHelp();
            break;
        }

        if (!device.IsOpen())
        {
            std::wcerr << L"set-ppl-antimalware requires the KnLiveDbg.sys driver device to be open\n";
            break;
        }

        // Resolve _EPROCESS.Protection field offset from the kernel PDB so
        // the driver does not have to track per-build layout drift.
        if (symbols.Modules().empty())
        {
            std::wstring loadError;
            if (!symbols.LoadKernelModules(&loadError))
            {
                std::wcerr << L"set-ppl-antimalware: failed to load kernel modules: " << loadError << L"\n";
                break;
            }
        }

        TypeFieldInfo protectionField = {};
        std::wstring fieldError;
        if (!symbols.FindField(L"nt!_EPROCESS", L"Protection", &protectionField, &fieldError))
        {
            std::wcerr << L"set-ppl-antimalware: could not resolve _EPROCESS.Protection: "
                       << fieldError << L"\n";
            break;
        }

        if (protectionField.Offset == 0 || protectionField.Offset > 0x2000)
        {
            std::wcerr << L"set-ppl-antimalware: _EPROCESS.Protection offset 0x"
                       << std::hex << protectionField.Offset << std::dec
                       << L" out of plausible range\n";
            break;
        }

        uint32_t pid = static_cast<uint32_t>(GetCurrentProcessId());

        // For 'status' we read the current byte by writing the same value
        // back -- the driver returns the old byte and the read-back which
        // is what we want to display. Writing the same byte is idempotent.
        uint8_t requestedValue = KNDBG_PROTECTION_PPL_ANTIMALWARE;
        bool isStatusOnly = false;
        if (action == L"off")
        {
            requestedValue = KNDBG_PROTECTION_NONE;
        }
        else if (action == L"status")
        {
            // Read current value first via a no-op rewrite. We need an
            // intermediate read; reuse the IOCTL by writing back what we
            // read. Simpler: do a single round where the new value is the
            // value we hope is already there (use 0x31 by default) -- the
            // response carries the OldProtection regardless. We then
            // immediately overwrite again with OldProtection to be
            // idempotent.
            isStatusOnly = true;
            requestedValue = KNDBG_PROTECTION_PPL_ANTIMALWARE;
        }

        uint8_t oldByte = 0;
        uint8_t readBack = 0;
        uint64_t eprocessAddress = 0;
        std::wstring ioctlError;
        if (!device.SetProcessProtection(
                pid,
                static_cast<uint32_t>(protectionField.Offset),
                requestedValue,
                &oldByte,
                &readBack,
                &eprocessAddress,
                &ioctlError))
        {
            std::wcerr << L"set-ppl-antimalware: IOCTL failed: " << ioctlError << L"\n";
            std::wcerr << L"  (hint: run 'write on' first; the driver requires write mode)\n";
            break;
        }

        // For status, restore the original byte so the read is non-destructive.
        if (isStatusOnly && oldByte != requestedValue)
        {
            std::wstring restoreError;
            if (!device.SetProcessProtection(
                    pid,
                    static_cast<uint32_t>(protectionField.Offset),
                    oldByte,
                    nullptr,
                    nullptr,
                    nullptr,
                    &restoreError))
            {
                std::wcerr << L"set-ppl-antimalware: status read succeeded but restoring the original byte failed: "
                           << restoreError << L"\n";
                std::wcerr << L"  process is currently 0x" << std::hex << static_cast<unsigned>(readBack)
                           << std::dec << L"\n";
            }
            readBack = oldByte;
        }

        PrintColoredText(L"[set-ppl-antimalware]", KNDBG_COLOR_TITLE);
        std::wcout << L" pid=" << std::dec << pid
                   << L" eprocess=" << HexTextWidth(eprocessAddress, 16, true)
                   << L" offset=0x" << std::hex << protectionField.Offset << std::dec
                   << L"\n";

        std::wcout << L"  before=0x" << std::hex << std::setw(2) << std::setfill(L'0')
                   << static_cast<unsigned>(oldByte) << std::dec
                   << L" (" << DescribeProtectionByte(oldByte) << L")\n";

        std::wcout << L"  after =0x" << std::hex << std::setw(2) << std::setfill(L'0')
                   << static_cast<unsigned>(readBack) << std::dec
                   << L" (" << DescribeProtectionByte(readBack) << L")";

        if (!isStatusOnly)
        {
            std::wcout << L" requested=0x" << std::hex << std::setw(2) << std::setfill(L'0')
                       << static_cast<unsigned>(requestedValue) << std::dec;
            if (readBack != requestedValue)
            {
                std::wcout << L" ";
                PrintColoredText(L"[write rejected]", KNDBG_COLOR_FAIL);
            }
            else if (oldByte != readBack)
            {
                std::wcout << L" ";
                PrintColoredText(L"[ok]", KNDBG_COLOR_OK);
            }
            else
            {
                std::wcout << L" ";
                PrintColoredText(L"[no change]", KNDBG_COLOR_DIM);
            }
        }
        std::wcout << L"\n";

        if (!isStatusOnly && readBack == KNDBG_PROTECTION_PPL_ANTIMALWARE)
        {
            std::wcout << L"  KnLiveDbg.exe is now PPL Antimalware; Microsoft-Windows-Threat-Intelligence\n"
                       << L"  ETW subscription is now allowed for this process.\n";
        }
    } while (false);
}

// Singleton subscriber owned by main.cpp. We keep it as a function-local
// static so destructor ordering is well-defined relative to wmain return.
static TiSubscriber& GetTiSubscriberInstance()
{
    static TiSubscriber s_instance;
    return s_instance;
}

static void PrintTiHelp()
{
    std::wcout << L"!ti command (Microsoft-Windows-Threat-Intelligence ETW):\n";
    std::wcout << L"  !ti start [/pid <PID>]... [/name <imageName>]... [/throttle <N>]\n";
    std::wcout << L"            [/log <path>] [/ring <N>]\n";
    std::wcout << L"  !ti stop\n";
    std::wcout << L"  !ti status\n";
    std::wcout << L"  !ti add /pid <PID> | /name <imageName>\n";
    std::wcout << L"  !ti remove /pid <PID> | /name <imageName>\n";
    std::wcout << L"  !ti watch                live tail (Ctrl+C to exit)\n";
    std::wcout << L"  !ti recent [N]           print last N ring events (default 50)\n";
    std::wcout << L"  !ti stats                histogram by task/process\n";
    std::wcout << L"  !ti by pid <PID>         ring filter\n";
    std::wcout << L"  !ti by task <name>       ring filter (substring)\n";
    std::wcout << L"  !ti grep <pattern>       case-insensitive substring grep\n";
    std::wcout << L"  !ti save <path>          export current ring to JSONL\n";
    std::wcout << L"  !ti clear                empty the ring\n";
    std::wcout << L"\n";
    std::wcout << L"prerequisites:\n";
    std::wcout << L"  This provider is PPL Antimalware gated; run 'set-ppl-antimalware'\n";
    std::wcout << L"  first or EnableTraceEx2 returns ERROR_ACCESS_DENIED.\n";
    std::wcout << L"\n";
    std::wcout << L"default output:\n";
    std::wcout << L"  Subscription is silent by default. Ring/log capture every event but the\n";
    std::wcout << L"  TUI prints nothing until '!ti watch' is invoked OR a /pid or /name\n";
    std::wcout << L"  watch target matches an incoming event.\n";
}

static std::wstring FormatTimestampLocal(uint64_t fileTimeTicks)
{
    FILETIME ft = {};
    ft.dwLowDateTime = static_cast<DWORD>(fileTimeTicks & 0xFFFFFFFFull);
    ft.dwHighDateTime = static_cast<DWORD>(fileTimeTicks >> 32);
    FILETIME localFt = {};
    if (!FileTimeToLocalFileTime(&ft, &localFt))
    {
        return L"--:--:--.---";
    }
    SYSTEMTIME st = {};
    if (!FileTimeToSystemTime(&localFt, &st))
    {
        return L"--:--:--.---";
    }
    wchar_t buf[24] = {};
    swprintf_s(buf, L"%02u:%02u:%02u.%03u", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

static std::wstring TiBasenameOnly(const std::wstring& path)
{
    if (path.empty())
    {
        return L"<unknown>";
    }
    size_t slash = path.find_last_of(L"\\/");
    return (slash == std::wstring::npos) ? path : path.substr(slash + 1);
}

static void PrintTiEventLine(const TiEventRecord& r)
{
    std::wcout << L"[" << FormatTimestampLocal(r.Timestamp) << L"] ";

    PrintColoredText(r.TaskName.empty() ? (L"Task" + std::to_wstring(r.TaskId)) : r.TaskName,
                     KNDBG_COLOR_TITLE);
    std::wcout << L" pid=" << r.ProcessId
               << L" tid=" << r.ThreadId
               << L" image=";
    PrintColoredText(TiBasenameOnly(r.ImagePath), KNDBG_COLOR_OK);

    // Cross-process target was extracted by OnEventRecord and stashed on
    // the record, so we just render it -- no payload walk or per-print
    // image resolution required here.
    if (r.TargetProcessId != 0)
    {
        std::wcout << L" ";
        PrintColoredText(L"->", KNDBG_COLOR_WARN);
        std::wcout << L" target=";
        PrintColoredText(r.TargetImageBase.empty() ? L"<?>" : r.TargetImageBase,
                         KNDBG_COLOR_FAIL);
        std::wcout << L"(pid=" << r.TargetProcessId << L")";
    }

    if (!r.Payload.empty())
    {
        std::wcout << L" {";
        size_t count = 0;
        for (const TiPayloadField& f : r.Payload)
        {
            if (count >= 8)
            {
                std::wcout << L", +" << (r.Payload.size() - count) << L" more";
                break;
            }
            if (count > 0)
            {
                std::wcout << L", ";
            }
            std::wcout << f.Name << L"=" << f.Value;
            ++count;
        }
        std::wcout << L"}";
    }
    std::wcout << L"\n";
}

static bool ParseTiStartArgs(
    const std::vector<std::wstring>& args,
    size_t startIndex,
    TiOptions* options,
    std::wstring* error)
{
    size_t i = startIndex;
    while (i < args.size())
    {
        std::wstring opt = ToLower(args[i]);

        if (opt == L"/pid")
        {
            if (i + 1 >= args.size())
            {
                *error = L"/pid requires a value";
                return false;
            }
            uint64_t v = 0;
            // Accept hex (0x prefix) as well as decimal so PIDs copied
            // from WinDbg / debugger output paste-work directly.
            if (!ParseUnsigned(args[i + 1], 0, &v) || v == 0 || v > 0xFFFFFFFFull)
            {
                *error = L"invalid PID: " + args[i + 1];
                return false;
            }
            options->WatchPids.push_back(static_cast<uint32_t>(v));
            i += 2;
            continue;
        }
        if (opt == L"/name")
        {
            if (i + 1 >= args.size())
            {
                *error = L"/name requires a value";
                return false;
            }
            options->WatchNames.push_back(args[i + 1]);
            i += 2;
            continue;
        }
        if (opt == L"/throttle")
        {
            if (i + 1 >= args.size())
            {
                *error = L"/throttle requires a value";
                return false;
            }
            uint64_t v = 0;
            if (!ParseUnsigned(args[i + 1], 0, &v) || v == 0 || v > 100000)
            {
                *error = L"invalid throttle (1..100000): " + args[i + 1];
                return false;
            }
            options->ThrottlePerSecond = static_cast<uint32_t>(v);
            i += 2;
            continue;
        }
        if (opt == L"/ring")
        {
            if (i + 1 >= args.size())
            {
                *error = L"/ring requires a value";
                return false;
            }
            uint64_t v = 0;
            if (!ParseUnsigned(args[i + 1], 0, &v) || v < 1024 || v > (1u << 22))
            {
                *error = L"invalid ring capacity (1024..4194304): " + args[i + 1];
                return false;
            }
            options->RingCapacity = static_cast<uint32_t>(v);
            i += 2;
            continue;
        }
        if (opt == L"/log")
        {
            if (i + 1 >= args.size())
            {
                *error = L"/log requires a path";
                return false;
            }
            options->LogDirectory = args[i + 1];
            i += 2;
            continue;
        }
        *error = L"unrecognised start option: " + args[i];
        return false;
    }
    return true;
}

static bool CheckSelfIsPplAntimalware(
    DeviceClient& device,
    SymbolEngine& symbols,
    uint8_t* outProtection,
    std::wstring* error)
{
    // Best-effort gate: returns true only when the EPROCESS.Protection byte
    // for the current process reads back as 0x31 (PPL Antimalware). When
    // symbols cannot resolve or the IOCTL fails, returns false but does
    // not mutate state; the caller still tries Start() and surfaces the
    // EnableTraceEx2 error.
    if (symbols.Modules().empty())
    {
        std::wstring loadError;
        if (!symbols.LoadKernelModules(&loadError))
        {
            if (error != nullptr)
            {
                *error = L"could not load kernel modules: " + loadError;
            }
            return false;
        }
    }

    // DirectoryTableBase lives in _KPROCESS (the Pcb sub-structure at offset 0
    // inside _EPROCESS). Reuse the canonical resolver instead of duplicating
    // the layout fallback; SymbolEngine::FindField now resolves the nested
    // Pcb.DirectoryTableBase path directly.
    uint32_t dtbOffset = 0;
    uint32_t userDtbOffset = 0;
    std::wstring dtbError;
    if (!ResolveProcessDirectoryTableBaseOffsets(symbols, &dtbOffset, &userDtbOffset, &dtbError))
    {
        if (error != nullptr)
        {
            *error = L"could not resolve _EPROCESS.DirectoryTableBase: " + dtbError;
        }
        return false;
    }

    TypeFieldInfo protField = {};
    std::wstring protError;
    if (!symbols.FindField(L"nt!_EPROCESS", L"Protection", &protField, &protError))
    {
        if (error != nullptr)
        {
            *error = L"could not resolve _EPROCESS.Protection: " + protError;
        }
        return false;
    }

    uint32_t pid = GetCurrentProcessId();
    ProcessAddressContext ctx = {};
    std::wstring resolveError;
    if (!device.ResolveProcess(pid, dtbOffset, 0, &ctx, &resolveError))
    {
        if (error != nullptr)
        {
            *error = L"ResolveProcess failed: " + resolveError;
        }
        return false;
    }

    uint64_t fieldAddr = 0;
    if (!TryAddOffset(ctx.Eprocess, protField.Offset, &fieldAddr))
    {
        if (error != nullptr)
        {
            *error = L"EPROCESS + Protection offset overflow";
        }
        return false;
    }

    std::vector<uint8_t> bytes;
    std::wstring readError;
    if (!device.ReadMemory(fieldAddr, 1, &bytes, &readError) || bytes.empty())
    {
        if (error != nullptr)
        {
            *error = L"ReadMemory(Protection) failed: " + readError;
        }
        return false;
    }

    if (outProtection != nullptr)
    {
        *outProtection = bytes[0];
    }
    return bytes[0] == 0x31;
}

static void HandleTiCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    (void)state;

    TiSubscriber& sub = GetTiSubscriberInstance();

    do
    {
        if (args.size() < 2 || HasHelpToken(args, 1))
        {
            PrintTiHelp();
            break;
        }

        std::wstring action = ToLower(args[1]);

        if (action == L"start")
        {
            if (sub.IsActive())
            {
                std::wcerr << L"!ti: subscriber already active. use '!ti stop' first or '!ti add' to extend watch.\n";
                break;
            }
            TiOptions options;
            options.SelfPid = GetCurrentProcessId();
            options.ExcludeSelf = true;
            std::wstring parseError;
            if (!ParseTiStartArgs(args, 2, &options, &parseError))
            {
                std::wcerr << L"!ti start: " << parseError << L"\n";
                PrintTiHelp();
                break;
            }

            if (!device.IsOpen())
            {
                std::wcerr << L"!ti start requires the KnLiveDbg.sys driver device to be open\n";
                break;
            }

            // Proactive PPL Antimalware gate. The provider returns
            // ERROR_ACCESS_DENIED from EnableTraceEx2 otherwise, but the
            // pre-check gives a much clearer remediation hint.
            uint8_t protByte = 0;
            std::wstring gateError;
            bool isPpl = CheckSelfIsPplAntimalware(device, symbols, &protByte, &gateError);
            if (!isPpl)
            {
                if (gateError.empty())
                {
                    std::wcerr << L"!ti start: this process is not PPL Antimalware (current Protection=0x"
                               << std::hex << std::setw(2) << std::setfill(L'0')
                               << static_cast<unsigned>(protByte) << std::dec
                               << L"). Microsoft-Windows-Threat-Intelligence requires the consumer\n"
                               << L"  to be PPL Antimalware. Run 'write on' then 'set-ppl-antimalware'\n"
                               << L"  first, then retry '!ti start'.\n";
                    break;
                }
                else
                {
                    // Symbols / IOCTL trouble; warn and fall through. The
                    // subscriber Start() will then return the underlying
                    // EnableTraceEx2 status if the process really is not PPL.
                    std::wcerr << L"!ti start: warning, could not pre-check PPL state (" << gateError
                               << L"); continuing.\n";
                }
            }

            // Register for the hard-exit cleanup path BEFORE Start() so a
            // CTRL_CLOSE that arrives in the microsecond gap between Start
            // returning and a post-Start store still tears the session down.
            // Stop() is idempotent (atomic exchange on Active) so calling
            // it on a never-started subscriber is a no-op.
            g_TiSubscriberForShutdown.store(&sub);

            std::wstring startError;
            if (!sub.Start(options, &startError))
            {
                // Roll back the registration on failure.
                g_TiSubscriberForShutdown.store(nullptr);
                std::wcerr << L"!ti start failed: " << startError << L"\n";
                break;
            }

            PrintColoredText(L"[ti]", KNDBG_COLOR_TITLE);
            std::wcout << L" subscribed to Microsoft-Windows-Threat-Intelligence (all tasks)\n";
            TiOptions current = sub.CurrentOptions();
            std::wcout << L"     log directory=" << current.LogDirectory
                       << L" base=" << current.LogBaseName
                       << L" rotate=" << (current.LogRotateBytes >> 20) << L"MB x "
                       << current.LogRotateCount << L"\n";
            std::wcout << L"     ring=" << current.RingCapacity
                       << L" throttle=" << current.ThrottlePerSecond << L"/s self_pid="
                       << current.SelfPid << L"\n";
            std::wcout << L"     watch:";
            if (current.WatchPids.empty() && current.WatchNames.empty())
            {
                std::wcout << L" <none> (silent forensic mode; use '!ti watch' for live tail)";
            }
            for (uint32_t p : current.WatchPids)
            {
                std::wcout << L" pid=" << p;
            }
            for (const std::wstring& n : current.WatchNames)
            {
                std::wcout << L" name=" << n;
            }
            std::wcout << L"\n";

            if (!current.WatchPids.empty() || !current.WatchNames.empty())
            {
                sub.SetLiveOutput(true);
                std::wcout << L"     live output: enabled for matching events (throttled).\n";
            }
            break;
        }

        if (action == L"stop")
        {
            if (!sub.IsActive())
            {
                std::wcerr << L"!ti: subscriber not active.\n";
                break;
            }
            std::wstring stopError;
            sub.Stop(&stopError);
            // Unregister AFTER Stop so the hard-exit path remains armed
            // during the teardown. Stop() is idempotent, so a CTRL_CLOSE
            // racing with our manual stop is harmless either way.
            g_TiSubscriberForShutdown.store(nullptr);
            PrintColoredText(L"[ti]", KNDBG_COLOR_TITLE);
            std::wcout << L" stopped. ring and log are kept; use '!ti clear' to drop the ring.\n";
            break;
        }

        if (action == L"status")
        {
            TiSubscriberStats s = sub.SnapshotStats();
            TiOptions opt = sub.CurrentOptions();
            PrintColoredText(L"[ti.status]", KNDBG_COLOR_TITLE);
            std::wcout << L" active=" << (sub.IsActive() ? L"yes" : L"no")
                       << L" live=" << (sub.IsLiveOutputEnabled() ? L"yes" : L"no")
                       << L"\n";
            std::wcout << L"  events received=" << s.EventsReceived
                       << L" kept=" << s.EventsKept
                       << L" dropped=" << s.EventsDropped
                       << L" self_excluded=" << s.EventsSelfExcluded
                       << L" watch_matched=" << s.EventsWatchMatched << L"\n";
            std::wcout << L"  logged=" << s.EventsLogged
                       << L" log_bytes=" << s.LogBytesWritten
                       << L" rotations=" << s.LogRotations << L"\n";
            std::wcout << L"  watch:";
            for (uint32_t p : opt.WatchPids)
            {
                std::wcout << L" pid=" << p;
            }
            for (const std::wstring& n : opt.WatchNames)
            {
                std::wcout << L" name=" << n;
            }
            if (opt.WatchPids.empty() && opt.WatchNames.empty())
            {
                std::wcout << L" <none>";
            }
            std::wcout << L"\n";
            break;
        }

        if (action == L"add" || action == L"remove")
        {
            if (args.size() < 4)
            {
                std::wcerr << L"!ti " << action << L": usage: !ti " << action << L" /pid <PID> | /name <imageName>\n";
                break;
            }
            std::wstring kind = ToLower(args[2]);
            const std::wstring& value = args[3];

            if (kind == L"/pid")
            {
                uint64_t v = 0;
                if (!ParseUnsigned(value, 0, &v) || v == 0 || v > 0xFFFFFFFFull)
                {
                    std::wcerr << L"!ti " << action << L": invalid PID: " << value << L"\n";
                    break;
                }
                bool ok = (action == L"add")
                    ? sub.AddWatchPid(static_cast<uint32_t>(v))
                    : sub.RemoveWatchPid(static_cast<uint32_t>(v));
                std::wcout << L"[ti] pid " << v << (action == L"add" ? L" added" : L" removed")
                           << (ok ? L"\n" : L" (no change)\n");
            }
            else if (kind == L"/name")
            {
                bool ok = (action == L"add")
                    ? sub.AddWatchName(value)
                    : sub.RemoveWatchName(value);
                std::wcout << L"[ti] name " << value
                           << (action == L"add" ? L" added" : L" removed")
                           << (ok ? L"\n" : L" (no change)\n");
            }
            else
            {
                std::wcerr << L"!ti " << action << L": unknown kind \"" << args[2] << L"\"\n";
            }
            break;
        }

        if (action == L"watch")
        {
            if (!sub.IsActive())
            {
                std::wcerr << L"!ti watch: subscriber not active. run '!ti start' first.\n";
                break;
            }
            const bool wasLive = sub.IsLiveOutputEnabled();
            sub.SetLiveOutput(true);
            PrintColoredText(L"[ti.watch]", KNDBG_COLOR_TITLE);
            std::wcout << L" live tail engaged. press Ctrl+C or Esc to detach (subscription stays up).\n";

            // Save the pre-watch Ctrl+C latch state and clear it for the
            // duration of the loop. On exit we restore the original value
            // so that any other long-running TUI command that was relying
            // on g_StopRequested is not silently disarmed by this watch.
            const bool savedStopRequested = g_StopRequested.load();
            g_StopRequested = false;
            for (;;)
            {
                if (g_StopRequested.load())
                {
                    g_StopRequested = false;
                    break;
                }
                if (_kbhit())
                {
                    int ch = _getch();
                    if (ch == 0x1B /* Esc */ || ch == L'q' || ch == L'Q')
                    {
                        break;
                    }
                    // Other keys are swallowed silently while watch is
                    // engaged. The prompt is paused; we cannot let typed
                    // characters reach the prompt parser because input is
                    // captured by _getch already.
                }
                std::vector<TiEventRecord> batch = sub.DrainPrintQueue(64);
                for (const TiEventRecord& r : batch)
                {
                    PrintTiEventLine(r);
                }
                uint64_t suppressed = sub.ConsumeThrottleSuppressedCount();
                if (suppressed > 0)
                {
                    PrintColoredText(L"[ti.throttle]", KNDBG_COLOR_WARN);
                    std::wcout << L" suppressed " << suppressed << L" events in the last window\n";
                }
                if (batch.empty())
                {
                    Sleep(50);
                }
            }
            // Restore the live-output preference rather than leaving it
            // sticky after exit. A subscriber that started silent stays
            // silent once watch detaches.
            sub.SetLiveOutput(wasLive);
            // Restore the pre-watch Ctrl+C latch so a parallel cancellable
            // operation that read this latch before we entered watch can
            // still observe its original state.
            g_StopRequested.store(savedStopRequested);
            std::wcout << L"[ti.watch] detached. ring/log still active.\n";
            break;
        }

        if (action == L"recent")
        {
            size_t n = 50;
            if (args.size() >= 3)
            {
                uint64_t v = 0;
                if (!ParseUnsigned(args[2], 10, &v) || v == 0)
                {
                    std::wcerr << L"!ti recent: invalid count: " << args[2] << L"\n";
                    break;
                }
                // Sanity cap; user can re-issue if they really need more.
                if (v > 10000)
                {
                    v = 10000;
                }
                n = static_cast<size_t>(v);
            }
            std::vector<TiEventRecord> recent = sub.Recent(n, false);
            for (const TiEventRecord& r : recent)
            {
                PrintTiEventLine(r);
            }
            std::wcout << L"[ti.recent] returned=" << recent.size() << L"\n";
            break;
        }

        if (action == L"stats")
        {
            std::map<std::wstring, uint64_t> taskHist;
            std::map<std::wstring, uint64_t> imageHist;
            size_t total = 0;
            sub.Histogram(&taskHist, &imageHist, &total);

            PrintColoredText(L"[ti.stats.task]", KNDBG_COLOR_TITLE);
            std::wcout << L" total ring=" << total << L"\n";
            for (const auto& kv : taskHist)
            {
                std::wcout << L"  " << kv.second << L"\t" << kv.first << L"\n";
            }
            PrintColoredText(L"[ti.stats.process]", KNDBG_COLOR_TITLE);
            std::wcout << L"\n";
            for (const auto& kv : imageHist)
            {
                std::wcout << L"  " << kv.second << L"\t" << kv.first << L"\n";
            }
            break;
        }

        if (action == L"by")
        {
            if (args.size() < 4)
            {
                std::wcerr << L"!ti by: usage: !ti by pid <PID> | !ti by task <name>\n";
                break;
            }
            std::wstring kind = ToLower(args[2]);
            if (kind == L"pid")
            {
                uint64_t v = 0;
                if (!ParseUnsigned(args[3], 0, &v) || v == 0)
                {
                    std::wcerr << L"!ti by pid: invalid PID: " << args[3] << L"\n";
                    break;
                }
                std::vector<TiEventRecord> filtered = sub.FilterByPid(static_cast<uint32_t>(v), 200);
                for (const TiEventRecord& r : filtered)
                {
                    PrintTiEventLine(r);
                }
                std::wcout << L"[ti.by.pid] matched=" << filtered.size() << L"\n";
            }
            else if (kind == L"task")
            {
                std::vector<TiEventRecord> filtered = sub.FilterByTask(args[3], 200);
                for (const TiEventRecord& r : filtered)
                {
                    PrintTiEventLine(r);
                }
                std::wcout << L"[ti.by.task] matched=" << filtered.size() << L"\n";
            }
            else
            {
                std::wcerr << L"!ti by: unknown kind \"" << args[2] << L"\"\n";
            }
            break;
        }

        if (action == L"grep")
        {
            if (args.size() < 3)
            {
                std::wcerr << L"!ti grep: usage: !ti grep <pattern>\n";
                break;
            }
            std::vector<TiEventRecord> filtered = sub.Grep(args[2], 200);
            for (const TiEventRecord& r : filtered)
            {
                PrintTiEventLine(r);
            }
            std::wcout << L"[ti.grep] matched=" << filtered.size() << L"\n";
            break;
        }

        if (action == L"save")
        {
            if (args.size() < 3)
            {
                std::wcerr << L"!ti save: usage: !ti save <path>\n";
                break;
            }
            std::wstring saveError;
            if (!sub.SaveTo(args[2], &saveError))
            {
                std::wcerr << L"!ti save failed: " << saveError << L"\n";
                break;
            }
            std::wcout << L"[ti.save] wrote " << args[2] << L"\n";
            break;
        }

        if (action == L"clear")
        {
            sub.Clear();
            std::wcout << L"[ti.clear] ring drained.\n";
            break;
        }

        std::wcerr << L"!ti: unknown subcommand \"" << args[1] << L"\"\n";
        PrintTiHelp();
    } while (false);
}

static void HandleAddressCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    do
    {
        if (HasHelpToken(args, 1))
        {
            PrintAddressHelp();
            break;
        }

        if (args.size() < 2)
        {
            std::wcerr << L"usage: !address <va>\n";
            PrintAddressHelp();
            break;
        }

        if (args.size() > 2)
        {
            std::wcerr << L"!address: unexpected extra argument \"" << args[2] << L"\"\n";
            break;
        }

        if (!device.IsOpen())
        {
            std::wcerr << L"!address requires the KnLiveDbg.sys driver device to be open\n";
            break;
        }

        std::wstring parseError;
        uint64_t address = 0;
        if (!ParseAddressOrSymbol(symbols, state, args[1], &address, &parseError))
        {
            std::wcerr << L"!address: failed to parse \"" << args[1] << L"\": " << parseError << L"\n";
            break;
        }

        AddressInspectResult result;
        std::wstring inspectError;
        if (!InspectAddress(device, symbols, address, &result, &inspectError))
        {
            std::wcerr << L"!address failed: " << inspectError << L"\n";
            break;
        }

        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"!address warning: " << warning << L"\n";
        }

        PrintAddressInspection(result);
    } while (false);
}

static void PrintPoolScanPeHelp()
{
    std::wcout << L"pool-scan-pe command:\n";
    std::wcout << L"  pool-scan-pe [/tag <ABCD>] [/min <bytes>] [/max <bytes>] [/limit <n>]\n";
    std::wcout << L"               [/nonpaged|/paged|/any] [/suspicious] [/dump <directory>]\n";
    std::wcout << L"\n";
    std::wcout << L"description:\n";
    std::wcout << L"  Enumerates big pool allocations via NtQuerySystemInformation\n";
    std::wcout << L"  (SystemBigPoolInformation=0x42) and runs the same PE header detection used\n";
    std::wcout << L"  by dump-pe on each entry's first 4 KB. The detector accepts both intact and\n";
    std::wcout << L"  signature-wiped PE headers, so reflectively-loaded modules, unpacker stages,\n";
    std::wcout << L"  and stomped driver replacements that zero MZ/PE to evade scanners are still\n";
    std::wcout << L"  surfaced. Each hit prints the pool tag, address/size, suspicion markers\n";
    std::wcout << L"  (which signatures were stripped), and PE metadata.\n";
    std::wcout << L"\n";
    std::wcout << L"options:\n";
    std::wcout << L"  /tag <ABCD>        only scan entries with the given 4-char pool tag.\n";
    std::wcout << L"  /min <bytes>       only scan entries >= <bytes> (default 0x1000).\n";
    std::wcout << L"  /max <bytes>       only scan entries <= <bytes>.\n";
    std::wcout << L"  /limit <n>         stop after <n> hits.\n";
    std::wcout << L"  /nonpaged          NonPaged entries only (default).\n";
    std::wcout << L"  /paged             Paged entries only.\n";
    std::wcout << L"  /any               include both Paged and NonPaged.\n";
    std::wcout << L"  /suspicious        only report hits whose MZ/PE/e_lfanew were wiped.\n";
    std::wcout << L"  /dump <directory>  also dump each detected PE to a file via dump-pe logic;\n";
    std::wcout << L"                     filename pattern is poolpe_<tag>_<address>.bin. The\n";
    std::wcout << L"                     directory is created if missing.\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  Requires SeDebugPrivilege and the KnLiveDbg.sys driver to be open. Per-entry\n";
    std::wcout << L"  reads use the driver's MmCopyMemory + MDL probe-and-lock fallback, so\n";
    std::wcout << L"  paged-out big pool allocations are recovered automatically.\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  pool-scan-pe\n";
    std::wcout << L"  pool-scan-pe /suspicious\n";
    std::wcout << L"  pool-scan-pe /tag Cdat /dump .\\poolpe-hits\n";
    std::wcout << L"  pool-scan-pe /min 0x4000 /suspicious /dump .\\poolpe-hits\n";
}

static void PrintPoolPeHit(const PoolPeHit& hit)
{
    bool wiped = hit.Probe.MzWiped || hit.Probe.PeSignatureWiped || hit.Probe.ELfanewMismatch;
    PrintColoredText(wiped ? L"[pool-pe.suspect]" : L"[pool-pe.hit]",
                     wiped ? KNDBG_COLOR_FAIL : KNDBG_COLOR_TITLE);

    std::wcout << L" address=" << HexTextWidth(hit.Address, 16, true);

    std::wstringstream sizeText;
    sizeText << L"0x" << std::hex << hit.SizeInBytes;
    std::wcout << L" size=";
    PrintColoredText(sizeText.str(), KNDBG_COLOR_ACCENT);

    std::wcout << L" tag=";
    PrintColoredText(hit.TagText, KNDBG_COLOR_OK);

    std::wcout << L" ";
    PrintColoredText(hit.NonPaged ? L"NonPaged" : L"Paged",
                     hit.NonPaged ? KNDBG_COLOR_OK : KNDBG_COLOR_DIM);

    std::wcout << L" nt=0x" << std::hex << hit.Probe.NtOffset
               << L" bits=" << std::dec << (hit.Probe.Is64Bit ? L"64" : L"32")
               << L" machine=0x" << std::hex << hit.Probe.Machine
               << L" sections=" << std::dec << hit.Probe.NumberOfSections
               << L" sizeOfImage=0x" << std::hex << hit.Probe.SizeOfImage
               << L" imageBase=0x" << hit.Probe.ImageBase
               << std::dec;

    if (wiped)
    {
        std::wcout << L" ";
        std::wstring tag = L"WIPED=[";
        bool first = true;
        if (hit.Probe.MzWiped)
        {
            tag += L"MZ";
            first = false;
        }
        if (hit.Probe.ELfanewMismatch)
        {
            if (!first) tag += L",";
            tag += L"e_lfanew";
            first = false;
        }
        if (hit.Probe.PeSignatureWiped)
        {
            if (!first) tag += L",";
            tag += L"PE";
        }
        tag += L"]";
        PrintColoredText(tag, KNDBG_COLOR_FAIL);
    }

    if (hit.DumpSucceeded)
    {
        std::wcout << L" dump=";
        PrintColoredText(hit.DumpedPath, KNDBG_COLOR_OK);
    }

    std::wcout << L"\n";
}

static void HandlePoolScanPeCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    (void)symbols;

    do
    {
        if (HasHelpToken(args, 1))
        {
            PrintPoolScanPeHelp();
            break;
        }

        if (!device.IsOpen())
        {
            std::wcerr << L"pool-scan-pe requires the KnLiveDbg.sys driver device to be open\n";
            break;
        }

        PoolPeHunter::Options options = {};
        options.Paged = PoolPeHunter::PagedFilter::NonPagedOnly;
        options.HasMinSize = true;
        options.MinSize = 0x1000;

        bool parseError = false;
        size_t i = 1;
        while (i < args.size())
        {
            std::wstring opt = ToLower(args[i]);

            if (opt == L"/nonpaged")
            {
                options.Paged = PoolPeHunter::PagedFilter::NonPagedOnly;
                ++i;
                continue;
            }
            if (opt == L"/paged")
            {
                options.Paged = PoolPeHunter::PagedFilter::PagedOnly;
                ++i;
                continue;
            }
            if (opt == L"/any")
            {
                options.Paged = PoolPeHunter::PagedFilter::Any;
                ++i;
                continue;
            }
            if (opt == L"/suspicious")
            {
                options.OnlySuspicious = true;
                ++i;
                continue;
            }

            if (opt == L"/tag")
            {
                if (i + 1 >= args.size())
                {
                    std::wcerr << L"pool-scan-pe: /tag requires a value\n";
                    parseError = true;
                    break;
                }
                uint32_t tag = 0;
                if (!ParsePoolTagText(args[i + 1], &tag))
                {
                    std::wcerr << L"pool-scan-pe: invalid tag \"" << args[i + 1] << L"\"\n";
                    parseError = true;
                    break;
                }
                options.HasTagFilter = true;
                options.TagFilter = tag;
                options.TagFilterText = args[i + 1];
                i += 2;
                continue;
            }

            if (opt == L"/min" || opt == L"/max" || opt == L"/limit")
            {
                if (i + 1 >= args.size())
                {
                    std::wcerr << L"pool-scan-pe: " << opt << L" requires a value\n";
                    parseError = true;
                    break;
                }
                uint64_t value = 0;
                if (!ParseUnsigned(args[i + 1], state.NumberBase, &value))
                {
                    std::wcerr << L"pool-scan-pe: failed to parse \"" << args[i + 1] << L"\" for " << opt << L"\n";
                    parseError = true;
                    break;
                }
                if (opt == L"/min")
                {
                    options.HasMinSize = true;
                    options.MinSize = value;
                }
                else if (opt == L"/max")
                {
                    options.HasMaxSize = true;
                    options.MaxSize = value;
                }
                else
                {
                    if (value > 0xFFFFFFFFull) value = 0xFFFFFFFFull;
                    options.LimitHits = static_cast<uint32_t>(value);
                }
                i += 2;
                continue;
            }

            if (opt == L"/dump")
            {
                if (i + 1 >= args.size())
                {
                    std::wcerr << L"pool-scan-pe: /dump requires a directory\n";
                    parseError = true;
                    break;
                }
                options.DumpEnabled = true;
                options.DumpDirectory = args[i + 1];
                i += 2;
                continue;
            }

            std::wcerr << L"pool-scan-pe: unrecognised argument \"" << args[i] << L"\"\n";
            PrintPoolScanPeHelp();
            parseError = true;
            break;
        }

        if (parseError)
        {
            break;
        }

        PoolPeHunter hunter(device);
        PoolPeHunterResult result = {};
        std::wstring error;
        if (!hunter.Scan(options, &result, &error))
        {
            std::wcerr << L"pool-scan-pe failed: " << error << L"\n";
            for (const std::wstring& warning : result.Warnings)
            {
                std::wcerr << L"pool-scan-pe warning: " << warning << L"\n";
            }
            break;
        }

        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"pool-scan-pe warning: " << warning << L"\n";
        }
        for (const std::wstring& diag : result.Diagnostics)
        {
            std::wcout << L"pool-scan-pe diag: " << diag << L"\n";
        }

        for (const PoolPeHit& hit : result.Hits)
        {
            PrintPoolPeHit(hit);
        }

        PrintColoredText(L"[pool-pe.summary]", KNDBG_COLOR_TITLE);
        std::wcout << L" total=" << std::dec << result.TotalEntries
                   << L" nonpaged=" << result.NonPagedCount
                   << L" paged=" << result.PagedCount
                   << L" scanned=" << result.Scanned
                   << L" readFail=" << result.ReadFailures
                   << L" hits=" << result.Hits.size()
                   << L" suspicious=" << result.SuspiciousWipes;
        if (!result.PrivilegeEnabled)
        {
            std::wcout << L" ";
            PrintColoredText(L"(no SeDebugPrivilege)", KNDBG_COLOR_WARN);
        }
        std::wcout << L"\n";
    } while (false);
}

static void HandleDumpPeCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    do
    {
        if (HasHelpToken(args, 1))
        {
            PrintDumpPeHelp();
            break;
        }

        if (args.size() < 3)
        {
            std::wcerr << L"usage: dump-pe <address> <path>\n";
            PrintDumpPeHelp();
            break;
        }

        if (!device.IsOpen())
        {
            std::wcerr << L"dump-pe requires the KnLiveDbg.sys driver device to be open\n";
            break;
        }

        std::wstring error;
        uint64_t address = 0;
        if (!ParseAddressOrSymbol(symbols, state, args[1], &address, &error))
        {
            std::wcerr << L"dump-pe: failed to parse address \"" << args[1] << L"\": " << error << L"\n";
            break;
        }

        std::wstring path = args[2];
        if (args.size() > 3)
        {
            std::wcerr << L"dump-pe: unexpected extra argument \"" << args[3] << L"\"\n";
            PrintDumpPeHelp();
            break;
        }

        DumpPeResult result = {};
        std::wstring dumpError;
        if (!DumpKernelPeToFile(device, address, path, &result, &dumpError))
        {
            std::wcerr << L"dump-pe failed: " << dumpError << L"\n";
            for (const std::wstring& warning : result.Warnings)
            {
                std::wcerr << L"dump-pe warning: " << warning << L"\n";
            }
            break;
        }

        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"dump-pe warning: " << warning << L"\n";
        }

        for (const DumpedSectionRecord& section : result.Sections)
        {
            PrintColoredText(L"[dump-pe.section]", KNDBG_COLOR_TITLE);
            std::wcout << L" name=";
            PrintColoredText(section.Name.empty() ? L"<unnamed>" : section.Name, KNDBG_COLOR_ACCENT);
            std::wcout << L" rva=0x" << std::hex << section.VirtualAddress
                       << L" vsize=0x" << section.VirtualSize
                       << L" raw=0x" << section.SizeOfRawData
                       << L" file=0x" << section.PointerToRawData
                       << std::dec;

            // Decode notable Characteristics flags. DISCARDABLE in particular
            // tells the operator the loader is expected to tear down the
            // section after load (e.g. INIT, .reloc), so a zero-fill outcome
            // is the documented behaviour rather than a bug.
            const uint32_t kImgScnMemDiscardable = 0x02000000;
            const uint32_t kImgScnMemExecute    = 0x20000000;
            const uint32_t kImgScnMemRead       = 0x40000000;
            const uint32_t kImgScnMemWrite      = 0x80000000;
            const uint32_t kImgScnMemNotPaged   = 0x08000000;

            std::wstring chars;
            if (section.Characteristics & kImgScnMemRead)        chars += L"R";
            if (section.Characteristics & kImgScnMemWrite)       chars += L"W";
            if (section.Characteristics & kImgScnMemExecute)     chars += L"X";
            if (section.Characteristics & kImgScnMemNotPaged)    chars += L"+NP";
            if (section.Characteristics & kImgScnMemDiscardable) chars += L"+DISCARD";
            if (!chars.empty())
            {
                std::wcout << L" chars=";
                PrintColoredText(chars,
                    (section.Characteristics & kImgScnMemDiscardable) ? KNDBG_COLOR_DIM : KNDBG_COLOR_ACCENT);
            }

            if (section.ZeroFilled)
            {
                std::wcout << L" ";
                if (section.Characteristics & kImgScnMemDiscardable)
                {
                    PrintColoredText(L"[ZERO-FILLED (discardable)]", KNDBG_COLOR_DIM);
                }
                else
                {
                    PrintColoredText(L"[ZERO-FILLED]", KNDBG_COLOR_WARN);
                }
            }
            else if (section.ReadSucceeded)
            {
                std::wcout << L" ";
                PrintColoredText(L"OK", KNDBG_COLOR_OK);
            }
            std::wcout << L"\n";
        }

        PrintColoredText(L"[dump-pe]", KNDBG_COLOR_TITLE);
        std::wcout << L" address=" << HexTextWidth(result.StartAddress, 16, true)
                   << L" bits=" << (result.Is64Bit ? L"64" : L"32")
                   << L" machine=0x" << std::hex << result.Machine << std::dec
                   << L" sections=" << result.NumberOfSections
                   << L" headers=0x" << std::hex << result.SizeOfHeaders
                   << L" imageBase=0x" << result.ImageBase
                   << L" sizeOfImage=0x" << result.SizeOfImage
                   << L" output=0x" << result.TotalFileSize << std::dec;

        if (result.RestoredDosMagic || result.RestoredPeSignature || result.RestoredELfanew)
        {
            std::wcout << L" ";
            std::wstring restored = L"recovered=[";
            bool first = true;
            if (result.RestoredDosMagic)
            {
                restored += L"MZ";
                first = false;
            }
            if (result.RestoredELfanew)
            {
                if (!first)
                {
                    restored += L",";
                }
                restored += L"e_lfanew";
                first = false;
            }
            if (result.RestoredPeSignature)
            {
                if (!first)
                {
                    restored += L",";
                }
                restored += L"PE";
            }
            restored += L"]";
            PrintColoredText(restored, KNDBG_COLOR_WARN);
        }

        std::wcout << L" path=";
        PrintColoredText(path, KNDBG_COLOR_OK);
        std::wcout << L"\n";
    } while (false);
}

static void PrintPoolHelp()
{
    std::wcout << L"!pool command:\n";
    std::wcout << L"  !pool big [options]\n";
    std::wcout << L"  !pool find /tag <TAG> [options]\n";
    std::wcout << L"  !pool summary\n";
    std::wcout << L"\n";
    std::wcout << L"scopes:\n";
    std::wcout << L"  big      enumerate big pool allocations via NtQuerySystemInformation(SystemBigPoolInformation=0x42).\n";
    std::wcout << L"           Returns allocations >= one page tracked by nt!PoolBigPageTable. Useful for hunting kernel\n";
    std::wcout << L"           cheat allocations, BYOVD payloads, and unusual large NonPaged ranges.\n";
    std::wcout << L"  find     same data as 'big' but requires at least one filter (/tag, /addr, /min, or /max) and is geared\n";
    std::wcout << L"           toward targeted searches.\n";
    std::wcout << L"  summary  print only the per-build totals and skip the per-entry listing.\n";
    std::wcout << L"\n";
    std::wcout << L"options:\n";
    std::wcout << L"  /tag <ABCD>     filter by 4-char ASCII tag (e.g. Wmem, MmCa, Cdat). Up to 4 characters; pad with spaces.\n";
    std::wcout << L"  /min <bytes>    keep only entries whose SizeInBytes >= <bytes> (hex or decimal).\n";
    std::wcout << L"  /max <bytes>    keep only entries whose SizeInBytes <= <bytes>.\n";
    std::wcout << L"  /addr <va>      keep only the entry containing <va>.\n";
    std::wcout << L"  /limit <n>      stop after printing <n> entries (default unlimited).\n";
    std::wcout << L"  /nonpaged       only include NonPaged entries (default).\n";
    std::wcout << L"  /paged          only include Paged entries.\n";
    std::wcout << L"  /any            include both Paged and NonPaged.\n";
    std::wcout << L"  /annotate       walk PTE for each kept NonPaged entry to mark R/W/X and large-page state.\n";
    std::wcout << L"                  Slower (issues one QueryAddress+TranslateVirtual IOCTL per entry).\n";
    std::wcout << L"  /wx             implies /annotate and keeps only effective W+X NonPaged entries.\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  Requires SeDebugPrivilege; run elevated. The scanner attempts to enable it automatically.\n";
    std::wcout << L"  Only big pool (>= 0x1000 bytes) is tracked by nt!PoolBigPageTable. Use !pool find /tag <TAG> to scan\n";
    std::wcout << L"  for known suspicious tags; combine with /annotate to spot W+X allocations (executable NonPaged pool).\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  !pool big\n";
    std::wcout << L"  !pool big /tag Cdat /annotate\n";
    std::wcout << L"  !pool find /wx /limit 20\n";
    std::wcout << L"  !pool find /min 0x10000 /annotate\n";
    std::wcout << L"  !pool find /addr 0xffffae8000123000\n";
    std::wcout << L"  !pool summary\n";
}

static void PrintBigPoolRecord(const BigPoolEntryRecord& entry, bool annotateRequested)
{
    PrintColoredText(L"[pool.big]", KNDBG_COLOR_TITLE);
    std::wcout << L" address=" << HexTextWidth(entry.VirtualAddress, 16, true);

    std::wcout << L" size=";
    std::wstringstream sizeText;
    sizeText << L"0x" << std::hex << entry.SizeInBytes;
    PrintColoredText(sizeText.str(), KNDBG_COLOR_ACCENT);
    std::wcout << L" (" << std::dec << entry.SizeInBytes << L")";

    std::wcout << L" tag=";
    PrintColoredText(entry.TagText, KNDBG_COLOR_OK);

    std::wcout << L" ";
    PrintColoredText(entry.NonPaged ? L"NonPaged" : L"Paged",
                     entry.NonPaged ? KNDBG_COLOR_OK : KNDBG_COLOR_DIM);

    if (annotateRequested)
    {
        if (entry.AttributesQueried)
        {
            std::wcout << L" R=";
            PrintColoredText(entry.IsReadable ? L"1" : L"0",
                             entry.IsReadable ? KNDBG_COLOR_OK : KNDBG_COLOR_DIM);
            std::wcout << L" W=";
            PrintColoredText(entry.IsWritable ? L"1" : L"0",
                             entry.IsWritable ? KNDBG_COLOR_WARN : KNDBG_COLOR_DIM);
            std::wcout << L" X=";
            PrintColoredText(entry.IsExecutable ? L"1" : L"0",
                             entry.IsExecutable ? KNDBG_COLOR_FAIL : KNDBG_COLOR_DIM);
            if (entry.IsLargePage)
            {
                std::wcout << L" LargePage";
            }
            if (entry.IsWritable && entry.IsExecutable)
            {
                std::wcout << L" ";
                PrintColoredText(L"[W+X]", KNDBG_COLOR_FAIL);
            }
        }
        else
        {
            std::wcout << L" attr=unavailable";
        }
    }

    std::wcout << L"\n";
}

static void HandlePoolCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    do
    {
        if (HasHelpToken(args, 1))
        {
            PrintPoolHelp();
            break;
        }

        PoolScanner::Options options = {};
        options.Target = PoolScanner::Scope::Big;
        options.Paged = PoolScanner::PagedFilter::NonPagedOnly;
        bool summaryOnly = false;

        size_t index = 1;
        if (index < args.size() && IsPoolScopeName(args[index]))
        {
            std::wstring scope = ToLower(args[index]);
            if (scope == L"big" || scope == L"bigpool")
            {
                options.Target = PoolScanner::Scope::Big;
            }
            else if (scope == L"find")
            {
                options.Target = PoolScanner::Scope::Find;
            }
            else if (scope == L"summary")
            {
                summaryOnly = true;
            }
            ++index;
        }

        bool parseError = false;
        while (index < args.size())
        {
            std::wstring opt = ToLower(args[index]);

            if (opt == L"/nonpaged")
            {
                options.Paged = PoolScanner::PagedFilter::NonPagedOnly;
                ++index;
                continue;
            }
            if (opt == L"/paged")
            {
                options.Paged = PoolScanner::PagedFilter::PagedOnly;
                ++index;
                continue;
            }
            if (opt == L"/any")
            {
                options.Paged = PoolScanner::PagedFilter::Any;
                ++index;
                continue;
            }
            if (opt == L"/annotate")
            {
                options.AnnotateAttributes = true;
                ++index;
                continue;
            }
            if (opt == L"/wx")
            {
                options.WxOnly = true;
                options.AnnotateAttributes = true;
                ++index;
                continue;
            }

            if (opt == L"/tag")
            {
                if (index + 1 >= args.size())
                {
                    std::wcerr << L"!pool: /tag requires a value\n";
                    parseError = true;
                    break;
                }
                uint32_t tag = 0;
                if (!ParsePoolTagText(args[index + 1], &tag))
                {
                    std::wcerr << L"!pool: invalid tag \"" << args[index + 1] << L"\"\n";
                    parseError = true;
                    break;
                }
                options.HasTagFilter = true;
                options.TagFilter = tag;
                options.TagFilterText = args[index + 1];
                index += 2;
                continue;
            }

            if (opt == L"/min" || opt == L"/max" || opt == L"/addr" || opt == L"/limit")
            {
                if (index + 1 >= args.size())
                {
                    std::wcerr << L"!pool: " << opt << L" requires a value\n";
                    parseError = true;
                    break;
                }
                uint64_t value = 0;
                if (!ParseUnsigned(args[index + 1], state.NumberBase, &value))
                {
                    std::wcerr << L"!pool: failed to parse \"" << args[index + 1] << L"\" for " << opt << L"\n";
                    parseError = true;
                    break;
                }
                if (opt == L"/min")
                {
                    options.HasMinSize = true;
                    options.MinSize = value;
                }
                else if (opt == L"/max")
                {
                    options.HasMaxSize = true;
                    options.MaxSize = value;
                }
                else if (opt == L"/addr")
                {
                    options.HasAddressFilter = true;
                    options.AddressFilter = value;
                }
                else
                {
                    if (value > 0xFFFFFFFFull)
                    {
                        value = 0xFFFFFFFFull;
                    }
                    options.LimitEntries = static_cast<uint32_t>(value);
                }
                index += 2;
                continue;
            }

            std::wcerr << L"!pool: unrecognised argument \"" << args[index] << L"\"\n";
            PrintPoolHelp();
            parseError = true;
            break;
        }

        if (parseError)
        {
            break;
        }

        if (options.Target == PoolScanner::Scope::Find &&
            !options.HasTagFilter && !options.HasAddressFilter &&
            !options.HasMinSize && !options.HasMaxSize &&
            !options.WxOnly)
        {
            std::wcerr << L"!pool find requires at least one of /tag, /addr, /min, /max, or /wx\n";
            PrintPoolHelp();
            break;
        }

        if (options.AnnotateAttributes && !device.IsOpen())
        {
            if (options.WxOnly)
            {
                std::wcerr << L"!pool /wx requires the KnLiveDbg.sys driver device to be open\n";
                break;
            }
            std::wcerr << L"!pool /annotate requires the KnLiveDbg.sys driver device to be open; continuing without attributes\n";
            options.AnnotateAttributes = false;
        }

        PoolScanner scanner(device, symbols);
        PoolScanResult result = {};
        std::wstring error;
        if (!scanner.Scan(options, &result, &error))
        {
            std::wcerr << L"!pool failed: " << error << L"\n";
            for (const std::wstring& warning : result.Warnings)
            {
                std::wcerr << L"!pool warning: " << warning << L"\n";
            }
            break;
        }

        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"!pool warning: " << warning << L"\n";
        }
        for (const std::wstring& diag : result.Diagnostics)
        {
            std::wcout << L"!pool diag: " << diag << L"\n";
        }

        if (!summaryOnly)
        {
            for (const BigPoolEntryRecord& entry : result.Entries)
            {
                PrintBigPoolRecord(entry, options.AnnotateAttributes);
            }
        }

        PrintColoredText(L"[pool.summary]", KNDBG_COLOR_TITLE);
        std::wcout << L" total=" << std::dec << result.TotalEntries
                   << L" nonpaged=" << result.NonPagedCount
                   << L" paged=" << result.PagedCount
                   << L" matching=" << result.MatchingCount;
        if (result.QueryBufferBytes != 0)
        {
            std::wcout << L" buffer=0x" << std::hex << result.QueryBufferBytes << std::dec;
        }
        if (result.QueryRetries != 0)
        {
            std::wcout << L" retries=" << result.QueryRetries;
        }
        if (!result.PrivilegeEnabled)
        {
            std::wcout << L" ";
            PrintColoredText(L"(no SeDebugPrivilege)", KNDBG_COLOR_WARN);
        }
        std::wcout << L"\n";
    } while (false);
}

static void PrintWnfHelp()
{
    std::wcout << L"!wnf command:\n";
    std::wcout << L"  !wnf decode <state-name-hash>\n";
    std::wcout << L"  !wnf instances\n";
    std::wcout << L"  !wnf instance <state-name-hash|entry-address>\n";
    std::wcout << L"  !wnf data <state-name-hash|entry-address>\n";
    std::wcout << L"  !wnf candidates\n";
    std::wcout << L"  !wnf lists\n";
    std::wcout << L"\n";
    std::wcout << L"scopes:\n";
    std::wcout << L"  decode     XOR the 64-bit raw state name against 0x41C64E6DA3BC0074 and parse Version/Lifetime/DataScope/PermanentData/Sequence/OwnerTag bit fields\n";
    std::wcout << L"  instances  walk live WNF instances through the modern LIST_ENTRY heuristic first, then legacy RTL_AVL_TABLE fallback\n";
    std::wcout << L"  instance   walk and filter by the supplied 64-bit state name or LIST_ENTRY-mode entry address\n";
    std::wcout << L"  data       walk to the matching instance and dump up to 256 bytes of its last-published WNF_STATE_DATA payload\n";
    std::wcout << L"  candidates anchor-disassembly diagnostic: dump every silo-state candidate found in the WNF entry-point functions plus the first 256 bytes at each, with kernel-pointer and state-name-shaped slot counts.\n";
    std::wcout << L"  lists      scan every silo candidate for LIST_ENTRY-shaped doubly-linked-list heads (modern Windows replaces RTL_AVL_TABLE for WNF subscription tracking with LIST_ENTRYs). Walks each non-empty chain and dumps the first 0x80 bytes per entry plus any state-name-shaped 64-bit value found within.\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  decode is standalone and always works on any build.\n";
    std::wcout << L"  LIST_ENTRY mode accepts stable entry addresses from !wnf instances and probes matched entries for _WNF_DATA_BLOCK pointers. Legacy AVL mode uses PDB-resolved WNF fields when available.\n";
    std::wcout << L"  Arguments accept hex (0x...) or decimal forms.\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  !wnf decode 0x41c64e6da3bc0075\n";
    std::wcout << L"  !wnf instances\n";
    std::wcout << L"  !wnf instance 0x41c64e6da3bc0075\n";
    std::wcout << L"  !wnf data 0x41c64e6da3bc0075\n";
}

static void PrintWnfDecodedHash(const WnfStateNameDecoded& decoded)
{
    PrintColoredText(L"[wnf.decode]", KNDBG_COLOR_TITLE);
    std::wcout << L" raw=" << HexTextWidth(decoded.Raw, 16, true)
               << L" decoded=" << HexTextWidth(decoded.Decoded, 16, true) << L"\n";
    std::wcout << L"  ";
    PrintColoredText(L"lifetime", KNDBG_COLOR_ACCENT);
    std::wcout << L"=";
    PrintColoredText(decoded.LifetimeText, KNDBG_COLOR_OK);
    std::wcout << L"(" << std::dec << decoded.Lifetime << L")";

    std::wcout << L" ";
    PrintColoredText(L"scope", KNDBG_COLOR_ACCENT);
    std::wcout << L"=";
    PrintColoredText(decoded.DataScopeText, KNDBG_COLOR_OK);
    std::wcout << L"(" << std::dec << decoded.DataScope << L")";

    std::wcout << L" version=" << std::dec << decoded.Version
               << L" permanent=" << (decoded.IsPermanent ? L"yes" : L"no") << L"\n";

    std::wcout << L"  sequence=0x" << std::hex << decoded.Sequence << std::dec
               << L" owner_tag=0x" << std::hex << decoded.OwnerTag << std::dec;
    if (!decoded.OwnerTagText.empty())
    {
        std::wcout << L"(\"" << decoded.OwnerTagText << L"\")";
    }
    std::wcout << L"\n";
}

static void PrintWnfInstance(const WnfInstanceRecord& record, bool compactSubs = false)
{
    PrintColoredText(L"[wnf.instance]", KNDBG_COLOR_TITLE);
    std::wcout << L" address=" << HexTextWidth(record.Address, 16, true);
    std::wcout << L" state=" << HexTextWidth(record.StateName, 16, true);
    std::wcout << L" lifetime=";
    PrintColoredText(record.Decoded.LifetimeText, KNDBG_COLOR_OK);
    std::wcout << L" scope=";
    PrintColoredText(record.Decoded.DataScopeText, KNDBG_COLOR_OK);
    if (!record.Decoded.OwnerTagText.empty())
    {
        std::wcout << L" owner=\"" << record.Decoded.OwnerTagText << L"\"";
    }
    if (record.HasOwningProcess)
    {
        std::wcout << L" owning=";
        if (record.HasOwningPid)
        {
            std::wcout << L"pid=";
            std::wstringstream pidStream;
            pidStream << std::dec << record.OwningPid;
            PrintColoredText(pidStream.str(), KNDBG_COLOR_OK);
        }
        if (record.HasOwningImageName)
        {
            std::wcout << L" image=\"";
            PrintColoredText(record.OwningImageName, KNDBG_COLOR_OK);
            std::wcout << L"\"";
        }
        if (!record.HasOwningPid && !record.HasOwningImageName)
        {
            std::wcout << HexTextWidth(record.OwningProcessAddress, 16, true);
        }
    }
    std::wcout << L"\n";

    if (record.HasChangeStamp || record.HasDataSize || record.HasLastDataBlock)
    {
        std::wcout << L"  ";
        if (record.HasChangeStamp)
        {
            std::wcout << L"changeStamp=0x" << std::hex << record.ChangeStamp << std::dec << L" ";
        }
        if (record.HasDataSize)
        {
            std::wcout << L"dataSize=" << std::dec << record.DataSize << L" ";
        }
        if (record.HasLastDataBlock)
        {
            std::wcout << L"lastDataBlock=" << HexTextWidth(record.LastDataBlock, 16, true);
        }
        std::wcout << L"\n";
    }

    if (!record.Subscribers.empty())
    {
        // Classify chained nodes by pool tag. Field evidence shows the
        // +0x48 chain is heterogeneous -- only Ntfc/Wnf-tagged nodes
        // are real WNF subscription records, while the rest are
        // other kernel objects sharing the same process-scope chain.
        // We count them separately and show a top-tag histogram so
        // the operator can immediately see how the chain decomposes.
        size_t trueSubs = 0;
        size_t otherObjects = 0;
        size_t unknownNodes = 0;
        size_t resolvedSubs = 0;
        std::map<std::wstring, size_t> tagHistogram;
        for (const WnfSubscriberRecord& sub : record.Subscribers)
        {
            if (sub.HasOwnPoolTag)
            {
                tagHistogram[sub.OwnPoolTag]++;
                if (sub.IsProcessCandidateTag)
                {
                    ++trueSubs;
                }
                else
                {
                    ++otherObjects;
                }
            }
            else
            {
                ++unknownNodes;
            }
            if (sub.HasProcess || sub.HasPid || sub.HasImageName)
            {
                ++resolvedSubs;
            }
        }
        std::wcout << L"  chained_nodes=" << std::dec << record.Subscribers.size()
                   << L" subscribers=" << trueSubs
                   << L" resolved=" << resolvedSubs
                   << L" other_objects=" << otherObjects;
        if (unknownNodes > 0)
        {
            std::wcout << L" unknown=" << unknownNodes;
        }
        if (!tagHistogram.empty())
        {
            std::vector<std::pair<std::wstring, size_t>> sortedTags(
                tagHistogram.begin(), tagHistogram.end());
            std::sort(sortedTags.begin(), sortedTags.end(),
                      [](const std::pair<std::wstring, size_t>& a,
                         const std::pair<std::wstring, size_t>& b)
                      {
                          if (a.second != b.second)
                          {
                              return a.second > b.second;
                          }
                          return a.first < b.first;
                      });
            constexpr size_t kMaxTags = 8;
            const size_t shown = sortedTags.size() < kMaxTags
                ? sortedTags.size()
                : kMaxTags;
            std::wcout << L" tags={";
            for (size_t i = 0; i < shown; ++i)
            {
                if (i > 0)
                {
                    std::wcout << L" ";
                }
                std::wcout << sortedTags[i].first << L":" << sortedTags[i].second;
            }
            if (sortedTags.size() > shown)
            {
                std::wcout << L" +" << (sortedTags.size() - shown) << L"more";
            }
            std::wcout << L"}";
        }
        std::wcout << L"\n";

        for (size_t i = 0; i < record.Subscribers.size(); ++i)
        {
            const WnfSubscriberRecord& sub = record.Subscribers[i];
            const bool subResolved =
                sub.HasProcess || sub.HasPid || sub.HasImageName;

            // Listing path: hide every unresolved node entirely. The
            // header stats already convey their existence; their per-
            // node hex dump would otherwise flood the output. The
            // single-entry views (Instance/Data) keep emitting every
            // node so the operator can still RE the layout.
            if (compactSubs && !subResolved)
            {
                continue;
            }

            PrintColoredText(L"  [wnf.sub]", KNDBG_COLOR_ACCENT);
            std::wcout << L" #" << std::dec << i
                       << L" node=" << HexTextWidth(sub.NodeAddress, 16, true)
                       << L" chain=+0x" << std::hex << sub.ListHeadEntryOffset << std::dec;
            if (sub.HasOwnPoolTag)
            {
                std::wcout << L" tag=\"" << sub.OwnPoolTag << L"\"";
            }
            if (sub.HasProcess)
            {
                std::wcout << L" process=" << HexTextWidth(sub.OwningProcessAddress, 16, true);
            }
            if (sub.HasPid)
            {
                std::wcout << L" pid=";
                std::wstringstream pidStream;
                pidStream << std::dec << sub.Pid;
                PrintColoredText(pidStream.str(), KNDBG_COLOR_OK);
            }
            if (sub.HasImageName)
            {
                std::wcout << L" image=\"";
                PrintColoredText(sub.ImageName, KNDBG_COLOR_OK);
                std::wcout << L"\"";
            }
            const bool isUnresolved =
                !sub.HasProcess && !sub.HasPid && !sub.HasImageName;
            if (isUnresolved)
            {
                // Tag identifies the node's kernel object type. Three
                // distinct categories drive how we annotate the line:
                //   (a) known process-subscription tag (Ntfc/Wnf*) but
                //       EPROCESS couldn't be located -> still a real
                //       subscriber, the layout just needs more RE.
                //   (b) known non-process tag (Sect/NtFs/Pnp*/AlRe/...) ->
                //       not a subscriber at all; the +0x48 chain is
                //       linking other process-scope objects through
                //       the same list head.
                //   (c) no pool tag recovered -> diagnostic case.
                if (!sub.HasOwnPoolTag)
                {
                    std::wcout << L" (unknown)";
                }
                else if (sub.IsProcessCandidateTag)
                {
                    std::wcout << L" (subscriber: unresolved)";
                }
                else
                {
                    std::wcout << L" (other-object)";
                }
            }
            std::wcout << L"\n";

            // Emit a hex dump only when EPROCESS resolution failed AND
            // the node either has no identifying pool tag or is a known
            // process-subscription candidate tag whose layout still
            // needs reverse engineering. Non-process objects (Sect,
            // NtFs, Pnp*, AlRe, SeAt, etc.) are skipped to keep the
            // listing path readable.
            const bool wantDump =
                isUnresolved && !sub.RawBytes.empty() &&
                (!sub.HasOwnPoolTag || sub.IsProcessCandidateTag);

            // For diagnostic visibility, also surface the prefix bytes
            // (0x40 bytes immediately preceding the node) whenever we
            // failed to recover an own pool tag. That tells the
            // operator where the real POOL_HEADER actually sits, or
            // confirms the node lives deeper inside a larger pooled
            // object than the heuristic currently reaches.
            const bool wantPrefixDump =
                isUnresolved && !sub.HasOwnPoolTag && !sub.PrefixBytes.empty();
            if (wantPrefixDump)
            {
                const size_t bytesPerLine = 16;
                const size_t prefixBytes = sub.PrefixBytes.size();
                for (size_t row = 0; row < prefixBytes; row += bytesPerLine)
                {
                    std::wcout << L"      pre-" << HexTextWidth(static_cast<uint64_t>(prefixBytes - row), 2, false)
                               << L"  ";
                    std::wstring asciiLine;
                    for (size_t j = 0; j < bytesPerLine; ++j)
                    {
                        if (row + j >= prefixBytes)
                        {
                            std::wcout << L"   ";
                            continue;
                        }
                        uint8_t byte = sub.PrefixBytes[row + j];
                        std::wcout << std::hex << std::setw(2) << std::setfill(L'0')
                                   << static_cast<uint32_t>(byte) << std::dec << L" ";
                        if (byte >= 0x20 && byte < 0x7f)
                        {
                            asciiLine.push_back(static_cast<wchar_t>(byte));
                        }
                        else
                        {
                            asciiLine.push_back(L'.');
                        }
                    }
                    std::wcout << L" " << asciiLine << L"\n";
                }
            }

            if (wantDump)
            {
                const size_t bytesPerLine = 16;
                const size_t dumpBytes = sub.RawBytes.size() < 0x80
                    ? sub.RawBytes.size()
                    : static_cast<size_t>(0x80);
                for (size_t row = 0; row < dumpBytes; row += bytesPerLine)
                {
                    std::wcout << L"      ";
                    std::wcout << HexTextWidth(static_cast<uint64_t>(row), 4, true) << L"  ";
                    std::wstring asciiLine;
                    for (size_t j = 0; j < bytesPerLine; ++j)
                    {
                        if (row + j >= dumpBytes)
                        {
                            std::wcout << L"   ";
                            continue;
                        }
                        uint8_t byte = sub.RawBytes[row + j];
                        std::wcout << std::hex << std::setw(2) << std::setfill(L'0')
                                   << static_cast<uint32_t>(byte) << std::dec << L" ";
                        if (byte >= 0x20 && byte < 0x7f)
                        {
                            asciiLine.push_back(static_cast<wchar_t>(byte));
                        }
                        else
                        {
                            asciiLine.push_back(L'.');
                        }
                    }
                    std::wcout << L" " << asciiLine << L"\n";
                }
            }
        }
    }
}

static void PrintWnfListHead(const WnfListHeadFinding& finding)
{
    PrintColoredText(L"[wnf.list]", KNDBG_COLOR_TITLE);
    std::wcout << L" silo=" << HexTextWidth(finding.SiloAddress, 16, true);
    std::wcout << L" head=silo+0x" << std::hex << finding.HeadOffset << std::dec;
    std::wcout << L"(" << HexTextWidth(finding.HeadAddress, 16, true) << L")";
    std::wcout << L" flink=" << HexTextWidth(finding.Flink, 16, true);
    std::wcout << L" blink=" << HexTextWidth(finding.Blink, 16, true);
    std::wcout << L" empty=" << (finding.IsEmpty ? L"yes" : L"no");
    std::wcout << L" entries=" << std::dec << finding.Entries.size() << L"\n";

    for (size_t e = 0; e < finding.Entries.size(); ++e)
    {
        const WnfListEntryWalkRecord& rec = finding.Entries[e];
        std::wcout << L"  ";
        PrintColoredText(L"entry[", KNDBG_COLOR_ACCENT);
        std::wcout << std::dec << e;
        PrintColoredText(L"]", KNDBG_COLOR_ACCENT);
        std::wcout << L" addr=" << HexTextWidth(rec.EntryAddress, 16, true);
        if (rec.HasStateName)
        {
            std::wcout << L" stateName=";
            PrintColoredText(HexTextWidth(rec.StateNameCandidate, 16, true), KNDBG_COLOR_OK);
            std::wcout << L" @+0x" << std::hex << rec.StateNameOffsetWithinEntry << std::dec;
            std::wcout << L" lifetime=" << rec.DecodedStateName.LifetimeText;
            std::wcout << L" scope=" << rec.DecodedStateName.DataScopeText;
        }
        std::wcout << L"\n";

        const size_t bytesPerLine = 16;
        // Cap visible hex dump at 0x80 bytes per entry even though
        // captured bytes may extend to 0x200 (for probe purposes).
        // Otherwise !wnf lists output would balloon 4x.
        const size_t displayBytes = rec.EntryBytes.size() < 0x80
            ? rec.EntryBytes.size()
            : static_cast<size_t>(0x80);
        for (size_t i = 0; i < displayBytes; i += bytesPerLine)
        {
            std::wcout << L"    ";
            std::wcout << HexTextWidth(static_cast<uint64_t>(i), 4, true) << L"  ";

            std::wstring asciiLine;
            for (size_t j = 0; j < bytesPerLine; ++j)
            {
                if (i + j >= displayBytes)
                {
                    std::wcout << L"   ";
                    continue;
                }
                uint8_t byte = rec.EntryBytes[i + j];
                std::wcout << std::hex << std::setw(2) << std::setfill(L'0')
                           << static_cast<uint32_t>(byte) << std::dec << L" ";
                if (byte >= 0x20 && byte < 0x7f)
                {
                    asciiLine.push_back(static_cast<wchar_t>(byte));
                }
                else
                {
                    asciiLine.push_back(L'.');
                }
            }
            std::wcout << L" " << asciiLine << L"\n";
        }

        // Verification probe: scan the FULL captured window (up to 0x200
        // bytes) for the 0x41C6XXXX_XXXXXXXX encoded WNF state name
        // fingerprint at any byte alignment. If found, this proves the
        // entry carries a full-form encoded state name and tells us
        // exactly where to read it from.
        for (size_t off = 0; off + sizeof(uint64_t) <= rec.EntryBytes.size(); ++off)
        {
            uint64_t value = 0;
            memcpy(&value, rec.EntryBytes.data() + off, sizeof(uint64_t));
            if ((value & 0xFFFF000000000000ull) != 0x41C6000000000000ull)
            {
                continue;
            }
            // Verify XOR-decode plausibility before claiming a match.
            WnfStateNameDecoded d = DecodeWnfStateName(value);
            if (d.Lifetime > 3 || d.DataScope > 5)
            {
                continue;
            }
            std::wcout << L"    ";
            PrintColoredText(L"[probe]", KNDBG_COLOR_OK);
            std::wcout << L" full-encoded @+0x" << std::hex << off
                       << L"=" << HexTextWidth(value, 16, true)
                       << L" lifetime=" << d.LifetimeText
                       << L" scope=" << d.DataScopeText;
            if (!d.OwnerTagText.empty())
            {
                std::wcout << L" owner=\"" << d.OwnerTagText << L"\"";
            }
            std::wcout << L"\n";
        }
    }
}

static void PrintWnfCandidateDump(const WnfSiloCandidateDump& dump)
{
    PrintColoredText(L"[wnf.candidate]", KNDBG_COLOR_TITLE);
    std::wcout << L" silo=" << HexTextWidth(dump.SiloAddress, 16, true);
    std::wcout << L" ptr=" << HexTextWidth(dump.PointerAddress, 16, true);
    std::wcout << L" anchor=\"" << dump.AnchorSymbol << L"\"";
    std::wcout << L"\n";

    if (!dump.NearestSymbol.empty())
    {
        std::wcout << L"  symbol=" << dump.NearestSymbol;
        if (!dump.NearestModule.empty())
        {
            std::wcout << L" module=" << dump.NearestModule;
        }
        std::wcout << L"\n";
    }

    std::wcout << L"  kernel_pointer_slots=" << std::dec << dump.KernelPointerSlots
               << L" embedded_state_name_hits=" << dump.EmbeddedStateNameHits << L"\n";

    if (dump.HeadBytes.empty())
    {
        std::wcout << L"  (head bytes unreadable)\n";
        return;
    }

    const size_t bytesPerLine = 16;
    for (size_t i = 0; i < dump.HeadBytes.size(); i += bytesPerLine)
    {
        std::wcout << L"  ";
        std::wcout << HexTextWidth(static_cast<uint64_t>(i), 4, true) << L"  ";

        std::wstring asciiLine;
        for (size_t j = 0; j < bytesPerLine; ++j)
        {
            if (i + j >= dump.HeadBytes.size())
            {
                std::wcout << L"   ";
                continue;
            }
            uint8_t byte = dump.HeadBytes[i + j];
            std::wcout << std::hex << std::setw(2) << std::setfill(L'0')
                       << static_cast<uint32_t>(byte) << std::dec << L" ";
            if (byte >= 0x20 && byte < 0x7f)
            {
                asciiLine.push_back(static_cast<wchar_t>(byte));
            }
            else
            {
                asciiLine.push_back(L'.');
            }
        }

        std::wcout << L" " << asciiLine << L"\n";
    }
}

static void PrintWnfDataDump(const WnfDataDump& data)
{
    PrintColoredText(L"[wnf.data]", KNDBG_COLOR_TITLE);
    std::wcout << L" state=" << HexTextWidth(data.StateName, 16, true)
               << L" instance=" << HexTextWidth(data.InstanceAddress, 16, true)
               << L" block=" << HexTextWidth(data.DataBlockAddress, 16, true)
               << L" size=" << std::dec << data.DataSize << L"\n";

    if (data.DataBytes.empty())
    {
        std::wcout << L"  (no bytes captured)\n";
        return;
    }

    const size_t bytesPerLine = 16;
    for (size_t i = 0; i < data.DataBytes.size(); i += bytesPerLine)
    {
        std::wcout << L"  ";
        std::wcout << HexTextWidth(static_cast<uint64_t>(i), 4, true) << L"  ";

        std::wstring asciiLine;
        for (size_t j = 0; j < bytesPerLine; ++j)
        {
            if (i + j >= data.DataBytes.size())
            {
                std::wcout << L"   ";
                continue;
            }
            uint8_t byte = data.DataBytes[i + j];
            std::wcout << std::hex << std::setw(2) << std::setfill(L'0')
                       << static_cast<uint32_t>(byte) << std::dec << L" ";
            if (byte >= 0x20 && byte < 0x7f)
            {
                asciiLine.push_back(static_cast<wchar_t>(byte));
            }
            else
            {
                asciiLine.push_back(L'.');
            }
        }

        std::wcout << L" " << asciiLine << L"\n";
    }
}

static void HandleWnfCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    do
    {
        if (HasHelpToken(args, 1))
        {
            PrintWnfHelp();
            break;
        }

        WnfScanner::Options options = {};
        options.Target = WnfScanner::Scope::Instances;

        size_t index = 1;
        if (index < args.size())
        {
            if (IsWnfScopeName(args[index]))
            {
                std::wstring scope = ToLower(args[index]);
                if (scope == L"decode")
                {
                    options.Target = WnfScanner::Scope::Decode;
                }
                else if (scope == L"instances")
                {
                    options.Target = WnfScanner::Scope::Instances;
                }
                else if (scope == L"instance")
                {
                    options.Target = WnfScanner::Scope::Instance;
                }
                else if (scope == L"data")
                {
                    options.Target = WnfScanner::Scope::Data;
                }
                else if (scope == L"candidates")
                {
                    options.Target = WnfScanner::Scope::Candidates;
                }
                else if (scope == L"lists")
                {
                    options.Target = WnfScanner::Scope::Lists;
                }
                ++index;
            }
            else
            {
                std::wcerr << L"usage: !wnf [decode|instances|instance|data|candidates|lists] [hash|entry-address]\n";
                PrintWnfHelp();
                break;
            }
        }

        bool needsHash = options.Target == WnfScanner::Scope::Decode ||
            options.Target == WnfScanner::Scope::Instance ||
            options.Target == WnfScanner::Scope::Data;

        if (needsHash)
        {
            if (index >= args.size())
            {
                std::wcerr << L"!wnf " << args[1] << L" requires a 64-bit state-name hash or LIST_ENTRY-mode entry address\n";
                break;
            }

            uint64_t parsed = 0;
            if (!ParseUnsigned(args[index], state.NumberBase, &parsed))
            {
                std::wcerr << L"!wnf: failed to parse hash/address \"" << args[index] << L"\"\n";
                break;
            }
            options.TargetHash = parsed;
            options.HasTargetHash = true;
            ++index;
        }

        if (index < args.size())
        {
            std::wcerr << L"!wnf: unexpected extra argument \"" << args[index] << L"\"\n";
            break;
        }

        if (options.Target != WnfScanner::Scope::Decode)
        {
            if (!device.IsOpen())
            {
                std::wcerr << L"!wnf live walking requires the KnLiveDbg.sys driver device to be open\n";
                break;
            }

            if (symbols.Modules().empty())
            {
                std::wstring loadError;
                if (!symbols.LoadKernelModules(&loadError))
                {
                    std::wcerr << L"!wnf failed: " << loadError << L"\n";
                    break;
                }
            }
        }

        WnfScanner scanner(device, symbols);
        WnfScanResult result = {};
        std::wstring error;
        if (!scanner.Scan(options, &result, &error))
        {
            std::wcerr << L"!wnf failed: " << error << L"\n";
            for (const std::wstring& warning : result.Warnings)
            {
                std::wcerr << L"!wnf warning: " << warning << L"\n";
            }
            if (options.Target != WnfScanner::Scope::Decode)
            {
                std::wcerr << L"!wnf diagnostics: silo_candidates_collected=" << std::dec
                           << result.SiloCandidatesCollected
                           << L" silo_candidates_after_filter=" << result.SiloCandidatesAfterFilter
                           << L" total_avl_tables_observed=" << result.TotalAvlTablesObserved
                           << L" wnf_related_avls_observed=" << result.WnfRelatedAvlsObserved << L"\n";
                for (const std::wstring& diag : result.Diagnostics)
                {
                    std::wcerr << L"!wnf diag: " << diag << L"\n";
                }
            }
            break;
        }

        for (const std::wstring& warning : result.Warnings)
        {
            std::wcerr << L"!wnf warning: " << warning << L"\n";
        }
        if (options.Target != WnfScanner::Scope::Decode &&
            (result.Diagnostics.size() > 0 || result.WnfRelatedAvlsObserved == 0))
        {
            std::wcout << L"!wnf diagnostics: silo_candidates_collected=" << std::dec
                       << result.SiloCandidatesCollected
                       << L" silo_candidates_after_filter=" << result.SiloCandidatesAfterFilter
                       << L" total_avl_tables_observed=" << result.TotalAvlTablesObserved
                       << L" wnf_related_avls_observed=" << result.WnfRelatedAvlsObserved << L"\n";
            for (const std::wstring& diag : result.Diagnostics)
            {
                std::wcout << L"!wnf diag: " << diag << L"\n";
            }
        }

        if (options.Target == WnfScanner::Scope::Decode)
        {
            PrintWnfDecodedHash(result.DecodedHash);
            break;
        }

        if (options.Target == WnfScanner::Scope::Candidates)
        {
            PrintColoredText(L"wnf candidates", KNDBG_COLOR_TITLE);
            std::wcout << L"=" << result.Candidates.size() << L"\n";
            for (const WnfSiloCandidateDump& dump : result.Candidates)
            {
                PrintWnfCandidateDump(dump);
            }
            break;
        }

        if (options.Target == WnfScanner::Scope::Lists)
        {
            PrintColoredText(L"wnf list heads", KNDBG_COLOR_TITLE);
            std::wcout << L"=" << result.ListHeads.size();
            uint32_t totalEntries = 0;
            uint32_t nonEmpty = 0;
            uint32_t withStateName = 0;
            for (const WnfListHeadFinding& f : result.ListHeads)
            {
                totalEntries += static_cast<uint32_t>(f.Entries.size());
                if (!f.IsEmpty) ++nonEmpty;
                for (const WnfListEntryWalkRecord& e : f.Entries)
                {
                    if (e.HasStateName) ++withStateName;
                }
            }
            std::wcout << L" non_empty=" << std::dec << nonEmpty
                       << L" total_entries=" << totalEntries
                       << L" entries_with_state_name=" << withStateName << L"\n";

            for (const WnfListHeadFinding& f : result.ListHeads)
            {
                PrintWnfListHead(f);
            }
            break;
        }

        PrintColoredText(L"wnf walk", KNDBG_COLOR_TITLE);
        std::wcout << L" silo_symbol=" << result.SiloStateSymbol
                   << L" silo=" << HexTextWidth(result.SiloStateAddress, 16, true)
                   << L" table_type=" << result.TableTypeName
                   << L"::" << result.TableFieldName
                   << L" table=" << HexTextWidth(result.TableAddress, 16, true)
                   << L" nodes_visited=" << std::dec << result.NodesVisited
                   << L" instances=" << result.Instances.size() << L"\n";

        // In the listing path (Scope::Instances) we hide non-subscription
        // chained objects -- their pool tag is shown in the per-entry
        // tag histogram and their hex dump would otherwise flood the
        // listing. Single-entry views (Instance / Data) still emit all
        // nodes so the operator can RE the full layout when needed.
        const bool compactSubs =
            (options.Target == WnfScanner::Scope::Instances);
        for (const WnfInstanceRecord& record : result.Instances)
        {
            PrintWnfInstance(record, compactSubs);
        }

        if (options.Target == WnfScanner::Scope::Data && result.Data.InstanceResolved)
        {
            PrintWnfDataDump(result.Data);
        }
    } while (false);
}

static void HandleUnassembleCommand(
    const std::vector<std::wstring>& args,
    const std::wstring& originalLine,
    DebuggerState& state,
    DeviceClient& device,
    DbgEngBackend& dbgeng,
    SymbolEngine& symbols)
{
    std::wstring command = NormalizeInputCommand(args[0]);
    std::wstring error;

    do
    {
        bool isFunction = command == L"uf";
        if (isFunction)
        {
            if (args.size() < 2)
            {
                std::wcerr << L"usage: uf <address|symbol> [max-instructions]\n";
                break;
            }
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
        if (isFunction)
        {
            count = 512;
        }

        std::wstring countText;
        if (args.size() >= 3)
        {
            countText = args[2];
            if (countText.size() > 1 && (countText[0] == L'L' || countText[0] == L'l'))
            {
                countText = countText.substr(1);
            }
        }

        if (args.size() >= 3 && !ParseUnsigned(countText, state.NumberBase, &count))
        {
            std::wcerr << L"invalid instruction count\n";
            break;
        }

        uint64_t maxCount = isFunction ? 4096 : 256;
        if (count == 0 || count > maxCount)
        {
            std::wcerr << L"instruction count must be between 1 and " << maxCount << L"\n";
            break;
        }

        if (device.IsOpen())
        {
            uint32_t bytesToRead = static_cast<uint32_t>(count * 16);
            std::vector<uint8_t> codeBytes;
            if (!ReadMemoryWithProcessContext(device, state, nullptr, address, bytesToRead, &codeBytes, &error))
            {
                std::wcerr << command << L" failed: driver code read failed: " << error << L"\n";
                break;
            }

            NativeDisassemblyResult nativeResult = {};
            bool disassembled = false;
            if (isFunction)
            {
                disassembled = DisassembleX64FunctionBytes(address, codeBytes, static_cast<uint32_t>(count), &nativeResult, &error);
            }
            else
            {
                disassembled = DisassembleX64CodeBytes(address, codeBytes, static_cast<uint32_t>(count), &nativeResult, &error);
            }

            if (!disassembled)
            {
                std::wcerr << command << L" failed: native disassembly failed: " << error << L"\n";
                break;
            }

            std::wcout << nativeResult.Text;
            if (!nativeResult.Text.empty() && nativeResult.Text.back() != L'\n')
            {
                std::wcout << L"\n";
            }

            state.LastDisassemblyAddress = nativeResult.NextOffset;
            state.HasLastDisassemblyAddress = true;
            break;
        }

        if (isFunction)
        {
            ExecuteDbgEngCommand(dbgeng, symbols, state, originalLine, true);
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
    stream << L"- native e* virtual writes default to System(pid 4) page-table context; use /process for a specific process\n";
    stream << L"- address arguments support arithmetic such as nt!Symbol+20 or 0xfffff80000000000-10\n";
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

static void PrintBackendHelp()
{
    std::wcout << L"backend command:\n";
    std::wcout << L"  backend [auto|native|dbgeng]\n";
    std::wcout << L"\n";
    std::wcout << L"subcommands:\n";
    std::wcout << L"  auto     prefer native implementations, route unsupported commands to DbgEng\n";
    std::wcout << L"  native   disable generic DbgEng fallback\n";
    std::wcout << L"  dbgeng   force DbgEng routing for most non-session commands\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  Session, service, callbacks, AI, native memory, dt, and u/uf commands stay intercepted by the TUI.\n";
    std::wcout << L"  Use kd <command> for a one-off raw DbgEng command without changing backend mode.\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  backend\n";
    std::wcout << L"  backend native\n";
    std::wcout << L"  backend dbgeng\n";
}

static void PrintKdInitHelp()
{
    std::wcout << L"kdinit command:\n";
    std::wcout << L"  kdinit\n";
    std::wcout << L"  kdinit /local [connect-options]\n";
    std::wcout << L"  kdinit /remote <connect-options>\n";
    std::wcout << L"\n";
    std::wcout << L"subcommands:\n";
    std::wcout << L"  /local    initialize a local live-kernel DbgEng backend\n";
    std::wcout << L"  /remote   initialize a remote-kernel DbgEng backend with connection options\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  kdinit is needed before reliable DbgEng-only command routing.\n";
    std::wcout << L"  Local live-kernel DbgEng support depends on Debugging Tools runtime availability and Windows policy.\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  kdinit\n";
    std::wcout << L"  kdinit /local\n";
    std::wcout << L"  kdinit /remote com:port=COM1,baud=115200\n";
}

static void PrintProbeHelp()
{
    std::wcout << L"probe command:\n";
    std::wcout << L"  probe [status|load [sys-path]|info|reset|unload]\n";
    std::wcout << L"\n";
    std::wcout << L"subcommands:\n";
    std::wcout << L"  status   show KnLiveDbgProbe service state and buffer addresses\n";
    std::wcout << L"  load     install/start KnLiveDbgProbe.sys from the EXE directory or sys-path\n";
    std::wcout << L"  info     query the probe buffer addresses and KNFW firmware provider state\n";
    std::wcout << L"  reset    rewrite the probe pattern\n";
    std::wcout << L"  unload   stop/delete the probe service\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  probe load\n";
    std::wcout << L"  probe info\n";
    std::wcout << L"  !fwtable provider KNFW\n";
    std::wcout << L"  probe unload\n";
}

static void PrintProcCtxHelp()
{
    std::wcout << L"procctx command:\n";
    std::wcout << L"  procctx [status|clear|<process-id>]\n";
    std::wcout << L"\n";
    std::wcout << L"subcommands:\n";
    std::wcout << L"  status       show the active process page-table context\n";
    std::wcout << L"  clear        clear the active process context\n";
    std::wcout << L"  <process-id> resolve EPROCESS, kernel DTB, and user DTB for that PID\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  d*/e*/vtop use the active context for user virtual addresses unless /process is supplied.\n";
    std::wcout << L"  /process on a single command does not change the persistent procctx setting.\n";
}

static void PrintWriteHelp()
{
    std::wcout << L"write command:\n";
    std::wcout << L"  write on|off\n";
    std::wcout << L"\n";
    std::wcout << L"subcommands:\n";
    std::wcout << L"  on    enable native write IOCTLs for the active device session\n";
    std::wcout << L"  off   disable native write IOCTLs for the active device session\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  Write mode defaults to on at startup. e* defaults to System(pid 4) context for kernel addresses.\n";
    std::wcout << L"  This is the driver session write gate; it does not validate that a target patch is semantically safe.\n";
}

static void PrintDmlProcHelp()
{
    std::wcout << L"!dml_proc command:\n";
    std::wcout << L"  !dml_proc [pid|name]\n";
    std::wcout << L"\n";
    std::wcout << L"subcommands/options:\n";
    std::wcout << L"  pid    optional decimal process ID filter, for example !dml_proc 4\n";
    std::wcout << L"  name   optional case-insensitive image-name substring, for example !dml_proc lsass\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  Native process listing that does not require a DbgEng current process/thread.\n";
    std::wcout << L"  The all-process form resolves PID 4, then walks _EPROCESS.ActiveProcessLinks.\n";
    std::wcout << L"  A decimal argument filters by PID; any other argument is an image-name substring.\n";
    std::wcout << L"  With a PID or name argument, only matching process records are printed.\n";
    std::wcout << L"  Output includes EPROCESS, PID, parent PID, active thread count, DTB, and image name.\n";
}

static void PrintVadHelp()
{
    std::wcout << L"!vad command:\n";
    std::wcout << L"  !vad <pid|image|eprocess> [/summary] [/exec] [/private] [/wx] [/pe] [/hiddenpte] [/limit <n>] [/json <path>]\n";
    std::wcout << L"\n";
    std::wcout << L"options:\n";
    std::wcout << L"  /summary   print only the summary and warnings\n";
    std::wcout << L"  /exec      show executable VADs only\n";
    std::wcout << L"  /private   show private-memory VADs only\n";
    std::wcout << L"  /wx        show writable executable VADs only\n";
    std::wcout << L"  /pe        probe private VAD first pages and show PE-like candidates only\n";
    std::wcout << L"  /hiddenpte walk process page tables and report present user PTE ranges not covered by any VAD\n";
    std::wcout << L"  /limit n   cap printed/JSON records while still walking the tree\n";
    std::wcout << L"  /json path write stable JSON output\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  The target can be a decimal PID, image name, or kernel EPROCESS address.\n";
    std::wcout << L"  Layouts are resolved from nt PDBs at runtime; drift or protected targets may produce partial warnings.\n";
    std::wcout << L"  Flags are evidence for triage, not proof of malicious injection.\n";
}

static void PrintThreadsHelp()
{
    std::wcout << L"!threads command:\n";
    std::wcout << L"  !threads <pid|image|eprocess> [/apc] [/stacks] [/limit <n>] [/json <path>]\n";
    std::wcout << L"\n";
    std::wcout << L"options:\n";
    std::wcout << L"  /apc      inspect ETHREAD APC queue fields when PDB layout is available\n";
    std::wcout << L"  /stacks   include stack base/limit fields in the table\n";
    std::wcout << L"  /limit n  cap printed/JSON records while still walking the thread list\n";
    std::wcout << L"  /json path write stable JSON output\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  The target can be a decimal PID, image name, or kernel EPROCESS address.\n";
    std::wcout << L"  User-module annotation uses the live process module snapshot when accessible.\n";
    std::wcout << L"  APC output is conservative evidence; incomplete layouts are reported as warnings.\n";
}

static void PrintVtopHelp()
{
    std::wcout << L"vtop command:\n";
    std::wcout << L"  vtop <address|symbol> [length]\n";
    std::wcout << L"  vtop /cr3 <directory-table-base> <address|symbol> [length]\n";
    std::wcout << L"  vtop /process <process-id> <address|symbol> [length]\n";
    std::wcout << L"\n";
    std::wcout << L"subcommands/options:\n";
    std::wcout << L"  /cr3       translate with an explicit directory-table base\n";
    std::wcout << L"  /process   resolve the process DTB and translate in that context\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  The output includes PML4/PML5 state, leaf entry PA, page size, and writable state.\n";
    std::wcout << L"  Without /cr3 or /process, user addresses use procctx when set; kernel addresses use the native kernel context.\n";
    std::wcout << L"  Address arguments accept + or - arithmetic such as nt!Symbol+20.\n";
    std::wcout << L"  length is bytes and is used to report the contiguous translated range.\n";
}

static void PrintDtHelp(const std::wstring& command)
{
    std::wstring name = command == L"dtx" ? L"dtx" : L"dt";

    std::wcout << name << L" command:\n";
    std::wcout << L"  " << name << L" [-rN] [-v] [-b] <type|type-pattern> [address|symbol] [field-filter...]\n";
    std::wcout << L"\n";
    std::wcout << L"options:\n";
    std::wcout << L"  -r      recurse one level into nested UDT fields\n";
    std::wcout << L"  -rN     recurse N levels\n";
    std::wcout << L"  -v      print verbose type metadata\n";
    std::wcout << L"  -b      bare field/type names where possible\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  Wildcard type patterns such as nt!* enumerate matching type names only.\n";
    std::wcout << L"  Exact type names can dump field layouts and read field values when an address is supplied.\n";
    std::wcout << L"  Address arguments accept + or - arithmetic such as nt!Symbol+20 or 0xffff`0000-10.\n";
    std::wcout << L"  nt! is treated as the loaded kernel image, including ntoskrnl/ntkrnlmp PDB names.\n";
    std::wcout << L"  Field filters match field names or field type names case-insensitively.\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  " << name << L" nt!_EPROCESS\n";
    std::wcout << L"  " << name << L" nt!_EPROCESS <address> UniqueProcessId ActiveProcessLinks\n";
    std::wcout << L"  " << name << L" nt!*\n";
}

static void PrintDisassemblyHelp()
{
    std::wcout << L"disassembly commands:\n";
    std::wcout << L"  u [address|symbol] [instruction-count]\n";
    std::wcout << L"  uf <address|symbol> [max-instructions]\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  u disassembles forward and remembers the next address.\n";
    std::wcout << L"  uf uses native byte reads when the driver is open, then follows local branch targets.\n";
    std::wcout << L"  Address arguments accept + or - arithmetic such as nt!Symbol+20.\n";
    std::wcout << L"  u defaults to 8 instructions and caps explicit counts at 256.\n";
    std::wcout << L"  uf defaults to 512 instructions and caps explicit counts at 4096.\n";
}

static void PrintDisplayHelp(const std::wstring& command)
{
    std::wcout << L"display memory commands:\n";
    std::wcout << L"  " << command << L" [/process <process-id>] <address|symbol> [count]\n";
    std::wcout << L"\n";
    std::wcout << L"families:\n";
    std::wcout << L"  d/db/da/dc/dd/df/dp/dq/du/dw/dyb/dyd\n";
    std::wcout << L"  dda/ddp/ddu/dpa/dpp/dpu/dqa/dqp/dqu\n";
    std::wcout << L"  dds/dps/dqs\n";
    std::wcout << L"\n";
    std::wcout << L"options:\n";
    std::wcout << L"  /process <process-id>  read in a process page-table context\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  count is element count for unit dumps and character count for string dumps.\n";
    std::wcout << L"  Address arguments accept + or - arithmetic such as nt!Symbol+20.\n";
    std::wcout << L"  unreadable bytes are shown as ?? when sparse reads can continue.\n";
    std::wcout << L"  dds/dps/dqs annotate values with nearest loaded symbols.\n";
}

static void PrintEnterHelp(const std::wstring& command)
{
    std::wcout << L"enter memory commands:\n";
    std::wcout << L"  " << command << L" [/process <process-id>] <address|symbol> <value...>\n";
    std::wcout << L"  " << command << L" [/process <process-id>] <address|symbol>\n";
    std::wcout << L"\n";
    std::wcout << L"families:\n";
    std::wcout << L"  e/eb/ew/ed/ef/ep/eq write integer values\n";
    std::wcout << L"  ea/eu write strings\n";
    std::wcout << L"  eza/ezu write zero-terminated strings\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  Address-only form prompts for replacement bytes. Kernel virtual writes use System(pid 4) context by default.\n";
    std::wcout << L"  /process <process-id> writes through that process page table for this command only.\n";
    std::wcout << L"  Address arguments accept + or - arithmetic such as nt!Symbol+20.\n";
    std::wcout << L"  Read-only leaf PTEs are temporarily marked writable, flushed, written, and restored.\n";
    std::wcout << L"  Integer values are little-endian and clipped to the command width.\n";
}

static void PrintPhysicalDisplayHelp(const std::wstring& command)
{
    std::wcout << L"physical display commands:\n";
    std::wcout << L"  " << command << L" <physical-address> [count]\n";
    std::wcout << L"\n";
    std::wcout << L"families:\n";
    std::wcout << L"  phys/pdb display bytes\n";
    std::wcout << L"  pdw/pdd/pdq display words, dwords, or qwords\n";
    std::wcout << L"  !db/!dw/!dd/!dq display physical bytes, words, dwords, or qwords\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  count is element count; phys, pdb, and !db default to byte dumps.\n";
    std::wcout << L"  Unreadable physical bytes are shown as ?? when sparse reads can continue.\n";
}

static void PrintPhysicalEnterHelp(const std::wstring& command)
{
    std::wcout << L"physical enter commands:\n";
    std::wcout << L"  " << command << L" <physical-address> [value...]\n";
    std::wcout << L"  " << command << L" <physical-address>\n";
    std::wcout << L"\n";
    std::wcout << L"families:\n";
    std::wcout << L"  peb/pew/ped/peq write bytes, words, dwords, or qwords\n";
    std::wcout << L"  !eb/!ew/!ed/!eq write physical bytes, words, dwords, or qwords\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  Address-only form prompts with the current physical value, like WinDbg eb-style editing.\n";
    std::wcout << L"  Physical writes bypass process page-table context and use the physical address directly.\n";
    std::wcout << L"  Integer values are little-endian and clipped to the command width.\n";
}

static void PrintSearchHelp()
{
    std::wcout << L"search command:\n";
    std::wcout << L"  s [-b|-w|-d|-q] <address> <length> <value...>\n";
    std::wcout << L"\n";
    std::wcout << L"options:\n";
    std::wcout << L"  -b   byte pattern\n";
    std::wcout << L"  -w   word pattern\n";
    std::wcout << L"  -d   dword pattern\n";
    std::wcout << L"  -q   qword pattern\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  length is bytes; value tokens are encoded using the selected pattern width.\n";
    std::wcout << L"  -b is the default when no width option is supplied.\n";
}

static void PrintCompareHelp()
{
    std::wcout << L"compare command:\n";
    std::wcout << L"  c <address1> <address2> <length>\n";
}

static void PrintFillHelp()
{
    std::wcout << L"fill command:\n";
    std::wcout << L"  f <address> <length> <byte-pattern...>\n";
    std::wcout << L"  fp <address> <length> <pointer-pattern...>\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  length is bytes; the pattern repeats until the target range is filled.\n";
}

static void PrintMoveHelp()
{
    std::wcout << L"move command:\n";
    std::wcout << L"  m <source> <destination> <length>\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  length is bytes; the command reads the source range first, then writes destination.\n";
}

static void PrintSetFieldHelp()
{
    std::wcout << L"setfield command:\n";
    std::wcout << L"  setfield <type> <address|symbol> <field> <value>\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  Resolves the field offset from symbols and writes the scalar value at address + offset.\n";
    std::wcout << L"  Use dt <type> <address> <field> first to confirm field layout and current value.\n";
}

static void PrintNumberBaseHelp()
{
    std::wcout << L"n command:\n";
    std::wcout << L"  n [10|16]\n";
    std::wcout << L"\n";
    std::wcout << L"subcommands:\n";
    std::wcout << L"  10   use decimal input base for unprefixed numeric values\n";
    std::wcout << L"  16   use hexadecimal input base for unprefixed numeric values\n";
}

static void PrintQuietHelp()
{
    std::wcout << L"sq command:\n";
    std::wcout << L"  sq [true|false]\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  Toggles quiet-mode state used by native output paths that honor it.\n";
}

static void PrintLogHelp()
{
    std::wcout << L"log command:\n";
    std::wcout << L"  log [enable|disable|status]\n";
    std::wcout << L"  log [on|off|start|stop]\n";
    std::wcout << L"\n";
    std::wcout << L"subcommands:\n";
    std::wcout << L"  enable|on|start     mirror console output to a new UTF-8 log file in the EXE directory\n";
    std::wcout << L"  disable|off|stop    flush, close, and detach the active log file\n";
    std::wcout << L"  status              show whether logging is active and print the current path\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  The live console keeps colors; the log file receives clean text without console attributes.\n";
    std::wcout << L"  The default subcommand is status.\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  log enable\n";
    std::wcout << L"  log status\n";
    std::wcout << L"  log disable\n";
}

static void PrintSymbolHelp(const std::wstring& command)
{
    std::wcout << L"symbol command:\n";
    if (command == L".sympath" || command == L"sympath")
    {
        std::wcout << L"  .sympath [path]\n";
        std::wcout << L"  sympath [path]\n";
        std::wcout << L"  Show or replace the current symbol path.\n";
    }
    else if (command == L".sympath+")
    {
        std::wcout << L"  .sympath+ <path>\n";
        std::wcout << L"  Append to the current symbol path.\n";
    }
    else if (command == L".reload" || command == L"reload" || command == L"ld")
    {
        std::wcout << L"  .reload\n";
        std::wcout << L"  reload\n";
        std::wcout << L"  ld\n";
        std::wcout << L"  Reload kernel module information and symbols.\n";
    }
    else if (command == L"lm" || command == L"modules")
    {
        std::wcout << L"  lm [filter]\n";
        std::wcout << L"  modules [filter]\n";
        std::wcout << L"  List loaded kernel modules; filter matches image names case-insensitively.\n";
    }
    else if (command == L"x")
    {
        std::wcout << L"  x <module!mask>\n";
        std::wcout << L"  Enumerate symbols matching a DbgHelp-style wildcard mask.\n";
    }
    else
    {
        std::wcout << L"  ln <symbol|address>\n";
        std::wcout << L"  addr <symbol|address>\n";
        std::wcout << L"  Resolve an expression and print the nearest loaded symbol.\n";
    }
}

static void PrintSessionHelp(const std::wstring& command)
{
    std::wstring name = command;

    if (name == L"||" || name == L"||s")
    {
        std::wcout << L"target command:\n";
        std::wcout << L"  ||\n";
        std::wcout << L"  ||s\n";
        std::wcout << L"  Show local live-memory system target status.\n";
    }
    else if (name == L"|")
    {
        std::wcout << L"target command:\n";
        std::wcout << L"  |\n";
        std::wcout << L"  Show the current native process context summary.\n";
    }
    else if (name == L"q" || name == L"qq" || name == L"qd" || name == L"quit" || name == L"exit")
    {
        std::wcout << L"quit commands:\n";
        std::wcout << L"  q | qq | qd | quit | exit\n";
        std::wcout << L"  Close the device handle, stop/delete the main driver service, then exit.\n";
    }
    else if (name == L"unload")
    {
        std::wcout << L"unload command:\n";
        std::wcout << L"  unload\n";
        std::wcout << L"  Stop/delete the main driver service, then exit.\n";
    }
    else if (name == L"home" || name == L"dashboard")
    {
        std::wcout << L"dashboard commands:\n";
        std::wcout << L"  home\n";
        std::wcout << L"  dashboard\n";
        std::wcout << L"  Redraw the startup dashboard.\n";
    }
    else if (name == L"cls")
    {
        std::wcout << L"cls command:\n";
        std::wcout << L"  cls\n";
        std::wcout << L"  Clear the console screen and return the cursor to the top-left cell.\n";
    }
    else if (name == L"drvstatus")
    {
        std::wcout << L"drvstatus command:\n";
        std::wcout << L"  drvstatus\n";
        std::wcout << L"  Show SCM state, active controller PID, handle count, and write mode.\n";
    }
    else if (name == L"version" || name == L"vertarget" || name == L"vercommand")
    {
        std::wcout << L"version commands:\n";
        std::wcout << L"  version\n";
        std::wcout << L"  vertarget\n";
        std::wcout << L"  vercommand\n";
        std::wcout << L"  Show tool, driver ABI, target Windows, or command identity information.\n";
    }
    else if (name == L"kd")
    {
        std::wcout << L"kd command:\n";
        std::wcout << L"  kd <windbg-command>\n";
        std::wcout << L"  Execute a raw DbgEng command independent of backend mode.\n";
    }
    else if (name == L"kddetach")
    {
        std::wcout << L"kddetach command:\n";
        std::wcout << L"  kddetach\n";
        std::wcout << L"  Shut down the current DbgEng backend instance.\n";
    }
}

static void PrintQueryHelp()
{
    std::wcout << L"query command:\n";
    std::wcout << L"  query <address|symbol> [length]\n";
    std::wcout << L"  Ask the driver for a native virtual-address range summary.\n";
    std::wcout << L"  length is bytes and defaults to one byte.\n";
}

static void PrintAiHelp()
{
    std::wcout << L"ai command:\n";
    std::wcout << L"  ai <question>\n";
    std::wcout << L"  ai <subcommand> [args...]\n";
    std::wcout << L"\n";
    std::wcout << L"primary subcommands:\n";
    std::wcout << L"  status       show provider, model, credential, and policy state\n";
    std::wcout << L"  config       configure provider, policy, model, base URL, effort, or auth\n";
    std::wcout << L"  plan         explicitly ask AI to produce executable command proposals\n";
    std::wcout << L"  run          execute planned read-only commands\n";
    std::wcout << L"  write        preview or confirm a planned write-like command\n";
    std::wcout << L"  explain      explicitly run a read-only command and ask AI to explain the output\n";
    std::wcout << L"  analyze      explicitly run a read-only command and ask AI for an analysis report\n";
    std::wcout << L"  show         show the loaded AI plan\n";
    std::wcout << L"  report       write a session report\n";
    std::wcout << L"\n";
    std::wcout << L"examples:\n";
    std::wcout << L"  ai a.exe pid\n";
    std::wcout << L"  ai a.exe eprocess\n";
    std::wcout << L"  ai WdFilter.sys object callbacks\n";
    std::wcout << L"  ai pid 1234 dtb\n";
    std::wcout << L"  ai callbacks all WdFilter.sys\n";
    std::wcout << L"  ai uf nt!PspCreateProcessNotifyRoutine 128\n";
    std::wcout << L"  ai check VBS status\n";
    std::wcout << L"  ai !ci options\n";
    std::wcout << L"  ai explain !module integrity all /summary\n";
    std::wcout << L"  ai analyze !wnf candidates\n";
    std::wcout << L"  ai config provider openrouter\n";
    std::wcout << L"  ai config test\n";
    std::wcout << L"\n";
    std::wcout << L"notes:\n";
    std::wcout << L"  Prefer ai <goal>. It auto-routes local tools, read-only evidence analysis, or command planning.\n";
    std::wcout << L"  Exact read-only commands such as callbacks, dt, u, !ci, or !vbs are treated as evidence to explain.\n";
    std::wcout << L"  ai plan and ai explain still work as explicit overrides when you want that mode.\n";
    std::wcout << L"  API-key providers load .env only from the EXE directory.\n";
    std::wcout << L"  ai run executes read-only validated plan commands; write-like commands require ai write confirm.\n";
    std::wcout << L"  Legacy detailed commands still work; use ai help <topic> when needed.\n";
}

static bool PrintAiSubcommandHelp(const std::wstring& action)
{
    bool handled = true;
    std::wstring name = ToLower(action);

    if (name == L"status")
    {
        std::wcout << L"ai status:\n";
        std::wcout << L"  ai status\n";
        std::wcout << L"  Show current AI provider runtime settings.\n";
    }
    else if (name == L"config")
    {
        std::wcout << L"ai config:\n";
        std::wcout << L"  ai config [status]\n";
        std::wcout << L"  ai config providers\n";
        std::wcout << L"  ai config provider <openai-codex-cli|openai-codex-subscription|deepseek|openrouter|off>\n";
        std::wcout << L"  ai config policy <allow-remote|local-only|status>\n";
        std::wcout << L"  ai config model <model>\n";
        std::wcout << L"  ai config base-url <url>\n";
        std::wcout << L"  ai config effort <minimal|low|medium|high|xhigh>\n";
        std::wcout << L"  ai config auth\n";
        std::wcout << L"  ai config test [prompt]\n";
        std::wcout << L"  Groups provider setup and connectivity checks under one visible subcommand.\n";
    }
    else if (name == L"providers")
    {
        std::wcout << L"ai providers:\n";
        std::wcout << L"  ai providers\n";
        std::wcout << L"  List provider names accepted by ai provider.\n";
    }
    else if (name == L"provider")
    {
        std::wcout << L"ai provider:\n";
        std::wcout << L"  ai provider <openai-codex-cli|openai-codex-subscription|deepseek|openrouter|off>\n";
        std::wcout << L"  API-key providers read credentials from .env beside KnLiveDbg.exe.\n";
        std::wcout << L"  DeepSeek uses DEEPSEEK_API_KEY; OpenRouter uses OPENROUTER_API_KEY.\n";
    }
    else if (name == L"policy")
    {
        std::wcout << L"ai policy:\n";
        std::wcout << L"  ai policy <allow-remote|local-only|status>\n";
        std::wcout << L"  local-only blocks remote API providers.\n";
    }
    else if (name == L"model")
    {
        std::wcout << L"ai model:\n";
        std::wcout << L"  ai model <model>\n";
        std::wcout << L"  Sets the provider model string without changing provider.\n";
        std::wcout << L"  The accepted model names depend on the selected provider.\n";
    }
    else if (name == L"base-url")
    {
        std::wcout << L"ai base-url:\n";
        std::wcout << L"  ai base-url <url>\n";
        std::wcout << L"  Sets an OpenAI-compatible API base URL for providers that support it.\n";
    }
    else if (name == L"effort")
    {
        std::wcout << L"ai effort:\n";
        std::wcout << L"  ai effort <minimal|low|medium|high|xhigh>\n";
        std::wcout << L"  Sets reasoning effort for compatible providers.\n";
    }
    else if (name == L"auth")
    {
        std::wcout << L"ai auth:\n";
        std::wcout << L"  ai auth\n";
        std::wcout << L"  Prints provider login and .env credential guidance.\n";
    }
    else if (name == L"preview" || name == L"ask")
    {
        std::wcout << L"ai " << name << L":\n";
        std::wcout << L"  ai preview <prompt>\n";
        std::wcout << L"  ai ask <prompt>\n";
        std::wcout << L"  preview prints the request locally; ask sends it to the selected provider.\n";
        std::wcout << L"  If the prompt is literally help, use ai ask \"help\" or ai help ask to avoid ambiguity.\n";
    }
    else if (name == L"plan")
    {
        std::wcout << L"ai plan:\n";
        std::wcout << L"  ai plan <prompt>\n";
        std::wcout << L"  Builds a validated read/write command plan for later ai run or ai write.\n";
    }
    else if (name == L"analyze")
    {
        std::wcout << L"ai analyze:\n";
        std::wcout << L"  ai analyze <read-only-command...>\n";
        std::wcout << L"  ai analyze callbacks [all|object|registry|process|thread|imageload|minifilter] [module]\n";
        std::wcout << L"  ai analyze callbacks [scope] /module <module>\n";
        std::wcout << L"  Runs a read-only evidence command and asks AI for an analysis report.\n";
        std::wcout << L"  Callback analysis remains available for compatibility.\n";
    }
    else if (name == L"explain")
    {
        std::wcout << L"ai explain:\n";
        std::wcout << L"  ai explain <read-only-command...>\n";
        std::wcout << L"  ai explain callbacks [all|object|registry|process|thread|imageload|minifilter] [module]\n";
        std::wcout << L"  ai explain dt <dt-args...>\n";
        std::wcout << L"  ai explain dtx <dtx-args...>\n";
        std::wcout << L"  ai explain <u|uf> <address|symbol> [instruction-count]\n";
        std::wcout << L"  ai explain !module integrity all /summary\n";
        std::wcout << L"  ai explain !wnf data <state-name-hash|entry-address>\n";
        std::wcout << L"  Runs a read-only evidence command and asks AI to explain fields, callbacks, or disassembly.\n";
    }
    else if (name == L"annotate")
    {
        std::wcout << L"ai annotate:\n";
        std::wcout << L"  ai annotate <u|uf> <address|symbol> [instruction-count]\n";
        std::wcout << L"  Runs native disassembly and asks AI to annotate likely behavior.\n";
    }
    else if (name == L"diagnose")
    {
        std::wcout << L"ai diagnose:\n";
        std::wcout << L"  ai diagnose <symbol/backend/type failure or operator note>\n";
    }
    else if (name == L"playbook")
    {
        std::wcout << L"ai playbook:\n";
        std::wcout << L"  ai playbook <callbacks|minifilter|object|address|driver> [argument] [run|dry-run]\n";
        std::wcout << L"  Generates investigation commands; run executes read-only plan items immediately.\n";
    }
    else if (name == L"show")
    {
        std::wcout << L"ai show:\n";
        std::wcout << L"  ai show\n";
        std::wcout << L"  Show the current parsed AI command plan.\n";
    }
    else if (name == L"run")
    {
        std::wcout << L"ai run:\n";
        std::wcout << L"  ai run <index|all>\n";
        std::wcout << L"  Execute planned commands that passed read-only validation.\n";
        std::wcout << L"  Session mutation, unload, backend changes, and write-like commands are blocked.\n";
    }
    else if (name == L"write")
    {
        std::wcout << L"ai write:\n";
        std::wcout << L"  ai write <index>\n";
        std::wcout << L"  ai write <index> confirm\n";
        std::wcout << L"  Preview backup/translation/verify commands before operator-confirmed writes.\n";
    }
    else if (name == L"transcript")
    {
        std::wcout << L"ai transcript:\n";
        std::wcout << L"  ai transcript <path|off|status>\n";
        std::wcout << L"  ai transcript max <bytes|off>\n";
        std::wcout << L"  ai transcript redact <on|off>\n";
    }
    else if (name == L"audit")
    {
        std::wcout << L"ai audit:\n";
        std::wcout << L"  ai audit <path|off|status>\n";
        std::wcout << L"  Records write-like AI command decisions.\n";
    }
    else if (name == L"report")
    {
        std::wcout << L"ai report:\n";
        std::wcout << L"  ai report <path>\n";
        std::wcout << L"  Writes a human-readable AI session report.\n";
    }
    else
    {
        handled = false;
    }

    return handled;
}

static void PrintAiHelpFromArgs(const std::vector<std::wstring>& args, size_t first)
{
    size_t index = first;

    if (index < args.size() && IsHelpToken(args[index]))
    {
        ++index;
    }

    if (index < args.size())
    {
        if (!PrintAiSubcommandHelp(args[index]))
        {
            std::wcerr << L"unknown ai help topic: " << args[index] << L"\n";
            PrintAiHelp();
        }
    }
    else
    {
        PrintAiHelp();
    }
}

static bool IsAiPromptPayloadAction(const std::wstring& action)
{
    return action == L"ask" || action == L"preview" || action == L"plan" || action == L"diagnose";
}

static bool IsAiSubcommandHelpRequest(const std::vector<std::wstring>& args, const std::wstring& action)
{
    bool help = false;

    do
    {
        if (args.size() < 3)
        {
            break;
        }

        if (IsAiPromptPayloadAction(action))
        {
            help = args.size() == 3 && IsHelpToken(args[2]);
            break;
        }

        for (size_t index = 2; index < args.size(); ++index)
        {
            if (IsHelpToken(args[index]))
            {
                help = true;
                break;
            }
        }
    } while (false);

    return help;
}

static bool PrintDetailedCommandHelp(const std::vector<std::wstring>& args, size_t commandIndex)
{
    bool handled = true;

    do
    {
        if (commandIndex >= args.size())
        {
            handled = false;
            break;
        }

        std::wstring command = CompletionCanonicalCommand(args[commandIndex]);
        size_t detailIndex = commandIndex + 1;
        if (detailIndex < args.size() && IsHelpToken(args[detailIndex]))
        {
            ++detailIndex;
        }

        if (command == L"help" || command == L"?")
        {
            PrintHelp(false);
        }
        else if (command == L"callbacks")
        {
            PrintCallbacksHelpFromArgs(args, detailIndex);
        }
        else if (command == L"ai")
        {
            PrintAiHelpFromArgs(args, detailIndex);
        }
        else if (command == L"backend")
        {
            PrintBackendHelp();
        }
        else if (command == L"kdinit")
        {
            PrintKdInitHelp();
        }
        else if (command == L"probe")
        {
            PrintProbeHelp();
        }
        else if (command == L"procctx")
        {
            PrintProcCtxHelp();
        }
        else if (command == L"write")
        {
            PrintWriteHelp();
        }
        else if (command == L"!dml_proc")
        {
            PrintDmlProcHelp();
        }
        else if (command == L"!vad")
        {
            PrintVadHelp();
        }
        else if (command == L"!threads")
        {
            PrintThreadsHelp();
        }
        else if (command == L"!snapshot")
        {
            PrintSnapshotHelp();
        }
        else if (command == L"!diff")
        {
            PrintDiffHelp();
        }
        else if (command == L"!wfp")
        {
            PrintWfpHelp();
        }
        else if (command == L"!alpc")
        {
            PrintAlpcHelp();
        }
        else if (command == L"byovd" || command == L"!byovd")
        {
            PrintByovdHelp();
        }
        else if (command == L"!vbs")
        {
            PrintVbsHelp();
        }
        else if (command == L"!ci")
        {
            PrintCiHelp();
        }
        else if (command == L"!securekernel")
        {
            PrintSecureKernelHelp();
        }
        else if (command == L"!etw")
        {
            PrintEtwHelp();
        }
        else if (command == L"!nmi")
        {
            PrintNmiHelp();
        }
        else if (command == L"!msrcheck")
        {
            PrintMsrCheckHelp();
        }
        else if (command == L"!cr")
        {
            PrintCrCheckHelp();
        }
        else if (command == L"!ssdt")
        {
            PrintSsdtHelp();
        }
        else if (command == L"!idt")
        {
            PrintIdtHelp();
        }
        else if (command == L"!fwtable")
        {
            PrintFirmwareTableHelp();
        }
        else if (command == L"!module")
        {
            PrintModuleIntegrityHelp();
        }
        else if (command == L"!driver")
        {
            PrintDriverIntegrityHelp();
        }
        else if (command == L"!pool")
        {
            PrintPoolHelp();
        }
        else if (command == L"dump-raw")
        {
            PrintDumpRawHelp();
        }
        else if (command == L"dump-pe")
        {
            PrintDumpPeHelp();
        }
        else if (command == L"pool-scan-pe")
        {
            PrintPoolScanPeHelp();
        }
        else if (command == L"!address")
        {
            PrintAddressHelp();
        }
        else if (command == L"set-ppl-antimalware")
        {
            PrintSetPplAntimalwareHelp();
        }
        else if (command == L"!ti")
        {
            PrintTiHelp();
        }
        else if (command == L"!wnf")
        {
            PrintWnfHelp();
        }
        else if (command == L"vtop")
        {
            PrintVtopHelp();
        }
        else if (command == L"dt" || command == L"dtx")
        {
            PrintDtHelp(command);
        }
        else if (command == L"u" || command == L"uf")
        {
            PrintDisassemblyHelp();
        }
        else if (IsDisplayCommand(command))
        {
            PrintDisplayHelp(command);
        }
        else if (IsEnterCommand(command))
        {
            PrintEnterHelp(command);
        }
        else if (IsPhysicalDisplayCommand(command))
        {
            PrintPhysicalDisplayHelp(command);
        }
        else if (IsPhysicalEnterCommand(command))
        {
            PrintPhysicalEnterHelp(command);
        }
        else if (command == L"s")
        {
            PrintSearchHelp();
        }
        else if (command == L"c")
        {
            PrintCompareHelp();
        }
        else if (command == L"f" || command == L"fp")
        {
            PrintFillHelp();
        }
        else if (command == L"m")
        {
            PrintMoveHelp();
        }
        else if (command == L"setfield")
        {
            PrintSetFieldHelp();
        }
        else if (command == L"n")
        {
            PrintNumberBaseHelp();
        }
        else if (command == L"sq")
        {
            PrintQuietHelp();
        }
        else if (command == L"log")
        {
            PrintLogHelp();
        }
        else if (command == L".sympath" || command == L"sympath" || command == L".sympath+" ||
                 command == L".reload" || command == L"reload" || command == L"ld" ||
                 command == L"lm" || command == L"modules" || command == L"x" ||
                 command == L"ln" || command == L"addr")
        {
            PrintSymbolHelp(command);
        }
        else if (command == L"query")
        {
            PrintQueryHelp();
        }
        else if (command == L"home" || command == L"dashboard" || command == L"drvstatus" ||
                 command == L"version" || command == L"vertarget" || command == L"vercommand" ||
                 command == L"kd" || command == L"kddetach" || command == L"unload" ||
                 command == L"||" || command == L"||s" || command == L"|" ||
                 command == L"q" || command == L"qq" || command == L"qd" ||
                 command == L"quit" || command == L"exit" || command == L"cls")
        {
            PrintSessionHelp(command);
        }
        else
        {
            handled = false;
        }
    } while (false);

    return handled;
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

// ASCII case-insensitive keyword match at a given offset. Used to spot
// provider-agnostic credential markers ("Bearer ", "Authorization") that do
// not start with the "sk-" prefix, such as ChatGPT/Codex OAuth JWTs and
// OpenRouter session tokens.
static bool MatchesKeywordCI(const std::wstring& value, size_t index, const wchar_t* keyword)
{
    bool matched = true;

    for (size_t k = 0; keyword[k] != L'\0'; ++k)
    {
        if (index + k >= value.size())
        {
            matched = false;
            break;
        }

        wchar_t a = value[index + k];
        wchar_t b = keyword[k];
        if (a >= L'A' && a <= L'Z')
        {
            a = static_cast<wchar_t>(a - L'A' + L'a');
        }
        if (b >= L'A' && b <= L'Z')
        {
            b = static_cast<wchar_t>(b - L'A' + L'a');
        }
        if (a != b)
        {
            matched = false;
            break;
        }
    }

    return matched;
}

static std::wstring RedactTranscriptText(const std::wstring& value)
{
    std::wstring result;

    for (size_t index = 0; index < value.size();)
    {
        if (MatchesKeywordCI(value, index, L"Bearer "))
        {
            // HTTP bearer token: redact the token that follows the scheme.
            result += L"Bearer <redacted>";
            index += 7; // length of "Bearer "
            while (index < value.size() && (value[index] == L' ' || value[index] == L'\t'))
            {
                ++index;
            }
            while (index < value.size() && IsSecretTokenChar(value[index]))
            {
                ++index;
            }
        }
        else if (MatchesKeywordCI(value, index, L"Authorization"))
        {
            // Only treat this as a header when a colon follows; otherwise it is
            // ordinary text and must be preserved verbatim.
            size_t scan = index + 13; // length of "Authorization"
            while (scan < value.size() && (value[scan] == L' ' || value[scan] == L'\t'))
            {
                ++scan;
            }

            if (scan < value.size() && value[scan] == L':')
            {
                result += L"Authorization: <redacted>";
                ++scan; // past ':'
                while (scan < value.size() && value[scan] != L'\r' && value[scan] != L'\n')
                {
                    ++scan;
                }
                index = scan;
            }
            else
            {
                result.append(value, index, 13);
                index += 13;
            }
        }
        else if (index + 3 <= value.size() &&
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

static bool ExtractJsonScalarValue(const std::wstring& json, const std::wstring& key, std::wstring* value)
{
    bool ok = false;
    std::wstring pattern = L"\"" + key + L"\"";
    size_t pos = json.find(pattern);

    do
    {
        if (value == nullptr)
        {
            break;
        }

        if (ExtractJsonStringValue(json, key, value))
        {
            ok = true;
            break;
        }

        if (pos == std::wstring::npos)
        {
            break;
        }

        size_t colon = json.find(L':', pos + pattern.size());
        if (colon == std::wstring::npos)
        {
            break;
        }

        size_t start = colon + 1;
        while (start < json.size() && iswspace(json[start]) != 0)
        {
            ++start;
        }

        size_t end = start;
        while (end < json.size() &&
               json[end] != L',' &&
               json[end] != L'}' &&
               json[end] != L']' &&
               iswspace(json[end]) == 0)
        {
            ++end;
        }

        if (end > start)
        {
            *value = TrimWhitespace(json.substr(start, end - start));
            ok = !value->empty();
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

static bool ExtractJsonObjectValue(const std::wstring& json, const std::wstring& key, std::wstring* value)
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

        size_t start = colon + 1;
        while (start < json.size() && iswspace(json[start]) != 0)
        {
            ++start;
        }

        if (start >= json.size() || json[start] != L'{')
        {
            break;
        }

        bool inString = false;
        bool escaped = false;
        int depth = 0;
        for (size_t index = start; index < json.size(); ++index)
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
                ++depth;
            }
            else if (ch == L'}')
            {
                --depth;
                if (depth == 0)
                {
                    *value = json.substr(start, index - start + 1);
                    ok = true;
                    break;
                }
            }
        }
    } while (false);

    return ok;
}

static std::vector<std::wstring> ExtractJsonStringArrayValues(const std::wstring& json, const std::wstring& key)
{
    std::vector<std::wstring> values;
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
        int arrayDepth = 0;
        for (size_t index = bracket; index < json.size(); ++index)
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

            if (ch == L'[')
            {
                ++arrayDepth;
                continue;
            }

            if (ch == L']')
            {
                --arrayDepth;
                if (arrayDepth == 0)
                {
                    break;
                }
                continue;
            }

            if (arrayDepth == 1 && ch == L'\"')
            {
                std::wstring value;
                size_t next = index + 1;
                if (ParseJsonStringAt(json, index, &value, &next))
                {
                    values.push_back(value);
                    index = next - 1;
                }
            }
        }
    } while (false);

    return values;
}

static std::vector<std::wstring> ExtractJsonObjectKeys(const std::wstring& json)
{
    std::vector<std::wstring> keys;
    int objectDepth = 0;
    bool inString = false;
    bool escaped = false;

    for (size_t index = 0; index < json.size(); ++index)
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
            if (objectDepth == 1)
            {
                std::wstring key;
                size_t next = index + 1;
                if (!ParseJsonStringAt(json, index, &key, &next))
                {
                    break;
                }

                size_t probe = next;
                while (probe < json.size() && iswspace(json[probe]) != 0)
                {
                    ++probe;
                }

                if (probe < json.size() && json[probe] == L':')
                {
                    keys.push_back(ToLower(key));
                }

                index = next - 1;
                continue;
            }

            inString = true;
            continue;
        }

        if (ch == L'{')
        {
            ++objectDepth;
            continue;
        }
        if (ch == L'}')
        {
            --objectDepth;
            if (objectDepth < 0)
            {
                break;
            }
            continue;
        }
    }

    return keys;
}

static bool JsonKeyAllowed(const std::wstring& key, const std::vector<std::wstring>& allowed)
{
    bool found = false;

    for (const std::wstring& candidate : allowed)
    {
        if (key == candidate)
        {
            found = true;
            break;
        }
    }

    return found;
}

static bool ValidateJsonObjectKeys(
    const std::wstring& json,
    const std::vector<std::wstring>& allowed,
    const std::wstring& context,
    std::wstring* error)
{
    bool ok = true;
    std::vector<std::wstring> keys = ExtractJsonObjectKeys(json);

    for (const std::wstring& key : keys)
    {
        if (!JsonKeyAllowed(key, allowed))
        {
            ok = false;
            if (error != nullptr)
            {
                *error = context + L" contains unsupported field: " + key;
            }
            break;
        }
    }

    return ok;
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

static bool IsAiSessionMutationCommand(const std::wstring& command)
{
    bool blocked = false;

    if (command == L"backend" ||
        command == L"kdinit" ||
        command == L"kddetach" ||
        command == L"cls" ||
        command == L"probe")
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
        if (IsNativeBangCommand(command))
        {
            backend = L"native";
            break;
        }

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
        command == L"pdq" ||
        command == L"!db" ||
        command == L"!dw" ||
        command == L"!dd" ||
        command == L"!dq")
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
            if (IsPhysicalDisplayCommand(command))
            {
                commandClass = L"physical-read";
                break;
            }

            if (command == L"!dml_proc")
            {
                commandClass = L"process";
                break;
            }

            if (command == L"!vad" || command == L"!threads")
            {
                commandClass = L"process-triage";
                break;
            }

            if (command == L"!wfp")
            {
                commandClass = L"wfp";
                break;
            }

            if (command == L"!alpc")
            {
                commandClass = L"alpc";
                break;
            }

            if (command == L"!vbs" || command == L"!ci" || command == L"!securekernel")
            {
                commandClass = L"vbs";
                break;
            }

            if (command == L"!etw")
            {
                commandClass = L"etw";
                break;
            }

            if (command == L"!nmi")
            {
                commandClass = L"nmi";
                break;
            }

            if (command == L"!fwtable")
            {
                commandClass = L"firmware-table";
                break;
            }

            if (command == L"!module" || command == L"!driver")
            {
                commandClass = L"integrity";
                break;
            }

            if (command == L"!pool")
            {
                commandClass = L"pool";
                break;
            }

            if (command == L"!wnf")
            {
                commandClass = L"wnf";
                break;
            }

            commandClass = L"dbgeng";
            break;
        }

        if (command == L"backend" || command == L"kdinit" || command == L"kddetach" ||
            command == L"drvstatus" || command == L"unload" || command == L"q" ||
            command == L"qq" || command == L"qd" || command == L"quit" || command == L"exit" ||
            command == L"version" || command == L"vertarget" || command == L"vercommand" ||
            command == L"home" || command == L"dashboard" || command == L"cls")
        {
            commandClass = L"session";
            break;
        }

        if (command == L"dt" || command == L"dtx")
        {
            commandClass = L"type";
            break;
        }

        if (command == L"callbacks")
        {
            commandClass = L"callbacks";
            break;
        }

        if (command == L"!dml_proc")
        {
            commandClass = L"process";
            break;
        }

        if (command == L"!vad" || command == L"!threads")
        {
            commandClass = L"process-triage";
            break;
        }

        if (command == L"!wfp")
        {
            commandClass = L"wfp";
            break;
        }

        if (command == L"!alpc")
        {
            commandClass = L"alpc";
            break;
        }

        if (command == L"!vbs" || command == L"!ci" || command == L"!securekernel")
        {
            commandClass = L"vbs";
            break;
        }

        if (command == L"!etw")
        {
            commandClass = L"etw";
            break;
        }

        if (command == L"!nmi")
        {
            commandClass = L"nmi";
            break;
        }

        if (command == L"!fwtable")
        {
            commandClass = L"firmware-table";
            break;
        }

        if (command == L"!module" || command == L"!driver")
        {
            commandClass = L"integrity";
            break;
        }

        if (command == L"!pool")
        {
            commandClass = L"pool";
            break;
        }

        if (command == L"!wnf")
        {
            commandClass = L"wnf";
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
        if (command == L"!vtop")
        {
            if (reason != nullptr)
            {
                *reason = L"unsupported command; use vtop";
            }
            break;
        }

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

        if (IsAiSessionMutationCommand(command))
        {
            if (reason != nullptr)
            {
                if (command == L"probe")
                {
                    *reason = L"probe service control is not allowed in AI plans";
                }
                else
                {
                    *reason = L"backend/session mutation commands are not allowed in AI plans";
                }
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
            if (inner == L"ai" ||
                IsShutdownOrUnloadCommand(inner) ||
                IsAiSessionMutationCommand(inner))
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

static bool ValidateCallbackCommandArgumentShape(
    const std::vector<std::wstring>& args,
    std::wstring* reason)
{
    bool ok = false;

    do
    {
        size_t index = 1;
        bool hasModuleFilter = false;

        if (args.size() <= index)
        {
            ok = true;
            break;
        }

        if (IsCallbackScopeName(args[index]))
        {
            ++index;
        }
        else if (IsDeprecatedCallbackScopeAlias(args[index]) ||
                 IsDeprecatedCallbackModuleOption(args[index]))
        {
            if (reason != nullptr)
            {
                *reason = L"callback command uses a deprecated alias; use all, object, registry, process, thread, imageload, minifilter, and /module";
            }
            break;
        }

        while (index < args.size())
        {
            if (IsCallbackModuleOption(args[index]))
            {
                if (index + 1 >= args.size())
                {
                    if (reason != nullptr)
                    {
                        *reason = L"callback /module option requires a module name";
                    }
                    break;
                }

                if (hasModuleFilter)
                {
                    if (reason != nullptr)
                    {
                        *reason = L"callback command has more than one module filter";
                    }
                    break;
                }

                hasModuleFilter = true;
                index += 2;
                continue;
            }

            if (IsDeprecatedCallbackScopeAlias(args[index]) ||
                IsDeprecatedCallbackModuleOption(args[index]) ||
                IsSwitchLikeToken(args[index]))
            {
                if (reason != nullptr)
                {
                    *reason = L"callback command uses an unsupported option or deprecated alias";
                }
                break;
            }

            if (hasModuleFilter)
            {
                if (reason != nullptr)
                {
                    *reason = L"callback command has more than one module filter";
                }
                break;
            }

            hasModuleFilter = true;
            ++index;
        }

        ok = index >= args.size();
    } while (false);

    return ok;
}

static bool ValidateFirmwareTableCommandArgumentShape(
    const std::vector<std::wstring>& args,
    std::wstring* reason)
{
    bool ok = false;

    do
    {
        size_t index = 1;
        std::wstring scope = L"providers";

        if (index < args.size())
        {
            if (!IsFirmwareTableScopeName(args[index]))
            {
                if (reason != nullptr)
                {
                    *reason = L"!fwtable scope must be providers or provider";
                }
                break;
            }

            scope = ToLower(args[index]);
            ++index;
        }

        if (scope == L"provider")
        {
            if (index >= args.size() || IsSwitchLikeToken(args[index]))
            {
                if (reason != nullptr)
                {
                    *reason = L"!fwtable provider requires a signature";
                }
                break;
            }
            ++index;
            if (index < args.size())
            {
                if (reason != nullptr)
                {
                    *reason = L"!fwtable provider takes no arguments after the signature";
                }
                break;
            }
        }
        else
        {
            bool hasModule = false;
            while (index < args.size())
            {
                if (!IsFirmwareTableOption(args[index]) ||
                    index + 1 >= args.size() ||
                    IsSwitchLikeToken(args[index + 1]))
                {
                    if (reason != nullptr)
                    {
                        *reason = L"!fwtable providers supports only /module <name>";
                    }
                    break;
                }

                if (hasModule)
                {
                    if (reason != nullptr)
                    {
                        *reason = L"!fwtable providers accepts only one /module filter";
                    }
                    break;
                }

                hasModule = true;
                index += 2;
            }

            if (index < args.size())
            {
                break;
            }
        }

        ok = true;
    } while (false);

    return ok;
}

static bool ValidateVadCommandArgumentShape(
    const std::vector<std::wstring>& args,
    std::wstring* reason)
{
    bool ok = false;

    do
    {
        if (args.size() < 2)
        {
            if (reason != nullptr)
            {
                *reason = L"!vad requires a process target";
            }
            break;
        }

        if (IsSwitchLikeToken(args[1]))
        {
            if (reason != nullptr)
            {
                *reason = L"!vad target must be a pid, image name, or eprocess address";
            }
            break;
        }

        if (args[1].find_first_of(L"<>|") != std::wstring::npos)
        {
            if (reason != nullptr)
            {
                *reason = L"!vad target must be a concrete pid, image name, or eprocess address, not a placeholder";
            }
            break;
        }

        size_t index = 2;
        bool shapeOk = true;
        while (index < args.size())
        {
            std::wstring option = ToLower(args[index]);
            if (option == L"/summary" ||
                option == L"/exec" ||
                option == L"/private" ||
                option == L"/wx" ||
                option == L"/pe" ||
                option == L"/hiddenpte" ||
                option == L"/hidden" ||
                option == L"/dkom")
            {
                ++index;
                continue;
            }

            if (option == L"/limit" || option == L"/json")
            {
                if (index + 1 >= args.size() || IsSwitchLikeToken(args[index + 1]))
                {
                    if (reason != nullptr)
                    {
                        *reason = L"!vad " + option + L" requires a value";
                    }
                    shapeOk = false;
                    break;
                }

                index += 2;
                continue;
            }

            if (reason != nullptr)
            {
                *reason = L"!vad supports /summary, /exec, /private, /wx, /pe, /hiddenpte, /limit, and /json options";
            }
            shapeOk = false;
            break;
        }

        if (!shapeOk)
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool ValidateThreadsCommandArgumentShape(
    const std::vector<std::wstring>& args,
    std::wstring* reason)
{
    bool ok = false;

    do
    {
        if (args.size() < 2)
        {
            if (reason != nullptr)
            {
                *reason = L"!threads requires a process target";
            }
            break;
        }

        if (IsSwitchLikeToken(args[1]))
        {
            if (reason != nullptr)
            {
                *reason = L"!threads target must be a pid, image name, or eprocess address";
            }
            break;
        }

        if (args[1].find_first_of(L"<>|") != std::wstring::npos)
        {
            if (reason != nullptr)
            {
                *reason = L"!threads target must be a concrete pid, image name, or eprocess address, not a placeholder";
            }
            break;
        }

        size_t index = 2;
        bool shapeOk = true;
        while (index < args.size())
        {
            std::wstring option = ToLower(args[index]);
            if (option == L"/apc" || option == L"/stacks")
            {
                ++index;
                continue;
            }

            if (option == L"/limit" || option == L"/json")
            {
                if (index + 1 >= args.size() || IsSwitchLikeToken(args[index + 1]))
                {
                    if (reason != nullptr)
                    {
                        *reason = L"!threads " + option + L" requires a value";
                    }
                    shapeOk = false;
                    break;
                }

                index += 2;
                continue;
            }

            if (reason != nullptr)
            {
                *reason = L"!threads supports /apc, /stacks, /limit, and /json options";
            }
            shapeOk = false;
            break;
        }

        if (!shapeOk)
        {
            break;
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
        else if (IsDisplayCommand(command))
        {
            if (args.size() >= 2)
            {
                if (IsDeprecatedProcessContextOption(args[1]))
                {
                    if (reason != nullptr)
                    {
                        *reason = L"memory command uses deprecated /pid option; use /process";
                    }
                    break;
                }

                if (IsSwitchLikeToken(args[1]) && !IsProcessContextOption(args[1]))
                {
                    if (reason != nullptr)
                    {
                        *reason = L"memory command uses an unsupported option";
                    }
                    break;
                }

                if (IsProcessContextOption(args[1]) && args.size() < 4)
                {
                    if (reason != nullptr)
                    {
                        *reason = L"memory /process option requires process id and address";
                    }
                    break;
                }
            }
        }
        else if (IsEnterCommand(command))
        {
            if (args.size() < 3)
            {
                if (reason != nullptr)
                {
                    *reason = L"write command requires target and at least one value";
                }
                break;
            }

            if (IsDeprecatedProcessContextOption(args[1]))
            {
                if (reason != nullptr)
                {
                    *reason = L"write command uses deprecated /pid option; use /process";
                }
                break;
            }

            if (IsSwitchLikeToken(args[1]) && !IsProcessContextOption(args[1]))
            {
                if (reason != nullptr)
                {
                    *reason = L"write command uses an unsupported option";
                }
                break;
            }

            if (IsProcessContextOption(args[1]) && args.size() < 5)
            {
                if (reason != nullptr)
                {
                    *reason = L"write /process option requires process id, target, and value";
                }
                break;
            }
        }
        else if (IsPhysicalEnterCommand(command))
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
            if (IsDeprecatedProcessContextOption(option))
            {
                if (reason != nullptr)
                {
                    *reason = L"vtop command uses deprecated /pid option; use /process";
                }
                break;
            }

            if (IsSwitchLikeToken(option) && option != L"/cr3" && !IsProcessContextOption(option))
            {
                if (reason != nullptr)
                {
                    *reason = L"vtop command uses an unsupported option";
                }
                break;
            }

            if ((option == L"/cr3" || option == L"/process") && args.size() < 4)
            {
                if (reason != nullptr)
                {
                    *reason = L"vtop option requires context value and address";
                }
                break;
            }
        }
        else if (command == L"callbacks")
        {
            if (!ValidateCallbackCommandArgumentShape(args, reason))
            {
                break;
            }
        }
        else if (command == L"!dml_proc")
        {
            if (args.size() > 2)
            {
                if (reason != nullptr)
                {
                    *reason = L"!dml_proc accepts at most one PID or name argument";
                }
                break;
            }

            if (args.size() == 2)
            {
                uint64_t pid = 0;
                std::wstring unsafeReason;
                if (!ParseDmlProcessPidFilter(args[1], &pid) &&
                    (ContainsUnsafeAiCommandCharacters(args[1], &unsafeReason) ||
                     IsHelpToken(args[1]) || IsSwitchLikeToken(args[1])))
                {
                    if (reason != nullptr)
                    {
                        *reason = L"!dml_proc argument must be a decimal PID or a plain image-name substring";
                    }
                    break;
                }
            }
        }
        else if (command == L"!vad")
        {
            if (!ValidateVadCommandArgumentShape(args, reason))
            {
                break;
            }
        }
        else if (command == L"!threads")
        {
            if (!ValidateThreadsCommandArgumentShape(args, reason))
            {
                break;
            }
        }
        else if (command == L"!wfp")
        {
            size_t index = 1;
            if (index < args.size())
            {
                if (!IsWfpScopeName(args[index]) && !IsWfpOption(args[index]))
                {
                    if (reason != nullptr)
                    {
                        *reason = L"!wfp scope must be providers, sublayers, callouts, filters, or layers";
                    }
                    break;
                }

                if (IsWfpScopeName(args[index]))
                {
                    ++index;
                }
            }

            bool optionShapeOk = true;
            while (index < args.size())
            {
                if (!IsWfpOption(args[index]) ||
                    index + 1 >= args.size() ||
                    IsSwitchLikeToken(args[index + 1]))
                {
                    if (reason != nullptr)
                    {
                        *reason = L"!wfp option requires /module|/layer|/provider followed by a value";
                    }
                    optionShapeOk = false;
                    break;
                }
                index += 2;
            }

            if (!optionShapeOk)
            {
                break;
            }
        }
        else if (command == L"!vbs" || command == L"!securekernel")
        {
            if (args.size() > 1)
            {
                if (reason != nullptr)
                {
                    *reason = command + L" takes no arguments";
                }
                break;
            }
        }
        else if (command == L"!ci")
        {
            if (args.size() > 2)
            {
                if (reason != nullptr)
                {
                    *reason = L"!ci accepts at most one subcommand (options|policy)";
                }
                break;
            }
            if (args.size() == 2 && !IsCiScopeName(args[1]))
            {
                if (reason != nullptr)
                {
                    *reason = L"!ci scope must be options or policy";
                }
                break;
            }
        }
        else if (command == L"!etw")
        {
            if (args.size() == 1)
            {
                // bare !etw defaults to loggers
            }
            else if (args.size() >= 2 && !IsEtwScopeName(args[1]))
            {
                if (reason != nullptr)
                {
                    *reason = L"!etw scope must be loggers or logger";
                }
                break;
            }
            else if (args.size() >= 2 && ToLower(args[1]) == L"loggers")
            {
                if (args.size() > 2)
                {
                    if (reason != nullptr)
                    {
                        *reason = L"!etw loggers takes no extra arguments";
                    }
                    break;
                }
            }
            else if (args.size() >= 2 && ToLower(args[1]) == L"logger")
            {
                if (args.size() != 3)
                {
                    if (reason != nullptr)
                    {
                        *reason = L"!etw logger requires exactly one index-or-name argument";
                    }
                    break;
                }
            }
            else if (args.size() >= 2 && ToLower(args[1]) == L"integrity")
            {
                if (args.size() > 2)
                {
                    if (reason != nullptr)
                    {
                        *reason = L"!etw integrity takes no extra arguments";
                    }
                    break;
                }
            }
        }
        else if (command == L"!nmi")
        {
            if (args.size() > 2)
            {
                if (reason != nullptr)
                {
                    *reason = L"!nmi accepts at most one subcommand (callbacks)";
                }
                break;
            }
            if (args.size() == 2 && !IsNmiScopeName(args[1]))
            {
                if (reason != nullptr)
                {
                    *reason = L"!nmi scope must be callbacks";
                }
                break;
            }
        }
        else if (command == L"!fwtable")
        {
            if (!ValidateFirmwareTableCommandArgumentShape(args, reason))
            {
                break;
            }
        }
        else if (command == L"!module" || command == L"!driver")
        {
            if (args.size() < 2 || ToLower(args[1]) != L"integrity")
            {
                if (reason != nullptr)
                {
                    *reason = command + L" scope must be integrity";
                }
                break;
            }

            size_t i = 2;
            bool hasTarget = false;
            bool shapeOk = true;
            while (i < args.size())
            {
                std::wstring option = ToLower(args[i]);
                if (command == L"!module" &&
                    (option == L"/summary" ||
                     option == L"/verbose" ||
                     option == L"/headers" ||
                     option == L"/sections" ||
                     option == L"/wx" ||
                     option == L"/mismatch"))
                {
                    ++i;
                    continue;
                }
                if (option == L"/limit" || option == L"/json")
                {
                    if (i + 1 >= args.size() || IsSwitchLikeToken(args[i + 1]))
                    {
                        if (reason != nullptr)
                        {
                            *reason = command + L" " + option + L" requires a value";
                        }
                        shapeOk = false;
                        break;
                    }
                    i += 2;
                    continue;
                }
                if (IsSwitchLikeToken(args[i]))
                {
                    if (reason != nullptr)
                    {
                        if (command == L"!module")
                        {
                            *reason = command + L" supports /summary, /verbose, /headers, /sections, /wx, /mismatch, /limit, and /json options";
                        }
                        else
                        {
                            *reason = command + L" supports only /limit and /json options";
                        }
                    }
                    shapeOk = false;
                    break;
                }
                if (hasTarget)
                {
                    if (reason != nullptr)
                    {
                        *reason = command + L" integrity accepts only one target filter";
                    }
                    shapeOk = false;
                    break;
                }
                hasTarget = true;
                ++i;
            }
            if (!shapeOk)
            {
                break;
            }
        }
        else if (command == L"!pool")
        {
            size_t i = 1;
            bool shapeOk = true;
            if (i < args.size() && IsPoolScopeName(args[i]))
            {
                ++i;
            }
            while (i < args.size())
            {
                std::wstring option = ToLower(args[i]);
                if (!IsPoolOption(option))
                {
                    if (reason != nullptr)
                    {
                        *reason = L"!pool argument must be a scope name or /option";
                    }
                    shapeOk = false;
                    break;
                }

                if (option == L"/tag" ||
                    option == L"/min" ||
                    option == L"/max" ||
                    option == L"/addr" ||
                    option == L"/limit")
                {
                    if (i + 1 >= args.size() || IsSwitchLikeToken(args[i + 1]))
                    {
                        if (reason != nullptr)
                        {
                            *reason = L"!pool " + option + L" requires a value";
                        }
                        shapeOk = false;
                        break;
                    }

                    i += 2;
                    continue;
                }

                ++i;
            }
            if (!shapeOk)
            {
                break;
            }
        }
        else if (command == L"!wnf")
        {
            size_t i = 1;
            if (i < args.size())
            {
                if (!IsWnfScopeName(args[i]))
                {
                    if (reason != nullptr)
                    {
                        *reason = L"!wnf scope must be decode, instances, instance, data, candidates, or lists";
                    }
                    break;
                }
                std::wstring scope = ToLower(args[i]);
                ++i;
                bool needsHash = (scope == L"decode" || scope == L"instance" || scope == L"data");
                if (scope == L"candidates" || scope == L"lists")
                {
                    // candidates/lists take no extra args
                    if (i < args.size())
                    {
                        if (reason != nullptr)
                        {
                            *reason = L"!wnf " + scope + L" takes no extra arguments";
                        }
                        break;
                    }
                }
                if (needsHash)
                {
                    if (i >= args.size() || IsSwitchLikeToken(args[i]))
                    {
                        if (reason != nullptr)
                        {
                            *reason = L"!wnf " + scope + L" requires a hash/address argument";
                        }
                        break;
                    }
                    ++i;
                }
                if (i < args.size())
                {
                    if (reason != nullptr)
                    {
                        *reason = L"!wnf takes no extra arguments after the hash/address";
                    }
                    break;
                }
            }
        }
        else if (command == L"!alpc")
        {
            size_t index = 1;
            bool requiresAddress = false;
            if (index < args.size())
            {
                if (!IsAlpcScopeName(args[index]) && !IsAlpcOption(args[index]))
                {
                    if (reason != nullptr)
                    {
                        *reason = L"!alpc scope must be ports, port, connections, or queues";
                    }
                    break;
                }

                if (IsAlpcScopeName(args[index]))
                {
                    std::wstring lowered = ToLower(args[index]);
                    if (lowered == L"port" || lowered == L"queues")
                    {
                        requiresAddress = true;
                    }
                    ++index;
                }
            }

            if (requiresAddress)
            {
                if (index >= args.size() || IsAlpcOption(args[index]))
                {
                    if (reason != nullptr)
                    {
                        *reason = L"!alpc port|queues requires an address argument";
                    }
                    break;
                }
                ++index;
            }

            bool optionShapeOk = true;
            while (index < args.size())
            {
                if (!IsAlpcOption(args[index]) ||
                    index + 1 >= args.size() ||
                    IsSwitchLikeToken(args[index + 1]))
                {
                    if (reason != nullptr)
                    {
                        *reason = L"!alpc option requires /name|/pid followed by a value";
                    }
                    optionShapeOk = false;
                    break;
                }
                index += 2;
            }

            if (!optionShapeOk)
            {
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
        if (ContainsUnsafeAiCommandCharacters(line, reason))
        {
            blocked = true;
            break;
        }

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

        if (IsAiSessionMutationCommand(command))
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
            if (inner == L"ai" ||
                IsShutdownOrUnloadCommand(inner) ||
                IsAiSessionMutationCommand(inner))
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
    stream << L"- Prefer read-only commands such as lm, ln, x, d*, dt, callbacks, !dml_proc, !vad, !threads, !wfp, !alpc, !vbs, !ci, !securekernel, !etw, !nmi, !fwtable, !wnf, vtop, pdb, !db, u, uf, and kd for raw DbgEng.\n";
    stream << L"- For VAD DKOM or hidden PTE checks, use !vad target /hiddenpte where target is a concrete PID, image name, or EPROCESS address. Add /summary or /limit <n> when the operator asks for concise output.\n";
    stream << L"- Use one command per JSON item. Do not use semicolon command chaining or multiline commands.\n";
    stream << L"- Do not use backend, kdinit, kddetach, cls, probe service control, q, quit, exit, unload, or nested ai commands in plans.\n";
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
            g_CommandStreamOutputSerial.fetch_add(1, std::memory_order_relaxed);
        }

        if (target_ != nullptr)
        {
            std::lock_guard<std::recursive_mutex> lock(g_ConsoleOutputMutex);
            return target_->sputc(ch);
        }

        return value;
    }

    std::streamsize xsputn(const wchar_t* text, std::streamsize count) override
    {
        if (capture_ != nullptr && text != nullptr && count > 0)
        {
            capture_->append(text, static_cast<size_t>(count));
            g_CommandStreamOutputSerial.fetch_add(1, std::memory_order_relaxed);
        }

        if (target_ != nullptr)
        {
            std::lock_guard<std::recursive_mutex> lock(g_ConsoleOutputMutex);
            return target_->sputn(text, count);
        }

        return count;
    }

    int sync() override
    {
        if (target_ != nullptr)
        {
            std::lock_guard<std::recursive_mutex> lock(g_ConsoleOutputMutex);
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

static bool TryGetEnterCommandArgumentIndexes(
    const std::vector<std::wstring>& commandArgs,
    size_t* addressIndex,
    size_t* valueIndex)
{
    bool ok = false;

    do
    {
        if (addressIndex == nullptr || valueIndex == nullptr || commandArgs.size() < 3)
        {
            break;
        }

        size_t index = 1;
        if (IsProcessContextOption(commandArgs[index]))
        {
            if (commandArgs.size() < 5)
            {
                break;
            }

            index += 2;
        }

        if (index >= commandArgs.size() || index + 1 >= commandArgs.size())
        {
            break;
        }

        *addressIndex = index;
        *valueIndex = index + 1;
        ok = true;
    } while (false);

    return ok;
}

static bool EstimateEnterWriteSize(const std::vector<std::wstring>& commandArgs, uint64_t* byteCount)
{
    bool ok = false;

    do
    {
        size_t addressIndex = 0;
        size_t valueIndex = 0;
        if (byteCount == nullptr ||
            !TryGetEnterCommandArgumentIndexes(commandArgs, &addressIndex, &valueIndex))
        {
            break;
        }

        std::wstring command = NormalizeInputCommand(commandArgs[0]);
        if (command == L"ea" || command == L"eza" || command == L"eu" || command == L"ezu")
        {
            std::wstring value = JoinArgs(commandArgs, valueIndex);
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

        uint64_t count = static_cast<uint64_t>(commandArgs.size() - valueIndex);
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
        uint64_t width = static_cast<uint64_t>(UnitWidthForPhysicalEnterCommand(command));

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
            size_t addressIndex = 0;
            size_t valueIndex = 0;
            if (!TryGetEnterCommandArgumentIndexes(commandArgs, &addressIndex, &valueIndex))
            {
                plan.Warning = L"cannot build write safety plan: enter command has too few arguments";
                break;
            }

            (void)valueIndex;

            uint64_t address = 0;
            std::wstring error;
            bool resolved = ParseAddressOrSymbol(symbols, state, commandArgs[addressIndex], &address, &error);
            uint64_t byteCount = 0;
            EstimateEnterWriteSize(commandArgs, &byteCount);

            bool hasExplicitContext = addressIndex >= 3 && IsProcessContextOption(commandArgs[1]);
            std::wstring contextPrefix = hasExplicitContext ? L"/process " + commandArgs[2] + L" " : L"/process 4 ";
            plan.TargetKind = hasExplicitContext ? L"virtual-process" : L"virtual-kernel-system";
            plan.Target = resolved ? HexText(address) : commandArgs[addressIndex];
            plan.Target += hasExplicitContext ? L" pid=" + commandArgs[2] : L" pid=4(default)";
            plan.ByteCountText = ByteCountText(byteCount);
            plan.BackupCommand = L"db " + contextPrefix + commandArgs[addressIndex] + L" " + std::to_wstring(byteCount == 0 ? 16 : byteCount);
            plan.VerifyCommand = plan.BackupCommand;
            plan.TranslationCommand = L"vtop " + contextPrefix + commandArgs[addressIndex] + L" " + std::to_wstring(byteCount == 0 ? 1 : byteCount);
            plan.Warning = L"virtual write: native e* defaults to System(pid 4) page-table context; verify page ownership, target module, and whether the range touches code, callbacks, list links, or reference counts";
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
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    bool* physical,
    uint64_t* address,
    uint64_t* byteCount,
    ProcessAddressContext* addressContext,
    bool* hasAddressContext)
{
    bool ok = false;
    std::vector<std::wstring> commandArgs = Split(commandLine);

    do
    {
        if (physical == nullptr || address == nullptr || byteCount == nullptr ||
            addressContext == nullptr || hasAddressContext == nullptr || commandArgs.empty())
        {
            break;
        }

        *physical = false;
        *address = 0;
        *byteCount = 0;
        *addressContext = ProcessAddressContext{};
        *hasAddressContext = false;

        std::wstring command = NormalizeInputCommand(commandArgs[0]);
        std::wstring error;
        if (IsEnterCommand(command))
        {
            size_t addressIndex = 0;
            size_t valueIndex = 0;
            if (!TryGetEnterCommandArgumentIndexes(commandArgs, &addressIndex, &valueIndex) ||
                !ParseAddressOrSymbol(symbols, state, commandArgs[addressIndex], address, &error) ||
                !EstimateEnterWriteSize(commandArgs, byteCount))
            {
                break;
            }

            (void)valueIndex;

            if (addressIndex >= 3 && IsProcessContextOption(commandArgs[1]))
            {
                uint64_t processId = 0;
                if (!ParseUnsigned(commandArgs[2], 10, &processId) ||
                    processId == 0 ||
                    processId > 0xffffffffull ||
                    !ResolveProcessAddressContext(device, symbols, static_cast<uint32_t>(processId), addressContext, &error))
                {
                    break;
                }
            }
            else if (!EnsureKernelProcessAddressContext(state, device, symbols, addressContext, &error))
            {
                break;
            }

            *hasAddressContext = true;
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
    DebuggerState& state,
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
        ProcessAddressContext addressContext = {};
        bool hasAddressContext = false;
        if (!ResolveWriteTargetForRestore(
                commandLine,
                state,
                device,
                symbols,
                &physical,
                &address,
                &byteCount,
                &addressContext,
                &hasAddressContext))
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
        bool readOk = false;
        if (physical)
        {
            readOk = device.ReadPhysical(address, static_cast<uint32_t>(byteCount), &bytes, &error);
        }
        else if (hasAddressContext)
        {
            readOk = ReadProcessVirtualMemory(device, addressContext, address, static_cast<uint32_t>(byteCount), &bytes, &error);
        }
        else
        {
            readOk = device.ReadMemory(address, static_cast<uint32_t>(byteCount), &bytes, &error);
        }

        if (!readOk)
        {
            std::wstring note = L"restore read failed: " + error;
            plan->Warning = plan->Warning.empty() ? note : plan->Warning + L"; " + note;
            break;
        }

        std::wstring restorePrefix = physical ? L"peb" : L"eb";
        if (!physical && hasAddressContext)
        {
            restorePrefix += L" /process " + std::to_wstring(addressContext.ProcessId);
        }

        plan->RestoreCommand = BuildByteRestoreCommand(restorePrefix, address, bytes);
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

struct AiEvidenceAnalysisMetadata
{
    std::wstring EventName;
    std::wstring Title;
    std::wstring Instructions;
};

static AiEvidenceAnalysisMetadata BuildAiEvidenceAnalysisMetadata(
    const std::wstring& commandLine,
    const std::wstring& defaultEventName)
{
    AiEvidenceAnalysisMetadata metadata = {};
    metadata.EventName = defaultEventName;
    metadata.Title = L"Explain this KnLiveDbg command output.";
    metadata.Instructions = L"Explain the important fields, anomalies, uncertainty, and concrete follow-up commands. Preserve raw addresses and values.";

    std::vector<std::wstring> commandArgs = Split(commandLine);
    if (!commandArgs.empty())
    {
        std::wstring topic = ToLower(NormalizeInputCommand(commandArgs[0]));
        if (topic == L"callbacks")
        {
            metadata.EventName = defaultEventName + L"_callbacks";
            metadata.Title = L"Analyze this KnLiveDbg kernel callback scan.";
            metadata.Instructions = L"Produce a callback analysis report from this KnLiveDbg callback scan output. Count records by surface, group by module, decode process notify metadata, call out image-load notify owners, non-image owners, missing symbols, unusual minifilter metadata, shared module ownership across surfaces, and concrete follow-up commands. Preserve raw addresses and confidence notes.";
        }
        if (topic == L"dt" || topic == L"dtx")
        {
            metadata.EventName = defaultEventName + L"_dt";
            metadata.Title = L"Explain this KnLiveDbg dt/dtx structure output.";
            metadata.Instructions = L"Explain important fields, pointer and LIST_ENTRY follow-ups, suspicious null or out-of-module values, and exact commands to inspect referenced fields. Keep raw offsets and values auditable.";
        }

        if (topic == L"u" || topic == L"uf")
        {
            metadata.EventName = defaultEventName + L"_disassembly";
            metadata.Title = L"Annotate this KnLiveDbg disassembly.";
            metadata.Instructions = L"Summarize likely routine purpose, call targets, direct and indirect call evidence, callback/dispatch/minifilter/process/thread/image-load classification hints, suspicious code patterns, uncertainty, and next commands such as ln, x, dt, dq, or uf.";
        }
    }

    return metadata;
}

static bool IsAiEvidenceCommandName(const std::wstring& command)
{
    bool evidenceCommand = false;
    std::wstring normalized = ToLower(NormalizeInputCommand(command));

    do
    {
        if (normalized == L"callbacks" ||
            normalized == L"dt" ||
            normalized == L"dtx" ||
            normalized == L"u" ||
            normalized == L"uf" ||
            normalized == L"ln" ||
            normalized == L"lm" ||
            normalized == L"x" ||
            normalized == L"vtop" ||
            normalized == L"!dml_proc" ||
            normalized == L"!vad" ||
            normalized == L"!threads" ||
            normalized == L"!wfp" ||
            normalized == L"!alpc" ||
            normalized == L"!vbs" ||
            normalized == L"!ci" ||
            normalized == L"!securekernel" ||
            normalized == L"!etw" ||
            normalized == L"!nmi" ||
            normalized == L"!msrcheck" ||
            normalized == L"!cr" ||
            normalized == L"!ssdt" ||
            normalized == L"!idt" ||
            normalized == L"!fwtable" ||
            normalized == L"!module" ||
            normalized == L"!driver" ||
            normalized == L"!pool" ||
            normalized == L"!address" ||
            normalized == L"!wnf")
        {
            evidenceCommand = true;
            break;
        }
    } while (false);

    return evidenceCommand;
}

static bool IsAiEvidenceCommandLine(const std::wstring& commandLine)
{
    std::vector<std::wstring> args = Split(commandLine);
    return !args.empty() && IsAiEvidenceCommandName(args[0]);
}

static bool TryBuildImplicitAiEvidenceCommand(const std::wstring& query, std::wstring* commandLine)
{
    bool built = false;

    do
    {
        if (commandLine == nullptr)
        {
            break;
        }

        commandLine->clear();
        std::vector<std::wstring> args = Split(query);
        if (args.empty())
        {
            break;
        }

        std::wstring first = ToLower(args[0]);
        if (first == L"explain" ||
            first == L"analyze" ||
            first == L"interpret" ||
            first == L"annotate")
        {
            if (args.size() < 2)
            {
                break;
            }

            std::wstring candidate = JoinArgs(args, 1);
            if (IsAiEvidenceCommandLine(candidate))
            {
                *commandLine = candidate;
                built = true;
            }
            break;
        }

        if (IsAiEvidenceCommandLine(query))
        {
            *commandLine = query;
            built = true;
        }
    } while (false);

    return built;
}

static bool ContainsAnyNoCase(const std::wstring& text, const std::vector<std::wstring>& needles)
{
    bool found = false;
    std::wstring lowered = ToLower(text);

    for (const std::wstring& needle : needles)
    {
        if (!needle.empty() && lowered.find(needle) != std::wstring::npos)
        {
            found = true;
            break;
        }
    }

    return found;
}

static bool StartsWithAnyNoCase(const std::wstring& text, const std::vector<std::wstring>& prefixes)
{
    bool found = false;
    std::wstring lowered = TrimWhitespace(ToLower(text));

    for (const std::wstring& prefix : prefixes)
    {
        if (prefix.empty())
        {
            continue;
        }

        if (lowered == prefix ||
            (lowered.size() > prefix.size() &&
             lowered.rfind(prefix + L" ", 0) == 0))
        {
            found = true;
            break;
        }
    }

    return found;
}

static bool ShouldAutoPlanAiQuery(const std::wstring& query)
{
    static const std::vector<std::wstring> conceptualPrefixes =
    {
        L"what is",
        L"what are",
        L"why",
        L"how do",
        L"how does",
        L"how can",
        L"explain",
        L"describe"
    };
    static const std::vector<std::wstring> planActionSignals =
    {
        L"check",
        L"show",
        L"list",
        L"inspect",
        L"find",
        L"dump",
        L"translate",
        L"decode",
        L"disassemble",
        L"enumerate",
        L"scan",
        L"triage",
        L"audit",
        L"verify",
        L"status",
        L"options",
        L"integrity"
    };
    static const std::vector<std::wstring> planInvestigationPhrases =
    {
        L"vbs",
        L"hvci",
        L"cioptions",
        L"ci options",
        L"securekernel",
        L"secure kernel",
        L"trustlet",
        L"kernel callback",
        L"module integrity",
        L"driver integrity",
        L"pool scan",
        L"pool tag",
        L"address inspect",
        L"symbol lookup"
    };
    bool shouldPlan = false;

    do
    {
        if (StartsWithAnyNoCase(query, conceptualPrefixes))
        {
            break;
        }

        if (ContainsAnyNoCase(query, planActionSignals) ||
            ContainsAnyNoCase(query, planInvestigationPhrases))
        {
            shouldPlan = true;
            break;
        }
    } while (false);

    return shouldPlan;
}

static bool IsAiCommandRecommendationQuery(const std::wstring& query)
{
    static const std::vector<std::wstring> commandPhrases =
    {
        L"list commands",
        L"show commands",
        L"what commands",
        L"which commands",
        L"commands to",
        L"command to",
        L"commands for",
        L"recommend commands",
        L"suggest commands"
    };

    return ContainsAnyNoCase(query, commandPhrases);
}

static void HandleAiPlanRequest(
    const std::wstring& prompt,
    const std::wstring& eventName,
    const std::wstring& requestLabel,
    DebuggerState& state,
    SymbolEngine& symbols,
    AiProviderRuntime& ai,
    AiPlanState& aiState)
{
    do
    {
        AiCompletionRequest request = {};
        request.System = BuildAiSystemPrompt(state, symbols);
        request.Prompt = BuildAiPlanPrompt(prompt);

        std::wcout << requestLabel << L": provider=" << ai.ProviderName()
                   << L" model=" << ai.Settings().Model
                   << L" credential=" << ai.CredentialStatus() << L"\n";

        AiCompletionResponse response = {};
        std::wstring error;
        if (!ai.Complete(request, &response, &error))
        {
            std::wcerr << L"ai plan failed: " << error << L"\n";
            WriteAiTranscriptEvent(aiState, eventName + L"_failed", error, L"");
            break;
        }

        AiPlanState parsed = {};
        PreserveAiSessionSettings(parsed, aiState);
        if (!ParseAiPlanResponse(response.Text, &parsed, &error))
        {
            aiState.RawResponse = response.Text;
            std::wcerr << L"ai plan parse failed: " << error << L"\n";
            std::wcerr << L"raw response:\n" << response.Text << L"\n";
            WriteAiTranscriptEvent(aiState, eventName + L"_parse_failed", error, L"");
            break;
        }

        aiState = parsed;
        WriteAiTranscriptEvent(aiState, eventName, L"plan loaded", L"");
        PrintAiPlan(aiState);
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
            add(L"callbacks all", L"enumerate object, registry, process, thread, image-load, and minifilter callbacks");
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
            add(L"callbacks object", L"enumerate object-manager filters by object type");
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
                add(L"callbacks all " + argument, L"find callback surfaces owned by the module");
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

struct AiProcessIntent
{
    bool IsProcessQuery = false;
    bool WantsPid = false;
    bool WantsEprocess = false;
    bool WantsDtb = false;
    bool WantsPeb = false;
    bool WantsInfo = false;
    bool HasPid = false;
    uint64_t Pid = 0;
    bool HasEprocess = false;
    uint64_t Eprocess = 0;
    std::wstring ImageName;
};

static bool IsAiQueryTokenBoundary(wchar_t ch)
{
    bool boundary = true;

    if (std::iswalnum(ch) != 0 ||
        ch == L'_' ||
        ch == L'-' ||
        ch == L'.' ||
        ch == L'\\' ||
        ch == L'/' ||
        ch == L':')
    {
        boundary = false;
    }

    return boundary;
}

static std::wstring TrimAiQueryToken(const std::wstring& value)
{
    std::wstring result;

    do
    {
        if (value.empty())
        {
            break;
        }

        size_t first = 0;
        size_t last = value.size();

        while (first < last && IsAiQueryTokenBoundary(value[first]))
        {
            ++first;
        }

        while (last > first && IsAiQueryTokenBoundary(value[last - 1]))
        {
            --last;
        }

        result = value.substr(first, last - first);
    } while (false);

    return result;
}

static bool ContainsAiQueryWord(const std::wstring& loweredValue, const std::wstring& loweredWord)
{
    bool found = false;

    do
    {
        if (loweredValue.empty() || loweredWord.empty())
        {
            break;
        }

        size_t offset = 0;
        while (offset < loweredValue.size())
        {
            size_t match = loweredValue.find(loweredWord, offset);
            if (match == std::wstring::npos)
            {
                break;
            }

            size_t end = match + loweredWord.size();
            bool leftBoundary = match == 0 || IsAiQueryTokenBoundary(loweredValue[match - 1]);
            bool rightBoundary = end >= loweredValue.size() || IsAiQueryTokenBoundary(loweredValue[end]);
            if (leftBoundary && rightBoundary)
            {
                found = true;
                break;
            }

            offset = end;
        }
    } while (false);

    return found;
}

static std::wstring LeafFileName(const std::wstring& value)
{
    std::wstring result = value;

    size_t slash = result.find_last_of(L"\\/");
    if (slash != std::wstring::npos && slash + 1 < result.size())
    {
        result = result.substr(slash + 1);
    }

    return result;
}

static std::wstring StripExeSuffix(const std::wstring& value)
{
    std::wstring result = value;
    std::wstring lowered = ToLower(result);

    if (lowered.size() > 4 && lowered.substr(lowered.size() - 4) == L".exe")
    {
        result = result.substr(0, result.size() - 4);
    }

    return result;
}

static std::wstring ExtractExeImageNameFromQuery(const std::wstring& query)
{
    std::wstring result;
    std::wstring lowered = ToLower(query);
    size_t exeIndex = lowered.find(L".exe");

    do
    {
        if (exeIndex == std::wstring::npos)
        {
            break;
        }

        size_t first = exeIndex;
        while (first > 0 && !IsAiQueryTokenBoundary(query[first - 1]))
        {
            --first;
        }

        size_t last = exeIndex + 4;
        result = LeafFileName(query.substr(first, last - first));
        result = TrimAiQueryToken(result);
    } while (false);

    return result;
}

static bool ProcessImageNameMatches(const std::wstring& recordName, const std::wstring& queryName)
{
    bool matched = false;

    do
    {
        std::wstring record = ToLower(LeafFileName(TrimAiQueryToken(recordName)));
        std::wstring query = ToLower(LeafFileName(TrimAiQueryToken(queryName)));
        if (record.empty() || query.empty() || record == L"<unknown>")
        {
            break;
        }

        if (record == query)
        {
            matched = true;
            break;
        }

        if (ToLower(StripExeSuffix(record)) == ToLower(StripExeSuffix(query)))
        {
            matched = true;
            break;
        }

        if (record.size() >= 15 && query.rfind(record, 0) == 0)
        {
            matched = true;
            break;
        }
    } while (false);

    return matched;
}

static ProcessTriageTarget ProcessTriageTargetFromDmlRecord(const DmlProcessRecord& record)
{
    ProcessTriageTarget target = {};
    target.ProcessId = static_cast<uint32_t>(record.ProcessId);
    target.Eprocess = record.Eprocess;
    target.DirectoryTableBase = record.DirectoryTableBase;
    target.UserDirectoryTableBase = record.UserDirectoryTableBase;
    target.Peb = record.Peb;
    target.HasPeb = record.HasPeb;
    target.ImageName = record.ImageName;
    return target;
}

static bool ResolveProcessTriageTarget(
    const std::wstring& rawTarget,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    ProcessTriageTarget* target,
    std::vector<std::wstring>* warnings,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (target == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid target output";
            }
            break;
        }

        *target = ProcessTriageTarget{};
        std::wstring input = TrimWhitespace(rawTarget);
        if (input.empty() || IsSwitchLikeToken(input))
        {
            if (error != nullptr)
            {
                *error = L"missing process target";
            }
            break;
        }

        bool wantPid = false;
        bool wantEprocess = false;
        uint64_t pid = 0;
        uint64_t eprocess = 0;

        if (ParseDmlProcessPidFilter(input, &pid))
        {
            wantPid = true;
        }
        else if (ParseUnsigned(input, state.NumberBase, &eprocess) && IsLikelyKernelVirtualAddress(eprocess))
        {
            wantEprocess = true;
        }

        DmlProcessCollection collection = {};
        if (!CollectDmlProcessRecords(state, device, symbols, &collection, error))
        {
            break;
        }

        if (warnings != nullptr)
        {
            warnings->insert(warnings->end(), collection.Warnings.begin(), collection.Warnings.end());
        }

        std::vector<DmlProcessRecord> matches;
        for (const DmlProcessRecord& record : collection.Records)
        {
            bool matched = false;

            if (wantPid)
            {
                matched = record.ProcessId == pid;
            }
            else if (wantEprocess)
            {
                matched = record.Eprocess == eprocess;
            }
            else
            {
                matched = ProcessImageNameMatches(record.ImageName, input);
            }

            if (matched)
            {
                matches.push_back(record);
            }
        }

        if (matches.empty())
        {
            if (error != nullptr)
            {
                *error = L"no process matched target: " + input;
            }
            break;
        }

        if (!wantPid && !wantEprocess && matches.size() > 1)
        {
            if (error != nullptr)
            {
                std::wstringstream stream;
                stream << L"multiple process matches for " << input << L"; use pid or eprocess:";
                size_t count = 0;
                for (const DmlProcessRecord& record : matches)
                {
                    if (count >= 6)
                    {
                        stream << L" ...";
                        break;
                    }
                    stream << L" " << record.ImageName << L"(pid=" << std::dec << record.ProcessId
                           << L",eprocess=" << HexTextWidth(record.Eprocess, 16, true) << L")";
                    ++count;
                }
                *error = stream.str();
            }
            break;
        }

        *target = ProcessTriageTargetFromDmlRecord(matches[0]);
        ok = true;
    } while (false);

    return ok;
}

static bool ParseProcessTriageLimit(const std::wstring& value, uint32_t numberBase, uint32_t* limit, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (limit == nullptr)
        {
            break;
        }

        uint64_t parsed = 0;
        if (!ParseUnsigned(value, numberBase, &parsed) || parsed > 0xffffffffull)
        {
            if (error != nullptr)
            {
                *error = L"invalid limit: " + value;
            }
            break;
        }

        *limit = static_cast<uint32_t>(parsed);
        ok = true;
    } while (false);

    return ok;
}

static void PrintProcessTriageWarnings(const std::wstring& prefix, const std::vector<std::wstring>& warnings)
{
    for (const std::wstring& warning : warnings)
    {
        std::wcerr << prefix << L" warning: " << warning << L"\n";
    }
}

static void PrintVadRecord(const ProcessVadRecord& record)
{
    WORD color = record.Executable && record.Writable ? KNDBG_COLOR_WARN : KNDBG_COLOR_ACCENT;

    PrintColoredText(HexTextWidth(record.StartAddress, 16, true), color);
    std::wcout << L"-" << HexTextWidth(record.EndAddress, 16, true);
    std::wcout << L" size=" << HexText(record.Size);
    std::wcout << L" vad=" << HexTextWidth(record.VadAddress, 16, true);
    std::wcout << L" prot=" << (record.HasProtection ? record.ProtectionText : L"?");
    if (record.HasPrivateMemory)
    {
        std::wcout << L" private=" << (record.PrivateMemory ? L"yes" : L"no");
    }
    if (record.PeProbeAttempted)
    {
        std::wcout << L" pe=" << (record.PeHeaderFound ? L"yes" : L"no");
    }
    if (!record.Classification.empty())
    {
        std::wcout << L" flags=" << record.Classification;
    }
    if (!record.Notes.empty())
    {
        std::wcout << L" notes=" << record.Notes;
    }
    std::wcout << L"\n";
}

static void PrintHiddenVadPteRecord(const ProcessHiddenVadPteRecord& record)
{
    WORD color = record.Executable ? KNDBG_COLOR_WARN : KNDBG_COLOR_ACCENT;

    PrintColoredText(L"[hidden-pte] ", color);
    std::wcout << HexTextWidth(record.StartAddress, 16, true)
               << L"-" << HexTextWidth(record.EndAddress, 16, true)
               << L" size=" << HexText(record.Size)
               << L" pages=" << std::dec << record.PageCount
               << L" page_size=" << HexText(record.PageSize)
               << L" phys=" << HexTextWidth(record.PhysicalAddress, 16, true)
               << L" leaf=" << HexTextWidth(record.LeafEntryAddress, 16, true)
               << L" entry=" << HexTextWidth(record.LeafEntry, 16, true)
               << L" user=" << (record.UserAccessible ? L"yes" : L"no")
               << L" writable=" << (record.Writable ? L"yes" : L"no")
               << L" exec=" << (record.Executable ? L"yes" : L"no");
    if (record.LargePage)
    {
        std::wcout << L" large=yes";
    }
    if (!record.Notes.empty())
    {
        std::wcout << L" notes=" << record.Notes;
    }
    std::wcout << L"\n";
}

static void PrintVadScanResult(const ProcessVadScanResult& result, bool summaryOnly)
{
    PrintColoredText(L"!vad", KNDBG_COLOR_TITLE);
    std::wcout << L" pid=" << std::dec << result.Target.ProcessId
               << L" image=" << result.Target.ImageName
               << L" eprocess=" << HexTextWidth(result.Target.Eprocess, 16, true)
               << L"\n";

    if (!summaryOnly)
    {
        for (const ProcessVadRecord& record : result.Records)
        {
            PrintVadRecord(record);
        }

        for (const ProcessHiddenVadPteRecord& record : result.HiddenPteRecords)
        {
            PrintHiddenVadPteRecord(record);
        }
    }

    PrintColoredText(L"[vad.summary]", KNDBG_COLOR_TITLE);
    std::wcout << L" nodes=" << result.NodesVisited
               << L" total=" << result.TotalRecords
               << L" matching=" << result.MatchingRecords
               << L" exec=" << result.ExecutableCount
               << L" private_exec=" << result.PrivateExecutableCount
               << L" wx=" << result.WxCount
               << L" pe=" << result.PeLikeCount
               << L" suspicious=" << result.SuspiciousCount
               << L" truncated=" << (result.Truncated ? L"yes" : L"no")
               << L"\n";

    if (result.HiddenPteScanEnabled)
    {
        PrintColoredText(L"[vad.hiddenpte]", KNDBG_COLOR_TITLE);
        std::wcout << L" paging_levels=" << result.PagingLevels
                   << L" pte_leafs=" << result.PteLeafMappings
                   << L" hidden_ranges=" << result.HiddenPteRanges
                   << L" hidden_bytes=" << HexText(result.HiddenPteBytes)
                   << L" hidden_exec=" << result.HiddenPteExecutableCount
                   << L" hidden_wx=" << result.HiddenPteWxCount
                   << L" page_table_pages=" << result.PageTablePagesRead
                   << L" read_failures=" << result.PageTableReadFailures
                   << L" truncated=" << (result.HiddenPteTruncated ? L"yes" : L"no")
                   << L"\n";
    }
}

static void PrintThreadRecord(const ProcessThreadRecord& record, bool includeStacks, bool includeApc)
{
    WORD color = record.SuspiciousStart ? KNDBG_COLOR_WARN : KNDBG_COLOR_ACCENT;

    PrintColoredText(HexTextWidth(record.Ethread, 16, true), color);
    std::wcout << L" tid=";
    if (record.HasThreadId)
    {
        std::wcout << std::dec << record.ThreadId;
    }
    else
    {
        std::wcout << L"?";
    }

    std::wcout << L" start=";
    if (record.HasStartAddress)
    {
        std::wcout << HexTextWidth(record.StartAddress, 16, true);
    }
    else
    {
        std::wcout << L"?";
    }

    std::wcout << L" win32=";
    if (record.HasWin32StartAddress)
    {
        std::wcout << HexTextWidth(record.Win32StartAddress, 16, true);
    }
    else
    {
        std::wcout << L"?";
    }

    if (!record.StartModule.empty())
    {
        std::wcout << L" module=" << record.StartModule;
    }
    else if (!record.Win32StartModule.empty())
    {
        std::wcout << L" module=" << record.Win32StartModule;
    }

    if (!record.VadClassification.empty())
    {
        std::wcout << L" vad=" << record.VadClassification;
    }

    if (record.HasTeb)
    {
        std::wcout << L" teb=" << HexTextWidth(record.Teb, 16, true);
    }

    if (includeStacks && record.HasStackBounds)
    {
        std::wcout << L" stack=" << HexTextWidth(record.StackLimit, 16, true)
                   << L"-" << HexTextWidth(record.StackBase, 16, true);
    }

    if (!record.Notes.empty())
    {
        std::wcout << L" notes=" << record.Notes;
    }

    std::wcout << L"\n";

    if (includeApc)
    {
        for (const ProcessApcQueueRecord& queue : record.ApcQueues)
        {
            std::wcout << L"    apc[" << queue.Name << L"] head="
                       << HexTextWidth(queue.HeadAddress, 16, true)
                       << L" present=" << (queue.Present ? L"yes" : L"no")
                       << L" nonempty=" << (queue.NonEmpty ? L"yes" : L"no")
                       << L" scanned=" << queue.EntriesScanned;
            if (queue.Truncated)
            {
                std::wcout << L" truncated=yes";
            }
            std::wcout << L"\n";

            for (const ProcessApcEntryRecord& entry : queue.Entries)
            {
                std::wcout << L"        kapc=" << HexTextWidth(entry.KapcAddress, 16, true)
                           << L" kernel=" << HexTextWidth(entry.KernelRoutine, 16, true)
                           << L" normal=" << HexTextWidth(entry.NormalRoutine, 16, true)
                           << L" suspicious=" << (entry.Suspicious ? L"yes" : L"no");
                if (!entry.KernelRoutineModule.empty())
                {
                    std::wcout << L" kmod=" << entry.KernelRoutineModule;
                }
                if (!entry.NormalRoutineModule.empty())
                {
                    std::wcout << L" nmod=" << entry.NormalRoutineModule;
                }
                if (!entry.Notes.empty())
                {
                    std::wcout << L" notes=" << entry.Notes;
                }
                std::wcout << L"\n";
            }
        }
    }
}

static void PrintThreadScanResult(const ProcessThreadScanResult& result, bool includeStacks, bool includeApc)
{
    PrintColoredText(L"!threads", KNDBG_COLOR_TITLE);
    std::wcout << L" pid=" << std::dec << result.Target.ProcessId
               << L" image=" << result.Target.ImageName
               << L" eprocess=" << HexTextWidth(result.Target.Eprocess, 16, true)
               << L"\n";

    for (const ProcessThreadRecord& record : result.Records)
    {
        PrintThreadRecord(record, includeStacks, includeApc);
    }

    PrintColoredText(L"[threads.summary]", KNDBG_COLOR_TITLE);
    std::wcout << L" visited=" << result.ThreadsVisited
               << L" records=" << result.MatchingRecords
               << L" suspicious_start=" << result.SuspiciousStartCount
               << L" nonempty_apc_queues=" << result.ApcNonEmptyCount
               << L" truncated=" << (result.Truncated ? L"yes" : L"no")
               << L"\n";
}

static void HandleVadCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    std::wstring error;

    do
    {
        if (args.size() < 2 || IsHelpToken(args[1]))
        {
            PrintVadHelp();
            break;
        }

        ProcessVadScanOptions options = {};
        std::vector<std::wstring> targetWarnings;
        if (!ResolveProcessTriageTarget(args[1], state, device, symbols, &options.Target, &targetWarnings, &error))
        {
            std::wcerr << L"!vad failed: " << error << L"\n";
            break;
        }

        std::wstring jsonPath;
        bool parseOk = true;
        for (size_t index = 2; index < args.size(); ++index)
        {
            std::wstring option = ToLower(args[index]);

            if (option == L"/summary")
            {
                options.SummaryOnly = true;
            }
            else if (option == L"/exec")
            {
                options.ExecOnly = true;
            }
            else if (option == L"/private")
            {
                options.PrivateOnly = true;
            }
            else if (option == L"/wx")
            {
                options.WxOnly = true;
            }
            else if (option == L"/pe")
            {
                options.ProbePe = true;
                options.PeOnly = true;
            }
            else if (option == L"/hiddenpte" || option == L"/hidden" || option == L"/dkom")
            {
                options.ScanHiddenPtes = true;
            }
            else if (option == L"/limit")
            {
                if (index + 1 >= args.size())
                {
                    std::wcerr << L"!vad failed: /limit requires a value\n";
                    parseOk = false;
                    break;
                }
                if (!ParseProcessTriageLimit(args[index + 1], state.NumberBase, &options.Limit, &error))
                {
                    std::wcerr << L"!vad failed: " << error << L"\n";
                    parseOk = false;
                    break;
                }
                ++index;
            }
            else if (option == L"/json")
            {
                if (index + 1 >= args.size())
                {
                    std::wcerr << L"!vad failed: /json requires a path\n";
                    parseOk = false;
                    break;
                }
                jsonPath = args[index + 1];
                ++index;
            }
            else
            {
                std::wcerr << L"!vad failed: unknown option " << args[index] << L"\n";
                parseOk = false;
                break;
            }
        }

        if (!parseOk)
        {
            break;
        }

        ProcessTriageScanner scanner(device, symbols);
        ProcessVadScanResult result = {};
        if (!scanner.ScanVad(options, &result, &error))
        {
            std::wcerr << L"!vad failed: " << error << L"\n";
            break;
        }

        result.Warnings.insert(result.Warnings.begin(), targetWarnings.begin(), targetWarnings.end());
        PrintVadScanResult(result, options.SummaryOnly);
        PrintProcessTriageWarnings(L"!vad", result.Warnings);

        if (!jsonPath.empty())
        {
            if (WriteUtf8TextFile(jsonPath, BuildProcessVadJson(result), &error))
            {
                std::wcout << L"json written: " << jsonPath << L"\n";
            }
            else
            {
                std::wcerr << L"!vad json failed: " << error << L"\n";
            }
        }
    } while (false);
}

static void HandleThreadsCommand(
    const std::vector<std::wstring>& args,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    std::wstring error;

    do
    {
        if (args.size() < 2 || IsHelpToken(args[1]))
        {
            PrintThreadsHelp();
            break;
        }

        ProcessThreadScanOptions options = {};
        std::vector<std::wstring> targetWarnings;
        if (!ResolveProcessTriageTarget(args[1], state, device, symbols, &options.Target, &targetWarnings, &error))
        {
            std::wcerr << L"!threads failed: " << error << L"\n";
            break;
        }

        std::wstring jsonPath;
        bool parseOk = true;
        for (size_t index = 2; index < args.size(); ++index)
        {
            std::wstring option = ToLower(args[index]);

            if (option == L"/apc")
            {
                options.IncludeApc = true;
            }
            else if (option == L"/stacks")
            {
                options.IncludeStacks = true;
            }
            else if (option == L"/limit")
            {
                if (index + 1 >= args.size())
                {
                    std::wcerr << L"!threads failed: /limit requires a value\n";
                    parseOk = false;
                    break;
                }
                if (!ParseProcessTriageLimit(args[index + 1], state.NumberBase, &options.Limit, &error))
                {
                    std::wcerr << L"!threads failed: " << error << L"\n";
                    parseOk = false;
                    break;
                }
                ++index;
            }
            else if (option == L"/json")
            {
                if (index + 1 >= args.size())
                {
                    std::wcerr << L"!threads failed: /json requires a path\n";
                    parseOk = false;
                    break;
                }
                jsonPath = args[index + 1];
                ++index;
            }
            else
            {
                std::wcerr << L"!threads failed: unknown option " << args[index] << L"\n";
                parseOk = false;
                break;
            }
        }

        if (!parseOk)
        {
            break;
        }

        ProcessTriageScanner scanner(device, symbols);
        ProcessThreadScanResult result = {};
        if (!scanner.ScanThreads(options, &result, &error))
        {
            std::wcerr << L"!threads failed: " << error << L"\n";
            break;
        }

        result.Warnings.insert(result.Warnings.begin(), targetWarnings.begin(), targetWarnings.end());
        PrintThreadScanResult(result, options.IncludeStacks, options.IncludeApc);
        PrintProcessTriageWarnings(L"!threads", result.Warnings);

        if (!jsonPath.empty())
        {
            if (WriteUtf8TextFile(jsonPath, BuildProcessThreadsJson(result), &error))
            {
                std::wcout << L"json written: " << jsonPath << L"\n";
            }
            else
            {
                std::wcerr << L"!threads json failed: " << error << L"\n";
            }
        }
    } while (false);
}

static bool TryExtractPidFromAiQuery(const std::vector<std::wstring>& tokens, uint64_t* pid)
{
    bool found = false;

    do
    {
        if (pid == nullptr)
        {
            break;
        }

        for (size_t index = 0; index < tokens.size(); ++index)
        {
            std::wstring token = ToLower(TrimAiQueryToken(tokens[index]));
            if (token.empty())
            {
                continue;
            }

            std::wstring value;
            if (token == L"pid" || token == L"processid" || token == L"process-id")
            {
                if (index + 1 < tokens.size())
                {
                    value = TrimAiQueryToken(tokens[index + 1]);
                }
            }
            else if (token.rfind(L"pid=", 0) == 0)
            {
                value = token.substr(4);
            }

            uint64_t parsed = 0;
            if (!value.empty() && ParseDmlProcessPidFilter(value, &parsed))
            {
                *pid = parsed;
                found = true;
                break;
            }
        }
    } while (false);

    return found;
}

static bool TryExtractEprocessFromAiQuery(
    const std::vector<std::wstring>& tokens,
    const DebuggerState& state,
    uint64_t* eprocess)
{
    bool found = false;

    do
    {
        if (eprocess == nullptr)
        {
            break;
        }

        for (size_t index = 0; index < tokens.size(); ++index)
        {
            std::wstring token = TrimAiQueryToken(tokens[index]);
            std::wstring lowered = ToLower(token);
            std::wstring value = token;

            if (lowered == L"eprocess" || lowered == L"_eprocess")
            {
                if (index + 1 < tokens.size())
                {
                    value = TrimAiQueryToken(tokens[index + 1]);
                }
                else
                {
                    value.clear();
                }
            }
            else if (lowered.rfind(L"eprocess=", 0) == 0)
            {
                value = token.substr(9);
            }
            else if (lowered.rfind(L"_eprocess=", 0) == 0)
            {
                value = token.substr(10);
            }

            uint64_t parsed = 0;
            if (!value.empty() &&
                ParseUnsigned(value, state.NumberBase, &parsed) &&
                IsLikelyKernelVirtualAddress(parsed))
            {
                *eprocess = parsed;
                found = true;
                break;
            }
        }
    } while (false);

    return found;
}

static AiProcessIntent ParseAiProcessIntent(const std::wstring& query, const DebuggerState& state)
{
    AiProcessIntent intent = {};
    std::wstring lowered = ToLower(query);
    std::vector<std::wstring> tokens = Split(query);
    bool hasProcessWord = ContainsAiQueryWord(lowered, L"process") ||
        ContainsNoCase(lowered, L"\xD504\xB85C\xC138\xC2A4");

    intent.ImageName = ExtractExeImageNameFromQuery(query);
    intent.WantsPid = ContainsNoCase(lowered, L"pid") ||
        ContainsNoCase(lowered, L"process id") ||
        ContainsNoCase(lowered, L"process-id");
    intent.WantsEprocess = ContainsNoCase(lowered, L"eprocess");
    intent.WantsDtb = ContainsNoCase(lowered, L"dtb") ||
        ContainsNoCase(lowered, L"dirbase") ||
        ContainsNoCase(lowered, L"directorytablebase") ||
        ContainsNoCase(lowered, L"cr3");
    intent.WantsPeb = ContainsNoCase(lowered, L"peb");
    intent.WantsInfo = ContainsNoCase(lowered, L"info") ||
        ContainsNoCase(lowered, L"summary") ||
        hasProcessWord;
    intent.HasPid = TryExtractPidFromAiQuery(tokens, &intent.Pid);
    intent.HasEprocess = TryExtractEprocessFromAiQuery(tokens, state, &intent.Eprocess);

    if (!intent.ImageName.empty() ||
        intent.HasPid ||
        (intent.HasEprocess &&
            (intent.WantsPid || intent.WantsEprocess || intent.WantsDtb || intent.WantsPeb || intent.WantsInfo)) ||
        ((intent.WantsPid || intent.WantsEprocess || intent.WantsDtb || intent.WantsPeb) &&
            hasProcessWord))
    {
        intent.IsProcessQuery = true;
    }

    if (intent.IsProcessQuery &&
        !intent.WantsPid &&
        !intent.WantsEprocess &&
        !intent.WantsDtb &&
        !intent.WantsPeb)
    {
        intent.WantsInfo = true;
    }

    return intent;
}

static bool AiProcessRecordMatchesIntent(const DmlProcessRecord& record, const AiProcessIntent& intent)
{
    bool matched = true;

    do
    {
        if (!intent.ImageName.empty())
        {
            if (!ProcessImageNameMatches(record.ImageName, intent.ImageName))
            {
                matched = false;
                break;
            }
        }

        if (intent.HasPid)
        {
            if (record.ProcessId != intent.Pid)
            {
                matched = false;
                break;
            }
        }

        if (intent.HasEprocess)
        {
            if (record.Eprocess != intent.Eprocess)
            {
                matched = false;
                break;
            }
        }
    } while (false);

    return matched;
}

static void PrintAiProcessAnswerLine(const DmlProcessRecord& record, const AiProcessIntent& intent)
{
    bool any = false;

    if (intent.WantsPid || intent.WantsInfo)
    {
        std::wcout << L"pid=" << std::dec << record.ProcessId;
        any = true;
    }

    if (intent.WantsEprocess || intent.WantsInfo)
    {
        std::wcout << (any ? L" " : L"");
        std::wcout << L"eprocess=" << HexTextWidth(record.Eprocess, 16, true);
        any = true;
    }

    if (intent.WantsDtb || intent.WantsInfo)
    {
        std::wcout << (any ? L" " : L"");
        std::wcout << L"dirbase=" << HexTextWidth(record.DirectoryTableBase, 16, true);
        if (record.UserDirectoryTableBase != 0)
        {
            std::wcout << L" userdirbase=" << HexTextWidth(record.UserDirectoryTableBase, 16, true);
        }
        any = true;
    }

    if (intent.WantsPeb || intent.WantsInfo)
    {
        std::wcout << (any ? L" " : L"");
        if (record.HasPeb)
        {
            std::wcout << L"peb=" << HexTextWidth(record.Peb, 16, true);
        }
        else
        {
            std::wcout << L"peb=<unavailable>";
        }
        any = true;
    }

    if (!any)
    {
        std::wcout << L"pid=" << std::dec << record.ProcessId
                   << L" eprocess=" << HexTextWidth(record.Eprocess, 16, true);
    }

    std::wcout << L"\n";
}

static void PrintAiProcessNextCommands(const DmlProcessRecord& record)
{
    std::wcout << L"next:\n";
    std::wcout << L"  dt nt!_EPROCESS " << HexTextWidth(record.Eprocess, 16, true) << L"\n";
    std::wcout << L"  procctx " << std::dec << record.ProcessId << L"\n";
    std::wcout << L"  db /process " << std::dec << record.ProcessId << L" <user-va> 80\n";
    std::wcout << L"  vtop /process " << std::dec << record.ProcessId << L" <user-va>\n";
}

static bool TryHandleAiProcessQuery(
    const std::wstring& query,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    bool handled = false;

    do
    {
        AiProcessIntent intent = ParseAiProcessIntent(query, state);
        if (!intent.IsProcessQuery)
        {
            break;
        }

        handled = true;

        DmlProcessCollection collection = {};
        std::wstring error;
        if (!CollectDmlProcessRecords(state, device, symbols, &collection, &error))
        {
            std::wcerr << L"ai local process query failed: " << error << L"\n";
            break;
        }

        std::vector<DmlProcessRecord> matches;
        for (const DmlProcessRecord& record : collection.Records)
        {
            if (AiProcessRecordMatchesIntent(record, intent))
            {
                matches.push_back(record);
            }
        }

        PrintColoredText(L"ai local", KNDBG_COLOR_TITLE);
        std::wcout << L": process query\n";

        if (matches.empty())
        {
            std::wcout << L"matches=0";
            if (!intent.ImageName.empty())
            {
                std::wcout << L" image=" << intent.ImageName;
            }
            if (intent.HasPid)
            {
                std::wcout << L" pid=" << std::dec << intent.Pid;
            }
            if (intent.HasEprocess)
            {
                std::wcout << L" eprocess=" << HexTextWidth(intent.Eprocess, 16, true);
            }
            std::wcout << L"\n";
            std::wcout << L"next:\n";
            std::wcout << L"  !dml_proc\n";
            break;
        }

        PrintDmlProcessHeader();
        for (const DmlProcessRecord& record : matches)
        {
            PrintDmlProcessRecord(record);
        }

        PrintColoredText(L"matches", KNDBG_COLOR_TITLE);
        std::wcout << L"=" << matches.size();
        if (collection.Truncated)
        {
            std::wcout << L" truncated=yes";
        }
        std::wcout << L"\n";

        for (const std::wstring& warning : collection.Warnings)
        {
            std::wcerr << L"ai local warning: " << warning << L"\n";
        }

        if (matches.size() == 1)
        {
            PrintColoredText(L"answer", KNDBG_COLOR_TITLE);
            std::wcout << L": ";
            PrintAiProcessAnswerLine(matches[0], intent);
            PrintAiProcessNextCommands(matches[0]);
        }
        else
        {
            std::wcout << L"answer: multiple matches; use pid or eprocess to narrow the query\n";
        }
    } while (false);

    return handled;
}

static bool TryHandleAiLocalQuery(
    const std::wstring& query,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols)
{
    bool handled = false;

    do
    {
        if (TryHandleAiProcessQuery(query, state, device, symbols))
        {
            handled = true;
            break;
        }
    } while (false);

    return handled;
}

enum class AiCapabilityQueryResult
{
    NotAttempted,
    Handled,
    Failed
};

struct AiCapabilityStep
{
    std::wstring Tool;
    std::wstring ArgsJson;
};

struct AiCapabilityPlan
{
    std::wstring Schema;
    std::wstring Summary;
    std::wstring RawResponse;
    std::vector<AiCapabilityStep> Steps;
};

struct AiCapabilityProcessFilter
{
    bool HasImage = false;
    std::wstring Image;
    bool HasPid = false;
    uint64_t Pid = 0;
    bool HasEprocess = false;
    uint64_t Eprocess = 0;
};

struct AiCapabilityStepResult
{
    bool HasProcesses = false;
    std::vector<DmlProcessRecord> Processes;
};

static bool TryParseAiCapabilitySourceIndex(const std::wstring& source, size_t* index)
{
    bool ok = false;

    do
    {
        if (index == nullptr || source.size() < 2 || source[0] != L'$')
        {
            break;
        }

        uint64_t parsed = 0;
        if (!ParseUnsigned(source.substr(1), 10, &parsed) ||
            parsed > static_cast<uint64_t>(std::numeric_limits<size_t>::max()))
        {
            break;
        }

        *index = static_cast<size_t>(parsed);
        ok = true;
    } while (false);

    return ok;
}

static std::wstring NormalizeAiCapabilityProcessField(const std::wstring& value)
{
    std::wstring field = ToLower(TrimWhitespace(value));

    if (field == L"name" || field == L"image" || field == L"imagename" || field == L"image_name")
    {
        field = L"image";
    }
    else if (field == L"processid" || field == L"process_id")
    {
        field = L"pid";
    }
    else if (field == L"address" || field == L"_eprocess")
    {
        field = L"eprocess";
    }
    else if (field == L"directorytablebase" || field == L"directory_table_base" || field == L"dirbase" || field == L"cr3")
    {
        field = L"dtb";
    }
    else if (field == L"userdirectorytablebase" || field == L"user_directory_table_base" || field == L"userdirbase")
    {
        field = L"userdtb";
    }
    else if (field == L"parent" || field == L"parentpid" || field == L"ppid")
    {
        field = L"ppid";
    }
    else if (field == L"active_threads" || field == L"activethreads")
    {
        field = L"threads";
    }

    return field;
}

static bool IsSupportedAiCapabilityProcessField(const std::wstring& field)
{
    return field == L"all" ||
        field == L"pid" ||
        field == L"image" ||
        field == L"eprocess" ||
        field == L"dtb" ||
        field == L"userdtb" ||
        field == L"peb" ||
        field == L"ppid" ||
        field == L"threads";
}

static std::vector<std::wstring> NormalizeAiCapabilityProcessFields(
    const std::vector<std::wstring>& rawFields,
    std::wstring* error)
{
    std::vector<std::wstring> fields;

    do
    {
        for (const std::wstring& rawField : rawFields)
        {
            std::wstring field = NormalizeAiCapabilityProcessField(rawField);
            if (field.empty())
            {
                continue;
            }

            if (!IsSupportedAiCapabilityProcessField(field))
            {
                if (error != nullptr)
                {
                    *error = L"unsupported process field: " + rawField;
                }
                fields.clear();
                break;
            }

            if (field == L"all")
            {
                fields.clear();
                break;
            }

            bool exists = false;
            for (const std::wstring& existing : fields)
            {
                if (existing == field)
                {
                    exists = true;
                    break;
                }
            }

            if (!exists)
            {
                fields.push_back(field);
            }
        }
    } while (false);

    return fields;
}

static std::vector<std::wstring> DefaultAiCapabilityProcessFields()
{
    std::vector<std::wstring> fields;
    fields.push_back(L"pid");
    fields.push_back(L"image");
    fields.push_back(L"eprocess");
    fields.push_back(L"dtb");
    fields.push_back(L"peb");
    return fields;
}

static bool ParseAiCapabilityProcessFilter(
    const std::wstring& argsJson,
    const DebuggerState& state,
    AiCapabilityProcessFilter* filter,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (filter == nullptr)
        {
            break;
        }

        *filter = AiCapabilityProcessFilter{};

        std::wstring image;
        if (!ExtractJsonStringValue(argsJson, L"image", &image))
        {
            ExtractJsonStringValue(argsJson, L"name", &image);
        }
        if (image.empty())
        {
            ExtractJsonStringValue(argsJson, L"process", &image);
        }
        if (!TrimWhitespace(image).empty())
        {
            filter->HasImage = true;
            filter->Image = TrimWhitespace(image);
        }

        std::wstring pidText;
        if (ExtractJsonScalarValue(argsJson, L"pid", &pidText) && !TrimWhitespace(pidText).empty())
        {
            uint64_t parsed = 0;
            if (!ParseDmlProcessPidFilter(TrimWhitespace(pidText), &parsed))
            {
                if (error != nullptr)
                {
                    *error = L"invalid process pid: " + pidText;
                }
                break;
            }

            filter->HasPid = true;
            filter->Pid = parsed;
        }

        std::wstring eprocessText;
        if (ExtractJsonScalarValue(argsJson, L"eprocess", &eprocessText) && !TrimWhitespace(eprocessText).empty())
        {
            uint64_t parsed = 0;
            if (!ParseUnsigned(TrimWhitespace(eprocessText), state.NumberBase, &parsed) ||
                !IsLikelyKernelVirtualAddress(parsed))
            {
                if (error != nullptr)
                {
                    *error = L"invalid EPROCESS address: " + eprocessText;
                }
                break;
            }

            filter->HasEprocess = true;
            filter->Eprocess = parsed;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool AiCapabilityRecordMatchesFilter(
    const DmlProcessRecord& record,
    const AiCapabilityProcessFilter& filter)
{
    bool matched = true;

    do
    {
        if (filter.HasImage && !ProcessImageNameMatches(record.ImageName, filter.Image))
        {
            matched = false;
            break;
        }

        if (filter.HasPid && record.ProcessId != filter.Pid)
        {
            matched = false;
            break;
        }

        if (filter.HasEprocess && record.Eprocess != filter.Eprocess)
        {
            matched = false;
            break;
        }
    } while (false);

    return matched;
}

static bool HasAiCapabilityProcessFilterArg(const std::wstring& argsJson)
{
    bool hasFilter = false;
    std::wstring value;

    do
    {
        if (ExtractJsonStringValue(argsJson, L"image", &value) ||
            ExtractJsonStringValue(argsJson, L"name", &value) ||
            ExtractJsonStringValue(argsJson, L"process", &value) ||
            ExtractJsonScalarValue(argsJson, L"pid", &value) ||
            ExtractJsonScalarValue(argsJson, L"eprocess", &value))
        {
            hasFilter = true;
            break;
        }
    } while (false);

    return hasFilter;
}

static bool CollectAiCapabilityProcessMatches(
    const std::wstring& argsJson,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    std::vector<DmlProcessRecord>* matches,
    bool* truncated,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (matches == nullptr || truncated == nullptr)
        {
            break;
        }

        matches->clear();
        *truncated = false;

        AiCapabilityProcessFilter filter = {};
        if (!ParseAiCapabilityProcessFilter(argsJson, state, &filter, error))
        {
            break;
        }

        DmlProcessCollection collection = {};
        if (!CollectDmlProcessRecords(state, device, symbols, &collection, error))
        {
            break;
        }

        for (const DmlProcessRecord& record : collection.Records)
        {
            if (AiCapabilityRecordMatchesFilter(record, filter))
            {
                matches->push_back(record);
            }
        }

        *truncated = collection.Truncated;
        for (const std::wstring& warning : collection.Warnings)
        {
            std::wcerr << L"ai tool warning: " << warning << L"\n";
        }

        ok = true;
    } while (false);

    return ok;
}

static bool ResolveAiCapabilityProcessInput(
    const std::wstring& argsJson,
    const std::vector<AiCapabilityStepResult>& results,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    std::vector<DmlProcessRecord>* records,
    bool* truncated,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (records == nullptr || truncated == nullptr)
        {
            break;
        }

        records->clear();
        *truncated = false;

        std::wstring source;
        ExtractJsonStringValue(argsJson, L"source", &source);
        if (!TrimWhitespace(source).empty())
        {
            size_t sourceIndex = 0;
            if (!TryParseAiCapabilitySourceIndex(TrimWhitespace(source), &sourceIndex) ||
                sourceIndex >= results.size() ||
                !results[sourceIndex].HasProcesses)
            {
                if (error != nullptr)
                {
                    *error = L"invalid process source reference: " + source;
                }
                break;
            }

            *records = results[sourceIndex].Processes;
            ok = true;
            break;
        }

        if (!results.empty() && results.back().HasProcesses)
        {
            if (!HasAiCapabilityProcessFilterArg(argsJson))
            {
                *records = results.back().Processes;
                ok = true;
                break;
            }
        }

        ok = CollectAiCapabilityProcessMatches(argsJson, state, device, symbols, records, truncated, error);
    } while (false);

    return ok;
}

static void PrintAiCapabilityProcessValue(
    const DmlProcessRecord& record,
    const std::wstring& field,
    bool* any)
{
    if (any != nullptr && *any)
    {
        std::wcout << L" ";
    }

    if (field == L"pid")
    {
        std::wcout << L"pid=" << std::dec << record.ProcessId;
    }
    else if (field == L"image")
    {
        std::wcout << L"image=" << record.ImageName;
    }
    else if (field == L"eprocess")
    {
        std::wcout << L"eprocess=" << HexTextWidth(record.Eprocess, 16, true);
    }
    else if (field == L"dtb")
    {
        std::wcout << L"dirbase=" << HexTextWidth(record.DirectoryTableBase, 16, true);
    }
    else if (field == L"userdtb")
    {
        std::wcout << L"userdirbase=" << HexTextWidth(record.UserDirectoryTableBase, 16, true);
    }
    else if (field == L"peb")
    {
        if (record.HasPeb)
        {
            std::wcout << L"peb=" << HexTextWidth(record.Peb, 16, true);
        }
        else
        {
            std::wcout << L"peb=<unavailable>";
        }
    }
    else if (field == L"ppid")
    {
        if (record.HasParentProcessId)
        {
            std::wcout << L"ppid=" << std::dec << record.ParentProcessId;
        }
        else
        {
            std::wcout << L"ppid=<unavailable>";
        }
    }
    else if (field == L"threads")
    {
        if (record.HasActiveThreads)
        {
            std::wcout << L"threads=" << std::dec << record.ActiveThreads;
        }
        else
        {
            std::wcout << L"threads=<unavailable>";
        }
    }

    if (any != nullptr)
    {
        *any = true;
    }
}

static void PrintAiCapabilityProcessDescriptions(
    const std::vector<DmlProcessRecord>& records,
    const std::vector<std::wstring>& rawFields)
{
    std::wstring error;
    std::vector<std::wstring> fields = NormalizeAiCapabilityProcessFields(rawFields, &error);
    if (!error.empty())
    {
        std::wcerr << L"ai tool warning: " << error << L"\n";
        fields = DefaultAiCapabilityProcessFields();
    }
    else if (fields.empty())
    {
        fields = DefaultAiCapabilityProcessFields();
    }

    for (size_t index = 0; index < records.size(); ++index)
    {
        std::wcout << L"[" << index << L"] ";
        bool any = false;
        for (const std::wstring& field : fields)
        {
            PrintAiCapabilityProcessValue(records[index], field, &any);
        }
        std::wcout << L"\n";
    }
}

static bool IsSupportedAiCapabilityTool(const std::wstring& tool)
{
    bool supported = false;

    if (tool == L"process.find" ||
        tool == L"process.describe" ||
        tool == L"type.describe" ||
        tool == L"callbacks.list" ||
        tool == L"wfp.list" ||
        tool == L"alpc.list" ||
        tool == L"vad.list" ||
        tool == L"threads.list" ||
        tool == L"etw.integrity" ||
        tool == L"nmi.list" ||
        tool == L"fwtable.list" ||
        tool == L"firmwaretable.list" ||
        tool == L"pool.find" ||
        tool == L"address.inspect" ||
        tool == L"wnf.decode" ||
        tool == L"wnf.list" ||
        tool == L"ti.query" ||
        tool == L"module.integrity" ||
        tool == L"driver.integrity" ||
        tool == L"assistant.answer")
    {
        supported = true;
    }

    return supported;
}

static bool ValidateAiCapabilityToolArgKeys(
    const std::wstring& tool,
    const std::wstring& argsJson,
    std::wstring* error)
{
    std::vector<std::wstring> allowed;

    if (tool == L"process.find")
    {
        allowed = {L"image", L"name", L"process", L"pid", L"eprocess"};
    }
    else if (tool == L"process.describe")
    {
        allowed = {L"source", L"image", L"name", L"process", L"pid", L"eprocess", L"fields"};
    }
    else if (tool == L"type.describe")
    {
        allowed = {L"source", L"image", L"name", L"process", L"pid", L"eprocess", L"address", L"type", L"fields"};
    }
    else if (tool == L"callbacks.list")
    {
        allowed = {L"scope", L"module", L"driver"};
    }
    else if (tool == L"wfp.list")
    {
        allowed = {L"scope", L"module", L"provider", L"layer"};
    }
    else if (tool == L"alpc.list")
    {
        allowed = {L"scope", L"name", L"pid"};
    }
    else if (tool == L"vad.list")
    {
        allowed = {L"source", L"image", L"name", L"process", L"pid", L"eprocess", L"exec", L"private", L"wx", L"pe", L"hiddenpte", L"dkom", L"summary", L"limit"};
    }
    else if (tool == L"threads.list")
    {
        allowed = {L"source", L"image", L"name", L"process", L"pid", L"eprocess", L"apc", L"stacks", L"limit"};
    }
    else if (tool == L"etw.integrity" || tool == L"assistant.answer")
    {
        allowed = {};
    }
    else if (tool == L"nmi.list")
    {
        allowed = {L"scope"};
    }
    else if (tool == L"fwtable.list" || tool == L"firmwaretable.list")
    {
        allowed = {L"scope", L"module", L"provider", L"signature"};
    }
    else if (tool == L"pool.find")
    {
        allowed = {L"tag", L"min", L"max", L"addr", L"address", L"limit", L"paged", L"annotate", L"wx"};
    }
    else if (tool == L"address.inspect")
    {
        allowed = {L"address", L"va", L"symbol"};
    }
    else if (tool == L"wnf.decode")
    {
        allowed = {L"hash", L"state", L"state_name"};
    }
    else if (tool == L"wnf.list")
    {
        allowed = {L"scope"};
    }
    else if (tool == L"ti.query")
    {
        allowed = {L"action", L"count", L"pid", L"task", L"pattern"};
    }
    else if (tool == L"module.integrity")
    {
        allowed = {L"module", L"name", L"target", L"limit", L"summary", L"verbose", L"headers", L"sections", L"wx", L"mismatch"};
    }
    else if (tool == L"driver.integrity")
    {
        allowed = {L"driver", L"name", L"target", L"limit"};
    }

    return ValidateJsonObjectKeys(argsJson, allowed, tool + L" args", error);
}

static bool ParseAiCapabilityPlanResponse(
    const std::wstring& responseText,
    AiCapabilityPlan* plan,
    std::wstring* error)
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
                *error = L"AI tool planner did not return a JSON object";
            }
            break;
        }

        AiCapabilityPlan parsed = {};
        parsed.RawResponse = responseText;
        if (!ValidateJsonObjectKeys(json, {L"schema", L"summary", L"steps"}, L"AI capability plan", error))
        {
            break;
        }

        ExtractJsonStringValue(json, L"schema", &parsed.Schema);
        ExtractJsonStringValue(json, L"summary", &parsed.Summary);
        if (parsed.Schema != L"kn-live-dbg.ai-capability-plan.v1")
        {
            if (error != nullptr)
            {
                *error = L"unsupported AI capability schema: " + parsed.Schema;
            }
            break;
        }

        std::vector<std::wstring> stepObjects = ExtractJsonArrayObjects(json, L"steps");
        if (stepObjects.empty())
        {
            if (error != nullptr)
            {
                *error = L"AI capability plan did not contain steps";
            }
            break;
        }

        if (stepObjects.size() > 6)
        {
            if (error != nullptr)
            {
                *error = L"AI capability plan has too many steps";
            }
            break;
        }

        for (const std::wstring& stepObject : stepObjects)
        {
            AiCapabilityStep step = {};
            std::vector<std::wstring> stepKeys = ExtractJsonObjectKeys(stepObject);
            if (!ValidateJsonObjectKeys(stepObject, {L"tool", L"capability", L"args"}, L"AI capability step", error))
            {
                parsed.Steps.clear();
                break;
            }

            ExtractJsonStringValue(stepObject, L"tool", &step.Tool);
            if (step.Tool.empty())
            {
                ExtractJsonStringValue(stepObject, L"capability", &step.Tool);
            }
            step.Tool = ToLower(TrimWhitespace(step.Tool));
            bool hasArgsField = JsonKeyAllowed(L"args", stepKeys);
            if (!ExtractJsonObjectValue(stepObject, L"args", &step.ArgsJson) && hasArgsField)
            {
                if (error != nullptr)
                {
                    *error = L"AI capability step args must be a JSON object";
                }
                parsed.Steps.clear();
                break;
            }
            if (step.ArgsJson.empty())
            {
                step.ArgsJson = L"{}";
            }

            if (!IsSupportedAiCapabilityTool(step.Tool))
            {
                if (error != nullptr)
                {
                    *error = L"unsupported AI capability tool: " + step.Tool;
                }
                parsed.Steps.clear();
                break;
            }

            if (!ValidateAiCapabilityToolArgKeys(step.Tool, step.ArgsJson, error))
            {
                parsed.Steps.clear();
                break;
            }

            parsed.Steps.push_back(step);
        }

        if (parsed.Steps.empty())
        {
            break;
        }

        *plan = parsed;
        ok = true;
    } while (false);

    return ok;
}

static std::wstring BuildAiCapabilityPlannerPrompt(const std::wstring& query)
{
    std::wstringstream stream;

    stream << L"You are the KnLiveDbg tool router. Choose local read-only tools for the operator request.\n";
    stream << L"Return only one JSON object, with no Markdown fences and no prose before or after it.\n";
    stream << L"Schema:\n";
    stream << L"{\"schema\":\"kn-live-dbg.ai-capability-plan.v1\",\"summary\":\"short summary\",\"steps\":[";
    stream << L"{\"tool\":\"process.find|process.describe|type.describe|callbacks.list|wfp.list|alpc.list|vad.list|threads.list|etw.integrity|nmi.list|fwtable.list|pool.find|address.inspect|wnf.decode|wnf.list|ti.query|module.integrity|driver.integrity|assistant.answer\",\"args\":{}}";
    stream << L"]}\n";
    stream << L"Available tools:\n";
    stream << L"- process.find: find live processes. Args are strings: image, pid, eprocess. Returns process records.\n";
    stream << L"- process.describe: print process fields. Args: source like \"$0\" or image/pid/eprocess, fields array. Supported fields: pid,image,eprocess,dtb,userdtb,peb,ppid,threads,all.\n";
    stream << L"- type.describe: dump a structure with dt. Args: source like \"$0\" or address/eprocess, type string, fields array of type field names. For process source, use each record EPROCESS address.\n";
    stream << L"- callbacks.list: list kernel callbacks. Args: scope string and optional module string. Supported scopes: all,object,registry,process,thread,imageload,minifilter.\n";
    stream << L"- wfp.list: list Windows Filtering Platform objects via fwpuclnt.dll. Args: scope (providers,sublayers,callouts,filters,layers; defaults to callouts), optional module (callouts/filters provider name or GUID), optional layer (filters only).\n";
    stream << L"- alpc.list: list ALPC ports discovered via Object Manager directory walk and CommunicationInfo links. Args: scope (ports,connections; defaults to ports), optional name substring, optional pid filter as decimal string.\n";
    stream << L"- vad.list: list target process VADs and optionally detect present PTE ranges missing from the VAD tree. Args: image, pid, eprocess, or source; optional booleans exec, private, wx, pe, hiddenpte, dkom, summary; optional limit string.\n";
    stream << L"- threads.list: list target process threads. Args: image, pid, eprocess, or source; optional booleans apc, stacks; optional limit string.\n";
    stream << L"- etw.integrity: check inline ETW GetCpuClock targets and suspicious callback redirects. Args: {}.\n";
    stream << L"- nmi.list: list registered NMI callbacks. Args: optional scope string \"callbacks\".\n";
    stream << L"- fwtable.list: list registered firmware table providers from nt!ExpFirmwareTableProviderListHead without invoking handlers. Args: optional scope providers|provider, optional module string, optional provider/signature string.\n";
    stream << L"- pool.find: find big pool entries. Args: optional tag, min, max, addr/address, limit strings; optional paged string any|nonpaged|paged; optional booleans annotate, wx. Use wx=true for W+X pool.\n";
    stream << L"- address.inspect: inspect one virtual address or symbol. Args: address, va, or symbol string.\n";
    stream << L"- wnf.decode: decode one WNF state-name hash. Args: hash, state, or state_name string.\n";
    stream << L"- wnf.list: list live WNF data. Args: optional scope string instances, candidates, or lists; defaults to instances.\n";
    stream << L"- ti.query: query the Threat Intelligence ring. Args: action recent|stats|by|grep; optional count, pid, task, pattern strings.\n";
    stream << L"- module.integrity: inspect loaded module PE headers, sections, and runtime page permissions. Args: optional module/name/target string, optional limit string, optional booleans summary, verbose, headers, sections, wx, mismatch.\n";
    stream << L"- driver.integrity: inspect DRIVER_OBJECT dispatch targets. Args: optional driver/name/target string and optional limit string.\n";
    stream << L"- assistant.answer: use this when none of the local tools fit the request. Args: {}.\n";
    stream << L"Rules:\n";
    stream << L"- Use only these tools. Do not emit debugger commands.\n";
    stream << L"- All scalar args must be JSON strings. Use fields as an array of strings. Do not invent fields.\n";
    stream << L"- Never emit raw kd commands, nested ai commands, writes, unload/shutdown, session mutation, command chaining, or multiline content.\n";
    stream << L"- For image-name process questions, first use process.find with image, then describe or type.describe source \"$0\".\n";
    stream << L"- For PID/EPROCESS/DTB/PEB answers, prefer process.describe.\n";
    stream << L"- For full _EPROCESS layout at the found process, use type.describe with type \"nt!_EPROCESS\" and source \"$0\".\n";
    stream << L"- For callback requests such as object callbacks for WdFilter.sys, use callbacks.list with scope \"object\" and module \"WdFilter.sys\".\n";
    stream << L"- For WFP questions such as callouts owned by tcpip or filters in the ALE auth connect layer, use wfp.list with the appropriate scope and module/layer.\n";
    stream << L"- For ALPC questions such as listing named ports or pairing csrss/lsass connections, use alpc.list with scope ports or connections and optional name/pid filters.\n";
    stream << L"- For executable private memory, W+X, PE-like VADs, process memory region triage, or VAD DKOM/hidden PTE checks, use vad.list directly. Use hiddenpte=true for VAD DKOM checks.\n";
    stream << L"- For suspicious thread starts, stack bounds, or APC evidence, use threads.list directly.\n";
    stream << L"- For inline ETW hook questions, use etw.integrity.\n";
    stream << L"- For NMI callback questions, use nmi.list.\n";
    stream << L"- For firmware table provider, SystemRegisterFirmwareTableInformationHandler, or firmware-table cheat-channel questions, use fwtable.list.\n";
    stream << L"- For W+X pool or suspicious big pool allocation questions, use pool.find with wx=true or explicit filters.\n";
    stream << L"- For address suspicion or page permission questions, use address.inspect.\n";
    stream << L"- For WNF decode questions, use wnf.decode; for live WNF instance/list questions, use wnf.list.\n";
    stream << L"- For recent Microsoft-Windows-Threat-Intelligence events, use ti.query with recent/stats/by/grep.\n";
    stream << L"- For driver dispatch integrity questions, use driver.integrity.\n";
    stream << L"- For module text or executable section integrity questions, use module.integrity. Use wx=true for W+X-only module triage, headers=true for PE header evidence, and sections=true for full section-table evidence.\n";
    stream << L"- Keep the plan read-only and no more than three steps unless the request needs more.\n";
    stream << L"Examples:\n";
    stream << L"- \"any inline ETW hook?\" => etw.integrity {}\n";
    stream << L"- \"list NMI callbacks\" => nmi.list {\"scope\":\"callbacks\"}\n";
    stream << L"- \"list firmware table providers\" => fwtable.list {\"scope\":\"providers\"}\n";
    stream << L"- \"show custom firmware handler ACPI\" => fwtable.list {\"scope\":\"provider\",\"provider\":\"ACPI\"}\n";
    stream << L"- \"show W+X pool allocations\" => pool.find {\"wx\":\"true\",\"limit\":\"50\"}\n";
    stream << L"- \"why is this address suspicious?\" => address.inspect {\"address\":\"<address>\"}\n";
    stream << L"- \"decode this WNF state name\" => wnf.decode {\"hash\":\"<hash>\"}\n";
    stream << L"- \"show live WNF instances\" => wnf.list {\"scope\":\"instances\"}\n";
    stream << L"- \"query recent TI WriteVM events\" => ti.query {\"action\":\"grep\",\"pattern\":\"WriteVM\"}\n";
    stream << L"- \"check driver dispatch integrity\" => driver.integrity {\"target\":\"all\"}\n";
    stream << L"- \"inspect module text integrity\" => module.integrity {\"target\":\"all\",\"headers\":\"true\",\"sections\":\"true\"}\n";
    stream << L"Operator request:\n";
    stream << query << L"\n";

    return stream.str();
}

static bool IsAiCapabilityAssistantAnswerPlan(const AiCapabilityPlan& plan)
{
    return plan.Steps.size() == 1 && plan.Steps[0].Tool == L"assistant.answer";
}

static bool ExecuteAiCapabilityProcessFind(
    const AiCapabilityStep& step,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    AiCapabilityStepResult* result,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            break;
        }

        bool truncated = false;
        if (!CollectAiCapabilityProcessMatches(step.ArgsJson, state, device, symbols, &result->Processes, &truncated, error))
        {
            break;
        }

        result->HasProcesses = true;
        PrintColoredText(L"ai tool", KNDBG_COLOR_TITLE);
        std::wcout << L": process.find\n";
        PrintDmlProcessHeader();
        for (const DmlProcessRecord& record : result->Processes)
        {
            PrintDmlProcessRecord(record);
        }

        PrintColoredText(L"matches", KNDBG_COLOR_TITLE);
        std::wcout << L"=" << result->Processes.size();
        if (truncated)
        {
            std::wcout << L" truncated=yes";
        }
        std::wcout << L"\n";
        ok = true;
    } while (false);

    return ok;
}

static bool ExecuteAiCapabilityProcessDescribe(
    const AiCapabilityStep& step,
    const std::vector<AiCapabilityStepResult>& results,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    AiCapabilityStepResult* result,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            break;
        }

        bool truncated = false;
        if (!ResolveAiCapabilityProcessInput(step.ArgsJson, results, state, device, symbols, &result->Processes, &truncated, error))
        {
            break;
        }

        result->HasProcesses = true;
        std::vector<std::wstring> fields = ExtractJsonStringArrayValues(step.ArgsJson, L"fields");

        PrintColoredText(L"ai tool", KNDBG_COLOR_TITLE);
        std::wcout << L": process.describe\n";
        PrintAiCapabilityProcessDescriptions(result->Processes, fields);
        PrintColoredText(L"records", KNDBG_COLOR_TITLE);
        std::wcout << L"=" << result->Processes.size();
        if (truncated)
        {
            std::wcout << L" truncated=yes";
        }
        std::wcout << L"\n";
        ok = true;
    } while (false);

    return ok;
}

static bool ValidateAiCapabilityScalarText(
    const std::wstring& value,
    const std::wstring& label,
    std::wstring* error);

static bool ExecuteAiCapabilityTypeDescribeForAddress(
    const std::wstring& typeName,
    const std::wstring& addressText,
    const std::vector<std::wstring>& fields,
    const DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        std::wstring trimmedType = TrimWhitespace(typeName);
        std::wstring trimmedAddress = TrimWhitespace(addressText);
        if (trimmedType.empty() || trimmedAddress.empty())
        {
            break;
        }

        if (!ValidateAiCapabilityScalarText(trimmedType, L"type name", error) ||
            !ValidateAiCapabilityScalarText(trimmedAddress, L"type address", error))
        {
            break;
        }

        if (IsSwitchLikeToken(trimmedType) || IsSwitchLikeToken(trimmedAddress))
        {
            if (error != nullptr)
            {
                *error = L"type.describe type and address cannot be option tokens";
            }
            break;
        }

        std::vector<std::wstring> args;
        args.push_back(L"dt");
        args.push_back(trimmedType);
        args.push_back(trimmedAddress);
        for (const std::wstring& field : fields)
        {
            std::wstring trimmedField = TrimWhitespace(field);
            if (trimmedField.empty() || ToLower(trimmedField) == L"all")
            {
                continue;
            }

            if (!ValidateAiCapabilityScalarText(trimmedField, L"type field", error) ||
                IsSwitchLikeToken(trimmedField))
            {
                if (error != nullptr && error->empty())
                {
                    *error = L"type.describe field cannot be an option token";
                }
                break;
            }

            args.push_back(trimmedField);
        }

        if (error != nullptr && !error->empty())
        {
            break;
        }

        std::wcout << L"tool> " << JoinArgs(args, 0) << L"\n";
        HandleDtCommand(args, state, device, symbols);
        ok = true;
    } while (false);

    return ok;
}

static bool ExecuteAiCapabilityTypeDescribe(
    const AiCapabilityStep& step,
    const std::vector<AiCapabilityStepResult>& results,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    AiCapabilityStepResult* result,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            break;
        }

        std::wstring typeName;
        ExtractJsonStringValue(step.ArgsJson, L"type", &typeName);
        if (TrimWhitespace(typeName).empty())
        {
            typeName = L"nt!_EPROCESS";
        }

        std::vector<std::wstring> fields = ExtractJsonStringArrayValues(step.ArgsJson, L"fields");

        std::wstring addressText;
        if (!ExtractJsonScalarValue(step.ArgsJson, L"address", &addressText))
        {
            ExtractJsonScalarValue(step.ArgsJson, L"eprocess", &addressText);
        }

        PrintColoredText(L"ai tool", KNDBG_COLOR_TITLE);
        std::wcout << L": type.describe\n";

        if (!TrimWhitespace(addressText).empty())
        {
            if (!ExecuteAiCapabilityTypeDescribeForAddress(typeName, TrimWhitespace(addressText), fields, state, device, symbols, error))
            {
                if (error != nullptr)
                {
                    if (error->empty())
                    {
                        *error = L"type.describe requires a type and address";
                    }
                }
                break;
            }

            ok = true;
            break;
        }

        std::vector<DmlProcessRecord> records;
        bool truncated = false;
        if (!ResolveAiCapabilityProcessInput(step.ArgsJson, results, state, device, symbols, &records, &truncated, error))
        {
            break;
        }

        result->HasProcesses = true;
        result->Processes = records;
        if (records.empty())
        {
            std::wcout << L"records=0\n";
            ok = true;
            break;
        }

        bool dumpOk = true;
        for (const DmlProcessRecord& record : records)
        {
            if (!ExecuteAiCapabilityTypeDescribeForAddress(
                    typeName,
                    HexTextWidth(record.Eprocess, 16, true),
                    fields,
                    state,
                    device,
                    symbols,
                    error))
            {
                dumpOk = false;
                break;
            }
        }

        if (!dumpOk)
        {
            break;
        }

        if (truncated)
        {
            std::wcout << L"records truncated=yes\n";
        }
        ok = true;
    } while (false);

    return ok;
}

static std::wstring NormalizeAiCapabilityCallbackScope(const std::wstring& value)
{
    std::wstring scope = ToLower(TrimWhitespace(value));

    if (scope.empty())
    {
        scope = L"all";
    }
    else if (scope == L"ob" ||
             scope == L"objects" ||
             scope == L"object-manager" ||
             scope == L"object callback" ||
             scope == L"object callbacks" ||
             scope == L"object-callback" ||
             scope == L"object-callbacks" ||
             scope == L"object_callbacks")
    {
        scope = L"object";
    }
    else if (scope == L"reg" ||
             scope == L"registry callback" ||
             scope == L"registry callbacks" ||
             scope == L"registry-callback" ||
             scope == L"registry-callbacks" ||
             scope == L"registry_callbacks")
    {
        scope = L"registry";
    }
    else if (scope == L"proc" ||
             scope == L"processes" ||
             scope == L"process callback" ||
             scope == L"process callbacks" ||
             scope == L"process-callback" ||
             scope == L"process-callbacks" ||
             scope == L"process_callbacks")
    {
        scope = L"process";
    }
    else if (scope == L"threads" ||
             scope == L"thread callback" ||
             scope == L"thread callbacks" ||
             scope == L"thread-callback" ||
             scope == L"thread-callbacks" ||
             scope == L"thread_callbacks")
    {
        scope = L"thread";
    }
    else if (scope == L"image" ||
             scope == L"loadimage" ||
             scope == L"load-image" ||
             scope == L"imgload" ||
             scope == L"image load" ||
             scope == L"image-load callback" ||
             scope == L"image-load callbacks" ||
             scope == L"image-load" ||
             scope == L"image load callback" ||
             scope == L"image load callbacks" ||
             scope == L"image_load")
    {
        scope = L"imageload";
    }
    else if (scope == L"mini" ||
             scope == L"minifilters" ||
             scope == L"flt" ||
             scope == L"fltmgr" ||
             scope == L"filter" ||
             scope == L"filters" ||
             scope == L"mini filter" ||
             scope == L"mini filters" ||
             scope == L"file system filter" ||
             scope == L"file system filters")
    {
        scope = L"minifilter";
    }

    return scope;
}

static bool ExecuteAiCapabilityAlpcList(
    const AiCapabilityStep& step,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        std::wstring scope;
        ExtractJsonStringValue(step.ArgsJson, L"scope", &scope);
        scope = ToLower(TrimWhitespace(scope));
        if (scope.empty())
        {
            scope = L"ports";
        }

        if (scope != L"ports" && scope != L"connections")
        {
            if (error != nullptr)
            {
                *error = L"alpc.list scope must be ports or connections";
            }
            break;
        }

        std::wstring name;
        ExtractJsonStringValue(step.ArgsJson, L"name", &name);
        name = TrimWhitespace(name);

        std::wstring pidText;
        ExtractJsonStringValue(step.ArgsJson, L"pid", &pidText);
        pidText = TrimWhitespace(pidText);

        std::wstring unsafeReason;
        if (!name.empty() && (ContainsUnsafeAiCommandCharacters(name, &unsafeReason) || IsHelpToken(name)))
        {
            if (error != nullptr)
            {
                *error = unsafeReason.empty() ? L"invalid alpc name filter" : unsafeReason;
            }
            break;
        }

        unsafeReason.clear();
        if (!pidText.empty() && (ContainsUnsafeAiCommandCharacters(pidText, &unsafeReason) || IsHelpToken(pidText)))
        {
            if (error != nullptr)
            {
                *error = unsafeReason.empty() ? L"invalid alpc pid filter" : unsafeReason;
            }
            break;
        }

        if (!pidText.empty())
        {
            uint64_t pid = 0;
            if (!ParseUnsigned(pidText, 10, &pid))
            {
                if (error != nullptr)
                {
                    *error = L"alpc.list pid must be a decimal process id";
                }
                break;
            }
        }

        std::vector<std::wstring> args;
        args.push_back(L"!alpc");
        args.push_back(scope);
        if (!name.empty())
        {
            args.push_back(L"/name");
            args.push_back(name);
        }
        if (!pidText.empty())
        {
            args.push_back(L"/pid");
            args.push_back(pidText);
        }

        PrintColoredText(L"ai tool", KNDBG_COLOR_TITLE);
        std::wcout << L": alpc.list\n";
        std::wcout << L"tool> " << JoinArgs(args, 0) << L"\n";
        HandleAlpcCommand(args, state, device, symbols);
        ok = true;
    } while (false);

    return ok;
}

static bool ExecuteAiCapabilityWfpList(
    const AiCapabilityStep& step,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        std::wstring scope;
        ExtractJsonStringValue(step.ArgsJson, L"scope", &scope);
        scope = ToLower(TrimWhitespace(scope));
        if (scope.empty())
        {
            scope = L"callouts";
        }

        WfpScanner::Scope target = WfpScanner::Scope::Callouts;
        if (!ResolveWfpScope(scope, &target))
        {
            if (error != nullptr)
            {
                *error = L"unsupported wfp scope: " + scope;
            }
            break;
        }

        std::wstring module;
        if (!ExtractJsonStringValue(step.ArgsJson, L"module", &module))
        {
            ExtractJsonStringValue(step.ArgsJson, L"provider", &module);
        }
        module = TrimWhitespace(module);

        std::wstring layer;
        ExtractJsonStringValue(step.ArgsJson, L"layer", &layer);
        layer = TrimWhitespace(layer);

        std::wstring unsafeReason;
        if (!module.empty() && (ContainsUnsafeAiCommandCharacters(module, &unsafeReason) || IsHelpToken(module)))
        {
            if (error != nullptr)
            {
                *error = unsafeReason.empty() ? L"invalid wfp module filter" : unsafeReason;
            }
            break;
        }

        unsafeReason.clear();
        if (!layer.empty() && (ContainsUnsafeAiCommandCharacters(layer, &unsafeReason) || IsHelpToken(layer)))
        {
            if (error != nullptr)
            {
                *error = unsafeReason.empty() ? L"invalid wfp layer filter" : unsafeReason;
            }
            break;
        }

        std::vector<std::wstring> args;
        args.push_back(L"!wfp");
        args.push_back(scope);
        if (!module.empty())
        {
            if (target == WfpScanner::Scope::Callouts)
            {
                args.push_back(L"/module");
                args.push_back(module);
            }
            else if (target == WfpScanner::Scope::Filters)
            {
                args.push_back(L"/provider");
                args.push_back(module);
            }
        }

        if (!layer.empty() && target == WfpScanner::Scope::Filters)
        {
            args.push_back(L"/layer");
            args.push_back(layer);
        }

        PrintColoredText(L"ai tool", KNDBG_COLOR_TITLE);
        std::wcout << L": wfp.list\n";
        std::wcout << L"tool> " << JoinArgs(args, 0) << L"\n";
        HandleWfpCommand(args);
        ok = true;
    } while (false);

    return ok;
}

static bool ExecuteAiCapabilityCallbacksList(
    const AiCapabilityStep& step,
    DeviceClient& device,
    SymbolEngine& symbols,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        std::wstring scope;
        ExtractJsonStringValue(step.ArgsJson, L"scope", &scope);
        scope = NormalizeAiCapabilityCallbackScope(scope);
        if (!IsCallbackScopeName(scope))
        {
            if (error != nullptr)
            {
                *error = L"unsupported callback scope: " + scope;
            }
            break;
        }

        std::wstring module;
        if (!ExtractJsonStringValue(step.ArgsJson, L"module", &module))
        {
            ExtractJsonStringValue(step.ArgsJson, L"driver", &module);
        }
        module = TrimWhitespace(module);

        std::wstring unsafeReason;
        if (!module.empty() &&
            (ContainsUnsafeAiCommandCharacters(module, &unsafeReason) ||
             IsCallbackModuleOption(module) ||
             IsHelpToken(module)))
        {
            if (error != nullptr)
            {
                *error = unsafeReason.empty() ? L"invalid callback module filter" : unsafeReason;
            }
            break;
        }

        std::vector<std::wstring> args;
        args.push_back(L"callbacks");
        args.push_back(scope);
        if (!module.empty())
        {
            args.push_back(module);
        }

        PrintColoredText(L"ai tool", KNDBG_COLOR_TITLE);
        std::wcout << L": callbacks.list\n";
        std::wcout << L"tool> " << JoinArgs(args, 0) << L"\n";
        HandleCallbacksCommand(args, device, symbols);
        ok = true;
    } while (false);

    return ok;
}

static bool ExtractAiCapabilityBooleanArg(
    const std::wstring& argsJson,
    const std::wstring& key,
    bool* value,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (value == nullptr)
        {
            break;
        }

        bool boolValue = false;
        if (ExtractJsonBoolValue(argsJson, key, &boolValue))
        {
            *value = boolValue;
            ok = true;
            break;
        }

        std::wstring scalar;
        if (!ExtractJsonScalarValue(argsJson, key, &scalar))
        {
            ok = true;
            break;
        }

        std::wstring normalized = ToLower(TrimWhitespace(scalar));
        if (normalized == L"true" || normalized == L"yes" || normalized == L"1" || normalized == L"on")
        {
            *value = true;
            ok = true;
            break;
        }
        if (normalized == L"false" || normalized == L"no" || normalized == L"0" || normalized == L"off")
        {
            *value = false;
            ok = true;
            break;
        }

        if (error != nullptr)
        {
            *error = L"invalid boolean argument " + key + L": " + scalar;
        }
    } while (false);

    return ok;
}

static bool ValidateAiCapabilityTriageStringArg(
    const std::wstring& argsJson,
    const std::wstring& key,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        std::wstring value;
        if (!ExtractJsonStringValue(argsJson, key, &value))
        {
            ok = true;
            break;
        }

        value = TrimWhitespace(value);
        if (value.empty())
        {
            ok = true;
            break;
        }

        std::wstring unsafeReason;
        if (ContainsUnsafeAiCommandCharacters(value, &unsafeReason) || IsHelpToken(value))
        {
            if (error != nullptr)
            {
                *error = unsafeReason.empty() ? L"invalid " + key + L" argument" : unsafeReason;
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool ValidateAiCapabilityTriageArgs(const std::wstring& argsJson, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (!ValidateAiCapabilityTriageStringArg(argsJson, L"image", error) ||
            !ValidateAiCapabilityTriageStringArg(argsJson, L"name", error) ||
            !ValidateAiCapabilityTriageStringArg(argsJson, L"process", error) ||
            !ValidateAiCapabilityTriageStringArg(argsJson, L"source", error))
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool ResolveAiCapabilityTriageRecords(
    const AiCapabilityStep& step,
    const std::vector<AiCapabilityStepResult>& results,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    std::vector<DmlProcessRecord>* records,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (records == nullptr)
        {
            break;
        }

        if (!ValidateAiCapabilityTriageArgs(step.ArgsJson, error))
        {
            break;
        }

        std::wstring source;
        ExtractJsonStringValue(step.ArgsJson, L"source", &source);
        if (TrimWhitespace(source).empty() &&
            !HasAiCapabilityProcessFilterArg(step.ArgsJson) &&
            (results.empty() || !results.back().HasProcesses))
        {
            if (error != nullptr)
            {
                *error = step.Tool + L" requires image, pid, eprocess, or source";
            }
            break;
        }

        bool truncated = false;
        if (!ResolveAiCapabilityProcessInput(step.ArgsJson, results, state, device, symbols, records, &truncated, error))
        {
            break;
        }

        if (records->empty())
        {
            if (error != nullptr)
            {
                *error = step.Tool + L" target did not match any process";
            }
            break;
        }

        if (records->size() > 8)
        {
            if (error != nullptr)
            {
                *error = step.Tool + L" matched too many processes; narrow by pid or eprocess";
            }
            break;
        }

        if (truncated)
        {
            std::wcerr << L"ai tool warning: process list was truncated\n";
        }

        ok = true;
    } while (false);

    return ok;
}

static bool AppendAiCapabilityLimitOption(
    const std::wstring& argsJson,
    const DebuggerState& state,
    std::vector<std::wstring>* args,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (args == nullptr)
        {
            break;
        }

        std::wstring limitText;
        if (!ExtractJsonScalarValue(argsJson, L"limit", &limitText) || TrimWhitespace(limitText).empty())
        {
            ok = true;
            break;
        }

        uint32_t limit = 0;
        if (!ParseProcessTriageLimit(TrimWhitespace(limitText), state.NumberBase, &limit, error))
        {
            break;
        }

        args->push_back(L"/limit");
        args->push_back(std::to_wstring(limit));
        ok = true;
    } while (false);

    return ok;
}

static bool ExecuteAiCapabilityVadList(
    const AiCapabilityStep& step,
    const std::vector<AiCapabilityStepResult>& results,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    AiCapabilityStepResult* result,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            break;
        }

        std::vector<DmlProcessRecord> records;
        if (!ResolveAiCapabilityTriageRecords(step, results, state, device, symbols, &records, error))
        {
            break;
        }

        bool execOnly = false;
        bool privateOnly = false;
        bool wxOnly = false;
        bool peOnly = false;
        bool hiddenPte = false;
        bool dkom = false;
        bool summaryOnly = false;
        if (!ExtractAiCapabilityBooleanArg(step.ArgsJson, L"exec", &execOnly, error) ||
            !ExtractAiCapabilityBooleanArg(step.ArgsJson, L"private", &privateOnly, error) ||
            !ExtractAiCapabilityBooleanArg(step.ArgsJson, L"wx", &wxOnly, error) ||
            !ExtractAiCapabilityBooleanArg(step.ArgsJson, L"pe", &peOnly, error) ||
            !ExtractAiCapabilityBooleanArg(step.ArgsJson, L"hiddenpte", &hiddenPte, error) ||
            !ExtractAiCapabilityBooleanArg(step.ArgsJson, L"dkom", &dkom, error) ||
            !ExtractAiCapabilityBooleanArg(step.ArgsJson, L"summary", &summaryOnly, error))
        {
            break;
        }

        PrintColoredText(L"ai tool", KNDBG_COLOR_TITLE);
        std::wcout << L": vad.list\n";

        for (const DmlProcessRecord& record : records)
        {
            std::vector<std::wstring> args;
            args.push_back(L"!vad");
            args.push_back(HexTextWidth(record.Eprocess, 16, true));
            if (summaryOnly)
            {
                args.push_back(L"/summary");
            }
            if (execOnly)
            {
                args.push_back(L"/exec");
            }
            if (privateOnly)
            {
                args.push_back(L"/private");
            }
            if (wxOnly)
            {
                args.push_back(L"/wx");
            }
            if (peOnly)
            {
                args.push_back(L"/pe");
            }
            if (hiddenPte || dkom)
            {
                args.push_back(L"/hiddenpte");
            }
            if (!AppendAiCapabilityLimitOption(step.ArgsJson, state, &args, error))
            {
                break;
            }

            std::wcout << L"tool> " << JoinArgs(args, 0) << L"\n";
            HandleVadCommand(args, state, device, symbols);
        }

        if (error != nullptr && !error->empty())
        {
            break;
        }

        result->HasProcesses = true;
        result->Processes = records;
        ok = true;
    } while (false);

    return ok;
}

static bool ExecuteAiCapabilityThreadsList(
    const AiCapabilityStep& step,
    const std::vector<AiCapabilityStepResult>& results,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    AiCapabilityStepResult* result,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            break;
        }

        std::vector<DmlProcessRecord> records;
        if (!ResolveAiCapabilityTriageRecords(step, results, state, device, symbols, &records, error))
        {
            break;
        }

        bool includeApc = false;
        bool includeStacks = false;
        if (!ExtractAiCapabilityBooleanArg(step.ArgsJson, L"apc", &includeApc, error) ||
            !ExtractAiCapabilityBooleanArg(step.ArgsJson, L"stacks", &includeStacks, error))
        {
            break;
        }

        PrintColoredText(L"ai tool", KNDBG_COLOR_TITLE);
        std::wcout << L": threads.list\n";

        for (const DmlProcessRecord& record : records)
        {
            std::vector<std::wstring> args;
            args.push_back(L"!threads");
            args.push_back(HexTextWidth(record.Eprocess, 16, true));
            if (includeApc)
            {
                args.push_back(L"/apc");
            }
            if (includeStacks)
            {
                args.push_back(L"/stacks");
            }
            if (!AppendAiCapabilityLimitOption(step.ArgsJson, state, &args, error))
            {
                break;
            }

            std::wcout << L"tool> " << JoinArgs(args, 0) << L"\n";
            HandleThreadsCommand(args, state, device, symbols);
        }

        if (error != nullptr && !error->empty())
        {
            break;
        }

        result->HasProcesses = true;
        result->Processes = records;
        ok = true;
    } while (false);

    return ok;
}

static bool ExtractAiCapabilityScalarAlias(
    const std::wstring& argsJson,
    const std::vector<std::wstring>& keys,
    std::wstring* value)
{
    bool found = false;

    do
    {
        if (value == nullptr)
        {
            break;
        }

        value->clear();
        for (const std::wstring& key : keys)
        {
            std::wstring candidate;
            if (ExtractJsonScalarValue(argsJson, key, &candidate) && !TrimWhitespace(candidate).empty())
            {
                *value = TrimWhitespace(candidate);
                found = true;
                break;
            }
        }
    } while (false);

    return found;
}

static bool ValidateAiCapabilityScalarText(
    const std::wstring& value,
    const std::wstring& label,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        std::wstring unsafeReason;
        if (ContainsUnsafeAiCommandCharacters(value, &unsafeReason) || IsHelpToken(value))
        {
            if (error != nullptr)
            {
                *error = unsafeReason.empty() ? L"invalid " + label + L" argument" : unsafeReason;
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool ExecuteAiCapabilityEtwIntegrity(
    const AiCapabilityStep& step,
    DeviceClient& device,
    SymbolEngine& symbols,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        (void)step;

        if (!device.IsOpen())
        {
            if (error != nullptr)
            {
                *error = L"etw.integrity requires the KnLiveDbg.sys driver device to be open";
            }
            break;
        }

        std::vector<std::wstring> args;
        args.push_back(L"!etw");
        args.push_back(L"integrity");

        PrintColoredText(L"ai tool", KNDBG_COLOR_TITLE);
        std::wcout << L": etw.integrity\n";
        std::wcout << L"tool> " << JoinArgs(args, 0) << L"\n";
        HandleEtwCommand(args, device, symbols);
        ok = true;
    } while (false);

    return ok;
}

static bool ExecuteAiCapabilityNmiList(
    const AiCapabilityStep& step,
    DeviceClient& device,
    SymbolEngine& symbols,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        std::wstring scope;
        ExtractJsonStringValue(step.ArgsJson, L"scope", &scope);
        scope = ToLower(TrimWhitespace(scope));
        if (scope.empty())
        {
            scope = L"callbacks";
        }
        if (scope != L"callbacks")
        {
            if (error != nullptr)
            {
                *error = L"nmi.list scope must be callbacks";
            }
            break;
        }
        if (!device.IsOpen())
        {
            if (error != nullptr)
            {
                *error = L"nmi.list requires the KnLiveDbg.sys driver device to be open";
            }
            break;
        }

        std::vector<std::wstring> args;
        args.push_back(L"!nmi");
        args.push_back(L"callbacks");

        PrintColoredText(L"ai tool", KNDBG_COLOR_TITLE);
        std::wcout << L": nmi.list\n";
        std::wcout << L"tool> " << JoinArgs(args, 0) << L"\n";
        HandleNmiCommand(args, device, symbols);
        ok = true;
    } while (false);

    return ok;
}

static bool ExecuteAiCapabilityFirmwareTableList(
    const AiCapabilityStep& step,
    const DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (!device.IsOpen())
        {
            if (error != nullptr)
            {
                *error = step.Tool + L" requires the KnLiveDbg.sys driver device to be open";
            }
            break;
        }

        std::wstring scope;
        ExtractJsonStringValue(step.ArgsJson, L"scope", &scope);
        scope = ToLower(TrimWhitespace(scope));
        if (scope.empty())
        {
            scope = L"providers";
        }
        if (scope != L"providers" && scope != L"provider")
        {
            if (error != nullptr)
            {
                *error = step.Tool + L" scope must be providers or provider";
            }
            break;
        }

        std::wstring module;
        ExtractJsonStringValue(step.ArgsJson, L"module", &module);
        module = TrimWhitespace(module);
        if (!module.empty() && !ValidateAiCapabilityScalarText(module, L"fwtable module", error))
        {
            break;
        }
        if (!module.empty() && IsSwitchLikeToken(module))
        {
            if (error != nullptr)
            {
                *error = L"fwtable module cannot be an option token";
            }
            break;
        }

        std::wstring provider;
        if (!ExtractAiCapabilityScalarAlias(step.ArgsJson, {L"provider", L"signature"}, &provider))
        {
            provider.clear();
        }
        if (!provider.empty() && !ValidateAiCapabilityScalarText(provider, L"fwtable provider", error))
        {
            break;
        }
        if (!provider.empty() && IsSwitchLikeToken(provider))
        {
            if (error != nullptr)
            {
                *error = L"fwtable provider cannot be an option token";
            }
            break;
        }
        if (!provider.empty() && !module.empty())
        {
            if (error != nullptr)
            {
                *error = L"fwtable module filter applies only to providers scope";
            }
            break;
        }

        std::vector<std::wstring> args;
        args.push_back(L"!fwtable");
        if (scope == L"provider" || !provider.empty())
        {
            if (provider.empty())
            {
                if (error != nullptr)
                {
                    *error = step.Tool + L" provider scope requires provider or signature";
                }
                break;
            }
            args.push_back(L"provider");
            args.push_back(provider);
        }
        else
        {
            args.push_back(L"providers");
            if (!module.empty())
            {
                args.push_back(L"/module");
                args.push_back(module);
            }
        }

        PrintColoredText(L"ai tool", KNDBG_COLOR_TITLE);
        std::wcout << L": fwtable.list\n";
        std::wcout << L"tool> " << JoinArgs(args, 0) << L"\n";
        HandleFirmwareTableCommand(args, state, device, symbols);
        ok = true;
    } while (false);

    return ok;
}

static bool ExecuteAiCapabilityPoolFind(
    const AiCapabilityStep& step,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        std::vector<std::wstring> args;
        args.push_back(L"!pool");
        args.push_back(L"find");

        bool hasFilter = false;
        bool parseFailed = false;

        std::wstring tag;
        if (ExtractAiCapabilityScalarAlias(step.ArgsJson, {L"tag"}, &tag))
        {
            if (!ValidateAiCapabilityScalarText(tag, L"pool tag", error))
            {
                break;
            }
            uint32_t tagValue = 0;
            if (!ParsePoolTagText(tag, &tagValue))
            {
                if (error != nullptr)
                {
                    *error = L"pool.find tag must be a 1..4 byte printable pool tag";
                }
                break;
            }
            args.push_back(L"/tag");
            args.push_back(tag);
            hasFilter = true;
        }

        const std::vector<std::pair<std::wstring, std::wstring>> numericOptions =
        {
            {L"min", L"/min"},
            {L"max", L"/max"},
            {L"addr", L"/addr"},
            {L"address", L"/addr"}
        };

        bool hasAddress = false;
        for (const std::pair<std::wstring, std::wstring>& item : numericOptions)
        {
            if (item.first == L"address" && hasAddress)
            {
                continue;
            }

            std::wstring value;
            if (!ExtractAiCapabilityScalarAlias(step.ArgsJson, {item.first}, &value))
            {
                continue;
            }
            if (!ValidateAiCapabilityScalarText(value, item.first, error))
            {
                parseFailed = true;
                break;
            }
            uint64_t parsed = 0;
            if (!ParseUnsigned(value, state.NumberBase, &parsed))
            {
                if (error != nullptr)
                {
                    *error = L"pool.find " + item.first + L" must be numeric";
                }
                parseFailed = true;
                break;
            }
            args.push_back(item.second);
            args.push_back(value);
            hasFilter = true;
            if (item.first == L"addr" || item.first == L"address")
            {
                hasAddress = true;
            }
        }

        if (parseFailed)
        {
            break;
        }

        std::wstring paged;
        if (ExtractAiCapabilityScalarAlias(step.ArgsJson, {L"paged"}, &paged))
        {
            paged = ToLower(TrimWhitespace(paged));
            if (paged == L"any" || paged == L"all")
            {
                args.push_back(L"/any");
            }
            else if (paged == L"paged" || paged == L"true")
            {
                args.push_back(L"/paged");
            }
            else if (paged == L"nonpaged" || paged == L"false")
            {
                args.push_back(L"/nonpaged");
            }
            else
            {
                if (error != nullptr)
                {
                    *error = L"pool.find paged must be any, paged, or nonpaged";
                }
                break;
            }
        }

        bool annotate = false;
        bool wx = false;
        if (!ExtractAiCapabilityBooleanArg(step.ArgsJson, L"annotate", &annotate, error) ||
            !ExtractAiCapabilityBooleanArg(step.ArgsJson, L"wx", &wx, error))
        {
            break;
        }
        if (wx)
        {
            if (!device.IsOpen())
            {
                if (error != nullptr)
                {
                    *error = L"pool.find wx requires the KnLiveDbg.sys driver device to be open";
                }
                break;
            }
            args.push_back(L"/wx");
            hasFilter = true;
        }
        else if (annotate)
        {
            if (!device.IsOpen())
            {
                if (error != nullptr)
                {
                    *error = L"pool.find annotate requires the KnLiveDbg.sys driver device to be open";
                }
                break;
            }
            args.push_back(L"/annotate");
        }

        if (!AppendAiCapabilityLimitOption(step.ArgsJson, state, &args, error))
        {
            break;
        }

        if (!hasFilter)
        {
            if (error != nullptr)
            {
                *error = L"pool.find requires tag, addr, min, max, or wx";
            }
            break;
        }

        PrintColoredText(L"ai tool", KNDBG_COLOR_TITLE);
        std::wcout << L": pool.find\n";
        std::wcout << L"tool> " << JoinArgs(args, 0) << L"\n";
        HandlePoolCommand(args, state, device, symbols);
        ok = true;
    } while (false);

    return ok;
}

static bool ExecuteAiCapabilityAddressInspect(
    const AiCapabilityStep& step,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (!device.IsOpen())
        {
            if (error != nullptr)
            {
                *error = L"address.inspect requires the KnLiveDbg.sys driver device to be open";
            }
            break;
        }

        std::wstring address;
        if (!ExtractAiCapabilityScalarAlias(step.ArgsJson, {L"address", L"va", L"symbol"}, &address))
        {
            if (error != nullptr)
            {
                *error = L"address.inspect requires address, va, or symbol";
            }
            break;
        }
        if (!ValidateAiCapabilityScalarText(address, L"address", error))
        {
            break;
        }

        std::vector<std::wstring> args;
        args.push_back(L"!address");
        args.push_back(address);

        PrintColoredText(L"ai tool", KNDBG_COLOR_TITLE);
        std::wcout << L": address.inspect\n";
        std::wcout << L"tool> " << JoinArgs(args, 0) << L"\n";
        HandleAddressCommand(args, state, device, symbols);
        ok = true;
    } while (false);

    return ok;
}

static bool ExecuteAiCapabilityWnfDecode(
    const AiCapabilityStep& step,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        std::wstring hash;
        if (!ExtractAiCapabilityScalarAlias(step.ArgsJson, {L"hash", L"state", L"state_name"}, &hash))
        {
            if (error != nullptr)
            {
                *error = L"wnf.decode requires hash, state, or state_name";
            }
            break;
        }
        if (!ValidateAiCapabilityScalarText(hash, L"wnf hash", error))
        {
            break;
        }
        uint64_t parsed = 0;
        if (!ParseUnsigned(hash, state.NumberBase, &parsed))
        {
            if (error != nullptr)
            {
                *error = L"wnf.decode hash must be numeric";
            }
            break;
        }

        std::vector<std::wstring> args;
        args.push_back(L"!wnf");
        args.push_back(L"decode");
        args.push_back(hash);

        PrintColoredText(L"ai tool", KNDBG_COLOR_TITLE);
        std::wcout << L": wnf.decode\n";
        std::wcout << L"tool> " << JoinArgs(args, 0) << L"\n";
        HandleWnfCommand(args, state, device, symbols);
        ok = true;
    } while (false);

    return ok;
}

static bool ExecuteAiCapabilityWnfList(
    const AiCapabilityStep& step,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (!device.IsOpen())
        {
            if (error != nullptr)
            {
                *error = L"wnf.list requires the KnLiveDbg.sys driver device to be open";
            }
            break;
        }

        std::wstring scope;
        ExtractJsonStringValue(step.ArgsJson, L"scope", &scope);
        scope = ToLower(TrimWhitespace(scope));
        if (scope.empty())
        {
            scope = L"instances";
        }
        if (scope != L"instances" && scope != L"candidates" && scope != L"lists")
        {
            if (error != nullptr)
            {
                *error = L"wnf.list scope must be instances, candidates, or lists";
            }
            break;
        }

        std::vector<std::wstring> args;
        args.push_back(L"!wnf");
        args.push_back(scope);

        PrintColoredText(L"ai tool", KNDBG_COLOR_TITLE);
        std::wcout << L": wnf.list\n";
        std::wcout << L"tool> " << JoinArgs(args, 0) << L"\n";
        HandleWnfCommand(args, state, device, symbols);
        ok = true;
    } while (false);

    return ok;
}

static bool ExecuteAiCapabilityTiQuery(
    const AiCapabilityStep& step,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        std::wstring action;
        ExtractJsonStringValue(step.ArgsJson, L"action", &action);
        action = ToLower(TrimWhitespace(action));

        std::wstring pattern;
        ExtractAiCapabilityScalarAlias(step.ArgsJson, {L"pattern"}, &pattern);
        std::wstring pidText;
        ExtractAiCapabilityScalarAlias(step.ArgsJson, {L"pid"}, &pidText);
        std::wstring task;
        ExtractAiCapabilityScalarAlias(step.ArgsJson, {L"task"}, &task);
        std::wstring count;
        ExtractAiCapabilityScalarAlias(step.ArgsJson, {L"count"}, &count);

        if (action.empty())
        {
            if (!pattern.empty())
            {
                action = L"grep";
            }
            else if (!pidText.empty() || !task.empty())
            {
                action = L"by";
            }
            else
            {
                action = L"recent";
            }
        }

        std::vector<std::wstring> args;
        args.push_back(L"!ti");

        if (action == L"recent")
        {
            args.push_back(L"recent");
            if (!count.empty())
            {
                uint64_t parsed = 0;
                if (!ValidateAiCapabilityScalarText(count, L"ti count", error) ||
                    !ParseUnsigned(count, 10, &parsed) ||
                    parsed == 0)
                {
                    if (error != nullptr && error->empty())
                    {
                        *error = L"ti.query count must be a positive decimal number";
                    }
                    break;
                }
                args.push_back(count);
            }
        }
        else if (action == L"stats")
        {
            args.push_back(L"stats");
        }
        else if (action == L"by")
        {
            args.push_back(L"by");
            if (!pidText.empty())
            {
                uint64_t parsed = 0;
                if (!ValidateAiCapabilityScalarText(pidText, L"ti pid", error) ||
                    !ParseUnsigned(pidText, 0, &parsed) ||
                    parsed == 0 ||
                    parsed > 0xffffffffull)
                {
                    if (error != nullptr && error->empty())
                    {
                        *error = L"ti.query pid must be a valid process id";
                    }
                    break;
                }
                args.push_back(L"pid");
                args.push_back(pidText);
            }
            else if (!task.empty())
            {
                if (!ValidateAiCapabilityScalarText(task, L"ti task", error))
                {
                    break;
                }
                args.push_back(L"task");
                args.push_back(task);
            }
            else
            {
                if (error != nullptr)
                {
                    *error = L"ti.query action by requires pid or task";
                }
                break;
            }
        }
        else if (action == L"grep")
        {
            if (pattern.empty())
            {
                if (error != nullptr)
                {
                    *error = L"ti.query action grep requires pattern";
                }
                break;
            }
            if (!ValidateAiCapabilityScalarText(pattern, L"ti pattern", error))
            {
                break;
            }
            args.push_back(L"grep");
            args.push_back(pattern);
        }
        else
        {
            if (error != nullptr)
            {
                *error = L"ti.query action must be recent, stats, by, or grep";
            }
            break;
        }

        PrintColoredText(L"ai tool", KNDBG_COLOR_TITLE);
        std::wcout << L": ti.query\n";
        std::wcout << L"tool> " << JoinArgs(args, 0) << L"\n";
        HandleTiCommand(args, state, device, symbols);
        ok = true;
    } while (false);

    return ok;
}

static bool ExecuteAiCapabilityModuleIntegrity(
    const AiCapabilityStep& step,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (!device.IsOpen())
        {
            if (error != nullptr)
            {
                *error = L"module.integrity requires the KnLiveDbg.sys driver device to be open";
            }
            break;
        }

        std::wstring target;
        ExtractAiCapabilityScalarAlias(step.ArgsJson, {L"module", L"name", L"target"}, &target);
        if (!target.empty() && !ValidateAiCapabilityScalarText(target, L"module target", error))
        {
            break;
        }
        if (!target.empty() && IsSwitchLikeToken(target))
        {
            if (error != nullptr)
            {
                *error = L"module target cannot be an option token";
            }
            break;
        }

        std::vector<std::wstring> args;
        args.push_back(L"!module");
        args.push_back(L"integrity");
        if (!target.empty())
        {
            args.push_back(target);
        }
        if (!AppendAiCapabilityLimitOption(step.ArgsJson, state, &args, error))
        {
            break;
        }

        bool summaryOnly = false;
        bool verbose = false;
        bool headers = false;
        bool sections = false;
        bool wx = false;
        bool mismatch = false;
        if (!ExtractAiCapabilityBooleanArg(step.ArgsJson, L"summary", &summaryOnly, error) ||
            !ExtractAiCapabilityBooleanArg(step.ArgsJson, L"verbose", &verbose, error) ||
            !ExtractAiCapabilityBooleanArg(step.ArgsJson, L"headers", &headers, error) ||
            !ExtractAiCapabilityBooleanArg(step.ArgsJson, L"sections", &sections, error) ||
            !ExtractAiCapabilityBooleanArg(step.ArgsJson, L"wx", &wx, error) ||
            !ExtractAiCapabilityBooleanArg(step.ArgsJson, L"mismatch", &mismatch, error))
        {
            break;
        }
        if (summaryOnly)
        {
            args.push_back(L"/summary");
        }
        if (verbose)
        {
            args.push_back(L"/verbose");
        }
        if (headers)
        {
            args.push_back(L"/headers");
        }
        if (sections)
        {
            args.push_back(L"/sections");
        }
        if (wx)
        {
            args.push_back(L"/wx");
        }
        if (mismatch)
        {
            args.push_back(L"/mismatch");
        }

        PrintColoredText(L"ai tool", KNDBG_COLOR_TITLE);
        std::wcout << L": module.integrity\n";
        std::wcout << L"tool> " << JoinArgs(args, 0) << L"\n";
        HandleModuleIntegrityCommand(args, state, device, symbols);
        ok = true;
    } while (false);

    return ok;
}

static bool ExecuteAiCapabilityDriverIntegrity(
    const AiCapabilityStep& step,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (!device.IsOpen())
        {
            if (error != nullptr)
            {
                *error = L"driver.integrity requires the KnLiveDbg.sys driver device to be open";
            }
            break;
        }

        std::wstring target;
        ExtractAiCapabilityScalarAlias(step.ArgsJson, {L"driver", L"name", L"target"}, &target);
        if (!target.empty() && !ValidateAiCapabilityScalarText(target, L"driver target", error))
        {
            break;
        }
        if (!target.empty() && IsSwitchLikeToken(target))
        {
            if (error != nullptr)
            {
                *error = L"driver target cannot be an option token";
            }
            break;
        }

        std::vector<std::wstring> args;
        args.push_back(L"!driver");
        args.push_back(L"integrity");
        if (!target.empty())
        {
            args.push_back(target);
        }
        if (!AppendAiCapabilityLimitOption(step.ArgsJson, state, &args, error))
        {
            break;
        }

        PrintColoredText(L"ai tool", KNDBG_COLOR_TITLE);
        std::wcout << L": driver.integrity\n";
        std::wcout << L"tool> " << JoinArgs(args, 0) << L"\n";
        HandleDriverIntegrityCommand(args, state, device, symbols);
        ok = true;
    } while (false);

    return ok;
}

static bool ExecuteAiCapabilityPlan(
    const AiCapabilityPlan& plan,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    std::wstring* error)
{
    bool ok = false;
    std::vector<AiCapabilityStepResult> results;

    do
    {
        if (!plan.Summary.empty())
        {
            PrintColoredText(L"ai tools", KNDBG_COLOR_TITLE);
            std::wcout << L": " << plan.Summary << L"\n";
        }

        for (const AiCapabilityStep& step : plan.Steps)
        {
            AiCapabilityStepResult result = {};
            bool stepOk = false;

            if (step.Tool == L"process.find")
            {
                stepOk = ExecuteAiCapabilityProcessFind(step, state, device, symbols, &result, error);
            }
            else if (step.Tool == L"process.describe")
            {
                stepOk = ExecuteAiCapabilityProcessDescribe(step, results, state, device, symbols, &result, error);
            }
            else if (step.Tool == L"type.describe")
            {
                stepOk = ExecuteAiCapabilityTypeDescribe(step, results, state, device, symbols, &result, error);
            }
            else if (step.Tool == L"callbacks.list")
            {
                stepOk = ExecuteAiCapabilityCallbacksList(step, device, symbols, error);
            }
            else if (step.Tool == L"wfp.list")
            {
                stepOk = ExecuteAiCapabilityWfpList(step, error);
            }
            else if (step.Tool == L"alpc.list")
            {
                stepOk = ExecuteAiCapabilityAlpcList(step, state, device, symbols, error);
            }
            else if (step.Tool == L"vad.list")
            {
                stepOk = ExecuteAiCapabilityVadList(step, results, state, device, symbols, &result, error);
            }
            else if (step.Tool == L"threads.list")
            {
                stepOk = ExecuteAiCapabilityThreadsList(step, results, state, device, symbols, &result, error);
            }
            else if (step.Tool == L"etw.integrity")
            {
                stepOk = ExecuteAiCapabilityEtwIntegrity(step, device, symbols, error);
            }
            else if (step.Tool == L"nmi.list")
            {
                stepOk = ExecuteAiCapabilityNmiList(step, device, symbols, error);
            }
            else if (step.Tool == L"fwtable.list" || step.Tool == L"firmwaretable.list")
            {
                stepOk = ExecuteAiCapabilityFirmwareTableList(step, state, device, symbols, error);
            }
            else if (step.Tool == L"pool.find")
            {
                stepOk = ExecuteAiCapabilityPoolFind(step, state, device, symbols, error);
            }
            else if (step.Tool == L"address.inspect")
            {
                stepOk = ExecuteAiCapabilityAddressInspect(step, state, device, symbols, error);
            }
            else if (step.Tool == L"wnf.decode")
            {
                stepOk = ExecuteAiCapabilityWnfDecode(step, state, device, symbols, error);
            }
            else if (step.Tool == L"wnf.list")
            {
                stepOk = ExecuteAiCapabilityWnfList(step, state, device, symbols, error);
            }
            else if (step.Tool == L"ti.query")
            {
                stepOk = ExecuteAiCapabilityTiQuery(step, state, device, symbols, error);
            }
            else if (step.Tool == L"module.integrity")
            {
                stepOk = ExecuteAiCapabilityModuleIntegrity(step, state, device, symbols, error);
            }
            else if (step.Tool == L"driver.integrity")
            {
                stepOk = ExecuteAiCapabilityDriverIntegrity(step, state, device, symbols, error);
            }
            else if (step.Tool == L"assistant.answer")
            {
                if (error != nullptr)
                {
                    *error = L"assistant.answer cannot be mixed with local tool steps";
                }
            }

            if (!stepOk)
            {
                break;
            }

            results.push_back(result);
        }

        ok = results.size() == plan.Steps.size();
    } while (false);

    return ok;
}

static AiCapabilityQueryResult TryHandleAiCapabilityQuery(
    const std::wstring& query,
    DebuggerState& state,
    DeviceClient& device,
    SymbolEngine& symbols,
    AiProviderRuntime& ai,
    AiPlanState& aiState)
{
    AiCapabilityQueryResult result = AiCapabilityQueryResult::NotAttempted;

    do
    {
        if (ToLower(ai.ProviderName()) == L"off")
        {
            break;
        }

        AiCompletionRequest request = {};
        request.System = BuildAiSystemPrompt(state, symbols);
        request.Prompt = BuildAiCapabilityPlannerPrompt(query);

        std::wcout << L"ai tool planner: provider=" << ai.ProviderName()
                   << L" model=" << ai.Settings().Model
                   << L" credential=" << ai.CredentialStatus() << L"\n";

        AiCompletionResponse response = {};
        std::wstring error;
        if (!ai.Complete(request, &response, &error))
        {
            std::wcerr << L"ai tool planner failed: " << error << L"\n";
            WriteAiTranscriptEvent(aiState, L"ai_tool_plan_failed", error, L"");
            result = AiCapabilityQueryResult::Failed;
            break;
        }

        AiCapabilityPlan plan = {};
        if (!ParseAiCapabilityPlanResponse(response.Text, &plan, &error))
        {
            std::wcerr << L"ai tool planner skipped: " << error << L"\n";
            WriteAiTranscriptEvent(aiState, L"ai_tool_plan_parse_failed", error, L"");
            result = AiCapabilityQueryResult::NotAttempted;
            break;
        }

        if (IsAiCapabilityAssistantAnswerPlan(plan))
        {
            WriteAiTranscriptEvent(aiState, L"ai_tool_plan_skipped", L"assistant.answer", L"");
            result = AiCapabilityQueryResult::NotAttempted;
            break;
        }

        WriteAiTranscriptEvent(aiState, L"ai_tool_plan", L"capability plan accepted", L"");
        if (!ExecuteAiCapabilityPlan(plan, state, device, symbols, &error))
        {
            std::wcerr << L"ai tool execution failed: " << error << L"\n";
            WriteAiTranscriptEvent(aiState, L"ai_tool_execution_failed", error, L"");
            result = AiCapabilityQueryResult::Failed;
            break;
        }

        result = AiCapabilityQueryResult::Handled;
    } while (false);

    return result;
}

static void HandleAiConfigTestCommand(const std::vector<std::wstring>& args, AiProviderRuntime& ai)
{
    static const std::wstring expectedMarker = L"kn-live-dbg-ai-ok";

    do
    {
        AiCompletionRequest request = {};
        request.System = L"You are a KnLiveDbg AI provider connectivity smoke test. Return exactly this marker and no other text: " + expectedMarker;
        if (args.size() >= 4)
        {
            request.Prompt = JoinArgs(args, 3);
        }
        else
        {
            request.Prompt = L"Return exactly: " + expectedMarker;
        }

        std::wcout << L"ai config test\n";
        std::wcout << L"  provider: " << ai.ProviderName() << L"\n";
        std::wcout << L"  model: " << (ai.Settings().Model.empty() ? L"(default)" : ai.Settings().Model) << L"\n";
        std::wcout << L"  remote policy: " << ai.RemotePolicyName() << L"\n";
        std::wcout << L"  credential: " << ai.CredentialStatus() << L"\n";
        std::wcout << L"  sending smoke request...\n";

        AiCompletionResponse response = {};
        std::wstring error;
        uint64_t startTick = GetTickCount64();
        bool completed = ai.Complete(request, &response, &error);
        uint64_t elapsed = GetTickCount64() - startTick;

        if (!completed)
        {
            std::wcout << L"  transport: failed\n";
            std::wcout << L"  elapsed: " << FormatElapsedSeconds(elapsed) << L"\n";
            std::wcerr << L"ai config test failed: " << error << L"\n";
            break;
        }

        bool markerOk = ContainsNoCase(response.Text, expectedMarker);
        std::wcout << L"  transport: ok\n";
        if (response.StatusCode != 0)
        {
            std::wcout << L"  http status: " << response.StatusCode << L"\n";
        }
        std::wcout << L"  elapsed: " << FormatElapsedSeconds(elapsed) << L"\n";
        std::wcout << L"  response marker: " << (markerOk ? L"ok" : L"missing") << L"\n";

        if (!markerOk)
        {
            std::wstring preview = TrimWhitespace(response.Text);
            if (preview.size() > 300)
            {
                preview.resize(300);
                preview += L"...";
            }

            std::wcout << L"  response preview: " << (preview.empty() ? L"(empty)" : preview) << L"\n";
        }
    } while (false);
}

static void HandleAiConfigCommand(
    const std::vector<std::wstring>& args,
    AiProviderRuntime& ai)
{
    do
    {
        if (args.size() < 3 || ToLower(args[2]) == L"status")
        {
            std::wcout << ai.StatusText();
            break;
        }

        std::wstring setting = ToLower(args[2]);
        if (setting == L"help")
        {
            PrintAiSubcommandHelp(L"config");
        }
        else if (setting == L"providers")
        {
            PrintAiProviders();
        }
        else if (setting == L"provider")
        {
            if (args.size() < 4)
            {
                std::wcerr << L"usage: ai config provider <name>\n";
                break;
            }

            std::wstring error;
            if (!ai.SetProvider(args[3], &error))
            {
                std::wcerr << L"ai config provider failed: " << error << L"\n";
                break;
            }

            std::wcout << ai.StatusText();
        }
        else if (setting == L"policy")
        {
            if (args.size() < 4 || ToLower(args[3]) == L"status")
            {
                std::wcout << L"ai remote policy: " << ai.RemotePolicyName() << L"\n";
                break;
            }

            std::wstring error;
            if (!ai.SetRemotePolicy(args[3], &error))
            {
                std::wcerr << L"ai config policy failed: " << error << L"\n";
                break;
            }

            std::wcout << ai.StatusText();
        }
        else if (setting == L"model")
        {
            if (args.size() < 4)
            {
                std::wcerr << L"usage: ai config model <model>\n";
                break;
            }

            ai.SetModel(JoinArgs(args, 3));
            std::wcout << ai.StatusText();
        }
        else if (setting == L"base-url")
        {
            if (args.size() < 4)
            {
                std::wcerr << L"usage: ai config base-url <url>\n";
                break;
            }

            ai.SetBaseUrl(JoinArgs(args, 3));
            std::wcout << ai.StatusText();
        }
        else if (setting == L"effort")
        {
            if (args.size() < 4)
            {
                std::wcerr << L"usage: ai config effort <minimal|low|medium|high|xhigh>\n";
                break;
            }

            ai.SetReasoningEffort(args[3]);
            std::wcout << ai.StatusText();
        }
        else if (setting == L"auth")
        {
            std::wcout << ai.AuthHelpText();
        }
        else if (setting == L"test")
        {
            HandleAiConfigTestCommand(args, ai);
        }
        else
        {
            std::wcerr << L"unknown ai config setting. type ai help config\n";
        }
    } while (false);
}

static void HandleAiFreeFormCommand(
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
        std::wstring query = JoinArgs(args, 1);
        if (TrimWhitespace(query).empty())
        {
            PrintAiHelp();
            break;
        }

        std::wstring implicitEvidenceCommand;
        if (TryBuildImplicitAiEvidenceCommand(query, &implicitEvidenceCommand))
        {
            AiEvidenceAnalysisMetadata metadata = BuildAiEvidenceAnalysisMetadata(
                implicitEvidenceCommand,
                L"ai_auto_explain");
            std::wcout << L"ai auto: evidence analysis\n";
            HandleAiEvidenceAnalysis(
                metadata.EventName,
                implicitEvidenceCommand,
                metadata.Title,
                metadata.Instructions,
                state,
                dbgeng,
                device,
                service,
                symbols,
                ai,
                aiState);
            break;
        }

        if (IsAiCommandRecommendationQuery(query))
        {
            std::wcout << L"ai auto: command recommendation request; building command plan\n";
            HandleAiPlanRequest(
                query,
                L"ai_auto_plan",
                L"ai auto-plan request",
                state,
                symbols,
                ai,
                aiState);
            break;
        }

        AiCapabilityQueryResult capabilityResult = TryHandleAiCapabilityQuery(
            query,
            state,
            device,
            symbols,
            ai,
            aiState);
        if (capabilityResult == AiCapabilityQueryResult::Handled)
        {
            break;
        }

        if (TryHandleAiLocalQuery(query, state, device, symbols))
        {
            break;
        }

        if (capabilityResult == AiCapabilityQueryResult::Failed)
        {
            break;
        }

        if (ShouldAutoPlanAiQuery(query))
        {
            std::wcout << L"ai auto: no direct local tool matched; building command plan\n";
            HandleAiPlanRequest(
                query,
                L"ai_auto_plan",
                L"ai auto-plan request",
                state,
                symbols,
                ai,
                aiState);
            break;
        }

        AiCompletionRequest request = {};
        request.System = BuildAiSystemPrompt(state, symbols);
        request.Prompt = query;
        std::wcout << L"ai request: provider=" << ai.ProviderName()
                   << L" model=" << ai.Settings().Model
                   << L" credential=" << ai.CredentialStatus() << L"\n";
        CompleteAndPrintAiRequest(L"ai_ask", request, ai, aiState);
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
        if (args.size() == 1)
        {
            std::wcout << ai.StatusText();
            break;
        }

        std::wstring action = ToLower(args[1]);
        if (action == L"help")
        {
            PrintAiHelpFromArgs(args, 1);
        }
        else if (IsAiSubcommandHelpRequest(args, action))
        {
            if (!PrintAiSubcommandHelp(action))
            {
                PrintAiHelp();
            }
        }
        else if (action == L"status")
        {
            std::wcout << ai.StatusText();
        }
        else if (action == L"config")
        {
            HandleAiConfigCommand(args, ai);
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
        else if (action == L"base-url")
        {
            if (args.size() < 3)
            {
                std::wcerr << L"usage: ai base-url <url>\n";
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
            if (args.size() == 2)
            {
                PrintAiPlan(aiState);
            }
            else
            {
                HandleAiFreeFormCommand(args, state, dbgeng, device, service, symbols, ai, aiState);
            }
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
            if (args.size() < 3)
            {
                std::wcerr << L"usage: ai analyze <read-only-command...>\n";
                break;
            }

            if (ToLower(args[2]) != L"callbacks")
            {
                HandleAiFreeFormCommand(args, state, dbgeng, device, service, symbols, ai, aiState);
                break;
            }

            std::wstring scope = L"all";
            std::wstring moduleFilter;
            if (args.size() >= 4)
            {
                size_t index = 3;
                if (IsCallbackScopeName(args[3]))
                {
                    scope = args[3];
                    index = 4;
                }
                else if (IsDeprecatedCallbackScopeAlias(args[3]) ||
                         IsDeprecatedCallbackModuleOption(args[3]))
                {
                    std::wcerr << L"usage: ai analyze callbacks [all|object|registry|process|thread|imageload|minifilter] [module]\n";
                    break;
                }

                while (index < args.size())
                {
                    if (IsCallbackModuleOption(args[index]))
                    {
                        if (index + 1 >= args.size())
                        {
                            std::wcerr << L"usage: ai analyze callbacks [scope] /module <module>\n";
                            break;
                        }

                        if (!moduleFilter.empty())
                        {
                            std::wcerr << L"usage: ai analyze callbacks [scope] [module]\n";
                            break;
                        }

                        moduleFilter = args[index + 1];
                        index += 2;
                        continue;
                    }

                    if (IsDeprecatedCallbackModuleOption(args[index]) ||
                        IsDeprecatedCallbackScopeAlias(args[index]))
                    {
                        std::wcerr << L"usage: ai analyze callbacks [scope] [module]\n";
                        break;
                    }

                    if (moduleFilter.empty())
                    {
                        moduleFilter = args[index];
                        ++index;
                        continue;
                    }

                    std::wcerr << L"usage: ai analyze callbacks [scope] [module]\n";
                    break;
                }

                if (index < args.size())
                {
                    break;
                }
            }

            std::wstring evidenceCommand = L"callbacks " + scope;
            if (!moduleFilter.empty())
            {
                evidenceCommand += L" " + moduleFilter;
            }

            HandleAiEvidenceAnalysis(
                L"ai_analyze_callbacks",
                evidenceCommand,
                L"Analyze this KnLiveDbg kernel callback scan.",
                L"Produce a callback analysis report from this KnLiveDbg callback scan output. Count records by surface, group by module, decode process notify metadata, call out image-load notify owners, non-image owners, missing symbols, unusual minifilter metadata, shared module ownership across surfaces, and concrete follow-up commands. Preserve raw addresses and confidence notes.",
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
            if (args.size() < 3)
            {
                std::wcerr << L"usage: ai explain <read-only-command...>\n";
                break;
            }

            std::wstring commandLine = JoinArgs(args, 2);
            AiEvidenceAnalysisMetadata metadata = BuildAiEvidenceAnalysisMetadata(commandLine, L"ai_explain");

            HandleAiEvidenceAnalysis(
                metadata.EventName,
                commandLine,
                metadata.Title,
                metadata.Instructions,
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
                L"Summarize likely routine purpose, call targets, direct and indirect call evidence, callback/dispatch/minifilter/process/thread/image-load classification hints, suspicious code patterns, uncertainty, and next commands such as ln, x, dt, dq, or uf.",
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

            HandleAiPlanRequest(
                JoinArgs(args, 2),
                L"ai_plan",
                L"ai plan request",
                state,
                symbols,
                ai,
                aiState);
        }
        else
        {
            HandleAiFreeFormCommand(args, state, dbgeng, device, service, symbols, ai, aiState);
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
            if (args.size() >= 2 && ToLower(args[1]) == L"all")
            {
                PrintHelp(true);
            }
            else if (args.size() >= 2)
            {
                if (!PrintDetailedCommandHelp(args, 1))
                {
                    std::wstring topic = CompletionCanonicalCommand(args[1]);
                    if (CommandRegistry::IsKnown(topic))
                    {
                        CommandRegistry::PrintCommandStatus(topic);
                    }
                    else
                    {
                        std::wcerr << L"unknown help topic: " << args[1] << L"\n";
                        PrintHelp(false);
                    }
                }
            }
            else
            {
                PrintHelp(false);
            }
        }
        else if (args.size() >= 2 && IsHelpToken(args[1]))
        {
            if (!PrintDetailedCommandHelp(args, 0))
            {
                CommandRegistry::PrintCommandStatus(command);
            }
        }
        else if (command == L"home" || command == L"dashboard")
        {
            PrintStartupTui(state, service, device, symbols, ai);
        }
        else if (command == L"cls")
        {
            if (!ClearConsoleScreen(&error))
            {
                std::wcerr << L"cls failed: " << error << L"\n";
            }
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
            if (args.size() >= 2 && ToLower(args[1]) == L"/remote")
            {
                if (args.size() < 3)
                {
                    std::wcerr << L"usage: kdinit /remote <connection-options>\n";
                    break;
                }

                state.DbgEngRemoteKernel = true;
                state.DbgEngConnectOptions = JoinArgs(args, 2);
            }
            else if (args.size() >= 2 && ToLower(args[1]) == L"/local")
            {
                state.DbgEngConnectOptions = args.size() >= 3 ? JoinArgs(args, 2) : L"";
            }
            else if (args.size() >= 2)
            {
                std::wcerr << L"usage: kdinit [/local [connect-options]|/remote <connect-options>]\n";
                break;
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
            HandleProbeCommand(args, state);
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
            HandleUnassembleCommand(args, originalLine, state, device, dbgeng, symbols);
        }
        else if (command == L"ai")
        {
            std::wstring aiAction = args.size() >= 2 ? ToLower(args[1]) : L"";
            if (aiAction == L"run" && !IsAiSubcommandHelpRequest(args, aiAction))
            {
                keepRunning = RunAiPlannedCommands(args, state, dbgeng, device, service, symbols, ai, aiState);
            }
            else
            {
                HandleAiCommand(args, state, dbgeng, device, service, symbols, ai, aiState);
            }
        }
        else if (command == L"!vtop")
        {
            std::wcerr << L"unknown command. type help or help all\n";
        }
        else if (state.Backend == DebuggerState::BackendMode::DbgEng &&
                 command != L"q" && command != L"qq" && command != L"qd" &&
                 command != L"quit" && command != L"exit" &&
                 command != L"unload" && command != L"drvstatus" &&
                 command != L"cls" &&
                 command != L"probe" &&
                 command != L"procctx" &&
                 command != L"callbacks" &&
                 command != L"ai" &&
                 !IsNativeBangCommand(command))
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
                PrintColoredText(L"Evaluate expression", KNDBG_COLOR_TITLE);
                std::wcout << L": " << HexText(value) << L" = " << std::dec << value << L"\n";
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

            PrintColoredText(L"symbol path", KNDBG_COLOR_TITLE);
            std::wcout << L": " << symbols.SymbolPath() << L"\n";
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

            PrintColoredText(L"symbol path", KNDBG_COLOR_TITLE);
            std::wcout << L": " << symbols.SymbolPath() << L"\n";
        }
        else if (command == L".reload" || command == L"reload" || command == L"ld")
        {
            if (symbols.LoadKernelModules(&error))
            {
                PrintColoredText(L"loaded module list", KNDBG_COLOR_TITLE);
                std::wcout << L": " << symbols.Modules().size() << L"\n";
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

                PrintColoredText(HexTextWidth(module.Base, 16, true), KNDBG_COLOR_ACCENT);
                std::wcout << L" size=" << HexText(module.Size) << L" ";
                PrintColoredText(module.ImageName, KNDBG_COLOR_TITLE);
                std::wcout << L" " << module.ImagePath << L"\n";
            }
        }
        else if (command == L"x" && args.size() >= 2)
        {
            std::vector<SymbolMatchInfo> matches;
            if (symbols.EnumerateSymbols(args[1], 512, &matches, &error))
            {
                for (const SymbolMatchInfo& match : matches)
                {
                    PrintColoredText(HexTextWidth(match.Address, 16, true), KNDBG_COLOR_ACCENT);
                    std::wcout << L" ";
                    PrintColoredText(match.Name, KNDBG_COLOR_TITLE);
                    std::wcout << L"\n";
                }

                PrintColoredText(L"symbols", KNDBG_COLOR_TITLE);
                std::wcout << L"=" << matches.size() << L"\n";
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
            PrintColoredText(args[1], KNDBG_COLOR_TITLE);
            std::wcout << L" = " << HexText(address) << L"\n";
            if (symbols.FindNearestSymbol(address, &nearest, &displacement, &error))
            {
                PrintColoredText(L"nearest", KNDBG_COLOR_ACCENT);
                std::wcout << L": ";
                PrintColoredText(nearest, KNDBG_COLOR_TITLE);
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
        else if (command == L"vtop")
        {
            HandleTranslateVirtualCommand(args, state, device, symbols);
        }
        else if (command == L"procctx")
        {
            HandleProcessContextCommand(args, state, device, symbols);
        }
        else if (command == L"!dml_proc")
        {
            HandleDmlProcCommand(args, state, device, symbols);
        }
        else if (command == L"!vad")
        {
            HandleVadCommand(args, state, device, symbols);
        }
        else if (command == L"!threads")
        {
            HandleThreadsCommand(args, state, device, symbols);
        }
        else if (command == L"!snapshot")
        {
            HandleSnapshotCommand(args, state, device, symbols);
        }
        else if (command == L"!diff")
        {
            HandleDiffCommand(args, state, device, symbols);
        }
        else if (command == L"!wfp")
        {
            if (args.size() >= 2 && ToLower(args[1]) == L"kernelcallouts")
            {
                HandleWfpKernelCalloutsCommand(args, device, symbols);
            }
            else
            {
                HandleWfpCommand(args);
            }
        }
        else if (command == L"!alpc")
        {
            HandleAlpcCommand(args, state, device, symbols);
        }
        else if (command == L"!vbs")
        {
            HandleVbsCommand(args, device, symbols);
        }
        else if (command == L"!ci")
        {
            HandleCiCommand(args, device, symbols);
        }
        else if (command == L"!securekernel")
        {
            HandleSecureKernelCommand(args, device, symbols);
        }
        else if (command == L"!etw")
        {
            HandleEtwCommand(args, device, symbols);
        }
        else if (command == L"!nmi")
        {
            HandleNmiCommand(args, device, symbols);
        }
        else if (command == L"!msrcheck")
        {
            HandleMsrCheckCommand(args, device, symbols);
        }
        else if (command == L"!cr")
        {
            HandleCrCommand(args, device);
        }
        else if (command == L"!ssdt")
        {
            HandleSsdtCommand(args, device, symbols);
        }
        else if (command == L"!idt")
        {
            HandleIdtCommand(args, device, symbols);
        }
        else if (command == L"!fwtable")
        {
            HandleFirmwareTableCommand(args, state, device, symbols);
        }
        else if (command == L"!module")
        {
            HandleModuleIntegrityCommand(args, state, device, symbols);
        }
        else if (command == L"!driver")
        {
            HandleDriverIntegrityCommand(args, state, device, symbols);
        }
        else if (command == L"byovd" || command == L"!byovd")
        {
            HandleByovdCommand(args, state, symbols);
        }
        else if (command == L"!pool")
        {
            HandlePoolCommand(args, state, device, symbols);
        }
        else if (command == L"dump-raw")
        {
            HandleDumpRawCommand(args, state, device, symbols);
        }
        else if (command == L"dump-pe")
        {
            HandleDumpPeCommand(args, state, device, symbols);
        }
        else if (command == L"pool-scan-pe")
        {
            HandlePoolScanPeCommand(args, state, device, symbols);
        }
        else if (command == L"!address")
        {
            HandleAddressCommand(args, state, device, symbols);
        }
        else if (command == L"set-ppl-antimalware")
        {
            HandleSetPplAntimalwareCommand(args, state, device, symbols);
        }
        else if (command == L"!ti")
        {
            HandleTiCommand(args, state, device, symbols);
        }
        else if (command == L"!wnf")
        {
            HandleWnfCommand(args, state, device, symbols);
        }
        else if (command == L"log")
        {
            HandleLogCommand(args);
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
        else if (command == L"callbacks")
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
                PrintColoredText(L"write mode", KNDBG_COLOR_TITLE);
                std::wcout << L": ";
                PrintColoredText(enabled ? L"on" : L"off", enabled ? KNDBG_COLOR_OK : KNDBG_COLOR_WARN);
                std::wcout << L"\n";
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
                PrintColoredText(L"wrote field", KNDBG_COLOR_OK);
                std::wcout << L" ";
                PrintColoredText(field.Name, KNDBG_COLOR_TITLE);
                std::wcout << L" at +0x" << std::hex << field.Offset << std::dec << L"\n";
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
                if (value != L"true" && value != L"false")
                {
                    std::wcerr << L"usage: sq [true|false]\n";
                    break;
                }

                state.Quiet = value == L"true";
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
            PrintLifecycleHeader(L"Main driver unload", L"device: " KNDBG_USER_DEVICE_NAME);
            PrintLifecycleStep(L"close device handle", L"release controller session");
            device.Close();
            PrintLifecycleOk(L"close device handle", L"closed");
            if (!UnloadDriverServiceWithUx(service, L"Main driver SCM unload", &unloadResult, &error))
            {
                std::wcerr << L"unload failed\n";
            }
            else
            {
                state.MainDriverUnloaded = true;
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
        ScopedCommandProgress progress(originalLine, origin, !args.empty());
        {
            ScopedWideStreamCapture capture(&result.Output, &result.Error);
            result.KeepRunning = HandleCommand(args, originalLine, state, dbgeng, device, service, symbols, ai, aiState);
        }
        progress.Complete();

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

    // Permanently install the tee buffer in front of std::wcout. Must
    // happen before any ScopedWideStreamCapture (i.e. before any
    // command is dispatched) so that "log enable" only needs to
    // attach a file sink at runtime, not swap rdbufs from inside a
    // capture's chain (which would silently drop the tee on the next
    // capture's destructor).
    InstallOutputTee();
    CommandRegistry::SetColorPrinter(PrintCommandRegistryColoredText);

    int exitCode = 1;
    DebuggerState state = {};
    state.NumberBase = 16;
    state.Quiet = false;
    state.MainDriverCleanupRequested = false;
    state.MainDriverUnloaded = false;
    state.ProbeDriverCleanupRequested = false;
    state.ProbeDriverUnloaded = false;
    state.ByovdFixtureCleanupRequested = false;
    state.ByovdFixtureUnloaded = false;
    state.HasSnapshotBaseline = false;
    state.SnapshotBaseline = SnapshotDocument{};
    state.SnapshotBaselineJsonPath.clear();
    state.SnapshotBaselineReportPath.clear();
    state.Backend = DebuggerState::BackendMode::Auto;

    DriverService service;
    DeviceClient device;
    SymbolEngine symbols;
    DbgEngBackend dbgeng;
    AiProviderRuntime ai;
    AiPlanState aiState = {};
    std::wstring error;

    do
    {
        DuplicateHandle(
            GetCurrentProcess(),
            GetCurrentThread(),
            GetCurrentProcess(),
            &g_MainThreadHandle,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS);
        SetConsoleCtrlHandler(ConsoleHandler, TRUE);

        PrintLifecycleHeader(L"KnLiveDbg launch", L"preflight checks");
        PrintLifecycleStep(L"elevation", L"administrator token");
        if (!IsElevated())
        {
            PrintLifecycleFail(L"elevation", L"administrator privileges are required");
            std::wcerr << L"KnLiveDbg must run elevated to install and load the driver.\n";
            break;
        }
        PrintLifecycleOk(L"elevation", L"administrator");

        PrintLifecycleStep(L"single instance", L"Global\\KnLiveDbg.Exe.SingleInstance");
        if (!AcquireSingleInstanceLock(&error))
        {
            PrintLifecycleFail(L"single instance", error);
            std::wcerr << error << L"\n";
            break;
        }
        PrintLifecycleOk(L"single instance", L"acquired");

        state.MainDriverCleanupRequested = true;

        std::wstring exeDir = GetExecutableDirectory();
        PrintLifecycleStep(L"symbol runtime consent", L"symsrv.yes");
        std::wstring symsrvConsentStatus;
        if (!EnsureSymsrvConsentFile(exeDir, &symsrvConsentStatus, &error))
        {
            PrintLifecycleWarn(L"symbol runtime consent", error);
            std::wcerr << L"symsrv consent warning: " << error << L"\n";
        }
        else
        {
            PrintLifecycleOk(L"symbol runtime consent", symsrvConsentStatus);
        }

        PrintLifecycleStep(L"register DIA", L"msdia COM");
        std::wstring diaStatus;
        if (!EnsureDiaRegistration(exeDir, &diaStatus, &error))
        {
            PrintLifecycleWarn(L"register DIA", error);
            std::wcerr << L"DIA registration warning: " << error << L"\n";
        }
        else
        {
            PrintLifecycleOk(L"register DIA", diaStatus);
        }

        STARTUP_SYMBOL_PATH_INFO startupSymbolPath = BuildStartupSymbolPath(symbols.SymbolPath(), exeDir);
        if (!startupSymbolPath.Path.empty())
        {
            symbols.SetSymbolPath(startupSymbolPath.Path);
        }

        std::wstring driverPath = exeDir + L"\\KnLiveDbg.sys";

        if (!LoadDriverServiceWithUx(service, L"Main driver startup", driverPath, &error))
        {
            std::wcerr << L"driver load failed\n";
            break;
        }

        PrintLifecycleStep(L"open device", KNDBG_USER_DEVICE_NAME);
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
            PrintLifecycleFail(L"open device", error);
            std::wcerr << L"device open failed: " << error << L"\n";
            break;
        }
        PrintLifecycleOk(L"open device", L"ready");

        PrintLifecycleStep(L"verify driver ABI", L"IOCTL_KNDBG_GET_VERSION");
        if (!device.QueryVersion(&error))
        {
            PrintLifecycleFail(L"verify driver ABI", error);
            std::wcerr << L"driver ABI check failed: " << error << L"\n";
            break;
        }
        PrintLifecycleOk(L"verify driver ABI", L"compatible");

        PrintLifecycleStep(L"symbol search path", L"EXE directory tree");
        if (startupSymbolPath.Truncated)
        {
            PrintLifecycleWarn(L"symbol search path", L"local dirs=" + std::to_wstring(startupSymbolPath.LocalDirectoryCount) + L" truncated");
        }
        else
        {
            PrintLifecycleOk(L"symbol search path", L"local dirs=" + std::to_wstring(startupSymbolPath.LocalDirectoryCount));
        }

        PrintLifecycleStep(L"symbol cache", L"EXE symbols directory");
        if (!startupSymbolPath.SymbolCacheReady)
        {
            std::wstring cacheWarning = startupSymbolPath.SymbolCacheError.empty() ?
                L"not configured" : startupSymbolPath.SymbolCacheError;
            PrintLifecycleWarn(L"symbol cache", cacheWarning);
            std::wcerr << L"symbol cache warning: " << cacheWarning << L"\n";
        }
        else
        {
            PrintLifecycleOk(L"symbol cache", startupSymbolPath.SymbolCachePath);
        }

        PrintLifecycleStep(L"initialize symbols", L"DbgHelp/DIA");
        if (!symbols.Initialize(symbols.SymbolPath(), &error))
        {
            PrintLifecycleWarn(L"initialize symbols", error);
            std::wcerr << L"symbol init warning: " << error << L"\n";
        }
        else if (!symbols.LoadKernelModules(&error))
        {
            PrintLifecycleWarn(L"load kernel modules", error);
            std::wcerr << L"symbol reload warning: " << error << L"\n";
        }
        else
        {
            PrintLifecycleOk(L"initialize symbols", L"modules=" + std::to_wstring(symbols.Modules().size()));

            PrintLifecycleStep(L"download kernel symbols", L"nt PDB");
            size_t kernelSymbolCount = 0;
            std::wstring preloadError;
            if (symbols.PreloadKernelSymbols(&kernelSymbolCount, &preloadError))
            {
                PrintLifecycleOk(L"download kernel symbols", L"loaded=" + std::to_wstring(kernelSymbolCount));
            }
            else
            {
                PrintLifecycleWarn(L"download kernel symbols", preloadError);
                std::wcerr << L"kernel symbol preload warning: " << preloadError << L"\n";
            }
        }

        std::wstring dotEnvError;
        ai.LoadDotEnvFiles(BuildDotEnvSearchPaths(exeDir), nullptr, &dotEnvError);

        PrintStartupTui(state, service, device, symbols, ai);

        while (!g_StopRequested)
        {
            std::wstring line;
            if (!ReadInteractiveCommandLine(L"knkd> ", state.CommandHistory, &line))
            {
                break;
            }

            std::vector<std::wstring> args = Split(line);
            if (args.empty())
            {
                continue;
            }

            AddCommandHistory(&state, line);

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

        exitCode = 0;
    } while (false);

    dbgeng.Shutdown();
    bool cleanupOk = true;
    if (!CleanupByovdFixtureDriverOnExit(state))
    {
        cleanupOk = false;
    }
    if (!CleanupProbeDriverOnExit(state))
    {
        cleanupOk = false;
    }
    if (!CleanupMainDriverOnExit(state, device, service))
    {
        cleanupOk = false;
    }
    if (!cleanupOk)
    {
        exitCode = 1;
    }

    if (g_MainThreadHandle != nullptr)
    {
        CloseHandle(g_MainThreadHandle);
        g_MainThreadHandle = nullptr;
    }
    ReleaseSingleInstanceLock();

    DisableOutputLog(nullptr);
    UninstallOutputTee();

    return exitCode;
}
