#include "SymbolEngine.h"
#include "BrokeredTypeLayouts.h"
#include "BrokeredSymbolIndexes.h"
#include "SymbolIndexBroker.h"
#include "SymbolArtifactResolver.h"

#include <winternl.h>

#include <algorithm>
#include <cstddef>
#include <cstring>
#include <cwctype>
#include <memory>
#include <new>
#include <sstream>


typedef LONG NTSTATUS;

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

typedef enum _KNDBG_SYSTEM_INFORMATION_CLASS
{
    KnDbgSystemModuleInformation = 11
} KNDBG_SYSTEM_INFORMATION_CLASS;

typedef struct _KNDBG_RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} KNDBG_RTL_PROCESS_MODULE_INFORMATION, *PKNDBG_RTL_PROCESS_MODULE_INFORMATION;

typedef struct _KNDBG_RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    KNDBG_RTL_PROCESS_MODULE_INFORMATION Modules[1];
} KNDBG_RTL_PROCESS_MODULES, *PKNDBG_RTL_PROCESS_MODULES;

typedef NTSTATUS (NTAPI* NtQuerySystemInformationPtr)(
    KNDBG_SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength);

static std::wstring SystemErrorText(const wchar_t* prefix, DWORD error)
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

static DWORD EnableModuleQueryPrivilege()
{
    // Recent Windows builds can return a successful module query with every
    // ImageBase redacted unless SeDebugPrivilege is enabled. An elevated
    // token may contain the privilege without having it enabled.
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
    {
        return GetLastError();
    }
    LUID luid = {};
    DWORD status = ERROR_SUCCESS;
    if (!LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid))
    {
        status = GetLastError();
    }
    else
    {
        TOKEN_PRIVILEGES privileges = {};
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = luid;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        SetLastError(ERROR_SUCCESS);
        if (!AdjustTokenPrivileges(token, FALSE, &privileges, 0, nullptr, nullptr))
        {
            status = GetLastError();
        }
        else
        {
            status = GetLastError(); // ERROR_NOT_ALL_ASSIGNED is not success.
        }
    }
    CloseHandle(token);
    return status;
}

static std::wstring AsWide(const char* value)
{
    std::wstring result;

    do
    {
        if (value == nullptr)
        {
            break;
        }

        int count = MultiByteToWideChar(CP_ACP, 0, value, -1, nullptr, 0);
        if (count <= 0)
        {
            break;
        }

        result.resize(static_cast<size_t>(count - 1));
        MultiByteToWideChar(CP_ACP, 0, value, -1, result.data(), count);
    } while (false);

    return result;
}

static std::wstring ToLowerString(const std::wstring& value)
{
    std::wstring result = value;

    for (wchar_t& ch : result)
    {
        ch = static_cast<wchar_t>(std::towlower(ch));
    }

    return result;
}

static std::wstring StripExtension(const std::wstring& value)
{
    std::wstring result = value;
    size_t dot = result.find_last_of(L'.');

    if (dot != std::wstring::npos)
    {
        result.resize(dot);
    }

    return result;
}

static bool IsNtKernelImageName(const std::wstring& imageName)
{
    bool result = false;

    do
    {
        std::wstring imageNoExtension = StripExtension(ToLowerString(imageName));
        if (imageNoExtension == L"ntoskrnl" || imageNoExtension.rfind(L"ntkrnl", 0) == 0)
        {
            result = true;
            break;
        }
    } while (false);

    return result;
}

static std::wstring SymbolModuleName(const KernelModuleInfo& module)
{
    std::wstring name = module.ImageName;

    do
    {
        if (IsNtKernelImageName(module.ImageName))
        {
            name = L"nt";
            break;
        }
    } while (false);

    return name;
}

static bool ModuleNameMatches(const std::wstring& imageName, const std::wstring& filter)
{
    bool matches = false;

    do
    {
        if (filter.empty())
        {
            matches = true;
            break;
        }

        std::wstring image = ToLowerString(imageName);
        std::wstring imageNoExtension = StripExtension(image);
        std::wstring normalizedFilter = StripExtension(ToLowerString(filter));

        if (image == normalizedFilter || imageNoExtension == normalizedFilter)
        {
            matches = true;
            break;
        }

        if (normalizedFilter == L"nt" && IsNtKernelImageName(imageName))
        {
            matches = true;
            break;
        }
    } while (false);

    return matches;
}

static bool WildcardMatchNoCase(const std::wstring& value, const std::wstring& pattern)
{
    bool matches = false;

    do
    {
        std::wstring text = ToLowerString(value);
        std::wstring mask = ToLowerString(pattern.empty() ? L"*" : pattern);

        size_t textIndex = 0;
        size_t maskIndex = 0;
        size_t starIndex = std::wstring::npos;
        size_t starTextIndex = 0;

        while (textIndex < text.size())
        {
            if (maskIndex < mask.size() && (mask[maskIndex] == L'?' || mask[maskIndex] == text[textIndex]))
            {
                ++textIndex;
                ++maskIndex;
            }
            else if (maskIndex < mask.size() && mask[maskIndex] == L'*')
            {
                starIndex = maskIndex;
                ++maskIndex;
                starTextIndex = textIndex;
            }
            else if (starIndex != std::wstring::npos)
            {
                maskIndex = starIndex + 1;
                ++starTextIndex;
                textIndex = starTextIndex;
            }
            else
            {
                break;
            }
        }

        if (textIndex != text.size())
        {
            break;
        }

        while (maskIndex < mask.size() && mask[maskIndex] == L'*')
        {
            ++maskIndex;
        }

        matches = maskIndex == mask.size();
    } while (false);

    return matches;
}

static std::wstring StripModuleQualifier(const std::wstring& value)
{
    std::wstring result = value;

    do
    {
        size_t bang = result.find_last_of(L'!');
        if (bang != std::wstring::npos)
        {
            result = result.substr(bang + 1);
        }
    } while (false);

    return result;
}

static std::wstring StripLeadingUnderscores(const std::wstring& value)
{
    std::wstring result = value;

    do
    {
        size_t index = 0;
        while (index < result.size() && result[index] == L'_')
        {
            ++index;
        }

        if (index != 0)
        {
            result = result.substr(index);
        }
    } while (false);

    return result;
}

static bool TypeNameMatchesNoCase(const std::wstring& value, const std::wstring& pattern)
{
    bool matches = false;

    do
    {
        std::wstring effectivePattern = pattern.empty() ? L"*" : pattern;
        if (WildcardMatchNoCase(value, effectivePattern))
        {
            matches = true;
            break;
        }

        std::wstring valueLeaf = StripModuleQualifier(value);
        std::wstring patternLeaf = StripModuleQualifier(effectivePattern);
        if (WildcardMatchNoCase(valueLeaf, patternLeaf))
        {
            matches = true;
            break;
        }

        std::wstring valueNoUnderscore = StripLeadingUnderscores(valueLeaf);
        std::wstring patternNoUnderscore = StripLeadingUnderscores(patternLeaf);
        if (WildcardMatchNoCase(valueNoUnderscore, patternNoUnderscore))
        {
            matches = true;
            break;
        }
    } while (false);

    return matches;
}

bool SymbolEngine::EnumKernelModules(std::vector<KernelModuleInfo>* modules, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (modules == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid modules output";
            }
            break;
        }

        modules->clear();
        const DWORD privilegeStatus = EnableModuleQueryPrivilege();

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
        {
            if (error != nullptr)
            {
                *error = SystemErrorText(L"GetModuleHandleW ntdll failed", GetLastError());
            }
            break;
        }

        auto query = reinterpret_cast<NtQuerySystemInformationPtr>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
        if (query == nullptr)
        {
            if (error != nullptr)
            {
                *error = SystemErrorText(L"GetProcAddress NtQuerySystemInformation failed", GetLastError());
            }
            break;
        }

        ULONG required = 0;
        NTSTATUS status = query(KnDbgSystemModuleInformation, nullptr, 0, &required);
        if (required == 0)
        {
            required = 64 * 1024;
        }

        if (!NT_SUCCESS(status) && status != STATUS_INFO_LENGTH_MISMATCH)
        {
            if (error != nullptr)
            {
                std::wstringstream stream;
                stream << L"NtQuerySystemInformation length query failed: 0x" << std::hex << status;
                *error = stream.str();
            }
            break;
        }

        std::vector<uint8_t> buffer;
        for (ULONG attempt = 0; attempt < 8; ++attempt)
        {
            buffer.assign(static_cast<size_t>(required) + 64 * 1024, 0);
            ULONG returnedLength = 0;
            status = query(
                KnDbgSystemModuleInformation,
                buffer.data(),
                static_cast<ULONG>(buffer.size()),
                &returnedLength);

            if (NT_SUCCESS(status))
            {
                required = returnedLength;
                break;
            }

            if (status != STATUS_INFO_LENGTH_MISMATCH)
            {
                break;
            }

            required = returnedLength != 0 ? returnedLength : static_cast<ULONG>(buffer.size() * 2);
        }

        if (!NT_SUCCESS(status))
        {
            if (error != nullptr)
            {
                std::wstringstream stream;
                stream << L"NtQuerySystemInformation modules failed: 0x" << std::hex << status;
                *error = stream.str();
            }
            break;
        }

        const size_t headerSize = offsetof(KNDBG_RTL_PROCESS_MODULES, Modules);
        const size_t available = std::min<size_t>(required, buffer.size());
        if (available < headerSize)
        {
            if (error != nullptr) { *error = L"module query returned a truncated header"; }
            break;
        }
        auto rawModules = reinterpret_cast<PKNDBG_RTL_PROCESS_MODULES>(buffer.data());
        if (rawModules->NumberOfModules == 0 ||
            rawModules->NumberOfModules > (available - headerSize) / sizeof(KNDBG_RTL_PROCESS_MODULE_INFORMATION))
        {
            if (error != nullptr) { *error = L"module query returned an empty or truncated inventory"; }
            break;
        }
        std::vector<KernelModuleInfo> collected;
        collected.reserve(rawModules->NumberOfModules);

        for (ULONG index = 0; index < rawModules->NumberOfModules; ++index)
        {
            const KNDBG_RTL_PROCESS_MODULE_INFORMATION& raw = rawModules->Modules[index];
            if (raw.ImageBase == nullptr || raw.ImageSize == 0)
            {
                if (error != nullptr)
                {
                    *error = L"kernel module addresses are redacted or invalid; SeDebugPrivilege must be assigned and enabled "
                             L"(privilege status=" + std::to_wstring(privilegeStatus) + L"); inventory is unavailable";
                }
                break;
            }
            const auto pathEnd = static_cast<const UCHAR*>(
                memchr(raw.FullPathName, '\0', sizeof(raw.FullPathName)));
            if (pathEnd == nullptr ||
                raw.OffsetToFileName > static_cast<size_t>(pathEnd - raw.FullPathName))
            {
                if (error != nullptr) { *error = L"module query returned an invalid image path"; }
                break;
            }
            KernelModuleInfo module = {};
            module.Base = reinterpret_cast<uint64_t>(raw.ImageBase);
            module.Size = raw.ImageSize;
            module.ImagePath = AsWide(reinterpret_cast<const char*>(raw.FullPathName));
            module.ImageName = AsWide(reinterpret_cast<const char*>(raw.FullPathName + raw.OffsetToFileName));
            collected.push_back(module);
        }

        if (collected.size() != rawModules->NumberOfModules)
        {
            break;
        }
        *modules = std::move(collected);

        ok = true;
    } while (false);

    return ok;
}

std::wstring SymbolEngine::ResolveModuleImagePath(const KernelModuleInfo& module) const
{
    std::wstring result = module.ImagePath;

    if (result.rfind(L"\\SystemRoot\\", 0) == 0)
    {
        wchar_t windowsPath[MAX_PATH] = {};
        if (GetWindowsDirectoryW(windowsPath, static_cast<UINT>(std::size(windowsPath))) != 0)
        {
            result = std::wstring(windowsPath) + result.substr(std::wstring(L"\\SystemRoot").size());
        }
    }
    else if (result.rfind(L"\\??\\", 0) == 0)
    {
        result = result.substr(4);
    }

    return result;
}

SymbolEngine::SymbolEngine() : ready_(false), symbolPath_(L"SRV*https://msdl.microsoft.com/download/symbols"),
    typeLayouts_(std::make_unique<BrokeredTypeLayouts>()), symbolIndexes_(std::make_unique<BrokeredSymbolIndexes>()) {}
SymbolEngine::~SymbolEngine() { Shutdown(); }
void SymbolEngine::ClearMetadata()
{ typeLayouts_->Clear(); symbolIndexes_->Clear(); indexedModules_.clear(); admittedModules_.clear(); indexFailures_.clear(); }
bool SymbolEngine::Initialize(const std::wstring& symbolPath, std::wstring* error)
{
    std::lock_guard<std::recursive_mutex> lock(symbolMutex_);
    Shutdown(); symbolPath_ = symbolPath; ready_ = true;
    if (error != nullptr) { error->clear(); } return true;
}
void SymbolEngine::Shutdown()
{
    std::lock_guard<std::recursive_mutex> lock(symbolMutex_);
    ClearMetadata(); ready_ = false;
    std::lock_guard<std::mutex> modulesLock(modulesMutex_); modules_.clear();
}
bool SymbolEngine::IsReady() const
{ std::lock_guard<std::recursive_mutex> lock(symbolMutex_); return ready_; }
const std::wstring& SymbolEngine::SymbolPath() const { return symbolPath_; }
void SymbolEngine::SetSymbolPath(const std::wstring& symbolPath)
{ std::lock_guard<std::recursive_mutex> lock(symbolMutex_); ClearMetadata(); symbolPath_ = symbolPath; }
std::vector<KernelModuleInfo> SymbolEngine::Modules() const { return CopyModules(); }
std::vector<KernelModuleInfo> SymbolEngine::CopyModules() const
{ std::lock_guard<std::mutex> lock(modulesMutex_); return modules_; }
bool SymbolEngine::ReadyModules(std::wstring* error)
{
    if (!ready_ && !Initialize(symbolPath_, error)) { return false; }
    return !modules_.empty() || LoadKernelModules(error);
}
bool SymbolEngine::LoadKernelModules(std::wstring* error)
{
    std::lock_guard<std::recursive_mutex> lock(symbolMutex_);
    if (!ready_ && !Initialize(symbolPath_, error)) { return false; }
    ClearMetadata();
    std::vector<KernelModuleInfo> discovered;
    const bool ok = EnumKernelModules(&discovered, error);
    std::lock_guard<std::mutex> modulesLock(modulesMutex_);
    modules_ = std::move(discovered);
    if (ok && error != nullptr) { error->clear(); }
    return ok;
}
bool SymbolEngine::EnsureModuleSymbolsLoaded(const KernelModuleInfo& module, std::wstring* error, uint64_t timeoutMs)
{
    if (error != nullptr) { error->clear(); }
    if (symbolIndexes_->Contains(module.Base)) { return true; }
    const auto failed = indexFailures_.find(module.Base);
    if (failed != indexFailures_.end())
    { if (error != nullptr) { *error = failed->second + L"; cached until symbol/module refresh"; } return false; }
    if (module.Base == 0 || module.Size == 0 || module.Size > UINT64_MAX - module.Base || timeoutMs == 0 ||
        (admittedModules_.count(module.Base) == 0 && admittedModules_.size() >= 512))
    { if (error != nullptr) { *error = L"invalid module range or symbol generation budget exhausted"; } return false; }
    std::wstring issue;
    try
    {
        // An evicted entry already belongs to this generation. Reacquisition
        // must not consume another identity slot or be blocked by a full ledger.
        admittedModules_.insert(module.Base);
        std::vector<wchar_t> path(32768);
        const auto count = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        SymbolIndex index;
        if (count != 0 && count < path.size() && ResolveBrokeredSymbolIndex(std::wstring(path.data(), count),
            ResolveModuleImagePath(module), module.Size, symbolPath_, &index, &issue, timeoutMs))
        {
            if (symbolIndexes_->Insert(module.Base, std::move(index)))
            { indexedModules_.insert(module.Base); return true; }
            issue = L"symbol index exceeds retained metadata budget";
        }
    }
    catch (const std::exception&) { issue = L"symbol index metadata allocation failed"; }
    if (issue.empty()) { issue = L"isolated symbol index unavailable"; }
    if (indexFailures_.size() < 512) { indexFailures_[module.Base] = issue; }
    if (error != nullptr) { *error = issue; } return false;
}
bool SymbolEngine::ShouldSearchTypeModule(const KernelModuleInfo& module, const std::wstring& filter) const
{
    return filter.empty() ? IsNtKernelImageName(module.ImageName) || indexedModules_.count(module.Base) != 0 :
        ModuleNameMatches(module.ImageName, filter);
}
bool SymbolEngine::PreloadKernelSymbols(size_t* loadedCount, std::wstring* error)
{
    std::lock_guard<std::recursive_mutex> lock(symbolMutex_);
    if (loadedCount != nullptr) { *loadedCount = 0; }
    if (!ReadyModules(error)) { return false; }
    size_t loaded = 0;
    std::wstring issue = L"kernel image was not found in the loaded module list";
    for (const auto& module : modules_)
    {
        if (IsNtKernelImageName(module.ImageName) && EnsureModuleSymbolsLoaded(module, &issue)) { ++loaded; }
    }
    if (loadedCount != nullptr) { *loadedCount = loaded; }
    if (error != nullptr) { *error = loaded != 0 ? L"" : issue; } return loaded != 0;
}
namespace
{
    bool SplitSymbolQuery(const std::wstring& text, std::wstring* module, std::wstring* leaf, bool pattern)
    {
        if (text.size() > 2048 || text.find(L'\0') != std::wstring::npos) { return false; }
        const auto bang = text.find(L'!');
        *module = bang == std::wstring::npos ? L"" : text.substr(0, bang);
        *leaf = bang == std::wstring::npos ? text : text.substr(bang + 1);
        if (pattern && leaf->empty()) { *leaf = L"*"; }
        return !leaf->empty() && leaf->size() <= 1024 && leaf->find(L'!') == std::wstring::npos &&
            (bang == std::wstring::npos || !module->empty());
    }
    uint64_t QueryRemaining(uint64_t started)
    { const auto elapsed = GetTickCount64() - started; return elapsed < 60000 ? 60000 - elapsed : 0; }
}
bool SymbolEngine::ResolveSymbol(const std::wstring& name, uint64_t* address, std::wstring* error)
{
    std::lock_guard<std::recursive_mutex> lock(symbolMutex_);
    if (address == nullptr) { if (error != nullptr) { *error = L"invalid symbol output"; } return false; }
    *address = 0;
    std::wstring filter, leaf;
    if (!SplitSymbolQuery(name, &filter, &leaf, false))
    { if (error != nullptr) { *error = L"invalid bounded symbol name"; } return false; }
    if (!ReadyModules(error)) { return false; }
    const auto started = GetTickCount64();
    bool found = false, unavailable = false; uint64_t result = 0;
    std::wstring issue = L"symbol not found in eligible modules";
    for (const auto& module : modules_)
    {
        // Bare field filters must never download every deferred module.
        if (filter.empty() ? indexedModules_.count(module.Base) == 0 : !ModuleNameMatches(module.ImageName, filter)) { continue; }
        if (!EnsureModuleSymbolsLoaded(module, &issue, QueryRemaining(started))) { unavailable = true; continue; }
        const auto entry = symbolIndexes_->Find(module.Base);
        uint32_t rva = 0; bool ambiguous = false;
        if (entry && entry->Resolve(leaf, &rva, &ambiguous))
        {
            const auto candidate = module.Base + rva;
            if (found && result != candidate) { ambiguous = true; }
            else { found = true; result = candidate; }
        }
        if (ambiguous)
        { if (error != nullptr) { *error = L"symbol name is ambiguous; use its module and exact linkage name"; } return false; }
    }
    if (!found || unavailable) { if (error != nullptr) { *error = issue; } return false; }
    *address = result; if (error != nullptr) { error->clear(); } return true;
}
bool SymbolEngine::FindNearestSymbol(uint64_t address, std::wstring* name, uint64_t* displacement, std::wstring* error)
{
    std::lock_guard<std::recursive_mutex> lock(symbolMutex_);
    if (name != nullptr) { name->clear(); } if (displacement != nullptr) { *displacement = 0; }
    if (name == nullptr || displacement == nullptr)
    { if (error != nullptr) { *error = L"invalid nearest-symbol output"; } return false; }
    if (!ReadyModules(error)) { return false; }
    const KernelModuleInfo* owner = nullptr;
    for (const auto& module : modules_)
    {
        if (module.Size > UINT64_MAX - module.Base || address < module.Base || address - module.Base >= module.Size) { continue; }
        if (owner != nullptr) { if (error != nullptr) { *error = L"overlapping module inventory"; } return false; }
        owner = &module;
    }
    if (owner == nullptr) { if (error != nullptr) { *error = L"address is outside the module inventory"; } return false; }
    if (!EnsureModuleSymbolsLoaded(*owner, error)) { return false; }
    const auto entry = symbolIndexes_->Find(owner->Base);
    const auto symbol = entry ? entry->Nearest(static_cast<uint32_t>(address - owner->Base)) : nullptr;
    if (symbol == nullptr) { if (error != nullptr) { *error = L"no preceding image-relative symbol"; } return false; }
    *name = symbol->Name;
    *displacement = address - owner->Base - symbol->Rva;
    if (error != nullptr) { error->clear(); } return true;
}
bool SymbolEngine::EnumerateSymbols(const std::wstring& mask, size_t limit, std::vector<SymbolMatchInfo>* matches, std::wstring* error)
{
    std::lock_guard<std::recursive_mutex> lock(symbolMutex_);
    if (matches == nullptr) { if (error != nullptr) { *error = L"invalid symbol output"; } return false; }
    matches->clear(); std::wstring filter, pattern;
    if (!SplitSymbolQuery(mask, &filter, &pattern, true))
    { if (error != nullptr) { *error = L"invalid bounded symbol pattern"; } return false; }
    if (!ReadyModules(error)) { return false; }
    const auto started = GetTickCount64();
    const auto maximum = limit == 0 ? SymbolIndexMaxRows : (std::min)(limit, SymbolIndexMaxRows);
    size_t available = 0, unavailable = 0;
    bool capped = false, exhausted = false;
    size_t resultBytes = 0;
    for (const auto& module : modules_)
    {
        if (!ModuleNameMatches(module.ImageName, filter)) { continue; }
        if (QueryRemaining(started) == 0) { exhausted = true; break; }
        if (!EnsureModuleSymbolsLoaded(module, nullptr, QueryRemaining(started))) { ++unavailable; continue; }
        const auto entry = symbolIndexes_->Find(module.Base);
        if (!entry) { ++unavailable; continue; } ++available;
        for (const auto& row : entry->Index.Symbols)
        {
            if (QueryRemaining(started) == 0) { exhausted = true; break; }
            if (!WildcardMatchNoCase(row.Name, pattern) && !WildcardMatchNoCase(row.LinkageName, pattern)) { continue; }
            const auto address = module.Base + row.Rva;
            // Canonical rows sort by RVA then display name, so provider aliases
            // for one name/address are adjacent within this module.
            if (!matches->empty() && matches->back().Address == address && matches->back().Name == row.Name) { continue; }
            const auto bytes = sizeof(SymbolMatchInfo) + (row.Name.size() + entry->Index.IndexSha256.size() + 2) * sizeof(wchar_t);
            if (matches->size() == maximum || bytes > SymbolIndexMaxBytes - resultBytes) { capped = true; break; }
            matches->push_back({address, static_cast<uint32_t>(row.Bytes), row.Name, row.SizeKnown, entry->Index.IndexSha256});
            resultBytes += bytes;
        }
        if (capped || exhausted) { break; }
    }
    if (error != nullptr)
    {
        *error = unavailable != 0 ? L"symbol enumeration incomplete: unavailable modules=" + std::to_wstring(unavailable) : L"";
        if (capped) { *error += L"; result limit reached"; }
        if (exhausted) { *error += L"; query time budget exhausted"; }
        if (available == 0 && error->empty()) { *error = L"no module matched symbol pattern"; }
    }
    return available != 0;
}
bool SymbolEngine::EnumerateTypes(const std::wstring& mask, size_t limit, std::vector<TypeMatchInfo>* matches, std::wstring* error)
{
    std::lock_guard<std::recursive_mutex> lock(symbolMutex_);
    if (matches == nullptr) { if (error != nullptr) { *error = L"invalid type output"; } return false; }
    matches->clear(); std::wstring filter, pattern;
    if (!SplitSymbolQuery(mask, &filter, &pattern, true))
    { if (error != nullptr) { *error = L"invalid bounded type pattern"; } return false; }
    if (!ReadyModules(error)) { return false; }
    const auto started = GetTickCount64();
    const auto maximum = limit == 0 ? SymbolIndexMaxRows : (std::min)(limit, SymbolIndexMaxRows);
    size_t available = 0, unavailable = 0, resultBytes = 0; bool capped = false, exhausted = false;
    for (const auto& module : modules_)
    {
        if (!ShouldSearchTypeModule(module, filter)) { continue; }
        if (QueryRemaining(started) == 0) { exhausted = true; break; }
        if (!EnsureModuleSymbolsLoaded(module, nullptr, QueryRemaining(started))) { ++unavailable; continue; }
        const auto entry = symbolIndexes_->Find(module.Base);
        if (!entry) { ++unavailable; continue; } ++available;
        for (const auto& row : entry->Index.Types)
        {
            if (QueryRemaining(started) == 0) { exhausted = true; break; }
            if (!TypeNameMatchesNoCase(row.Name, pattern)) { continue; }
            const auto bytes = sizeof(TypeMatchInfo) + (module.ImageName.size() + row.Name.size() + entry->Index.IndexSha256.size() + 3) * sizeof(wchar_t);
            if (matches->size() == maximum || bytes > SymbolIndexMaxBytes - resultBytes) { capped = true; break; }
            matches->push_back({SymbolModuleName(module), row.Name, module.Base, row.ProviderId, row.Bytes,
                row.SizeKnown, entry->Index.IndexSha256});
            resultBytes += bytes;
        }
        if (capped || exhausted) { break; }
    }
    if (error != nullptr)
    {
        *error = unavailable != 0 ? L"type enumeration incomplete: unavailable modules=" + std::to_wstring(unavailable) : L"";
        if (capped) { *error += L"; result limit reached"; }
        if (exhausted) { *error += L"; query time budget exhausted"; }
        if (available == 0 && error->empty()) { *error = L"no eligible module matched type pattern"; }
    }
    return available != 0;
}

bool SymbolEngine::GetTypeLayoutById(uint64_t moduleBase, ULONG typeId, const std::wstring& typeName,
    TypeLayoutInfo* layout, std::wstring* error)
{
    std::lock_guard<std::recursive_mutex> lock(symbolMutex_);
    if (layout != nullptr) { *layout = {}; }
    if (!ready_ || !typeLayouts_->FindById(moduleBase, typeId, typeName, layout))
    {
        if (error != nullptr) { *error = L"isolated type ID is unavailable or was invalidated; resolve its root again"; }
        return false;
    }
    if (error != nullptr) { error->clear(); }
    return true;
}

bool SymbolEngine::GetTypeLayout(const std::wstring& typeName, TypeLayoutInfo* layout, std::wstring* error)
{
    std::lock_guard<std::recursive_mutex> lock(symbolMutex_);
    if (layout == nullptr) { if (error != nullptr) { *error = L"invalid type layout output"; } return false; }
    *layout = {};
    if (typeName.empty() || typeName.size() > 2048 || typeName.find(L'\0') != std::wstring::npos)
    { if (error != nullptr) { *error = L"invalid bounded type name"; } return false; }
    try
    {
        if (!ready_ && !Initialize(symbolPath_, error)) { return false; }
        if (modules_.empty())
        {
            // Discovery for a type request does not register/load images in
            // DbgHelp. The artifact resolver and restricted worker own this path.
            std::vector<KernelModuleInfo> discovered;
            if (!EnumKernelModules(&discovered, error)) { return false; }
            std::lock_guard<std::mutex> modulesLock(modulesMutex_);
            modules_ = std::move(discovered);
        }
        const auto bang = typeName.find(L'!');
        const auto moduleFilter = bang == std::wstring::npos ? L"" : typeName.substr(0, bang);
        const auto leaf = bang == std::wstring::npos ? typeName : typeName.substr(bang + 1);
        if (leaf.empty() || leaf.size() > 1024 || leaf.find(L'!') != std::wstring::npos)
        { if (error != nullptr) { *error = L"invalid qualified type name"; } return false; }
        std::vector<wchar_t> executable(32768);
        const auto count = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
        if (count == 0 || count >= executable.size()) { return false; }
        std::wstring lastError = L"no module matched isolated type query";
        for (const auto& module : modules_)
        {
            if ((!moduleFilter.empty() && !ModuleNameMatches(module.ImageName, moduleFilter)) ||
                (moduleFilter.empty() && !IsNtKernelImageName(module.ImageName) && !ShouldSearchTypeModule(module, L""))) { continue; }
            if (typeLayouts_->Find(module.Base, typeName, layout))
            { if (error != nullptr) { error->clear(); } return true; }
            TypeSchemaPackage schema;
            if (ResolveBrokeredTypeSchema(std::wstring(executable.data(), count), ResolveModuleImagePath(module),
                module.Size, symbolPath_, leaf, &schema, &lastError) &&
                typeLayouts_->Insert(module.Base, typeName, schema, layout, &lastError))
            { if (error != nullptr) { error->clear(); } return true; }
        }
        if (error != nullptr) { *error = lastError; }
    }
    catch (const std::exception&)
    {
        *layout = {};
        if (error != nullptr) { *error = L"isolated type layout failed while materializing bounded metadata"; }
    }
    return false;
}

bool SymbolEngine::GetTypeFields(const std::wstring& typeName, std::vector<TypeFieldInfo>* fields, ULONG64* typeSize, std::wstring* error)
{
    std::lock_guard<std::recursive_mutex> lock(symbolMutex_);
    if (typeSize != nullptr) { *typeSize = 0; }
    if (fields == nullptr) { if (error != nullptr) { *error = L"invalid field output"; } return false; }
    fields->clear();
    TypeLayoutInfo layout;
    if (!GetTypeLayout(typeName, &layout, error)) { return false; }
    *fields = std::move(layout.Fields);
    if (typeSize != nullptr) { *typeSize = layout.Size; }
    return true;
}

bool SymbolEngine::FindField(const std::wstring& typeName, const std::wstring& fieldName, TypeFieldInfo* field, std::wstring* error)
{
    std::lock_guard<std::recursive_mutex> lock(symbolMutex_);
    if (field == nullptr) { if (error != nullptr) { *error = L"invalid field output"; } return false; }
    *field = {};
    if (error != nullptr) { *error = L"field path is invalid, unavailable or ambiguous"; }
    if (fieldName.empty() || fieldName.size() > 8192 || fieldName.find(L'\0') != std::wstring::npos) { return false; }
    std::vector<std::wstring> segments;
    size_t begin = 0;
    for (;;)
    {
        const auto dot = fieldName.find(L'.', begin);
        auto segment = fieldName.substr(begin, dot == std::wstring::npos ? dot : dot - begin);
        if (segment.empty() || segment.size() > 1024 || segments.size() == TypeSchemaMaxDepth) { return false; }
        segments.push_back(std::move(segment));
        if (dot == std::wstring::npos) { break; }
        begin = dot + 1;
    }
    // Preserve exact spelling first. Case-insensitive compatibility lookup is
    // valid only when unique; never choose a field by enumeration order.
    const auto find = [](const std::vector<TypeFieldInfo>& fields, const std::wstring& name) -> const TypeFieldInfo*
    {
        for (const auto& candidate : fields) { if (candidate.Name == name) { return &candidate; } }
        const TypeFieldInfo* result = nullptr;
        for (const auto& candidate : fields)
        {
            if (_wcsicmp(candidate.Name.c_str(), name.c_str()) != 0) { continue; }
            if (result != nullptr) { return nullptr; }
            result = &candidate;
        }
        return result;
    };
    TypeLayoutInfo layout;
    if (!GetTypeLayout(typeName, &layout, error)) { return false; }
    const auto rootSize = layout.Size;
    uint64_t offset = 0;
    TypeFieldInfo current;
    for (size_t i = 0; i < segments.size(); ++i)
    {
        const auto member = find(layout.Fields, segments[i]);
        if (member == nullptr || member->Offset > layout.Size || member->StorageLength > layout.Size - member->Offset ||
            offset > rootSize || member->Offset > rootSize - offset) { break; }
        current = *member;
        offset += current.Offset;
        if (offset > UINT32_MAX || current.StorageLength > rootSize - offset) { break; }
        if (i + 1 == segments.size())
        {
            current.Offset = static_cast<ULONG>(offset);
            *field = std::move(current);
            if (error != nullptr) { error->clear(); }
            return true;
        }
        if (current.ChildTypeId == 0 || !GetTypeLayoutById(current.ModuleBase, current.ChildTypeId, current.TypeName, &layout, error))
        { break; }
    }
    if (error != nullptr) { *error = L"field path is unavailable or ambiguous; only bounded embedded members can be traversed"; }
    return false;
}
std::optional<uint64_t> SymbolEngine::ParseAddressOrSymbol(const std::wstring& value, std::wstring* error)
{
    std::optional<uint64_t> result;

    do
    {
        if (value.empty())
        {
            if (error != nullptr)
            {
                *error = L"Empty address";
            }
            break;
        }

        wchar_t* end = nullptr;
        uint64_t address = wcstoull(value.c_str(), &end, 0);
        if (end != nullptr && *end == L'\0')
        {
            result = address;
            break;
        }

        if (ResolveSymbol(value, &address, error))
        {
            result = address;
        }
    } while (false);

    return result;
}
