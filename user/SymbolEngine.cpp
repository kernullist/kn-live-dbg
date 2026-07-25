#include "SymbolEngine.h"

#include <dia2.h>
#include <winternl.h>

#include <algorithm>
#include <cwctype>
#include <memory>
#include <sstream>

#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "diaguids.lib")
#pragma comment(lib, "OleAut32.lib")

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

typedef HRESULT (STDAPICALLTYPE* DllGetClassObjectPtr)(REFCLSID classId, REFIID interfaceId, LPVOID* object);

static HMODULE g_DiaLocalModule = nullptr;
static std::wstring g_DiaLocalModulePath;

static std::wstring DbgHelpErrorText(const wchar_t* prefix, DWORD error)
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

static std::wstring LoadedModulePathText(const wchar_t* moduleName)
{
    std::wstring result = L"not-loaded";

    do
    {
        if (moduleName == nullptr || moduleName[0] == L'\0')
        {
            break;
        }

        HMODULE module = GetModuleHandleW(moduleName);
        if (module == nullptr)
        {
            break;
        }

        wchar_t path[MAX_PATH] = {};
        DWORD length = GetModuleFileNameW(module, path, static_cast<DWORD>(std::size(path)));
        if (length == 0)
        {
            result = L"loaded-path-unavailable";
            break;
        }

        if (length >= static_cast<DWORD>(std::size(path)))
        {
            result = L"loaded-path-truncated";
            break;
        }

        result = path;
    } while (false);

    return result;
}

static std::wstring GetExecutableDirectory()
{
    std::wstring result;

    do
    {
        wchar_t path[MAX_PATH] = {};
        DWORD length = GetModuleFileNameW(nullptr, path, static_cast<DWORD>(std::size(path)));
        if (length == 0 || length >= static_cast<DWORD>(std::size(path)))
        {
            break;
        }

        result = path;
        size_t slash = result.find_last_of(L"\\/");
        if (slash == std::wstring::npos)
        {
            result.clear();
            break;
        }

        result.resize(slash);
    } while (false);

    return result;
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

static std::wstring GetDbgHelpModuleName(const KernelModuleInfo& module)
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

static bool IsLoadedCodeViewSymbolType(SYM_TYPE type)
{
    return type == SymPdb || type == SymDia || type == SymCv;
}

static std::wstring SymbolTypeName(SYM_TYPE type)
{
    std::wstring name;

    switch (type)
    {
    case SymNone:
        name = L"SymNone";
        break;
    case SymCoff:
        name = L"SymCoff";
        break;
    case SymCv:
        name = L"SymCv";
        break;
    case SymPdb:
        name = L"SymPdb";
        break;
    case SymExport:
        name = L"SymExport";
        break;
    case SymDeferred:
        name = L"SymDeferred";
        break;
    case SymSym:
        name = L"SymSym";
        break;
    case SymDia:
        name = L"SymDia";
        break;
    case SymVirtual:
        name = L"SymVirtual";
        break;
    default:
        name = L"SymUnknown";
        break;
    }

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

static std::wstring GetTypeSymbolName(HANDLE process, DWORD64 moduleBase, ULONG typeId)
{
    std::wstring name;
    WCHAR* rawName = nullptr;

    if (SymGetTypeInfo(process, moduleBase, typeId, TI_GET_SYMNAME, &rawName) && rawName != nullptr)
    {
        name = rawName;
        LocalFree(rawName);
    }

    return name;
}

static std::wstring BaseTypeName(DWORD baseType, ULONG64 length)
{
    std::wstring name;

    switch (baseType)
    {
    case 0:
        name = L"<no type>";
        break;
    case 1:
        name = L"void";
        break;
    case 2:
        name = L"char";
        break;
    case 3:
        name = L"wchar_t";
        break;
    case 6:
        name = length == 8 ? L"__int64" : (length == 2 ? L"short" : L"long");
        break;
    case 7:
        name = length == 8 ? L"unsigned __int64" : (length == 2 ? L"unsigned short" : L"unsigned long");
        break;
    case 8:
        name = length == 8 ? L"double" : L"float";
        break;
    case 10:
        name = L"bool";
        break;
    case 13:
        name = L"long";
        break;
    case 14:
        name = L"unsigned long";
        break;
    case 31:
        name = L"HRESULT";
        break;
    case 32:
        name = L"char16_t";
        break;
    case 33:
        name = L"char32_t";
        break;
    case 34:
        name = L"char8_t";
        break;
    default:
        name = L"<base>";
        break;
    }

    return name;
}

static std::wstring DescribeType(HANDLE process, DWORD64 moduleBase, ULONG typeId, ULONG depth)
{
    std::wstring name;

    do
    {
        if (typeId == 0)
        {
            break;
        }

        DWORD tag = 0;
        SymGetTypeInfo(process, moduleBase, typeId, TI_GET_SYMTAG, &tag);

        if (tag == KNDBG_SYMTAG_POINTER_TYPE)
        {
            ULONG childTypeId = 0;
            if (depth < 8 && SymGetTypeInfo(process, moduleBase, typeId, TI_GET_TYPEID, &childTypeId))
            {
                name = DescribeType(process, moduleBase, childTypeId, depth + 1);
            }

            if (name.empty())
            {
                name = L"void";
            }

            name += L" *";
            break;
        }

        if (tag == KNDBG_SYMTAG_ARRAY_TYPE)
        {
            ULONG childTypeId = 0;
            ULONG count = 0;
            if (depth < 8 && SymGetTypeInfo(process, moduleBase, typeId, TI_GET_TYPEID, &childTypeId))
            {
                name = DescribeType(process, moduleBase, childTypeId, depth + 1);
            }

            if (name.empty())
            {
                name = L"<array>";
            }

            if (SymGetTypeInfo(process, moduleBase, typeId, TI_GET_COUNT, &count))
            {
                std::wstringstream stream;
                stream << name << L"[" << count << L"]";
                name = stream.str();
            }
            else
            {
                name += L"[]";
            }
            break;
        }

        if (tag == KNDBG_SYMTAG_BASE_TYPE)
        {
            DWORD baseType = 0;
            ULONG64 length = 0;
            SymGetTypeInfo(process, moduleBase, typeId, TI_GET_BASETYPE, &baseType);
            SymGetTypeInfo(process, moduleBase, typeId, TI_GET_LENGTH, &length);
            name = BaseTypeName(baseType, length);
            break;
        }

        name = GetTypeSymbolName(process, moduleBase, typeId);
        if (!name.empty())
        {
            break;
        }

        ULONG childTypeId = 0;
        if (depth < 8 && SymGetTypeInfo(process, moduleBase, typeId, TI_GET_TYPEID, &childTypeId))
        {
            name = DescribeType(process, moduleBase, childTypeId, depth + 1);
        }
    } while (false);

    if (name.empty())
    {
        name = L"<unnamed>";
    }

    return name;
}

template <typename T>
static void ReleaseCom(T*& value)
{
    if (value != nullptr)
    {
        value->Release();
        value = nullptr;
    }
}

static std::wstring HResultText(const wchar_t* prefix, HRESULT hr)
{
    std::wstringstream stream;
    stream << prefix << L": 0x" << std::hex << static_cast<unsigned long>(hr);
    return stream.str();
}

static bool CreateDiaDataSourceFromModule(HMODULE module, IDiaDataSource** source, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (source == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid DIA data source output";
            }
            break;
        }

        *source = nullptr;

        if (module == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid DIA module handle";
            }
            break;
        }

        FARPROC proc = GetProcAddress(module, "DllGetClassObject");
        if (proc == nullptr)
        {
            if (error != nullptr)
            {
                *error = DbgHelpErrorText(L"GetProcAddress DllGetClassObject failed", GetLastError());
            }
            break;
        }

        auto getClassObject = reinterpret_cast<DllGetClassObjectPtr>(proc);
        IClassFactory* factory = nullptr;
        HRESULT hr = getClassObject(CLSID_DiaSource, IID_IClassFactory, reinterpret_cast<void**>(&factory));
        if (FAILED(hr) || factory == nullptr)
        {
            if (error != nullptr)
            {
                *error = HResultText(L"DllGetClassObject CLSID_DiaSource failed", hr);
            }
            ReleaseCom(factory);
            break;
        }

        hr = factory->CreateInstance(nullptr, __uuidof(IDiaDataSource), reinterpret_cast<void**>(source));
        ReleaseCom(factory);
        if (FAILED(hr) || *source == nullptr)
        {
            if (error != nullptr)
            {
                *error = HResultText(L"IClassFactory::CreateInstance IDiaDataSource failed", hr);
            }
            ReleaseCom(*source);
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool CreateDiaDataSource(IDiaDataSource** source, std::wstring* provider, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (source == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid DIA data source output";
            }
            break;
        }

        *source = nullptr;
        if (provider != nullptr)
        {
            provider->clear();
        }

        HRESULT hr = CoCreateInstance(
            CLSID_DiaSource,
            nullptr,
            CLSCTX_INPROC_SERVER,
            __uuidof(IDiaDataSource),
            reinterpret_cast<void**>(source));
        if (SUCCEEDED(hr) && *source != nullptr)
        {
            if (provider != nullptr)
            {
                *provider = L"registered COM";
            }
            ok = true;
            break;
        }

        ReleaseCom(*source);
        std::wstring coCreateError = HResultText(L"CoCreateInstance CLSID_DiaSource failed", hr);

        if (g_DiaLocalModule != nullptr)
        {
            std::wstring localError;
            if (CreateDiaDataSourceFromModule(g_DiaLocalModule, source, &localError))
            {
                if (provider != nullptr)
                {
                    *provider = L"local " + g_DiaLocalModulePath;
                }
                ok = true;
                break;
            }

            if (error != nullptr)
            {
                *error = coCreateError + L"; local DIA fallback failed: " + localError;
            }
            break;
        }

        std::wstring exeDir = GetExecutableDirectory();
        if (exeDir.empty())
        {
            if (error != nullptr)
            {
                *error = coCreateError + L"; local DIA fallback failed: executable directory unavailable";
            }
            break;
        }

        const wchar_t* candidates[] =
        {
            L"msdia140.dll",
            L"msdia150.dll"
        };

        std::wstring lastLocalError = L"no local msdia dll found";
        for (const wchar_t* candidate : candidates)
        {
            std::wstring path = exeDir + L"\\" + candidate;
            DWORD attributes = GetFileAttributesW(path.c_str());
            if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
            {
                continue;
            }

            HMODULE module = LoadLibraryW(path.c_str());
            if (module == nullptr)
            {
                lastLocalError = path + L": " + DbgHelpErrorText(L"LoadLibraryW DIA failed", GetLastError());
                continue;
            }

            std::wstring createError;
            if (!CreateDiaDataSourceFromModule(module, source, &createError))
            {
                lastLocalError = path + L": " + createError;
                FreeLibrary(module);
                continue;
            }

            g_DiaLocalModule = module;
            g_DiaLocalModulePath = path;
            if (provider != nullptr)
            {
                *provider = L"local " + path;
            }
            ok = true;
            break;
        }

        if (!ok && error != nullptr)
        {
            *error = coCreateError + L"; local DIA fallback failed: " + lastLocalError;
        }
    } while (false);

    return ok;
}

static std::wstring BstrToWide(BSTR value)
{
    std::wstring result;

    if (value != nullptr)
    {
        result.assign(value, SysStringLen(value));
    }

    return result;
}

static std::wstring DiaSymbolName(IDiaSymbol* symbol)
{
    std::wstring name;
    BSTR rawName = nullptr;

    if (symbol != nullptr && SUCCEEDED(symbol->get_name(&rawName)))
    {
        name = BstrToWide(rawName);
    }

    if (rawName != nullptr)
    {
        SysFreeString(rawName);
    }

    return name;
}

static std::wstring DiaDescribeType(IDiaSymbol* type, ULONG depth)
{
    std::wstring name;

    do
    {
        if (type == nullptr)
        {
            break;
        }

        DWORD tag = 0;
        type->get_symTag(&tag);

        if (tag == SymTagPointerType)
        {
            IDiaSymbol* child = nullptr;
            if (depth < 8 && SUCCEEDED(type->get_type(&child)) && child != nullptr)
            {
                name = DiaDescribeType(child, depth + 1);
            }
            ReleaseCom(child);

            if (name.empty())
            {
                name = L"void";
            }
            name += L"*";
            break;
        }

        if (tag == SymTagArrayType)
        {
            IDiaSymbol* child = nullptr;
            if (depth < 8 && SUCCEEDED(type->get_type(&child)) && child != nullptr)
            {
                name = DiaDescribeType(child, depth + 1);
            }
            ReleaseCom(child);

            DWORD count = 0;
            type->get_count(&count);
            if (name.empty())
            {
                name = L"<array>";
            }

            std::wstringstream stream;
            stream << name << L"[" << count << L"]";
            name = stream.str();
            break;
        }

        if (tag == SymTagBaseType)
        {
            DWORD baseType = 0;
            ULONGLONG length = 0;
            type->get_baseType(&baseType);
            type->get_length(&length);
            name = BaseTypeName(baseType, length);
            break;
        }

        name = DiaSymbolName(type);
        if (!name.empty())
        {
            break;
        }

        IDiaSymbol* child = nullptr;
        if (depth < 8 && SUCCEEDED(type->get_type(&child)) && child != nullptr)
        {
            name = DiaDescribeType(child, depth + 1);
        }
        ReleaseCom(child);
    } while (false);

    if (name.empty())
    {
        name = L"<unknown>";
    }

    return name;
}

static std::wstring GetLoadedPdbPath(HANDLE process, uint64_t moduleBase)
{
    std::wstring path;

    do
    {
        if (moduleBase == 0)
        {
            break;
        }

        IMAGEHLP_MODULEW64 moduleInfo = {};
        moduleInfo.SizeOfStruct = sizeof(moduleInfo);
        if (!SymGetModuleInfoW64(process, moduleBase, &moduleInfo))
        {
            break;
        }

        if (moduleInfo.LoadedPdbName[0] != L'\0')
        {
            path = moduleInfo.LoadedPdbName;
        }
    } while (false);

    return path;
}

typedef struct _KNDBG_FORCE_SYMBOL_LOAD_CONTEXT
{
    bool SeenSymbol;
} KNDBG_FORCE_SYMBOL_LOAD_CONTEXT;

static BOOL CALLBACK KnDbgForceSymbolLoadCallback(PSYMBOL_INFOW SymbolInfo, ULONG SymbolSize, PVOID UserContext)
{
    UNREFERENCED_PARAMETER(SymbolInfo);
    UNREFERENCED_PARAMETER(SymbolSize);

    auto context = reinterpret_cast<KNDBG_FORCE_SYMBOL_LOAD_CONTEXT*>(UserContext);
    if (context != nullptr)
    {
        context->SeenSymbol = true;
    }

    return FALSE;
}

SymbolEngine::SymbolEngine() :
    process_(GetCurrentProcess()),
    ready_(false),
    symbolPath_(L"SRV*https://msdl.microsoft.com/download/symbols")
{
}

SymbolEngine::~SymbolEngine()
{
    Shutdown();
}

bool SymbolEngine::Initialize(const std::wstring& symbolPath, std::wstring* error)
{
    bool ok = false;

    do
    {
        Shutdown();

        symbolPath_ = symbolPath;
        SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_EXACT_SYMBOLS);

        if (!SymInitializeW(process_, symbolPath_.c_str(), FALSE))
        {
            if (error != nullptr)
            {
                *error = DbgHelpErrorText(L"SymInitializeW failed", GetLastError());
            }
            break;
        }

        ready_ = true;
        ok = true;
    } while (false);

    return ok;
}

void SymbolEngine::Shutdown()
{
    if (ready_)
    {
        SymCleanup(process_);
        ready_ = false;
    }

    modules_.clear();
}

bool SymbolEngine::IsReady() const
{
    return ready_;
}

const std::wstring& SymbolEngine::SymbolPath() const
{
    return symbolPath_;
}

void SymbolEngine::SetSymbolPath(const std::wstring& symbolPath)
{
    symbolPath_ = symbolPath;

    if (ready_)
    {
        SymSetSearchPathW(process_, symbolPath_.c_str());
    }
}

const std::vector<KernelModuleInfo>& SymbolEngine::Modules() const
{
    return modules_;
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

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
        {
            if (error != nullptr)
            {
                *error = DbgHelpErrorText(L"GetModuleHandleW ntdll failed", GetLastError());
            }
            break;
        }

        auto query = reinterpret_cast<NtQuerySystemInformationPtr>(GetProcAddress(ntdll, "NtQuerySystemInformation"));
        if (query == nullptr)
        {
            if (error != nullptr)
            {
                *error = DbgHelpErrorText(L"GetProcAddress NtQuerySystemInformation failed", GetLastError());
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

        auto rawModules = reinterpret_cast<PKNDBG_RTL_PROCESS_MODULES>(buffer.data());
        modules->clear();
        modules->reserve(rawModules->NumberOfModules);

        for (ULONG index = 0; index < rawModules->NumberOfModules; ++index)
        {
            const KNDBG_RTL_PROCESS_MODULE_INFORMATION& raw = rawModules->Modules[index];
            KernelModuleInfo module = {};
            module.Base = reinterpret_cast<uint64_t>(raw.ImageBase);
            module.Size = raw.ImageSize;
            module.ImagePath = AsWide(reinterpret_cast<const char*>(raw.FullPathName));
            module.ImageName = AsWide(reinterpret_cast<const char*>(raw.FullPathName + raw.OffsetToFileName));
            modules->push_back(module);
        }

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

bool SymbolEngine::EnsureModuleLoaded(const KernelModuleInfo& module, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (module.Base == 0)
        {
            if (error != nullptr)
            {
                *error = L"Invalid module base";
            }
            break;
        }

        IMAGEHLP_MODULEW64 moduleInfo = {};
        moduleInfo.SizeOfStruct = sizeof(moduleInfo);
        if (SymGetModuleInfoW64(process_, module.Base, &moduleInfo))
        {
            if (moduleInfo.SymType != SymNone)
            {
                ok = true;
                break;
            }

            SymUnloadModule64(process_, module.Base);
        }

        std::wstring imagePath = ResolveModuleImagePath(module);
        std::wstring moduleName = GetDbgHelpModuleName(module);

        SetLastError(ERROR_SUCCESS);
        DWORD64 loaded = SymLoadModuleExW(
            process_,
            nullptr,
            imagePath.empty() ? nullptr : imagePath.c_str(),
            moduleName.empty() ? nullptr : moduleName.c_str(),
            module.Base,
            module.Size,
            nullptr,
            0);

        DWORD lastError = GetLastError();
        if (loaded == 0 && lastError != ERROR_SUCCESS)
        {
            if (error != nullptr)
            {
                *error = DbgHelpErrorText(L"SymLoadModuleExW failed", lastError);
            }
            break;
        }

        moduleInfo = {};
        moduleInfo.SizeOfStruct = sizeof(moduleInfo);
        if (!SymGetModuleInfoW64(process_, module.Base, &moduleInfo))
        {
            lastError = GetLastError();
            if (error != nullptr)
            {
                *error = DbgHelpErrorText(L"SymGetModuleInfoW64 failed", lastError);
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool SymbolEngine::EnsureModuleSymbolsLoaded(const KernelModuleInfo& module, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (!EnsureModuleLoaded(module, error))
        {
            break;
        }

        IMAGEHLP_MODULEW64 moduleInfo = {};
        moduleInfo.SizeOfStruct = sizeof(moduleInfo);
        if (SymGetModuleInfoW64(process_, module.Base, &moduleInfo) &&
            IsLoadedCodeViewSymbolType(moduleInfo.SymType))
        {
            ok = true;
            break;
        }

        std::wstring reloadError;
        if (ReloadModuleWithImmediateSymbols(module, &reloadError))
        {
            ok = true;
            break;
        }

        KNDBG_FORCE_SYMBOL_LOAD_CONTEXT context = {};
        SetLastError(ERROR_SUCCESS);
        BOOL enumOk = SymEnumSymbolsW(process_, module.Base, L"*", KnDbgForceSymbolLoadCallback, &context);
        DWORD lastError = GetLastError();

        moduleInfo = {};
        moduleInfo.SizeOfStruct = sizeof(moduleInfo);
        if (SymGetModuleInfoW64(process_, module.Base, &moduleInfo) &&
            IsLoadedCodeViewSymbolType(moduleInfo.SymType))
        {
            ok = true;
            break;
        }

        if (error != nullptr)
        {
            std::wstringstream stream;
            stream << L"CodeView/PDB symbols were not loaded for " << GetDbgHelpModuleName(module)
                   << L" symType=" << static_cast<int>(moduleInfo.SymType)
                   << L" (" << SymbolTypeName(moduleInfo.SymType) << L")";
            if (moduleInfo.LoadedPdbName[0] != L'\0')
            {
                stream << L" pdb=" << moduleInfo.LoadedPdbName;
            }
            if (!reloadError.empty())
            {
                stream << L"; reload=" << reloadError;
            }
            if (!enumOk && lastError != ERROR_SUCCESS)
            {
                stream << L"; " << DbgHelpErrorText(L"SymEnumSymbolsW force load failed", lastError);
            }
            stream << L"; dbghelp=" << LoadedModulePathText(L"dbghelp.dll")
                   << L"; symsrv=" << LoadedModulePathText(L"symsrv.dll");
            *error = stream.str();
        }
    } while (false);

    return ok;
}

bool SymbolEngine::ReloadModuleWithImmediateSymbols(const KernelModuleInfo& module, std::wstring* error)
{
    bool ok = false;
    DWORD originalOptions = SymGetOptions();
    bool restoreOptions = false;

    do
    {
        std::wstring imagePath = ResolveModuleImagePath(module);
        if (imagePath.empty())
        {
            if (error != nullptr)
            {
                *error = L"Module image path is empty";
            }
            break;
        }

        DWORD immediateOptions = originalOptions & ~SYMOPT_DEFERRED_LOADS;
        SymSetOptions(immediateOptions);
        restoreOptions = true;

        SymUnloadModule64(process_, module.Base);

        std::wstring moduleName = GetDbgHelpModuleName(module);
        SetLastError(ERROR_SUCCESS);
        DWORD64 loaded = SymLoadModuleExW(
            process_,
            nullptr,
            imagePath.c_str(),
            moduleName.empty() ? nullptr : moduleName.c_str(),
            module.Base,
            module.Size,
            nullptr,
            0);

        DWORD lastError = GetLastError();
        if (loaded == 0 && lastError != ERROR_SUCCESS)
        {
            if (error != nullptr)
            {
                *error = DbgHelpErrorText(L"SymLoadModuleExW immediate failed", lastError);
            }
            break;
        }

        IMAGEHLP_MODULEW64 moduleInfo = {};
        moduleInfo.SizeOfStruct = sizeof(moduleInfo);
        if (!SymGetModuleInfoW64(process_, module.Base, &moduleInfo))
        {
            lastError = GetLastError();
            if (error != nullptr)
            {
                *error = DbgHelpErrorText(L"SymGetModuleInfoW64 immediate failed", lastError);
            }
            break;
        }

        if (!IsLoadedCodeViewSymbolType(moduleInfo.SymType))
        {
            if (error != nullptr)
            {
                std::wstringstream stream;
                stream << L"immediate load symType=" << static_cast<int>(moduleInfo.SymType)
                       << L" (" << SymbolTypeName(moduleInfo.SymType) << L")";
                if (moduleInfo.LoadedPdbName[0] != L'\0')
                {
                    stream << L" pdb=" << moduleInfo.LoadedPdbName;
                }
                stream << L" image=" << imagePath;
                *error = stream.str();
            }
            break;
        }

        ok = true;
    } while (false);

    if (restoreOptions)
    {
        SymSetOptions(originalOptions);
    }

    return ok;
}

bool SymbolEngine::LoadKernelModules(std::wstring* error)
{
    bool ok = false;

    do
    {
        if (!ready_)
        {
            if (!Initialize(symbolPath_, error))
            {
                break;
            }
        }

        std::vector<KernelModuleInfo> modules;
        if (!EnumKernelModules(&modules, error))
        {
            break;
        }

        for (const KernelModuleInfo& module : modules)
        {
            EnsureModuleLoaded(module, nullptr);
        }

        modules_ = std::move(modules);
        ok = true;
    } while (false);

    return ok;
}

bool SymbolEngine::PreloadKernelSymbols(size_t* loadedCount, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (loadedCount != nullptr)
        {
            *loadedCount = 0;
        }

        if (!ready_)
        {
            if (!Initialize(symbolPath_, error))
            {
                break;
            }
        }

        if (modules_.empty())
        {
            if (!LoadKernelModules(error))
            {
                break;
            }
        }

        bool sawKernelImage = false;
        std::wstring lastError;
        size_t localCount = 0;

        for (const KernelModuleInfo& module : modules_)
        {
            if (!IsNtKernelImageName(module.ImageName))
            {
                continue;
            }

            sawKernelImage = true;
            std::wstring localError;
            if (!EnsureModuleSymbolsLoaded(module, &localError))
            {
                lastError = localError;
                continue;
            }

            ++localCount;
        }

        if (!sawKernelImage)
        {
            if (error != nullptr)
            {
                *error = L"Kernel image was not found in the loaded module list";
            }
            break;
        }

        if (localCount == 0)
        {
            if (error != nullptr)
            {
                *error = lastError.empty() ? L"Kernel symbols were not loaded" : lastError;
            }
            break;
        }

        if (loadedCount != nullptr)
        {
            *loadedCount = localCount;
        }

        ok = true;
    } while (false);

    return ok;
}

bool SymbolEngine::LoadDiaDataForModule(const KernelModuleInfo& module, IDiaDataSource* source, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (source == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid DIA data source";
            }
            break;
        }

        std::wstring lastError;
        std::wstring pdbPath = GetLoadedPdbPath(process_, module.Base);
        if (!pdbPath.empty())
        {
            HRESULT hr = source->loadDataFromPdb(pdbPath.c_str());
            if (SUCCEEDED(hr))
            {
                ok = true;
                break;
            }

            lastError = HResultText(L"IDiaDataSource::loadDataFromPdb failed", hr);
        }

        std::wstring imagePath = ResolveModuleImagePath(module);
        if (imagePath.empty())
        {
            if (error != nullptr)
            {
                *error = lastError.empty() ? L"DIA loadDataForExe failed: no module image path" : lastError;
            }
            break;
        }

        HRESULT hr = source->loadDataForExe(imagePath.c_str(), symbolPath_.c_str(), nullptr);
        if (FAILED(hr))
        {
            if (error != nullptr)
            {
                std::wstring exeError = HResultText(L"IDiaDataSource::loadDataForExe failed", hr);
                *error = lastError.empty() ? exeError : lastError + L"; " + exeError;
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool SymbolEngine::ResolveSymbol(const std::wstring& name, uint64_t* address, std::wstring* error)
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

        if (!ready_)
        {
            if (!Initialize(symbolPath_, error))
            {
                break;
            }
        }

        wchar_t buffer[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t)] = {};
        PSYMBOL_INFOW symbol = reinterpret_cast<PSYMBOL_INFOW>(buffer);
        symbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
        symbol->MaxNameLen = MAX_SYM_NAME;

        if (!SymFromNameW(process_, name.c_str(), symbol))
        {
            if (error != nullptr)
            {
                *error = DbgHelpErrorText(L"SymFromNameW failed", GetLastError());
            }
            break;
        }

        *address = symbol->Address;
        ok = true;
    } while (false);

    return ok;
}

bool SymbolEngine::FindNearestSymbol(uint64_t address, std::wstring* name, uint64_t* displacement, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (name == nullptr || displacement == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid nearest-symbol output";
            }
            break;
        }

        if (!ready_)
        {
            if (!Initialize(symbolPath_, error))
            {
                break;
            }
        }

        wchar_t buffer[sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t)] = {};
        PSYMBOL_INFOW symbol = reinterpret_cast<PSYMBOL_INFOW>(buffer);
        symbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
        symbol->MaxNameLen = MAX_SYM_NAME;

        DWORD64 localDisplacement = 0;
        if (!SymFromAddrW(process_, address, &localDisplacement, symbol))
        {
            if (error != nullptr)
            {
                *error = DbgHelpErrorText(L"SymFromAddrW failed", GetLastError());
            }
            break;
        }

        *name = symbol->Name;
        *displacement = localDisplacement;
        ok = true;
    } while (false);

    return ok;
}

typedef struct _KNDBG_ENUM_SYMBOL_CONTEXT
{
    std::vector<SymbolMatchInfo>* Matches;
    size_t Limit;
} KNDBG_ENUM_SYMBOL_CONTEXT;

static BOOL CALLBACK KnDbgEnumSymbolsCallback(PSYMBOL_INFOW SymbolInfo, ULONG SymbolSize, PVOID UserContext)
{
    BOOL keepGoing = TRUE;

    do
    {
        auto context = reinterpret_cast<KNDBG_ENUM_SYMBOL_CONTEXT*>(UserContext);
        if (context == nullptr || context->Matches == nullptr || SymbolInfo == nullptr)
        {
            keepGoing = FALSE;
            break;
        }

        SymbolMatchInfo match = {};
        match.Address = SymbolInfo->Address;
        match.Size = SymbolSize;
        match.Name = SymbolInfo->Name;
        context->Matches->push_back(match);

        if (context->Limit != 0 && context->Matches->size() >= context->Limit)
        {
            keepGoing = FALSE;
        }
    } while (false);

    return keepGoing;
}

typedef struct _KNDBG_ENUM_TYPE_CONTEXT
{
    HANDLE Process;
    std::vector<TypeMatchInfo>* Matches;
    size_t Limit;
    uint64_t ModuleBase;
    std::wstring ModuleName;
    std::wstring Mask;
    bool StoppedAtLimit;
} KNDBG_ENUM_TYPE_CONTEXT;

static BOOL CALLBACK KnDbgEnumTypesCallback(PSYMBOL_INFOW SymbolInfo, ULONG SymbolSize, PVOID UserContext)
{
    BOOL keepGoing = TRUE;

    do
    {
        auto context = reinterpret_cast<KNDBG_ENUM_TYPE_CONTEXT*>(UserContext);
        if (context == nullptr || context->Matches == nullptr || SymbolInfo == nullptr)
        {
            keepGoing = FALSE;
            break;
        }

        if (!TypeNameMatchesNoCase(SymbolInfo->Name, context->Mask))
        {
            break;
        }

        TypeMatchInfo match = {};
        match.ModuleName = context->ModuleName;
        match.Name = SymbolInfo->Name;
        match.ModuleBase = SymbolInfo->ModBase != 0 ? SymbolInfo->ModBase : context->ModuleBase;
        match.TypeId = SymbolInfo->TypeIndex;
        match.Size = SymbolSize;

        if (match.Size == 0 && context->Process != nullptr && match.ModuleBase != 0 && match.TypeId != 0)
        {
            SymGetTypeInfo(context->Process, match.ModuleBase, match.TypeId, TI_GET_LENGTH, &match.Size);
        }

        context->Matches->push_back(match);

        if (context->Limit != 0 && context->Matches->size() >= context->Limit)
        {
            context->StoppedAtLimit = true;
            keepGoing = FALSE;
        }
    } while (false);

    return keepGoing;
}

bool SymbolEngine::EnumerateSymbols(const std::wstring& mask, size_t limit, std::vector<SymbolMatchInfo>* matches, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (matches == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid symbol output";
            }
            break;
        }

        if (!ready_)
        {
            if (!Initialize(symbolPath_, error))
            {
                break;
            }
        }

        std::wstring effectiveMask = mask.empty() ? L"*" : mask;
        std::wstring moduleFilter;
        std::wstring symbolMask = effectiveMask;
        size_t bang = effectiveMask.find(L'!');
        if (bang != std::wstring::npos)
        {
            moduleFilter = effectiveMask.substr(0, bang);
            symbolMask = effectiveMask.substr(bang + 1);
            if (symbolMask.empty())
            {
                symbolMask = L"*";
            }
        }

        matches->clear();
        KNDBG_ENUM_SYMBOL_CONTEXT context = {};
        context.Matches = matches;
        context.Limit = limit;

        bool foundThroughModule = false;
        DWORD lastError = ERROR_SUCCESS;
        std::wstring lastDetail;

        if (moduleFilter.empty())
        {
            if (!SymEnumSymbolsW(process_, 0, symbolMask.c_str(), KnDbgEnumSymbolsCallback, &context))
            {
                lastError = GetLastError();
            }
            else
            {
                foundThroughModule = true;
            }
        }

        if (matches->empty() || !moduleFilter.empty())
        {
            for (const KernelModuleInfo& module : modules_)
            {
                if (!ModuleNameMatches(module.ImageName, moduleFilter))
                {
                    continue;
                }

                std::wstring loadError;
                if (!EnsureModuleLoaded(module, &loadError))
                {
                    lastDetail = loadError;
                    continue;
                }

                if (SymEnumSymbolsW(process_, module.Base, symbolMask.c_str(), KnDbgEnumSymbolsCallback, &context))
                {
                    foundThroughModule = true;
                }
                else
                {
                    lastError = GetLastError();
                }

                if (limit != 0 && matches->size() >= limit)
                {
                    break;
                }
            }
        }

        if (!foundThroughModule && matches->empty())
        {
            if (error != nullptr)
            {
                *error = lastDetail.empty() ? DbgHelpErrorText(L"SymEnumSymbolsW failed", lastError) : lastDetail;
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool SymbolEngine::EnumerateTypesWithDia(
    const KernelModuleInfo& module,
    const std::wstring& typeMask,
    size_t limit,
    std::vector<TypeMatchInfo>* matches,
    bool* stoppedAtLimit,
    std::wstring* error)
{
    bool ok = false;
    bool coInitialized = false;

    do
    {
        if (matches == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid DIA type match output";
            }
            break;
        }

        if (stoppedAtLimit != nullptr)
        {
            *stoppedAtLimit = false;
        }

        if (limit != 0 && matches->size() >= limit)
        {
            if (stoppedAtLimit != nullptr)
            {
                *stoppedAtLimit = true;
            }
            ok = true;
            break;
        }

        HRESULT coHr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (SUCCEEDED(coHr))
        {
            coInitialized = true;
        }
        else if (coHr != RPC_E_CHANGED_MODE)
        {
            if (error != nullptr)
            {
                *error = HResultText(L"CoInitializeEx failed", coHr);
            }
            break;
        }

        IDiaDataSource* source = nullptr;
        IDiaSession* session = nullptr;
        IDiaSymbol* global = nullptr;
        IDiaEnumSymbols* udtEnum = nullptr;

        std::wstring diaProvider;
        std::wstring diaCreateError;
        if (!CreateDiaDataSource(&source, &diaProvider, &diaCreateError))
        {
            if (error != nullptr)
            {
                *error = diaCreateError;
            }
            ReleaseCom(udtEnum);
            ReleaseCom(global);
            ReleaseCom(session);
            ReleaseCom(source);
            break;
        }

        std::wstring diaLoadError;
        if (!LoadDiaDataForModule(module, source, &diaLoadError))
        {
            if (error != nullptr)
            {
                *error = diaLoadError;
            }
            ReleaseCom(udtEnum);
            ReleaseCom(global);
            ReleaseCom(session);
            ReleaseCom(source);
            break;
        }

        HRESULT hr = source->openSession(&session);
        if (FAILED(hr))
        {
            if (error != nullptr)
            {
                *error = HResultText(L"IDiaDataSource::openSession failed", hr);
            }
            ReleaseCom(udtEnum);
            ReleaseCom(global);
            ReleaseCom(session);
            ReleaseCom(source);
            break;
        }

        session->put_loadAddress(module.Base);

        hr = session->get_globalScope(&global);
        if (FAILED(hr) || global == nullptr)
        {
            if (error != nullptr)
            {
                *error = HResultText(L"IDiaSession::get_globalScope failed", hr);
            }
            ReleaseCom(udtEnum);
            ReleaseCom(global);
            ReleaseCom(session);
            ReleaseCom(source);
            break;
        }

        hr = global->findChildren(SymTagUDT, nullptr, nsNone, &udtEnum);
        if (FAILED(hr) || udtEnum == nullptr)
        {
            if (error != nullptr)
            {
                *error = HResultText(L"DIA findChildren UDT failed", hr);
            }
            ReleaseCom(udtEnum);
            ReleaseCom(global);
            ReleaseCom(session);
            ReleaseCom(source);
            break;
        }

        std::wstring moduleName = GetDbgHelpModuleName(module);
        while (true)
        {
            IDiaSymbol* udt = nullptr;
            ULONG fetched = 0;
            hr = udtEnum->Next(1, &udt, &fetched);
            if (hr != S_OK || fetched == 0 || udt == nullptr)
            {
                ReleaseCom(udt);
                if (FAILED(hr))
                {
                    if (error != nullptr)
                    {
                        *error = HResultText(L"DIA type enumeration failed", hr);
                    }
                    break;
                }

                ok = true;
                break;
            }

            std::wstring name = DiaSymbolName(udt);
            if (!name.empty() && TypeNameMatchesNoCase(name, typeMask))
            {
                TypeMatchInfo match = {};
                match.ModuleName = moduleName;
                match.Name = name;
                match.ModuleBase = module.Base;

                DWORD symIndexId = 0;
                if (SUCCEEDED(udt->get_symIndexId(&symIndexId)))
                {
                    match.TypeId = symIndexId;
                }

                ULONGLONG length = 0;
                if (SUCCEEDED(udt->get_length(&length)))
                {
                    match.Size = length;
                }

                matches->push_back(match);

                if (limit != 0 && matches->size() >= limit)
                {
                    if (stoppedAtLimit != nullptr)
                    {
                        *stoppedAtLimit = true;
                    }
                    ReleaseCom(udt);
                    ok = true;
                    break;
                }
            }

            ReleaseCom(udt);
        }

        ReleaseCom(udtEnum);
        ReleaseCom(global);
        ReleaseCom(session);
        ReleaseCom(source);
    } while (false);

    if (coInitialized)
    {
        CoUninitialize();
    }

    return ok;
}

bool SymbolEngine::EnumerateTypes(const std::wstring& mask, size_t limit, std::vector<TypeMatchInfo>* matches, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (matches == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid type match output";
            }
            break;
        }

        if (!ready_)
        {
            if (!Initialize(symbolPath_, error))
            {
                break;
            }
        }

        if (modules_.empty())
        {
            if (!LoadKernelModules(error))
            {
                break;
            }
        }

        std::wstring effectiveMask = mask.empty() ? L"*" : mask;
        std::wstring moduleFilter;
        std::wstring typeMask = effectiveMask;
        size_t bang = effectiveMask.find(L'!');
        if (bang != std::wstring::npos)
        {
            moduleFilter = effectiveMask.substr(0, bang);
            typeMask = effectiveMask.substr(bang + 1);
            if (typeMask.empty())
            {
                typeMask = L"*";
            }
        }

        matches->clear();
        KNDBG_ENUM_TYPE_CONTEXT context = {};
        context.Process = process_;
        context.Matches = matches;
        context.Limit = limit;
        context.Mask = typeMask;

        bool foundThroughModule = false;
        bool matchedModule = false;
        DWORD lastError = ERROR_SUCCESS;
        std::wstring lastDetail;

        for (const KernelModuleInfo& module : modules_)
        {
            if (!ModuleNameMatches(module.ImageName, moduleFilter))
            {
                continue;
            }

            matchedModule = true;
            std::wstring loadError;
            if (!EnsureModuleLoaded(module, &loadError))
            {
                lastDetail = loadError;
                continue;
            }

            std::wstring symbolLoadError;
            if (!EnsureModuleSymbolsLoaded(module, &symbolLoadError) && !symbolLoadError.empty())
            {
                lastDetail = symbolLoadError;
            }

            context.ModuleBase = module.Base;
            context.ModuleName = GetDbgHelpModuleName(module);
            context.StoppedAtLimit = false;

            if (SymEnumTypesW(process_, module.Base, KnDbgEnumTypesCallback, &context))
            {
                foundThroughModule = true;
            }
            else if (context.StoppedAtLimit)
            {
                foundThroughModule = true;
            }
            else
            {
                lastError = GetLastError();
                std::wstring diaError;
                bool diaStoppedAtLimit = false;
                context.StoppedAtLimit = false;
                if (EnumerateTypesWithDia(module, typeMask, limit, matches, &diaStoppedAtLimit, &diaError))
                {
                    foundThroughModule = true;
                    context.StoppedAtLimit = diaStoppedAtLimit;
                }
                else if (!diaError.empty())
                {
                    lastDetail = diaError;
                }
            }

            if (limit != 0 && matches->size() >= limit)
            {
                break;
            }
        }

        if (!matchedModule)
        {
            if (error != nullptr)
            {
                *error = L"No loaded module matched type pattern module: " + moduleFilter;
            }
            break;
        }

        if (!foundThroughModule && matches->empty())
        {
            if (error != nullptr)
            {
                *error = lastDetail.empty() ? DbgHelpErrorText(L"SymEnumTypesW failed", lastError) : lastDetail;
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool SymbolEngine::GetTypeLayoutWithDia(const std::wstring& typeName, uint64_t preferredModuleBase, TypeLayoutInfo* layout, std::wstring* error)
{
    bool ok = false;
    bool coInitialized = false;

    do
    {
        if (layout == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid DIA layout output";
            }
            break;
        }

        if (!ready_)
        {
            if (!Initialize(symbolPath_, error))
            {
                break;
            }
        }

        if (modules_.empty())
        {
            if (!LoadKernelModules(error))
            {
                break;
            }
        }

        std::wstring lookupTypeName = typeName;
        std::wstring moduleFilter;
        size_t bang = typeName.find(L'!');
        if (bang != std::wstring::npos)
        {
            moduleFilter = typeName.substr(0, bang);
            lookupTypeName = typeName.substr(bang + 1);
        }

        if (lookupTypeName.empty())
        {
            if (error != nullptr)
            {
                *error = L"Invalid DIA type name";
            }
            break;
        }

        HRESULT coHr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (SUCCEEDED(coHr))
        {
            coInitialized = true;
        }
        else if (coHr != RPC_E_CHANGED_MODE)
        {
            if (error != nullptr)
            {
                *error = HResultText(L"CoInitializeEx failed", coHr);
            }
            break;
        }

        std::wstring lastError;
        bool matchedModule = false;

        for (const KernelModuleInfo& module : modules_)
        {
            if (preferredModuleBase != 0 && module.Base != preferredModuleBase)
            {
                continue;
            }

            if (!moduleFilter.empty() && !ModuleNameMatches(module.ImageName, moduleFilter))
            {
                continue;
            }

            matchedModule = true;
            EnsureModuleLoaded(module, nullptr);

            IDiaDataSource* source = nullptr;
            IDiaSession* session = nullptr;
            IDiaSymbol* global = nullptr;
            IDiaEnumSymbols* udtEnum = nullptr;
            IDiaSymbol* udt = nullptr;

            std::wstring diaProvider;
            std::wstring diaCreateError;
            if (!CreateDiaDataSource(&source, &diaProvider, &diaCreateError))
            {
                lastError = diaCreateError;
                ReleaseCom(udt);
                ReleaseCom(udtEnum);
                ReleaseCom(global);
                ReleaseCom(session);
                ReleaseCom(source);
                continue;
            }

            std::wstring diaLoadError;
            if (!LoadDiaDataForModule(module, source, &diaLoadError))
            {
                lastError = diaLoadError;
                ReleaseCom(udt);
                ReleaseCom(udtEnum);
                ReleaseCom(global);
                ReleaseCom(session);
                ReleaseCom(source);
                continue;
            }

            HRESULT hr = source->openSession(&session);
            if (FAILED(hr))
            {
                lastError = HResultText(L"IDiaDataSource::openSession failed", hr);
                ReleaseCom(udt);
                ReleaseCom(udtEnum);
                ReleaseCom(global);
                ReleaseCom(session);
                ReleaseCom(source);
                continue;
            }

            session->put_loadAddress(module.Base);

            hr = session->get_globalScope(&global);
            if (FAILED(hr) || global == nullptr)
            {
                lastError = HResultText(L"IDiaSession::get_globalScope failed", hr);
                ReleaseCom(udt);
                ReleaseCom(udtEnum);
                ReleaseCom(global);
                ReleaseCom(session);
                ReleaseCom(source);
                continue;
            }

            hr = global->findChildren(SymTagUDT, nullptr, nsNone, &udtEnum);
            if (FAILED(hr) || udtEnum == nullptr)
            {
                lastError = HResultText(L"DIA findChildren UDT failed", hr);
                ReleaseCom(udt);
                ReleaseCom(udtEnum);
                ReleaseCom(global);
                ReleaseCom(session);
                ReleaseCom(source);
                continue;
            }

            while (true)
            {
                ULONG fetched = 0;
                hr = udtEnum->Next(1, &udt, &fetched);
                if (hr != S_OK || fetched != 1 || udt == nullptr)
                {
                    ReleaseCom(udt);
                    break;
                }

                std::wstring diaName = DiaSymbolName(udt);
                if (TypeNameMatchesNoCase(diaName, lookupTypeName))
                {
                    break;
                }

                ReleaseCom(udt);
            }

            if (udt == nullptr)
            {
                std::wstringstream stream;
                stream << L"DIA type not found: module=" << GetDbgHelpModuleName(module)
                       << L" type=" << lookupTypeName;
                std::wstring pdbPath = GetLoadedPdbPath(process_, module.Base);
                if (!pdbPath.empty())
                {
                    stream << L" pdb=" << pdbPath;
                }
                stream << L" image=" << ResolveModuleImagePath(module);
                lastError = stream.str();
                ReleaseCom(udtEnum);
                ReleaseCom(global);
                ReleaseCom(session);
                ReleaseCom(source);
                continue;
            }

            ULONG fetched = 0;
            TypeLayoutInfo local = {};
            local.Name = typeName;
            local.ModuleBase = module.Base;
            local.TypeId = 0;
            local.Size = 0;

            ULONGLONG typeLength = 0;
            if (SUCCEEDED(udt->get_length(&typeLength)))
            {
                local.Size = typeLength;
            }

            IDiaEnumSymbols* dataEnum = nullptr;
            hr = udt->findChildren(SymTagData, nullptr, nsNone, &dataEnum);
            if (SUCCEEDED(hr) && dataEnum != nullptr)
            {
                while (true)
                {
                    IDiaSymbol* data = nullptr;
                    fetched = 0;
                    hr = dataEnum->Next(1, &data, &fetched);
                    if (FAILED(hr) || fetched != 1 || data == nullptr)
                    {
                        ReleaseCom(data);
                        break;
                    }

                    TypeFieldInfo field = {};
                    field.ModuleBase = module.Base;
                    field.TypeId = 0;
                    field.ChildTypeId = 0;
                    field.Offset = 0;
                    field.Length = 0;
                    field.Tag = SymTagData;
                    field.ChildTag = 0;
                    field.BaseType = 0;
                    field.IsBitField = false;
                    field.BitPosition = 0;
                    field.Name = DiaSymbolName(data);

                    LONG offset = 0;
                    if (FAILED(data->get_offset(&offset)) || offset < 0 || field.Name.empty())
                    {
                        ReleaseCom(data);
                        continue;
                    }

                    field.Offset = static_cast<ULONG>(offset);

                    ULONGLONG dataLength = 0;
                    if (SUCCEEDED(data->get_length(&dataLength)))
                    {
                        field.Length = dataLength;
                    }

                    DWORD bitPosition = 0;
                    if (SUCCEEDED(data->get_bitPosition(&bitPosition)))
                    {
                        field.IsBitField = true;
                        field.BitPosition = bitPosition;
                    }

                    IDiaSymbol* dataType = nullptr;
                    if (SUCCEEDED(data->get_type(&dataType)) && dataType != nullptr)
                    {
                        DWORD childTag = 0;
                        dataType->get_symTag(&childTag);
                        field.ChildTag = childTag;
                        dataType->get_baseType(&field.BaseType);
                        if (field.Length == 0 || !field.IsBitField)
                        {
                            ULONGLONG childLength = 0;
                            if (SUCCEEDED(dataType->get_length(&childLength)))
                            {
                                field.Length = childLength;
                            }
                        }
                        field.TypeName = DiaDescribeType(dataType, 0);
                    }
                    ReleaseCom(dataType);

                    if (field.TypeName.empty())
                    {
                        field.TypeName = L"<unknown>";
                    }

                    local.Fields.push_back(field);
                    ReleaseCom(data);
                }
            }
            ReleaseCom(dataEnum);

            std::sort(
                local.Fields.begin(),
                local.Fields.end(),
                [](const TypeFieldInfo& left, const TypeFieldInfo& right)
                {
                    if (left.Offset != right.Offset)
                    {
                        return left.Offset < right.Offset;
                    }

                    return left.BitPosition < right.BitPosition;
                });

            *layout = local;
            ok = true;

            ReleaseCom(udt);
            ReleaseCom(udtEnum);
            ReleaseCom(global);
            ReleaseCom(session);
            ReleaseCom(source);
            break;
        }

        if (!ok && error != nullptr)
        {
            if (!matchedModule)
            {
                std::wstringstream stream;
                stream << L"DIA type lookup failed: no module matched";
                if (!moduleFilter.empty())
                {
                    stream << L" filter=" << moduleFilter;
                }
                if (preferredModuleBase != 0)
                {
                    stream << L" base=0x" << std::hex << preferredModuleBase;
                }
                *error = stream.str();
            }
            else
            {
                *error = lastError.empty() ? L"DIA type lookup failed" : lastError;
            }
        }
    } while (false);

    if (coInitialized)
    {
        CoUninitialize();
    }

    return ok;
}

bool SymbolEngine::GetTypeLayoutById(uint64_t moduleBase, ULONG typeId, const std::wstring& typeName, TypeLayoutInfo* layout, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (layout == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid type layout output";
            }
            break;
        }

        if (!ready_)
        {
            if (!Initialize(symbolPath_, error))
            {
                break;
            }
        }

        if (moduleBase == 0 || typeId == 0)
        {
            if (error != nullptr)
            {
                *error = L"Invalid type identity";
            }
            break;
        }

        layout->Name = typeName.empty() ? DescribeType(process_, moduleBase, typeId, 0) : typeName;
        layout->ModuleBase = moduleBase;
        layout->TypeId = typeId;
        layout->Size = 0;
        layout->Fields.clear();

        ULONG childrenCount = 0;
        if (!SymGetTypeInfo(process_, moduleBase, typeId, TI_GET_CHILDRENCOUNT, &childrenCount))
        {
            if (error != nullptr)
            {
                *error = DbgHelpErrorText(L"TI_GET_CHILDRENCOUNT failed", GetLastError());
            }
            break;
        }

        SymGetTypeInfo(process_, moduleBase, typeId, TI_GET_LENGTH, &layout->Size);

        if (childrenCount == 0)
        {
            ok = true;
            break;
        }

        size_t findChildrenSize = FIELD_OFFSET(TI_FINDCHILDREN_PARAMS, ChildId) + sizeof(ULONG) * childrenCount;
        std::vector<uint8_t> findChildrenBuffer(findChildrenSize);
        auto findChildren = reinterpret_cast<TI_FINDCHILDREN_PARAMS*>(findChildrenBuffer.data());
        findChildren->Count = childrenCount;
        findChildren->Start = 0;

        if (!SymGetTypeInfo(process_, moduleBase, typeId, TI_FINDCHILDREN, findChildren))
        {
            if (error != nullptr)
            {
                *error = DbgHelpErrorText(L"TI_FINDCHILDREN failed", GetLastError());
            }
            break;
        }

        layout->Fields.reserve(childrenCount);
        size_t skippedWithoutOffset = 0;

        for (ULONG index = 0; index < childrenCount; ++index)
        {
            ULONG childId = findChildren->ChildId[index];
            TypeFieldInfo field = {};
            field.ModuleBase = moduleBase;
            field.TypeId = childId;
            field.ChildTypeId = 0;
            field.Offset = 0;
            field.Length = 0;
            field.Tag = 0;
            field.ChildTag = 0;
            field.BaseType = 0;
            field.IsBitField = false;
            field.BitPosition = 0;

            // Only data members and base classes participate in layout offsets.
            // Nested types/functions without TI_GET_OFFSET used to be recorded
            // as Offset=0 and silently corrupt every scanner that trusted them.
            if (!SymGetTypeInfo(process_, moduleBase, childId, TI_GET_SYMTAG, &field.Tag))
            {
                ++skippedWithoutOffset;
                continue;
            }

            if (field.Tag != SymTagData && field.Tag != SymTagBaseClass)
            {
                continue;
            }

            WCHAR* rawName = nullptr;
            if (SymGetTypeInfo(process_, moduleBase, childId, TI_GET_SYMNAME, &rawName) && rawName != nullptr)
            {
                field.Name = rawName;
                LocalFree(rawName);
            }

            if (field.Name.empty())
            {
                continue;
            }

            if (!SymGetTypeInfo(process_, moduleBase, childId, TI_GET_OFFSET, &field.Offset))
            {
                // Do not invent Offset=0 for named members when DbgHelp fails.
                // A true first member may still be 0 only when OFFSET succeeds.
                ++skippedWithoutOffset;
                continue;
            }

            SymGetTypeInfo(process_, moduleBase, childId, TI_GET_LENGTH, &field.Length);

            if (SymGetTypeInfo(process_, moduleBase, childId, TI_GET_BITPOSITION, &field.BitPosition))
            {
                field.IsBitField = true;
            }

            if (SymGetTypeInfo(process_, moduleBase, childId, TI_GET_TYPEID, &field.ChildTypeId))
            {
                SymGetTypeInfo(process_, moduleBase, field.ChildTypeId, TI_GET_LENGTH, &field.Length);
                SymGetTypeInfo(process_, moduleBase, field.ChildTypeId, TI_GET_BASETYPE, &field.BaseType);
                SymGetTypeInfo(process_, moduleBase, field.ChildTypeId, TI_GET_SYMTAG, &field.ChildTag);
                field.TypeName = DescribeType(process_, moduleBase, field.ChildTypeId, 0);
            }

            if (field.TypeName.empty())
            {
                field.TypeName = L"<unknown>";
            }

            layout->Fields.push_back(field);
        }

        if (layout->Fields.empty() && childrenCount != 0 && skippedWithoutOffset != 0)
        {
            if (error != nullptr)
            {
                *error = L"type has children but no members with a valid TI_GET_OFFSET";
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool SymbolEngine::GetTypeLayout(const std::wstring& typeName, TypeLayoutInfo* layout, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (layout == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid type layout output";
            }
            break;
        }

        if (!ready_)
        {
            if (!Initialize(symbolPath_, error))
            {
                break;
            }
        }

        if (modules_.empty())
        {
            if (!LoadKernelModules(error))
            {
                break;
            }
        }

        ULONG typeId = 0;
        DWORD64 moduleBase = 0;
        std::vector<uint8_t> symbolBuffer(sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(wchar_t));
        PSYMBOL_INFOW symbol = reinterpret_cast<PSYMBOL_INFOW>(symbolBuffer.data());
        symbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
        symbol->MaxNameLen = MAX_SYM_NAME;

        std::wstring lookupTypeName = typeName;
        std::wstring moduleFilter;
        size_t bang = typeName.find(L'!');
        if (bang != std::wstring::npos)
        {
            moduleFilter = typeName.substr(0, bang);
            lookupTypeName = typeName.substr(bang + 1);
        }

        if (!moduleFilter.empty())
        {
            for (const KernelModuleInfo& module : modules_)
            {
                if (!ModuleNameMatches(module.ImageName, moduleFilter))
                {
                    continue;
                }

                EnsureModuleSymbolsLoaded(module, nullptr);

                RtlZeroMemory(symbolBuffer.data(), symbolBuffer.size());
                symbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
                symbol->MaxNameLen = MAX_SYM_NAME;

                if (SymGetTypeFromNameW(process_, module.Base, lookupTypeName.c_str(), symbol))
                {
                    typeId = symbol->TypeIndex;
                    moduleBase = symbol->ModBase != 0 ? symbol->ModBase : module.Base;
                    break;
                }
            }
        }

        if (typeId == 0)
        {
            std::vector<TypeMatchInfo> matches;
            std::wstring enumError;
            if (EnumerateTypes(typeName, 1, &matches, &enumError) && !matches.empty())
            {
                typeId = matches.front().TypeId;
                moduleBase = matches.front().ModuleBase;
            }
        }

        if (typeId == 0 && !SymGetTypeFromNameW(process_, 0, typeName.c_str(), symbol))
        {
            bool found = false;
            for (const KernelModuleInfo& module : modules_)
            {
                if (!moduleFilter.empty() && !ModuleNameMatches(module.ImageName, moduleFilter))
                {
                    continue;
                }

                EnsureModuleSymbolsLoaded(module, nullptr);

                RtlZeroMemory(symbolBuffer.data(), symbolBuffer.size());
                symbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
                symbol->MaxNameLen = MAX_SYM_NAME;

                if (SymGetTypeFromNameW(process_, module.Base, lookupTypeName.c_str(), symbol))
                {
                    typeId = symbol->TypeIndex;
                    moduleBase = symbol->ModBase != 0 ? symbol->ModBase : module.Base;
                    found = true;
                    break;
                }
            }

            if (!found)
            {
                std::wstring dbgHelpError = DbgHelpErrorText(L"SymGetTypeFromNameW failed", GetLastError());
                std::wstring diaError;
                if (GetTypeLayoutWithDia(typeName, 0, layout, &diaError))
                {
                    ok = true;
                    break;
                }

                if (error != nullptr)
                {
                    *error = dbgHelpError + L"; DIA fallback failed: " + diaError;
                }
                break;
            }
        }
        else
        {
            if (typeId == 0)
            {
                typeId = symbol->TypeIndex;
                moduleBase = symbol->ModBase;
            }
        }

        if (moduleBase == 0)
        {
            for (const KernelModuleInfo& module : modules_)
            {
                if (!moduleFilter.empty() && !ModuleNameMatches(module.ImageName, moduleFilter))
                {
                    continue;
                }

                EnsureModuleSymbolsLoaded(module, nullptr);

                RtlZeroMemory(symbolBuffer.data(), symbolBuffer.size());
                symbol->SizeOfStruct = sizeof(SYMBOL_INFOW);
                symbol->MaxNameLen = MAX_SYM_NAME;

                if (SymGetTypeFromNameW(process_, module.Base, lookupTypeName.c_str(), symbol))
                {
                    moduleBase = symbol->ModBase != 0 ? symbol->ModBase : module.Base;
                    typeId = symbol->TypeIndex;
                    break;
                }
            }
        }

        if (moduleBase == 0 && !modules_.empty())
        {
            moduleBase = modules_.front().Base;
        }

        if (!GetTypeLayoutById(moduleBase, typeId, typeName, layout, error))
        {
            std::wstring dbgHelpError = error != nullptr ? *error : L"DbgHelp type layout failed";
            std::wstring diaError;
            if (GetTypeLayoutWithDia(typeName, moduleBase, layout, &diaError))
            {
                ok = true;
                break;
            }

            if (error != nullptr)
            {
                *error = dbgHelpError + L"; DIA fallback failed: " + diaError;
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool SymbolEngine::GetTypeFields(const std::wstring& typeName, std::vector<TypeFieldInfo>* fields, ULONG64* typeSize, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (fields == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid field output";
            }
            break;
        }

        TypeLayoutInfo layout = {};
        if (!GetTypeLayout(typeName, &layout, error))
        {
            break;
        }

        *fields = layout.Fields;
        if (typeSize != nullptr)
        {
            *typeSize = layout.Size;
        }

        ok = true;
    } while (false);

    return ok;
}

bool SymbolEngine::FindField(const std::wstring& typeName, const std::wstring& fieldName, TypeFieldInfo* field, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (field == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Invalid field output";
            }
            break;
        }

        // Split the field name on '.' so callers can resolve nested paths such
        // as "Pcb.DirectoryTableBase" through embedded UDTs without manually
        // chasing each level. A single segment keeps the original flat-lookup
        // behavior. Pointer dereference paths are intentionally not supported;
        // this resolves field offsets within a structure for "<base> + Offset"
        // address math, so only embedded aggregate members are descended into.
        std::vector<std::wstring> segments;
        bool malformedPath = false;
        size_t pathStart = 0;
        while (pathStart <= fieldName.size())
        {
            size_t dot = fieldName.find(L'.', pathStart);
            std::wstring segment = (dot == std::wstring::npos)
                ? fieldName.substr(pathStart)
                : fieldName.substr(pathStart, dot - pathStart);
            if (segment.empty())
            {
                malformedPath = true;
                break;
            }
            segments.push_back(segment);
            if (dot == std::wstring::npos)
            {
                break;
            }
            pathStart = dot + 1;
        }

        if (malformedPath || segments.empty())
        {
            if (error != nullptr)
            {
                *error = L"Invalid field path";
            }
            break;
        }

        auto findInFields = [](const std::vector<TypeFieldInfo>& fields, const std::wstring& name) -> const TypeFieldInfo*
        {
            for (const TypeFieldInfo& candidate : fields)
            {
                if (_wcsicmp(candidate.Name.c_str(), name.c_str()) == 0)
                {
                    return &candidate;
                }
            }
            return nullptr;
        };

        // Resolve the first segment against the root type by name.
        std::vector<TypeFieldInfo> rootFields;
        if (!GetTypeFields(typeName, &rootFields, nullptr, error))
        {
            break;
        }

        const TypeFieldInfo* match = findInFields(rootFields, segments[0]);
        if (match == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"Field was not found";
            }
            break;
        }

        TypeFieldInfo current = *match;
        ULONG cumulativeOffset = current.Offset;
        bool pathOk = true;

        // Descend through each remaining segment by enumerating the embedded
        // aggregate type identified by the parent field's ChildTypeId.
        for (size_t i = 1; i < segments.size(); ++i)
        {
            if (current.ChildTypeId == 0 || current.ModuleBase == 0)
            {
                if (error != nullptr)
                {
                    *error = L"Field path segment is not an aggregate type";
                }
                pathOk = false;
                break;
            }

            TypeLayoutInfo childLayout = {};
            if (!GetTypeLayoutById(current.ModuleBase, current.ChildTypeId, current.TypeName, &childLayout, error))
            {
                pathOk = false;
                break;
            }

            const TypeFieldInfo* childMatch = findInFields(childLayout.Fields, segments[i]);
            if (childMatch == nullptr)
            {
                if (error != nullptr)
                {
                    *error = L"Field was not found";
                }
                pathOk = false;
                break;
            }

            current = *childMatch;
            cumulativeOffset += current.Offset;
        }

        if (!pathOk)
        {
            break;
        }

        // The leaf keeps its own type/length/bitfield metadata, but the offset
        // is reported relative to the root type so callers can use
        // <root-address> + field.Offset directly.
        *field = current;
        field->Offset = cumulativeOffset;
        ok = true;
    } while (false);

    return ok;
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
