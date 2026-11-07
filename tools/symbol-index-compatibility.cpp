// Separate compatibility oracle for compiler-owned fixtures only. The product
// never calls this provider path or loads this test executable as a fallback.
#include <Windows.h>
#include <DbgHelp.h>
#include <cstdio>
#include <string>
#pragma comment(lib, "dbghelp.lib")

struct Context { HANDLE Process; DWORD64 Base; size_t Count = 0; bool Valid = true; };
BOOL CALLBACK Type(PSYMBOL_INFOW symbol, ULONG, void* raw)
{
    auto& context = *static_cast<Context*>(raw);
    // The tested DbgHelp provider includes the terminator in NameLen. Preserve
    // the legacy API's terminated name, with an explicit scan bound.
    const auto length = symbol == nullptr ? 0 : wcsnlen_s(symbol->Name, 1025);
    if (length == 0 || length > 1024 || context.Count == 200000)
    {
        std::fprintf(stderr, "invalid type row: name_length=%lu count=%zu\n", symbol == nullptr ? 0ul : symbol->NameLen, context.Count);
        context.Valid = false; return FALSE;
    }
    const std::wstring name(symbol->Name, length);
    for (const auto c : name)
    { if (c < 32 || (c >= 127 && c <= 159)) { context.Valid = false; return FALSE; } }
    char utf8[4097]{};
    const auto bytes = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name.data(), static_cast<int>(name.size()),
        utf8, sizeof(utf8) - 1, nullptr, nullptr);
    if (bytes == 0) { context.Valid = false; return FALSE; }
    ULONG64 size = 0;
    const bool known = SymGetTypeInfo(context.Process, context.Base, symbol->TypeIndex, TI_GET_LENGTH, &size) != FALSE;
    std::printf("type\t%lu\t%u\t%llu\t%s\n", symbol->Tag, known ? 1u : 0u, size, utf8);
    ++context.Count; return TRUE;
}
int wmain(int argc, wchar_t** argv)
{
    if (argc != 3) { return 2; }
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    SymSetOptions(SYMOPT_EXACT_SYMBOLS | SYMOPT_NO_PROMPTS | SYMOPT_UNDNAME | SYMOPT_IGNORE_NT_SYMPATH |
        SYMOPT_DISABLE_SYMSRV_AUTODETECT);
    const auto process = GetCurrentProcess();
    if (!SymInitializeW(process, argv[2], FALSE)) { return 3; }
    const auto base = SymLoadModuleExW(process, nullptr, argv[1], nullptr, 0x180000000ull, 0, nullptr, 0);
    if (base == 0) { SymCleanup(process); return 4; }
    Context context{process, base};
    const bool ok = SymEnumTypesW(process, base, Type, &context) != FALSE && context.Valid;
    if (!ok) { std::fprintf(stderr, "type enumeration failed: error=%lu rows=%zu\n", GetLastError(), context.Count); }
    SymCleanup(process);
    if (ok) { std::printf("complete\t%zu\n", context.Count); }
    return ok ? 0 : 5;
}
