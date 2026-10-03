#pragma once

#include "../user/KmonEvidencePolicy.h"
#include "../user/KmonImportResolver.h"
#include <iostream>

inline bool KmonFalsePositiveSelfTest()
{
    size_t passed = 0;
    size_t failed = 0;
    const auto check = [&](bool value, const char* name)
    {
        if (value)
        {
            ++passed;
        }
        else
        {
            ++failed;
            std::cout << "[kmon.fp] FAIL " << name << "\n";
        }
    };
    for (DWORD error : {ERROR_ACCESS_DENIED, ERROR_SHARING_VIOLATION, ERROR_BAD_NETPATH,
        ERROR_PARTIAL_COPY, ERROR_INVALID_PARAMETER, ERROR_SUCCESS})
    {
        check(!KmonFileQueryKnown(INVALID_FILE_ATTRIBUTES, error), "query failure is not file absence");
    }
    check(KmonFileQueryKnown(INVALID_FILE_ATTRIBUTES, ERROR_FILE_NOT_FOUND), "missing file retained");
    check(KmonFileQueryKnown(INVALID_FILE_ATTRIBUTES, ERROR_PATH_NOT_FOUND), "missing path retained");
    check(KmonFileQueryKnown(FILE_ATTRIBUTE_NORMAL, ERROR_ACCESS_DENIED), "successful query ignores stale error");
    KmonRepeatObservation repeat;
    check(repeat.Observe(L"objectA:bytesA", 100, 20) == 1, "first observation");
    check(repeat.Observe(L"objectB:bytesA", 101, 20) == 1, "new object resets confirmation");
    check(repeat.Observe(L"objectB:bytesB", 102, 20) == 1, "different bytes reset confirmation");
    check(repeat.Observe(L"objectB:bytesB", 103, 20) == 2, "stable positive confirms");
    check(repeat.Observe(L"", 104, 20) == 0, "unknown resets confirmation");
    check(repeat.Observe(L"objectB:bytesB", 105, 20) == 1, "read failure breaks consecutive observations");
    check(repeat.Observe(L"objectB:bytesB", 200, 20) == 1, "stale evidence resets confirmation");
    check(repeat.Observe(L"objectB:bytesB", 199, 20) == 1, "clock reversal resets confirmation");
    for (const wchar_t* kind : {L"driver.official_load", L"driver.official_unload", L"driver.drop_load",
        L"driver.device", L"driver.image_only", L"driver.handle", L"driver.ioctl", L"process.create",
        L"hook.window", L"loader.activity", L"mapper.watch", L"finding.layout_change", L"finding.code_modified"})
    {
        check(std::wstring(KmonEventCategory(kind)) == L"observation", "normal activity remains observation");
    }
    check(std::wstring(KmonEventCategory(L"process.implant")) == L"lead", "heuristic stays reviewable");
    check(std::wstring(KmonEventCategory(L"future.detector")) == L"lead", "unknown kind does not assert a verdict");
    check(std::wstring(KmonEventCategory(L"coverage.image")) == L"coverage", "coverage remains coverage");
    check(std::wstring(KmonEventCategory(L"sensor.image_name")) == L"sensor", "failure remains sensor state");
    check(std::wstring(KmonEventCategory(L"gap.kernel_rw")) == L"coverage", "missing telemetry remains coverage");

    std::vector<uint8_t> exporter(4096, 0);
    IMAGE_EXPORT_DIRECTORY directory = {};
    directory.Base = 7;
    directory.NumberOfFunctions = 1;
    directory.NumberOfNames = 1;
    directory.AddressOfFunctions = 0x180;
    directory.AddressOfNames = 0x190;
    directory.AddressOfNameOrdinals = 0x1A0;
    std::memcpy(exporter.data() + 0x100, &directory, sizeof(directory));
    uint32_t entry = 0x220;
    uint32_t name = 0x200;
    std::memcpy(exporter.data() + 0x180, &entry, 4);
    std::memcpy(exporter.data() + 0x190, &name, 4);
    std::memcpy(exporter.data() + 0x200, "Routine", 8);
    std::memcpy(exporter.data() + 0x220, "bar.#7", 7);
    std::vector<uint8_t> owner = exporter;
    entry = 0x400;
    std::memcpy(owner.data() + 0x180, &entry, 4);
    const auto reader = [](const std::vector<uint8_t>& image)
    {
        return KmonRvaReader([&image](uint32_t rva, uint32_t size, std::vector<uint8_t>* bytes)
        {
            if (rva >= image.size() || size > image.size() - rva)
            {
                return false;
            }
            bytes->assign(image.begin() + rva, image.begin() + rva + size);
            return true;
        });
    };
    const KmonExportLookup lookup = [&](const std::wstring& module, const KmonImportSymbol& symbol,
        uint64_t* address, std::string* forwarder)
    {
        if (module != L"foo.dll" && module != L"bar.dll")
        {
            return false;
        }
        uint32_t rva = 0;
        const bool success = KmonReadExport(reader(module == L"foo.dll" ? exporter : owner), 4096,
            0x100, 0x200, symbol, &rva, forwarder);
        *address = rva == 0 ? 0 : 0x10000000ull + rva;
        return success;
    };
    KmonImportSymbol symbol;
    symbol.Name = "Routine";
    uint64_t target = 0;
    check(KmonResolveImportTarget(L"Foo", symbol, lookup, &target) && target == 0x10000400,
        "non-inbox forwarder by ordinal resolves exactly");
    symbol.Name = "DifferentRoutine";
    check(!KmonResolveImportTarget(L"Foo", symbol, lookup, &target) && target == 0,
        "unrelated forwarder does not hide changed target");
    symbol = {};
    symbol.ByOrdinal = true;
    symbol.Ordinal = 7;
    check(KmonResolveImportTarget(L"foo.dll", symbol, lookup, &target) && target != 0x10000410,
        "different function address is not a matching forwarder");
    symbol.Ordinal = 6;
    check(!KmonResolveImportTarget(L"foo.dll", symbol, lookup, &target), "ordinal underflow rejected");
    symbol.Ordinal = 8;
    check(!KmonResolveImportTarget(L"foo.dll", symbol, lookup, &target), "ordinal overflow rejected");
    symbol.Ordinal = 7;
    std::memcpy(exporter.data() + 0x220, "foo.#7", 7);
    check(!KmonResolveImportTarget(L"foo.dll", symbol, lookup, &target), "forwarder cycle remains unknown");
    for (const char* invalid : {"bar.#65536", "bar.#-1", "bar.#", "bar", ".Routine", "bar."})
    {
        std::memset(exporter.data() + 0x220, 0, 256);
        std::memcpy(exporter.data() + 0x220, invalid, std::strlen(invalid));
        check(!KmonResolveImportTarget(L"foo.dll", symbol, lookup, &target), "malformed forwarder remains unknown");
    }
    std::memset(exporter.data() + 0x220, 'a', 256);
    check(!KmonResolveImportTarget(L"foo.dll", symbol, lookup, &target), "unterminated forwarder rejected");
    entry = UINT32_MAX;
    std::memcpy(exporter.data() + 0x180, &entry, 4);
    check(!KmonResolveImportTarget(L"foo.dll", symbol, lookup, &target), "out-of-image export rejected");
    std::cout << "[kmon.fp] passed=" << passed << " failed=" << failed << "\n";
    return failed == 0;
}
