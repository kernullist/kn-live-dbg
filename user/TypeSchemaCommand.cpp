#include "TypeSchema.h"
#include "TypeSchemaBroker.h"
#include "ParserWorkerProcess.h"
#include "McpJson.h"
#include <filesystem>
#include <iostream>

namespace
{
    std::wstring ExecutablePath()
    {
        std::vector<wchar_t> path(32768);
        const auto length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
        return length != 0 && length < path.size() ? std::wstring(path.data(), length) : L"";
    }
}

int RunTypeSchemaWorkerCommand(int argc, wchar_t** argv)
{
    if (argc != 6 || !IsRestrictedParserWorker())
    {
        return 3;
    }
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    try
    {
        HANDLE files[3]{};
        for (size_t i = 0; i < std::size(files); ++i)
        {
            const std::wstring text = argv[3 + i];
            if (text.empty() || text.size() > 20 || text.find_first_not_of(L"0123456789") != std::wstring::npos)
            {
                return 4;
            }
            uint64_t value = 0;
            for (const auto c : text)
            {
                if (value > (UINTPTR_MAX - (c - L'0')) / 10) { return 4; }
                value = value * 10 + (c - L'0');
            }
            if (value == 0 || value == UINTPTR_MAX) { return 4; }
            files[i] = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(value));
        }
        TypeSchemaPackage package;
        if (!GenerateTypeSchemaFromHandles(files[0], files[1], files[2], argv[2], &package, nullptr,
            _wcsicmp(argv[1], L"--schema-live-worker") == 0))
        {
            return 5;
        }
        package.ParserIsolated = true;
        const auto output = mcpjson::WideToUtf8(TypeSchemaJson(package));
        if (output.empty() || output.size() > TypeSchemaMaxBytes)
        {
            return 6;
        }
        size_t offset = 0;
        while (offset < output.size())
        {
            DWORD written = 0;
            if (!WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), output.data() + offset,
                static_cast<DWORD>(output.size() - offset), &written, nullptr) || written == 0)
            {
                return 7;
            }
            offset += written;
        }
        return 0;
    }
    catch (const std::exception&)
    {
        return 8;
    }
}

int RunTypeSchemaCommand(int argc, wchar_t** argv)
{
    TypeSchemaPackage package;
    std::wstring error;
    bool success = false;
    try
    {
        if (argc == 7 && std::wstring(argv[2]) == L"create")
        {
            success = GenerateBrokeredTypeSchema(ExecutablePath(), argv[3], argv[4], argv[5], &package, &error) &&
                SaveTypeSchema(argv[6], package, &error);
        }
        else if (argc == 4 && std::wstring(argv[2]) == L"inspect")
        {
            success = LoadTypeSchema(argv[3], &package, &error);
        }
        else
        {
            error = L"usage: --schema create <image> <pdb> <exact-type> <new-output> | --schema inspect <package>";
        }
    }
    catch (const std::exception&)
    {
        error = L"schema operation failed while materializing bounded metadata";
    }
    if (!success)
    {
        std::wcerr << (error.empty() ? L"schema operation failed" : error) << L"\n";
        return 1;
    }
    std::wcout << TypeSchemaJson(package) << L"\n";
    return 0;
}
