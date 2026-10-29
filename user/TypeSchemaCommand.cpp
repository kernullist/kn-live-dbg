#include "TypeSchema.h"
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
    if (argc != 5 || !IsRestrictedParserWorker())
    {
        return 3;
    }
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
    try
    {
        const auto executable = ExecutablePath();
        if (executable.empty())
        {
            return 4;
        }
        const auto provider = std::filesystem::path(executable).parent_path() / L"msdia140.dll";
        TypeSchemaPackage package;
        if (!GenerateTypeSchema(argv[2], argv[3], argv[4], provider.wstring(), &package, nullptr))
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
            ParserWorkerRequest request;
            request.Executable = ExecutablePath();
            request.Arguments = {L"--schema-worker", std::filesystem::absolute(argv[3]).wstring(),
                std::filesystem::absolute(argv[4]).wstring(), argv[5]};
            const auto worker = RunParserWorker(request);
            if (worker.Status == L"exited")
            {
                const auto json = mcpjson::Utf8ToWide(worker.Output);
                success = mcpjson::WideToUtf8(json) == worker.Output && ParseTypeSchema(json, &package, &error) &&
                    package.ParserIsolated && package.TypeName == argv[5] && SaveTypeSchema(argv[6], package, &error);
            }
            else
            {
                error = L"schema worker " + worker.Status + L"; error=" + std::to_wstring(worker.Error) +
                    L"; exit=" + std::to_wstring(worker.ExitCode);
            }
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
