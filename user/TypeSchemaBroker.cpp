#include "TypeSchemaBroker.h"
#include "ExecutableImage.h"
#include "McpJson.h"
#include "ParserWorkerProcess.h"
#include "SchemaArtifact.h"
#include <filesystem>

namespace
{
    std::wstring GuidText(const GUID& guid)
    {
        wchar_t text[33]{};
        swprintf_s(text, L"%08lx%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x", guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
        return text;
    }
}

bool AcceptTypeSchemaWorkerOutput(const std::string& output, const TypeSchemaBinding& expected,
    TypeSchemaPackage* package, std::wstring* error)
{
    if (error != nullptr) { *error = L"schema worker output does not match the brokered artifacts"; }
    if (package == nullptr) { return false; }
    *package = {};
    if (output.empty() || output.size() > TypeSchemaMaxBytes) { return false; }
    const auto json = mcpjson::Utf8ToWide(output);
    TypeSchemaPackage parsed;
    if (mcpjson::WideToUtf8(json) != output || !ParseTypeSchema(json, &parsed, nullptr) || !parsed.ParserIsolated ||
        parsed.ImageSha256 != expected.ImageSha256 || parsed.PdbSha256 != expected.PdbSha256 ||
        parsed.ProviderSha256 != expected.ProviderSha256 || parsed.PdbGuid != expected.PdbGuid ||
        parsed.PdbAge != expected.PdbAge || parsed.Machine != expected.Machine || parsed.ImageSize != expected.ImageSize ||
        (parsed.TypeName != expected.TypeName && (!expected.AllowTypeAliases ||
            NormalizeSchemaTypeAlias(expected.TypeName).empty() ||
            NormalizeSchemaTypeAlias(parsed.TypeName) != NormalizeSchemaTypeAlias(expected.TypeName))))
    {
        return false;
    }
    *package = std::move(parsed);
    if (error != nullptr) { error->clear(); }
    return true;
}

bool GenerateBrokeredTypeSchema(const std::wstring& executable, const std::wstring& image,
    const std::wstring& pdb, const std::wstring& typeName, TypeSchemaPackage* package, std::wstring* error,
    uint64_t workerTimeoutMs, const std::atomic<bool>* cancellation, bool allowTypeAliases)
{
    if (error != nullptr) { *error = L"schema broker requires stable local artifacts and the installed parser runtime"; }
    if (package == nullptr) { return false; }
    *package = {};
    const auto cancelled = [&]() { return cancellation != nullptr && cancellation->load(); };
    if (executable.empty() || executable.size() > 30000 || executable.find(L'\0') != std::wstring::npos ||
        !std::filesystem::path(executable).is_absolute() || typeName.empty() || typeName.size() > 1024 ||
        typeName.find(L'\0') != std::wstring::npos || mcpjson::SanitizeUtf16(typeName) != typeName ||
        workerTimeoutMs == 0 || workerTimeoutMs > 60000 || cancelled()) { return false; }
    SchemaArtifact imageFile, pdbFile, providerFile;
    const auto provider = std::filesystem::path(executable).parent_path() / L"msdia140.dll";
    if (!imageFile.Open(image, 512ull * 1024 * 1024) || cancelled() ||
        !pdbFile.Open(pdb, 1024ull * 1024 * 1024) || cancelled() ||
        !providerFile.Open(provider.wstring(), 64ull * 1024 * 1024) || !providerFile.PinPath() || cancelled()) { return false; }
    executable_image::DiskPeMetadata metadata;
    if (!executable_image::ReadDiskPeIdentityHandle(imageFile.Handle(), &metadata, nullptr) ||
        !metadata.HasPdbIdentity || metadata.Machine != IMAGE_FILE_MACHINE_AMD64) { return false; }
    TypeSchemaBinding binding{imageFile.Sha256, pdbFile.Sha256, providerFile.Sha256, GuidText(metadata.PdbGuid),
        metadata.PdbAge, metadata.Machine, metadata.SizeOfImage, typeName};
    binding.AllowTypeAliases = allowTypeAliases;
    ParserWorkerRequest request;
    request.Executable = executable;
    request.Arguments = {allowTypeAliases ? L"--schema-live-worker" : L"--schema-worker", typeName};
    request.ReadOnlyFiles = {imageFile.Handle(), pdbFile.Handle(), providerFile.Handle()};
    request.TimeoutMs = workerTimeoutMs;
    request.Cancellation = cancellation;
    const auto worker = RunParserWorker(request);
    if (worker.Status != L"exited")
    {
        if (error != nullptr)
        {
            *error = L"schema worker " + worker.Status + L"; error=" + std::to_wstring(worker.Error) +
                L"; exit=" + std::to_wstring(worker.ExitCode);
        }
        return false;
    }
    TypeSchemaPackage accepted;
    if (cancelled() || !AcceptTypeSchemaWorkerOutput(worker.Output, binding, &accepted, error) ||
        !imageFile.Unchanged() || !pdbFile.Unchanged() || !providerFile.Unchanged() || cancelled())
    {
        if (error != nullptr && error->empty()) { *error = L"schema broker artifact verification did not complete"; }
        return false;
    }
    *package = std::move(accepted);
    if (error != nullptr) { error->clear(); }
    return true;
}
