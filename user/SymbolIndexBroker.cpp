#include "SymbolIndexBroker.h"
#include "SchemaArtifact.h"
#include "SymbolArtifactResolver.h"
#include "ExecutableImage.h"
#include "ParserWorkerProcess.h"
#include <filesystem>

bool AcceptSymbolIndexWorkerOutput(const std::string& output, const SymbolIndex& expected, SymbolIndex* index)
{
    if (index == nullptr) { return false; }
    *index = {};
    SymbolIndex result;
    if (!DecodeSymbolIndex(output, &result) || result.ImageSha256 != expected.ImageSha256 || result.PdbSha256 != expected.PdbSha256 ||
        result.ProviderSha256 != expected.ProviderSha256 || result.PdbGuid != expected.PdbGuid || result.PdbAge != expected.PdbAge ||
        result.ImageSize != expected.ImageSize || result.Machine != expected.Machine) { return false; }
    *index = std::move(result); return true;
}
bool GenerateBrokeredSymbolIndex(const std::wstring& executable, const std::wstring& image, const std::wstring& pdb,
    SymbolIndex* index, std::wstring* error, uint64_t timeoutMs)
{
    if (error != nullptr) { *error = L"symbol index requires approved local artifacts and the installed parser runtime"; }
    if (index == nullptr) { return false; }
    *index = {};
    if (executable.empty() || executable.size() > 30000 || executable.find(L'\0') != std::wstring::npos ||
        !std::filesystem::path(executable).is_absolute() || timeoutMs == 0 || timeoutMs > 60000) { return false; }
    SchemaArtifact imageFile, pdbFile, providerFile;
    const auto provider = std::filesystem::path(executable).parent_path() / L"msdia140.dll";
    if (!imageFile.Open(image, 512ull * 1024 * 1024) || !pdbFile.Open(pdb, 1024ull * 1024 * 1024) ||
        !providerFile.Open(provider.wstring(), 64ull * 1024 * 1024) || !providerFile.PinPath()) { return false; }
    executable_image::DiskPeMetadata metadata;
    if (!executable_image::ReadDiskPeIdentityHandle(imageFile.Handle(), &metadata, nullptr) || !metadata.HasPdbIdentity ||
        metadata.Machine != IMAGE_FILE_MACHINE_AMD64) { return false; }
    SymbolIndex expected;
    expected.ImageSha256 = imageFile.Sha256; expected.PdbSha256 = pdbFile.Sha256; expected.ProviderSha256 = providerFile.Sha256;
    wchar_t guid[33]{}; const auto& g = metadata.PdbGuid;
    swprintf_s(guid, L"%08lx%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x", g.Data1, g.Data2, g.Data3,
        g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3], g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7]);
    expected.PdbGuid = guid; expected.PdbAge = metadata.PdbAge; expected.ImageSize = metadata.SizeOfImage; expected.Machine = metadata.Machine;
    ParserWorkerRequest request;
    request.Executable = executable; request.Arguments = {L"--symbol-index-worker"}; request.TimeoutMs = timeoutMs;
    request.OutputLimit = SymbolIndexMaxBytes; request.ReadOnlyFiles = {imageFile.Handle(), pdbFile.Handle(), providerFile.Handle()};
    request.ProviderFileIndex = 2;
    const auto worker = RunParserWorker(request);
    if (worker.Status != L"exited")
    {
        if (error != nullptr) { *error = L"symbol worker " + worker.Status + L"; error=" + std::to_wstring(worker.Error) +
            L"; exit=" + std::to_wstring(worker.ExitCode) + L"; profile_hresult=" + std::to_wstring(static_cast<uint32_t>(worker.ProfileError)); }
        return false;
    }
    SymbolIndex result;
    if (!AcceptSymbolIndexWorkerOutput(worker.Output, expected, &result) || !imageFile.Unchanged() || !pdbFile.Unchanged() || !providerFile.Unchanged())
    { if (error != nullptr) { *error = L"symbol worker output failed bounded artifact verification"; } return false; }
    *index = std::move(result);
    if (error != nullptr) { error->clear(); }
    return true;
}
bool ResolveBrokeredSymbolIndex(const std::wstring& executable, const std::wstring& image, uint32_t expectedImageSize,
    const std::wstring& symbolPath, SymbolIndex* index, std::wstring* error, uint64_t timeoutMs)
{
    if (index == nullptr) { return false; }
    *index = {};
    SymbolIndex result;
    const auto consume = [&](const std::wstring& approvedImage, const std::wstring& pdb, uint64_t timeout,
        AcceptedSymbolArtifacts* accepted, std::wstring* issue)
    {
        if (!GenerateBrokeredSymbolIndex(executable, approvedImage, pdb, &result, issue, timeout)) { return false; }
        *accepted = {result.ImageSha256, result.PdbSha256}; return true;
    };
    if (!ResolveSymbolArtifacts(executable, image, expectedImageSize, symbolPath, consume, error, timeoutMs)) { return false; }
    *index = std::move(result); return true;
}
