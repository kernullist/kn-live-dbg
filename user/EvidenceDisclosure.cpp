#include "EvidenceDisclosure.h"
#include "EvidencePrivacy.h"
#include "ImageVerificationRecipe.h"
#include "AnalystSnapshot.h"
#include "BoundedObservationJson.h"
#include "ContentHash.h"
#include <algorithm>
#include <filesystem>

namespace fs = std::filesystem;
using namespace bounded_observation_json;
namespace
{
    using Handle = std::unique_ptr<void, decltype(&CloseHandle)>;
    Handle Own(HANDLE h) { return {h == INVALID_HANDLE_VALUE ? nullptr : h, &CloseHandle}; }
    std::wstring Native(const fs::path& p) { auto path = p; path.make_preferred(); return L"\\\\?\\" + path.wstring(); }
    std::wstring Field(const std::wstring& json, const wchar_t* key)
    {
        std::wstring value; mcpjson::GetString(json, key, &value); return value;
    }
    bool Hex(const std::wstring& text, size_t length)
    {
        return text.size() == length && text.find_first_not_of(L"0123456789abcdef") == std::wstring::npos;
    }
    std::wstring Lower(std::wstring text)
    {
        for (auto& c : text) { if (c >= L'A' && c <= L'Z') { c += L'a' - L'A'; } } return text;
    }
    Handle Read(const fs::path& path, size_t maximum, std::wstring* text, std::wstring* digest)
    {
        auto file = Own(CreateFileW(Native(path).c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr));
        BY_HANDLE_FILE_INFORMATION info{}; LARGE_INTEGER size{};
        if (!file || GetFileType(file.get()) != FILE_TYPE_DISK || !GetFileInformationByHandle(file.get(), &info) ||
            (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0 || info.nNumberOfLinks != 1 ||
            !GetFileSizeEx(file.get(), &size) || size.QuadPart <= 0 || static_cast<uint64_t>(size.QuadPart) > maximum) { return Own(INVALID_HANDLE_VALUE); }
        std::vector<uint8_t> bytes(static_cast<size_t>(size.QuadPart)); DWORD read = 0;
        if (!ReadFile(file.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) || read != bytes.size()) { return Own(INVALID_HANDLE_VALUE); }
        const std::string utf8(bytes.begin(), bytes.end()); *text = mcpjson::Utf8ToWide(utf8); *digest = ContentHash::Bytes(bytes);
        if (digest->empty() || mcpjson::WideToUtf8(*text) != utf8 || !mcpjson::ValidateDocument(*text)) { return Own(INVALID_HANDLE_VALUE); }
        return file;
    }
    struct Manifest
    {
        std::wstring Id, RootIdentity, Principal, SourcePath, SourceSchema, SourceFileSha, SourceSemanticSha, ProofSha, FactsSha;
        uint64_t Created = 0;
    };
    std::wstring Json(const Manifest& m)
    {
        if (!Hex(m.Id, 32) || !Hex(m.SourceFileSha, 64) || !Hex(m.SourceSemanticSha, 64) || !Hex(m.ProofSha, 64) || !Hex(m.FactsSha, 64) ||
            !Text(m.RootIdentity, 160) || !Text(m.Principal, 256) || !Text(m.SourcePath, 30000) || m.Created == 0 ||
            (m.SourceSchema != L"kn.image_recipe.v1" && m.SourceSchema != L"kn.image_recipe.v2" && m.SourceSchema != L"kn.image_slice.v1" &&
                m.SourceSchema != L"kn.image_slice.v2" && m.SourceSchema != L"kn.image_sweep.v1")) { return L""; }
        return L"{\"schema\":\"kn.redaction_manifest.v1\",\"policy\":\"kn.image_counts_redaction.v1\",\"redaction_id\":" + mcpjson::Quote(m.Id) +
            L",\"root_identity\":" + mcpjson::Quote(m.RootIdentity) + L",\"principal\":" + mcpjson::Quote(m.Principal) +
            L",\"source_path\":" + mcpjson::Quote(m.SourcePath) + L",\"source_schema\":" + mcpjson::Quote(m.SourceSchema) +
            L",\"source_file_sha256\":" + mcpjson::Quote(m.SourceFileSha) + L",\"source_semantic_sha256\":" + mcpjson::Quote(m.SourceSemanticSha) +
            L",\"replay_proof_sha256\":" + mcpjson::Quote(m.ProofSha) + L",\"facts_file\":\"facts.knshare\",\"facts_sha256\":" + mcpjson::Quote(m.FactsSha) +
            L",\"created_filetime\":" + N(m.Created) + L",\"collector_authenticated\":false,\"transfer_authorized\":false,\"originals_modified\":false}";
    }
    bool Parse(const std::wstring& json, Manifest* out)
    {
        Manifest m;
        m.Id = Field(json, L"redaction_id"); m.RootIdentity = Field(json, L"root_identity"); m.Principal = Field(json, L"principal");
        m.SourcePath = Field(json, L"source_path"); m.SourceSchema = Field(json, L"source_schema");
        m.SourceFileSha = Field(json, L"source_file_sha256"); m.SourceSemanticSha = Field(json, L"source_semantic_sha256");
        m.ProofSha = Field(json, L"replay_proof_sha256"); m.FactsSha = Field(json, L"facts_sha256");
        if (!Number(json, L"created_filetime", &m.Created) || Json(m) != json) { return false; }
        *out = std::move(m); return true;
    }
}
class EvidenceDisclosureLease
{
public:
    EvidencePrivacyGuard Privacy;
    Handle FactsFile{nullptr, &CloseHandle}, ManifestFile{nullptr, &CloseHandle};
    std::wstring Root, FactsSha, ManifestSha, Id;
};

EvidenceDisclosurePackage LoadEvidenceDisclosure(const std::wstring& root)
{
    EvidenceDisclosurePackage result;
    const auto fail = [&](const wchar_t* issue) { result.Status = L"denied"; result.Issue = issue; result.Lease.reset(); return result; };
    try
    {
        auto lease = std::make_shared<EvidenceDisclosureLease>(); EvidencePrivacyReport privacy;
        if (!lease->Privacy.Open(root, true, &privacy)) { return fail(L"disclosure_requires_valid_private_root"); }
        result.Root = privacy.RootPath;
        lease->FactsFile = Read(fs::path(result.Root) / L"facts.knshare", 4096, &result.Facts, &result.FactsSha256);
        lease->ManifestFile = Read(fs::path(result.Root) / L"redaction.knredact", 256 * 1024, &result.Manifest, &result.ManifestSha256);
        MinimizedImageFacts facts; Manifest manifest;
        if (!lease->FactsFile || !lease->ManifestFile || !lease->Privacy.CheckFile(lease->FactsFile.get()) ||
            !lease->Privacy.CheckFile(lease->ManifestFile.get()) || !ParseMinimizedImageFacts(result.Facts, &facts) || !Parse(result.Manifest, &manifest) ||
            manifest.Id != facts.Id || manifest.FactsSha != result.FactsSha256 || manifest.RootIdentity != privacy.RootIdentity || manifest.Principal != privacy.OwnerSid)
        {
            return fail(L"disclosure_missing_corrupt_or_unbound");
        }
        result.Id = facts.Id; result.Status = L"ready";
        lease->Root = result.Root; lease->Id = result.Id; lease->FactsSha = result.FactsSha256; lease->ManifestSha = result.ManifestSha256;
        result.Lease = std::move(lease);
    }
    catch (...) { return fail(L"disclosure_inspection_exception"); }
    return result;
}

EvidenceDisclosurePackage PrepareImageDisclosure(const std::wstring& source, const std::wstring& newRoot,
    bool efs, const std::function<void(const wchar_t*)>& observer)
{
    EvidenceDisclosurePackage result;
    const auto fail = [&](const wchar_t* issue) { result.Status = L"denied"; result.Issue = issue; return result; };
    try
    {
        if (!Text(source, 30000)) { return fail(L"invalid_disclosure_source"); }
        const auto input = fs::absolute(source).lexically_normal();
        auto original = input, replayInput = input;
        const auto extension = Lower(input.extension().wstring());
        if (extension != L".knslice" && extension != L".knsweep")
        {
            if (Lower(input.filename().wstring()) == L"recipe.knverify") { replayInput = input.parent_path(); }
            else { original /= L"recipe.knverify"; }
        }
        std::wstring originalJson, originalHash;
        auto originalFile = Read(original, ImageRecipeMaxBytes, &originalJson, &originalHash);
        if (!originalFile) { return fail(L"disclosure_original_unavailable"); }
        const auto replay = ReplayImageRecipe(replayInput.wstring(), false, nullptr);
        const auto semanticHash = Field(originalJson, extension == L".knsweep" ? L"manifest_sha256" : L"recipe_sha256");
        if (!Hex(semanticHash, 64) || semanticHash != (extension == L".knsweep" ? replay.ManifestSha256 : replay.RecipeSha256))
            { return fail(L"disclosure_original_replay_binding_failed"); }
        MinimizedImageFacts facts;
        if (!ProjectImageDisclosure(replay, NewDisclosureId(), &facts)) { return fail(L"disclosure_original_policy_replay_failed"); }
        result.Facts = MinimizedImageFactsJson(facts); result.FactsSha256 = DisclosureTextSha256(result.Facts); result.Id = facts.Id;
        if (observer) { observer(L"disclosure_replayed"); }
        const auto initialized = InitializeEvidencePrivateStore(newRoot, efs);
        result.Root = initialized.RootPath; result.TemporaryDirectory = initialized.TemporaryDirectory;
        if (initialized.Status != L"ready") { result.Issue = initialized.Issue; return result; }
        EvidencePrivacyGuard guard; EvidencePrivacyReport privacy;
        if (!guard.Open(result.Root, true, &privacy)) { return fail(L"disclosure_private_root_admission_failed"); }
        FILETIME now{}; GetSystemTimeAsFileTime(&now);
        Manifest manifest;
        manifest.Id = facts.Id; manifest.RootIdentity = privacy.RootIdentity; manifest.Principal = privacy.OwnerSid;
        manifest.SourcePath = original.wstring(); manifest.SourceSchema = Field(originalJson, L"schema");
        manifest.SourceFileSha = originalHash; manifest.SourceSemanticSha = semanticHash;
        manifest.ProofSha = DisclosureTextSha256(replay.Proof); manifest.FactsSha = result.FactsSha256;
        manifest.Created = (uint64_t(now.dwHighDateTime) << 32) | now.dwLowDateTime;
        result.Manifest = Json(manifest); result.ManifestSha256 = DisclosureTextSha256(result.Manifest);
        if (result.Manifest.empty() || result.ManifestSha256.empty() || result.FactsSha256.empty()) { return fail(L"disclosure_manifest_invalid"); }
        if (!SaveObservationJson(Native(fs::path(result.Root) / L"facts.knshare"), result.Facts, nullptr)) { return fail(L"disclosure_facts_publication_failed"); }
        if (observer) { observer(L"disclosure_facts_committed"); }
        if (!SaveObservationJson(Native(fs::path(result.Root) / L"redaction.knredact"), result.Manifest, nullptr)) { return fail(L"disclosure_manifest_publication_failed"); }
        if (observer) { observer(L"disclosure_manifest_committed"); }
        return LoadEvidenceDisclosure(result.Root);
    }
    catch (...) { return fail(L"disclosure_preparation_exception"); }
}

bool SaveDisclosureTransferRecord(const EvidenceDisclosurePackage& package, const std::wstring& id,
    bool outcome, const std::wstring& json, std::wstring* error)
{
    const auto fail = [&](const wchar_t* issue) { if (error) { *error = issue; } return false; };
    try
    {
        const auto& lease = package.Lease;
        if (!lease || package.Status != L"ready" || package.Root != lease->Root || package.Id != lease->Id ||
            package.FactsSha256 != lease->FactsSha || package.ManifestSha256 != lease->ManifestSha || !Hex(id, 32) ||
            json.size() > 65536 || !mcpjson::ValidateDocument(json) ||
            Field(json, L"schema") != (outcome ? L"kn.disclosure_transfer_result.v1" : L"kn.disclosure_transfer_intent.v1"))
            { return fail(L"invalid_disclosure_transfer_record"); }
        const auto privacy = InspectEvidencePrivacy(package.Root, true);
        if (privacy.Status != L"ready") { return fail(L"disclosure_protection_changed"); }
        const auto file = fs::path(package.Root) / (L"transfer-" + id + (outcome ? L".knsendresult" : L".knsend"));
        if (!SaveObservationJson(Native(file), json, nullptr)) { return fail(L"disclosure_transfer_record_not_committed"); }
        std::wstring actual, digest;
        auto verified = Read(file, 256 * 1024, &actual, &digest);
        if (!verified || !lease->Privacy.CheckFile(verified.get()) || actual != json) { return fail(L"disclosure_transfer_record_not_verified"); }
        return true;
    }
    catch (...) { return fail(L"disclosure_transfer_record_exception"); }
}
std::wstring EvidenceDisclosurePackageJson(const EvidenceDisclosurePackage& p)
{
    return L"{\"schema\":\"kn.disclosure_package.v1\",\"status\":" + mcpjson::Quote(p.Status) + L",\"issue\":" + mcpjson::Quote(p.Issue) +
        L",\"root\":" + mcpjson::Quote(p.Root) + L",\"temporary_directory\":" + mcpjson::Quote(p.TemporaryDirectory) +
        L",\"manifest_sha256\":" + mcpjson::Quote(p.ManifestSha256) + L",\"facts_sha256\":" + mcpjson::Quote(p.FactsSha256) +
        L",\"facts\":" + (p.Status == L"ready" ? p.Facts : L"null") + L",\"transfer_authorized\":false,\"collector_authenticated\":false}";
}
