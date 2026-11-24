#include "ProcessImageSourceReceipt.h"
#include "BoundedObservationJson.h"
#include "ImageClaimPublication.h"
#include "ImageArchiveDependencies.h"
#include "ReferenceArtifact.h"
#include "SymbolArtifactCache.h"
#include <algorithm>
#include <cwctype>
#include <string_view>

bool ReplayProcessImageSource(const std::wstring& reportPath, const std::wstring& reportSha256,
    const std::wstring& imageCase, std::wstring& output, ProcessImageSourceFiles* retained)
{
    if (retained) { *retained = {}; }
    std::wstring verified = L"null", capture = L"null", pin = L"null";
    const auto finish = [&](const wchar_t* status, bool matched = false)
    {
        output = L"{\"schema\":\"kn.image_source_replay.v1\",\"status\":" + mcpjson::Quote(status) +
            L",\"report_sha256\":" + pin + L",\"capture_status\":" + capture + L",\"source_initialization\":" + verified +
            L",\"original_claim_matched\":" + bounded_observation_json::B(matched) + L",\"collector_authenticated\":false,\"execution_observed\":false}";
        return std::wstring_view(status) == L"replayed";
    };
    ReferenceArtifact file;
    std::filesystem::path path;
    symbol_artifacts::Directories reportParents;
    if (!symbol_artifacts::LocalRoot(reportPath, &path) || !reportParents.Pin(path.parent_path(), false) ||
        !file.Open(path.wstring(), nullptr, ImageClaimPublicationMaxBytes)) { return finish(L"report_unavailable"); }
    if (file.Sha256() != reportSha256) { return finish(L"report_digest_mismatch"); }
    pin = mcpjson::Quote(reportSha256);
    const auto& bytes = file.Bytes();
    const auto page = mcpjson::Utf8ToWide(std::string(bytes.begin(), bytes.end()));
    ProcessImageCaptureReport report;
    if (const auto issue = ParseProcessImageCaptureReport(page, report)) { return finish(issue); }
    verified = report.ReceiptJson;
    capture = mcpjson::Quote(report.CaptureStatus);
    ReferenceArtifact claimFile, referenceFile;
    const auto keep = [&]()
    {
        if (!retained) { return true; }
        if (!file.Unchanged() || (report.Published() && (!claimFile.Unchanged() || !referenceFile.Unchanged()))) { return false; }
        retained->CaptureStatus = report.CaptureStatus;
        retained->SourceStatus = report.SourceStatus;
        retained->Report = file.Snapshot();
        if (report.Published()) { retained->Claim = claimFile.Snapshot(); retained->Reference = referenceFile.Snapshot(); }
        return true;
    };
    if (!report.Published())
    {
        if (!imageCase.empty()) { return finish(L"unexpected_image_case"); }
        return finish(keep() ? L"replayed" : L"report_unavailable");
    }
    auto selected = imageCase;
    if (selected.empty())
    {
        auto relative = (path.parent_path().filename() / path.filename()).generic_wstring();
        std::transform(relative.begin(), relative.end(), relative.begin(), towlower);
        const auto id = ImageSourceReportCollection(relative, reportSha256);
        if (id.empty()) { return finish(L"image_case_required"); }
        const auto neighbor = std::filesystem::path(ImageSourceCasePath(id, reportSha256)).filename();
        selected = (path.parent_path() / neighbor).wstring();
    }
    symbol_artifacts::Directories caseParents, references;
    if (!symbol_artifacts::LocalRoot(selected, &path) || !caseParents.Pin(path.parent_path(), false))
        { return finish(L"image_case_unavailable"); }
    const DWORD attr = GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || (attr & FILE_ATTRIBUTE_REPARSE_POINT)) { return finish(L"image_case_unavailable"); }
    if (attr & FILE_ATTRIBUTE_DIRECTORY)
    {
        if (!references.Pin(path, false)) { return finish(L"image_case_unavailable"); }
        path /= L""; // Select directory replay even for a directory with a suffix.
    }
    else if (_wcsicmp(path.extension().c_str(), L".kncapture") != 0 ||
        !references.Pin(path.parent_path().parent_path() / L"image-references", false))
        { return finish(L"image_case_unavailable"); }
    if (retained)
    {
        const bool direct = (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
        const auto referenceRoot = direct ? path : path.parent_path().parent_path() / L"image-references";
        if (!claimFile.Open((direct ? path / L"recipe.knverify" : path).wstring(), nullptr, ImageClaimPublicationMaxBytes) ||
            !referenceFile.Open((referenceRoot / (report.ReferenceSha256 + L".knblob")).wstring(), nullptr) ||
            referenceFile.Sha256() != report.ReferenceSha256) { return finish(L"image_case_unavailable"); }
    }
    DirectImageReplayEvidence evidence;
    const auto replay = ReplayImageRecipe(path.wstring(), false, nullptr, &evidence);
    if (replay.Status != L"replayed" || replay.OriginalClaimStatus != L"reproduced") { return finish(L"image_case_unavailable"); }
    const auto& recipe = evidence.Recipe;
    if (recipe.FormatVersion != 3 || recipe.SourceId != report.SourceId || recipe.ReadSet.TargetId != report.TargetId ||
        recipe.ReadSet.OperationId != report.OperationId || recipe.ReferenceSha256 != report.ReferenceSha256 ||
        recipe.Policy != report.Policy || recipe.SourceConsistency != report.Consistency ||
        replay.RecipeSha256 != report.RecipeSha256 || replay.RecordedResult != report.Result ||
        replay.CaptureInterrupted != (report.CaptureStatus == L"interrupted")) { return finish(L"image_case_mismatch"); }
    if (!keep()) { return finish(L"image_case_unavailable"); }
    return finish(L"replayed", true);
}
