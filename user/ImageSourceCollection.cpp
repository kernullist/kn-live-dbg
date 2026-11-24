#include "ImageSourceCollection.h"
#include "ProcessImageSourceReceipt.h"
#include "ProcessImageCapture.h"
#include "ArtifactOutput.h"
#include "RuntimeCapabilities.h"
#include "ImageArchiveDependencies.h"
#include "ImageClaimPublication.h"
#include "EvidenceArtifactPublication.h"
#include "EvidenceStore.h"
#include "BoundedObservationJson.h"
#include <algorithm>
#include <cwctype>
#include <iostream>

using namespace evidence_artifact_publication;
namespace fs = std::filesystem;

namespace
{
    bool ValidId(const std::wstring& id)
    {
        return !id.empty() && id.size() <= 20 && id.find_first_not_of(L"0123456789") == std::wstring::npos &&
            (id.size() == 1 || id.front() != L'0');
    }

    bool ProtectOutput(HANDLE sink, const std::vector<std::wstring>& args, bool valid, bool archive,
        bool hasCase, std::vector<DistinctArtifactInput>& leases)
    {
        if (GetFileType(sink) != FILE_TYPE_DISK) { return true; }
        const size_t caseIndex = archive ? 6 : 4;
        if (args.size() > caseIndex + (archive ? 2 : 3)) { return false; }
        for (size_t i = 2; i < args.size(); ++i)
        {
            if (valid && i != 2 && !(archive && i == 4) && !(hasCase && i == caseIndex)) { continue; }
            if (!HoldImageCommandOperand(sink, args[i], leases)) { return false; }
            fs::path path;
            if (!symbol_artifacts::LocalRoot(args[i], &path)) { continue; }
            const bool managedReport = (!valid || i == 2) && _wcsicmp(path.extension().c_str(), L".knsource") == 0 &&
                _wcsicmp(path.parent_path().filename().c_str(), L"image-captures") == 0;
            if (managedReport && !HoldImageCommandOperand(sink, path.parent_path().wstring(), leases)) { return false; }
            if ((managedReport || ((!valid || i == caseIndex) && _wcsicmp(path.extension().c_str(), L".kncapture") == 0)) &&
                !HoldImageCommandOperand(sink, (path.parent_path().parent_path() / L"image-references").wstring(), leases)) { return false; }
        }
        return true;
    }
}

ImageSourceCollection JournalProcessImageSource(const std::wstring& report, const std::wstring& pin,
    const std::wstring& imageCase, const std::wstring& store, const std::wstring& collectionId)
{
    ImageSourceCollection out;
    out.Id = collectionId;
    const auto fail = [&](const std::wstring& issue) { out.Issue = issue; return out; };
    try
    {
        if (!ValidId(collectionId)) { return fail(L"invalid_collection_id"); }
        ProcessImageSourceFiles inputs;
        std::wstring replay;
        if (!ReplayProcessImageSource(report, pin, imageCase, replay, &inputs))
        {
            std::wstring issue;
            mcpjson::GetString(replay, L"status", &issue);
            return fail(issue.empty() ? L"source_replay_failed" : issue);
        }
        out.ReportSha256 = inputs.Report->Sha256;
        out.ReportPath = ImageSourceReportPath(collectionId, out.ReportSha256);
        out.CaptureStatus = inputs.CaptureStatus;
        out.SourceStatus = inputs.SourceStatus;
        if (inputs.Claim) { out.CapturePath = ImageSourceCasePath(collectionId, out.ReportSha256); }
        EvidencePrivacyGuard privacy;
        EvidencePrivacyReport protection;
        if (!privacy.Open(store, false, &protection)) { return fail(L"private_store_unavailable"); }
        const fs::path root(protection.RootPath);
        EvidenceStoreLease barrier;
        if (!barrier.Acquire(protection.RootPath, false, &out.Issue)) { return out; }
        EvidenceJournal journal;
        if (!journal.Open(protection.RootPath, collectionId, &out.Issue, EvidenceJournalPolicy::ImageSourceV1,
            [&](HANDLE file) { return privacy.CheckFile(file); })) { return out; }
        if (!journal.State().SourceReportPath.empty() && journal.State().SourceReportPath != out.ReportPath)
            { return fail(L"collection_contains_different_report"); }
        out.Status = L"incomplete";
        out.ReportCommitted = !journal.State().SourceReportPath.empty();
        out.Closed = journal.State().Closed;
        out.HeadSha256 = journal.State().HeadSha256;
        auto captures = PinFolder(root / L"image-captures");
        if (!captures) { return fail(L"capture_store_directory_unavailable"); }
        Handle references(nullptr, &CloseHandle);
        EvidenceJournalTransaction transaction;
        transaction.Kind = L"image_source"; transaction.Id = out.ReportSha256;
        std::vector<std::unique_ptr<SchemaArtifact>> leases;
        const auto keep = [&](const std::wstring& relative, const RetainedReferenceArtifact& file, const wchar_t* schema)
        {
            bool created = false;
            auto& lease = leases.emplace_back();
            if (!Retain(root / relative, file.Bytes, file.Sha256, privacy, &lease, &created)) { return false; }
            transaction.Members.push_back({relative, file.Sha256, schema, file.Bytes.size()});
            return true;
        };
        if (inputs.Claim)
        {
            references = PinFolder(root / L"image-references");
            if (!references || !keep(L"image-references/" + inputs.Reference->Sha256 + L".knblob", *inputs.Reference, L"raw.bytes") ||
                !keep(out.CapturePath, *inputs.Claim, ImageClaimPublicationSchema)) { return fail(L"image_publication_failed"); }
        }
        if (!keep(out.ReportPath, *inputs.Report, L"kn.image_capture.v3")) { return fail(L"report_publication_failed"); }
        const auto memberCommit = journal.Commit(transaction);
        out.ReportCommitted = memberCommit.Committed; out.HeadSha256 = journal.State().HeadSha256;
        if (!memberCommit.Committed || !memberCommit.Indexed) { return fail(memberCommit.Issue); }

        const auto ledger = ImageSourceSessionJson(collectionId, transaction.Members, out.CaptureStatus, out.SourceStatus);
        const auto encoded = mcpjson::WideToUtf8(ledger);
        const std::vector<uint8_t> bytes(encoded.begin(), encoded.end());
        const auto path = ImageSourceSessionPath(collectionId);
        std::unique_ptr<SchemaArtifact> ledgerLease;
        bool created = false;
        if (!Retain(root / path, bytes, ContentHash::Bytes(bytes), privacy, &ledgerLease, &created))
            { return fail(L"ledger_publication_failed"); }
        EvidenceJournalTransaction closure;
        closure.Kind = L"closure"; closure.Id = L"0";
        closure.Members = {EvidenceJournalJsonMember(path, ledger)};
        for (const auto& m : transaction.Members) { closure.Requires.push_back(m.Path); }
        const auto closed = journal.Commit(std::move(closure));
        out.Closed = journal.State().Closed; out.HeadSha256 = journal.State().HeadSha256;
        out.Indexed = closed.Committed && closed.Indexed;
        if (!out.Closed || !out.Indexed) { return fail(closed.Issue); }
        out.Status = L"archived";
        return out;
    }
    catch (const std::exception&) { return fail(L"source_collection_failed"); }
}

std::wstring ImageSourceCollectionJson(const ImageSourceCollection& r)
{
    using mcpjson::Quote;
    using bounded_observation_json::B;
    return L"{\"schema\":\"kn.image_source_collection.v1\",\"status\":" + Quote(r.Status) +
        L",\"issue\":" + Quote(r.Issue) + L",\"collection_id\":" + Quote(r.Id) +
        L",\"report_path\":" + Quote(r.ReportPath) + L",\"report_sha256\":" + Quote(r.ReportSha256) +
        L",\"capture_path\":" + Quote(r.CapturePath) + L",\"capture_status\":" + Quote(r.CaptureStatus) +
        L",\"source_status\":" + Quote(r.SourceStatus) + L",\"head_sha256\":" + Quote(r.HeadSha256) +
        L",\"report_committed\":" + B(r.ReportCommitted) + L",\"closed\":" + B(r.Closed) + L",\"indexed\":" + B(r.Indexed) +
        L",\"collector_authenticated\":false,\"execution_observed\":false,\"power_loss_durability_established\":false}";
}

int RunImageSourceCommand(const std::vector<std::wstring>& args, bool directJsonOutput)
{
    const bool archive = args.size() >= 2 && _wcsicmp(args[1].c_str(), L"journal-image-source") == 0;
    const size_t caseIndex = archive ? 6 : 4;
    const bool json = !args.empty() && _wcsicmp(args.back().c_str(), L"/json") == 0;
    auto fields = args.size() - (json ? 1 : 0);
    const bool hasExport = !archive && fields > caseIndex && !_wcsnicmp(args[fields - 1].c_str(), L"/iat:", 5);
    const auto exportName = hasExport ? args[--fields].substr(5) : L"";
    const bool validExport = !hasExport || (!exportName.empty() && exportName.size() <= 255 &&
        std::all_of(exportName.begin(), exportName.end(), [](wchar_t c) { return c >= 0x21 && c <= 0x7e; }));
    const bool hasCase = fields == caseIndex + 1;
    const bool valid = validExport && (fields == caseIndex || hasCase) && !args[2].empty() && args[3].size() == 64 &&
        args[3].find_first_not_of(L"0123456789abcdefABCDEF") == std::wstring::npos &&
        (!archive || (!args[4].empty() && args[4][0] != L'/' && ValidId(args[5]))) &&
        (!hasCase || (!args[caseIndex].empty() && args[caseIndex][0] != L'/'));
    const auto sink = GetStdHandle(valid ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
    std::vector<DistinctArtifactInput> leases;
    if (!ProtectOutput(sink, args, valid, archive, hasCase, leases)) { return 2; }
    if (!valid)
    {
        if (archive) { std::wcerr << L"usage: !kmon journal-image-source <capture-report> <report-sha256> <private-store> <collection-id> [directory|capture.kncapture] [/json]\n"; }
        else { std::wcerr << L"usage: !kmon replay-image-source <capture-report> <report-sha256> [directory|capture.kncapture] [/iat:export-name] [/json]\n"; }
        return 2;
    }
    auto pin = args[3];
    std::transform(pin.begin(), pin.end(), pin.begin(), towlower);
    const auto imageCase = hasCase ? args[caseIndex] : L"";
    std::wstring output;
    bool ok = false;
    if (archive)
    {
        const auto result = JournalProcessImageSource(args[2], pin, imageCase, args[4], args[5]);
        output = ImageSourceCollectionJson(result);
        ok = result.Status == L"archived";
    }
    else
    {
        try { ok = ReplayProcessImageSource(args[2], pin, imageCase, output, nullptr, exportName); }
        catch (const std::exception&) { output = L"{\"schema\":\"kn.image_source_replay.v1\",\"status\":\"replay_failed\"}"; }
    }
    if (!ProtectOutput(sink, args, true, archive, hasCase, leases)) { return 2; }
    if (directJsonOutput) { if (!WriteCapabilityJson(output)) { return 3; } }
    else { std::wcout << output << L"\n"; }
    return ok ? 0 : 1;
}
