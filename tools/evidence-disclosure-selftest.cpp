#include "../user/AiProvider.h"
#include "../user/EvidenceDisclosure.h"
#include "../user/ImageVerificationRecipe.h"
#include "../user/AnalystSnapshot.h"
#include "../user/McpJson.h"
#include <Windows.h>
#include <filesystem>
#include <iostream>
#include <string>

namespace fs = std::filesystem;
static void Print(const std::wstring& value) { std::cout << mcpjson::WideToUtf8(value) << std::endl; }
static std::wstring B(bool value) { return value ? L"true" : L"false"; }
static std::wstring ReadText(const wchar_t* path)
{
    std::wstring text;
    if (!ReadAnalystSnapshot(path, &text, nullptr)) { return L""; }
    return text;
}
int wmain(int argc, wchar_t** argv)
{
    if (argc < 3) { return 2; }
    const std::wstring action = argv[1];
    if (action == L"--prepare" && (argc == 5 || argc == 6))
    {
        const auto package = PrepareImageDisclosure(argv[2], argv[3], std::wstring(argv[4]) == L"efs", [&](const wchar_t* phase) {
            if (argc == 6 && std::wstring(argv[5]) == phase)
            {
                Print(L"{\"observed\":" + mcpjson::Quote(phase) + L"}");
                std::string resume; std::getline(std::cin, resume);
            }
        });
        Print(EvidenceDisclosurePackageJson(package)); return package.Status == L"ready" ? 0 : 1;
    }
    if (action == L"--inspect" && argc == 3)
    {
        const auto package = LoadEvidenceDisclosure(argv[2]); Print(EvidenceDisclosurePackageJson(package));
        return package.Status == L"ready" ? 0 : 1;
    }
    if (action == L"--replay" && argc == 3)
    {
        const auto replay = ReplayImageRecipe(argv[2], false, nullptr); Print(ImageRecipeReplayJson(replay));
        return replay.Status == L"replayed" ? 0 : 1;
    }
    if (action == L"--facts" && argc == 3)
    {
        MinimizedImageFacts facts;
        const bool valid = ParseMinimizedImageFacts(ReadText(argv[2]), &facts);
        Print(L"{\"valid\":" + B(valid) + L"}"); return valid ? 0 : 1;
    }
    if (action != L"--ai" || argc != 4) { return 2; }
    const std::wstring mode = argv[3];
    AiProviderRuntime ai;
    AiCompletionRequest request;
    AiCompletionResponse response{};
    std::wstring error;
    if (mode == L"raw" || mode == L"unknown" || mode == L"operator" || mode == L"forged")
    {
        request.System = L"synthetic operator instruction"; request.Prompt = L"synthetic-operator-only";
        if (mode == L"unknown") { request.Origin = static_cast<AiRequestOrigin>(99); }
        if (mode == L"operator") { request.Origin = AiRequestOrigin::OperatorText; }
        if (mode == L"forged") { request.Origin = AiRequestOrigin::ReviewedEvidence; }
        const bool completed = ai.Complete(request, &response, &error);
        Print(L"{\"completed\":" + B(completed) + L",\"error\":" + mcpjson::Quote(error) + L"}"); return 0;
    }
    auto package = LoadEvidenceDisclosure(argv[2]);
    if (mode == L"forged_package") { package.Facts += L" "; }
    AiEvidenceReview review;
    const bool prepared = ai.PrepareEvidenceReview(package, &review, &error);
    if (!prepared)
    {
        Print(L"{\"prepared\":false,\"error\":" + mcpjson::Quote(error) + L"}"); return 0;
    }
    Print(L"{\"prepared\":true,\"id\":" + mcpjson::Quote(review.Id) + L",\"destination\":" + review.Destination +
        L",\"system\":" + mcpjson::Quote(review.System) + L",\"facts\":" + review.Facts + L"}");
    if (mode == L"preview") { return 0; }
    if (mode == L"hold") { std::string resume; std::getline(std::cin, resume); }
    auto copy = review;
    if (mode == L"cancel") { AiProviderRuntime::RevokeEvidenceReview(&review); review = copy; }
    if (mode == L"facts_changed") { review.Facts += L" "; }
    if (mode == L"system_changed") { review.System += L"changed"; }
    if (mode == L"destination_changed") { review.Destination += L" "; }
    if (mode == L"model_before") { ai.SetModel(L"changed-model"); }
    if (mode == L"key_before")
    {
        SetEnvironmentVariableW(L"KNLIVEDBG_OPENROUTER_API_KEY", L"changed-synthetic-key"); ai.ReloadFromEnvironment();
    }
    if (mode == L"intent_collision")
    {
        if (!SaveObservationJson((fs::path(package.Root) / (L"transfer-" + review.Id + L".knsend")).wstring(), L"{}", nullptr)) { return 4; }
    }
    const bool approved = ai.ApproveEvidenceReview(review, mode == L"wrong_id" ? L"wrong" : review.Id, &request, &error);
    bool completed = false, second = false;
    if (approved)
    {
        if (mode == L"intent_hold")
        {
            Print(L"{\"observed\":\"intent_committed_before_dispatch\",\"id\":" + mcpjson::Quote(review.Id) + L"}");
            std::string resume; std::getline(std::cin, resume);
        }
        if (mode == L"model_after") { ai.SetModel(L"changed-model"); }
        if (mode == L"key_after")
        {
            SetEnvironmentVariableW(L"KNLIVEDBG_OPENROUTER_API_KEY", L"changed-synthetic-key"); ai.ReloadFromEnvironment();
        }
        if (mode == L"payload_after") { request.Prompt += L"injected-source-text"; }
        if (mode == L"result_collision")
        {
            if (!SaveObservationJson((fs::path(package.Root) / (L"transfer-" + review.Id + L".knsendresult")).wstring(), L"{}", nullptr)) { return 4; }
        }
        completed = ai.Complete(request, &response, &error);
        AiCompletionResponse repeated{}; std::wstring secondError;
        second = ai.Complete(request, &repeated, &secondError);
        AiCompletionRequest repeatedApproval;
        if (ai.ApproveEvidenceReview(copy, copy.Id, &repeatedApproval, &secondError)) { return 5; }
    }
    Print(L"{\"approved\":" + B(approved) + L",\"completed\":" + B(completed) + L",\"reused\":" + B(second) +
        L",\"outcome\":" + mcpjson::Quote(response.DisclosureOutcome) + L",\"audit\":" + B(response.DisclosureAuditRecorded) +
        L",\"error\":" + mcpjson::Quote(error) + L"}");
    return second ? 6 : 0;
}
