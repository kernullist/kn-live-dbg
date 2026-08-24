#pragma once

#include "AiProvider.h"

#include <string>
#include <vector>

struct AiUseTarget
{
    std::wstring Spec;
    std::wstring Preset;
    AiProviderKind Provider;
    std::wstring Model;
    std::wstring Label;
    std::wstring Summary;
    bool Remote;
};

struct AiCloudModel
{
    std::wstring Id;
    std::wstring Name;
    std::wstring Summary;
    double Intelligence;
    bool Live;
};

struct AiPresetInfo
{
    std::wstring Name;
    AiProviderKind Provider;
    std::wstring Model;
    std::wstring Summary;
    bool Remote;
};

class AiModelCatalog
{
public:
    static const wchar_t* CuratedAsOf();

    static std::vector<AiPresetInfo> Presets();
    static std::vector<AiCloudModel> CuratedCloudModels();
    static std::vector<std::pair<std::wstring, std::wstring>> Aliases();

    static bool Resolve(const std::wstring& spec, AiUseTarget* target, std::wstring* error);
    static bool ResolveModel(const std::wstring& spec, AiUseTarget* target, std::wstring* error);
    static bool ModelFitsProvider(
        AiProviderKind provider,
        const AiUseTarget& model,
        std::wstring* error);

    static std::wstring ProviderDisplayName(AiProviderKind provider);
    static bool DetectPreset(
        AiProviderKind provider,
        const std::wstring& model,
        AiPresetInfo* preset);

    static std::vector<std::wstring> CompletionTokens();
    static std::vector<std::wstring> ModelCompletionTokens();
    static bool DescribeToken(
        const std::wstring& token,
        std::wstring* syntax,
        std::wstring* summary);

    static bool ParseOpenRouterModelsJson(
        const std::wstring& json,
        std::vector<AiCloudModel>* models,
        std::wstring* error);
    static void SetLiveModels(const std::vector<AiCloudModel>& models);
    static void ClearLiveModels();
    static const std::vector<AiCloudModel>& LiveModels();
    static size_t LiveModelCount();

    static std::vector<AiCloudModel> Search(const std::wstring& query);
    static std::wstring ModelsText(
        AiProviderKind provider,
        const std::wstring& model,
        const std::wstring& query);

    static bool SelfTest();
};
