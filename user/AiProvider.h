#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

enum class AiProviderKind
{
    Disabled,
    CodexCli,
    OpenAICodex,
    DeepSeek,
    OpenRouter
};

enum class AiRemotePolicy
{
    AllowRemote,
    LocalOnly
};

struct AiProviderSettings
{
    AiProviderKind Provider;
    AiRemotePolicy RemotePolicy;
    std::wstring Model;
    std::wstring BaseUrl;
    std::wstring ApiKey;
    std::wstring ApiKeySource;
    std::wstring CodexCliPath;
    std::wstring CodexAuthFile;
    std::wstring ReasoningEffort;
    std::wstring DotEnvPath;
    std::wstring DotEnvWritePath;
    std::wstring RemotePolicySource;
    uint32_t TimeoutSeconds;
};

class AiDisclosureGrant;
struct EvidenceDisclosurePackage;
enum class AiRequestOrigin { Unreviewed, OperatorText, ReviewedEvidence };

struct AiCompletionRequest
{
    std::wstring System;
    std::wstring Prompt;
    AiRequestOrigin Origin = AiRequestOrigin::Unreviewed;
    std::shared_ptr<AiDisclosureGrant> Disclosure;
};

struct AiEvidenceReview
{
    std::wstring Id, Destination, System, Facts, FactsSha256, ManifestSha256;
private:
    friend class AiProviderRuntime;
    std::shared_ptr<AiDisclosureGrant> Grant;
};

struct AiCompletionResponse
{
    std::wstring Text;
    std::wstring RawBody;
    uint32_t StatusCode;
    bool Truncated;
    std::wstring DisclosureOutcome;
    bool DisclosureAuditRecorded = false;
};

class AiProviderRuntime
{
public:
    AiProviderRuntime();

    const AiProviderSettings& Settings() const;

    void ReloadFromEnvironment();
    bool LoadDotEnvFiles(const std::vector<std::wstring>& paths, std::wstring* loadedPath, std::wstring* error);
    bool SetProvider(const std::wstring& provider, std::wstring* error);
    void SetModel(const std::wstring& model);
    void SetBaseUrl(const std::wstring& baseUrl);
    void SetReasoningEffort(const std::wstring& effort);
    bool SetRemotePolicy(const std::wstring& policy, std::wstring* error);

    std::wstring ProviderName() const;
    std::wstring RemotePolicyName() const;
    std::wstring CredentialStatus() const;
    std::wstring StatusText() const;
    std::wstring HealthText() const;
    std::wstring AuthHelpText() const;
    std::wstring PreviewText(const AiCompletionRequest& request) const;
    std::wstring ModelsText(const std::wstring& query) const;

    bool ApplyUse(const std::wstring& spec, const std::wstring& modelOverride, std::wstring* error);
    bool SaveToDotEnv(std::wstring* savedPath, std::wstring* error);
    bool RefreshCloudModels(std::wstring* error);

    bool Complete(const AiCompletionRequest& request, AiCompletionResponse* response, std::wstring* error);
    bool PrepareEvidenceReview(const EvidenceDisclosurePackage& package, AiEvidenceReview* review, std::wstring* error) const;
    bool ApproveEvidenceReview(const AiEvidenceReview& review, const std::wstring& confirmationId, AiCompletionRequest* request, std::wstring* error) const;
    static void RevokeEvidenceReview(AiEvidenceReview* review);

    static std::vector<std::wstring> SupportedProviderNames();
    static bool NormalizeProviderName(const std::wstring& value, AiProviderKind* provider, std::wstring* normalized);
    static bool ParseAssistantSelfTest();
    static bool ProcessCaptureSelfTest();
    static bool HttpResponseBodySelfTest();
    static bool HttpRedirectSelfTest();

private:
    struct ConfigEntry
    {
        std::wstring Name;
        std::wstring Value;
        std::wstring Source;
    };

    AiProviderSettings settings_;
    std::vector<ConfigEntry> dotEnvValues_;

    void ApplyProviderDefaults(bool preserveModel);
    void LoadCredentials();
    std::wstring ConfigValue(const wchar_t* name, std::wstring* source) const;
    bool ResolveCodexTokens(std::wstring* accessToken, std::wstring* refreshToken, std::wstring* source) const;

    bool CompleteWithCodexCli(const AiCompletionRequest& request, AiCompletionResponse* response, std::wstring* error) const;
    bool CompleteWithOpenAICompatible(const AiCompletionRequest& request, AiCompletionResponse* response, std::wstring* error) const;
    bool CompleteWithOpenAICodex(const AiCompletionRequest& request, AiCompletionResponse* response, std::wstring* error,
        const AiDisclosureGrant* disclosure = nullptr) const;
    bool DisclosureDestination(std::wstring* destination, std::wstring* binding, std::wstring* access, std::wstring* refresh, std::wstring* error) const;
};
