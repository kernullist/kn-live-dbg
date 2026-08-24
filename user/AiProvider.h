#pragma once

#include <cstdint>
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

struct AiCompletionRequest
{
    std::wstring System;
    std::wstring Prompt;
};

struct AiCompletionResponse
{
    std::wstring Text;
    std::wstring RawBody;
    uint32_t StatusCode;
    bool Truncated;
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

    static std::vector<std::wstring> SupportedProviderNames();
    static bool NormalizeProviderName(const std::wstring& value, AiProviderKind* provider, std::wstring* normalized);
    static bool ParseAssistantSelfTest();

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
    bool CompleteWithOpenAICodex(const AiCompletionRequest& request, AiCompletionResponse* response, std::wstring* error) const;
};
