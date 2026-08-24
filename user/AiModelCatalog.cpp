#include "AiModelCatalog.h"

#include <algorithm>
#include <cstdlib>
#include <cwctype>
#include <sstream>
#include <utility>

namespace
{
    std::wstring Trim(const std::wstring& value)
    {
        size_t begin = 0;
        size_t end = value.size();

        while (begin < end && iswspace(value[begin]) != 0)
        {
            ++begin;
        }

        while (end > begin && iswspace(value[end - 1]) != 0)
        {
            --end;
        }

        return value.substr(begin, end - begin);
    }

    std::wstring ToLower(const std::wstring& value)
    {
        std::wstring result = value;
        for (wchar_t& ch : result)
        {
            ch = static_cast<wchar_t>(towlower(ch));
        }

        return result;
    }

    bool Same(const std::wstring& left, const wchar_t* right)
    {
        return right != nullptr && ToLower(left) == ToLower(right);
    }

    std::wstring LastPathSegment(const std::wstring& id)
    {
        size_t slash = id.find_last_of(L'/');
        if (slash == std::wstring::npos)
        {
            return id;
        }

        return id.substr(slash + 1);
    }

    bool ShouldSkipLiveId(const std::wstring& id)
    {
        bool skip = false;
        const std::wstring lowered = ToLower(id);

        if (lowered.empty() ||
            lowered.front() == L'~' ||
            lowered.find(L":batch") != std::wstring::npos ||
            lowered.find(L"image") != std::wstring::npos ||
            lowered.find(L"imagine") != std::wstring::npos)
        {
            skip = true;
        }

        return skip;
    }

    struct PresetDef
    {
        const wchar_t* Name;
        AiProviderKind Provider;
        const wchar_t* Model;
        const wchar_t* Summary;
        bool Remote;
    };

    struct CloudModelDef
    {
        const wchar_t* Id;
        const wchar_t* Name;
        const wchar_t* Summary;
        double Intelligence;
    };

    struct AliasDef
    {
        const wchar_t* Name;
        const wchar_t* ModelId;
    };

    const PresetDef kPresets[] =
    {
        { L"cloud", AiProviderKind::OpenRouter, L"anthropic/claude-opus-5", L"OpenRouter frontier (Claude Opus 5)", true },
        { L"cheap", AiProviderKind::OpenRouter, L"openai/gpt-oss-120b", L"OpenRouter low-cost open-weight", true },
        { L"deepseek", AiProviderKind::DeepSeek, L"deepseek-chat", L"DeepSeek native API", true },
        { L"private", AiProviderKind::CodexCli, L"default", L"local Codex CLI, no HTTP from this process", false },
        { L"chatgpt", AiProviderKind::OpenAICodex, L"gpt-5.5", L"ChatGPT/Codex OAuth", true },
        { L"off", AiProviderKind::Disabled, L"", L"disable the model provider", false },
    };

    // Snapshot of frontier OpenRouter text models as of 2026-08-24.
    // Live `ai models refresh` adds newer IDs on top of this list.
    const CloudModelDef kCurated[] =
    {
        { L"anthropic/claude-opus-5", L"Claude Opus 5", L"Anthropic flagship, top intelligence/coding", 63.1 },
        { L"anthropic/claude-fable-5", L"Claude Fable 5", L"Anthropic writing/reasoning flagship", 62.1 },
        { L"openai/gpt-5.6-sol", L"GPT-5.6 Sol", L"OpenAI GPT-5.6 flagship", 60.9 },
        { L"x-ai/grok-4.6", L"Grok 4.6", L"SpaceXAI flagship, strong coding/agents", 60.9 },
        { L"moonshotai/kimi-k3", L"Kimi K3", L"Moonshot flagship", 59.7 },
        { L"z-ai/glm-5.3", L"GLM 5.3", L"Z.ai flagship reasoning", 59.5 },
        { L"qwen/qwen3.8-max", L"Qwen3.8 Max", L"Alibaba Qwen3.8 flagship", 58.1 },
        { L"anthropic/claude-opus-4.8", L"Claude Opus 4.8", L"Previous Anthropic Opus", 57.3 },
        { L"meta/muse-spark-1.2", L"Muse Spark 1.2", L"Meta agentic reasoning", 56.8 },
        { L"openai/gpt-5.6-terra", L"GPT-5.6 Terra", L"OpenAI GPT-5.6 balanced tier", 56.6 },
        { L"openai/gpt-5.5", L"GPT-5.5", L"OpenAI GPT-5.5", 56.3 },
        { L"google/gemini-3.7-flash", L"Gemini 3.7 Flash", L"Google fast frontier", 56.0 },
        { L"x-ai/grok-4.5", L"Grok 4.5", L"Previous SpaceXAI flagship", 55.8 },
        { L"anthropic/claude-sonnet-5", L"Claude Sonnet 5", L"Anthropic Sonnet-class", 55.3 },
        { L"deepseek/deepseek-v4-pro-0813", L"DeepSeek V4 Pro 0813", L"DeepSeek V4 Pro GA", 53.2 },
        { L"openai/gpt-5.6-luna", L"GPT-5.6 Luna", L"OpenAI GPT-5.6 fast/cheap tier", 52.3 },
        { L"deepseek/deepseek-v4-flash-0731", L"DeepSeek V4 Flash 0731", L"DeepSeek V4 Flash", 51.8 },
        { L"google/gemini-3.6-flash", L"Gemini 3.6 Flash", L"Google 3.6 Flash", 51.6 },
        { L"google/gemini-3.1-pro-preview", L"Gemini 3.1 Pro Preview", L"Google 3.1 Pro preview", 47.7 },
        { L"anthropic/claude-opus-5-fast", L"Claude Opus 5 Fast", L"Opus 5 faster, higher price", 0.0 },
        { L"openai/gpt-5.6-sol-pro", L"GPT-5.6 Sol Pro", L"GPT-5.6 Sol with pro reasoning", 0.0 },
        { L"openai/gpt-oss-120b", L"gpt-oss-120b", L"Open-weight, low cost", 24.1 },
        { L"deepseek/deepseek-r1", L"DeepSeek R1", L"Legacy DeepSeek reasoner", 18.6 },
        { L"deepseek-chat", L"deepseek-chat", L"DeepSeek native chat model", 0.0 },
        { L"deepseek-reasoner", L"deepseek-reasoner", L"DeepSeek native reasoner model", 0.0 },
    };

    const AliasDef kAliases[] =
    {
        { L"opus", L"anthropic/claude-opus-5" },
        { L"opus5", L"anthropic/claude-opus-5" },
        { L"claude", L"anthropic/claude-opus-5" },
        { L"claude-opus-5", L"anthropic/claude-opus-5" },
        { L"fable", L"anthropic/claude-fable-5" },
        { L"sonnet", L"anthropic/claude-sonnet-5" },
        { L"sonnet5", L"anthropic/claude-sonnet-5" },
        { L"gpt", L"openai/gpt-5.6-sol" },
        { L"gpt5", L"openai/gpt-5.6-sol" },
        { L"gpt-5.6", L"openai/gpt-5.6-sol" },
        { L"sol", L"openai/gpt-5.6-sol" },
        { L"gpt-5.5", L"openai/gpt-5.5" },
        { L"grok", L"x-ai/grok-4.6" },
        { L"grok4", L"x-ai/grok-4.6" },
        { L"grok-4.6", L"x-ai/grok-4.6" },
        { L"grok-4.5", L"x-ai/grok-4.5" },
        { L"gemini", L"google/gemini-3.7-flash" },
        { L"flash", L"google/gemini-3.7-flash" },
        { L"kimi", L"moonshotai/kimi-k3" },
        { L"k3", L"moonshotai/kimi-k3" },
        { L"glm", L"z-ai/glm-5.3" },
        { L"qwen", L"qwen/qwen3.8-max" },
        { L"muse", L"meta/muse-spark-1.2" },
        { L"oss", L"openai/gpt-oss-120b" },
        { L"gpt-oss", L"openai/gpt-oss-120b" },
        { L"r1", L"deepseek/deepseek-r1" },
        { L"v4", L"deepseek/deepseek-v4-pro-0813" },
        { L"deepseek-v4", L"deepseek/deepseek-v4-pro-0813" },
    };

    std::vector<AiCloudModel> g_liveModels;

    AiCloudModel FromDef(const CloudModelDef& def)
    {
        AiCloudModel model = {};
        model.Id = def.Id;
        model.Name = def.Name;
        model.Summary = def.Summary;
        model.Intelligence = def.Intelligence;
        model.Live = false;
        return model;
    }

    bool FindCurated(const std::wstring& id, AiCloudModel* model)
    {
        bool found = false;
        const std::wstring lowered = ToLower(id);

        for (const CloudModelDef& def : kCurated)
        {
            if (ToLower(def.Id) == lowered)
            {
                if (model != nullptr)
                {
                    *model = FromDef(def);
                }

                found = true;
                break;
            }
        }

        return found;
    }

    bool FindLive(const std::wstring& id, AiCloudModel* model)
    {
        bool found = false;
        const std::wstring lowered = ToLower(id);

        for (const AiCloudModel& live : g_liveModels)
        {
            if (ToLower(live.Id) == lowered)
            {
                if (model != nullptr)
                {
                    *model = live;
                }

                found = true;
                break;
            }
        }

        return found;
    }

    bool FindAlias(const std::wstring& spec, std::wstring* modelId)
    {
        bool found = false;
        const std::wstring lowered = ToLower(spec);

        for (const AliasDef& alias : kAliases)
        {
            if (ToLower(alias.Name) == lowered)
            {
                if (modelId != nullptr)
                {
                    *modelId = alias.ModelId;
                }

                found = true;
                break;
            }
        }

        return found;
    }

    bool FindPreset(const std::wstring& spec, AiPresetInfo* preset)
    {
        bool found = false;
        const std::wstring lowered = ToLower(spec);

        for (const PresetDef& def : kPresets)
        {
            if (ToLower(def.Name) == lowered)
            {
                if (preset != nullptr)
                {
                    preset->Name = def.Name;
                    preset->Provider = def.Provider;
                    preset->Model = def.Model != nullptr ? def.Model : L"";
                    preset->Summary = def.Summary;
                    preset->Remote = def.Remote;
                }

                found = true;
                break;
            }
        }

        return found;
    }

    std::vector<AiCloudModel> AllKnownModels()
    {
        std::vector<AiCloudModel> models;
        for (const CloudModelDef& def : kCurated)
        {
            models.push_back(FromDef(def));
        }

        for (const AiCloudModel& live : g_liveModels)
        {
            bool exists = false;
            for (const AiCloudModel& known : models)
            {
                if (ToLower(known.Id) == ToLower(live.Id))
                {
                    exists = true;
                    break;
                }
            }

            if (!exists)
            {
                models.push_back(live);
            }
        }

        return models;
    }

    AiProviderKind ProviderForModelId(const std::wstring& modelId)
    {
        AiProviderKind provider = AiProviderKind::OpenRouter;
        const std::wstring lowered = ToLower(modelId);

        if (lowered == L"deepseek-chat" || lowered == L"deepseek-reasoner")
        {
            provider = AiProviderKind::DeepSeek;
        }

        return provider;
    }

    void FillTargetFromModel(const AiCloudModel& model, const std::wstring& spec, AiUseTarget* target)
    {
        target->Spec = spec;
        target->Preset.clear();
        target->Provider = ProviderForModelId(model.Id);
        target->Model = model.Id;
        target->Label = model.Name.empty() ? model.Id : model.Name;
        target->Summary = model.Summary.empty() ? model.Name : model.Summary;
        target->Remote = target->Provider != AiProviderKind::CodexCli &&
            target->Provider != AiProviderKind::Disabled;
    }

    bool ResolveKnownModel(const std::wstring& spec, AiUseTarget* target)
    {
        bool found = false;
        AiCloudModel model = {};

        do
        {
            if (FindCurated(spec, &model) || FindLive(spec, &model))
            {
                FillTargetFromModel(model, spec, target);
                found = true;
                break;
            }

            std::wstring aliasId;
            if (FindAlias(spec, &aliasId))
            {
                if (!FindCurated(aliasId, &model) && !FindLive(aliasId, &model))
                {
                    model = {};
                    model.Id = aliasId;
                    model.Name = aliasId;
                    model.Summary = L"alias target";
                }

                FillTargetFromModel(model, spec, target);
                found = true;
                break;
            }
        } while (false);

        return found;
    }

    std::vector<AiCloudModel> UniqueSuffixMatches(const std::wstring& spec)
    {
        std::vector<AiCloudModel> exactId;
        std::vector<AiCloudModel> exactTail;
        std::vector<AiCloudModel> substring;
        const std::wstring needle = ToLower(spec);

        if (needle.size() < 3)
        {
            return exactId;
        }

        for (const AiCloudModel& model : AllKnownModels())
        {
            const std::wstring idLower = ToLower(model.Id);
            const std::wstring nameLower = ToLower(model.Name);
            const std::wstring tail = ToLower(LastPathSegment(model.Id));
            if (idLower == needle)
            {
                exactId.push_back(model);
            }
            else if (tail == needle)
            {
                exactTail.push_back(model);
            }
            else if (idLower.find(needle) != std::wstring::npos ||
                     (!nameLower.empty() && nameLower.find(needle) != std::wstring::npos))
            {
                substring.push_back(model);
            }
        }

        if (!exactId.empty())
        {
            return exactId;
        }

        if (!exactTail.empty())
        {
            return exactTail;
        }

        return substring;
    }

    std::wstring FormatScore(double value)
    {
        std::wstringstream stream;
        if (value > 0.0)
        {
            stream.setf(std::ios::fixed);
            stream.precision(value == static_cast<int>(value) ? 0 : 1);
            stream << value;
        }
        else
        {
            stream << L"-";
        }

        return stream.str();
    }

    size_t SkipJsonWhitespace(const std::wstring& text, size_t index)
    {
        while (index < text.size() && iswspace(text[index]) != 0)
        {
            ++index;
        }

        return index;
    }

    bool ExtractJsonString(const std::wstring& text, size_t colon, std::wstring* value, size_t* end)
    {
        bool ok = false;
        size_t index = SkipJsonWhitespace(text, colon + 1);

        do
        {
            if (value == nullptr || index >= text.size() || text[index] != L'\"')
            {
                break;
            }

            ++index;
            std::wstring parsed;
            bool escaped = false;
            for (; index < text.size(); ++index)
            {
                wchar_t ch = text[index];
                if (escaped)
                {
                    parsed += ch;
                    escaped = false;
                    continue;
                }

                if (ch == L'\\')
                {
                    escaped = true;
                    continue;
                }

                if (ch == L'\"')
                {
                    *value = parsed;
                    if (end != nullptr)
                    {
                        *end = index + 1;
                    }

                    ok = true;
                    break;
                }

                parsed += ch;
            }
        } while (false);

        return ok;
    }

    bool ExtractJsonNumber(const std::wstring& text, size_t colon, double* value)
    {
        bool ok = false;
        size_t index = SkipJsonWhitespace(text, colon + 1);

        do
        {
            if (value == nullptr || index >= text.size())
            {
                break;
            }

            size_t begin = index;
            if (text[index] == L'-')
            {
                ++index;
            }

            while (index < text.size() &&
                   ((text[index] >= L'0' && text[index] <= L'9') || text[index] == L'.'))
            {
                ++index;
            }

            if (index == begin)
            {
                break;
            }

            *value = wcstod(text.substr(begin, index - begin).c_str(), nullptr);
            ok = true;
        } while (false);

        return ok;
    }

    bool ExtractObjectFieldString(const std::wstring& object, const wchar_t* key, std::wstring* value)
    {
        bool ok = false;
        const std::wstring pattern = std::wstring(L"\"") + key + L"\"";
        size_t pos = 0;

        while ((pos = object.find(pattern, pos)) != std::wstring::npos)
        {
            size_t colon = SkipJsonWhitespace(object, pos + pattern.size());
            if (colon < object.size() && object[colon] == L':')
            {
                size_t end = 0;
                if (ExtractJsonString(object, colon, value, &end))
                {
                    ok = true;
                    break;
                }
            }

            ++pos;
        }

        return ok;
    }

    bool ExtractObjectFieldNumber(const std::wstring& object, const wchar_t* key, double* value)
    {
        bool ok = false;
        const std::wstring pattern = std::wstring(L"\"") + key + L"\"";
        size_t pos = 0;

        while ((pos = object.find(pattern, pos)) != std::wstring::npos)
        {
            size_t colon = SkipJsonWhitespace(object, pos + pattern.size());
            if (colon < object.size() && object[colon] == L':')
            {
                if (ExtractJsonNumber(object, colon, value))
                {
                    ok = true;
                    break;
                }
            }

            ++pos;
        }

        return ok;
    }

    bool ExtractNextJsonObject(const std::wstring& text, size_t start, std::wstring* object, size_t* end)
    {
        bool ok = false;
        size_t index = start;

        do
        {
            while (index < text.size() && text[index] != L'{')
            {
                if (text[index] == L']')
                {
                    break;
                }

                ++index;
            }

            if (index >= text.size() || text[index] != L'{')
            {
                break;
            }

            size_t begin = index;
            int depth = 0;
            bool inString = false;
            bool escaped = false;
            for (; index < text.size(); ++index)
            {
                wchar_t ch = text[index];
                if (inString)
                {
                    if (escaped)
                    {
                        escaped = false;
                    }
                    else if (ch == L'\\')
                    {
                        escaped = true;
                    }
                    else if (ch == L'\"')
                    {
                        inString = false;
                    }

                    continue;
                }

                if (ch == L'\"')
                {
                    inString = true;
                }
                else if (ch == L'{')
                {
                    ++depth;
                }
                else if (ch == L'}')
                {
                    --depth;
                    if (depth == 0)
                    {
                        if (object != nullptr)
                        {
                            *object = text.substr(begin, index - begin + 1);
                        }

                        if (end != nullptr)
                        {
                            *end = index + 1;
                        }

                        ok = true;
                        break;
                    }
                }
            }
        } while (false);

        return ok;
    }

    void AddUniqueToken(std::vector<std::wstring>* tokens, const std::wstring& value)
    {
        if (tokens == nullptr || value.empty())
        {
            return;
        }

        for (const std::wstring& existing : *tokens)
        {
            if (ToLower(existing) == ToLower(value))
            {
                return;
            }
        }

        tokens->push_back(value);
    }
}

const wchar_t* AiModelCatalog::CuratedAsOf()
{
    return L"2026-08-24";
}

std::vector<AiPresetInfo> AiModelCatalog::Presets()
{
    std::vector<AiPresetInfo> presets;
    for (const PresetDef& def : kPresets)
    {
        AiPresetInfo preset = {};
        preset.Name = def.Name;
        preset.Provider = def.Provider;
        preset.Model = def.Model != nullptr ? def.Model : L"";
        preset.Summary = def.Summary;
        preset.Remote = def.Remote;
        presets.push_back(preset);
    }

    return presets;
}

std::vector<AiCloudModel> AiModelCatalog::CuratedCloudModels()
{
    std::vector<AiCloudModel> models;
    for (const CloudModelDef& def : kCurated)
    {
        models.push_back(FromDef(def));
    }

    return models;
}

std::vector<std::pair<std::wstring, std::wstring>> AiModelCatalog::Aliases()
{
    std::vector<std::pair<std::wstring, std::wstring>> aliases;
    for (const AliasDef& alias : kAliases)
    {
        aliases.push_back(std::make_pair(std::wstring(alias.Name), std::wstring(alias.ModelId)));
    }

    return aliases;
}

std::wstring AiModelCatalog::ProviderDisplayName(AiProviderKind provider)
{
    std::wstring name = L"disabled";

    switch (provider)
    {
    case AiProviderKind::CodexCli:
        name = L"openai-codex-cli";
        break;
    case AiProviderKind::OpenAICodex:
        name = L"openai-codex-subscription";
        break;
    case AiProviderKind::DeepSeek:
        name = L"deepseek";
        break;
    case AiProviderKind::OpenRouter:
        name = L"openrouter";
        break;
    default:
        break;
    }

    return name;
}

bool AiModelCatalog::DetectPreset(
    AiProviderKind provider,
    const std::wstring& model,
    AiPresetInfo* preset)
{
    bool found = false;
    const std::wstring lowered = ToLower(model);

    for (const PresetDef& def : kPresets)
    {
        if (def.Provider != provider)
        {
            continue;
        }

        const std::wstring presetModel = def.Model != nullptr ? ToLower(def.Model) : std::wstring();
        if (presetModel == lowered ||
            (presetModel == L"default" && (lowered.empty() || lowered == L"default")))
        {
            if (preset != nullptr)
            {
                preset->Name = def.Name;
                preset->Provider = def.Provider;
                preset->Model = def.Model != nullptr ? def.Model : L"";
                preset->Summary = def.Summary;
                preset->Remote = def.Remote;
            }

            found = true;
            break;
        }
    }

    return found;
}

bool AiModelCatalog::Resolve(const std::wstring& spec, AiUseTarget* target, std::wstring* error)
{
    bool ok = false;
    std::wstring text = Trim(spec);

    do
    {
        if (target == nullptr)
        {
            break;
        }

        *target = {};
        if (text.empty())
        {
            if (error != nullptr)
            {
                *error = L"usage: ai use <preset|model>";
            }

            break;
        }

        AiPresetInfo preset = {};
        if (FindPreset(text, &preset))
        {
            target->Spec = text;
            target->Preset = preset.Name;
            target->Provider = preset.Provider;
            target->Model = preset.Model;
            target->Label = preset.Name;
            target->Summary = preset.Summary;
            target->Remote = preset.Remote;
            ok = true;
            break;
        }

        if (ResolveModel(text, target, error))
        {
            ok = true;
            break;
        }
    } while (false);

    return ok;
}

bool AiModelCatalog::ResolveModel(const std::wstring& spec, AiUseTarget* target, std::wstring* error)
{
    bool ok = false;
    std::wstring text = Trim(spec);

    do
    {
        if (target == nullptr)
        {
            break;
        }

        *target = {};
        if (text.empty())
        {
            if (error != nullptr)
            {
                *error = L"missing model name";
            }

            break;
        }

        if (text.front() == L'/' || text.find(L' ') != std::wstring::npos)
        {
            if (error != nullptr)
            {
                *error = L"invalid model name '" + text + L"'";
            }

            break;
        }

        if (ResolveKnownModel(text, target))
        {
            ok = true;
            break;
        }

        std::vector<AiCloudModel> matches = UniqueSuffixMatches(text);
        if (matches.size() == 1)
        {
            FillTargetFromModel(matches[0], text, target);
            ok = true;
            break;
        }

        if (matches.size() > 1)
        {
            if (error != nullptr)
            {
                std::wstringstream stream;
                stream << L"ambiguous model '" << text << L"'. matches:\n";
                size_t shown = 0;
                for (const AiCloudModel& model : matches)
                {
                    stream << L"  " << model.Id << L"\n";
                    ++shown;
                    if (shown >= 8)
                    {
                        stream << L"  ... type ai models " << text << L"\n";
                        break;
                    }
                }

                *error = stream.str();
            }

            break;
        }

        if (text.find(L'/') != std::wstring::npos)
        {
            AiCloudModel model = {};
            model.Id = text;
            model.Name = text;
            model.Summary = L"OpenRouter model id";
            FillTargetFromModel(model, text, target);
            ok = true;
            break;
        }

        if (error != nullptr)
        {
            *error = L"unknown model '" + text + L"'. type ai models or ai models refresh";
        }
    } while (false);

    return ok;
}

bool AiModelCatalog::ModelFitsProvider(
    AiProviderKind provider,
    const AiUseTarget& model,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (provider == AiProviderKind::Disabled)
        {
            if (error != nullptr)
            {
                *error = L"ai use off does not take a model";
            }

            break;
        }

        if (provider == model.Provider)
        {
            ok = true;
            break;
        }

        if (provider == AiProviderKind::OpenRouter &&
            model.Model.find(L'/') != std::wstring::npos)
        {
            ok = true;
            break;
        }

        if (error != nullptr)
        {
            *error = L"model " + model.Model + L" is for " +
                ProviderDisplayName(model.Provider) + L", not " +
                ProviderDisplayName(provider);
        }
    } while (false);

    return ok;
}

std::vector<std::wstring> AiModelCatalog::CompletionTokens()
{
    std::vector<std::wstring> tokens;
    for (const PresetDef& def : kPresets)
    {
        AddUniqueToken(&tokens, def.Name);
    }

    for (const AliasDef& alias : kAliases)
    {
        AddUniqueToken(&tokens, alias.Name);
    }

    for (const std::wstring& modelToken : ModelCompletionTokens())
    {
        AddUniqueToken(&tokens, modelToken);
    }

    AddUniqueToken(&tokens, L"help");
    return tokens;
}

std::vector<std::wstring> AiModelCatalog::ModelCompletionTokens()
{
    std::vector<std::wstring> tokens;
    for (const CloudModelDef& def : kCurated)
    {
        AddUniqueToken(&tokens, def.Id);
    }

    std::vector<AiCloudModel> live = g_liveModels;
    std::sort(
        live.begin(),
        live.end(),
        [](const AiCloudModel& left, const AiCloudModel& right)
        {
            return left.Intelligence > right.Intelligence;
        });

    size_t added = 0;
    for (const AiCloudModel& model : live)
    {
        if (model.Intelligence <= 0.0 && added >= 40)
        {
            continue;
        }

        AddUniqueToken(&tokens, model.Id);
        ++added;
        if (added >= 40)
        {
            break;
        }
    }

    return tokens;
}

bool AiModelCatalog::DescribeToken(
    const std::wstring& token,
    std::wstring* syntax,
    std::wstring* summary)
{
    bool found = false;
    const std::wstring text = Trim(token);

    do
    {
        AiPresetInfo preset = {};
        if (FindPreset(text, &preset))
        {
            if (syntax != nullptr)
            {
                *syntax = L"ai use " + preset.Name;
            }

            if (summary != nullptr)
            {
                *summary = preset.Summary;
            }

            found = true;
            break;
        }

        std::wstring aliasId;
        if (FindAlias(text, &aliasId))
        {
            if (syntax != nullptr)
            {
                *syntax = L"ai use " + aliasId;
            }

            if (summary != nullptr)
            {
                *summary = L"alias for " + aliasId;
            }

            found = true;
            break;
        }

        AiCloudModel model = {};
        if (FindCurated(text, &model) || FindLive(text, &model))
        {
            if (syntax != nullptr)
            {
                *syntax = L"ai use " + model.Id;
            }

            if (summary != nullptr)
            {
                std::wstring line = model.Name.empty() ? model.Summary : model.Name;
                if (model.Intelligence > 0.0)
                {
                    line += L"  intel " + FormatScore(model.Intelligence);
                }

                if (line.empty())
                {
                    line = L"cloud model";
                }

                *summary = line;
            }

            found = true;
            break;
        }

        if (Same(text, L"refresh"))
        {
            if (syntax != nullptr)
            {
                *syntax = L"ai models refresh";
            }

            if (summary != nullptr)
            {
                *summary = L"fetch live OpenRouter model list";
            }

            found = true;
            break;
        }
    } while (false);

    return found;
}

bool AiModelCatalog::ParseOpenRouterModelsJson(
    const std::wstring& json,
    std::vector<AiCloudModel>* models,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (models == nullptr)
        {
            break;
        }

        models->clear();
        size_t data = json.find(L"\"data\"");
        if (data == std::wstring::npos)
        {
            if (error != nullptr)
            {
                *error = L"OpenRouter models JSON is missing a data array";
            }

            break;
        }

        size_t array = json.find(L'[', data);
        if (array == std::wstring::npos)
        {
            if (error != nullptr)
            {
                *error = L"OpenRouter models JSON data array is missing";
            }

            break;
        }

        size_t cursor = array + 1;
        for (;;)
        {
            std::wstring object;
            size_t end = 0;
            if (!ExtractNextJsonObject(json, cursor, &object, &end))
            {
                break;
            }

            cursor = end;
            std::wstring id;
            if (!ExtractObjectFieldString(object, L"id", &id) || ShouldSkipLiveId(id))
            {
                continue;
            }

            AiCloudModel model = {};
            model.Id = id;
            ExtractObjectFieldString(object, L"name", &model.Name);
            ExtractObjectFieldNumber(object, L"intelligence_index", &model.Intelligence);
            if (model.Name.empty())
            {
                model.Name = LastPathSegment(id);
            }

            model.Summary = model.Name;
            if (model.Intelligence > 0.0)
            {
                model.Summary += L"  intel " + FormatScore(model.Intelligence);
            }

            model.Live = true;
            models->push_back(model);
        }

        ok = true;
    } while (false);

    return ok;
}

void AiModelCatalog::SetLiveModels(const std::vector<AiCloudModel>& models)
{
    g_liveModels = models;
}

void AiModelCatalog::ClearLiveModels()
{
    g_liveModels.clear();
}

const std::vector<AiCloudModel>& AiModelCatalog::LiveModels()
{
    return g_liveModels;
}

size_t AiModelCatalog::LiveModelCount()
{
    return g_liveModels.size();
}

std::vector<AiCloudModel> AiModelCatalog::Search(const std::wstring& query)
{
    return UniqueSuffixMatches(Trim(query));
}

std::wstring AiModelCatalog::ModelsText(
    AiProviderKind provider,
    const std::wstring& model,
    const std::wstring& query)
{
    std::wstringstream stream;
    const std::wstring needle = Trim(query);

    AiPresetInfo current = {};
    stream << L"current: ";
    if (DetectPreset(provider, model, &current))
    {
        stream << current.Name << L"  ";
    }

    stream << ProviderDisplayName(provider);
    if (!model.empty())
    {
        stream << L" / " << model;
    }

    stream << L"\n";

    if (!needle.empty() && ToLower(needle) != L"refresh")
    {
        std::vector<AiCloudModel> matches = Search(needle);
        stream << L"matches for '" << needle << L"':\n";
        if (matches.empty())
        {
            stream << L"  (none). type ai models refresh if the id is new.\n";
        }
        else
        {
            size_t shown = 0;
            for (const AiCloudModel& item : matches)
            {
                stream << L"  " << item.Id;
                if (!item.Name.empty() && item.Name != item.Id)
                {
                    stream << L"  " << item.Name;
                }

                if (item.Intelligence > 0.0)
                {
                    stream << L"  intel " << FormatScore(item.Intelligence);
                }

                stream << L"\n";
                ++shown;
                if (shown >= 24)
                {
                    stream << L"  ...\n";
                    break;
                }
            }

            stream << L"type: ai use <id>\n";
        }

        return stream.str();
    }

    stream << L"presets:\n";
    for (const PresetDef& def : kPresets)
    {
        stream << L"  " << def.Name;
        stream << L"  " << ProviderDisplayName(def.Provider);
        if (def.Model != nullptr && def.Model[0] != L'\0')
        {
            stream << L" / " << def.Model;
        }

        stream << L"  " << (def.Remote ? L"remote" : L"local");
        stream << L"  " << def.Summary << L"\n";
    }

    stream << L"cloud models (curated " << CuratedAsOf() << L"):\n";
    for (const CloudModelDef& def : kCurated)
    {
        if (Same(def.Id, L"deepseek-chat") || Same(def.Id, L"deepseek-reasoner"))
        {
            continue;
        }

        stream << L"  " << def.Id << L"  " << def.Name;
        if (def.Intelligence > 0.0)
        {
            stream << L"  intel " << FormatScore(def.Intelligence);
        }

        stream << L"\n";
    }

    stream << L"aliases: opus, grok, gpt, sol, gemini, kimi, glm, qwen, oss, r1, v4\n";

    if (g_liveModels.empty())
    {
        stream << L"live catalog: (none). type ai models refresh to fetch OpenRouter.\n";
    }
    else
    {
        std::vector<AiCloudModel> live = g_liveModels;
        std::sort(
            live.begin(),
            live.end(),
            [](const AiCloudModel& left, const AiCloudModel& right)
            {
                return left.Intelligence > right.Intelligence;
            });

        stream << L"live OpenRouter (" << g_liveModels.size() << L" models, top by intelligence):\n";
        size_t shown = 0;
        for (const AiCloudModel& item : live)
        {
            if (item.Intelligence <= 0.0 && shown >= 10)
            {
                continue;
            }

            stream << L"  " << item.Id << L"  " << item.Name;
            if (item.Intelligence > 0.0)
            {
                stream << L"  intel " << FormatScore(item.Intelligence);
            }

            stream << L"\n";
            ++shown;
            if (shown >= 25)
            {
                break;
            }
        }
    }

    stream << L"pick with: ai use cloud | ai use grok | ai use <model-id>\n";
    return stream.str();
}

bool AiModelCatalog::SelfTest()
{
    bool ok = false;

    do
    {
        AiUseTarget target = {};
        std::wstring error;
        if (!Resolve(L"cloud", &target, &error) ||
            target.Provider != AiProviderKind::OpenRouter ||
            target.Model != L"anthropic/claude-opus-5")
        {
            break;
        }

        target = {};
        if (!Resolve(L"grok", &target, &error) || target.Model != L"x-ai/grok-4.6")
        {
            break;
        }

        target = {};
        if (!Resolve(L"grok-4.6", &target, &error) || target.Model != L"x-ai/grok-4.6")
        {
            break;
        }

        target = {};
        if (!Resolve(L"cheap", &target, &error) || target.Model != L"openai/gpt-oss-120b")
        {
            break;
        }

        target = {};
        if (!Resolve(L"private", &target, &error) || target.Provider != AiProviderKind::CodexCli)
        {
            break;
        }

        const std::wstring json =
            L"{\"data\":["
            L"{\"id\":\"anthropic/claude-opus-5\",\"name\":\"Claude Opus 5\","
            L"\"benchmarks\":{\"artificial_analysis\":{\"intelligence_index\":63.1}}},"
            L"{\"id\":\"x-ai/grok-4.6\",\"name\":\"Grok 4.6\","
            L"\"benchmarks\":{\"artificial_analysis\":{\"intelligence_index\":60.9}}},"
            L"{\"id\":\"openai/gpt-5.6-sol:batch\",\"name\":\"skip me\"},"
            L"{\"id\":\"google/gemini-3.1-flash-image\",\"name\":\"skip image\"}"
            L"]}";

        std::vector<AiCloudModel> parsed;
        if (!ParseOpenRouterModelsJson(json, &parsed, &error) || parsed.size() != 2)
        {
            break;
        }

        if (parsed[0].Id != L"anthropic/claude-opus-5" || parsed[0].Intelligence < 63.0)
        {
            break;
        }

        std::wstring syntax;
        std::wstring summary;
        if (!DescribeToken(L"opus", &syntax, &summary) || summary.find(L"anthropic/claude-opus-5") == std::wstring::npos)
        {
            break;
        }

        if (!DescribeToken(L"anthropic/claude-opus-5", &syntax, &summary) || summary.empty())
        {
            break;
        }

        target = {};
        if (!ResolveModel(L"gpt-5.6-sol", &target, &error) ||
            target.Model != L"openai/gpt-5.6-sol")
        {
            break;
        }

        target = {};
        if (ResolveModel(L"/verbose", &target, &error))
        {
            break;
        }

        AiUseTarget grok = {};
        AiUseTarget nativeDeepSeek = {};
        if (!Resolve(L"grok", &grok, &error) ||
            !ResolveModel(L"deepseek-chat", &nativeDeepSeek, &error))
        {
            break;
        }

        if (!ModelFitsProvider(AiProviderKind::OpenRouter, grok, &error) ||
            ModelFitsProvider(AiProviderKind::DeepSeek, grok, &error) ||
            !ModelFitsProvider(AiProviderKind::DeepSeek, nativeDeepSeek, &error) ||
            ModelFitsProvider(AiProviderKind::OpenRouter, nativeDeepSeek, &error) ||
            ModelFitsProvider(AiProviderKind::Disabled, grok, &error))
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}
