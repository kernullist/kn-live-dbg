#pragma once

#include <cstdint>
#include <string>
#include <vector>

enum class AiCapabilityCost : uint32_t
{
    Cheap = 0,
    Expensive = 1,
    ExpensiveIfDeep = 2
};

struct AiCapabilityToolDef
{
    const wchar_t* Name;
    const wchar_t* Description;
    const wchar_t* Args;
    const wchar_t* RanCommand;
    AiCapabilityCost Cost;
};

struct AiPlaybookStepDef
{
    const wchar_t* Tool;
    const wchar_t* ArgsJson;
};

struct AiPlaybookDef
{
    const wchar_t* Name;
    const wchar_t* Aliases;
    const wchar_t* Summary;
    const AiPlaybookStepDef* Steps;
    size_t StepCount;
    bool NeedsAddress;
};

const AiCapabilityToolDef* AiCapabilityTools(size_t* count);
const AiCapabilityToolDef* FindAiCapabilityTool(const std::wstring& name);
bool IsAiCapabilityCatalogTool(const std::wstring& name);
AiCapabilityCost GetAiCapabilityToolCost(const std::wstring& name);
const wchar_t* AiCapabilityCostLabel(AiCapabilityCost cost);
const AiPlaybookDef* AiCapabilityPlaybooks(size_t* count);
const AiPlaybookDef* FindAiPlaybook(const std::wstring& query);
std::wstring SubstituteAiPlaybookPlaceholders(
    const std::wstring& argsJson,
    const std::wstring& address);
std::wstring BuildAiCapabilityPlannerPrompt(
    const std::wstring& query,
    const std::wstring& sessionHints);
std::wstring ApplyAiSessionContext(
    const std::wstring& query,
    uint32_t lastPid,
    const std::wstring& lastImage,
    const std::wstring& lastAddress,
    const std::wstring& lastDumpPath);
bool IsAiConceptualQuery(const std::wstring& query);
bool StripAiGoalOptions(std::wstring* query, bool* verbose);
bool AiCapabilityCatalogSelfTest();
