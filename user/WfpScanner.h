#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct WfpRecord
{
    std::wstring Kind;
    std::wstring Name;
    std::wstring Description;
    std::wstring Key;
    std::wstring LayerKey;
    std::wstring LayerName;
    std::wstring SubLayerKey;
    std::wstring SubLayerName;
    std::wstring ProviderKey;
    std::wstring ProviderName;
    std::wstring ProviderService;
    std::wstring ActionText;
    std::wstring ActionKey;
    std::wstring CalloutKey;
    std::wstring CalloutName;
    std::wstring FlagsText;
    std::wstring WeightText;
    std::wstring ConditionsText;
    std::wstring AppIdText;
    std::wstring Notes;
    uint64_t Id = 0;
    uint32_t Flags = 0;
    uint32_t CalloutId = 0;
    uint32_t LayerId = 0;
    uint32_t Action = 0;
    uint32_t NumConditions = 0;
    uint16_t SubLayerWeight = 0;
    bool HasProvider = false;
    bool HasCallout = false;
    bool HasId = false;
    bool HasLayerId = false;
    bool HasCalloutId = false;
    bool HasSubLayerWeight = false;
    bool HasAppIdCondition = false;
};

struct WfpScanResult
{
    std::vector<WfpRecord> Records;
    std::vector<std::wstring> Warnings;
    std::wstring Scope;
    bool EngineOpened = false;
};

class WfpScanner
{
public:
    enum class Scope
    {
        Providers,
        SubLayers,
        Callouts,
        Filters,
        Layers
    };

    struct Options
    {
        Scope Target = Scope::Callouts;
        std::wstring ModuleFilter;
        std::wstring LayerFilter;
        std::wstring ProviderFilter;
    };

    WfpScanner();

    bool Scan(const Options& options, WfpScanResult* result, std::wstring* error);
};

std::wstring BuildWfpJson(const WfpScanResult& result);
