#include "../user/TemporalFactStore.h"
#include "../user/McpJson.h"
#include <filesystem>
#include <iostream>

namespace
{
    EvidenceBundle Fixture(uint64_t ordinal)
    {
        EvidenceBundle b;
        b.Acquisition = L"local_user_reader";
        b.CollectionId = L"synthetic_collection";
        b.Origin = {std::wstring(32, L'a'), std::wstring(31, L'b') + std::to_wstring(ordinal), std::wstring(32, L'c'), 7};
        b.CaptureStartedMs = 100 + ordinal * 20;
        b.CaptureEndedMs = b.CaptureStartedMs + 10;
        b.ReferenceConsistent = true;
        auto& r = b.Receipt.Reference;
        r.Id = ordinal;
        r.Context.Identity.BootId = b.Origin.LocalBootId;
        r.Context.Identity.ProcessId = 55;
        r.Context.Identity.CreateTime = 50;
        r.Context.MonotonicMs = b.CaptureStartedMs;
        r.Context.ArrivalMonotonicMs = 1000 - ordinal;
        r.Context.ArrivalSequence = 10 - ordinal;
        r.Context.Source = L"owned_synthetic_clock_fixture";
        r.Context.DependencyGroup = L"fixture_memory";
        r.Context.MappingGeneration = 42;
        r.Context.PfnKnown = true;
        r.Context.Pfn = 99;
        r.Address = r.Root = 0x11000;
        r.Role = L"tls_callback";
        r.SlotStable = true;
        b.Receipt.Disposition = L"current";
        b.Spans.push_back({r.Address, 32, L"target_head", L"valid", std::vector<uint8_t>(32, 0x90)});
        return b;
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc == 3 && std::wstring(argv[1]) == L"--fixtures")
    {
        for (uint64_t i = 1; i <= 3; ++i)
        {
            if (!SaveEvidenceBundle((std::filesystem::path(argv[2]) / (std::to_wstring(i) + L".kncase")).wstring(), Fixture(i), nullptr)) { return 1; }
        }
        return 0;
    }
    if (argc == 3 && std::wstring(argv[1]) == L"--parse")
    {
        EvidenceBundle b;
        return LoadEvidenceBundle(argv[2], &b, nullptr) ? 0 : 1;
    }
    if (argc >= 4 && (std::wstring(argv[1]) == L"--cancel-load" || std::wstring(argv[1]) == L"--cancel-query" ||
        std::wstring(argv[1]) == L"--zero-load-budget"))
    {
        const std::wstring action = argv[1];
        std::atomic<bool> cancel{true};
        const auto store = LoadTemporalFactStore(std::vector<std::wstring>(argv + 2, argv + argc),
            action == L"--cancel-load" ? &cancel : nullptr, action == L"--zero-load-budget" ? 0 : 5000);
        TemporalFactQuery query;
        if (action == L"--cancel-query") { query.Cancellation = &cancel; query.TimeBudgetMs = 0; }
        const auto page = QueryTemporalFacts(store, query);
        std::cout << mcpjson::WideToUtf8(TemporalFactsJson(store, query, page)) << '\n';
        return 0;
    }
    if (argc < 8 || std::wstring(argv[1]) != L"--query") { return 2; }
    TemporalFactQuery query;
    query.MaximumGapMs = std::stoull(argv[2]);
    query.Limit = static_cast<size_t>(std::stoull(argv[3]));
    query.Cursor = argv[4];
    query.TimeBudgetMs = std::stoull(argv[5]);
    const std::vector<std::wstring> paths(argv + 6, argv + argc);
    const auto store = LoadTemporalFactStore(paths);
    const auto page = QueryTemporalFacts(store, query);
    std::cout << mcpjson::WideToUtf8(TemporalFactsJson(store, query, page)) << '\n';
    return page.Status == L"ok" ? 0 : 1;
}
