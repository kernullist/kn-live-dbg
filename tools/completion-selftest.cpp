#include "../user/CommandRegistry.h"
#include "../user/CompletionHints.h"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

int main()
{
    size_t passed = 0;
    size_t failed = 0;
    auto check = [&](bool condition, const char* name)
    {
        if (condition)
        {
            ++passed;
        }
        else
        {
            ++failed;
            std::cerr << "[completion.selftest] FAIL " << name << '\n';
        }
    };
    auto has = [](const std::vector<std::wstring>& args, const wchar_t* token)
    {
        const auto candidates = CollectCompletionCandidates(args);
        return std::find(candidates.begin(), candidates.end(), token) != candidates.end();
    };
    check(has({L"!kmon", L"iotrace"}, L"off") && has({L"!kmon", L"iotrace"}, L"status") &&
        !has({L"!kmon", L"iotrace"}, L"on"), "iotrace direct stop/status");
    check(has({L"!kmon", L"iotrace", L"driver"}, L"on") &&
        !has({L"!kmon", L"iotrace", L"driver"}, L"off"), "iotrace driver accepts on only");
    check(!has({L"!snapshot", L"save", L"file.json"}, L"/memory") &&
        has({L"!snapshot", L"baseline"}, L"/memory"), "memory-only baseline is not a save option");
    check(!has({L"remote", L"on", L"--bind"}, L"--peer") &&
        has({L"remote", L"on", L"--bind", L"127.0.0.1"}, L"--peer"), "listener address value slot");
    check(!has({L"!ti", L"watch"}, L"/pid") && !has({L"!ti", L"add"}, L"/throttle"), "TI action-specific options");
    check(!has({L"!kmon", L"start", L"/name", L"!ti"}, L"/ring"), "argument text is not a nested command");
    check(!has({L"!kmon", L"cases", L"/json"}, L"/json") &&
        has({L"!kmon", L"cases", L"/role", L"/json"}, L"/json"), "consumed option versus identical value");
    check(CollectCompletionCandidates({L"!kmon", L"unknown"}).empty() &&
        CollectCompletionCandidates({L"ai", L"investigate"}).empty(), "unknown action does not restart root completion");

    for (const auto& info : CommandRegistry::Commands())
    {
        CompletionCommandGuide guide = {};
        check(FindCompletionCommandGuide(info.Name, {}, &guide) && guide.Syntax != nullptr &&
            guide.Summary != nullptr && guide.Summary[0] != L'\0', "registered command guide");
        const auto root = CollectCompletionCandidates({info.Name});
        for (const auto& token : root)
        {
            CompletionHint hint = {};
            check(FindCompletionTokenHint(info.Name, {info.Name}, token, &hint) &&
                hint.Summary != nullptr && hint.Summary[0] != L'\0', "root candidate description");
        }
    }

    const auto afterQuote = BuildCompletionContext(L"!kmon start /log \"C:\\my logs\" /lay", 1000);
    check(afterQuote.CanComplete && afterQuote.ArgsBefore == std::vector<std::wstring>
        {L"!kmon", L"start", L"/log", L"C:\\my logs"} && afterQuote.Prefix == L"/lay", "quoted path tokenization");
    const auto insideQuote = BuildCompletionContext(L"ai chat \"!kmon /pid\"", 16);
    check(!insideQuote.CanComplete, "quoted command text is opaque");
    const auto emptyValue = BuildCompletionContext(L"!kmon start /name \"\" /lay", 1000);
    check(emptyValue.ArgsBefore.size() == 4 && emptyValue.ArgsBefore.back().empty(), "empty quoted value is retained");

    // Exercise every cursor position, including oversized cursors, on generated
    // input. The assertions validate edits against the original token bounds.
    uint32_t random = 0x7202026u;
    const std::wstring alphabet = L" abcd!/?-\"\t0123";
    const std::vector<std::wstring> seeds =
    {
        L"", L"help ", L"ai chat ", L"!kmon start ", L"!kmon cases ",
        L"!kmon start /log ", L"!diff baseline /domain ", L"remote on --bind ",
        L"!callbacks disable ", L"help !timeline ", L"dD ", L"ai explain !vad "
    };
    for (size_t trial = 0; trial < 300; ++trial)
    {
        std::wstring original = seeds[trial % seeds.size()];
        for (size_t index = 0; index < trial % 37; ++index)
        {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            original.push_back(alphabet[random % alphabet.size()]);
        }
        for (size_t pos = 0; pos <= original.size() + 1; ++pos)
        {
            const auto context = BuildCompletionContext(original, pos);
            const size_t bounded = std::min(pos, original.size());
            check(context.TokenStart <= bounded && bounded <= context.TokenEnd &&
                context.TokenEnd <= original.size(), "cursor token bounds");
            std::wstring line = original;
            size_t cursor = pos;
            bool listed = true;
            std::wstring listing = L"stale";
            const bool changed = ApplyTabCompletion(&line, &cursor, &listed, &listing);
            check(cursor <= line.size(), "completion cursor bounds");
            if (!context.CanComplete)
            {
                check(!changed && !listed && line == original && listing.empty(), "quoted input remains unchanged");
            }
            if (changed)
            {
                const auto suffix = original.substr(context.TokenEnd);
                check(line.substr(0, context.TokenStart) == original.substr(0, context.TokenStart) &&
                    (suffix.empty() || (line.size() >= suffix.size() && line.substr(line.size() - suffix.size()) == suffix)),
                    "completion preserves surrounding text");
            }
        }
    }
    std::wstring line = L"REM";
    size_t cursor = std::numeric_limits<size_t>::max();
    check(ApplyTabCompletion(&line, &cursor, nullptr, nullptr) && line == L"remote ", "case-insensitive completion with clamped cursor");
    check(!ApplyTabCompletion(nullptr, &cursor, nullptr, nullptr), "null line");
    std::cout << "[completion.selftest] passed=" << passed << " failed=" << failed << '\n';
    return failed == 0 ? 0 : 1;
}
