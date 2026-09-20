// Shared by the local console, remote client, and remote completion requests.
namespace
{
    bool CompletionHelpToken(const std::wstring& value)
    {
        const std::wstring token = HintLower(value);
        return token == L"help" || token == L"?" || token == L"/?" || token == L"-?";
    }

    bool CompletionOption(const std::wstring& token)
    {
        return !token.empty() && (token[0] == L'/' || token[0] == L'-');
    }

    void AddUniqueToken(std::vector<std::wstring>* out, const wchar_t* token)
    {
        if (token != nullptr && token[0] != L'\0' && std::find(out->begin(), out->end(), token) == out->end())
        {
            out->push_back(token);
        }
    }

    void AddHintTableTokens(std::vector<std::wstring>* out, const CompletionHint* tokens, size_t count)
    {
        for (size_t index = 0; index < count; ++index)
        {
            AddUniqueToken(out, tokens[index].Token);
        }
    }

    std::vector<std::wstring> CompletionTopicArgs(std::vector<std::wstring> args)
    {
        // Consume wrappers iteratively so hostile input cannot recurse indefinitely.
        while (args.size() > 1)
        {
            if (HintLower(args[0]) == L"help")
            {
                args.erase(args.begin());
            }
            else if (HintCanonicalCommand(args[0]) == L"ai" && args.size() > 2 &&
                (HintLower(args[1]) == L"explain" || HintLower(args[1]) == L"analyze" || HintLower(args[1]) == L"annotate"))
            {
                args.erase(args.begin(), args.begin() + 2);
            }
            else if (CompletionHelpToken(args[1]) && HintCanonicalCommand(args[0]) != L"!timeline")
            {
                args.erase(args.begin() + 1);
            }
            else
            {
                break;
            }
        }
        return args;
    }

    bool CompletionTakesValue(const CompletionHint& hint)
    {
        if (hint.Syntax == nullptr || !CompletionOption(hint.Token))
        {
            return false;
        }
        const std::wstring marker = std::wstring(hint.Token) + L" <";
        return std::wstring(hint.Syntax).find(marker) != std::wstring::npos;
    }

    std::wstring PendingCompletionOption(const std::vector<std::wstring>& args)
    {
        std::wstring pending;
        for (size_t index = 1; index < args.size(); ++index)
        {
            if (!pending.empty())
            {
                pending.clear();
                continue;
            }
            const std::vector<std::wstring> before(args.begin(), args.begin() + index);
            CompletionHint hint = {};
            if (FindCompletionTokenHint(HintCanonicalCommand(args[0]), before, args[index], &hint) &&
                CompletionTakesValue(hint))
            {
                pending = HintLower(args[index]);
            }
        }
        return pending;
    }

    void KeepCompletionTokens(std::vector<std::wstring>* out, std::initializer_list<const wchar_t*> allowed)
    {
        out->erase(std::remove_if(out->begin(), out->end(), [&](const std::wstring& token)
        {
            return std::none_of(allowed.begin(), allowed.end(), [&](const wchar_t* item)
            {
                return SameToken(item, token);
            });
        }), out->end());
    }

    void KeepCompletionOptions(std::vector<std::wstring>* out)
    {
        out->erase(std::remove_if(out->begin(), out->end(), [](const std::wstring& token)
        {
            return !CompletionOption(token) && !CompletionHelpToken(token);
        }), out->end());
    }
}

std::vector<std::wstring> CollectCompletionCandidates(const std::vector<std::wstring>& argsBefore)
{
    std::vector<std::wstring> out;
    std::vector<std::wstring> args = CompletionTopicArgs(argsBefore);
    do
    {
        if (args.empty() || (args.size() == 1 && HintLower(args[0]) == L"help"))
        {
            for (const CommandInfo& info : CommandRegistry::Commands())
            {
                AddUniqueToken(&out, info.Name);
            }
            if (!args.empty())
            {
                AddUniqueToken(&out, L"all");
            }
            break;
        }

        const std::wstring original = HintLower(args[0]);
        const std::wstring command = HintCanonicalCommand(args[0]);
        const CompletionCommandTable* table = FindCommandTable(command);
        if (table == nullptr)
        {
            // Registered DbgEng commands still have local routing help.
            if (CommandRegistry::Find(args[0]) != nullptr && args.size() == 1)
            {
                AddUniqueToken(&out, L"help");
            }
            break;
        }
        if (original == L"!unloaded" || original == L"!piddb" || original == L"!cihash")
        {
            args[0] = L"!mapper";
            args.insert(args.begin() + 1, original.substr(1));
        }
        const std::wstring first = args.size() > 1 ? HintLower(args[1]) : L"";
        const std::wstring second = args.size() > 2 ? HintLower(args[2]) : L"";
        if (args.size() > 2 && CompletionHelpToken(args.back()))
        {
            break;
        }
        const std::wstring scopeKey = SelectScopeKey(command, args);
        const CompletionScopeTable* scope = FindScopeTable(*table, scopeKey);
        if (scope != nullptr)
        {
            AddHintTableTokens(&out, scope->Tokens, scope->TokenCount);
        }

        const std::wstring pending = PendingCompletionOption(args);
        if (!pending.empty())
        {
            out.clear();
            if (command == L"!diff" && pending == L"/domain")
            {
                AddHintTableTokens(&out, kDiffDomainTokens, std::size(kDiffDomainTokens));
            }
            else if (command == L"!diff" && pending == L"/risk")
            {
                AddHintTableTokens(&out, kDiffRiskTokens, std::size(kDiffRiskTokens));
            }
            break;
        }

        if (command == L"!kmon")
        {
            if (args.size() == 1)
            {
                AddHintTableTokens(&out, kKmonOptTokens, std::size(kKmonOptTokens));
            }
            else if (first == L"add" || first == L"remove")
            {
                KeepCompletionTokens(&out, {L"/pid", L"/name", L"/driver", L"help"});
                if (args.size() > 2)
                {
                    out.clear();
                }
            }
            else if (first == L"iotrace")
            {
                if (args.size() == 2)
                {
                    KeepCompletionTokens(&out, {L"off", L"status", L"help"});
                }
                else if (args.size() > 3 || second == L"off" || second == L"status")
                {
                    out.clear();
                }
                else
                {
                    KeepCompletionTokens(&out, {L"on", L"help"});
                }
            }
            else if (first == L"layouts")
            {
                if (std::none_of(args.begin() + 2, args.end(), [](const std::wstring& token)
                {
                    return HintLower(token) == L"/pid";
                }))
                {
                    out.erase(std::remove(out.begin(), out.end(), L"/initial"), out.end());
                }
            }
            if (first == L"cases" || first == L"surfaces" || first == L"layouts" || first == L"diff")
            {
                for (size_t index = 2; index < args.size(); ++index)
                {
                    const std::vector<std::wstring> before(args.begin(), args.begin() + index);
                    CompletionHint hint = {};
                    if (FindCompletionTokenHint(command, before, args[index], &hint) && CompletionOption(args[index]))
                    {
                        out.erase(std::remove_if(out.begin(), out.end(), [&](const std::wstring& token)
                        {
                            return HintLower(token) == HintLower(args[index]);
                        }), out.end());
                        if (CompletionTakesValue(hint) && index + 1 < args.size())
                        {
                            ++index;
                        }
                    }
                }
            }
        }
        else if (command == L"!ti")
        {
            if (first == L"add" || first == L"remove")
            {
                KeepCompletionTokens(&out, {L"/pid", L"/name", L"help"});
                if (args.size() > 2)
                {
                    out.clear();
                }
            }
            else if (first == L"by" && args.size() > 2)
            {
                KeepCompletionTokens(&out, {L"help"});
            }
        }
        else if (command == L"!timeline")
        {
            if (args.size() == 1)
            {
                KeepCompletionTokens(&out, {L"dashboard", L"reset", L"help"});
            }
            else if (scopeKey.empty())
            {
                out.clear();
            }
            else if (first == L"help" && args.size() > 2)
            {
                out.clear();
            }
            else if (first == L"live" && args.size() > 2)
            {
                if (second == L"on" || second == L"start")
                {
                    KeepCompletionTokens(&out, {L"/capacity", L"help"});
                }
                else if (second == L"drain")
                {
                    KeepCompletionTokens(&out, {L"/limit", L"help"});
                }
                else
                {
                    KeepCompletionTokens(&out, {L"help"});
                }
            }
            else if (first == L"ingest" && second == L"ti" && args.size() > 3)
            {
                KeepCompletionOptions(&out);
            }
        }
        else if (command == L"!diff")
        {
            out.erase(std::remove_if(out.begin(), out.end(), [](const std::wstring& token)
            {
                return !CompletionOption(token) && token != L"baseline" && token != L"help";
            }), out.end());
            if (args.size() > 1)
            {
                KeepCompletionOptions(&out);
            }
        }
        else if (command == L"!snapshot")
        {
            if (first == L"baseline" || first == L"save")
            {
                KeepCompletionTokens(&out, {L"/all", L"/name", L"/memory", L"help"});
                if (first == L"save")
                {
                    out.erase(std::remove(out.begin(), out.end(), L"/memory"), out.end());
                }
            }
            else if (first == L"show")
            {
                KeepCompletionTokens(&out, {L"/domains", L"/no-domains", L"/warnings", L"help"});
                if (args.size() == 2)
                {
                    AddUniqueToken(&out, L"baseline");
                }
            }
            else
            {
                KeepCompletionTokens(&out, {L"baseline", L"save", L"show", L"help"});
            }
        }
        else if (command == L"!driver")
        {
            out.erase(std::remove(out.begin(), out.end(), L"/dispatch"), out.end());
            out.erase(std::remove(out.begin(), out.end(), L"/devices"), out.end());
            if (first == L"object")
            {
                AddHintTableTokens(&out, kDrvobjTokens, std::size(kDrvobjTokens));
            }
            else if (!first.empty())
            {
                KeepCompletionOptions(&out);
                if (args.size() == 2 && (first == L"list" || first == L"integrity"))
                {
                    AddUniqueToken(&out, L"all");
                }
            }
        }
        else if (command == L"!minifilter")
        {
            if (first == L"list" || first == L"show")
            {
                KeepCompletionTokens(&out, {L"/json", L"help"});
            }
            else if (first == L"disable-all" || first == L"enable-all")
            {
                KeepCompletionOptions(&out);
            }
            else if (first == L"disable" || first == L"enable" || first == L"irp" || first == L"status")
            {
                if (args.size() == 2 || args.size() > 3)
                {
                    KeepCompletionOptions(&out);
                }
                if (first == L"irp" || first == L"status")
                {
                    out.erase(std::remove_if(out.begin(), out.end(), [](const std::wstring& token)
                    {
                        return token == L"/pre" || token == L"/post" || token == L"/both";
                    }), out.end());
                }
            }
        }
        else if (command == L"!fwtable")
        {
            if (first == L"provider" && args.size() > 2)
            {
                out.clear();
            }
        }
        else if (command == L"!byovd")
        {
            if (first == L"fixture" && args.size() > 2)
            {
                KeepCompletionTokens(&out, {L"help"});
            }
            else if (first == L"scan")
            {
                KeepCompletionOptions(&out);
            }
        }
        else if (command == L"!vad" || command == L"!mapper" || command == L"!payload" || command == L"!module")
        {
            if (args.size() > 1)
            {
                KeepCompletionOptions(&out);
                if (command == L"!module" && first == L"integrity" && args.size() == 2)
                {
                    AddUniqueToken(&out, L"all");
                }
            }
        }
        else if (command == L"ai")
        {
            if (args.size() > 1 && scopeKey.empty())
            {
                out.clear();
            }
            else if (first == L"use" || first == L"models" || first == L"model" || (first == L"config" && second == L"model"))
            {
                const auto tokens = first == L"use" && args.size() == 2
                    ? AiModelCatalog::CompletionTokens() : AiModelCatalog::ModelCompletionTokens();
                for (const auto& token : tokens)
                {
                    AddUniqueToken(&out, token.c_str());
                }
            }
            else if (first == L"write" && args.size() > 2)
            {
                KeepCompletionTokens(&out, {L"confirm", L"help"});
            }
        }
        else if (command == L"mcp" || command == L"remote")
        {
            if (args.size() > 1 && first != L"on" && first != L"start" &&
                first != L"client-setup" && first != L"setup" && first != L"connect")
            {
                KeepCompletionTokens(&out, {L"help"});
            }
            if (args.size() > 2 && (first == L"client-setup" || first == L"setup" || first == L"connect"))
            {
                out.clear();
            }
        }
        else if (args.size() > 1 && scopeKey.empty())
        {
            KeepCompletionOptions(&out);
            if (scope != nullptr && (scope->Tokens == kHelpOnlyTokens || scope->Tokens == kProcessOptTokens ||
                scope->Tokens == kVtopTokens || scope->Tokens == kSearchTokens))
            {
                // These parsers consume switches only before the address/data.
                out.clear();
            }
        }
    } while (false);

    std::sort(out.begin(), out.end(), [](const std::wstring& left, const std::wstring& right)
    {
        const std::wstring lowerLeft = HintLower(left);
        const std::wstring lowerRight = HintLower(right);
        return lowerLeft == lowerRight ? left < right : lowerLeft < lowerRight;
    });
    return out;
}

CompletionContext BuildCompletionContext(const std::wstring& line, size_t cursor)
{
    CompletionContext context = {};
    cursor = std::min(cursor, line.size());
    if (line.find(L'\0') != std::wstring::npos)
    {
        context.TokenStart = cursor;
        context.TokenEnd = cursor;
        return context;
    }
    size_t index = 0;
    while (index < line.size())
    {
        if (std::iswspace(line[index]) != 0)
        {
            if (index >= cursor)
            {
                break;
            }
            ++index;
            continue;
        }
        const size_t start = index;
        bool quoted = false;
        bool hasQuote = false;
        std::wstring token;
        while (index < line.size())
        {
            const wchar_t ch = line[index];
            if (ch == L'"')
            {
                quoted = !quoted;
                hasQuote = true;
            }
            else if (!quoted && std::iswspace(ch) != 0)
            {
                break;
            }
            else
            {
                token.push_back(ch);
            }
            ++index;
        }
        if (cursor <= index)
        {
            context.TokenStart = start;
            context.TokenEnd = index;
            context.Prefix = line.substr(start, cursor - start);
            context.CanComplete = !hasQuote;
            return context;
        }
        context.ArgsBefore.push_back(token);
    }
    context.TokenStart = cursor;
    context.TokenEnd = cursor;
    context.CanComplete = true;
    return context;
}

bool ApplyTabCompletion(std::wstring* line, size_t* cursor, bool* listed, std::wstring* listing)
{
    bool changed = false;
    if (listed != nullptr)
    {
        *listed = false;
    }
    if (listing != nullptr)
    {
        listing->clear();
    }
    do
    {
        if (line == nullptr || cursor == nullptr)
        {
            break;
        }
        *cursor = std::min(*cursor, line->size());
        const CompletionContext context = BuildCompletionContext(*line, *cursor);
        if (!context.CanComplete)
        {
            break;
        }
        const auto candidates = CollectCompletionCandidates(context.ArgsBefore);
        std::vector<std::wstring> matches;
        const std::wstring prefix = HintLower(context.Prefix);
        for (const auto& token : candidates)
        {
            if (HintLower(token).rfind(prefix, 0) == 0)
            {
                matches.push_back(token);
            }
        }
        if (matches.empty())
        {
            break;
        }
        std::wstring replacement = matches[0];
        if (matches.size() > 1)
        {
            for (size_t index = 1; index < matches.size(); ++index)
            {
                size_t length = 0;
                while (length < replacement.size() && length < matches[index].size() &&
                    std::towlower(replacement[length]) == std::towlower(matches[index][length]))
                {
                    ++length;
                }
                replacement.resize(length);
            }
            // dD/dd and dS/ds are distinct commands. Never rewrite an ambiguous
            // case-sensitive token merely because the folded prefix matches.
            if (replacement.size() <= prefix.size())
            {
                const auto topics = CompletionTopicArgs(context.ArgsBefore);
                if (listing != nullptr)
                {
                    *listing = BuildCompletionListing(matches, topics.empty() ? L"" : HintCanonicalCommand(topics[0]), topics);
                }
                if (listed != nullptr)
                {
                    *listed = true;
                }
                break;
            }
        }
        line->replace(context.TokenStart, context.TokenEnd - context.TokenStart, replacement);
        *cursor = context.TokenStart + replacement.size();
        if (matches.size() == 1 && *cursor == line->size())
        {
            line->insert(*cursor, 1, L' ');
            ++(*cursor);
        }
        changed = true;
    } while (false);
    return changed;
}
