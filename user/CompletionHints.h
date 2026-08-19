#pragma once

#include <string>
#include <vector>

struct CompletionHint
{
    const wchar_t* Token;
    const wchar_t* Syntax;
    const wchar_t* Summary;
};

struct CompletionCommandGuide
{
    const wchar_t* Command;
    const wchar_t* Syntax;
    const wchar_t* Summary;
};

bool FindCompletionCommandGuide(
    const std::wstring& command,
    const std::vector<std::wstring>& argsBefore,
    CompletionCommandGuide* guide);

bool FindCompletionTokenHint(
    const std::wstring& command,
    const std::vector<std::wstring>& argsBefore,
    const std::wstring& token,
    CompletionHint* hint);

// Annotated Tab listing: command summary + full usage, then each match
// with its syntax and description. Root listings with many matches stay
// one line per command (name + summary).
std::wstring BuildCompletionListing(
    const std::vector<std::wstring>& matches,
    const std::wstring& command,
    const std::vector<std::wstring>& argsBefore);
