#pragma once

#include <string>
#include <vector>

using CommandRegistryColor = unsigned short;
using CommandRegistryColorPrinter = void (*)(const std::wstring& text, CommandRegistryColor color);

enum class CommandSupport
{
    Native,
    Alias,
    DbgEng,
    Extension
};

struct CommandInfo
{
    const wchar_t* Name;
    const wchar_t* Canonical;
    const wchar_t* Group;
    const wchar_t* Summary;
    CommandSupport Support;
};

class CommandRegistry
{
public:
    static void SetColorPrinter(CommandRegistryColorPrinter printer);
    static std::wstring Normalize(const std::wstring& command);
    static const CommandInfo* Find(const std::wstring& command);
    static bool IsKnown(const std::wstring& command);
    static const std::vector<CommandInfo>& Commands();
    static void PrintSummary(bool includeDbgEng);
    static void PrintCommandStatus(const std::wstring& command);
};
