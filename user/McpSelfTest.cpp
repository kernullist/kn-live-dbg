#include "McpSelfTest.h"

#include "McpServer.h"

#include <algorithm>
#include <iostream>
#include <set>
#include <string>
#include <vector>

namespace
{
    struct SelfTestContext
    {
        uint32_t Passed = 0;
        uint32_t Failed = 0;
    };

    void Check(
        SelfTestContext* context,
        bool condition,
        const wchar_t* name)
    {
        do
        {
            if (context == nullptr)
            {
                break;
            }

            if (condition)
            {
                ++context->Passed;
                std::wcout << L"[mcp.selftest] PASS " << name << L"\n";
            }
            else
            {
                ++context->Failed;
                std::wcerr << L"[mcp.selftest] FAIL " << name << L"\n";
            }
        } while (false);
    }

    bool HasArgument(
        const McpToolCatalogEntry& entry,
        const std::wstring& name)
    {
        return std::find(entry.Arguments.begin(), entry.Arguments.end(), name) != entry.Arguments.end();
    }

    bool HasExactlyArguments(
        const McpToolCatalogEntry& entry,
        const std::vector<std::wstring>& expected)
    {
        bool ok = true;

        do
        {
            if (entry.Arguments.size() != expected.size())
            {
                ok = false;
                break;
            }

            for (const std::wstring& name : expected)
            {
                if (!HasArgument(entry, name))
                {
                    ok = false;
                    break;
                }
            }
        } while (false);

        return ok;
    }

    bool CatalogContains(
        const std::vector<McpToolCatalogEntry>& entries,
        const std::wstring& name)
    {
        bool found = false;
        for (const McpToolCatalogEntry& entry : entries)
        {
            if (entry.Name == name)
            {
                found = true;
                break;
            }
        }
        return found;
    }

    bool CheckReadOnlyTool(
        SelfTestContext* context,
        const std::wstring& name,
        const std::vector<std::wstring>& expectedArgs)
    {
        bool ok = false;

        do
        {
            McpToolCatalogEntry entry = {};
            if (!FindMcpToolCatalogEntry(name, &entry))
            {
                Check(context, false, L"mcp-tool-present");
                break;
            }

            std::wstring readOnlyName = L"mcp-readonly-" + name;
            Check(context, entry.ReadOnly, readOnlyName.c_str());

            std::wstring argsName = L"mcp-args-" + name;
            Check(context, HasExactlyArguments(entry, expectedArgs), argsName.c_str());
            ok = entry.ReadOnly && HasExactlyArguments(entry, expectedArgs);
        } while (false);

        return ok;
    }
}

int RunMcpToolCatalogSelfTest()
{
    int exitCode = 1;
    SelfTestContext context = {};

    do
    {
        std::vector<McpToolCatalogEntry> catalog = BuildMcpToolCatalogSnapshot();
        Check(&context, !catalog.empty(), L"catalog-not-empty");

        std::set<std::wstring> names;
        bool unique = true;
        for (const McpToolCatalogEntry& entry : catalog)
        {
            if (!names.insert(entry.Name).second)
            {
                unique = false;
            }
        }
        Check(&context, unique, L"catalog-unique-tool-names");

        CheckReadOnlyTool(&context, L"timeline.status", {});
        CheckReadOnlyTool(
            &context,
            L"timeline.query",
            {L"source", L"domain", L"pid", L"limit", L"order"});
        CheckReadOnlyTool(
            &context,
            L"timeline.export",
            {L"source", L"domain", L"pid", L"limit", L"order"});
        CheckReadOnlyTool(
            &context,
            L"timeline.reconcile",
            {L"path", L"snapshot", L"source", L"domain", L"pid", L"limit"});
        CheckReadOnlyTool(
            &context,
            L"graph.query",
            {L"source", L"domain", L"image", L"pid", L"limit", L"order"});

        Check(&context, !CatalogContains(catalog, L"timeline.clear"), L"timeline-clear-not-mcp-tool");
        Check(&context, !CatalogContains(catalog, L"timeline.ingest"), L"timeline-ingest-not-mcp-tool");
        Check(&context, !CatalogContains(catalog, L"timeline.live"), L"timeline-live-not-mcp-tool");
        Check(&context, !CatalogContains(catalog, L"timeline.start"), L"timeline-start-not-mcp-tool");
        Check(&context, !CatalogContains(catalog, L"timeline.stop"), L"timeline-stop-not-mcp-tool");
        Check(&context, !CatalogContains(catalog, L"timeline.drain"), L"timeline-drain-not-mcp-tool");

        McpToolCatalogEntry writeEntry = {};
        bool writeToolOk =
            FindMcpToolCatalogEntry(L"memory.write_virtual", &writeEntry) &&
            !writeEntry.ReadOnly;
        Check(&context, writeToolOk, L"write-tools-marked-write");

        std::wcout << L"[mcp.selftest] passed=" << context.Passed
                   << L" failed=" << context.Failed << L"\n";
        if (context.Failed == 0)
        {
            exitCode = 0;
        }
    } while (false);

    return exitCode;
}
