#include "McpSelfTest.h"

#include "EtwScanner.h"
#include "McpServer.h"
#include "McpJson.h"

#include <Aclapi.h>
#include <winhttp.h>
#include <algorithm>
#include <iostream>
#include <limits>
#include <set>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp.lib")

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

    bool HasCurrentUserOnlyDacl(const std::wstring& path)
    {
        bool ok = false;
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        PACL dacl = nullptr;
        HANDLE token = nullptr;

        do
        {
            const DWORD securityStatus = GetNamedSecurityInfoW(
                const_cast<LPWSTR>(path.c_str()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                nullptr,
                nullptr,
                &dacl,
                nullptr,
                &descriptor);
            if (securityStatus != ERROR_SUCCESS ||
                descriptor == nullptr ||
                dacl == nullptr ||
                dacl->AceCount != 1)
            {
                break;
            }

            SECURITY_DESCRIPTOR_CONTROL control = 0;
            DWORD revision = 0;
            if (!GetSecurityDescriptorControl(
                    descriptor,
                    &control,
                    &revision) ||
                (control & SE_DACL_PROTECTED) == 0)
            {
                break;
            }

            void* rawAce = nullptr;
            if (!GetAce(dacl, 0, &rawAce) || rawAce == nullptr)
            {
                break;
            }
            const ACCESS_ALLOWED_ACE* ace =
                static_cast<const ACCESS_ALLOWED_ACE*>(rawAce);
            if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE ||
                (ace->Mask & FILE_ALL_ACCESS) != FILE_ALL_ACCESS)
            {
                break;
            }

            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
            {
                break;
            }
            DWORD required = 0;
            GetTokenInformation(token, TokenUser, nullptr, 0, &required);
            if (required == 0)
            {
                break;
            }
            std::vector<unsigned char> buffer(required);
            if (!GetTokenInformation(
                    token,
                    TokenUser,
                    buffer.data(),
                    required,
                    &required))
            {
                break;
            }
            const TOKEN_USER* tokenUser =
                reinterpret_cast<const TOKEN_USER*>(buffer.data());
            ok = EqualSid(
                const_cast<DWORD*>(&ace->SidStart),
                tokenUser->User.Sid) != FALSE;
        } while (false);

        if (token != nullptr)
        {
            CloseHandle(token);
        }
        if (descriptor != nullptr)
        {
            LocalFree(descriptor);
        }
        return ok;
    }

    bool RunSensitiveFileSelfTest(bool* replacementOk, bool* daclOk)
    {
        bool ok = false;
        wchar_t temporaryDirectory[MAX_PATH] = {};
        wchar_t temporaryPath[MAX_PATH] = {};

        if (replacementOk != nullptr)
        {
            *replacementOk = false;
        }
        if (daclOk != nullptr)
        {
            *daclOk = false;
        }

        do
        {
            if (GetTempPathW(MAX_PATH, temporaryDirectory) == 0 ||
                GetTempFileNameW(
                    temporaryDirectory,
                    L"kmd",
                    0,
                    temporaryPath) == 0)
            {
                break;
            }
            DeleteFileW(temporaryPath);

            std::wstring error;
            if (!WriteMcpSensitiveFile(temporaryPath, "first", &error) ||
                !WriteMcpSensitiveFile(temporaryPath, "second", &error))
            {
                break;
            }

            HANDLE file = CreateFileW(
                temporaryPath,
                GENERIC_READ,
                FILE_SHARE_READ,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                break;
            }
            char buffer[16] = {};
            DWORD read = 0;
            const bool readOk =
                ReadFile(file, buffer, sizeof(buffer), &read, nullptr) != FALSE;
            CloseHandle(file);
            if (replacementOk != nullptr)
            {
                *replacementOk =
                    readOk && read == 6 && std::string(buffer, read) == "second";
            }
            if (daclOk != nullptr)
            {
                *daclOk = HasCurrentUserOnlyDacl(temporaryPath);
            }
            ok = true;
        } while (false);

        if (temporaryPath[0] != L'\0')
        {
            DeleteFileW(temporaryPath);
        }
        return ok;
    }
}

int RunMcpToolCatalogSelfTest()
{
    int exitCode = 1;
    SelfTestContext context = {};

    do
    {
        McpServer queueServer;
        queueServer.jobReadyEvent_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        Check(&context, queueServer.jobReadyEvent_ != nullptr, L"queue-test-event");
        McpEngineRequest queueRequest{ McpRequestKind::ToolCall, L"memory.write_virtual", L"{}" };
        McpEngineResult queueResult;
        Check(&context, queueServer.EnqueueAndWait(queueRequest, 0, &queueResult) && queueResult.IsError &&
            queueResult.Text.find(L"cancelled before execution") != std::wstring::npos && !queueServer.TryPopJob(),
            L"timeout-removes-pending-write");
        ResetEvent(queueServer.JobReadyEvent());
        auto runningWait = std::async(std::launch::async, [&]()
        {
            return queueServer.EnqueueAndWait(queueRequest, 1000, &queueResult);
        });
        const DWORD runningSignal = WaitForSingleObject(queueServer.JobReadyEvent(), 5000);
        auto runningJob = queueServer.TryPopJob();
        Check(&context, runningSignal == WAIT_OBJECT_0 && runningJob != nullptr, L"queue-dispatch-test");
        Check(&context, runningWait.get() && queueResult.IsError &&
            queueResult.Text.find(L"outcome unknown") != std::wstring::npos, L"timeout-does-not-claim-running-write-cancelled");
        if (runningJob != nullptr)
        {
            runningJob->ResultPromise.set_value(McpEngineResult{});
        }
        auto stopWait = std::async(std::launch::async, [&]()
        {
            return queueServer.EnqueueAndWait(queueRequest, 30000, &queueResult);
        });
        Check(&context, WaitForSingleObject(queueServer.JobReadyEvent(), 5000) == WAIT_OBJECT_0, L"queue-stop-test");
        queueServer.RequestStop();
        Check(&context, stopWait.wait_for(std::chrono::seconds(2)) == std::future_status::ready && stopWait.get() &&
            queueResult.IsError && !queueServer.TryPopJob(), L"stop-unblocks-transport-without-engine-drain");
        queueServer.Stop();

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
        CheckReadOnlyTool(
            &context,
            L"token.inspect",
            {L"pid", L"image", L"eprocess", L"limit"});
        CheckReadOnlyTool(&context, L"ti.subscribe", {L"action"});
        CheckReadOnlyTool(&context, L"etw.providers", {});
        CheckReadOnlyTool(&context, L"etw.ti_cross", {});
        CheckReadOnlyTool(&context, L"hal.scan", {});
        CheckReadOnlyTool(&context, L"hive.list", {});
        CheckReadOnlyTool(&context, L"dpc.list", {});
        CheckReadOnlyTool(&context, L"timer.list", {});
        CheckReadOnlyTool(&context, L"minifilter.list", {L"filter", L"name"});
        CheckReadOnlyTool(
            &context,
            L"payload.inspect",
            {L"address", L"va", L"symbol"});
        CheckReadOnlyTool(&context, L"payload.scan", {L"limit"});
        CheckReadOnlyTool(&context, L"mapper.list", {L"scope", L"limit"});
        CheckReadOnlyTool(&context, L"hiddenproc.list", {});
        CheckReadOnlyTool(&context, L"handles.list", {L"pid", L"target", L"limit"});
        CheckReadOnlyTool(&context, L"hv.posture", {});
        CheckReadOnlyTool(&context, L"dma.posture", {});
        CheckReadOnlyTool(
            &context,
            L"kpage.list",
            {L"deep", L"wx", L"pe", L"limit"});

        EtwTiCrossInput silentInput = {};
        silentInput.TiActive = true;
        silentInput.PplAntimalware = true;
        silentInput.StartTickMs = 1000;
        silentInput.NowTickMs = 31000;
        EtwTiCrossResult silentResult = {};
        std::wstring silentError;
        const bool silentOk = EtwScanner::BuildTiCrossView(
            silentInput,
            &silentResult,
            &silentError);
        Check(
            &context,
            silentOk &&
                silentResult.Status == L"silent" &&
                !silentResult.Suspicious,
            L"ti-silence-alone-not-suspicious");

        EtwTiCrossInput dropInput = {};
        dropInput.TiActive = true;
        dropInput.PplAntimalware = true;
        dropInput.EventsReceived = (std::numeric_limits<uint64_t>::max)();
        dropInput.EventsDropped = (std::numeric_limits<uint64_t>::max)();
        dropInput.StartTickMs = 1;
        dropInput.NowTickMs = 30001;
        EtwTiCrossResult dropResult = {};
        std::wstring dropError;
        const bool dropOk = EtwScanner::BuildTiCrossView(
            dropInput,
            &dropResult,
            &dropError);
        Check(
            &context,
            dropOk &&
                dropResult.Status == L"dropping" &&
                !dropResult.Suspicious,
            L"ti-drop-rate-overflow-safe");

        bool replacementOk = false;
        bool daclOk = false;
        const bool sensitiveFileOk = RunSensitiveFileSelfTest(
            &replacementOk,
            &daclOk);
        Check(&context, sensitiveFileOk, L"mcp-sensitive-file-write");
        Check(&context, replacementOk, L"mcp-sensitive-file-atomic-replace");
        Check(&context, daclOk, L"mcp-sensitive-file-current-user-dacl");

        std::wstring password;
        std::wstring passwordError;
        Check(
            &context,
            !SanitizeMcpPassword(L"ab", &password, &passwordError),
            L"mcp-password-too-short");
        Check(
            &context,
            SanitizeMcpPassword(L"lab1", &password, &passwordError) &&
                password == L"lab1",
            L"mcp-password-min-length");
        Check(
            &context,
            !SanitizeMcpPassword(L"bad pass", &password, &passwordError),
            L"mcp-password-rejects-space");
        Check(
            &context,
            IsMcpWildcardBind(L"") &&
                IsMcpWildcardBind(L"0.0.0.0") &&
                IsMcpWildcardBind(L"+") &&
                NormalizeMcpBindAddress(L"*") == L"0.0.0.0",
            L"mcp-bind-wildcard");
        Check(
            &context,
            IsMcpLoopbackBind(L"loopback") &&
                IsMcpLoopbackBind(L"127.0.0.1") &&
                NormalizeMcpBindAddress(L"localhost") == L"loopback",
            L"mcp-bind-loopback");
        Check(
            &context,
            NormalizeMcpBindAddress(L"192.168.56.10") == L"192.168.56.10",
            L"mcp-bind-specific-ip");
        Check(
            &context,
            IsMcpConcreteIpv4Bind(L"192.168.56.10") &&
                !IsMcpConcreteIpv4Bind(L"999.0.0.1") &&
                !IsMcpConcreteIpv4Bind(L"192.168.56") &&
                !IsMcpConcreteIpv4Bind(L"--allow-write"),
            L"mcp-bind-concrete-ipv4");
        Check(
            &context,
            McpAuthorizationMatchesPassword("Bearer lab1", L"lab1") &&
                McpAuthorizationMatchesPassword("bearer lab1", L"lab1") &&
                McpAuthorizationMatchesPassword("lab1", L"lab1"),
            L"mcp-auth-accepts-bearer-and-raw");
        Check(
            &context,
            !McpAuthorizationMatchesPassword("Bearer lab2", L"lab1") &&
                !McpAuthorizationMatchesPassword("Bearer lab1x", L"lab1") &&
                !McpAuthorizationMatchesPassword("", L"lab1"),
            L"mcp-auth-rejects-mismatch");

        std::vector<McpListenAddress> listenAddresses;
        CollectMcpListenAddresses(&listenAddresses);
        bool hasLoopback = false;
        for (const McpListenAddress& address : listenAddresses)
        {
            if (address.Ip == L"127.0.0.1" && address.Loopback)
            {
                hasLoopback = true;
                break;
            }
        }
        Check(&context, hasLoopback, L"mcp-listen-addresses-include-loopback");

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

        McpToolCatalogEntry callbackSetEntry = {};
        const bool callbackSetOk =
            FindMcpToolCatalogEntry(L"callbacks.set", &callbackSetEntry) &&
            !callbackSetEntry.ReadOnly &&
            HasExactlyArguments(callbackSetEntry, {L"action", L"module", L"scope"});
        Check(&context, callbackSetOk, L"callbacks-set-write-tool");

        std::wcout << L"[mcp.selftest] passed=" << context.Passed
                   << L" failed=" << context.Failed << L"\n";
        if (context.Failed == 0)
        {
            exitCode = 0;
        }
    } while (false);

    return exitCode;
}

int RunMcpTransportSelfTest()
{
    SelfTestContext context;
    McpServer server;
    McpServerConfig config;
    config.Port = 51768;
    config.BindAddress = L"127.0.0.1";
    config.Password = L"kn-command-selftest";
    std::wstring error;
    if (!server.Start(config, &error))
    {
        std::wcerr << L"[mcp.http.selftest] listener failed: " << error << L"\n";
        return 1;
    }
    HINTERNET session = WinHttpOpen(L"KnLiveDbg command self-test", WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET connection = session != nullptr ? WinHttpConnect(session, L"127.0.0.1", config.Port, 0) : nullptr;
    if (session != nullptr)
    {
        WinHttpSetTimeouts(session, 5000, 5000, 5000, 5000);
    }
    auto post = [&](const std::string& body, DWORD expectedStatus, const wchar_t* expectedText, const wchar_t* name)
    {
        HINTERNET request = connection != nullptr ? WinHttpOpenRequest(connection, L"POST", L"/mcp/", nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0) : nullptr;
        bool ok = false;
        do
        {
            if (request == nullptr)
            {
                break;
            }
            const std::wstring headers = L"Authorization: Bearer " + config.Password + L"\r\nContent-Type: application/json\r\n";
            if (!WinHttpSendRequest(request, headers.c_str(), static_cast<DWORD>(headers.size()),
                    const_cast<char*>(body.data()), static_cast<DWORD>(body.size()), static_cast<DWORD>(body.size()), 0) ||
                !WinHttpReceiveResponse(request, nullptr))
            {
                break;
            }
            DWORD status = 0;
            DWORD statusBytes = sizeof(status);
            if (!WinHttpQueryHeaders(request, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                    WINHTTP_HEADER_NAME_BY_INDEX, &status, &statusBytes, WINHTTP_NO_HEADER_INDEX) || status != expectedStatus)
            {
                break;
            }
            std::string response;
            char chunk[4096];
            DWORD received = 0;
            bool complete = false;
            while (WinHttpReadData(request, chunk, sizeof(chunk), &received))
            {
                if (received == 0)
                {
                    complete = true;
                    break;
                }
                response.append(chunk, received);
                if (response.size() > 65536)
                {
                    break;
                }
            }
            const std::wstring decoded = mcpjson::Utf8ToWide(response);
            ok = complete && mcpjson::ValidateDocument(decoded) && decoded.find(expectedText) != std::wstring::npos;
        } while (false);
        if (request != nullptr)
        {
            WinHttpCloseHandle(request);
        }
        Check(&context, ok, name);
    };
    const std::string ping = R"({"jsonrpc":"2.0","id":1,"method":"ping"})";
    post(ping, 200, L"\"result\":{}", L"http-complete-body");
    post(ping + "garbage", 200, L"-32700", L"http-trailing-data-rejected");
    post(R"({"jsonrpc":"2.0","id":1,"method":"ping","method":"initialize"})", 200, L"-32700", L"http-duplicate-key-rejected");
    post(R"({"id":1,"method":"ping"})", 200, L"-32600", L"http-jsonrpc-version-required");
    post(R"({"jsonrpc":"2.0","id":true,"method":"ping"})", 200, L"-32600", L"http-invalid-id-rejected");
    post(std::string("\xc0\xaf", 2), 200, L"-32700", L"http-invalid-utf8-rejected");
    std::string large = R"({"jsonrpc":"2.0","id":1,"method":"ping","padding":")";
    large.append(1024 * 1024 - large.size() - 2, 'x');
    large += "\"}";
    post(large, 200, L"\"result\":{}", L"http-body-at-limit");
    large.insert(large.size() - 2, "x");
    post(large, 400, L"-32700", L"http-body-over-limit-rejected");
    post(ping, 200, L"\"result\":{}", L"http-recovers-after-rejected-body");
    if (connection != nullptr)
    {
        WinHttpCloseHandle(connection);
    }
    if (session != nullptr)
    {
        WinHttpCloseHandle(session);
    }
    server.Stop();
    std::wcout << L"[mcp.http.selftest] passed=" << context.Passed << L" failed=" << context.Failed << L"\n";
    return context.Failed == 0 ? 0 : 1;
}
