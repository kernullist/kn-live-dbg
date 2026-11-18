#include "McpSelfTest.h"

#include "EtwScanner.h"
#include "McpServer.h"
#include "McpJson.h"
#include "TimelineStore.h"

#include <Aclapi.h>
#include <winhttp.h>
#include <algorithm>
#include <cmath>
#include <fstream>
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
        queueServer.config_.AllowWrite = true;
        McpEngineRequest queueRequest{ McpRequestKind::ToolCall, L"ti.clear", L"{}" };
        McpEngineResult queueResult;
        Check(&context, queueServer.EnqueueAndWait(queueRequest, 0, &queueResult) && queueResult.IsError &&
            queueResult.Text.find(L"cancelled before execution") != std::wstring::npos && !queueServer.TryPopJob(),
            L"timeout-removes-pending-write");
        std::wstring cancelledId;
        std::wstring operationState;
        Check(&context, mcpjson::GetString(queueResult.OperationJson, L"operation_id", &cancelledId) &&
            IsMcpOperationId(cancelledId) &&
            mcpjson::GetString(queueServer.OperationStatus(cancelledId).StructuredJson, L"state", &operationState) &&
            operationState == L"cancelled_before_execution", L"queued-timeout-retains-operation-id");
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
            const auto before = queueServer.OperationStatus(runningJob->OperationId);
            Check(&context, !before.IsError && mcpjson::GetString(before.StructuredJson, L"state", &operationState) &&
                operationState == L"unknown_outcome" && queueResult.OutcomeUnknown,
                L"running-timeout-query-without-engine-hop");
            queueServer.CompleteJob(runningJob, McpEngineResult{});
            const auto after = queueServer.OperationStatus(runningJob->OperationId);
            Check(&context, !after.IsError && mcpjson::GetString(after.StructuredJson, L"state", &operationState) &&
                operationState == L"succeeded", L"late-completion-retained-after-waiter-left");
            McpEngineResult duplicate;
            duplicate.IsError = true;
            queueServer.CompleteJob(runningJob, duplicate);
            Check(&context, queueServer.OperationStatus(runningJob->OperationId).StructuredJson == after.StructuredJson,
                L"duplicate-completion-cannot-rewrite-outcome");
        }
        Check(&context, queueServer.OperationStatus(L"bad-id").IsError &&
            queueServer.OperationStatus(std::wstring(32, L'0')).IsError, L"missing-operation-not-a-success");
        ResetEvent(queueServer.JobReadyEvent());
        auto completedWait = std::async(std::launch::async, [&]()
        {
            return queueServer.EnqueueAndWait(queueRequest, 10000, &queueResult);
        });
        Check(&context, WaitForSingleObject(queueServer.JobReadyEvent(), 5000) == WAIT_OBJECT_0, L"normal-operation-enqueued");
        auto completedJob = queueServer.TryPopJob();
        Check(&context, completedJob != nullptr, L"normal-operation-dispatched");
        McpEngineResult completedResult;
        completedResult.IsError = true;
        completedResult.OutcomeUnknown = true;
        completedResult.StructuredJson = L"{\"fixture\":true}";
        queueServer.CompleteJob(completedJob, completedResult);
        Check(&context, completedWait.get() && queueResult.IsError && queueResult.OutcomeUnknown &&
            queueResult.StructuredJson == completedResult.StructuredJson &&
            mcpjson::GetString(queueResult.OperationJson, L"state", &operationState) && operationState == L"unknown_outcome",
            L"exception-outcome-retained-with-original-payload");
        auto stopWait = std::async(std::launch::async, [&]()
        {
            return queueServer.EnqueueAndWait(queueRequest, 30000, &queueResult);
        });
        Check(&context, WaitForSingleObject(queueServer.JobReadyEvent(), 5000) == WAIT_OBJECT_0, L"queue-stop-test");
        queueServer.RequestStop();
        Check(&context, stopWait.wait_for(std::chrono::seconds(2)) == std::future_status::ready && stopWait.get() &&
            queueResult.IsError && !queueServer.TryPopJob(), L"stop-unblocks-transport-without-engine-drain");
        queueServer.Stop();
        Check(&context, mcpjson::GetString(queueResult.OperationJson, L"state", &operationState) &&
            operationState == L"cancelled_before_execution", L"stop-retains-queued-cancellation");

        std::vector<McpToolCatalogEntry> catalog = BuildMcpToolCatalogSnapshot();
        McpServer observer;
        observer.config_.ObserveOnly = true;
        observer.config_.BindAddress = L"127.0.0.1";
        observer.jobReadyEvent_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        size_t dispatches = 0;
        TimelineStore retained(80);
        std::vector<TimelineEvent> fixtures;
        for (unsigned index = 1; index <= 70; ++index)
        {
            TimelineEvent event;
            event.TimestampFileTime = index;
            event.Source = L"fixture";
            event.Domain = L"test";
            event.Action = L"sample";
            event.Entity = std::to_wstring(index);
            event.ProcessId = 7;
            fixtures.push_back(event);
        }
        Check(&context, retained.IngestEvents(fixtures).Added == 70, L"observe-owned-events");
        auto dispatch = [&](const McpEngineRequest& request)
        {
            ++dispatches;
            return ReadMcpObservedTimeline(request, retained);
        };
        auto blockedBeforeAdmission = [&](const McpEngineRequest& request)
        {
            McpEngineResult admission;
            const bool responded = observer.EnqueueAndWait(request, 0, &admission);
            const auto terminal = observer.DispatchAuthorized(request, dispatch);
            return responded && admission.IsError && !admission.OutcomeUnknown && admission.OperationJson.empty() &&
                terminal.IsError && terminal.StructuredJson == admission.StructuredJson && dispatches == 0 &&
                !observer.TryPopJob() && WaitForSingleObject(observer.JobReadyEvent(), 0) == WAIT_TIMEOUT;
        };
        const std::set<std::wstring> engineTools{ L"timeline.status", L"timeline.query", L"graph.query", L"ti.subscribe" };
        bool closed = observer.jobReadyEvent_ != nullptr;
        for (const auto& entry : catalog)
        {
            if (!engineTools.count(entry.Name))
            {
                closed &= blockedBeforeAdmission({ McpRequestKind::ToolCall, entry.Name, L"{}" });
            }
        }
        Check(&context, closed, L"observe-catalog-denials-before-queue-and-dispatch");
        for (const auto& uri : { L"kn://snapshot/current", L"kn://audit/tail", L"kn://modules/kernel",
            L"kn://session/symbols", L"kn://capabilities", L"kn://new" })
        {
            Check(&context, blockedBeforeAdmission({ McpRequestKind::ResourceRead, uri, L"" }), L"observe-resource-denial");
        }
        for (const auto& args : { LR"({"action":"start"})", LR"({"action":"stop"})", LR"({"action":"STATUS"})",
            LR"({"action":"status\u0000start"})", LR"({"act\u0069on":"status","action":"stop"})" })
        {
            Check(&context, blockedBeforeAdmission({ McpRequestKind::ToolCall, L"ti.subscribe", args }), L"observe-action-denial");
        }
        for (const auto& args : std::vector<std::wstring>{ LR"({"limit":"0"})", LR"({"limit":"65"})", LR"({"limit":"01"})",
            LR"({"limit":32})", LR"({"pid":"4294967296"})", LR"({"order":"other"})", LR"({"domain":"a\u0000b"})",
            LR"({"path":"unused"})", L"{\"source\":\"" + std::wstring(129, L'x') + L"\"}", std::wstring(4095, L' ') + L"{}" })
        {
            Check(&context, blockedBeforeAdmission({ McpRequestKind::ToolCall, L"timeline.query", args }), L"observe-invalid-filter");
        }
        Check(&context, blockedBeforeAdmission({ McpRequestKind::ToolCall, L"future.tool", L"{}" }) &&
            blockedBeforeAdmission({ McpRequestKind::ResourceRead, L"kn://session/info", L"{}" }), L"observe-unknown-or-mixed-kind");
        const auto invoke = [&](const wchar_t* name, const wchar_t* args)
        {
            return observer.DispatchAuthorized({ McpRequestKind::ToolCall, name, args }, dispatch).StructuredJson;
        };
        const auto defaultQuery = invoke(L"timeline.query", L"{}");
        const auto oldest = invoke(L"timeline.query", LR"({"source":"fixture","domain":"test","pid":"7","limit":"1","order":"oldest"})");
        const auto graph = invoke(L"graph.query", LR"({"limit":"64","pid":"7"})");
        const auto noMatch = invoke(L"graph.query", LR"({"pid":"4294967295","limit":"1"})");
        Check(&context, defaultQuery.find(L"\"count\":50,") != std::wstring::npos &&
            defaultQuery.find(L"\"eventId\":70,") != std::wstring::npos &&
            oldest.find(L"\"count\":1,") != std::wstring::npos && oldest.find(L"\"eventId\":1,") != std::wstring::npos &&
            graph.find(L"\"matchedEvents\":64,\"truncated\":true") != std::wstring::npos &&
            noMatch.find(L"\"matchedEvents\":0,\"truncated\":false") != std::wstring::npos &&
            dispatches == 4 && retained.GetStats().Stored == 70 && retained.PeekNextEventId() == 71,
            L"observe-bounded-retained-query-and-graph");
        Check(&context, McpObserveAddressSelfTest(), L"observe-connection-address-boundary");
        McpEngineResult result;
        std::wstring nonBmp;
        for (int index = 0; index < 128; ++index) { nonBmp += L"\U0001f642"; }
        auto filterAllowed = [&](const std::wstring& text)
        {
            return observer.AuthorizeEngineRequest(
                { McpRequestKind::ToolCall, L"graph.query", L"{\"image\":" + mcpjson::Quote(text) + L"}" }, &result);
        };
        Check(&context, filterAllowed(nonBmp) && !filterAllowed(nonBmp + L"x"), L"observe-filter-budget-counts-unicode-scalars");
        for (const auto& uri : { L"kn://session/info", L"kn://drivers/status", L"kn://ti/stats" })
        {
            Check(&context, observer.AuthorizeEngineRequest({ McpRequestKind::ResourceRead, uri, L"" }, &result),
                L"observe-permitted-status-resource");
        }
        Check(&context, observer.AuthorizeEngineRequest({ McpRequestKind::ToolCall, L"ti.subscribe", L"{}" }, &result) &&
            observer.AuthorizeEngineRequest({ McpRequestKind::ToolCall, L"ti.subscribe", LR"({"action":"status"})" }, &result),
            L"observe-status-actions");
        McpServerConfig incompatible = observer.config_;
        incompatible.AllowWrite = true;
        Check(&context, !observer.Start(incompatible, nullptr) && !observer.AllowWrite() &&
            !observer.IsRunning() && observer.JobReadyEvent() != nullptr, L"observe-write-conflict-refused-before-setup");
        McpServer legacy;
        Check(&context, legacy.AuthorizeEngineRequest({ McpRequestKind::ToolCall, L"ti.subscribe", LR"({"action":"\fSTATUS\u000b"})" }, &result)
            && !legacy.AuthorizeEngineRequest({ McpRequestKind::ToolCall, L"ti.subscribe", LR"({"action":"stop"})" }, &result)
            && result.IsError && result.OperationJson.empty(), L"legacy-status-normalization-and-prequeue-lifecycle-denial");
        for (const auto& bind : std::vector<std::wstring>{ L"0.0.0.0", L"+", L"192.0.2.1", std::wstring(L"127.0.0.1\0x", 11) })
        {
            McpServerConfig invalid = observer.config_;
            invalid.BindAddress = bind;
            Check(&context, !observer.Start(invalid, nullptr) && !observer.IsRunning() &&
                observer.BindAddress() == L"127.0.0.1" && observer.JobReadyEvent() != nullptr, L"observe-refuses-bind-before-setup");
        }
        Check(&context, !catalog.empty(), L"catalog-not-empty");
        Check(&context, McpRequestBodySelfTest(), L"http-body-bounds-eof-and-read-failure");
        Check(&context, McpOperationWireSelfTest(), L"operation-wire-preserves-payload-and-exposes-metadata");
        CheckReadOnlyTool(&context, L"operations.get", {L"operation_id"});
        std::wstring operationArgumentError;
        Check(&context, ValidateMcpToolArguments(L"operations.get", L"{\"operation_id\":\"00000000000000000000000000000001\"}", &operationArgumentError) &&
            !ValidateMcpToolArguments(L"operations.get", L"{}", &operationArgumentError) &&
            !ValidateMcpToolArguments(L"operations.get", L"{\"operation_id\":1}", &operationArgumentError) &&
            !ValidateMcpToolArguments(L"operations.get", L"{\"operation_id\":\"x\",\"retry\":true}", &operationArgumentError),
            L"operation-query-closed-arguments");
        {
            std::wstring value;
            Check(&context, mcpjson::GetString(
                LR"({"m\u0065thod":"ping","params":{"items":[{},[],null,true,-1.2e+3]}})",
                L"method", &value) && value == L"ping", L"json-escaped-key-and-nested-values");
            const wchar_t* invalid[] =
            {
                LR"({"method":"ping"} trailing)",
                LR"({"method":"ping" "id":1})",
                LR"({"method":"ping","params":[})",
                LR"({"method":"ping","id":01})",
                LR"({"method":"ping","id":1e})",
                LR"({"method":"ping","params":{"x":truejunk}})",
                LR"({"method":"ping","method":"tools/call"})",
                LR"({"method":"p\qing"})",
                LR"({"method":"ping",})"
            };
            for (size_t index = 0; index < _countof(invalid); ++index)
            {
                const std::wstring name = L"json-reject-malformed-" + std::to_wstring(index);
                Check(&context, !mcpjson::GetString(invalid[index], L"method", &value), name.c_str());
            }
            const std::wstring deep = L"{\"x\":" + std::wstring(130, L'[') + L"0" +
                std::wstring(130, L']') + L"}";
            Check(&context, !mcpjson::IsObject(deep), L"json-bounded-nesting");
            Check(&context, mcpjson::ValidateDocument(std::wstring(64, L'[') + L"0" + std::wstring(64, L']')) &&
                !mcpjson::ValidateDocument(std::wstring(65, L'[') + L"0" + std::wstring(65, L']')),
                L"json-nesting-limit-boundary");
            Check(&context, mcpjson::Utf8ToWide(std::string("\xc0\xaf", 2)).empty(), L"json-reject-invalid-utf8");
        }

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
                silentResult.Status == L"unknown" &&
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
                dropResult.Status == L"unknown" &&
                dropResult.EventsDropped == dropInput.EventsDropped &&
                dropResult.EventsLost == 0 &&
                dropResult.ConsumerMissingSequence == 0 &&
                std::isfinite(dropResult.EventsPerSecond) &&
                dropResult.EventsPerSecond > 0 &&
                !dropResult.Suspicious,
            L"ti-retention-pressure-is-not-consumer-loss");

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

static bool McpManifestMatches(const std::wstring& response, const wchar_t* list, const wchar_t* field,
                               const std::set<std::wstring>& expected)
{
    std::wstring result, items;
    if (!mcpjson::FindRawValue(response, L"result", &result) || !mcpjson::FindRawValue(result, list, &items) ||
        items.empty() || items.front() != L'[') { return false; }
    std::set<std::wstring> names;
    size_t pos = 1;
    mcpjson::SkipWhitespace(items, &pos);
    while (pos < items.size() && items[pos] != L']')
    {
        std::wstring name;
        size_t end = pos;
        if (!mcpjson::ScanValue(items, pos, &end) || !mcpjson::GetString(items.substr(pos, end - pos), field, &name) ||
            !names.insert(name).second) { return false; }
        pos = end;
        mcpjson::SkipWhitespace(items, &pos);
        if (pos < items.size() && items[pos] == L',') { ++pos; mcpjson::SkipWhitespace(items, &pos); }
    }
    return names == expected;
}

int RunMcpTransportSelfTest(bool observe)
{
    SelfTestContext context;
    McpServer server;
    McpServerConfig config;
    config.Port = 51768;
    config.BindAddress = L"127.0.0.1";
    config.Password = L"kn-command-selftest";
    config.ObserveOnly = observe;
    if (observe)
    {
        wchar_t directory[MAX_PATH] = {}, path[MAX_PATH] = {};
        const DWORD length = GetTempPathW(MAX_PATH, directory);
        if (!length || length >= MAX_PATH || !GetTempFileNameW(directory, L"mco", 0, path)) { return 1; }
        config.AuditPath = path;
    }
    std::wstring error;
    if (!server.Start(config, &error))
    {
        std::wcerr << L"[mcp.http.selftest] listener failed: " << error << L"\n";
        if (observe) { DeleteFileW(config.AuditPath.c_str()); }
        return 1;
    }
    HINTERNET session = WinHttpOpen(L"KnLiveDbg command self-test", WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET connection = session != nullptr ? WinHttpConnect(session, L"127.0.0.1", config.Port, 0) : nullptr;
    if (session != nullptr)
    {
        WinHttpSetTimeouts(session, 5000, 5000, 5000, 45000);
    }
    std::wstring sessionId;
    std::wstring lastResponse;
    auto post = [&](const std::string& body, DWORD expectedStatus, const wchar_t* expectedText, const wchar_t* name)
    {
        lastResponse.clear();
        HINTERNET request = connection != nullptr ? WinHttpOpenRequest(connection, L"POST", L"/mcp/", nullptr,
            WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0) : nullptr;
        bool ok = false;
        do
        {
            if (request == nullptr)
            {
                break;
            }
            std::wstring headers = L"Authorization: Bearer " + config.Password + L"\r\nContent-Type: application/json\r\n";
            if (!sessionId.empty())
            {
                headers += L"Mcp-Session-Id: " + sessionId + L"\r\n";
            }
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
            lastResponse = mcpjson::Utf8ToWide(response);
            ok = complete && mcpjson::ValidateDocument(lastResponse) && lastResponse.find(expectedText) != std::wstring::npos;
            wchar_t header[128] = {};
            DWORD headerBytes = sizeof(header);
            if (WinHttpQueryHeaders(request, WINHTTP_QUERY_CUSTOM, L"Mcp-Session-Id", header, &headerBytes, WINHTTP_NO_HEADER_INDEX))
            {
                sessionId.assign(header, headerBytes / sizeof(wchar_t));
                while (!sessionId.empty() && sessionId.back() == L'\0')
                {
                    sessionId.pop_back();
                }
            }
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
    post(large, 413, L"-32700", L"http-body-over-limit-rejected");
    post(ping, 200, L"\"result\":{}", L"http-recovers-after-rejected-body");
    post(R"({"jsonrpc":"2.0","id":2,"method":"initialize","params":{}})", 200,
        L"protocolVersion", L"http-operation-initialize");
    Check(&context, !sessionId.empty(), L"http-session-header-retained");
    if (observe)
    {
        const auto originalSession = sessionId;
        McpServerConfig conflict = config;
        conflict.ObserveOnly = false;
        conflict.AllowWrite = true;
        Check(&context, !server.Start(conflict, &error) && server.IsRunning() && server.ObserveOnly() &&
            !server.AllowWrite() && !server.IsNetworkExposed(), L"http-observe-ceiling-survives-repeated-start");
        sessionId = L"stale-test-id";
        post(R"({"jsonrpc":"2.0","id":11,"method":"tools/list"})", 200, L"invalid or missing", L"http-observe-stale-session");
        Check(&context, sessionId == L"stale-test-id", L"http-observe-denial-withholds-session-header");
        sessionId = originalSession;
        post(R"({"jsonrpc":"2.0","id":12,"method":"tools/list"})", 200, L"operations.get", L"http-observe-tools-list");
        Check(&context, McpManifestMatches(lastResponse, L"tools", L"name", { L"operations.get", L"timeline.status",
            L"timeline.query", L"graph.query", L"ti.subscribe" }) && lastResponse.find(L"\"enum\":[\"status\"]") != std::wstring::npos,
            L"http-observe-exact-tools-and-status-schema");
        post(R"({"jsonrpc":"2.0","id":13,"method":"resources/list"})", 200, L"kn://capabilities", L"http-observe-resources-list");
        Check(&context, McpManifestMatches(lastResponse, L"resources", L"uri", { L"kn://capabilities", L"kn://session/info",
            L"kn://drivers/status", L"kn://ti/stats" }), L"http-observe-exact-resources");
        post(R"({"jsonrpc":"2.0","id":14,"method":"resources/read","params":{"uri":"kn://capabilities"}})",
            200, LR"(\"scope\":\"observe\")", L"http-observe-capabilities");
        Check(&context, lastResponse.find(L"snapshot.capture") == std::wstring::npos &&
            lastResponse.find(L"knlivedbg/operation") == std::wstring::npos, L"http-observe-capabilities-served-inline");
        post(R"({"jsonrpc":"2.0","id":15,"method":"prompts/list"})", 200, L"\"prompts\":[]", L"http-observe-empty-prompts");
        post(R"({"jsonrpc":"2.0","id":16,"method":"prompts/get","params":{"name":"observe-audit-canary"}})",
            200, L"blocked by MCP session policy", L"http-observe-prompts-closed");
        for (const auto& tool : { "snapshot.capture", "timeline.export", "timeline.reconcile", "snapshot.diff",
            "observe-audit-canary" })
        {
            const auto body = std::string(R"({"jsonrpc":"2.0","id":17,"method":"tools/call","params":{"name":")") +
                tool + R"(","arguments":{"path":"observe-audit-canary"}}})";
            post(body, 200, L"blocked_by_policy", L"http-observe-tool-policy-denial");
            Check(&context, lastResponse.find(L"operation_id") == std::wstring::npos &&
                lastResponse.find(L"observe-audit-canary") == std::wstring::npos, L"http-observe-denial-has-no-ledger-entry-or-input");
        }
        post(R"({"jsonrpc":"2.0","id":18,"method":"tools/call","params":{"name":"ti.subscribe","arguments":{"action":"start"}}})",
            200, L"blocked_by_policy", L"http-observe-mixed-tool-denied");
        post(R"({"jsonrpc":"2.0","id":19,"method":"tools/call","params":{"name":"graph.query","arguments":{"limit":"65"}}})",
            200, L"invalid_arguments", L"http-observe-query-budget-enforced");
        post(R"({"jsonrpc":"2.0","id":20,"method":"resources/read","params":{"uri":"kn://observe-audit-canary"}})",
            200, L"blocked by MCP session policy", L"http-observe-resource-denied");
        Check(&context, !server.TryPopJob() && WaitForSingleObject(server.JobReadyEvent(), 0) == WAIT_TIMEOUT,
            L"http-observe-no-work-signalled-by-denials");
        auto retainedRead = std::async(std::launch::async, [&]()
        {
            if (WaitForSingleObject(server.JobReadyEvent(), 5000) != WAIT_OBJECT_0) { return false; }
            auto job = server.TryPopJob();
            if (!job) { return false; }
            TimelineStore timeline(1);
            auto result = server.DispatchAuthorized(job->Request,
                [&](const McpEngineRequest& req) { return ReadMcpObservedTimeline(req, timeline); });
            const bool ok = !result.IsError && IsMcpOperationId(job->OperationId);
            server.CompleteJob(job, std::move(result));
            return ok;
        });
        post(R"({"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"timeline.query","arguments":{"source":"observe-audit-canary","limit":"1"}}})",
            200, L"kn-live-dbg.timeline.v1", L"http-observe-retained-query");
        Check(&context, retainedRead.get() && lastResponse.find(L"\"state\":\"succeeded\"") != std::wstring::npos,
            L"http-observe-allowed-operation-receipt");
    }
    else
    {
        std::set<std::wstring> expected;
        for (const auto& tool : BuildMcpToolCatalogSnapshot())
        {
            if (tool.ReadOnly) { expected.insert(tool.Name); }
        }
        post(R"({"jsonrpc":"2.0","id":22,"method":"tools/list"})", 200, L"snapshot.capture", L"http-legacy-tools-list");
        Check(&context, expected.size() == 68 && McpManifestMatches(lastResponse, L"tools", L"name", expected),
            L"http-legacy-complete-write-locked-catalog");
        post(R"({"jsonrpc":"2.0","id":23,"method":"resources/list"})", 200, L"kn://snapshot/current", L"http-legacy-resources-list");
        Check(&context, McpManifestMatches(lastResponse, L"resources", L"uri", { L"kn://capabilities", L"kn://session/info",
            L"kn://drivers/status", L"kn://ti/stats", L"kn://modules/kernel", L"kn://session/symbols", L"kn://snapshot/current",
            L"kn://audit/tail" }), L"http-legacy-complete-resource-catalog");
    }
    std::promise<void> releaseEngine;
    auto release = releaseEngine.get_future();
    auto engine = std::async(std::launch::async, [&]()
    {
        if (WaitForSingleObject(server.JobReadyEvent(), 5000) != WAIT_OBJECT_0)
        {
            return false;
        }
        auto job = server.TryPopJob();
        if (job == nullptr || release.wait_for(std::chrono::seconds(60)) != std::future_status::ready)
        {
            return false;
        }
        McpEngineResult result;
        result.StructuredJson = L"{\"fixture\":true}";
        server.CompleteJob(job, result);
        return true;
    });
    post(observe ? R"({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"timeline.status","arguments":{}}})" :
        R"({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"process.find","arguments":{}}})",
        200, L"unknown_outcome", L"http-dispatched-operation-times-out");
    std::wstring rpcResult;
    std::wstring meta;
    std::wstring operation;
    std::wstring operationId;
    Check(&context, mcpjson::FindRawValue(lastResponse, L"result", &rpcResult) &&
        mcpjson::FindRawValue(rpcResult, L"_meta", &meta) &&
        mcpjson::FindRawValue(meta, L"knlivedbg/operation", &operation) &&
        mcpjson::GetString(operation, L"operation_id", &operationId) && IsMcpOperationId(operationId),
        L"http-timeout-carries-operation-id");
    const std::string query = mcpjson::WideToUtf8(L"{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"operations.get\",\"arguments\":{\"operation_id\":" +
        mcpjson::Quote(operationId) + L"}}}");
    post(query, 200, L"\"state\":\"unknown_outcome\"", L"http-status-bypasses-blocked-engine");
    Check(&context, !server.TryPopJob(), L"http-status-does-not-enqueue-another-operation");
    releaseEngine.set_value();
    Check(&context, engine.get(), L"http-late-engine-completion");
    std::string finalQuery = query;
    const auto requestId = finalQuery.find("\"id\":4");
    if (requestId != std::string::npos)
    {
        finalQuery.replace(requestId, 6, "\"id\":5");
    }
    post(finalQuery, 200, L"\"state\":\"succeeded\"", L"http-late-completion-status");
    post(R"({"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"operations.get","arguments":{"operation_id":1}}})",
        200, L"\"isError\":true", L"http-operation-invalid-arguments");
    post(R"({"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"operations.get","arguments":{"operation_id":"00000000000000000000000000000000"}}})",
        200, L"not_retained", L"http-operation-unknown-id");
    for (unsigned variant = 0; variant < 2; ++variant)
    {
        auto resourceEngine = std::async(std::launch::async, [&]()
        {
            if (WaitForSingleObject(server.JobReadyEvent(), 5000) != WAIT_OBJECT_0)
            {
                return false;
            }
            auto job = server.TryPopJob();
            if (job == nullptr || job->Request.Kind != McpRequestKind::ResourceRead)
            {
                return false;
            }
            McpEngineResult result;
            result.IsError = variant != 0;
            result.Text = L"synthetic resource";
            result.StructuredJson = L"{\"fixture\":true}";
            server.CompleteJob(job, result);
            return true;
        });
        const std::string body = "{\"jsonrpc\":\"2.0\",\"id\":" + std::to_string(8 + variant) +
            ",\"method\":\"resources/read\",\"params\":{\"uri\":\"kn://session/info\"}}";
        post(body, 200, variant == 0 ? L"\"state\":\"succeeded\"" : L"\"state\":\"failed\"",
            variant == 0 ? L"http-resource-success-metadata" : L"http-resource-error-metadata");
        Check(&context, resourceEngine.get(), L"http-resource-engine-finished");
        operation.clear();
        bool metadataOk = false;
        if (variant == 0)
        {
            metadataOk = mcpjson::FindRawValue(lastResponse, L"result", &rpcResult) &&
                mcpjson::FindRawValue(rpcResult, L"_meta", &meta) &&
                mcpjson::FindRawValue(meta, L"knlivedbg/operation", &operation);
        }
        else
        {
            metadataOk = mcpjson::FindRawValue(lastResponse, L"error", &rpcResult) &&
                mcpjson::FindRawValue(rpcResult, L"data", &operation);
        }
        Check(&context, metadataOk && mcpjson::GetString(operation, L"operation_id", &operationId) &&
            IsMcpOperationId(operationId), L"http-resource-operation-id-location");
    }
    if (connection != nullptr)
    {
        WinHttpCloseHandle(connection);
    }
    if (session != nullptr)
    {
        WinHttpCloseHandle(session);
    }
    if (observe)
    {
        server.RequestStop();
        McpServerConfig next = config;
        next.ObserveOnly = false;
        next.AllowWrite = true;
        Check(&context, !server.Start(next, &error) && server.ObserveOnly() && !server.AllowWrite(),
            L"http-observe-scope-pinned-until-listener-joined");
    }
    server.Stop();
    if (observe)
    {
        std::ifstream file(config.AuditPath.c_str(), std::ios::binary);
        std::string audit{ std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>{} };
        Check(&context, !sessionId.empty() && audit.find("\"scope\":\"observe\"") != std::string::npos &&
            audit.find("\"decision\":\"blocked_by_policy\"") != std::string::npos &&
            audit.find("\"decision\":\"invalid_arguments\"") != std::string::npos &&
            audit.find("observe-audit-canary") == std::string::npos && audit.find("\"args\":") == std::string::npos &&
            audit.find(mcpjson::WideToUtf8(sessionId)) == std::string::npos &&
            audit.find(mcpjson::WideToUtf8(config.Password)) == std::string::npos, L"http-observe-audit-metadata-only");
        file.close();
        Check(&context, DeleteFileW(config.AuditPath.c_str()) != FALSE, L"http-observe-owned-audit-removed");
    }
    std::wcout << (observe ? L"[mcp.observe.selftest]" : L"[mcp.http.selftest]") <<
        L" passed=" << context.Passed << L" failed=" << context.Failed << L"\n";
    return context.Failed == 0 ? 0 : 1;
}
