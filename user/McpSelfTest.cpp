#include "McpSelfTest.h"

#include "EtwScanner.h"
#include "McpServer.h"
#include "McpOperationJournal.h"
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
#include <stdexcept>
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
        observer.observeUsage_ = std::make_shared<McpObserveUsage>();
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
        {
            McpServer scoped;
            scoped.config_.ObserveOnly = true;
            const McpObserveGrant evidence{std::wstring(64, L'a'), L"fixture", {}, McpObserveAccess::Evidence};
            const McpObserveGrant operations{std::wstring(64, L'b'), L"fixture", {}, McpObserveAccess::Operations};
            scoped.config_.Principals = {evidence, operations};
            McpEngineResult denial;
            McpEngineRequest read{McpRequestKind::ToolCall, L"timeline.query", L"{}", operations};
            std::atomic<uint32_t> balance{64};
            TimelineScanBudget scan(64, balance);
            Check(&context, !scoped.AuthorizeEngineRequest(read, &denial) && denial.IsError &&
                ReadMcpObservedTimeline(read, retained, scan).IsError && scan.ExaminedCount() == 0,
                L"operation access cannot reach the retained reader");
            read.Grant.Access = McpObserveAccess::Both;
            Check(&context, !scoped.AuthorizeEngineRequest(read, &denial), L"engine rejects a widened copy of a configured grant");
            const std::wstring id(32, L'1');
            Check(&context, scoped.operations_.Begin(id, L"timeline.query", 1, 1, {}, evidence.Fingerprint) &&
                scoped.OperationStatus(id, evidence).IsError &&
                scoped.OperationStatus(id, evidence).StructuredJson.find(id) == std::wstring::npos,
                L"direct receipt lookup enforces evidence-only access before reading a known ID");
        }
        auto dispatch = [&](const McpEngineRequest& request, TimelineScanBudget* scan)
        {
            ++dispatches;
            if (!scan) { return McpEngineResult{true, L"missing observe scan budget"}; }
            return ReadMcpObservedTimeline(request, retained, *scan);
        };
        auto blockedBeforeAdmission = [&](const McpEngineRequest& request)
        {
            McpEngineResult admission;
            const bool responded = observer.EnqueueAndWait(request, 0, &admission);
            McpEngineResult terminal;
            const bool rejected = !observer.AuthorizeEngineRequest(request, &terminal) &&
                !observer.DispatchJob(std::make_shared<McpJob>(request, L""), dispatch);
            return responded && admission.IsError && !admission.OutcomeUnknown && admission.OperationJson.empty() &&
                rejected && terminal.IsError && terminal.StructuredJson == admission.StructuredJson && dispatches == 0 &&
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
        const auto runJob = [&](McpServer& server, const McpEngineRequest& request, const McpEngineDispatchFn& handler)
        {
            McpEngineResult result;
            auto waiter = std::async(std::launch::async, [&]() { return server.EnqueueAndWait(request, 5000, &result); });
            if (WaitForSingleObject(server.JobReadyEvent(), 5000) == WAIT_OBJECT_0)
            {
                auto job = server.TryPopJob();
                if (job) { server.DispatchJob(job, handler); }
            }
            if (!waiter.get()) { result.IsError = true; }
            return result;
        };
        const auto invoke = [&](const wchar_t* name, const wchar_t* args)
        {
            return runJob(observer, { McpRequestKind::ToolCall, name, args }, dispatch).StructuredJson;
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
        Check(&context, observer.observeUsage_->AdmittedCalls == 4 && observer.observeUsage_->RequestedEvents == 116 &&
            McpObserveUsage::MaxExaminedEvents - observer.observeUsage_->RemainingScan.load() == 186,
            L"observe-admissions-predicates-and-graph-lookahead-charged-once");
        const McpEngineRequest statusRequest{ McpRequestKind::ToolCall, L"timeline.status", L"{}" };
        const auto exception = runJob(observer, statusRequest, [](const McpEngineRequest&, TimelineScanBudget* scan) -> McpEngineResult
        {
            scan->Visit();
            throw std::runtime_error("private fixture error");
        });
        Check(&context, exception.OutcomeUnknown && exception.Text.find(L"private fixture error") == std::wstring::npos &&
            exception.OperationJson.find(L"\"examined_events\":1,") != std::wstring::npos &&
            exception.OperationJson.find(L"\"state\":\"unknown_outcome\"") != std::wstring::npos,
            L"observe-exception-preserves-examined-work-without-private-detail");
        Check(&context, !observer.DispatchJob(std::make_shared<McpJob>(statusRequest, L""), dispatch) &&
            dispatches == 4, L"observe-cannot-dispatch-an-unadmitted-request");
        auto initializeFixture = [](McpServer& server)
        {
            server.config_.ObserveOnly = true;
            server.observeUsage_ = std::make_shared<McpObserveUsage>();
            server.jobReadyEvent_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        };
        McpServer admissions;
        initializeFixture(admissions);
        const McpEngineRequest fullPage{ McpRequestKind::ToolCall, L"timeline.query", LR"({"limit":"64"})" };
        auto cancelAtAdmission = [&](const McpEngineRequest& request)
        {
            McpEngineResult result;
            admissions.EnqueueAndWait(request, 0, &result);
            return result;
        };
        admissions.maxPending_ = 0;
        McpEngineResult busy;
        Check(&context, !admissions.EnqueueAndWait(fullPage, 0, &busy) && admissions.observeUsage_->AdmittedCalls == 0,
            L"observe-queue-busy-has-no-charge");
        admissions.maxPending_ = 8;
        McpServer ledgerFull;
        initializeFixture(ledgerFull);
        bool filled = true;
        for (unsigned index = 0; index < McpOperationLedger::Capacity; ++index)
        {
            wchar_t id[33]{};
            swprintf_s(id, L"%032x", index);
            filled &= ledgerFull.operations_.Begin(id, L"fixture", 1);
        }
        Check(&context, filled && !ledgerFull.EnqueueAndWait(fullPage, 0, &busy) && busy.OperationJson.empty() &&
            ledgerFull.observeUsage_->AdmittedCalls == 0 && ledgerFull.observeUsage_->RequestedEvents == 0 &&
            WaitForSingleObject(ledgerFull.JobReadyEvent(), 0) == WAIT_TIMEOUT, L"observe-ledger-full-does-not-spend-admission");
        bool cancelled = true;
        for (unsigned index = 0; index < 15; ++index)
        {
            cancelled &= cancelAtAdmission(fullPage).OperationJson.find(L"cancelled_before_execution") != std::wstring::npos;
        }
        std::promise<void> begin;
        auto start = begin.get_future().share();
        auto contend = [&]() { start.wait(); return cancelAtAdmission(fullPage); };
        auto left = std::async(std::launch::async, contend);
        auto right = std::async(std::launch::async, contend);
        begin.set_value();
        const auto a = left.get(), b = right.get();
        const auto& denied = a.OperationJson.empty() ? a : b;
        Check(&context, cancelled && a.OperationJson.empty() != b.OperationJson.empty() &&
            denied.IsError && denied.BudgetLimit == McpBudgetLimit::RequestedEvents &&
            admissions.observeUsage_->AdmittedCalls == 16 && admissions.observeUsage_->RequestedEvents == 1024 &&
            admissions.observeUsage_->RemainingScan == McpObserveUsage::MaxExaminedEvents && !admissions.TryPopJob(),
            L"observe-concurrent-last-admission-and-queued-cancel-accounting");
        for (unsigned index = 16; index < McpObserveUsage::MaxCalls; ++index) { cancelAtAdmission(statusRequest); }
        const auto noCalls = cancelAtAdmission(statusRequest);
        Check(&context, noCalls.BudgetLimit == McpBudgetLimit::Calls && noCalls.OperationJson.empty() &&
            admissions.observeUsage_->AdmittedCalls == McpObserveUsage::MaxCalls, L"observe-exact-call-budget");

        McpServer traversal;
        initializeFixture(traversal);
        TimelineStore large(4097);
        std::vector<TimelineEvent> records(4097, fixtures.front());
        for (size_t index = 0; index < records.size(); ++index) { records[index].TimestampFileTime = 1 + index; }
        Check(&context, large.IngestEvents(records).Added == records.size(), L"observe-scan-quota-owned-corpus");
        auto queryLarge = [&](const McpEngineRequest& req, TimelineScanBudget* scan)
        {
            return ReadMcpObservedTimeline(req, large, *scan);
        };
        bool bounded = !runJob(traversal, { McpRequestKind::ToolCall, L"timeline.query", LR"({"limit":"1"})" }, queryLarge).IsError;
        const auto initialPayload = traversal.observeUsage_->PayloadBytes;
        for (unsigned index = 0; index < 16; ++index)
        {
            const McpEngineRequest filtered{ McpRequestKind::ToolCall, index % 2 ? L"graph.query" : L"timeline.query",
                LR"({"source":"absent","limit":"1"})" };
            const auto result = runJob(traversal, index % 3 ? filtered : statusRequest, queryLarge);
            bounded &= result.BudgetLimit == (index == 15 ? McpBudgetLimit::ExaminedEvents : McpBudgetLimit::QueryExaminedEvents) &&
                result.OperationJson.find(L"\"state\":\"failed\"") != std::wstring::npos &&
                result.OperationJson.find(index == 15 ? L"\"examined_events\":4095," : L"\"examined_events\":4096,") != std::wstring::npos &&
                result.StructuredJson.find(L"\"stage\":\"dispatch\"") != std::wstring::npos &&
                result.StructuredJson.find(L"absent") == std::wstring::npos;
        }
        McpEngineResult exhaustedScan;
        Check(&context, bounded && traversal.EnqueueAndWait(statusRequest, 0, &exhaustedScan) &&
            exhaustedScan.BudgetLimit == McpBudgetLimit::ExaminedEvents && exhaustedScan.OperationJson.empty() &&
            traversal.observeUsage_->RemainingScan == 0 && traversal.observeUsage_->PayloadBytes == initialPayload,
            L"observe-exhausted-scan-suppresses-partial-results-and-stops-further-timeline-admission");

        McpServer payloads;
        initializeFixture(payloads);
        const McpEngineRequest tiStatus{ McpRequestKind::ToolCall, L"ti.subscribe", L"{}" };
        auto publishText = [&](const std::wstring& text)
        {
            return runJob(payloads, tiStatus, [&](const McpEngineRequest&, TimelineScanBudget*)
            {
                McpEngineResult result;
                result.Text = text;
                return result;
            });
        };
        const std::wstring page(McpObserveUsage::MaxResultPayloadBytes / 2, L'\u00e9');
        const auto tooBig = publishText(page + L"x");
        bool published = !publishText(L"\u20ac").IsError;
        for (unsigned index = 0; index < 15; ++index) { published &= !publishText(page).IsError; }
        const auto tooMuch = publishText(page);
        published &= !publishText(std::wstring(McpObserveUsage::MaxResultPayloadBytes - 3, L'a')).IsError;
        McpEngineResult noBytes;
        Check(&context, published && tooBig.BudgetLimit == McpBudgetLimit::ResultPayloadBytes &&
            tooMuch.BudgetLimit == McpBudgetLimit::PayloadBytes && tooMuch.Text.find(L'\u00e9') == std::wstring::npos &&
            tooMuch.StructuredJson.find(L"\"stage\":\"publication\"") != std::wstring::npos &&
            payloads.EnqueueAndWait(tiStatus, 0, &noBytes) && noBytes.BudgetLimit == McpBudgetLimit::PayloadBytes &&
            noBytes.OperationJson.empty() && payloads.observeUsage_->PayloadBytes == McpObserveUsage::MaxPayloadBytes,
            L"observe-exact-utf8-result-and-lifetime-publication-budget");

        McpServer late;
        initializeFixture(late);
        McpEngineResult timedOut;
        auto client = std::async(std::launch::async, [&]() { return late.EnqueueAndWait(statusRequest, 2000, &timedOut); });
        const bool enqueued = WaitForSingleObject(late.JobReadyEvent(), 5000) == WAIT_OBJECT_0;
        auto pendingJob = late.TryPopJob();
        std::promise<void> entered, finish;
        auto running = entered.get_future();
        auto released = finish.get_future();
        auto worker = std::async(std::launch::async, [&]()
        {
            return late.DispatchJob(pendingJob, [&](const McpEngineRequest&, TimelineScanBudget* scan)
            {
                scan->Visit();
                entered.set_value();
                const bool signalled = released.wait_for(std::chrono::seconds(10)) == std::future_status::ready;
                McpEngineResult result;
                result.IsError = !signalled;
                result.Text.assign(McpObserveUsage::MaxResultPayloadBytes + 1, L'p');
                return result;
            });
        });
        const bool observed = running.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
        const bool returned = client.get();
        finish.set_value();
        const bool finished = worker.get();
        const auto settlement = late.OperationStatus(pendingJob ? pendingJob->OperationId : L"").StructuredJson;
        Check(&context, enqueued && observed && returned && finished && timedOut.OutcomeUnknown &&
            timedOut.OperationJson.find(L"\"examined_events\":null") != std::wstring::npos &&
            settlement.find(L"\"state\":\"failed\"") != std::wstring::npos &&
            settlement.find(L"\"examined_events\":1,\"payload_utf8_bytes\":0") != std::wstring::npos &&
            settlement.find(L"\"dimension\":\"per_result_payload_utf8_bytes\",\"stage\":\"publication\"") != std::wstring::npos &&
            late.observeUsage_->AdmittedCalls == 1 && late.observeUsage_->PayloadBytes == 0,
            L"observe-running-timeout-settles-late-budget-denial-and-cost");
        Check(&context, McpObserveAddressSelfTest(), L"observe-connection-address-boundary");
        Check(&context, McpObserveTlsSelfTest(), L"observe-tls-principal-certificate-transport-and-local-endpoint-boundary");
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

// A separate process lets the test controller terminate this exact listener
// after a real queue/dispatch boundary, without running the live debugger.
int RunMcpJournalTransportFixture(const std::wstring& directory)
{
    std::wstring password;
    if (!std::getline(std::wcin, password) || password.empty()) { return 1; }
    const McpObserveGrant source{std::wstring(64, L'a'), L"ti"};
    McpObserveGrant target = source;
    target.Target = ObservationIdentity{std::wstring(32, L'1'), 22, 33};
    const McpObserveGrant* grants[] = {&source, &target};
    for (bool tls : {false, true})
    {
        const auto mode = tls ? McpJournalMode::ScopedHttps : McpJournalMode::ScopedLoopback;
        const auto other = tls ? McpJournalMode::ScopedLoopback : McpJournalMode::ScopedHttps;
        const auto root = directory + (tls ? L"\\https" : L"\\loopback");
        if (GetFileAttributesW(root.c_str()) != INVALID_FILE_ATTRIBUTES || GetLastError() != ERROR_FILE_NOT_FOUND) { return 1; }
        {
            McpOperationJournal journal;
            if (!journal.Open(root, password, nullptr, mode)) { return 1; }
            for (const auto* grant : grants)
            {
                McpOperationSnapshot record;
                record.Id = std::wstring(32, grant->Target ? L'a' : L'b');
                record.Name = L"timeline.query";
                record.OwnerFingerprint = grant->Fingerprint;
                record.Journal = journal.Identify({McpRequestKind::ToolCall, record.Name, L"{}", *grant});
                if (!record.Journal || !journal.Persist(record)) { return 1; }
            }
        }
        McpOperationJournal recovered;
        if (recovered.Open(root, password, nullptr, other) || !recovered.Open(root, password, nullptr, mode)) { return 1; }
        for (const auto* grant : grants)
        {
            std::wstring receipt;
            const std::wstring id(32, grant->Target ? L'a' : L'b');
            if (!recovered.Lookup(id, *grant, &receipt) || receipt.find(McpScopedJournalName(tls, grant->Target.has_value())) == std::wstring::npos ||
                recovered.Lookup(id, grant->Target ? source : target, &receipt)) { return 1; }
        }
    }
    std::wcout << L"transport journal isolation and recovery passed" << std::endl;
    return 0;
}

int RunMcpJournalFixture(const wchar_t* directory, uint16_t port, const std::vector<McpObserveGrant>& grants, uint32_t targetSessionSeconds, bool tls)
{
    McpServer server;
    McpServerConfig config;
    config.Port = port;
    config.ObserveOnly = true;
    config.Tls = tls;
    config.BindAddress = L"127.0.0.1";
    config.Principals = grants;
    config.TargetSessionSeconds = targetSessionSeconds;
    if (std::wstring(directory) != L"-") { config.OperationJournalDirectory = directory; }
    config.AuditPath = config.OperationJournalDirectory.empty() ? L"fixture-audit.jsonl" : config.OperationJournalDirectory + L"\\fixture-audit.jsonl";
    std::wstring error, line;
    if (!std::getline(std::wcin, config.Password) || !server.Start(config, &error))
    {
        std::wcout << (tls ? L"unavailable: " + error : L"unavailable") << std::endl;
        return 1;
    }
    if (!grants.empty() && (server.TokenSource() != L"principal" || !server.Password().empty() || !server.Token().empty())) { return 2; }
    std::wcout << L"ready" << std::endl;
    TimelineStore timeline(1);
    if (!grants.empty())
    {
        // Interleave exact, case-variant and prefix labels and carry a raw field
        // on every row. The wire oracle exercises the normal retained store.
        uint32_t pid = 0;
        for (const auto* source : {L"alpha", L"beta", L"Alpha", L"alpha.more", L"alpha"})
        {
            TimelineEvent row;
            row.Source = source;
            row.Domain = L"process";
            row.Action = L"fixture-" + std::to_wstring(++pid);
            row.ProcessId = pid;
            row.TimestampFileTime = pid;
            row.Evidence[L"private"] = L"fixture-private-context";
            row.Summary = L"fixture-private-summary";
            timeline.IngestEvents({row});
        }
    }
    std::shared_ptr<McpJob> job;
    const bool targetFixture = std::any_of(grants.begin(), grants.end(), [](const auto& grant) { return grant.Target.has_value(); });
    std::shared_ptr<McpJob> observedRequest;
    if (targetFixture)
    {
        const std::wstring boot(32, L'b'), otherBoot(32, L'c');
        auto append = [&](const std::wstring& bootId, uint32_t pid, uint64_t created, uint64_t timestamp, const wchar_t* action)
        {
            TiEventRecord event;
            event.ProcessBootId = bootId;
            event.ProcessId = pid;
            event.ProcessCreateTime = created;
            event.ThreadId = 17;
            event.TargetProcessId = pid == 73 ? 94 : 73;
            event.Timestamp = timestamp;
            event.TaskName = action;
            return timeline.IngestThreatIntel({event}, L"all", 1).Added;
        };
        // Submit the unqualified twin first, then the same row twice with a verified lifetime.
        if (append({}, 73, 100, 1010, L"HeaderA") != 1 || append(boot, 73, 100, 1010, L"HeaderA") != 1 ||
            append(boot, 73, 100, 1010, L"HeaderA") != 0) { return 2; }
        append(boot, 73, 100, 1011, L"HeaderB");
        append(boot, 73, 200, 1020, L"ReusedPid");
        append(otherBoot, 73, 100, 1021, L"OtherBoot");
        append(boot, 94, 100, 1022, L"PayloadPeer");
        append(boot, 73, 0, 1023, L"MissingCreation");
        append(boot, 73, 2000, 1024, L"FutureCreation");
        append(std::wstring(32, L'0'), 73, 100, 1025, L"InvalidBoot");
        TimelineEvent imported;
        imported.Source = L"ti";
        imported.Domain = L"threat-intelligence";
        imported.Action = L"Imported";
        imported.ProcessId = 73;
        imported.Evidence[L"process_instance_id"] = boot + L":73:100";
        timeline.IngestEvents({imported});
        bool more = false;
        if (timeline.RetainedTargets(L"ti", 73, more).size() != 3 || more ||
            timeline.RetainedTargets(L"ti", 94, more).size() != 1 || more) { return 2; }
    }
    auto waitForExpiry = [&](const McpEngineRequest& request)
    {
        if (!request.Grant.Target) { return false; }
        const auto deadline = GetTickCount64() + 15000;
        for (;;)
        {
            {
                std::lock_guard<std::mutex> lock(server.queueMutex_);
                if (!server.TargetSessionAllowedLocked(request.Grant, request.TargetSession)) { return true; }
            }
            if (GetTickCount64() >= deadline) { return false; }
            Sleep(10);
        }
    };
    while (std::getline(std::wcin, line) && line != L"stop")
    {
        if (!grants.empty() && line == L"evict")
        {
            timeline.SetCapacity(2048);
            TimelineEvent row;
            row.Source = L"alpha.more";
            row.Domain = L"process";
            for (uint32_t i = 1; i <= 1023; ++i)
            {
                row.TimestampFileTime = i;
                row.Action = std::to_wstring(i);
                timeline.IngestEvents({row});
            }
            timeline.SetCapacity(1024); // leaves the last alpha row at the front
            row.Source = L"beta";
            row.Action.assign(129, L'x');
            if (timeline.IngestEvents({row, row}).Added != 1) { return 2; }
            std::wcout << L"evicted" << std::endl;
        }
        else if (!grants.empty() && line == L"clear")
        {
            timeline.Clear();
            std::wcout << L"cleared" << std::endl;
        }
        else if (line == L"queued")
        {
            if (WaitForSingleObject(server.JobReadyEvent(), 15000) != WAIT_OBJECT_0) { return 2; }
            std::lock_guard<std::mutex> lock(server.queueMutex_);
            if (server.queue_.size() != 1) { return 2; }
            if (targetFixture) { observedRequest = server.queue_.front(); }
            std::wcout << L"queued " << server.queue_.front()->OperationId << std::endl;
        }
        else if (line == L"dispatch" && !job)
        {
            job = server.TryPopJob();
            std::wcout << (job ? L"dispatched " + job->OperationId : L"refused") << std::endl;
        }
        else if (line == L"await-expiry" && targetFixture)
        {
            // The queued HTTP call occupies the listener. Observe its own lease
            // under the production lock before allowing the next fixture action.
            if (!observedRequest || !waitForExpiry(observedRequest->Request)) { return 2; }
            std::wcout << L"expired" << std::endl;
        }
        else if (line == L"return-across-expiry" && job && targetFixture)
        {
            bool read = false;
            const bool claimed = server.DispatchJob(job, [&](const McpEngineRequest& request, TimelineScanBudget* scan)
            {
                auto result = ReadMcpObservedTimeline(request, timeline, *scan);
                read = !result.IsError && !result.StructuredJson.empty() && scan->ExaminedCount() > 0;
                read = waitForExpiry(request) && read;
                return result;
            });
            job.reset();
            std::wcout << (claimed && read ? L"read-across-expiry" : L"refused") << std::endl;
        }
        else if (line == L"restart-held" && job)
        {
            std::promise<void> entered, release;
            auto started = entered.get_future();
            auto finish = release.get_future();
            auto old = std::async(std::launch::async, [&]()
            {
                return server.DispatchJob(job, [&](const McpEngineRequest& req, TimelineScanBudget* scan)
                {
                    entered.set_value();
                    finish.wait();
                    return ReadMcpObservedTimeline(req, timeline, *scan);
                });
            });
            const bool running = started.wait_for(std::chrono::seconds(5)) == std::future_status::ready;
            server.Stop();
            const bool restarted = server.Start(config, &error);
            release.set_value();
            const bool claimed = old.get();
            job.reset();
            std::wcout << (running && restarted && claimed ? L"restarted" : L"refused") << std::endl;
        }
        else if (line == L"return" && job)
        {
            const bool claimed = server.DispatchJob(job, [&](const McpEngineRequest& request, TimelineScanBudget* scan)
            {
                return ReadMcpObservedTimeline(request, timeline, *scan);
            });
            job.reset();
            std::wcout << (claimed ? L"returned" : L"refused") << std::endl;
        }
        else { return 2; }
    }
    server.Stop();
    return 0;
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
            return IsMcpOperationId(job->OperationId) && server.DispatchJob(job,
                [&](const McpEngineRequest& req, TimelineScanBudget* scan) { return ReadMcpObservedTimeline(req, timeline, *scan); });
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
    const auto readWireBudget = [&]()
    {
        post(R"({"jsonrpc":"2.0","id":24,"method":"resources/read","params":{"uri":"kn://capabilities"}})",
            200, L"kn.mcp_observe_budget.v1", L"http-observe-budget-resource");
        std::wstring result, contents, text, budget;
        if (mcpjson::FindRawValue(lastResponse, L"result", &result) &&
            mcpjson::FindRawValue(result, L"contents", &contents) && contents.size() >= 2 &&
            mcpjson::GetString(contents.substr(1, contents.size() - 2), L"text", &text))
        {
            mcpjson::FindRawValue(text, L"observe_budget", &budget);
        }
        return budget;
    };
    const auto used = [](const std::wstring& budget, const wchar_t* dimension)
    {
        std::wstring entry, count;
        if (mcpjson::FindRawValue(budget, dimension, &entry)) { mcpjson::FindRawValue(entry, L"used", &count); }
        return count;
    };
    if (observe)
    {
        const auto budget = readWireBudget();
        Check(&context, used(budget, L"admitted_calls") == L"1" && used(budget, L"requested_events") == L"1" &&
            used(budget, L"examined_events") == L"0", L"http-observe-denials-and-control-lookups-uncharged");
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
        bool released = false;
        auto handler = [&](const McpEngineRequest&, TimelineScanBudget*)
        {
            McpEngineResult completed;
            released = release.wait_for(std::chrono::seconds(60)) == std::future_status::ready;
            completed.IsError = !released;
            completed.StructuredJson = L"{\"fixture\":true}";
            return completed;
        };
        return job && server.DispatchJob(job, handler) && released && !server.DispatchJob(job, handler);
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
    if (observe)
    {
        std::wstring charge;
        Check(&context, mcpjson::FindRawValue(operation, L"observe_charge", &charge) &&
            charge.find(L"\"examined_events\":null") != std::wstring::npos && charge.find(L"\"payload_utf8_bytes\":null") != std::wstring::npos,
            L"http-observe-unsettled-costs-stay-unknown-after-timeout");
    }
    const std::string query = mcpjson::WideToUtf8(L"{\"jsonrpc\":\"2.0\",\"id\":4,\"method\":\"tools/call\",\"params\":{\"name\":\"operations.get\",\"arguments\":{\"operation_id\":" +
        mcpjson::Quote(operationId) + L"}}}");
    post(query, 200, L"\"state\":\"unknown_outcome\"", L"http-status-bypasses-blocked-engine");
    Check(&context, !server.TryPopJob(), L"http-status-does-not-enqueue-another-operation");
    std::wstring waitingBudget;
    if (observe) { waitingBudget = readWireBudget(); }
    releaseEngine.set_value();
    Check(&context, engine.get(), L"http-late-engine-completion");
    std::string finalQuery = query;
    const auto requestId = finalQuery.find("\"id\":4");
    if (requestId != std::string::npos)
    {
        finalQuery.replace(requestId, 6, "\"id\":5");
    }
    post(finalQuery, 200, L"\"state\":\"succeeded\"", L"http-late-completion-status");
    if (observe)
    {
        Check(&context, lastResponse.find(L"\"payload_utf8_bytes\":16") != std::wstring::npos &&
            lastResponse.find(L"\"examined_events\":0") != std::wstring::npos, L"http-observe-late-receipt-settles-payload");
        const auto after = readWireBudget();
        const auto beforeBytes = used(waitingBudget, L"payload_utf8_bytes");
        Check(&context, used(waitingBudget, L"admitted_calls") == L"2" && used(after, L"admitted_calls") == L"2" &&
            !beforeBytes.empty() && used(after, L"payload_utf8_bytes") == std::to_wstring(
                wcstoul(beforeBytes.c_str(), nullptr, 10) + std::string("{\"fixture\":true}").size()),
            L"http-observe-timeout-and-duplicate-completion-charge-once");
    }
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
            return server.DispatchJob(job, [&](const McpEngineRequest&, TimelineScanBudget*)
            {
                McpEngineResult result;
                result.IsError = variant != 0;
                result.Text = L"synthetic resource";
                result.StructuredJson = L"{\"fixture\":true}";
                return result;
            });
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
    if (observe)
    {
        bool completed = true;
        auto oversized = std::async(std::launch::async, [&]()
        {
            if (WaitForSingleObject(server.JobReadyEvent(), 5000) != WAIT_OBJECT_0) { return false; }
            return server.DispatchJob(server.TryPopJob(), [](const McpEngineRequest&, TimelineScanBudget*)
            {
                McpEngineResult result;
                result.Text.assign(McpObserveUsage::MaxResultPayloadBytes, L'x');
                result.StructuredJson = LR"({"observe-audit-canary":true})";
                return result;
            });
        });
        post(R"({"jsonrpc":"2.0","id":25,"method":"resources/read","params":{"uri":"kn://ti/stats"}})",
            200, L"per_result_payload_utf8_bytes", L"http-observe-oversize-resource-withheld");
        std::wstring errorEnvelope, data, deniedId, denial, stage;
        Check(&context, oversized.get() && mcpjson::FindRawValue(lastResponse, L"error", &errorEnvelope) &&
            mcpjson::FindRawValue(errorEnvelope, L"data", &data) && mcpjson::GetString(data, L"operation_id", &deniedId) &&
            IsMcpOperationId(deniedId) && mcpjson::FindRawValue(data, L"budget_denial", &denial) &&
            mcpjson::GetString(denial, L"stage", &stage) && stage == L"publication" &&
            lastResponse.find(L"observe-audit-canary") == std::wstring::npos,
            L"http-observe-resource-error-retains-receipt-and-typed-denial");
        const std::string lookup = mcpjson::WideToUtf8(L"{\"jsonrpc\":\"2.0\",\"id\":31,\"method\":\"tools/call\",\"params\":{\"name\":\"operations.get\",\"arguments\":{\"operation_id\":" +
            mcpjson::Quote(deniedId) + L"}}}");
        post(lookup, 200, L"\"state\":\"failed\"", L"http-observe-denied-result-lookup");
        Check(&context, lastResponse.find(L"\"dimension\":\"per_result_payload_utf8_bytes\"") != std::wstring::npos &&
            lastResponse.find(L"\"stage\":\"publication\"") != std::wstring::npos && lastResponse.find(L"\"payload_utf8_bytes\":0") != std::wstring::npos,
            L"http-observe-denial-cause-and-zero-publication-survive-lookup");
        for (unsigned index = 0; index < 16; ++index)
        {
            const auto page = std::string(R"({"jsonrpc":"2.0","id":26,"method":"tools/call","params":{"name":"timeline.query","arguments":{"limit":")") +
                (index == 15 ? "63" : "64") + R"("}}})";
            auto reader = std::async(std::launch::async, [&]()
            {
                if (WaitForSingleObject(server.JobReadyEvent(), 5000) != WAIT_OBJECT_0) { return false; }
                auto job = server.TryPopJob();
                if (!job) { return false; }
                TimelineStore store(1);
                return server.DispatchJob(job, [&](const McpEngineRequest& request, TimelineScanBudget* scan)
                {
                    return ReadMcpObservedTimeline(request, store, *scan);
                });
            });
            post(page, 200, L"\"state\":\"succeeded\"", L"http-observe-page-admission");
            completed &= reader.get();
        }
        const auto full = readWireBudget();
        const auto priorSession = sessionId;
        post(R"({"jsonrpc":"2.0","id":27,"method":"initialize","params":{}})", 200, L"protocolVersion",
            L"http-observe-repeat-client-initialize");
        Check(&context, completed && used(full, L"requested_events") == L"1024" && sessionId != priorSession &&
            readWireBudget() == full, L"http-observe-initialize-cannot-replenish-quota");
        post(R"({"jsonrpc":"2.0","id":28,"method":"tools/call","params":{"name":"graph.query","arguments":{"limit":"1"}}})",
            200, L"budget_exhausted", L"http-observe-exhausted-requests-denied");
        Check(&context, lastResponse.find(L"\"dimension\":\"requested_events\"") != std::wstring::npos &&
            lastResponse.find(L"operation_id") == std::wstring::npos &&
            WaitForSingleObject(server.JobReadyEvent(), 0) == WAIT_TIMEOUT, L"http-observe-no-operation-after-quota");
        post(finalQuery, 200, L"\"state\":\"succeeded\"", L"http-observe-outcome-lookup-after-quota");
        Check(&context, readWireBudget() == full, L"http-observe-exhaustion-and-receipt-leave-budget-intact");
        std::promise<void> finishOldJob;
        auto finish = finishOldJob.get_future();
        auto oldEngine = std::async(std::launch::async, [&]()
        {
            if (WaitForSingleObject(server.JobReadyEvent(), 5000) != WAIT_OBJECT_0) { return false; }
            return server.DispatchJob(server.TryPopJob(), [&](const McpEngineRequest&, TimelineScanBudget* scan)
            {
                server.RequestStop();
                McpEngineResult result;
                result.IsError = !scan || finish.wait_for(std::chrono::seconds(30)) != std::future_status::ready || !scan->Visit();
                result.Text = L"prior listener fixture";
                return result;
            });
        });
        post(R"({"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"ti.subscribe","arguments":{}}})",
            200, L"unknown_outcome", L"http-observe-stop-after-dispatch-retains-unknown-outcome");
        server.Stop();
        const bool restarted = server.Start(config, &error);
        finishOldJob.set_value();
        Check(&context, oldEngine.get(), L"http-observe-prior-listener-completion-observed");
        Check(&context, restarted, L"http-observe-fresh-listener");
        if (restarted)
        {
            post(R"({"jsonrpc":"2.0","id":29,"method":"initialize","params":{}})", 200, L"protocolVersion", L"http-observe-fresh-session");
            const auto fresh = readWireBudget();
            Check(&context, used(fresh, L"admitted_calls") == L"0" && used(fresh, L"requested_events") == L"0" &&
                used(fresh, L"examined_events") == L"0" && used(fresh, L"payload_utf8_bytes") == L"0",
                L"http-observe-new-listener-has-fresh-allowance");
            post(finalQuery, 200, L"not_retained", L"http-observe-new-listener-has-fresh-ledger");
        }
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
            audit.find("\"decision\":\"budget_exhausted\"") != std::string::npos &&
            audit.find("\"stage\":\"admission\"") != std::string::npos && audit.find("\"stage\":\"publication\"") != std::string::npos &&
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
