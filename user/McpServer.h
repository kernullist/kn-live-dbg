#pragma once

// In-process MCP (Model Context Protocol) server for KnLiveDbg. Transport is
// Streamable HTTP (http.sys). Default listen is all interfaces (0.0.0.0 / "+")
// so multi-adapter hosts do not bind the wrong NIC. Auth is a session password
// the operator types at `mcp on`. The server owns the HTTP listener thread,
// authentication, JSON-RPC framing, the static tool/resource/prompt catalog,
// and a serialized job queue. It NEVER touches the kernel engine directly:
// each tool/resource call is pushed onto the queue and executed on the single
// engine thread (which owns DeviceClient and DbgHelp/DIA) via the dispatch
// callback the engine drains.
//
// See docs/MCP_SERVER_DESIGN.md for the full design and security rationale.

#include <Windows.h>
#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

enum class McpRequestKind
{
    ToolCall,
    ResourceRead
};

// A unit of work to run on the engine thread. For ToolCall, Name is the tool
// id (e.g. "callbacks.list") and ArgumentsJson is the raw JSON object the
// client supplied. For ResourceRead, Name is the resource URI.
struct McpEngineRequest
{
    McpRequestKind Kind;
    std::wstring Name;
    std::wstring ArgumentsJson;
};

// Result produced by the engine-thread dispatch. Text is the primary human/
// model-readable content (already redacted by the engine). StructuredJson, if
// non-empty, is a serialized JSON object surfaced as MCP structuredContent.
struct McpEngineResult
{
    bool IsError = false;
    std::wstring Text;
    std::wstring StructuredJson;
};

struct McpJob
{
    McpEngineRequest Request;
    std::promise<McpEngineResult> ResultPromise;
};

// Invoked ON the engine thread for each dequeued job. Implemented in main.cpp
// so it can reach the file-static capability/command/write machinery.
using McpEngineDispatchFn = std::function<McpEngineResult(const McpEngineRequest&)>;

struct McpListenAddress
{
    std::wstring Ip;
    std::wstring AdapterName;
    bool Loopback = false;
    bool LinkLocal = false;
};

struct McpServerConfig
{
    uint16_t Port = 51766;
    bool AllowWrite = false;
    // Append-only JSONL forensic log of every MCP request. Set by the caller
    // at "mcp on"; logging is always on while the server runs (independent of
    // the operator's `ai audit` setting).
    std::wstring AuditPath;
    // Default "0.0.0.0" listens on every adapter (http.sys strong wildcard
    // "+"). "loopback" / "127.0.0.1" stays local-only. A concrete IP pins one
    // address in addition to loopback. Do not pick an adapter by default:
    // multi-NIC hosts otherwise bind the wrong interface.
    std::wstring BindAddress = L"0.0.0.0";
    // Session password set when the operator enables MCP. Not persisted across
    // process restarts. Clients send it as `Authorization: Bearer <password>`.
    std::wstring Password;
};

bool SanitizeMcpPassword(
    const std::wstring& raw,
    std::wstring* password,
    std::wstring* error);
bool IsMcpWildcardBind(const std::wstring& bindAddress);
bool IsMcpLoopbackBind(const std::wstring& bindAddress);
bool IsMcpConcreteIpv4Bind(const std::wstring& bindAddress);
std::wstring NormalizeMcpBindAddress(const std::wstring& bindAddress);
void CollectMcpListenAddresses(std::vector<McpListenAddress>* addresses);
bool McpAuthorizationMatchesPassword(
    const std::string& authorization,
    const std::wstring& password);

// Atomically writes an MCP secret-bearing file with a protected DACL granting
// full access only to the current process user. The destination is replaced
// only after the complete temporary file has been flushed.
bool WriteMcpSensitiveFile(
    const std::wstring& path,
    const std::string& bytes,
    std::wstring* error);

struct McpToolCatalogEntry
{
    std::wstring Name;
    bool ReadOnly = true;
    std::vector<std::wstring> Arguments;
};

std::vector<McpToolCatalogEntry> BuildMcpToolCatalogSnapshot();
bool FindMcpToolCatalogEntry(const std::wstring& name, McpToolCatalogEntry* entry);

class McpServer
{
public:
    McpServer();
    ~McpServer();

    McpServer(const McpServer&) = delete;
    McpServer& operator=(const McpServer&) = delete;

    // Starts the http.sys listener. Default bind is all interfaces
    // (http://+:<port>/mcp/). Requires a session password. Returns false (with
    // error) if the password is invalid or transport initialization fails.
    bool Start(const McpServerConfig& config, std::wstring* error);

    // Stops the listener, cancels queued jobs, and joins the listener thread.
    void Stop();

    // Lightweight stop request for use from inside the engine loop's control
    // path: signals the listener and flips running_ without joining/closing
    // (the engine thread performs the full Stop() after it exits the loop).
    void RequestStop();

    bool IsRunning() const;
    bool AllowWrite() const;
    // True if name is an advertised non-read-only (write) tool. The kTools table
    // is the single source of truth for write-ness; the engine routes by this.
    bool IsWriteTool(const std::wstring& name) const;
    uint16_t Port() const;
    std::wstring BindAddress() const;
    bool IsLoopbackOnly() const;
    bool WildcardBound() const;
    bool IsNetworkExposed() const;
    std::vector<std::wstring> RegisteredHosts() const;
    std::wstring Token() const;
    std::wstring Password() const;
    std::wstring TokenSource() const;
    std::wstring AuditPath() const;

    // Engine-thread interface. The engine waits on JobReadyEvent(), then drains
    // pending jobs with TryPopJob() and fulfills each via the job's promise.
    HANDLE JobReadyEvent() const;
    std::shared_ptr<McpJob> TryPopJob();

private:
    // Listener-side (transport) helpers.
    void ListenerThreadMain();
    bool EnqueueAndWait(const McpEngineRequest& request, uint32_t timeoutMs, McpEngineResult* result);
    void AppendAuditLine(const std::wstring& line);
    bool AddUrlPrefix(void* urlGroup, const std::wstring& host, std::wstring* error);

    std::mutex auditMutex_;

    McpServerConfig config_;
    std::wstring token_;
    std::wstring tokenSource_;
    std::wstring sessionId_;
    std::vector<std::wstring> registeredHosts_;
    bool wildcardBound_ = false;

    // http.sys handles.
    void* serverSessionId_ = nullptr;  // HTTP_SERVER_SESSION_ID (HTTP_OPAQUE_ID)
    void* urlGroupId_ = nullptr;       // HTTP_URL_GROUP_ID
    HANDLE requestQueue_ = nullptr;
    bool httpInitialized_ = false;

    std::thread listener_;
    HANDLE stopEvent_ = nullptr;
    std::atomic<bool> running_{ false };
    std::atomic<bool> stopRequested_{ false };
    std::mutex stopMutex_;

    // Serialized job queue drained by the single engine thread.
    std::mutex queueMutex_;
    std::deque<std::shared_ptr<McpJob>> queue_;
    HANDLE jobReadyEvent_ = nullptr;
    size_t maxPending_ = 8;
};
