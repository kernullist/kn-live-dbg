#pragma once

// In-process MCP (Model Context Protocol) server for KnLiveDbg. Transport is
// loopback-only Streamable HTTP (http.sys), bound to 127.0.0.1/::1. The server
// owns the HTTP listener thread, authentication, JSON-RPC framing, the static
// tool/resource/prompt catalog, and a serialized job queue. It NEVER touches
// the kernel engine directly: each tool/resource call is pushed onto the queue
// and executed on the single engine thread (which owns DeviceClient and
// DbgHelp/DIA) via the dispatch callback the engine drains.
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

struct McpServerConfig
{
    uint16_t Port = 51766;
    bool AllowWrite = false;
    // Append-only JSONL forensic log of every MCP request. Set by the caller
    // at "mcp on"; logging is always on while the server runs (independent of
    // the operator's `ai audit` setting).
    std::wstring AuditPath;
    // Empty = loopback-only (127.0.0.1/[::1]) and strict loopback Host check
    // (the secure default). A concrete IP, or "0.0.0.0"/"+"/"*" for all
    // interfaces, opts into NETWORK exposure: the URL is also registered on
    // that address and the Host check is relaxed (the bearer token + Origin
    // rejection remain the barrier). Use only on a trusted lab segment.
    std::wstring BindAddress;
    // Bearer-token stability so a client registered once keeps working across
    // restarts. Resolution order in Start(): TokenOverride (--token) >
    // KNLIVEDBG_TOKEN env > persisted TokenPath file > freshly minted (then
    // persisted). RotateToken (--new-token) forces a fresh random token,
    // overwriting the persisted file.
    std::wstring TokenPath;      // persisted per-user token file (<LocalAppData>\kn-live-dbg\mcp-token)
    std::vector<std::wstring> LegacyTokenPaths; // optional old per-port token files
    std::wstring TokenOverride;  // explicit --token value; empty = none
    bool RotateToken = false;    // --new-token
};

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

    // Starts the http.sys listener on 127.0.0.1:<port>/mcp (and [::1]). Resolves
    // a stable bearer token. Returns false (with error) if token persistence or
    // transport initialization fails. On success the server accepts requests.
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
    std::wstring Token() const;
    // How the active token was obtained: "override" | "env" | "reused" | "new".
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
    // Resolves the bearer token per the config precedence (see McpServerConfig)
    // and records how it was obtained in tokenSource_.
    bool ResolveToken(std::wstring* token, std::wstring* error);

    std::mutex auditMutex_;

    McpServerConfig config_;
    std::wstring token_;
    std::wstring tokenSource_;
    std::wstring sessionId_;

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
