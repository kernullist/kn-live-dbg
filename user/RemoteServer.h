#pragma once

#include "RemoteProtocol.h"

#include <atomic>
#include <cstdint>
#include <deque>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

struct RemoteHelloInfo
{
    std::wstring Hostname;
    std::wstring Os;
    uint32_t Abi = 15;
    bool WriteMode = true;
    bool Cloak = false;
};

struct RemoteServerConfig
{
    uint16_t Port = knremote::kDefaultPort;
    std::wstring BindAddress = L"0.0.0.0";
    std::wstring Peer;
    std::wstring Password;
    std::wstring AuditPath;
    bool AddFirewall = true;
    RemoteHelloInfo Hello;
};

struct RemoteEngineResult
{
    bool IsError = false;
    std::wstring Code;
    std::wstring Stdout;
    std::wstring Stderr;
    bool KeepRunning = true;
};

struct RemoteJob
{
    std::wstring Line;
    std::wstring RequestId;
    std::promise<RemoteEngineResult> ResultPromise;
    std::shared_ptr<std::atomic<bool>> Cancelled;
};

class RemoteServer
{
public:
    RemoteServer();
    ~RemoteServer();

    RemoteServer(const RemoteServer&) = delete;
    RemoteServer& operator=(const RemoteServer&) = delete;

    bool Start(const RemoteServerConfig& config, std::wstring* error);
    void Stop();
    void RequestStop();
    void DisconnectSession();

    bool IsRunning() const;
    uint16_t Port() const;
    std::wstring BindAddress() const;
    bool IsLoopbackOnly() const;
    std::wstring PeerIp() const;
    std::wstring AuditPath() const;
    std::wstring FirewallWarning() const;

    void SetHelloWriteMode(bool writeMode);
    RemoteHelloInfo Hello() const;

    HANDLE JobReadyEvent() const;
    HANDLE StopEvent() const;
    HANDLE WriteOffEvent() const;
    std::shared_ptr<RemoteJob> TryPopJob();

    void AppendAuditLine(const std::wstring& line);

private:
    void ListenerThreadMain();
    void HandleClient(SOCKET client, const std::wstring& peerIp, uint32_t peerHost);
    bool RecvAll(SOCKET sock, char* buffer, int length, DWORD deadlineTick, std::wstring* error);
    bool RecvFrame(SOCKET sock, std::wstring* json, DWORD deadlineTick, std::wstring* error);
    bool SendJson(SOCKET sock, const std::wstring& json, std::wstring* error);
    bool EnqueueAndWait(
        const std::wstring& line,
        const std::wstring& requestId,
        SOCKET client,
        RemoteEngineResult* result);
    bool AuthAllowed(uint32_t peerHost);
    void RecordAuthFailure(uint32_t peerHost);
    void RecordAuthSuccess(uint32_t peerHost);

    RemoteServerConfig config_;
    RemoteHelloInfo hello_;
    mutable std::mutex helloMutex_;

    SOCKET listenSock_ = INVALID_SOCKET;
    SOCKET sessionSock_ = INVALID_SOCKET;
    mutable std::mutex sessionMutex_;
    std::wstring peerIp_;
    bool wsaStarted_ = false;
    bool firewallAdded_ = false;
    std::wstring firewallWarning_;

    std::thread listener_;
    HANDLE stopEvent_ = nullptr;
    HANDLE writeOffEvent_ = nullptr;
    HANDLE jobReadyEvent_ = nullptr;
    std::atomic<bool> running_{ false };

    std::mutex queueMutex_;
    std::deque<std::shared_ptr<RemoteJob>> queue_;
    std::atomic<bool> commandInFlight_{ false };

    std::mutex lockoutMutex_;
    std::map<uint32_t, int> failCounts_;
    int globalFails_ = 0;

    std::mutex auditMutex_;
};

bool ParseRemoteConnectArgs(
    int argc,
    wchar_t** argv,
    std::wstring* host,
    uint16_t* port,
    std::wstring* error);

bool HasUnknownControllerArgv(int argc, wchar_t** argv);
bool IsRemoteDeniedCommandLine(const std::wstring& line, std::wstring* reason);
bool IsRemoteAddressOnlyEnter(const std::wstring& line);

int RemoteClientMain(int argc, wchar_t** argv);
int RunRemoteProtocolSelfTest();
int RunRemoteConnectArgvSelfTest();
