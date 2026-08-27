#include "RemoteServer.h"

#include "CommandRegistry.h"
#include "CompletionHints.h"
#include "RemoteFirewall.h"

#include <chrono>
#include <cstdio>
#include <cwctype>
#include <fstream>
#include <sstream>

namespace
{
    std::wstring SockError(const wchar_t* prefix)
    {
        return std::wstring(prefix) + L" (" + std::to_wstring(WSAGetLastError()) + L")";
    }

    std::wstring Ipv4Text(const in_addr& addr)
    {
        char text[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &addr, text, INET_ADDRSTRLEN);
        return mcpjson::Utf8ToWide(text);
    }

    std::wstring LocalHostname()
    {
        wchar_t name[MAX_COMPUTERNAME_LENGTH + 1] = {};
        DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
        if (!GetComputerNameW(name, &size))
        {
            return L"unknown";
        }
        return name;
    }

    std::wstring LocalOsText()
    {
        return L"Windows";
    }

    std::wstring MakeSessionId()
    {
        LARGE_INTEGER qpc = {};
        QueryPerformanceCounter(&qpc);
        wchar_t text[17] = {};
        swprintf_s(
            text,
            L"%08x%08x",
            static_cast<unsigned>(qpc.LowPart),
            GetTickCount());
        return text;
    }
}

RemoteServer::RemoteServer()
{
    stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    writeOffEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    jobReadyEvent_ = CreateEventW(nullptr, FALSE, FALSE, nullptr);
}

RemoteServer::~RemoteServer()
{
    Stop();
    if (stopEvent_ != nullptr)
    {
        CloseHandle(stopEvent_);
        stopEvent_ = nullptr;
    }
    if (writeOffEvent_ != nullptr)
    {
        CloseHandle(writeOffEvent_);
        writeOffEvent_ = nullptr;
    }
    if (jobReadyEvent_ != nullptr)
    {
        CloseHandle(jobReadyEvent_);
        jobReadyEvent_ = nullptr;
    }
}

bool RemoteServer::Start(const RemoteServerConfig& config, std::wstring* error)
{
    bool ok = false;
    std::wstring password;

    do
    {
        if (running_.load())
        {
            if (error != nullptr)
            {
                *error = L"remote server is already running";
            }
            break;
        }

        if (config.Port == knremote::kMcpPort)
        {
            if (error != nullptr)
            {
                *error = L"MCP port; use 51767";
            }
            break;
        }
        if (config.Port == 0)
        {
            if (error != nullptr)
            {
                *error = L"invalid port";
            }
            break;
        }

        std::wstring passwordError;
        if (!knremote::SanitizeRemotePassword(config.Password, &password, &passwordError))
        {
            if (error != nullptr)
            {
                *error = passwordError;
            }
            break;
        }

        const std::wstring bind = knremote::NormalizeBindAddress(config.BindAddress);
        in_addr bindAddr = {};
        if (!knremote::ParseIpv4(bind, &bindAddr))
        {
            if (error != nullptr)
            {
                *error = L"--bind must be 0.0.0.0, 127.0.0.1, or an IPv4 address";
            }
            break;
        }

        if (!config.Peer.empty())
        {
            in_addr peer = {};
            if (!knremote::ParseIpv4(config.Peer, &peer))
            {
                if (error != nullptr)
                {
                    *error = L"--peer must be an IPv4 address";
                }
                break;
            }
        }

        WSADATA wsa = {};
        const int wsaRc = WSAStartup(MAKEWORD(2, 2), &wsa);
        if (wsaRc != 0)
        {
            if (error != nullptr)
            {
                *error = L"WSAStartup failed";
            }
            break;
        }
        wsaStarted_ = true;
        firewallWarning_.clear();
        commandInFlight_.store(false);
        {
            std::lock_guard<std::mutex> lock(lockoutMutex_);
            failCounts_.clear();
            globalFails_ = 0;
        }

        listenSock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listenSock_ == INVALID_SOCKET)
        {
            if (error != nullptr)
            {
                *error = SockError(L"socket failed");
            }
            break;
        }

        BOOL reuse = TRUE;
        setsockopt(
            listenSock_,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            reinterpret_cast<const char*>(&reuse),
            sizeof(reuse));

        sockaddr_in local = {};
        local.sin_family = AF_INET;
        local.sin_port = htons(config.Port);
        local.sin_addr = bindAddr;
        if (::bind(listenSock_, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0)
        {
            if (error != nullptr)
            {
                *error = SockError(L"bind failed");
            }
            break;
        }
        if (::listen(listenSock_, 4) != 0)
        {
            if (error != nullptr)
            {
                *error = SockError(L"listen failed");
            }
            break;
        }

        config_ = config;
        config_.Password = password;
        config_.BindAddress = bind;
        {
            std::lock_guard<std::mutex> lock(helloMutex_);
            hello_ = config.Hello;
        }

        const bool loopback = knremote::IsLoopbackBind(bind);
        if (config.AddFirewall && !loopback)
        {
            std::wstring fwError;
            if (!AddRemoteFirewallRule(config.Port, config.Peer, &fwError))
            {
                // Keep listening; inbound may still work if the firewall is off.
                firewallAdded_ = false;
                firewallWarning_ = fwError.empty()
                    ? L"firewall rule failed, inbound may be blocked"
                    : fwError;
            }
            else
            {
                firewallAdded_ = true;
            }
        }

        ResetEvent(stopEvent_);
        ResetEvent(writeOffEvent_);
        running_.store(true);
        try
        {
            listener_ = std::thread(&RemoteServer::ListenerThreadMain, this);
        }
        catch (...)
        {
            running_.store(false);
            if (error != nullptr)
            {
                *error = L"failed to start listener thread";
            }
            break;
        }

        ok = true;
    } while (false);

    if (!password.empty())
    {
        SecureZeroMemory(&password[0], password.size() * sizeof(wchar_t));
        password.clear();
    }

    if (!ok)
    {
        if (!config_.Password.empty())
        {
            SecureZeroMemory(&config_.Password[0], config_.Password.size() * sizeof(wchar_t));
            config_.Password.clear();
        }
        if (firewallAdded_)
        {
            RemoveRemoteFirewallRule();
            firewallAdded_ = false;
        }
        if (listenSock_ != INVALID_SOCKET)
        {
            closesocket(listenSock_);
            listenSock_ = INVALID_SOCKET;
        }
        if (wsaStarted_)
        {
            WSACleanup();
            wsaStarted_ = false;
        }
    }

    return ok;
}

void RemoteServer::Stop()
{
    running_.store(false);
    if (stopEvent_ != nullptr)
    {
        SetEvent(stopEvent_);
    }
    DisconnectSession();
    SOCKET listen = listenSock_;
    if (listen != INVALID_SOCKET)
    {
        closesocket(listen);
    }
    if (listener_.joinable())
    {
        listener_.join();
    }
    listenSock_ = INVALID_SOCKET;
    commandInFlight_.store(false);
    {
        std::lock_guard<std::mutex> lock(lockoutMutex_);
        failCounts_.clear();
        globalFails_ = 0;
    }
    if (!config_.Password.empty())
    {
        SecureZeroMemory(&config_.Password[0], config_.Password.size() * sizeof(wchar_t));
        config_.Password.clear();
    }

    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        while (!queue_.empty())
        {
            auto job = queue_.front();
            queue_.pop_front();
            try
            {
                RemoteEngineResult cancelled;
                cancelled.IsError = true;
                cancelled.Code = L"denied";
                cancelled.Stderr = L"remote server stopped";
                job->ResultPromise.set_value(cancelled);
            }
            catch (...)
            {
            }
        }
    }

    if (firewallAdded_)
    {
        RemoveRemoteFirewallRule();
        firewallAdded_ = false;
    }
    if (wsaStarted_)
    {
        WSACleanup();
        wsaStarted_ = false;
    }
}

void RemoteServer::RequestStop()
{
    running_.store(false);
    if (stopEvent_ != nullptr)
    {
        SetEvent(stopEvent_);
    }
    DisconnectSession();
}

void RemoteServer::DisconnectSession()
{
    SOCKET sock = INVALID_SOCKET;
    {
        std::lock_guard<std::mutex> lock(sessionMutex_);
        sock = sessionSock_;
        sessionSock_ = INVALID_SOCKET;
        peerIp_.clear();
    }
    if (sock != INVALID_SOCKET)
    {
        // Wake a recv/select in HandleClient. Last protocol bytes must already
        // have been send()ed; HandleClient owns closesocket.
        shutdown(sock, SD_BOTH);
    }
}

bool RemoteServer::IsRunning() const
{
    return running_.load();
}

uint16_t RemoteServer::Port() const
{
    return config_.Port;
}

std::wstring RemoteServer::BindAddress() const
{
    return config_.BindAddress;
}

bool RemoteServer::IsLoopbackOnly() const
{
    return knremote::IsLoopbackBind(config_.BindAddress);
}

std::wstring RemoteServer::PeerIp() const
{
    std::lock_guard<std::mutex> lock(sessionMutex_);
    return peerIp_;
}

std::wstring RemoteServer::AuditPath() const
{
    return config_.AuditPath;
}

std::wstring RemoteServer::FirewallWarning() const
{
    return firewallWarning_;
}

void RemoteServer::SetHelloWriteMode(bool writeMode)
{
    std::lock_guard<std::mutex> lock(helloMutex_);
    hello_.WriteMode = writeMode;
}

RemoteHelloInfo RemoteServer::Hello() const
{
    std::lock_guard<std::mutex> lock(helloMutex_);
    return hello_;
}

HANDLE RemoteServer::JobReadyEvent() const
{
    return jobReadyEvent_;
}

HANDLE RemoteServer::StopEvent() const
{
    return stopEvent_;
}

HANDLE RemoteServer::WriteOffEvent() const
{
    return writeOffEvent_;
}

std::shared_ptr<RemoteJob> RemoteServer::TryPopJob()
{
    std::lock_guard<std::mutex> lock(queueMutex_);
    if (queue_.empty())
    {
        return nullptr;
    }
    auto job = queue_.front();
    queue_.pop_front();
    commandInFlight_.store(true);
    return job;
}

void RemoteServer::AppendAuditLine(const std::wstring& line)
{
    std::lock_guard<std::mutex> lock(auditMutex_);
    if (config_.AuditPath.empty())
    {
        return;
    }

    const size_t slash = config_.AuditPath.find_last_of(L"\\/");
    if (slash != std::wstring::npos)
    {
        CreateDirectoryW(config_.AuditPath.substr(0, slash).c_str(), nullptr);
    }

    HANDLE file = CreateFileW(
        config_.AuditPath.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (file == INVALID_HANDLE_VALUE)
    {
        return;
    }

    LARGE_INTEGER size = {};
    if (GetFileSizeEx(file, &size) && size.QuadPart > 64ll * 1024ll * 1024ll)
    {
        CloseHandle(file);
        const std::wstring rotated = config_.AuditPath + L".1";
        DeleteFileW(rotated.c_str());
        MoveFileW(config_.AuditPath.c_str(), rotated.c_str());
        file = CreateFileW(
            config_.AuditPath.c_str(),
            FILE_APPEND_DATA,
            FILE_SHARE_READ,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            return;
        }
    }

    std::wstring withNl = line;
    if (withNl.empty() || withNl.back() != L'\n')
    {
        withNl.push_back(L'\n');
    }
    const std::string utf8 = mcpjson::WideToUtf8(withNl);
    DWORD written = 0;
    WriteFile(file, utf8.data(), static_cast<DWORD>(utf8.size()), &written, nullptr);
    CloseHandle(file);
}

void RemoteServer::ListenerThreadMain()
{
    while (running_.load())
    {
        const SOCKET listen = listenSock_;
        if (listen == INVALID_SOCKET)
        {
            break;
        }

        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(listen, &readSet);
        timeval timeout = {};
        timeout.tv_sec = 0;
        timeout.tv_usec = 200000;
        const int ready = select(0, &readSet, nullptr, nullptr, &timeout);
        if (ready == SOCKET_ERROR)
        {
            if (!running_.load())
            {
                break;
            }
            continue;
        }
        if (ready == 0)
        {
            continue;
        }

        sockaddr_in peer = {};
        int peerLen = sizeof(peer);
        SOCKET client = accept(listen, reinterpret_cast<sockaddr*>(&peer), &peerLen);
        if (client == INVALID_SOCKET)
        {
            continue;
        }

        knremote::EnableTcpNoDelay(client);

        bool sessionBusy = false;
        {
            std::lock_guard<std::mutex> lock(sessionMutex_);
            sessionBusy = sessionSock_ != INVALID_SOCKET;
        }
        if (sessionBusy)
        {
            SendJson(
                client,
                knremote::MakeObject(L"error", L"s-0", L"\"code\":\"session-busy\""),
                nullptr);
            knremote::CloseTcpGraceful(client, knremote::kCloseDrainMs);
            continue;
        }

        const std::wstring peerIp = Ipv4Text(peer.sin_addr);
        if (!config_.Peer.empty() && peerIp != config_.Peer)
        {
            knremote::CloseTcpGraceful(client, knremote::kCloseDrainMs);
            continue;
        }

        fd_set probeSet;
        FD_ZERO(&probeSet);
        FD_SET(client, &probeSet);
        timeval probeTimeout = {};
        probeTimeout.tv_sec = static_cast<long>(knremote::kAuthFirstByteMs / 1000);
        probeTimeout.tv_usec = static_cast<long>((knremote::kAuthFirstByteMs % 1000) * 1000);
        const int probeReady = select(0, &probeSet, nullptr, nullptr, &probeTimeout);
        if (probeReady <= 0)
        {
            knremote::CloseTcpGraceful(client, knremote::kCloseDrainMs);
            continue;
        }

        HandleClient(client, peerIp, ntohl(peer.sin_addr.s_addr));
    }
}

bool RemoteServer::RecvAll(
    SOCKET sock,
    char* buffer,
    int length,
    DWORD deadlineTick,
    std::wstring* error)
{
    bool ok = false;
    int received = 0;

    do
    {
        if (sock == INVALID_SOCKET || buffer == nullptr || length <= 0)
        {
            break;
        }

        while (received < length)
        {
            if (knremote::DeadlineReached(deadlineTick))
            {
                if (error != nullptr)
                {
                    *error = L"frame-timeout";
                }
                break;
            }

            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(sock, &readSet);
            timeval timeout = {};
            timeout.tv_sec = 0;
            timeout.tv_usec = 200000;
            const int ready = select(0, &readSet, nullptr, nullptr, &timeout);
            if (ready == SOCKET_ERROR)
            {
                if (error != nullptr)
                {
                    *error = L"recv failed";
                }
                break;
            }
            if (ready == 0)
            {
                continue;
            }

            const int n = recv(sock, buffer + received, length - received, 0);
            if (n <= 0)
            {
                if (error != nullptr)
                {
                    *error = L"peer drop";
                }
                break;
            }
            received += n;
        }

        ok = received == length;
    } while (false);

    return ok;
}

bool RemoteServer::RecvFrame(
    SOCKET sock,
    std::wstring* json,
    DWORD deadlineTick,
    std::wstring* error)
{
    bool ok = false;
    do
    {
        unsigned char header[8] = {};
        if (!RecvAll(sock, reinterpret_cast<char*>(header), 8, deadlineTick, error))
        {
            break;
        }
        uint32_t length = 0;
        if (!knremote::DecodeHeader(header, &length, error))
        {
            break;
        }
        std::string body;
        body.resize(length);
        if (!RecvAll(sock, &body[0], static_cast<int>(length), deadlineTick, error))
        {
            break;
        }
        if (json != nullptr)
        {
            *json = mcpjson::Utf8ToWide(body);
        }
        ok = true;
    } while (false);
    return ok;
}

bool RemoteServer::SendJson(SOCKET sock, const std::wstring& json, std::wstring* error)
{
    bool ok = false;
    do
    {
        std::string bytes;
        if (!knremote::EncodeFrame(json, &bytes, error))
        {
            break;
        }
        int sent = 0;
        while (sent < static_cast<int>(bytes.size()))
        {
            const int n = send(sock, bytes.data() + sent, static_cast<int>(bytes.size()) - sent, 0);
            if (n <= 0)
            {
                if (error != nullptr)
                {
                    *error = L"send failed";
                }
                break;
            }
            sent += n;
        }
        ok = sent == static_cast<int>(bytes.size());
    } while (false);
    return ok;
}

bool RemoteServer::EnqueueAndWait(
    const std::wstring& line,
    const std::wstring& requestId,
    SOCKET client,
    RemoteEngineResult* result)
{
    bool ok = false;
    do
    {
        if (result == nullptr)
        {
            break;
        }
        if (commandInFlight_.load())
        {
            result->IsError = true;
            result->Code = L"engine-busy";
            result->Stderr = L"engine busy";
            ok = true;
            break;
        }

        auto job = std::make_shared<RemoteJob>();
        job->Line = line;
        job->RequestId = requestId;
        job->Cancelled = std::make_shared<std::atomic<bool>>(false);
        std::future<RemoteEngineResult> future = job->ResultPromise.get_future();

        {
            std::lock_guard<std::mutex> lock(queueMutex_);
            if (queue_.size() >= knremote::kMaxPending)
            {
                result->IsError = true;
                result->Code = L"engine-busy";
                result->Stderr = L"engine busy";
                ok = true;
                break;
            }
            queue_.push_back(job);
        }
        SetEvent(jobReadyEvent_);

        // Keep the TCP session alive while the engine runs (dump/hunt can
        // exceed the 60s dead-peer window). Heartbeats also give the client
        // a frame to reset its recv deadline.
        for (;;)
        {
            if (future.wait_for(std::chrono::milliseconds(knremote::kHeartbeatMs)) ==
                std::future_status::ready)
            {
                break;
            }
            SendJson(
                client,
                knremote::MakeObject(L"heartbeat", L"s-hb", L""),
                nullptr);
        }
        *result = future.get();
        commandInFlight_.store(false);
        ok = true;
    } while (false);
    return ok;
}

bool RemoteServer::AuthAllowed(uint32_t peerHost)
{
    std::lock_guard<std::mutex> lock(lockoutMutex_);
    if (globalFails_ >= knremote::kGlobalAuthLockout)
    {
        return false;
    }
    auto it = failCounts_.find(peerHost);
    if (it != failCounts_.end() && it->second >= knremote::kAuthFailLockout)
    {
        return false;
    }
    return true;
}

void RemoteServer::RecordAuthFailure(uint32_t peerHost)
{
    std::lock_guard<std::mutex> lock(lockoutMutex_);
    failCounts_[peerHost] += 1;
    globalFails_ += 1;
}

void RemoteServer::RecordAuthSuccess(uint32_t peerHost)
{
    std::lock_guard<std::mutex> lock(lockoutMutex_);
    failCounts_.erase(peerHost);
}

void RemoteServer::HandleClient(SOCKET client, const std::wstring& peerIp, uint32_t peerHost)
{
    {
        std::lock_guard<std::mutex> lock(sessionMutex_);
        sessionSock_ = client;
        peerIp_ = peerIp;
    }

    std::wstring error;
    DWORD authDeadline = GetTickCount() + knremote::kAuthDeadlineMs;
    std::wstring authJson;

    do
    {
        if (!AuthAllowed(peerHost))
        {
            SendJson(
                client,
                knremote::MakeObject(L"auth-err", L"s-0", L"\"code\":\"lockout\""),
                nullptr);
            break;
        }

        if (!RecvFrame(client, &authJson, authDeadline, &error))
        {
            break;
        }

        int64_t version = 0;
        std::wstring type;
        knremote::GetNumberField(authJson, L"v", &version);
        knremote::GetStringField(authJson, L"type", &type);
        if (version != 1)
        {
            SendJson(
                client,
                knremote::MakeObject(L"error", L"s-0", L"\"code\":\"unsupported-v\""),
                nullptr);
            break;
        }
        if (type != L"auth")
        {
            SendJson(
                client,
                knremote::MakeObject(L"auth-err", L"s-0", L"\"code\":\"protocol\""),
                nullptr);
            break;
        }

        std::wstring presented;
        std::wstring id;
        knremote::GetStringField(authJson, L"password", &presented);
        knremote::GetStringField(authJson, L"id", &id);
        Sleep(250);
        std::string left = mcpjson::WideToUtf8(presented);
        std::string right = mcpjson::WideToUtf8(config_.Password);
        const bool passwordOk = knremote::ConstantTimeEqual(left, right);
        if (!left.empty())
        {
            SecureZeroMemory(&left[0], left.size());
            left.clear();
        }
        if (!right.empty())
        {
            SecureZeroMemory(&right[0], right.size());
            right.clear();
        }
        if (!presented.empty())
        {
            SecureZeroMemory(&presented[0], presented.size() * sizeof(wchar_t));
            presented.clear();
        }
        if (!authJson.empty())
        {
            SecureZeroMemory(&authJson[0], authJson.size() * sizeof(wchar_t));
            authJson.clear();
        }
        if (id.empty())
        {
            id = L"c-1";
        }
        if (!passwordOk)
        {
            RecordAuthFailure(peerHost);
            const wchar_t* code = AuthAllowed(peerHost) ? L"bad-password" : L"lockout";
            std::wstring extra = L"\"code\":";
            extra += knremote::Quote(code);
            SendJson(client, knremote::MakeObject(L"auth-err", id, extra), nullptr);
            break;
        }

        RecordAuthSuccess(peerHost);
        const std::wstring session = MakeSessionId();
        if (!SendJson(
            client,
            knremote::MakeObject(L"auth-ok", id, L"\"session\":" + knremote::Quote(session)),
            nullptr))
        {
            break;
        }

        RemoteHelloInfo hello = Hello();
        std::wstring extra;
        extra += L"\"hostname\":" + knremote::Quote(hello.Hostname.empty() ? LocalHostname() : hello.Hostname);
        extra += L",\"os\":" + knremote::Quote(hello.Os.empty() ? LocalOsText() : hello.Os);
        extra += L",\"abi\":" + std::to_wstring(hello.Abi);
        extra += L",\"writeMode\":";
        extra += hello.WriteMode ? L"true" : L"false";
        extra += L",\"cloak\":";
        extra += hello.Cloak ? L"true" : L"false";
        extra += L",\"bind\":" + knremote::Quote(config_.BindAddress);
        extra += L",\"port\":" + std::to_wstring(config_.Port);
        extra += L",\"cleartext\":true";
        extra += L",\"caps\":[\"command\",\"completion\"]";
        if (!SendJson(client, knremote::MakeObject(L"hello", id, extra), nullptr))
        {
            break;
        }

        DWORD lastActivity = GetTickCount();
        DWORD lastHeartbeat = GetTickCount();
        while (running_.load())
        {
            {
                std::lock_guard<std::mutex> lock(sessionMutex_);
                if (sessionSock_ != client)
                {
                    break;
                }
            }
            if (knremote::IntervalElapsed(lastActivity, knremote::kDeadPeerMs))
            {
                break;
            }
            if (knremote::IntervalElapsed(lastHeartbeat, knremote::kHeartbeatMs))
            {
                SendJson(client, knremote::MakeObject(L"heartbeat", L"s-hb", L""), nullptr);
                lastHeartbeat = GetTickCount();
            }

            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(client, &readSet);
            timeval timeout = {};
            timeout.tv_sec = 0;
            timeout.tv_usec = 200000;
            const int ready = select(0, &readSet, nullptr, nullptr, &timeout);
            if (ready <= 0)
            {
                continue;
            }

            std::wstring json;
            const DWORD frameDeadline = GetTickCount() + knremote::kFrameDeadlineMs;
            if (!RecvFrame(client, &json, frameDeadline, &error))
            {
                break;
            }
            lastActivity = GetTickCount();

            int64_t msgVersion = 1;
            knremote::GetNumberField(json, L"v", &msgVersion);
            if (msgVersion != 1)
            {
                SendJson(client, knremote::MakeObject(L"error", L"s-0", L"\"code\":\"unsupported-v\""), nullptr);
                break;
            }

            std::wstring msgType;
            std::wstring msgId;
            knremote::GetStringField(json, L"type", &msgType);
            knremote::GetStringField(json, L"id", &msgId);
            if (msgId.empty())
            {
                msgId = L"c-0";
            }

            if (msgType == L"heartbeat")
            {
                SendJson(client, knremote::MakeObject(L"heartbeat", msgId, L""), nullptr);
                continue;
            }
            if (msgType == L"disconnect")
            {
                break;
            }
            if (msgType == L"cancel")
            {
                std::lock_guard<std::mutex> lock(queueMutex_);
                bool cancelledQueued = false;
                for (auto& job : queue_)
                {
                    if (job->Cancelled)
                    {
                        job->Cancelled->store(true);
                        cancelledQueued = true;
                    }
                }
                if (!cancelledQueued && commandInFlight_.load())
                {
                    SendJson(
                        client,
                        knremote::MakeObject(L"error", msgId, L"\"code\":\"not-cancelable\""),
                        nullptr);
                }
                continue;
            }
            if (msgType == L"completion-request")
            {
                if (commandInFlight_.load())
                {
                    SendJson(
                        client,
                        knremote::MakeObject(L"error", msgId, L"\"code\":\"engine-busy\""),
                        nullptr);
                    continue;
                }
                std::wstring line;
                knremote::GetStringField(json, L"line", &line);
                int64_t cursor = static_cast<int64_t>(line.size());
                knremote::GetNumberField(json, L"cursor", &cursor);
                if (cursor < 0)
                {
                    cursor = 0;
                }
                if (cursor > static_cast<int64_t>(line.size()))
                {
                    cursor = static_cast<int64_t>(line.size());
                }
                size_t pos = static_cast<size_t>(cursor);
                size_t tokenStart = pos;
                while (tokenStart > 0 && iswspace(line[tokenStart - 1]) == 0)
                {
                    --tokenStart;
                }
                const std::wstring prefix = line.substr(tokenStart, pos - tokenStart);
                const std::vector<std::wstring> argsBefore = knremote::SplitLine(line.substr(0, tokenStart));
                const std::vector<std::wstring> candidates = CollectCompletionCandidates(argsBefore);
                std::wstring matchesJson = L"[";
                bool first = true;
                std::wstring prefixLower = prefix;
                for (wchar_t& ch : prefixLower)
                {
                    ch = static_cast<wchar_t>(towlower(ch));
                }
                for (const std::wstring& name : candidates)
                {
                    std::wstring lower = name;
                    for (wchar_t& ch : lower)
                    {
                        ch = static_cast<wchar_t>(towlower(ch));
                    }
                    if (!prefixLower.empty() && lower.rfind(prefixLower, 0) != 0)
                    {
                        continue;
                    }
                    if (!first)
                    {
                        matchesJson += L",";
                    }
                    first = false;
                    matchesJson += knremote::Quote(name);
                }
                matchesJson += L"]";
                std::wstring completionExtra = L"\"matches\":" + matchesJson +
                    L",\"replacement\":" + knremote::Quote(prefix) +
                    L",\"appendSpace\":true";
                SendJson(client, knremote::MakeObject(L"completion-response", msgId, completionExtra), nullptr);
                continue;
            }
            if (msgType != L"command-submit")
            {
                SendJson(client, knremote::MakeObject(L"error", msgId, L"\"code\":\"denied\""), nullptr);
                continue;
            }

            std::wstring line;
            knremote::GetStringField(json, L"line", &line);
            if (line.size() > knremote::kMaxCommandChars)
            {
                SendJson(client, knremote::MakeObject(L"error", msgId, L"\"code\":\"too-large\""), nullptr);
                continue;
            }

            std::wstring denyReason;
            std::wstring rejectText;
            if (IsRemoteDeniedCommandLine(line, &denyReason))
            {
                rejectText = L"denied: " + denyReason;
            }
            else if (IsRemoteAddressOnlyEnter(line))
            {
                rejectText = L"supply values on the command line";
            }
            if (!rejectText.empty())
            {
                std::wstring rejectExtra = L"\"seq\":0,\"last\":true,\"stdout\":\"\",\"stderr\":";
                rejectExtra += knremote::Quote(rejectText);
                rejectExtra += L",\"keepRunning\":true,\"isError\":true,\"code\":\"denied\"";
                SendJson(client, knremote::MakeObject(L"command-result", msgId, rejectExtra), nullptr);
                continue;
            }

            RemoteEngineResult result;
            EnqueueAndWait(line, msgId, client, &result);
            lastActivity = GetTickCount();
            lastHeartbeat = lastActivity;

            std::wstring stdoutText = result.Stdout;
            std::wstring marker;
            if (mcpjson::WideToUtf8(stdoutText).size() > knremote::kInlineTruncateBytes)
            {
                stdoutText = stdoutText.substr(0, 4096);
                marker = L"\n[truncated]\n";
                stdoutText += marker;
            }

            const std::string utf8 = mcpjson::WideToUtf8(stdoutText);
            size_t offset = 0;
            int seq = 0;
            if (utf8.empty())
            {
                std::wstring emptyExtra = L"\"seq\":0,\"last\":true,\"stdout\":\"\",\"stderr\":";
                emptyExtra += knremote::Quote(result.Stderr);
                emptyExtra += L",\"keepRunning\":";
                emptyExtra += result.KeepRunning ? L"true" : L"false";
                emptyExtra += L",\"isError\":";
                emptyExtra += result.IsError ? L"true" : L"false";
                SendJson(client, knremote::MakeObject(L"command-result", msgId, emptyExtra), nullptr);
            }
            else
            {
                while (offset < utf8.size())
                {
                    const size_t end = knremote::ColorSafeChunkEnd(
                        utf8,
                        offset,
                        knremote::kResultChunkBytes);
                    const size_t chunk = end > offset ? (end - offset) : (utf8.size() - offset);
                    const std::string part = utf8.substr(offset, chunk);
                    offset += chunk;
                    const bool last = offset >= utf8.size();
                    std::wstring chunkExtra = L"\"seq\":" + std::to_wstring(seq++);
                    chunkExtra += L",\"last\":";
                    chunkExtra += last ? L"true" : L"false";
                    chunkExtra += L",\"stdout\":" + knremote::Quote(mcpjson::Utf8ToWide(part));
                    chunkExtra += L",\"stderr\":" + knremote::Quote(last ? result.Stderr : L"");
                    chunkExtra += L",\"keepRunning\":";
                    chunkExtra += result.KeepRunning ? L"true" : L"false";
                    chunkExtra += L",\"isError\":";
                    chunkExtra += result.IsError ? L"true" : L"false";
                    if (result.IsError && !result.Code.empty())
                    {
                        chunkExtra += L",\"code\":" + knremote::Quote(result.Code);
                    }
                    SendJson(client, knremote::MakeObject(L"command-result", msgId, chunkExtra), nullptr);
                }
            }
        }
    } while (false);

    {
        std::lock_guard<std::mutex> lock(sessionMutex_);
        if (sessionSock_ == client)
        {
            sessionSock_ = INVALID_SOCKET;
            peerIp_.clear();
        }
    }
    knremote::CloseTcpGraceful(client, knremote::kCloseDrainMs);
}

bool IsRemoteDeniedCommandLine(const std::wstring& line, std::wstring* reason)
{
    bool denied = false;
    do
    {
        const std::vector<std::wstring> args = knremote::SplitLine(line);
        if (args.empty())
        {
            break;
        }

        std::wstring token = args[0];
        const CommandInfo* info = CommandRegistry::Find(token);
        std::wstring canonical = token;
        if (info != nullptr && info->Canonical != nullptr)
        {
            canonical = info->Canonical;
        }
        for (wchar_t& ch : canonical)
        {
            ch = static_cast<wchar_t>(towlower(ch));
        }

        auto set = [&](const wchar_t* text)
        {
            denied = true;
            if (reason != nullptr)
            {
                *reason = text;
            }
        };

        if (canonical == L"q" || canonical == L"qq" || canonical == L"qd")
        {
            set(L"session-lifetime");
            break;
        }
        if (canonical == L"unload" || canonical == L"mcp" || canonical == L"remote")
        {
            set(L"session-lifetime");
            break;
        }
        if (canonical == L"kd" || canonical == L"kdinit" || canonical == L"kddetach" ||
            canonical == L"backend")
        {
            set(L"session-lifetime");
            break;
        }
        if (canonical == L"log")
        {
            set(L"log is console-local");
            break;
        }
        if (canonical == L".sympath+")
        {
            set(L"symbol path change denied");
            break;
        }
        if (canonical == L".sympath" && args.size() > 1)
        {
            set(L"symbol path change denied");
            break;
        }
        if (canonical == L"probe" && args.size() >= 2)
        {
            std::wstring action = args[1];
            for (wchar_t& ch : action)
            {
                ch = static_cast<wchar_t>(towlower(ch));
            }
            if (action == L"load" || action == L"unload")
            {
                set(L"probe load/unload denied");
                break;
            }
        }
        if (canonical == L"!byovd" && args.size() >= 3)
        {
            std::wstring a = args[1];
            std::wstring b = args[2];
            for (wchar_t& ch : a)
            {
                ch = static_cast<wchar_t>(towlower(ch));
            }
            for (wchar_t& ch : b)
            {
                ch = static_cast<wchar_t>(towlower(ch));
            }
            if (a == L"fixture" && (b == L"load" || b == L"unload"))
            {
                set(L"fixture load denied");
                break;
            }
        }

        if (info != nullptr && info->Support == CommandSupport::DbgEng)
        {
            set(L"dbgeng-only");
            break;
        }
        if (info == nullptr)
        {
            if (!token.empty() && token[0] == L'!')
            {
                set(L"unknown bang/dbgeng");
                break;
            }
            set(L"unknown command");
            break;
        }
    } while (false);

    return denied;
}

bool IsRemoteAddressOnlyEnter(const std::wstring& line)
{
    bool addressOnly = false;
    do
    {
        const std::vector<std::wstring> args = knremote::SplitLine(line);
        if (args.empty())
        {
            break;
        }
        std::wstring command = args[0];
        for (wchar_t& ch : command)
        {
            ch = static_cast<wchar_t>(towlower(ch));
        }
        const bool isEnter =
            command == L"e" || command == L"ea" || command == L"eb" || command == L"ed" ||
            command == L"ef" || command == L"ep" || command == L"eq" || command == L"eu" ||
            command == L"ew" || command == L"eza" || command == L"ezu" ||
            command == L"peb" || command == L"pew" || command == L"ped" || command == L"peq" ||
            command == L"!eb" || command == L"!ew" || command == L"!ed" || command == L"!eq";
        if (!isEnter)
        {
            break;
        }

        size_t index = 1;
        if (args.size() > 1)
        {
            std::wstring opt = args[1];
            for (wchar_t& ch : opt)
            {
                ch = static_cast<wchar_t>(towlower(ch));
            }
            if (opt == L"/process")
            {
                index = 3;
            }
        }
        if (index >= args.size())
        {
            break;
        }
        addressOnly = index + 1 >= args.size();
    } while (false);
    return addressOnly;
}

bool ParseRemoteConnectArgs(
    int argc,
    wchar_t** argv,
    std::wstring* host,
    uint16_t* port,
    std::wstring* error)
{
    bool ok = false;
    do
    {
        if (argc < 3 || argv == nullptr || argv[1] == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"usage: KnLiveDbg.exe --connect <ipv4>:<port>";
            }
            break;
        }

        std::wstring first = argv[1];
        for (wchar_t& ch : first)
        {
            ch = static_cast<wchar_t>(towlower(ch));
        }
        if (first != L"--connect")
        {
            if (error != nullptr)
            {
                *error = L"usage: KnLiveDbg.exe --connect <ipv4>:<port>";
            }
            break;
        }

        ok = knremote::ParseHostPort(argv[2], host, port, error);
    } while (false);
    return ok;
}

bool HasUnknownControllerArgv(int argc, wchar_t** argv)
{
    bool unknown = false;
    for (int i = 1; i < argc && argv != nullptr; ++i)
    {
        std::wstring token = argv[i];
        for (wchar_t& ch : token)
        {
            ch = static_cast<wchar_t>(towlower(ch));
        }
        if (token == L"--cloak")
        {
            continue;
        }
        if (token == L"--cloak-resume")
        {
            if (i + 1 < argc)
            {
                ++i;
            }
            continue;
        }
        if (token == L"--cloak-cleanup")
        {
            if (i + 1 < argc)
            {
                ++i;
            }
            continue;
        }
        unknown = true;
        break;
    }
    return unknown;
}

