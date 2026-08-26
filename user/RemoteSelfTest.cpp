#include "RemoteServer.h"

#include "CompletionHints.h"
#include "McpJson.h"

#include <algorithm>
#include <iostream>
#include <string>
#include <thread>

namespace
{
    struct Ctx
    {
        uint32_t Passed = 0;
        uint32_t Failed = 0;
    };

    void Check(Ctx* ctx, bool condition, const wchar_t* name)
    {
        if (ctx == nullptr)
        {
            return;
        }
        if (condition)
        {
            ++ctx->Passed;
            std::wcout << L"[remote.selftest] PASS " << name << L"\n";
        }
        else
        {
            ++ctx->Failed;
            std::wcerr << L"[remote.selftest] FAIL " << name << L"\n";
        }
    }
}

int RunRemoteConnectArgvSelfTest()
{
    Ctx ctx;
    wchar_t exeName[] = L"KnLiveDbg.exe";
    wchar_t connect[] = L"--connect";
    wchar_t target[] = L"127.0.0.1:51767";
    wchar_t* argv[] = { exeName, connect, target };
    std::wstring host;
    uint16_t port = 0;
    std::wstring error;
    Check(&ctx, ParseRemoteConnectArgs(3, argv, &host, &port, &error), L"parse-connect");
    Check(&ctx, host == L"127.0.0.1" && port == 51767, L"parse-connect-values");

    wchar_t cloak[] = L"--cloak";
    wchar_t* cloakArgv[] = { exeName, cloak };
    Check(&ctx, !HasUnknownControllerArgv(2, cloakArgv), L"cloak-known");

    wchar_t* unknown[] = { exeName, connect, target };
    Check(&ctx, HasUnknownControllerArgv(3, unknown), L"connect-unknown-on-controller");

    if (ctx.Failed != 0)
    {
        std::wcerr << L"[remote.selftest] connect-argv failures=" << ctx.Failed << L"\n";
        return 1;
    }
    return 0;
}

int RunRemoteProtocolSelfTest()
{
    Ctx ctx;

    std::wstring password;
    std::wstring error;
    Check(&ctx, !knremote::SanitizeRemotePassword(L"abcd", &password, &error), L"password-min");
    Check(&ctx, knremote::SanitizeRemotePassword(L"abcde", &password, &error), L"password-ok");
    {
        const DWORD started = GetTickCount() - 50;
        Check(&ctx, knremote::IntervalElapsed(started, 10), L"interval-elapsed");
        Check(&ctx, knremote::DeadlineReached(GetTickCount() - 1), L"deadline-reached");
        Check(&ctx, !knremote::DeadlineReached(GetTickCount() + 60000), L"deadline-future");
    }

    std::wstring json = knremote::MakeObject(L"auth", L"c-1", L"\"password\":\"x\"");
    std::string frame;
    Check(&ctx, knremote::EncodeFrame(json, &frame, &error), L"encode-frame");
    Check(&ctx, frame.size() >= 8, L"frame-header");
    uint32_t length = 0;
    Check(
        &ctx,
        knremote::DecodeHeader(reinterpret_cast<const unsigned char*>(frame.data()), &length, &error),
        L"decode-header");

    unsigned char bad[8] = { 'X', 'X', 'X', 'X', 1, 0, 0, 0 };
    Check(&ctx, !knremote::DecodeHeader(bad, &length, &error), L"bad-magic");

    unsigned char huge[8] = { 'K', 'N', 'R', '1', 0xff, 0xff, 0xff, 0x7f };
    Check(&ctx, !knremote::DecodeHeader(huge, &length, &error), L"oversize");

    Check(&ctx, IsRemoteDeniedCommandLine(L"q", nullptr), L"deny-q");
    Check(&ctx, IsRemoteDeniedCommandLine(L"unload", nullptr), L"deny-unload");
    Check(&ctx, IsRemoteDeniedCommandLine(L"kd r", nullptr), L"deny-kd");
    Check(&ctx, IsRemoteDeniedCommandLine(L"mcp on", nullptr), L"deny-mcp");
    Check(&ctx, IsRemoteDeniedCommandLine(L"probe load", nullptr), L"deny-probe-load");
    Check(&ctx, !IsRemoteDeniedCommandLine(L"dt nt!_EPROCESS", nullptr), L"allow-dt");
    Check(&ctx, IsRemoteAddressOnlyEnter(L"eb ffff800000000000"), L"address-only-eb");
    Check(&ctx, IsRemoteAddressOnlyEnter(L"ef ffff800000000000"), L"address-only-ef");
    {
        std::vector<std::wstring> root = CollectCompletionCandidates({});
        Check(
            &ctx,
            std::find(root.begin(), root.end(), L"remote") != root.end(),
            L"complete-root-remote");
        std::vector<std::wstring> remoteOn = CollectCompletionCandidates({ L"remote" });
        Check(
            &ctx,
            std::find(remoteOn.begin(), remoteOn.end(), L"on") != remoteOn.end(),
            L"complete-remote-on");
        std::vector<std::wstring> flags = CollectCompletionCandidates({ L"remote", L"on" });
        Check(
            &ctx,
            std::find(flags.begin(), flags.end(), L"--loopback") != flags.end(),
            L"complete-remote-loopback");
        std::wstring line = L"rem";
        size_t cursor = line.size();
        bool listed = false;
        std::wstring listing;
        Check(
            &ctx,
            ApplyTabCompletion(&line, &cursor, &listed, &listing) && line.rfind(L"remote", 0) == 0,
            L"tab-expands-remote");
    }
    Check(&ctx, !IsRemoteAddressOnlyEnter(L"eb ffff800000000000 90"), L"eb-with-value");
    {
        const std::string hangul = mcpjson::WideToUtf8(L"\uD55C\uAE00");
        Check(&ctx, hangul.size() >= 6, L"utf8-hangul-bytes");
        Check(
            &ctx,
            knremote::Utf8ChunkEnd(hangul, 0, 4) == 3,
            L"utf8-chunk-no-split");
        Check(
            &ctx,
            knremote::Utf8ChunkEnd(hangul, 0, 6) == 6,
            L"utf8-chunk-full");
    }

    wchar_t exe2[] = L"x";
    wchar_t connect2[] = L"--connect";
    wchar_t lan[] = L"10.0.0.5:51767";
    wchar_t* argvOk[] = { exe2, connect2, lan };
    std::wstring host;
    uint16_t port = 0;
    Check(&ctx, ParseRemoteConnectArgs(3, argvOk, &host, &port, &error) && host == L"10.0.0.5", L"connect-lan");

    RemoteServer server;
    RemoteServerConfig config;
    config.Port = 51767;
    config.BindAddress = L"127.0.0.1";
    config.Password = L"twelvechars!!";
    config.AddFirewall = false;
    config.Hello.Hostname = L"selftest";
    config.Hello.Os = L"Windows";
    config.Hello.Abi = 15;
    if (!server.Start(config, &error))
    {
        Check(&ctx, false, L"server-start");
        std::wcerr << L"start error: " << error << L"\n";
    }
    else
    {
        Check(&ctx, true, L"server-start");
        Check(&ctx, server.IsLoopbackOnly(), L"loopback-bind");
        server.Stop();
        Check(&ctx, !server.IsRunning(), L"server-stop");
    }

    if (ctx.Failed != 0)
    {
        std::wcerr << L"[remote.selftest] failures=" << ctx.Failed << L"\n";
        return 1;
    }
    std::wcout << L"[remote.selftest] passed=" << ctx.Passed << L"\n";
    return 0;
}
