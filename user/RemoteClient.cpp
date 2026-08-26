#include "RemoteServer.h"

#include "CompletionHints.h"

#include <conio.h>
#include <iostream>
#include <vector>

namespace
{
    bool RecvAll(SOCKET sock, char* buffer, int length, DWORD deadlineTick)
    {
        int received = 0;
        while (received < length)
        {
            if (knremote::DeadlineReached(deadlineTick))
            {
                return false;
            }
            fd_set readSet;
            FD_ZERO(&readSet);
            FD_SET(sock, &readSet);
            timeval timeout = {};
            timeout.tv_sec = 0;
            timeout.tv_usec = 200000;
            const int ready = select(0, &readSet, nullptr, nullptr, &timeout);
            if (ready <= 0)
            {
                if (ready == SOCKET_ERROR)
                {
                    return false;
                }
                continue;
            }
            const int n = recv(sock, buffer + received, length - received, 0);
            if (n <= 0)
            {
                return false;
            }
            received += n;
        }
        return true;
    }

    bool RecvJson(SOCKET sock, std::wstring* json, DWORD deadlineTick, std::wstring* error)
    {
        unsigned char header[8] = {};
        if (!RecvAll(sock, reinterpret_cast<char*>(header), 8, deadlineTick))
        {
            if (error != nullptr)
            {
                *error = L"peer drop";
            }
            return false;
        }
        uint32_t length = 0;
        if (!knremote::DecodeHeader(header, &length, error))
        {
            return false;
        }
        std::string body;
        body.resize(length);
        if (!RecvAll(sock, &body[0], static_cast<int>(length), deadlineTick))
        {
            if (error != nullptr)
            {
                *error = L"peer drop";
            }
            return false;
        }
        if (json != nullptr)
        {
            *json = mcpjson::Utf8ToWide(body);
        }
        return true;
    }

    bool SendJson(SOCKET sock, const std::wstring& json, std::wstring* error)
    {
        std::string bytes;
        if (!knremote::EncodeFrame(json, &bytes, error))
        {
            return false;
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
                return false;
            }
            sent += n;
        }
        return true;
    }

    bool ReadHiddenLine(const wchar_t* prompt, std::wstring* line)
    {
        bool ok = false;
        HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        DWORD originalMode = 0;
        bool restored = true;

        do
        {
            if (line == nullptr || prompt == nullptr)
            {
                break;
            }
            line->clear();
            if (input == nullptr || input == INVALID_HANDLE_VALUE ||
                !GetConsoleMode(input, &originalMode))
            {
                break;
            }
            DWORD written = 0;
            WriteConsoleW(output, prompt, static_cast<DWORD>(wcslen(prompt)), &written, nullptr);
            const DWORD hiddenMode =
                (originalMode | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT) &
                ~ENABLE_ECHO_INPUT;
            if (!SetConsoleMode(input, hiddenMode))
            {
                break;
            }
            restored = false;
            wchar_t buffer[256] = {};
            DWORD read = 0;
            if (!ReadConsoleW(input, buffer, 255, &read, nullptr))
            {
                break;
            }
            SetConsoleMode(input, originalMode);
            restored = true;
            WriteConsoleW(output, L"\n", 1, &written, nullptr);
            std::wstring text(buffer, read);
            while (!text.empty() &&
                   (text.back() == L'\r' || text.back() == L'\n' ||
                    text.back() == L' ' || text.back() == L'\t'))
            {
                text.pop_back();
            }
            *line = text;
            ok = true;
        } while (false);

        if (!restored)
        {
            SetConsoleMode(input, originalMode);
        }
        return ok;
    }

    void DrawRemoteLine(
        HANDLE output,
        COORD start,
        const wchar_t* prompt,
        const std::wstring& line,
        size_t cursor,
        size_t* rendered)
    {
        CONSOLE_SCREEN_BUFFER_INFO info = {};
        if (!GetConsoleScreenBufferInfo(output, &info))
        {
            return;
        }

        const SHORT width = info.dwSize.X > 0 ? info.dwSize.X : 80;
        const size_t promptLen = prompt != nullptr ? wcslen(prompt) : 0;
        const size_t visible = promptLen + line.size();
        SetConsoleCursorPosition(output, start);

        DWORD written = 0;
        if (prompt != nullptr && promptLen > 0)
        {
            WriteConsoleW(output, prompt, static_cast<DWORD>(promptLen), &written, nullptr);
        }
        if (!line.empty())
        {
            WriteConsoleW(output, line.c_str(), static_cast<DWORD>(line.size()), &written, nullptr);
        }
        if (rendered != nullptr && *rendered > visible)
        {
            const size_t extra = *rendered - visible;
            std::wstring spaces(extra, L' ');
            WriteConsoleW(output, spaces.c_str(), static_cast<DWORD>(spaces.size()), &written, nullptr);
        }
        if (rendered != nullptr)
        {
            *rendered = visible;
        }

        const int abs = static_cast<int>(start.Y) * width + start.X +
            static_cast<int>(promptLen + cursor);
        COORD pos = {};
        pos.X = static_cast<SHORT>(abs % width);
        pos.Y = static_cast<SHORT>(abs / width);
        SetConsoleCursorPosition(output, pos);
    }

    bool SendHeartbeatIfDue(SOCKET sock, DWORD* lastHeartbeat, std::wstring* error)
    {
        if (lastHeartbeat == nullptr)
        {
            return false;
        }
        if (!knremote::IntervalElapsed(*lastHeartbeat, knremote::kHeartbeatMs))
        {
            return true;
        }
        if (!SendJson(sock, knremote::MakeObject(L"heartbeat", L"c-hb", L""), error))
        {
            return false;
        }
        *lastHeartbeat = GetTickCount();
        return true;
    }

    enum class IncomingKind
    {
        None = 0,
        Heartbeat,
        Disconnect,
        CommandResult,
        Error,
        Other,
        RecvFailed
    };

    IncomingKind PollIncoming(
        SOCKET sock,
        DWORD waitMs,
        std::wstring* json,
        std::wstring* error)
    {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(sock, &readSet);
        timeval timeout = {};
        timeout.tv_sec = static_cast<long>(waitMs / 1000);
        timeout.tv_usec = static_cast<long>((waitMs % 1000) * 1000);
        const int ready = select(0, &readSet, nullptr, nullptr, &timeout);
        if (ready == SOCKET_ERROR)
        {
            if (error != nullptr)
            {
                *error = L"recv failed";
            }
            return IncomingKind::RecvFailed;
        }
        if (ready == 0)
        {
            return IncomingKind::None;
        }

        if (!RecvJson(sock, json, GetTickCount() + knremote::kFrameDeadlineMs, error))
        {
            return IncomingKind::RecvFailed;
        }

        std::wstring type;
        knremote::GetStringField(*json, L"type", &type);
        if (type == L"heartbeat")
        {
            return IncomingKind::Heartbeat;
        }
        if (type == L"disconnect")
        {
            return IncomingKind::Disconnect;
        }
        if (type == L"command-result")
        {
            return IncomingKind::CommandResult;
        }
        if (type == L"error")
        {
            return IncomingKind::Error;
        }
        return IncomingKind::Other;
    }

    bool ReadRemoteCommandLine(
        const wchar_t* prompt,
        std::vector<std::wstring>* history,
        std::wstring* line,
        SOCKET sock,
        DWORD* lastHeartbeat,
        bool* disconnected,
        std::wstring* error)
    {
        bool ok = false;
        HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        HANDLE input = GetStdHandle(STD_INPUT_HANDLE);

        do
        {
            if (line == nullptr)
            {
                break;
            }
            line->clear();
            if (disconnected != nullptr)
            {
                *disconnected = false;
            }

            DWORD originalMode = 0;
            const bool consoleInput =
                input != nullptr &&
                input != INVALID_HANDLE_VALUE &&
                GetConsoleMode(input, &originalMode);
            if (!consoleInput)
            {
                DWORD written = 0;
                if (prompt != nullptr)
                {
                    WriteConsoleW(output, prompt, static_cast<DWORD>(wcslen(prompt)), &written, nullptr);
                }
                wchar_t buffer[8192] = {};
                DWORD read = 0;
                if (!ReadConsoleW(input, buffer, 8191, &read, nullptr))
                {
                    break;
                }
                std::wstring text(buffer, read);
                while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n'))
                {
                    text.pop_back();
                }
                *line = text;
                ok = true;
                break;
            }

            CONSOLE_SCREEN_BUFFER_INFO info = {};
            GetConsoleScreenBufferInfo(output, &info);
            COORD start = info.dwCursorPosition;
            size_t rendered = 0;
            size_t cursor = 0;
            size_t historyIndex = history != nullptr ? history->size() : 0;
            std::wstring draft;
            bool hasDraft = false;

            DrawRemoteLine(output, start, prompt, *line, cursor, &rendered);

            while (true)
            {
                if (!SendHeartbeatIfDue(sock, lastHeartbeat, error))
                {
                    if (disconnected != nullptr)
                    {
                        *disconnected = true;
                    }
                    break;
                }

                std::wstring incoming;
                const IncomingKind kind = PollIncoming(sock, 50, &incoming, error);
                if (kind == IncomingKind::RecvFailed || kind == IncomingKind::Disconnect)
                {
                    if (disconnected != nullptr)
                    {
                        *disconnected = true;
                    }
                    break;
                }
                if (kind == IncomingKind::Error)
                {
                    std::wstring code;
                    knremote::GetStringField(incoming, L"code", &code);
                    std::wcerr << L"error: " << code << L"\n";
                    GetConsoleScreenBufferInfo(output, &info);
                    start = info.dwCursorPosition;
                    rendered = 0;
                    DrawRemoteLine(output, start, prompt, *line, cursor, &rendered);
                    continue;
                }
                if (kind == IncomingKind::CommandResult)
                {
                    std::wstring stdoutText;
                    knremote::GetStringField(incoming, L"stdout", &stdoutText);
                    if (!stdoutText.empty())
                    {
                        std::wcout << stdoutText;
                        if (stdoutText.back() != L'\n')
                        {
                            std::wcout << L"\n";
                        }
                    }
                    GetConsoleScreenBufferInfo(output, &info);
                    start = info.dwCursorPosition;
                    rendered = 0;
                    DrawRemoteLine(output, start, prompt, *line, cursor, &rendered);
                    continue;
                }

                if (_kbhit() == 0)
                {
                    continue;
                }

                const int key = _getwch();
                if (key == 0 || key == 0xe0)
                {
                    const int extended = _getwch();
                    if (extended == 72 && history != nullptr && !history->empty())
                    {
                        if (historyIndex == history->size())
                        {
                            draft = *line;
                            hasDraft = true;
                            historyIndex = history->size() - 1;
                        }
                        else if (historyIndex > 0)
                        {
                            --historyIndex;
                        }
                        else
                        {
                            MessageBeep(MB_OK);
                            continue;
                        }
                        *line = (*history)[historyIndex];
                        cursor = line->size();
                        DrawRemoteLine(output, start, prompt, *line, cursor, &rendered);
                    }
                    else if (extended == 80 && history != nullptr)
                    {
                        if (historyIndex >= history->size())
                        {
                            MessageBeep(MB_OK);
                            continue;
                        }
                        if (historyIndex + 1 < history->size())
                        {
                            ++historyIndex;
                            *line = (*history)[historyIndex];
                        }
                        else
                        {
                            historyIndex = history->size();
                            *line = hasDraft ? draft : L"";
                        }
                        cursor = line->size();
                        DrawRemoteLine(output, start, prompt, *line, cursor, &rendered);
                    }
                    else if (extended == 75 && cursor > 0)
                    {
                        --cursor;
                        DrawRemoteLine(output, start, prompt, *line, cursor, &rendered);
                    }
                    else if (extended == 77 && cursor < line->size())
                    {
                        ++cursor;
                        DrawRemoteLine(output, start, prompt, *line, cursor, &rendered);
                    }
                    else if (extended == 71)
                    {
                        cursor = 0;
                        DrawRemoteLine(output, start, prompt, *line, cursor, &rendered);
                    }
                    else if (extended == 79)
                    {
                        cursor = line->size();
                        DrawRemoteLine(output, start, prompt, *line, cursor, &rendered);
                    }
                    else if (extended == 83 && cursor < line->size())
                    {
                        line->erase(cursor, 1);
                        historyIndex = history != nullptr ? history->size() : 0;
                        hasDraft = false;
                        DrawRemoteLine(output, start, prompt, *line, cursor, &rendered);
                    }
                    continue;
                }

                if (key == L'\r' || key == L'\n')
                {
                    std::wcout << L"\n";
                    ok = true;
                    break;
                }
                if (key == 3)
                {
                    if (!line->empty())
                    {
                        line->clear();
                        cursor = 0;
                        historyIndex = history != nullptr ? history->size() : 0;
                        hasDraft = false;
                        DrawRemoteLine(output, start, prompt, *line, cursor, &rendered);
                        continue;
                    }
                    std::wcout << L"^C\n";
                    break;
                }
                if (key == 26)
                {
                    std::wcout << L"\n";
                    break;
                }
                if (key == L'\t')
                {
                    bool listed = false;
                    std::wstring listing;
                    const bool changed = ApplyTabCompletion(line, &cursor, &listed, &listing);
                    if (listed && !listing.empty())
                    {
                        std::wcout << listing;
                        GetConsoleScreenBufferInfo(output, &info);
                        start = info.dwCursorPosition;
                        rendered = 0;
                        DrawRemoteLine(output, start, prompt, *line, cursor, &rendered);
                    }
                    else if (changed)
                    {
                        historyIndex = history != nullptr ? history->size() : 0;
                        hasDraft = false;
                        DrawRemoteLine(output, start, prompt, *line, cursor, &rendered);
                    }
                    else
                    {
                        MessageBeep(MB_OK);
                    }
                    continue;
                }
                if (key == L'\b')
                {
                    if (cursor > 0)
                    {
                        line->erase(cursor - 1, 1);
                        --cursor;
                        historyIndex = history != nullptr ? history->size() : 0;
                        hasDraft = false;
                        DrawRemoteLine(output, start, prompt, *line, cursor, &rendered);
                    }
                    continue;
                }
                if (key >= 32 && key != 127)
                {
                    line->insert(cursor, 1, static_cast<wchar_t>(key));
                    ++cursor;
                    historyIndex = history != nullptr ? history->size() : 0;
                    hasDraft = false;
                    DrawRemoteLine(output, start, prompt, *line, cursor, &rendered);
                }
            }
        } while (false);

        return ok;
    }
}

int RemoteClientMain(int argc, wchar_t** argv)
{
    std::wstring host;
    uint16_t port = 0;
    std::wstring error;
    if (!ParseRemoteConnectArgs(argc, argv, &host, &port, &error))
    {
        std::wcerr << error << L"\n";
        return 2;
    }

    WSADATA wsa = {};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        std::wcerr << L"WSAStartup failed\n";
        return 1;
    }

    int exitCode = 1;
    SOCKET sock = INVALID_SOCKET;
    std::wstring password;
    do
    {
        if (!ReadHiddenLine(L"password: ", &password))
        {
            std::wcerr << L"password prompt requires an interactive console\n";
            exitCode = 2;
            break;
        }

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET)
        {
            std::wcerr << L"socket failed\n";
            break;
        }

        sockaddr_in remote = {};
        remote.sin_family = AF_INET;
        remote.sin_port = htons(port);
        if (!knremote::ParseIpv4(host, &remote.sin_addr))
        {
            std::wcerr << L"--connect requires an IPv4 literal\n";
            exitCode = 2;
            break;
        }

        if (connect(sock, reinterpret_cast<sockaddr*>(&remote), sizeof(remote)) != 0)
        {
            std::wcerr << L"connect failed\n";
            exitCode = 5;
            break;
        }

        std::wstring auth = knremote::MakeObject(
            L"auth",
            L"c-1",
            L"\"password\":" + knremote::Quote(password));
        if (password.size() >= 1)
        {
            SecureZeroMemory(&password[0], password.size() * sizeof(wchar_t));
            password.clear();
        }
        const bool authSent = SendJson(sock, auth, &error);
        if (!auth.empty())
        {
            SecureZeroMemory(&auth[0], auth.size() * sizeof(wchar_t));
            auth.clear();
        }
        if (!authSent)
        {
            std::wcerr << L"auth send failed\n";
            exitCode = 5;
            break;
        }

        std::wstring reply;
        if (!RecvJson(sock, &reply, GetTickCount() + knremote::kAuthDeadlineMs, &error))
        {
            std::wcerr << L"auth failed: " << error << L"\n";
            exitCode = 5;
            break;
        }

        std::wstring type;
        knremote::GetStringField(reply, L"type", &type);
        if (type == L"auth-err")
        {
            std::wstring code;
            knremote::GetStringField(reply, L"code", &code);
            std::wcerr << L"auth-err: " << code << L"\n";
            exitCode = 4;
            break;
        }
        if (type != L"auth-ok")
        {
            std::wcerr << L"unexpected auth reply\n";
            exitCode = 6;
            break;
        }

        std::wstring helloJson;
        if (!RecvJson(sock, &helloJson, GetTickCount() + knremote::kAuthDeadlineMs, &error))
        {
            std::wcerr << L"hello failed: " << error << L"\n";
            exitCode = 5;
            break;
        }
        knremote::GetStringField(helloJson, L"type", &type);
        if (type != L"hello")
        {
            std::wcerr << L"expected hello\n";
            exitCode = 6;
            break;
        }

        std::wstring hostname;
        std::wstring os;
        int64_t abi = 0;
        bool writeMode = false;
        bool cloak = false;
        bool cleartext = true;
        knremote::GetStringField(helloJson, L"hostname", &hostname);
        knremote::GetStringField(helloJson, L"os", &os);
        knremote::GetNumberField(helloJson, L"abi", &abi);
        knremote::GetBoolField(helloJson, L"writeMode", &writeMode);
        knremote::GetBoolField(helloJson, L"cloak", &cloak);
        knremote::GetBoolField(helloJson, L"cleartext", &cleartext);

        std::wcout << L"connected " << hostname << L" " << os
                   << L" abi=" << abi
                   << L" write=" << (writeMode ? L"on" : L"off")
                   << L" cloak=" << (cloak ? L"yes" : L"no")
                   << L" cleartext=" << (cleartext ? L"true" : L"false")
                   << L"\n";
        if (cleartext)
        {
            std::wcout << L"warning: session is cleartext; lab LAN only\n";
        }

        uint32_t nextId = 2;
        bool running = true;
        std::vector<std::wstring> history;
        DWORD lastHeartbeat = GetTickCount();
        while (running)
        {
            std::wstring line;
            bool disconnected = false;
            if (!ReadRemoteCommandLine(
                    L"knkd> ",
                    &history,
                    &line,
                    sock,
                    &lastHeartbeat,
                    &disconnected,
                    &error))
            {
                exitCode = disconnected ? 5 : 0;
                break;
            }
            if (line.empty())
            {
                continue;
            }
            history.push_back(line);

            std::wstring lowered = line;
            for (wchar_t& ch : lowered)
            {
                ch = static_cast<wchar_t>(towlower(ch));
            }
            if (lowered == L"cls")
            {
                HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
                CONSOLE_SCREEN_BUFFER_INFO info = {};
                if (GetConsoleScreenBufferInfo(output, &info))
                {
                    DWORD written = 0;
                    COORD origin = {};
                    FillConsoleOutputCharacterW(
                        output,
                        L' ',
                        info.dwSize.X * info.dwSize.Y,
                        origin,
                        &written);
                    SetConsoleCursorPosition(output, origin);
                }
                continue;
            }
            if (lowered == L"disconnect" || lowered == L"q" || lowered == L"quit" || lowered == L"exit")
            {
                SendJson(sock, knremote::MakeObject(L"disconnect", L"c-end", L"\"reason\":\"client\""), nullptr);
                exitCode = 0;
                break;
            }

            const std::wstring id = L"c-" + std::to_wstring(nextId++);
            const std::wstring submit = knremote::MakeObject(
                L"command-submit",
                id,
                L"\"line\":" + knremote::Quote(line));
            if (!SendJson(sock, submit, &error))
            {
                std::wcerr << L"send failed\n";
                exitCode = 5;
                break;
            }

            bool done = false;
            DWORD lastResult = GetTickCount();
            while (!done)
            {
                if (!SendHeartbeatIfDue(sock, &lastHeartbeat, &error))
                {
                    std::wcerr << L"peer drop\n";
                    exitCode = 5;
                    running = false;
                    break;
                }
                if (knremote::IntervalElapsed(lastResult, knremote::kDeadPeerMs))
                {
                    std::wcerr << L"peer drop\n";
                    exitCode = 5;
                    running = false;
                    break;
                }

                std::wstring msg;
                const IncomingKind kind = PollIncoming(sock, 200, &msg, &error);
                if (kind == IncomingKind::None || kind == IncomingKind::Heartbeat)
                {
                    if (kind == IncomingKind::Heartbeat)
                    {
                        lastResult = GetTickCount();
                    }
                    continue;
                }
                if (kind == IncomingKind::RecvFailed || kind == IncomingKind::Disconnect)
                {
                    std::wcerr << L"peer drop\n";
                    exitCode = 5;
                    running = false;
                    break;
                }
                lastResult = GetTickCount();
                if (kind == IncomingKind::Error)
                {
                    std::wstring code;
                    knremote::GetStringField(msg, L"code", &code);
                    std::wcerr << L"error: " << code << L"\n";
                    done = true;
                    continue;
                }
                if (kind == IncomingKind::CommandResult)
                {
                    std::wstring stdoutText;
                    std::wstring stderrText;
                    bool last = false;
                    knremote::GetStringField(msg, L"stdout", &stdoutText);
                    knremote::GetStringField(msg, L"stderr", &stderrText);
                    knremote::GetBoolField(msg, L"last", &last);
                    if (!stdoutText.empty())
                    {
                        std::wcout << stdoutText;
                        if (stdoutText.back() != L'\n')
                        {
                            std::wcout << L"\n";
                        }
                    }
                    if (!stderrText.empty())
                    {
                        std::wcerr << stderrText;
                        if (stderrText.back() != L'\n')
                        {
                            std::wcerr << L"\n";
                        }
                    }
                    if (last)
                    {
                        done = true;
                    }
                    continue;
                }
            }
        }
    } while (false);

    if (sock != INVALID_SOCKET)
    {
        closesocket(sock);
    }
    if (!password.empty())
    {
        SecureZeroMemory(&password[0], password.size() * sizeof(wchar_t));
        password.clear();
    }
    WSACleanup();
    return exitCode;
}
