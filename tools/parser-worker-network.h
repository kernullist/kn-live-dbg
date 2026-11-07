#pragma once

#include <WinSock2.h>
#include <WS2tcpip.h>
#include "../user/ParserWorkerProcess.h"
#include <string>
#include <iostream>
#pragma comment(lib, "ws2_32.lib")

namespace worker_network
{
    struct Socket
    {
        SOCKET Value = INVALID_SOCKET;
        ~Socket() { if (Value != INVALID_SOCKET) { closesocket(Value); } }
    };
    inline sockaddr_storage Address(int family, unsigned short port)
    {
        sockaddr_storage result{};
        if (family == AF_INET)
        {
            auto* address = reinterpret_cast<sockaddr_in*>(&result);
            address->sin_family = AF_INET; address->sin_port = htons(port);
            address->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        }
        else
        {
            auto* address = reinterpret_cast<sockaddr_in6*>(&result);
            address->sin6_family = AF_INET6; address->sin6_port = htons(port); address->sin6_addr = in6addr_loopback;
        }
        return result;
    }
    inline int AddressBytes(int family) { return family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6); }
    inline int Ready(SOCKET socket, unsigned milliseconds)
    {
        fd_set reads; FD_ZERO(&reads); FD_SET(socket, &reads);
        timeval timeout{}; timeout.tv_sec = milliseconds / 1000; timeout.tv_usec = (milliseconds % 1000) * 1000;
        return select(0, &reads, nullptr, nullptr, &timeout);
    }
    inline unsigned short Bind(Socket& socket, int family, int type)
    {
        socket.Value = ::socket(family, type, 0);
        auto address = Address(family, 0); int bytes = AddressBytes(family);
        if (socket.Value == INVALID_SOCKET || bind(socket.Value, reinterpret_cast<sockaddr*>(&address), bytes) != 0 ||
            getsockname(socket.Value, reinterpret_cast<sockaddr*>(&address), &bytes) != 0 ||
            (type == SOCK_STREAM && listen(socket.Value, 4) != 0)) { return 0; }
        return ntohs(family == AF_INET ? reinterpret_cast<sockaddr_in*>(&address)->sin_port :
            reinterpret_cast<sockaddr_in6*>(&address)->sin6_port);
    }
    inline int Child(int argc, wchar_t** argv)
    {
        if (argc != 6) { return 110; }
        const auto family = std::wstring(argv[3]) == L"4" ? AF_INET : std::wstring(argv[3]) == L"6" ? AF_INET6 : 0;
        const int tcpPort = _wtoi(argv[4]), udpPort = _wtoi(argv[5]);
        if (!family || tcpPort <= 0 || tcpPort > 65535 || udpPort <= 0 || udpPort > 65535) { return 111; }
        WSADATA data{}; if (WSAStartup(MAKEWORD(2, 2), &data) != 0) { return 112; }
        bool attempted = false;
        {
            Socket tcp{socket(family, SOCK_STREAM, 0)}, udp{socket(family, SOCK_DGRAM, 0)};
            u_long nonblocking = 1;
            if (tcp.Value == INVALID_SOCKET || udp.Value == INVALID_SOCKET || ioctlsocket(tcp.Value, FIONBIO, &nonblocking)) { return 113; }
            const auto tcpAddress = Address(family, static_cast<unsigned short>(tcpPort));
            const auto connected = connect(tcp.Value, reinterpret_cast<const sockaddr*>(&tcpAddress), AddressBytes(family));
            bool tcpDenied = false;
            if (connected == SOCKET_ERROR)
            {
                const auto error = WSAGetLastError();
                if (error == WSAEACCES) { tcpDenied = true; }
                else if (error == WSAEWOULDBLOCK)
                {
                    fd_set writes, errors; FD_ZERO(&writes); FD_ZERO(&errors); FD_SET(tcp.Value, &writes); FD_SET(tcp.Value, &errors);
                    timeval timeout{0, 500000};
                    const auto ready = select(0, nullptr, &writes, &errors, &timeout);
                    int status = 0, bytes = sizeof(status);
                    tcpDenied = ready == 0 || (ready > 0 && getsockopt(tcp.Value, SOL_SOCKET, SO_ERROR,
                        reinterpret_cast<char*>(&status), &bytes) == 0 && (status == WSAEACCES || status == WSAETIMEDOUT));
                }
            }
            const auto udpAddress = Address(family, static_cast<unsigned short>(udpPort));
            const auto sent = sendto(udp.Value, "kn-worker", 9, 0, reinterpret_cast<const sockaddr*>(&udpAddress), AddressBytes(family));
            const auto udpError = WSAGetLastError();
            // UDP submission may succeed before WFP drops the datagram. The
            // independent parent listener, not sendto's return value, is the
            // delivery oracle. Unexpected API/setup failures still fail.
            attempted = tcpDenied && (sent == 9 || (sent == SOCKET_ERROR && udpError == WSAEACCES));
        }
        WSACleanup();
        DWORD written = 0;
        if (!attempted) { return 114; }
        const auto output = std::string("network_attempted");
        return WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), output.data(), static_cast<DWORD>(output.size()), &written, nullptr) && written == output.size() ? 0 : 115;
    }
    inline void Run(const std::wstring& executable, void(*check)(bool, const char*))
    {
        WSADATA data{};
        const bool started = WSAStartup(MAKEWORD(2, 2), &data) == 0;
        check(started, "owned network control initialization"); if (!started) { return; }
        for (const auto family : {AF_INET, AF_INET6})
        {
            Socket tcp, udp;
            const auto tcpPort = Bind(tcp, family, SOCK_STREAM), udpPort = Bind(udp, family, SOCK_DGRAM);
            check(tcpPort != 0 && udpPort != 0, "owned TCP and UDP loopback listeners");
            if (!tcpPort || !udpPort) { continue; }
            const auto baseline = [&]() {
                bool tcpBaseline = false, udpBaseline = false;
                Socket connection{socket(family, SOCK_STREAM, 0)}, datagram{socket(family, SOCK_DGRAM, 0)};
                const auto tcpAddress = Address(family, tcpPort), udpAddress = Address(family, udpPort);
                if (connect(connection.Value, reinterpret_cast<const sockaddr*>(&tcpAddress), AddressBytes(family)) == 0 &&
                    send(connection.Value, "kn-parent", 9, 0) == 9 && Ready(tcp.Value, 1000) == 1)
                {
                    Socket accepted{accept(tcp.Value, nullptr, nullptr)}; char message[32]{};
                    tcpBaseline = accepted.Value != INVALID_SOCKET && Ready(accepted.Value, 1000) == 1 &&
                        recv(accepted.Value, message, sizeof(message), 0) == 9 && std::string(message, 9) == "kn-parent";
                }
                if (sendto(datagram.Value, "kn-parent", 9, 0, reinterpret_cast<const sockaddr*>(&udpAddress), AddressBytes(family)) == 9 && Ready(udp.Value, 1000) == 1)
                {
                    char message[32]{};
                    udpBaseline = recvfrom(udp.Value, message, sizeof(message), 0, nullptr, nullptr) == 9 && std::string(message, 9) == "kn-parent";
                }
                return tcpBaseline && udpBaseline;
            };
            check(baseline(), "ordinary parent reaches both owned listeners before worker attempts");
            ParserWorkerRequest request; request.Executable = executable;
            request.Arguments = {L"--child", L"network", family == AF_INET ? L"4" : L"6", std::to_wstring(tcpPort), std::to_wstring(udpPort)};
            const auto result = RunParserWorker(request);
            check(result.Status == L"exited" && result.SandboxVerified && result.Output == "network_attempted", "zero-capability worker completes TCP and UDP attempts");
            const bool noTcp = Ready(tcp.Value, 500) == 0, noUdp = Ready(udp.Value, 500) == 0;
            check(noTcp && noUdp, "owned listeners receive no worker connection or datagram");
            check(baseline(), "ordinary parent still reaches both listeners after worker attempts");
        }
        WSACleanup();
    }
}
