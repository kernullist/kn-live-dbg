#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct AlpcPortRecord
{
    std::wstring Name;
    std::wstring DirectoryPath;
    std::wstring OwnerImageName;
    std::wstring Notes;
    uint64_t Address = 0;
    uint64_t OwnerProcess = 0;
    uint64_t OwnerProcessId = 0;
    uint64_t ConnectionPort = 0;
    uint64_t CommunicationInfo = 0;
    uint64_t ServerCommunicationPort = 0;
    uint64_t ClientCommunicationPort = 0;
    uint32_t MainQueueLength = 0;
    uint32_t PendingQueueLength = 0;
    uint32_t LargeMessageQueueLength = 0;
    uint32_t CanceledQueueLength = 0;
    uint32_t WaitQueueLength = 0;
    uint32_t Flags = 0;
    uint8_t  TypeIndex = 0;
    bool     HasOwnerProcess = false;
    bool     HasCommunicationInfo = false;
    bool     HasConnectionPort = false;
    bool     HasQueueData = false;
    bool     IsConnectionPort = false;
    bool     IsServerCommunicationPort = false;
    bool     IsClientCommunicationPort = false;
    bool     IsNamedDirectoryPort = false;
};

struct AlpcScanResult
{
    std::vector<AlpcPortRecord> Records;
    std::vector<std::wstring>   Warnings;
    uint64_t AlpcPortTypeAddress = 0;
    uint32_t AlpcPortTypeIndex = 0;
    bool     TypeIndexResolved = false;
};

class AlpcScanner
{
public:
    enum class Scope
    {
        Ports,
        Port,
        Connections,
        Queues
    };

    struct Options
    {
        Scope    Target = Scope::Ports;
        std::wstring NameFilter;
        uint64_t Address = 0;
        uint64_t PidFilter = 0;
        bool     HasAddress = false;
        bool     HasPidFilter = false;
    };

    AlpcScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(const Options& options, AlpcScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};

std::wstring BuildAlpcJson(const AlpcScanResult& result);
