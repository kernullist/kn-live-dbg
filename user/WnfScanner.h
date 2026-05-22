#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

constexpr uint64_t kWnfStateNameXorKey = 0x41C64E6DA3BC0074ull;

struct WnfStateNameDecoded
{
    uint64_t Raw = 0;
    uint64_t Decoded = 0;
    uint32_t Version = 0;
    uint32_t Lifetime = 0;
    uint32_t DataScope = 0;
    bool     IsPermanent = false;
    uint64_t Sequence = 0;
    uint64_t OwnerTag = 0;
    std::wstring LifetimeText;
    std::wstring DataScopeText;
    std::wstring OwnerTagText;
};

struct WnfSubscriberRecord
{
    uint64_t NodeAddress = 0;
    uint64_t ListHeadEntryOffset = 0;  // offset within parent entry where the list head lives
    uint64_t OwningProcessAddress = 0;
    uint64_t Pid = 0;
    std::wstring ImageName;
    std::wstring OwnPoolTag;           // 4-char ASCII pool tag read from node-0x10 (the node's own chunk header)
    bool     HasProcess = false;
    bool     HasPid = false;
    bool     HasImageName = false;
    bool     HasOwnPoolTag = false;
    bool     IsProcessCandidateTag = false; // true when OwnPoolTag is one of the known WNF-subscription tags
    std::vector<uint8_t> RawBytes;     // first 0x80 bytes of subscription record for diagnostics
    std::vector<uint8_t> PrefixBytes;  // 0x40 bytes immediately before NodeAddress (for chunk-start hunt)
};

struct WnfInstanceRecord
{
    uint64_t Address = 0;
    uint64_t StateName = 0;
    WnfStateNameDecoded Decoded;
    uint64_t ChangeStamp = 0;
    uint32_t DataSize = 0;
    uint64_t LastDataBlock = 0;
    // Entry-level "owning/host process" recovered from the stable
    // EPROCESS pointer found at node-0x30 of every subscription
    // record on the entry. Same value across all subscribers for a
    // given entry -- not the subscriber's PID/image, but the process
    // that owns/hosts this WNF state.
    uint64_t OwningProcessAddress = 0;
    uint64_t OwningPid = 0;
    std::wstring OwningImageName;
    bool     HasChangeStamp = false;
    bool     HasDataSize = false;
    bool     HasLastDataBlock = false;
    bool     HasOwningProcess = false;
    bool     HasOwningPid = false;
    bool     HasOwningImageName = false;
    std::vector<WnfSubscriberRecord> Subscribers;
};

struct WnfDataDump
{
    uint64_t StateName = 0;
    WnfStateNameDecoded Decoded;
    uint64_t InstanceAddress = 0;
    uint64_t DataBlockAddress = 0;
    uint32_t DataSize = 0;
    std::vector<uint8_t> DataBytes;
    bool     InstanceResolved = false;
    bool     DataResolved = false;
};

struct WnfSiloCandidateDump
{
    uint64_t PointerAddress = 0;
    uint64_t SiloAddress = 0;
    std::wstring AnchorSymbol;
    std::wstring NearestSymbol;
    std::wstring NearestModule;
    std::vector<uint8_t> HeadBytes;
    uint32_t EmbeddedStateNameHits = 0;
    uint32_t KernelPointerSlots = 0;
};

struct WnfListEntryWalkRecord
{
    uint64_t EntryAddress = 0;
    std::vector<uint8_t> EntryBytes;
    uint64_t StateNameCandidate = 0;
    WnfStateNameDecoded DecodedStateName;
    bool HasStateName = false;
    uint64_t StateNameOffsetWithinEntry = 0;
};

struct WnfListHeadFinding
{
    uint64_t SiloAddress = 0;
    uint64_t HeadOffset = 0;
    uint64_t HeadAddress = 0;
    uint64_t Flink = 0;
    uint64_t Blink = 0;
    bool IsEmpty = false;
    std::vector<WnfListEntryWalkRecord> Entries;
};

struct WnfScanResult
{
    std::vector<WnfInstanceRecord>      Instances;
    std::vector<WnfSiloCandidateDump>   Candidates;
    std::vector<WnfListHeadFinding>     ListHeads;
    WnfStateNameDecoded DecodedHash;
    WnfDataDump Data;
    std::wstring SiloStateSymbol;
    std::wstring TableTypeName;
    std::wstring TableFieldName;
    uint64_t SiloStateAddress = 0;
    uint64_t TableAddress = 0;
    uint32_t NodesVisited = 0;
    uint32_t SiloCandidatesCollected = 0;
    uint32_t SiloCandidatesAfterFilter = 0;
    uint32_t TotalAvlTablesObserved = 0;
    uint32_t WnfRelatedAvlsObserved = 0;
    std::vector<std::wstring> Diagnostics;
    std::vector<std::wstring> Warnings;
    bool SiloStateResolved = false;
    bool TableResolved = false;
    bool NameInstanceLayoutResolved = false;
};

WnfStateNameDecoded DecodeWnfStateName(uint64_t raw);

class WnfScanner
{
public:
    enum class Scope
    {
        Decode,
        Instances,
        Instance,
        Data,
        Candidates,
        Lists
    };

    struct Options
    {
        Scope    Target = Scope::Decode;
        uint64_t TargetHash = 0;
        bool     HasTargetHash = false;
    };

    WnfScanner(DeviceClient& device, SymbolEngine& symbols);
    bool Scan(const Options& options, WnfScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};
