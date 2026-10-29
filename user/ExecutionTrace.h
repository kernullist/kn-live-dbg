#pragma once

#include "AddressSpaceDescriptor.h"
#include <atomic>
#include <optional>
#include <string>
#include <vector>

constexpr size_t ExecutionTraceMaxBytes = 2 * 1024 * 1024;
constexpr size_t ExecutionTraceMaxSamples = 4096;

struct TraceAddressSpace
{
    std::wstring Id;
    std::wstring Domain;
    uint32_t ProcessId = 0;
    uint64_t ProcessCreateTime = 0;
    uint64_t RootIdentity = 0;
    uint64_t Epoch = 0;
    AddressSpaceDescriptor Format;
};

struct TraceCodeVersion
{
    std::wstring Id;
    std::wstring Space;
    std::wstring Sha256;
    uint64_t Base = 0;
    uint64_t FirstTick = 0;
    uint64_t LastTick = 0;
    std::vector<uint8_t> Bytes;
};

struct TraceSample
{
    uint64_t Sequence = 0;
    uint64_t Tick = 0;
    std::optional<uint32_t> Cpu;
    std::wstring Space;
    uint32_t ThreadId = 0;
    uint64_t ThreadCreateTime = 0;
    uint64_t Ip = 0;
    std::wstring CodeVersion;
};

struct TraceLossInterval
{
    uint64_t FirstTick = 0;
    uint64_t LastTick = 0;
    std::wstring Reason;
};

struct ExecutionTrace
{
    std::wstring SourceId;
    std::wstring Producer;
    std::wstring Kind;
    std::wstring TargetId;
    std::wstring BootId;
    std::wstring VmId;
    std::optional<uint32_t> Vtl;
    std::wstring ClockDomain;
    uint64_t TicksPerSecond = 0;
    uint64_t FirstTick = 0;
    uint64_t LastTick = 0;
    std::optional<uint64_t> ReportedLost;
    uint64_t SequenceGaps = 0;
    std::wstring FileSha256;
    std::vector<TraceAddressSpace> Spaces;
    std::vector<TraceCodeVersion> Code;
    std::vector<TraceSample> Samples;
    std::vector<TraceLossInterval> Loss;
};

// Qualification checks imported metadata. It never authenticates a producer,
// runs a decoder, or independently establishes execution or write attribution.
bool ParseExecutionTrace(const std::wstring& json, ExecutionTrace* trace, std::wstring* error,
    const std::atomic<bool>* cancellation = nullptr);
std::wstring ExecutionTracePageJson(const ExecutionTrace& trace, size_t offset, size_t limit);
int RunExecutionTraceCommand(const std::vector<std::wstring>& args,
    const std::atomic<bool>* cancellation = nullptr);
