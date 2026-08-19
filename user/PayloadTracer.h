#pragma once

#include "AddressInspector.h"
#include "DeviceClient.h"
#include "LeftoverCommon.h"
#include "MemoryDumper.h"
#include "NativeDisassembler.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct PayloadHookPointer
{
    uint64_t Address = 0;
    std::wstring Source;
};

struct PayloadTraceRecord
{
    uint64_t Address = 0;
    std::wstring Source;
    std::wstring Classification;
    std::wstring Risk;
    std::wstring Notes;
    std::wstring ModuleName;
    std::wstring SymbolName;
    AddressInspectResult Inspect;
    PeHeaderProbe Pe = {};
    NativeDisassemblyResult Disasm;
    uint64_t PoolAddress = 0;
    uint64_t PoolSize = 0;
    uint32_t PoolTag = 0;
    uint64_t PeProbeAddress = 0;
    bool InLoadedModule = false;
    bool InBigPool = false;
    bool PoolNonPaged = false;
    bool PeProbed = false;
    bool DisasmOk = false;
};

struct PayloadTraceOptions
{
    uint32_t DisasmInstructions = 16;
    uint32_t Limit = 16;
    bool ScanHooks = false;
};

struct PayloadTraceResult
{
    std::vector<PayloadTraceRecord> Records;
    std::vector<std::wstring> Warnings;
    std::vector<std::wstring> CoverageNotes;
    uint64_t HookPointersSeen = 0;
    uint64_t UniqueUnbacked = 0;
    uint64_t Traced = 0;
    uint64_t FilteredLowRisk = 0;
    bool HookSweepComplete = false;
    bool Incomplete = false;
    bool BigPoolQueried = false;
};

class PayloadTracer
{
public:
    PayloadTracer(DeviceClient& device, SymbolEngine& symbols);

    bool TraceAddress(
        uint64_t address,
        const std::wstring& source,
        const PayloadTraceOptions& options,
        PayloadTraceRecord* record,
        std::wstring* error);
    bool Scan(const PayloadTraceOptions& options, PayloadTraceResult* result, std::wstring* error);

private:
    void CollectHookPointers(
        std::vector<PayloadHookPointer>* pointers,
        PayloadTraceResult* result);
    void TracePrepared(
        const std::vector<PayloadHookPointer>& pointers,
        const PayloadTraceOptions& options,
        PayloadTraceResult* result);

    DeviceClient& device_;
    SymbolEngine& symbols_;
    std::vector<LeftoverModuleRange> modules_;
    LeftoverBigPoolSnapshot pool_;
    bool modulesReady_ = false;
    bool poolReady_ = false;
};

std::wstring BuildPayloadTraceJson(const PayloadTraceResult& result);
bool PayloadTracerSelfTest();
