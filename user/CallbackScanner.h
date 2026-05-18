#pragma once

#include "DeviceClient.h"
#include "SymbolEngine.h"

#include <cstdint>
#include <string>
#include <vector>

struct KernelCallbackRecord
{
    std::wstring Kind;
    std::wstring Target;
    std::wstring Altitude;
    std::wstring FunctionModule;
    std::wstring FunctionSymbol;
    std::wstring PostFunctionModule;
    std::wstring PostFunctionSymbol;
    std::wstring ContextModule;
    std::wstring ContextSymbol;
    std::wstring ObjectTypeSource;
    std::wstring RootSource;
    std::wstring CallbackName;
    std::wstring FilterName;
    std::wstring Notes;
    uint32_t Slot = 0;
    uint32_t Operations = 0;
    uint32_t ObjectTypeIndex = 0xffffffffu;
    uint32_t MajorFunction = 0xffffffffu;
    uint32_t CallbackFlags = 0;
    uint32_t FilterFlags = 0;
    uint32_t FrameId = 0xffffffffu;
    uint64_t ObjectType = 0;
    uint64_t RootAddress = 0;
    uint64_t Frame = 0;
    uint64_t Filter = 0;
    uint64_t DriverObject = 0;
    uint64_t ListEntry = 0;
    uint64_t Entry = 0;
    uint64_t CallbackBlock = 0;
    uint64_t CallbackEntry = 0;
    uint64_t Function = 0;
    uint64_t PostFunction = 0;
    uint64_t Context = 0;
    uint64_t Cookie = 0;
    uint64_t RawValue = 0;
};

struct KernelCallbackScanResult
{
    std::vector<KernelCallbackRecord> Records;
    std::vector<std::wstring> Warnings;
};

class KernelCallbackScanner
{
public:
    KernelCallbackScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(const std::wstring& scope, KernelCallbackScanResult* result, std::wstring* error);

private:
    bool ScanProcessCallbacks(KernelCallbackScanResult* result, std::wstring* error);
    bool ScanThreadCallbacks(KernelCallbackScanResult* result, std::wstring* error);
    bool ScanRegistryCallbacks(KernelCallbackScanResult* result, std::wstring* error);
    bool ScanObjectCallbacks(KernelCallbackScanResult* result, std::wstring* error);
    bool ScanMinifilterCallbacks(KernelCallbackScanResult* result, std::wstring* error);
    bool ScanObjectTypeCallbacks(
        const std::wstring& target,
        uint64_t objectTypeAddress,
        uint32_t objectTypeIndex,
        const std::wstring& objectTypeSource,
        KernelCallbackScanResult* result,
        std::wstring* error);

    DeviceClient& device_;
    SymbolEngine& symbols_;
};
