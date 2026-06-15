#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "DeviceClient.h"
#include "SymbolEngine.h"

// One kernel-mode WFP callout: the registered classify/notify/flowDelete
// function pointers recovered from the netio.sys callout array, joined to the
// user-mode callout metadata (name/layer/provider) by callout id. The
// user-mode Base Filtering Engine does not expose these kernel function
// pointers, so they are the actual hook surface for network filter drivers.
struct WfpKernelCallout
{
    uint32_t CalloutId = 0;
    uint64_t EntryAddress = 0;
    uint64_t ClassifyFn = 0;
    uint64_t NotifyFn = 0;
    uint64_t FlowDeleteFn = 0;
    std::wstring ClassifyModule;
    std::wstring ClassifySymbol;
    std::wstring NotifyModule;
    std::wstring FlowDeleteModule;
    bool ClassifySuspicious = false;
    bool HasMetadata = false;
    std::wstring Name;
    std::wstring LayerName;
    std::wstring ProviderName;
    std::wstring Notes;
};

struct WfpCalloutScanResult
{
    bool Resolved = false;
    uint64_t GlobalSymbol = 0;   // netio!gWfpGlobal address
    uint64_t EngineBase = 0;     // resolved engine struct base
    uint64_t ArrayAddress = 0;   // callout array base
    uint32_t Count = 0;          // callout slot count
    uint32_t EntrySize = 0;      // bytes per callout slot
    uint32_t ClassifyOffset = 0; // classifyFn offset within a slot
    uint32_t CountOffset = 0;    // count field offset within the engine struct
    uint32_t ArrayOffset = 0;    // array-pointer offset within the engine struct
    bool EngineFromPointer = false; // true if engine base came from *gWfpGlobal
    std::wstring LayoutSource;   // which candidate layout validated
    std::vector<WfpKernelCallout> Callouts;
    std::vector<std::wstring> Warnings;
    bool AnySuspicious = false;
    uint32_t SuspiciousCount = 0;
};

// Resolves the kernel-mode WFP callout table from live kernel memory and
// recovers each callout's classify/notify/flowDelete function pointers. The
// table location and per-slot layout are not in public PDBs and drift across
// builds, so the scanner anchors on the public symbol netio!gWfpGlobal and
// scores documented candidate layouts against live pointers (the same
// guarded-fallback discipline used by the firmware-table and WNF scanners),
// then joins each slot to user-mode callout metadata by callout id. No new
// driver IOCTL is required: it reuses the existing memory-read primitive.
// Requires the driver device to be open and netio.sys symbols to resolve.
class WfpCalloutScanner
{
public:
    WfpCalloutScanner(DeviceClient& device, SymbolEngine& symbols);

    bool Scan(WfpCalloutScanResult* result, std::wstring* error);

private:
    DeviceClient& device_;
    SymbolEngine& symbols_;
};
