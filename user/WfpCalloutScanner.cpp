#include "WfpCalloutScanner.h"

#include <map>
#include <sstream>

#include "WfpScanner.h"

namespace
{
    constexpr uint64_t kKernelSpaceMin = 0xffff800000000000ull;
    constexpr uint32_t kMaxCalloutCount = 0x4000;       // sanity bound on slot count
    constexpr uint32_t kMaxWalkBytes = 0x100000 - 0x1000; // keep a single read under the transfer cap
    constexpr uint32_t kSampleEntries = 64;              // entries sampled while scoring a layout
    constexpr uint32_t kNotifyOffset = 0x18;             // notifyFn within a slot (informational)
    constexpr uint32_t kFlowDeleteOffset = 0x20;         // flowDeleteFn within a slot (informational)

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelSpaceMin;
    }

    bool ReadU32(DeviceClient& device, uint64_t address, uint32_t* value)
    {
        std::vector<uint8_t> bytes;
        if (!device.ReadMemory(address, sizeof(uint32_t), &bytes, nullptr) || bytes.size() != sizeof(uint32_t))
        {
            return false;
        }
        memcpy(value, bytes.data(), sizeof(uint32_t));
        return true;
    }

    bool ReadU64(DeviceClient& device, uint64_t address, uint64_t* value)
    {
        std::vector<uint8_t> bytes;
        if (!device.ReadMemory(address, sizeof(uint64_t), &bytes, nullptr) || bytes.size() != sizeof(uint64_t))
        {
            return false;
        }
        memcpy(value, bytes.data(), sizeof(uint64_t));
        return true;
    }

    uint64_t ReadEntryU64(const std::vector<uint8_t>& buffer, size_t entryOffset, uint32_t fieldOffset)
    {
        size_t pos = entryOffset + fieldOffset;
        if (pos + sizeof(uint64_t) > buffer.size())
        {
            return 0;
        }
        uint64_t value = 0;
        memcpy(&value, buffer.data() + pos, sizeof(uint64_t));
        return value;
    }

    std::wstring FindOwningModule(SymbolEngine& symbols, uint64_t address)
    {
        for (const KernelModuleInfo& module : symbols.Modules())
        {
            uint64_t end = module.Base + module.Size;
            if (end < module.Base)
            {
                continue;
            }
            if (address >= module.Base && address < end)
            {
                return module.ImageName;
            }
        }
        return std::wstring();
    }

    std::wstring NearestSymbolText(SymbolEngine& symbols, uint64_t address)
    {
        std::wstring nearest;
        uint64_t displacement = 0;
        std::wstring ignored;
        if (!symbols.FindNearestSymbol(address, &nearest, &displacement, &ignored))
        {
            return std::wstring();
        }
        std::wstringstream stream;
        stream << nearest;
        if (displacement != 0)
        {
            stream << L"+0x" << std::hex << displacement;
        }
        return stream.str();
    }

    struct LayoutCandidate
    {
        uint32_t CountOffset;
        uint32_t ArrayOffset;
        uint32_t EntrySize;
        uint32_t ClassifyOffset;
        const wchar_t* Source;
    };

    // Scores a candidate layout by sampling the callout array and counting how
    // many non-null classify pointers land inside a loaded kernel module.
    // Returns a score in [0,1]; outValidated/outNonNull report the sample.
    double ScoreLayout(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t engineBase,
        const LayoutCandidate& layout,
        uint32_t* outCount,
        uint64_t* outArray,
        uint32_t* outNonNull)
    {
        *outCount = 0;
        *outArray = 0;
        *outNonNull = 0;

        uint32_t count = 0;
        uint64_t arrayPtr = 0;
        if (!ReadU32(device, engineBase + layout.CountOffset, &count) ||
            !ReadU64(device, engineBase + layout.ArrayOffset, &arrayPtr))
        {
            return 0.0;
        }

        if (count == 0 || count > kMaxCalloutCount || !IsKernelAddress(arrayPtr))
        {
            return 0.0;
        }

        uint32_t sample = count < kSampleEntries ? count : kSampleEntries;
        uint32_t sampleBytes = sample * layout.EntrySize;
        std::vector<uint8_t> buffer;
        if (!device.ReadMemory(arrayPtr, sampleBytes, &buffer, nullptr) || buffer.size() != sampleBytes)
        {
            return 0.0;
        }

        uint32_t nonNull = 0;
        uint32_t valid = 0;
        for (uint32_t i = 0; i < sample; ++i)
        {
            uint64_t classifyFn = ReadEntryU64(buffer, static_cast<size_t>(i) * layout.EntrySize, layout.ClassifyOffset);
            if (classifyFn == 0)
            {
                continue;
            }
            ++nonNull;
            if (IsKernelAddress(classifyFn) && !FindOwningModule(symbols, classifyFn).empty())
            {
                ++valid;
            }
        }

        *outCount = count;
        *outArray = arrayPtr;
        *outNonNull = nonNull;

        if (nonNull < 4)
        {
            return 0.0;
        }
        return static_cast<double>(valid) / static_cast<double>(nonNull);
    }

    void BuildCalloutMetadata(std::map<uint32_t, WfpRecord>* metadata)
    {
        WfpScanner scanner;
        WfpScanner::Options options = {};
        options.Target = WfpScanner::Scope::Callouts;
        WfpScanResult result = {};
        std::wstring error;
        if (!scanner.Scan(options, &result, &error))
        {
            return;
        }
        for (const WfpRecord& record : result.Records)
        {
            if (record.HasCalloutId)
            {
                (*metadata)[record.CalloutId] = record;
            }
        }
    }
}

WfpCalloutScanner::WfpCalloutScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool WfpCalloutScanner::Scan(WfpCalloutScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid WFP callout scan result output";
            }
            break;
        }

        *result = WfpCalloutScanResult{};

        if (symbols_.Modules().empty())
        {
            std::wstring loadError;
            if (!symbols_.LoadKernelModules(&loadError))
            {
                if (error != nullptr)
                {
                    *error = L"could not load kernel modules: " + loadError;
                }
                break;
            }
        }

        uint64_t globalSymbol = 0;
        if (!symbols_.ResolveSymbol(L"netio!gWfpGlobal", &globalSymbol, nullptr) || globalSymbol == 0)
        {
            result->Warnings.push_back(
                L"netio!gWfpGlobal not resolved; netio.sys private/public symbols are required for kernel callout walking");
            ok = true; // not a hard error: report cleanly that we could not resolve
            break;
        }
        result->GlobalSymbol = globalSymbol;

        // The engine state may live at the symbol directly or behind a pointer
        // at the symbol. Validate both interpretations against the layouts.
        std::vector<uint64_t> bases;
        bases.push_back(globalSymbol);
        uint64_t deref = 0;
        if (ReadU64(device_, globalSymbol, &deref) && IsKernelAddress(deref))
        {
            bases.push_back(deref);
        }

        const LayoutCandidate documented[] =
        {
            { 0x190, 0x198, 0x50, 0x10, L"gWfpGlobal+0x198 / 0x50-byte slots / classify +0x10" },
            { 0x548, 0x550, 0x40, 0x10, L"gWfpGlobal+0x550 / 0x40-byte slots / classify +0x10" }
        };

        double bestScore = 0.0;
        uint64_t bestBase = 0;
        LayoutCandidate bestLayout = documented[0];
        uint32_t bestCount = 0;
        uint64_t bestArray = 0;

        for (uint64_t base : bases)
        {
            for (const LayoutCandidate& layout : documented)
            {
                uint32_t count = 0;
                uint64_t arrayPtr = 0;
                uint32_t nonNull = 0;
                double score = ScoreLayout(device_, symbols_, base, layout, &count, &arrayPtr, &nonNull);
                if (score > bestScore)
                {
                    bestScore = score;
                    bestBase = base;
                    bestLayout = layout;
                    bestCount = count;
                    bestArray = arrayPtr;
                }
            }
        }

        // Bounded fallback scan if no documented layout validated, to tolerate
        // offset drift on builds the documented offsets do not match.
        if (bestScore < 0.8)
        {
            const uint32_t entrySizes[] = { 0x50, 0x40, 0x48, 0x60 };
            for (uint64_t base : bases)
            {
                for (uint32_t arrayOff = 0x180; arrayOff <= 0x560; arrayOff += 8)
                {
                    for (uint32_t entrySize : entrySizes)
                    {
                        LayoutCandidate layout = { arrayOff - 8, arrayOff, entrySize, 0x10, L"scored fallback" };
                        uint32_t count = 0;
                        uint64_t arrayPtr = 0;
                        uint32_t nonNull = 0;
                        double score = ScoreLayout(device_, symbols_, base, layout, &count, &arrayPtr, &nonNull);
                        if (score > bestScore)
                        {
                            bestScore = score;
                            bestBase = base;
                            bestLayout = layout;
                            bestCount = count;
                            bestArray = arrayPtr;
                        }
                    }
                }
            }
        }

        if (bestScore < 0.8 || bestArray == 0)
        {
            result->Warnings.push_back(
                L"could not locate a plausible WFP callout array from gWfpGlobal; netio.sys layout may have drifted (offsets need RE refinement on this build)");
            ok = true;
            break;
        }

        result->EngineBase = bestBase;
        result->ArrayAddress = bestArray;
        result->Count = bestCount;
        result->EntrySize = bestLayout.EntrySize;
        result->ClassifyOffset = bestLayout.ClassifyOffset;
        result->LayoutSource = bestLayout.Source;
        result->Resolved = true;

        // Walk the full array (bounded by the transfer cap).
        uint32_t walkCount = bestCount;
        uint64_t walkBytes = static_cast<uint64_t>(walkCount) * bestLayout.EntrySize;
        if (walkBytes > kMaxWalkBytes)
        {
            walkCount = kMaxWalkBytes / bestLayout.EntrySize;
            result->Warnings.push_back(L"callout count exceeds single-read bound; walk truncated");
        }

        std::vector<uint8_t> buffer;
        uint32_t bufferBytes = walkCount * bestLayout.EntrySize;
        if (!device_.ReadMemory(bestArray, bufferBytes, &buffer, nullptr) || buffer.size() != bufferBytes)
        {
            result->Warnings.push_back(L"failed to read the full callout array");
            ok = true;
            break;
        }

        std::map<uint32_t, WfpRecord> metadata;
        BuildCalloutMetadata(&metadata);

        for (uint32_t i = 0; i < walkCount; ++i)
        {
            size_t entryOffset = static_cast<size_t>(i) * bestLayout.EntrySize;
            uint64_t classifyFn = ReadEntryU64(buffer, entryOffset, bestLayout.ClassifyOffset);
            if (classifyFn == 0)
            {
                continue; // empty slot
            }

            WfpKernelCallout callout = {};
            callout.CalloutId = i;
            callout.EntryAddress = bestArray + entryOffset;
            callout.ClassifyFn = classifyFn;
            callout.NotifyFn = ReadEntryU64(buffer, entryOffset, kNotifyOffset);
            callout.FlowDeleteFn = ReadEntryU64(buffer, entryOffset, kFlowDeleteOffset);

            callout.ClassifyModule = FindOwningModule(symbols_, classifyFn);
            callout.ClassifySymbol = NearestSymbolText(symbols_, classifyFn);
            if (!IsKernelAddress(callout.ClassifyFn) || callout.ClassifyModule.empty())
            {
                callout.ClassifySuspicious = true;
                callout.Notes = L"classify function outside loaded kernel modules";
                ++result->SuspiciousCount;
                result->AnySuspicious = true;
            }

            if (callout.NotifyFn != 0 && IsKernelAddress(callout.NotifyFn))
            {
                callout.NotifyModule = FindOwningModule(symbols_, callout.NotifyFn);
            }
            if (callout.FlowDeleteFn != 0 && IsKernelAddress(callout.FlowDeleteFn))
            {
                callout.FlowDeleteModule = FindOwningModule(symbols_, callout.FlowDeleteFn);
            }

            auto it = metadata.find(i);
            if (it != metadata.end())
            {
                callout.HasMetadata = true;
                callout.Name = it->second.Name;
                callout.LayerName = it->second.LayerName;
                callout.ProviderName = it->second.ProviderName;
            }

            result->Callouts.push_back(std::move(callout));
        }

        ok = true;
    } while (false);

    return ok;
}
