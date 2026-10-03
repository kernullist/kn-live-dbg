#include "IdtScanner.h"
#include "McpJson.h"

#include <cstdio>
#include <sstream>

namespace
{
    constexpr uint64_t kKernelSpaceMin = 0xffff800000000000ull;
    constexpr uint32_t kIdtEntrySize = 16;
    constexpr uint32_t kMaxIdtEntries = 256;

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelSpaceMin;
    }

    bool IdtTableShapeValid(const IdtInfo& idt, uint32_t expectedCount = 0)
    {
        return IsKernelAddress(idt.Base) && idt.Limit < kIdtEntrySize * kMaxIdtEntries &&
            (idt.Limit + 1u) % kIdtEntrySize == 0 && idt.Base <= ~0ull - idt.Limit &&
            (expectedCount == 0 || (idt.Limit + 1u) / kIdtEntrySize == expectedCount);
    }

    bool IdtHandlerDiffers(const IdtEntry& baseline, bool present, uint64_t handler)
    {
        return baseline.Present != present || (present && baseline.Handler != handler);
    }

    std::wstring FindOwningModule(SymbolEngine& symbols, uint64_t address)
    {
        const std::vector<KernelModuleInfo> modules = symbols.CopyModules();
        for (const KernelModuleInfo& module : modules)
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

    uint16_t ReadU16(const uint8_t* p)
    {
        uint16_t value = 0;
        memcpy(&value, p, sizeof(value));
        return value;
    }

    uint32_t ReadU32(const uint8_t* p)
    {
        uint32_t value = 0;
        memcpy(&value, p, sizeof(value));
        return value;
    }
}

IdtScanner::IdtScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool IdtScanner::Scan(IdtScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid IDT scan result output";
            }
            break;
        }

        *result = IdtScanResult{};

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

        // Read the first processor's table before comparing the other CPUs.
        IdtInfo idt = {};
        if (!device_.ReadIdt(0, &idt, error))
        {
            break;
        }

        result->ProcessorNumber = idt.ProcessorNumber;
        result->IdtBase = idt.Base;
        result->IdtLimit = idt.Limit;

        if (!IdtTableShapeValid(idt) || idt.ProcessorNumber != 0)
        {
            if (error != nullptr)
            {
                *error = L"invalid IDT base, table length, or processor identity";
            }
            break;
        }

        uint32_t entryCount = (idt.Limit + 1u) / kIdtEntrySize;
        result->EntryCount = entryCount;

        std::vector<uint8_t> bytes;
        uint32_t tableBytes = entryCount * kIdtEntrySize;
        if (!device_.ReadMemory(idt.Base, tableBytes, &bytes, error) || bytes.size() != tableBytes)
        {
            if (error != nullptr && error->empty())
            {
                *error = L"failed to read IDT entries";
            }
            break;
        }

        for (uint32_t vector = 0; vector < entryCount; ++vector)
        {
            const uint8_t* p = bytes.data() + (vector * kIdtEntrySize);

            uint16_t offsetLow = ReadU16(p + 0);
            uint16_t selector = ReadU16(p + 2);
            uint8_t istByte = p[4];
            uint8_t typeByte = p[5];
            uint16_t offsetMid = ReadU16(p + 6);
            uint32_t offsetHigh = ReadU32(p + 8);

            IdtEntry entry = {};
            entry.Vector = vector;
            entry.Selector = selector;
            entry.Ist = static_cast<uint8_t>(istByte & 0x7);
            entry.GateType = static_cast<uint8_t>(typeByte & 0xF);
            entry.Dpl = static_cast<uint8_t>((typeByte >> 5) & 0x3);
            entry.Present = (typeByte & 0x80) != 0;
            entry.Handler = static_cast<uint64_t>(offsetLow) |
                            (static_cast<uint64_t>(offsetMid) << 16) |
                            (static_cast<uint64_t>(offsetHigh) << 32);

            if (entry.Present)
            {
                entry.Module = FindOwningModule(symbols_, entry.Handler);
                entry.Symbol = NearestSymbolText(symbols_, entry.Handler);
                entry.InKernelModule = !entry.Module.empty() && IsKernelAddress(entry.Handler);

                if (!entry.InKernelModule)
                {
                    entry.Suspicious = true;
                    entry.Notes = L"interrupt handler outside loaded kernel modules";
                    ++result->SuspiciousCount;
                    result->AnySuspicious = true;
                }
            }

            result->Entries.push_back(entry);
        }

        // Cross-check every other active processor's IDT against the BSP. The
        // kernel programs identical handlers on every core, so a per-CPU
        // handler divergence is a single-core interrupt-hook signal. Per-CPU
        // IDT bases legitimately differ, so only handler values are compared.
        uint32_t cpuCount = static_cast<uint32_t>(GetActiveProcessorCount(ALL_PROCESSOR_GROUPS));
        if (cpuCount == 0)
        {
            if (error != nullptr)
            {
                *error = L"could not query active processors for IDT coverage";
            }
            break;
        }
        result->ProcessorCount = cpuCount;
        if (cpuCount > 256)
        {
            result->Warnings.push_back(L"IDT processor scan capped at 256; coverage is incomplete");
            cpuCount = 256;
        }

        for (uint32_t cpu = 1; cpu < cpuCount; ++cpu)
        {
            IdtInfo other = {};
            std::wstring otherError;
            if (!device_.ReadIdt(cpu, &other, &otherError))
            {
                result->Warnings.push_back(L"failed to read IDTR on cpu " + std::to_wstring(cpu) + L": " + otherError);
                continue;
            }

            if (!IdtTableShapeValid(other, entryCount) || other.ProcessorNumber != cpu)
            {
                result->Warnings.push_back(L"IDT base, table length, or processor identity mismatch on cpu " +
                    std::to_wstring(cpu) + L"; comparison is incomplete");
                continue;
            }

            const uint32_t otherCount = (other.Limit + 1u) / kIdtEntrySize;

            std::vector<uint8_t> otherBytes;
            uint32_t otherTableBytes = otherCount * kIdtEntrySize;
            if (!device_.ReadMemory(other.Base, otherTableBytes, &otherBytes, nullptr) || otherBytes.size() != otherTableBytes)
            {
                result->Warnings.push_back(L"failed to read IDT entries on cpu " + std::to_wstring(cpu));
                continue;
            }

            ++result->ProcessorsCompared;

            for (uint32_t vector = 0; vector < otherCount && vector < result->Entries.size(); ++vector)
            {
                IdtEntry& base = result->Entries[vector];
                const uint8_t* p = otherBytes.data() + (static_cast<size_t>(vector) * kIdtEntrySize);
                uint8_t otherType = p[5];
                bool otherPresent = (otherType & 0x80) != 0;
                uint16_t offsetLow = ReadU16(p + 0);
                uint16_t offsetMid = ReadU16(p + 6);
                uint32_t offsetHigh = ReadU32(p + 8);
                uint64_t handler = static_cast<uint64_t>(offsetLow) |
                                   (static_cast<uint64_t>(offsetMid) << 16) |
                                   (static_cast<uint64_t>(offsetHigh) << 32);

                if (!IdtHandlerDiffers(base, otherPresent, handler))
                {
                    continue;
                }

                if (!base.Divergent)
                {
                    base.Divergent = true;
                    ++result->DivergentCount;
                    if (!base.Suspicious)
                    {
                        base.Suspicious = true;
                        ++result->SuspiciousCount;
                        result->AnySuspicious = true;
                    }
                }

                std::wstringstream note;
                note << L"handler differs on cpu " << cpu << L" (0x" << std::hex << handler << L")";
                if (!base.Notes.empty())
                {
                    base.Notes += L"; ";
                }
                base.Notes += note.str();
            }
        }

        ok = true;
    } while (false);

    return ok;
}

namespace
{
    std::wstring IdtJsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }
}

std::wstring BuildIdtJson(const IdtScanResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.idt.v1\",\"processorNumber\":";
    out += std::to_wstring(result.ProcessorNumber);
    out += L",\"idtBase\":" + mcpjson::Quote(IdtJsonHex(result.IdtBase));
    out += L",\"idtLimit\":" + std::to_wstring(result.IdtLimit);
    out += L",\"entryCount\":" + std::to_wstring(result.EntryCount);
    out += L",\"processorCount\":" + std::to_wstring(result.ProcessorCount);
    out += L",\"processorsCompared\":" + std::to_wstring(result.ProcessorsCompared);
    out += L",\"divergentCount\":" + std::to_wstring(result.DivergentCount);
    out += L",\"anySuspicious\":";
    out += result.AnySuspicious ? L"true" : L"false";
    out += L",\"suspiciousCount\":" + std::to_wstring(result.SuspiciousCount);
    out += L",\"entries\":[";

    for (size_t index = 0; index < result.Entries.size(); ++index)
    {
        const IdtEntry& entry = result.Entries[index];
        if (index > 0)
        {
            out += L",";
        }

        out += L"{\"vector\":" + std::to_wstring(entry.Vector);
        out += L",\"handler\":" + mcpjson::Quote(IdtJsonHex(entry.Handler));
        out += L",\"selector\":" + std::to_wstring(entry.Selector);
        out += L",\"ist\":" + std::to_wstring(static_cast<uint32_t>(entry.Ist));
        out += L",\"gateType\":" + std::to_wstring(static_cast<uint32_t>(entry.GateType));
        out += L",\"dpl\":" + std::to_wstring(static_cast<uint32_t>(entry.Dpl));
        out += L",\"present\":";
        out += entry.Present ? L"true" : L"false";
        out += L",\"inKernelModule\":";
        out += entry.InKernelModule ? L"true" : L"false";
        out += L",\"suspicious\":";
        out += entry.Suspicious ? L"true" : L"false";
        out += L",\"divergent\":";
        out += entry.Divergent ? L"true" : L"false";
        if (!entry.Module.empty())
        {
            out += L",\"module\":" + mcpjson::Quote(entry.Module);
        }
        if (!entry.Symbol.empty())
        {
            out += L",\"symbol\":" + mcpjson::Quote(entry.Symbol);
        }
        if (!entry.Notes.empty())
        {
            out += L",\"notes\":" + mcpjson::Quote(entry.Notes);
        }
        out += L"}";
    }

    out += L"],\"warnings\":[";
    for (size_t index = 0; index < result.Warnings.size(); ++index)
    {
        if (index > 0)
        {
            out += L",";
        }
        out += mcpjson::Quote(result.Warnings[index]);
    }
    out += L"]}";

    return out;
}


bool IdtScannerSelfTest()
{
    IdtEntry baseline;
    if (IdtHandlerDiffers(baseline, false, 0x1234) || !IdtHandlerDiffers(baseline, true, 0))
    {
        return false;
    }
    baseline.Present = true;
    baseline.Handler = 0xfffff80000100000ull;
    if (IdtHandlerDiffers(baseline, true, baseline.Handler) ||
        !IdtHandlerDiffers(baseline, false, baseline.Handler) ||
        !IdtHandlerDiffers(baseline, true, baseline.Handler + 1))
    {
        return false;
    }
    IdtScanResult coverage;
    coverage.ProcessorCount = 512;
    coverage.ProcessorsCompared = 255;
    std::wstring count;
    if (!mcpjson::FindRawValue(BuildIdtJson(coverage), L"processorCount", &count) || count != L"512")
    {
        return false;
    }
    IdtInfo info = {};
    info.Base = 0xffff800000001000ull;
    info.Limit = 4095;
    if (!IdtTableShapeValid(info, 256) || IdtTableShapeValid(info, 255))
    {
        return false;
    }
    for (uint32_t limit : {0u, 14u, 4094u, 4096u, 0xffffffffu})
    {
        info.Limit = limit;
        if (IdtTableShapeValid(info))
        {
            return false;
        }
    }
    info.Limit = 4095;
    info.Base = ~0ull - 4094;
    if (IdtTableShapeValid(info))
    {
        return false;
    }
    info.Base = 0x1000;
    return !IdtTableShapeValid(info);
}
