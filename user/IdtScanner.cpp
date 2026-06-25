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

        // Read the IDTR for the boot processor. Per-processor IDT comparison is
        // a future enhancement; the BSP table is representative for handler
        // ownership validation.
        IdtInfo idt = {};
        if (!device_.ReadIdt(0, &idt, error))
        {
            break;
        }

        result->ProcessorNumber = idt.ProcessorNumber;
        result->IdtBase = idt.Base;
        result->IdtLimit = idt.Limit;

        if (!IsKernelAddress(idt.Base))
        {
            if (error != nullptr)
            {
                *error = L"implausible IDT base";
            }
            break;
        }

        uint32_t entryCount = (idt.Limit + 1u) / kIdtEntrySize;
        if (entryCount == 0)
        {
            if (error != nullptr)
            {
                *error = L"IDT limit yields zero entries";
            }
            break;
        }
        if (entryCount > kMaxIdtEntries)
        {
            result->Warnings.push_back(L"IDT entry count exceeds 256; clamping");
            entryCount = kMaxIdtEntries;
        }
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
        if (cpuCount > 256)
        {
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

            if (!IsKernelAddress(other.Base))
            {
                continue;
            }

            uint32_t otherCount = (other.Limit + 1u) / kIdtEntrySize;
            if (otherCount == 0)
            {
                continue;
            }
            if (otherCount > entryCount)
            {
                otherCount = entryCount;
            }

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
                if (!base.Present)
                {
                    continue;
                }

                const uint8_t* p = otherBytes.data() + (static_cast<size_t>(vector) * kIdtEntrySize);
                uint16_t offsetLow = ReadU16(p + 0);
                uint16_t offsetMid = ReadU16(p + 6);
                uint32_t offsetHigh = ReadU32(p + 8);
                uint64_t handler = static_cast<uint64_t>(offsetLow) |
                                   (static_cast<uint64_t>(offsetMid) << 16) |
                                   (static_cast<uint64_t>(offsetHigh) << 32);

                if (handler == base.Handler)
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
