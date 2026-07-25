#include "SsdtScanner.h"

#include <cstdio>
#include <sstream>

#include "LayoutResolver.h"
#include "McpJson.h"

namespace
{
    constexpr uint64_t kKernelSpaceMin = 0xffff800000000000ull;
    constexpr uint32_t kMaxServiceLimit = 0x4000; // sane upper bound on syscall count
    constexpr uint32_t kDescriptorStride = 0x20;  // x64 sizeof(_KSERVICE_TABLE_DESCRIPTOR)

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelSpaceMin;
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

    bool StartsWithCI(const std::wstring& value, const std::wstring& prefix)
    {
        if (value.size() < prefix.size())
        {
            return false;
        }
        for (size_t i = 0; i < prefix.size(); ++i)
        {
            wchar_t a = value[i];
            wchar_t b = prefix[i];
            if (a >= L'A' && a <= L'Z')
            {
                a = static_cast<wchar_t>(a - L'A' + L'a');
            }
            if (b >= L'A' && b <= L'Z')
            {
                b = static_cast<wchar_t>(b - L'A' + L'a');
            }
            if (a != b)
            {
                return false;
            }
        }
        return true;
    }

    bool EqualsCI(const std::wstring& a, const std::wstring& b)
    {
        return a.size() == b.size() && StartsWithCI(a, b);
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

    bool AnyWin32kModuleLoaded(SymbolEngine& symbols)
    {
        for (const KernelModuleInfo& module : symbols.Modules())
        {
            if (StartsWithCI(module.ImageName, L"win32k"))
            {
                return true;
            }
        }
        return false;
    }
}

SsdtScanner::SsdtScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool SsdtScanner::Scan(SsdtScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid SSDT scan result output";
            }
            break;
        }

        *result = SsdtScanResult{};

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

        // Resolve descriptor field offsets PDB-first, with the stable x64
        // fallback layout (Base +0x00, Limit +0x10), and bound them so a bad
        // PDB type cannot push a read out of the descriptor.
        ResolvedFieldOffset baseField = ResolveFieldOffset(symbols_, L"nt!_KSERVICE_TABLE_DESCRIPTOR", L"Base", 0x00);
        ResolvedFieldOffset limitField = ResolveFieldOffset(symbols_, L"nt!_KSERVICE_TABLE_DESCRIPTOR", L"Limit", 0x10);
        if (baseField.Offset + sizeof(uint64_t) > kDescriptorStride)
        {
            baseField.Offset = 0x00;
        }
        if (limitField.Offset + sizeof(uint32_t) > kDescriptorStride)
        {
            limitField.Offset = 0x10;
        }

        struct TableTarget
        {
            std::wstring DescriptorSymbol;
            uint64_t DescriptorAddress;
            std::wstring Name;
            bool Win32k = false;
            // Filter/optional tables may own routines in third-party modules;
            // only flag targets outside every loaded kernel image.
            bool AnyLoadedModuleOk = false;
        };

        std::vector<TableTarget> targets;

        uint64_t nativeDescriptor = 0;
        if (symbols_.ResolveSymbol(L"nt!KeServiceDescriptorTable", &nativeDescriptor, nullptr) && nativeDescriptor != 0)
        {
            TableTarget target = {};
            target.DescriptorSymbol = L"nt!KeServiceDescriptorTable";
            target.DescriptorAddress = nativeDescriptor;
            target.Name = L"KeServiceDescriptorTable (native)";
            target.Win32k = false;
            targets.push_back(target);
        }
        else
        {
            result->Warnings.push_back(L"nt!KeServiceDescriptorTable symbol not resolved");
        }

        uint64_t shadowDescriptor = 0;
        if (symbols_.ResolveSymbol(L"nt!KeServiceDescriptorTableShadow", &shadowDescriptor, nullptr) && shadowDescriptor != 0)
        {
            // Shadow array holds up to four descriptors on modern Windows:
            //   [0] native (often aliases KeServiceDescriptorTable)
            //   [1] win32k
            //   [2] filter / optional
            //   [3] unused / optional
            // Prefer PDB/symbol size for the slot bound; without it, only the
            // legacy native+win32k slots are trusted and [2]/[3] are marked unverified.
            const bool win32kLoaded = AnyWin32kModuleLoaded(symbols_);
            if (!win32kLoaded)
            {
                result->Warnings.push_back(
                    L"win32k modules not loaded; shadow[1] may be empty (other shadow slots still checked)");
            }

            uint32_t shadowSlotCount = 4;
            bool shadowBoundVerified = false;
            {
                std::vector<SymbolMatchInfo> matches;
                if (symbols_.EnumerateSymbols(L"nt!KeServiceDescriptorTableShadow", 8, &matches, nullptr))
                {
                    for (const SymbolMatchInfo& match : matches)
                    {
                        if (match.Address == shadowDescriptor && match.Size >= kDescriptorStride)
                        {
                            shadowSlotCount = static_cast<uint32_t>(match.Size / kDescriptorStride);
                            if (shadowSlotCount == 0)
                            {
                                shadowSlotCount = 2;
                            }
                            if (shadowSlotCount > 4)
                            {
                                shadowSlotCount = 4;
                            }
                            shadowBoundVerified = true;
                            break;
                        }
                    }
                }
            }
            if (!shadowBoundVerified)
            {
                // Without a verified array size, keep legacy [0]/[1] as trusted
                // coverage and still probe [2]/[3] as optional/unverified.
                result->Warnings.push_back(
                    L"KeServiceDescriptorTableShadow array bound unverified; scanning slots [0..3] with "
                    L"[2]/[3] treated as filter/optional");
            }

            for (uint32_t slot = 0; slot < shadowSlotCount; ++slot)
            {
                const uint64_t descriptorAddress =
                    shadowDescriptor + static_cast<uint64_t>(slot) * kDescriptorStride;

                // Skip shadow[0] when it is the same object as the public native table.
                if (slot == 0 && nativeDescriptor != 0 && descriptorAddress == nativeDescriptor)
                {
                    continue;
                }

                uint64_t probeBase = 0;
                uint32_t probeLimit = 0;
                if (!ReadU64(device_, descriptorAddress + baseField.Offset, &probeBase) ||
                    !ReadU32(device_, descriptorAddress + limitField.Offset, &probeLimit))
                {
                    continue;
                }
                if (probeBase == 0 || probeLimit == 0 || !IsKernelAddress(probeBase))
                {
                    continue;
                }

                // Avoid double-walking the same table base already covered by native.
                if (nativeDescriptor != 0)
                {
                    uint64_t nativeBase = 0;
                    if (ReadU64(device_, nativeDescriptor + baseField.Offset, &nativeBase) &&
                        nativeBase != 0 &&
                        nativeBase == probeBase)
                    {
                        result->Warnings.push_back(
                            L"KeServiceDescriptorTableShadow[" + std::to_wstring(slot) +
                            L"] aliases native KiServiceTable; not double-scanned");
                        continue;
                    }
                }

                TableTarget target = {};
                target.DescriptorSymbol =
                    L"nt!KeServiceDescriptorTableShadow[" + std::to_wstring(slot) + L"]";
                target.DescriptorAddress = descriptorAddress;
                if (slot == 0)
                {
                    target.Name = L"KeServiceDescriptorTableShadow[0] (native/filter alias)";
                    target.Win32k = false;
                }
                else if (slot == 1)
                {
                    target.Name = L"KeServiceDescriptorTableShadow[1] (win32k)";
                    target.Win32k = true;
                }
                else
                {
                    target.Name =
                        L"KeServiceDescriptorTableShadow[" + std::to_wstring(slot) +
                        L"] (filter/optional)";
                    target.Win32k = false;
                    target.AnyLoadedModuleOk = true;
                }
                targets.push_back(target);
            }
        }
        else
        {
            result->Warnings.push_back(
                L"nt!KeServiceDescriptorTableShadow not resolved; only native SSDT scanned");
        }

        if (targets.empty())
        {
            if (error != nullptr)
            {
                *error = L"no service descriptor table could be resolved";
            }
            break;
        }

        for (const TableTarget& target : targets)
        {
            SsdtTable table = {};
            table.Name = target.Name;
            table.DescriptorSymbol = target.DescriptorSymbol;

            uint64_t tableBase = 0;
            uint32_t limit = 0;
            if (!ReadU64(device_, target.DescriptorAddress + baseField.Offset, &tableBase) ||
                !ReadU32(device_, target.DescriptorAddress + limitField.Offset, &limit))
            {
                table.Warning = L"failed to read service descriptor";
                result->Tables.push_back(table);
                continue;
            }

            if (tableBase == 0 || !IsKernelAddress(tableBase))
            {
                table.Warning = L"implausible service table base";
                result->Tables.push_back(table);
                continue;
            }

            if (limit == 0)
            {
                table.Warning = L"service table limit is zero";
                result->Tables.push_back(table);
                continue;
            }

            if (limit > kMaxServiceLimit)
            {
                table.Warning = L"service table limit exceeds sane bound; descriptor likely misresolved";
                result->Tables.push_back(table);
                continue;
            }

            table.TableBase = tableBase;
            table.Limit = limit;
            table.Resolved = true;

            std::wstring expectedModule;
            if (target.AnyLoadedModuleOk)
            {
                table.ExpectedModule = L"<any-loaded-module>";
            }
            else if (!target.Win32k)
            {
                // Prefer a fixed ntoskrnl expectation. Deriving expectedModule
                // from FindOwningModule(tableBase) lets a redirected descriptor
                // Base inside a clone table make every entry look clean.
                uint64_t kiServiceTable = 0;
                const bool haveKiServiceTable =
                    symbols_.ResolveSymbol(L"nt!KiServiceTable", &kiServiceTable, nullptr) &&
                    kiServiceTable != 0;
                const std::wstring tableOwner = FindOwningModule(symbols_, tableBase);
                const std::wstring ntosOwner =
                    haveKiServiceTable ? FindOwningModule(symbols_, kiServiceTable) : std::wstring();

                if (haveKiServiceTable && tableBase != kiServiceTable)
                {
                    table.Warning =
                        L"native service table base does not match nt!KiServiceTable (" +
                        NearestSymbolText(symbols_, tableBase) + L")";
                    ++table.SuspiciousCount;
                    ++result->SuspiciousCount;
                    result->AnySuspicious = true;
                }

                if (!ntosOwner.empty())
                {
                    expectedModule = ntosOwner;
                }
                else if (!tableOwner.empty() &&
                         (EqualsCI(tableOwner, L"ntoskrnl.exe") ||
                          EqualsCI(tableOwner, L"ntkrnlpa.exe") ||
                          EqualsCI(tableOwner, L"ntkrnlmp.exe") ||
                          EqualsCI(tableOwner, L"ntkrpamp.exe")))
                {
                    expectedModule = tableOwner;
                }
                else
                {
                    expectedModule = L"ntoskrnl.exe";
                    if (!tableOwner.empty() && !EqualsCI(tableOwner, expectedModule))
                    {
                        table.Warning =
                            (table.Warning.empty() ? L"" : table.Warning + L"; ") +
                            L"native table base owned by " + tableOwner +
                            L" instead of ntoskrnl";
                        ++table.SuspiciousCount;
                        ++result->SuspiciousCount;
                        result->AnySuspicious = true;
                    }
                }
                table.ExpectedModule = expectedModule;
            }
            else
            {
                table.ExpectedModule = L"win32k*";
            }

            std::vector<uint8_t> bytes;
            uint32_t tableBytes = limit * sizeof(uint32_t);
            if (!device_.ReadMemory(tableBase, tableBytes, &bytes, nullptr) || bytes.size() != tableBytes)
            {
                table.Warning = L"failed to read service table entries";
                result->Tables.push_back(table);
                continue;
            }

            for (uint32_t i = 0; i < limit; ++i)
            {
                int32_t raw = 0;
                memcpy(&raw, bytes.data() + (i * sizeof(uint32_t)), sizeof(int32_t));

                SsdtEntry entry = {};
                entry.Index = i;
                entry.RawValue = raw;
                entry.ArgBytes = static_cast<uint8_t>(raw & 0xF);

                // x64 encoding: arithmetic shift preserves the (usually
                // negative) offset from the table base into the .text section.
                int64_t offset = static_cast<int64_t>(raw >> 4);
                entry.Routine = tableBase + static_cast<uint64_t>(offset);

                entry.Module = FindOwningModule(symbols_, entry.Routine);
                entry.Symbol = NearestSymbolText(symbols_, entry.Routine);

                if (!IsKernelAddress(entry.Routine) || entry.Module.empty())
                {
                    entry.Suspicious = true;
                    entry.InExpectedModule = false;
                    entry.Notes = L"service routine outside loaded kernel modules";
                }
                else if (target.AnyLoadedModuleOk)
                {
                    // Filter/optional tables may legitimately point into third
                    // party filter drivers; only outside-all-modules is bad.
                    entry.InExpectedModule = true;
                }
                else if (!target.Win32k)
                {
                    entry.InExpectedModule = EqualsCI(entry.Module, expectedModule);
                    if (!entry.InExpectedModule)
                    {
                        entry.Suspicious = true;
                        entry.Notes = L"native syscall routine outside the kernel image (" + entry.Module + L")";
                    }
                }
                else
                {
                    entry.InExpectedModule = StartsWithCI(entry.Module, L"win32k");
                    if (!entry.InExpectedModule)
                    {
                        entry.Suspicious = true;
                        entry.Notes = L"win32k syscall routine outside win32k modules (" + entry.Module + L")";
                    }
                }

                if (entry.Suspicious)
                {
                    ++table.SuspiciousCount;
                    ++result->SuspiciousCount;
                    result->AnySuspicious = true;
                }

                table.Entries.push_back(entry);
            }

            result->Tables.push_back(table);
        }

        ok = true;
    } while (false);

    return ok;
}

namespace
{
    std::wstring SsdtJsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }
}

std::wstring BuildSsdtJson(const SsdtScanResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.ssdt.v1\",\"anySuspicious\":";
    out += result.AnySuspicious ? L"true" : L"false";
    out += L",\"suspiciousCount\":" + std::to_wstring(result.SuspiciousCount);
    out += L",\"tableCount\":" + std::to_wstring(result.Tables.size());
    out += L",\"tables\":[";

    for (size_t tableIndex = 0; tableIndex < result.Tables.size(); ++tableIndex)
    {
        const SsdtTable& table = result.Tables[tableIndex];
        if (tableIndex > 0)
        {
            out += L",";
        }

        out += L"{\"name\":" + mcpjson::Quote(table.Name);
        if (!table.DescriptorSymbol.empty())
        {
            out += L",\"descriptorSymbol\":" + mcpjson::Quote(table.DescriptorSymbol);
        }
        out += L",\"tableBase\":" + mcpjson::Quote(SsdtJsonHex(table.TableBase));
        out += L",\"limit\":" + std::to_wstring(table.Limit);
        out += L",\"expectedModule\":" + mcpjson::Quote(table.ExpectedModule);
        out += L",\"resolved\":";
        out += table.Resolved ? L"true" : L"false";
        out += L",\"suspiciousCount\":" + std::to_wstring(table.SuspiciousCount);
        if (!table.Warning.empty())
        {
            out += L",\"warning\":" + mcpjson::Quote(table.Warning);
        }

        out += L",\"entries\":[";
        for (size_t entryIndex = 0; entryIndex < table.Entries.size(); ++entryIndex)
        {
            const SsdtEntry& entry = table.Entries[entryIndex];
            if (entryIndex > 0)
            {
                out += L",";
            }

            out += L"{\"index\":" + std::to_wstring(entry.Index);
            out += L",\"rawValue\":" + std::to_wstring(entry.RawValue);
            out += L",\"argBytes\":" + std::to_wstring(static_cast<uint32_t>(entry.ArgBytes));
            out += L",\"routine\":" + mcpjson::Quote(SsdtJsonHex(entry.Routine));
            if (!entry.Module.empty())
            {
                out += L",\"module\":" + mcpjson::Quote(entry.Module);
            }
            if (!entry.Symbol.empty())
            {
                out += L",\"symbol\":" + mcpjson::Quote(entry.Symbol);
            }
            out += L",\"inExpectedModule\":";
            out += entry.InExpectedModule ? L"true" : L"false";
            out += L",\"suspicious\":";
            out += entry.Suspicious ? L"true" : L"false";
            if (!entry.Notes.empty())
            {
                out += L",\"notes\":" + mcpjson::Quote(entry.Notes);
            }
            out += L"}";
        }
        out += L"]";

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
