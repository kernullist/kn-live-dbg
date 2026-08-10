#include "HiveScanner.h"

#include "LayoutResolver.h"
#include "McpJson.h"

#include <cstring>
#include <set>
#include <sstream>

namespace
{
    constexpr uint64_t kKernelSpaceMin = 0xffff800000000000ull;
    constexpr uint32_t kMaxHives = 512;
    constexpr uint32_t kMaxLayoutProbe = 0x200;

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelSpaceMin;
    }

    bool ReadU64(DeviceClient& device, uint64_t address, uint64_t* value)
    {
        std::vector<uint8_t> bytes;
        if (!device.ReadMemory(address, sizeof(uint64_t), &bytes, nullptr) ||
            bytes.size() != sizeof(uint64_t))
        {
            return false;
        }
        memcpy(value, bytes.data(), sizeof(uint64_t));
        return true;
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

    bool ModuleLooksLikeNt(const std::wstring& imageName)
    {
        if (imageName.empty())
        {
            return false;
        }
        std::wstring lower = imageName;
        for (wchar_t& ch : lower)
        {
            if (ch >= L'A' && ch <= L'Z')
            {
                ch = static_cast<wchar_t>(ch - L'A' + L'a');
            }
        }
        return lower.find(L"ntoskrnl") != std::wstring::npos ||
            lower.find(L"ntkrnl") != std::wstring::npos;
    }

    bool ResolveHiveListHead(SymbolEngine& symbols, uint64_t* address, std::wstring* matched)
    {
        // CmpMasterHive is a CMHIVE* singleton, not a LIST_ENTRY head - never
        // use it as a list anchor.
        const std::wstring candidates[] =
        {
            L"nt!CmpHiveListHead",
            L"nt!CmHiveListHead"
        };

        for (const std::wstring& name : candidates)
        {
            uint64_t value = 0;
            if (symbols.ResolveSymbol(name, &value, nullptr) && value != 0 && IsKernelAddress(value))
            {
                *address = value;
                *matched = name;
                return true;
            }
        }
        return false;
    }

    struct HiveLayout
    {
        uint32_t HiveListOffset = 0;
        uint32_t GetCellOffset = 0;
        uint32_t ReleaseCellOffset = 0;
        uint32_t AllocateOffset = 0;
        uint32_t FreeOffset = 0;
        bool HasRelease = false;
        bool HasAllocate = false;
        bool HasFree = false;
        bool FromPdb = false;
    };

    bool ResolveHiveLayout(SymbolEngine& symbols, HiveLayout* layout, std::vector<std::wstring>* warnings)
    {
        bool ok = false;
        do
        {
            if (layout == nullptr)
            {
                break;
            }
            *layout = HiveLayout{};

            // Prefer _HHIVE embedded at the front of _CMHIVE on modern builds.
            ResolvedFieldOffset getCell = ResolveFieldOffset(symbols, L"nt!_HHIVE", L"GetCellRoutine", 0x18);
            ResolvedFieldOffset releaseCell = ResolveFieldOffset(symbols, L"nt!_HHIVE", L"ReleaseCellRoutine", 0x20);
            ResolvedFieldOffset allocate = ResolveFieldOffset(symbols, L"nt!_HHIVE", L"Allocate", 0x28);
            ResolvedFieldOffset freeField = ResolveFieldOffset(symbols, L"nt!_HHIVE", L"Free", 0x30);

            // HiveList is mandatory from PDB. Hard-coded 0xA68 is build-volatile
            // and will invent fake hives; refuse that path.
            TypeFieldInfo field = {};
            std::wstring ignored;
            bool hiveListFromPdb = symbols.FindField(L"nt!_CMHIVE", L"HiveList", &field, &ignored);

            layout->GetCellOffset = getCell.Offset;
            layout->ReleaseCellOffset = releaseCell.Offset;
            layout->AllocateOffset = allocate.Offset;
            layout->FreeOffset = freeField.Offset;
            layout->HasRelease = releaseCell.FromPdb;
            layout->HasAllocate = allocate.FromPdb;
            layout->HasFree = freeField.FromPdb;

            if (!getCell.FromPdb)
            {
                // Stable public x64 HHIVE function-pointer block used by
                // multiple research tools: GetCell at +0x18 after base fields.
                layout->GetCellOffset = 0x18;
                layout->ReleaseCellOffset = 0x20;
                layout->AllocateOffset = 0x28;
                layout->FreeOffset = 0x30;
                layout->HasRelease = true;
                layout->HasAllocate = true;
                layout->HasFree = true;
                if (warnings != nullptr)
                {
                    warnings->push_back(
                        L"_HHIVE.GetCellRoutine not in PDB; using guarded x64 fallback offsets");
                }
            }

            if (!hiveListFromPdb)
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(
                        L"_CMHIVE.HiveList not in PDB; hive walk aborted (no trusted list offset)");
                }
                // Leave HiveListOffset = 0 and FromPdb false; Scan will fail closed.
                ok = true;
                break;
            }

            layout->HiveListOffset = field.Offset;
            // HiveList is PDB-trusted. GetCell may still use guarded fallback.
            layout->FromPdb = true;

            if (layout->GetCellOffset >= kMaxLayoutProbe ||
                layout->HiveListOffset >= 0x4000)
            {
                if (warnings != nullptr)
                {
                    warnings->push_back(L"hive layout offsets look implausible");
                }
                layout->HiveListOffset = 0;
                layout->FromPdb = false;
            }

            ok = true;
        } while (false);
        return ok;
    }

    bool LooksLikeGetCellRoutine(SymbolEngine& symbols, uint64_t routine)
    {
        if (routine == 0 || !IsKernelAddress(routine))
        {
            return false;
        }
        std::wstring module = FindOwningModule(symbols, routine);
        if (!ModuleLooksLikeNt(module))
        {
            return false;
        }
        std::wstring symbol = NearestSymbolText(symbols, routine);
        // Accept any ntoskrnl-owned routine; symbol name hint is soft.
        (void)symbol;
        return true;
    }

    std::wstring JsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }
}

HiveScanner::HiveScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool HiveScanner::Scan(const Options& options, HiveScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid hive scan result output";
            }
            break;
        }

        *result = HiveScanResult{};

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

        uint64_t listHead = 0;
        std::wstring listSymbol;
        if (!ResolveHiveListHead(symbols_, &listHead, &listSymbol))
        {
            if (error != nullptr)
            {
                *error = L"hive list head symbol not resolved (tried CmpHiveListHead/CmHiveListHead)";
            }
            result->CoverageComplete = false;
            break;
        }

        result->ListHeadAddress = listHead;
        result->ListHeadSymbol = listSymbol;
        result->ListHeadResolved = true;

        HiveLayout layout = {};
        if (!ResolveHiveLayout(symbols_, &layout, &result->Warnings))
        {
            if (error != nullptr)
            {
                *error = L"failed to resolve hive layout";
            }
            break;
        }

        result->LayoutFromPdb = layout.FromPdb;
        result->HiveListOffset = layout.HiveListOffset;
        result->GetCellOffset = layout.GetCellOffset;
        result->ReleaseCellOffset = layout.ReleaseCellOffset;

        if (layout.HiveListOffset == 0 || !layout.FromPdb)
        {
            if (error != nullptr)
            {
                *error = L"hive list layout unavailable without PDB-resolved _CMHIVE.HiveList";
            }
            result->CoverageComplete = false;
            break;
        }

        uint64_t flink = 0;
        if (!ReadU64(device_, listHead, &flink) || flink == 0)
        {
            if (error != nullptr)
            {
                *error = L"failed to read hive list Flink";
            }
            break;
        }

        // Empty list sentinel.
        if (flink == listHead)
        {
            result->CoverageComplete = true;
            ok = true;
            break;
        }

        std::set<uint64_t> visited;
        uint64_t entry = flink;
        uint32_t index = 0;
        uint32_t limit = options.Limit == 0 ? kMaxHives : options.Limit;
        if (limit > kMaxHives)
        {
            limit = kMaxHives;
        }

        while (entry != 0 && entry != listHead && index < limit)
        {
            if (visited.find(entry) != visited.end())
            {
                result->Warnings.push_back(L"hive list cycle detected; walk stopped");
                break;
            }
            visited.insert(entry);

            if (!IsKernelAddress(entry))
            {
                result->Warnings.push_back(L"non-canonical hive list entry; walk stopped");
                break;
            }

            // entry points at HiveList LIST_ENTRY inside CMHIVE.
            uint64_t hiveBase = entry;
            if (layout.HiveListOffset != 0)
            {
                if (entry < layout.HiveListOffset)
                {
                    result->Warnings.push_back(L"hive list entry underflow; walk stopped");
                    break;
                }
                hiveBase = entry - layout.HiveListOffset;
            }

            HiveRecord record = {};
            record.Index = index;
            record.ListEntryAddress = entry;
            record.HiveAddress = hiveBase;

            uint64_t getCell = 0;
            if (!ReadU64(device_, hiveBase + layout.GetCellOffset, &getCell))
            {
                record.Notes = L"GetCellRoutine read failed";
                record.Suspicious = true;
            }
            else
            {
                record.GetCellRoutine = getCell;
                record.GetCellModule = FindOwningModule(symbols_, getCell);
                record.GetCellSymbol = NearestSymbolText(symbols_, getCell);

                if (getCell == 0 || !IsKernelAddress(getCell) || record.GetCellModule.empty())
                {
                    record.Suspicious = true;
                    record.Notes = L"GetCellRoutine outside loaded kernel modules";
                }
                else if (!ModuleLooksLikeNt(record.GetCellModule))
                {
                    record.Suspicious = true;
                    record.Notes = L"GetCellRoutine owned by non-nt module (" + record.GetCellModule + L")";
                }
                else if (!LooksLikeGetCellRoutine(symbols_, getCell))
                {
                    // still nt-owned; keep as info unless we want soft note
                }
            }

            if (layout.HasRelease)
            {
                uint64_t releaseCell = 0;
                if (ReadU64(device_, hiveBase + layout.ReleaseCellOffset, &releaseCell) && releaseCell != 0)
                {
                    record.HasReleaseCell = true;
                    record.ReleaseCellRoutine = releaseCell;
                    record.ReleaseCellModule = FindOwningModule(symbols_, releaseCell);
                    record.ReleaseCellSymbol = NearestSymbolText(symbols_, releaseCell);
                    if (!IsKernelAddress(releaseCell) || record.ReleaseCellModule.empty() ||
                        !ModuleLooksLikeNt(record.ReleaseCellModule))
                    {
                        record.Suspicious = true;
                        if (!record.Notes.empty())
                        {
                            record.Notes += L"; ";
                        }
                        record.Notes += L"ReleaseCellRoutine outside ntoskrnl";
                    }
                }
            }

            if (layout.HasAllocate)
            {
                uint64_t allocate = 0;
                if (ReadU64(device_, hiveBase + layout.AllocateOffset, &allocate) && allocate != 0)
                {
                    record.HasAllocate = true;
                    record.Allocate = allocate;
                }
            }
            if (layout.HasFree)
            {
                uint64_t freeRoutine = 0;
                if (ReadU64(device_, hiveBase + layout.FreeOffset, &freeRoutine) && freeRoutine != 0)
                {
                    record.HasFree = true;
                    record.Free = freeRoutine;
                }
            }

            if (record.Suspicious)
            {
                ++result->SuspiciousCount;
                result->AnySuspicious = true;
            }

            result->Hives.push_back(record);
            ++index;

            uint64_t next = 0;
            if (!ReadU64(device_, entry, &next))
            {
                result->Warnings.push_back(L"failed to read next hive list Flink; walk stopped");
                break;
            }
            entry = next;
        }

        if (index >= limit && entry != listHead && entry != 0)
        {
            result->Warnings.push_back(L"hive walk hit limit; coverage incomplete");
            result->CoverageComplete = false;
        }
        else if (entry == listHead || entry == 0)
        {
            result->CoverageComplete = true;
        }

        ok = true;
    } while (false);

    return ok;
}

std::wstring BuildHiveJson(const HiveScanResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.hive.v1\"";
    out += L",\"listHeadResolved\":";
    out += result.ListHeadResolved ? L"true" : L"false";
    out += L",\"listHeadAddress\":" + mcpjson::Quote(JsonHex(result.ListHeadAddress));
    out += L",\"listHeadSymbol\":" + mcpjson::Quote(result.ListHeadSymbol);
    out += L",\"layoutFromPdb\":";
    out += result.LayoutFromPdb ? L"true" : L"false";
    out += L",\"coverageComplete\":";
    out += result.CoverageComplete ? L"true" : L"false";
    out += L",\"anySuspicious\":";
    out += result.AnySuspicious ? L"true" : L"false";
    out += L",\"suspiciousCount\":" + std::to_wstring(result.SuspiciousCount);
    out += L",\"hiveCount\":" + std::to_wstring(result.Hives.size());
    out += L",\"getCellOffset\":" + std::to_wstring(result.GetCellOffset);
    out += L",\"hiveListOffset\":" + std::to_wstring(result.HiveListOffset);
    out += L",\"warnings\":[";
    for (size_t i = 0; i < result.Warnings.size(); ++i)
    {
        if (i > 0)
        {
            out += L",";
        }
        out += mcpjson::Quote(result.Warnings[i]);
    }
    out += L"],\"hives\":[";
    for (size_t i = 0; i < result.Hives.size(); ++i)
    {
        const HiveRecord& hive = result.Hives[i];
        if (i > 0)
        {
            out += L",";
        }
        out += L"{\"index\":" + std::to_wstring(hive.Index);
        out += L",\"hiveAddress\":" + mcpjson::Quote(JsonHex(hive.HiveAddress));
        out += L",\"listEntryAddress\":" + mcpjson::Quote(JsonHex(hive.ListEntryAddress));
        out += L",\"getCellRoutine\":" + mcpjson::Quote(JsonHex(hive.GetCellRoutine));
        out += L",\"getCellModule\":" + mcpjson::Quote(hive.GetCellModule);
        out += L",\"getCellSymbol\":" + mcpjson::Quote(hive.GetCellSymbol);
        out += L",\"releaseCellRoutine\":" + mcpjson::Quote(JsonHex(hive.ReleaseCellRoutine));
        out += L",\"releaseCellModule\":" + mcpjson::Quote(hive.ReleaseCellModule);
        out += L",\"suspicious\":";
        out += hive.Suspicious ? L"true" : L"false";
        out += L",\"notes\":" + mcpjson::Quote(hive.Notes);
        out += L"}";
    }
    out += L"]}";
    return out;
}
