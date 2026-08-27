#include "HalDispatchScanner.h"

#include "McpJson.h"

#include <algorithm>
#include <cstring>
#include <cstdio>
#include <sstream>

namespace
{
    constexpr uint64_t kKernelSpaceMin = 0xffff800000000000ull;
    constexpr uint32_t kMaxDispatchSlots = 128;

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

    const KernelModuleInfo* FindOwningModule(SymbolEngine& symbols, uint64_t address)
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
                return &module;
            }
        }
        return nullptr;
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

    bool PathLooksLikeInboxKernel(const std::wstring& path)
    {
        if (path.empty() || path.find_last_of(L"\\/") == std::wstring::npos)
        {
            return true;
        }

        std::wstring lower = path;
        for (wchar_t& ch : lower)
        {
            if (ch >= L'A' && ch <= L'Z')
            {
                ch = static_cast<wchar_t>(ch - L'A' + L'a');
            }
        }
        return lower.find(L"\\system32\\") != std::wstring::npos ||
            lower.find(L"/system32/") != std::wstring::npos ||
            lower.find(L"system32\\") == 0 ||
            lower.find(L"system32/") == 0;
    }

    bool ModuleLooksLikeNtOrHal(const std::wstring& imageName, const std::wstring& imagePath = std::wstring())
    {
        if (imageName.empty() && imagePath.empty())
        {
            return false;
        }

        std::wstring lower = imageName.empty() ? imagePath : imageName;
        for (wchar_t& ch : lower)
        {
            if (ch >= L'A' && ch <= L'Z')
            {
                ch = static_cast<wchar_t>(ch - L'A' + L'a');
            }
        }
        const size_t slash = lower.find_last_of(L"\\/");
        if (slash != std::wstring::npos && slash + 1 < lower.size())
        {
            lower = lower.substr(slash + 1);
        }

        const bool inboxName =
            lower == L"ntoskrnl.exe" ||
            lower == L"ntkrnlmp.exe" ||
            lower == L"ntkrnlpa.exe" ||
            lower == L"ntkrnlup.exe" ||
            lower == L"hal.dll" ||
            lower == L"hal.sys" ||
            lower == L"halaacpi.dll" ||
            lower == L"halacpi.dll" ||
            lower == L"halmacpi.dll" ||
            lower == L"pci.sys" ||
            lower == L"acpi.sys" ||
            lower == L"pciide.sys" ||
            lower == L"pciidex.sys";
        if (!inboxName)
        {
            return false;
        }

        const std::wstring& pathForCheck = imagePath.empty() ? imageName : imagePath;
        return PathLooksLikeInboxKernel(pathForCheck);
    }

    bool ResolveTablePointerFields(
        SymbolEngine& symbols,
        const std::vector<std::wstring>& typeNames,
        std::vector<TypeFieldInfo>* fields,
        std::wstring* resolvedType,
        std::wstring* error)
    {
        if (fields == nullptr)
        {
            return false;
        }
        fields->clear();

        std::wstring lastError;
        for (const std::wstring& typeName : typeNames)
        {
            TypeLayoutInfo layout = {};
            std::wstring layoutError;
            if (!symbols.GetTypeLayout(typeName, &layout, &layoutError))
            {
                if (!layoutError.empty())
                {
                    lastError = layoutError;
                }
                continue;
            }

            for (const TypeFieldInfo& field : layout.Fields)
            {
                if (field.IsBitField ||
                    field.ChildTag != KNDBG_SYMTAG_POINTER_TYPE ||
                    field.Length != sizeof(uint64_t) ||
                    static_cast<uint64_t>(field.Offset) + sizeof(uint64_t) > layout.Size)
                {
                    continue;
                }
                fields->push_back(field);
            }

            if (!fields->empty())
            {
                std::sort(
                    fields->begin(),
                    fields->end(),
                    [](const TypeFieldInfo& left, const TypeFieldInfo& right)
                    {
                        return left.Offset < right.Offset;
                    });
                if (resolvedType != nullptr)
                {
                    *resolvedType = typeName;
                }
                return true;
            }
            lastError = typeName + L" contains no pointer fields";
        }

        if (error != nullptr)
        {
            *error = lastError.empty()
                ? L"no HAL dispatch type layout resolved"
                : lastError;
        }
        return false;
    }

    bool ScanOneTable(
        DeviceClient& device,
        SymbolEngine& symbols,
        const std::wstring& symbolName,
        const std::wstring& displayName,
        const std::vector<std::wstring>& typeNames,
        uint32_t requestedLimit,
        HalDispatchTable* table,
        std::vector<std::wstring>* warnings)
    {
        bool ok = false;

        do
        {
            if (table == nullptr)
            {
                break;
            }

            *table = HalDispatchTable{};
            table->Name = displayName;
            table->Symbol = symbolName;

            uint64_t base = 0;
            std::wstring resolveError;
            if (!symbols.ResolveSymbol(symbolName, &base, &resolveError) || base == 0)
            {
                table->Warning = L"symbol not resolved: " + symbolName;
                if (warnings != nullptr && !resolveError.empty())
                {
                    warnings->push_back(symbolName + L": " + resolveError);
                }
                break;
            }

            if (!IsKernelAddress(base))
            {
                table->Warning = L"table base is not a kernel-canonical address";
                break;
            }

            table->Base = base;
            table->Resolved = true;

            std::vector<TypeFieldInfo> pointerFields;
            std::wstring resolvedType;
            std::wstring layoutError;
            if (!ResolveTablePointerFields(
                    symbols,
                    typeNames,
                    &pointerFields,
                    &resolvedType,
                    &layoutError))
            {
                table->Warning =
                    L"PDB pointer-field layout unavailable; raw qword scanning disabled";
                if (warnings != nullptr)
                {
                    warnings->push_back(symbolName + L": " + table->Warning +
                        (layoutError.empty() ? std::wstring() : L" (" + layoutError + L")"));
                }
                ok = true;
                break;
            }

            table->BoundFromPdb = true;
            table->CoverageComplete = true;
            if (warnings != nullptr && !resolvedType.empty())
            {
                warnings->push_back(
                    symbolName + L": pointer fields from " + resolvedType);
            }
            uint32_t fieldLimit = static_cast<uint32_t>(pointerFields.size());
            if (fieldLimit > kMaxDispatchSlots)
            {
                fieldLimit = kMaxDispatchSlots;
                table->CoverageComplete = false;
                table->Warning = L"PDB pointer-field count exceeds safety limit";
            }
            if (requestedLimit != 0 && fieldLimit > requestedLimit)
            {
                fieldLimit = requestedLimit;
                table->CoverageComplete = false;
                table->Warning = L"operator limit truncated HAL dispatch coverage";
            }
            table->SlotCount = fieldLimit;

            for (uint32_t index = 0; index < fieldLimit; ++index)
            {
                const TypeFieldInfo& field = pointerFields[index];
                HalDispatchSlot slot = {};
                slot.Index = index;
                slot.Name = field.Name;
                slot.SlotAddress = base + field.Offset;

                uint64_t routine = 0;
                if (!ReadU64(device, slot.SlotAddress, &routine))
                {
                    slot.Notes = L"slot read failed";
                    table->CoverageComplete = false;
                    table->Slots.push_back(slot);
                    continue;
                }

                slot.Routine = routine;
                if (routine == 0)
                {
                    slot.NullSlot = true;
                    table->Slots.push_back(slot);
                    continue;
                }

                ++table->NonNullCount;
                const KernelModuleInfo* owner = FindOwningModule(symbols, routine);
                slot.Module = owner != nullptr ? owner->ImageName : std::wstring();
                slot.Symbol = NearestSymbolText(symbols, routine);

                if (!IsKernelAddress(routine) || slot.Module.empty() || owner == nullptr)
                {
                    slot.Suspicious = true;
                    slot.Notes = L"HAL dispatch routine outside loaded kernel modules";
                    ++table->SuspiciousCount;
                }
                else if (!ModuleLooksLikeNtOrHal(owner->ImageName, owner->ImagePath))
                {
                    slot.Suspicious = true;
                    slot.Notes =
                        L"HAL dispatch routine owned by unexpected module (" +
                        slot.Module + L")";
                    ++table->SuspiciousCount;
                }

                table->Slots.push_back(slot);
            }

            ok = true;
        } while (false);

        return ok;
    }

    std::wstring JsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }
}

HalDispatchScanner::HalDispatchScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool HalDispatchScanner::Scan(const Options& options, HalDispatchScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid HAL scan result output";
            }
            break;
        }

        *result = HalDispatchScanResult{};
        result->CoverageComplete = true;

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

        struct Target
        {
            std::wstring Symbol;
            std::wstring Name;
            std::vector<std::wstring> TypeNames;
            bool Optional = false;
        };

        std::vector<Target> targets;
        if (options.Target == Scope::All || options.Target == Scope::Dispatch)
        {
            Target target = {};
            target.Symbol = L"nt!HalDispatchTable";
            target.Name = L"HalDispatchTable";
            target.TypeNames = {L"nt!_HAL_DISPATCH"};
            target.Optional = false;
            targets.push_back(target);
        }
        if (options.Target == Scope::All || options.Target == Scope::Private)
        {
            Target target = {};
            target.Symbol = L"nt!HalPrivateDispatchTable";
            target.Name = L"HalPrivateDispatchTable";
            target.TypeNames =
            {
                L"nt!_HAL_PRIVATE_DISPATCH",
                L"nt!_HAL_PRIVATE_DISPATCH_TABLE"
            };
            target.Optional = true;
            targets.push_back(target);
        }

        for (const Target& target : targets)
        {
            HalDispatchTable table = {};
            const bool scanned = ScanOneTable(
                device_,
                symbols_,
                target.Symbol,
                target.Name,
                target.TypeNames,
                options.Limit,
                &table,
                &result->Warnings);

            if (!scanned || !table.Resolved)
            {
                if (!target.Optional)
                {
                    if (error != nullptr)
                    {
                        *error = table.Warning.empty()
                            ? (L"failed to scan " + target.Symbol)
                            : table.Warning;
                    }
                    result->Tables.push_back(table);
                    break;
                }

                result->CoverageComplete = false;
                if (!table.Warning.empty())
                {
                    result->Warnings.push_back(table.Warning);
                }
                result->Tables.push_back(table);
                continue;
            }

            result->SuspiciousCount += table.SuspiciousCount;
            if (!table.CoverageComplete)
            {
                result->CoverageComplete = false;
            }
            if (table.SuspiciousCount > 0)
            {
                result->AnySuspicious = true;
            }
            result->Tables.push_back(table);
        }

        if (result->Tables.empty())
        {
            if (error != nullptr)
            {
                *error = L"no HAL dispatch table could be scanned";
            }
            break;
        }

        // Required table(s) must resolve for overall success.
        bool requiredOk = false;
        if (options.Target == Scope::Private)
        {
            for (const HalDispatchTable& table : result->Tables)
            {
                if (table.Name == L"HalPrivateDispatchTable" && table.Resolved)
                {
                    requiredOk = true;
                    break;
                }
            }
            if (!requiredOk)
            {
                if (error != nullptr)
                {
                    *error = L"nt!HalPrivateDispatchTable could not be resolved";
                }
                break;
            }
        }
        else
        {
            for (const HalDispatchTable& table : result->Tables)
            {
                if (table.Name == L"HalDispatchTable" && table.Resolved)
                {
                    requiredOk = true;
                    break;
                }
            }
            if (!requiredOk)
            {
                if (error != nullptr)
                {
                    *error = L"nt!HalDispatchTable could not be resolved";
                }
                break;
            }
        }

        ok = true;
    } while (false);

    return ok;
}

std::wstring BuildHalDispatchJson(const HalDispatchScanResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.hal.v1\",\"anySuspicious\":";
    out += result.AnySuspicious ? L"true" : L"false";
    out += L",\"suspiciousCount\":" + std::to_wstring(result.SuspiciousCount);
    out += L",\"coverageComplete\":";
    out += result.CoverageComplete ? L"true" : L"false";
    out += L",\"tableCount\":" + std::to_wstring(result.Tables.size());
    out += L",\"warnings\":[";
    for (size_t i = 0; i < result.Warnings.size(); ++i)
    {
        if (i > 0)
        {
            out += L",";
        }
        out += mcpjson::Quote(result.Warnings[i]);
    }
    out += L"],\"tables\":[";

    for (size_t tableIndex = 0; tableIndex < result.Tables.size(); ++tableIndex)
    {
        const HalDispatchTable& table = result.Tables[tableIndex];
        if (tableIndex > 0)
        {
            out += L",";
        }
        out += L"{\"name\":" + mcpjson::Quote(table.Name);
        out += L",\"symbol\":" + mcpjson::Quote(table.Symbol);
        out += L",\"resolved\":";
        out += table.Resolved ? L"true" : L"false";
        out += L",\"boundFromPdb\":";
        out += table.BoundFromPdb ? L"true" : L"false";
        out += L",\"coverageComplete\":";
        out += table.CoverageComplete ? L"true" : L"false";
        out += L",\"base\":" + mcpjson::Quote(JsonHex(table.Base));
        out += L",\"slotCount\":" + std::to_wstring(table.SlotCount);
        out += L",\"nonNullCount\":" + std::to_wstring(table.NonNullCount);
        out += L",\"suspiciousCount\":" + std::to_wstring(table.SuspiciousCount);
        out += L",\"warning\":" + mcpjson::Quote(table.Warning);
        out += L",\"slots\":[";

        bool firstSlot = true;
        for (const HalDispatchSlot& slot : table.Slots)
        {
            if (!slot.Suspicious && !slot.NullSlot && slot.Notes.empty())
            {
                // Keep JSON compact: emit non-null slots always for forensics.
            }
            if (!firstSlot)
            {
                out += L",";
            }
            firstSlot = false;
            out += L"{\"index\":" + std::to_wstring(slot.Index);
            out += L",\"name\":" + mcpjson::Quote(slot.Name);
            out += L",\"slotAddress\":" + mcpjson::Quote(JsonHex(slot.SlotAddress));
            out += L",\"routine\":" + mcpjson::Quote(JsonHex(slot.Routine));
            out += L",\"nullSlot\":";
            out += slot.NullSlot ? L"true" : L"false";
            out += L",\"suspicious\":";
            out += slot.Suspicious ? L"true" : L"false";
            out += L",\"module\":" + mcpjson::Quote(slot.Module);
            out += L",\"symbol\":" + mcpjson::Quote(slot.Symbol);
            out += L",\"notes\":" + mcpjson::Quote(slot.Notes);
            out += L"}";
        }
        out += L"]}";
    }

    out += L"]}";
    return out;
}

bool HalDispatchOwnershipSelfTest()
{
    return ModuleLooksLikeNtOrHal(L"pci.sys") &&
        ModuleLooksLikeNtOrHal(L"ACPI.sys") &&
        ModuleLooksLikeNtOrHal(L"pciide.sys") &&
        ModuleLooksLikeNtOrHal(L"ntoskrnl.exe") &&
        ModuleLooksLikeNtOrHal(L"hal.dll") &&
        ModuleLooksLikeNtOrHal(L"halaacpi.dll") &&
        ModuleLooksLikeNtOrHal(L"pci.sys", L"\\SystemRoot\\System32\\drivers\\pci.sys") &&
        ModuleLooksLikeNtOrHal(L"pci.sys", L"System32\\drivers\\pci.sys") &&
        !ModuleLooksLikeNtOrHal(L"pci.sys", L"C:\\Temp\\pci.sys") &&
        !ModuleLooksLikeNtOrHal(L"pci.sys", L"\\SystemRoot\\Temp\\pci.sys") &&
        !ModuleLooksLikeNtOrHal(L"halaware.sys") &&
        !ModuleLooksLikeNtOrHal(L"hal.evil.sys") &&
        !ModuleLooksLikeNtOrHal(L"ntoskrnl_hook.sys") &&
        !ModuleLooksLikeNtOrHal(L"capcom.sys") &&
        !ModuleLooksLikeNtOrHal(L"notahalaware.sys") &&
        !ModuleLooksLikeNtOrHal(L"");
}
