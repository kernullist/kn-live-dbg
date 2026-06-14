#include "NmiScanner.h"

#include "LayoutResolver.h"

#include <algorithm>
#include <sstream>

namespace
{
    constexpr uint64_t kKernelSpaceMin    = 0xffff800000000000ull;
    constexpr uint32_t kMaxNmiCallbacks   = 256;
    constexpr uint32_t kMaxRawBytesPerRead = 0x100;

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelSpaceMin;
    }

    bool TryAdd(uint64_t left, uint64_t right, uint64_t* result)
    {
        bool ok = false;

        do
        {
            if (result == nullptr)
            {
                break;
            }
            if (left > (~0ull - right))
            {
                break;
            }
            *result = left + right;
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadKernelBytes(
        DeviceClient& device,
        uint64_t address,
        uint32_t length,
        std::vector<uint8_t>* bytes,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (bytes == nullptr || length == 0 || length > kMaxRawBytesPerRead)
            {
                if (error != nullptr)
                {
                    *error = L"invalid read request";
                }
                break;
            }
            if (!device.ReadMemory(address, length, bytes, error))
            {
                break;
            }
            if (bytes->size() != length)
            {
                if (error != nullptr)
                {
                    *error = L"short kernel read";
                }
                break;
            }
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadU64(DeviceClient& device, uint64_t address, uint64_t* value, std::wstring* error)
    {
        bool ok = false;
        do
        {
            if (value == nullptr)
            {
                break;
            }
            std::vector<uint8_t> bytes;
            if (!ReadKernelBytes(device, address, sizeof(uint64_t), &bytes, error))
            {
                break;
            }
            memcpy(value, bytes.data(), sizeof(uint64_t));
            ok = true;
        } while (false);
        return ok;
    }

    void AnnotateAddress(
        SymbolEngine& symbols,
        uint64_t address,
        std::wstring* moduleName,
        std::wstring* symbolName)
    {
        if (moduleName != nullptr)
        {
            moduleName->clear();
        }
        if (symbolName != nullptr)
        {
            symbolName->clear();
        }

        do
        {
            if (address == 0 || !IsKernelAddress(address))
            {
                break;
            }

            for (const KernelModuleInfo& module : symbols.Modules())
            {
                uint64_t end = module.Base + module.Size;
                if (end < module.Base)
                {
                    continue;
                }
                if (address >= module.Base && address < end)
                {
                    if (moduleName != nullptr)
                    {
                        *moduleName = module.ImageName;
                    }
                    break;
                }
            }

            std::wstring nearest;
            uint64_t displacement = 0;
            std::wstring ignored;
            if (symbols.FindNearestSymbol(address, &nearest, &displacement, &ignored))
            {
                if (symbolName != nullptr)
                {
                    std::wstringstream stream;
                    stream << nearest;
                    if (displacement != 0)
                    {
                        stream << L"+0x" << std::hex << displacement;
                    }
                    *symbolName = stream.str();
                }
            }
        } while (false);
    }

    bool AddressInLoadedModule(SymbolEngine& symbols, uint64_t address)
    {
        bool inside = false;
        for (const KernelModuleInfo& module : symbols.Modules())
        {
            uint64_t end = module.Base + module.Size;
            if (end < module.Base)
            {
                continue;
            }
            if (address >= module.Base && address < end)
            {
                inside = true;
                break;
            }
        }
        return inside;
    }

    bool ResolveNmiListHead(
        SymbolEngine& symbols,
        uint64_t* address,
        std::wstring* matched)
    {
        bool ok = false;

        do
        {
            if (address == nullptr || matched == nullptr)
            {
                break;
            }

            const std::wstring candidates[] =
            {
                L"nt!KiNmiCallbackListHead",
                L"nt!KiNmiCallbackList"
            };

            for (const std::wstring& name : candidates)
            {
                std::wstring ignored;
                if (symbols.ResolveSymbol(name, address, &ignored))
                {
                    *matched = name;
                    ok = true;
                    break;
                }
            }
        } while (false);

        return ok;
    }
}

NmiScanner::NmiScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool NmiScanner::Scan(NmiScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid scan result output";
            }
            break;
        }

        *result = NmiScanResult{};

        uint64_t listHead = 0;
        std::wstring listSymbol;
        if (!ResolveNmiListHead(symbols_, &listHead, &listSymbol))
        {
            if (error != nullptr)
            {
                *error = L"NMI callback list head symbol not resolved (tried nt!KiNmiCallbackListHead and nt!KiNmiCallbackList)";
            }
            break;
        }

        result->ListHeadAddress = listHead;
        result->ListHeadSymbol = listSymbol;
        result->ListHeadResolved = true;

        uint64_t firstNode = 0;
        std::wstring readError;
        if (!ReadU64(device_, listHead, &firstNode, &readError))
        {
            if (error != nullptr)
            {
                *error = L"failed to read NMI list head: " + readError;
            }
            break;
        }

        result->FirstNodeAddress = firstNode;

        // Resolve the KNMI_HANDLER_CALLBACK node layout. Public nt PDBs almost
        // never expose this internal type, so the guarded fallback offsets
        // (Next/Callback/Context/Handle = 0x00/0x08/0x10/0x18) are the normal
        // path; emit a single warning when any field falls back so layout
        // drift on a future build becomes visible instead of silent.
        ResolvedFieldOffset nextField     = ResolveFieldOffset(symbols_, L"nt!_KNMI_HANDLER_CALLBACK", L"Next",     0x00);
        ResolvedFieldOffset callbackField = ResolveFieldOffset(symbols_, L"nt!_KNMI_HANDLER_CALLBACK", L"Callback", 0x08);
        ResolvedFieldOffset contextField  = ResolveFieldOffset(symbols_, L"nt!_KNMI_HANDLER_CALLBACK", L"Context",  0x10);
        ResolvedFieldOffset handleField   = ResolveFieldOffset(symbols_, L"nt!_KNMI_HANDLER_CALLBACK", L"Handle",   0x18);

        // Keep per-node reads bounded: a resolved offset must leave room for a
        // full pointer inside the read window. Revert any implausible offset to
        // its known-good fallback so a mismatched PDB type cannot push a read
        // out of bounds.
        struct FieldFallback { ResolvedFieldOffset* field; uint32_t fallback; };
        const FieldFallback fieldFallbacks[] =
        {
            { &nextField, 0x00 },
            { &callbackField, 0x08 },
            { &contextField, 0x10 },
            { &handleField, 0x18 }
        };
        for (const FieldFallback& entry : fieldFallbacks)
        {
            if (static_cast<uint64_t>(entry.field->Offset) + sizeof(uint64_t) > kMaxRawBytesPerRead)
            {
                entry.field->Offset = entry.fallback;
                entry.field->FromPdb = false;
                entry.field->UsedFallback = true;
            }
        }

        if (nextField.UsedFallback || callbackField.UsedFallback ||
            contextField.UsedFallback || handleField.UsedFallback)
        {
            result->Warnings.push_back(
                L"KNMI_HANDLER_CALLBACK layout resolved from guarded fallback offsets "
                L"(PDB lacks the type); node fields may drift on future Windows builds");
        }

        uint32_t nodeReadSize = 0x20;
        for (const FieldFallback& entry : fieldFallbacks)
        {
            uint32_t needed = entry.field->Offset + static_cast<uint32_t>(sizeof(uint64_t));
            if (needed > nodeReadSize)
            {
                nodeReadSize = needed;
            }
        }
        if (nodeReadSize > kMaxRawBytesPerRead)
        {
            nodeReadSize = kMaxRawBytesPerRead;
        }

        uint64_t current = firstNode;
        std::vector<uint64_t> visited;
        visited.reserve(16);

        while (current != 0 && visited.size() < kMaxNmiCallbacks)
        {
            if (!IsKernelAddress(current))
            {
                result->Warnings.push_back(L"NMI callback node pointer not in kernel canonical range");
                break;
            }

            if (std::find(visited.begin(), visited.end(), current) != visited.end())
            {
                result->Warnings.push_back(L"NMI callback list cycle detected");
                break;
            }
            visited.push_back(current);

            std::vector<uint8_t> nodeBytes;
            if (!ReadKernelBytes(device_, current, nodeReadSize, &nodeBytes, nullptr))
            {
                result->Warnings.push_back(L"failed to read NMI callback node at " + std::to_wstring(current));
                break;
            }

            uint64_t next = 0;
            uint64_t callback = 0;
            uint64_t context = 0;
            uint64_t handle = 0;
            memcpy(&next,     nodeBytes.data() + nextField.Offset,     sizeof(uint64_t));
            memcpy(&callback, nodeBytes.data() + callbackField.Offset, sizeof(uint64_t));
            memcpy(&context,  nodeBytes.data() + contextField.Offset,  sizeof(uint64_t));
            memcpy(&handle,   nodeBytes.data() + handleField.Offset,   sizeof(uint64_t));

            NmiCallbackRecord record = {};
            record.Slot = static_cast<uint32_t>(visited.size() - 1);
            record.NodeAddress = current;
            record.Callback = callback;
            record.Context = context;
            record.Handle = handle;

            if (callback != 0 && IsKernelAddress(callback))
            {
                AnnotateAddress(symbols_, callback, &record.CallbackModule, &record.CallbackSymbol);
                if (!AddressInLoadedModule(symbols_, callback))
                {
                    record.Suspicious = true;
                    record.Notes = L"callback target outside loaded kernel modules";
                }
            }
            else if (callback != 0)
            {
                record.Suspicious = true;
                record.Notes = L"callback pointer not in kernel canonical range";
            }

            result->Callbacks.push_back(std::move(record));

            current = next;
        }

        ok = true;
    } while (false);

    return ok;
}
