#include "NmiScanner.h"

#include "LayoutResolver.h"
#include "McpJson.h"

#include <algorithm>
#include <cstdio>
#include <map>
#include <sstream>

namespace
{
    constexpr uint64_t kKernelSpaceMin    = 0xffff800000000000ull;
    constexpr uint32_t kMaxNmiCallbacks   = 256;
    constexpr uint32_t kMaxRawBytesPerRead = 0x100;

    bool NmiFieldShapeKnown(const TypeLayoutInfo& layout, const TypeFieldInfo& field, uint32_t offset)
    {
        return layout.Size != 0 && layout.Size <= kMaxRawBytesPerRead && !field.IsBitField &&
            field.Length == 8 && field.Offset == offset && field.Offset <= layout.Size &&
            8 <= layout.Size - field.Offset;
    }

    template<typename Reader>
    bool CaptureNmiWindow(Reader& read, uint64_t head, uint32_t size,
        uint32_t nextOffset, uint32_t callbackOffset, uint32_t contextOffset, uint32_t handleOffset,
        std::vector<NmiCallbackRecord>* records, bool* complete)
    {
        records->clear();
        *complete = false;
        std::vector<uint8_t> headBefore;
        if (size == 0 || size > kMaxRawBytesPerRead ||
            !read(head, 8, &headBefore) || headBefore.size() != 8)
        {
            return false;
        }
        const uint32_t offsets[] = {nextOffset, callbackOffset, contextOffset, handleOffset};
        for (uint32_t offset : offsets)
        {
            if (offset > size || 8 > size - offset)
            {
                return false;
            }
        }
        uint64_t current = 0;
        memcpy(&current, headBefore.data(), 8);
        std::vector<std::pair<uint64_t, std::vector<uint8_t>>> captured;
        while (current != 0 && captured.size() < kMaxNmiCallbacks)
        {
            if (current < kKernelSpaceMin || current > ~0ull - size || (current & 7) != 0 ||
                std::any_of(captured.begin(), captured.end(), [&](const auto& item)
                {
                    return item.first == current;
                }))
            {
                break;
            }
            std::vector<uint8_t> bytes;
            if (!read(current, size, &bytes) || bytes.size() != size)
            {
                break;
            }
            NmiCallbackRecord record;
            record.NodeAddress = current;
            record.Slot = static_cast<uint32_t>(records->size());
            memcpy(&record.Callback, bytes.data() + callbackOffset, 8);
            memcpy(&record.Context, bytes.data() + contextOffset, 8);
            memcpy(&record.Handle, bytes.data() + handleOffset, 8);
            captured.emplace_back(current, bytes);
            records->push_back(record);
            memcpy(&current, bytes.data() + nextOffset, 8);
        }
        std::vector<uint8_t> after;
        for (const auto& item : captured)
        {
            if (!read(item.first, size, &after) || after != item.second)
            {
                records->clear();
                return false;
            }
        }
        if (!read(head, 8, &after) || after != headBefore)
        {
            records->clear();
            return false;
        }
        *complete = current == 0;
        return true;
    }

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
        if (symbols_.CopyModules().empty())
        {
            std::wstring moduleError;
            if (!symbols_.LoadKernelModules(&moduleError) || symbols_.CopyModules().empty())
            {
                result->Incomplete = true;
                if (error != nullptr)
                {
                    *error = L"NMI callback ownership requires a kernel module inventory: " + moduleError;
                }
                break;
            }
        }

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

        TypeLayoutInfo nodeLayout;
        bool layoutKnown = symbols_.GetTypeLayout(L"nt!_KNMI_HANDLER_CALLBACK", &nodeLayout, nullptr);
        const wchar_t* names[] = {L"Next", L"Callback", L"Context", L"Handle"};
        for (size_t index = 0; index < ARRAYSIZE(names); ++index)
        {
            TypeFieldInfo field;
            layoutKnown = symbols_.FindField(L"nt!_KNMI_HANDLER_CALLBACK", names[index], &field, nullptr) &&
                NmiFieldShapeKnown(nodeLayout, field, fieldFallbacks[index].field->Offset) && layoutKnown;
            for (size_t prior = 0; prior < index; ++prior)
            {
                const uint32_t left = fieldFallbacks[prior].field->Offset;
                const uint32_t right = fieldFallbacks[index].field->Offset;
                layoutKnown = layoutKnown && (left + 8 <= right || right + 8 <= left);
            }
        }
        result->LayoutFromPdb = layoutKnown;
        result->Incomplete = !layoutKnown;
        auto read = [&](uint64_t address, uint32_t bytes, std::vector<uint8_t>* output)
        {
            return IsKernelAddress(address) && address <= ~0ull - bytes &&
                ReadKernelBytes(device_, address, bytes, output, nullptr);
        };
        bool complete = false;
        if (!CaptureNmiWindow(read, listHead, nodeReadSize, nextField.Offset, callbackField.Offset,
                contextField.Offset, handleField.Offset, &result->Callbacks, &complete))
        {
            result->Incomplete = true;
            result->Warnings.push_back(L"NMI callback window changed or could not be revalidated");
        }
        result->FirstNodeAddress = result->Callbacks.empty() ? 0 : result->Callbacks.front().NodeAddress;
        for (NmiCallbackRecord& record : result->Callbacks)
        {
            if (!layoutKnown)
            {
                record.Notes = L"unverified NMI layout diagnostic; callback role is unknown";
                continue;
            }
            if (record.Callback != 0 && IsKernelAddress(record.Callback))
            {
                AnnotateAddress(symbols_, record.Callback, &record.CallbackModule, &record.CallbackSymbol);
                record.Suspicious = !AddressInLoadedModule(symbols_, record.Callback);
                if (record.Suspicious)
                {
                    record.Notes = L"observed callback target outside loaded kernel modules";
                }
            }
            else if (record.Callback != 0)
            {
                record.Suspicious = true;
                record.Notes = L"observed callback pointer outside kernel canonical range";
            }
        }
        if (!complete)
        {
            result->Incomplete = true;
            result->Warnings.push_back(L"NMI callback window did not reach the list terminator; coverage is partial");
        }
        result->Warnings.push_back(L"equal NMI snapshots do not reference registration lifetime or exclude address reuse");

        ok = true;
    } while (false);

    return ok;
}

namespace
{
    std::wstring NmiJsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }
}

std::wstring BuildNmiJson(const NmiScanResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.nmi.v1\",\"count\":";
    out += std::to_wstring(result.Callbacks.size());
    out += L",\"listHeadAddress\":" + mcpjson::Quote(NmiJsonHex(result.ListHeadAddress));
    if (!result.ListHeadSymbol.empty())
    {
        out += L",\"listHeadSymbol\":" + mcpjson::Quote(result.ListHeadSymbol);
    }
    out += L",\"listHeadResolved\":";
    out += result.ListHeadResolved ? L"true" : L"false";
    out += L",\"incomplete\":";
    out += result.Incomplete ? L"true" : L"false";
    out += L",\"layoutFromPdb\":";
    out += result.LayoutFromPdb ? L"true" : L"false";
    if (result.FirstNodeAddress != 0)
    {
        out += L",\"firstNodeAddress\":" + mcpjson::Quote(NmiJsonHex(result.FirstNodeAddress));
    }
    out += L",\"records\":[";

    for (size_t index = 0; index < result.Callbacks.size(); ++index)
    {
        const NmiCallbackRecord& record = result.Callbacks[index];
        if (index > 0)
        {
            out += L",";
        }

        out += L"{\"slot\":" + std::to_wstring(record.Slot);
        out += L",\"nodeAddress\":" + mcpjson::Quote(NmiJsonHex(record.NodeAddress));
        out += L",\"callback\":" + mcpjson::Quote(NmiJsonHex(record.Callback));
        if (record.Context != 0)
        {
            out += L",\"context\":" + mcpjson::Quote(NmiJsonHex(record.Context));
        }
        if (record.Handle != 0)
        {
            out += L",\"handle\":" + mcpjson::Quote(NmiJsonHex(record.Handle));
        }
        if (!record.CallbackModule.empty())
        {
            out += L",\"callbackModule\":" + mcpjson::Quote(record.CallbackModule);
        }
        if (!record.CallbackSymbol.empty())
        {
            out += L",\"callbackSymbol\":" + mcpjson::Quote(record.CallbackSymbol);
        }
        if (!record.Notes.empty())
        {
            out += L",\"notes\":" + mcpjson::Quote(record.Notes);
        }
        out += L",\"suspicious\":";
        out += record.Suspicious ? L"true" : L"false";
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

bool NmiScannerSelfTest()
{
    TypeLayoutInfo layout;
    layout.Size = 32;
    TypeFieldInfo field;
    field.Offset = 8;
    field.Length = 8;
    if (!NmiFieldShapeKnown(layout, field, 8))
    {
        return false;
    }
    field.Length = 4;
    if (NmiFieldShapeKnown(layout, field, 8))
    {
        return false;
    }
    field.Length = 8;
    field.IsBitField = true;
    if (NmiFieldShapeKnown(layout, field, 8))
    {
        return false;
    }
    field.IsBitField = false;
    layout.Size = 12;
    if (NmiFieldShapeKnown(layout, field, 8))
    {
        return false;
    }
    const uint64_t head = 0xffff800020000000ull;
    const uint64_t node = head + 0x1000;
    std::map<uint64_t, std::vector<uint8_t>> memory;
    memory[head].resize(8);
    memcpy(memory[head].data(), &node, 8);
    memory[node].resize(32);
    const uint64_t callback = head + 0x9000;
    memcpy(memory[node].data() + 8, &callback, 8);
    auto read = [&](uint64_t address, uint32_t bytes, std::vector<uint8_t>* data)
    {
        const auto found = memory.find(address);
        if (found == memory.end() || found->second.size() != bytes)
        {
            return false;
        }
        *data = found->second;
        return true;
    };
    std::vector<NmiCallbackRecord> records;
    bool complete = false;
    if (!CaptureNmiWindow(read, head, 32, 0, 8, 16, 24, &records, &complete) ||
        !complete || records.size() != 1 || records.front().Callback != callback)
    {
        return false;
    }
    size_t reads = 0;
    auto unlink = [&](uint64_t address, uint32_t bytes, std::vector<uint8_t>* data)
    {
        if (!read(address, bytes, data))
        {
            return false;
        }
        if (address == head && ++reads == 2)
        {
            data->assign(8, 0);
        }
        return true;
    };
    if (CaptureNmiWindow(unlink, head, 32, 0, 8, 16, 24, &records, &complete) || !records.empty())
    {
        return false;
    }
    reads = 0;
    auto changed = [&](uint64_t address, uint32_t bytes, std::vector<uint8_t>* data)
    {
        if (!read(address, bytes, data))
        {
            return false;
        }
        if (address == node && ++reads == 2)
        {
            (*data)[8] ^= 1;
        }
        return true;
    };
    return !CaptureNmiWindow(changed, head, 32, 0, 8, 16, 24, &records, &complete) && records.empty();
}
