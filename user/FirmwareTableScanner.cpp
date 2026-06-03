#include "FirmwareTableScanner.h"

#include <algorithm>
#include <cwctype>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>

namespace
{
    constexpr uint64_t kKernelSpaceMin = 0xff00000000000000ull;
    constexpr uint32_t kMaxFirmwareProviders = 512;
    constexpr uint32_t kMaxRawBytesPerRead = 0x100;
    constexpr uint32_t kFirmwareProviderNodeSize = 0x28;
    constexpr uint32_t kFirmwareProviderLinkOffset = 0x00;
    constexpr uint32_t kFirmwareProviderSignatureOffset = 0x10;
    constexpr uint32_t kFirmwareProviderRegisterOffset = 0x14;
    constexpr uint32_t kFirmwareProviderHandlerOffset = 0x18;
    constexpr uint32_t kFirmwareProviderDriverObjectOffset = 0x20;

    struct FirmwareProviderLayout
    {
        std::wstring TypeName;
        uint32_t NodeSize = kFirmwareProviderNodeSize;
        uint32_t LinkOffset = kFirmwareProviderLinkOffset;
        uint32_t ProviderSignatureOffset = kFirmwareProviderSignatureOffset;
        uint32_t RegisterOffset = kFirmwareProviderRegisterOffset;
        uint32_t HandlerOffset = kFirmwareProviderHandlerOffset;
        uint32_t DriverObjectOffset = kFirmwareProviderDriverObjectOffset;
        bool FromPdb = false;
    };

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

    bool TrySub(uint64_t left, uint64_t right, uint64_t* result)
    {
        bool ok = false;

        do
        {
            if (result == nullptr)
            {
                break;
            }

            if (left < right)
            {
                break;
            }

            *result = left - right;
            ok = true;
        } while (false);

        return ok;
    }

    bool TryRangeEnd(uint64_t base, uint64_t size, uint64_t* end)
    {
        return TryAdd(base, size, end);
    }

    bool UpdateRequiredNodeSize(uint32_t offset, uint32_t length, uint32_t* requiredSize)
    {
        bool ok = false;

        do
        {
            if (requiredSize == nullptr || length == 0)
            {
                break;
            }

            uint64_t end = 0;
            if (!TryAdd(offset, length, &end))
            {
                break;
            }

            if (end > kMaxRawBytesPerRead)
            {
                break;
            }

            if (end > *requiredSize)
            {
                *requiredSize = static_cast<uint32_t>(end);
            }

            ok = true;
        } while (false);

        return ok;
    }

    std::wstring HexText(uint64_t value, int width)
    {
        std::wstringstream stream;
        stream << L"0x" << std::hex << std::setw(width) << std::setfill(L'0') << value << std::dec;
        return stream.str();
    }

    std::wstring ToLowerCopy(const std::wstring& value)
    {
        std::wstring result = value;

        for (wchar_t& ch : result)
        {
            ch = static_cast<wchar_t>(std::towlower(ch));
        }

        return result;
    }

    std::wstring ComparableModuleName(const std::wstring& value, bool removeExtension)
    {
        std::wstring comparable;

        do
        {
            std::wstring text = value;
            while (!text.empty() && iswspace(text.front()))
            {
                text.erase(text.begin());
            }
            while (!text.empty() && iswspace(text.back()))
            {
                text.pop_back();
            }

            if (text.empty())
            {
                break;
            }

            size_t bang = text.find(L'!');
            if (bang != std::wstring::npos)
            {
                text = text.substr(0, bang);
            }

            size_t slash = text.find_last_of(L"\\/");
            if (slash != std::wstring::npos)
            {
                text = text.substr(slash + 1);
            }

            text = ToLowerCopy(text);
            if (removeExtension)
            {
                size_t dot = text.find_last_of(L'.');
                if (dot != std::wstring::npos)
                {
                    text = text.substr(0, dot);
                }
            }

            comparable = text;
        } while (false);

        return comparable;
    }

    bool ModuleNamesMatch(const std::wstring& left, const std::wstring& right)
    {
        bool matched = false;

        do
        {
            std::wstring leftBase = ComparableModuleName(left, false);
            std::wstring rightBase = ComparableModuleName(right, false);
            if (leftBase.empty() || rightBase.empty())
            {
                break;
            }

            if (leftBase == rightBase)
            {
                matched = true;
                break;
            }

            std::wstring leftStem = ComparableModuleName(left, true);
            std::wstring rightStem = ComparableModuleName(right, true);
            if (!leftStem.empty() && leftStem == rightStem)
            {
                matched = true;
                break;
            }
        } while (false);

        return matched;
    }

    void AppendNote(std::wstring* notes, const std::wstring& note)
    {
        do
        {
            if (notes == nullptr || note.empty())
            {
                break;
            }

            if (!notes->empty())
            {
                *notes += L"; ";
            }

            *notes += note;
        } while (false);
    }

    std::wstring SanitizeForConsole(const std::wstring& input)
    {
        std::wstring result;
        result.reserve(input.size());

        for (wchar_t ch : input)
        {
            if (ch == 0)
            {
                continue;
            }
            if (ch < 0x20 || ch == 0x7f)
            {
                wchar_t buffer[8] = {};
                int written = swprintf_s(buffer, L"\\x%02x", static_cast<unsigned int>(static_cast<uint16_t>(ch)));
                if (written > 0)
                {
                    result.append(buffer, static_cast<size_t>(written));
                }
                continue;
            }
            if (ch >= 0xd800 && ch <= 0xdfff)
            {
                result.push_back(L'?');
                continue;
            }

            result.push_back(ch);
        }

        return result;
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

            if (!IsKernelAddress(address))
            {
                if (error != nullptr)
                {
                    *error = L"address is not a kernel pointer";
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

    bool ReadKernelBytesChunked(
        DeviceClient& device,
        uint64_t address,
        uint32_t length,
        std::vector<uint8_t>* bytes,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (bytes == nullptr || length == 0)
            {
                if (error != nullptr)
                {
                    *error = L"invalid chunked read request";
                }
                break;
            }

            bytes->clear();
            bytes->reserve(length);

            uint32_t offset = 0;
            while (offset < length)
            {
                uint64_t chunkAddress = 0;
                if (!TryAdd(address, offset, &chunkAddress))
                {
                    if (error != nullptr)
                    {
                        *error = L"chunked read address overflow";
                    }
                    break;
                }

                uint32_t remaining = length - offset;
                uint32_t chunkLength = std::min<uint32_t>(remaining, kMaxRawBytesPerRead);
                std::vector<uint8_t> chunk;
                if (!ReadKernelBytes(device, chunkAddress, chunkLength, &chunk, error))
                {
                    break;
                }

                bytes->insert(bytes->end(), chunk.begin(), chunk.end());
                offset += chunkLength;
            }

            if (bytes->size() != length)
            {
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool ReadU16(DeviceClient& device, uint64_t address, uint16_t* value, std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                break;
            }

            std::vector<uint8_t> bytes;
            if (!ReadKernelBytes(device, address, sizeof(uint16_t), &bytes, error))
            {
                break;
            }

            memcpy(value, bytes.data(), sizeof(uint16_t));
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadU32(DeviceClient& device, uint64_t address, uint32_t* value, std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                break;
            }

            std::vector<uint8_t> bytes;
            if (!ReadKernelBytes(device, address, sizeof(uint32_t), &bytes, error))
            {
                break;
            }

            memcpy(value, bytes.data(), sizeof(uint32_t));
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

    bool ReadFieldInteger(
        DeviceClient& device,
        uint64_t base,
        const TypeFieldInfo& field,
        uint32_t fallbackWidth,
        uint64_t* value,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                break;
            }

            uint64_t address = 0;
            if (!TryAdd(base, field.Offset, &address))
            {
                if (error != nullptr)
                {
                    *error = L"field address overflow";
                }
                break;
            }

            uint32_t width = static_cast<uint32_t>(field.Length);
            if (field.ChildTag == KNDBG_SYMTAG_POINTER_TYPE)
            {
                width = sizeof(uint64_t);
            }
            if (width == 0 || width > sizeof(uint64_t))
            {
                width = fallbackWidth;
            }
            if (width == 0 || width > sizeof(uint64_t))
            {
                width = sizeof(uint64_t);
            }

            std::vector<uint8_t> bytes;
            if (!ReadKernelBytes(device, address, width, &bytes, error))
            {
                break;
            }

            uint64_t decoded = 0;
            memcpy(&decoded, bytes.data(), bytes.size());
            *value = decoded;
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadUnicodeStringAt(DeviceClient& device, uint64_t address, std::wstring* value)
    {
        bool ok = false;

        do
        {
            if (value == nullptr)
            {
                break;
            }

            value->clear();

            uint16_t length = 0;
            uint64_t buffer = 0;
            uint64_t bufferAddress = 0;
            if (!ReadU16(device, address, &length, nullptr) ||
                !TryAdd(address, 8, &bufferAddress) ||
                !ReadU64(device, bufferAddress, &buffer, nullptr))
            {
                break;
            }

            if (length == 0 || buffer == 0)
            {
                ok = true;
                break;
            }

            if (length > 2048)
            {
                length = 2048;
            }
            if ((length % sizeof(wchar_t)) != 0)
            {
                break;
            }

            std::vector<uint8_t> bytes;
            if (!ReadKernelBytesChunked(device, buffer, length, &bytes, nullptr))
            {
                break;
            }

            std::wstring decoded;
            decoded.assign(
                reinterpret_cast<const wchar_t*>(bytes.data()),
                bytes.size() / sizeof(wchar_t));
            *value = SanitizeForConsole(decoded);
            ok = true;
        } while (false);

        return ok;
    }

    const KernelModuleInfo* FindModuleForAddress(const std::vector<KernelModuleInfo>& modules, uint64_t address)
    {
        const KernelModuleInfo* found = nullptr;

        for (const KernelModuleInfo& module : modules)
        {
            uint64_t end = 0;
            if (!TryRangeEnd(module.Base, module.Size, &end))
            {
                continue;
            }
            if (address >= module.Base && address < end)
            {
                found = &module;
                break;
            }
        }

        return found;
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

            const KernelModuleInfo* module = FindModuleForAddress(symbols.Modules(), address);
            if (module != nullptr && moduleName != nullptr)
            {
                *moduleName = module->ImageName;
            }

            std::wstring nearest;
            uint64_t displacement = 0;
            std::wstring ignored;
            if (symbols.FindNearestSymbol(address, &nearest, &displacement, &ignored) &&
                symbolName != nullptr)
            {
                std::wstringstream stream;
                stream << nearest;
                if (displacement != 0)
                {
                    stream << L"+0x" << std::hex << displacement << std::dec;
                }
                *symbolName = stream.str();
            }
        } while (false);
    }

    std::wstring ProviderSignatureText(uint32_t signature)
    {
        wchar_t text[5] = {};
        bool printable = true;

        for (uint32_t index = 0; index < 4; ++index)
        {
            uint8_t ch = static_cast<uint8_t>((signature >> ((3 - index) * 8)) & 0xff);
            if (ch < 0x20 || ch > 0x7e)
            {
                printable = false;
                break;
            }
            text[index] = static_cast<wchar_t>(ch);
        }

        if (!printable)
        {
            return L"";
        }

        return text;
    }

    bool IsStandardProviderSignature(uint32_t signature)
    {
        bool standard = false;

        do
        {
            if (ProviderSignatureText(signature) == L"ACPI" ||
                ProviderSignatureText(signature) == L"FIRM" ||
                ProviderSignatureText(signature) == L"RSMB")
            {
                standard = true;
                break;
            }
        } while (false);

        return standard;
    }

    bool ResolveDriverObjectFields(
        SymbolEngine& symbols,
        TypeFieldInfo* driverStart,
        TypeFieldInfo* driverSize,
        TypeFieldInfo* driverName)
    {
        bool ok = false;

        do
        {
            if (driverStart == nullptr || driverSize == nullptr || driverName == nullptr)
            {
                break;
            }

            std::wstring ignored;
            if (!symbols.FindField(L"nt!_DRIVER_OBJECT", L"DriverStart", driverStart, &ignored))
            {
                break;
            }
            if (!symbols.FindField(L"nt!_DRIVER_OBJECT", L"DriverSize", driverSize, &ignored))
            {
                break;
            }
            if (!symbols.FindField(L"nt!_DRIVER_OBJECT", L"DriverName", driverName, &ignored))
            {
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool TryFindFieldOffset(
        SymbolEngine& symbols,
        const std::wstring& typeName,
        const std::vector<std::wstring>& names,
        uint32_t* offset)
    {
        bool ok = false;

        do
        {
            if (offset == nullptr)
            {
                break;
            }

            for (const std::wstring& name : names)
            {
                TypeFieldInfo field = {};
                std::wstring ignored;
                if (symbols.FindField(typeName, name, &field, &ignored))
                {
                    *offset = field.Offset;
                    ok = true;
                    break;
                }
            }
        } while (false);

        return ok;
    }

    FirmwareProviderLayout ResolveFirmwareProviderLayout(SymbolEngine& symbols)
    {
        FirmwareProviderLayout layout = {};

        const std::wstring candidates[] =
        {
            L"nt!_FIRMWARE_TABLE_PROVIDER",
            L"nt!_FIRMWARE_TABLE_PROVIDER_NODE",
            L"nt!_FIRMWARE_TABLE_HANDLER_NODE",
            L"nt!_SYSTEM_FIRMWARE_TABLE_HANDLER_NODE",
            L"nt!_EXP_FIRMWARE_TABLE_PROVIDER"
        };

        for (const std::wstring& typeName : candidates)
        {
            TypeLayoutInfo typeLayout = {};
            std::wstring ignored;
            if (!symbols.GetTypeLayout(typeName, &typeLayout, &ignored))
            {
                continue;
            }

            FirmwareProviderLayout candidate = {};
            candidate.TypeName = typeName;
            if (typeLayout.Size < kFirmwareProviderNodeSize)
            {
                continue;
            }
            candidate.NodeSize = static_cast<uint32_t>(std::min<ULONG64>(typeLayout.Size, kMaxRawBytesPerRead));

            if (!TryFindFieldOffset(symbols, typeName, {L"Link", L"Links", L"ListEntry", L"Entry"}, &candidate.LinkOffset) ||
                !TryFindFieldOffset(symbols, typeName, {L"ProviderSignature"}, &candidate.ProviderSignatureOffset) ||
                !TryFindFieldOffset(symbols, typeName, {L"Register", L"Registered"}, &candidate.RegisterOffset) ||
                !TryFindFieldOffset(symbols, typeName, {L"FirmwareTableHandler", L"Handler"}, &candidate.HandlerOffset) ||
                !TryFindFieldOffset(symbols, typeName, {L"DriverObject"}, &candidate.DriverObjectOffset))
            {
                continue;
            }

            uint32_t requiredSize = 0;
            if (!UpdateRequiredNodeSize(candidate.LinkOffset, static_cast<uint32_t>(sizeof(uint64_t) * 2), &requiredSize) ||
                !UpdateRequiredNodeSize(candidate.DriverObjectOffset, static_cast<uint32_t>(sizeof(uint64_t)), &requiredSize) ||
                !UpdateRequiredNodeSize(candidate.HandlerOffset, static_cast<uint32_t>(sizeof(uint64_t)), &requiredSize) ||
                !UpdateRequiredNodeSize(candidate.ProviderSignatureOffset, static_cast<uint32_t>(sizeof(uint32_t)), &requiredSize) ||
                !UpdateRequiredNodeSize(candidate.RegisterOffset, static_cast<uint32_t>(sizeof(uint8_t)), &requiredSize) ||
                requiredSize > candidate.NodeSize)
            {
                continue;
            }

            candidate.FromPdb = true;
            layout = candidate;
            break;
        }

        return layout;
    }

    void AnnotateDriverObject(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t driverObject,
        const TypeFieldInfo& driverStartField,
        const TypeFieldInfo& driverSizeField,
        const TypeFieldInfo& driverNameField,
        bool hasDriverFields,
        FirmwareTableProviderRecord* record)
    {
        do
        {
            if (record == nullptr)
            {
                break;
            }

            if (driverObject == 0)
            {
                record->Suspicious = true;
                AppendNote(&record->Notes, L"DriverObject is null");
                break;
            }
            if (!IsKernelAddress(driverObject))
            {
                record->Suspicious = true;
                AppendNote(&record->Notes, L"DriverObject is not a kernel pointer");
                break;
            }

            if (!hasDriverFields)
            {
                AppendNote(&record->Notes, L"_DRIVER_OBJECT PDB fields unavailable");
                break;
            }

            uint64_t value = 0;
            if (ReadFieldInteger(device, driverObject, driverStartField, sizeof(uint64_t), &value, nullptr))
            {
                record->DriverStart = value;
                const KernelModuleInfo* module = FindModuleForAddress(symbols.Modules(), value);
                if (module != nullptr)
                {
                    record->DriverModule = module->ImageName;
                }
                else if (value != 0)
                {
                    record->Suspicious = true;
                    AppendNote(&record->Notes, L"DriverStart is outside loaded module ranges");
                }
            }
            else
            {
                AppendNote(&record->Notes, L"DriverStart unreadable");
            }

            if (ReadFieldInteger(device, driverObject, driverSizeField, sizeof(uint32_t), &value, nullptr))
            {
                record->DriverSize = static_cast<uint32_t>(value);
            }

            uint64_t driverNameAddress = 0;
            if (TryAdd(driverObject, driverNameField.Offset, &driverNameAddress))
            {
                ReadUnicodeStringAt(device, driverNameAddress, &record->DriverName);
            }

            if (!record->HandlerModule.empty() && !record->DriverModule.empty() &&
                !ModuleNamesMatch(record->HandlerModule, record->DriverModule))
            {
                record->Suspicious = true;
                AppendNote(&record->Notes, L"handler module does not match DriverObject owner");
            }
        } while (false);
    }
}

FirmwareTableScanner::FirmwareTableScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool FirmwareTableScanner::Scan(FirmwareTableScanResult* result, std::wstring* error)
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

        *result = FirmwareTableScanResult{};

        uint64_t listHead = 0;
        if (!symbols_.ResolveSymbol(L"nt!ExpFirmwareTableProviderListHead", &listHead, error))
        {
            if (error != nullptr)
            {
                *error = L"firmware table provider list head symbol not resolved: nt!ExpFirmwareTableProviderListHead";
            }
            break;
        }

        result->ListHeadAddress = listHead;
        result->ListHeadSymbol = L"nt!ExpFirmwareTableProviderListHead";

        FirmwareProviderLayout providerLayout = ResolveFirmwareProviderLayout(symbols_);
        result->UsedFallbackLayout = !providerLayout.FromPdb;

        std::wstring ignored;
        uint64_t resource = 0;
        if (symbols_.ResolveSymbol(L"nt!ExpFirmwareTableResource", &resource, &ignored))
        {
            result->ResourceAddress = resource;
            result->ResourceSymbol = L"nt!ExpFirmwareTableResource";
        }

        TypeFieldInfo driverStartField = {};
        TypeFieldInfo driverSizeField = {};
        TypeFieldInfo driverNameField = {};
        bool hasDriverFields = ResolveDriverObjectFields(
            symbols_,
            &driverStartField,
            &driverSizeField,
            &driverNameField);

        if (!hasDriverFields)
        {
            result->Warnings.push_back(L"_DRIVER_OBJECT PDB fields unavailable; driver object annotation will be limited");
        }

        uint64_t first = 0;
        std::wstring readError;
        if (!ReadU64(device_, listHead, &first, &readError))
        {
            if (error != nullptr)
            {
                *error = L"failed to read firmware provider list head: " + readError;
            }
            break;
        }

        std::set<uint64_t> visited;
        std::map<uint32_t, uint32_t> signatureCounts;
        uint64_t current = first;
        uint32_t slot = 0;

        while (current != listHead)
        {
            if (slot >= kMaxFirmwareProviders)
            {
                result->Warnings.push_back(L"firmware provider walk reached maximum entry limit");
                break;
            }

            if (!IsKernelAddress(current))
            {
                result->Warnings.push_back(L"firmware provider list contains nonkernel link " + HexText(current, 16));
                break;
            }

            if (visited.find(current) != visited.end())
            {
                result->Warnings.push_back(L"firmware provider list loop detected at " + HexText(current, 16));
                break;
            }
            visited.insert(current);

            uint64_t node = 0;
            if (!TrySub(current, providerLayout.LinkOffset, &node))
            {
                result->Warnings.push_back(L"firmware provider node address underflow at " + HexText(current, 16));
                break;
            }

            std::vector<uint8_t> bytes;
            readError.clear();
            if (!ReadKernelBytes(device_, node, providerLayout.NodeSize, &bytes, &readError))
            {
                result->Warnings.push_back(L"failed to read firmware provider node " + HexText(node, 16) + L": " + readError);
                break;
            }

            uint32_t requiredSize = 0;
            if (!UpdateRequiredNodeSize(providerLayout.LinkOffset, static_cast<uint32_t>(sizeof(uint64_t) * 2), &requiredSize) ||
                !UpdateRequiredNodeSize(providerLayout.DriverObjectOffset, static_cast<uint32_t>(sizeof(uint64_t)), &requiredSize) ||
                !UpdateRequiredNodeSize(providerLayout.HandlerOffset, static_cast<uint32_t>(sizeof(uint64_t)), &requiredSize) ||
                !UpdateRequiredNodeSize(providerLayout.ProviderSignatureOffset, static_cast<uint32_t>(sizeof(uint32_t)), &requiredSize) ||
                !UpdateRequiredNodeSize(providerLayout.RegisterOffset, static_cast<uint32_t>(sizeof(uint8_t)), &requiredSize))
            {
                result->Warnings.push_back(L"firmware provider node layout has invalid field offsets at " + HexText(node, 16));
                break;
            }
            if (bytes.size() < requiredSize)
            {
                result->Warnings.push_back(L"firmware provider node layout exceeds read size at " + HexText(node, 16));
                break;
            }

            FirmwareTableProviderRecord record = {};
            record.Slot = slot;
            record.NodeAddress = node;
            record.ListEntry = current;
            memcpy(&record.Flink, bytes.data() + providerLayout.LinkOffset + 0x00, sizeof(uint64_t));
            memcpy(&record.Blink, bytes.data() + providerLayout.LinkOffset + 0x08, sizeof(uint64_t));
            memcpy(&record.ProviderSignature, bytes.data() + providerLayout.ProviderSignatureOffset, sizeof(uint32_t));
            memcpy(&record.RegisterFlag, bytes.data() + providerLayout.RegisterOffset, sizeof(uint8_t));
            memcpy(&record.FirmwareTableHandler, bytes.data() + providerLayout.HandlerOffset, sizeof(uint64_t));
            memcpy(&record.DriverObject, bytes.data() + providerLayout.DriverObjectOffset, sizeof(uint64_t));

            record.ProviderText = ProviderSignatureText(record.ProviderSignature);
            record.StandardProvider = IsStandardProviderSignature(record.ProviderSignature);
            if (!record.StandardProvider)
            {
                record.Suspicious = true;
                AppendNote(&record.Notes, L"nonstandard provider signature");
            }

            if (!IsKernelAddress(record.Flink) && record.Flink != listHead)
            {
                record.Suspicious = true;
                AppendNote(&record.Notes, L"Flink is not a kernel pointer");
            }
            if (!IsKernelAddress(record.Blink) && record.Blink != listHead)
            {
                record.Suspicious = true;
                AppendNote(&record.Notes, L"Blink is not a kernel pointer");
            }

            uint64_t nextBlink = 0;
            uint64_t nextBlinkAddress = 0;
            if (record.Flink != 0 && IsKernelAddress(record.Flink) &&
                TryAdd(record.Flink, sizeof(uint64_t), &nextBlinkAddress) &&
                ReadU64(device_, nextBlinkAddress, &nextBlink, nullptr) &&
                nextBlink != current)
            {
                record.Suspicious = true;
                AppendNote(&record.Notes, L"Flink/Blink backlink mismatch");
            }

            uint64_t previousFlink = 0;
            if (record.Blink != 0 && IsKernelAddress(record.Blink) &&
                ReadU64(device_, record.Blink, &previousFlink, nullptr) &&
                previousFlink != current)
            {
                record.Suspicious = true;
                AppendNote(&record.Notes, L"Blink/Flink forward-link mismatch");
            }

            AnnotateAddress(
                symbols_,
                record.FirmwareTableHandler,
                &record.HandlerModule,
                &record.HandlerSymbol);

            if (record.FirmwareTableHandler == 0)
            {
                record.Suspicious = true;
                AppendNote(&record.Notes, L"handler is null");
            }
            else if (!IsKernelAddress(record.FirmwareTableHandler))
            {
                record.Suspicious = true;
                AppendNote(&record.Notes, L"handler is not a kernel pointer");
            }
            else if (FindModuleForAddress(symbols_.Modules(), record.FirmwareTableHandler) == nullptr)
            {
                record.Suspicious = true;
                AppendNote(&record.Notes, L"handler is outside loaded module ranges");
            }

            AnnotateDriverObject(
                device_,
                symbols_,
                record.DriverObject,
                driverStartField,
                driverSizeField,
                driverNameField,
                hasDriverFields,
                &record);

            ++signatureCounts[record.ProviderSignature];
            result->Records.push_back(record);

            current = record.Flink;
            ++slot;
        }

        for (FirmwareTableProviderRecord& record : result->Records)
        {
            if (signatureCounts[record.ProviderSignature] > 1)
            {
                record.Suspicious = true;
                AppendNote(&record.Notes, L"duplicate provider signature");
            }
        }

        ok = true;
    } while (false);

    return ok;
}
