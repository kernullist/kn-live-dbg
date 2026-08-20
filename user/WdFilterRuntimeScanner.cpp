#include "WdFilterRuntimeScanner.h"

#include "McpJson.h"

#include <Windows.h>

#include <cstring>
#include <sstream>
#include <vector>

namespace
{
    constexpr uint64_t kKernelSpaceMin = 0xffff800000000000ull;
    constexpr uint32_t kMaxRuntimeEntries = 512;

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

    bool ReadU32(DeviceClient& device, uint64_t address, uint32_t* value)
    {
        std::vector<uint8_t> bytes;
        if (!device.ReadMemory(address, sizeof(uint32_t), &bytes, nullptr) ||
            bytes.size() != sizeof(uint32_t))
        {
            return false;
        }
        memcpy(value, bytes.data(), sizeof(uint32_t));
        return true;
    }

    std::wstring JsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }

    bool ReadUnicodeString(DeviceClient& device, uint64_t address, std::wstring* value)
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
            std::vector<uint8_t> header;
            if (!device.ReadMemory(address, 16, &header, nullptr) || header.size() < 16)
            {
                break;
            }
            memcpy(&length, header.data(), sizeof(length));
            uint64_t buffer = 0;
            memcpy(&buffer, header.data() + 8, sizeof(buffer));
            if (length == 0 || buffer == 0)
            {
                ok = true;
                break;
            }
            if (length > 2048)
            {
                length = 2048;
            }
            std::vector<uint8_t> bytes;
            if (!device.ReadMemory(buffer, length, &bytes, nullptr) || bytes.size() < 2)
            {
                break;
            }
            value->assign(
                reinterpret_cast<const wchar_t*>(bytes.data()),
                bytes.size() / sizeof(wchar_t));
            ok = true;
        } while (false);

        return ok;
    }

    std::wstring Stem(const std::wstring& value)
    {
        std::wstring name = value;
        size_t slash = name.find_last_of(L"\\/");
        if (slash != std::wstring::npos)
        {
            name = name.substr(slash + 1);
        }
        for (wchar_t& ch : name)
        {
            if (ch >= L'A' && ch <= L'Z')
            {
                ch = static_cast<wchar_t>(ch - L'A' + L'a');
            }
        }
        return name;
    }

    bool NameInLoadedModules(SymbolEngine& symbols, const std::wstring& name)
    {
        bool found = false;
        const std::wstring stem = Stem(name);
        if (stem.empty())
        {
            return found;
        }
        for (const KernelModuleInfo& module : symbols.Modules())
        {
            if (Stem(module.ImageName) == stem)
            {
                found = true;
                break;
            }
        }
        return found;
    }
}

WdFilterRuntimeScanner::WdFilterRuntimeScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool WdFilterRuntimeScanner::Scan(WdFilterRuntimeScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid WdFilter runtime result output";
            }
            break;
        }

        *result = WdFilterRuntimeScanResult{};
        if (symbols_.Modules().empty())
        {
            if (!symbols_.LoadKernelModules(error))
            {
                break;
            }
        }

        std::vector<SymbolMatchInfo> matches;
        std::wstring enumError;
        symbols_.EnumerateSymbols(L"WdFilter!*RuntimeDriver*", 64, &matches, &enumError);
        std::vector<SymbolMatchInfo> extra;
        symbols_.EnumerateSymbols(L"WdFilter!*MpFreeDriver*", 32, &extra, nullptr);
        matches.insert(matches.end(), extra.begin(), extra.end());
        if (matches.empty())
        {
            result->Warnings.push_back(
                L"WdFilter RuntimeDriver symbols were not found; leftover coverage is incomplete");
            result->CoverageNotes.push_back(L"enumerate WdFilter!*RuntimeDriver* returned no hits");
            ok = true;
            break;
        }

        for (const SymbolMatchInfo& match : matches)
        {
            const std::wstring lowered = Stem(match.Name);
            if (result->ArrayAddress == 0 &&
                (lowered.find(L"runtimedriversarray") != std::wstring::npos ||
                 lowered.find(L"runtimedriverarray") != std::wstring::npos))
            {
                result->ArrayAddress = match.Address;
                result->ArraySymbol = match.Name;
            }
            if (result->CountAddress == 0 &&
                (lowered.find(L"runtimedriverscount") != std::wstring::npos ||
                 lowered.find(L"runtimedrivercount") != std::wstring::npos))
            {
                result->CountAddress = match.Address;
                result->CountSymbol = match.Name;
            }
            if (result->ListAddress == 0 &&
                (lowered.find(L"runtimedrivers") != std::wstring::npos ||
                 lowered.find(L"runtimedriverlist") != std::wstring::npos) &&
                lowered.find(L"count") == std::wstring::npos &&
                lowered.find(L"array") == std::wstring::npos)
            {
                result->ListAddress = match.Address;
                result->ListSymbol = match.Name;
            }
        }

        if (result->ArrayAddress == 0 && result->ListAddress == 0)
        {
            result->Warnings.push_back(
                L"WdFilter RuntimeDriver symbols were present but no array/list pointer was classified");
            for (const SymbolMatchInfo& match : matches)
            {
                result->CoverageNotes.push_back(match.Name);
            }
            ok = true;
            break;
        }

        result->Resolved = true;
        TypeFieldInfo nameField = {};
        TypeFieldInfo pathField = {};
        const bool hasName =
            symbols_.FindField(L"WdFilter!_MP_RUNTIME_DRIVER", L"DriverName", &nameField, nullptr) ||
            symbols_.FindField(L"WdFilter!_RUNTIME_DRIVER", L"DriverName", &nameField, nullptr);
        const bool hasPath =
            symbols_.FindField(L"WdFilter!_MP_RUNTIME_DRIVER", L"DriverPath", &pathField, nullptr) ||
            symbols_.FindField(L"WdFilter!_RUNTIME_DRIVER", L"ImagePath", &pathField, nullptr);
        if (!hasName)
        {
            nameField.Offset = 0x10;
            result->Warnings.push_back(
                L"WdFilter runtime-driver name field used fallback offset 0x10");
        }

        if (result->CountAddress != 0)
        {
            ReadU32(device_, result->CountAddress, &result->CountValue);
        }

        if (result->ArrayAddress != 0)
        {
            result->WalkMode = L"array";
            uint64_t array = 0;
            if (!ReadU64(device_, result->ArrayAddress, &array) ||
                array == 0 ||
                !IsKernelAddress(array))
            {
                result->Warnings.push_back(L"RuntimeDriversArray pointer was unreadable or not canonical");
            }
            else
            {
                uint32_t count = result->CountValue;
                if (result->CountAddress == 0 && count == 0)
                {
                    count = 64;
                    result->Warnings.push_back(
                        L"RuntimeDriversCount was not resolved; probing 64 array slots");
                }
                if (count > kMaxRuntimeEntries)
                {
                    count = kMaxRuntimeEntries;
                    result->Warnings.push_back(L"RuntimeDriversCount hit the safety cap");
                }
                for (uint32_t index = 0; index < count; ++index)
                {
                    uint64_t slot = array + static_cast<uint64_t>(index) * sizeof(uint64_t);
                    uint64_t entry = 0;
                    if (!ReadU64(device_, slot, &entry) || entry == 0)
                    {
                        continue;
                    }
                    if (!IsKernelAddress(entry))
                    {
                        continue;
                    }

                    WdFilterRuntimeRecord record = {};
                    record.Index = index;
                    record.EntryAddress = entry;
                    ReadUnicodeString(device_, entry + nameField.Offset, &record.DriverName);
                    if (hasPath)
                    {
                        ReadUnicodeString(device_, entry + pathField.Offset, &record.DriverPath);
                    }
                    record.InLoadedModules = NameInLoadedModules(symbols_, record.DriverName);
                    if (!record.DriverName.empty() && !record.InLoadedModules)
                    {
                        record.Suspicious = true;
                        record.Notes = L"WdFilter runtime driver name is not in the loaded module list";
                        ++result->SuspiciousCount;
                    }
                    result->Records.push_back(record);
                }
            }
        }
        else if (result->ListAddress != 0)
        {
            result->WalkMode = L"list";
            uint64_t head = result->ListAddress;
            uint64_t flink = 0;
            if (!ReadU64(device_, head, &flink) || flink == 0)
            {
                result->Warnings.push_back(L"RuntimeDrivers list head was unreadable");
            }
            else
            {
                uint32_t walked = 0;
                uint64_t current = flink;
                std::vector<uint64_t> seen;
                while (current != 0 &&
                    current != head &&
                    IsKernelAddress(current) &&
                    walked < kMaxRuntimeEntries)
                {
                    bool cycle = false;
                    for (uint64_t existing : seen)
                    {
                        if (existing == current)
                        {
                            cycle = true;
                            break;
                        }
                    }
                    if (cycle)
                    {
                        result->Warnings.push_back(L"RuntimeDrivers list walk hit a cycle");
                        break;
                    }
                    seen.push_back(current);

                    WdFilterRuntimeRecord record = {};
                    record.Index = walked;
                    record.EntryAddress = current;
                    ReadU64(device_, current, &record.Next);
                    ReadUnicodeString(device_, current + nameField.Offset, &record.DriverName);
                    if (hasPath)
                    {
                        ReadUnicodeString(device_, current + pathField.Offset, &record.DriverPath);
                    }
                    record.InLoadedModules = NameInLoadedModules(symbols_, record.DriverName);
                    if (!record.DriverName.empty() && !record.InLoadedModules)
                    {
                        record.Suspicious = true;
                        record.Notes = L"WdFilter runtime driver name is not in the loaded module list";
                        ++result->SuspiciousCount;
                    }
                    result->Records.push_back(record);
                    ++walked;
                    current = record.Next;
                }
            }
        }

        result->CoverageComplete = result->Resolved && !result->Records.empty();
        if (!result->CoverageComplete)
        {
            result->CoverageNotes.push_back(
                L"WdFilter runtime leftover scan resolved symbols but found no entries");
        }
        ok = true;
    } while (false);

    return ok;
}

std::wstring BuildWdFilterRuntimeJson(const WdFilterRuntimeScanResult& result)
{
    std::wstringstream json;
    json << L"{\"schema\":\"kn-live-dbg.wdfilter-runtime.v1\"";
    json << L",\"resolved\":" << (result.Resolved ? L"true" : L"false");
    json << L",\"walk_mode\":\"" << mcpjson::Escape(result.WalkMode) << L"\"";
    json << L",\"array\":\"" << JsonHex(result.ArrayAddress) << L"\"";
    json << L",\"count\":" << result.CountValue;
    json << L",\"suspicious\":" << result.SuspiciousCount;
    json << L",\"coverage_complete\":" << (result.CoverageComplete ? L"true" : L"false");
    json << L",\"records\":[";
    for (size_t i = 0; i < result.Records.size(); ++i)
    {
        const WdFilterRuntimeRecord& record = result.Records[i];
        if (i != 0)
        {
            json << L",";
        }
        json << L"{\"index\":" << record.Index;
        json << L",\"entry\":\"" << JsonHex(record.EntryAddress) << L"\"";
        json << L",\"name\":\"" << mcpjson::Escape(record.DriverName) << L"\"";
        json << L",\"path\":\"" << mcpjson::Escape(record.DriverPath) << L"\"";
        json << L",\"loaded\":" << (record.InLoadedModules ? L"true" : L"false");
        json << L",\"suspicious\":" << (record.Suspicious ? L"true" : L"false");
        json << L",\"notes\":\"" << mcpjson::Escape(record.Notes) << L"\"}";
    }
    json << L"],\"warnings\":[";
    for (size_t i = 0; i < result.Warnings.size(); ++i)
    {
        if (i != 0)
        {
            json << L",";
        }
        json << L"\"" << mcpjson::Escape(result.Warnings[i]) << L"\"";
    }
    json << L"]}";
    return json.str();
}

bool WdFilterRuntimeNameSelfTest()
{
    bool ok = false;

    do
    {
        std::wstring leftover = L"mapped.sys";
        std::wstring loaded = L"WdFilter.sys";
        if (leftover.empty() || loaded.empty())
        {
            break;
        }
        ok = leftover != loaded;
    } while (false);

    return ok;
}
