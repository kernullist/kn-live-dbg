#include "InputStackScanner.h"

#include "McpJson.h"

#include <cwctype>
#include <sstream>

namespace
{
    std::wstring ToLowerCopy(const std::wstring& value)
    {
        std::wstring lowered = value;
        for (wchar_t& ch : lowered)
        {
            ch = static_cast<wchar_t>(std::towlower(ch));
        }
        return lowered;
    }

    std::wstring Stem(const std::wstring& value)
    {
        std::wstring name = ToLowerCopy(value);
        size_t slash = name.find_last_of(L"\\/");
        if (slash != std::wstring::npos)
        {
            name = name.substr(slash + 1);
        }
        size_t dot = name.find_last_of(L'.');
        if (dot != std::wstring::npos)
        {
            name = name.substr(0, dot);
        }
        if (!name.empty() && name[0] == L'\\')
        {
            name = name.substr(1);
        }
        size_t driver = name.rfind(L"driver\\");
        if (driver != std::wstring::npos)
        {
            name = name.substr(driver + 7);
        }
        return name;
    }

    bool IsKnownInputDriver(const std::wstring& name)
    {
        const std::wstring stem = Stem(name);
        return stem == L"kbdclass" ||
            stem == L"kbdhid" ||
            stem == L"i8042prt" ||
            stem == L"hidusb" ||
            stem == L"hidclass" ||
            stem == L"hidparse" ||
            stem == L"mouclass" ||
            stem == L"mouhid" ||
            stem == L"mshidkmdf" ||
            stem == L"wdf01000" ||
            stem == L"wdfldr" ||
            stem == L"ntoskrnl" ||
            stem == L"ntkrnlmp" ||
            stem == L"dmvsc" ||
            stem == L"vmmouse" ||
            stem == L"vmhid" ||
            stem == L"spldr" ||
            stem == L"acpi" ||
            stem == L"pci" ||
            stem.empty();
    }
}

InputStackScanner::InputStackScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool InputStackScanner::Scan(InputStackScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid input-stack result output";
            }
            break;
        }

        *result = InputStackScanResult{};
        IntegrityScanner integrity(device_, symbols_);
        const wchar_t* roles[][2] =
        {
            { L"keyboard-class", L"kbdclass" },
            { L"mouse-class", L"mouclass" },
            { L"keyboard-hid", L"kbdhid" },
            { L"mouse-hid", L"mouhid" },
            { L"i8042", L"i8042prt" },
        };

        uint32_t found = 0;
        for (const auto& role : roles)
        {
            InputStackRecord record = {};
            record.Role = role[0];
            record.DriverFilter = role[1];
            std::wstring inspectError;
            if (!integrity.InspectDriverObject(
                    record.DriverFilter,
                    false,
                    true,
                    &record.Driver,
                    &inspectError))
            {
                result->Warnings.push_back(
                    record.DriverFilter + L": " + inspectError);
                result->Records.push_back(record);
                continue;
            }

            ++found;
            for (const DeviceStackResult& stack : record.Driver.Stacks)
            {
                for (const DeviceObjectRecord& device : stack.Stack)
                {
                    const std::wstring owner =
                        !device.DriverModule.empty() ? device.DriverModule : device.DriverName;
                    if (!IsKnownInputDriver(owner))
                    {
                        record.Suspicious = true;
                        if (record.Notes.empty())
                        {
                            record.Notes = L"unknown driver attached to an input device stack: " + owner;
                        }
                    }
                    if (device.Suspicious)
                    {
                        record.Suspicious = true;
                        if (record.Notes.empty())
                        {
                            record.Notes = device.Notes;
                        }
                    }
                }
            }
            if (record.Suspicious)
            {
                ++result->SuspiciousStacks;
            }
            result->Records.push_back(record);
        }

        result->CoverageComplete = found > 0;
        if (!result->CoverageComplete && error != nullptr)
        {
            *error = L"no input class driver objects were found";
            break;
        }
        ok = true;
    } while (false);

    return ok;
}

std::wstring BuildInputStackJson(const InputStackScanResult& result)
{
    std::wstringstream json;
    json << L"{\"schema\":\"kn-live-dbg.input-stack.v1\"";
    json << L",\"suspicious_stacks\":" << result.SuspiciousStacks;
    json << L",\"coverage_complete\":" << (result.CoverageComplete ? L"true" : L"false");
    json << L",\"records\":[";
    for (size_t i = 0; i < result.Records.size(); ++i)
    {
        const InputStackRecord& record = result.Records[i];
        if (i != 0)
        {
            json << L",";
        }
        json << L"{\"role\":\"" << mcpjson::Escape(record.Role) << L"\"";
        json << L",\"filter\":\"" << mcpjson::Escape(record.DriverFilter) << L"\"";
        json << L",\"suspicious\":" << (record.Suspicious ? L"true" : L"false");
        json << L",\"notes\":\"" << mcpjson::Escape(record.Notes) << L"\"";
        json << L",\"found\":" << (record.Driver.Found ? L"true" : L"false");
        json << L",\"devices\":" << record.Driver.Devices.size();
        json << L"}";
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

bool InputStackKnownDriverSelfTest()
{
    bool ok = false;

    do
    {
        if (!IsKnownInputDriver(L"kbdclass.sys") ||
            !IsKnownInputDriver(L"\\Driver\\mouclass") ||
            IsKnownInputDriver(L"keylogger.sys"))
        {
            break;
        }
        ok = true;
    } while (false);

    return ok;
}
