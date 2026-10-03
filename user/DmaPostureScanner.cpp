#include "DmaPostureScanner.h"

#include "McpJson.h"

#include <Windows.h>
#include <SetupAPI.h>

#include <algorithm>
#include <sstream>
#include <vector>

namespace
{
    constexpr DWORD kAcpiProvider = 'ACPI';

    bool FirmwareListSizeValid(DWORD returned, size_t capacity)
    {
        return returned != 0 && returned <= capacity && returned % sizeof(uint32_t) == 0;
    }

    bool BoundedPropertyString(const wchar_t* data, size_t capacity, DWORD type,
        DWORD bytes, bool multi, std::wstring* output)
    {
        output->clear();
        if (data == nullptr || type != (multi ? REG_MULTI_SZ : REG_SZ) ||
            bytes == 0 || bytes % sizeof(wchar_t) != 0 || bytes / sizeof(wchar_t) > capacity)
        {
            return false;
        }
        const size_t characters = bytes / sizeof(wchar_t);
        if (data[characters - 1] != L'\0' || (multi &&
            (characters < 2 || data[characters - 2] != L'\0')))
        {
            return false;
        }
        for (size_t index = 0; index < characters; ++index)
        {
            if (data[index] == L'\0')
            {
                if (!multi || index + 1 >= characters || data[index + 1] == L'\0')
                {
                    break;
                }
                output->push_back(L';');
            }
            else
            {
                output->push_back(data[index]);
            }
        }
        return true;
    }

    std::wstring ReadDeviceProperty(HDEVINFO devices, SP_DEVINFO_DATA* device,
        DWORD property, bool multi)
    {
        wchar_t buffer[1024] = {};
        DWORD type = 0;
        DWORD bytes = 0;
        std::wstring value;
        if (SetupDiGetDeviceRegistryPropertyW(devices, device, property, &type,
            reinterpret_cast<PBYTE>(buffer), sizeof(buffer), &bytes))
        {
            BoundedPropertyString(buffer, std::size(buffer), type, bytes, multi, &value);
        }
        return value;
    }

    std::wstring FourCcText(uint32_t signature)
    {
        wchar_t text[5] = {};
        text[0] = static_cast<wchar_t>(signature & 0xff);
        text[1] = static_cast<wchar_t>((signature >> 8) & 0xff);
        text[2] = static_cast<wchar_t>((signature >> 16) & 0xff);
        text[3] = static_cast<wchar_t>((signature >> 24) & 0xff);
        return text;
    }

    std::wstring ToLowerCopy(const std::wstring& value)
    {
        std::wstring lowered = value;
        for (wchar_t& ch : lowered)
        {
            if (ch >= L'A' && ch <= L'Z')
            {
                ch = static_cast<wchar_t>(ch - L'A' + L'a');
            }
        }
        return lowered;
    }

    bool LooksLikeRemovableBus(const std::wstring& hardwareId, const std::wstring& description)
    {
        const std::wstring id = ToLowerCopy(hardwareId) + L" " + ToLowerCopy(description);
        return id.find(L"thunderbolt") != std::wstring::npos ||
            id.find(L"usb4") != std::wstring::npos ||
            id.find(L"1394") != std::wstring::npos ||
            id.find(L"firewire") != std::wstring::npos ||
            id.find(L"cc_0c03") != std::wstring::npos ||
            id.find(L"cc_0c04") != std::wstring::npos;
    }

    bool ReadRegistryString(
        HKEY root,
        const wchar_t* path,
        const wchar_t* valueName,
        std::wstring* value)
    {
        bool ok = false;
        HKEY key = nullptr;

        do
        {
            if (value == nullptr)
            {
                break;
            }
            value->clear();
            if (RegOpenKeyExW(root, path, 0, KEY_READ, &key) != ERROR_SUCCESS)
            {
                break;
            }

            DWORD type = 0;
            DWORD bytes = 0;
            if (RegQueryValueExW(key, valueName, nullptr, &type, nullptr, &bytes) != ERROR_SUCCESS ||
                bytes == 0 || bytes > 16384 || bytes % sizeof(wchar_t) != 0 ||
                (type != REG_SZ && type != REG_EXPAND_SZ))
            {
                break;
            }
            std::vector<wchar_t> buffer((bytes / sizeof(wchar_t)) + 1);
            const DWORD capacityBytes = bytes;
            if (RegQueryValueExW(
                    key,
                    valueName,
                    nullptr,
                    &type,
                    reinterpret_cast<LPBYTE>(buffer.data()),
                    &bytes) != ERROR_SUCCESS || bytes == 0 || bytes > capacityBytes ||
                bytes % sizeof(wchar_t) != 0 || (type != REG_SZ && type != REG_EXPAND_SZ))
            {
                break;
            }
            *value = buffer.data();
            ok = true;
        } while (false);

        if (key != nullptr)
        {
            RegCloseKey(key);
        }
        return ok;
    }

    bool ReadRegistryDword(
        HKEY root,
        const wchar_t* path,
        const wchar_t* valueName,
        uint32_t* value)
    {
        bool ok = false;
        HKEY key = nullptr;

        do
        {
            if (value == nullptr)
            {
                break;
            }
            *value = 0;
            if (RegOpenKeyExW(root, path, 0, KEY_READ, &key) != ERROR_SUCCESS)
            {
                break;
            }
            DWORD type = 0;
            DWORD data = 0;
            DWORD bytes = sizeof(data);
            if (RegQueryValueExW(
                    key,
                    valueName,
                    nullptr,
                    &type,
                    reinterpret_cast<LPBYTE>(&data),
                    &bytes) != ERROR_SUCCESS ||
                type != REG_DWORD || bytes != sizeof(data))
            {
                break;
            }
            *value = data;
            ok = true;
        } while (false);

        if (key != nullptr)
        {
            RegCloseKey(key);
        }
        return ok;
    }
}

bool DmaPostureScanner::Scan(DmaPostureScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid DMA posture result output";
            }
            break;
        }

        *result = DmaPostureScanResult{};
        DWORD tableBytes = EnumSystemFirmwareTables(kAcpiProvider, nullptr, 0);
        if (tableBytes == 0 || tableBytes % sizeof(uint32_t) != 0)
        {
            result->Warnings.push_back(L"EnumSystemFirmwareTables(ACPI) returned no signatures");
        }
        else
        {
            size_t signatureCount = tableBytes / sizeof(uint32_t);
            if (signatureCount > 256)
            {
                signatureCount = 256;
                result->Warnings.push_back(L"ACPI firmware-table signature list was capped at 256");
            }
            std::vector<uint32_t> signatures(signatureCount);
            DWORD written = EnumSystemFirmwareTables(
                kAcpiProvider,
                signatures.data(),
                static_cast<DWORD>(signatures.size() * sizeof(uint32_t)));
            if (!FirmwareListSizeValid(written, signatures.size() * sizeof(uint32_t)))
            {
                result->Warnings.push_back(L"ACPI firmware-table signature enumeration failed or changed size");
                signatures.clear();
            }
            else
            {
                signatures.resize(written / sizeof(uint32_t));
                result->FirmwareInventoryComplete = true;
            }
            for (uint32_t signature : signatures)
            {
                if (signature == 0)
                {
                    continue;
                }
                DmaAcpiTableRecord table = {};
                table.Signature = FourCcText(signature);
                table.Present = true;
                DWORD size = GetSystemFirmwareTable(kAcpiProvider, signature, nullptr, 0);
                table.Length = size;
                if (table.Signature == L"DMAR")
                {
                    result->DmarPresent = true;
                    table.Notes = L"Intel VT-d DMAR table";
                }
                else if (table.Signature == L"IVRS")
                {
                    result->IvrsPresent = true;
                    table.Notes = L"AMD-Vi IVRS table";
                }
                if (table.Signature == L"DMAR" || table.Signature == L"IVRS")
                {
                    result->AcpiTables.push_back(table);
                }
            }
        }
        result->IommuFirmwarePresent = result->DmarPresent || result->IvrsPresent;

        uint32_t dmaProtection = 0;
        if (ReadRegistryDword(
                HKEY_LOCAL_MACHINE,
                L"SYSTEM\\CurrentControlSet\\Control\\DmaSecurity",
                L"DmaGuardOptIn",
                &dmaProtection))
        {
            result->DmaGuardConfigurationKnown = true;
            result->DmaGuardConfigurationValue = dmaProtection;
            result->DmaSecurityPath = L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DmaSecurity\\DmaGuardOptIn";
            result->DmaSecurityValue = std::to_wstring(dmaProtection);
        }
        else
        {
            std::wstring policy;
            if (ReadRegistryString(
                    HKEY_LOCAL_MACHINE,
                    L"SYSTEM\\CurrentControlSet\\Control\\DmaSecurity",
                    nullptr,
                    &policy))
            {
                result->DmaSecurityPath = L"HKLM\\SYSTEM\\CurrentControlSet\\Control\\DmaSecurity";
            }
            result->Warnings.push_back(
                L"DmaGuardOptIn was not readable; Kernel DMA Protection state is unknown");
        }

        result->Warnings.push_back(
            L"Registry configuration and ACPI tables do not establish active or pre-boot DMA enforcement");
        HDEVINFO devs = SetupDiGetClassDevsW(
            nullptr,
            L"PCI",
            nullptr,
            DIGCF_PRESENT | DIGCF_ALLCLASSES);
        if (devs == INVALID_HANDLE_VALUE)
        {
            result->Warnings.push_back(L"SetupDiGetClassDevs(PCI) failed");
        }
        else
        {
            SP_DEVINFO_DATA info = {};
            info.cbSize = sizeof(info);
            for (DWORD index = 0; SetupDiEnumDeviceInfo(devs, index, &info); ++index)
            {
                if (index >= 4096)
                {
                    result->Warnings.push_back(L"PCI enumeration hit the 4096 device safety cap");
                    break;
                }

                wchar_t instanceId[512] = {};
                const std::wstring hardwareId = ReadDeviceProperty(devs, &info, SPDRP_HARDWAREID, true);
                const std::wstring description = ReadDeviceProperty(devs, &info, SPDRP_DEVICEDESC, false);
                const std::wstring className = ReadDeviceProperty(devs, &info, SPDRP_CLASS, false);
                if (!SetupDiGetDeviceInstanceIdW(devs, &info, instanceId, 512, nullptr))
                {
                    instanceId[0] = L'\0';
                }
                instanceId[511] = L'\0';

                if (!LooksLikeRemovableBus(hardwareId, description))
                {
                    continue;
                }

                DmaPciDeviceRecord device = {};
                device.InstanceId = instanceId;
                device.Description = description;
                device.HardwareId = hardwareId;
                device.Class = className;
                device.RemovableBus = true;
                device.Notes = L"PCI device on a removable / DMA-capable bus class";
                ++result->RemovableBusCount;
                result->PciDevices.push_back(device);
            }
            SetupDiDestroyDeviceInfoList(devs);
        }

        result->CoverageComplete = false;
        ok = true;
    } while (false);

    return ok;
}

std::wstring BuildDmaPostureJson(const DmaPostureScanResult& result)
{
    std::wstringstream json;
    json << L"{\"schema\":\"kn-live-dbg.dma-posture.v1\"";
    json << L",\"dmar\":" << (result.DmarPresent ? L"true" : L"false");
    json << L",\"ivrs\":" << (result.IvrsPresent ? L"true" : L"false");
    json << L",\"iommu_firmware\":" << (result.IommuFirmwarePresent ? L"true" : L"false");
    json << L",\"firmware_inventory_complete\":" << (result.FirmwareInventoryComplete ? L"true" : L"false");
    json << L",\"kernel_dma_protection_enabled\":"
         << (result.KernelDmaProtectionEnabled ? L"true" : L"false");
    json << L",\"kernel_dma_protection_resolved\":"
         << (result.KernelDmaProtectionResolved ? L"true" : L"false");
    json << L",\"removable_buses\":" << result.RemovableBusCount;
    json << L",\"dma_guard_configuration_known\":" << (result.DmaGuardConfigurationKnown ? L"true" : L"false");
    json << L",\"dma_guard_configuration_value\":" << result.DmaGuardConfigurationValue;
    json << L",\"enforcement_scope\":\"unknown; same-OS configuration inventory\"";
    json << L",\"coverage_complete\":" << (result.CoverageComplete ? L"true" : L"false");
    json << L",\"acpi\":[";
    for (size_t i = 0; i < result.AcpiTables.size(); ++i)
    {
        if (i != 0)
        {
            json << L",";
        }
        json << L"{\"signature\":\"" << mcpjson::Escape(result.AcpiTables[i].Signature)
             << L"\",\"length\":" << result.AcpiTables[i].Length
             << L",\"notes\":\"" << mcpjson::Escape(result.AcpiTables[i].Notes) << L"\"}";
    }
    json << L"],\"pci\":[";
    for (size_t i = 0; i < result.PciDevices.size(); ++i)
    {
        if (i != 0)
        {
            json << L",";
        }
        json << L"{\"instance\":\"" << mcpjson::Escape(result.PciDevices[i].InstanceId)
             << L"\",\"description\":\"" << mcpjson::Escape(result.PciDevices[i].Description)
             << L"\",\"hardware_id\":\"" << mcpjson::Escape(result.PciDevices[i].HardwareId)
             << L"\"}";
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

bool DmaAcpiSignatureSelfTest()
{
    bool ok = false;

    do
    {
        if (!FirmwareListSizeValid(8, 8) || FirmwareListSizeValid(12, 8) ||
            FirmwareListSizeValid(7, 8) || FirmwareListSizeValid(0, 8))
        {
            break;
        }
        const wchar_t property[] = L"PCI\\VEN_8086\0PCI\\CC_0C03\0";
        std::wstring propertyText;
        if (!BoundedPropertyString(property, std::size(property), REG_MULTI_SZ,
                sizeof(property), true, &propertyText) ||
            !LooksLikeRemovableBus(propertyText, L"") ||
            BoundedPropertyString(property, 2, REG_MULTI_SZ, sizeof(property), true, &propertyText) ||
            BoundedPropertyString(property, std::size(property), REG_BINARY, sizeof(property), true, &propertyText) ||
            BoundedPropertyString(property, std::size(property), REG_MULTI_SZ,
                sizeof(property) - sizeof(wchar_t), true, &propertyText))
        {
            break;
        }
        const uint32_t dmar = 'RAMD';
        std::wstring text = FourCcText(dmar);
        if (text != L"DMAR")
        {
            break;
        }
        if (!LooksLikeRemovableBus(L"PCI\\VEN_8086&CC_0C03", L"USB xHCI"))
        {
            break;
        }
        if (LooksLikeRemovableBus(L"PCI\\VEN_8086&CC_0300", L"VGA"))
        {
            break;
        }
        DmaPostureScanResult configured;
        configured.DmaGuardConfigurationKnown = true;
        configured.DmaGuardConfigurationValue = 1;
        if (configured.KernelDmaProtectionResolved || configured.KernelDmaProtectionEnabled ||
            BuildDmaPostureJson(configured).find(L"\"kernel_dma_protection_resolved\":false") == std::wstring::npos)
        {
            break;
        }
        ok = true;
    } while (false);

    return ok;
}
