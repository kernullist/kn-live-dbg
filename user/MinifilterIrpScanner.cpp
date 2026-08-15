#include "MinifilterIrpScanner.h"

#include "../shared/KnLiveDbgIoctl.h"
#include "LeftoverCommon.h"
#include "McpJson.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <mutex>
#include <set>
#include <sstream>

namespace
{
    constexpr uint32_t kIrpMjOperationEnd = 0x80;
    constexpr uint32_t kMaxFrames = 32;
    constexpr uint32_t kMaxFilters = 512;
    constexpr uint32_t kMaxOperations = 256;

    struct MinifilterLayout
    {
        uint32_t GlobalsFrameList = 0;
        uint32_t ResourceList = 0;
        uint32_t FrameLinks = 0;
        uint32_t FrameId = 0;
        uint32_t FrameRegisteredFilters = 0;
        uint32_t FilterBase = 0;
        uint32_t FilterName = 0;
        uint32_t FilterAltitude = 0;
        uint32_t FilterFlags = 0;
        uint32_t FilterDriverObject = 0;
        uint32_t FilterOperations = 0;
        uint32_t ObjectPrimaryLink = 0;
        uint32_t OperationMajor = 0;
        uint32_t OperationFlags = 0;
        uint32_t OperationPre = 0;
        uint32_t OperationPost = 0;
        uint32_t OperationSize = 0;
        uint32_t DriverStart = 0;
        bool HasDriverStart = false;
    };

    struct IrpBackupKey
    {
        uint64_t Filter = 0;
        uint32_t MajorFunction = 0;
    };

    bool operator<(const IrpBackupKey& left, const IrpBackupKey& right)
    {
        if (left.Filter != right.Filter)
        {
            return left.Filter < right.Filter;
        }
        return left.MajorFunction < right.MajorFunction;
    }

    struct IrpBackupValue
    {
        uint64_t Pre = 0;
        uint64_t Post = 0;
        std::wstring FilterName;
    };

    std::mutex g_BackupLock;
    std::map<IrpBackupKey, IrpBackupValue> g_Backups;

    std::wstring ToLowerCopy(const std::wstring& value)
    {
        std::wstring out = value;
        for (wchar_t& ch : out)
        {
            if (ch >= L'A' && ch <= L'Z')
            {
                ch = static_cast<wchar_t>(ch - L'A' + L'a');
            }
        }
        return out;
    }

    bool ReadListEntry(DeviceClient& device, uint64_t address, uint64_t* flink, uint64_t* blink)
    {
        bool ok = false;
        do
        {
            if (flink == nullptr || blink == nullptr)
            {
                break;
            }
            if (!LeftoverReadU64(device, address, flink, nullptr))
            {
                break;
            }
            uint64_t blinkAddr = 0;
            if (!LeftoverTryAdd(address, 8, &blinkAddr) ||
                !LeftoverReadU64(device, blinkAddr, blink, nullptr))
            {
                break;
            }
            ok = true;
        } while (false);
        return ok;
    }

    bool FindFieldOffset(
        SymbolEngine& symbols,
        const std::wstring* types,
        size_t typeCount,
        const std::wstring* fields,
        size_t fieldCount,
        uint32_t* offset,
        std::wstring* error)
    {
        bool ok = false;
        do
        {
            if (offset == nullptr || types == nullptr || fields == nullptr)
            {
                break;
            }
            for (size_t typeIndex = 0; typeIndex < typeCount && !ok; ++typeIndex)
            {
                for (size_t fieldIndex = 0; fieldIndex < fieldCount; ++fieldIndex)
                {
                    TypeFieldInfo field = {};
                    std::wstring ignored;
                    if (symbols.FindField(types[typeIndex], fields[fieldIndex], &field, &ignored))
                    {
                        *offset = field.Offset;
                        ok = true;
                        break;
                    }
                }
            }
            if (!ok && error != nullptr)
            {
                *error = L"missing field " + fields[0] + L" on " + types[0];
            }
        } while (false);
        return ok;
    }

    bool BuildLayout(SymbolEngine& symbols, MinifilterLayout* layout, std::wstring* error)
    {
        bool ok = false;
        do
        {
            if (layout == nullptr)
            {
                break;
            }
            *layout = MinifilterLayout{};

            const std::wstring globalsTypes[] = { L"fltmgr!_GLOBALS", L"_GLOBALS" };
            const std::wstring frameTypes[] = { L"fltmgr!_FLTP_FRAME", L"_FLTP_FRAME" };
            const std::wstring filterTypes[] = { L"fltmgr!_FLT_FILTER", L"_FLT_FILTER" };
            const std::wstring objectTypes[] = { L"fltmgr!_FLT_OBJECT", L"_FLT_OBJECT" };
            const std::wstring resourceTypes[] =
            {
                L"fltmgr!_FLT_RESOURCE_LIST_HEAD",
                L"_FLT_RESOURCE_LIST_HEAD"
            };
            const std::wstring operationTypes[] =
            {
                L"fltmgr!_FLT_OPERATION_REGISTRATION",
                L"_FLT_OPERATION_REGISTRATION"
            };

            const std::wstring frameListNames[] = { L"FrameList" };
            const std::wstring resourceListNames[] = { L"rList", L"List", L"ListHead" };
            const std::wstring linksNames[] = { L"Links" };
            const std::wstring frameIdNames[] = { L"FrameID", L"FrameId" };
            const std::wstring registeredNames[] = { L"RegisteredFilters", L"FilterList" };
            const std::wstring baseNames[] = { L"Base" };
            const std::wstring nameNames[] = { L"Name" };
            const std::wstring altitudeNames[] = { L"DefaultAltitude", L"Altitude" };
            const std::wstring flagsNames[] = { L"Flags" };
            const std::wstring driverNames[] = { L"DriverObject" };
            const std::wstring operationsNames[] = { L"Operations" };
            const std::wstring primaryNames[] = { L"PrimaryLink", L"Links" };
            const std::wstring majorNames[] = { L"MajorFunction" };
            const std::wstring preNames[] = { L"PreOperation" };
            const std::wstring postNames[] = { L"PostOperation" };

            if (!FindFieldOffset(symbols, globalsTypes, 2, frameListNames, 1, &layout->GlobalsFrameList, error) ||
                !FindFieldOffset(symbols, resourceTypes, 2, resourceListNames, 3, &layout->ResourceList, error) ||
                !FindFieldOffset(symbols, frameTypes, 2, linksNames, 1, &layout->FrameLinks, error) ||
                !FindFieldOffset(symbols, frameTypes, 2, frameIdNames, 2, &layout->FrameId, error) ||
                !FindFieldOffset(symbols, frameTypes, 2, registeredNames, 2, &layout->FrameRegisteredFilters, error) ||
                !FindFieldOffset(symbols, filterTypes, 2, baseNames, 1, &layout->FilterBase, error) ||
                !FindFieldOffset(symbols, filterTypes, 2, nameNames, 1, &layout->FilterName, error) ||
                !FindFieldOffset(symbols, filterTypes, 2, altitudeNames, 2, &layout->FilterAltitude, error) ||
                !FindFieldOffset(symbols, filterTypes, 2, flagsNames, 1, &layout->FilterFlags, error) ||
                !FindFieldOffset(symbols, filterTypes, 2, driverNames, 1, &layout->FilterDriverObject, error) ||
                !FindFieldOffset(symbols, filterTypes, 2, operationsNames, 1, &layout->FilterOperations, error) ||
                !FindFieldOffset(symbols, objectTypes, 2, primaryNames, 2, &layout->ObjectPrimaryLink, error) ||
                !FindFieldOffset(symbols, operationTypes, 2, majorNames, 1, &layout->OperationMajor, error) ||
                !FindFieldOffset(symbols, operationTypes, 2, flagsNames, 1, &layout->OperationFlags, error) ||
                !FindFieldOffset(symbols, operationTypes, 2, preNames, 1, &layout->OperationPre, error) ||
                !FindFieldOffset(symbols, operationTypes, 2, postNames, 1, &layout->OperationPost, error))
            {
                break;
            }

            TypeLayoutInfo operationLayout = {};
            std::wstring layoutError;
            if (symbols.GetTypeLayout(L"fltmgr!_FLT_OPERATION_REGISTRATION", &operationLayout, &layoutError) ||
                symbols.GetTypeLayout(L"_FLT_OPERATION_REGISTRATION", &operationLayout, &layoutError))
            {
                layout->OperationSize = static_cast<uint32_t>(operationLayout.Size);
            }
            if (layout->OperationSize < 24 || layout->OperationSize > 128)
            {
                if (error != nullptr)
                {
                    *error = L"unexpected _FLT_OPERATION_REGISTRATION size";
                }
                break;
            }

            TypeFieldInfo driverStart = {};
            std::wstring ignored;
            if (symbols.FindField(L"nt!_DRIVER_OBJECT", L"DriverStart", &driverStart, &ignored))
            {
                layout->DriverStart = driverStart.Offset;
                layout->HasDriverStart = true;
            }

            ok = true;
        } while (false);
        return ok;
    }

    void Annotate(
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
        if (address == 0 || !LeftoverIsKernelCanonical(address))
        {
            return;
        }

        for (const KernelModuleInfo& module : symbols.Modules())
        {
            uint64_t end = 0;
            if (!LeftoverTryAdd(module.Base, module.Size, &end))
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
        if (symbolName != nullptr &&
            symbols.FindNearestSymbol(address, &nearest, &displacement, &ignored) &&
            !nearest.empty())
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

    bool ReadOperationSlot(
        DeviceClient& device,
        SymbolEngine& symbols,
        const MinifilterLayout& layout,
        uint64_t operations,
        uint32_t index,
        MinifilterIrpSlot* slot)
    {
        bool ok = false;
        do
        {
            if (slot == nullptr)
            {
                break;
            }
            *slot = MinifilterIrpSlot{};
            uint64_t entry = 0;
            if (!LeftoverTryAdd(operations, static_cast<uint64_t>(index) * layout.OperationSize, &entry))
            {
                break;
            }

            uint64_t majorAddr = 0;
            if (!LeftoverTryAdd(entry, layout.OperationMajor, &majorAddr))
            {
                break;
            }
            uint8_t major = 0;
            std::vector<uint8_t> majorBytes;
            if (!device.ReadMemory(majorAddr, 1, &majorBytes, nullptr) || majorBytes.size() != 1)
            {
                break;
            }
            major = majorBytes[0];
            if (major == kIrpMjOperationEnd)
            {
                slot->MajorFunction = kIrpMjOperationEnd;
                slot->MajorName = MinifilterIrpMajorName(kIrpMjOperationEnd);
                ok = true;
                break;
            }

            uint64_t flags = 0;
            uint64_t pre = 0;
            uint64_t post = 0;
            uint64_t flagsAddr = 0;
            uint64_t preAddr = 0;
            uint64_t postAddr = 0;
            if (LeftoverTryAdd(entry, layout.OperationFlags, &flagsAddr))
            {
                uint32_t flags32 = 0;
                if (LeftoverReadU32(device, flagsAddr, &flags32, nullptr))
                {
                    flags = flags32;
                }
            }
            if (LeftoverTryAdd(entry, layout.OperationPre, &preAddr))
            {
                LeftoverReadU64(device, preAddr, &pre, nullptr);
            }
            if (LeftoverTryAdd(entry, layout.OperationPost, &postAddr))
            {
                LeftoverReadU64(device, postAddr, &post, nullptr);
            }

            slot->Index = index;
            slot->MajorFunction = major;
            slot->MajorName = MinifilterIrpMajorName(major);
            slot->Flags = static_cast<uint32_t>(flags);
            slot->Entry = entry;
            slot->Pre = LeftoverIsKernelCanonical(pre) ? pre : 0;
            slot->Post = LeftoverIsKernelCanonical(post) ? post : 0;
            slot->PreActive = slot->Pre != 0;
            slot->PostActive = slot->Post != 0;
            slot->Disabled = !slot->PreActive && !slot->PostActive;
            Annotate(symbols, slot->Pre, &slot->PreModule, &slot->PreSymbol);
            Annotate(symbols, slot->Post, &slot->PostModule, &slot->PostSymbol);
            ok = true;
        } while (false);
        return ok;
    }

    bool ReadFilterOperations(
        DeviceClient& device,
        SymbolEngine& symbols,
        const MinifilterLayout& layout,
        MinifilterFilterRecord* filter)
    {
        bool ok = false;
        do
        {
            if (filter == nullptr)
            {
                break;
            }
            filter->OperationsTable.clear();
            filter->OperationCount = 0;
            filter->ActiveOperationCount = 0;
            if (filter->Operations == 0 || !LeftoverIsKernelCanonical(filter->Operations))
            {
                ok = true;
                break;
            }

            for (uint32_t index = 0; index < kMaxOperations; ++index)
            {
                MinifilterIrpSlot slot = {};
                if (!ReadOperationSlot(device, symbols, layout, filter->Operations, index, &slot))
                {
                    break;
                }
                if (slot.MajorFunction == kIrpMjOperationEnd)
                {
                    break;
                }
                ++filter->OperationCount;
                if (!slot.Disabled)
                {
                    ++filter->ActiveOperationCount;
                }
                filter->OperationsTable.push_back(slot);
            }
            ok = true;
        } while (false);
        return ok;
    }

    bool ReadUnicodeField(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t object,
        uint32_t offset,
        std::wstring* value)
    {
        bool ok = false;
        do
        {
            if (value == nullptr)
            {
                break;
            }
            value->clear();
            uint64_t field = 0;
            if (!LeftoverTryAdd(object, offset, &field))
            {
                break;
            }
            ok = LeftoverReadUnicodeString(device, symbols, field, value, nullptr);
        } while (false);
        return ok;
    }

    bool EnumerateFilters(
        DeviceClient& device,
        SymbolEngine& symbols,
        const MinifilterLayout& layout,
        uint64_t fltGlobals,
        MinifilterIrpScanResult* result,
        std::wstring* error)
    {
        bool ok = false;
        do
        {
            if (result == nullptr)
            {
                break;
            }

            uint64_t frameList = 0;
            uint64_t frameHead = 0;
            if (!LeftoverTryAdd(fltGlobals, layout.GlobalsFrameList, &frameList) ||
                !LeftoverTryAdd(frameList, layout.ResourceList, &frameHead))
            {
                if (error != nullptr)
                {
                    *error = L"minifilter frame list address overflow";
                }
                break;
            }

            uint64_t frameFlink = 0;
            uint64_t frameBlink = 0;
            if (!ReadListEntry(device, frameHead, &frameFlink, &frameBlink))
            {
                if (error != nullptr)
                {
                    *error = L"failed to read minifilter frame list head";
                }
                break;
            }
            if (frameFlink == frameHead)
            {
                result->CoverageComplete = true;
                result->CoverageNotes.push_back(L"minifilter frame list is empty");
                ok = true;
                break;
            }

            std::set<uint64_t> seenFrames;
            std::set<uint64_t> seenFilters;
            uint64_t frameLink = frameFlink;
            for (uint32_t frameIndex = 0;
                 frameIndex < kMaxFrames &&
                     frameLink != 0 &&
                     frameLink != frameHead;
                 ++frameIndex)
            {
                if (!LeftoverIsKernelCanonical(frameLink) || !seenFrames.insert(frameLink).second)
                {
                    result->Warnings.push_back(L"minifilter frame list walk stopped (cycle or non-kernel link)");
                    break;
                }

                uint64_t nextFrame = 0;
                uint64_t ignoredBlink = 0;
                if (!ReadListEntry(device, frameLink, &nextFrame, &ignoredBlink))
                {
                    break;
                }

                uint64_t frame = 0;
                if (!LeftoverTryAdd(frameLink, 0, &frame))
                {
                    frameLink = nextFrame;
                    continue;
                }
                // Links is inside the frame; subtract the field offset.
                if (layout.FrameLinks > frameLink)
                {
                    frameLink = nextFrame;
                    continue;
                }
                frame = frameLink - layout.FrameLinks;
                if (!LeftoverIsKernelCanonical(frame))
                {
                    frameLink = nextFrame;
                    continue;
                }

                uint32_t frameId = 0;
                uint64_t frameIdAddr = 0;
                if (LeftoverTryAdd(frame, layout.FrameId, &frameIdAddr))
                {
                    LeftoverReadU32(device, frameIdAddr, &frameId, nullptr);
                }

                uint64_t registered = 0;
                uint64_t filterHead = 0;
                if (!LeftoverTryAdd(frame, layout.FrameRegisteredFilters, &registered) ||
                    !LeftoverTryAdd(registered, layout.ResourceList, &filterHead))
                {
                    frameLink = nextFrame;
                    continue;
                }

                uint64_t filterFlink = 0;
                uint64_t filterBlink = 0;
                if (!ReadListEntry(device, filterHead, &filterFlink, &filterBlink))
                {
                    frameLink = nextFrame;
                    continue;
                }

                uint64_t filterLink = filterFlink;
                for (uint32_t filterIndex = 0;
                     filterIndex < kMaxFilters &&
                         filterLink != 0 &&
                         filterLink != filterHead;
                     ++filterIndex)
                {
                    if (!LeftoverIsKernelCanonical(filterLink) || !seenFilters.insert(filterLink).second)
                    {
                        result->Warnings.push_back(L"minifilter filter list walk stopped (cycle or non-kernel link)");
                        break;
                    }

                    uint64_t nextFilter = 0;
                    uint64_t filterBlink2 = 0;
                    if (!ReadListEntry(device, filterLink, &nextFilter, &filterBlink2))
                    {
                        break;
                    }

                    const uint64_t primaryOffset =
                        static_cast<uint64_t>(layout.FilterBase) + layout.ObjectPrimaryLink;
                    if (primaryOffset > filterLink)
                    {
                        filterLink = nextFilter;
                        continue;
                    }
                    const uint64_t filterAddress = filterLink - primaryOffset;
                    if (!LeftoverIsKernelCanonical(filterAddress))
                    {
                        filterLink = nextFilter;
                        continue;
                    }

                    MinifilterFilterRecord filter = {};
                    filter.Frame = frame;
                    filter.FrameId = frameId;
                    filter.Filter = filterAddress;
                    ReadUnicodeField(device, symbols, filterAddress, layout.FilterName, &filter.Name);
                    ReadUnicodeField(device, symbols, filterAddress, layout.FilterAltitude, &filter.Altitude);
                    uint64_t flagsAddr = 0;
                    if (LeftoverTryAdd(filterAddress, layout.FilterFlags, &flagsAddr))
                    {
                        LeftoverReadU32(device, flagsAddr, &filter.Flags, nullptr);
                    }
                    uint64_t driverAddr = 0;
                    if (LeftoverTryAdd(filterAddress, layout.FilterDriverObject, &driverAddr))
                    {
                        LeftoverReadU64(device, driverAddr, &filter.DriverObject, nullptr);
                    }
                    uint64_t opsAddr = 0;
                    if (LeftoverTryAdd(filterAddress, layout.FilterOperations, &opsAddr))
                    {
                        LeftoverReadU64(device, opsAddr, &filter.Operations, nullptr);
                    }
                    if (layout.HasDriverStart && LeftoverIsKernelCanonical(filter.DriverObject))
                    {
                        uint64_t startAddr = 0;
                        if (LeftoverTryAdd(filter.DriverObject, layout.DriverStart, &startAddr))
                        {
                            LeftoverReadU64(device, startAddr, &filter.DriverStart, nullptr);
                            Annotate(symbols, filter.DriverStart, &filter.DriverModule, nullptr);
                        }
                    }
                    filter.WellKnownInbox = MinifilterIrpNameLooksInbox(filter.Name);
                    if (filter.WellKnownInbox)
                    {
                        LeftoverAppendNote(&filter.Notes, L"well-known inbox filter");
                    }
                    ReadFilterOperations(device, symbols, layout, &filter);
                    result->Filters.push_back(filter);
                    filterLink = nextFilter;
                }

                frameLink = nextFrame;
            }

            result->CoverageComplete = true;
            ok = true;
        } while (false);
        return ok;
    }

    bool FilterMatchesSpecifier(const MinifilterFilterRecord& filter, const std::wstring& specifier)
    {
        bool match = false;
        do
        {
            if (specifier.empty())
            {
                break;
            }

            uint64_t address = 0;
            std::wstring parseError;
            // Bare hex / 0x addresses select a filter object exactly.
            if ((specifier.size() >= 2 && specifier[0] == L'0' && (specifier[1] == L'x' || specifier[1] == L'X')) ||
                specifier.find_first_not_of(L"0123456789abcdefABCDEF`") == std::wstring::npos)
            {
                wchar_t* end = nullptr;
                std::wstring hex = specifier;
                if (hex.size() >= 2 && hex[0] == L'0' && (hex[1] == L'x' || hex[1] == L'X'))
                {
                    hex = hex.substr(2);
                }
                hex.erase(std::remove(hex.begin(), hex.end(), L'`'), hex.end());
                address = wcstoull(hex.c_str(), &end, 16);
                if (end != nullptr && *end == L'\0' && address != 0)
                {
                    match = (filter.Filter == address) || (filter.Operations == address);
                    break;
                }
            }

            const std::wstring wanted = ToLowerCopy(LeftoverModuleBaseName(specifier));
            const std::wstring name = ToLowerCopy(LeftoverModuleBaseName(filter.Name));
            const std::wstring module = ToLowerCopy(LeftoverModuleBaseName(filter.DriverModule));
            if (!wanted.empty() && (name == wanted || module == wanted))
            {
                match = true;
                break;
            }
            if (!wanted.empty() &&
                ((name.find(wanted) != std::wstring::npos) ||
                 (module.find(wanted) != std::wstring::npos)))
            {
                match = true;
            }
        } while (false);
        return match;
    }

    bool SelectFilter(
        const MinifilterIrpScanResult& scan,
        const std::wstring& specifier,
        MinifilterFilterRecord* selected,
        std::wstring* error)
    {
        bool ok = false;
        do
        {
            if (selected == nullptr)
            {
                break;
            }
            std::vector<const MinifilterFilterRecord*> hits;
            for (const MinifilterFilterRecord& filter : scan.Filters)
            {
                if (FilterMatchesSpecifier(filter, specifier))
                {
                    hits.push_back(&filter);
                }
            }
            if (hits.empty())
            {
                if (error != nullptr)
                {
                    *error = L"no minifilter matched \"" + specifier + L"\"";
                }
                break;
            }
            if (hits.size() > 1)
            {
                if (error != nullptr)
                {
                    std::wstringstream stream;
                    stream << L"filter specifier \"" << specifier << L"\" is ambiguous ("
                           << hits.size() << L" matches):";
                    for (const MinifilterFilterRecord* hit : hits)
                    {
                        stream << L" " << (hit->Name.empty() ? L"<unnamed>" : hit->Name)
                               << L"@" << LeftoverFormatHex(hit->Filter, 16);
                    }
                    *error = stream.str();
                }
                break;
            }
            *selected = *hits[0];
            ok = true;
        } while (false);
        return ok;
    }

    bool WritePointer(
        DeviceClient& device,
        uint64_t address,
        uint64_t value,
        std::wstring* error)
    {
        bool ok = false;
        do
        {
            std::vector<uint8_t> bytes(sizeof(uint64_t));
            memcpy(bytes.data(), &value, sizeof(uint64_t));
            if (!device.WriteMemory(address, bytes, error))
            {
                break;
            }
            uint64_t readBack = 0;
            if (!LeftoverReadU64(device, address, &readBack, error))
            {
                break;
            }
            if (readBack != value)
            {
                if (error != nullptr)
                {
                    *error = L"write verify failed at " + LeftoverFormatHex(address, 16) +
                             L" expected=" + LeftoverFormatHex(value, 16) +
                             L" read=" + LeftoverFormatHex(readBack, 16);
                }
                break;
            }
            ok = true;
        } while (false);
        return ok;
    }

    bool WriteModeEnabled(DeviceClient& device, std::wstring* error)
    {
        bool enabled = false;
        DriverSessionStatus session = {};
        if (!device.QuerySessionStatus(&session, error))
        {
            return false;
        }
        enabled = (session.Flags & KNDBG_SESSION_FLAG_WRITE_ENABLED) != 0;
        if (!enabled && error != nullptr)
        {
            *error = L"write mode is off; run 'write on' before changing minifilter IRP handlers";
        }
        return enabled;
    }
}

std::wstring MinifilterIrpMajorName(uint32_t majorFunction)
{
    std::wstring name;
    switch (majorFunction)
    {
    case 0x00: name = L"IRP_MJ_CREATE"; break;
    case 0x01: name = L"IRP_MJ_CREATE_NAMED_PIPE"; break;
    case 0x02: name = L"IRP_MJ_CLOSE"; break;
    case 0x03: name = L"IRP_MJ_READ"; break;
    case 0x04: name = L"IRP_MJ_WRITE"; break;
    case 0x05: name = L"IRP_MJ_QUERY_INFORMATION"; break;
    case 0x06: name = L"IRP_MJ_SET_INFORMATION"; break;
    case 0x07: name = L"IRP_MJ_QUERY_EA"; break;
    case 0x08: name = L"IRP_MJ_SET_EA"; break;
    case 0x09: name = L"IRP_MJ_FLUSH_BUFFERS"; break;
    case 0x0a: name = L"IRP_MJ_QUERY_VOLUME_INFORMATION"; break;
    case 0x0b: name = L"IRP_MJ_SET_VOLUME_INFORMATION"; break;
    case 0x0c: name = L"IRP_MJ_DIRECTORY_CONTROL"; break;
    case 0x0d: name = L"IRP_MJ_FILE_SYSTEM_CONTROL"; break;
    case 0x0e: name = L"IRP_MJ_DEVICE_CONTROL"; break;
    case 0x0f: name = L"IRP_MJ_INTERNAL_DEVICE_CONTROL"; break;
    case 0x10: name = L"IRP_MJ_SHUTDOWN"; break;
    case 0x11: name = L"IRP_MJ_LOCK_CONTROL"; break;
    case 0x12: name = L"IRP_MJ_CLEANUP"; break;
    case 0x13: name = L"IRP_MJ_CREATE_MAILSLOT"; break;
    case 0x14: name = L"IRP_MJ_QUERY_SECURITY"; break;
    case 0x15: name = L"IRP_MJ_SET_SECURITY"; break;
    case 0x16: name = L"IRP_MJ_POWER"; break;
    case 0x17: name = L"IRP_MJ_SYSTEM_CONTROL"; break;
    case 0x18: name = L"IRP_MJ_DEVICE_CHANGE"; break;
    case 0x19: name = L"IRP_MJ_QUERY_QUOTA"; break;
    case 0x1a: name = L"IRP_MJ_SET_QUOTA"; break;
    case 0x1b: name = L"IRP_MJ_PNP"; break;
    case 0x80: name = L"IRP_MJ_OPERATION_END"; break;
    case 0xff: name = L"IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION"; break;
    case 0xfe: name = L"IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION"; break;
    case 0xfd: name = L"IRP_MJ_ACQUIRE_FOR_MOD_WRITE"; break;
    case 0xfc: name = L"IRP_MJ_RELEASE_FOR_MOD_WRITE"; break;
    case 0xfb: name = L"IRP_MJ_ACQUIRE_FOR_CC_FLUSH"; break;
    case 0xfa: name = L"IRP_MJ_RELEASE_FOR_CC_FLUSH"; break;
    case 0xf9: name = L"IRP_MJ_QUERY_OPEN"; break;
    case 0xf3: name = L"IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE"; break;
    case 0xf2: name = L"IRP_MJ_NETWORK_QUERY_OPEN"; break;
    case 0xf1: name = L"IRP_MJ_MDL_READ"; break;
    case 0xf0: name = L"IRP_MJ_MDL_READ_COMPLETE"; break;
    case 0xef: name = L"IRP_MJ_PREPARE_MDL_WRITE"; break;
    case 0xee: name = L"IRP_MJ_MDL_WRITE_COMPLETE"; break;
    case 0xed: name = L"IRP_MJ_VOLUME_MOUNT"; break;
    case 0xec: name = L"IRP_MJ_VOLUME_DISMOUNT"; break;
    default:
        {
            std::wstringstream stream;
            stream << L"IRP_MJ_0x" << std::hex << std::uppercase << majorFunction;
            name = stream.str();
        }
        break;
    }
    return name;
}

bool IsMinifilterIrpAllToken(const std::wstring& text)
{
    std::wstring raw = ToLowerCopy(text);
    while (!raw.empty() && (raw.back() == L' ' || raw.back() == L'\t'))
    {
        raw.pop_back();
    }
    if (raw.rfind(L"irp_mj_", 0) == 0)
    {
        raw = raw.substr(7);
    }
    else if (raw.rfind(L"mj_", 0) == 0)
    {
        raw = raw.substr(3);
    }
    return raw == L"all" || raw == L"*" || raw == L"every";
}

bool IsMinifilterWriteAction(const std::wstring& text)
{
    const std::wstring raw = ToLowerCopy(text);
    return raw == L"disable" ||
           raw == L"enable" ||
           raw == L"disable-all" ||
           raw == L"enable-all";
}

bool ParseMinifilterIrpMajor(const std::wstring& text, uint32_t* majorFunction, std::wstring* error)
{
    bool ok = false;
    do
    {
        if (majorFunction == nullptr)
        {
            break;
        }
        std::wstring raw = ToLowerCopy(text);
        while (!raw.empty() && (raw.back() == L' ' || raw.back() == L'\t'))
        {
            raw.pop_back();
        }
        if (raw.rfind(L"irp_mj_", 0) == 0)
        {
            raw = raw.substr(7);
        }
        else if (raw.rfind(L"mj_", 0) == 0)
        {
            raw = raw.substr(3);
        }

        struct Alias
        {
            const wchar_t* Name;
            uint32_t Value;
        };
        const Alias aliases[] =
        {
            { L"create", 0x00 },
            { L"create_named_pipe", 0x01 },
            { L"close", 0x02 },
            { L"read", 0x03 },
            { L"write", 0x04 },
            { L"query_information", 0x05 },
            { L"queryinformation", 0x05 },
            { L"set_information", 0x06 },
            { L"setinformation", 0x06 },
            { L"query_ea", 0x07 },
            { L"set_ea", 0x08 },
            { L"flush_buffers", 0x09 },
            { L"query_volume_information", 0x0a },
            { L"set_volume_information", 0x0b },
            { L"directory_control", 0x0c },
            { L"directory", 0x0c },
            { L"dir", 0x0c },
            { L"file_system_control", 0x0d },
            { L"fsctl", 0x0d },
            { L"device_control", 0x0e },
            { L"ioctl", 0x0e },
            { L"internal_device_control", 0x0f },
            { L"shutdown", 0x10 },
            { L"lock_control", 0x11 },
            { L"cleanup", 0x12 },
            { L"create_mailslot", 0x13 },
            { L"query_security", 0x14 },
            { L"set_security", 0x15 },
            { L"power", 0x16 },
            { L"system_control", 0x17 },
            { L"device_change", 0x18 },
            { L"query_quota", 0x19 },
            { L"set_quota", 0x1a },
            { L"pnp", 0x1b },
            { L"acquire_for_section_synchronization", 0xff },
            { L"section_sync", 0xff },
            { L"release_for_section_synchronization", 0xfe },
            { L"acquire_for_mod_write", 0xfd },
            { L"release_for_mod_write", 0xfc },
            { L"acquire_for_cc_flush", 0xfb },
            { L"release_for_cc_flush", 0xfa },
            { L"query_open", 0xf9 },
            { L"fast_io_check_if_possible", 0xf3 },
            { L"network_query_open", 0xf2 },
            { L"mdl_read", 0xf1 },
            { L"mdl_read_complete", 0xf0 },
            { L"prepare_mdl_write", 0xef },
            { L"mdl_write_complete", 0xee },
            { L"volume_mount", 0xed },
            { L"volume_dismount", 0xec }
        };

        for (const Alias& alias : aliases)
        {
            if (raw == alias.Name)
            {
                *majorFunction = alias.Value;
                ok = true;
                break;
            }
        }
        if (ok)
        {
            break;
        }

        uint64_t parsed = 0;
        std::wstring number = raw;
        uint32_t base = 10;
        if (number.size() >= 2 && number[0] == L'0' && number[1] == L'x')
        {
            number = number.substr(2);
            base = 16;
        }
        else if (number.size() >= 2 && number[0] == L'0' && number[1] == L'n')
        {
            number = number.substr(2);
            base = 10;
        }
        wchar_t* end = nullptr;
        parsed = wcstoull(number.c_str(), &end, static_cast<int>(base));
        if (end == nullptr || *end != L'\0' || parsed > 0xffull)
        {
            if (error != nullptr)
            {
                *error = L"unrecognised IRP major \"" + text + L"\"";
            }
            break;
        }
        *majorFunction = static_cast<uint32_t>(parsed);
        ok = true;
    } while (false);
    return ok;
}

bool MinifilterIrpNameLooksInbox(const std::wstring& name)
{
    const std::wstring lower = ToLowerCopy(LeftoverModuleBaseName(name));
    const wchar_t* known[] =
    {
        L"wdfilter",
        L"fileinfo",
        L"luafv",
        L"npsvctrig",
        L"filecrypt",
        L"bindflt",
        L"storqosflt",
        L"cldflt",
        L"wcifs",
        L"fsdepends",
        L"rdyboost",
        L"wof",
        L"overlay",
        L"csvfs",
        L"refs",
        L"ntfs",
        L"fastfat",
        L"exfat",
        L"udfs",
        L"cdfs",
        L"fltmgr"
    };
    for (const wchar_t* item : known)
    {
        if (lower == item || lower == (std::wstring(item) + L".sys"))
        {
            return true;
        }
    }
    return false;
}

MinifilterIrpScanner::MinifilterIrpScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool MinifilterIrpScanner::Scan(MinifilterIrpScanResult* result, std::wstring* error)
{
    bool ok = false;
    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"minifilter scan output is null";
            }
            break;
        }
        *result = MinifilterIrpScanResult{};
        if (symbols_.Modules().empty())
        {
            std::wstring loadError;
            if (!symbols_.LoadKernelModules(&loadError))
            {
                if (error != nullptr)
                {
                    *error = loadError;
                }
                break;
            }
        }

        MinifilterLayout layout = {};
        if (!BuildLayout(symbols_, &layout, error))
        {
            break;
        }
        result->LayoutFromPdb = true;

        const std::wstring symbolsToTry[] =
        {
            L"fltmgr!FltGlobals",
            L"fltmgr!FltGlobalData"
        };
        uint64_t fltGlobals = 0;
        for (const std::wstring& name : symbolsToTry)
        {
            std::wstring ignored;
            if (symbols_.ResolveSymbol(name, &fltGlobals, &ignored) &&
                LeftoverIsKernelCanonical(fltGlobals))
            {
                result->FltGlobalsSymbol = name;
                break;
            }
            fltGlobals = 0;
        }
        if (fltGlobals == 0)
        {
            if (error != nullptr)
            {
                *error = L"fltmgr!FltGlobals was not resolved";
            }
            result->CoverageNotes.push_back(L"minifilter coverage is absent without FltGlobals");
            break;
        }
        result->FltGlobals = fltGlobals;

        if (!EnumerateFilters(device_, symbols_, layout, fltGlobals, result, error))
        {
            break;
        }
        ok = true;
    } while (false);
    return ok;
}

bool MinifilterIrpScanner::Show(
    const std::wstring& specifier,
    MinifilterFilterRecord* filter,
    MinifilterIrpScanResult* result,
    std::wstring* error)
{
    bool ok = false;
    do
    {
        MinifilterIrpScanResult local = {};
        if (!Scan(&local, error))
        {
            if (result != nullptr)
            {
                *result = local;
            }
            break;
        }
        if (result != nullptr)
        {
            *result = local;
        }
        if (!SelectFilter(local, specifier, filter, error))
        {
            break;
        }
        ok = true;
    } while (false);
    return ok;
}

bool MinifilterIrpScanner::SetIrp(
    const std::wstring& specifier,
    uint32_t majorFunction,
    MinifilterIrpAction action,
    MinifilterIrpWhich which,
    MinifilterIrpChange* change,
    MinifilterIrpScanResult* result,
    std::wstring* error)
{
    bool ok = false;
    do
    {
        if (change == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"minifilter IRP change output is null";
            }
            break;
        }
        *change = MinifilterIrpChange{};
        if (majorFunction == kIrpMjOperationEnd)
        {
            if (error != nullptr)
            {
                *error = L"refusing to mutate IRP_MJ_OPERATION_END";
            }
            break;
        }
        if (action != MinifilterIrpAction::Status && !WriteModeEnabled(device_, error))
        {
            break;
        }

        MinifilterFilterRecord filter = {};
        if (!Show(specifier, &filter, result, error))
        {
            break;
        }

        const MinifilterIrpSlot* found = nullptr;
        for (const MinifilterIrpSlot& slot : filter.OperationsTable)
        {
            if (slot.MajorFunction == majorFunction)
            {
                found = &slot;
                break;
            }
        }
        if (found == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"filter " + (filter.Name.empty() ? LeftoverFormatHex(filter.Filter, 16) : filter.Name) +
                         L" has no " + MinifilterIrpMajorName(majorFunction) + L" registration";
            }
            break;
        }

        change->Filter = filter.Filter;
        change->FilterName = filter.Name;
        change->WellKnownInbox = filter.WellKnownInbox;
        change->Before = *found;
        change->After = *found;

        if (action == MinifilterIrpAction::Status)
        {
            ok = true;
            break;
        }

        MinifilterLayout layout = {};
        if (!BuildLayout(symbols_, &layout, error))
        {
            break;
        }

        uint64_t preAddr = 0;
        uint64_t postAddr = 0;
        if (!LeftoverTryAdd(found->Entry, layout.OperationPre, &preAddr) ||
            !LeftoverTryAdd(found->Entry, layout.OperationPost, &postAddr))
        {
            if (error != nullptr)
            {
                *error = L"operation slot field address overflow";
            }
            break;
        }

        const bool touchPre = (which == MinifilterIrpWhich::Both || which == MinifilterIrpWhich::Pre);
        const bool touchPost = (which == MinifilterIrpWhich::Both || which == MinifilterIrpWhich::Post);
        uint64_t newPre = found->Pre;
        uint64_t newPost = found->Post;

        if (action == MinifilterIrpAction::Disable)
        {
            IrpBackupKey key = {};
            key.Filter = filter.Filter;
            key.MajorFunction = majorFunction;
            IrpBackupValue value = {};
            value.Pre = found->Pre;
            value.Post = found->Post;
            value.FilterName = filter.Name;
            {
                std::lock_guard<std::mutex> guard(g_BackupLock);
                auto existing = g_Backups.find(key);
                if (existing == g_Backups.end())
                {
                    g_Backups[key] = value;
                }
                else
                {
                    if (existing->second.Pre == 0 && value.Pre != 0)
                    {
                        existing->second.Pre = value.Pre;
                    }
                    if (existing->second.Post == 0 && value.Post != 0)
                    {
                        existing->second.Post = value.Post;
                    }
                }
            }
            if (touchPre)
            {
                newPre = 0;
            }
            if (touchPost)
            {
                newPost = 0;
            }
        }
        else
        {
            IrpBackupKey key = {};
            key.Filter = filter.Filter;
            key.MajorFunction = majorFunction;
            IrpBackupValue value = {};
            bool haveBackup = false;
            {
                std::lock_guard<std::mutex> guard(g_BackupLock);
                auto existing = g_Backups.find(key);
                if (existing != g_Backups.end())
                {
                    value = existing->second;
                    haveBackup = true;
                }
            }
            if (!haveBackup)
            {
                if (error != nullptr)
                {
                    *error = L"no saved pre/post for " +
                             (filter.Name.empty() ? LeftoverFormatHex(filter.Filter, 16) : filter.Name) +
                             L" " + MinifilterIrpMajorName(majorFunction) +
                             L"; enable only works after a disable in this session";
                }
                break;
            }
            change->UsedBackup = true;
            if (touchPre)
            {
                newPre = value.Pre;
            }
            if (touchPost)
            {
                newPost = value.Post;
            }
        }

        if (touchPre && newPre != found->Pre)
        {
            if (!WritePointer(device_, preAddr, newPre, error))
            {
                break;
            }
            change->PreChanged = true;
        }
        if (touchPost && newPost != found->Post)
        {
            if (!WritePointer(device_, postAddr, newPost, error))
            {
                break;
            }
            change->PostChanged = true;
        }

        MinifilterIrpSlot after = {};
        if (!ReadOperationSlot(device_, symbols_, layout, filter.Operations, found->Index, &after))
        {
            if (error != nullptr)
            {
                *error = L"failed to re-read operation slot after write";
            }
            break;
        }
        change->After = after;
        ok = true;
    } while (false);
    return ok;
}

bool MinifilterIrpScanner::SetAllIrps(
    const std::wstring& specifier,
    MinifilterIrpAction action,
    MinifilterIrpWhich which,
    MinifilterIrpBatchResult* batch,
    MinifilterIrpScanResult* result,
    std::wstring* error)
{
    bool ok = false;
    do
    {
        if (batch == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"minifilter IRP batch output is null";
            }
            break;
        }
        *batch = MinifilterIrpBatchResult{};
        if (action != MinifilterIrpAction::Disable && action != MinifilterIrpAction::Enable)
        {
            if (error != nullptr)
            {
                *error = L"SetAllIrps requires disable or enable";
            }
            break;
        }

        MinifilterFilterRecord filter = {};
        if (!Show(specifier, &filter, result, error))
        {
            break;
        }
        batch->Filter = filter.Filter;
        batch->FilterName = filter.Name;
        batch->WellKnownInbox = filter.WellKnownInbox;
        if (filter.OperationsTable.empty())
        {
            if (error != nullptr)
            {
                *error = L"filter has no IRP registrations";
            }
            break;
        }

        uint32_t backupHits = 0;
        if (action == MinifilterIrpAction::Enable)
        {
            std::lock_guard<std::mutex> guard(g_BackupLock);
            for (const MinifilterIrpSlot& slot : filter.OperationsTable)
            {
                IrpBackupKey key = {};
                key.Filter = filter.Filter;
                key.MajorFunction = slot.MajorFunction;
                if (g_Backups.find(key) != g_Backups.end())
                {
                    ++backupHits;
                }
            }
            if (backupHits == 0)
            {
                if (error != nullptr)
                {
                    *error = L"no saved IRP handlers for " +
                             (filter.Name.empty() ? LeftoverFormatHex(filter.Filter, 16) : filter.Name) +
                             L"; enable all only works after disable all (or per-IRP disable) in this session";
                }
                break;
            }
        }

        if (!WriteModeEnabled(device_, error))
        {
            break;
        }

        const std::wstring exactFilter = LeftoverFormatHex(filter.Filter, 16);
        bool anyWriteFailed = false;
        for (const MinifilterIrpSlot& slot : filter.OperationsTable)
        {
            ++batch->Attempted;
            if (slot.MajorFunction == kIrpMjOperationEnd)
            {
                ++batch->Skipped;
                continue;
            }
            if (action == MinifilterIrpAction::Enable)
            {
                IrpBackupKey key = {};
                key.Filter = filter.Filter;
                key.MajorFunction = slot.MajorFunction;
                bool haveBackup = false;
                {
                    std::lock_guard<std::mutex> guard(g_BackupLock);
                    haveBackup = g_Backups.find(key) != g_Backups.end();
                }
                if (!haveBackup)
                {
                    ++batch->Skipped;
                    continue;
                }
            }
            else if (action == MinifilterIrpAction::Disable)
            {
                const bool preNeeded = (which == MinifilterIrpWhich::Both || which == MinifilterIrpWhich::Pre);
                const bool postNeeded = (which == MinifilterIrpWhich::Both || which == MinifilterIrpWhich::Post);
                const bool alreadyOff =
                    (!preNeeded || !slot.PreActive) &&
                    (!postNeeded || !slot.PostActive);
                if (alreadyOff)
                {
                    ++batch->Skipped;
                    continue;
                }
            }

            MinifilterIrpChange change = {};
            MinifilterIrpScanResult ignoredScan = {};
            std::wstring slotError;
            if (!SetIrp(exactFilter, slot.MajorFunction, action, which, &change, &ignoredScan, &slotError))
            {
                ++batch->Failed;
                anyWriteFailed = true;
                batch->Failures.push_back(slot.MajorName + L": " + slotError);
                continue;
            }
            if (change.PreChanged || change.PostChanged)
            {
                ++batch->Changed;
            }
            else
            {
                ++batch->Skipped;
            }
            batch->Changes.push_back(change);
        }

        if (anyWriteFailed && batch->Changed == 0)
        {
            if (error != nullptr)
            {
                *error = L"failed to change any IRP handler";
                if (!batch->Failures.empty())
                {
                    *error += L" (" + batch->Failures.front() + L")";
                }
            }
            break;
        }
        ok = true;
    } while (false);
    return ok;
}

std::wstring BuildMinifilterIrpJson(const MinifilterIrpScanResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.minifilter.v1\"";
    out += L",\"fltGlobals\":" + mcpjson::Quote(LeftoverFormatHex(result.FltGlobals, 16));
    out += L",\"fltGlobalsSymbol\":" + mcpjson::Quote(result.FltGlobalsSymbol);
    out += L",\"layoutFromPdb\":";
    out += result.LayoutFromPdb ? L"true" : L"false";
    out += L",\"coverageComplete\":";
    out += result.CoverageComplete ? L"true" : L"false";
    out += L",\"filters\":[";
    for (size_t index = 0; index < result.Filters.size(); ++index)
    {
        const MinifilterFilterRecord& filter = result.Filters[index];
        if (index > 0)
        {
            out += L",";
        }
        out += L"{\"name\":" + mcpjson::Quote(filter.Name);
        out += L",\"altitude\":" + mcpjson::Quote(filter.Altitude);
        out += L",\"filter\":" + mcpjson::Quote(LeftoverFormatHex(filter.Filter, 16));
        out += L",\"frameId\":" + std::to_wstring(filter.FrameId);
        out += L",\"driver\":" + mcpjson::Quote(LeftoverFormatHex(filter.DriverObject, 16));
        out += L",\"driverModule\":" + mcpjson::Quote(filter.DriverModule);
        out += L",\"operations\":" + mcpjson::Quote(LeftoverFormatHex(filter.Operations, 16));
        out += L",\"operationCount\":" + std::to_wstring(filter.OperationCount);
        out += L",\"activeOperationCount\":" + std::to_wstring(filter.ActiveOperationCount);
        out += L",\"wellKnownInbox\":";
        out += filter.WellKnownInbox ? L"true" : L"false";
        out += L",\"slots\":[";
        for (size_t slotIndex = 0; slotIndex < filter.OperationsTable.size(); ++slotIndex)
        {
            const MinifilterIrpSlot& slot = filter.OperationsTable[slotIndex];
            if (slotIndex > 0)
            {
                out += L",";
            }
            out += L"{\"index\":" + std::to_wstring(slot.Index);
            out += L",\"major\":" + std::to_wstring(slot.MajorFunction);
            out += L",\"name\":" + mcpjson::Quote(slot.MajorName);
            out += L",\"pre\":" + mcpjson::Quote(LeftoverFormatHex(slot.Pre, 16));
            out += L",\"post\":" + mcpjson::Quote(LeftoverFormatHex(slot.Post, 16));
            out += L",\"preModule\":" + mcpjson::Quote(slot.PreModule);
            out += L",\"postModule\":" + mcpjson::Quote(slot.PostModule);
            out += L",\"disabled\":";
            out += slot.Disabled ? L"true" : L"false";
            out += L"}";
        }
        out += L"]}";
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

std::wstring BuildMinifilterIrpChangeJson(const MinifilterIrpChange& change)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.minifilter-irp.v1\"";
    out += L",\"filter\":" + mcpjson::Quote(LeftoverFormatHex(change.Filter, 16));
    out += L",\"name\":" + mcpjson::Quote(change.FilterName);
    out += L",\"major\":" + std::to_wstring(change.Before.MajorFunction);
    out += L",\"majorName\":" + mcpjson::Quote(change.Before.MajorName);
    out += L",\"preBefore\":" + mcpjson::Quote(LeftoverFormatHex(change.Before.Pre, 16));
    out += L",\"postBefore\":" + mcpjson::Quote(LeftoverFormatHex(change.Before.Post, 16));
    out += L",\"preAfter\":" + mcpjson::Quote(LeftoverFormatHex(change.After.Pre, 16));
    out += L",\"postAfter\":" + mcpjson::Quote(LeftoverFormatHex(change.After.Post, 16));
    out += L",\"preChanged\":";
    out += change.PreChanged ? L"true" : L"false";
    out += L",\"postChanged\":";
    out += change.PostChanged ? L"true" : L"false";
    out += L",\"usedBackup\":";
    out += change.UsedBackup ? L"true" : L"false";
    out += L",\"wellKnownInbox\":";
    out += change.WellKnownInbox ? L"true" : L"false";
    out += L"}";
    return out;
}

std::wstring BuildMinifilterIrpBatchJson(const MinifilterIrpBatchResult& batch)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.minifilter-irp-batch.v1\"";
    out += L",\"filter\":" + mcpjson::Quote(LeftoverFormatHex(batch.Filter, 16));
    out += L",\"name\":" + mcpjson::Quote(batch.FilterName);
    out += L",\"attempted\":" + std::to_wstring(batch.Attempted);
    out += L",\"changed\":" + std::to_wstring(batch.Changed);
    out += L",\"skipped\":" + std::to_wstring(batch.Skipped);
    out += L",\"failed\":" + std::to_wstring(batch.Failed);
    out += L",\"wellKnownInbox\":";
    out += batch.WellKnownInbox ? L"true" : L"false";
    out += L",\"changes\":[";
    for (size_t index = 0; index < batch.Changes.size(); ++index)
    {
        if (index > 0)
        {
            out += L",";
        }
        out += BuildMinifilterIrpChangeJson(batch.Changes[index]);
    }
    out += L"],\"failures\":[";
    for (size_t index = 0; index < batch.Failures.size(); ++index)
    {
        if (index > 0)
        {
            out += L",";
        }
        out += mcpjson::Quote(batch.Failures[index]);
    }
    out += L"]}";
    return out;
}

bool MinifilterIrpScannerSelfTest()
{
    bool ok = true;
    do
    {
        uint32_t major = 0;
        if (!ParseMinifilterIrpMajor(L"IRP_MJ_CREATE", &major, nullptr) || major != 0)
        {
            ok = false;
            break;
        }
        if (!ParseMinifilterIrpMajor(L"directory_control", &major, nullptr) || major != 0x0c)
        {
            ok = false;
            break;
        }
        if (!ParseMinifilterIrpMajor(L"0x6", &major, nullptr) || major != 6)
        {
            ok = false;
            break;
        }
        if (ParseMinifilterIrpMajor(L"not-an-irp", &major, nullptr))
        {
            ok = false;
            break;
        }
        if (!IsMinifilterIrpAllToken(L"all") ||
            !IsMinifilterIrpAllToken(L"*") ||
            !IsMinifilterIrpAllToken(L"every") ||
            !IsMinifilterIrpAllToken(L"IRP_MJ_ALL") ||
            IsMinifilterIrpAllToken(L"CREATE") ||
            !IsMinifilterWriteAction(L"disable-all") ||
            !IsMinifilterWriteAction(L"ENABLE") ||
            IsMinifilterWriteAction(L"show"))
        {
            ok = false;
            break;
        }
        {
            MinifilterIrpBatchResult batch = {};
            batch.FilterName = L"UnionFS";
            batch.Attempted = 2;
            batch.Changed = 1;
            batch.Skipped = 1;
            const std::wstring json = BuildMinifilterIrpBatchJson(batch);
            if (json.find(L"kn-live-dbg.minifilter-irp-batch.v1") == std::wstring::npos ||
                json.find(L"\"changed\":1") == std::wstring::npos)
            {
                ok = false;
                break;
            }
        }
        if (MinifilterIrpMajorName(0x00) != L"IRP_MJ_CREATE" ||
            MinifilterIrpMajorName(0xff) != L"IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION")
        {
            ok = false;
            break;
        }
        if (!MinifilterIrpNameLooksInbox(L"WdFilter") ||
            !MinifilterIrpNameLooksInbox(L"cldflt.sys") ||
            MinifilterIrpNameLooksInbox(L"UnionFS"))
        {
            ok = false;
            break;
        }
    } while (false);
    return ok;
}
