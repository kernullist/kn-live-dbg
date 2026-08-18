#include "MinifilterIrpScanner.h"

#include "../shared/KnLiveDbgIoctl.h"
#include "LeftoverCommon.h"
#include "McpJson.h"

#include <Windows.h>

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
    constexpr uint32_t kMaxInstances = 2048;
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
        uint32_t FilterInstanceList = 0;
        uint32_t InstanceFilterLink = 0;
        uint32_t InstanceFilter = 0;
        uint32_t InstanceCallbackNodes = 0;
        uint32_t CallbackNodeLinks = 0;
        uint32_t CallbackNodePre = 0x18;
        uint32_t CallbackNodePost = 0x20;
        uint32_t CallbackNodeInstance = 0x10;
        uint32_t CallbackNodeSize = 0x28;
        uint32_t CallbackNodeCount = 50;
        bool CallbackNodesArePointers = true;
        bool HasDriverStart = false;
        bool HasLiveCallbackLayout = false;
    };

    bool CollectFilterInstances(
        DeviceClient& device,
        const MinifilterLayout& layout,
        uint64_t filter,
        std::vector<uint64_t>* instances,
        std::wstring* error);
    uint32_t CountLiveCallbackNodes(
        DeviceClient& device,
        const MinifilterLayout& layout,
        const std::vector<uint64_t>& instances);
    void InferCallbackNodeArray(SymbolEngine& symbols, MinifilterLayout* layout);

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

    struct LiveNodeBackup
    {
        uint64_t Filter = 0;
        uint64_t Node = 0;
        uint64_t Pre = 0;
        uint64_t Post = 0;
        uint32_t MajorFunction = 0xffffffffu;
    };

    struct IrpBackupValue
    {
        uint64_t Pre = 0;
        uint64_t Post = 0;
        std::wstring FilterName;
    };

    std::mutex g_BackupLock;
    std::map<IrpBackupKey, IrpBackupValue> g_Backups;
    std::map<uint64_t, LiveNodeBackup> g_NodeBackups;
    uint64_t g_FltNopThunk = 0;

    uint32_t CountNodeBackupsForFilter(uint64_t filter)
    {
        uint32_t count = 0;
        std::lock_guard<std::mutex> guard(g_BackupLock);
        for (const auto& entry : g_NodeBackups)
        {
            if (entry.second.Filter == filter &&
                (entry.second.Pre != 0 || entry.second.Post != 0))
            {
                ++count;
            }
        }
        return count;
    }

    constexpr uint32_t kIrpMjMaximumFunction = 0x1b;
    constexpr uint32_t kSweepMajor = 0xffffffffu;

    uint32_t CallbackIndexFromMajor(uint32_t major)
    {
        uint32_t index = 0xffffffffu;
        if (major <= kIrpMjMaximumFunction)
        {
            index = major;
        }
        else if (major > kIrpMjMaximumFunction && major <= 0xffu)
        {
            // FltMgr stores UCHAR-negative FS-filter / FastIO majors
            // after the 0x00-0x1B IRP slots. 0xFF -> 0x1C.
            const uint8_t inverted = static_cast<uint8_t>(~static_cast<uint8_t>(major));
            index = kIrpMjMaximumFunction + 1u + inverted;
        }

        return index;
    }

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

    bool BytesAreReturnZero(const uint8_t* bytes, size_t length)
    {
        bool match = false;
        if (bytes != nullptr)
        {
            if (length >= 3 &&
                ((bytes[0] == 0x33 && bytes[1] == 0xc0 && bytes[2] == 0xc3) ||
                 (bytes[0] == 0x31 && bytes[1] == 0xc0 && bytes[2] == 0xc3)))
            {
                match = true;
            }
            else if (length >= 4 &&
                     bytes[0] == 0x48 &&
                     (bytes[1] == 0x33 || bytes[1] == 0x31) &&
                     bytes[2] == 0xc0 &&
                     bytes[3] == 0xc3)
            {
                match = true;
            }
        }
        return match;
    }

    bool FindModuleRange(
        SymbolEngine& symbols,
        const wchar_t* name,
        uint64_t* base,
        uint64_t* size)
    {
        bool ok = false;
        do
        {
            if (base == nullptr || size == nullptr || name == nullptr)
            {
                break;
            }
            for (const KernelModuleInfo& module : symbols.Modules())
            {
                if (LeftoverNamesMatch(module.ImageName, name))
                {
                    *base = module.Base;
                    *size = module.Size;
                    ok = true;
                    break;
                }
            }
        } while (false);
        return ok;
    }

    bool FindGuardCfReturnZero(
        DeviceClient& device,
        uint64_t moduleBase,
        uint64_t moduleSize,
        uint64_t* thunk)
    {
        bool ok = false;
        do
        {
            if (thunk == nullptr || moduleBase == 0 || moduleSize < 0x400)
            {
                break;
            }

            // LeftoverReadBytes caps at 8 KB. Headers fit; the CFG table does not.
            std::vector<uint8_t> headers;
            if (!LeftoverReadBytes(device, moduleBase, 0x1000, &headers, nullptr) ||
                headers.size() < sizeof(IMAGE_DOS_HEADER))
            {
                break;
            }

            IMAGE_DOS_HEADER dos = {};
            memcpy(&dos, headers.data(), sizeof(dos));
            if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0)
            {
                break;
            }

            const uint32_t ntOffset = static_cast<uint32_t>(dos.e_lfanew);
            if (ntOffset + sizeof(IMAGE_NT_HEADERS64) > headers.size())
            {
                uint64_t ntVa = 0;
                if (!LeftoverTryAdd(moduleBase, ntOffset, &ntVa) ||
                    !LeftoverReadBytes(device, ntVa, sizeof(IMAGE_NT_HEADERS64), &headers, nullptr) ||
                    headers.size() < sizeof(IMAGE_NT_HEADERS64))
                {
                    break;
                }
            }

            IMAGE_NT_HEADERS64 nt = {};
            if (ntOffset + sizeof(nt) <= headers.size() &&
                headers.size() != sizeof(IMAGE_NT_HEADERS64))
            {
                memcpy(&nt, headers.data() + ntOffset, sizeof(nt));
            }
            else if (headers.size() >= sizeof(nt))
            {
                memcpy(&nt, headers.data(), sizeof(nt));
            }
            else
            {
                break;
            }

            if (nt.Signature != IMAGE_NT_SIGNATURE ||
                nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
                nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
            {
                break;
            }

            const IMAGE_DATA_DIRECTORY dir =
                nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
            const uint32_t cfgNeed = static_cast<uint32_t>(
                FIELD_OFFSET(IMAGE_LOAD_CONFIG_DIRECTORY64, GuardFlags) + sizeof(DWORD));
            if (dir.VirtualAddress == 0 || dir.Size < cfgNeed)
            {
                break;
            }

            uint64_t cfgVa = 0;
            if (!LeftoverTryAdd(moduleBase, dir.VirtualAddress, &cfgVa))
            {
                break;
            }

            std::vector<uint8_t> loadConfig;
            const uint32_t cfgRead = (std::min)(
                static_cast<uint32_t>(dir.Size),
                static_cast<uint32_t>(sizeof(IMAGE_LOAD_CONFIG_DIRECTORY64)));
            if (!LeftoverReadBytes(device, cfgVa, cfgRead, &loadConfig, nullptr) ||
                loadConfig.size() < cfgNeed)
            {
                break;
            }

            IMAGE_LOAD_CONFIG_DIRECTORY64 cfg = {};
            memcpy(&cfg, loadConfig.data(), (std::min)(loadConfig.size(), sizeof(cfg)));
            if (cfg.Size < cfgNeed)
            {
                break;
            }

            uint64_t tableVa = cfg.GuardCFFunctionTable;
            const uint64_t tableCount = cfg.GuardCFFunctionCount;
            if (tableVa >= moduleBase && tableVa < moduleBase + moduleSize)
            {
            }
            else if (tableVa < moduleSize)
            {
                if (!LeftoverTryAdd(moduleBase, tableVa, &tableVa))
                {
                    break;
                }
            }
            else
            {
                break;
            }

            const uint32_t extra = (cfg.GuardFlags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >>
                IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT;
            const uint32_t stride = 4u + extra;
            if (stride < 4 || stride > 20 || tableCount == 0 || tableCount > 100000)
            {
                break;
            }

            const uint32_t chunkBytes = 0x1000;
            const uint64_t entriesPerChunk = chunkBytes / stride;
            if (entriesPerChunk == 0)
            {
                break;
            }

            for (uint64_t index = 0; index < tableCount && !ok; )
            {
                const uint64_t remaining = tableCount - index;
                const uint32_t batch = static_cast<uint32_t>((std::min)(remaining, entriesPerChunk));
                uint64_t chunkVa = 0;
                if (!LeftoverTryAdd(tableVa, index * stride, &chunkVa))
                {
                    break;
                }

                std::vector<uint8_t> table;
                if (!LeftoverReadBytes(device, chunkVa, batch * stride, &table, nullptr) ||
                    table.size() < static_cast<size_t>(batch) * stride)
                {
                    break;
                }

                for (uint32_t entry = 0; entry < batch; ++entry)
                {
                    uint32_t rva = 0;
                    memcpy(&rva, table.data() + (static_cast<size_t>(entry) * stride), sizeof(rva));
                    if (rva == 0 || static_cast<uint64_t>(rva) + 8 > moduleSize)
                    {
                        continue;
                    }

                    uint64_t codeVa = 0;
                    if (!LeftoverTryAdd(moduleBase, rva, &codeVa))
                    {
                        continue;
                    }

                    std::vector<uint8_t> bytes;
                    if (!LeftoverReadBytes(device, codeVa, 8, &bytes, nullptr) || bytes.size() < 3)
                    {
                        continue;
                    }
                    if (BytesAreReturnZero(bytes.data(), bytes.size()))
                    {
                        *thunk = codeVa;
                        ok = true;
                        break;
                    }
                }

                index += batch;
            }
        } while (false);
        return ok;
    }

    bool EnsureFltNopThunk(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t* thunk,
        std::wstring* error)
    {
        bool ok = false;
        do
        {
            if (thunk == nullptr)
            {
                break;
            }
            if (g_FltNopThunk != 0)
            {
                *thunk = g_FltNopThunk;
                ok = true;
                break;
            }

            uint64_t found = 0;
            uint64_t base = 0;
            uint64_t size = 0;
            if (FindModuleRange(symbols, L"fltmgr.sys", &base, &size))
            {
                FindGuardCfReturnZero(device, base, size, &found);
            }
            if (found == 0 && FindModuleRange(symbols, L"ntoskrnl.exe", &base, &size))
            {
                FindGuardCfReturnZero(device, base, size, &found);
            }
            if (found == 0 && FindModuleRange(symbols, L"ntkrnlmp.exe", &base, &size))
            {
                FindGuardCfReturnZero(device, base, size, &found);
            }
            if (found == 0)
            {
                if (error != nullptr)
                {
                    *error = L"no CFG-valid return-0 thunk in fltmgr/nt; "
                             L"refusing to NULL or unlink live CallbackNodes "
                             L"(those crash with 0x139)";
                }
                break;
            }

            g_FltNopThunk = found;
            *thunk = found;
            ok = true;
        } while (false);
        return ok;
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

    void InferCallbackNodeArray(SymbolEngine& symbols, MinifilterLayout* layout)
    {
        do
        {
            if (layout == nullptr)
            {
                break;
            }

            TypeLayoutInfo instanceLayout = {};
            std::wstring ignored;
            if (!symbols.GetTypeLayout(L"fltmgr!_FLT_INSTANCE", &instanceLayout, &ignored) &&
                !symbols.GetTypeLayout(L"_FLT_INSTANCE", &instanceLayout, &ignored))
            {
                break;
            }

            const TypeFieldInfo* nodesField = nullptr;
            for (const TypeFieldInfo& field : instanceLayout.Fields)
            {
                if (field.Name == L"CallbackNodes" || field.Name == L"CallbackNode")
                {
                    nodesField = &field;
                    layout->InstanceCallbackNodes = field.Offset;
                    break;
                }
            }
            if (nodesField == nullptr)
            {
                break;
            }

            // SymbolEngine reports the element size for array fields. Use the
            // gap to the next FLT_INSTANCE field as the real array bytes.
            uint32_t nextOffset = 0;
            bool haveNext = false;
            for (const TypeFieldInfo& field : instanceLayout.Fields)
            {
                if (field.Offset > nodesField->Offset &&
                    (!haveNext || field.Offset < nextOffset))
                {
                    nextOffset = field.Offset;
                    haveNext = true;
                }
            }

            uint64_t arrayBytes = 0;
            if (haveNext)
            {
                arrayBytes = static_cast<uint64_t>(nextOffset) - nodesField->Offset;
            }
            else if (instanceLayout.Size > nodesField->Offset)
            {
                arrayBytes = instanceLayout.Size - nodesField->Offset;
            }
            if (arrayBytes < 16 * sizeof(uint64_t))
            {
                break;
            }

            TypeLayoutInfo nodeLayout = {};
            const bool haveNodeType =
                symbols.GetTypeLayout(L"fltmgr!_CALLBACK_NODE", &nodeLayout, &ignored) ||
                symbols.GetTypeLayout(L"_CALLBACK_NODE", &nodeLayout, &ignored);
            if (haveNodeType &&
                nodeLayout.Size >= 24 &&
                arrayBytes >= nodeLayout.Size &&
                (arrayBytes % nodeLayout.Size) == 0)
            {
                const uint32_t count = static_cast<uint32_t>(arrayBytes / nodeLayout.Size);
                if (count >= 16 && count <= 64)
                {
                    layout->CallbackNodesArePointers = false;
                    layout->CallbackNodeCount = count;
                    layout->CallbackNodeSize = static_cast<uint32_t>(nodeLayout.Size);
                    break;
                }
            }

            if ((arrayBytes % sizeof(uint64_t)) == 0)
            {
                const uint32_t count = static_cast<uint32_t>(arrayBytes / sizeof(uint64_t));
                if (count >= 16 && count <= 64)
                {
                    layout->CallbackNodesArePointers = true;
                    layout->CallbackNodeCount = count;
                }
            }
        } while (false);
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

            const std::wstring instanceTypes[] = { L"fltmgr!_FLT_INSTANCE", L"_FLT_INSTANCE" };
            const std::wstring instanceListNames[] = { L"InstanceList" };
            const std::wstring filterLinkNames[] = { L"FilterLink", L"FilterList" };
            const std::wstring instanceFilterNames[] = { L"Filter" };
            FindFieldOffset(
                symbols,
                filterTypes,
                2,
                instanceListNames,
                1,
                &layout->FilterInstanceList,
                &ignored);

            TypeFieldInfo instanceBase = {};
            uint32_t instanceBaseOffset = 0;
            if (symbols.FindField(L"fltmgr!_FLT_INSTANCE", L"Base", &instanceBase, &ignored) ||
                symbols.FindField(L"_FLT_INSTANCE", L"Base", &instanceBase, &ignored))
            {
                instanceBaseOffset = instanceBase.Offset;
            }
            layout->InstanceFilterLink = instanceBaseOffset + layout->ObjectPrimaryLink;
            FindFieldOffset(
                symbols,
                instanceTypes,
                2,
                filterLinkNames,
                2,
                &layout->InstanceFilterLink,
                &ignored);
            FindFieldOffset(
                symbols,
                instanceTypes,
                2,
                instanceFilterNames,
                1,
                &layout->InstanceFilter,
                &ignored);

            InferCallbackNodeArray(symbols, layout);

            const std::wstring callbackTypes[] =
            {
                L"fltmgr!_CALLBACK_NODE",
                L"_CALLBACK_NODE"
            };
            const std::wstring callbackLinkNames[] = { L"CallbackLinks", L"Links" };
            const std::wstring callbackPreNames[] = { L"PreOperation", L"Pre" };
            const std::wstring callbackPostNames[] = { L"PostOperation", L"Post" };
            const std::wstring callbackInstanceNames[] = { L"Instance" };
            FindFieldOffset(
                symbols,
                callbackTypes,
                2,
                callbackLinkNames,
                2,
                &layout->CallbackNodeLinks,
                &ignored);
            FindFieldOffset(
                symbols,
                callbackTypes,
                2,
                callbackPreNames,
                2,
                &layout->CallbackNodePre,
                &ignored);
            FindFieldOffset(
                symbols,
                callbackTypes,
                2,
                callbackPostNames,
                2,
                &layout->CallbackNodePost,
                &ignored);
            FindFieldOffset(
                symbols,
                callbackTypes,
                2,
                callbackInstanceNames,
                1,
                &layout->CallbackNodeInstance,
                &ignored);

            layout->HasLiveCallbackLayout =
                layout->FilterInstanceList != 0 &&
                layout->InstanceCallbackNodes != 0 &&
                layout->InstanceFilterLink != 0 &&
                layout->InstanceFilter != 0 &&
                layout->CallbackNodeCount != 0 &&
                layout->CallbackNodePre != layout->CallbackNodePost;

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
            if (g_FltNopThunk != 0)
            {
                if (slot->Pre == g_FltNopThunk)
                {
                    slot->Pre = 0;
                }
                if (slot->Post == g_FltNopThunk)
                {
                    slot->Post = 0;
                }
            }
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
                    filter.LiveLayoutAvailable = layout.HasLiveCallbackLayout;
                    if (layout.HasLiveCallbackLayout)
                    {
                        std::vector<uint64_t> instances;
                        std::wstring instanceError;
                        if (CollectFilterInstances(
                                device,
                                layout,
                                filterAddress,
                                &instances,
                                &instanceError))
                        {
                            filter.InstanceCount = static_cast<uint32_t>(instances.size());
                            filter.LiveCallbackCount = CountLiveCallbackNodes(
                                device,
                                layout,
                                instances);
                            if (filter.ActiveOperationCount == 0 &&
                                filter.LiveCallbackCount > 0)
                            {
                                LeftoverAppendNote(
                                    &filter.Notes,
                                    L"Operations table is empty but live CallbackNodes still fire");
                            }
                        }
                        else if (!instanceError.empty())
                        {
                            LeftoverAppendNote(&filter.Notes, instanceError);
                        }
                    }
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

    bool CollectFilterInstances(
        DeviceClient& device,
        const MinifilterLayout& layout,
        uint64_t filter,
        std::vector<uint64_t>* instances,
        std::wstring* error)
    {
        bool ok = false;
        do
        {
            if (instances == nullptr)
            {
                break;
            }
            instances->clear();
            if (!layout.HasLiveCallbackLayout)
            {
                if (error != nullptr)
                {
                    *error = L"PDB is missing FLT_INSTANCE.CallbackNodes; "
                             L"writing FLT_FILTER.Operations does not stop live FltMgr dispatch";
                }
                break;
            }

            uint64_t listField = 0;
            uint64_t head = 0;
            if (!LeftoverTryAdd(filter, layout.FilterInstanceList, &listField) ||
                !LeftoverTryAdd(listField, layout.ResourceList, &head))
            {
                if (error != nullptr)
                {
                    *error = L"FLT_FILTER.InstanceList address overflow";
                }
                break;
            }

            uint64_t flink = 0;
            uint64_t blink = 0;
            if (!ReadListEntry(device, head, &flink, &blink))
            {
                if (error != nullptr)
                {
                    *error = L"failed to read FLT_FILTER.InstanceList";
                }
                break;
            }

            std::set<uint64_t> seen;
            uint64_t link = flink;
            bool recoveredAny = false;
            for (uint32_t index = 0;
                 index < kMaxInstances && link != 0 && link != head;
                 ++index)
            {
                if (!LeftoverIsKernelCanonical(link) || !seen.insert(link).second)
                {
                    break;
                }

                uint64_t next = 0;
                uint64_t ignoredBlink = 0;
                if (!ReadListEntry(device, link, &next, &ignoredBlink))
                {
                    break;
                }

                if (layout.InstanceFilterLink > link)
                {
                    link = next;
                    continue;
                }

                const uint64_t instance = link - layout.InstanceFilterLink;
                if (!LeftoverIsKernelCanonical(instance))
                {
                    link = next;
                    continue;
                }

                recoveredAny = true;
                if (layout.InstanceFilter != 0)
                {
                    uint64_t filterField = 0;
                    uint64_t owner = 0;
                    if (!LeftoverTryAdd(instance, layout.InstanceFilter, &filterField) ||
                        !LeftoverReadU64(device, filterField, &owner, nullptr) ||
                        owner != filter)
                    {
                        link = next;
                        continue;
                    }
                }

                instances->push_back(instance);
                link = next;
            }

            if (flink != head && instances->empty())
            {
                if (error != nullptr)
                {
                    *error = recoveredAny
                        ? L"FLT_FILTER.InstanceList entries did not resolve to this filter"
                        : L"could not recover FLT_INSTANCE from InstanceList";
                }
                break;
            }

            ok = true;
        } while (false);
        return ok;
    }

    bool ReadCallbackNodePointers(
        DeviceClient& device,
        const MinifilterLayout& layout,
        uint64_t node,
        uint64_t* pre,
        uint64_t* post,
        uint64_t* instance)
    {
        bool ok = false;
        do
        {
            if (node == 0 || !LeftoverIsKernelCanonical(node))
            {
                break;
            }

            uint64_t preValue = 0;
            uint64_t postValue = 0;
            uint64_t instanceValue = 0;
            uint64_t preAddr = 0;
            uint64_t postAddr = 0;
            uint64_t instanceAddr = 0;
            if (!LeftoverTryAdd(node, layout.CallbackNodePre, &preAddr) ||
                !LeftoverTryAdd(node, layout.CallbackNodePost, &postAddr))
            {
                break;
            }
            LeftoverReadU64(device, preAddr, &preValue, nullptr);
            LeftoverReadU64(device, postAddr, &postValue, nullptr);
            if (layout.CallbackNodeInstance != 0 &&
                LeftoverTryAdd(node, layout.CallbackNodeInstance, &instanceAddr))
            {
                LeftoverReadU64(device, instanceAddr, &instanceValue, nullptr);
            }

            if (pre != nullptr)
            {
                *pre = LeftoverIsKernelCanonical(preValue) ? preValue : 0;
            }
            if (post != nullptr)
            {
                *post = LeftoverIsKernelCanonical(postValue) ? postValue : 0;
            }
            if (instance != nullptr)
            {
                *instance = LeftoverIsKernelCanonical(instanceValue) ? instanceValue : 0;
            }
            ok = true;
        } while (false);
        return ok;
    }

    bool ResolveCallbackNode(
        DeviceClient& device,
        const MinifilterLayout& layout,
        uint64_t instance,
        uint32_t index,
        uint64_t* node)
    {
        bool ok = false;
        do
        {
            if (node == nullptr || index >= layout.CallbackNodeCount)
            {
                break;
            }

            uint64_t array = 0;
            if (!LeftoverTryAdd(instance, layout.InstanceCallbackNodes, &array))
            {
                break;
            }

            uint64_t resolved = 0;
            if (layout.CallbackNodesArePointers)
            {
                uint64_t slot = 0;
                uint64_t pointer = 0;
                if (!LeftoverTryAdd(array, static_cast<uint64_t>(index) * sizeof(uint64_t), &slot) ||
                    !LeftoverReadU64(device, slot, &pointer, nullptr) ||
                    !LeftoverIsKernelCanonical(pointer))
                {
                    break;
                }
                resolved = pointer;
            }
            else
            {
                if (!LeftoverTryAdd(array, static_cast<uint64_t>(index) * layout.CallbackNodeSize, &resolved))
                {
                    break;
                }
            }

            uint64_t nodeInstance = 0;
            uint64_t pre = 0;
            uint64_t post = 0;
            if (!ReadCallbackNodePointers(device, layout, resolved, &pre, &post, &nodeInstance))
            {
                break;
            }
            if (layout.CallbackNodeInstance != 0 && nodeInstance != instance)
            {
                break;
            }

            *node = resolved;
            ok = true;
        } while (false);
        return ok;
    }

    void CollectInstanceCallbackNodes(
        DeviceClient& device,
        const MinifilterLayout& layout,
        uint64_t instance,
        std::vector<uint64_t>* nodes)
    {
        if (nodes == nullptr)
        {
            return;
        }
        for (uint32_t index = 0; index < layout.CallbackNodeCount; ++index)
        {
            uint64_t node = 0;
            if (ResolveCallbackNode(device, layout, instance, index, &node))
            {
                nodes->push_back(node);
            }
        }
    }

    bool IsOriginalCallback(uint64_t address, uint64_t nopThunk)
    {
        return address != 0 && address != nopThunk && LeftoverIsKernelCanonical(address);
    }

    uint32_t CountLiveCallbackNodes(
        DeviceClient& device,
        const MinifilterLayout& layout,
        const std::vector<uint64_t>& instances)
    {
        uint32_t live = 0;
        for (uint64_t instance : instances)
        {
            std::vector<uint64_t> nodes;
            CollectInstanceCallbackNodes(device, layout, instance, &nodes);
            for (uint64_t node : nodes)
            {
                uint64_t pre = 0;
                uint64_t post = 0;
                if (ReadCallbackNodePointers(device, layout, node, &pre, &post, nullptr) &&
                    (IsOriginalCallback(pre, g_FltNopThunk) ||
                     IsOriginalCallback(post, g_FltNopThunk)))
                {
                    ++live;
                }
            }
        }
        return live;
    }

    void RememberLiveNode(
        uint64_t filter,
        uint32_t majorFunction,
        uint64_t node,
        uint64_t pre,
        uint64_t post)
    {
        if (node == 0)
        {
            return;
        }
        if (g_FltNopThunk != 0)
        {
            if (pre == g_FltNopThunk)
            {
                pre = 0;
            }
            if (post == g_FltNopThunk)
            {
                post = 0;
            }
        }
        if (pre == 0 && post == 0)
        {
            return;
        }

        LiveNodeBackup backup = {};
        backup.Filter = filter;
        backup.Node = node;
        backup.Pre = pre;
        backup.Post = post;
        backup.MajorFunction = majorFunction;

        std::lock_guard<std::mutex> guard(g_BackupLock);
        auto existing = g_NodeBackups.find(node);
        if (existing == g_NodeBackups.end())
        {
            g_NodeBackups[node] = backup;
        }
        else
        {
            if (existing->second.Pre == 0 && pre != 0)
            {
                existing->second.Pre = pre;
            }
            if (existing->second.Post == 0 && post != 0)
            {
                existing->second.Post = post;
            }
            if (existing->second.MajorFunction == kSweepMajor &&
                majorFunction != kSweepMajor)
            {
                existing->second.MajorFunction = majorFunction;
            }
        }
    }

    bool PatchCallbackNode(
        DeviceClient& device,
        const MinifilterLayout& layout,
        uint64_t filter,
        uint32_t majorFunction,
        uint64_t node,
        MinifilterIrpAction action,
        MinifilterIrpWhich which,
        uint64_t nopThunk,
        uint32_t* changed,
        uint32_t* failed,
        std::wstring* error)
    {
        bool ok = false;
        do
        {
            if (changed == nullptr || failed == nullptr)
            {
                break;
            }
            if (action == MinifilterIrpAction::Disable && nopThunk == 0)
            {
                ++(*failed);
                if (error != nullptr && error->empty())
                {
                    *error = L"missing CFG-valid nop thunk";
                }
                break;
            }

            uint64_t preAddr = 0;
            uint64_t postAddr = 0;
            uint64_t currentPre = 0;
            uint64_t currentPost = 0;
            if (!LeftoverTryAdd(node, layout.CallbackNodePre, &preAddr) ||
                !LeftoverTryAdd(node, layout.CallbackNodePost, &postAddr) ||
                !ReadCallbackNodePointers(device, layout, node, &currentPre, &currentPost, nullptr))
            {
                ++(*failed);
                break;
            }

            const bool touchPre = (which == MinifilterIrpWhich::Both || which == MinifilterIrpWhich::Pre);
            const bool touchPost = (which == MinifilterIrpWhich::Both || which == MinifilterIrpWhich::Post);
            uint64_t newPre = currentPre;
            uint64_t newPost = currentPost;

            if (action == MinifilterIrpAction::Disable)
            {
                RememberLiveNode(filter, majorFunction, node, currentPre, currentPost);
                // Leave original NULLs alone. FltMgr skips those at attach;
                // replacing them with a thunk can change post registration.
                if (touchPre && currentPre != 0)
                {
                    newPre = nopThunk;
                }
                if (touchPost && currentPost != 0)
                {
                    newPost = nopThunk;
                }
            }
            else
            {
                LiveNodeBackup backup = {};
                bool haveBackup = false;
                {
                    std::lock_guard<std::mutex> guard(g_BackupLock);
                    auto existing = g_NodeBackups.find(node);
                    if (existing != g_NodeBackups.end())
                    {
                        backup = existing->second;
                        haveBackup = true;
                    }
                }
                if (!haveBackup)
                {
                    ok = true;
                    break;
                }
                if (touchPre)
                {
                    newPre = backup.Pre;
                }
                if (touchPost)
                {
                    newPost = backup.Post;
                }
            }

            bool wrote = false;
            if (touchPre && newPre != currentPre)
            {
                std::wstring writeError;
                if (!WritePointer(device, preAddr, newPre, &writeError))
                {
                    ++(*failed);
                    if (error != nullptr && error->empty())
                    {
                        *error = writeError;
                    }
                    break;
                }
                wrote = true;
            }
            if (touchPost && newPost != currentPost)
            {
                std::wstring writeError;
                if (!WritePointer(device, postAddr, newPost, &writeError))
                {
                    ++(*failed);
                    if (error != nullptr && error->empty())
                    {
                        *error = writeError;
                    }
                    break;
                }
                wrote = true;
            }
            if (wrote)
            {
                ++(*changed);
            }
            ok = true;
        } while (false);
        return ok;
    }

    bool PatchLiveCallbackNodes(
        DeviceClient& device,
        const MinifilterLayout& layout,
        uint64_t filter,
        uint32_t majorFunction,
        uint64_t matchPre,
        uint64_t matchPost,
        MinifilterIrpAction action,
        MinifilterIrpWhich which,
        uint64_t nopThunk,
        uint32_t* changed,
        uint32_t* failed,
        std::wstring* error)
    {
        bool ok = false;
        do
        {
            if (changed == nullptr || failed == nullptr)
            {
                break;
            }

            std::vector<uint64_t> instances;
            if (!CollectFilterInstances(device, layout, filter, &instances, error))
            {
                break;
            }

            std::set<uint64_t> patched;
            const uint32_t index = CallbackIndexFromMajor(majorFunction);
            for (uint64_t instance : instances)
            {
                uint64_t indexed = 0;
                if (index != 0xffffffffu &&
                    ResolveCallbackNode(device, layout, instance, index, &indexed))
                {
                    if (patched.insert(indexed).second)
                    {
                        PatchCallbackNode(
                            device,
                            layout,
                            filter,
                            majorFunction,
                            indexed,
                            action,
                            which,
                            nopThunk,
                            changed,
                            failed,
                            error);
                    }
                    continue;
                }

                std::vector<uint64_t> nodes;
                CollectInstanceCallbackNodes(device, layout, instance, &nodes);
                for (uint64_t node : nodes)
                {
                    if (!patched.insert(node).second)
                    {
                        continue;
                    }
                    uint64_t pre = 0;
                    uint64_t post = 0;
                    if (!ReadCallbackNodePointers(device, layout, node, &pre, &post, nullptr))
                    {
                        continue;
                    }
                    if (matchPre == 0 && matchPost == 0)
                    {
                        continue;
                    }
                    const bool preMatch = (matchPre == 0) || (pre == matchPre);
                    const bool postMatch = (matchPost == 0) || (post == matchPost);
                    if (preMatch && postMatch)
                    {
                        PatchCallbackNode(
                            device,
                            layout,
                            filter,
                            majorFunction,
                            node,
                            action,
                            which,
                            nopThunk,
                            changed,
                            failed,
                            error);
                    }
                }
            }

            ok = true;
        } while (false);
        return ok;
    }

    bool SlotStillHasLiveCallback(
        DeviceClient& device,
        const MinifilterLayout& layout,
        const std::vector<uint64_t>& instances,
        uint32_t majorFunction,
        uint64_t matchPre,
        uint64_t matchPost,
        MinifilterIrpWhich which)
    {
        bool live = false;
        (void)which;
        const uint32_t index = CallbackIndexFromMajor(majorFunction);

        for (uint64_t instance : instances)
        {
            uint64_t indexed = 0;
            if (index != 0xffffffffu &&
                ResolveCallbackNode(device, layout, instance, index, &indexed))
            {
                uint64_t pre = 0;
                uint64_t post = 0;
                if (ReadCallbackNodePointers(device, layout, indexed, &pre, &post, nullptr) &&
                    (IsOriginalCallback(pre, g_FltNopThunk) ||
                     IsOriginalCallback(post, g_FltNopThunk)))
                {
                    live = true;
                    break;
                }
                continue;
            }

            if (matchPre == 0 && matchPost == 0)
            {
                continue;
            }

            std::vector<uint64_t> nodes;
            CollectInstanceCallbackNodes(device, layout, instance, &nodes);
            for (uint64_t node : nodes)
            {
                uint64_t pre = 0;
                uint64_t post = 0;
                if (!ReadCallbackNodePointers(device, layout, node, &pre, &post, nullptr))
                {
                    continue;
                }
                const bool preMatch = (matchPre == 0) || (pre == matchPre);
                const bool postMatch = (matchPost == 0) || (post == matchPost);
                if (preMatch &&
                    postMatch &&
                    (IsOriginalCallback(pre, g_FltNopThunk) ||
                     IsOriginalCallback(post, g_FltNopThunk)))
                {
                    live = true;
                    break;
                }
            }
            if (live)
            {
                break;
            }
        }

        return live;
    }

    bool SweepRemainingLiveNodes(
        DeviceClient& device,
        const MinifilterLayout& layout,
        uint64_t filter,
        MinifilterIrpAction action,
        MinifilterIrpWhich which,
        uint64_t nopThunk,
        uint32_t* changed,
        uint32_t* failed,
        std::wstring* error)
    {
        bool ok = false;
        do
        {
            std::vector<uint64_t> instances;
            if (!CollectFilterInstances(device, layout, filter, &instances, error))
            {
                break;
            }

            for (uint64_t instance : instances)
            {
                std::vector<uint64_t> nodes;
                CollectInstanceCallbackNodes(device, layout, instance, &nodes);
                for (uint64_t node : nodes)
                {
                    uint64_t pre = 0;
                    uint64_t post = 0;
                    if (!ReadCallbackNodePointers(device, layout, node, &pre, &post, nullptr))
                    {
                        continue;
                    }
                    if (action == MinifilterIrpAction::Disable &&
                        !IsOriginalCallback(pre, nopThunk) &&
                        !IsOriginalCallback(post, nopThunk))
                    {
                        continue;
                    }
                    PatchCallbackNode(
                        device,
                        layout,
                        filter,
                        kSweepMajor,
                        node,
                        action,
                        which,
                        nopThunk,
                        changed,
                        failed,
                        error);
                }
            }
            ok = true;
        } while (false);
        return ok;
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

uint32_t MinifilterCallbackIndexFromMajor(uint32_t majorFunction)
{
    return CallbackIndexFromMajor(majorFunction);
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
        L"mssecflt",
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

        uint64_t ignoredThunk = 0;
        EnsureFltNopThunk(device_, symbols_, &ignoredThunk, nullptr);

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

        uint64_t nopThunk = 0;
        if (!EnsureFltNopThunk(device_, symbols_, &nopThunk, error))
        {
            break;
        }

        MinifilterLayout layout = {};
        if (!BuildLayout(symbols_, &layout, error))
        {
            break;
        }
        if (!layout.HasLiveCallbackLayout)
        {
            if (error != nullptr)
            {
                *error = L"PDB is missing FLT_INSTANCE.CallbackNodes; "
                         L"writing FLT_FILTER.Operations does not stop live FltMgr dispatch";
            }
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
        bool haveOperationsBackup = false;

        if (action == MinifilterIrpAction::Disable)
        {
            IrpBackupKey key = {};
            key.Filter = filter.Filter;
            key.MajorFunction = majorFunction;
            IrpBackupValue value = {};
            value.Pre = found->Pre;
            value.Post = found->Post;
            value.FilterName = filter.Name;
            if (value.Pre != 0 || value.Post != 0)
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
            // Never write NULL into a live-copied slot. New attaches copy
            // Operations and FltMgr will kCFG-call a NULL Pre/Post.
            if (touchPre && found->Pre != 0)
            {
                newPre = nopThunk;
            }
            if (touchPost && found->Post != 0)
            {
                newPost = nopThunk;
            }
        }
        else
        {
            IrpBackupKey key = {};
            key.Filter = filter.Filter;
            key.MajorFunction = majorFunction;
            IrpBackupValue value = {};
            {
                std::lock_guard<std::mutex> guard(g_BackupLock);
                auto existing = g_Backups.find(key);
                if (existing != g_Backups.end())
                {
                    value = existing->second;
                    haveOperationsBackup = true;
                }
            }
            if (haveOperationsBackup)
            {
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
        }

        // Live CallbackNodes are what FltMgr dispatches. Replace Pre/Post with
        // a CFG-valid return-0 thunk. Never write NULL and never unlink lists.
        std::wstring liveError;
        if (!PatchLiveCallbackNodes(
                device_,
                layout,
                filter.Filter,
                majorFunction,
                found->Pre,
                found->Post,
                action,
                which,
                nopThunk,
                &change->LiveNodesChanged,
                &change->LiveNodesFailed,
                &liveError))
        {
            if (error != nullptr)
            {
                *error = liveError.empty()
                    ? L"failed to patch live FLT_INSTANCE.CallbackNodes"
                    : liveError;
            }
            break;
        }

        if (action == MinifilterIrpAction::Disable)
        {
            std::vector<uint64_t> instances;
            std::wstring instanceError;
            if (CollectFilterInstances(
                    device_,
                    layout,
                    filter.Filter,
                    &instances,
                    &instanceError) &&
                !instances.empty())
            {
                if (SlotStillHasLiveCallback(
                        device_,
                        layout,
                        instances,
                        majorFunction,
                        found->Pre,
                        found->Post,
                        which))
                {
                    if (error != nullptr)
                    {
                        *error = L"live FLT_INSTANCE.CallbackNodes still have handlers; "
                                 L"FltMgr would still call the original callback";
                    }
                    break;
                }
                if (change->LiveNodesChanged == 0 &&
                    (found->PreActive || found->PostActive) &&
                    CountLiveCallbackNodes(device_, layout, instances) == 0)
                {
                    if (error != nullptr)
                    {
                        *error = L"attached instances were found but no live "
                                 L"CallbackNodes could be read; refusing to touch "
                                 L"FLT_FILTER.Operations only";
                    }
                    break;
                }
            }
        }

        if (action == MinifilterIrpAction::Enable &&
            !haveOperationsBackup &&
            change->LiveNodesChanged == 0)
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
            if (backupHits == 0 && CountNodeBackupsForFilter(filter.Filter) == 0)
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
                if (!haveBackup && CountNodeBackupsForFilter(filter.Filter) == 0)
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
            if (change.PreChanged || change.PostChanged || change.LiveNodesChanged > 0)
            {
                ++batch->Changed;
            }
            else
            {
                ++batch->Skipped;
            }
            batch->LiveNodesChanged += change.LiveNodesChanged;
            batch->LiveNodesFailed += change.LiveNodesFailed;
            batch->Changes.push_back(change);
        }

        MinifilterLayout layout = {};
        std::wstring layoutError;
        uint64_t nopThunk = 0;
        if (BuildLayout(symbols_, &layout, &layoutError) &&
            layout.HasLiveCallbackLayout &&
            EnsureFltNopThunk(device_, symbols_, &nopThunk, &layoutError))
        {
            uint32_t swept = 0;
            uint32_t sweepFailed = 0;
            std::wstring sweepError;
            if (SweepRemainingLiveNodes(
                    device_,
                    layout,
                    filter.Filter,
                    action,
                    which,
                    nopThunk,
                    &swept,
                    &sweepFailed,
                    &sweepError))
            {
                batch->LiveNodesChanged += swept;
                batch->LiveNodesFailed += sweepFailed;
                if (swept > 0)
                {
                    ++batch->Changed;
                }
            }
            else if (!sweepError.empty())
            {
                batch->Failures.push_back(L"live CallbackNodes sweep: " + sweepError);
                ++batch->Failed;
                anyWriteFailed = true;
            }
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
        out += L",\"instanceCount\":" + std::to_wstring(filter.InstanceCount);
        out += L",\"liveCallbackCount\":" + std::to_wstring(filter.LiveCallbackCount);
        out += L",\"liveLayoutAvailable\":";
        out += filter.LiveLayoutAvailable ? L"true" : L"false";
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
    out += L",\"liveNodesChanged\":" + std::to_wstring(change.LiveNodesChanged);
    out += L",\"liveNodesFailed\":" + std::to_wstring(change.LiveNodesFailed);
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
    out += L",\"liveNodesChanged\":" + std::to_wstring(batch.LiveNodesChanged);
    out += L",\"liveNodesFailed\":" + std::to_wstring(batch.LiveNodesFailed);
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
        if (MinifilterCallbackIndexFromMajor(0x00) != 0 ||
            MinifilterCallbackIndexFromMajor(0x1b) != 0x1b ||
            MinifilterCallbackIndexFromMajor(0xff) != 0x1c ||
            MinifilterCallbackIndexFromMajor(0xfe) != 0x1d ||
            MinifilterCallbackIndexFromMajor(0xec) != 0x2f)
        {
            ok = false;
            break;
        }
        {
            const uint8_t xorRet[] = { 0x33, 0xc0, 0xc3 };
            const uint8_t xorRaxRet[] = { 0x48, 0x33, 0xc0, 0xc3 };
            const uint8_t notNop[] = { 0x90, 0x90, 0xc3 };
            if (!BytesAreReturnZero(xorRet, sizeof(xorRet)) ||
                !BytesAreReturnZero(xorRaxRet, sizeof(xorRaxRet)) ||
                BytesAreReturnZero(notNop, sizeof(notNop)))
            {
                ok = false;
                break;
            }
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
