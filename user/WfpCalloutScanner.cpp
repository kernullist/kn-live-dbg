#include "WfpCalloutScanner.h"

#include <map>
#include <sstream>
#include <set>
#include <algorithm>
#include <cstring>
#include <fwpmu.h>
#include <Rpc.h>

#pragma comment(lib, "Fwpuclnt.lib")

#include "WfpScanner.h"

namespace
{
    constexpr uint64_t kKernelSpaceMin = 0xffff800000000000ull;
    constexpr uint32_t kMaxCalloutCount = 0x4000;       // sanity bound on slot count
    constexpr uint32_t kMaxWalkBytes = 0x100000 - 0x1000; // keep a single read under the transfer cap
    constexpr uint32_t kSampleEntries = 64;              // entries sampled while scoring a layout
    // notify/flowDelete sit immediately after classifyFn in the slot. The
    // walk derives those offsets from the scored classify field so a
    // drifted classify offset does not leave notify-only hooks unread.

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelSpaceMin;
    }

    bool ReadU32(DeviceClient& device, uint64_t address, uint32_t* value)
    {
        std::vector<uint8_t> bytes;
        if (!device.ReadMemory(address, sizeof(uint32_t), &bytes, nullptr) || bytes.size() != sizeof(uint32_t))
        {
            return false;
        }
        memcpy(value, bytes.data(), sizeof(uint32_t));
        return true;
    }

    bool ReadU64(DeviceClient& device, uint64_t address, uint64_t* value)
    {
        std::vector<uint8_t> bytes;
        if (!device.ReadMemory(address, sizeof(uint64_t), &bytes, nullptr) || bytes.size() != sizeof(uint64_t))
        {
            return false;
        }
        memcpy(value, bytes.data(), sizeof(uint64_t));
        return true;
    }

    uint64_t ReadEntryU64(const std::vector<uint8_t>& buffer, size_t entryOffset, uint32_t fieldOffset)
    {
        size_t pos = entryOffset + fieldOffset;
        if (pos + sizeof(uint64_t) > buffer.size())
        {
            return 0;
        }
        uint64_t value = 0;
        memcpy(&value, buffer.data() + pos, sizeof(uint64_t));
        return value;
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

    struct LayoutCandidate
    {
        uint32_t CountOffset;
        uint32_t ArrayOffset;
        uint32_t EntrySize;
        uint32_t ClassifyOffset;
        const wchar_t* Source;
    };

    // Scores a candidate layout by sampling the callout array and counting how
    // many non-null classify pointers land inside a loaded kernel module.
    // Returns a score in [0,1]; outValidated/outNonNull report the sample.
    double ScoreLayout(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t engineBase,
        const LayoutCandidate& layout,
        uint32_t* outCount,
        uint64_t* outArray,
        uint32_t* outNonNull)
    {
        *outCount = 0;
        *outArray = 0;
        *outNonNull = 0;

        uint32_t count = 0;
        uint64_t arrayPtr = 0;
        if (!ReadU32(device, engineBase + layout.CountOffset, &count) ||
            !ReadU64(device, engineBase + layout.ArrayOffset, &arrayPtr))
        {
            return 0.0;
        }

        if (count == 0 || count > kMaxCalloutCount || !IsKernelAddress(arrayPtr))
        {
            return 0.0;
        }

        uint32_t sample = count < kSampleEntries ? count : kSampleEntries;
        uint32_t sampleBytes = sample * layout.EntrySize;
        std::vector<uint8_t> buffer;
        if (!device.ReadMemory(arrayPtr, sampleBytes, &buffer, nullptr) || buffer.size() != sampleBytes)
        {
            return 0.0;
        }

        uint32_t nonNull = 0;
        uint32_t valid = 0;
        for (uint32_t i = 0; i < sample; ++i)
        {
            const size_t entryOffset = static_cast<size_t>(i) * layout.EntrySize;
            uint64_t classifyFn = ReadEntryU64(buffer, entryOffset, layout.ClassifyOffset);
            const uint32_t notifyOffset = layout.ClassifyOffset + 8;
            const uint32_t flowDeleteOffset = layout.ClassifyOffset + 16;
            uint64_t notifyFn = 0;
            uint64_t flowDeleteFn = 0;
            if (notifyOffset + sizeof(uint64_t) <= layout.EntrySize)
            {
                notifyFn = ReadEntryU64(buffer, entryOffset, notifyOffset);
            }
            if (flowDeleteOffset + sizeof(uint64_t) <= layout.EntrySize)
            {
                flowDeleteFn = ReadEntryU64(buffer, entryOffset, flowDeleteOffset);
            }
            if (classifyFn == 0 && notifyFn == 0 && flowDeleteFn == 0)
            {
                continue;
            }
            ++nonNull;
            const uint64_t ownedProbe = (classifyFn != 0)
                ? classifyFn
                : ((notifyFn != 0) ? notifyFn : flowDeleteFn);
            if (IsKernelAddress(ownedProbe) && !FindOwningModule(symbols, ownedProbe).empty())
            {
                ++valid;
            }
        }

        *outCount = count;
        *outArray = arrayPtr;
        *outNonNull = nonNull;

        if (nonNull < 4)
        {
            return 0.0;
        }
        return static_cast<double>(valid) / static_cast<double>(nonNull);
    }

    void BuildCalloutMetadata(std::map<uint32_t, WfpRecord>* metadata)
    {
        WfpScanner scanner;
        WfpScanner::Options options = {};
        options.Target = WfpScanner::Scope::Callouts;
        WfpScanResult result = {};
        std::wstring error;
        if (!scanner.Scan(options, &result, &error))
        {
            return;
        }
        for (const WfpRecord& record : result.Records)
        {
            if (record.HasCalloutId)
            {
                (*metadata)[record.CalloutId] = record;
            }
        }
    }
}

WfpCalloutScanner::WfpCalloutScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

namespace
{
    constexpr size_t kPolicyStateCharacters = 16384;
    constexpr size_t kPolicyTotalCharacters = 8 * 1024 * 1024;

    bool PolicyAppend(std::wstring* state, const std::wstring& value)
    {
        if (value.size() > kPolicyStateCharacters ||
            state->size() > kPolicyStateCharacters - value.size() ||
            state->size() + value.size() > kPolicyStateCharacters - 24)
        {
            return false;
        }
        *state += std::to_wstring(value.size()) + L":" + value;
        return true;
    }

    bool PolicyBytes(std::wstring* state, const void* data, size_t bytes)
    {
        if (bytes > 4096 || (bytes != 0 && data == nullptr))
        {
            return false;
        }
        const auto* values = static_cast<const uint8_t*>(data);
        static constexpr wchar_t digits[] = L"0123456789abcdef";
        std::wstring text;
        text.reserve(bytes * 2);
        for (size_t i = 0; i < bytes; ++i)
        {
            text.push_back(digits[values[i] >> 4]);
            text.push_back(digits[values[i] & 15]);
        }
        return PolicyAppend(state, text);
    }

    std::wstring PolicyGuid(const GUID& value)
    {
        std::wstring out;
        PolicyBytes(&out, &value, sizeof(value));
        return out;
    }

    bool PolicyString(std::wstring* state, const wchar_t* text)
    {
        if (text == nullptr)
        {
            return PolicyAppend(state, L"");
        }
        const size_t length = wcsnlen_s(text, 1025);
        return length <= 1024 && PolicyAppend(state, std::wstring(text, length));
    }

    bool PolicyTokenSids(std::wstring* state, const SID_AND_ATTRIBUTES* sids, size_t count)
    {
        if (count > 64 || (count != 0 && sids == nullptr) || !PolicyAppend(state, std::to_wstring(count)))
        {
            return false;
        }
        for (size_t i = 0; i < count; ++i)
        {
            if (sids[i].Sid == nullptr || !IsValidSid(sids[i].Sid) ||
                !PolicyBytes(state, sids[i].Sid, GetLengthSid(sids[i].Sid)) ||
                !PolicyAppend(state, std::to_wstring(sids[i].Attributes)))
            {
                return false;
            }
        }
        return true;
    }

    template<typename Value>
    bool PolicyScalar(std::wstring* state, const Value& value)
    {
        if (!PolicyAppend(state, std::to_wstring(value.type)))
        {
            return false;
        }
        switch (value.type)
        {
        case FWP_EMPTY:
            return true;
        case FWP_UINT8:
            return PolicyBytes(state, &value.uint8, sizeof(value.uint8));
        case FWP_UINT16:
            return PolicyBytes(state, &value.uint16, sizeof(value.uint16));
        case FWP_UINT32:
            return PolicyBytes(state, &value.uint32, sizeof(value.uint32));
        case FWP_UINT64:
            return PolicyBytes(state, value.uint64, sizeof(uint64_t));
        case FWP_INT8:
            return PolicyBytes(state, &value.int8, sizeof(value.int8));
        case FWP_INT16:
            return PolicyBytes(state, &value.int16, sizeof(value.int16));
        case FWP_INT32:
            return PolicyBytes(state, &value.int32, sizeof(value.int32));
        case FWP_INT64:
            return PolicyBytes(state, value.int64, sizeof(int64_t));
        case FWP_FLOAT:
            return PolicyBytes(state, &value.float32, sizeof(value.float32));
        case FWP_DOUBLE:
            return PolicyBytes(state, value.double64, sizeof(double));
        case FWP_BYTE_ARRAY16_TYPE:
            return PolicyBytes(state, value.byteArray16, sizeof(FWP_BYTE_ARRAY16));
        case FWP_BYTE_ARRAY6_TYPE:
            return PolicyBytes(state, value.byteArray6, sizeof(FWP_BYTE_ARRAY6));
        case FWP_BYTE_BLOB_TYPE:
            return value.byteBlob != nullptr && PolicyBytes(state, value.byteBlob->data, value.byteBlob->size);
        case FWP_SECURITY_DESCRIPTOR_TYPE:
            return value.sd != nullptr && PolicyBytes(state, value.sd->data, value.sd->size);
        case FWP_TOKEN_ACCESS_INFORMATION_TYPE:
            return value.tokenAccessInformation != nullptr &&
                PolicyBytes(state, value.tokenAccessInformation->data, value.tokenAccessInformation->size);
        case FWP_TOKEN_INFORMATION_TYPE:
            return value.tokenInformation != nullptr &&
                PolicyTokenSids(state, value.tokenInformation->sids, value.tokenInformation->sidCount) &&
                PolicyTokenSids(state, value.tokenInformation->restrictedSids, value.tokenInformation->restrictedSidCount);
        case FWP_SID:
            return value.sid != nullptr && IsValidSid(value.sid) &&
                PolicyBytes(state, value.sid, GetLengthSid(value.sid));
        case FWP_UNICODE_STRING_TYPE:
            return PolicyString(state, value.unicodeString);
        default:
            return false;
        }
    }

    bool PolicyCondition(std::wstring* state, const FWP_CONDITION_VALUE0& value)
    {
        if (value.type == FWP_V4_ADDR_MASK)
        {
            return value.v4AddrMask != nullptr && PolicyAppend(state, L"v4mask") &&
                PolicyBytes(state, &value.v4AddrMask->addr, sizeof(uint32_t)) &&
                PolicyBytes(state, &value.v4AddrMask->mask, sizeof(uint32_t));
        }
        if (value.type == FWP_V6_ADDR_MASK)
        {
            return value.v6AddrMask != nullptr && value.v6AddrMask->prefixLength <= 128 &&
                PolicyAppend(state, L"v6mask") && PolicyBytes(state, value.v6AddrMask->addr, 16) &&
                PolicyBytes(state, &value.v6AddrMask->prefixLength, 1);
        }
        if (value.type == FWP_RANGE_TYPE)
        {
            return value.rangeValue != nullptr && PolicyAppend(state, L"range") &&
                PolicyScalar(state, value.rangeValue->valueLow) && PolicyScalar(state, value.rangeValue->valueHigh);
        }
        return PolicyScalar(state, value);
    }

    bool BuildPolicyFilterState(const FWPM_FILTER0& filter, WfpPolicyRecord* record)
    {
        record->Kind = L"filter";
        record->Key = PolicyGuid(filter.filterKey);
        record->Id = filter.filterId;
        record->Flags = filter.flags;
        if (filter.displayData.name != nullptr)
        {
            record->Name.assign(filter.displayData.name, wcsnlen_s(filter.displayData.name, 512));
        }
        bool complete = PolicyAppend(&record->State, std::to_wstring(filter.flags)) &&
            PolicyAppend(&record->State, PolicyGuid(filter.layerKey)) &&
            PolicyAppend(&record->State, PolicyGuid(filter.subLayerKey)) &&
            PolicyAppend(&record->State, filter.providerKey == nullptr ? L"" : PolicyGuid(*filter.providerKey)) &&
            PolicyBytes(&record->State, filter.providerData.data, filter.providerData.size) &&
            PolicyAppend(&record->State, std::to_wstring(filter.action.type)) &&
            PolicyAppend(&record->State, (filter.action.type & FWP_ACTION_FLAG_CALLOUT) != 0
                ? PolicyGuid(filter.action.calloutKey) : L"") &&
            PolicyScalar(&record->State, filter.weight) && PolicyScalar(&record->State, filter.effectiveWeight);
        if ((filter.flags & FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT) != 0)
        {
            complete = PolicyAppend(&record->State, PolicyGuid(filter.providerContextKey)) && complete;
        }
        else
        {
            complete = PolicyAppend(&record->State, std::to_wstring(filter.rawContext)) && complete;
        }
        complete = PolicyAppend(&record->State, std::to_wstring(filter.numFilterConditions)) && complete;
        if (filter.numFilterConditions > 128 || (filter.numFilterConditions != 0 && filter.filterCondition == nullptr))
        {
            return false;
        }
        std::vector<std::wstring> conditions;
        for (uint32_t i = 0; i < filter.numFilterConditions; ++i)
        {
            const FWPM_FILTER_CONDITION0& condition = filter.filterCondition[i];
            std::wstring state;
            complete = condition.matchType < FWP_MATCH_TYPE_MAX &&
                PolicyAppend(&state, PolicyGuid(condition.fieldKey)) &&
                PolicyAppend(&state, std::to_wstring(condition.matchType)) &&
                PolicyCondition(&state, condition.conditionValue) && complete;
            conditions.push_back(std::move(state));
        }
        std::sort(conditions.begin(), conditions.end());
        for (const std::wstring& state : conditions)
        {
            complete = PolicyAppend(&record->State, state) && complete;
        }
        return complete;
    }

    struct PolicyEngineOwner
    {
        HANDLE Handle = nullptr;
        bool Transaction = false;
        ~PolicyEngineOwner()
        {
            if (Handle != nullptr)
            {
                if (Transaction)
                {
                    FwpmTransactionAbort0(Handle);
                }
                FwpmEngineClose0(Handle);
            }
        }
    };

    struct PolicyMemoryOwner
    {
        void* Value = nullptr;
        ~PolicyMemoryOwner()
        {
            if (Value != nullptr)
            {
                FwpmFreeMemory0(&Value);
            }
        }
    };

    template<typename Item, typename Create, typename Enumerate, typename Destroy, typename Visitor>
    bool EnumeratePolicyObjects(HANDLE engine, Create create, Enumerate enumerate, Destroy destroy,
        Visitor& visit, size_t maximum, std::vector<std::wstring>* warnings)
    {
        HANDLE handle = nullptr;
        const DWORD status = create(engine, nullptr, &handle);
        if (status != ERROR_SUCCESS)
        {
            warnings->push_back(L"WFP enumeration creation failed: " + std::to_wstring(status));
            return false;
        }
        struct EnumOwner
        {
            HANDLE Engine;
            HANDLE Handle;
            Destroy Release;
            ~EnumOwner()
            {
                Release(Engine, Handle);
            }
        } owner{engine, handle, destroy};
        size_t observed = 0;
        while (true)
        {
            Item** entries = nullptr;
            UINT32 count = 0;
            const DWORD next = enumerate(engine, handle, 128, &entries, &count);
            PolicyMemoryOwner memory;
            memory.Value = entries;
            if (next != ERROR_SUCCESS || count > 128 || (count != 0 && entries == nullptr))
            {
                warnings->push_back(L"WFP enumeration failed or returned invalid bounds: " + std::to_wstring(next));
                return false;
            }
            if (count == 0)
            {
                return true;
            }
            if (observed > maximum || count > maximum - observed)
            {
                warnings->push_back(L"WFP inventory reached its bounded object cap");
                return false;
            }
            observed += count;
            for (UINT32 i = 0; i < count; ++i)
            {
                if (entries[i] == nullptr || !visit(*entries[i]))
                {
                    warnings->push_back(L"WFP inventory identity or evidence budget failed validation");
                    return false;
                }
            }
        }
    }
}

bool WfpCalloutScanner::ScanPolicy(WfpPolicyScanResult* result, std::wstring* error)
{
    if (result == nullptr)
    {
        return false;
    }
    *result = WfpPolicyScanResult{};
    result->SnapshotTickMs = GetTickCount64();
    PolicyEngineOwner engine;
    DWORD status = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine.Handle);
    if (status == ERROR_SUCCESS)
    {
        status = FwpmTransactionBegin0(engine.Handle, FWPM_TXN_READ_ONLY);
    }
    if (status != ERROR_SUCCESS)
    {
        if (error != nullptr)
        {
            *error = L"WFP read-only snapshot transaction failed: " + std::to_wstring(status);
        }
        return false;
    }
    engine.Transaction = true;
    result->ReadOnlyTransaction = true;
    std::set<std::wstring> identities;
    size_t characters = 0;
    bool fieldsComplete = true;
    const auto keep = [&](WfpPolicyRecord&& record)
    {
        if (!identities.insert(record.Kind + L":" + record.Key).second ||
            record.State.size() > kPolicyTotalCharacters - characters)
        {
            return false;
        }
        characters += record.State.size();
        fieldsComplete = fieldsComplete && record.StateComplete;
        result->Records.push_back(std::move(record));
        return true;
    };
    auto visitFilter = [&](const FWPM_FILTER0& filter)
    {
        WfpPolicyRecord record;
        record.StateComplete = BuildPolicyFilterState(filter, &record);
        return keep(std::move(record));
    };
    const bool filters = EnumeratePolicyObjects<FWPM_FILTER0>(engine.Handle,
        FwpmFilterCreateEnumHandle0, FwpmFilterEnum0, FwpmFilterDestroyEnumHandle0,
        visitFilter, 16384, &result->Warnings);
    auto visitCallout = [&](const FWPM_CALLOUT0& callout)
    {
        WfpPolicyRecord record;
        record.Kind = L"callout";
        record.Key = PolicyGuid(callout.calloutKey);
        record.Id = callout.calloutId;
        record.Flags = callout.flags;
        if (callout.displayData.name != nullptr)
        {
            record.Name.assign(callout.displayData.name, wcsnlen_s(callout.displayData.name, 512));
        }
        record.StateComplete = PolicyAppend(&record.State, std::to_wstring(callout.flags)) &&
            PolicyAppend(&record.State, PolicyGuid(callout.applicableLayer)) &&
            PolicyAppend(&record.State, callout.providerKey == nullptr ? L"" : PolicyGuid(*callout.providerKey)) &&
            PolicyBytes(&record.State, callout.providerData.data, callout.providerData.size);
        return keep(std::move(record));
    };
    const bool callouts = EnumeratePolicyObjects<FWPM_CALLOUT0>(engine.Handle,
        FwpmCalloutCreateEnumHandle0, FwpmCalloutEnum0, FwpmCalloutDestroyEnumHandle0,
        visitCallout, 8192, &result->Warnings);
    auto visitProvider = [&](const FWPM_PROVIDER0& provider)
    {
        WfpPolicyRecord record;
        record.Kind = L"provider";
        record.Key = PolicyGuid(provider.providerKey);
        record.Flags = provider.flags;
        if (provider.displayData.name != nullptr)
        {
            record.Name.assign(provider.displayData.name, wcsnlen_s(provider.displayData.name, 512));
        }
        record.StateComplete = PolicyAppend(&record.State, std::to_wstring(provider.flags)) &&
            PolicyString(&record.State, provider.serviceName) &&
            PolicyBytes(&record.State, provider.providerData.data, provider.providerData.size);
        return keep(std::move(record));
    };
    const bool providers = EnumeratePolicyObjects<FWPM_PROVIDER0>(engine.Handle,
        FwpmProviderCreateEnumHandle0, FwpmProviderEnum0, FwpmProviderDestroyEnumHandle0,
        visitProvider, 4096, &result->Warnings);
    auto visitSublayer = [&](const FWPM_SUBLAYER0& sublayer)
    {
        WfpPolicyRecord record;
        record.Kind = L"sublayer";
        record.Key = PolicyGuid(sublayer.subLayerKey);
        record.Flags = sublayer.flags;
        if (sublayer.displayData.name != nullptr)
        {
            record.Name.assign(sublayer.displayData.name, wcsnlen_s(sublayer.displayData.name, 512));
        }
        record.StateComplete = PolicyAppend(&record.State, std::to_wstring(sublayer.flags)) &&
            PolicyAppend(&record.State, std::to_wstring(sublayer.weight)) &&
            PolicyAppend(&record.State, sublayer.providerKey == nullptr ? L"" : PolicyGuid(*sublayer.providerKey)) &&
            PolicyBytes(&record.State, sublayer.providerData.data, sublayer.providerData.size);
        return keep(std::move(record));
    };
    const bool sublayers = EnumeratePolicyObjects<FWPM_SUBLAYER0>(engine.Handle,
        FwpmSubLayerCreateEnumHandle0, FwpmSubLayerEnum0, FwpmSubLayerDestroyEnumHandle0,
        visitSublayer, 4096, &result->Warnings);
    result->InventoryComplete = filters && callouts && providers && sublayers;
    result->CoverageComplete = result->InventoryComplete && fieldsComplete;
    result->Warnings.push_back(L"BFE enumeration includes only readable objects; ACL changes can alter visibility");
    if (!fieldsComplete)
    {
        result->Warnings.push_back(L"some WFP condition values exceed supported type or size bounds; state comparison is partial");
    }
    return true;
}

bool WfpPolicyScannerSelfTest()
{
    FWPM_FILTER0 filter = {};
    filter.filterId = 1;
    filter.action.type = FWP_ACTION_BLOCK;
    WfpPolicyRecord first;
    if (!BuildPolicyFilterState(filter, &first))
    {
        return false;
    }
    WfpPolicyRecord same;
    if (!BuildPolicyFilterState(filter, &same) || same.State != first.State)
    {
        return false;
    }
    filter.action.type = FWP_ACTION_PERMIT;
    WfpPolicyRecord changed;
    if (!BuildPolicyFilterState(filter, &changed) || changed.State == first.State)
    {
        return false;
    }
    FWPM_FILTER_CONDITION0 condition = {};
    condition.matchType = FWP_MATCH_EQUAL;
    condition.conditionValue.type = FWP_UINT16;
    condition.conditionValue.uint16 = 443;
    filter.numFilterConditions = 1;
    filter.filterCondition = &condition;
    WfpPolicyRecord port;
    if (!BuildPolicyFilterState(filter, &port))
    {
        return false;
    }
    condition.conditionValue.uint16 = 80;
    WfpPolicyRecord changedPort;
    if (!BuildPolicyFilterState(filter, &changedPort) || changedPort.State == port.State)
    {
        return false;
    }
    filter.numFilterConditions = 129;
    WfpPolicyRecord oversized;
    if (BuildPolicyFilterState(filter, &oversized))
    {
        return false;
    }
    filter.numFilterConditions = 1;
    condition.conditionValue.type = static_cast<FWP_DATA_TYPE>(0xffff);
    WfpPolicyRecord unsupported;
    return !BuildPolicyFilterState(filter, &unsupported);
}

bool WfpCalloutScanner::Scan(WfpCalloutScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid WFP callout scan result output";
            }
            break;
        }

        *result = WfpCalloutScanResult{};

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

        uint64_t globalSymbol = 0;
        if (!symbols_.ResolveSymbol(L"netio!gWfpGlobal", &globalSymbol, nullptr) || globalSymbol == 0)
        {
            result->Resolved = false;
            result->CoverageComplete = false;
            result->Incomplete = true;
            result->Warnings.push_back(
                L"netio!gWfpGlobal not resolved; netio.sys private/public symbols are required for kernel callout walking");
            result->Warnings.push_back(
                L"coverage incomplete: kernel callout table was not walked (not a clean empty result)");
            ok = true; // soft failure: operator sees unresolved, not a crash
            break;
        }
        result->GlobalSymbol = globalSymbol;

        // The engine state may live at the symbol directly or behind a pointer
        // at the symbol. Validate both interpretations against the layouts.
        std::vector<uint64_t> bases;
        bases.push_back(globalSymbol);
        uint64_t deref = 0;
        if (ReadU64(device_, globalSymbol, &deref) && IsKernelAddress(deref))
        {
            bases.push_back(deref);
        }

        const LayoutCandidate documented[] =
        {
            // Win11 (validated on a 26x00-era build): engine struct behind the
            // pointer at gWfpGlobal, count @ +0x198, array @ +0x1a0, 0x60-byte
            // slots, classify @ +0x10.
            { 0x198, 0x1a0, 0x60, 0x10, L"*gWfpGlobal+0x1a0 / 0x60-byte slots / classify +0x10 (Win11)" },
            { 0x190, 0x198, 0x50, 0x10, L"gWfpGlobal+0x198 / 0x50-byte slots / classify +0x10" },
            { 0x548, 0x550, 0x40, 0x10, L"gWfpGlobal+0x550 / 0x40-byte slots / classify +0x10" }
        };

        double bestScore = 0.0;
        uint64_t bestBase = 0;
        LayoutCandidate bestLayout = documented[0];
        uint32_t bestCount = 0;
        uint64_t bestArray = 0;

        for (uint64_t base : bases)
        {
            for (const LayoutCandidate& layout : documented)
            {
                uint32_t count = 0;
                uint64_t arrayPtr = 0;
                uint32_t nonNull = 0;
                double score = ScoreLayout(device_, symbols_, base, layout, &count, &arrayPtr, &nonNull);
                if (score > bestScore)
                {
                    bestScore = score;
                    bestBase = base;
                    bestLayout = layout;
                    bestCount = count;
                    bestArray = arrayPtr;
                }
            }
        }

        // Bounded fallback scan if no documented layout validated, to tolerate
        // offset drift on builds the documented offsets do not match.
        if (bestScore < 0.8)
        {
            const uint32_t entrySizes[] = { 0x50, 0x40, 0x48, 0x60 };
            for (uint64_t base : bases)
            {
                for (uint32_t arrayOff = 0x180; arrayOff <= 0x560; arrayOff += 8)
                {
                    for (uint32_t entrySize : entrySizes)
                    {
                        LayoutCandidate layout = { arrayOff - 8, arrayOff, entrySize, 0x10, L"scored fallback" };
                        uint32_t count = 0;
                        uint64_t arrayPtr = 0;
                        uint32_t nonNull = 0;
                        double score = ScoreLayout(device_, symbols_, base, layout, &count, &arrayPtr, &nonNull);
                        if (score > bestScore)
                        {
                            bestScore = score;
                            bestBase = base;
                            bestLayout = layout;
                            bestCount = count;
                            bestArray = arrayPtr;
                        }
                    }
                }
            }
        }

        if (bestScore < 0.8 || bestArray == 0)
        {
            result->Resolved = false;
            result->CoverageComplete = false;
            result->Incomplete = true;
            result->Warnings.push_back(
                L"could not locate a plausible WFP callout array from gWfpGlobal; netio.sys layout may have drifted (offsets need RE refinement on this build)");
            result->Warnings.push_back(
                L"coverage incomplete: kernel callout table was not walked (not a clean empty result)");
            ok = true;
            break;
        }

        result->EngineBase = bestBase;
        result->ArrayAddress = bestArray;
        result->Count = bestCount;
        result->EntrySize = bestLayout.EntrySize;
        result->ClassifyOffset = bestLayout.ClassifyOffset;
        result->CountOffset = bestLayout.CountOffset;
        result->ArrayOffset = bestLayout.ArrayOffset;
        result->EngineFromPointer = (bestBase != globalSymbol);
        result->LayoutSource = bestLayout.Source;
        result->Resolved = true;

        // Walk the full array (bounded by the transfer cap).
        uint32_t walkCount = bestCount;
        uint64_t walkBytes = static_cast<uint64_t>(walkCount) * bestLayout.EntrySize;
        if (walkBytes > kMaxWalkBytes)
        {
            walkCount = kMaxWalkBytes / bestLayout.EntrySize;
            result->Incomplete = true;
            result->Warnings.push_back(L"callout count exceeds single-read bound; walk truncated");
        }

        std::vector<uint8_t> buffer;
        uint32_t bufferBytes = walkCount * bestLayout.EntrySize;
        if (!device_.ReadMemory(bestArray, bufferBytes, &buffer, nullptr) || buffer.size() != bufferBytes)
        {
            result->CoverageComplete = false;
            result->Incomplete = true;
            result->Warnings.push_back(L"failed to read the full callout array");
            result->Warnings.push_back(
                L"coverage incomplete: layout resolved but array bytes were not readable");
            ok = true;
            break;
        }

        std::map<uint32_t, WfpRecord> metadata;
        BuildCalloutMetadata(&metadata);

        for (uint32_t i = 0; i < walkCount; ++i)
        {
            size_t entryOffset = static_cast<size_t>(i) * bestLayout.EntrySize;
            uint64_t classifyFn = ReadEntryU64(buffer, entryOffset, bestLayout.ClassifyOffset);
            const uint32_t notifyOffset = bestLayout.ClassifyOffset + 8;
            const uint32_t flowDeleteOffset = bestLayout.ClassifyOffset + 16;
            uint64_t notifyFn = 0;
            uint64_t flowDeleteFn = 0;
            if (notifyOffset + sizeof(uint64_t) <= bestLayout.EntrySize)
            {
                notifyFn = ReadEntryU64(buffer, entryOffset, notifyOffset);
            }
            if (flowDeleteOffset + sizeof(uint64_t) <= bestLayout.EntrySize)
            {
                flowDeleteFn = ReadEntryU64(buffer, entryOffset, flowDeleteOffset);
            }
            if (classifyFn == 0 && notifyFn == 0 && flowDeleteFn == 0)
            {
                continue;
            }

            WfpKernelCallout callout = {};
            callout.CalloutId = i;
            callout.EntryAddress = bestArray + entryOffset;
            callout.ClassifyFn = classifyFn;
            callout.NotifyFn = notifyFn;
            callout.FlowDeleteFn = flowDeleteFn;

            if (classifyFn != 0)
            {
                callout.ClassifyModule = FindOwningModule(symbols_, classifyFn);
                callout.ClassifySymbol = NearestSymbolText(symbols_, classifyFn);
                if (!IsKernelAddress(callout.ClassifyFn) || callout.ClassifyModule.empty())
                {
                    callout.ClassifySuspicious = true;
                    callout.Notes = L"classify function outside loaded kernel modules";
                    ++result->SuspiciousCount;
                    result->AnySuspicious = true;
                }
            }

            if (callout.NotifyFn != 0)
            {
                if (IsKernelAddress(callout.NotifyFn))
                {
                    callout.NotifyModule = FindOwningModule(symbols_, callout.NotifyFn);
                }
                if (!IsKernelAddress(callout.NotifyFn) || callout.NotifyModule.empty())
                {
                    callout.NotifySuspicious = true;
                    if (callout.Notes.empty())
                    {
                        callout.Notes = L"notify function outside loaded kernel modules";
                    }
                    else
                    {
                        callout.Notes += L"; notify outside loaded modules";
                    }
                    ++result->SuspiciousCount;
                    result->AnySuspicious = true;
                }
            }
            if (callout.FlowDeleteFn != 0)
            {
                if (IsKernelAddress(callout.FlowDeleteFn))
                {
                    callout.FlowDeleteModule = FindOwningModule(symbols_, callout.FlowDeleteFn);
                }
                if (!IsKernelAddress(callout.FlowDeleteFn) || callout.FlowDeleteModule.empty())
                {
                    callout.FlowDeleteSuspicious = true;
                    if (callout.Notes.empty())
                    {
                        callout.Notes = L"flowDelete function outside loaded kernel modules";
                    }
                    else
                    {
                        callout.Notes += L"; flowDelete outside loaded modules";
                    }
                    ++result->SuspiciousCount;
                    result->AnySuspicious = true;
                }
            }

            auto it = metadata.find(i);
            if (it != metadata.end())
            {
                callout.HasMetadata = true;
                callout.Name = it->second.Name;
                callout.LayerName = it->second.LayerName;
                callout.ProviderName = it->second.ProviderName;
            }

            result->Callouts.push_back(std::move(callout));
        }

        result->CoverageComplete = !result->Incomplete;
        ok = true;
    } while (false);

    return ok;
}
