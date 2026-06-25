#include "WfpScanner.h"

#include <Windows.h>
#include <Rpc.h>
#include <winsock2.h>
#include <ws2ipdef.h>
#include <fwpmu.h>

#include "McpJson.h"

#include <algorithm>
#include <cstdio>
#include <cwctype>
#include <sstream>
#include <utility>

#pragma comment(lib, "Fwpuclnt.lib")

namespace
{
    constexpr uint32_t kWfpEnumPageSize = 128;

    std::wstring ToLowerCopy(const std::wstring& value)
    {
        std::wstring result = value;

        for (wchar_t& ch : result)
        {
            ch = static_cast<wchar_t>(std::towlower(ch));
        }

        return result;
    }

    std::wstring TrimCopy(const std::wstring& value)
    {
        std::wstring result;

        do
        {
            size_t first = 0;
            while (first < value.size() && std::iswspace(value[first]) != 0)
            {
                ++first;
            }

            if (first >= value.size())
            {
                break;
            }

            size_t last = value.size();
            while (last > first && std::iswspace(value[last - 1]) != 0)
            {
                --last;
            }

            result = value.substr(first, last - first);
        } while (false);

        return result;
    }

    std::wstring FormatGuidText(const GUID& g)
    {
        wchar_t buf[64];

        int written = swprintf_s(
            buf,
            L"{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
            static_cast<unsigned long>(g.Data1),
            static_cast<unsigned int>(g.Data2),
            static_cast<unsigned int>(g.Data3),
            g.Data4[0],
            g.Data4[1],
            g.Data4[2],
            g.Data4[3],
            g.Data4[4],
            g.Data4[5],
            g.Data4[6],
            g.Data4[7]);

        if (written < 0)
        {
            return L"{?}";
        }

        return std::wstring(buf);
    }

    bool ParseGuidText(const std::wstring& text, GUID* out)
    {
        bool ok = false;

        do
        {
            if (out == nullptr || text.empty())
            {
                break;
            }

            std::wstring stripped = TrimCopy(text);
            if (stripped.size() >= 2 && stripped.front() == L'{' && stripped.back() == L'}')
            {
                stripped = stripped.substr(1, stripped.size() - 2);
            }

            if (stripped.size() != 36)
            {
                break;
            }

            unsigned long d1 = 0;
            unsigned int d2 = 0;
            unsigned int d3 = 0;
            unsigned int b[8] = {};
            int matched = swscanf_s(
                stripped.c_str(),
                L"%8lx-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x",
                &d1, &d2, &d3,
                &b[0], &b[1], &b[2], &b[3], &b[4], &b[5], &b[6], &b[7]);

            if (matched != 11)
            {
                break;
            }

            out->Data1 = static_cast<unsigned long>(d1);
            out->Data2 = static_cast<unsigned short>(d2);
            out->Data3 = static_cast<unsigned short>(d3);
            for (int i = 0; i < 8; ++i)
            {
                out->Data4[i] = static_cast<unsigned char>(b[i]);
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool GuidsEqual(const GUID& a, const GUID& b)
    {
        return memcmp(&a, &b, sizeof(GUID)) == 0;
    }

    std::wstring FormatDisplayDataName(const FWPM_DISPLAY_DATA0& display)
    {
        if (display.name != nullptr)
        {
            return std::wstring(display.name);
        }

        return std::wstring();
    }

    std::wstring FormatDisplayDataDescription(const FWPM_DISPLAY_DATA0& display)
    {
        if (display.description != nullptr)
        {
            return std::wstring(display.description);
        }

        return std::wstring();
    }

    std::wstring FormatNullableString(const wchar_t* value)
    {
        if (value == nullptr)
        {
            return std::wstring();
        }

        return std::wstring(value);
    }

    bool ContainsNoCase(const std::wstring& haystack, const std::wstring& needle)
    {
        bool found = false;

        do
        {
            if (needle.empty())
            {
                found = true;
                break;
            }

            std::wstring h = ToLowerCopy(haystack);
            std::wstring n = ToLowerCopy(needle);
            if (h.find(n) != std::wstring::npos)
            {
                found = true;
            }
        } while (false);

        return found;
    }

    const wchar_t* FwpActionTypeText(uint32_t action)
    {
        const wchar_t* text = L"Unknown";

        switch (action)
        {
        case FWP_ACTION_BLOCK:
            text = L"Block";
            break;
        case FWP_ACTION_PERMIT:
            text = L"Permit";
            break;
        case FWP_ACTION_CALLOUT_TERMINATING:
            text = L"CalloutTerminating";
            break;
        case FWP_ACTION_CALLOUT_INSPECTION:
            text = L"CalloutInspection";
            break;
        case FWP_ACTION_CALLOUT_UNKNOWN:
            text = L"CalloutUnknown";
            break;
        case FWP_ACTION_CONTINUE:
            text = L"Continue";
            break;
        case FWP_ACTION_NONE:
            text = L"None";
            break;
        case FWP_ACTION_NONE_NO_MATCH:
            text = L"NoneNoMatch";
            break;
        default:
            if (action == 0x00001009u)
            {
                text = L"BitmaskPermit";
            }
            else if (action == 0x0000100au)
            {
                text = L"BitmaskBlock";
            }
            break;
        }

        return text;
    }

    std::wstring AppendFlagToken(const std::wstring& acc, const wchar_t* token)
    {
        std::wstring result = acc;

        if (!result.empty())
        {
            result.append(L"|");
        }

        result.append(token);
        return result;
    }

    std::wstring FormatProviderFlags(uint32_t flags)
    {
        std::wstring acc;

        if ((flags & FWPM_PROVIDER_FLAG_PERSISTENT) != 0)
        {
            acc = AppendFlagToken(acc, L"persistent");
        }

        if ((flags & 0x00000010u) != 0)
        {
            acc = AppendFlagToken(acc, L"disabled");
        }

        return acc;
    }

    std::wstring FormatSubLayerFlags(uint32_t flags)
    {
        std::wstring acc;

        if ((flags & FWPM_SUBLAYER_FLAG_PERSISTENT) != 0)
        {
            acc = AppendFlagToken(acc, L"persistent");
        }

        return acc;
    }

    std::wstring FormatCalloutFlags(uint32_t flags)
    {
        std::wstring acc;

        if ((flags & FWPM_CALLOUT_FLAG_PERSISTENT) != 0)
        {
            acc = AppendFlagToken(acc, L"persistent");
        }

        if ((flags & FWPM_CALLOUT_FLAG_USES_PROVIDER_CONTEXT) != 0)
        {
            acc = AppendFlagToken(acc, L"usesProviderContext");
        }

        if ((flags & FWPM_CALLOUT_FLAG_REGISTERED) != 0)
        {
            acc = AppendFlagToken(acc, L"registered");
        }

        return acc;
    }

    std::wstring FormatLayerFlags(uint32_t flags)
    {
        std::wstring acc;

        if ((flags & FWPM_LAYER_FLAG_KERNEL) != 0)
        {
            acc = AppendFlagToken(acc, L"kernel");
        }

        if ((flags & FWPM_LAYER_FLAG_BUILTIN) != 0)
        {
            acc = AppendFlagToken(acc, L"builtin");
        }

        if ((flags & FWPM_LAYER_FLAG_CLASSIFY_MOSTLY) != 0)
        {
            acc = AppendFlagToken(acc, L"classifyMostly");
        }

        if ((flags & FWPM_LAYER_FLAG_BUFFERED) != 0)
        {
            acc = AppendFlagToken(acc, L"buffered");
        }

        return acc;
    }

    std::wstring FormatFilterFlags(uint32_t flags)
    {
        std::wstring acc;

        if ((flags & FWPM_FILTER_FLAG_PERSISTENT) != 0)
        {
            acc = AppendFlagToken(acc, L"persistent");
        }

        if ((flags & FWPM_FILTER_FLAG_BOOTTIME) != 0)
        {
            acc = AppendFlagToken(acc, L"boottime");
        }

        if ((flags & FWPM_FILTER_FLAG_HAS_PROVIDER_CONTEXT) != 0)
        {
            acc = AppendFlagToken(acc, L"hasProviderContext");
        }

        if ((flags & FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT) != 0)
        {
            acc = AppendFlagToken(acc, L"clearActionRight");
        }

        if ((flags & FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED) != 0)
        {
            acc = AppendFlagToken(acc, L"permitIfCalloutUnregistered");
        }

        if ((flags & FWPM_FILTER_FLAG_DISABLED) != 0)
        {
            acc = AppendFlagToken(acc, L"disabled");
        }

        if ((flags & FWPM_FILTER_FLAG_INDEXED) != 0)
        {
            acc = AppendFlagToken(acc, L"indexed");
        }

        if ((flags & 0x00000080u) != 0)
        {
            acc = AppendFlagToken(acc, L"hasSecurityRealmProviderContext");
        }

        if ((flags & 0x00000100u) != 0)
        {
            acc = AppendFlagToken(acc, L"systemOsOnly");
        }

        if ((flags & 0x00000200u) != 0)
        {
            acc = AppendFlagToken(acc, L"gameOsOnly");
        }

        if ((flags & 0x00000400u) != 0)
        {
            acc = AppendFlagToken(acc, L"silentMode");
        }

        if ((flags & 0x00000800u) != 0)
        {
            acc = AppendFlagToken(acc, L"ipsecNoAcquireInitiate");
        }

        return acc;
    }

    std::wstring FormatFwpValueText(const FWP_VALUE0& value)
    {
        std::wstringstream stream;

        switch (value.type)
        {
        case FWP_EMPTY:
            stream << L"empty";
            break;
        case FWP_UINT8:
            stream << L"0x" << std::hex << static_cast<unsigned int>(value.uint8) << std::dec;
            break;
        case FWP_UINT16:
            stream << L"0x" << std::hex << static_cast<unsigned int>(value.uint16) << std::dec;
            break;
        case FWP_UINT32:
            stream << L"0x" << std::hex << static_cast<unsigned long>(value.uint32) << std::dec;
            break;
        case FWP_UINT64:
            if (value.uint64 != nullptr)
            {
                stream << L"0x" << std::hex << *value.uint64 << std::dec;
            }
            else
            {
                stream << L"<null>";
            }
            break;
        case FWP_INT8:
            stream << static_cast<int>(value.int8);
            break;
        case FWP_INT16:
            stream << static_cast<int>(value.int16);
            break;
        case FWP_INT32:
            stream << static_cast<long>(value.int32);
            break;
        case FWP_INT64:
            if (value.int64 != nullptr)
            {
                stream << *value.int64;
            }
            else
            {
                stream << L"<null>";
            }
            break;
        default:
            stream << L"type=" << static_cast<unsigned int>(value.type);
            break;
        }

        return stream.str();
    }

    const wchar_t* FwpMatchTypeText(FWP_MATCH_TYPE matchType)
    {
        const wchar_t* text = L"Unknown";

        switch (matchType)
        {
        case FWP_MATCH_EQUAL:
            text = L"Equal";
            break;
        case FWP_MATCH_GREATER:
            text = L"Greater";
            break;
        case FWP_MATCH_LESS:
            text = L"Less";
            break;
        case FWP_MATCH_GREATER_OR_EQUAL:
            text = L"GreaterOrEqual";
            break;
        case FWP_MATCH_LESS_OR_EQUAL:
            text = L"LessOrEqual";
            break;
        case FWP_MATCH_RANGE:
            text = L"Range";
            break;
        case FWP_MATCH_FLAGS_ALL_SET:
            text = L"FlagsAllSet";
            break;
        case FWP_MATCH_FLAGS_ANY_SET:
            text = L"FlagsAnySet";
            break;
        case FWP_MATCH_FLAGS_NONE_SET:
            text = L"FlagsNoneSet";
            break;
        case FWP_MATCH_EQUAL_CASE_INSENSITIVE:
            text = L"EqualCaseInsensitive";
            break;
        case FWP_MATCH_NOT_EQUAL:
            text = L"NotEqual";
            break;
        case FWP_MATCH_PREFIX:
            text = L"Prefix";
            break;
        case FWP_MATCH_NOT_PREFIX:
            text = L"NotPrefix";
            break;
        default:
            break;
        }

        return text;
    }

    std::wstring FormatConditionFieldKeyText(const GUID& key)
    {
        std::wstring text;

        if (GuidsEqual(key, FWPM_CONDITION_ALE_APP_ID))
        {
            text = L"ALE_APP_ID";
        }
        else if (GuidsEqual(key, FWPM_CONDITION_ALE_USER_ID))
        {
            text = L"ALE_USER_ID";
        }
        else if (GuidsEqual(key, FWPM_CONDITION_IP_LOCAL_ADDRESS))
        {
            text = L"IP_LOCAL_ADDRESS";
        }
        else if (GuidsEqual(key, FWPM_CONDITION_IP_REMOTE_ADDRESS))
        {
            text = L"IP_REMOTE_ADDRESS";
        }
        else if (GuidsEqual(key, FWPM_CONDITION_IP_LOCAL_ADDRESS_V4))
        {
            text = L"IP_LOCAL_ADDRESS_V4";
        }
        else if (GuidsEqual(key, FWPM_CONDITION_IP_REMOTE_ADDRESS_V4))
        {
            text = L"IP_REMOTE_ADDRESS_V4";
        }
        else if (GuidsEqual(key, FWPM_CONDITION_IP_LOCAL_ADDRESS_V6))
        {
            text = L"IP_LOCAL_ADDRESS_V6";
        }
        else if (GuidsEqual(key, FWPM_CONDITION_IP_REMOTE_ADDRESS_V6))
        {
            text = L"IP_REMOTE_ADDRESS_V6";
        }
        else if (GuidsEqual(key, FWPM_CONDITION_IP_PROTOCOL))
        {
            text = L"IP_PROTOCOL";
        }
        else if (GuidsEqual(key, FWPM_CONDITION_IP_LOCAL_PORT))
        {
            text = L"IP_LOCAL_PORT";
        }
        else if (GuidsEqual(key, FWPM_CONDITION_IP_REMOTE_PORT))
        {
            text = L"IP_REMOTE_PORT";
        }
        else if (GuidsEqual(key, FWPM_CONDITION_FLAGS))
        {
            text = L"FLAGS";
        }
        else
        {
            text = FormatGuidText(key);
        }

        return text;
    }

    std::wstring FormatByteArrayHex(const uint8_t* data, uint32_t size, uint32_t maxBytes)
    {
        std::wstringstream stream;

        do
        {
            if (data == nullptr || size == 0)
            {
                stream << L"<empty>";
                break;
            }

            uint32_t printed = std::min(size, maxBytes);
            stream << L"hex:";
            for (uint32_t index = 0; index < printed; ++index)
            {
                wchar_t byteText[4] = {};
                swprintf_s(byteText, L"%02x", static_cast<unsigned int>(data[index]));
                stream << byteText;
            }

            if (printed < size)
            {
                stream << L"...";
            }
        } while (false);

        return stream.str();
    }

    std::wstring FormatByteBlobText(const FWP_BYTE_BLOB* blob)
    {
        std::wstring text;

        do
        {
            if (blob == nullptr || blob->data == nullptr || blob->size == 0)
            {
                text = L"<empty>";
                break;
            }

            if ((blob->size % sizeof(wchar_t)) == 0)
            {
                size_t charCount = blob->size / sizeof(wchar_t);
                std::wstring candidate(
                    reinterpret_cast<const wchar_t*>(blob->data),
                    reinterpret_cast<const wchar_t*>(blob->data) + charCount);

                while (!candidate.empty() && candidate.back() == L'\0')
                {
                    candidate.pop_back();
                }

                size_t printable = 0;
                for (wchar_t ch : candidate)
                {
                    if (ch == L'\\' ||
                        ch == L'/' ||
                        ch == L':' ||
                        ch == L'.' ||
                        ch == L'_' ||
                        ch == L'-' ||
                        std::iswalnum(ch) != 0 ||
                        std::iswspace(ch) != 0)
                    {
                        ++printable;
                    }
                }

                if (!candidate.empty() && printable * 2 >= candidate.size())
                {
                    text = candidate;
                    break;
                }
            }

            text = FormatByteArrayHex(blob->data, blob->size, 48);
        } while (false);

        return text;
    }

    std::wstring FormatFwpConditionValueText(const FWP_CONDITION_VALUE0& value)
    {
        std::wstringstream stream;

        switch (value.type)
        {
        case FWP_EMPTY:
            stream << L"empty";
            break;
        case FWP_UINT8:
            stream << L"0x" << std::hex << static_cast<unsigned int>(value.uint8) << std::dec;
            break;
        case FWP_UINT16:
            stream << L"0x" << std::hex << static_cast<unsigned int>(value.uint16) << std::dec;
            break;
        case FWP_UINT32:
            stream << L"0x" << std::hex << static_cast<unsigned long>(value.uint32) << std::dec;
            break;
        case FWP_UINT64:
            if (value.uint64 != nullptr)
            {
                stream << L"0x" << std::hex << *value.uint64 << std::dec;
            }
            else
            {
                stream << L"<null>";
            }
            break;
        case FWP_INT8:
            stream << static_cast<int>(value.int8);
            break;
        case FWP_INT16:
            stream << static_cast<int>(value.int16);
            break;
        case FWP_INT32:
            stream << static_cast<long>(value.int32);
            break;
        case FWP_INT64:
            if (value.int64 != nullptr)
            {
                stream << *value.int64;
            }
            else
            {
                stream << L"<null>";
            }
            break;
        case FWP_BYTE_BLOB_TYPE:
            stream << FormatByteBlobText(value.byteBlob);
            break;
        case FWP_UNICODE_STRING_TYPE:
            if (value.unicodeString != nullptr)
            {
                stream << value.unicodeString;
            }
            else
            {
                stream << L"<null>";
            }
            break;
        case FWP_BYTE_ARRAY16_TYPE:
            if (value.byteArray16 != nullptr)
            {
                stream << FormatByteArrayHex(value.byteArray16->byteArray16, 16, 16);
            }
            else
            {
                stream << L"<null>";
            }
            break;
        case FWP_BYTE_ARRAY6_TYPE:
            if (value.byteArray6 != nullptr)
            {
                stream << FormatByteArrayHex(value.byteArray6->byteArray6, 6, 6);
            }
            else
            {
                stream << L"<null>";
            }
            break;
        case FWP_V4_ADDR_MASK:
            if (value.v4AddrMask != nullptr)
            {
                stream << L"addr=0x" << std::hex << value.v4AddrMask->addr
                       << L"/mask=0x" << value.v4AddrMask->mask << std::dec;
            }
            else
            {
                stream << L"<null>";
            }
            break;
        case FWP_V6_ADDR_MASK:
            if (value.v6AddrMask != nullptr)
            {
                stream << FormatByteArrayHex(value.v6AddrMask->addr, 16, 16)
                       << L"/prefix=" << static_cast<unsigned int>(value.v6AddrMask->prefixLength);
            }
            else
            {
                stream << L"<null>";
            }
            break;
        case FWP_RANGE_TYPE:
            if (value.rangeValue != nullptr)
            {
                stream << L"range";
            }
            else
            {
                stream << L"<null>";
            }
            break;
        default:
            stream << L"type=" << static_cast<unsigned int>(value.type);
            break;
        }

        return stream.str();
    }

    void AppendLimitedConditionText(
        std::wstring* text,
        const std::wstring& part,
        size_t maxChars)
    {
        do
        {
            if (text == nullptr || part.empty() || text->size() >= maxChars)
            {
                break;
            }

            if (!text->empty())
            {
                text->append(L"; ");
            }

            size_t remaining = maxChars - text->size();
            if (part.size() <= remaining)
            {
                text->append(part);
            }
            else if (remaining > 3)
            {
                text->append(part.substr(0, remaining - 3));
                text->append(L"...");
            }
        } while (false);
    }

    std::wstring FormatFilterConditionsText(
        const FWPM_FILTER0& filter,
        std::wstring* appIdText,
        bool* hasAppIdCondition)
    {
        constexpr size_t kMaxConditionText = 4096;
        std::wstring text;

        do
        {
            if (appIdText != nullptr)
            {
                appIdText->clear();
            }
            if (hasAppIdCondition != nullptr)
            {
                *hasAppIdCondition = false;
            }

            if (filter.filterCondition == nullptr || filter.numFilterConditions == 0)
            {
                break;
            }

            for (UINT32 index = 0; index < filter.numFilterConditions; ++index)
            {
                const FWPM_FILTER_CONDITION0& condition = filter.filterCondition[index];
                std::wstring field = FormatConditionFieldKeyText(condition.fieldKey);
                std::wstring value = FormatFwpConditionValueText(condition.conditionValue);
                std::wstring part = field;
                part += L" ";
                part += FwpMatchTypeText(condition.matchType);
                part += L" ";
                part += value;
                AppendLimitedConditionText(&text, part, kMaxConditionText);

                if (GuidsEqual(condition.fieldKey, FWPM_CONDITION_ALE_APP_ID))
                {
                    if (hasAppIdCondition != nullptr)
                    {
                        *hasAppIdCondition = true;
                    }
                    if (appIdText != nullptr && appIdText->empty())
                    {
                        *appIdText = value;
                    }
                }
            }
        } while (false);

        return text;
    }

    std::wstring DecodeFwpmError(DWORD status)
    {
        std::wstringstream stream;

        switch (status)
        {
        case ERROR_SUCCESS:
            stream << L"ok";
            break;
        case FWP_E_NOT_FOUND:
            stream << L"FWP_E_NOT_FOUND";
            break;
        case ERROR_ACCESS_DENIED:
            stream << L"ERROR_ACCESS_DENIED (run elevated)";
            break;
        case RPC_S_SERVER_UNAVAILABLE:
            stream << L"RPC_S_SERVER_UNAVAILABLE (BFE service not running)";
            break;
        case EPT_S_NOT_REGISTERED:
            stream << L"EPT_S_NOT_REGISTERED (BFE endpoint not registered)";
            break;
        default:
            stream << L"status=0x" << std::hex << status << std::dec;
            break;
        }

        return stream.str();
    }

    struct ProviderIndexEntry
    {
        GUID Key;
        std::wstring Name;
        std::wstring Description;
        std::wstring ServiceName;
        uint32_t Flags = 0;
    };

    struct LayerIndexEntry
    {
        GUID Key;
        std::wstring Name;
        std::wstring Description;
        uint32_t LayerId = 0;
        uint32_t Flags = 0;
    };

    struct SubLayerIndexEntry
    {
        GUID Key;
        std::wstring Name;
    };

    bool BuildProviderIndex(HANDLE engine, std::vector<ProviderIndexEntry>* index, std::wstring* warnings)
    {
        bool ok = false;

        do
        {
            if (index == nullptr)
            {
                break;
            }

            HANDLE enumHandle = nullptr;
            DWORD status = FwpmProviderCreateEnumHandle0(engine, nullptr, &enumHandle);
            if (status != ERROR_SUCCESS)
            {
                if (warnings != nullptr)
                {
                    *warnings = L"FwpmProviderCreateEnumHandle0 failed: " + DecodeFwpmError(status);
                }
                break;
            }

            bool errored = false;
            for (;;)
            {
                FWPM_PROVIDER0** entries = nullptr;
                UINT32 numReturned = 0;
                status = FwpmProviderEnum0(engine, enumHandle, kWfpEnumPageSize, &entries, &numReturned);
                if (status != ERROR_SUCCESS)
                {
                    if (warnings != nullptr)
                    {
                        *warnings = L"FwpmProviderEnum0 failed: " + DecodeFwpmError(status);
                    }
                    errored = true;
                    break;
                }

                if (entries == nullptr || numReturned == 0)
                {
                    if (entries != nullptr)
                    {
                        FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
                    }
                    break;
                }

                for (UINT32 i = 0; i < numReturned; ++i)
                {
                    if (entries[i] == nullptr)
                    {
                        continue;
                    }

                    ProviderIndexEntry entry = {};
                    entry.Key = entries[i]->providerKey;
                    entry.Name = FormatDisplayDataName(entries[i]->displayData);
                    entry.Description = FormatDisplayDataDescription(entries[i]->displayData);
                    entry.ServiceName = FormatNullableString(entries[i]->serviceName);
                    entry.Flags = entries[i]->flags;
                    index->push_back(std::move(entry));
                }

                FwpmFreeMemory0(reinterpret_cast<void**>(&entries));

                if (numReturned < kWfpEnumPageSize)
                {
                    break;
                }
            }

            FwpmProviderDestroyEnumHandle0(engine, enumHandle);
            if (errored)
            {
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool BuildLayerIndex(HANDLE engine, std::vector<LayerIndexEntry>* index, std::wstring* warnings)
    {
        bool ok = false;

        do
        {
            if (index == nullptr)
            {
                break;
            }

            HANDLE enumHandle = nullptr;
            DWORD status = FwpmLayerCreateEnumHandle0(engine, nullptr, &enumHandle);
            if (status != ERROR_SUCCESS)
            {
                if (warnings != nullptr)
                {
                    *warnings = L"FwpmLayerCreateEnumHandle0 failed: " + DecodeFwpmError(status);
                }
                break;
            }

            bool errored = false;
            for (;;)
            {
                FWPM_LAYER0** entries = nullptr;
                UINT32 numReturned = 0;
                status = FwpmLayerEnum0(engine, enumHandle, kWfpEnumPageSize, &entries, &numReturned);
                if (status != ERROR_SUCCESS)
                {
                    if (warnings != nullptr)
                    {
                        *warnings = L"FwpmLayerEnum0 failed: " + DecodeFwpmError(status);
                    }
                    errored = true;
                    break;
                }

                if (entries == nullptr || numReturned == 0)
                {
                    if (entries != nullptr)
                    {
                        FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
                    }
                    break;
                }

                for (UINT32 i = 0; i < numReturned; ++i)
                {
                    if (entries[i] == nullptr)
                    {
                        continue;
                    }

                    LayerIndexEntry entry = {};
                    entry.Key = entries[i]->layerKey;
                    entry.Name = FormatDisplayDataName(entries[i]->displayData);
                    entry.Description = FormatDisplayDataDescription(entries[i]->displayData);
                    entry.LayerId = entries[i]->layerId;
                    entry.Flags = entries[i]->flags;
                    index->push_back(std::move(entry));
                }

                FwpmFreeMemory0(reinterpret_cast<void**>(&entries));

                if (numReturned < kWfpEnumPageSize)
                {
                    break;
                }
            }

            FwpmLayerDestroyEnumHandle0(engine, enumHandle);
            if (errored)
            {
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool BuildSubLayerIndex(HANDLE engine, std::vector<SubLayerIndexEntry>* index, std::wstring* warnings)
    {
        bool ok = false;

        do
        {
            if (index == nullptr)
            {
                break;
            }

            HANDLE enumHandle = nullptr;
            DWORD status = FwpmSubLayerCreateEnumHandle0(engine, nullptr, &enumHandle);
            if (status != ERROR_SUCCESS)
            {
                if (warnings != nullptr)
                {
                    *warnings = L"FwpmSubLayerCreateEnumHandle0 failed: " + DecodeFwpmError(status);
                }
                break;
            }

            bool errored = false;
            for (;;)
            {
                FWPM_SUBLAYER0** entries = nullptr;
                UINT32 numReturned = 0;
                status = FwpmSubLayerEnum0(engine, enumHandle, kWfpEnumPageSize, &entries, &numReturned);
                if (status != ERROR_SUCCESS)
                {
                    if (warnings != nullptr)
                    {
                        *warnings = L"FwpmSubLayerEnum0 failed: " + DecodeFwpmError(status);
                    }
                    errored = true;
                    break;
                }

                if (entries == nullptr || numReturned == 0)
                {
                    if (entries != nullptr)
                    {
                        FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
                    }
                    break;
                }

                for (UINT32 i = 0; i < numReturned; ++i)
                {
                    if (entries[i] == nullptr)
                    {
                        continue;
                    }

                    SubLayerIndexEntry entry = {};
                    entry.Key = entries[i]->subLayerKey;
                    entry.Name = FormatDisplayDataName(entries[i]->displayData);
                    index->push_back(std::move(entry));
                }

                FwpmFreeMemory0(reinterpret_cast<void**>(&entries));

                if (numReturned < kWfpEnumPageSize)
                {
                    break;
                }
            }

            FwpmSubLayerDestroyEnumHandle0(engine, enumHandle);
            if (errored)
            {
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    const ProviderIndexEntry* LookupProvider(const std::vector<ProviderIndexEntry>& index, const GUID& key)
    {
        const ProviderIndexEntry* found = nullptr;

        for (const ProviderIndexEntry& entry : index)
        {
            if (GuidsEqual(entry.Key, key))
            {
                found = &entry;
                break;
            }
        }

        return found;
    }

    const LayerIndexEntry* LookupLayer(const std::vector<LayerIndexEntry>& index, const GUID& key)
    {
        const LayerIndexEntry* found = nullptr;

        for (const LayerIndexEntry& entry : index)
        {
            if (GuidsEqual(entry.Key, key))
            {
                found = &entry;
                break;
            }
        }

        return found;
    }

    const SubLayerIndexEntry* LookupSubLayer(const std::vector<SubLayerIndexEntry>& index, const GUID& key)
    {
        const SubLayerIndexEntry* found = nullptr;

        for (const SubLayerIndexEntry& entry : index)
        {
            if (GuidsEqual(entry.Key, key))
            {
                found = &entry;
                break;
            }
        }

        return found;
    }

    bool ModuleFilterMatchesProvider(const std::wstring& filter, const ProviderIndexEntry* provider)
    {
        bool match = false;

        do
        {
            if (filter.empty())
            {
                match = true;
                break;
            }

            if (provider == nullptr)
            {
                break;
            }

            GUID parsedGuid = {};
            if (ParseGuidText(filter, &parsedGuid) && GuidsEqual(parsedGuid, provider->Key))
            {
                match = true;
                break;
            }

            if (!provider->ServiceName.empty() && ContainsNoCase(provider->ServiceName, filter))
            {
                match = true;
                break;
            }

            if (!provider->Name.empty() && ContainsNoCase(provider->Name, filter))
            {
                match = true;
                break;
            }
        } while (false);

        return match;
    }

    bool LayerFilterMatches(const std::wstring& filter, const GUID& layerKey, const LayerIndexEntry* layer)
    {
        bool match = false;

        do
        {
            if (filter.empty())
            {
                match = true;
                break;
            }

            GUID parsedGuid = {};
            if (ParseGuidText(filter, &parsedGuid) && GuidsEqual(parsedGuid, layerKey))
            {
                match = true;
                break;
            }

            if (layer != nullptr && !layer->Name.empty() && ContainsNoCase(layer->Name, filter))
            {
                match = true;
                break;
            }
        } while (false);

        return match;
    }
}

WfpScanner::WfpScanner()
{
}

bool WfpScanner::Scan(const Options& options, WfpScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid result output";
            }
            break;
        }

        result->Records.clear();
        result->Warnings.clear();
        result->EngineOpened = false;

        switch (options.Target)
        {
        case Scope::Providers:
            result->Scope = L"providers";
            break;
        case Scope::SubLayers:
            result->Scope = L"sublayers";
            break;
        case Scope::Callouts:
            result->Scope = L"callouts";
            break;
        case Scope::Filters:
            result->Scope = L"filters";
            break;
        case Scope::Layers:
            result->Scope = L"layers";
            break;
        default:
            result->Scope = L"unknown";
            break;
        }

        HANDLE engine = nullptr;
        DWORD status = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine);
        if (status != ERROR_SUCCESS || engine == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"FwpmEngineOpen0 failed: " + DecodeFwpmError(status);
            }
            break;
        }

        result->EngineOpened = true;

        std::vector<ProviderIndexEntry> providerIndex;
        std::vector<LayerIndexEntry> layerIndex;
        std::vector<SubLayerIndexEntry> sublayerIndex;
        std::wstring indexWarning;

        if (!BuildProviderIndex(engine, &providerIndex, &indexWarning) && !indexWarning.empty())
        {
            result->Warnings.push_back(indexWarning);
            indexWarning.clear();
        }

        if (!BuildLayerIndex(engine, &layerIndex, &indexWarning) && !indexWarning.empty())
        {
            result->Warnings.push_back(indexWarning);
            indexWarning.clear();
        }

        if (!BuildSubLayerIndex(engine, &sublayerIndex, &indexWarning) && !indexWarning.empty())
        {
            result->Warnings.push_back(indexWarning);
            indexWarning.clear();
        }

        bool scanOk = false;

        switch (options.Target)
        {
        case Scope::Providers:
            scanOk = true;
            for (const ProviderIndexEntry& provider : providerIndex)
            {
                WfpRecord record = {};
                record.Kind = L"wfp.provider";
                record.Name = provider.Name;
                record.Description = provider.Description;
                record.Key = FormatGuidText(provider.Key);
                record.ProviderKey = record.Key;
                record.ProviderName = provider.Name;
                record.ProviderService = provider.ServiceName;
                record.Flags = provider.Flags;
                record.FlagsText = FormatProviderFlags(provider.Flags);
                record.HasProvider = true;
                result->Records.push_back(std::move(record));
            }
            break;
        case Scope::SubLayers:
        {
            scanOk = true;
            HANDLE enumHandle = nullptr;
            status = FwpmSubLayerCreateEnumHandle0(engine, nullptr, &enumHandle);
            if (status != ERROR_SUCCESS)
            {
                result->Warnings.push_back(L"FwpmSubLayerCreateEnumHandle0 failed: " + DecodeFwpmError(status));
                scanOk = false;
                break;
            }

            for (;;)
            {
                FWPM_SUBLAYER0** entries = nullptr;
                UINT32 numReturned = 0;
                status = FwpmSubLayerEnum0(engine, enumHandle, kWfpEnumPageSize, &entries, &numReturned);
                if (status != ERROR_SUCCESS)
                {
                    result->Warnings.push_back(L"FwpmSubLayerEnum0 failed: " + DecodeFwpmError(status));
                    scanOk = false;
                    break;
                }

                if (entries == nullptr || numReturned == 0)
                {
                    if (entries != nullptr)
                    {
                        FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
                    }
                    break;
                }

                for (UINT32 i = 0; i < numReturned; ++i)
                {
                    if (entries[i] == nullptr)
                    {
                        continue;
                    }

                    WfpRecord record = {};
                    record.Kind = L"wfp.sublayer";
                    record.Name = FormatDisplayDataName(entries[i]->displayData);
                    record.Description = FormatDisplayDataDescription(entries[i]->displayData);
                    record.Key = FormatGuidText(entries[i]->subLayerKey);
                    record.SubLayerKey = record.Key;
                    record.SubLayerName = record.Name;
                    record.Flags = entries[i]->flags;
                    record.FlagsText = FormatSubLayerFlags(entries[i]->flags);
                    record.SubLayerWeight = entries[i]->weight;
                    record.HasSubLayerWeight = true;
                    if (entries[i]->providerKey != nullptr)
                    {
                        const ProviderIndexEntry* provider = LookupProvider(providerIndex, *entries[i]->providerKey);
                        record.ProviderKey = FormatGuidText(*entries[i]->providerKey);
                        if (provider != nullptr)
                        {
                            record.ProviderName = provider->Name;
                            record.ProviderService = provider->ServiceName;
                        }
                        record.HasProvider = true;
                    }

                    result->Records.push_back(std::move(record));
                }

                FwpmFreeMemory0(reinterpret_cast<void**>(&entries));

                if (numReturned < kWfpEnumPageSize)
                {
                    break;
                }
            }

            FwpmSubLayerDestroyEnumHandle0(engine, enumHandle);
            break;
        }
        case Scope::Callouts:
        {
            scanOk = true;
            HANDLE enumHandle = nullptr;
            status = FwpmCalloutCreateEnumHandle0(engine, nullptr, &enumHandle);
            if (status != ERROR_SUCCESS)
            {
                result->Warnings.push_back(L"FwpmCalloutCreateEnumHandle0 failed: " + DecodeFwpmError(status));
                scanOk = false;
                break;
            }

            for (;;)
            {
                FWPM_CALLOUT0** entries = nullptr;
                UINT32 numReturned = 0;
                status = FwpmCalloutEnum0(engine, enumHandle, kWfpEnumPageSize, &entries, &numReturned);
                if (status != ERROR_SUCCESS)
                {
                    result->Warnings.push_back(L"FwpmCalloutEnum0 failed: " + DecodeFwpmError(status));
                    scanOk = false;
                    break;
                }

                if (entries == nullptr || numReturned == 0)
                {
                    if (entries != nullptr)
                    {
                        FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
                    }
                    break;
                }

                for (UINT32 i = 0; i < numReturned; ++i)
                {
                    if (entries[i] == nullptr)
                    {
                        continue;
                    }

                    const ProviderIndexEntry* provider = nullptr;
                    if (entries[i]->providerKey != nullptr)
                    {
                        provider = LookupProvider(providerIndex, *entries[i]->providerKey);
                    }

                    if (!ModuleFilterMatchesProvider(options.ModuleFilter, provider))
                    {
                        continue;
                    }

                    WfpRecord record = {};
                    record.Kind = L"wfp.callout";
                    record.Name = FormatDisplayDataName(entries[i]->displayData);
                    record.Description = FormatDisplayDataDescription(entries[i]->displayData);
                    record.Key = FormatGuidText(entries[i]->calloutKey);
                    record.CalloutKey = record.Key;
                    record.CalloutName = record.Name;
                    record.HasCallout = true;
                    record.Flags = entries[i]->flags;
                    record.FlagsText = FormatCalloutFlags(entries[i]->flags);
                    record.CalloutId = entries[i]->calloutId;
                    record.HasCalloutId = true;
                    record.LayerKey = FormatGuidText(entries[i]->applicableLayer);
                    const LayerIndexEntry* layer = LookupLayer(layerIndex, entries[i]->applicableLayer);
                    if (layer != nullptr)
                    {
                        record.LayerName = layer->Name;
                        record.LayerId = layer->LayerId;
                        record.HasLayerId = true;
                    }

                    if (entries[i]->providerKey != nullptr)
                    {
                        record.ProviderKey = FormatGuidText(*entries[i]->providerKey);
                        record.HasProvider = true;
                    }

                    if (provider != nullptr)
                    {
                        record.ProviderName = provider->Name;
                        record.ProviderService = provider->ServiceName;
                    }

                    result->Records.push_back(std::move(record));
                }

                FwpmFreeMemory0(reinterpret_cast<void**>(&entries));

                if (numReturned < kWfpEnumPageSize)
                {
                    break;
                }
            }

            FwpmCalloutDestroyEnumHandle0(engine, enumHandle);
            break;
        }
        case Scope::Filters:
        {
            scanOk = true;
            HANDLE enumHandle = nullptr;
            status = FwpmFilterCreateEnumHandle0(engine, nullptr, &enumHandle);
            if (status != ERROR_SUCCESS)
            {
                result->Warnings.push_back(L"FwpmFilterCreateEnumHandle0 failed: " + DecodeFwpmError(status));
                scanOk = false;
                break;
            }

            for (;;)
            {
                FWPM_FILTER0** entries = nullptr;
                UINT32 numReturned = 0;
                status = FwpmFilterEnum0(engine, enumHandle, kWfpEnumPageSize, &entries, &numReturned);
                if (status != ERROR_SUCCESS)
                {
                    result->Warnings.push_back(L"FwpmFilterEnum0 failed: " + DecodeFwpmError(status));
                    scanOk = false;
                    break;
                }

                if (entries == nullptr || numReturned == 0)
                {
                    if (entries != nullptr)
                    {
                        FwpmFreeMemory0(reinterpret_cast<void**>(&entries));
                    }
                    break;
                }

                for (UINT32 i = 0; i < numReturned; ++i)
                {
                    if (entries[i] == nullptr)
                    {
                        continue;
                    }

                    const LayerIndexEntry* layer = LookupLayer(layerIndex, entries[i]->layerKey);
                    if (!LayerFilterMatches(options.LayerFilter, entries[i]->layerKey, layer))
                    {
                        continue;
                    }

                    const ProviderIndexEntry* provider = nullptr;
                    if (entries[i]->providerKey != nullptr)
                    {
                        provider = LookupProvider(providerIndex, *entries[i]->providerKey);
                    }

                    if (!options.ProviderFilter.empty() && !ModuleFilterMatchesProvider(options.ProviderFilter, provider))
                    {
                        continue;
                    }

                    WfpRecord record = {};
                    record.Kind = L"wfp.filter";
                    record.Name = FormatDisplayDataName(entries[i]->displayData);
                    record.Description = FormatDisplayDataDescription(entries[i]->displayData);
                    record.Key = FormatGuidText(entries[i]->filterKey);
                    record.Id = entries[i]->filterId;
                    record.HasId = true;
                    record.Flags = entries[i]->flags;
                    record.FlagsText = FormatFilterFlags(entries[i]->flags);
                    record.Action = entries[i]->action.type;
                    record.ActionText = FwpActionTypeText(entries[i]->action.type);
                    if ((entries[i]->action.type & FWP_ACTION_FLAG_CALLOUT) != 0)
                    {
                        record.ActionKey = FormatGuidText(entries[i]->action.calloutKey);
                    }
                    record.WeightText = FormatFwpValueText(entries[i]->weight);
                    record.NumConditions = entries[i]->numFilterConditions;
                    record.ConditionsText = FormatFilterConditionsText(
                        *entries[i],
                        &record.AppIdText,
                        &record.HasAppIdCondition);
                    record.LayerKey = FormatGuidText(entries[i]->layerKey);
                    if (layer != nullptr)
                    {
                        record.LayerName = layer->Name;
                        record.LayerId = layer->LayerId;
                        record.HasLayerId = true;
                    }

                    record.SubLayerKey = FormatGuidText(entries[i]->subLayerKey);
                    const SubLayerIndexEntry* sublayer = LookupSubLayer(sublayerIndex, entries[i]->subLayerKey);
                    if (sublayer != nullptr)
                    {
                        record.SubLayerName = sublayer->Name;
                    }

                    if (entries[i]->providerKey != nullptr)
                    {
                        record.ProviderKey = FormatGuidText(*entries[i]->providerKey);
                        record.HasProvider = true;
                    }

                    if (provider != nullptr)
                    {
                        record.ProviderName = provider->Name;
                        record.ProviderService = provider->ServiceName;
                    }

                    result->Records.push_back(std::move(record));
                }

                FwpmFreeMemory0(reinterpret_cast<void**>(&entries));

                if (numReturned < kWfpEnumPageSize)
                {
                    break;
                }
            }

            FwpmFilterDestroyEnumHandle0(engine, enumHandle);
            break;
        }
        case Scope::Layers:
            scanOk = true;
            for (const LayerIndexEntry& layer : layerIndex)
            {
                WfpRecord record = {};
                record.Kind = L"wfp.layer";
                record.Name = layer.Name;
                record.Description = layer.Description;
                record.Key = FormatGuidText(layer.Key);
                record.LayerKey = record.Key;
                record.LayerName = layer.Name;
                record.LayerId = layer.LayerId;
                record.HasLayerId = true;
                record.Flags = layer.Flags;
                record.FlagsText = FormatLayerFlags(layer.Flags);
                result->Records.push_back(std::move(record));
            }
            break;
        default:
            if (error != nullptr)
            {
                *error = L"unknown wfp scope";
            }
            break;
        }

        FwpmEngineClose0(engine);

        if (!scanOk)
        {
            if (error != nullptr && error->empty())
            {
                *error = L"wfp enumeration failed";
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

namespace
{
    std::wstring WfpJsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }
}

std::wstring BuildWfpJson(const WfpScanResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.wfp.v1\",\"scope\":";
    out += mcpjson::Quote(result.Scope);
    out += L",\"engineOpened\":";
    out += result.EngineOpened ? L"true" : L"false";
    out += L",\"count\":";
    out += std::to_wstring(result.Records.size());
    out += L",\"records\":[";

    for (size_t index = 0; index < result.Records.size(); ++index)
    {
        const WfpRecord& record = result.Records[index];
        if (index > 0)
        {
            out += L",";
        }

        out += L"{\"kind\":" + mcpjson::Quote(record.Kind);
        if (!record.Name.empty())
        {
            out += L",\"name\":" + mcpjson::Quote(record.Name);
        }
        if (!record.Description.empty())
        {
            out += L",\"description\":" + mcpjson::Quote(record.Description);
        }
        if (!record.Key.empty())
        {
            out += L",\"key\":" + mcpjson::Quote(record.Key);
        }
        if (record.HasId)
        {
            out += L",\"id\":" + mcpjson::Quote(WfpJsonHex(record.Id));
        }
        if (!record.LayerName.empty())
        {
            out += L",\"layerName\":" + mcpjson::Quote(record.LayerName);
        }
        if (record.HasLayerId)
        {
            out += L",\"layerId\":" + std::to_wstring(record.LayerId);
        }
        if (!record.SubLayerName.empty())
        {
            out += L",\"subLayerName\":" + mcpjson::Quote(record.SubLayerName);
        }
        if (record.HasSubLayerWeight)
        {
            out += L",\"subLayerWeight\":" + std::to_wstring(record.SubLayerWeight);
        }
        if (!record.ProviderName.empty())
        {
            out += L",\"providerName\":" + mcpjson::Quote(record.ProviderName);
        }
        if (!record.ProviderService.empty())
        {
            out += L",\"providerService\":" + mcpjson::Quote(record.ProviderService);
        }
        if (!record.ActionText.empty())
        {
            out += L",\"actionText\":" + mcpjson::Quote(record.ActionText);
        }
        out += L",\"action\":" + std::to_wstring(record.Action);
        if (!record.CalloutName.empty())
        {
            out += L",\"calloutName\":" + mcpjson::Quote(record.CalloutName);
        }
        if (record.HasCalloutId)
        {
            out += L",\"calloutId\":" + std::to_wstring(record.CalloutId);
        }
        if (!record.FlagsText.empty())
        {
            out += L",\"flagsText\":" + mcpjson::Quote(record.FlagsText);
        }
        out += L",\"flags\":" + std::to_wstring(record.Flags);
        if (!record.WeightText.empty())
        {
            out += L",\"weightText\":" + mcpjson::Quote(record.WeightText);
        }
        out += L",\"numConditions\":" + std::to_wstring(record.NumConditions);
        if (!record.ConditionsText.empty())
        {
            out += L",\"conditionsText\":" + mcpjson::Quote(record.ConditionsText);
        }
        if (!record.AppIdText.empty())
        {
            out += L",\"appIdText\":" + mcpjson::Quote(record.AppIdText);
        }
        if (!record.Notes.empty())
        {
            out += L",\"notes\":" + mcpjson::Quote(record.Notes);
        }
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
