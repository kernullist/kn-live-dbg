#include "QosPolicyScanner.h"

#include <Windows.h>
#include <Wbemidl.h>
#include <OleAuto.h>

#include <algorithm>
#include <cwctype>
#include <limits>
#include <sstream>
#include <utility>

#pragma comment(lib, "Wbemuuid.lib")

namespace
{
    constexpr uint64_t kSevereThrottleBitsPerSecond =
        64ull * 1024ull * 8ull;

    std::wstring HresultText(
        const std::wstring& context,
        HRESULT value)
    {
        std::wstringstream stream;
        stream << context
               << L" (HRESULT=0x"
               << std::hex
               << static_cast<unsigned long>(value)
               << L")";
        return stream.str();
    }

    std::wstring ToLowerCopy(const std::wstring& value)
    {
        std::wstring result = value;
        for (wchar_t& ch : result)
        {
            ch = static_cast<wchar_t>(
                std::towlower(ch));
        }
        return result;
    }

    enum class PropertyReadResult
    {
        Missing,
        Present,
        Invalid
    };

    PropertyReadResult ReadVariant(
        IWbemClassObject* object,
        const wchar_t* name,
        VARIANT* value)
    {
        if (object == nullptr ||
            name == nullptr ||
            value == nullptr)
        {
            return PropertyReadResult::Invalid;
        }

        VariantInit(value);
        HRESULT hr = object->Get(
            name,
            0,
            value,
            nullptr,
            nullptr);
        if (hr != WBEM_S_NO_ERROR)
        {
            VariantClear(value);
            return PropertyReadResult::Invalid;
        }
        if (value->vt == VT_EMPTY ||
            value->vt == VT_NULL)
        {
            VariantClear(value);
            return PropertyReadResult::Missing;
        }
        return PropertyReadResult::Present;
    }

    bool CopyBstrStrict(
        BSTR value,
        std::wstring* text)
    {
        if (text == nullptr)
        {
            return false;
        }
        text->clear();
        if (value == nullptr)
        {
            return true;
        }

        const UINT length =
            SysStringLen(value);
        if (std::find(
                value,
                value + length,
                L'\0') != value + length)
        {
            return false;
        }
        text->assign(
            value,
            static_cast<size_t>(length));
        return true;
    }

    bool HasNonWhitespace(
        const std::wstring& value)
    {
        return std::any_of(
            value.begin(),
            value.end(),
            [](wchar_t ch)
            {
                return std::iswspace(ch) == 0;
            });
    }

    PropertyReadResult ReadText(
        IWbemClassObject* object,
        const wchar_t* name,
        std::wstring* text)
    {
        if (text == nullptr)
        {
            return PropertyReadResult::Invalid;
        }
        text->clear();

        VARIANT value = {};
        VariantInit(&value);
        const PropertyReadResult state =
            ReadVariant(object, name, &value);
        if (state != PropertyReadResult::Present)
        {
            return state;
        }

        if (value.vt != VT_BSTR)
        {
            VariantClear(&value);
            return PropertyReadResult::Invalid;
        }
        const bool copied =
            CopyBstrStrict(
                value.bstrVal,
                text);
        VariantClear(&value);
        return copied
            ? PropertyReadResult::Present
            : PropertyReadResult::Invalid;
    }

    bool VariantToUint64(
        const VARIANT& value,
        uint64_t* number)
    {
        if (number == nullptr)
        {
            return false;
        }
        *number = 0;

        bool ok = true;
        switch (value.vt)
        {
        case VT_UI1:
            *number = value.bVal;
            break;
        case VT_I1:
            if (value.cVal < 0)
            {
                ok = false;
            }
            else
            {
                *number =
                    static_cast<uint64_t>(value.cVal);
            }
            break;
        case VT_UI2:
            *number = value.uiVal;
            break;
        case VT_I2:
            if (value.iVal < 0)
            {
                ok = false;
            }
            else
            {
                *number =
                    static_cast<uint64_t>(value.iVal);
            }
            break;
        case VT_UI4:
            *number = value.ulVal;
            break;
        case VT_I4:
            if (value.lVal < 0)
            {
                ok = false;
            }
            else
            {
                *number =
                    static_cast<uint64_t>(value.lVal);
            }
            break;
        case VT_UI8:
            *number = value.ullVal;
            break;
        case VT_I8:
            if (value.llVal < 0)
            {
                ok = false;
            }
            else
            {
                *number =
                    static_cast<uint64_t>(value.llVal);
            }
            break;
        case VT_UINT:
            *number = value.uintVal;
            break;
        case VT_INT:
            if (value.intVal < 0)
            {
                ok = false;
            }
            else
            {
                *number =
                    static_cast<uint64_t>(
                        value.intVal);
            }
            break;
        case VT_BSTR:
        {
            const UINT length =
                value.bstrVal == nullptr
                    ? 0
                    : SysStringLen(
                          value.bstrVal);
            if (length == 0)
            {
                ok = false;
                break;
            }

            uint64_t parsed = 0;
            for (UINT index = 0;
                 index < length;
                 ++index)
            {
                const wchar_t ch =
                    value.bstrVal[index];
                if (ch < L'0' ||
                    ch > L'9')
                {
                    ok = false;
                    break;
                }
                const uint64_t digit =
                    static_cast<uint64_t>(
                        ch - L'0');
                if (parsed >
                    (std::numeric_limits<
                         uint64_t>::max() -
                     digit) /
                        10)
                {
                    ok = false;
                    break;
                }
                parsed = parsed * 10 + digit;
            }
            if (ok)
            {
                *number = parsed;
            }
            break;
        }
        default:
            ok = false;
            break;
        }
        return ok;
    }

    PropertyReadResult ReadUint64(
        IWbemClassObject* object,
        const wchar_t* name,
        uint64_t* number)
    {
        if (number == nullptr)
        {
            return PropertyReadResult::Invalid;
        }
        *number = 0;

        VARIANT value = {};
        VariantInit(&value);
        const PropertyReadResult state =
            ReadVariant(object, name, &value);
        if (state != PropertyReadResult::Present)
        {
            return state;
        }

        const bool ok =
            VariantToUint64(value, number);
        VariantClear(&value);
        return ok
            ? PropertyReadResult::Present
            : PropertyReadResult::Invalid;
    }

    HRESULT CreateActiveStoreQueryContext(
        IWbemContext** context)
    {
        if (context == nullptr)
        {
            return E_POINTER;
        }
        *context = nullptr;

        IWbemContext* created = nullptr;
        HRESULT hr = CoCreateInstance(
            CLSID_WbemContext,
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_IWbemContext,
            reinterpret_cast<void**>(&created));
        if (FAILED(hr) || created == nullptr)
        {
            if (created != nullptr)
            {
                created->Release();
            }
            return FAILED(hr) ? hr : E_UNEXPECTED;
        }

        VARIANT policyStore = {};
        VariantInit(&policyStore);
        policyStore.vt = VT_BSTR;
        policyStore.bstrVal =
            SysAllocString(L"ActiveStore");
        if (policyStore.bstrVal == nullptr)
        {
            created->Release();
            return E_OUTOFMEMORY;
        }

        hr = created->SetValue(
            L"PolicyStore",
            0,
            &policyStore);
        VariantClear(&policyStore);
        if (FAILED(hr))
        {
            created->Release();
            return hr;
        }

        *context = created;
        return S_OK;
    }

    bool ActiveStoreQueryContextSelfTest()
    {
        bool coUninitialize = false;
        HRESULT hr = CoInitializeEx(
            nullptr,
            COINIT_MULTITHREADED);
        if (SUCCEEDED(hr))
        {
            coUninitialize = true;
        }
        else if (hr != RPC_E_CHANGED_MODE)
        {
            return false;
        }

        IWbemContext* context = nullptr;
        hr = CreateActiveStoreQueryContext(
            &context);
        VARIANT value = {};
        VariantInit(&value);
        std::wstring policyStore;
        const bool passed =
            SUCCEEDED(hr) &&
            context != nullptr &&
            context->GetValue(
                L"PolicyStore",
                0,
                &value) == S_OK &&
            value.vt == VT_BSTR &&
            CopyBstrStrict(
                value.bstrVal,
                &policyStore) &&
            policyStore == L"ActiveStore";
        VariantClear(&value);
        if (context != nullptr)
        {
            context->Release();
        }
        if (coUninitialize)
        {
            CoUninitialize();
        }
        return passed;
    }
}

bool QosPolicyScanner::Scan(
    QosPolicyScanResult* result,
    std::wstring* error)
{
    if (error != nullptr)
    {
        error->clear();
    }
    if (result == nullptr)
    {
        if (error != nullptr)
        {
            *error = L"invalid QoS policy result output";
        }
        return false;
    }

    *result = QosPolicyScanResult{};
    bool coUninitialize = false;
    IWbemLocator* locator = nullptr;
    IWbemServices* services = nullptr;
    IWbemContext* queryContext = nullptr;
    IEnumWbemClassObject* enumerator = nullptr;
    bool ok = false;

    do
    {
        HRESULT hr = CoInitializeEx(
            nullptr,
            COINIT_MULTITHREADED);
        if (SUCCEEDED(hr))
        {
            coUninitialize = true;
        }
        else if (hr != RPC_E_CHANGED_MODE)
        {
            if (error != nullptr)
            {
                *error = HresultText(
                    L"QoS CoInitializeEx failed",
                    hr);
            }
            break;
        }

        hr = CoCreateInstance(
            CLSID_WbemLocator,
            nullptr,
            CLSCTX_INPROC_SERVER,
            IID_IWbemLocator,
            reinterpret_cast<void**>(&locator));
        if (hr != S_OK ||
            locator == nullptr)
        {
            if (error != nullptr)
            {
                *error = HresultText(
                    L"QoS IWbemLocator creation failed",
                    hr);
            }
            break;
        }

        BSTR namespaceName =
            SysAllocString(L"ROOT\\StandardCimv2");
        if (namespaceName == nullptr)
        {
            if (error != nullptr)
            {
                *error =
                    L"QoS WMI namespace allocation failed";
            }
            break;
        }
        hr = locator->ConnectServer(
            namespaceName,
            nullptr,
            nullptr,
            nullptr,
            0,
            nullptr,
            nullptr,
            &services);
        SysFreeString(namespaceName);
        if (hr != WBEM_S_NO_ERROR ||
            services == nullptr)
        {
            if (error != nullptr)
            {
                *error = HresultText(
                    L"QoS WMI ConnectServer failed",
                    hr);
            }
            break;
        }

        hr = CoSetProxyBlanket(
            services,
            RPC_C_AUTHN_WINNT,
            RPC_C_AUTHZ_NONE,
            nullptr,
            RPC_C_AUTHN_LEVEL_CALL,
            RPC_C_IMP_LEVEL_IMPERSONATE,
            nullptr,
            EOAC_NONE);
        if (hr != S_OK)
        {
            if (error != nullptr)
            {
                *error = HresultText(
                    L"QoS WMI proxy security failed",
                    hr);
            }
            break;
        }

        hr = CreateActiveStoreQueryContext(
            &queryContext);
        if (FAILED(hr) ||
            queryContext == nullptr)
        {
            if (error != nullptr)
            {
                *error = HresultText(
                    L"QoS ActiveStore query context failed",
                    hr);
            }
            break;
        }

        // NetQos declares PolicyStore as a CIM query option. The provider
        // receives it through IWbemContext; putting it in WQL or omitting
        // the context does not enumerate the effective ActiveStore.
        BSTR language = SysAllocString(L"WQL");
        BSTR query = SysAllocString(
            L"SELECT * FROM "
            L"MSFT_NetQosPolicySettingData");
        if (language == nullptr || query == nullptr)
        {
            if (language != nullptr)
            {
                SysFreeString(language);
            }
            if (query != nullptr)
            {
                SysFreeString(query);
            }
            if (error != nullptr)
            {
                *error =
                    L"QoS WMI query allocation failed";
            }
            break;
        }

        hr = services->ExecQuery(
            language,
            query,
            WBEM_FLAG_FORWARD_ONLY |
                WBEM_FLAG_RETURN_IMMEDIATELY,
            queryContext,
            &enumerator);
        SysFreeString(language);
        SysFreeString(query);
        if (hr != WBEM_S_NO_ERROR ||
            enumerator == nullptr)
        {
            if (error != nullptr)
            {
                *error = HresultText(
                    L"QoS WMI query failed",
                    hr);
            }
            break;
        }

        bool enumerationComplete = false;
        bool propertyCoverageComplete = true;
        uint64_t recordNumber = 0;
        while (true)
        {
            IWbemClassObject* object = nullptr;
            ULONG returned = 0;
            hr = enumerator->Next(
                5000,
                1,
                &object,
                &returned);
            if (hr == WBEM_S_FALSE || returned == 0)
            {
                enumerationComplete =
                    hr == WBEM_S_FALSE;
                if (object != nullptr)
                {
                    object->Release();
                }
                if (!enumerationComplete &&
                    error != nullptr)
                {
                    *error = HresultText(
                        L"QoS WMI enumeration timed out",
                        hr);
                }
                break;
            }
            if (FAILED(hr) || object == nullptr)
            {
                if (object != nullptr)
                {
                    object->Release();
                }
                if (error != nullptr)
                {
                    *error = HresultText(
                        L"QoS WMI enumeration failed",
                        hr);
                }
                break;
            }

            ++recordNumber;
            QosPolicyRecord record = {};
            record.FromActiveStore = true;
            const auto addPropertyWarning =
                [&](const std::wstring& property,
                    const std::wstring& reason)
                {
                    propertyCoverageComplete = false;
                    result->Warnings.push_back(
                        L"QoS policy record " +
                        std::to_wstring(
                            recordNumber) +
                        L" has " + reason +
                        L" " + property);
                };

            PropertyReadResult propertyState =
                ReadText(
                    object,
                    L"Name",
                    &record.Name);
            if (propertyState !=
                    PropertyReadResult::Present ||
                !HasNonWhitespace(record.Name))
            {
                addPropertyWarning(
                    L"Name",
                    propertyState ==
                            PropertyReadResult::Invalid
                        ? L"an invalid"
                        : L"a missing or empty");
            }

            propertyState = ReadText(
                object,
                L"InstanceID",
                &record.InstanceId);
            if (propertyState !=
                    PropertyReadResult::Present ||
                !HasNonWhitespace(
                    record.InstanceId))
            {
                addPropertyWarning(
                    L"InstanceID",
                    propertyState ==
                            PropertyReadResult::Invalid
                        ? L"an invalid"
                        : L"a missing or empty");
            }

            propertyState = ReadText(
                object,
                L"Owner",
                &record.Owner);
            if (propertyState ==
                PropertyReadResult::Invalid)
            {
                addPropertyWarning(
                    L"Owner",
                    L"an invalid");
            }

            propertyState = ReadText(
                object,
                L"AppPathNameMatchCondition",
                &record.AppPathName);
            if (propertyState ==
                PropertyReadResult::Invalid)
            {
                addPropertyWarning(
                    L"AppPathNameMatchCondition",
                    L"an invalid");
            }

            propertyState = ReadUint64(
                object,
                L"ThrottleRateAction",
                &record.ThrottleRateBitsPerSecond);
            record.HasThrottleRate =
                propertyState ==
                PropertyReadResult::Present;
            if (propertyState ==
                PropertyReadResult::Invalid)
            {
                addPropertyWarning(
                    L"ThrottleRateAction",
                    L"an invalid");
            }

            uint64_t number = 0;
            propertyState = ReadUint64(
                object,
                L"NetworkProfile",
                &number);
            if (propertyState ==
                PropertyReadResult::Present)
            {
                if (number <=
                    std::numeric_limits<
                        uint32_t>::max())
                {
                    record.NetworkProfile =
                        static_cast<uint32_t>(
                            number);
                }
                else
                {
                    addPropertyWarning(
                        L"NetworkProfile",
                        L"an out-of-range");
                }
            }
            else if (propertyState ==
                     PropertyReadResult::Invalid)
            {
                addPropertyWarning(
                    L"NetworkProfile",
                    L"an invalid");
            }

            propertyState = ReadUint64(
                object,
                L"Precedence",
                &number);
            if (propertyState ==
                PropertyReadResult::Present)
            {
                if (number <=
                    std::numeric_limits<
                        uint32_t>::max())
                {
                    record.Precedence =
                        static_cast<uint32_t>(
                            number);
                }
                else
                {
                    addPropertyWarning(
                        L"Precedence",
                        L"an out-of-range");
                }
            }
            else if (propertyState ==
                     PropertyReadResult::Invalid)
            {
                addPropertyWarning(
                    L"Precedence",
                    L"an invalid");
            }

            object->Release();
            result->Records.push_back(
                std::move(record));
        }

        if (!enumerationComplete)
        {
            break;
        }

        std::sort(
            result->Records.begin(),
            result->Records.end(),
            [](const QosPolicyRecord& left,
               const QosPolicyRecord& right)
            {
                const std::wstring leftKey =
                    ToLowerCopy(
                        left.InstanceId.empty()
                            ? left.Name
                            : left.InstanceId);
                const std::wstring rightKey =
                    ToLowerCopy(
                        right.InstanceId.empty()
                            ? right.Name
                            : right.InstanceId);
                return leftKey < rightKey;
            });
        result->CoverageComplete =
            propertyCoverageComplete;
        ok = true;
    } while (false);

    if (enumerator != nullptr)
    {
        enumerator->Release();
    }
    if (queryContext != nullptr)
    {
        queryContext->Release();
    }
    if (services != nullptr)
    {
        services->Release();
    }
    if (locator != nullptr)
    {
        locator->Release();
    }
    if (coUninitialize)
    {
        CoUninitialize();
    }
    return ok;
}

bool QosPolicyHasSevereThrottle(
    const QosPolicyRecord& record)
{
    return record.HasThrottleRate &&
        record.ThrottleRateBitsPerSecond != 0 &&
        record.ThrottleRateBitsPerSecond <=
            kSevereThrottleBitsPerSecond;
}

bool QosPolicyScannerSelfTest()
{
    if (!ActiveStoreQueryContextSelfTest())
    {
        return false;
    }

    VARIANT numeric;
    VariantInit(&numeric);
    numeric.vt = VT_BSTR;
    numeric.bstrVal =
        SysAllocString(L"65536");
    uint64_t parsed = 0;
    if (numeric.bstrVal == nullptr ||
        !VariantToUint64(numeric, &parsed) ||
        parsed != 65536)
    {
        VariantClear(&numeric);
        return false;
    }
    VariantClear(&numeric);

    VariantInit(&numeric);
    numeric.vt = VT_BSTR;
    numeric.bstrVal =
        SysAllocStringLen(
            L"64\0junk",
            7);
    if (numeric.bstrVal == nullptr)
    {
        return false;
    }
    const bool acceptedEmbeddedNull =
        VariantToUint64(
            numeric,
            &parsed);
    VariantClear(&numeric);
    if (acceptedEmbeddedNull)
    {
        return false;
    }

    BSTR ambiguousText =
        SysAllocStringLen(
            L"MsSense.exe\0ignored.exe",
            23);
    if (ambiguousText == nullptr)
    {
        return false;
    }
    std::wstring copiedText;
    const bool acceptedAmbiguousText =
        CopyBstrStrict(
            ambiguousText,
            &copiedText);
    SysFreeString(ambiguousText);
    if (acceptedAmbiguousText ||
        HasNonWhitespace(L" \t\r\n"))
    {
        return false;
    }

    VariantInit(&numeric);
    numeric.vt = VT_BSTR;
    numeric.bstrVal =
        SysAllocString(L"18446744073709551616");
    if (numeric.bstrVal == nullptr)
    {
        return false;
    }
    const bool acceptedOverflow =
        VariantToUint64(numeric, &parsed);
    VariantClear(&numeric);
    if (acceptedOverflow)
    {
        return false;
    }

    VariantInit(&numeric);
    numeric.vt = VT_I8;
    numeric.llVal = -1;
    if (VariantToUint64(numeric, &parsed))
    {
        return false;
    }

    QosPolicyRecord record = {};
    record.HasThrottleRate = true;
    record.ThrottleRateBitsPerSecond = 64;
    if (!QosPolicyHasSevereThrottle(record))
    {
        return false;
    }

    record.ThrottleRateBitsPerSecond =
        kSevereThrottleBitsPerSecond;
    if (!QosPolicyHasSevereThrottle(record))
    {
        return false;
    }

    record.ThrottleRateBitsPerSecond =
        kSevereThrottleBitsPerSecond + 1;
    if (QosPolicyHasSevereThrottle(record))
    {
        return false;
    }

    record.ThrottleRateBitsPerSecond = 0;
    if (QosPolicyHasSevereThrottle(record))
    {
        return false;
    }

    record.HasThrottleRate = false;
    record.ThrottleRateBitsPerSecond = 64;
    return !QosPolicyHasSevereThrottle(record);
}
