#include "WheaEvent.h"
#include "WheaRecord.h"
#include "RebootEvent.h"
#include "SchemaArtifact.h"
#include "SymbolArtifactCache.h"
#include "McpJson.h"

#include <Shlwapi.h>
#include <xmllite.h>
#include <wrl/client.h>
#include <array>
#include <string_view>

#pragma comment(lib, "xmllite.lib")
#pragma comment(lib, "shlwapi.lib")

namespace
{
    using Microsoft::WRL::ComPtr;
    using mcpjson::Quote;
    using View = std::wstring_view;
    constexpr size_t MaxXmlBytes = 8u << 20;
    constexpr size_t MaxPayload = 1u << 20;
    constexpr View EventNamespace = L"http://schemas.microsoft.com/win/2004/08/events/event";
    constexpr wchar_t WheaProvider[] = L"{c26c4f3c-3f66-4e99-8f8a-39405cfed220}";
    constexpr wchar_t PowerProvider[] = L"{331c3b3a-2005-44c2-ac5e-77220c37d6b4}";
    constexpr wchar_t GeneralProvider[] = L"{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}";

    bool XmlSpace(wchar_t c) { return c == L' ' || c == L'\t' || c == L'\n' || c == L'\r'; }

    std::optional<uint64_t> Decimal(View text, uint64_t limit)
    {
        while (!text.empty() && XmlSpace(text.front())) { text.remove_prefix(1); }
        while (!text.empty() && XmlSpace(text.back())) { text.remove_suffix(1); }
        if (text.empty()) { return {}; }
        uint64_t value = 0;
        for (wchar_t c : text)
        {
            if (c < L'0' || c > L'9') { return {}; }
            const auto digit = static_cast<unsigned>(c - L'0');
            if (value > limit / 10 || (value == limit / 10 && digit > limit % 10)) { return {}; }
            value = value * 10 + digit;
        }
        return value;
    }

    bool UtcTimestamp(View t, std::optional<uint64_t>& fileTime)
    {
        if (t.size() < 20 || t.size() > 30 || t[4] != L'-' || t[7] != L'-' || t[10] != L'T' ||
            t[13] != L':' || t[16] != L':' || t.back() != L'Z') { return false; }
        if (t.size() != 20 && (t.size() < 22 || t[19] != L'.')) { return false; }
        for (size_t i = 0; i + 1 < t.size(); ++i)
        {
            if (i == 4 || i == 7 || i == 10 || i == 13 || i == 16 || i == 19) { continue; }
            if (t[i] < L'0' || t[i] > L'9') { return false; }
        }
        SYSTEMTIME st{};
        auto n = [&](size_t at, size_t count) { return static_cast<WORD>(*Decimal(t.substr(at, count), 9999)); };
        st.wYear = n(0, 4); st.wMonth = n(5, 2); st.wDay = n(8, 2);
        st.wHour = n(11, 2); st.wMinute = n(14, 2); st.wSecond = n(17, 2);
        FILETIME ft{};
        if (!SystemTimeToFileTime(&st, &ft)) { return false; }
        uint64_t fraction = 0, place = 1000000;
        for (size_t i = 20; i + 1 < t.size(); ++i)
        {
            // Keep valid sub-100 ns XML for older reports. Its exact value cannot be a FILETIME.
            if (!place && t[i] != L'0') { return true; }
            fraction += (t[i] - L'0') * place;
            place /= 10;
        }
        fileTime = ((static_cast<uint64_t>(ft.dwHighDateTime) << 32) | ft.dwLowDateTime) + fraction;
        return true;
    }

    enum class Group { Other, System, Data };
    enum Field { None, Provider, Time, Id, Version, RecordId, Channel, Length, Raw,
        StopCode, Parameter1, Parameter2, Parameter3, Parameter4, OldTime, NewTime, Count };

    bool Attribute(IXmlReader& reader, const wchar_t* name, std::wstring& out)
    {
        if (reader.MoveToAttributeByName(name, L"") != S_OK) { return false; }
        const wchar_t* text = nullptr;
        UINT size = 0;
        const bool ok = reader.GetValue(&text, &size) == S_OK && size <= 256;
        if (ok) { out.assign(text, size); }
        return reader.MoveToElement() == S_OK && ok;
    }

    int Nibble(wchar_t c)
    {
        if (c >= L'0' && c <= L'9') { return c - L'0'; }
        if (c >= L'A' && c <= L'F') { return c - L'A' + 10; }
        if (c >= L'a' && c <= L'f') { return c - L'a' + 10; }
        return -1;
    }

    struct Event
    {
        enum class Kind { Whea, Reboot, Clock };
        Kind kind = Kind::Whea;
        Group group = Group::Other;
        Field field = None;
        bool sawSystem = false, sawData = false, otherPayload = false;
        std::array<bool, Count> seen{};
        std::array<std::wstring, Count> text;
        std::wstring providerGuid, xmlDigest, payloadDigest, metadata = L"null";
        std::vector<uint8_t> payload;
        int high = -1;
        const wchar_t* payloadError = nullptr;
        uint64_t xmlBytes = 0;
        std::optional<uint64_t> declaredBytes, decodedBytes;
        std::optional<bool> samePayload;
        const wchar_t* status = L"malformed_event_xml";

        bool Reject(const wchar_t* why) { status = why; return false; }

        bool Start(IXmlReader& reader, UINT depth, View name, bool namespaced)
        {
            if (depth == 0)
            { return (namespaced && name == L"Event") || Reject(L"unsupported_event_document"); }
            if (depth == 1)
            {
                group = Group::Other;
                if (namespaced && name == L"System")
                {
                    if (sawSystem) { return Reject(L"ambiguous_event_fields"); }
                    sawSystem = true; group = Group::System;
                }
                if (namespaced && name == L"EventData")
                {
                    if (!sawSystem) { return Reject(L"unsupported_event_document"); }
                    if (sawData || otherPayload) { return Reject(L"ambiguous_event_fields"); }
                    sawData = true; group = Group::Data;
                }
                else if (namespaced && (name == L"UserData" || name == L"DebugData" || name == L"BinaryEventData" ||
                    name == L"ProcessingErrorData"))
                {
                    if (sawData || otherPayload) { return Reject(L"ambiguous_event_fields"); }
                    otherPayload = true;
                }
                return true;
            }
            if (depth > 2) { return field == None || Reject(L"nested_event_value"); }
            field = None;
            if (!namespaced) { return true; }
            if (group == Group::System)
            {
                if (name == L"Provider") { field = Provider; }
                else if (name == L"TimeCreated") { field = Time; }
                else if (name == L"EventID") { field = Id; }
                else if (name == L"Version") { field = Version; }
                else if (name == L"EventRecordID") { field = RecordId; }
                else if (name == L"Channel") { field = Channel; }
            }
            if (group == Group::Data && name == L"Data")
            {
                std::wstring key;
                if (Attribute(reader, L"Name", key))
                {
                    if (kind == Kind::Reboot)
                    {
                        if (key == L"BugcheckCode") { field = StopCode; }
                        else if (key == L"BugcheckParameter1") { field = Parameter1; }
                        else if (key == L"BugcheckParameter2") { field = Parameter2; }
                        else if (key == L"BugcheckParameter3") { field = Parameter3; }
                        else if (key == L"BugcheckParameter4") { field = Parameter4; }
                    }
                    else if (kind == Kind::Clock)
                    {
                        if (key == L"OldTime") { field = OldTime; }
                        else if (key == L"NewTime") { field = NewTime; }
                    }
                    else if (key == L"RawData") { field = Raw; }
                    else if (key == L"Length") { field = Length; }
                }
            }
            if (field == None) { return true; }
            if (seen[field]) { return Reject(L"ambiguous_event_fields"); }
            seen[field] = true;
            if (field == Provider && (!Attribute(reader, L"Name", text[Provider]) || !Attribute(reader, L"Guid", providerGuid)))
            { return Reject(L"provider_identity_unavailable"); }
            if (field == Time && !Attribute(reader, L"SystemTime", text[Time])) { return Reject(L"event_metadata_incomplete"); }
            if (reader.IsEmptyElement()) { field = None; }
            return true;
        }

        bool Value(View value)
        {
            if (field == None) { return true; }
            if (field == Provider || field == Time)
            {
                for (wchar_t c : value) { if (!XmlSpace(c)) { return Reject(L"unexpected_metadata_text"); } }
                return true;
            }
            if (field != Raw)
            {
                if (value.size() > 256 - text[field].size()) { return Reject(L"event_field_limit"); }
                text[field].append(value);
                return true;
            }
            if (payloadError) { return true; }
            for (wchar_t c : value)
            {
                if (XmlSpace(c)) { continue; }
                const int nibble = Nibble(c);
                if (nibble < 0) { payloadError = L"invalid_payload_hex"; break; }
                if (high < 0) { high = nibble; continue; }
                if (payload.size() == MaxPayload) { payloadError = L"event_payload_limit"; break; }
                payload.push_back(static_cast<uint8_t>(high * 16 + nibble));
                high = -1;
            }
            return true;
        }

        bool Read(IXmlReader& reader)
        {
            XmlNodeType type{};
            HRESULT hr;
            unsigned nodes = 0;
            while ((hr = reader.Read(&type)) == S_OK)
            {
                if (++nodes > 4096) { return Reject(L"event_node_limit"); }
                UINT depth = 0;
                if (reader.GetDepth(&depth) != S_OK) { return false; }
                if (type == XmlNodeType_Element)
                {
                    const wchar_t *local = nullptr, *ns = nullptr;
                    UINT nl = 0, nn = 0;
                    if (reader.GetLocalName(&local, &nl) != S_OK || reader.GetNamespaceUri(&ns, &nn) != S_OK ||
                        !Start(reader, depth, View(local, nl), View(ns ? ns : L"", nn) == EventNamespace)) { return false; }
                }
                else if (type == XmlNodeType_EndElement)
                {
                    if (depth <= 2) { field = None; }
                    if (depth <= 1) { group = Group::Other; }
                }
                else if (field != None && (type == XmlNodeType_Text || type == XmlNodeType_CDATA || type == XmlNodeType_Whitespace))
                {
                    const wchar_t* value = nullptr;
                    UINT size = 0;
                    if (reader.GetValue(&value, &size) != S_OK || !Value(View(value, size))) { return false; }
                }
            }
            return hr == S_FALSE;
        }

        struct Identity { uint64_t id, version, recordId; std::optional<uint64_t> fileTime; };

        std::optional<Identity> Metadata(const wchar_t* name, const wchar_t* guid)
        {
            if (!seen[Provider] || text[Provider] != name || providerGuid.size() != 38 ||
                CompareStringOrdinal(providerGuid.c_str(), 38, guid, 38, TRUE) != CSTR_EQUAL ||
                text[Channel] != L"System") { status = L"different_event_source"; return {}; }
            const auto id = Decimal(text[Id], UINT16_MAX), version = Decimal(text[Version], UINT8_MAX);
            const auto recordId = Decimal(text[RecordId], UINT64_MAX);
            std::optional<uint64_t> time;
            if (!id || !version || !recordId || !*recordId || !UtcTimestamp(text[Time], time))
            { status = L"event_metadata_incomplete"; return {}; }
            metadata = L"{\"provider\":" + Quote(name) + L",\"channel\":\"System\",\"event_id\":" +
                std::to_wstring(*id) + L",\"version\":" + std::to_wstring(*version) + L",\"event_record_id\":" +
                Quote(std::to_wstring(*recordId)) + L",\"system_time_utc\":" + Quote(text[Time]) + L"}";
            return Identity{*id, *version, *recordId, time};
        }

        void Compare(const WheaRecord& dump)
        {
            const auto identity = Metadata(L"Microsoft-Windows-WHEA-Logger", WheaProvider);
            if (!identity) { return; }
            const auto id = identity->id;
            // Version-zero WHEA-Logger manifest templates expose Length and RawData together.
            if (identity->version != 0 || !((id >= 1 && id <= 3) || (id >= 16 && id <= 29) || (id >= 40 && id <= 47)))
            { status = L"unsupported_event_template"; return; }
            if (seen[Length]) { declaredBytes = Decimal(text[Length], UINT32_MAX); }
            if (!sawData || !seen[Raw]) { status = L"event_payload_missing"; return; }
            if (payloadError) { status = payloadError; return; }
            if (high >= 0) { status = L"invalid_payload_hex"; return; }
            decodedBytes = payload.size();
            if (!seen[Length]) { status = L"event_payload_missing"; return; }
            if (!declaredBytes || !*declaredBytes || *declaredBytes != *decodedBytes)
            { status = L"event_length_mismatch"; return; }
            payloadDigest = ContentHash::Bytes(payload);
            if (payloadDigest.empty()) { status = L"event_hash_unavailable"; return; }
            if (dump.status != L"linked") { status = L"dump_record_unavailable"; return; }
            samePayload = dump.captured == payload.size() && dump.digest == payloadDigest;
            status = *samePayload ? L"matching_payload_bytes" : L"different_payload_bytes";
        }

        WheaEventComparison Result(const WheaRecord& dump) const
        {
            return {L"{\"schema\":\"kn.whea_event_comparison.v1\",\"status\":" + Quote(status) +
                L",\"xml_sha256\":" + (xmlDigest.empty() ? L"null" : Quote(xmlDigest)) + L",\"xml_bytes\":" +
                (xmlDigest.empty() ? L"null" : std::to_wstring(xmlBytes)) + L",\"event\":" + metadata +
                L",\"declared_payload_bytes\":" + (declaredBytes ? std::to_wstring(*declaredBytes) : L"null") +
                L",\"payload_bytes\":" + (decodedBytes ? std::to_wstring(*decodedBytes) : L"null") +
                L",\"payload_sha256\":" + (payloadDigest.empty() ? L"null" : Quote(payloadDigest)) +
                L",\"dump_record_sha256\":" + (dump.status == L"linked" ? Quote(dump.digest) : L"null") +
                L",\"same_payload_bytes\":" + (samePayload ? (*samePayload ? L"true" : L"false") : L"null") +
                L",\"source_authenticated\":false}", samePayload, dump.status == L"linked", !payloadDigest.empty()};
        }
    };

    bool Parse(const BYTE* bytes, UINT count, Event& event)
    {
        const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (FAILED(initialized)) { return event.Reject(L"xml_reader_unavailable"); }
        struct Apartment { ~Apartment() { CoUninitialize(); } } apartment;
        ComPtr<IStream> stream;
        stream.Attach(SHCreateMemStream(bytes, count));
        ComPtr<IXmlReader> reader;
        if (!stream || FAILED(CreateXmlReader(__uuidof(IXmlReader), reinterpret_cast<void**>(reader.GetAddressOf()), nullptr)) ||
            FAILED(reader->SetProperty(XmlReaderProperty_ConformanceLevel, XmlConformanceLevel_Document)) ||
            FAILED(reader->SetProperty(XmlReaderProperty_DtdProcessing, DtdProcessing_Prohibit)) ||
            FAILED(reader->SetProperty(XmlReaderProperty_XmlResolver, 0)) ||
            FAILED(reader->SetProperty(XmlReaderProperty_MaxElementDepth, 32)) || FAILED(reader->SetInput(stream.Get())))
        { return event.Reject(L"xml_reader_unavailable"); }
        return event.Read(*reader.Get());
    }
}

void DecodeRebootEvent(const BYTE* xml, UINT byteCount, RebootEventComparison& result)
{
    Event event;
    event.kind = Event::Kind::Reboot;
    if (!Parse(xml, byteCount, event)) { result.status = event.status; return; }
    const auto id = event.Metadata(L"Microsoft-Windows-Kernel-Power", PowerProvider);
    if (!id) { result.status = event.status; return; }
    result.metadata = event.metadata;
    if (id->recordId != result.recordId) { result.status = L"record_id_mismatch"; return; }
    if (id->id != 41 || id->version > 10) { result.status = L"unsupported_event_template"; return; }
    result.xmlFileTime = id->fileTime;
    if (!id->version) { result.status = L"event_stop_code_unavailable"; return; }
    SavedCrashStop stop;
    const auto code = Decimal(event.text[StopCode], UINT32_MAX);
    if (!code) { result.status = L"event_stop_fields_invalid"; return; }
    stop.code = static_cast<ULONG>(*code);
    result.eventCode = stop.code;
    // The version-one manifest has a code but no bugcheck parameters.
    if (id->version == 1) { result.status = stop.code ? L"event_code_only" : L"event_stop_code_unavailable"; return; }
    for (size_t i = 0; i < stop.args.size(); ++i)
    {
        const auto& text = event.text[Parameter1 + i];
        if (text.size() < 3 || text.size() > 18 || text[0] != L'0' || (text[1] != L'x' && text[1] != L'X'))
        { result.status = L"event_stop_fields_invalid"; return; }
        for (size_t j = 2; j < text.size(); ++j)
        {
            const auto digit = Nibble(text[j]);
            if (digit < 0) { result.status = L"event_stop_fields_invalid"; return; }
            stop.args[i] = (stop.args[i] << 4) | static_cast<unsigned>(digit);
        }
    }
    result.eventStop = stop;
    result.status = stop.code ? L"dump_stop_unqualified" : L"event_stop_code_unavailable";
}

const wchar_t* DecodeRebootClockChange(const BYTE* xml, UINT byteCount, RebootClockChange& change)
{
    Event event;
    event.kind = Event::Kind::Clock;
    if (!Parse(xml, byteCount, event)) { return event.status; }
    const auto id = event.Metadata(L"Microsoft-Windows-Kernel-General", GeneralProvider);
    if (!id) { return event.status; }
    if (id->recordId != change.recordId) { return L"record_id_mismatch"; }
    if (id->id != 1 || id->version > 4 || id->version != change.version) { return L"unsupported_event_template"; }
    UtcTimestamp(event.text[OldTime], change.oldTime);
    UtcTimestamp(event.text[NewTime], change.newTime);
    if (!change.oldTime || !change.newTime || !*change.oldTime || !*change.newTime ||
        *change.oldTime > INT64_MAX || *change.newTime > INT64_MAX) { return L"clock_fields_invalid"; }
    return nullptr;
}

std::wstring WheaEventComparison::Hypothesis() const
{
    const std::wstring paths = L"[\"/whea_record/captured_sha256\",\"/whea_event/xml_sha256\","
        L"\"/whea_event/event\",\"/whea_event/payload_sha256\"]";
    const bool same = samePayload.value_or(false);
    std::wstring missing;
    if (!dumpAvailable) { missing = Quote(L"/whea_record/status"); }
    if (!eventAvailable) { missing += (missing.empty() ? L"" : L",") + Quote(L"/whea_event/status"); }
    return L"{\"candidate\":\"same_whea_record_bytes_in_event_export\",\"state\":" +
        Quote(!samePayload ? L"unresolved" : same ? L"supported_by_payloads" : L"different_payloads") +
        L",\"support\":" + (same ? paths : L"[]") + L",\"contrary\":" + (samePayload && !same ? paths : L"[]") +
        L",\"missing\":[" + missing + L"]" +
        L",\"next\":" + Quote(same ? L"verify_event_origin_host_boot_and_time" : L"locate_the_original_event_for_the_saved_record") + L"}";
}

WheaEventComparison CompareSavedWheaEvent(const std::wstring& name, const std::wstring& pin, const WheaRecord& dump)
{
    std::filesystem::path path;
    symbol_artifacts::Directories parents;
    SchemaArtifact file;
    Event event;
    if (!symbol_artifacts::LocalRoot(name, &path) || !parents.Pin(path.parent_path(), false) || !file.Open(path.wstring(), MaxXmlBytes))
    { event.status = L"event_source_unavailable"; return event.Result(dump); }
    event.xmlDigest = file.Sha256;
    event.xmlBytes = file.Bytes();
    if (event.xmlDigest != pin) { event.status = L"event_digest_mismatch"; return event.Result(dump); }
    std::vector<uint8_t> bytes(static_cast<size_t>(event.xmlBytes));
    DWORD used = 0;
    if (bytes.empty() || !approved_file::ReadAt(file.Handle(), 0, bytes.data(), static_cast<DWORD>(bytes.size()), &used) ||
        used != bytes.size()) { event.status = L"event_source_unreadable"; return event.Result(dump); }
    if (Parse(bytes.data(), static_cast<UINT>(bytes.size()), event)) { event.Compare(dump); }
    if (!file.Unchanged())
    {
        Event changed;
        changed.status = L"event_source_changed_or_unreadable";
        return changed.Result(dump);
    }
    return event.Result(dump);
}
