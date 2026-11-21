#include "WheaRecord.h"
#include "ContentHash.h"
#include "McpJson.h"

#include <initguid.h>
// The desktop CPER header refers to the ntdef.h KIRQL alias in its DPC section.
using KIRQL = UCHAR;
#include <cper.h>
#include <wrl/client.h>
#include <algorithm>
#include <cstring>
#include <utility>
#include <vector>

namespace
{
    using mcpjson::Quote;
    using Microsoft::WRL::ComPtr;
    using Header = WHEA_ERROR_RECORD_HEADER;
    using Descriptor = WHEA_ERROR_RECORD_SECTION_DESCRIPTOR;
    static_assert(sizeof(Header) == 128 && sizeof(Descriptor) == 72);
    constexpr ULONG MaxLength = 1u << 20;
    constexpr USHORT MaxSections = 128;
    constexpr unsigned MaxReads = 512;

    std::wstring Hex(uint64_t value)
    {
        wchar_t text[24]{};
        swprintf_s(text, L"0x%llx", static_cast<unsigned long long>(value));
        return Quote(text);
    }

    std::wstring Guid(const GUID& id)
    {
        wchar_t text[40]{};
        return StringFromGUID2(id, text, static_cast<int>(std::size(text))) ? Quote(text) : L"null";
    }

    void Append(std::wstring& list, const std::wstring& element)
    {
        if (!list.empty()) { list += L","; }
        list += element;
    }

    bool Digest(const uint8_t* data, size_t size, std::wstring& out)
    {
        ContentHash hash;
        if (!hash.Add(data, size)) { return false; }
        out = hash.Finish();
        return !out.empty();
    }

    class SavedRecord
    {
    public:
        SavedRecord(IDebugDataSpaces& spaces, uint64_t base, WheaRecord& result)
            : Spaces(spaces), Base(base), Result(result) {}

        // Grow only the contiguous prefix from successful reads. A small dump can
        // end partway through a page, including partway through the fixed header.
        bool ReadTo(size_t length)
        {
            if (length - 1 > UINT64_MAX - Base) { Result.status = L"address_overflow"; return false; }
            const size_t initial = Data.size();
            Data.resize(length);
            size_t filled = initial;
            while (filled < length)
            {
                if (Calls == MaxReads) { Result.status = L"read_budget_exceeded"; break; }
                const uint64_t address = Base + filled;
                const ULONG ask = static_cast<ULONG>((std::min)(length - filled, size_t{4096} - (address & 4095)));
                ULONG got = 0;
                const HRESULT hr = Spaces.ReadVirtual(address, Data.data() + filled, ask, &got);
                ++Calls;
                Append(Result.reads, L"{\"offset\":" + std::to_wstring(filled) + L",\"requested\":" +
                    std::to_wstring(ask) + L",\"returned\":" + std::to_wstring(got) + L",\"hr\":" +
                    Hex(static_cast<ULONG>(hr)) + L"}");
                if (hr != S_OK || !got || got > ask) { Result.status = L"incomplete_read"; break; }
                filled += got;
            }
            Data.resize(filled);
            return filled == length;
        }

        std::vector<uint8_t> Data;

    private:
        IDebugDataSpaces& Spaces;
        uint64_t Base;
        WheaRecord& Result;
        unsigned Calls = 0;
    };

    std::wstring Fields(const WHEA_MEMORY_ERROR_SECTION& s)
    {
        const auto v = s.ValidBits;
        return L"{\"valid_bits\":" + Hex(v.ValidBits) +
            L",\"error_type\":" + (v.ErrorType ? std::to_wstring(s.ErrorType) : L"null") +
            L",\"physical_address\":" + (v.PhysicalAddress ? Hex(s.PhysicalAddress) : L"null") +
            L",\"physical_address_mask\":" + (v.PhysicalAddressMask ? Hex(s.PhysicalAddressMask) : L"null") +
            L",\"node\":" + (v.Node ? std::to_wstring(s.Node) : L"null") +
            L",\"module\":" + (v.Module ? std::to_wstring(s.Module) : L"null") + L"}";
    }

    std::wstring Fields(const WHEA_PROCESSOR_GENERIC_ERROR_SECTION& s)
    {
        const auto v = s.ValidBits;
        return L"{\"valid_bits\":" + Hex(v.ValidBits) +
            L",\"processor_type\":" + (v.ProcessorType ? std::to_wstring(s.ProcessorType) : L"null") +
            L",\"error_type\":" + (v.ErrorType ? std::to_wstring(s.ErrorType) : L"null") +
            L",\"operation\":" + (v.Operation ? std::to_wstring(s.Operation) : L"null") +
            L",\"processor_id\":" + (v.ProcessorId ? Hex(s.ProcessorId) : L"null") +
            L",\"instruction_pointer\":" + (v.InstructionPointer ? Hex(s.InstructionPointer) : L"null") + L"}";
    }

    std::wstring Fields(const WHEA_PCIEXPRESS_ERROR_SECTION& s)
    {
        std::wstring id = L"null";
        if (s.ValidBits.DeviceId)
        {
            const auto d = s.DeviceId;
            id = L"{\"vendor\":" + Hex(d.VendorID) + L",\"device_id\":" + Hex(d.DeviceID) +
                L",\"segment\":" + std::to_wstring(d.Segment) + L",\"primary_bus\":" + std::to_wstring(d.PrimaryBusNumber) +
                L",\"device\":" + std::to_wstring(d.DeviceNumber) + L",\"function\":" + std::to_wstring(d.FunctionNumber) + L"}";
        }
        return L"{\"valid_bits\":" + Hex(s.ValidBits.ValidBits) +
            L",\"port_type\":" + (s.ValidBits.PortType ? std::to_wstring(s.PortType) : L"null") +
            L",\"device\":" + id + L"}";
    }

    template<class T>
    std::wstring Decode(const uint8_t* bytes, size_t size, size_t minimum = sizeof(T))
    {
        if (size < minimum) { return L"null"; }
        T value{};
        std::memcpy(&value, bytes, (std::min)(size, sizeof(T)));
        return Fields(value);
    }

    std::wstring HeaderJson(const Header& h)
    {
        return L"{\"revision\":" + Hex(h.Revision.AsUSHORT) + L",\"length\":" + std::to_wstring(h.Length) +
            L",\"section_count\":" + std::to_wstring(h.SectionCount) + L",\"severity\":" +
            std::to_wstring(static_cast<ULONG>(h.Severity)) + L",\"flags\":" + Hex(h.Flags.AsULONG) +
            L",\"valid_bits\":" + Hex(h.ValidBits.AsULONG) + L",\"record_id\":" + Hex(h.RecordId) +
            L",\"creator\":" + Guid(h.CreatorId) + L",\"notify_type\":" + Guid(h.NotifyType) +
            L",\"timestamp_raw\":" + (h.ValidBits.Timestamp ? Hex(h.Timestamp.AsLARGE_INTEGER.QuadPart) : L"null") +
            L",\"platform\":" + (h.ValidBits.PlatformId ? Guid(h.PlatformId) : L"null") +
            L",\"partition\":" + (h.ValidBits.PartitionId ? Guid(h.PartitionId) : L"null") + L"}";
    }

    struct McaComparison
    {
        std::optional<uint64_t> expected;
        bool anyValid = false;
        bool matched = false;
        bool matchedCorrected = false;
    };

    std::wstring Bank(ULONG bank, MCI_STATUS status, uint64_t address, uint64_t misc, McaComparison& compare)
    {
        const auto valid = status.CommonBits.Valid != 0;
        const auto equal = valid && compare.expected && status.QuadPart == *compare.expected;
        compare.anyValid |= valid;
        compare.matched |= equal;
        compare.matchedCorrected |= equal && !status.CommonBits.UncorrectedError;
        return L"{\"bank\":" + std::to_wstring(bank) + L",\"status\":" + Hex(status.QuadPart) +
            L",\"valid\":" + (valid ? L"true" : L"false") +
            L",\"uncorrected\":" + (valid ? (status.CommonBits.UncorrectedError ? L"true" : L"false") : L"null") +
            L",\"mca_error_code\":" + (valid ? Hex(status.CommonBits.McaErrorCode) : L"null") +
            L",\"model_error_code\":" + (valid ? Hex(status.CommonBits.ModelErrorCode) : L"null") +
            L",\"matches_stop_status\":" +
            (valid && compare.expected ? (equal ? L"true" : L"false") : L"null") + L",\"address\":" +
            (valid && status.CommonBits.AddressValid ? Hex(address) : L"null") + L",\"misc\":" +
            (valid && status.CommonBits.MiscValid ? Hex(misc) : L"null") + L"}";
    }

    std::wstring McaFields(const uint8_t* bytes, size_t size, McaComparison& compare, const wchar_t*& decode)
    {
        using Mca = WHEA_XPF_MCA_SECTION;
        ULONG version = 0;
        if (size < sizeof(version)) { decode = L"body_too_short"; return L"null"; }
        std::memcpy(&version, bytes, sizeof(version));
        size_t minimum = 0;
        switch (version)
        {
        case WHEA_XPF_MCA_SECTION_VERSION_2: minimum = offsetof(Mca, RecoveryInfo); break;
        case WHEA_XPF_MCA_SECTION_VERSION_3: minimum = offsetof(Mca, ExBankCount); break;
        case WHEA_XPF_MCA_SECTION_VERSION_4: minimum = sizeof(Mca); break;
        default: decode = L"unsupported_mca_version"; return L"null";
        }
        if (size < minimum) { decode = L"body_too_short"; return L"null"; }
        Mca m{};
        std::memcpy(&m, bytes, minimum);
        if (m.ExtendedRegisterCount > WHEA_XPF_MCA_EXTREG_MAX_COUNT || m.ExBankCount > WHEA_XPF_MCA_EXBANK_COUNT)
        { decode = L"invalid_mca_counts"; return L"null"; }
        auto banks = Bank(m.BankNumber, m.Status, m.Address, m.Misc, compare);
        for (ULONG i = 0; i < m.ExBankCount; ++i)
        { Append(banks, Bank(m.BankNumberEx[i], m.StatusEx[i], m.AddressEx[i], m.MiscEx[i], compare)); }
        return L"{\"version\":" + std::to_wstring(version) + L",\"cpu_vendor\":" +
            std::to_wstring(static_cast<ULONG>(m.CpuVendor)) + L",\"processor_number\":" + std::to_wstring(m.ProcessorNumber) +
            L",\"banks\":[" + banks + L"]}";
    }

    std::wstring SectionJson(const Descriptor& d, const uint8_t* bytes, const std::wstring& sha,
        McaComparison& compare, bool& incomplete)
    {
        const wchar_t* type = L"unknown";
        std::wstring fields = L"null";
        const wchar_t* decode = L"selected_fields";
        if (IsEqualGUID(d.SectionType, MEMORY_ERROR_SECTION_GUID))
        {
            type = L"memory";
            // The original platform memory format ends immediately after ErrorType.
            using Memory = WHEA_MEMORY_ERROR_SECTION;
            // Extended validity bits name bytes after the legacy 73-byte prefix.
            uint64_t validity = 0;
            if (d.SectionLength >= sizeof(validity)) { std::memcpy(&validity, bytes, sizeof(validity)); }
            const auto minimum = (validity >> 15) ? sizeof(Memory) : offsetof(Memory, ErrorType) + 1;
            fields = Decode<Memory>(bytes, d.SectionLength, minimum);
        }
        else if (IsEqualGUID(d.SectionType, PROCESSOR_GENERIC_ERROR_SECTION_GUID))
        { type = L"processor_generic"; fields = Decode<WHEA_PROCESSOR_GENERIC_ERROR_SECTION>(bytes, d.SectionLength); }
        else if (IsEqualGUID(d.SectionType, PCIEXPRESS_ERROR_SECTION_GUID))
        { type = L"pci_express"; fields = Decode<WHEA_PCIEXPRESS_ERROR_SECTION>(bytes, d.SectionLength); }
        else if (IsEqualGUID(d.SectionType, XPF_MCA_SECTION_GUID))
        { type = L"x86_x64_mca"; fields = McaFields(bytes, d.SectionLength, compare, decode); }
        else
        {
            decode = L"opaque";
            if (IsEqualGUID(d.SectionType, XPF_PROCESSOR_ERROR_SECTION_GUID)) { type = L"x86_x64_processor"; }
        }
        incomplete = fields == L"null" && std::wcscmp(decode, L"opaque") != 0;
        if (incomplete && std::wcscmp(decode, L"selected_fields") == 0) { decode = L"body_too_short"; }
        return L"{\"type_guid\":" + Guid(d.SectionType) + L",\"type\":" + Quote(type) +
            L",\"revision\":" + Hex(d.Revision.AsUSHORT) + L",\"offset\":" + std::to_wstring(d.SectionOffset) +
            L",\"length\":" + std::to_wstring(d.SectionLength) + L",\"sha256\":" + Quote(sha) +
            L",\"severity\":" + std::to_wstring(static_cast<ULONG>(d.SectionSeverity)) + L",\"flags\":" +
            Hex(d.Flags.AsULONG) + L",\"valid_bits\":" + Hex(d.ValidBits.AsUCHAR) +
            L",\"decode\":" + Quote(decode) +
            L",\"fields\":" + fields + L"}";
    }

    int SeverityRank(WHEA_ERROR_SEVERITY severity)
    {
        switch (severity)
        {
        case WheaErrSevFatal: return 3;
        case WheaErrSevRecoverable: return 2;
        case WheaErrSevCorrected: return 1;
        case WheaErrSevInformational: return 0;
        default: return -1;
        }
    }

    void ParseSections(const Header& h, const std::vector<uint8_t>& data, uint64_t sourceType, WheaRecord& r)
    {
        const size_t tableEnd = sizeof(Header) + h.SectionCount * sizeof(Descriptor);
        std::vector<Descriptor> desc(h.SectionCount);
        std::memcpy(desc.data(), data.data() + sizeof(Header), tableEnd - sizeof(Header));
        std::vector<std::pair<ULONG, ULONG>> ranges;
        for (const auto& d : desc)
        {
            if (d.Revision.AsUSHORT != WHEA_ERROR_RECORD_SECTION_DESCRIPTOR_REVISION)
            { r.status = L"unsupported_descriptor_revision"; return; }
            if (d.SectionOffset < tableEnd || d.SectionOffset > h.Length || !d.SectionLength ||
                d.SectionLength > h.Length - d.SectionOffset)
            { r.status = L"invalid_section_extent"; return; }
            ranges.emplace_back(d.SectionOffset, d.SectionOffset + d.SectionLength);
        }
        std::sort(ranges.begin(), ranges.end());
        for (size_t i = 1; i < ranges.size(); ++i)
        {
            if (ranges[i].first < ranges[i - 1].second) { r.status = L"overlapping_sections"; return; }
        }

        int highestSeverity = -1;
        bool unknownSeverity = false, incomplete = false, uncertainSection = false;
        McaComparison compare{r.stopMciStatus};
        std::wstring sections;
        for (const auto& d : desc)
        {
            const auto* bytes = data.data() + d.SectionOffset;
            std::wstring sha;
            if (!Digest(bytes, d.SectionLength, sha)) { r.status = L"digest_unavailable"; return; }
            bool incompleteHere = false;
            Append(sections, SectionJson(d, bytes, sha, compare, incompleteHere));
            incomplete |= incompleteHere;
            const auto rank = SeverityRank(d.SectionSeverity);
            highestSeverity = (std::max)(highestSeverity, rank);
            unknownSeverity |= rank < 0;
            uncertainSection |= d.Flags.Reserved || d.ValidBits.Reserved || d.Reserved;
        }
        r.sections = L"[" + sections + L"]";
        r.status = L"linked";
        unsigned index = 0;
        auto issue = [&](bool present, const wchar_t* reason, std::wstring& evidence)
        {
            if (!present) { return; }
            Append(r.issues, Quote(reason));
            Append(evidence, Quote(L"/whea_record/qualifiers/" + std::to_wstring(index++)));
        };
        issue(h.Flags.PreviousError != 0, L"previous_error", r.contrary);
        issue(h.Flags.Simulated != 0, L"simulated", r.contrary);
        issue(h.Flags.Recovered || h.Flags.RecoveryInProgress, L"recovery", r.contrary);
        issue(h.Flags.SectionsTruncated != 0, L"sections_truncated", r.missing);
        issue(h.Flags.DeviceDriver || sourceType == 0x10, L"device_driver_source", r.missing);
        issue(sourceType == 1 || sourceType == 2, L"corrected_stop_source", r.contrary);
        issue(sourceType == 7, L"boot_error_source", r.missing);
        issue(h.Flags.Reserved || h.ValidBits.Reserved || uncertainSection, L"unrecognized_flags", r.missing);
        issue(incomplete, L"incomplete_known_section", r.missing);
        issue(sourceType == 0 && !r.stopMciStatus, L"non_dword_stop_status_parts", r.missing);
        issue(sourceType == 0 && !compare.anyValid, L"valid_mca_bank_unavailable", r.missing);
        issue(compare.expected && compare.anyValid && !compare.matched, L"recorded_mca_statuses_differ", r.contrary);
        issue(compare.matchedCorrected, L"matching_bank_uncorrected_bit_clear", r.contrary);
        const int headerSeverity = SeverityRank(h.Severity);
        issue(unknownSeverity || headerSeverity < 0, L"unrecognized_severity", r.missing);
        issue(headerSeverity >= 0 && !unknownSeverity && headerSeverity != highestSeverity,
            L"inconsistent_section_severity", r.contrary);
        if (headerSeverity >= 0 && h.Severity != WheaErrSevFatal)
        { Append(r.contrary, Quote(L"/whea_record/header/severity")); }
        if (!r.issues.empty()) { r.fatalState = L"qualified_record"; }
        else { r.fatalState = h.Severity == WheaErrSevFatal ? L"supported_by_record" : L"different_record_severity"; }
    }

    void ReadRecord(SavedRecord& reader, uint64_t sourceType, WheaRecord& r)
    {
        if (!reader.ReadTo(sizeof(Header))) { return; }
        Header h{};
        std::memcpy(&h, reader.Data.data(), sizeof(h));
        if (h.Signature != WHEA_ERROR_RECORD_SIGNATURE || h.SignatureEnd != WHEA_ERROR_RECORD_SIGNATURE_END)
        { r.status = L"invalid_signature"; return; }
        if (h.Revision.AsUSHORT != WHEA_ERROR_RECORD_REVISION) { r.status = L"unsupported_header_revision"; return; }
        r.header = HeaderJson(h);
        if (!h.SectionCount || h.Length < sizeof(Header) + h.SectionCount * sizeof(Descriptor))
        { r.status = L"invalid_header_extent"; return; }
        if (h.Length > MaxLength || h.SectionCount > MaxSections) { r.status = L"record_budget_exceeded"; return; }
        if (reader.ReadTo(h.Length)) { ParseSections(h, reader.Data, sourceType, r); }
    }
}

void InspectStopWheaRecord(IDebugClient4& client, uint64_t sourceType, uint64_t address,
    uint64_t statusHigh, uint64_t statusLow, WheaRecord& result)
{
    if (sourceType > 0x10 || (sourceType >= 9 && sourceType <= 0xb))
    { result.status = L"unsupported_amd64_error_source"; return; }
    if (sourceType == 0 && statusHigh <= UINT32_MAX && statusLow <= UINT32_MAX)
    { result.stopMciStatus = (statusHigh << 32) | statusLow; }
    // The widest AMD64 canonical high half admits both four- and five-level targets.
    if (address < 0xff00000000000000ull) { result.status = L"invalid_record_address"; return; }
    ComPtr<IDebugDataSpaces> spaces;
    if (FAILED(client.QueryInterface(IID_PPV_ARGS(spaces.GetAddressOf())))) { result.status = L"data_spaces_unavailable"; return; }
    SavedRecord reader(*spaces.Get(), address, result);
    ReadRecord(reader, sourceType, result);
    result.captured = reader.Data.size();
    if (result.captured && !Digest(reader.Data.data(), result.captured, result.digest))
    {
        result.status = L"digest_unavailable";
        result.fatalState = L"unresolved";
        result.sections = L"null";
        result.issues.clear();
        result.contrary.clear();
        result.missing.clear();
    }
}

std::wstring WheaRecord::Json() const
{
    return L"{\"status\":" + Quote(status) + L",\"reads\":[" + reads + L"],\"captured_bytes\":" +
        std::to_wstring(captured) + L",\"captured_sha256\":" + (digest.empty() ? L"null" : Quote(digest)) +
        L",\"stop_mci_status\":" + (stopMciStatus ? Hex(*stopMciStatus) : L"null") +
        L",\"header\":" + header + L",\"sections\":" + sections + L",\"qualifiers\":[" + issues + L"]}";
}

std::wstring WheaRecord::Hypothesis() const
{
    const auto recordPaths = L"[\"/header/bugcheck/parameters/1\",\"/dbgeng/bugcheck/parameters/1\","
        L"\"/whea_record/header/severity\",\"/whea_record/sections\"]";
    return L"{\"candidate\":\"fatal_error_reported_at_stop\",\"state\":" + Quote(fatalState) +
        L",\"support\":" + (fatalState == L"supported_by_record" ? recordPaths : L"[]") +
        L",\"contrary\":[" + contrary + L"],\"missing\":[" +
        (status == L"linked" ? missing : Quote(L"/whea_record/status")) + L"],\"next\":" + Quote(status == L"linked" ? L"compare_record_with_independent_hardware_event_and_history" :
            L"obtain_saved_record_bytes_and_a_matching_crash_event") + L"}";
}
