#include "ImageVerificationRecipe.h"
#include "ContentHash.h"
#include "McpJson.h"
#include "ObservationSourceJson.h"
#include <set>

namespace
{
    std::wstring N(uint64_t number)
    {
        return mcpjson::Quote(std::to_wstring(number));
    }
    std::wstring B(bool value)
    {
        return value ? L"true" : L"false";
    }
    bool N(const std::wstring& json, const wchar_t* key, uint64_t* number)
    {
        std::wstring text;
        if (!mcpjson::GetString(json, key, &text) || text.empty() || text.size() > 20)
        {
            return false;
        }
        *number = 0;
        for (const auto c : text)
        {
            if (c < L'0' || c > L'9' || *number > (UINT64_MAX - (c - L'0')) / 10)
            {
                return false;
            }
            *number = *number * 10 + c - L'0';
        }
        return true;
    }
    bool B(const std::wstring& json, const wchar_t* key, bool* value)
    {
        std::wstring raw;
        if (!mcpjson::FindRawValue(json, key, &raw) || (raw != L"true" && raw != L"false"))
        {
            return false;
        }
        *value = raw == L"true";
        return true;
    }
    bool Text(const std::wstring& value, size_t limit)
    {
        return !value.empty() && value.size() <= limit && value.find(L'\0') == std::wstring::npos &&
            mcpjson::SanitizeUtf16(value) == value;
    }
    std::wstring Hex(const std::vector<uint8_t>& bytes)
    {
        std::wstring out;
        for (const auto byte : bytes)
        {
            out += L"0123456789abcdef"[byte >> 4];
            out += L"0123456789abcdef"[byte & 15];
        }
        return out;
    }
    bool Hex(const std::wstring& text, std::vector<uint8_t>* bytes)
    {
        if (text.size() > 8192 || text.size() % 2 != 0 || text.find_first_not_of(L"0123456789abcdef") != std::wstring::npos)
        {
            return false;
        }
        const auto digit = [](wchar_t c)
        {
            return c <= L'9' ? c - L'0' : c - L'a' + 10;
        };
        for (size_t i = 0; i < text.size(); i += 2)
        {
            bytes->push_back(static_cast<uint8_t>((digit(text[i]) << 4) | digit(text[i + 1])));
        }
        return true;
    }
    bool State(const std::wstring& json, const wchar_t* key, ObservationReadState* state)
    {
        std::wstring name;
        if (!mcpjson::GetString(json, key, &name))
        {
            return false;
        }
        for (int i = 0; i <= static_cast<int>(ObservationReadState::Cancelled); ++i)
        {
            if (name == ObservationReadStateName(static_cast<ObservationReadState>(i)))
            {
                *state = static_cast<ObservationReadState>(i);
                return true;
            }
        }
        return false;
    }
    bool Array(const std::wstring& object, const wchar_t* name, size_t limit, std::vector<std::wstring>* rows)
    {
        std::wstring raw;
        if (!mcpjson::FindRawValue(object, name, &raw) || raw.empty() || raw[0] != L'[')
        {
            return false;
        }
        size_t pos = 1;
        while (pos < raw.size() && raw[pos] != L']')
        {
            size_t end = 0;
            if (rows->size() == limit || !mcpjson::ScanValue(raw, pos, &end))
            {
                return false;
            }
            rows->push_back(raw.substr(pos, end - pos));
            pos = end;
            if (pos < raw.size() && raw[pos] == L',')
            {
                ++pos;
                if (pos == raw.size() || raw[pos] == L']')
                {
                    return false;
                }
            }
            else
            {
                break;
            }
        }
        return pos + 1 == raw.size() && raw[pos] == L']';
    }
    bool Valid(const ImageVerificationRecipe& p)
    {
        if (!Text(p.Policy, 128) || p.ReferenceSha256.size() != 64 ||
            p.ReferenceSha256.find_first_not_of(L"0123456789abcdef") != std::wstring::npos ||
            !Text(p.OriginalReference, 30000) || !Text(p.OriginalFileIdentity, 128) ||
            !Text(p.SourceId, 1024) || !Text(p.SourceConsistency, 128) || p.CapturedFileTime == 0 ||
            (p.VirtualAddressBits != 48 && p.VirtualAddressBits != 57) || p.ImageBase == 0 ||
            p.Length == 0 || p.Length > 4096 || p.ImageBase > UINT64_MAX - p.Rva ||
            p.ImageBase + p.Rva > UINT64_MAX - p.Length || p.Reads.empty() || p.Reads.size() > ImageRecipeMaxReads ||
            p.Normalization.empty() || p.Normalization.size() > 512 * 1024 || p.Normalization[0] != L'{' ||
            p.RecordedResult.empty() || p.RecordedResult.size() > 128 * 1024 || p.RecordedResult[0] != L'{' ||
            !mcpjson::ValidateDocument(p.Normalization) || !mcpjson::ValidateDocument(p.RecordedResult))
        {
            return false;
        }
        const auto space = AddressSpaceDescriptor::FromPagingLevels(p.VirtualAddressBits == 57 ? 5 : 4);
        const auto canonical = [&](uint64_t address, uint64_t size)
        {
            return space.UserRange(address, size) || space.KernelRange(address, size);
        };
        if (!canonical(p.ImageBase, 1) || !canonical(p.ImageBase + p.Rva, p.Length))
        {
            return false;
        }
        uint64_t budget = ImageRecipeReadBudget, lastTick = 0;
        for (const auto& read : p.Reads)
        {
            const auto& result = read.Result;
            if (read.Length == 0 || read.Length > 4096 || read.Length > budget || read.Address > UINT64_MAX - read.Length ||
                !Text(result.SourceId, 1024) || !Text(result.Consistency, 128) ||
                result.ClockDomain != L"collector_steady_clock_ms" || result.EndedTick < result.StartedTick ||
                result.StartedTick < lastTick || result.State < ObservationReadState::Complete ||
                result.State > ObservationReadState::Cancelled || result.Spans.size() > read.Length ||
                !Text(result.NativeStatusDomain, 128) || result.SideEffectsPossible)
            {
                return false;
            }
            if (result.State == ObservationReadState::Complete &&
                (result.SourceId != p.SourceId || result.Consistency != p.SourceConsistency))
            {
                return false;
            }
            budget -= read.Length;
            lastTick = result.EndedTick;
            if (result.Spans.empty())
            {
                if (result.State == ObservationReadState::Complete || result.State == ObservationReadState::Partial)
                {
                    return false;
                }
                continue;
            }
            uint64_t consumed = 0;
            const auto state = result.Spans.front().State;
            bool same = true;
            for (const auto& span : result.Spans)
            {
                if (span.RequestedBytes == 0 || span.RequestedBytes > read.Length - consumed ||
                    span.Address != read.Address + consumed || span.State == ObservationReadState::Partial ||
                    span.State < ObservationReadState::Complete || span.State > ObservationReadState::Cancelled ||
                    (span.State == ObservationReadState::Complete ? span.Bytes.size() != span.RequestedBytes : !span.Bytes.empty()))
                {
                    return false;
                }
                if (span.State == ObservationReadState::Complete &&
                    (!canonical(span.Address, span.RequestedBytes) || result.SourceId != p.SourceId ||
                        result.Consistency != p.SourceConsistency))
                {
                    return false;
                }
                consumed += span.RequestedBytes;
                same = same && span.State == state;
            }
            if (consumed != read.Length || result.State != (same ? state : ObservationReadState::Partial))
            {
                return false;
            }
        }
        return true;
    }

    std::wstring Payload(const ImageVerificationRecipe& p)
    {
        std::wstring json = L"{\"policy\":" + mcpjson::Quote(p.Policy) + L",\"reference_sha256\":" + mcpjson::Quote(p.ReferenceSha256) +
            L",\"original_reference\":" + mcpjson::Quote(p.OriginalReference) + L",\"original_file_identity\":" + mcpjson::Quote(p.OriginalFileIdentity) +
            L",\"source_id\":" + mcpjson::Quote(p.SourceId) + L",\"source_consistency\":" + mcpjson::Quote(p.SourceConsistency) +
            L",\"captured_filetime\":" + N(p.CapturedFileTime) + L",\"virtual_address_bits\":" + N(p.VirtualAddressBits) +
            L",\"image_base\":" + N(p.ImageBase) + L",\"rva\":" + N(p.Rva) + L",\"length\":" + N(p.Length) +
            L",\"collector_authenticated\":false,\"signer_approved\":false,\"hotpatch_epoch\":\"unavailable\","
            L"\"normalization\":" + p.Normalization + L",\"recorded_result\":" + p.RecordedResult + L",\"reads\":[";
        bool first = true;
        for (const auto& read : p.Reads)
        {
            if (!first)
            {
                json += L",";
            }
            first = false;
            const auto& r = read.Result;
            json += L"{\"address\":" + N(read.Address) + L",\"length\":" + N(read.Length) +
                L",\"state\":" + mcpjson::Quote(ObservationReadStateName(r.State)) +
                L",\"source_id\":" + mcpjson::Quote(r.SourceId) + L",\"consistency\":" + mcpjson::Quote(r.Consistency) +
                L",\"clock_domain\":" + mcpjson::Quote(r.ClockDomain) + L",\"started_tick\":" + N(r.StartedTick) +
                L",\"ended_tick\":" + N(r.EndedTick) + L",\"cancelled\":" + B(r.CancellationObserved) +
                L",\"identity_revalidated\":" + B(r.IdentityRevalidated) +
                L",\"native_status_domain\":" + mcpjson::Quote(r.NativeStatusDomain) + L",\"native_status\":" + N(r.NativeStatus) +
                L",\"spans\":[";
            bool firstSpan = true;
            for (const auto& span : r.Spans)
            {
                if (!firstSpan)
                {
                    json += L",";
                }
                firstSpan = false;
                json += L"{\"address\":" + N(span.Address) + L",\"length\":" + N(span.RequestedBytes) +
                    L",\"state\":" + mcpjson::Quote(ObservationReadStateName(span.State)) + L",\"bytes\":" + mcpjson::Quote(Hex(span.Bytes)) + L"}";
            }
            json += L"]}";
        }
        return json + L"]}";
    }
}

std::wstring ImageRecipeJson(const ImageVerificationRecipe& recipe)
{
    if (!Valid(recipe))
    {
        return L"";
    }
    const auto payload = Payload(recipe);
    const auto bytes = mcpjson::WideToUtf8(payload);
    if (bytes.size() > ImageRecipeMaxBytes - 256)
    {
        return L"";
    }
    ContentHash hash;
    const auto digest = hash.Add(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()) ? hash.Finish() : L"";
    return digest.empty() ? L"" : L"{\"schema\":\"kn.image_recipe.v1\",\"recipe_sha256\":" + mcpjson::Quote(digest) + L",\"payload\":" + payload + L"}";
}

bool ParseImageRecipe(const std::wstring& json, ImageVerificationRecipe* recipe, std::wstring* error)
{
    if (error != nullptr)
    {
        *error = L"image recipe is corrupt, noncanonical, unsupported, or exceeds its budget";
    }
    ImageVerificationRecipe p;
    std::wstring payload;
    uint64_t bits = 0, rva = 0, length = 0;
    std::vector<std::wstring> reads;
    if (recipe == nullptr || json.size() > ImageRecipeMaxBytes || !mcpjson::ValidateDocument(json) ||
        !mcpjson::FindRawValue(json, L"payload", &payload) || !mcpjson::GetString(payload, L"policy", &p.Policy) ||
        !mcpjson::GetString(payload, L"reference_sha256", &p.ReferenceSha256) ||
        !mcpjson::GetString(payload, L"original_reference", &p.OriginalReference) ||
        !mcpjson::GetString(payload, L"original_file_identity", &p.OriginalFileIdentity) ||
        !mcpjson::GetString(payload, L"source_id", &p.SourceId) || !mcpjson::GetString(payload, L"source_consistency", &p.SourceConsistency) ||
        !N(payload, L"captured_filetime", &p.CapturedFileTime) || !N(payload, L"virtual_address_bits", &bits) || bits > UINT32_MAX ||
        !N(payload, L"image_base", &p.ImageBase) || !N(payload, L"rva", &rva) || rva > UINT32_MAX ||
        !N(payload, L"length", &length) || length > 4096 ||
        !mcpjson::FindRawValue(payload, L"normalization", &p.Normalization) ||
        !mcpjson::FindRawValue(payload, L"recorded_result", &p.RecordedResult) || !Array(payload, L"reads", ImageRecipeMaxReads, &reads))
    {
        return false;
    }
    p.VirtualAddressBits = static_cast<uint32_t>(bits);
    p.Rva = static_cast<uint32_t>(rva);
    p.Length = static_cast<uint32_t>(length);
    for (const auto& row : reads)
    {
        ImageRecipeRead read;
        auto& r = read.Result;
        uint64_t nativeStatus = 0;
        std::vector<std::wstring> spans;
        if (!N(row, L"address", &read.Address) || !N(row, L"length", &length) || length > 4096 ||
            !State(row, L"state", &r.State) || !mcpjson::GetString(row, L"source_id", &r.SourceId) ||
            !mcpjson::GetString(row, L"consistency", &r.Consistency) || !mcpjson::GetString(row, L"clock_domain", &r.ClockDomain) ||
            !N(row, L"started_tick", &r.StartedTick) || !N(row, L"ended_tick", &r.EndedTick) ||
            !B(row, L"cancelled", &r.CancellationObserved) || !B(row, L"identity_revalidated", &r.IdentityRevalidated) ||
            !mcpjson::GetString(row, L"native_status_domain", &r.NativeStatusDomain) || !N(row, L"native_status", &nativeStatus) ||
            nativeStatus > UINT32_MAX || !Array(row, L"spans", 4096, &spans))
        {
            return false;
        }
        read.Length = static_cast<uint32_t>(length);
        r.NativeStatus = static_cast<uint32_t>(nativeStatus);
        for (const auto& spanJson : spans)
        {
            ObservationReadSpan span;
            std::wstring hex;
            if (!N(spanJson, L"address", &span.Address) || !N(spanJson, L"length", &length) || length > 4096 ||
                !State(spanJson, L"state", &span.State) || !mcpjson::GetString(spanJson, L"bytes", &hex) || !Hex(hex, &span.Bytes))
            {
                return false;
            }
            span.RequestedBytes = static_cast<uint32_t>(length);
            r.Spans.push_back(std::move(span));
        }
        p.Reads.push_back(std::move(read));
    }
    if (!Valid(p) || ImageRecipeJson(p) != json)
    {
        return false;
    }
    *recipe = std::move(p);
    if (error != nullptr)
    {
        error->clear();
    }
    return true;
}

std::wstring ImageRecipeReplayJson(const ImageRecipeReplay& replay)
{
    return L"{\"schema\":\"kn.image_replay.v1\",\"status\":" + mcpjson::Quote(replay.Status) +
        L",\"mode\":" + mcpjson::Quote(replay.Mode) + L",\"recipe_sha256\":" + mcpjson::Quote(replay.RecipeSha256) +
        L",\"recorded_policy\":" + mcpjson::Quote(replay.RecordedPolicy) + L",\"current_policy\":" + mcpjson::Quote(ImageRecipePolicy) +
        L",\"collector_authenticated\":false,\"execution_observed\":false,\"rereads_are_recorded\":true,\"recorded_result\":" +
        (replay.RecordedResult.empty() ? L"null" : replay.RecordedResult) + L",\"result\":" +
        (replay.CurrentResult.empty() ? L"null" : replay.CurrentResult) + L"}";
}
