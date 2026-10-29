#pragma once

#include "EvidenceBundle.h"
#include "McpJson.h"
#include "ObservationSource.h"

class BundleObservationSource final : public IObservationSource
{
public:
    explicit BundleObservationSource(EvidenceBundle bundle) : Bundle(std::move(bundle))
    {
        // Canonical serialization validates all metadata and bounds before use.
        // Bind identity to the entire immutable payload, not a reusable sequence.
        std::wstring digest;
        const auto json = EvidenceBundleJson(Bundle);
        if (!json.empty() && mcpjson::GetString(json, L"payload_sha256", &digest) && digest.size() == 64)
        {
            Caps.SourceId = L"bundle:" + digest;
        }
        Caps.Consistency = L"recorded_bundle";
        Caps.AddressSpace = Bundle.Receipt.Reference.Context.AddressSpace;
    }

    const ObservationSourceCapabilities& Capabilities() const override
    {
        return Caps;
    }

protected:
    ObservationReadResult ReadSpans(const ObservationReadRequest& request) override
    {
        const auto count = request.Length;
        std::vector<uint8_t> values(count);
        std::vector<ObservationReadState> states(count, ObservationReadState::NotCaptured);
        for (const auto& span : Bundle.Spans)
        {
            if (span.RequestedBytes == 0 || span.RequestedBytes > 4096 ||
                span.Address > UINT64_MAX - span.RequestedBytes ||
                (span.State != L"valid" && span.State != L"read_failed" && span.State != L"skipped") ||
                (span.State == L"valid" ? span.Bytes.size() != span.RequestedBytes : !span.Bytes.empty()))
            {
                return {};
            }
            const uint64_t begin = (std::max)(request.Address, span.Address);
            const uint64_t end = (std::min)(request.Address + count, span.Address + span.RequestedBytes);
            for (uint64_t address = begin; address < end; ++address)
            {
                const auto at = static_cast<size_t>(address - request.Address);
                auto& state = states[at];
                if (span.State == L"valid")
                {
                    const auto value = span.Bytes[static_cast<size_t>(address - span.Address)];
                    if (state == ObservationReadState::Conflict ||
                        (state == ObservationReadState::Complete && values[at] != value))
                    {
                        state = ObservationReadState::Conflict;
                    }
                    else
                    {
                        state = ObservationReadState::Complete;
                        values[at] = value;
                    }
                }
                else if (state != ObservationReadState::Complete && state != ObservationReadState::Conflict &&
                    state != ObservationReadState::Failed)
                {
                    state = span.State == L"read_failed" ? ObservationReadState::Failed : ObservationReadState::Skipped;
                }
            }
        }
        ObservationReadResult result;
        for (uint32_t at = 0; at < count;)
        {
            uint32_t end = at + 1;
            while (end < count && states[end] == states[at])
            {
                ++end;
            }
            ObservationReadSpan span;
            span.Address = request.Address + at;
            span.RequestedBytes = end - at;
            span.State = states[at];
            if (span.State == ObservationReadState::Complete)
            {
                span.Bytes.assign(values.begin() + at, values.begin() + end);
            }
            result.Spans.push_back(std::move(span));
            at = end;
        }
        return result;
    }

private:
    const EvidenceBundle Bundle;
    ObservationSourceCapabilities Caps;
};
