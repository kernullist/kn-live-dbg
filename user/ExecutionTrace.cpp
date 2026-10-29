#include "ExecutionTrace.h"
#include "ContentHash.h"
#include "McpJson.h"
#include "ReferenceArtifact.h"

#include <algorithm>
#include <iostream>
#include <map>
#include <set>

namespace
{
    using Object = std::map<std::wstring, std::wstring>;

    bool Members(const std::wstring& json, std::initializer_list<const wchar_t*> keys, Object* out)
    {
        if (!mcpjson::IsObject(json))
        {
            return false;
        }
        std::set<std::wstring> expected(keys.begin(), keys.end());
        size_t pos = 0;
        mcpjson::SkipWhitespace(json, &pos);
        ++pos;
        for (;;)
        {
            mcpjson::SkipWhitespace(json, &pos);
            if (pos == json.size() || json[pos] == L'}')
            {
                break;
            }
            size_t end = pos;
            if (!mcpjson::ScanString(json, &end))
            {
                return false;
            }
            const auto key = mcpjson::Unescape(json.substr(pos, end - pos));
            pos = end;
            mcpjson::SkipWhitespace(json, &pos);
            if (pos == json.size() || json[pos++] != L':' || expected.erase(key) != 1)
            {
                return false;
            }
            mcpjson::SkipWhitespace(json, &pos);
            if (!mcpjson::ScanValue(json, pos, &end))
            {
                return false;
            }
            out->emplace(key, json.substr(pos, end - pos));
            pos = end;
            mcpjson::SkipWhitespace(json, &pos);
            if (pos < json.size() && json[pos] == L',')
            {
                ++pos;
            }
        }
        return expected.empty();
    }

    bool Text(const std::wstring& raw, std::wstring* value, size_t maximum = 128)
    {
        if (raw.size() < 2 || raw.front() != L'"' || raw.back() != L'"')
        {
            return false;
        }
        // The shared display decoder repairs unpaired surrogates. Identity
        // input must reject them before decoding to avoid silent aliasing.
        bool high = false;
        for (size_t i = 1; i + 1 < raw.size(); ++i)
        {
            wchar_t c = raw[i];
            if (c == L'\\')
            {
                c = raw[++i];
                if (c == L'u')
                {
                    if (i + 4 >= raw.size())
                    {
                        return false;
                    }
                    c = static_cast<wchar_t>(wcstoul(raw.substr(i + 1, 4).c_str(), nullptr, 16));
                    i += 4;
                }
            }
            if (c >= 0xd800 && c <= 0xdbff)
            {
                if (high)
                {
                    return false;
                }
                high = true;
            }
            else if (c >= 0xdc00 && c <= 0xdfff)
            {
                if (!high)
                {
                    return false;
                }
                high = false;
            }
            else if (high)
            {
                return false;
            }
        }
        if (high)
        {
            return false;
        }
        *value = mcpjson::Unescape(raw);
        return !value->empty() && value->size() <= maximum && mcpjson::SanitizeUtf16(*value) == *value &&
            std::none_of(value->begin(), value->end(), [](wchar_t c)
            {
                return c < 0x20;
            });
    }

    bool Decimal(const std::wstring& value, uint64_t* number)
    {
        if (value.empty() || value.size() > 20 || (value.size() > 1 && value[0] == L'0'))
        {
            return false;
        }
        *number = 0;
        for (const auto c : value)
        {
            if (c < L'0' || c > L'9' || *number > (UINT64_MAX - (c - L'0')) / 10)
            {
                return false;
            }
            *number = *number * 10 + c - L'0';
        }
        return true;
    }

    template<typename T>
    bool Number(const std::wstring& raw, T* value)
    {
        std::wstring text;
        uint64_t number = 0;
        if (!Text(raw, &text, 20) || !Decimal(text, &number) || number > static_cast<T>(-1))
        {
            return false;
        }
        *value = static_cast<T>(number);
        return true;
    }

    template<typename T>
    bool OptionalNumber(const std::wstring& raw, std::optional<T>* value)
    {
        T number = 0;
        if (raw == L"null")
        {
            value->reset();
            return true;
        }
        if (!Number(raw, &number))
        {
            return false;
        }
        *value = number;
        return true;
    }

    bool Array(const std::wstring& raw, size_t maximum, std::vector<std::wstring>* rows)
    {
        if (raw.empty() || raw.front() != L'[' || !mcpjson::ValidateDocument(raw))
        {
            return false;
        }
        size_t pos = 1;
        for (;;)
        {
            mcpjson::SkipWhitespace(raw, &pos);
            if (pos == raw.size() || raw[pos] == L']')
            {
                break;
            }
            size_t end = 0;
            if (rows->size() == maximum || !mcpjson::ScanValue(raw, pos, &end))
            {
                return false;
            }
            rows->push_back(raw.substr(pos, end - pos));
            pos = end;
            mcpjson::SkipWhitespace(raw, &pos);
            if (pos < raw.size() && raw[pos] == L',')
            {
                ++pos;
            }
        }
        return true;
    }

    const TraceAddressSpace* Space(const ExecutionTrace& trace, const std::wstring& id)
    {
        for (const auto& space : trace.Spaces)
        {
            if (space.Id == id)
            {
                return &space;
            }
        }
        return nullptr;
    }

    const TraceCodeVersion* Code(const ExecutionTrace& trace, const std::wstring& id)
    {
        for (const auto& code : trace.Code)
        {
            if (code.Id == id)
            {
                return &code;
            }
        }
        return nullptr;
    }

    bool Range(const TraceAddressSpace& space, uint64_t address, size_t length)
    {
        return space.Domain == L"kernel" ? space.Format.KernelRange(address, length) : space.Format.UserRange(address, length);
    }

    bool Bytes(const std::wstring& raw, std::vector<uint8_t>* bytes)
    {
        std::wstring hex;
        if (!Text(raw, &hex, 8192) || hex.size() % 2 != 0 ||
            hex.find_first_not_of(L"0123456789abcdef") != std::wstring::npos)
        {
            return false;
        }
        const auto digit = [](wchar_t c)
        {
            return c <= L'9' ? c - L'0' : c - L'a' + 10;
        };
        for (size_t i = 0; i < hex.size(); i += 2)
        {
            bytes->push_back(static_cast<uint8_t>((digit(hex[i]) << 4) | digit(hex[i + 1])));
        }
        return true;
    }

    std::wstring N(uint64_t value)
    {
        return mcpjson::Quote(std::to_wstring(value));
    }

    template<typename T>
    std::wstring O(const std::optional<T>& value)
    {
        return value.has_value() ? N(*value) : L"null";
    }

    std::wstring Cursor(const ExecutionTrace& trace, size_t limit, size_t offset)
    {
        return L"kt1:" + trace.FileSha256 + L":" + std::to_wstring(limit) + L":" + std::to_wstring(offset);
    }

    const wchar_t* Qualification(const ExecutionTrace& trace, const TraceSample& sample)
    {
        const auto* space = Space(trace, sample.Space);
        if (space == nullptr || space->ProcessId == 0 || space->ProcessCreateTime == 0 ||
            space->RootIdentity == 0 || space->Epoch == 0 || sample.ThreadId == 0 ||
            sample.ThreadCreateTime < space->ProcessCreateTime || sample.ThreadCreateTime == 0)
        {
            return L"identity_or_address_space_unknown";
        }
        if (trace.Kind == L"cpu_sample" && (!sample.Cpu.has_value() || !trace.Vtl.has_value()))
        {
            return L"cpu_or_vtl_unknown";
        }
        if (!sample.CodeVersion.empty())
        {
            const auto* code = Code(trace, sample.CodeVersion);
            if (code == nullptr || code->Space != sample.Space || sample.Tick < code->FirstTick ||
                sample.Tick > code->LastTick || sample.Ip < code->Base || sample.Ip - code->Base >= code->Bytes.size())
            {
                return L"code_context_mismatch";
            }
            for (const auto& other : trace.Code)
            {
                if (other.Space != sample.Space || sample.Tick < other.FirstTick || sample.Tick > other.LastTick)
                {
                    continue;
                }
                const uint64_t start = (std::max)(code->Base, other.Base);
                const uint64_t left = start - code->Base;
                const uint64_t right = start - other.Base;
                if (left < code->Bytes.size() && right < other.Bytes.size())
                {
                    const size_t length = (std::min)(code->Bytes.size() - static_cast<size_t>(left),
                        other.Bytes.size() - static_cast<size_t>(right));
                    if (!std::equal(code->Bytes.begin() + static_cast<size_t>(left),
                        code->Bytes.begin() + static_cast<size_t>(left) + length,
                        other.Bytes.begin() + static_cast<size_t>(right)))
                    {
                        return L"conflicting_code_versions";
                    }
                }
            }
        }
        return L"metadata_consistent";
    }
}

bool ParseExecutionTrace(const std::wstring& json, ExecutionTrace* trace, std::wstring* error,
    const std::atomic<bool>* cancellation)
{
    if (trace == nullptr)
    {
        return false;
    }
    *trace = {};
    if (error != nullptr)
    {
        *error = L"invalid bounded execution trace or inconsistent scope";
    }
    const auto cancelled = [&]()
    {
        if (cancellation != nullptr && cancellation->load())
        {
            if (error != nullptr)
            {
                *error = L"execution trace import cancelled";
            }
            return true;
        }
        return false;
    };
    if (json.empty() || json.size() > ExecutionTraceMaxBytes || cancelled())
    {
        return false;
    }
    Object root;
    Object source;
    std::wstring schema;
    std::wstring architecture;
    ExecutionTrace parsed;
    if (!Members(json, {L"schema", L"source", L"address_spaces", L"code_versions", L"samples", L"loss_intervals"}, &root) ||
        !Text(root[L"schema"], &schema) || schema != L"kn.execution_trace.v1" ||
        !Members(root[L"source"], {L"id", L"producer", L"kind", L"target_id", L"boot_id", L"vm_id", L"vtl",
            L"architecture", L"clock_domain", L"ticks_per_second", L"first_tick", L"last_tick", L"records_lost"}, &source) ||
        !Text(source[L"id"], &parsed.SourceId) || !Text(source[L"producer"], &parsed.Producer) ||
        !Text(source[L"kind"], &parsed.Kind) ||
        (parsed.Kind != L"cpu_sample" && parsed.Kind != L"saved_context" && parsed.Kind != L"pointer_reference") ||
        !Text(source[L"target_id"], &parsed.TargetId) || !Text(source[L"boot_id"], &parsed.BootId) ||
        !Text(source[L"vm_id"], &parsed.VmId) || !OptionalNumber(source[L"vtl"], &parsed.Vtl) ||
        (parsed.Vtl.has_value() && *parsed.Vtl > 1) || !Text(source[L"architecture"], &architecture) || architecture != L"amd64" ||
        !Text(source[L"clock_domain"], &parsed.ClockDomain) || !Number(source[L"ticks_per_second"], &parsed.TicksPerSecond) ||
        parsed.TicksPerSecond == 0 || !Number(source[L"first_tick"], &parsed.FirstTick) ||
        !Number(source[L"last_tick"], &parsed.LastTick) || parsed.FirstTick > parsed.LastTick ||
        !OptionalNumber(source[L"records_lost"], &parsed.ReportedLost))
    {
        return false;
    }
    std::vector<std::wstring> rows;
    if (!Array(root[L"address_spaces"], 64, &rows))
    {
        return false;
    }
    for (const auto& row : rows)
    {
        Object fields;
        TraceAddressSpace space;
        uint32_t levels = 0;
        if (cancelled() || !Members(row, {L"id", L"domain", L"pid", L"process_create_time", L"root_identity", L"epoch", L"paging_levels"}, &fields) ||
            !Text(fields[L"id"], &space.Id) || Space(parsed, space.Id) != nullptr ||
            !Text(fields[L"domain"], &space.Domain) || (space.Domain != L"user" && space.Domain != L"kernel") ||
            !Number(fields[L"pid"], &space.ProcessId) || !Number(fields[L"process_create_time"], &space.ProcessCreateTime) ||
            !Number(fields[L"root_identity"], &space.RootIdentity) || !Number(fields[L"epoch"], &space.Epoch) ||
            !Number(fields[L"paging_levels"], &levels) || (levels != 4 && levels != 5))
        {
            return false;
        }
        space.Format = AddressSpaceDescriptor::FromPagingLevels(levels);
        parsed.Spaces.push_back(std::move(space));
    }
    rows.clear();
    if (!Array(root[L"code_versions"], 128, &rows))
    {
        return false;
    }
    for (const auto& row : rows)
    {
        Object fields;
        TraceCodeVersion code;
        if (cancelled() || !Members(row, {L"id", L"space", L"base", L"bytes_hex", L"sha256", L"first_tick", L"last_tick"}, &fields) ||
            !Text(fields[L"id"], &code.Id) || Code(parsed, code.Id) != nullptr || !Text(fields[L"space"], &code.Space) ||
            !Number(fields[L"base"], &code.Base) || !Bytes(fields[L"bytes_hex"], &code.Bytes) ||
            !Text(fields[L"sha256"], &code.Sha256, 64) || code.Sha256.size() != 64 || ContentHash::Bytes(code.Bytes) != code.Sha256 ||
            !Number(fields[L"first_tick"], &code.FirstTick) || !Number(fields[L"last_tick"], &code.LastTick) ||
            code.FirstTick > code.LastTick || code.FirstTick < parsed.FirstTick || code.LastTick > parsed.LastTick)
        {
            return false;
        }
        const auto* space = Space(parsed, code.Space);
        if (space == nullptr || !Range(*space, code.Base, code.Bytes.size()))
        {
            return false;
        }
        parsed.Code.push_back(std::move(code));
    }
    rows.clear();
    if (!Array(root[L"samples"], ExecutionTraceMaxSamples, &rows))
    {
        return false;
    }
    for (const auto& row : rows)
    {
        Object fields;
        TraceSample sample;
        if (cancelled() || !Members(row, {L"sequence", L"tick", L"cpu", L"space", L"tid", L"thread_create_time", L"ip", L"code_version"}, &fields) ||
            !Number(fields[L"sequence"], &sample.Sequence) || sample.Sequence == 0 ||
            !Number(fields[L"tick"], &sample.Tick) || sample.Tick < parsed.FirstTick || sample.Tick > parsed.LastTick ||
            !OptionalNumber(fields[L"cpu"], &sample.Cpu) || !Text(fields[L"space"], &sample.Space) ||
            !Number(fields[L"tid"], &sample.ThreadId) || !Number(fields[L"thread_create_time"], &sample.ThreadCreateTime) ||
            !Number(fields[L"ip"], &sample.Ip) ||
            (fields[L"code_version"] != L"null" && !Text(fields[L"code_version"], &sample.CodeVersion)))
        {
            return false;
        }
        const auto* space = Space(parsed, sample.Space);
        if (space == nullptr || !Range(*space, sample.Ip, 1) ||
            (!sample.CodeVersion.empty() && Code(parsed, sample.CodeVersion) == nullptr))
        {
            return false;
        }
        if (!parsed.Samples.empty())
        {
            const auto& previous = parsed.Samples.back();
            if (sample.Sequence <= previous.Sequence || sample.Tick < previous.Tick)
            {
                return false;
            }
            parsed.SequenceGaps += sample.Sequence - previous.Sequence - 1;
        }
        parsed.Samples.push_back(std::move(sample));
    }
    if (parsed.ReportedLost.has_value() && *parsed.ReportedLost < parsed.SequenceGaps)
    {
        return false;
    }
    rows.clear();
    if (!Array(root[L"loss_intervals"], 128, &rows))
    {
        return false;
    }
    for (const auto& row : rows)
    {
        Object fields;
        TraceLossInterval loss;
        if (cancelled() || !Members(row, {L"first_tick", L"last_tick", L"reason"}, &fields) ||
            !Number(fields[L"first_tick"], &loss.FirstTick) || !Number(fields[L"last_tick"], &loss.LastTick) ||
            loss.FirstTick > loss.LastTick || loss.FirstTick < parsed.FirstTick || loss.LastTick > parsed.LastTick ||
            !Text(fields[L"reason"], &loss.Reason))
        {
            return false;
        }
        parsed.Loss.push_back(std::move(loss));
    }
    if (cancelled())
    {
        return false;
    }
    *trace = std::move(parsed);
    if (error != nullptr)
    {
        error->clear();
    }
    return true;
}

std::wstring ExecutionTracePageJson(const ExecutionTrace& trace, size_t offset, size_t limit)
{
    if (offset > trace.Samples.size() || limit == 0 || limit > 128 || trace.FileSha256.size() != 64)
    {
        return L"{}";
    }
    const size_t end = offset + (std::min)(limit, trace.Samples.size() - offset);
    std::wstring out = L"{\"schema\":\"kn.execution_trace_query.v1\",\"status\":\"ok\",\"policy\":\"imported-samples-v1\"";
    out += L",\"collector_authenticated\":false,\"execution_independently_verified\":false,\"execution_observed\":false";
    out += L",\"control_flow_observed\":false,\"write_observed\":false,\"actor_attributed\":false,\"continuous_execution\":false";
    out += L",\"file_sha256\":" + mcpjson::Quote(trace.FileSha256);
    out += L",\"source\":{\"id\":" + mcpjson::Quote(trace.SourceId) + L",\"producer\":" + mcpjson::Quote(trace.Producer);
    out += L",\"kind\":" + mcpjson::Quote(trace.Kind) + L",\"target_id\":" + mcpjson::Quote(trace.TargetId);
    out += L",\"boot_id\":" + mcpjson::Quote(trace.BootId) + L",\"vm_id\":" + mcpjson::Quote(trace.VmId) + L",\"vtl\":" + O(trace.Vtl);
    out += L",\"architecture\":\"amd64\",\"pointer_bytes\":\"8\",\"clock_alignment\":\"not_established\"";
    out += L",\"clock_domain\":" + mcpjson::Quote(trace.ClockDomain) + L",\"ticks_per_second\":" + N(trace.TicksPerSecond);
    out += L",\"first_tick\":" + N(trace.FirstTick) + L",\"last_tick\":" + N(trace.LastTick) + L"}";
    out += L",\"records_lost\":" + O(trace.ReportedLost) + L",\"sequence_gaps\":" + N(trace.SequenceGaps);
    out += L",\"loss_intervals\":[";
    for (size_t i = 0; i < trace.Loss.size(); ++i)
    {
        const auto& loss = trace.Loss[i];
        out += (i == 0 ? L"" : L",") + std::wstring(L"{\"first_tick\":") + N(loss.FirstTick) +
            L",\"last_tick\":" + N(loss.LastTick) + L",\"reason\":" + mcpjson::Quote(loss.Reason) + L"}";
    }
    out += L"],\"address_spaces\":[";
    for (size_t i = 0; i < trace.Spaces.size(); ++i)
    {
        const auto& space = trace.Spaces[i];
        out += (i == 0 ? L"" : L",") + std::wstring(L"{\"id\":") + mcpjson::Quote(space.Id) +
            L",\"domain\":" + mcpjson::Quote(space.Domain) + L",\"pid\":" + N(space.ProcessId) +
            L",\"process_create_time\":" + N(space.ProcessCreateTime) + L",\"root_identity\":" + N(space.RootIdentity) +
            L",\"epoch\":" + N(space.Epoch) + L",\"virtual_address_bits\":" + N(space.Format.VirtualAddressBits) + L"}";
    }
    out += L"],\"code_versions\":[";
    for (size_t i = 0; i < trace.Code.size(); ++i)
    {
        const auto& code = trace.Code[i];
        out += (i == 0 ? L"" : L",") + std::wstring(L"{\"id\":") + mcpjson::Quote(code.Id) +
            L",\"space\":" + mcpjson::Quote(code.Space) + L",\"base\":" + N(code.Base) +
            L",\"size\":" + N(code.Bytes.size()) + L",\"sha256\":" + mcpjson::Quote(code.Sha256) +
            L",\"first_tick\":" + N(code.FirstTick) + L",\"last_tick\":" + N(code.LastTick) +
            L",\"retained_bytes_hash_verified\":true,\"runtime_mapping_verified\":false}";
    }
    out += L"],\"samples_total\":" + std::to_wstring(trace.Samples.size()) + L",\"offset\":" + std::to_wstring(offset);
    out += L",\"next_cursor\":" + mcpjson::Quote(end < trace.Samples.size() ? Cursor(trace, limit, end) : L"");
    out += L",\"query_complete\":" + std::wstring(end == trace.Samples.size() ? L"true" : L"false") + L",\"samples\":[";
    for (size_t i = offset; i < end; ++i)
    {
        const auto& sample = trace.Samples[i];
        const auto reason = Qualification(trace, sample);
        const bool qualified = std::wstring(reason) == L"metadata_consistent";
        const auto reportedLevel = !qualified ? L"unqualified" : trace.Kind == L"cpu_sample" ? L"X2" :
            trace.Kind == L"saved_context" ? L"X1" : L"X0";
        const bool lossOverlap = std::any_of(trace.Loss.begin(), trace.Loss.end(), [&](const auto& loss)
        {
            return sample.Tick >= loss.FirstTick && sample.Tick <= loss.LastTick;
        });
        out += (i == offset ? L"" : L",") + std::wstring(L"{\"sequence\":") + N(sample.Sequence) +
            L",\"tick\":" + N(sample.Tick) + L",\"cpu\":" + O(sample.Cpu) + L",\"space\":" + mcpjson::Quote(sample.Space) +
            L",\"tid\":" + N(sample.ThreadId) + L",\"thread_create_time\":" + N(sample.ThreadCreateTime) +
            L",\"ip\":" + N(sample.Ip) + L",\"code_version\":" + (sample.CodeVersion.empty() ? L"null" : mcpjson::Quote(sample.CodeVersion)) +
            L",\"qualified_reported_level\":" + mcpjson::Quote(reportedLevel) + L",\"qualification\":" + mcpjson::Quote(reason) +
            L",\"loss_interval_overlap\":" + (lossOverlap ? L"true" : L"false") + L"}";
    }
    return out + L"],\"identity_time_format\":\"windows_filetime\",\"live_backend_opened\":false,\"raw_decoder_used\":false}";
}

int RunExecutionTraceCommand(const std::vector<std::wstring>& args, const std::atomic<bool>* cancellation)
{
    std::wstring error;
    std::wstring cursor;
    uint64_t limit = 64;
    bool seenLimit = false;
    bool seenCursor = false;
    bool seenJson = false;
    bool arguments = !args.empty() && !args[0].empty();
    for (size_t i = 1; arguments && i < args.size(); ++i)
    {
        if (args[i] == L"/limit" && !seenLimit && i + 1 < args.size())
        {
            seenLimit = true;
            arguments = Decimal(args[++i], &limit) && limit >= 1 && limit <= 128;
        }
        else if (args[i] == L"/cursor" && !seenCursor && i + 1 < args.size())
        {
            seenCursor = true;
            cursor = args[++i];
            arguments = !cursor.empty() && cursor.size() <= 128;
        }
        else if (args[i] == L"/json" && !seenJson)
        {
            seenJson = true;
        }
        else
        {
            arguments = false;
        }
    }
    if (!arguments)
    {
        std::wcerr << L"usage: --offline !kmon trace <file> [/limit 1..128] [/cursor token] [/json]\n";
        return 2;
    }
    try
    {
        ReferenceArtifact file;
        ExecutionTrace trace;
        if (cancellation != nullptr && cancellation->load())
        {
            error = L"execution trace import cancelled";
        }
        else if (file.Open(args[0], &error, ExecutionTraceMaxBytes))
        {
            const auto& bytes = file.Bytes();
            const std::string utf8(bytes.begin(), bytes.end());
            const auto json = mcpjson::Utf8ToWide(utf8);
            if (mcpjson::WideToUtf8(json) != utf8)
            {
                error = L"trace input must be strict UTF-8 without a BOM";
            }
            else if (ParseExecutionTrace(json, &trace, &error, cancellation))
            {
                trace.FileSha256 = file.Sha256();
                uint64_t offset = 0;
                const auto prefix = Cursor(trace, static_cast<size_t>(limit), 0);
                const auto stem = prefix.substr(0, prefix.size() - 1);
                if (!cursor.empty() && (cursor.rfind(stem, 0) != 0 ||
                    !Decimal(cursor.substr(stem.size()), &offset) || offset > trace.Samples.size()))
                {
                    error = L"cursor does not match the immutable input and query";
                }
                else if (cancellation != nullptr && cancellation->load())
                {
                    error = L"execution trace import cancelled";
                }
                else
                {
                    std::cout << mcpjson::WideToUtf8(ExecutionTracePageJson(trace,
                        static_cast<size_t>(offset), static_cast<size_t>(limit))) << "\n";
                    std::cout.flush();
                    return std::cout ? 0 : 1;
                }
            }
        }
    }
    catch (const std::exception&)
    {
        error = L"execution trace import could not materialize bounded input";
    }
    std::cout << mcpjson::WideToUtf8(L"{\"schema\":\"kn.execution_trace_query.v1\",\"status\":\"unavailable\",\"execution_observed\":false,\"error\":" +
        mcpjson::Quote(error) + L"}") << "\n";
    return 1;
}
