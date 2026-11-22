#include "V8Profile.h"
#include "ArtifactOutput.h"
#include "ContentHash.h"
#include "McpJson.h"
#include "ReferenceArtifact.h"
#include "TraceJsonFields.h"

#include <algorithm>
#include <charconv>
#include <cstring>
#include <iterator>
#include <iostream>
#include <map>
#include <optional>
#include <sstream>
#include <string_view>

namespace
{
    using View = std::string_view;
    using mcpjson::Quote;
    constexpr uint32_t MaxEvents = 65536;
    constexpr uint32_t MaxLines = 1000000;
    constexpr uint64_t LastUser = 0x00007fffffffffffULL;
    constexpr size_t NoLocation = SIZE_MAX;
    struct Failure { const wchar_t* reason; };
    void Need(bool ok, const wchar_t* reason) { if (!ok) { throw Failure{reason}; } }
    void Running(const std::atomic<bool>* stop) { Need(!stop || !stop->load(), L"cancelled"); }

    template<class T> bool Number(View field, T& value, int base = 10)
    {
        if (field.empty()) { return false; }
        const auto end = field.data() + field.size();
        const auto result = std::from_chars(field.data(), end, value, base);
        return result.ec == std::errc{} && result.ptr == end;
    }

    uint64_t Address(View field)
    {
        uint64_t value = 0;
        Need(field.size() > 2 && field.substr(0, 2) == "0x" && Number(field.substr(2), value, 16), L"invalid_address");
        return value;
    }

    bool Extent(uint64_t start, uint32_t size)
    {
        return start >= 0x10000 && start <= LastUser && size && size - 1 <= LastUser - start;
    }

    // V8 escapes commas inside strings. Take just the fields this record consumes.
    View Take(View& tail)
    {
        const auto pos = tail.find(',');
        const auto first = tail.substr(0, pos);
        tail = pos == View::npos ? View{} : tail.substr(pos + 1);
        return first;
    }

    struct Code
    {
        uint32_t record = 0, size = 0, deopt = 0;
        uint64_t start = 0, time = 0;
        std::optional<uint64_t> functionTag;
        int kind = 0;
        View tag, name, marker;
        uint32_t binaryRecord = 0;
        size_t body = 0;
        View binaryName;
        std::wstring bodyHash;
        bool JsDeclaration() const
        {
            return (tag == "JS" || tag == "Eval" || tag == "Script") && kind >= 9 && kind <= 12;
        }
        bool JsMachine() const
        {
            return JsDeclaration() && functionTag && Extent(*functionTag, 1) &&
                ((kind == 10 && marker == "^") || (kind == 11 && (marker == "+" || marker == "+'")) ||
                 (kind == 12 && (marker == "*" || marker == "*'")));
        }
    };

    struct Location { uint64_t base; size_t code; uint32_t record; };
    struct MappingEvent { char type; uint64_t from, to; size_t code; };
    struct Tick
    {
        uint32_t ordinal = 0, record = 0, state = 0, depth = 0;
        uint64_t pc = 0, time = 0, top = 0;
        bool external = false, overflow = false;
        size_t location = NoLocation;
    };

    struct Profile
    {
        std::vector<Code> codes;
        std::vector<Location> locations;
        std::map<uint64_t, size_t> active;
        std::vector<MappingEvent> transcript;
        std::vector<Tick> page;
        uint32_t lines = 0, ticks = 0, overflows = 0, begin = 0, end = 0, period = 0, moves = 0, deletes = 0;
        uint64_t lastTime = 0;
        bool reversed = false, incompleteMap = false, shortLine = false;

        void Clock(uint64_t t) { reversed |= t < lastTime; lastTime = t; }

        void Place(uint64_t start, size_t code)
        {
            const auto size = codes[code].size;
            Need(Extent(start, size) && locations.size() < MaxEvents, L"invalid_or_excessive_ranges");
            auto it = active.lower_bound(start);
            if (it != active.begin())
            {
                const auto prev = std::prev(it);
                if (start - prev->first < codes[locations[prev->second].code].size) { it = prev; }
            }
            // V8's dynamic code map retires the entire old entry on any intersection.
            while (it != active.end() && it->first < start + size) { it = active.erase(it); }
            active.emplace(start, locations.size());
            locations.push_back({start, code, lines});
        }

        size_t Find(uint64_t pc) const
        {
            auto it = active.upper_bound(pc);
            if (it == active.begin()) { return NoLocation; }
            --it;
            return pc - it->first < codes[locations[it->second].code].size ? it->second : NoLocation;
        }

        void Create(View fields)
        {
            Need(codes.size() < MaxEvents && transcript.size() < MaxEvents, L"mapping_limit");
            const auto columns = std::count(fields.begin(), fields.end(), ',');
            Need(columns == 5 || columns == 7, L"invalid_code_creation");
            Code c;
            c.record = lines;
            c.tag = Take(fields);
            Need(!c.tag.empty() && Number(Take(fields), c.kind) && Number(Take(fields), c.time), L"invalid_code_creation");
            c.start = Address(Take(fields));
            Need(Number(Take(fields), c.size) && Extent(c.start, c.size), L"invalid_code_extent");
            c.name = Take(fields);
            if (columns == 7) { c.functionTag = Address(Take(fields)); c.marker = fields; }
            const bool callback = c.tag == "Callback";
            Need(callback ? c.kind == -2 && c.size == 1 && columns == 5 : c.kind >= 0 && c.kind <= 12, L"unsupported_code_kind");
            Clock(c.time);
            const auto id = codes.size();
            codes.push_back(c);
            Place(c.start, id);
            // Callback registrations have no binary code-creation record.
            if (!callback) { transcript.push_back({'C', c.start, c.size, id}); }
        }

        void Relocate(View fields)
        {
            Need(transcript.size() < MaxEvents && std::count(fields.begin(), fields.end(), ',') == 1, L"invalid_code_move");
            const auto from = Address(Take(fields));
            const auto to = Address(fields);
            Need(Extent(from, 1) && Extent(to, 1), L"invalid_code_move");
            transcript.push_back({'M', from, to, 0});
            ++moves;
            const auto it = active.find(from);
            if (it == active.end()) { incompleteMap = true; return; }
            const auto code = locations[it->second].code;
            active.erase(it);
            Place(to, code);
        }

        void Sample(View fields, uint32_t offset, uint32_t limit)
        {
            Need(!fields.empty() && fields.back() != ',' && std::count(fields.begin(), fields.end(), ',') >= 4, L"invalid_tick");
            Tick t;
            t.record = lines;
            t.ordinal = ++ticks;
            t.pc = Address(Take(fields));
            Need(Number(Take(fields), t.time), L"invalid_tick");
            const auto external = Take(fields);
            Need(external == "0" || external == "1", L"invalid_tick");
            t.external = external == "1";
            t.top = Address(Take(fields));
            Need(Number(Take(fields), t.state) && t.state <= 9, L"invalid_tick");
            while (!fields.empty())
            {
                const auto frame = Take(fields);
                if (frame == "overflow")
                {
                    Need(!t.depth && !t.overflow, L"invalid_overflow");
                    t.overflow = true;
                    ++overflows;
                }
                else { Address(frame); Need(++t.depth <= 1024, L"stack_limit"); }
            }
            Clock(t.time);
            if (t.ordinal > offset && page.size() < limit)
            {
                t.location = Find(t.pc);
                page.push_back(t);
            }
        }

        void Read(const std::vector<uint8_t>& bytes, uint32_t offset, uint32_t limit, const std::atomic<bool>* stop)
        {
            View file(reinterpret_cast<const char*>(bytes.data()), bytes.size());
            bool version = false, platform = false;
            while (!file.empty())
            {
                Running(stop);
                Need(lines < MaxLines, L"record_limit");
                const auto nl = file.find('\n');
                if (nl == View::npos) { shortLine = true; break; }
                auto line = file.substr(0, nl);
                file.remove_prefix(nl + 1);
                ++lines;
                if (!line.empty() && line.back() == '\r') { line.remove_suffix(1); }
                Need(!line.empty() && line.find('\0') == View::npos, L"invalid_log_record");
                const auto type = Take(line);
                if (type == "v8-version")
                {
                    Need(lines == 1 && line == "13,6,233,17,-node.63,0", L"unsupported_v8_version");
                    version = true;
                }
                else if (type == "v8-platform")
                {
                    Need(lines == 2 && !platform && line == "windows,unknown", L"unsupported_v8_platform");
                    platform = true;
                }
                else
                {
                    Need(version && platform, L"missing_v8_header");
                    if (type == "code-creation") { Create(line); }
                    else if (type == "tick") { Sample(line, offset, limit); }
                    else if (type == "code-move") { Relocate(line); }
                    else if (type == "code-delete")
                    {
                        const auto address = Address(line);
                        Need(Extent(address, 1), L"invalid_code_delete");
                        incompleteMap |= active.erase(address) == 0;
                        ++deletes;
                    }
                    else if (type == "code-deopt")
                    {
                        uint64_t t = 0;
                        uint32_t size = 0;
                        Need(Number(Take(line), t) && Number(Take(line), size), L"invalid_deopt");
                        const auto address = Address(Take(line));
                        Need(Extent(address, 1), L"invalid_deopt");
                        const auto it = active.find(address);
                        Need(!line.empty(), L"invalid_deopt");
                        Clock(t);
                        if (it != active.end())
                        {
                            auto& c = codes[locations[it->second].code];
                            if (!c.deopt) { c.deopt = lines; }
                        }
                        else { incompleteMap = true; }
                    }
                    else if (type.substr(0, 5) == "code-" && type != "code-source-info" && type != "code-disassemble" &&
                        type != "code-disable-optimization")
                    {
                        incompleteMap = true;
                    }
                    else if (type == "profiler")
                    {
                        Need(line == "end" || line.substr(0, 6) == "begin,", L"invalid_profiler_boundary");
                        const auto event = Take(line);
                        if (event == "begin")
                        {
                            Need(!begin && !end && Number(line, period) && period, L"invalid_profiler_boundary");
                            begin = lines;
                        }
                        else
                        {
                            Need(event == "end" && begin && !end && line.empty(), L"invalid_profiler_boundary");
                            end = lines;
                        }
                    }
                }
            }
            Need(version && platform, L"missing_v8_header");
            Need(offset <= ticks, L"invalid_cursor");
        }

        bool Reused(const Tick& tick, const Location& at) const
        {
            for (const auto& loc : locations)
            {
                if ((loc.code != at.code || loc.base != at.base) && tick.pc >= loc.base && tick.pc - loc.base < codes[loc.code].size) { return true; }
            }
            return false;
        }
    };

    struct ByteLog
    {
        const wchar_t* status = L"not_supplied";
        uint32_t records = 0, gcMarkers = 0;
        bool matched = false;

        void Read(const std::vector<uint8_t>& bytes, Profile& p, const std::atomic<bool>* stop)
        {
            if (bytes.size() < 4 || std::memcmp(bytes.data(), "x64\0", 4))
            { status = L"unsupported_architecture"; return; }
            status = L"invalid_binary_record";
            size_t pos = 4, event = 0;
            bool equal = true;
            const auto u32 = [&](size_t at) { uint32_t v; std::memcpy(&v, bytes.data() + at, sizeof(v)); return v; };
            const auto u64 = [&](size_t at) { uint64_t v; std::memcpy(&v, bytes.data() + at, sizeof(v)); return v; };
            while (pos < bytes.size())
            {
                Running(stop);
                if (records >= MaxEvents) { status = L"binary_record_limit"; return; }
                ++records;
                const char type = static_cast<char>(bytes[pos++]);
                if (type == 'G') { ++gcMarkers; continue; }
                // The Windows x64 writer emits the native structure (including padding)
                // after a one-byte tag. Never reinterpret its unaligned fields.
                const auto* e = event < p.transcript.size() ? &p.transcript[event] : nullptr;
                ++event;
                if (type == 'M')
                {
                    if (bytes.size() - pos < 16) { return; }
                    const auto from = u64(pos), to = u64(pos + 8);
                    if (!Extent(from, 1) || !Extent(to, 1)) { return; }
                    equal &= e && e->type == 'M' && e->from == from && e->to == to;
                    pos += 16;
                    continue;
                }
                if (type != 'C' || bytes.size() - pos < 24) { return; }
                const auto nameSize = u32(pos), size = u32(pos + 16);
                const auto address = u64(pos + 8);
                pos += 24;
                if (!nameSize || nameSize > 4096 || !Extent(address, size) || nameSize > bytes.size() - pos) { return; }
                const View name(reinterpret_cast<const char*>(bytes.data() + pos), nameSize);
                pos += nameSize;
                if (size > bytes.size() - pos) { return; }
                if (e && e->type == 'C' && e->from == address && e->to == size)
                {
                    auto& c = p.codes[e->code];
                    c.binaryRecord = records;
                    c.binaryName = name;
                    c.body = pos;
                }
                else { equal = false; }
                pos += size;
            }
            matched = equal && event == p.transcript.size();
            status = matched ? L"matching_event_sequence" : L"event_sequence_mismatch";
        }
    };

    void AppendUtf8(std::string& out, uint32_t c)
    {
        if (c < 0x80) { out += static_cast<char>(c); return; }
        if (c < 0x800) { out += static_cast<char>(0xc0 | (c >> 6)); }
        else
        {
            if (c < 0x10000) { out += static_cast<char>(0xe0 | (c >> 12)); }
            else
            {
                out += static_cast<char>(0xf0 | (c >> 18));
                out += static_cast<char>(0x80 | ((c >> 12) & 63));
            }
            out += static_cast<char>(0x80 | ((c >> 6) & 63));
        }
        out += static_cast<char>(0x80 | (c & 63));
    }

    bool NameEquals(View wire, View binary)
    {
        if (wire.size() > 6 * 4096) { return false; }
        // The text logger writes a function's UTF-8 C string and its UTF-16 script
        // name through different escaping paths. The binary logger writes UTF-8.
        std::string narrow, wide;
        std::vector<std::pair<size_t, size_t>> splits{{0, 0}};
        for (size_t i = 0; i < wire.size();)
        {
            uint32_t cp = static_cast<unsigned char>(wire[i++]);
            bool octet = true;
            if (cp == '\\')
            {
                if (i == wire.size()) { return false; }
                const auto ch = wire[i++];
                if (ch == 'n') { cp = '\n'; }
                else if (ch == '\\') { cp = '\\'; }
                else
                {
                    const size_t n = ch == 'x' ? 2 : ch == 'u' ? 4 : 0;
                    if (!n || wire.size() - i < n || !Number(wire.substr(i, n), cp, 16)) { return false; }
                    i += n;
                    octet = n == 2;
                    if (cp >= 0xd800 && cp <= 0xdbff)
                    {
                        uint32_t low = 0;
                        if (wire.size() - i < 6 || wire.substr(i, 2) != "\\u" || !Number(wire.substr(i + 2, 4), low, 16) ||
                            low < 0xdc00 || low > 0xdfff) { return false; }
                        cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00;
                        i += 6;
                    }
                    else if (cp >= 0xdc00 && cp <= 0xdfff) { return false; }
                }
            }
            if (octet) { narrow += static_cast<char>(cp); } else { AppendUtf8(narrow, cp); }
            AppendUtf8(wide, cp);
            if (cp == ' ') { splits.emplace_back(narrow.size(), wide.size()); }
        }
        splits.emplace_back(narrow.size(), wide.size());
        size_t prefix = 0, suffix = 0;
        while (prefix < narrow.size() && prefix < binary.size() && narrow[prefix] == binary[prefix]) { ++prefix; }
        while (suffix < wide.size() && suffix < binary.size() && wide[wide.size() - 1 - suffix] == binary[binary.size() - 1 - suffix]) { ++suffix; }
        return std::any_of(splits.begin(), splits.end(), [&](const auto& split) {
            const auto tail = wide.size() - split.second;
            return split.first <= prefix && tail <= suffix && split.first + tail == binary.size();
        });
    }

    bool MatchesLabel(const Code& c)
    {
        if (c.binaryName.size() >= 4096) { return false; } // The writer truncates at this limit.
        auto name = c.binaryName;
        if (name.substr(0, c.tag.size()) != c.tag) { return false; }
        name.remove_prefix(c.tag.size());
        if (name.empty() || name.front() != ':') { return false; }
        name.remove_prefix(1);
        if (name.substr(0, c.marker.size()) != c.marker) { return false; }
        name.remove_prefix(c.marker.size());
        // The script-only overload inserts a separator before the script name.
        return NameEquals(c.name, name) || (!name.empty() && name.front() == ' ' && NameEquals(c.name, name.substr(1)));
    }

    struct Options
    {
        std::wstring pin, path, bytesPin, cursor;
        uint32_t limit = 64, offset = 0;
    };

    bool Pin(const std::wstring& value, std::wstring& out)
    {
        if (value.size() != 64 || value.find_first_not_of(L"0123456789abcdefABCDEF") != std::wstring::npos) { return false; }
        out = value;
        for (auto& c : out) { if (c >= L'A' && c <= L'F') { c += L'a' - L'A'; } }
        return true;
    }

    bool ParseArgs(const std::vector<std::wstring>& args, bool inherited, Options& o)
    {
        if (args.size() < 3 || args.size() > 11 || args[0].empty() || (inherited && args[0] != L"-") || !Pin(args[2], o.pin))
        { return false; }
        bool limit = false, json = false;
        for (size_t i = 3; i < args.size(); ++i)
        {
            if (args[i] == L"/code-log" && !inherited && o.path.empty() && args.size() - i >= 3)
            {
                o.path = args[++i];
                if (o.path.empty() || !Pin(args[++i], o.bytesPin)) { return false; }
            }
            else if (args[i] == L"/limit" && !limit && i+1 < args.size())
            {
                uint64_t value = 0;
                if (!trace_json::Decimal(args[++i], &value) || !value || value > 128) { return false; }
                limit = true;
                o.limit = static_cast<uint32_t>(value);
            }
            else if (args[i] == L"/cursor" && o.cursor.empty() && i+1 < args.size())
            {
                o.cursor = args[++i];
                if (o.cursor.empty() || o.cursor.size() > 170) { return false; }
            }
            else if (args[i] == L"/json" && !json) { json = true; }
            else { return false; }
        }
        return true;
    }

    std::wstring Stem(const Options& o)
    {
        return L"kv8:" + o.pin + L":" + (o.path.empty() ? L"-" : o.bytesPin) + L":" + std::to_wstring(o.limit) + L":";
    }

    std::wstring Hex(uint64_t value) { std::wostringstream s; s << L"0x" << std::hex << value; return Quote(s.str()); }
    std::wstring Num(uint64_t value) { return std::to_wstring(value); }
    std::wstring Id(uint64_t value) { return Quote(Num(value)); }
    std::wstring Maybe(uint32_t value) { return value ? Num(value) : L"null"; }
    const wchar_t* Bool(bool value) { return value ? L"true" : L"false"; }
    std::wstring Label(View value)
    {
        if (value.size() > 1024 || std::any_of(value.begin(), value.end(), [](unsigned char c) { return c < 32 || c > 126; }))
        { return L"null"; }
        return Quote(std::wstring(value.begin(), value.end()));
    }

    std::wstring Hash(const uint8_t* bytes, size_t size)
    {
        ContentHash hash;
        Need(hash.Add(bytes, size), L"hash_unavailable");
        auto result = hash.Finish();
        Need(!result.empty(), L"hash_unavailable");
        return Quote(result);
    }

    std::wstring Row(Profile& p, const Tick& t, const ByteLog& side, const std::vector<uint8_t>& bytes)
    {
        const Location* loc = t.location == NoLocation ? nullptr : &p.locations[t.location];
        Code* c = loc ? &p.codes[loc->code] : nullptr;
        const wchar_t* relation = L"no_logged_range";
        bool native = false;
        if (t.external) { relation = L"external_callback"; }
        else if (!p.begin || !p.end || p.shortLine || p.incompleteMap) { relation = L"incomplete_history"; }
        else if (t.record <= p.begin || t.record >= p.end) { relation = L"outside_profiler_markers"; }
        else if (t.overflow) { relation = L"sample_buffer_overflow"; }
        else if (p.reversed || (c && c->time >= t.time)) { relation = L"clock_unqualified"; }
        else if (c)
        {
            if (c->kind == 9) { relation = L"interpreter_bytecode_range"; }
            else if (!c->JsMachine()) { relation = L"other_code_range"; }
            else if (p.Reused(t, *loc)) { relation = L"address_reused"; }
            else if (c->deopt && c->deopt < t.record) { relation = L"deoptimization_reported"; }
            else if (loc->record != c->record) { relation = L"relocated_js_range"; }
            else { relation = L"reported_js_range"; native = true; }
        }
        std::wstring range = L"null", body = L"null";
        const wchar_t* binding = side.status;
        if (c)
        {
            const auto offset = t.pc - loc->base;
            range = L"{\"creation_record\":" + Num(c->record) + L",\"location_record\":" + Num(loc->record) +
                L",\"creation_logger_us\":" + Id(c->time) + L",\"creation_start\":" + Hex(c->start) +
                L",\"mapped_start\":" + Hex(loc->base) + L",\"reported_size\":" + Num(c->size) +
                L",\"pc_offset\":" + Num(offset) + L",\"v8_tag\":" + Label(c->tag) + L",\"v8_kind\":" + std::to_wstring(c->kind) +
                L",\"creation_sfi\":" + (c->JsDeclaration() && c->functionTag ? Hex(*c->functionTag) : L"null") +
                L",\"tier_marker\":" + (c->functionTag ? Label(c->marker) : L"null") +
                L",\"escaped_name\":" + Label(c->name) + L",\"deopt_record\":" + Maybe(c->deopt) + L"}";
            if (native && side.matched)
            {
                if (!MatchesLabel(*c)) { binding = L"label_unconfirmed"; }
                else
                {
                    binding = L"matched_code_record";
                    const auto length = (std::min)(uint64_t{32}, c->size - offset);
                    const auto fileOffset = c->body + static_cast<size_t>(offset);
                    if (c->bodyHash.empty()) { c->bodyHash = Hash(bytes.data() + c->body, c->size); }
                    body = L"{\"binary_record\":" + Num(c->binaryRecord) + L",\"body_file_offset\":" + Num(c->body) +
                        L",\"body_sha256\":" + c->bodyHash + L",\"window_file_offset\":" + Num(fileOffset) +
                        L",\"window_bytes\":" + Num(length) + L",\"window_sha256\":" + Hash(bytes.data() + fileOffset, static_cast<size_t>(length)) + L"}";
                }
            }
        }
        if (!native && side.matched) { binding = L"no_qualified_js_range"; }
        return L"{\"sample_ordinal\":" + Num(t.ordinal) + L",\"record_ordinal\":" + Num(t.record) +
            L",\"logger_time_us\":" + Id(t.time) + L",\"sampled_pc\":" + Hex(t.pc) + L",\"vm_state\":" + Num(t.state) +
            L",\"has_external_callback\":" + Bool(t.external) + L",\"tos_or_external_entry\":" + Hex(t.top) +
            L",\"stack_frames_reported\":" + Num(t.depth) + L",\"sample_buffer_overflow\":" + Bool(t.overflow) +
            L",\"range_relation\":" + Quote(relation) + L",\"log_order_range\":" + range +
            L",\"byte_relation\":" + Quote(binding) + L",\"code_record_bytes\":" + body +
            L",\"code_version\":null,\"verified_level\":\"unqualified\"}";
    }

    bool OpenNamed(const std::wstring& input, ReferenceArtifact& file)
    {
        std::filesystem::path path;
        symbol_artifacts::Directories parents;
        if (!symbol_artifacts::LocalRoot(input, &path) || !parents.Pin(path.parent_path(), false)) { return false; }
        const auto h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        const std::unique_ptr<void, decltype(&CloseHandle)> handle(h == INVALID_HANDLE_VALUE ? nullptr : h, &CloseHandle);
        return handle && file.OpenResidentLocalHandle(handle.get(), nullptr, ReferenceArtifactMaxBytes);
    }

    int Write(const std::wstring& value, int result)
    {
        std::cout << mcpjson::WideToUtf8(value) << '\n';
        std::cout.flush();
        return std::cout ? result : 2;
    }

    int Query(const std::vector<std::wstring>& args, Options& o, const std::atomic<bool>* stop, bool inherited)
    {
        const std::wstring head = L"{\"schema\":\"kn.v8_profile_query.v1\",\"status\":";
        ReferenceArtifact text, bytes;
        try
        {
            Running(stop);
            Need(inherited ? text.OpenResidentLocalHandle(GetStdHandle(STD_INPUT_HANDLE), nullptr, ReferenceArtifactMaxBytes) : OpenNamed(args[0], text), L"profile_unavailable");
            Need(text.Sha256() == o.pin, L"profile_digest_mismatch");
            if (!o.path.empty())
            {
                Need(OpenNamed(o.path, bytes), L"code_log_unavailable");
                Need(bytes.Sha256() == o.bytesPin, L"code_log_digest_mismatch");
                Need(bytes.FileIdentity() != text.FileIdentity(), L"identical_inputs");
            }
            const auto stem = Stem(o);
            if (!o.cursor.empty())
            {
                uint64_t offset = 0;
                Need(o.cursor.rfind(stem, 0) == 0 && trace_json::Decimal(o.cursor.substr(stem.size()), &offset) && offset <= MaxLines, L"invalid_cursor");
                o.offset = static_cast<uint32_t>(offset);
            }
            Profile p;
            p.Read(text.Bytes(), o.offset, o.limit, stop);
            ByteLog side;
            if (!o.path.empty()) { side.Read(bytes.Bytes(), p, stop); }
            const bool partial = !p.begin || !p.end || p.shortLine || p.incompleteMap || (!o.path.empty() && !side.matched);
            const auto next = o.offset + p.page.size();
            auto out = head + Quote(partial ? L"partial" : L"ok") + L",\"profile_sha256\":" + Quote(text.Sha256()) +
                L",\"profile_bytes\":" + Num(text.Bytes().size()) + L",\"code_log_sha256\":" + (o.path.empty() ? L"null" : Quote(bytes.Sha256())) +
                L",\"code_log_bytes\":" + (o.path.empty() ? L"null" : Num(bytes.Bytes().size())) +
                L",\"v8_version\":\"13.6.233.17-node.63\",\"platform\":\"windows\",\"code_log_status\":" + Quote(side.status) +
                L",\"binary_records_examined\":" + Num(side.records) + L",\"binary_gc_markers\":" + Num(side.gcMarkers) +
                L",\"records_seen\":" + Num(p.lines) + L",\"code_creations\":" + Num(p.codes.size()) + L",\"code_moves\":" + Num(p.moves) +
                L",\"code_deletes\":" + Num(p.deletes) + L",\"profiler_begin_record\":" + Maybe(p.begin) + L",\"profiler_end_record\":" + Maybe(p.end) +
                L",\"requested_period_us\":" + Maybe(p.period) + L",\"overflow_ticks\":" + Num(p.overflows) +
                L",\"clock_reversed\":" + Bool(p.reversed) + L",\"incomplete_final_line\":" + Bool(p.shortLine) +
                L",\"unresolved_mapping_change\":" + Bool(p.incompleteMap) + L",\"samples_total\":" + Num(p.ticks) +
                L",\"offset\":" + Num(o.offset) + L",\"next_cursor\":" + Quote(next < p.ticks ? stem + Num(next) : L"") +
                L",\"source_kind\":\"v8_statistical_tick\",\"clock\":\"v8_logger_elapsed_microseconds\",\"sample_time_us\":null,"
                L"\"collector_authenticated\":false,\"execution_independently_verified\":false,\"code_at_sample_time_verified\":false,"
                L"\"live_backend_opened\":false,\"raw_decoder_used\":true,"
                L"\"process_id\":null,\"thread_id\":null,\"cpu\":null,\"vtl\":null,\"lost_samples\":null,\"samples\":[";
            bool first = true;
            for (const auto& t : p.page)
            {
                Running(stop);
                if (!first) { out += L','; }
                first = false;
                out += Row(p, t, side, bytes.Bytes());
            }
            Running(stop);
            return Write(out + L"]}", partial ? 1 : 0);
        }
        catch (const Failure& error)
        {
            return Write(head + L"\"unavailable\",\"error\":" + Quote(error.reason) + L",\"profile_sha256\":" +
                (text.Sha256().empty() ? L"null" : Quote(text.Sha256())) + L",\"code_log_sha256\":" +
                (bytes.Sha256().empty() ? L"null" : Quote(bytes.Sha256())) + L",\"execution_independently_verified\":false}", 1);
        }
    }
}

int RunV8ProfileQuery(const std::vector<std::wstring>& args, const std::atomic<bool>* stop, bool inherited)
{
    try
    {
        Options o;
        const bool valid = ParseArgs(args, inherited, o);
        const auto sink = GetStdHandle(valid ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
        std::vector<DistinctArtifactInput> guards;
        if (GetFileType(sink) == FILE_TYPE_DISK)
        {
            if (inherited)
            {
                // A restricted query cannot open a named sidecar to compare it
                // with a redirected diagnostic stream.
                if (!valid && std::find(args.begin(), args.end(), L"/code-log") != args.end()) { return 2; }
                const auto source = GetStdHandle(STD_INPUT_HANDLE);
                if (GetFileType(source) == FILE_TYPE_DISK && !DistinctLocalFileHandles(source, sink)) { return 2; }
            }
            else
            {
                guards.resize(1 + std::count(args.begin(), args.end(), L"/code-log"));
                if (!guards[0].Hold(sink, args[0])) { return 2; }
                size_t held = 1;
                for (size_t i = 1; i + 1 < args.size(); ++i)
                {
                    if (args[i] == L"/code-log" && !guards[held++].Hold(sink, args[i+1])) { return 2; }
                }
            }
        }
        if (!valid)
        {
            std::wcerr << L"usage: trace " << (inherited ? L"-" : L"<local.log>") << L" /v8 <sha256>"
                << (inherited ? L"" : L" [/code-log <local.log.ll> <sha256>]") << L" [/limit 1..128] [/cursor token] [/json]\n";
            return 2;
        }
        return Query(args, o, stop, inherited);
    }
    catch (const std::exception&) { return 1; }
}
