#include "EtlProfile.h"
#include "ArtifactOutput.h"
#include "BoundedObservationJson.h"
#include "ContentHash.h"
#include "EtlCaptureSettings.h"
#include "ImageLoaderWindow.h"
#include "ImageProcessMappings.h"
#include "ImageVerificationRecipe.h"
#include "RuntimeCapabilities.h"
#include "SavedEtlInput.h"
#include <filesystem>

namespace
{
    using bounded_observation_json::N;
    using mcpjson::Quote;
    constexpr GUID KernelProcess{0x22fb2cd6, 0x0e7b, 0x422b, {0xa0, 0xc7, 0x2f, 0xad, 0x1f, 0xd0, 0xe7, 0x16}};
    constexpr size_t MaxBoundaries = 4096;
    struct Identity { uint32_t Pid = 0; uint64_t Birth = 0; };
    struct Point
    {
        uint32_t Ordinal = 0;
        int64_t Tick = 0;
        uint16_t Logger = 0, Id = 0;
        uint8_t Version = 0;
    };
    struct ProcessPoint { Point Event; Identity Process; };
    struct Image
    {
        Point Event;
        uint64_t Base = 0, Size = 0, Preferred = 0;
        uint32_t Checksum = 0, Stamp = 0;
        uint8_t Width = 0;
        std::wstring Name;
    };
    struct Scan
    {
        const ImageVerificationRecipe& Recipe;
        const std::wstring& Pin;
        Identity Collector, Target;
        image_loader::Window Window;
        Point Marker;
        std::vector<ProcessPoint> Processes;
        std::vector<Image> Images;
        uint32_t Records = 0, Markers = 0, Malformed = 0, Loss = 0;
        uint64_t Buffers = 0, NameUnits = 0;
        bool Limit = false;
    };

    bool Field(const std::wstring& source, size_t& pos, uint64_t& result)
    {
        const auto end = source.find(L':', pos);
        if (end == std::wstring::npos || end == pos || end - pos > 20 || source[pos] == L'0') { return false; }
        result = 0;
        for (; pos < end; ++pos)
        {
            const auto c = source[pos];
            if (c < L'0' || c > L'9' || result > (UINT64_MAX - (c - L'0')) / 10) { return false; }
            result = result * 10 + c - L'0';
        }
        ++pos;
        return true;
    }

    bool Identities(Scan& s)
    {
        const auto& p = s.Recipe;
        constexpr std::wstring_view prefix = L"process_handle:";
        if (p.FormatVersion != 3 || p.SourceId.rfind(prefix, 0) != 0 || p.ReadSet.Reads.empty() ||
            p.SourceConsistency != L"handle_bound_single_read") { return false; }
        size_t pos = prefix.size();
        uint64_t collector = 0, target = 0;
        if (!Field(p.SourceId, pos, collector) || collector > UINT32_MAX || !Field(p.SourceId, pos, s.Collector.Birth) ||
            !Field(p.SourceId, pos, target) || target > UINT32_MAX || !Field(p.SourceId, pos, s.Target.Birth)) { return false; }
        s.Collector.Pid = static_cast<uint32_t>(collector);
        s.Target.Pid = static_cast<uint32_t>(target);
        const auto id = L"process:" + std::to_wstring(target) + L":" + std::to_wstring(s.Target.Birth);
        const auto& space = p.ReadSet.Reads.front().Source.AddressSpace;
        const auto shape = std::to_wstring(space.VirtualAddressBits) + L":" + std::to_wstring(space.UserMaximum) +
            (space.LegacyAssumed ? L":assumed" : L":declared");
        return p.SourceId.substr(pos) == shape && p.ReadSet.TargetId == id && p.ReadSet.AddressSpaceId == id + L":user";
    }

    uint64_t Little(const uint8_t* bytes, size_t width)
    {
        uint64_t value = 0;
        std::memcpy(&value, bytes, width);
        return value;
    }

    void Observe(Scan& s, const EVENT_RECORD& e)
    {
        if (s.Limit) { return; }
        if (s.Records == etl_profile::MaxEventRecords) { s.Limit = true; return; }
        const auto& h = e.EventHeader;
        const auto& d = h.EventDescriptor;
        const Point point{++s.Records, h.TimeStamp.QuadPart, e.BufferContext.LoggerId, d.Id, d.Version};
        if (etl_profile::LossMarker(h)) { ++s.Loss; return; }
        const auto* bytes = static_cast<const uint8_t*>(e.UserData);
        const size_t length = e.UserDataLength;
        if (IsEqualGUID(h.ProviderId, image_loader::Provider) && h.ProcessId == s.Collector.Pid && d.Id == 1)
        {
            if (d.Version != 1 || !bytes || length < 64) { ++s.Malformed; return; }
            if (!std::equal(s.Pin.begin(), s.Pin.end(), bytes)) { return; }
            if (length != offsetof(image_loader::Window, Reads) + s.Recipe.Reads.size() * sizeof(image_loader::Interval) ||
                length > sizeof(s.Window) || d.Channel != image_loader::Completed.Channel || d.Level != image_loader::Completed.Level ||
                d.Opcode != image_loader::Completed.Opcode || d.Task != image_loader::Completed.Task || d.Keyword != image_loader::Completed.Keyword ||
                (h.Flags & (EVENT_HEADER_FLAG_CLASSIC_HEADER | EVENT_HEADER_FLAG_STRING_ONLY | EVENT_HEADER_FLAG_TRACE_MESSAGE)))
                { ++s.Malformed; return; }
            ++s.Markers;
            s.Marker = point;
            std::memcpy(&s.Window, bytes, length);
            return;
        }
        if (!IsEqualGUID(h.ProviderId, KernelProcess) || (d.Id != 1 && d.Id != 2 && d.Id != 5 && d.Id != 6)) { return; }
        if (!bytes || (h.Flags & EVENT_HEADER_FLAG_CLASSIC_HEADER)) { ++s.Malformed; return; }
        if (d.Id <= 2)
        {
            if (length < 4) { ++s.Malformed; return; }
            const auto pid = static_cast<uint32_t>(Little(bytes, 4));
            if (pid != s.Collector.Pid && pid != s.Target.Pid) { return; }
            if ((d.Id == 1 && d.Version > 5) || (d.Id == 2 && d.Version > 2)) { ++s.Malformed; return; }
            const size_t offset = (d.Id == 1 ? d.Version >= 3 : d.Version >= 2) ? 12 : 4;
            if (length < offset + 8) { ++s.Malformed; return; }
            if (s.Processes.size() >= MaxBoundaries) { s.Limit = true; return; }
            s.Processes.push_back({point, {pid, Little(bytes + offset, 8)}});
            return;
        }
        const auto flags = h.Flags & (EVENT_HEADER_FLAG_32_BIT_HEADER | EVENT_HEADER_FLAG_64_BIT_HEADER);
        const size_t width = flags == EVENT_HEADER_FLAG_32_BIT_HEADER ? 4 : flags == EVENT_HEADER_FLAG_64_BIT_HEADER ? 8 : 0;
        const size_t fixed = 3 * width + 12;
        if (d.Version != 0 || !width || length < fixed + 2) { ++s.Malformed; return; }
        if (Little(bytes + 2 * width, 4) != s.Target.Pid) { return; }
        const auto base = Little(bytes, width), size = Little(bytes + width, width);
        if (!size || size > UINT64_MAX - base) { ++s.Malformed; return; }
        // Include other image bases if any byte observed in this recipe overlaps them.
        if (base != s.Recipe.ImageBase && std::none_of(s.Recipe.Reads.begin(), s.Recipe.Reads.end(), [&](const auto& r) {
                return r.Address < base + size && base < r.Address + r.Length;
            })) { return; }
        const size_t textBytes = length - fixed;
        if (textBytes < 4 || textBytes % 2 || Little(bytes + length - 2, 2) != 0) { ++s.Malformed; return; }
        const auto units = (textBytes - 2) / 2;
        if (s.Images.size() >= MaxBoundaries || s.NameUnits + units > 1024 * 1024) { s.Limit = true; return; }
        Image image{point, base, size, Little(bytes + 2 * width + 12, width),
                    static_cast<uint32_t>(Little(bytes + 2 * width + 4, 4)),
                    static_cast<uint32_t>(Little(bytes + 2 * width + 8, 4)), static_cast<uint8_t>(width)};
        image.Name.resize(units);
        std::memcpy(image.Name.data(), bytes + fixed, textBytes - 2);
        if (image.Name.find(L'\0') != std::wstring::npos || mcpjson::SanitizeUtf16(image.Name) != image.Name)
            { ++s.Malformed; return; }
        s.NameUnits += units;
        s.Images.push_back(std::move(image));
    }

    void WINAPI Record(EVENT_RECORD* e)
    {
        auto& s = *static_cast<Scan*>(e->UserContext);
        try { Observe(s, *e); } catch (...) { s.Limit = true; }
    }
    ULONG WINAPI Buffer(EVENT_TRACE_LOGFILEW* log)
    {
        auto& s = *static_cast<Scan*>(log->Context);
        ++s.Buffers;
        return !s.Limit;
    }

    const wchar_t* ReadTrace(etl_profile::SavedEtlInput& source, Scan& scan, TRACE_LOGFILE_HEADER& header)
    {
        EVENT_TRACE_LOGFILEW log{};
        log.LogFileName = const_cast<LPWSTR>(source.PinnedVolumePath().c_str());
        log.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
        log.EventRecordCallback = Record;
        log.BufferCallback = Buffer;
        log.Context = &scan;
        auto handle = OpenTraceW(&log);
        if (handle == INVALID_PROCESSTRACE_HANDLE) { return L"open_trace_failed"; }
        const auto status = ProcessTrace(&handle, 1, nullptr, nullptr);
        header = log.LogfileHeader;
        CloseTrace(handle);
        if (!source.Revalidated()) { return L"trace_identity_changed"; }
        return status == ERROR_SUCCESS || scan.Limit ? nullptr : L"trace_read_failed";
    }

    struct Lifetime { const Point* Start = nullptr; const Point* End = nullptr; };
    // QPC readings from different threads within one tick have ambiguous order.
    bool ClockBefore(int64_t first, int64_t second)
    {
        return first > 0 && first < second && second - first > 1;
    }
    bool ClockAmbiguous(int64_t a, int64_t b) { return !ClockBefore(a, b) && !ClockBefore(b, a); }

    bool EncloseProcess(const Scan& s, const Identity& id, int64_t lo, int64_t hi, Lifetime& life)
    {
        for (const auto& row : s.Processes)
        {
            if (row.Process.Pid != id.Pid || row.Process.Birth != id.Birth) { continue; }
            auto& endpoint = row.Event.Id == 1 ? life.Start : life.End;
            if (endpoint || row.Event.Logger != s.Marker.Logger) { return false; }
            endpoint = &row.Event;
        }
        if (!life.Start || !life.End || life.Start->Ordinal >= life.End->Ordinal ||
            !ClockBefore(life.Start->Tick, lo) || !ClockBefore(hi, life.End->Tick)) { return false; }
        for (const auto& other : s.Processes)
        {
            if (other.Process.Pid == id.Pid && other.Process.Birth != id.Birth &&
                ((other.Event.Ordinal >= life.Start->Ordinal && other.Event.Ordinal <= life.End->Ordinal) ||
                 (!ClockBefore(other.Event.Tick, life.Start->Tick) && !ClockBefore(life.End->Tick, other.Event.Tick)))) { return false; }
        }
        return true;
    }

    std::wstring Q(int64_t tick) { return Quote(std::to_wstring(tick)); }
    std::wstring At(const Point* p)
    {
        return !p ? L"null" : L"{\"record\":" + N(p->Ordinal) + L",\"qpc\":" + Q(p->Tick) +
            L",\"logger\":" + N(p->Logger) + L",\"id\":" + N(p->Id) + L",\"version\":" + N(p->Version) + L"}";
    }
    bool SameImage(const Image& a, const Image& b)
    {
        return a.Base == b.Base && a.Size == b.Size && a.Preferred == b.Preferred && a.Width == b.Width &&
            a.Checksum == b.Checksum && a.Stamp == b.Stamp && a.Name == b.Name;
    }
    uint64_t Milliseconds(int64_t tick, int64_t frequency)
    {
        return static_cast<uint64_t>(tick / frequency) * 1000 +
            static_cast<uint64_t>((tick % frequency) * 1000 / frequency);
    }
    struct Outcome
    {
        Lifetime Collector, Target;
        const Image* Load = nullptr;
        const Image* Unload = nullptr;
        std::vector<const Image*> Changes;
        bool ReadWindowValidated = false;
        bool Qualified = false;
    };

    const wchar_t* Assess(const Scan& s, const TRACE_LOGFILE_HEADER& h, Outcome& out)
    {
        if (s.Limit) { return L"observation_limit"; }
        if (s.Malformed) { return L"unsupported_or_malformed_record"; }
        if (h.EventsLost || h.BuffersLost || s.Loss ||
            etl_profile::AccountBuffers(h.LogFileMode, h.BuffersWritten, s.Buffers) != etl_profile::BufferAccounting::Matched)
            { return L"trace_coverage_gap"; }
        if (s.Markers != 1) { return s.Markers ? L"ambiguous_capture_marker" : L"capture_marker_missing"; }
        if ((h.LogFileMode & (EVENT_TRACE_PRIVATE_LOGGER_MODE | EVENT_TRACE_PRIVATE_IN_PROC)) &&
            (!s.Processes.empty() || !s.Images.empty())) { return L"kernel_events_in_private_session"; }
        const auto& w = s.Window;
        if (h.ReservedFlags != 1 || w.Frequency < 1000 || w.Frequency > INT64_MAX / 1000 || h.PerfFreq.QuadPart != w.Frequency ||
            w.Capture.Start <= 0 || w.Capture.End <= w.Capture.Start || s.Marker.Tick < w.Capture.End ||
            Milliseconds(w.Capture.Start, w.Frequency) < s.Recipe.ReadSet.StartedTick ||
            Milliseconds(w.Capture.Start, w.Frequency) > s.Recipe.Mappings.Reads.front().Before.StartedTick ||
            Milliseconds(w.Capture.End, w.Frequency) < s.Recipe.Mappings.Final.back().EndedTick ||
            Milliseconds(w.Capture.End, w.Frequency) > s.Recipe.ReadSet.SnapshotTick)
            { return L"clock_unqualified"; }
        auto last = w.Capture.Start;
        for (size_t i = 0; i < s.Recipe.Reads.size(); ++i)
        {
            const auto& mapping = s.Recipe.Mappings.Reads[i];
            const auto& read = s.Recipe.Reads[i].Result;
            if (w.Reads[i].Start < last || w.Reads[i].End < w.Reads[i].Start || w.Reads[i].End > w.Capture.End ||
                Milliseconds(w.Reads[i].Start, w.Frequency) < mapping.Before.EndedTick ||
                Milliseconds(w.Reads[i].Start, w.Frequency) > read.StartedTick ||
                Milliseconds(w.Reads[i].End, w.Frequency) < read.EndedTick ||
                Milliseconds(w.Reads[i].End, w.Frequency) > mapping.After.StartedTick)
                { return L"read_clock_conflict"; }
            last = w.Reads[i].End;
        }
        out.ReadWindowValidated = true;
        if (!EncloseProcess(s, s.Collector, w.Capture.Start, s.Marker.Tick, out.Collector) ||
            !EncloseProcess(s, s.Target, w.Capture.Start, w.Capture.End, out.Target) ||
            !(out.Collector.Start->Ordinal < s.Marker.Ordinal && s.Marker.Ordinal < out.Collector.End->Ordinal))
            { return L"process_generation_unavailable"; }
        last = out.Target.Start->Tick;
        const Image* active = nullptr;
        for (const auto& image : s.Images)
        {
            const auto& e = image.Event;
            const bool ordinal = out.Target.Start->Ordinal < e.Ordinal && e.Ordinal < out.Target.End->Ordinal;
            if (ClockAmbiguous(e.Tick, out.Target.Start->Tick) || ClockAmbiguous(e.Tick, out.Target.End->Tick))
                { return L"image_clock_conflict"; }
            const bool clock = ClockBefore(out.Target.Start->Tick, e.Tick) && ClockBefore(e.Tick, out.Target.End->Tick);
            if (ordinal != clock) { return L"image_clock_conflict"; }
            if (!ordinal) { continue; }
            if (e.Logger != s.Marker.Logger || !ClockBefore(last, e.Tick) || ClockAmbiguous(e.Tick, s.Marker.Tick) ||
                (ClockBefore(e.Tick, s.Marker.Tick) != (e.Ordinal < s.Marker.Ordinal))) { return L"image_clock_conflict"; }
            last = e.Tick;
            if (e.Id == 5)
            {
                if (active) { return L"conflicting_loader_transitions"; }
                active = &image;
            }
            else
            {
                if (!active || !SameImage(*active, image)) { return L"conflicting_loader_transitions"; }
                active = nullptr;
            }
            if (ClockAmbiguous(e.Tick, w.Capture.Start) || ClockAmbiguous(e.Tick, w.Capture.End)) { return L"loader_boundary_coincident"; }
            if (e.Tick > w.Capture.Start && e.Tick < w.Capture.End) { out.Changes.push_back(&image); }
            else if (e.Tick < w.Capture.Start) { out.Load = &image; }
            else if (!out.Unload) { out.Unload = &image; }
        }
        if (!out.Changes.empty()) { return L"loader_transition_in_capture"; }
        if (!out.Load || !out.Unload || out.Load->Event.Id != 5 || out.Unload->Event.Id != 6)
            { return L"loader_boundaries_unavailable"; }
        if (!SameImage(*out.Load, *out.Unload) || out.Load->Base != s.Recipe.ImageBase ||
            std::any_of(s.Recipe.Reads.begin(), s.Recipe.Reads.end(), [&](const auto& r) {
                return r.Address < out.Load->Base || r.Address + r.Length > out.Load->Base + out.Load->Size;
            })) { return L"loader_identity_conflict"; }
        if (!AssessImageProcessMappings(s.Recipe).NativeImageMappingObserved) { return L"native_image_mapping_unqualified"; }
        out.Qualified = true;
        return L"recorded_loader_interval";
    }

    std::wstring ImageJson(const Image* image)
    {
        if (!image) { return L"null"; }
        return L"{\"event\":" + At(&image->Event) + L",\"base\":" + N(image->Base) + L",\"size\":" + N(image->Size) +
            L",\"preferred_base\":" + N(image->Preferred) + L",\"checksum\":" + N(image->Checksum) +
            L",\"timestamp\":" + N(image->Stamp) + L",\"pointer_bytes\":" + N(image->Width) + L",\"name\":" + Quote(image->Name) + L"}";
    }
    std::wstring ProcessJson(const Identity& id, const Lifetime& span)
    {
        return L"{\"pid\":" + N(id.Pid) + L",\"creation_filetime\":" + N(id.Birth) + L",\"start\":" + At(span.Start) +
            L",\"end\":" + At(span.End) + L"}";
    }

    struct Inputs
    {
        std::wstring TracePath, CapturePath, TracePin, RecipePin, ExpectedPage, StatementPath;
        etl_profile::StatementAuthority Authority;
    };

    struct WindowReplay
    {
        const Inputs& Expected;
        std::wstring Trace, Recipe, Publication, Claim, Reference, Page;
        const wchar_t* SourceStatus = nullptr;
        std::wstring SourceIssue;
        bool ReadWindowValidated = false;
        etl_profile::CaptureStatement Statement;

        std::wstring Json(const wchar_t* status) const
        {
            const auto nullable = [](const std::wstring& value) { return value.empty() ? std::wstring(L"null") : Quote(value); };
            const bool match = !Page.empty() && Page == Expected.ExpectedPage;
            return L"{\"schema\":\"kn.image_loader_window_replay.v1\",\"status\":" + Quote(status) +
                L",\"expected_etl_sha256\":" + Quote(Expected.TracePin) + L",\"etl_sha256\":" + nullable(Trace) +
                L",\"expected_recipe_sha256\":" + Quote(Expected.RecipePin) + L",\"recipe_sha256\":" + nullable(Recipe) +
                L",\"claim_publication_sha256\":" + nullable(Publication) + L",\"original_claim_sha256\":" + nullable(Claim) +
                L",\"reference_sha256\":" + nullable(Reference) + L",\"original_claim_reproduced\":" + (Claim.empty() ? L"false" : L"true") +
                L",\"expected_page_sha256\":" + Quote(Expected.ExpectedPage) + L",\"replayed_page_sha256\":" + nullable(Page) +
                L",\"page_bytes_match\":" + (Page.empty() ? L"null" : match ? L"true" : L"false") +
                L",\"source_status\":" + (SourceStatus ? Quote(SourceStatus) : L"null") + L",\"source_issue\":" + nullable(SourceIssue) +
                L",\"capture_statement\":" + (Expected.StatementPath.empty() ? std::wstring(L"null") : Statement.Json(Expected.Authority, match)) +
                L",\"read_window_in_attested_etl\":" + (match && Statement.Bound() && ReadWindowValidated ? L"true" : L"false") +
                L",\"collector_authenticated\":false,\"execution_observed\":false,\"continuous_mapping_proven\":false}";
        }
    };

    struct RangeObservation
    {
        Identity Collector, Target;
        AddressSpaceDescriptor Space;
        uint64_t Base = 0, Address = 0;
        uint32_t Rva = 0;
        int64_t Frequency = 0;
        image_loader::Interval Support;
        std::vector<size_t> Reads;
        std::vector<uint8_t> Bytes;
        std::wstring Digest;
        const wchar_t* Issue = L"verified_read_window_required";

        std::wstring Json() const
        {
            if (Issue) { return L"{\"issue\":" + Quote(Issue) + L"}"; }
            std::wstring ordinals = L"[";
            for (const auto ordinal : Reads)
            {
                if (ordinals.size() > 1) { ordinals += L","; }
                ordinals += N(ordinal);
            }
            return L"{\"issue\":null,\"collector_pid\":" + N(Collector.Pid) + L",\"collector_creation_filetime\":" + N(Collector.Birth) +
                L",\"target_pid\":" + N(Target.Pid) + L",\"target_creation_filetime\":" + N(Target.Birth) + L",\"image_base\":" + N(Base) +
                L",\"rva\":" + N(Rva) + L",\"address\":" + N(Address) + L",\"length\":" + N(Bytes.size()) +
                L",\"observed_bytes_sha256\":" + Quote(Digest) + L",\"supporting_reads\":" + ordinals +
                L"],\"read_start_qpc\":" + Q(Support.Start) + L",\"read_end_qpc\":" + Q(Support.End) +
                L",\"qpc_frequency\":" + Q(Frequency) + L"}";
        }
    };

    void ObserveRange(const DirectImageReplayEvidence& original, const Scan& scan, const Outcome& out,
        const std::wstring& issue, RangeObservation& range)
    {
        const auto& p = original.Recipe;
        // Incomplete process/image sequences may contain a reuse or clock conflict.
        const bool markerOnly = scan.Images.empty() && (issue == L"loader_boundaries_unavailable" ||
            (issue == L"process_generation_unavailable" && scan.Processes.empty()));
        if (!out.Qualified && !markerOnly) { range.Issue = L"loader_evidence_unqualified"; return; }
        if (!original.ReferenceQualified || !AssessImageProcessMappings(p).NativeImageMappingObserved)
            { range.Issue = L"native_image_mapping_unqualified"; return; }
        if (!p.Length || p.ImageBase > UINT64_MAX - p.Rva || p.ImageBase + p.Rva > UINT64_MAX - p.Length)
            { range.Issue = L"image_range_unavailable"; return; }
        const auto address = p.ImageBase + p.Rva;
        if (original.Comparison.Observed.size() != p.Length ||
            !ConsistentImageRecipeBytes(p, address, p.Length, &range.Bytes) || range.Bytes != original.Comparison.Observed)
            { range.Issue = L"original_range_bytes_unavailable_or_conflicting"; return; }
        bool fullRead = false;
        for (size_t i = 0; i < p.Reads.size(); ++i)
        {
            const auto& read = p.Reads[i];
            if (read.Address >= address + p.Length || read.Address + read.Length <= address) { continue; }
            if (!read.Result.IdentityRevalidated || read.Result.OperationDeadlineExceeded ||
                read.Result.State != ObservationReadState::Complete)
                { range.Issue = L"original_range_read_unqualified"; return; }
            fullRead = fullRead || (read.Address <= address && read.Address + read.Length >= address + p.Length);
            if (range.Reads.empty()) { range.Support.Start = scan.Window.Reads[i].Start; }
            range.Reads.push_back(i + 1);
            range.Support.End = scan.Window.Reads[i].End;
        }
        if (!fullRead) { range.Issue = L"original_full_range_read_missing"; return; }
        range.Digest = ContentHash::Bytes(range.Bytes);
        if (range.Digest.empty()) { range.Issue = L"observed_bytes_hash_unavailable"; return; }
        range.Base = p.ImageBase;
        range.Rva = p.Rva;
        range.Address = address;
        range.Target = scan.Target;
        range.Collector = scan.Collector;
        range.Frequency = scan.Window.Frequency;
        range.Space = p.ReadSet.Reads.front().Source.AddressSpace;
        range.Issue = nullptr;
    }

    struct Evaluation
    {
        WindowReplay Replay;
        std::wstring Json;
        DistinctArtifactInput TraceGuard, ClaimGuard, ReferenceGuard, StatementGuard;
        RangeObservation Range;
    };

    int Read(const Inputs& inputs, Evaluation& result, bool compare = false)
    {
        const auto sink = GetStdHandle(STD_OUTPUT_HANDLE);
        const bool disk = GetFileType(sink) == FILE_TYPE_DISK;
        const std::filesystem::path capture(inputs.CapturePath);
        std::error_code ec;
        const bool directory = std::filesystem::is_directory(capture, ec);
        const bool managed = _wcsicmp(capture.extension().c_str(), L".kncapture") == 0;
        if (!directory && !managed) { return 2; }
        if (disk && (!result.TraceGuard.Hold(sink, inputs.TracePath) ||
            !result.StatementGuard.Hold(sink, inputs.StatementPath) ||
            !result.ClaimGuard.Hold(sink, (directory ? capture / L"recipe.knverify" : capture).wstring()))) { return 2; }
        auto& receipt = result.Replay;
        const auto fail = [&](const wchar_t* reason) {
            result.Json = !inputs.ExpectedPage.empty() ? receipt.Json(reason) :
                L"{\"schema\":\"kn.image_loader_window.v1\",\"status\":\"unavailable\",\"issue\":" +
                Quote(reason) + L",\"recorded_loader_interval\":false}";
            return 1;
        };
        DirectImageReplayEvidence original;
        std::wstring error;
        const auto replay = ReplayImageRecipe(capture.wstring(), false, &error, &original);
        if (replay.Status != L"replayed" || replay.OriginalClaimStatus != L"reproduced")
            { return disk ? 2 : fail(L"original_claim_unavailable"); }
        const auto references = directory ? capture : capture.parent_path().parent_path() / L"image-references";
        if (disk && !result.ReferenceGuard.Hold(sink, (references / (original.Recipe.ReferenceSha256 + L".knblob")).wstring())) { return 2; }
        receipt.Recipe = replay.RecipeSha256;
        receipt.Publication = replay.ClaimPublicationSha256;
        receipt.Claim = replay.RecordedClaimSha256;
        receipt.Reference = original.Recipe.ReferenceSha256;
        if (replay.RecipeSha256 != inputs.RecipePin) { return fail(L"recipe_pin_mismatch"); }
        Scan scan{original.Recipe, inputs.RecipePin};
        if (!Identities(scan)) { return fail(L"native_process_recipe_required"); }
        etl_profile::SavedEtlInput source;
        if (!source.Open(inputs.TracePath)) { return fail(L"trace_unavailable_or_pin_mismatch"); }
        receipt.Trace = source.File.Sha256;
        if (receipt.Trace != inputs.TracePin) { return fail(L"trace_unavailable_or_pin_mismatch"); }
        TRACE_LOGFILE_HEADER h{};
        if (const auto failure = ReadTrace(source, scan, h)) { return fail(failure); }
        Outcome out;
        const std::wstring issue = Assess(scan, h, out);
        const bool changed = issue == L"loader_transition_in_capture";
        const auto status = out.Qualified ? L"bracketed" : changed ? L"transition_observed" : L"unavailable";
        const auto& w = scan.Window;
        std::wstring rows = L"[";
        if (scan.Markers == 1)
        {
            for (size_t i = 0; i < scan.Recipe.Reads.size(); ++i)
            {
                const auto& read = scan.Recipe.Reads[i];
                if (i) { rows += L","; }
                rows += L"{\"read\":" + N(i + 1) + L",\"address\":" + N(read.Address) + L",\"length\":" + N(read.Length) +
                    L",\"start_qpc\":" + Q(w.Reads[i].Start) + L",\"end_qpc\":" + Q(w.Reads[i].End) + L"}";
            }
        }
        std::wstring changes = L"[";
        for (const auto* image : out.Changes)
        {
            if (changes.size() > 1) { changes += L","; }
            std::wstring reads = L"[";
            for (size_t i = 0; i < scan.Recipe.Reads.size(); ++i)
            {
                if (ClockBefore(w.Reads[i].Start, image->Event.Tick) && ClockBefore(image->Event.Tick, w.Reads[i].End))
                    { if (reads.size() > 1) { reads += L","; } reads += N(i + 1); }
            }
            changes += L"{\"image\":" + ImageJson(image) + L",\"strictly_inside_reads\":" + reads + L"]}";
        }
        const auto json = L"{\"schema\":\"kn.image_loader_window.v1\",\"status\":" +
            Quote(status) + L",\"issue\":" + Quote(issue) +
            L",\"etl_sha256\":" + Quote(inputs.TracePin) + L",\"recipe_sha256\":" + Quote(inputs.RecipePin) +
            L",\"original_claim_sha256\":" + Quote(replay.RecordedClaimSha256) + L",\"reference_sha256\":" + Quote(scan.Recipe.ReferenceSha256) +
            L",\"original_claim_reproduced\":true,\"collector_generation\":" + ProcessJson(scan.Collector, out.Collector) +
            L",\"target_generation\":" + ProcessJson(scan.Target, out.Target) + L",\"marker\":" + At(scan.Markers ? &scan.Marker : nullptr) +
            L",\"matching_markers\":" + N(scan.Markers) + L",\"trace_clock_type\":" + N(h.ReservedFlags) +
            L",\"qpc_frequency\":" + Q(h.PerfFreq.QuadPart) + L",\"capture_start_qpc\":" + Q(w.Capture.Start) +
            L",\"capture_end_qpc\":" + Q(w.Capture.End) + L",\"read_windows\":" + rows + L"],\"records_seen\":" + N(scan.Records) +
            L",\"malformed_records\":" + N(scan.Malformed) + L",\"events_lost\":" + N(h.EventsLost) +
            L",\"buffers_lost\":" + N(h.BuffersLost) + L",\"loss_markers\":" + N(scan.Loss) +
            L",\"buffers_processed\":" + N(scan.Buffers) + L",\"buffers_written\":" + N(h.BuffersWritten) +
            L",\"previous_image\":" + ImageJson(out.Load) + L",\"next_image\":" + ImageJson(out.Unload) +
            L",\"loader_transitions\":" + changes + L"],\"recorded_loader_interval\":" + (out.Qualified ? L"true" : L"false") +
            L",\"continuous_mapping_proven\":false,\"collector_authenticated\":false,\"execution_observed\":false,\"current_state_known\":false}";
        const bool measured = out.Qualified || changed;
        if (inputs.ExpectedPage.empty()) { result.Json = json; return measured ? 0 : 1; }
        const auto digest = etl_profile::ReportFileSha256(json);
        if (digest.empty()) { return fail(L"page_hash_unavailable"); }
        if (!inputs.StatementPath.empty())
        {
            const auto verified = etl_profile::ReadCaptureStatement(inputs.StatementPath, inputs.Authority, source.File);
            if (!source.Revalidated()) { return fail(L"trace_identity_changed"); }
            receipt.Statement = verified;
        }
        receipt.Page = digest;
        receipt.SourceStatus = status;
        receipt.SourceIssue = issue;
        receipt.ReadWindowValidated = out.ReadWindowValidated;
        const bool match = digest == inputs.ExpectedPage;
        const bool accepted = inputs.StatementPath.empty() || receipt.Statement.Bound();
        const auto disposition = !match ? L"page_mismatch" : accepted ? L"matched" : L"capture_statement_rejected";
        if (compare && match && receipt.Statement.Bound() && receipt.Statement.CaptureController && out.ReadWindowValidated)
            { ObserveRange(original, scan, out, issue, result.Range); }
        result.Json = receipt.Json(disposition);
        return match && accepted && measured ? 0 : 1;
    }

    struct PairDecision
    {
        const wchar_t* Status;
        const wchar_t* Issue;
        bool LeftFirst = false;
    };

    PairDecision Relate(const Evaluation& left, const Evaluation& right)
    {
        const auto& a = left.Range;
        const auto& b = right.Range;
        if (a.Issue || b.Issue) { return {L"unfulfilled", L"endpoint_unqualified"}; }
        const auto& x = left.Replay.Statement;
        const auto& y = right.Replay.Statement;
        if (x.TargetJson == L"null" || y.TargetJson == L"null" || x.BootJson == L"null" || y.BootJson == L"null")
            { return {L"unfulfilled", L"controller_target_or_boot_missing"}; }
        if (x.TargetJson != y.TargetJson || x.BootJson != y.BootJson)
            { return {L"contradicted", L"controller_targets_or_boots_differ"}; }
        if (left.Replay.Trace == right.Replay.Trace && x.SessionJson != y.SessionJson)
            { return {L"contradicted", L"recording_session_conflict"}; }
        if (left.Replay.Recipe == right.Replay.Recipe) { return {L"unfulfilled", L"same_original_observation"}; }
        if (a.Target.Pid != b.Target.Pid || a.Target.Birth != b.Target.Birth)
            { return {L"contradicted", L"process_generations_differ"}; }
        if (!SameAddressContract(a.Space, b.Space))
            { return {L"contradicted", L"address_space_shapes_differ"}; }
        if (a.Base != b.Base || a.Rva != b.Rva || a.Bytes.size() != b.Bytes.size())
            { return {L"contradicted", L"image_ranges_differ"}; }
        if (a.Frequency != b.Frequency) { return {L"contradicted", L"qpc_frequencies_differ"}; }
        if (ClockBefore(a.Support.End, b.Support.Start)) { return {L"supported", nullptr, true}; }
        if (ClockBefore(b.Support.End, a.Support.Start)) { return {L"supported", nullptr, false}; }
        return {L"unfulfilled", L"read_order_unresolved"};
    }

    int Compare(const std::vector<std::wstring>& args)
    {
        // Each observation supplies an ETL, ETL pin, capture, recipe pin, report pin and statement.
        etl_profile::StatementAuthority key;
        if (args.size() != 16 || !etl_profile::ParseStatementAuthority(L"capture_controller", args[1], key)) { return 2; }
        const auto parse = [&](size_t i, Inputs& in) {
            if (args[i] != L"--observation" || args[i + 1].empty() || args[i + 3].empty() || args[i + 6].empty() ||
                !etl_profile::NormalizeDigest(args[i + 2], in.TracePin) || !etl_profile::NormalizeDigest(args[i + 4], in.RecipePin) ||
                !etl_profile::NormalizeDigest(args[i + 5], in.ExpectedPage)) { return false; }
            in.TracePath = args[i + 1];
            in.CapturePath = args[i + 3];
            in.StatementPath = args[i + 6];
            in.Authority = key;
            return true;
        };
        Inputs first, second;
        if (!parse(2, first) || !parse(9, second)) { return 2; }
        Evaluation left{{first}}, right{{second}};
        if (Read(first, left, true) == 2 || Read(second, right, true) == 2) { return 2; }
        const auto decision = Relate(left, right);
        std::wstring edge = L"null";
        if (!decision.Issue)
        {
            const auto& a = left.Range;
            const auto& b = right.Range;
            size_t differences = 0;
            std::wstring ranges = L"[";
            for (size_t i = 0; i < a.Bytes.size();)
            {
                if (a.Bytes[i] == b.Bytes[i]) { ++i; continue; }
                const auto start = i++;
                while (i < a.Bytes.size() && a.Bytes[i] != b.Bytes[i]) { ++i; }
                if (differences) { ranges += L","; }
                differences += i - start;
                ranges += L"{\"offset\":" + N(start) + L",\"length\":" + N(i - start) + L"}";
            }
            const auto end = decision.LeftFirst ? a.Support.End : b.Support.End;
            const auto begin = decision.LeftFirst ? b.Support.Start : a.Support.Start;
            edge = L"{\"kind\":\"temporal_candidate\",\"order\":" + Quote(decision.LeftFirst ? L"left_before_right" : L"right_before_left") +
                L",\"earlier_read_end_qpc\":" + Q(end) + L",\"later_read_start_qpc\":" + Q(begin) + L",\"between_read_ticks\":" + Q(begin - end) +
                L",\"observed_bytes_equal\":" + (differences ? L"false" : L"true") + L",\"differing_byte_count\":" + N(differences) +
                L",\"differing_ranges\":" + ranges + L"],\"same_retained_reference\":" + (left.Replay.Reference == right.Replay.Reference ? L"true" : L"false") +
                L",\"collector_generations_differ\":" + (a.Collector.Pid != b.Collector.Pid || a.Collector.Birth != b.Collector.Birth ? L"true" : L"false") + L"}";
        }
        const auto render = [](const Evaluation& e) { return L"{\"replay\":" + e.Json + L",\"range\":" + e.Range.Json() + L"}"; };
        const auto json = L"{\"schema\":\"kn.image_observation_pair.v1\",\"status\":" + Quote(decision.Status) +
            L",\"issue\":" + (decision.Issue ? Quote(decision.Issue) : std::wstring(L"null")) +
            L",\"left\":" + render(left) + L",\"right\":" + render(right) + L",\"edge\":" + edge +
            L",\"continuous_mapping_proven\":false,\"execution_observed\":false,\"writer_observed\":false}";
        return WriteCapabilityJson(json) ? (decision.Issue ? 1 : 0) : 2;
    }
}

int RunEtlImageLifetime(const std::vector<std::wstring>& args)
{
    if (!args.empty() && args.front() == L"--compare") { return Compare(args); }
    Inputs inputs;
    if (args.size() < 7 || args.size() > 13 || args[1] != L"--sha256" || args[3] != L"--capture" || args[5] != L"--recipe-sha256" ||
        !etl_profile::NormalizeDigest(args[2], inputs.TracePin) || !etl_profile::NormalizeDigest(args[6], inputs.RecipePin)) { return 2; }
    for (size_t i = 7; i < args.size();)
    {
        if (args[i] == L"--check-page" && inputs.ExpectedPage.empty() && i + 1 < args.size() &&
            etl_profile::NormalizeDigest(args[i + 1], inputs.ExpectedPage)) { i += 2; }
        else if (args[i] == L"--capture-statement" && inputs.StatementPath.empty() && i + 3 < args.size() && !args[i + 1].empty() &&
            etl_profile::ParseStatementAuthority(args[i + 2], args[i + 3], inputs.Authority))
        {
            inputs.StatementPath = args[i + 1];
            i += 4;
        }
        else { return 2; }
    }
    if (!inputs.StatementPath.empty() && inputs.ExpectedPage.empty()) { return 2; }
    inputs.TracePath = args[0];
    inputs.CapturePath = args[4];
    Evaluation result{{inputs}};
    const int code = Read(inputs, result);
    return code == 2 || !WriteCapabilityJson(result.Json) ? 2 : code;
}
