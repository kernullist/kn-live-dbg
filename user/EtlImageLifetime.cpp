#include "EtlProfile.h"
#include "ArtifactOutput.h"
#include "BoundedObservationJson.h"
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
                length > sizeof(s.Window) || d.Opcode || d.Keyword != 1 || (h.Flags & EVENT_HEADER_FLAG_CLASSIC_HEADER))
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

    int Read(const std::vector<std::wstring>& args, const std::wstring& tracePin, const std::wstring& recipePin)
    {
        const auto sink = GetStdHandle(STD_OUTPUT_HANDLE);
        const bool disk = GetFileType(sink) == FILE_TYPE_DISK;
        const std::filesystem::path capture(args[4]);
        std::error_code ec;
        const bool directory = std::filesystem::is_directory(capture, ec);
        const bool managed = _wcsicmp(capture.extension().c_str(), L".kncapture") == 0;
        if (!directory && !managed) { return 2; }
        DistinctArtifactInput traceGuard, rootGuard, referenceGuard;
        if (disk && (!traceGuard.Hold(sink, args[0]) ||
            !rootGuard.Hold(sink, (directory ? capture / L"recipe.knverify" : capture).wstring()))) { return 2; }
        const auto fail = [&](const wchar_t* reason) {
            const auto json = L"{\"schema\":\"kn.image_loader_window.v1\",\"status\":\"unavailable\",\"issue\":" +
                Quote(reason) + L",\"recorded_loader_interval\":false}";
            return WriteCapabilityJson(json) ? 1 : 2;
        };
        DirectImageReplayEvidence original;
        std::wstring error;
        const auto replay = ReplayImageRecipe(capture.wstring(), false, &error, &original);
        if (replay.Status != L"replayed" || replay.OriginalClaimStatus != L"reproduced")
            { return disk ? 2 : fail(L"original_claim_unavailable"); }
        const auto references = directory ? capture : capture.parent_path().parent_path() / L"image-references";
        if (disk && !referenceGuard.Hold(sink, (references / (original.Recipe.ReferenceSha256 + L".knblob")).wstring())) { return 2; }
        if (replay.RecipeSha256 != recipePin) { return fail(L"recipe_pin_mismatch"); }
        Scan scan{original.Recipe, recipePin};
        if (!Identities(scan)) { return fail(L"native_process_recipe_required"); }
        etl_profile::SavedEtlInput source;
        if (!source.Open(args[0]) || source.File.Sha256 != tracePin) { return fail(L"trace_unavailable_or_pin_mismatch"); }
        TRACE_LOGFILE_HEADER h{};
        if (const auto failure = ReadTrace(source, scan, h)) { return fail(failure); }
        Outcome out;
        const std::wstring issue = Assess(scan, h, out);
        const bool changed = issue == L"loader_transition_in_capture";
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
            Quote(out.Qualified ? L"bracketed" : changed ? L"transition_observed" : L"unavailable") + L",\"issue\":" + Quote(issue) +
            L",\"etl_sha256\":" + Quote(tracePin) + L",\"recipe_sha256\":" + Quote(recipePin) +
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
        return WriteCapabilityJson(json) ? (out.Qualified || changed ? 0 : 1) : 2;
    }
}

int RunEtlImageLifetime(const std::vector<std::wstring>& args)
{
    std::wstring trace, recipe;
    if (args.size() != 7 || args[1] != L"--sha256" || args[3] != L"--capture" || args[5] != L"--recipe-sha256" ||
        !etl_profile::NormalizeDigest(args[2], trace) || !etl_profile::NormalizeDigest(args[6], recipe)) { return 2; }
    return Read(args, trace, recipe);
}
