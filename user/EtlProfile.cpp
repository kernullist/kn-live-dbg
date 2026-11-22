#include "EtlProfile.h"
#include "SavedEtlInput.h"
#include "ContentHash.h"
#include "EtlCaptureSettings.h"
#include "EtlDiskIo.h"
#include "EtlFaultSchedule.h"
#include "EtlActivitySchedule.h"
#include "EtlReadyBatch.h"
#include "EtlCaptureStatement.h"
#include "EtlClrEvidence.h"
#include "EtlReferenceImage.h"
#include "ReferenceArtifact.h"
#include "ArtifactOutput.h"
#include "SourceCapabilities.h"

#include <evntrace.h>
#include <array>
#include <iostream>

namespace
{
    using etl_profile::Sample;
    using etl_profile::BufferAccounting;
    constexpr auto MaxBytes = etl_profile::MaxFileBytes;
    constexpr auto MaxRecords = etl_profile::MaxEventRecords;
    constexpr auto MaxPage = etl_profile::MaxPageRows;
    using mcpjson::Quote;

    enum class Family { Profile, Switches, DiskIo, HardFaults };
    struct FamilyFields
    {
        const wchar_t* kind;
        const wchar_t* descriptor;
        const wchar_t* decoded;
        const wchar_t* unsupported;
    };
    constexpr FamilyFields EventFamilies[] = {
        {L"cpu_sample", L",\"provider_guid\":\"ce1dbfb4-137e-4da6-87b0-3f59aa102cbc\",\"event_id\":0,\"opcode\":46,\"version\":2",
            L",\"decoded_samples\":", L",\"unsupported_profile_records\":"},
        {L"context_switch", L",\"provider_guid\":\"3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c\",\"event_id\":0,\"opcode\":36,\"versions\":[2,3,4]",
            L",\"decoded_switches\":", L",\"unsupported_switch_records\":"},
        {L"disk_io", L",\"provider_guid\":\"3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c\",\"event_id\":0,\"opcodes\":[10,11,12,13,14,15],\"versions\":[2,3]",
            L",\"decoded_disk_records\":", L",\"unsupported_disk_records\":"},
        {L"hard_fault", L",\"provider_guid\":\"3d6fa8d3-fe05-11d0-9dda-00c04fd7ba7c\",\"event_id\":0,\"opcode\":32,\"version\":2",
            L",\"decoded_hard_faults\":", L",\"unsupported_hard_fault_records\":"}
    };
    constexpr size_t MaxArguments = 22;
    constexpr FamilyFields MarkerFields{L"activity_marker", L",\"opcodes\":[1,2],\"header_scope\":\"keyed_nonclassic_start_stop\"",
        L",\"decoded_activity_markers\":", L",\"excluded_start_stop_records\":"};

    struct Options
    {
        uint32_t after = 0;
        uint32_t limit = 64;
        std::wstring digest, referencePath, referenceDigest, expectedPage, statementPath;
        etl_profile::StatementAuthority statementAuthority;
        Family family = Family::Profile;
        bool threads = false, images = false, processes = false;
        bool intervals = false, haveTid = false, builds = false, settings = false, clr = false;
        uint32_t tid = 0;
        uint32_t scheduleOf = 0;
        std::vector<uint32_t> readyRecords;
        bool multipleReady = false;
        bool ReadyQuery() const { return !readyRecords.empty(); }
        uint32_t activityStart = 0, activityStop = 0;
        bool activityMarkers = false;
        bool Switches() const { return family == Family::Switches; }
        bool SchedulingActivity() const { return Switches() && activityStart; }
        bool DiskIo() const { return family == Family::DiskIo; }
        bool HardFaults() const { return family == Family::HardFaults; }
        const FamilyFields& Fields() const { return activityMarkers ? MarkerFields : EventFamilies[static_cast<size_t>(family)]; }
        bool WithIntervals() const { return Switches() && (intervals || haveTid); }
        bool WithThreads() const { return threads || images || processes; }
        bool NeedsThreadIndex() const { return WithThreads() || scheduleOf || activityStart || ReadyQuery(); }
        std::wstring ActivitySelectorJson() const
        {
            return activityStart ? L",\"requested_start_record\":" + std::to_wstring(activityStart) +
                L",\"requested_stop_record\":" + std::to_wstring(activityStop) : L"";
        }
        std::wstring ReadySelectorJson() const
        {
            if (!ReadyQuery()) { return {}; }
            if (!multipleReady) { return L",\"requested_ready_record\":" + std::to_wstring(readyRecords.front()); }
            std::wstring result = L",\"requested_ready_records\":[";
            for (const auto record : readyRecords)
            {
                if (record != readyRecords.front()) { result += L','; }
                result += std::to_wstring(record);
            }
            return result + L"]";
        }
        std::wstring ActivityPagingJson() const
        {
            return SchedulingActivity() ? L",\"after\":" + std::to_wstring(after) + L",\"interval_page_limit\":" + std::to_wstring(limit) : L"";
        }
        const wchar_t* Prefix() const
        {
            if (activityMarkers) { return L"{\"schema\":\"kn.etl_activity_markers.v1\",\"status\":"; }
            if (DiskIo()) { return L"{\"schema\":\"kn.etl_disk_io.v1\",\"status\":"; }
            if (multipleReady) { return L"{\"schema\":\"kn.etl_switches.v6\",\"status\":"; }
            if (ReadyQuery()) { return L"{\"schema\":\"kn.etl_switches.v5\",\"status\":"; }
            if (SchedulingActivity()) { return L"{\"schema\":\"kn.etl_switches.v4\",\"status\":"; }
            if (activityStart) { return L"{\"schema\":\"kn.etl_hard_faults.v3\",\"status\":"; }
            if (HardFaults()) { return scheduleOf ? L"{\"schema\":\"kn.etl_hard_faults.v2\",\"status\":" : L"{\"schema\":\"kn.etl_hard_faults.v1\",\"status\":"; }
            if (clr) { return L"{\"schema\":\"kn.etl_profile.v8\",\"status\":"; }
            if (settings) { return Switches() ? L"{\"schema\":\"kn.etl_switches.v3\",\"status\":" : L"{\"schema\":\"kn.etl_profile.v7\",\"status\":"; }
            if (WithIntervals()) { return L"{\"schema\":\"kn.etl_switches.v2\",\"status\":"; }
            if (Switches()) { return L"{\"schema\":\"kn.etl_switches.v1\",\"status\":"; }
            if (builds) { return L"{\"schema\":\"kn.etl_profile.v6\",\"status\":"; }
            if (!referencePath.empty()) { return L"{\"schema\":\"kn.etl_profile.v5\",\"status\":"; }
            if (processes) { return L"{\"schema\":\"kn.etl_profile.v4\",\"status\":"; }
            if (images) { return L"{\"schema\":\"kn.etl_profile.v3\",\"status\":"; }
            return threads ? L"{\"schema\":\"kn.etl_profile.v2\",\"status\":" : L"{\"schema\":\"kn.etl_profile.v1\",\"status\":";
        }
    };

    bool Decimal(const std::wstring& text, uint32_t maximum, uint32_t& value)
    {
        if (text.empty() || text.size() > 10 || (text.size() > 1 && text.front() == L'0')) { return false; }
        uint64_t number = 0;
        for (const auto c : text)
        {
            if (c < L'0' || c > L'9') { return false; }
            number = number * 10 + (c - L'0');
        }
        if (number > maximum) { return false; }
        value = static_cast<uint32_t>(number);
        return true;
    }

    bool ParseReadyRecords(const std::wstring& text, bool multiple, std::vector<uint32_t>& records)
    {
        if (text.size() > MaxPage * 8) { return false; }
        size_t pos = 0;
        do
        {
            const auto comma = text.find(L',', pos);
            uint32_t record = 0;
            if ((!multiple && comma != std::wstring::npos) || records.size() == MaxPage ||
                !Decimal(text.substr(pos, comma - pos), MaxRecords, record) || !record ||
                (!records.empty() && record <= records.back())) { return false; }
            records.push_back(record);
            if (comma == std::wstring::npos) { return true; }
            pos = comma + 1;
        } while (pos < text.size());
        return false;
    }

    bool Parse(const std::vector<std::wstring>& args, Options& options)
    {
        if (args.size() < 3 || args.size() > MaxArguments || args[0].empty() ||
            args[1] != L"--sha256" || !etl_profile::NormalizeDigest(args[2], options.digest)) { return false; }
        bool haveAfter = false, haveLimit = false;
        for (size_t i = 3; i < args.size(); ++i)
        {
            if (args[i] == L"--clr-evidence" && options.family == Family::Profile && !options.clr) { options.clr = true; continue; }
            if (args[i] == L"--capture-settings" && (options.family == Family::Profile || options.Switches()) && !options.settings)
            { options.settings = true; continue; }
            if (args[i] == L"--thread-evidence" && options.family == Family::Profile && !options.threads) { options.threads = true; continue; }
            if (args[i] == L"--image-evidence" && options.family == Family::Profile && !options.images) { options.images = true; continue; }
            if (args[i] == L"--process-evidence" && options.family == Family::Profile && !options.processes) { options.processes = true; continue; }
            if (args[i] == L"--build-evidence" && options.family == Family::Profile && !options.builds) { options.builds = true; continue; }
            if (args[i] == L"--reference-image" && options.family == Family::Profile && options.referencePath.empty())
            {
                if (args.size() - i < 3 || args[i + 1].empty() || !etl_profile::NormalizeDigest(args[i + 2], options.referenceDigest)) { return false; }
                options.referencePath = args[i + 1];
                i += 2;
                continue;
            }
            if (args[i] == L"--capture-statement" && options.statementPath.empty())
            {
                if (i + 3 >= args.size() || args[i + 1].empty() ||
                    !etl_profile::ParseStatementAuthority(args[i + 2], args[i + 3], options.statementAuthority)) { return false; }
                options.statementPath = args[i + 1];
                i += 3;
                continue;
            }
            if (args[i] == L"--intervals" && options.Switches() && !options.intervals) { options.intervals = true; continue; }
            if (args[i] == L"--activity-markers" && options.HardFaults() && !options.activityMarkers) { options.activityMarkers = true; continue; }
            if (i + 1 == args.size()) { return false; }
            if (args[i] == L"--after" && !haveAfter && Decimal(args[i + 1], MaxRecords, options.after))
            { haveAfter = true; }
            else if (args[i] == L"--limit" && !haveLimit && Decimal(args[i + 1], MaxPage, options.limit) && options.limit)
            { haveLimit = true; }
            else if (args[i] == L"--check-page" && options.expectedPage.empty())
            {
                if (!etl_profile::NormalizeDigest(args[i + 1], options.expectedPage)) { return false; }
            }
            else if (args[i] == L"--thread-id" && (options.Switches() || options.HardFaults()) && !options.haveTid && Decimal(args[i + 1], UINT32_MAX, options.tid))
            { options.haveTid = true; }
            else if ((args[i] == L"--ready-origin" || args[i] == L"--ready-origins") && options.Switches() && !options.ReadyQuery())
            {
                options.multipleReady = args[i] == L"--ready-origins";
                if (!ParseReadyRecords(args[i + 1], options.multipleReady, options.readyRecords)) { return false; }
            }
            else if (args[i] == L"--schedule-of" && options.HardFaults() && !options.scheduleOf)
            {
                if (!Decimal(args[i + 1], MaxRecords, options.scheduleOf) || !options.scheduleOf) { return false; }
            }
            else if (!options.activityStart && ((options.HardFaults() && args[i] == L"--activity-window") ||
                (options.Switches() && args[i] == L"--schedule-activity")))
            {
                if (i + 2 >= args.size() || !Decimal(args[i + 1], MaxRecords, options.activityStart) || !options.activityStart ||
                    !Decimal(args[i + 2], MaxRecords, options.activityStop) || options.activityStop <= options.activityStart) { return false; }
                ++i;
            }
            else { return false; }
            ++i;
        }
        if (options.ReadyQuery())
        {
            if (haveAfter || haveLimit || options.haveTid || options.intervals || options.settings || options.activityStart) { return false; }
            options.limit = static_cast<uint32_t>(options.readyRecords.size());
        }
        if (options.HardFaults() && options.haveTid && !options.activityMarkers) { return false; }
        if (options.activityMarkers && (options.activityStart || options.scheduleOf)) { return false; }
        if (options.SchedulingActivity())
        {
            if (options.haveTid || options.intervals || options.settings) { return false; }
        }
        else if (options.activityStart)
        {
            if (haveAfter || haveLimit || options.scheduleOf) { return false; }
            options.limit = MaxPage;
        }
        if (options.scheduleOf)
        {
            if (haveAfter || haveLimit) { return false; }
            options.after = options.scheduleOf - 1;
            options.limit = 1;
        }
        if (options.builds || !options.referencePath.empty()) { options.images = true; options.processes = true; }
        if (options.clr) { options.processes = true; }
        return options.statementPath.empty() || !options.expectedPage.empty();
    }

    struct TraceCounts
    {
        uint32_t records = 0, decoded = 0, unsupported = 0, lossMarkers = 0;
        uint64_t processedBuffers = 0;
        bool budgetExceeded = false;
    };

    struct Scan : TraceCounts
    {
        Options options;
        etl_profile::ThreadIndex threadIndex;
        etl_profile::ImageIndex imageIndex;
        etl_profile::BuildIndex buildIndex;
        etl_profile::CaptureSettings settings;
        etl_profile::ProcessIndex processIndex;
        etl_profile::ClrIndex clrIndex;
        etl_profile::ScheduleHistory history;
        std::array<etl_profile::DiskTotals, 3> diskTotals{};
        std::array<etl_profile::DiskEvent, MaxPage> diskPage{};
        etl_profile::HardFaultTotals faultTotals;
        etl_profile::ActivityWindow activity;
        etl_profile::ActivitySchedule residency;
        etl_profile::ReadyBatch origins;
        uint32_t decodedReady = 0, unsupportedReady = 0, unassignedReady = 0;
        std::vector<std::pair<uint32_t, etl_profile::ActivityMarker>> markers;
        etl_profile::FaultSchedule faultSchedule;
        std::array<etl_profile::HardFault, MaxPage> faultPage{};
        std::array<Sample, MaxPage> page{};
        std::array<etl_profile::SwitchEvent, MaxPage> switchPage{};
        std::array<etl_profile::IntervalWitnesses, MaxPage> witnesses{};
        uint32_t matched = 0;
        size_t used = 0, replayedRows = 0;
        bool replaying = false, replayMismatch = false;
    };

    void ReplayActivityMarker(const EVENT_RECORD& event, Scan& scan)
    {
        const auto opcode = event.EventHeader.EventDescriptor.Opcode;
        const bool start = scan.records == scan.options.activityStart;
        const bool stop = scan.records == scan.options.activityStop;
        if (start || stop || opcode == 1 || opcode == 2)
        {
            const auto marker = etl_profile::ActivityMarker::Read(event, scan.records);
            if (start || stop)
            {
                scan.replayMismatch |= !(start ? scan.activity.start : scan.activity.stop).SameRecord(marker);
                ++scan.replayedRows;
                if (scan.options.SchedulingActivity()) { scan.history.ObserveClock(marker.tick); }
            }
            scan.activity.ObserveMarker(marker);
        }
    }

    void ReplayActivityFault(const EVENT_RECORD& event, Scan& scan)
    {
        etl_profile::HardFault row{};
        const auto match = etl_profile::DecodeHardFault(event, &row);
        if (match == etl_profile::Match::Unsupported) { ++scan.unsupported; }
        if (match != etl_profile::Match::Decoded) { return; }
        row.record = scan.records;
        row.ordinal = ++scan.decoded;
        scan.activity.ObserveFault(row);
    }

    void ReplayRecord(const EVENT_RECORD& event, Scan& scan)
    {
        if (scan.options.activityStart)
        {
            ReplayActivityMarker(event, scan);
            if (scan.options.HardFaults()) { ReplayActivityFault(event, scan); return; }
        }
        if (scan.options.ReadyQuery())
        {
            scan.origins.ReplaySelection(event, scan.records, scan.options.readyRecords, scan.history, scan.replayedRows, scan.replayMismatch);
        }
        const bool faultQuery = scan.options.scheduleOf != 0;
        if (faultQuery && IsEqualGUID(event.EventHeader.ProviderId, etl_profile::PageFaultProvider))
        {
            etl_profile::HardFault row{};
            const auto match = etl_profile::DecodeHardFault(event, &row);
            if (match == etl_profile::Match::Unsupported) { ++scan.unsupported; }
            if (match != etl_profile::Match::Decoded) { return; }
            scan.history.ObserveClock(row.timestamp);
            if (++scan.decoded == scan.options.scheduleOf)
            {
                const auto& first = scan.faultPage[0];
                scan.replayMismatch |= first.record != scan.records || first.timestamp != row.timestamp ||
                    first.cpu != row.cpu || first.flags != row.flags || first.loggerId != row.loggerId ||
                    first.width != row.width || first.headerTid != row.headerTid || first.headerPid != row.headerPid ||
                    first.keyword != row.keyword || first.level != row.level || first.channel != row.channel ||
                    first.task != row.task || first.extendedItems != row.extendedItems || first.stackItems != row.stackItems ||
                    first.initialTime != row.initialTime || first.readOffset != row.readOffset ||
                    first.faultingTid != row.faultingTid || first.byteCount != row.byteCount;
                ++scan.replayedRows;
            }
            return;
        }
        if (!IsEqualGUID(event.EventHeader.ProviderId, etl_profile::ThreadProvider)) { return; }
        if (event.EventHeader.EventDescriptor.Opcode != 36)
        {
            scan.history.OtherThreadEvent(event, scan.records);
            return;
        }
        etl_profile::SwitchEvent point{};
        if (etl_profile::DecodeSwitch(event, &point) != etl_profile::Match::Decoded)
        {
            if (faultQuery) { ++scan.faultSchedule.unsupportedSwitches; } else { ++scan.unsupported; }
            return;
        }
        point.record = scan.records;
        if (faultQuery)
        {
            point.ordinal = ++scan.faultSchedule.switches;
            scan.faultSchedule.Observe(scan.history, point, scan.faultPage[0]);
            return;
        }
        point.ordinal = ++scan.decoded;
        if (scan.options.ReadyQuery())
        {
            scan.origins.ReplaySwitch(scan.history, point, scan.replayedRows, scan.replayMismatch);
            return;
        }
        if (scan.options.SchedulingActivity())
        {
            scan.residency.Observe(scan.history, point, scan.activity, scan.options.after, scan.options.limit);
            return;
        }
        etl_profile::IntervalWitnesses* witnesses = nullptr;
        if (scan.replayedRows < scan.used && scan.switchPage[scan.replayedRows].record == point.record)
        {
            const auto& first = scan.switchPage[scan.replayedRows];
            scan.replayMismatch |= first.ordinal != point.ordinal || first.timestamp != point.timestamp ||
                first.cpu != point.cpu || first.flags != point.flags || first.loggerId != point.loggerId ||
                first.version != point.version || std::memcmp(&first.fields, &point.fields, sizeof(point.fields)) != 0;
            witnesses = &scan.witnesses[scan.replayedRows++];
        }
        scan.history.Observe(point, witnesses);
    }

    void ObserveRecord(Scan& scan, PEVENT_RECORD event)
    {
        if (scan.replaying) { ReplayRecord(*event, scan); return; }
        if (scan.options.activityMarkers)
        {
            const auto opcode = event->EventHeader.EventDescriptor.Opcode;
            if (opcode != 1 && opcode != 2) { return; }
            const auto row = etl_profile::ActivityMarker::Read(*event, scan.records);
            if (!row.StartOrStop()) { return; }
            if (!row.Keyed()) { ++scan.unsupported; return; }
            ++scan.decoded;
            if (scan.options.haveTid && row.tid != scan.options.tid) { return; }
            if (++scan.matched > scan.options.after && scan.used < scan.options.limit)
            {
                scan.markers.emplace_back(scan.decoded, row);
                ++scan.used;
            }
            return;
        }
        auto collect = [&](etl_profile::Match match, auto& row, auto& page)
        {
            if (match == etl_profile::Match::Unsupported) { ++scan.unsupported; }
            if (match != etl_profile::Match::Decoded) { return false; }
            row.ordinal = ++scan.decoded;
            row.record = scan.records;
            ++scan.matched;
            if (!scan.options.activityStart && row.ordinal > scan.options.after && scan.used < scan.options.limit) { page[scan.used++] = row; }
            return true;
        };
        if (scan.options.DiskIo())
        {
            etl_profile::DiskEvent row;
            if (collect(etl_profile::DecodeDisk(*event, row), row, scan.diskPage)) { scan.diskTotals[row.Operation()].Observe(row); }
            return;
        }
        if (scan.options.NeedsThreadIndex()) { scan.threadIndex.Observe(*event, scan.records); }
        if (scan.options.ReadyQuery())
        {
            scan.origins.Select(*event, scan.records, scan.options.readyRecords);
            if (!IsEqualGUID(event->EventHeader.ProviderId, etl_profile::ThreadProvider)) { return; }
            if (event->EventHeader.EventDescriptor.Opcode == 50)
            {
                etl_profile::ReadyPoint ready;
                const auto match = etl_profile::DecodeReady(*event, scan.records, ready);
                if (match == etl_profile::Match::Unsupported) { ++scan.unsupportedReady; }
                if (match == etl_profile::Match::Decoded)
                {
                    ++scan.decodedReady;
                    if (!ready.tid || ready.tid == UINT32_MAX) { ++scan.unassignedReady; }
                }
                return;
            }
            etl_profile::SwitchEvent row{};
            const auto match = etl_profile::DecodeSwitch(*event, &row);
            if (match == etl_profile::Match::Unsupported) { ++scan.unsupported; }
            if (match == etl_profile::Match::Decoded)
            {
                row.record = scan.records;
                row.ordinal = ++scan.decoded;
                scan.origins.SelectSwitch(row);
            }
            return;
        }
        if (scan.options.activityStart)
        {
            if (scan.records == scan.options.activityStart) { scan.activity.start = etl_profile::ActivityMarker::Read(*event, scan.records); }
            if (scan.records == scan.options.activityStop) { scan.activity.stop = etl_profile::ActivityMarker::Read(*event, scan.records); }
        }
        if (scan.options.HardFaults())
        {
            etl_profile::HardFault row;
            if (collect(etl_profile::DecodeHardFault(*event, &row), row, scan.faultPage)) { scan.faultTotals.Observe(row); }
            return;
        }
        if (scan.options.settings) { scan.settings.Observe(*event, scan.records); }
        if (scan.options.builds) { scan.buildIndex.Observe(*event, scan.records); }
        if (scan.options.clr) { scan.clrIndex.Observe(*event, scan.records); }
        if (scan.options.images) { scan.imageIndex.Observe(*event, scan.records); }
        if (scan.options.processes) { scan.processIndex.Observe(*event, scan.records, scan.options.images); }
        const bool keep = !scan.options.SchedulingActivity() && scan.matched >= scan.options.after && scan.used < scan.options.limit;
        etl_profile::SwitchEvent scratch;
        auto* sw = keep ? &scan.switchPage[scan.used] : (scan.options.haveTid ? &scratch : nullptr);
        const auto match = scan.options.Switches() ? etl_profile::DecodeSwitch(*event, sw) :
            etl_profile::Decode(*event, keep ? &scan.page[scan.used] : nullptr);
        if (match == etl_profile::Match::Unsupported) { ++scan.unsupported; }
        if (match != etl_profile::Match::Decoded) { return; }
        ++scan.decoded;
        if (scan.options.haveTid && sw->fields.oldTid != scan.options.tid && sw->fields.newTid != scan.options.tid) { return; }
        ++scan.matched;
        if (keep)
        {
            etl_profile::RecordEnvelope& row = scan.options.Switches() ?
                static_cast<etl_profile::RecordEnvelope&>(scan.switchPage[scan.used]) : scan.page[scan.used];
            row.ordinal = scan.decoded;
            row.record = scan.records;
            ++scan.used;
        }
    }

    struct CapabilityFamily
    {
        EtlCapabilityRecords records;
        // The largest admitted payload is a 64-bit v3 DiskIo read or write.
        std::array<uint8_t, 52> firstPayload{};

        void Observe(const EVENT_RECORD& event, etl_profile::Match match, uint32_t ordinal)
        {
            if (!records.Decoded && match == etl_profile::Match::Decoded && event.UserDataLength <= firstPayload.size())
            {
                records.FirstPayloadBytes = event.UserDataLength;
                std::memcpy(firstPayload.data(), event.UserData, records.FirstPayloadBytes);
            }
            records.Count(match, ordinal);
        }

        bool Save(EtlCapabilityRecords& result) const
        {
            result = records;
            if (!result.Decoded) { return true; }
            ContentHash hash;
            if (!result.FirstPayloadBytes || !hash.Add(firstPayload.data(), result.FirstPayloadBytes)) { return false; }
            result.FirstPayloadSha256 = hash.Finish();
            return !result.FirstPayloadSha256.empty();
        }
    };

    struct CapabilityScan : TraceCounts
    {
        CapabilityFamily profile, switches, disk, hardFault;
    };

    void ObserveRecord(CapabilityScan& scan, PEVENT_RECORD event)
    {
        scan.profile.Observe(*event, etl_profile::Decode(*event, nullptr), scan.records);
        scan.switches.Observe(*event, etl_profile::DecodeSwitch(*event, nullptr), scan.records);
        etl_profile::DiskEvent disk;
        scan.disk.Observe(*event, etl_profile::DecodeDisk(*event, disk), scan.records);
        scan.hardFault.Observe(*event, etl_profile::DecodeHardFault(*event, nullptr), scan.records);
    }

    template<class State>
    void WINAPI OnRecord(PEVENT_RECORD event)
    {
        auto& scan = *static_cast<State*>(event->UserContext);
        if (scan.records == MaxRecords) { scan.budgetExceeded = true; return; }
        ++scan.records;
        if (etl_profile::LossMarker(event->EventHeader)) { ++scan.lossMarkers; }
        ObserveRecord(scan, event);
    }

    template<class State>
    ULONG WINAPI OnBuffer(PEVENT_TRACE_LOGFILEW log)
    {
        auto& scan = *static_cast<State*>(log->Context);
        ++scan.processedBuffers;
        return !scan.budgetExceeded;
    }

    struct TraceResult
    {
        const wchar_t* failure = nullptr;
        ULONG win32 = ERROR_SUCCESS;
        bool sourceChanged = false;
    };

    struct Trace
    {
        PROCESSTRACE_HANDLE handle = INVALID_PROCESSTRACE_HANDLE;
        ~Trace() { if (handle != INVALID_PROCESSTRACE_HANDLE) { CloseTrace(handle); } }

        TraceResult OpenSingle(EVENT_TRACE_LOGFILEW& log)
        {
            handle = OpenTraceW(&log);
            if (handle == INVALID_PROCESSTRACE_HANDLE) { return {L"open_trace_failed", GetLastError()}; }
            return {};
        }

        TraceResult ProcessPinned(SchemaArtifact& source, const std::wstring& volumePath, const TraceCounts& scan)
        {
            const auto status = ProcessTrace(&handle, 1, nullptr, nullptr);
            if (!source.PathNamesFile(volumePath) || !source.Unchanged()) { return {L"source_changed", 0, true}; }
            if (scan.budgetExceeded) { return {L"record_budget_exceeded"}; }
            if (status != ERROR_SUCCESS) { return {L"process_trace_failed", status}; }
            return {};
        }
    };

    bool OpenSource(const std::filesystem::path& path, symbol_artifacts::Directories& parents,
        SchemaArtifact& source, std::wstring& volumePath, uint64_t maximum = MaxBytes,
        std::optional<uint64_t>* memberBytes = nullptr, DWORD* apiError = nullptr)
    {
        const auto failed = [&] { if (apiError) { *apiError = GetLastError(); } return false; };
        HANDLE raw = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
            FILE_FLAG_OPEN_NO_RECALL | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (raw == INVALID_HANDLE_VALUE) { return failed(); }
        const std::unique_ptr<void, decltype(&CloseHandle)> lease(raw, &CloseHandle);
        FILE_ATTRIBUTE_TAG_INFO attributes{};
        constexpr DWORD excluded = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_OFFLINE |
            FILE_ATTRIBUTE_RECALL_ON_OPEN | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS;
        if (!GetFileInformationByHandleEx(raw, FileAttributeTagInfo, &attributes, sizeof(attributes))) { return failed(); }
        if (attributes.FileAttributes & excluded) { return false; }
        if (memberBytes)
        {
            LARGE_INTEGER size{};
            if (!GetFileSizeEx(raw, &size)) { return failed(); }
            if (size.QuadPart < 0) { return false; }
            const auto actual = static_cast<uint64_t>(size.QuadPart);
            *memberBytes = actual;
            if (actual != maximum) { return false; }
        }
        if (!source.OpenHandle(raw, maximum) || !source.PathNamesFile()) { return false; }
        // OpenTrace takes a name. Use the leased file's volume GUID and the
        // pinned directory hierarchy for the entire decode, including reopens.
        std::vector<wchar_t> buffer(32768);
        const auto length = GetFinalPathNameByHandleW(raw, buffer.data(), static_cast<DWORD>(buffer.size()), VOLUME_NAME_GUID);
        if (!length) { return failed(); }
        if (length >= buffer.size()) { return false; }
        volumePath.assign(buffer.data(), length);
        if (volumePath.rfind(L"\\\\?\\Volume{", 0) != 0) { return false; }
        const auto root = volumePath.find(L"}\\");
        if (root == std::wstring::npos) { return false; }
        // A substituted drive can start below the real volume root. Hold each
        // actual ancestor against rename and reparse changes, then check the leaf.
        for (auto end = volumePath.find(L'\\', root + 2); end != std::wstring::npos; end = volumePath.find(L'\\', end + 1))
        {
            if (!parents.HoldExisting(volumePath.substr(0, end), FILE_SHARE_READ, apiError)) { return false; }
        }
        return source.PathNamesFile(volumePath);
    }

    bool OpenTraceSource(const std::wstring& name, symbol_artifacts::Directories& parents, SchemaArtifact& source,
        std::wstring& volumePath, uint64_t maximum = MaxBytes, std::optional<uint64_t>* memberBytes = nullptr, DWORD* apiError = nullptr)
    {
        if (apiError) { *apiError = ERROR_SUCCESS; }
        std::filesystem::path path;
        return symbol_artifacts::LocalRoot(name, &path) && parents.Pin(path.parent_path(), false, FILE_SHARE_READ | FILE_SHARE_WRITE, apiError) &&
            OpenSource(path, parents, source, volumePath, maximum, memberBytes, apiError);
    }

    etl_profile::CaptureStatement ReadCaptureStatement(const Options& options, const SchemaArtifact& etl)
    {
        etl_profile::SavedEtlInput statement;
        etl_profile::CaptureStatement result;
        result.Status = L"statement_unavailable";
        if (!statement.Open(options.statementPath, etl_profile::MaxStatementBytes)) { return result; }
        std::vector<uint8_t> bytes;
        if (!statement.ReadStatement(bytes)) { result.Status = L"statement_changed"; }
        else { result = etl_profile::VerifyCaptureStatement(bytes, options.statementAuthority, etl.Sha256, etl.Bytes()); }
        result.FileSha256 = statement.File.Sha256;
        return result;
    }

    std::wstring Hex(uint64_t value)
    {
        wchar_t text[20]{};
        swprintf_s(text, L"0x%llx", static_cast<unsigned long long>(value));
        return Quote(text);
    }

    std::wstring LoggerJson(uint16_t logger, bool include)
    {
        return include ? L",\"logger_id\":" + std::to_wstring(logger) : std::wstring{};
    }

    std::wstring SettingsManifestJson(const etl_profile::CaptureSettings& s, const TRACE_LOGFILE_HEADER& header)
    {
        auto out = std::wstring(L",\"capture_settings\":{\"scope\":\"saved_file_logger_records\",\"original_session_id\":null,") +
            L"\"mask_provider\":\"68fdd900-4a3e-11d1-84f4-0000f80464e3\",\"interval_provider\":\"ce1dbfb4-137e-4da6-87b0-3f59aa102cbc\"," +
            L"\"loss_provider\":\"6a399ae0-4bc6-4de9-870b-3657f8947e7e\",\"header_timer_resolution_100ns\":" +
            std::to_wstring(header.TimerResolution) + L",\"group_mask_records\":" + std::to_wstring(s.maskCount) +
            L",\"profile_interval_records\":" + std::to_wstring(s.intervalCount) + L",\"loss_indications\":" + std::to_wstring(s.lossCount) +
            L",\"unsupported_group_masks\":" + std::to_wstring(s.unsupportedMasks) +
            L",\"unsupported_profile_intervals\":" + std::to_wstring(s.unsupportedIntervals) +
            L",\"retained_records\":" + std::to_wstring(s.records.size()) + L",\"retention\":" + Quote(s.retention) + L",\"records\":[";
        for (const auto& e : s.records)
        {
            if (&e != s.records.data()) { out += L','; }
            out += L"{\"record_ordinal\":" + std::to_wstring(e.record) + L",\"raw_timestamp\":" + Quote(std::to_wstring(e.tick)) +
                L",\"logger_id\":" + std::to_wstring(e.logger) + L",\"cpu\":" + std::to_wstring(e.cpu) +
                L",\"cpu_field\":" + Quote((e.flags & EVENT_HEADER_FLAG_PROCESSOR_INDEX) ? L"processor_index" : L"processor_number") +
                L",\"header_flags\":" + std::to_wstring(e.flags) + L",\"pointer_bytes\":" + (e.width ? std::to_wstring(e.width) : L"null") +
                L",\"event_id\":" + std::to_wstring(e.eventId) + L",\"version\":" + std::to_wstring(e.version) +
                L",\"opcode\":" + std::to_wstring(e.opcode) + L",\"event_keyword\":" + Hex(e.keyword) +
                L",\"event_level\":" + std::to_wstring(e.level) + L",\"event_channel\":" + std::to_wstring(e.channel) +
                L",\"event_task\":" + std::to_wstring(e.task) + L",\"payload_bytes\":" + std::to_wstring(e.payloadBytes);
            const bool mask = e.kind == etl_profile::SettingKind::GroupMask;
            const bool loss = e.kind == etl_profile::SettingKind::Loss;
            out += L",\"kind\":" + Quote(mask ? L"group_mask" : loss ? L"loss_indication" : L"profile_interval") +
                L",\"payload_status\":" + Quote(loss ? L"envelope_only" : e.supported ? L"decoded" : L"unsupported");
            if (e.supported && mask)
            {
                out += L",\"group_masks\":[";
                for (size_t i = 0; i < e.masks.size(); ++i)
                {
                    if (i) { out += L','; }
                    out += std::to_wstring(e.masks[i]);
                }
                out += L"],\"kernel_event_version\":" + (e.version == 2 ? std::to_wstring(e.kernelVersion) : L"null");
            }
            else if (e.supported && !loss)
            {
                out += L",\"profile_source\":" + std::to_wstring(e.source) +
                    L",\"new_interval_raw\":" + std::to_wstring(e.newInterval) + L",\"old_interval_raw\":" + std::to_wstring(e.oldInterval) +
                    L",\"profile_source_name\":" + (e.version == 3 ? Quote(std::wstring(s.Name(e))) : L"null");
            }
            out += L'}';
        }
        return out + L"]}";
    }

    std::wstring SettingBracketJson(const etl_profile::SettingBracket& r, bool timer)
    {
        auto ordinal = [](const etl_profile::SettingRecord* p) { return p ? std::to_wstring(p->record) : std::wstring(L"null"); };
        auto out = L"{\"relation\":" + Quote(r.relation) + L",\"before_record\":" + ordinal(r.before) +
            L",\"after_record\":" + ordinal(r.after);
        if (timer)
        {
            out += L",\"collection_start_record\":" + ordinal(r.start) + L",\"collection_end_record\":" + ordinal(r.end) +
                L",\"reported_period_100ns\":" + (r.period ? std::to_wstring(r.period) : L"null");
        }
        return out + L"}";
    }

    std::wstring SettingsEvidenceJson(const Scan& scan, const etl_profile::RecordEnvelope& row, bool clock, bool gap)
    {
        if (!scan.options.settings) { return {}; }
        using etl_profile::SettingKind;
        auto out = std::wstring(L",\"capture_setting_evidence\":{\"group_mask_bracket\":") +
            SettingBracketJson(scan.settings.At(row, SettingKind::GroupMask, clock, gap), false);
        if (!scan.options.Switches())
        {
            out += L",\"timer_bracket\":" + SettingBracketJson(scan.settings.At(row, SettingKind::ProfileInterval, clock, gap), true);
        }
        return out + L"}";
    }

    std::wstring ThreadPointJson(const etl_profile::ThreadEvent* e, bool includeLogger)
    {
        if (!e) { return L"null"; }
        return L"{\"record_ordinal\":" + std::to_wstring(e->record) + L",\"raw_timestamp\":" + Quote(std::to_wstring(e->tick)) +
            L",\"event\":" + Quote(etl_profile::ThreadEventName(e->opcode)) + L",\"opcode\":" + std::to_wstring(e->opcode) +
            L",\"payload_pid\":" + std::to_wstring(e->pid) + L",\"payload_tid\":" + std::to_wstring(e->tid) + LoggerJson(e->logger, includeLogger) + L"}";
    }

    std::wstring ThreadPairJson(const etl_profile::ThreadPair& pair, bool includeLogger)
    {
        return L",\"thread_evidence\":{\"relation\":" + Quote(pair.relation) + L",\"paired_record_pid\":" +
            (pair.pairedPid ? std::to_wstring(pair.before->pid) : L"null") + L",\"before\":" + ThreadPointJson(pair.before, includeLogger) +
            L",\"after\":" + ThreadPointJson(pair.after, includeLogger) + L"}";
    }

    std::wstring ImageEventJson(const etl_profile::ImageEvent& e, const etl_profile::ImageIndex& index, bool includeLogger)
    {
        return L"{\"record_ordinal\":" + std::to_wstring(e.record) + L",\"raw_timestamp\":" + Quote(std::to_wstring(e.tick)) +
            L",\"opcode\":" + std::to_wstring(e.opcode) + L",\"version\":" + std::to_wstring(e.version) +
            L",\"pointer_bytes\":" + std::to_wstring(e.width) + L",\"payload_pid\":" + std::to_wstring(e.pid) +
            L",\"image_base\":" + Hex(e.base) + L",\"image_size\":" + Hex(e.size) + L",\"preferred_base\":" + Hex(e.preferred) +
            L",\"image_checksum\":" + std::to_wstring(e.checksum) + L",\"pe_timestamp\":" + std::to_wstring(e.stamp) +
            L",\"signature_level\":" + (e.version == 3 ? std::to_wstring(e.signatureLevel) : L"null") +
            L",\"signature_type\":" + (e.version == 3 ? std::to_wstring(e.signatureType) : L"null") +
            L",\"recorded_file_name\":" + Quote(std::wstring(index.Name(e))) + LoggerJson(e.logger, includeLogger) + L"}";
    }

    std::wstring ImageMatchJson(const etl_profile::ImageMatch& match, std::vector<const etl_profile::ImageEvent*>& records)
    {
        auto result = L",\"image_evidence\":{\"relation\":" + Quote(match.relation) +
            L",\"candidate_ranges\":" + std::to_wstring(match.count) + L",\"reported_rva\":" +
            (match.paired ? Hex(match.rva) : L"null") + L",\"witnesses\":[";
        for (size_t i = 0; i < (std::min)(match.count, match.witnesses.size()); ++i)
        {
            const auto& w = match.witnesses[i];
            if (i) { result += L','; }
            if (w.before) { records.push_back(w.before); }
            if (w.after) { records.push_back(w.after); }
            result += L"{\"relation\":" + Quote(w.relation) + L",\"before_record\":" +
                (w.before ? std::to_wstring(w.before->record) : L"null") + L",\"after_record\":" +
                (w.after ? std::to_wstring(w.after->record) : L"null") + L"}";
        }
        return result + L"]}";
    }

    std::wstring ProcessEventJson(const etl_profile::ProcessEvent& e)
    {
        return L"{\"record_ordinal\":" + std::to_wstring(e.record) + L",\"raw_timestamp\":" + Quote(std::to_wstring(e.tick)) +
            L",\"event\":" + Quote(e.opcode == 39 ? L"defunct" : etl_profile::ThreadEventName(e.opcode)) +
            L",\"opcode\":" + std::to_wstring(e.opcode) + L",\"version\":" + std::to_wstring(e.version) +
            L",\"pointer_bytes\":" + std::to_wstring(e.width) + L",\"logger_id\":" + std::to_wstring(e.logger) +
            L",\"payload_pid\":" + std::to_wstring(e.pid) + L",\"parent_pid\":" + std::to_wstring(e.parent) +
            L",\"session_id\":" + std::to_wstring(e.session) + L",\"exit_status\":" + std::to_wstring(e.exitStatus) +
            L",\"defunct_exit_time_raw\":" + (e.version == 5 ? Quote(std::to_wstring(e.exitTime)) : L"null") + L"}";
    }

    std::wstring ProcessPairJson(const etl_profile::ProcessPair& p, std::vector<const etl_profile::ProcessEvent*>& records)
    {
        if (p.before) { records.push_back(p.before); }
        if (p.after) { records.push_back(p.after); }
        return L",\"process_evidence\":{\"relation\":" + Quote(p.relation) + L",\"candidate_pid\":" +
            (p.candidatePid ? std::to_wstring(p.candidatePid) : L"null") + L",\"before_record\":" +
            (p.before ? std::to_wstring(p.before->record) : L"null") + L",\"after_record\":" +
            (p.after ? std::to_wstring(p.after->record) : L"null") + L",\"opaque_key_comparison\":" + Quote(p.keyComparison) +
            L",\"recorded_generation\":" + (p.generation ? L"{\"payload_pid\":" + std::to_wstring(p.candidatePid) +
                L",\"start_record\":" + std::to_wstring(p.before->record) + L"}" : L"null") + L"}";
    }

    std::wstring ClrPointJson(const etl_profile::ClrPoint& p)
    {
        const auto& m = p.method;
        const auto* action = m.Observation == ClrMethodAction::Load ? L"load" :
            m.Observation == ClrMethodAction::Unload ? L"unload" : L"rundown";
        return L"{\"record_ordinal\":" + std::to_wstring(p.record) + L",\"raw_timestamp\":" + Quote(std::to_wstring(p.tick)) +
            L",\"header_process_id\":" + std::to_wstring(p.pid) + L",\"logger_id\":" + std::to_wstring(p.logger) +
            L",\"provider_guid\":" + Quote(m.RundownProvider ? L"a669021c-c450-4609-a035-5af59af4df18" : L"e13c0d23-ccbc-4e12-931b-d9cc2eee27e4") +
            L",\"event_id\":" + std::to_wstring(m.EventId) + L",\"version\":" + std::to_wstring(m.EventVersion) +
            L",\"opcode\":" + std::to_wstring(p.opcode) + L",\"action\":" + Quote(action) +
            L",\"method_start\":" + Hex(m.Start) + L",\"method_size\":" + std::to_wstring(m.Size) +
            L",\"method_id\":" + Hex(m.MethodId) + L",\"module_id\":" + Hex(m.ModuleId) +
            L",\"method_token\":" + Hex(m.MethodToken) + L",\"method_flags\":" + Hex(m.MethodFlags) +
            L",\"clr_instance_id\":" + (m.RuntimeInstance ? std::to_wstring(*m.RuntimeInstance) : L"null") +
            L",\"rejit_id\":" + (m.ReJitId ? Hex(*m.ReJitId) : L"null") + L"}";
    }

    std::wstring ClrMatchJson(const etl_profile::ClrMatch& m, const Sample& sample, const etl_profile::ProcessPair& process,
        std::vector<const etl_profile::ClrPoint*>& records)
    {
        auto out = L",\"clr_evidence\":{\"relation\":" + Quote(m.relation) + L",\"candidate_ranges\":" +
            std::to_wstring(m.count) + L",\"process_start_record\":" + (m.lifetime ? std::to_wstring(process.before->record) : L"null") +
            L",\"method_offset\":" + (m.lifetime ? Hex(sample.ip - m.witnesses.front().before->method.Start) : L"null") + L",\"witnesses\":[";
        for (size_t i = 0; i < (std::min)(m.count, m.witnesses.size()); ++i)
        {
            const auto& w = m.witnesses[i];
            if (i) { out += L','; }
            if (w.before) { records.push_back(w.before); }
            if (w.after) { records.push_back(w.after); }
            out += L"{\"before_record\":" + (w.before ? std::to_wstring(w.before->record) : L"null") +
                L",\"after_record\":" + (w.after ? std::to_wstring(w.after->record) : L"null") + L"}";
        }
        return out + L"]}";
    }

    std::wstring ImageProcessJson(const etl_profile::ProcessPair& process, const etl_profile::ImageMatch& image,
        const etl_profile::ProcessImagePair& bound)
    {
        return L",\"image_process_evidence\":{\"relation\":" + Quote(bound.relation) + L",\"process_start_record\":" +
            (bound.paired ? std::to_wstring(process.before->record) : L"null") + L",\"reported_rva\":" +
            (bound.paired ? Hex(image.rva) : L"null") + L"}";
    }

    const wchar_t* FieldJson(etl_profile::FieldComparison value)
    {
        using etl_profile::FieldComparison;
        return value == FieldComparison::Unavailable ? L"null" : value == FieldComparison::Equal ? L"true" : L"false";
    }

    std::wstring GuidJson(const GUID& id)
    {
        wchar_t out[37]{};
        swprintf_s(out, L"%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", id.Data1, id.Data2, id.Data3,
            id.Data4[0], id.Data4[1], id.Data4[2], id.Data4[3], id.Data4[4], id.Data4[5], id.Data4[6], id.Data4[7]);
        return Quote(out);
    }

    std::wstring BuildEventJson(const etl_profile::BuildEvent& e)
    {
        auto out = L"{\"record_ordinal\":" + std::to_wstring(e.record) + L",\"raw_timestamp\":" + Quote(std::to_wstring(e.tick)) +
            L",\"version\":2,\"opcode\":" + std::to_wstring(e.opcode) + L",\"pointer_bytes\":" + std::to_wstring(e.width) +
            L",\"logger_id\":" + std::to_wstring(e.logger) + L",\"header_process_id\":" + std::to_wstring(e.headerPid) +
            L",\"payload_pid\":" + std::to_wstring(e.pid) + L",\"image_base\":" + Hex(e.base);
        if (!e.opcode) { out += L",\"image_size\":" + Hex(e.size) + L",\"pe_timestamp\":" + std::to_wstring(e.stamp); }
        if (e.opcode == 36) { out += L",\"rsds_guid\":" + GuidJson(e.guid) + L",\"pdb_age\":" + std::to_wstring(e.age); }
        return out + L"}";
    }

    std::wstring MarkerJson(const etl_profile::MarkerRange& range, std::vector<const etl_profile::BuildEvent*>& records)
    {
        auto out = L"{\"marker_count\":" + std::to_wstring(range.count) + L",\"marker_records\":[";
        for (size_t i = 0; i < (std::min)(range.count, size_t{2}); ++i)
        {
            if (i) { out += L','; }
            records.push_back(range.first + i);
            out += std::to_wstring(range.first[i].record);
        }
        return out + L"]}";
    }

    std::wstring BuildEndpointJson(const etl_profile::BuildEndpoint& e, std::vector<const etl_profile::BuildEvent*>& records)
    {
        return L",\"merge_build\":{\"relation\":" + Quote(e.relation) + L",\"loader_count\":" + std::to_wstring(e.loaders) +
            L",\"image_id\":" + MarkerJson(e.info, records) + L",\"no_debug_id\":" + MarkerJson(e.none, records) +
            L",\"native_rsds\":" + MarkerJson(e.rsds, records) + L"}";
    }

    std::wstring BuildPairJson(const etl_profile::BuildPair& pair, const etl_profile::ReferenceImage* reference)
    {
        auto out = L",\"build_evidence\":{\"relation\":" + Quote(pair.relation) + L",\"reference_comparison\":";
        if (!pair.rsds || !reference) { return out + L"null}"; }
        const auto fields = etl_profile::CompareMergeFields(*reference, pair);
        return out + L"{\"rsds_guid_equal\":" + FieldJson(fields.guid) + L",\"pdb_age_equal\":" + FieldJson(fields.age) +
            L",\"merge_timestamp_equal\":" + FieldJson(fields.stamp) + L"}}";
    }

    bool AppendReferenceEvidence(std::wstring& report, const etl_profile::ReferenceImage& reference,
        const etl_profile::ImageIndex& index, const etl_profile::ImageMatch& image, const etl_profile::ProcessImagePair& bound,
        const etl_profile::BuildPair* build)
    {
        const auto* point = bound.paired ? image.witnesses[0].before : nullptr;
        const auto result = etl_profile::CompareReference(reference, point, point ? index.Name(*point) : std::wstring_view{}, image.rva, build);
        report += L",\"reference_evidence\":{\"relation\":" + Quote(result.relation) + L",\"loader_fields\":";
        if (point)
        {
            report += std::wstring(L"{\"file_name\":") + FieldJson(result.name) + L",\"image_size\":" + FieldJson(result.size) +
                L",\"pe_timestamp\":" + FieldJson(result.stamp) + L",\"image_checksum\":" + FieldJson(result.checksum) +
                L",\"default_base_relation\":" + Quote(result.defaultBase) + L"}";
        }
        else { report += L"null"; }
        report += L",\"file_location\":" + Quote(result.location) + L",\"reference_window\":";
        if (!result.length) { report += L"null}"; return true; }
        const auto digest = etl_profile::ReferenceWindowHash(reference, result);
        if (digest.empty()) { return false; }
        report += L"{\"file_offset\":" + std::to_wstring(result.offset) + L",\"byte_count\":" + std::to_wstring(result.length) +
            L",\"sha256\":" + Quote(digest) + L"}}";
        return true;
    }

    template<typename Event, typename Format>
    void AppendRecords(std::wstring& result, const wchar_t* name, std::vector<const Event*>& records, Format format)
    {
        result += L"],\"";
        result += name;
        result += L"\":[";
        std::sort(records.begin(), records.end(), [](const Event* a, const Event* b) { return a->record < b->record; });
        records.erase(std::unique(records.begin(), records.end()), records.end());
        for (size_t i = 0; i < records.size(); ++i)
        {
            if (i) { result += L','; }
            result += format(*records[i]);
        }
    }

    std::wstring RecordLocationJson(const etl_profile::RecordEnvelope& s)
    {
        return L",\"record_ordinal\":" + std::to_wstring(s.record) +
            L",\"raw_timestamp\":" + Quote(std::to_wstring(s.timestamp)) + L",\"cpu\":" + std::to_wstring(s.cpu) +
            L",\"cpu_field\":" + Quote((s.flags & EVENT_HEADER_FLAG_PROCESSOR_INDEX) ? L"processor_index" : L"processor_number");
    }

    std::wstring RecordHeaderJson(const etl_profile::RecordEnvelope& s)
    {
        return L",\"pointer_bytes\":" + std::to_wstring(s.width) + L",\"header_thread_id\":" + std::to_wstring(s.headerTid) +
            L",\"header_process_id\":" + std::to_wstring(s.headerPid) + L",\"header_flags\":" + std::to_wstring(s.flags) +
            L",\"logger_id\":" + std::to_wstring(s.loggerId) + L",\"event_keyword\":" + Hex(s.keyword) +
            L",\"event_level\":" + std::to_wstring(s.level) + L",\"event_channel\":" + std::to_wstring(s.channel) +
            L",\"event_task\":" + std::to_wstring(s.task) + L",\"extended_data_items\":" + std::to_wstring(s.extendedItems) +
            L",\"stack_extension_items\":" + std::to_wstring(s.stackItems);
    }

    std::wstring SampleJson(const Sample& s, const etl_profile::ThreadPair* thread,
        const std::wstring& evidence = {}, bool includeLogger = false)
    {
        return L"{\"sample_ordinal\":" + std::to_wstring(s.ordinal) + RecordLocationJson(s) +
            L",\"instruction_pointer\":" + Hex(s.ip) + L",\"sampled_thread_id\":" + std::to_wstring(s.tid) +
            L",\"count_field\":" + std::to_wstring(s.count) + L",\"reserved_field\":" + std::to_wstring(s.reserved) +
            RecordHeaderJson(s) +
            (thread ? ThreadPairJson(*thread, includeLogger) : L"") + evidence + L"}";
    }

    std::wstring ScheduleRefJson(const etl_profile::ScheduleRef& ref)
    {
        return L"\"record_ordinal\":" + std::to_wstring(ref.record) + L",\"raw_timestamp\":" + Quote(std::to_wstring(ref.tick)) +
            L",\"cpu\":" + std::to_wstring(ref.cpu) + L",\"cpu_field\":" + Quote(ref.indexed ? L"processor_index" : L"processor_number") +
            L",\"logger_id\":" + std::to_wstring(ref.logger);
    }

    std::wstring EdgeJson(const etl_profile::ScheduleEdge& edge)
    {
        using etl_profile::EdgeKind;
        if (!edge.at.record) { return L"null"; }
        const bool boundary = edge.kind == EdgeKind::Boundary;
        const auto kind = boundary ? etl_profile::ThreadEventName(edge.opcode) : edge.kind == EdgeKind::In ? L"switch_in" : L"switch_out";
        auto json = L"{" + ScheduleRefJson(edge.at) + L",\"kind\":" + Quote(kind) + L",\"payload_tid\":" + std::to_wstring(edge.tid) +
            L",\"version\":" + std::to_wstring(edge.version) + L",\"opcode\":" + std::to_wstring(edge.opcode);
        if (boundary) { json += L",\"payload_pid\":" + std::to_wstring(edge.pid); }
        else { json += L",\"switch_ordinal\":" + std::to_wstring(edge.switchOrdinal); }
        if (edge.kind == EdgeKind::Out)
        { json += L",\"old_state\":" + std::to_wstring(edge.state) + L",\"old_wait_reason\":" + std::to_wstring(edge.reason); }
        return json + L"}";
    }

    std::wstring ReadyJson(const etl_profile::ReadyPoint& p)
    {
        if (!p.at.record) { return L"null"; }
        return L"{" + ScheduleRefJson(p.at) + L",\"payload_tid\":" + std::to_wstring(p.tid) +
            L",\"adjust_reason\":" + std::to_wstring(p.reason) + L",\"adjust_increment\":" + std::to_wstring(p.increment) +
            L",\"ready_flags\":" + std::to_wstring(p.flags) + L",\"reserved_field\":" + std::to_wstring(p.reserved) + L"}";
    }

    std::wstring Elapsed(bool measured, int64_t begin, int64_t end)
    {
        return measured ? Quote(std::to_wstring(etl_profile::TickDistance(begin, end))) : L"null";
    }

    std::wstring ReadyOriginFields(const Scan& scan, const etl_profile::ReadyOrigin& o, bool qpc, bool gap)
    {
        const auto& r = o.ready;
        const auto& h = scan.history;
        const auto& cpu = o.source;
        const auto& target = o.target;
        const auto sourcePair = o.Bracket(scan.threadIndex, cpu.end.record ? cpu.end.fields.oldTid : o.cpuAtReady.tid, qpc, gap);
        const auto targetPair = o.Bracket(scan.threadIndex, r.tid, qpc, gap);
        const auto running = o.Assess(h, sourcePair, true, qpc, gap);
        const auto off = o.Assess(h, targetPair, false, qpc, gap);
        const auto dispatch = o.Dispatch(h, off);
        const auto edge = o.Relationship(running, dispatch, sourcePair);
        const auto& sequence = target.witnesses.ready;
        const auto end = [](const etl_profile::ReadyOrigin::Span& span, bool running) {
            return EdgeJson(etl_profile::ScheduleSlice{span.end, span.witnesses, running, 0, 0}.End());
        };
        return L"\"selected_ready\":" + ReadyJson(r) + L",\"header_thread_id\":" + std::to_wstring(o.headerTid) +
            L",\"header_process_id\":" + std::to_wstring(o.headerPid) + L",\"header_flags\":" + std::to_wstring(o.headerFlags) +
            L",\"executing_dpc\":" + (r.flags & etl_profile::ReadyDpc ? L"true" : L"false") + L",\"direct_switch_attempt\":" + (r.flags & etl_profile::ReadyDirectSwitchAttempt ? L"true" : L"false") +
            L",\"source_cpu_context\":{\"relation\":" + Quote(running.relation) + L",\"switch_in\":" + EdgeJson(o.cpuAtReady) +
            L",\"switch_out\":" + end(cpu, true) + L",\"header_binding\":" + Quote(o.HeaderBinding(sourcePair).relation) + ThreadPairJson(sourcePair, true) +
            L"},\"target_dispatch\":{\"relation\":" + Quote(dispatch.relation) + L",\"off_cpu_relation\":" + Quote(off.relation) +
            L",\"preceding_thread_event\":" + EdgeJson(o.targetAtReady) + L",\"switch_out\":" +
            (o.targetAtReady.kind == etl_profile::EdgeKind::Out ? EdgeJson(o.targetAtReady) : L"null") + L",\"switch_in\":" + end(target, false) +
            L",\"ready_records\":" + std::to_wstring(sequence.count) + L",\"dispatchable_records\":" + std::to_wstring(sequence.dispatchable) +
            L",\"first_ready\":" + ReadyJson(sequence.first) + L",\"last_ready\":" + (sequence.count > 1 ? ReadyJson(sequence.last) : L"null") +
            L",\"switch_out_to_ready_ticks\":" + Elapsed(dispatch.measured, target.witnesses.previousIncomingThread.at.tick, r.at.tick) +
            L",\"ready_to_switch_in_ticks\":" + Elapsed(dispatch.measured, r.at.tick, target.end.timestamp) + ThreadPairJson(targetPair, true) +
            L"},\"relationship\":{\"relation\":" + Quote(edge.relation) + L",\"readying_tid\":" +
            (edge.measured ? std::to_wstring(cpu.end.fields.oldTid) : L"null") + L",\"readying_pid\":" +
            (edge.measured ? std::to_wstring(sourcePair.before->pid) : L"null") + L"}";
    }

    std::wstring ReadyOriginJson(const Scan& scan, bool qpc, bool gap)
    {
        const auto& h = scan.history;
        auto result = std::wstring(L",\"ready_records\":") + std::to_wstring(h.readyCount) + L",\"unsupported_ready_records\":" + std::to_wstring(h.unsupportedReady) +
            L",\"unassigned_ready_records\":" + std::to_wstring(h.unassignedReady) + L",\"thread_boundary_records\":" + std::to_wstring(h.boundaries) +
            L",\"unsupported_thread_boundaries\":" + std::to_wstring(h.unsupportedBoundaries);
        if (!scan.options.multipleReady)
        { return result + L"," + ReadyOriginFields(scan, scan.origins.rows.front(), qpc, gap); }
        result += L",\"ready_origins\":[";
        for (const auto& origin : scan.origins.rows)
        {
            if (&origin != &scan.origins.rows.front()) { result += L','; }
            result += L"{" + ReadyOriginFields(scan, origin, qpc, gap) + L"}";
        }
        return result + L"]";
    }

    std::wstring IntervalsJson(const Scan& scan, size_t index, bool clock, bool gap)
    {
        const auto& e = scan.switchPage[index];
        const auto& w = scan.witnesses[index];
        const auto& out = w.previousIncomingThread;
        const auto run = etl_profile::AssessSpan(scan.history, e, w, true, clock, gap);
        const auto off = etl_profile::AssessSpan(scan.history, e, w, false, clock, gap);
        const auto ready = etl_profile::AssessReady(w.ready, out, e, off.measured, scan.history.unsupportedReady);
        return L",\"match_ordinal\":" + std::to_wstring(scan.options.after + index + 1) +
            L",\"on_cpu\":{\"relation\":" + Quote(run.relation) + L",\"elapsed_ticks\":" +
            Elapsed(run.measured, w.previousCpu.at.tick, e.timestamp) + L",\"previous_switch\":" + EdgeJson(w.previousCpu) +
            L",\"other_thread_event\":" + (etl_profile::SameTransition(w.previousOutgoingThread, w.previousCpu) ? L"null" : EdgeJson(w.previousOutgoingThread)) +
            L"},\"off_cpu\":{\"relation\":" + Quote(off.relation) + L",\"elapsed_ticks\":" + Elapsed(off.measured, out.at.tick, e.timestamp) +
            L",\"previous_thread_event\":" + EdgeJson(out) + L",\"readiness\":{\"relation\":" + Quote(ready.relation) +
            L",\"ready_records\":" + std::to_wstring(w.ready.count) + L",\"dispatchable_records\":" + std::to_wstring(w.ready.dispatchable) +
            L",\"first_ready\":" + ReadyJson(w.ready.first) + L",\"last_ready\":" + (w.ready.count > 1 ? ReadyJson(w.ready.last) : L"null") +
            L",\"switch_out_to_ready_ticks\":" + Elapsed(ready.measured, out.at.tick, w.ready.last.at.tick) +
            L",\"ready_to_switch_in_ticks\":" + Elapsed(ready.measured, w.ready.last.at.tick, e.timestamp) + L"}}";
    }

    std::wstring SwitchJson(const etl_profile::SwitchEvent& s, const std::wstring& intervals)
    {
        const auto& f = s.fields;
        return L"{\"switch_ordinal\":" + std::to_wstring(s.ordinal) + RecordLocationJson(s) +
            L",\"version\":" + std::to_wstring(s.version) + L",\"new_thread_id\":" + std::to_wstring(f.newTid) +
            L",\"old_thread_id\":" + std::to_wstring(f.oldTid) + L",\"new_priority\":" + std::to_wstring(f.newPriority) +
            L",\"old_priority\":" + std::to_wstring(f.oldPriority) + L",\"previous_c_state\":" + std::to_wstring(f.previousCState) +
            L",\"spare_byte\":" + std::to_wstring(f.spare) + L",\"old_wait_reason\":" + std::to_wstring(f.oldWaitReason) +
            L",\"old_wait_mode\":" + (s.version == 2 ? std::to_wstring(f.modeOrFlags) : L"null") +
            L",\"thread_flags\":" + (s.version >= 3 ? std::to_wstring(static_cast<uint8_t>(f.modeOrFlags)) : L"null") +
            L",\"old_state\":" + std::to_wstring(f.oldState) + L",\"old_wait_ideal_processor\":" + std::to_wstring(f.idealProcessor) +
            L",\"new_wait_time\":" + std::to_wstring(f.newWaitTime) + L",\"reserved_field\":" + std::to_wstring(f.reserved) +
            RecordHeaderJson(s) + intervals + L"}";
    }

    std::wstring ReplayReceipt(const Options& o, const wchar_t* status, const std::wstring& source,
        const std::wstring& replayed = {}, const wchar_t* sourceStatus = nullptr, DWORD error = 0,
        const std::wstring& reference = {}, const etl_profile::CaptureStatement& statement = {}, uint32_t badRecord = 0)
    {
        const bool withStatement = !o.statementPath.empty();
        const auto schema = withStatement ? L"kn.etl_page_replay.v2" : L"kn.etl_page_replay.v1";
        return L"{\"schema\":" + Quote(schema) + L",\"status\":" + Quote(status) +
            L",\"source_kind\":" + Quote(o.Fields().kind) +
            L",\"expected_source_sha256\":" + Quote(o.digest) + L",\"expected_reference_sha256\":" +
            (o.referenceDigest.empty() ? L"null" : Quote(o.referenceDigest)) +
            L",\"source_sha256\":" + (source.empty() ? L"null" : Quote(source)) +
            L",\"reference_sha256\":" + (reference.empty() ? L"null" : Quote(reference)) +
            L",\"expected_page_sha256\":" + Quote(o.expectedPage) +
            L",\"replayed_page_sha256\":" + (replayed.empty() ? L"null" : Quote(replayed)) +
            L",\"page_bytes_match\":" + (replayed.empty() ? L"null" : replayed == o.expectedPage ? L"true" : L"false") +
            L",\"source_status\":" + (sourceStatus ? Quote(sourceStatus) : L"null") +
            (o.scheduleOf ? L",\"requested_fault_ordinal\":" + std::to_wstring(o.scheduleOf) : L"") + o.ActivitySelectorJson() + o.ReadySelectorJson() +
            (badRecord ? L",\"failed_ready_record\":" + std::to_wstring(badRecord) : L"") +
            (o.activityMarkers ? L",\"thread_filter\":" + (o.haveTid ? std::to_wstring(o.tid) : L"null") : L"") +
            L",\"after\":" + std::to_wstring(o.after) + L",\"limit\":" + std::to_wstring(o.limit) +
            (withStatement ? L",\"capture_statement\":" + statement.Json(o.statementAuthority, replayed == o.expectedPage) : L"") +
            L",\"collector_authenticated\":false,\"win32_status\":" + (error ? std::to_wstring(error) : L"null") + L"}";
    }

    int Failure(const Options& options, const wchar_t* status, const std::wstring& digest = {}, DWORD error = 0, const std::wstring& referenceDigest = {})
    {
        if (!options.expectedPage.empty())
        {
            return WriteCapabilityJson(ReplayReceipt(options, status, digest, {}, nullptr, error, referenceDigest)) ? 1 : 2;
        }
        const auto report = std::wstring(options.Prefix()) + Quote(status) + L",\"source_sha256\":" +
            (digest.empty() ? L"null" : Quote(digest)) + L",\"win32_status\":" +
            (error ? std::to_wstring(error) : L"null") + (options.referencePath.empty() ? L"" :
                L",\"reference_sha256\":" + (referenceDigest.empty() ? L"null" : Quote(referenceDigest))) +
            (options.SchedulingActivity() ? options.ActivitySelectorJson() + options.ActivityPagingJson() : options.ReadySelectorJson()) + L"}";
        return WriteCapabilityJson(report) ? 1 : 2;
    }

    bool CaptureGap(const Scan& scan, BufferAccounting accounting, const TRACE_LOGFILE_HEADER& h)
    {
        return accounting != BufferAccounting::Matched || h.EventsLost || h.BuffersLost || scan.lossMarkers;
    }

    bool Partial(const Scan& scan, BufferAccounting accounting, const TRACE_LOGFILE_HEADER& h)
    {
        if (scan.options.ReadyQuery() && (scan.unsupportedReady || scan.unassignedReady || scan.threadIndex.unsupported)) { return true; }
        if (scan.options.SchedulingActivity() || scan.options.ReadyQuery())
        {
            return CaptureGap(scan, accounting, h) ||
                scan.unsupported || !scan.threadIndex.Complete();
        }
        if (scan.options.DiskIo() || scan.options.HardFaults())
        {
            return CaptureGap(scan, accounting, h) || (!scan.options.activityMarkers && scan.unsupported);
        }
        return etl_profile::RequiresPartialPage(h.LogFileMode, accounting) ||
            !scan.threadIndex.Complete() || !scan.imageIndex.Complete() || !scan.processIndex.Complete() || !scan.buildIndex.Complete() || !scan.settings.Complete() || !scan.clrIndex.Complete();
    }

    std::wstring DiskEventJson(const etl_profile::DiskEvent& row)
    {
        return L"{\"disk_event_ordinal\":" + std::to_wstring(row.ordinal) + L",\"record_ordinal\":" + std::to_wstring(row.record) +
            L",\"raw_timestamp\":" + Quote(std::to_wstring(row.timestamp)) + L",\"opcode\":" + std::to_wstring(row.opcode) +
            L",\"version\":" + std::to_wstring(row.version) + L",\"pointer_bytes\":" + std::to_wstring(row.width) +
            L",\"logger_id\":" + std::to_wstring(row.loggerId) + L",\"cpu\":" + std::to_wstring(row.cpu) +
            L",\"cpu_field\":" + Quote((row.flags & EVENT_HEADER_FLAG_PROCESSOR_INDEX) ? L"processor_index" : L"processor_number") +
            L",\"operation\":" + Quote(etl_profile::DiskOperations[row.Operation()]) + L",\"phase\":" + Quote(row.IsCompletion() ? L"completion" : L"initiation") +
            L",\"reported_issuing_tid\":" + (row.version == 3 ? std::to_wstring(row.issuingTid) : L"null") +
            L",\"disk_number\":" + (row.IsCompletion() ? std::to_wstring(row.diskNumber) : L"null") +
            L",\"transfer_bytes\":" + (row.IsTransfer() ? std::to_wstring(row.transferBytes) : L"null") +
            L",\"high_res_response_ticks\":" + (row.IsCompletion() ? Quote(std::to_wstring(row.responseTicks)) : L"null") + L"}";
    }

    std::wstring DiskResultsJson(const Scan& scan, const TRACE_LOGFILE_HEADER& h)
    {
        auto out = std::wstring(L",\"response_ticks_per_second\":") + (h.PerfFreq.QuadPart > 0 ? Quote(std::to_wstring(h.PerfFreq.QuadPart)) : L"null") +
            L",\"operations\":[";
        for (size_t i = 0; i < scan.diskTotals.size(); ++i)
        {
            const auto& total = scan.diskTotals[i];
            if (i) { out += L','; }
            out += L"{\"operation\":" + Quote(etl_profile::DiskOperations[i]) + L",\"initiations\":" + std::to_wstring(total.starts) +
                L",\"completions\":" + std::to_wstring(total.completions) + L",\"transfer_bytes\":" +
                (i < 2 ? Quote(std::to_wstring(total.transferBytes)) : L"null") + L",\"longest_response_ties\":" +
                std::to_wstring(total.longestTies) + L",\"first_longest_response\":" +
                (total.longestTies ? DiskEventJson(total.longest) : L"null") + L"}";
        }
        out += L"],\"disk_events\":[";
        for (size_t i = 0; i < scan.used; ++i)
        {
            if (i) { out += L','; }
            out += DiskEventJson(scan.diskPage[i]);
        }
        return out + L"]}";
    }

    std::wstring HardFaultJson(const etl_profile::HardFault& row, bool qpc)
    {
        const auto elapsed = qpc ? row.OrderedTicks() : std::nullopt;
        const auto timing = !qpc ? L"qpc_unavailable" : row.initialTime <= 0 ? L"nonpositive_start" :
            elapsed ? L"ordered_qpc" : L"end_precedes_start";
        return L"{\"fault_ordinal\":" + std::to_wstring(row.ordinal) + RecordLocationJson(row) + RecordHeaderJson(row) +
            L",\"faulting_thread_id\":" + std::to_wstring(row.faultingTid) + L",\"initial_time_raw\":" + Quote(std::to_wstring(row.initialTime)) +
            L",\"read_offset\":" + Quote(std::to_wstring(row.readOffset)) + L",\"byte_count\":" + std::to_wstring(row.byteCount) +
            L",\"timing_status\":" + Quote(timing) + L",\"elapsed_qpc_ticks\":" + (elapsed ? Quote(std::to_wstring(*elapsed)) : L"null") + L"}";
    }

    std::wstring ScheduleSliceJson(const etl_profile::ScheduleSlice& slice, uint32_t unresolvedReady,
        etl_profile::ReportedSpan span)
    {
        auto out = L"{\"relation\":" + Quote(span.relation) + L",\"start\":" + EdgeJson(slice.Start()) +
            L",\"end\":" + EdgeJson(slice.End()) + L",\"overlap_start_raw\":" + Quote(std::to_wstring(slice.beginTick)) +
            L",\"overlap_end_raw\":" + Quote(std::to_wstring(slice.endTick)) + L",\"overlap_ticks\":" +
            Elapsed(span.measured, slice.beginTick, slice.endTick);
        if (!slice.running)
        {
            const auto& ready = slice.witnesses.ready;
            const auto split = etl_profile::AssessReady(ready, slice.Start(), slice.end, span.measured, unresolvedReady);
            const auto pivot = slice.ReadyPivot();
            out += L",\"readiness\":{\"relation\":" + Quote(split.relation) + L",\"ready_records\":" + std::to_wstring(ready.count) +
                L",\"dispatchable_records\":" + std::to_wstring(ready.dispatchable) + L",\"first_ready\":" + ReadyJson(ready.first) +
                L",\"last_ready\":" + (ready.count > 1 ? ReadyJson(ready.last) : L"null") +
                L",\"before_ready_ticks\":" + Elapsed(split.measured, slice.beginTick, pivot) +
                L",\"after_ready_ticks\":" + Elapsed(split.measured, pivot, slice.endTick) + L"}";
        }
        return out + L'}';
    }

    std::wstring FaultScheduleJson(const Scan& scan, bool gap)
    {
        const auto& fault = scan.faultPage[0];
        const auto& schedule = scan.faultSchedule;
        const auto& history = scan.history;
        const auto pair = etl_profile::FaultThreadPair(scan.threadIndex, fault, schedule.qpc, gap);
        const auto partition = schedule.Summarize(history, fault, pair, gap);
        auto out = L",\"fault_schedule\":{\"requested_fault_ordinal\":" + std::to_wstring(fault.ordinal) +
            L",\"status\":" + Quote(partition.status) + L",\"on_cpu_ticks\":" +
            (partition.measured ? Quote(std::to_wstring(partition.running)) : L"null") + L",\"off_cpu_ticks\":" +
            (partition.measured ? Quote(std::to_wstring(partition.offCpu)) : L"null") + ThreadPairJson(pair, true) +
            L",\"decoded_switches\":" + std::to_wstring(schedule.switches) + L",\"unsupported_switch_records\":" + std::to_wstring(schedule.unsupportedSwitches) +
            L",\"ready_records\":" + std::to_wstring(history.readyCount) + L",\"unsupported_ready_records\":" + std::to_wstring(history.unsupportedReady) +
            L",\"thread_boundaries\":" + std::to_wstring(history.boundaries) + L",\"unsupported_thread_boundaries\":" + std::to_wstring(history.unsupportedBoundaries) +
            L",\"intersecting_intervals\":" + std::to_wstring(schedule.candidates) + L",\"interval_limit\":" + std::to_wstring(MaxPage) + L",\"intervals\":[";
        for (const auto& slice : schedule.slices)
        {
            if (&slice != schedule.slices.data()) { out += L','; }
            out += ScheduleSliceJson(slice, history.unsupportedReady, slice.Assess(history, fault.loggerId, pair, schedule.qpc, gap || schedule.unsupportedSwitches));
        }
        return out + L"]}";
    }

    std::wstring ActivityMarkerJson(const etl_profile::ActivityMarker& m)
    {
        return L"{\"record_ordinal\":" + std::to_wstring(m.record) + L",\"raw_timestamp\":" + Quote(std::to_wstring(m.tick)) +
            L",\"provider_guid\":" + GuidJson(m.provider) + L",\"activity_id\":" + GuidJson(m.activity) +
            L",\"event_id\":" + std::to_wstring(m.eventId) + L",\"task\":" + std::to_wstring(m.task) +
            L",\"opcode\":" + std::to_wstring(m.opcode) + L",\"version\":" + std::to_wstring(m.version) +
            L",\"channel\":" + std::to_wstring(m.channel) + L",\"header_flags\":" + std::to_wstring(m.flags) + L",\"event_property\":" + std::to_wstring(m.properties) +
            L",\"logger_id\":" + std::to_wstring(m.logger) + L",\"header_process_id\":" + std::to_wstring(m.pid) +
            L",\"header_thread_id\":" + std::to_wstring(m.tid) + L"}";
    }

    std::wstring ActivityWindowJson(const etl_profile::ActivityWindow& w)
    {
        const auto issue = w.FaultIssue();
        const auto count = [&](uint32_t n) { return w.boundaryIssue ? std::wstring(L"null") : std::to_wstring(n); };
        auto out = L",\"activity_window\":{\"status\":" + Quote(issue ? issue : L"measured") +
            L",\"start\":" + ActivityMarkerJson(w.start) + L",\"stop\":" + ActivityMarkerJson(w.stop) + ThreadPairJson(w.thread, true) +
            L",\"window_ticks\":" + Elapsed(!w.WindowIssue(), w.start.tick, w.stop.tick) + L",\"fault_union_ticks\":" +
            (issue ? L"null" : Quote(std::to_wstring(w.UnionTicks()))) + L",\"process_key_boundaries\":" + (w.start.Keyed() ? std::to_wstring(w.sameKey) : L"null") +
            L",\"intervening_boundaries\":" + (w.start.Keyed() ? std::to_wstring(w.intervening) : L"null") +
            L",\"unassigned_activity_boundaries\":" + (w.start.Keyed() ? std::to_wstring(w.unassignedMarkers) : L"null") +
            L",\"decoded_faults_on_start_logger\":" + std::to_wstring(w.loggerFaults) + L",\"candidate_faults\":" + count(w.candidates) +
            L",\"untimed_thread_faults\":" + count(w.untimed) + L",\"unassigned_possible_faults\":" + count(w.ambiguousTid) +
            L",\"other_logger_thread_faults\":" + count(w.foreignLogger) + L",\"faults_outside_thread_bracket\":" + count(w.outsideLifetime) +
            L",\"fault_limit\":" + std::to_wstring(MaxPage) + L",\"overlaps\":[";
        for (const auto& r : w.rows)
        {
            if (&r != w.rows.data()) { out += L','; }
            out += L"{\"fault_ordinal\":" + std::to_wstring(r.fault.ordinal) + L",\"record_ordinal\":" + std::to_wstring(r.fault.record) +
                L",\"overlap_start_raw\":" + Quote(std::to_wstring(r.begin)) + L",\"overlap_end_raw\":" + Quote(std::to_wstring(r.end)) +
                L",\"overlap_ticks\":" + Elapsed(!issue, r.begin, r.end) + L"}";
        }
        return out + L"]}";
    }

    std::wstring ActivityScheduleJson(const Scan& scan, bool gap)
    {
        const auto& w = scan.activity;
        const auto& r = scan.residency;
        const auto& history = scan.history;
        const auto windowIssue = w.WindowIssue();
        const auto issue = r.Issue(w, history, gap);
        const auto ticks = [&](uint64_t value) { return issue ? std::wstring(L"null") : Quote(std::to_wstring(value)); };
        const auto ready = r.Readiness(history);
        auto out = L",\"activity_schedule\":{\"status\":" + Quote(issue ? issue : L"covered") +
            L",\"start\":" + ActivityMarkerJson(w.start) + L",\"stop\":" + ActivityMarkerJson(w.stop) + ThreadPairJson(w.thread, true) +
            L",\"window_ticks\":" + Elapsed(!windowIssue, w.start.tick, w.stop.tick) +
            L",\"on_cpu_ticks\":" + ticks(r.running) + L",\"off_cpu_ticks\":" + ticks(r.offCpu) +
            L",\"before_ready_ticks\":" + ticks(ready.before) + L",\"after_ready_ticks\":" + ticks(ready.after) +
            L",\"waiting_before_ready_ticks\":" + ticks(ready.waitingBefore) +
            L",\"unclassified_off_cpu_ticks\":" + ticks(r.offCpu - ready.before - ready.after) +
            L",\"off_cpu_intervals\":" + (issue ? L"null" : std::to_wstring(r.offIntervals)) +
            L",\"split_off_cpu_intervals\":" + (issue ? L"null" : std::to_wstring(ready.intervals)) +
            L",\"process_key_boundaries\":" + (w.start.Keyed() ? std::to_wstring(w.sameKey) : L"null") +
            L",\"intervening_boundaries\":" + (w.start.Keyed() ? std::to_wstring(w.intervening) : L"null") +
            L",\"unassigned_activity_boundaries\":" + (w.start.Keyed() ? std::to_wstring(w.unassignedMarkers) : L"null") +
            L",\"ready_records\":" + std::to_wstring(history.readyCount) + L",\"unsupported_ready_records\":" + std::to_wstring(history.unsupportedReady) +
            L",\"unassigned_ready_records\":" + std::to_wstring(history.unassignedReady) +
            L",\"thread_boundaries\":" + std::to_wstring(history.boundaries) + L",\"unsupported_thread_boundaries\":" + std::to_wstring(history.unsupportedBoundaries) +
            L",\"intersecting_intervals\":" + std::to_wstring(r.count) + L",\"intervals\":[";
        for (const auto& slice : r.page)
        {
            if (&slice != r.page.data()) { out += L','; }
            const auto span = windowIssue ? etl_profile::ReportedSpan{windowIssue} : slice.Assess(history, w.start.logger, w.thread, true, gap);
            out += ScheduleSliceJson(slice, history.unsupportedReady + history.unassignedReady, span);
        }
        return out + L"]}";
    }

    std::wstring HardFaultResultsJson(const Scan& scan, const TRACE_LOGFILE_HEADER& h, bool partial)
    {
        const bool qpc = h.ReservedFlags == 1 && h.PerfFreq.QuadPart > 0;
        const auto& total = scan.faultTotals;
        const auto timed = qpc ? total.ordered : 0;
        auto out = L",\"fault_summary\":{\"read_bytes\":" + Quote(std::to_wstring(total.bytes)) +
            L",\"timed_faults\":" + std::to_wstring(timed) + L",\"untimed_faults\":" + std::to_wstring(scan.decoded - timed) +
            L",\"longest_fault_ties\":" + std::to_wstring(qpc ? total.longestTies : 0) + L",\"first_longest_fault\":" +
            (timed ? HardFaultJson(total.longest, qpc) : L"null") + L"},\"hard_faults\":[";
        const auto count = scan.options.activityStart ? scan.activity.rows.size() : scan.used;
        for (size_t i = 0; i < count; ++i)
        {
            if (i) { out += L','; }
            out += HardFaultJson(scan.options.activityStart ? scan.activity.rows[i].fault : scan.faultPage[i], qpc);
        }
        out += L']';
        if (scan.options.scheduleOf) { out += FaultScheduleJson(scan, partial); }
        if (scan.options.activityStart) { out += ActivityWindowJson(scan.activity); }
        return out + L"}";
    }

    std::wstring Report(const Scan& scan, const TRACE_LOGFILE_HEADER& h, const SchemaArtifact& source, BufferAccounting accounting,
        const etl_profile::ReferenceImage* reference)
    {
        const auto clock = h.ReservedFlags == 1 ? L"qpc" : h.ReservedFlags == 2 ? L"system_time" :
            h.ReservedFlags == 3 ? L"cpu_cycle" : L"unknown";
        const bool partial = Partial(scan, accounting, h);
        const auto comparison = etl_profile::BufferComparisonName(accounting);
        auto result = std::wstring(scan.options.Prefix()) + Quote(partial ? L"partial" : L"read") + L",\"source_sha256\":" + Quote(source.Sha256) +
            L",\"source_bytes\":" + std::to_wstring(source.Bytes()) +
            (scan.options.ReadyQuery() ? L",\"provider_guid\":\"3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c\",\"event_id\":0,"
                L"\"ready_opcode\":50,\"ready_version\":2,\"switch_opcode\":36,\"switch_versions\":[2,3,4]" : scan.options.Fields().descriptor) +
            L",\"clock\":{\"raw_type\":" + std::to_wstring(h.ReservedFlags) + L",\"kind\":" + Quote(clock) +
            L",\"header_perf_frequency\":" + Quote(std::to_wstring(h.PerfFreq.QuadPart)) + L"}" +
            L",\"log_header\":{\"pointer_bytes\":" + std::to_wstring(h.PointerSize) + L",\"processors\":" + std::to_wstring(h.NumberOfProcessors) +
            L",\"start_filetime\":" + Quote(std::to_wstring(h.StartTime.QuadPart)) +
            L",\"end_filetime\":" + Quote(std::to_wstring(h.EndTime.QuadPart)) +
            L",\"log_mode\":" + std::to_wstring(h.LogFileMode) + L",\"events_lost\":" + std::to_wstring(h.EventsLost) +
            L",\"buffers_lost\":" + std::to_wstring(h.BuffersLost) + L",\"buffers_written\":" + std::to_wstring(h.BuffersWritten) + L"}" +
            (scan.options.ReadyQuery() ?
                L",\"qualification\":{\"evidence\":\"reported_readying_cpu_context\",\"producer_authenticity\":\"unverified\","
                L"\"wait_object\":null,\"wait_cause\":null,\"critical_path\":null}" : scan.options.activityMarkers ?
                L",\"qualification\":{\"evidence\":\"reported_activity_boundary\",\"producer_authenticity\":\"unverified\",\"logical_task_identity\":null}" : scan.options.SchedulingActivity() ?
                L",\"qualification\":{\"evidence\":\"reported_activity_thread_scheduling\",\"producer_authenticity\":\"unverified\","
                L"\"logical_task_identity\":null,\"wait_object\":null,\"wait_cause\":null,\"cross_thread_critical_path\":null}" : scan.options.activityStart ?
                L",\"qualification\":{\"evidence\":\"reported_activity_window_and_thread_faults\",\"producer_authenticity\":\"unverified\","
                L"\"fault_scope\":\"decoded_hard_faults_on_recorded_thread\",\"hard_fault_capture_policy\":null,"
                L"\"logical_task_identity\":null,\"wait_cause\":null,\"disk_request\":null,\"critical_path\":null}" : scan.options.scheduleOf ?
                L",\"qualification\":{\"evidence\":\"reported_hard_fault_schedule_overlap\",\"producer_authenticity\":\"unverified\","
                L"\"authenticated_thread_lifetime\":null,\"wait_cause\":null,\"file_identity\":null,\"disk_request\":null,\"critical_path\":null}" : scan.options.HardFaults() ?
                L",\"qualification\":{\"evidence\":\"reported_hard_fault\",\"producer_authenticity\":\"unverified\","
                L"\"thread_lifetime\":null,\"file_identity\":null,\"disk_request\":null,\"critical_path\":null}" : scan.options.DiskIo() ?
                L",\"qualification\":{\"evidence\":\"recorded_disk_io\",\"producer_authenticity\":\"unverified\","
                L"\"request_generation\":null,\"thread_lifetime\":null,\"device_service_time\":null,\"io_status\":null,\"cross_provider_join\":false}" :
             scan.options.WithIntervals() ?
                L",\"qualification\":{\"evidence\":\"reported_scheduler_intervals\",\"producer_authenticity\":\"unverified\","
                L"\"thread_lifetime\":null,\"process_generation\":null,\"wait_object\":null,\"wait_cause\":null,\"wait_time_unit\":null,"
                L"\"capture_enable_flags\":null,\"stack_capture_policy\":null,\"capture_privilege\":null}" : scan.options.Switches() ?
                L",\"qualification\":{\"evidence\":\"reported_context_switch\",\"producer_authenticity\":\"unverified\","
                L"\"thread_lifetime\":null,\"process_generation\":null,\"wait_duration\":null,\"wait_time_unit\":null,"
                L"\"capture_enable_flags\":null,\"stack_capture_policy\":null,\"capture_privilege\":null}" :
                L",\"qualification\":{\"evidence\":\"reported_cpu_sample\",\"producer_authenticity\":\"unverified\","
            L"\"verified_level\":\"unqualified\",\"sampled_process_id\":null,\"thread_lifetime\":null,"
            L"\"address_space\":null,\"vm\":null,\"vtl\":null,\"code_version\":null,\"capture_privilege\":null,"
            L"\"capture_enable_flags\":null,\"stack_capture_policy\":null,\"sample_loss_intervals\":null}") +
            L",\"records_seen\":" + std::to_wstring(scan.records) + scan.options.Fields().decoded + std::to_wstring(scan.decoded) +
            L",\"buffers_processed\":" + std::to_wstring(scan.processedBuffers) + L",\"buffer_comparison\":" + Quote(comparison) +
            L",\"loss_marker_records\":" + std::to_wstring(scan.lossMarkers) +
            scan.options.Fields().unsupported + std::to_wstring(scan.unsupported) +
            (scan.options.ReadyQuery() ? scan.options.ReadySelectorJson() :
                scan.options.SchedulingActivity() ? scan.options.ActivitySelectorJson() + scan.options.ActivityPagingJson() :
                L",\"after\":" + std::to_wstring(scan.options.after)) +
            L",\"next_after\":";
        const auto pageEnd = scan.options.after + (scan.options.SchedulingActivity() ? scan.residency.page.size() : scan.used);
        const auto matches = scan.options.SchedulingActivity() ? scan.residency.count : scan.matched;
        result += !scan.options.scheduleOf && pageEnd > scan.options.after && pageEnd < matches ? std::to_wstring(pageEnd) : L"null";
        if (scan.options.ReadyQuery())
        { return result + ReadyOriginJson(scan, h.ReservedFlags == 1 && h.PerfFreq.QuadPart > 0, partial) + L"}"; }
        if (scan.options.SchedulingActivity()) { return result + ActivityScheduleJson(scan, partial) + L"}"; }
        if (scan.options.DiskIo()) { return result + DiskResultsJson(scan, h); }
        if (scan.options.activityMarkers)
        {
            result += L",\"thread_filter\":" + (scan.options.haveTid ? std::to_wstring(scan.options.tid) : L"null") +
                L",\"matched_markers\":" + std::to_wstring(scan.matched) + L",\"markers\":[";
            for (size_t i = 0; i < scan.markers.size(); ++i)
            {
                const auto& [ordinal, row] = scan.markers[i];
                if (i) { result += L','; }
                result += L"{\"marker_ordinal\":" + std::to_wstring(ordinal) + L",\"event\":" + ActivityMarkerJson(row) + L"}";
            }
            return result + L"]}";
        }
        if (scan.options.HardFaults()) { return result + HardFaultResultsJson(scan, h, partial); }
        const bool comparableClock = (h.ReservedFlags == 1 && h.PerfFreq.QuadPart > 0) || h.ReservedFlags == 2;
        const bool captureGap = CaptureGap(scan, accounting, h);
        if (scan.options.settings) { result += SettingsManifestJson(scan.settings, h); }
        if (scan.options.Switches())
        {
            if (scan.options.WithIntervals())
            {
                const auto& history = scan.history;
                const auto hz = h.ReservedFlags == 2 ? 10'000'000ll : h.PerfFreq.QuadPart;
                result += L",\"interval_source\":{\"thread_filter\":" + (scan.options.haveTid ? std::to_wstring(scan.options.tid) : L"null") +
                    L",\"matched_switches\":" + std::to_wstring(scan.matched) + L",\"ticks_per_second\":" +
                    (comparableClock ? Quote(std::to_wstring(hz)) : L"null") + L",\"ready_opcode\":50,\"ready_version\":2,\"ready_records\":" +
                    std::to_wstring(history.readyCount) + L",\"unsupported_ready_records\":" + std::to_wstring(history.unsupportedReady) +
                    L",\"boundary_version\":3,\"thread_boundaries\":" + std::to_wstring(history.boundaries) +
                    L",\"unsupported_thread_boundaries\":" + std::to_wstring(history.unsupportedBoundaries) +
                    L",\"cpu_scope\":" + Quote(history.ambiguousScope ? L"unqualified" : history.seenSwitch ? L"comparable" : L"unobserved") +
                    L",\"cpus_with_tid_conflict\":" + std::to_wstring(history.cpuConflicts) +
                    L",\"cpus_with_clock_conflict\":" + std::to_wstring(history.cpuClockConflicts) +
                    L",\"unknown_switch_tid\":" + (history.unknownSwitchTid ? L"true" : L"false") +
                    L",\"scheduler_clock_reversed\":" + (history.reversedClock ? L"true}" : L"false}");
            }
            result += L",\"switches\":[";
            for (size_t i = 0; i < scan.used; ++i)
            {
                if (i) { result += L','; }
                const auto intervals = scan.options.WithIntervals() ?
                    IntervalsJson(scan, i, comparableClock, captureGap || scan.unsupported) : std::wstring{};
                result += SwitchJson(scan.switchPage[i], intervals + SettingsEvidenceJson(scan, scan.switchPage[i], comparableClock, captureGap));
            }
            return result + L"]}";
        }
        if (scan.options.WithThreads())
        {
            result += L",\"thread_source\":{\"provider_guid\":\"3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c\",\"version\":3,"
                L"\"decoded_events\":" + std::to_wstring(scan.threadIndex.decoded) +
                L",\"retained_events\":" + std::to_wstring(scan.threadIndex.events.size()) +
                L",\"unsupported_events\":" + std::to_wstring(scan.threadIndex.unsupported) + L"}";
        }
        if (scan.options.images)
        {
            result += L",\"image_source\":{\"provider_guid\":\"2cb15d1d-5fc1-11d2-abe1-00a0c911f518\",\"versions\":[2,3],"
                L"\"decoded_events\":" + std::to_wstring(scan.imageIndex.decoded) +
                L",\"retained_events\":" + std::to_wstring(scan.imageIndex.events.size()) +
                L",\"unsupported_events\":" + std::to_wstring(scan.imageIndex.unsupported) +
                L",\"retention\":" + Quote(scan.imageIndex.retention) + L"}";
        }
        if (scan.options.processes)
        {
            const auto& index = scan.processIndex;
            result += L",\"process_source\":{\"provider_guid\":\"3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c\","
                L"\"event_id\":0,\"lifecycle_opcodes\":[1,2,3,4],\"lifecycle_versions\":[2,3,4],"
                L"\"defunct_opcode\":39,\"defunct_versions\":[2,3,4,5],\"decoded_events\":" + std::to_wstring(index.decoded) +
                L",\"retained_events\":" + std::to_wstring(index.events.size()) + L",\"unsupported_events\":" +
                std::to_wstring(index.unsupported) + L",\"defunct_events\":" + std::to_wstring(index.defunct) +
                L",\"source_clock_reversed\":" + (index.processClock.reversed ? L"true" : L"false") +
                L",\"image_binding_clock_reversed\":" + (scan.options.images ? (index.imageClock.reversed ? L"true" : L"false") : L"null") +
                L",\"generation_scope\":\"source_sha256_and_start_record\",\"creation_filetime\":null}";
        }
        if (scan.options.clr)
        {
            const auto& c = scan.clrIndex;
            result += L",\"clr_source\":{\"load_events\":" + std::to_wstring(c.loads) +
                L",\"unload_events\":" + std::to_wstring(c.unloads) + L",\"rundown_events\":" + std::to_wstring(c.inventory) +
                L",\"unsupported_events\":" + std::to_wstring(c.unsupported) + L",\"unknown_pid_events\":" + std::to_wstring(c.unknownPid) +
                L",\"retained_events\":" + std::to_wstring(c.events.size()) + L",\"clock_reversed\":" + (c.clock.reversed ? L"true" : L"false") +
                L",\"runtime_bytes_observed\":false}";
        }
        const bool buildCoverage = comparableClock && !captureGap && scan.imageIndex.Complete() && !scan.imageIndex.unsupported;
        if (scan.options.builds)
        {
            const auto& index = scan.buildIndex;
            result += L",\"build_source\":{\"provider_guid\":\"b3e675d7-2554-4f18-830b-2762732560de\",\"event_id\":0,"
                L"\"version\":2,\"opcodes\":[0,32,36],\"origin\":\"merge_metadata\",\"producer_authenticity\":\"unverified\","
                L"\"runtime_bytes_observed\":false,\"decoded_events\":" + std::to_wstring(index.decoded) +
                L",\"retained_events\":" + std::to_wstring(index.events.size()) + L",\"unsupported_events\":" +
                std::to_wstring(index.unsupported) + L",\"other_opcodes\":" + std::to_wstring(index.other) +
                L",\"header_pid_conflicts\":" + std::to_wstring(index.pidConflicts) + L"}";
        }
        if (reference)
        {
            const auto& pe = reference->pe;
            result += L",\"reference_image\":{\"file_sha256\":" + Quote(reference->file.Sha256) +
                L",\"file_bytes\":" + std::to_wstring(reference->file.Bytes()) + L",\"file_name\":" + Quote(reference->leaf) +
                L",\"machine\":" + std::to_wstring(pe.Machine) + L",\"optional_magic\":" + std::to_wstring(pe.OptionalMagic) +
                L",\"image_size\":" + Hex(pe.SizeOfImage) + L",\"pe_timestamp\":" + std::to_wstring(pe.TimeDateStamp) +
                L",\"image_checksum\":" + std::to_wstring(pe.CheckSum) + L",\"preferred_base\":" + Hex(pe.ImageBase) +
                L",\"max_window_bytes\":" + std::to_wstring(etl_profile::MaxReferenceWindow) + L",\"runtime_bytes_observed\":false}";
        }
        if (reference && scan.options.builds)
        {
            const auto& b = reference->build;
            result += L",\"reference_build\":{\"status\":" + Quote(b.status) + L",\"rsds_guid\":" +
                (b.valid ? GuidJson(b.guid) : L"null") + L",\"pdb_age\":" + (b.valid ? std::to_wstring(b.age) : L"null") + L"}";
        }
        std::vector<const etl_profile::BuildEvent*> buildRecords;
        std::vector<const etl_profile::ImageEvent*> records;
        std::vector<const etl_profile::ProcessEvent*> processRecords;
        std::vector<const etl_profile::ClrPoint*> clrRecords;
        result += L",\"samples\":[";
        for (size_t i = 0; i < scan.used; ++i)
        {
            if (i) { result += L','; }
            if (scan.options.WithThreads())
            {
                const auto pair = scan.threadIndex.Lookup(scan.page[i], comparableClock, captureGap);
                std::wstring evidence;
                etl_profile::ProcessPair process;
                if (scan.options.processes)
                {
                    process = scan.processIndex.Lookup(scan.page[i], pair, comparableClock, captureGap || scan.unsupported);
                    evidence = ProcessPairJson(process, processRecords);
                    if (scan.options.clr)
                    {
                        const auto match = scan.clrIndex.Lookup(scan.page[i], process, comparableClock, captureGap);
                        evidence += ClrMatchJson(match, scan.page[i], process, clrRecords);
                    }
                }
                if (scan.options.images)
                {
                    const uint32_t pid = pair.pairedPid ? pair.before->pid : 0;
                    const auto image = scan.imageIndex.Lookup(scan.page[i], pid, comparableClock, captureGap);
                    evidence += ImageMatchJson(image, records);
                    if (scan.options.processes)
                    {
                        const auto bound = etl_profile::ImageInProcess(process, image, scan.processIndex.imageClock.reversed);
                        evidence += ImageProcessJson(process, image, bound);
                        etl_profile::BuildPair build;
                        if (scan.options.builds)
                        {
                            if (bound.paired)
                            {
                                const auto& witness = image.witnesses[0];
                                build = etl_profile::MatchBuildPair(scan.buildIndex.At(*witness.before, buildCoverage),
                                    scan.buildIndex.At(*witness.after, buildCoverage));
                            }
                            evidence += BuildPairJson(build, reference);
                        }
                        if (reference && !AppendReferenceEvidence(evidence, *reference, scan.imageIndex, image, bound,
                            scan.options.builds ? &build : nullptr)) { return {}; }
                    }
                }
                evidence += SettingsEvidenceJson(scan, scan.page[i], comparableClock, captureGap);
                result += SampleJson(scan.page[i], &pair, evidence, scan.options.processes);
            }
            else { result += SampleJson(scan.page[i], nullptr, SettingsEvidenceJson(scan, scan.page[i], comparableClock, captureGap)); }
        }
        if (scan.options.images)
        {
            AppendRecords(result, L"image_records", records, [&](const auto& e) {
                auto row = ImageEventJson(e, scan.imageIndex, scan.options.processes);
                if (scan.options.builds)
                {
                    row.pop_back();
                    row += BuildEndpointJson(scan.buildIndex.At(e, buildCoverage), buildRecords) + L"}";
                }
                return row;
            });
        }
        if (scan.options.clr) { AppendRecords(result, L"clr_records", clrRecords, ClrPointJson); }
        if (scan.options.builds) { AppendRecords(result, L"build_records", buildRecords, BuildEventJson); }
        if (scan.options.processes) { AppendRecords(result, L"process_records", processRecords, ProcessEventJson); }
        return result + L"]}";
    }

    template<class State>
    EVENT_TRACE_LOGFILEW ConfigureLog(std::wstring& volumePath, State& scan)
    {
        EVENT_TRACE_LOGFILEW log{};
        log.LogFileName = volumePath.data();
        log.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
        log.EventRecordCallback = OnRecord<State>;
        log.BufferCallback = OnBuffer<State>;
        log.Context = &scan;
        return log;
    }

    ULONG ReplayIntervals(Scan& scan, std::wstring& path, const TRACE_LOGFILE_HEADER& original)
    {
        const TraceCounts first = scan;
        static_cast<TraceCounts&>(scan) = {};
        scan.replaying = true;
        auto log = ConfigureLog(path, scan);
        Trace replay;
        replay.handle = OpenTraceW(&log);
        if (replay.handle == INVALID_PROCESSTRACE_HANDLE) { return GetLastError(); }
        const auto status = ProcessTrace(&replay.handle, 1, nullptr, nullptr);
        if (status != ERROR_SUCCESS) { return status; }
        const auto& h = log.LogfileHeader;
        const auto expectedRows = scan.options.ReadyQuery() ? scan.origins.expectedRows : scan.options.activityStart ? 2 : scan.used;
        if (scan.replayMismatch || scan.replayedRows != expectedRows || scan.budgetExceeded ||
            (scan.options.ReadyQuery() && (scan.decodedReady != scan.history.readyCount || scan.unsupportedReady != scan.history.unsupportedReady ||
                scan.unassignedReady != scan.history.unassignedReady)) ||
            ((scan.options.scheduleOf || scan.options.SchedulingActivity() || scan.options.ReadyQuery()) && (scan.threadIndex.decoded != scan.history.boundaries ||
                scan.threadIndex.unsupported != scan.history.unsupportedBoundaries)) ||
            scan.records != first.records || scan.decoded != first.decoded || scan.unsupported != first.unsupported ||
            scan.processedBuffers != first.processedBuffers || scan.lossMarkers != first.lossMarkers ||
            h.StartTime.QuadPart != original.StartTime.QuadPart || h.EndTime.QuadPart != original.EndTime.QuadPart ||
            h.BootTime.QuadPart != original.BootTime.QuadPart || h.ReservedFlags != original.ReservedFlags ||
            h.PerfFreq.QuadPart != original.PerfFreq.QuadPart || h.NumberOfProcessors != original.NumberOfProcessors ||
            h.PointerSize != original.PointerSize || h.LogFileMode != original.LogFileMode ||
            h.BuffersWritten != original.BuffersWritten || h.BuffersLost != original.BuffersLost || h.EventsLost != original.EventsLost)
        { return ERROR_INVALID_DATA; }
        return ERROR_SUCCESS;
    }

}

bool etl_profile::NormalizeDigest(const std::wstring& input, std::wstring& result)
{
    if (input.size() != 64 || input.find_first_not_of(L"0123456789abcdefABCDEF") != std::wstring::npos) { return false; }
    result = input;
    std::transform(result.begin(), result.end(), result.begin(),
        [](wchar_t c) { return c >= L'A' && c <= L'F' ? static_cast<wchar_t>(c + L'a' - L'A') : c; });
    return true;
}

static int ReadValidatedEtl(const std::vector<std::wstring>& args, Scan& scan)
{
    symbol_artifacts::Directories parents;
    SchemaArtifact source;
    std::wstring volumePath;
    DWORD openError = ERROR_SUCCESS;
    if (!OpenTraceSource(args[0], parents, source, volumePath, MaxBytes, nullptr, &openError))
    {
        return WriteWithDistinctInput(STD_OUTPUT_HANDLE, args[0], [&] {
            return Failure(scan.options, L"source_unavailable", {}, openError);
        }, true);
    }
    if (source.Sha256 != scan.options.digest) { return Failure(scan.options, L"digest_mismatch", source.Sha256); }
    symbol_artifacts::Directories referenceParents;
    etl_profile::ReferenceImage reference;
    std::wstring referenceVolumePath;
    if (!scan.options.referencePath.empty())
    {
        std::filesystem::path referencePath;
        if (!symbol_artifacts::LocalRoot(scan.options.referencePath, &referencePath) ||
            !referenceParents.Pin(referencePath.parent_path(), false) ||
            !OpenSource(referencePath, referenceParents, reference.file, referenceVolumePath, ReferenceArtifactMaxBytes))
        { return Failure(scan.options, L"reference_unavailable", source.Sha256); }
        if (source.PathNamesFile(referenceVolumePath))
        { return Failure(scan.options, L"reference_is_trace", source.Sha256, 0, reference.file.Sha256); }
        if (reference.file.Sha256 != scan.options.referenceDigest)
        { return Failure(scan.options, L"reference_digest_mismatch", source.Sha256, 0, reference.file.Sha256); }
        if (!executable_image::ReadDiskPeIdentityHandle(reference.file.Handle(), &reference.pe, nullptr))
        { return Failure(scan.options, L"reference_invalid_pe", source.Sha256, 0, reference.file.Sha256); }
        if (scan.options.builds) { reference.build = etl_profile::ReadReferenceBuild(reference.file, reference.pe); }
        reference.leaf = referencePath.filename().wstring();
    }
    auto log = ConfigureLog(volumePath, scan);
    Trace trace;
    const auto opened = trace.OpenSingle(log);
    if (opened.failure) { return Failure(scan.options, opened.failure, source.Sha256, opened.win32); }
    if (scan.options.activityMarkers)
    {
        try { scan.markers.reserve(scan.options.limit); }
        catch (const std::bad_alloc&) { return Failure(scan.options, L"marker_page_unavailable", source.Sha256); }
    }
    if (scan.options.settings)
    {
        try { scan.settings.Prepare(); }
        catch (const std::bad_alloc&) { return Failure(scan.options, L"settings_index_unavailable", source.Sha256); }
    }
    if (scan.options.NeedsThreadIndex())
    {
        try
        {
            scan.threadIndex.Prepare();
            if (scan.options.ReadyQuery()) { scan.origins.Prepare(scan.options.readyRecords.size()); }
            if (scan.options.clr) { scan.clrIndex.Prepare(); }
            if (scan.options.builds) { scan.buildIndex.Prepare(); }
            if (scan.options.images) { scan.imageIndex.Prepare(); }
            if (scan.options.processes) { scan.processIndex.Prepare(); }
        }
        catch (const std::bad_alloc&)
        { return Failure(scan.options, (scan.options.images || scan.options.processes) ? L"evidence_index_unavailable" : L"thread_index_unavailable", source.Sha256); }
    }
    const auto processed = trace.ProcessPinned(source, volumePath, scan);
    if (processed.failure)
    {
        return Failure(scan.options, processed.failure, processed.sourceChanged ? std::wstring{} : source.Sha256, processed.win32);
    }
    const auto accounting = etl_profile::AccountBuffers(log.LogfileHeader.LogFileMode, log.LogfileHeader.BuffersWritten, scan.processedBuffers);
    const bool partial = Partial(scan, accounting, log.LogfileHeader);
    if (scan.options.NeedsThreadIndex() && scan.threadIndex.Complete()) { scan.threadIndex.Sort(); }
    for (size_t i = 0; i < scan.origins.rows.size(); ++i)
    {
        const auto& origin = scan.origins.rows[i];
        if (origin.match == etl_profile::Match::Decoded) { continue; }
        const auto badRecord = scan.options.multipleReady ? scan.options.readyRecords[i] : 0;
        const auto status = !origin.observed ? L"ready_record_not_observed" :
            origin.match == etl_profile::Match::Unsupported ? L"unsupported_ready_record" : L"not_ready_thread";
        const auto sourceStatus = partial ? L"partial" : L"read";
        const auto diagnostic = scan.options.expectedPage.empty() ?
            std::wstring(scan.options.Prefix()) + Quote(status) + L",\"source_status\":" + Quote(sourceStatus) +
                L",\"source_sha256\":" + Quote(source.Sha256) + scan.options.ReadySelectorJson() +
                (badRecord ? L",\"failed_ready_record\":" + std::to_wstring(badRecord) : L"") + L",\"records_seen\":" + std::to_wstring(scan.records) + L"}" :
            ReplayReceipt(scan.options, status, source.Sha256, {}, sourceStatus, 0, {}, {}, badRecord);
        return WriteCapabilityJson(diagnostic) ? 1 : 2;
    }
    if (scan.options.activityStart && !scan.activity.stop.record)
    {
        const auto sourceStatus = partial ? L"partial" : L"read";
        const auto diagnostic = scan.options.expectedPage.empty() ?
            std::wstring(scan.options.Prefix()) + L"\"activity_record_not_observed\",\"source_status\":" + Quote(sourceStatus) +
                L",\"source_sha256\":" + Quote(source.Sha256) + scan.options.ActivitySelectorJson() + scan.options.ActivityPagingJson() +
                L",\"records_seen\":" + std::to_wstring(scan.records) + L"}" :
            ReplayReceipt(scan.options, L"activity_record_not_observed", source.Sha256, {}, sourceStatus);
        return WriteCapabilityJson(diagnostic) ? 1 : 2;
    }
    if (scan.options.scheduleOf && !scan.used)
    {
        const auto sourceStatus = partial ? L"partial" : L"read";
        const auto diagnostic = scan.options.expectedPage.empty() ?
            std::wstring(scan.options.Prefix()) + L"\"fault_not_observed\",\"source_status\":" + Quote(sourceStatus) +
                L",\"source_sha256\":" + Quote(source.Sha256) + L",\"requested_fault_ordinal\":" + std::to_wstring(scan.options.scheduleOf) +
                L",\"decoded_hard_faults\":" + std::to_wstring(scan.decoded) + L"}" :
            ReplayReceipt(scan.options, L"fault_not_observed", source.Sha256, {}, sourceStatus);
        return WriteCapabilityJson(diagnostic) ? 1 : 2;
    }
    if (!scan.options.SchedulingActivity() && !partial && scan.options.after > scan.matched) { return Failure(scan.options, L"cursor_out_of_range", source.Sha256); }
    if (scan.options.WithIntervals() || scan.options.scheduleOf || scan.options.activityStart || scan.options.ReadyQuery())
    {
        try
        {
            const bool qpc = log.LogfileHeader.ReservedFlags == 1 && log.LogfileHeader.PerfFreq.QuadPart > 0;
            if (scan.options.activityStart)
            {
                const bool markerGap = scan.options.SchedulingActivity() ? CaptureGap(scan, accounting, log.LogfileHeader) : partial;
                scan.activity.Prepare(scan.threadIndex, qpc, markerGap);
                if (scan.options.SchedulingActivity())
                {
                    scan.history.Prepare(log.LogfileHeader.NumberOfProcessors, scan.activity.start.tid);
                    scan.residency.Prepare(scan.activity.start.tick, scan.options.limit);
                }
            }
            else if (scan.options.ReadyQuery())
            {
                scan.origins.PrepareReplay(scan.history, log.LogfileHeader.NumberOfProcessors);
            }
            else if (scan.options.scheduleOf)
            {
                scan.history.Prepare(log.LogfileHeader.NumberOfProcessors, scan.faultPage[0].faultingTid);
                scan.faultSchedule.Prepare(qpc);
            }
            else { scan.history.Prepare(log.LogfileHeader.NumberOfProcessors, scan.switchPage.data(), scan.used); }
        }
        catch (const std::bad_alloc&) { return Failure(scan.options, L"interval_index_unavailable", source.Sha256); }
        const auto replay = ReplayIntervals(scan, volumePath, log.LogfileHeader);
        if (!source.PathNamesFile(volumePath) || !source.Unchanged()) { return Failure(scan.options, L"source_changed"); }
        if (replay != ERROR_SUCCESS) { return Failure(scan.options, L"interval_replay_failed", source.Sha256, replay); }
    }
    if (scan.options.SchedulingActivity() && !partial && !scan.activity.WindowIssue() && scan.options.after > scan.residency.count)
    { return Failure(scan.options, L"cursor_out_of_range", source.Sha256); }
    if (scan.options.clr && scan.clrIndex.Complete()) { scan.clrIndex.Sort(); }
    if (scan.options.images && scan.imageIndex.Complete()) { scan.imageIndex.Sort(); }
    if (scan.options.processes && scan.processIndex.Complete()) { scan.processIndex.Sort(); }
    if (scan.options.builds)
    {
        try { scan.buildIndex.Sort(scan.imageIndex); }
        catch (const std::bad_alloc&) { return Failure(scan.options, L"evidence_index_unavailable", source.Sha256); }
    }
    const bool haveReference = !scan.options.referencePath.empty();
    const auto report = Report(scan, log.LogfileHeader, source, accounting, haveReference ? &reference : nullptr);
    if (haveReference && (!reference.file.PathNamesFile(referenceVolumePath) || !reference.file.Unchanged()))
    { return Failure(scan.options, L"reference_changed", source.Sha256); }
    if (report.empty()) { return Failure(scan.options, L"reference_read_failed", source.Sha256, 0, reference.file.Sha256); }
    if (!scan.options.expectedPage.empty())
    {
        const auto bytes = CapabilityJsonFileBytes(report);
        ContentHash hash;
        if (bytes.empty() || !hash.Add(reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()))
        { return Failure(scan.options, L"page_hash_unavailable", source.Sha256); }
        const auto digest = hash.Finish();
        if (digest.empty()) { return Failure(scan.options, L"page_hash_unavailable", source.Sha256); }
        const bool match = digest == scan.options.expectedPage;
        etl_profile::CaptureStatement statement;
        const bool withStatement = !scan.options.statementPath.empty();
        if (withStatement)
        {
            statement = ReadCaptureStatement(scan.options, source);
            if (!source.PathNamesFile(volumePath) || !source.Unchanged()) { return Failure(scan.options, L"source_changed"); }
            if (haveReference && (!reference.file.PathNamesFile(referenceVolumePath) || !reference.file.Unchanged()))
            { return Failure(scan.options, L"reference_changed", source.Sha256); }
        }
        const bool accepted = !withStatement || statement.Bound();
        const auto receiptStatus = !match ? L"page_mismatch" : accepted ? L"matched" : L"capture_statement_rejected";
        const auto receipt = ReplayReceipt(scan.options, receiptStatus, source.Sha256, digest, partial ? L"partial" : L"read",
            0, haveReference ? reference.file.Sha256 : std::wstring{}, statement);
        return WriteCapabilityJson(receipt) ? (match && accepted && !partial ? 0 : 1) : 2;
    }
    return WriteCapabilityJson(report) ? (partial ? 1 : 0) : 2;
}

static int ReadSavedEtl(const std::vector<std::wstring>& args, Family family)
{
    Scan scan;
    scan.options.family = family;
    if (Parse(args, scan.options))
    {
        return WriteWithDistinctInput(STD_OUTPUT_HANDLE, scan.options.statementPath, [&] {
            return WriteWithDistinctInput(STD_OUTPUT_HANDLE, scan.options.referencePath, [&] { return ReadValidatedEtl(args, scan); });
        });
    }
    // A rejected command has no reliable operand positions. Keep a disk-backed
    // diagnostic distinct from every possible input, including misplaced paths.
    const auto sink = GetStdHandle(STD_ERROR_HANDLE);
    const bool disk = GetFileType(sink) == FILE_TYPE_DISK;
    if (disk && args.size() > MaxArguments) { return 2; }
    std::vector<DistinctArtifactInput> guards(disk ? args.size() : 0);
    for (size_t i = 0; i < guards.size(); ++i)
    {
        if (!guards[i].Hold(sink, args[i])) { return 2; }
    }
    std::wcerr << (scan.options.HardFaults() ?
        L"usage: KnLiveDbg.exe --etl-hard-faults <local.etl> --sha256 <digest> [[--activity-markers [--thread-id TID]] [--after N] [--limit 1..128] | --schedule-of <fault-ordinal> | --activity-window <start-record> <stop-record>] [--check-page <page-sha256> [--capture-statement <file.jws> <capture_controller|archive_witness> <trusted-p256-point>]]\n" : scan.options.DiskIo() ?
        L"usage: KnLiveDbg.exe --etl-disk-io <local.etl> --sha256 <digest> [--after N] [--limit 1..128] [--check-page <page-sha256> [--capture-statement <file.jws> <capture_controller|archive_witness> <trusted-p256-point>]]\n" : scan.options.Switches() ?
        L"usage: KnLiveDbg.exe --etl-switches <local.etl> --sha256 <digest> [--after N] [--limit 1..128] [[--intervals] [--thread-id N] [--capture-settings] | --schedule-activity <start-record> <stop-record>] [--check-page <page-sha256> [--capture-statement <file.jws> <capture_controller|archive_witness> <trusted-p256-point>]]\n" :
        L"usage: KnLiveDbg.exe --etl-profile <local.etl> --sha256 <digest> [--after N] [--limit 1..128] [--thread-evidence] [--image-evidence] [--process-evidence] [--clr-evidence] [--build-evidence] [--capture-settings] [--reference-image <local.pe> <pe-sha256>] [--check-page <page-sha256> [--capture-statement <file.jws> <capture_controller|archive_witness> <trusted-p256-point>]]\n");
    return 2;
}

bool etl_profile::SavedEtlInput::Open(const std::wstring& name, uint64_t maximum, DWORD* apiError)
{
    return OpenTraceSource(name, Parents, File, VolumePath, maximum, nullptr, apiError);
}

bool etl_profile::SavedEtlInput::OpenMember(const std::wstring& name, uint64_t expectedBytes, std::optional<uint64_t>& observedBytes, DWORD& apiError)
{
    return OpenTraceSource(name, Parents, File, VolumePath, expectedBytes, &observedBytes, &apiError);
}

bool etl_profile::SavedEtlInput::Revalidated()
{
    return File.PathNamesFile(VolumePath) && File.Unchanged();
}

bool etl_profile::SavedEtlInput::ReadStatement(std::vector<uint8_t>& bytes)
{
    if (File.Bytes() > MaxInventoryBytes) { return false; }
    bytes.resize(static_cast<size_t>(File.Bytes()));
    DWORD read = 0;
    return approved_file::ReadAt(File.Handle(), 0, bytes.data(), static_cast<DWORD>(bytes.size()), &read) &&
        read == bytes.size() && ContentHash::Bytes(bytes) == File.Sha256 && Revalidated();
}

void etl_profile::SavedEtlInput::Probe(SavedEtlCapabilityProbe& probe)
{
    probe.SourceSha256 = File.Sha256;
    probe.SourceBytes = File.Bytes();
    if (probe.ExpectedSha256 != File.Sha256) { probe.Status = L"digest_mismatch"; return; }

    CapabilityScan scan;
    auto log = ConfigureLog(VolumePath, scan);
    Trace trace;
    auto result = trace.OpenSingle(log);
    probe.TraceOpened = trace.handle != INVALID_PROCESSTRACE_HANDLE;
    if (!result.failure)
    {
        result = trace.ProcessPinned(File, VolumePath, scan);
        probe.SourceRevalidated = !result.sourceChanged;
    }
    if (result.failure)
    {
        probe.Status = result.failure;
        if (result.win32) { probe.Win32Status = result.win32; }
        return;
    }
    const auto& h = log.LogfileHeader;
    EtlCapabilityCoverage coverage;
    if (!scan.profile.Save(coverage.Profile) || !scan.switches.Save(coverage.Switches) ||
        !scan.disk.Save(coverage.DiskIo) || !scan.hardFault.Save(coverage.HardFault))
    {
        probe.Status = L"sample_hash_unavailable";
        return;
    }
    coverage.LogMode = h.LogFileMode;
    coverage.RecordsSeen = scan.records;
    coverage.BuffersWritten = h.BuffersWritten;
    coverage.BuffersProcessed = scan.processedBuffers;
    coverage.Accounting = etl_profile::AccountBuffers(h.LogFileMode, h.BuffersWritten, scan.processedBuffers);
    coverage.EventsLost = h.EventsLost;
    coverage.BuffersLost = h.BuffersLost;
    coverage.LossMarkers = scan.lossMarkers;
    probe.Win32Status = ERROR_SUCCESS;
    probe.Status = coverage.HasGap() ? L"partial" : L"read";
    probe.Coverage = std::move(coverage);
}

int RunEtlCapabilityProbe(const std::vector<std::wstring>& args, const std::wstring& binaryVersion)
{
    SavedEtlCapabilityProbe probe;
    const auto selector = [](const std::wstring& arg) { return _wcsicmp(arg.c_str(), capability_probes::SavedEtl.Selector) == 0; };
    if (args.size() != 4 || !selector(args[0]) || args[1].empty() || args[2] != L"--sha256" || !etl_profile::NormalizeDigest(args[3], probe.ExpectedSha256))
    {
        return WriteWithDistinctSelectedInputs(STD_ERROR_HANDLE, args, selector, [] {
            std::wcerr << L"usage: KnLiveDbg.exe " << capability_probes::Invocation(capability_probes::SavedEtl) << L"\n";
            return 2;
        });
    }
    return WriteWithDistinctInput(STD_OUTPUT_HANDLE, args[1], [&] {
        etl_profile::SavedEtlInput input;
        if (input.Open(args[1])) { input.Probe(probe); }
        if (!WriteCapabilityJson(SourceCapabilitiesJson(binaryVersion, probe))) { return 2; }
        return probe.Coverage && !probe.Coverage->HasGap() ? 0 : 1;
    });
}

int RunEtlProfile(const std::vector<std::wstring>& args)
{
    return ReadSavedEtl(args, Family::Profile);
}

int RunEtlSwitches(const std::vector<std::wstring>& args)
{
    return ReadSavedEtl(args, Family::Switches);
}

int RunEtlDiskIo(const std::vector<std::wstring>& args)
{
    return ReadSavedEtl(args, Family::DiskIo);
}

int RunEtlHardFaults(const std::vector<std::wstring>& args)
{
    return ReadSavedEtl(args, Family::HardFaults);
}
