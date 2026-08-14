#include "SnapshotPrinter.h"

#include "SnapshotJson.h"

#include <iostream>
#include <map>
#include <sstream>

namespace
{
    std::wstring EvidenceValue(const SnapshotRecord& record, const std::wstring& key)
    {
        std::wstring value;
        auto it = record.Evidence.find(key);
        if (it != record.Evidence.end())
        {
            value = it->second;
        }
        return value;
    }

    std::wstring FollowUpForRecord(const SnapshotRecord& record)
    {
        std::wstring follow;

        if (record.Domain == L"pool")
        {
            if (SnapshotRecordHasTag(record, L"pool-pe"))
            {
                follow = L"pool-scan-pe /tag " + EvidenceValue(record, L"tag") + L" /dump .\\poolpe-hits";
            }
            else if (SnapshotRecordHasTag(record, L"wx"))
            {
                follow = L"!pool find /addr " + EvidenceValue(record, L"address") + L" /annotate";
            }
        }
        else if (record.Domain == L"vad-dkom")
        {
            follow = L"!vad " + EvidenceValue(record, L"eprocess") + L" /hiddenpte";
        }
        else if (record.Domain == L"drivers")
        {
            std::wstring driver = EvidenceValue(record, L"driver");
            if (driver.empty())
            {
                driver = EvidenceValue(record, L"name");
            }
            follow = driver.empty()
                ? L"!driver integrity"
                : L"!driver integrity " + driver;
        }
        else if (record.Domain == L"modules")
        {
            follow = L"!module integrity " + EvidenceValue(record, L"image") + L" /headers /sections";
        }
        else if (record.Domain == L"callbacks")
        {
            follow = L"callbacks all " + EvidenceValue(record, L"function_module");
        }
        else if (record.Domain == L"byovd")
        {
            follow = L"byovd scan /no-update";
        }
        else if (record.Domain == L"etw")
        {
            follow = L"!etw integrity";
        }
        else if (record.Domain == L"nmi")
        {
            follow = L"!nmi callbacks";
        }
        else if (record.Domain == L"fwtable")
        {
            follow = L"!fwtable providers";
        }

        return follow;
    }

    bool ShouldPrintFinding(const SnapshotDiffFinding& finding, const SnapshotDiffOptions& options)
    {
        bool print = true;
        if (options.HighOnly && SnapshotRiskRank(finding.NewRecord.Risk) < 3)
        {
            print = false;
        }
        return print;
    }

    uint32_t PrintedLimit(const SnapshotDiffOptions& options)
    {
        return options.Limit == 0 ? 0xffffffffu : options.Limit;
    }

    void AppendFindingMarkdown(std::wstringstream& stream, const SnapshotDiffFinding& finding)
    {
        const SnapshotRecord& record = finding.NewRecord;
        stream << L"- `" << finding.Kind << L"` **" << record.Domain << L"** ["
               << record.Risk << L"] " << record.Display << L"\n";
        stream << L"  - identity: `" << record.Identity << L"`\n";
        stream << L"  - tags: ";
        for (size_t i = 0; i < record.Tags.size(); ++i)
        {
            if (i != 0)
            {
                stream << L", ";
            }
            stream << L"`" << record.Tags[i] << L"`";
        }
        stream << L"\n";

        uint32_t emitted = 0;
        for (const auto& item : record.Evidence)
        {
            if (emitted >= 8)
            {
                stream << L"  - evidence: additional fields elided\n";
                break;
            }
            stream << L"  - " << item.first << L": `" << item.second << L"`\n";
            ++emitted;
        }

        std::wstring follow = FollowUpForRecord(record);
        if (!follow.empty())
        {
            stream << L"  - follow-up: `" << follow << L"`\n";
        }
    }
}

void PrintSnapshotSummary(const SnapshotDocument& document, bool domains, bool warnings)
{
    std::wcout << L"[snapshot] label=" << document.Label
               << L" ts=" << document.TimestampUtc
               << L" records=" << document.Records.size()
               << L" processes=" << document.Processes.size();
    if (!document.JsonPath.empty())
    {
        std::wcout << L" json=" << document.JsonPath;
    }
    if (!document.ReportPath.empty())
    {
        std::wcout << L" report=" << document.ReportPath;
    }
    std::wcout << L"\n";

    if (domains)
    {
        std::vector<SnapshotDomainCount> counts = BuildSnapshotDomainCounts(document);
        for (const SnapshotDomainCount& count : counts)
        {
            std::wcout << L"[snapshot." << count.Domain << L"] records=" << count.Records
                       << L" high=" << count.High
                       << L" medium=" << count.Medium
                       << L" low=" << count.Low
                       << L" info=" << count.Info << L"\n";
        }
    }

    if (warnings)
    {
        for (const auto& item : document.DomainWarnings)
        {
            for (const std::wstring& warning : item.second)
            {
                std::wcout << L"[snapshot.warning] domain=" << item.first
                           << L" " << warning << L"\n";
            }
        }
    }
}

void PrintSnapshotDiff(const SnapshotDiffResult& diff, const SnapshotDiffOptions& options)
{
    std::wcout << L"[diff] baseline=" << diff.BaselineLabel
               << L" current=" << diff.CurrentLabel
               << L" sameBoot=" << (diff.SameBoot ? L"yes" : L"no")
               << L" added=" << diff.Added
               << L" escalated=" << diff.Escalated
               << L" removed=" << diff.Removed
               << L" high=" << diff.High;
    if (!diff.ReportPath.empty())
    {
        std::wcout << L" report=" << diff.ReportPath;
    }
    std::wcout << L"\n";

    for (const std::wstring& warning : diff.Warnings)
    {
        std::wcout << L"[diff.warning] " << warning << L"\n";
    }

    for (const auto& item : diff.Domains)
    {
        const SnapshotDiffDomainSummary& domain = item.second;
        if (domain.Domain == L"pool")
        {
            uint64_t shown = 0;
            for (const SnapshotDiffFinding& finding : diff.Findings)
            {
                if (finding.NewRecord.Domain == L"pool" && ShouldPrintFinding(finding, options))
                {
                    ++shown;
                }
            }
            uint64_t hidden = shown > PrintedLimit(options) ? shown - PrintedLimit(options) : 0;
            if (shown > PrintedLimit(options))
            {
                shown = PrintedLimit(options);
            }
            std::wcout << L"[diff.pool] added=" << domain.Added
                       << L" removed=" << domain.Removed
                       << L" peSuspect=" << domain.PoolPeSuspect
                       << L" pe=" << domain.PoolPe
                       << L" wx=" << domain.PoolWx
                       << L" shown=" << shown
                       << L" hidden=" << hidden << L"\n";
        }
        else if (domain.Domain == L"vad-dkom")
        {
            std::wcout << L"[diff.vad-dkom] newProcesses=" << domain.VadNewProcesses
                       << L" scanned=" << domain.VadScanned
                       << L" hiddenPte=" << domain.VadHiddenPte
                       << L" wxHidden=" << domain.VadWxHidden
                       << L" failed=" << domain.VadFailed << L"\n";
        }
        else
        {
            std::wcout << L"[diff." << domain.Domain << L"] added=" << domain.Added
                       << L" escalated=" << domain.Escalated
                       << L" removed=" << domain.Removed
                       << L" high=" << domain.High
                       << L" medium=" << domain.Medium;
            if (domain.HiddenChildFindings != 0)
            {
                std::wcout << L" hiddenChildren=" << domain.HiddenChildFindings;
            }
            std::wcout << L"\n";
        }
    }

    if (options.SummaryOnly)
    {
        return;
    }

    std::map<std::wstring, uint32_t> printedByDomain;
    for (const SnapshotDiffFinding& finding : diff.Findings)
    {
        if (!ShouldPrintFinding(finding, options))
        {
            continue;
        }

        uint32_t& printed = printedByDomain[finding.NewRecord.Domain];
        if (printed >= PrintedLimit(options))
        {
            continue;
        }
        ++printed;

        const SnapshotRecord& record = finding.NewRecord;
        std::wcout << L"  "
                   << (finding.Kind == L"added"
                           ? L"+"
                           : (finding.Kind == L"removed"
                                  ? L"-"
                                  : L"~"))
                   << L" [" << record.Risk << L"] "
                   << record.Domain << L" " << record.Display << L"\n";
        std::wcout << L"    identity=" << record.Identity << L"\n";

        if (record.Domain == L"pool")
        {
            std::wcout << L"    evidence: tag=" << EvidenceValue(record, L"tag")
                       << L" size=" << EvidenceValue(record, L"size")
                       << L" addr=" << EvidenceValue(record, L"address")
                       << L" wx=" << EvidenceValue(record, L"writable") << L"/"
                       << EvidenceValue(record, L"executable") << L"\n";
        }
        else if (record.Domain == L"vad-dkom")
        {
            std::wcout << L"    evidence: process=" << EvidenceValue(record, L"image")
                       << L" pid=" << EvidenceValue(record, L"pid")
                       << L" start=" << EvidenceValue(record, L"start")
                       << L" size=" << EvidenceValue(record, L"size")
                       << L" wx=" << EvidenceValue(record, L"writable") << L"/"
                       << EvidenceValue(record, L"executable") << L"\n";
        }
        else if (record.Domain == L"drivers" && SnapshotRecordHasTag(record, L"driver"))
        {
            std::wcout << L"    evidence: name=" << EvidenceValue(record, L"name")
                       << L" object=" << EvidenceValue(record, L"object")
                       << L" size=" << EvidenceValue(record, L"size")
                       << L" owning_module=" << EvidenceValue(record, L"owning_module")
                       << L" suspicious_dispatch=" << EvidenceValue(record, L"suspicious_dispatch_count")
                       << L"\n";
        }
        else
        {
            uint32_t emitted = 0;
            std::wcout << L"    evidence:";
            for (const auto& item : record.Evidence)
            {
                if (emitted >= 4)
                {
                    break;
                }
                std::wcout << L" " << item.first << L"=" << item.second;
                ++emitted;
            }
            std::wcout << L"\n";
        }

        std::wstring follow = FollowUpForRecord(record);
        if (!follow.empty())
        {
            std::wcout << L"    next: " << follow << L"\n";
        }
    }
}

std::wstring BuildSnapshotBaselineMarkdown(const SnapshotDocument& document)
{
    std::wstringstream stream;
    stream << L"# Kn Live Dbg Baseline Snapshot\n\n";
    stream << L"- label: `" << document.Label << L"`\n";
    stream << L"- timestamp: `" << document.TimestampUtc << L"`\n";
    stream << L"- records: `" << document.Records.size() << L"`\n";
    stream << L"- processes: `" << document.Processes.size() << L"`\n";
    stream << L"- json: `" << document.JsonPath << L"`\n\n";

    stream << L"## Domain Counts\n\n";
    for (const SnapshotDomainCount& count : BuildSnapshotDomainCounts(document))
    {
        stream << L"- `" << count.Domain << L"` records=" << count.Records
               << L" high=" << count.High
               << L" medium=" << count.Medium
               << L" low=" << count.Low
               << L" info=" << count.Info << L"\n";
    }

    stream << L"\n## High Risk Records\n\n";
    uint32_t emitted = 0;
    for (const SnapshotRecord& record : document.Records)
    {
        if (SnapshotRiskRank(record.Risk) < 3)
        {
            continue;
        }
        stream << L"- **" << record.Domain << L"** " << record.Display
               << L" identity=`" << record.Identity << L"`\n";
        ++emitted;
        if (emitted >= 40)
        {
            stream << L"- additional high-risk records elided\n";
            break;
        }
    }
    if (emitted == 0)
    {
        stream << L"- none\n";
    }

    stream << L"\n## Warnings\n\n";
    bool anyWarning = false;
    for (const auto& item : document.DomainWarnings)
    {
        for (const std::wstring& warning : item.second)
        {
            stream << L"- `" << item.first << L"` " << warning << L"\n";
            anyWarning = true;
        }
    }
    if (!anyWarning)
    {
        stream << L"- none\n";
    }

    return stream.str();
}

std::wstring BuildSnapshotDiffMarkdown(const SnapshotDiffResult& diff, const SnapshotDiffOptions& options)
{
    std::wstringstream stream;
    stream << L"# Kn Live Dbg Snapshot Diff\n\n";
    stream << L"- baseline: `" << diff.BaselineLabel << L"`\n";
    stream << L"- current: `" << diff.CurrentLabel << L"`\n";
    stream << L"- same boot: `" << (diff.SameBoot ? L"yes" : L"no") << L"`\n";
    stream << L"- added: `" << diff.Added << L"`\n";
    stream << L"- escalated: `" << diff.Escalated << L"`\n";
    stream << L"- removed: `" << diff.Removed << L"`\n";
    stream << L"- high: `" << diff.High << L"`\n\n";

    stream << L"## Domain Summary\n\n";
    for (const auto& item : diff.Domains)
    {
        const SnapshotDiffDomainSummary& domain = item.second;
        stream << L"- `" << domain.Domain << L"` added=" << domain.Added
               << L" escalated=" << domain.Escalated
               << L" removed=" << domain.Removed
               << L" high=" << domain.High
               << L" medium=" << domain.Medium;
        if (domain.HiddenChildFindings != 0)
        {
            stream << L" hiddenChildren=" << domain.HiddenChildFindings;
        }
        if (domain.Domain == L"pool")
        {
            stream << L" peSuspect=" << domain.PoolPeSuspect
                   << L" pe=" << domain.PoolPe
                   << L" wx=" << domain.PoolWx;
        }
        if (domain.Domain == L"vad-dkom")
        {
            stream << L" newProcesses=" << domain.VadNewProcesses
                   << L" hiddenPte=" << domain.VadHiddenPte
                   << L" wxHidden=" << domain.VadWxHidden;
        }
        stream << L"\n";
    }

    stream << L"\n## Top Findings\n\n";
    uint64_t emitted = 0;
    uint64_t limit = static_cast<uint64_t>(PrintedLimit(options)) * 4ull;
    for (const SnapshotDiffFinding& finding : diff.Findings)
    {
        if (!ShouldPrintFinding(finding, options))
        {
            continue;
        }
        AppendFindingMarkdown(stream, finding);
        ++emitted;
        if (emitted >= limit)
        {
            stream << L"- additional findings elided\n";
            break;
        }
    }
    if (emitted == 0)
    {
        stream << L"- none\n";
    }

    stream << L"\n## Warnings\n\n";
    if (diff.Warnings.empty())
    {
        stream << L"- none\n";
    }
    else
    {
        for (const std::wstring& warning : diff.Warnings)
        {
            stream << L"- " << warning << L"\n";
        }
    }

    return stream.str();
}
