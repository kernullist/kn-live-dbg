#include "SnapshotDiff.h"

#include <algorithm>
#include <set>
#include <sstream>

namespace
{
    std::wstring DiffRecordKey(
        const std::wstring& domain,
        const std::wstring& identity)
    {
        // A delimiter-only key can collide when an imported snapshot embeds
        // that delimiter in a domain or identity. Prefix the domain length so
        // every pair has one unambiguous representation.
        return std::to_wstring(domain.size()) +
            L":" +
            domain +
            identity;
    }

    std::wstring DiffRecordKey(const SnapshotRecord& record)
    {
        return DiffRecordKey(
            record.Domain,
            record.Identity);
    }

    bool DomainAllowed(const SnapshotDiffOptions& options, const std::wstring& domain)
    {
        bool allowed = true;
        if (!options.DomainFilter.empty() &&
            SnapshotToLower(options.DomainFilter) != SnapshotToLower(domain))
        {
            allowed = false;
        }
        return allowed;
    }

    uint64_t EvidenceUint64(const SnapshotRecord& record, const std::wstring& key)
    {
        uint64_t value = 0;
        auto it = record.Evidence.find(key);
        if (it != record.Evidence.end())
        {
            for (wchar_t ch : it->second)
            {
                if (ch >= L'0' && ch <= L'9')
                {
                    uint64_t digit = static_cast<uint64_t>(ch - L'0');
                    // Saturate instead of silently wrapping when a crafted
                    // snapshot supplies an oversized decimal evidence value.
                    if (value > (0xFFFFFFFFFFFFFFFFull - digit) / 10ull)
                    {
                        value = 0xFFFFFFFFFFFFFFFFull;
                        break;
                    }
                    value = (value * 10ull) + digit;
                }
                else if (value != 0)
                {
                    break;
                }
            }
        }
        return value;
    }

    bool EvidenceChanged(const SnapshotRecord& oldRecord, const SnapshotRecord& newRecord, const std::wstring& key)
    {
        std::wstring oldValue;
        std::wstring newValue;
        auto oldIt = oldRecord.Evidence.find(key);
        auto newIt = newRecord.Evidence.find(key);
        if (oldIt != oldRecord.Evidence.end())
        {
            oldValue = oldIt->second;
        }
        if (newIt != newRecord.Evidence.end())
        {
            newValue = newIt->second;
        }
        return oldValue != newValue;
    }

    bool DriverDispatchPointerChanged(
        const SnapshotRecord& oldRecord,
        const SnapshotRecord& newRecord)
    {
        auto stableNonemptyEvidence =
            [&oldRecord, &newRecord](const std::wstring& key)
            {
                auto oldValue = oldRecord.Evidence.find(key);
                auto newValue = newRecord.Evidence.find(key);
                return oldValue != oldRecord.Evidence.end() &&
                    newValue != newRecord.Evidence.end() &&
                    !oldValue->second.empty() &&
                    oldValue->second == newValue->second;
            };

        auto oldFunction =
            oldRecord.Evidence.find(L"function");
        auto newFunction =
            newRecord.Evidence.find(L"function");
        return
            newRecord.Domain == L"drivers" &&
            SnapshotRecordHasTag(oldRecord, L"dispatch") &&
            SnapshotRecordHasTag(newRecord, L"dispatch") &&
            stableNonemptyEvidence(L"driver_object") &&
            stableNonemptyEvidence(L"driver_start") &&
            oldFunction != oldRecord.Evidence.end() &&
            newFunction != newRecord.Evidence.end() &&
            !oldFunction->second.empty() &&
            !newFunction->second.empty() &&
            oldFunction->second != newFunction->second;
    }

    bool IsEscalatedRecord(
        const SnapshotRecord& oldRecord,
        const SnapshotRecord& newRecord,
        bool sameBoot)
    {
        bool escalated = SnapshotRiskRank(newRecord.Risk) > SnapshotRiskRank(oldRecord.Risk);

        if (!escalated &&
            sameBoot &&
            DriverDispatchPointerChanged(oldRecord, newRecord))
        {
            // Cross-image delegation is legitimate for many driver stacks, but
            // the actual MajorFunction pointer should remain stable within the
            // same boot. Preserve that temporal detection even when the static
            // record is intentionally low-risk telemetry.
            escalated = true;
        }

        if (!escalated &&
            sameBoot &&
            newRecord.Domain == L"etw")
        {
            escalated = EvidenceChanged(oldRecord, newRecord, L"get_cpu_clock") &&
                SnapshotRiskRank(newRecord.Risk) >= 2;
        }

        if (!escalated &&
            sameBoot &&
            newRecord.Domain == L"cpu-state")
        {
            // The kernel keeps these values/tables stable within a boot, so any
            // change to a SYSCALL MSR / control register value or an SSDT/IDT
            // routine-set fingerprint between a same-boot baseline and a later
            // snapshot is a tampering signal, regardless of risk rank.
            escalated = EvidenceChanged(oldRecord, newRecord, L"value") ||
                EvidenceChanged(oldRecord, newRecord, L"fingerprint");
        }

        if (!escalated && newRecord.Domain == L"pool")
        {
            escalated = (SnapshotRecordHasTag(newRecord, L"wx") &&
                !SnapshotRecordHasTag(oldRecord, L"wx")) ||
                (SnapshotRecordHasTag(newRecord, L"pool-pe") &&
                !SnapshotRecordHasTag(oldRecord, L"pool-pe"));
        }

        if (!escalated && newRecord.Domain == L"vad-dkom")
        {
            escalated = SnapshotRecordHasTag(newRecord, L"hidden-pte") &&
                !SnapshotRecordHasTag(oldRecord, L"hidden-pte");
        }

        return escalated;
    }

    bool IsVadScanRecord(const SnapshotRecord& record)
    {
        return record.Domain == L"vad-dkom" &&
            SnapshotRecordHasTag(record, L"process-scanned");
    }

    bool IsDriverDispatchRecord(const SnapshotRecord& record)
    {
        return record.Domain == L"drivers" &&
            SnapshotRecordHasTag(record, L"dispatch");
    }

    std::wstring DriverParentKeyFromDispatch(const SnapshotRecord& record)
    {
        std::wstring key;

        do
        {
            auto driver = record.Evidence.find(L"driver");
            if (driver == record.Evidence.end() || driver->second.empty())
            {
                break;
            }

            key = DiffRecordKey(
                L"drivers",
                std::wstring(L"driver:") +
                    SnapshotToLower(driver->second));
        } while (false);

        return key;
    }

    void AddVadScanCounters(SnapshotDiffResult* result, const SnapshotRecord& record)
    {
        if (result == nullptr || !IsVadScanRecord(record))
        {
            return;
        }

        SnapshotDiffDomainSummary& domain = result->Domains[record.Domain];
        domain.Domain = record.Domain;
        ++domain.VadNewProcesses;
        ++domain.VadScanned;
        if (SnapshotRecordHasTag(record, L"scan-failed"))
        {
            ++domain.VadFailed;
        }
    }

    int PoolPriority(const SnapshotDiffFinding& finding)
    {
        const SnapshotRecord& record = finding.NewRecord;
        if (SnapshotRecordHasTag(record, L"pool-pe-suspect"))
        {
            return 0;
        }
        if (SnapshotRecordHasTag(record, L"pool-pe"))
        {
            return 1;
        }
        if (SnapshotRecordHasTag(record, L"wx"))
        {
            return 2;
        }
        if (SnapshotRecordHasTag(record, L"large") &&
            SnapshotRecordHasTag(record, L"nonpaged"))
        {
            return 3;
        }
        return 4;
    }

    bool FindingLess(const SnapshotDiffFinding& a, const SnapshotDiffFinding& b)
    {
        bool less = false;

        uint32_t ra = SnapshotRiskRank(a.NewRecord.Risk);
        uint32_t rb = SnapshotRiskRank(b.NewRecord.Risk);
        if (ra != rb)
        {
            less = ra > rb;
            return less;
        }

        if (a.NewRecord.Domain == L"pool" && b.NewRecord.Domain == L"pool")
        {
            int pa = PoolPriority(a);
            int pb = PoolPriority(b);
            if (pa != pb)
            {
                less = pa < pb;
                return less;
            }

            uint64_t sa = EvidenceUint64(a.NewRecord, L"size");
            uint64_t sb = EvidenceUint64(b.NewRecord, L"size");
            if (sa != sb)
            {
                less = sa > sb;
                return less;
            }
        }

        if (a.NewRecord.Domain != b.NewRecord.Domain)
        {
            less = a.NewRecord.Domain < b.NewRecord.Domain;
        }
        else
        {
            less = a.NewRecord.Display < b.NewRecord.Display;
        }

        return less;
    }

    void AddDomainCounters(SnapshotDiffResult* result, const SnapshotDiffFinding& finding)
    {
        if (result == nullptr)
        {
            return;
        }

        SnapshotDiffDomainSummary& domain = result->Domains[finding.NewRecord.Domain];
        domain.Domain = finding.NewRecord.Domain;
        if (finding.Kind == L"added")
        {
            ++domain.Added;
        }
        else if (finding.Kind == L"escalated")
        {
            ++domain.Escalated;
        }

        if (SnapshotRiskRank(finding.NewRecord.Risk) >= 3)
        {
            ++domain.High;
        }
        else if (SnapshotRiskRank(finding.NewRecord.Risk) == 2)
        {
            ++domain.Medium;
        }

        if (finding.NewRecord.Domain == L"pool")
        {
            if (SnapshotRecordHasTag(finding.NewRecord, L"pool-pe-suspect"))
            {
                ++domain.PoolPeSuspect;
            }
            if (SnapshotRecordHasTag(finding.NewRecord, L"pool-pe"))
            {
                ++domain.PoolPe;
            }
            if (SnapshotRecordHasTag(finding.NewRecord, L"wx"))
            {
                ++domain.PoolWx;
            }
        }

        if (finding.NewRecord.Domain == L"vad-dkom")
        {
            if (SnapshotRecordHasTag(finding.NewRecord, L"hidden-pte"))
            {
                ++domain.VadHiddenPte;
            }
            if (SnapshotRecordHasTag(finding.NewRecord, L"wx"))
            {
                ++domain.VadWxHidden;
            }
        }
    }
}

bool BuildSnapshotDiff(
    const SnapshotDocument& oldSnapshot,
    const SnapshotDocument& newSnapshot,
    const SnapshotDiffOptions& options,
    SnapshotDiffResult* result,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid diff result output";
            }
            break;
        }

        *result = SnapshotDiffResult{};
        result->BaselineLabel = oldSnapshot.Label;
        result->CurrentLabel = newSnapshot.Label;
        bool comparableBootIds = !oldSnapshot.BootId.empty() &&
            !newSnapshot.BootId.empty() &&
            oldSnapshot.BootId != L"boot-unknown" &&
            newSnapshot.BootId != L"boot-unknown";
        result->SameBoot = options.InMemoryBaseline ||
            (oldSnapshot.SameBootOnly &&
                newSnapshot.SameBootOnly &&
                comparableBootIds &&
                oldSnapshot.BootId == newSnapshot.BootId);
        if (!result->SameBoot)
        {
            result->Warnings.push_back(L"snapshot boot identifiers differ or are missing");
        }

        auto oldFingerprint = oldSnapshot.Metadata.find(L"byovd_catalog_fingerprint");
        auto newFingerprint = newSnapshot.Metadata.find(L"byovd_catalog_fingerprint");
        if (oldFingerprint != oldSnapshot.Metadata.end() &&
            newFingerprint != newSnapshot.Metadata.end() &&
            oldFingerprint->second != newFingerprint->second)
        {
            result->Warnings.push_back(L"BYOVD catalog fingerprint changed between snapshots");
        }

        std::map<std::wstring, SnapshotRecord> oldRecords;
        bool uniqueRecords = true;
        for (const SnapshotRecord& record : oldSnapshot.Records)
        {
            const std::wstring key = DiffRecordKey(record);
            if (!oldRecords.emplace(key, record).second)
            {
                if (error != nullptr)
                {
                    *error =
                        L"baseline snapshot contains duplicate record identity: " +
                        record.Domain +
                        L"/" +
                        record.Identity;
                }
                uniqueRecords = false;
                break;
            }
        }
        if (!uniqueRecords)
        {
            break;
        }

        std::set<std::wstring> newRecordKeys;
        for (const SnapshotRecord& record : newSnapshot.Records)
        {
            if (!newRecordKeys.insert(
                    DiffRecordKey(record)).second)
            {
                if (error != nullptr)
                {
                    *error =
                        L"current snapshot contains duplicate record identity: " +
                        record.Domain +
                        L"/" +
                        record.Identity;
                }
                uniqueRecords = false;
                break;
            }
        }
        if (!uniqueRecords)
        {
            break;
        }

        std::set<std::wstring> addedDriverParents;
        for (const SnapshotRecord& record : newSnapshot.Records)
        {
            if (record.Domain != L"drivers" ||
                !SnapshotRecordHasTag(record, L"driver") ||
                !DomainAllowed(options, record.Domain))
            {
                continue;
            }

            if (oldRecords.find(DiffRecordKey(record)) == oldRecords.end())
            {
                addedDriverParents.insert(DiffRecordKey(record));
            }
        }

        for (const SnapshotRecord& record : newSnapshot.Records)
        {
            if (record.Domain == L"process")
            {
                continue;
            }

            if (!DomainAllowed(options, record.Domain))
            {
                continue;
            }

            if (IsVadScanRecord(record))
            {
                AddVadScanCounters(result, record);
                if (!SnapshotRecordHasTag(record, L"scan-failed"))
                {
                    continue;
                }
            }

            if (options.HighOnly && SnapshotRiskRank(record.Risk) < 3)
            {
                continue;
            }

            if (!options.Details &&
                SnapshotRiskRank(record.Risk) < 3 &&
                IsDriverDispatchRecord(record))
            {
                std::wstring parentKey = DriverParentKeyFromDispatch(record);
                if (!parentKey.empty() &&
                    addedDriverParents.find(parentKey) != addedDriverParents.end())
                {
                    SnapshotDiffDomainSummary& domain = result->Domains[L"drivers"];
                    domain.Domain = L"drivers";
                    ++domain.HiddenChildFindings;
                    continue;
                }
            }

            auto oldIt = oldRecords.find(DiffRecordKey(record));
            if (oldIt == oldRecords.end())
            {
                SnapshotDiffFinding finding;
                finding.Kind = L"added";
                finding.NewRecord = record;
                result->Findings.push_back(std::move(finding));
                ++result->Added;
                if (SnapshotRiskRank(record.Risk) >= 3)
                {
                    ++result->High;
                }
            }
            else if (IsEscalatedRecord(oldIt->second, record, result->SameBoot))
            {
                SnapshotDiffFinding finding;
                finding.Kind = L"escalated";
                finding.OldRecord = oldIt->second;
                finding.NewRecord = record;
                if (result->SameBoot &&
                    DriverDispatchPointerChanged(oldIt->second, record) &&
                    SnapshotRiskRank(finding.NewRecord.Risk) < 2)
                {
                    finding.NewRecord.Risk = L"medium";
                    finding.NewRecord.Tags.push_back(L"baseline-pointer-change");
                    auto oldFunction =
                        oldIt->second.Evidence.find(L"function");
                    if (oldFunction != oldIt->second.Evidence.end())
                    {
                        finding.NewRecord.Evidence[L"baseline_function"] =
                            oldFunction->second;
                    }
                }
                result->Findings.push_back(std::move(finding));
                ++result->Escalated;
                if (SnapshotRiskRank(record.Risk) >= 3)
                {
                    ++result->High;
                }
            }
        }

        std::sort(result->Findings.begin(), result->Findings.end(), FindingLess);

        for (const SnapshotDiffFinding& finding : result->Findings)
        {
            AddDomainCounters(result, finding);
        }

        ok = true;
    } while (false);

    return ok;
}

bool SnapshotDriverDispatchDiffSelfTest()
{
    SnapshotRecord oldDispatch = {};
    oldDispatch.Domain = L"drivers";
    oldDispatch.Identity = L"driver-dispatch:selftest:14";
    oldDispatch.Display = L"selftest DEVICE_CONTROL";
    oldDispatch.Risk = L"low";
    oldDispatch.Tags = {L"dispatch"};
    oldDispatch.Evidence[L"driver"] = L"selftest";
    oldDispatch.Evidence[L"driver_object"] =
        L"0xffffa00000001000";
    oldDispatch.Evidence[L"driver_start"] =
        L"0xfffff80000000000";
    oldDispatch.Evidence[L"function"] = L"0xfffff80000001000";

    SnapshotRecord newDispatch = oldDispatch;
    newDispatch.Evidence[L"function"] = L"0xfffff80000002000";

    SnapshotDocument oldSnapshot = {};
    SnapshotDocument newSnapshot = {};
    oldSnapshot.Records.push_back(oldDispatch);
    newSnapshot.Records.push_back(newDispatch);

    SnapshotDiffOptions options = {};
    options.InMemoryBaseline = true;
    options.Details = true;
    SnapshotDiffResult result = {};
    std::wstring error;
    if (!BuildSnapshotDiff(
            oldSnapshot,
            newSnapshot,
            options,
            &result,
            &error) ||
        result.Findings.size() != 1 ||
        result.Findings[0].Kind != L"escalated" ||
        result.Findings[0].NewRecord.Risk != L"medium" ||
        !SnapshotRecordHasTag(
            result.Findings[0].NewRecord,
            L"baseline-pointer-change"))
    {
        return false;
    }

    SnapshotDocument reloadedSnapshot = newSnapshot;
    reloadedSnapshot.Records[0].Evidence[L"driver_object"] =
        L"0xffffa00000002000";
    SnapshotDiffResult reloadedResult = {};
    if (!BuildSnapshotDiff(
            oldSnapshot,
            reloadedSnapshot,
            options,
            &reloadedResult,
            &error) ||
        !reloadedResult.Findings.empty())
    {
        return false;
    }

    SnapshotDocument typeChangedBaseline = oldSnapshot;
    typeChangedBaseline.Records[0].Tags.clear();
    SnapshotDiffResult typeChangedResult = {};
    if (!BuildSnapshotDiff(
            typeChangedBaseline,
            newSnapshot,
            options,
            &typeChangedResult,
            &error) ||
        !typeChangedResult.Findings.empty())
    {
        return false;
    }

    SnapshotDocument missingFunctionBaseline = oldSnapshot;
    missingFunctionBaseline.Records[0].Evidence.erase(
        L"function");
    SnapshotDiffResult missingFunctionResult = {};
    if (!BuildSnapshotDiff(
            missingFunctionBaseline,
            newSnapshot,
            options,
            &missingFunctionResult,
            &error) ||
        !missingFunctionResult.Findings.empty())
    {
        return false;
    }

    SnapshotDocument duplicateBaseline = oldSnapshot;
    duplicateBaseline.Records.push_back(oldDispatch);
    SnapshotDiffResult duplicateResult = {};
    if (BuildSnapshotDiff(
            duplicateBaseline,
            newSnapshot,
            options,
            &duplicateResult,
            &error))
    {
        return false;
    }

    SnapshotRecord collisionA = {};
    collisionA.Domain = L"a";
    collisionA.Identity = L"b\nc";
    collisionA.Risk = L"low";
    SnapshotRecord collisionB = {};
    collisionB.Domain = L"a\nb";
    collisionB.Identity = L"c";
    collisionB.Risk = L"low";
    SnapshotDocument collisionOld = {};
    collisionOld.Records = {collisionA, collisionB};
    SnapshotDocument collisionNew = collisionOld;
    SnapshotDiffResult collisionResult = {};
    if (!BuildSnapshotDiff(
            collisionOld,
            collisionNew,
            options,
            &collisionResult,
            &error) ||
        !collisionResult.Findings.empty())
    {
        return false;
    }

    oldSnapshot.SameBootOnly = true;
    newSnapshot.SameBootOnly = true;
    oldSnapshot.BootId = L"boot-a";
    newSnapshot.BootId = L"boot-b";
    options.InMemoryBaseline = false;
    result = {};
    if (!BuildSnapshotDiff(
            oldSnapshot,
            newSnapshot,
            options,
            &result,
            &error) ||
        result.SameBoot ||
        !result.Findings.empty())
    {
        return false;
    }

    SnapshotRecord oldEtw = {};
    oldEtw.Domain = L"etw";
    oldEtw.Identity = L"logger:selftest";
    oldEtw.Risk = L"medium";
    oldEtw.Evidence[L"get_cpu_clock"] =
        L"0xfffff80000001000";
    SnapshotRecord newEtw = oldEtw;
    newEtw.Evidence[L"get_cpu_clock"] =
        L"0xfffff80000002000";
    SnapshotDocument oldEtwSnapshot = {};
    SnapshotDocument newEtwSnapshot = {};
    oldEtwSnapshot.SameBootOnly = true;
    newEtwSnapshot.SameBootOnly = true;
    oldEtwSnapshot.BootId = L"boot-a";
    newEtwSnapshot.BootId = L"boot-b";
    oldEtwSnapshot.Records.push_back(oldEtw);
    newEtwSnapshot.Records.push_back(newEtw);
    SnapshotDiffResult etwResult = {};
    if (!BuildSnapshotDiff(
            oldEtwSnapshot,
            newEtwSnapshot,
            options,
            &etwResult,
            &error) ||
        etwResult.SameBoot ||
        !etwResult.Findings.empty())
    {
        return false;
    }

    // A normal risk-rank change remains reportable across boots, but a
    // coincidental dispatch-address change must not acquire the stronger
    // same-boot pointer-change label or risk promotion.
    oldSnapshot.Records[0].Risk = L"info";
    result = {};
    return BuildSnapshotDiff(
               oldSnapshot,
               newSnapshot,
               options,
               &result,
               &error) &&
        !result.SameBoot &&
        result.Findings.size() == 1 &&
        result.Findings[0].NewRecord.Risk == L"low" &&
        !SnapshotRecordHasTag(
            result.Findings[0].NewRecord,
            L"baseline-pointer-change");
}
