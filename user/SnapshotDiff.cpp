#include "SnapshotDiff.h"

#include <algorithm>
#include <set>
#include <sstream>

namespace
{
    std::wstring DiffRecordKey(const SnapshotRecord& record)
    {
        return record.Domain + L"\n" + record.Identity;
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

    bool IsEscalatedRecord(const SnapshotRecord& oldRecord, const SnapshotRecord& newRecord)
    {
        bool escalated = SnapshotRiskRank(newRecord.Risk) > SnapshotRiskRank(oldRecord.Risk);

        if (!escalated && newRecord.Domain == L"drivers" && SnapshotRecordHasTag(newRecord, L"dispatch"))
        {
            escalated = EvidenceChanged(oldRecord, newRecord, L"function") ||
                EvidenceChanged(oldRecord, newRecord, L"module") ||
                EvidenceChanged(oldRecord, newRecord, L"in_loaded_module");
            if (escalated && SnapshotRiskRank(newRecord.Risk) < 2)
            {
                escalated = false;
            }
        }

        if (!escalated && newRecord.Domain == L"etw")
        {
            escalated = EvidenceChanged(oldRecord, newRecord, L"get_cpu_clock") &&
                SnapshotRiskRank(newRecord.Risk) >= 2;
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

            key = L"drivers\n" + std::wstring(L"driver:") + SnapshotToLower(driver->second);
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
        for (const SnapshotRecord& record : oldSnapshot.Records)
        {
            oldRecords[DiffRecordKey(record)] = record;
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
            else if (IsEscalatedRecord(oldIt->second, record))
            {
                SnapshotDiffFinding finding;
                finding.Kind = L"escalated";
                finding.OldRecord = oldIt->second;
                finding.NewRecord = record;
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
