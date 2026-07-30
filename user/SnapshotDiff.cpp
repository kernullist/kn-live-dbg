#include "SnapshotDiff.h"

#include <algorithm>
#include <limits>
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

    bool TryEvidenceByteStrict(
        const SnapshotRecord& record,
        const std::wstring& key,
        uint8_t* parsed)
    {
        if (parsed == nullptr)
        {
            return false;
        }
        *parsed = 0;

        const auto item =
            record.Evidence.find(key);
        if (item == record.Evidence.end() ||
            item->second.empty())
        {
            return false;
        }

        uint64_t value = 0;
        for (const wchar_t ch : item->second)
        {
            if (ch < L'0' || ch > L'9')
            {
                return false;
            }
            const uint64_t digit =
                static_cast<uint64_t>(
                    ch - L'0');
            if (value >
                (std::numeric_limits<uint8_t>::max() -
                 digit) /
                    10)
            {
                return false;
            }
            value = value * 10 + digit;
        }
        *parsed = static_cast<uint8_t>(value);
        return true;
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

    bool NonEmptyEvidenceChanged(
        const SnapshotRecord& oldRecord,
        const SnapshotRecord& newRecord,
        const std::wstring& key)
    {
        auto oldValue = oldRecord.Evidence.find(key);
        auto newValue = newRecord.Evidence.find(key);
        return oldValue != oldRecord.Evidence.end() &&
            newValue != newRecord.Evidence.end() &&
            !oldValue->second.empty() &&
            !newValue->second.empty() &&
            oldValue->second != newValue->second;
    }

    bool SnapshotMetadataTrue(
        const SnapshotDocument& snapshot,
        const std::wstring& key)
    {
        auto value = snapshot.Metadata.find(key);
        return value != snapshot.Metadata.end() &&
            SnapshotToLower(value->second) == L"true";
    }

    std::wstring SnapshotLeafName(const std::wstring& value)
    {
        size_t separator = value.find_last_of(L"\\/");
        return SnapshotToLower(
            separator == std::wstring::npos
                ? value
                : value.substr(separator + 1));
    }

    bool ProcessProtectionChanged(
        const SnapshotRecord& oldRecord,
        const SnapshotRecord& newRecord)
    {
        uint8_t oldProtection = 0;
        uint8_t newProtection = 0;
        return oldRecord.Domain ==
                L"process-security" &&
            newRecord.Domain == L"process-security" &&
            SnapshotRecordHasTag(oldRecord, L"process-protection") &&
            SnapshotRecordHasTag(newRecord, L"process-protection") &&
            TryEvidenceByteStrict(
                oldRecord,
                L"protection_raw",
                &oldProtection) &&
            TryEvidenceByteStrict(
                newRecord,
                L"protection_raw",
                &newProtection) &&
            oldProtection != newProtection;
    }

    bool ProcessProtectionDowngraded(
        const SnapshotRecord& oldRecord,
        const SnapshotRecord& newRecord)
    {
        uint8_t oldProtectionByte = 0;
        uint8_t newProtectionByte = 0;
        if (!TryEvidenceByteStrict(
                oldRecord,
                L"protection_raw",
                &oldProtectionByte) ||
            !TryEvidenceByteStrict(
                newRecord,
                L"protection_raw",
                &newProtectionByte))
        {
            return false;
        }
        const uint64_t oldProtection =
            oldProtectionByte;
        const uint64_t newProtection =
            newProtectionByte;
        const uint64_t oldType = oldProtection & 0x7ull;
        const uint64_t newType = newProtection & 0x7ull;
        const uint64_t oldSigner = (oldProtection >> 4) & 0xfull;
        const uint64_t newSigner = (newProtection >> 4) & 0xfull;
        return oldProtection != 0 &&
            (newProtection == 0 ||
             newType < oldType ||
             newSigner < oldSigner);
    }

    bool ProcessProtectionOwnerStillPresent(
        const SnapshotRecord& protection,
        const SnapshotDocument& current)
    {
        static const std::wstring prefix =
            L"process-security:";
        if (protection.Identity.size() <=
                prefix.size() ||
            protection.Identity.compare(
                0,
                prefix.size(),
                prefix) != 0)
        {
            return false;
        }

        const std::wstring processIdentity =
            protection.Identity.substr(
                prefix.size());
        return std::any_of(
            current.Records.begin(),
            current.Records.end(),
            [&](const SnapshotRecord& record)
            {
                return record.Domain ==
                        L"process" &&
                    record.Identity ==
                        processIdentity;
            });
    }

    std::wstring EvidenceText(
        const SnapshotRecord& record,
        const std::wstring& key)
    {
        auto value = record.Evidence.find(key);
        return value == record.Evidence.end()
            ? L""
            : value->second;
    }

    bool MinifilterAttachmentDetachedTransition(
        const SnapshotRecord& baseline,
        const SnapshotRecord& current)
    {
        return
            baseline.Domain ==
                L"minifilter-attachments" &&
            current.Domain ==
                L"minifilter-attachments" &&
            SnapshotRecordHasTag(
                baseline,
                L"minifilter-attachment") &&
            SnapshotRecordHasTag(
                current,
                L"minifilter-attachment") &&
            SnapshotToLower(
                EvidenceText(
                    baseline,
                    L"detached_volume")) ==
                L"false" &&
            SnapshotToLower(
                EvidenceText(
                    current,
                    L"detached_volume")) ==
                L"true";
    }

    bool MinifilterVolumeStillPresent(
        const SnapshotRecord& attachment,
        const SnapshotDocument& current)
    {
        const std::wstring expected =
            SnapshotToLower(
                EvidenceText(
                    attachment,
                    L"volume_name"));
        if (expected.empty())
        {
            return false;
        }

        for (const SnapshotRecord& record :
             current.Records)
        {
            if (record.Domain !=
                    L"minifilter-attachments" ||
                !SnapshotRecordHasTag(
                    record,
                    L"minifilter-volume"))
            {
                continue;
            }
            if (SnapshotToLower(
                    EvidenceText(
                        record,
                        L"volume_name")) ==
                expected)
            {
                return true;
            }
        }
        return false;
    }

    bool MinifilterStillRegistered(
        const SnapshotRecord& attachment,
        const SnapshotDocument& current)
    {
        const std::wstring expected =
            SnapshotToLower(
                EvidenceText(
                    attachment,
                    L"filter_name"));
        if (expected.empty())
        {
            return false;
        }

        for (const SnapshotRecord& record :
             current.Records)
        {
            if (record.Domain != L"callbacks" ||
                !SnapshotRecordHasTag(
                    record,
                    L"callback") ||
                SnapshotToLower(
                    EvidenceText(
                        record,
                        L"kind")) !=
                    L"minifilter")
            {
                continue;
            }
            if (SnapshotToLower(
                    EvidenceText(
                        record,
                        L"target")) ==
                expected)
            {
                return true;
            }
        }
        return false;
    }

    bool CleanMinifilterAttachmentSemanticallyPresent(
        const SnapshotRecord& baseline,
        const SnapshotDocument& current)
    {
        const std::wstring expectedFilter =
            SnapshotToLower(
                EvidenceText(
                    baseline,
                    L"filter_name"));
        const std::wstring expectedVolume =
            SnapshotToLower(
                EvidenceText(
                    baseline,
                    L"volume_name"));
        const std::wstring expectedAltitude =
            SnapshotToLower(
                EvidenceText(
                    baseline,
                    L"altitude"));
        const std::wstring expectedInstance =
            SnapshotToLower(
                EvidenceText(
                    baseline,
                    L"instance_name"));
        if (expectedFilter.empty() ||
            expectedVolume.empty() ||
            (expectedAltitude.empty() &&
             expectedInstance.empty()))
        {
            return false;
        }

        for (const SnapshotRecord& record :
             current.Records)
        {
            if (record.Domain !=
                    L"minifilter-attachments" ||
                !SnapshotRecordHasTag(
                    record,
                    L"minifilter-attachment") ||
                SnapshotToLower(
                    EvidenceText(
                        record,
                        L"kind")) !=
                    L"minifilter" ||
                SnapshotToLower(
                    EvidenceText(
                        record,
                        L"filter_name")) !=
                    expectedFilter ||
                SnapshotToLower(
                    EvidenceText(
                        record,
                        L"volume_name")) !=
                    expectedVolume)
            {
                continue;
            }

            if (SnapshotToLower(
                    EvidenceText(
                        record,
                        L"detached_volume")) !=
                    L"true" &&
                ((!expectedAltitude.empty() &&
                  SnapshotToLower(
                      EvidenceText(
                          record,
                          L"altitude")) ==
                      expectedAltitude) ||
                 (expectedAltitude.empty() &&
                  !expectedInstance.empty() &&
                  SnapshotToLower(
                      EvidenceText(
                          record,
                          L"instance_name")) ==
                      expectedInstance)))
            {
                return true;
            }
        }
        return false;
    }

    bool CallbackOwnerStillLoaded(
        const SnapshotRecord& callback,
        const SnapshotDocument& current)
    {
        auto owner = callback.Evidence.find(L"function_module");
        if (owner == callback.Evidence.end() || owner->second.empty())
        {
            return false;
        }

        const std::wstring ownerLeaf =
            SnapshotLeafName(owner->second);
        if (ownerLeaf.empty())
        {
            return false;
        }

        for (const SnapshotRecord& record : current.Records)
        {
            if (record.Domain != L"modules" ||
                !SnapshotRecordHasTag(record, L"module"))
            {
                continue;
            }

            auto image = record.Evidence.find(L"image");
            if (image != record.Evidence.end() &&
                SnapshotLeafName(image->second) == ownerLeaf)
            {
                return true;
            }
            if (SnapshotLeafName(record.Display) == ownerLeaf)
            {
                return true;
            }
        }

        return false;
    }

    bool CallbackSemanticIdentityMatches(
        const SnapshotRecord& baseline,
        const SnapshotRecord& current)
    {
        if (baseline.Domain != L"callbacks" ||
            current.Domain != L"callbacks" ||
            !SnapshotRecordHasTag(baseline, L"callback") ||
            !SnapshotRecordHasTag(current, L"callback"))
        {
            return false;
        }

        static const wchar_t* kRequiredIdentityFields[] =
        {
            L"kind",
            L"function",
            L"function_module"
        };
        for (const wchar_t* field : kRequiredIdentityFields)
        {
            auto oldValue = baseline.Evidence.find(field);
            auto newValue = current.Evidence.find(field);
            if (oldValue == baseline.Evidence.end() ||
                newValue == current.Evidence.end() ||
                oldValue->second.empty() ||
                SnapshotToLower(oldValue->second) !=
                    SnapshotToLower(newValue->second))
            {
                return false;
            }
        }

        auto oldTarget = baseline.Evidence.find(L"target");
        auto newTarget = current.Evidence.find(L"target");
        const std::wstring oldTargetValue =
            oldTarget == baseline.Evidence.end()
                ? L""
                : SnapshotToLower(oldTarget->second);
        const std::wstring newTargetValue =
            newTarget == current.Evidence.end()
                ? L""
                : SnapshotToLower(newTarget->second);
        return oldTargetValue == newTargetValue;
    }

    bool CallbackSemanticallyPresent(
        const SnapshotRecord& baseline,
        const SnapshotDocument& current)
    {
        for (const SnapshotRecord& record : current.Records)
        {
            if (CallbackSemanticIdentityMatches(
                    baseline,
                    record))
            {
                return true;
            }
        }
        return false;
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
        bool sameBoot,
        bool minifilterAttachmentCoverageComplete)
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
            ProcessProtectionChanged(oldRecord, newRecord))
        {
            escalated = true;
        }

        if (!escalated &&
            sameBoot &&
            minifilterAttachmentCoverageComplete &&
            MinifilterAttachmentDetachedTransition(
                oldRecord,
                newRecord))
        {
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
        else if (finding.Kind == L"removed")
        {
            ++domain.Removed;
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
    if (error != nullptr)
    {
        error->clear();
    }

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

        const bool callbackCoverageComplete =
            SnapshotMetadataTrue(
                newSnapshot,
                L"callbacks_coverage_complete");
        const bool moduleCoverageComplete =
            SnapshotMetadataTrue(
                newSnapshot,
                L"modules_coverage_complete");
        const bool
            minifilterAttachmentCoverageComplete =
                SnapshotMetadataTrue(
                    newSnapshot,
                    L"minifilter_attachments_coverage_complete");
        const bool processSecurityCoverageComplete =
            SnapshotMetadataTrue(
                newSnapshot,
                L"process_security_coverage_complete");

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
                if (options.HighOnly &&
                    SnapshotRiskRank(record.Risk) < 3)
                {
                    continue;
                }

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
            else if (IsEscalatedRecord(
                         oldIt->second,
                         record,
                         result->SameBoot,
                         minifilterAttachmentCoverageComplete))
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

                if (result->SameBoot &&
                    ProcessProtectionChanged(
                        oldIt->second,
                        record))
                {
                    uint8_t oldProtectionByte = 0;
                    uint8_t newProtectionByte = 0;
                    const bool protectionParsed =
                        TryEvidenceByteStrict(
                            oldIt->second,
                            L"protection_raw",
                            &oldProtectionByte) &&
                        TryEvidenceByteStrict(
                            record,
                            L"protection_raw",
                            &newProtectionByte);
                    if (!protectionParsed)
                    {
                        continue;
                    }
                    const uint64_t oldProtection =
                        oldProtectionByte;
                    const uint64_t newProtection =
                        newProtectionByte;
                    const bool stripped =
                        oldProtection != 0 &&
                        newProtection == 0;
                    const bool downgraded =
                        ProcessProtectionDowngraded(
                            oldIt->second,
                            record);
                    finding.NewRecord.Risk =
                        downgraded ? L"high" : L"medium";
                    finding.NewRecord.Tags.push_back(
                        L"baseline-protection-change");
                    finding.NewRecord.Tags.push_back(
                        stripped
                            ? L"protection-stripped"
                            : (downgraded
                                ? L"protection-downgraded"
                                : L"protection-changed"));
                    finding.NewRecord.Evidence[
                        L"baseline_protection_raw"] =
                        std::to_wstring(oldProtection);
                    finding.NewRecord.Evidence[
                        L"baseline_protection_hex"] =
                        SnapshotHex(oldProtection, 2);
                    finding.NewRecord.Evidence[
                        L"current_protection_raw"] =
                        std::to_wstring(newProtection);
                    finding.NewRecord.Evidence[
                        L"current_protection_hex"] =
                        SnapshotHex(newProtection, 2);
                }

                if (result->SameBoot &&
                    minifilterAttachmentCoverageComplete &&
                    MinifilterAttachmentDetachedTransition(
                        oldIt->second,
                        record))
                {
                    finding.NewRecord.Risk =
                        L"medium";
                    finding.NewRecord.Tags.push_back(
                        L"baseline-minifilter-detach");
                    finding.NewRecord.Tags.push_back(
                        L"storage-stack-detached");
                    finding.NewRecord.Evidence[
                        L"baseline_detached_volume"] =
                            L"false";
                    finding.NewRecord.Evidence[
                        L"current_detached_volume"] =
                            L"true";
                }

                if (options.HighOnly &&
                    SnapshotRiskRank(
                        finding.NewRecord.Risk) < 3)
                {
                    continue;
                }

                result->Findings.push_back(std::move(finding));
                ++result->Escalated;
                if (SnapshotRiskRank(
                        result->Findings.back().NewRecord.Risk) >= 3)
                {
                    ++result->High;
                }
            }
        }

        bool baselineHasCallbacks = false;
        for (const SnapshotRecord& record : oldSnapshot.Records)
        {
            if (record.Domain == L"callbacks" &&
                SnapshotRecordHasTag(record, L"callback"))
            {
                baselineHasCallbacks = true;
                break;
            }
        }

        const bool callbackRemovalRequested =
            result->SameBoot &&
            baselineHasCallbacks &&
            DomainAllowed(options, L"callbacks");
        if (callbackRemovalRequested &&
            (!callbackCoverageComplete ||
             !moduleCoverageComplete))
        {
            result->Warnings.push_back(
                L"callback removal comparison skipped because current "
                L"callback or module coverage is incomplete");
        }
        else if (callbackRemovalRequested)
        {
            for (const SnapshotRecord& oldRecord : oldSnapshot.Records)
            {
                if (oldRecord.Domain != L"callbacks" ||
                    !SnapshotRecordHasTag(
                        oldRecord,
                        L"callback") ||
                    newRecordKeys.find(
                        DiffRecordKey(oldRecord)) !=
                        newRecordKeys.end() ||
                    CallbackSemanticallyPresent(
                        oldRecord,
                        newSnapshot) ||
                    !CallbackOwnerStillLoaded(
                        oldRecord,
                        newSnapshot))
                {
                    continue;
                }

                SnapshotDiffFinding finding;
                finding.Kind = L"removed";
                finding.OldRecord = oldRecord;
                finding.NewRecord = oldRecord;
                if (SnapshotRiskRank(
                        finding.NewRecord.Risk) < 2)
                {
                    finding.NewRecord.Risk = L"medium";
                }
                finding.NewRecord.Tags.push_back(
                    L"baseline-record-removed");
                finding.NewRecord.Tags.push_back(
                    L"callback-removed");
                finding.NewRecord.Evidence[
                    L"baseline_present"] = L"true";
                finding.NewRecord.Evidence[
                    L"current_present"] = L"false";

                if (options.HighOnly &&
                    SnapshotRiskRank(
                        finding.NewRecord.Risk) < 3)
                {
                    continue;
                }

                result->Findings.push_back(std::move(finding));
                ++result->Removed;
                if (SnapshotRiskRank(
                        result->Findings.back().NewRecord.Risk) >= 3)
                {
                    ++result->High;
                }
            }
        }

        bool baselineHasProcessProtection =
            false;
        for (const SnapshotRecord& record :
             oldSnapshot.Records)
        {
            if (record.Domain ==
                    L"process-security" &&
                SnapshotRecordHasTag(
                    record,
                    L"process-protection"))
            {
                baselineHasProcessProtection =
                    true;
                break;
            }
        }

        const bool processProtectionRemovalRequested =
            result->SameBoot &&
            baselineHasProcessProtection &&
            DomainAllowed(
                options,
                L"process-security");
        if (processProtectionRemovalRequested &&
            !processSecurityCoverageComplete)
        {
            result->Warnings.push_back(
                L"process protection removal comparison skipped because current process-security coverage is incomplete");
        }
        else if (processProtectionRemovalRequested)
        {
            for (const SnapshotRecord& oldRecord :
                 oldSnapshot.Records)
            {
                if (oldRecord.Domain !=
                        L"process-security" ||
                    !SnapshotRecordHasTag(
                        oldRecord,
                        L"process-protection") ||
                    newRecordKeys.find(
                        DiffRecordKey(oldRecord)) !=
                        newRecordKeys.end() ||
                    !ProcessProtectionOwnerStillPresent(
                        oldRecord,
                        newSnapshot))
                {
                    continue;
                }

                SnapshotDiffFinding finding;
                finding.Kind = L"removed";
                finding.OldRecord = oldRecord;
                finding.NewRecord = oldRecord;
                finding.NewRecord.Risk = L"high";
                finding.NewRecord.Tags.push_back(
                    L"baseline-record-removed");
                finding.NewRecord.Tags.push_back(
                    L"process-protection-evidence-removed");
                finding.NewRecord.Evidence[
                    L"baseline_present"] = L"true";
                finding.NewRecord.Evidence[
                    L"current_present"] = L"false";
                finding.NewRecord.Evidence[
                    L"current_process_present"] = L"true";

                result->Findings.push_back(
                    std::move(finding));
                ++result->Removed;
                ++result->High;
            }
        }

        bool baselineHasMinifilterAttachments =
            false;
        for (const SnapshotRecord& record :
             oldSnapshot.Records)
        {
            if (record.Domain ==
                    L"minifilter-attachments" &&
                SnapshotRecordHasTag(
                    record,
                    L"minifilter-attachment") &&
                SnapshotToLower(
                    EvidenceText(
                        record,
                        L"kind")) ==
                    L"minifilter")
            {
                baselineHasMinifilterAttachments =
                    true;
                break;
            }
        }

        const bool
            minifilterRemovalRequested =
                result->SameBoot &&
                baselineHasMinifilterAttachments &&
                DomainAllowed(
                    options,
                    L"minifilter-attachments");
        if (minifilterRemovalRequested &&
            (!minifilterAttachmentCoverageComplete ||
             !callbackCoverageComplete))
        {
            result->Warnings.push_back(
                L"minifilter attachment removal comparison skipped because current attachment or callback coverage is incomplete");
        }
        else if (minifilterRemovalRequested)
        {
            for (const SnapshotRecord& oldRecord :
                 oldSnapshot.Records)
            {
                if (oldRecord.Domain !=
                        L"minifilter-attachments" ||
                    !SnapshotRecordHasTag(
                        oldRecord,
                        L"minifilter-attachment") ||
                    SnapshotToLower(
                        EvidenceText(
                            oldRecord,
                            L"kind")) !=
                        L"minifilter" ||
                    newRecordKeys.find(
                        DiffRecordKey(oldRecord)) !=
                        newRecordKeys.end() ||
                    CleanMinifilterAttachmentSemanticallyPresent(
                        oldRecord,
                        newSnapshot) ||
                    !MinifilterVolumeStillPresent(
                        oldRecord,
                        newSnapshot) ||
                    !MinifilterStillRegistered(
                        oldRecord,
                        newSnapshot))
                {
                    continue;
                }

                SnapshotDiffFinding finding;
                finding.Kind = L"removed";
                finding.OldRecord = oldRecord;
                finding.NewRecord = oldRecord;
                finding.NewRecord.Risk =
                    L"medium";
                finding.NewRecord.Tags.push_back(
                    L"baseline-record-removed");
                finding.NewRecord.Tags.push_back(
                    L"minifilter-attachment-removed");
                finding.NewRecord.Tags.push_back(
                    L"filter-still-registered");
                finding.NewRecord.Tags.push_back(
                    L"volume-still-present");
                finding.NewRecord.Evidence[
                    L"baseline_present"] = L"true";
                finding.NewRecord.Evidence[
                    L"current_present"] = L"false";
                finding.NewRecord.Evidence[
                    L"current_filter_registered"] =
                        L"true";
                finding.NewRecord.Evidence[
                    L"current_volume_present"] =
                        L"true";

                if (options.HighOnly)
                {
                    continue;
                }

                result->Findings.push_back(
                    std::move(finding));
                ++result->Removed;
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
    std::wstring error = L"stale error";
    if (!BuildSnapshotDiff(
            oldSnapshot,
            newSnapshot,
            options,
            &result,
            &error) ||
        !error.empty() ||
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
    if (!BuildSnapshotDiff(
            oldSnapshot,
            newSnapshot,
            options,
            &result,
            &error) ||
        result.SameBoot ||
        result.Findings.size() != 1 ||
        result.Findings[0].NewRecord.Risk != L"low" ||
        SnapshotRecordHasTag(
            result.Findings[0].NewRecord,
            L"baseline-pointer-change"))
    {
        return false;
    }

    SnapshotRecord callback = {};
    callback.Domain = L"callbacks";
    callback.Identity =
        L"callback:process:selftest:securityflt+1000";
    callback.Display =
        L"process selftest securityflt.sys+0x1000";
    callback.Risk = L"medium";
    callback.Tags = {L"callback"};
    callback.Evidence[L"kind"] = L"process";
    callback.Evidence[L"target"] = L"process";
    callback.Evidence[L"function"] =
        L"0xfffff80000001000";
    callback.Evidence[L"function_module"] =
        L"securityflt.sys";

    SnapshotRecord callbackOwner = {};
    callbackOwner.Domain = L"modules";
    callbackOwner.Identity = L"module:securityflt.sys";
    callbackOwner.Display = L"securityflt.sys";
    callbackOwner.Risk = L"low";
    callbackOwner.Tags = {L"module"};
    callbackOwner.Evidence[L"image"] =
        L"securityflt.sys";

    SnapshotDocument callbackOld = {};
    SnapshotDocument callbackNew = {};
    callbackOld.Records = {callback, callbackOwner};
    callbackNew.Records = {callbackOwner};
    callbackNew.Metadata[L"callbacks_coverage_complete"] =
        L"true";
    callbackNew.Metadata[L"modules_coverage_complete"] =
        L"true";
    options.InMemoryBaseline = true;
    SnapshotDiffResult callbackResult = {};
    if (!BuildSnapshotDiff(
            callbackOld,
            callbackNew,
            options,
            &callbackResult,
            &error) ||
        callbackResult.Removed != 1 ||
        callbackResult.Findings.size() != 1 ||
        callbackResult.Findings[0].Kind != L"removed" ||
        callbackResult.Findings[0].NewRecord.Risk !=
            L"medium" ||
        !SnapshotRecordHasTag(
            callbackResult.Findings[0].NewRecord,
            L"callback-removed") ||
        callbackResult.Domains[L"callbacks"].Removed != 1)
    {
        return false;
    }

    SnapshotDocument ownerUnloaded = callbackNew;
    ownerUnloaded.Records.clear();
    SnapshotDiffResult ownerUnloadedResult = {};
    if (!BuildSnapshotDiff(
            callbackOld,
            ownerUnloaded,
            options,
            &ownerUnloadedResult,
            &error) ||
        !ownerUnloadedResult.Findings.empty())
    {
        return false;
    }

    SnapshotRecord reregisteredCallback = callback;
    reregisteredCallback.Identity =
        L"callback:process:selftest:securityflt+1000:new-entry";
    reregisteredCallback.Evidence[L"entry"] =
        L"0xffffa00000002000";
    SnapshotDocument callbackReregistered = callbackNew;
    callbackReregistered.Records =
        {reregisteredCallback, callbackOwner};
    SnapshotDiffResult callbackReregisteredResult = {};
    if (!BuildSnapshotDiff(
            callbackOld,
            callbackReregistered,
            options,
            &callbackReregisteredResult,
            &error) ||
        callbackReregisteredResult.Removed != 0 ||
        std::any_of(
            callbackReregisteredResult.Findings.begin(),
            callbackReregisteredResult.Findings.end(),
            [](const SnapshotDiffFinding& finding)
            {
                return finding.Kind == L"removed";
            }))
    {
        return false;
    }

    SnapshotRecord targetlessCallback = callback;
    targetlessCallback.Identity =
        L"callback:image::securityflt+1000";
    targetlessCallback.Evidence[L"kind"] = L"image";
    targetlessCallback.Evidence[L"target"] = L"";
    SnapshotRecord targetlessReregistered =
        targetlessCallback;
    targetlessReregistered.Identity =
        L"callback:image::securityflt+1000:new-entry";
    targetlessReregistered.Evidence[L"entry"] =
        L"0xffffa00000003000";
    SnapshotDocument targetlessOld = callbackOld;
    targetlessOld.Records =
        {targetlessCallback, callbackOwner};
    SnapshotDocument targetlessNew = callbackNew;
    targetlessNew.Records =
        {targetlessReregistered, callbackOwner};
    SnapshotDiffResult targetlessResult = {};
    if (!BuildSnapshotDiff(
            targetlessOld,
            targetlessNew,
            options,
            &targetlessResult,
            &error) ||
        targetlessResult.Removed != 0 ||
        std::any_of(
            targetlessResult.Findings.begin(),
            targetlessResult.Findings.end(),
            [](const SnapshotDiffFinding& finding)
            {
                return finding.Kind == L"removed";
            }))
    {
        return false;
    }

    SnapshotDocument callbackIncomplete = callbackNew;
    callbackIncomplete.Metadata[
        L"callbacks_coverage_complete"] = L"false";
    SnapshotDiffResult callbackIncompleteResult = {};
    if (!BuildSnapshotDiff(
            callbackOld,
            callbackIncomplete,
            options,
            &callbackIncompleteResult,
            &error) ||
        !callbackIncompleteResult.Findings.empty() ||
        callbackIncompleteResult.Warnings.empty())
    {
        return false;
    }

    callbackOld.SameBootOnly = true;
    callbackNew.SameBootOnly = true;
    callbackOld.BootId = L"boot-a";
    callbackNew.BootId = L"boot-b";
    options.InMemoryBaseline = false;
    SnapshotDiffResult callbackCrossBootResult = {};
    if (!BuildSnapshotDiff(
            callbackOld,
            callbackNew,
            options,
            &callbackCrossBootResult,
            &error) ||
        callbackCrossBootResult.SameBoot ||
        !callbackCrossBootResult.Findings.empty())
    {
        return false;
    }

    SnapshotRecord protectedProcess = {};
    protectedProcess.Domain = L"process-security";
    protectedProcess.Identity =
        L"process-security:4321:100";
    protectedProcess.Display =
        L"MsMpEng.exe pid=4321 protection=0x31";
    protectedProcess.Risk = L"info";
    protectedProcess.Tags =
        {L"process-security", L"process-protection"};
    protectedProcess.Evidence[L"pid"] = L"4321";
    protectedProcess.Evidence[L"image"] =
        L"MsMpEng.exe";
    protectedProcess.Evidence[L"protection_raw"] =
        L"49";
    protectedProcess.Evidence[L"protection_hex"] =
        L"0x31";

    SnapshotRecord strippedProcess = protectedProcess;
    strippedProcess.Display =
        L"MsMpEng.exe pid=4321 protection=0x00";
    strippedProcess.Evidence[L"protection_raw"] =
        L"0";
    strippedProcess.Evidence[L"protection_hex"] =
        L"0x00";

    SnapshotDocument protectionOld = {};
    SnapshotDocument protectionNew = {};
    protectionOld.Records = {protectedProcess};
    protectionNew.Records = {strippedProcess};
    options.InMemoryBaseline = true;
    SnapshotDiffResult protectionResult = {};
    if (!BuildSnapshotDiff(
            protectionOld,
            protectionNew,
            options,
            &protectionResult,
            &error) ||
        protectionResult.Findings.size() != 1 ||
        protectionResult.Findings[0].Kind !=
            L"escalated" ||
        protectionResult.Findings[0].NewRecord.Risk !=
            L"high" ||
        !SnapshotRecordHasTag(
            protectionResult.Findings[0].NewRecord,
            L"protection-stripped") ||
        protectionResult.High != 1)
    {
        return false;
    }

    SnapshotRecord malformedProtection =
        protectedProcess;
    malformedProtection.Evidence[
        L"protection_raw"] =
            L"49junk";
    SnapshotDocument malformedOld = {};
    SnapshotDocument malformedNew = {};
    malformedOld.Records =
        {malformedProtection};
    malformedNew.Records =
        {strippedProcess};
    SnapshotDiffResult malformedResult = {};
    if (!BuildSnapshotDiff(
            malformedOld,
            malformedNew,
            options,
            &malformedResult,
            &error) ||
        !malformedResult.Findings.empty())
    {
        return false;
    }

    SnapshotDocument upgradeOld = {};
    SnapshotDocument upgradeNew = {};
    upgradeOld.Records = {strippedProcess};
    upgradeNew.Records = {protectedProcess};
    SnapshotDiffResult upgradeResult = {};
    if (!BuildSnapshotDiff(
            upgradeOld,
            upgradeNew,
            options,
            &upgradeResult,
            &error) ||
        upgradeResult.Findings.size() != 1 ||
        upgradeResult.Findings[0].NewRecord.Risk !=
            L"medium" ||
        SnapshotRecordHasTag(
            upgradeResult.Findings[0].NewRecord,
            L"protection-stripped"))
    {
        return false;
    }

    SnapshotRecord processOwner = {};
    processOwner.Domain = L"process";
    processOwner.Identity = L"4321:100";
    processOwner.Risk = L"info";
    SnapshotDocument protectionMissingOld = {};
    SnapshotDocument protectionMissingNew = {};
    protectionMissingOld.Records =
        {processOwner, protectedProcess};
    protectionMissingNew.Records =
        {processOwner};
    protectionMissingNew.Metadata[
        L"process_security_coverage_complete"] =
            L"true";
    options.InMemoryBaseline = true;
    SnapshotDiffResult protectionMissingResult = {};
    if (!BuildSnapshotDiff(
            protectionMissingOld,
            protectionMissingNew,
            options,
            &protectionMissingResult,
            &error) ||
        protectionMissingResult.Findings.size() !=
            1 ||
        protectionMissingResult.Findings[0].Kind !=
            L"removed" ||
        protectionMissingResult.Findings[0].
                NewRecord.Risk !=
            L"high" ||
        !SnapshotRecordHasTag(
            protectionMissingResult.Findings[0].
                NewRecord,
            L"process-protection-evidence-removed") ||
        protectionMissingResult.Removed != 1 ||
        protectionMissingResult.High != 1)
    {
        return false;
    }

    protectionMissingNew.Metadata[
        L"process_security_coverage_complete"] =
            L"false";
    SnapshotDiffResult protectionIncompleteResult = {};
    if (!BuildSnapshotDiff(
            protectionMissingOld,
            protectionMissingNew,
            options,
            &protectionIncompleteResult,
            &error) ||
        !protectionIncompleteResult.Findings.empty() ||
        protectionIncompleteResult.Warnings.empty())
    {
        return false;
    }

    protectionOld.SameBootOnly = true;
    protectionNew.SameBootOnly = true;
    protectionOld.BootId = L"boot-a";
    protectionNew.BootId = L"boot-b";
    options.InMemoryBaseline = false;
    SnapshotDiffResult protectionCrossBootResult = {};
    return BuildSnapshotDiff(
               protectionOld,
               protectionNew,
               options,
               &protectionCrossBootResult,
               &error) &&
        !protectionCrossBootResult.SameBoot &&
        protectionCrossBootResult.Findings.empty();
}

bool SnapshotMinifilterAttachmentDiffSelfTest()
{
    SnapshotRecord attachment = {};
    attachment.Domain =
        L"minifilter-attachments";
    attachment.Identity =
        L"minifilter-attachment:selftest";
    attachment.Display =
        L"minifilter WdFilter on HarddiskVolume3";
    attachment.Risk = L"low";
    attachment.Tags =
        {L"minifilter-attachment", L"minifilter"};
    attachment.Evidence[L"kind"] =
        L"minifilter";
    attachment.Evidence[L"filter_name"] =
        L"WdFilter";
    attachment.Evidence[L"instance_name"] =
        L"WdFilter Instance";
    attachment.Evidence[L"volume_name"] =
        L"\\Device\\HarddiskVolume3";
    attachment.Evidence[L"altitude"] =
        L"328010";
    attachment.Evidence[L"detached_volume"] =
        L"false";

    SnapshotRecord detached = attachment;
    detached.Evidence[L"detached_volume"] =
        L"true";
    detached.Tags.push_back(
        L"detached-volume");

    SnapshotDocument transitionOld = {};
    SnapshotDocument transitionNew = {};
    transitionOld.Records = {attachment};
    transitionNew.Records = {detached};
    transitionNew.Metadata[
        L"minifilter_attachments_coverage_complete"] =
            L"true";

    SnapshotDiffOptions options = {};
    options.InMemoryBaseline = true;
    options.Details = true;
    SnapshotDiffResult transitionResult = {};
    std::wstring error;
    if (!BuildSnapshotDiff(
            transitionOld,
            transitionNew,
            options,
            &transitionResult,
            &error) ||
        transitionResult.Findings.size() != 1 ||
        transitionResult.Findings[0].Kind !=
            L"escalated" ||
        transitionResult.Findings[0].
                NewRecord.Risk !=
            L"medium" ||
        !SnapshotRecordHasTag(
            transitionResult.Findings[0].
                NewRecord,
            L"baseline-minifilter-detach"))
    {
        return false;
    }

    SnapshotDocument incompleteTransition =
        transitionNew;
    incompleteTransition.Metadata[
        L"minifilter_attachments_coverage_complete"] =
            L"false";
    SnapshotDiffResult incompleteResult = {};
    if (!BuildSnapshotDiff(
            transitionOld,
            incompleteTransition,
            options,
            &incompleteResult,
            &error) ||
        !incompleteResult.Findings.empty())
    {
        return false;
    }

    transitionOld.SameBootOnly = true;
    transitionNew.SameBootOnly = true;
    transitionOld.BootId = L"boot-a";
    transitionNew.BootId = L"boot-b";
    options.InMemoryBaseline = false;
    SnapshotDiffResult crossBootTransition = {};
    if (!BuildSnapshotDiff(
            transitionOld,
            transitionNew,
            options,
            &crossBootTransition,
            &error) ||
        crossBootTransition.SameBoot ||
        !crossBootTransition.Findings.empty())
    {
        return false;
    }

    SnapshotRecord volume = {};
    volume.Domain =
        L"minifilter-attachments";
    volume.Identity =
        L"minifilter-volume:selftest";
    volume.Display =
        L"Filter Manager volume HarddiskVolume3";
    volume.Risk = L"low";
    volume.Tags =
        {L"minifilter-volume"};
    volume.Evidence[L"volume_name"] =
        L"\\Device\\HarddiskVolume3";

    SnapshotRecord callback = {};
    callback.Domain = L"callbacks";
    callback.Identity =
        L"callback:minifilter:wd-filter";
    callback.Display =
        L"minifilter WdFilter";
    callback.Risk = L"medium";
    callback.Tags = {L"callback"};
    callback.Evidence[L"kind"] =
        L"minifilter";
    callback.Evidence[L"target"] =
        L"WdFilter";
    callback.Evidence[L"function"] =
        L"0xfffff80000001000";
    callback.Evidence[L"function_module"] =
        L"WdFilter.sys";

    SnapshotDocument removalOld = {};
    SnapshotDocument removalNew = {};
    removalOld.Records =
        {attachment, volume, callback};
    removalNew.Records =
        {volume, callback};
    removalNew.Metadata[
        L"minifilter_attachments_coverage_complete"] =
            L"true";
    removalNew.Metadata[
        L"callbacks_coverage_complete"] =
            L"true";
    options.InMemoryBaseline = true;
    SnapshotDiffResult removalResult = {};
    if (!BuildSnapshotDiff(
            removalOld,
            removalNew,
            options,
            &removalResult,
            &error) ||
        removalResult.Removed != 1 ||
        removalResult.Findings.size() != 1 ||
        removalResult.Findings[0].Kind !=
            L"removed" ||
        removalResult.Findings[0].
                NewRecord.Risk !=
            L"medium" ||
        !SnapshotRecordHasTag(
            removalResult.Findings[0].
                NewRecord,
            L"minifilter-attachment-removed") ||
        removalResult.Domains[
            L"minifilter-attachments"].Removed !=
            1)
    {
        return false;
    }

    SnapshotDocument filterUnloaded =
        removalNew;
    filterUnloaded.Records = {volume};
    SnapshotDiffResult filterUnloadedResult = {};
    if (!BuildSnapshotDiff(
            removalOld,
            filterUnloaded,
            options,
            &filterUnloadedResult,
            &error) ||
        filterUnloadedResult.Removed != 0 ||
        std::any_of(
            filterUnloadedResult.Findings.begin(),
            filterUnloadedResult.Findings.end(),
            [](const SnapshotDiffFinding& finding)
            {
                return SnapshotRecordHasTag(
                    finding.NewRecord,
                    L"minifilter-attachment-removed");
            }))
    {
        return false;
    }

    SnapshotDocument volumeRemoved =
        removalNew;
    volumeRemoved.Records = {callback};
    SnapshotDiffResult volumeRemovedResult = {};
    if (!BuildSnapshotDiff(
            removalOld,
            volumeRemoved,
            options,
            &volumeRemovedResult,
            &error) ||
        volumeRemovedResult.Removed != 0 ||
        std::any_of(
            volumeRemovedResult.Findings.begin(),
            volumeRemovedResult.Findings.end(),
            [](const SnapshotDiffFinding& finding)
            {
                return SnapshotRecordHasTag(
                    finding.NewRecord,
                    L"minifilter-attachment-removed");
            }))
    {
        return false;
    }

    SnapshotRecord replacement = attachment;
    replacement.Identity =
        L"minifilter-attachment:selftest-replacement";
    replacement.Evidence[L"instance_name"] =
        L"WdFilter Replacement";
    SnapshotRecord detachedReplacement =
        replacement;
    detachedReplacement.Identity =
        L"minifilter-attachment:selftest-detached-replacement";
    detachedReplacement.Evidence[L"instance_name"] =
        L"WdFilter Detached Replacement";
    detachedReplacement.Evidence[L"detached_volume"] =
        L"true";
    detachedReplacement.Tags.push_back(
        L"detached-volume");
    SnapshotDocument reattached =
        removalNew;
    reattached.Records =
        {
            detachedReplacement,
            replacement,
            volume,
            callback
        };
    SnapshotDiffResult reattachedResult = {};
    if (!BuildSnapshotDiff(
            removalOld,
            reattached,
            options,
            &reattachedResult,
            &error) ||
        reattachedResult.Removed != 0 ||
        std::any_of(
            reattachedResult.Findings.begin(),
            reattachedResult.Findings.end(),
            [](const SnapshotDiffFinding& finding)
            {
                return SnapshotRecordHasTag(
                    finding.NewRecord,
                    L"minifilter-attachment-removed");
            }))
    {
        return false;
    }

    SnapshotRecord decoy = replacement;
    decoy.Identity =
        L"minifilter-attachment:selftest-decoy";
    decoy.Evidence[L"instance_name"] =
        L"WdFilter Decoy";
    decoy.Evidence[L"altitude"] =
        L"328011";
    SnapshotDocument decoyPresent =
        removalNew;
    decoyPresent.Records =
        {decoy, volume, callback};
    SnapshotDiffResult decoyResult = {};
    if (!BuildSnapshotDiff(
            removalOld,
            decoyPresent,
            options,
            &decoyResult,
            &error) ||
        decoyResult.Removed != 1 ||
        std::none_of(
            decoyResult.Findings.begin(),
            decoyResult.Findings.end(),
            [](const SnapshotDiffFinding& finding)
            {
                return SnapshotRecordHasTag(
                    finding.NewRecord,
                    L"minifilter-attachment-removed");
            }))
    {
        return false;
    }

    SnapshotDocument incompleteRemoval =
        removalNew;
    incompleteRemoval.Metadata[
        L"minifilter_attachments_coverage_complete"] =
            L"false";
    SnapshotDiffResult incompleteRemovalResult = {};
    if (!BuildSnapshotDiff(
            removalOld,
            incompleteRemoval,
            options,
            &incompleteRemovalResult,
            &error) ||
        !incompleteRemovalResult.Findings.empty() ||
        incompleteRemovalResult.Warnings.empty())
    {
        return false;
    }

    removalOld.SameBootOnly = true;
    removalNew.SameBootOnly = true;
    removalOld.BootId = L"boot-a";
    removalNew.BootId = L"boot-b";
    options.InMemoryBaseline = false;
    SnapshotDiffResult crossBootRemoval = {};
    return BuildSnapshotDiff(
               removalOld,
               removalNew,
               options,
               &crossBootRemoval,
               &error) &&
        !crossBootRemoval.SameBoot &&
        crossBootRemoval.Findings.empty();
}
