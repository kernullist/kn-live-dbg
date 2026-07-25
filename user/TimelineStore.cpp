#include "TimelineStore.h"

#include "SnapshotDiff.h"
#include "SnapshotJson.h"

#include <algorithm>
#include <cerrno>
#include <cwchar>
#include <map>
#include <set>
#include <sstream>
#include <utility>

namespace
{
    constexpr size_t kMinTimelineCapacity = 1024;
    constexpr size_t kMaxTimelineCapacity = 1u << 22;

    std::wstring HexU64(uint64_t value)
    {
        std::wstringstream stream;
        stream << L"0x" << std::hex << value << std::dec;
        return stream.str();
    }

    void AppendEventKeyPart(std::wstring* key, const std::wstring& value)
    {
        if (key != nullptr)
        {
            *key += std::to_wstring(value.size());
            *key += L":";
            *key += value;
            *key += L"|";
        }
    }

    void AppendEventKeyPart(std::wstring* key, uint64_t value)
    {
        AppendEventKeyPart(key, std::to_wstring(value));
    }

    bool TimelineEventKeySkipsEvidence(const std::wstring& name)
    {
        bool skip = false;
        std::wstring lowered = TimelineToLower(name);

        if (lowered == L"mode" || lowered == L"source")
        {
            skip = true;
        }

        return skip;
    }

    std::wstring TimelineEventKey(const TimelineEvent& event)
    {
        std::wstring key;

        AppendEventKeyPart(&key, event.TimestampFileTime);
        AppendEventKeyPart(&key, event.TimestampUtc);
        AppendEventKeyPart(&key, event.Source);
        AppendEventKeyPart(&key, event.Domain);
        AppendEventKeyPart(&key, event.Action);
        AppendEventKeyPart(&key, event.ProcessId);
        AppendEventKeyPart(&key, event.ThreadId);
        AppendEventKeyPart(&key, event.TargetProcessId);
        AppendEventKeyPart(&key, event.Entity);
        AppendEventKeyPart(&key, event.Summary);
        AppendEventKeyPart(&key, event.Risk);
        AppendEventKeyPart(&key, event.Confidence);

        for (const auto& item : event.Evidence)
        {
            if (!TimelineEventKeySkipsEvidence(item.first))
            {
                AppendEventKeyPart(&key, item.first);
                AppendEventKeyPart(&key, item.second);
            }
        }

        return key;
    }

    std::wstring TiTaskText(const TiEventRecord& event)
    {
        std::wstring text = event.TaskName;
        if (text.empty())
        {
            text = L"Task" + std::to_wstring(static_cast<uint32_t>(event.TaskId));
        }
        return text;
    }

    bool TimelineTextContainsAny(
        const std::wstring& text,
        const wchar_t* const* needles,
        size_t count,
        std::wstring* matched)
    {
        bool found = false;

        for (size_t index = 0; index < count; ++index)
        {
            if (needles[index] != nullptr &&
                text.find(needles[index]) != std::wstring::npos)
            {
                if (matched != nullptr)
                {
                    *matched = needles[index];
                }
                found = true;
                break;
            }
        }

        return found;
    }

    std::wstring TiEventClassificationText(const TiEventRecord& event)
    {
        std::wstring text = TiTaskText(event);
        text += L" ";
        text += event.TaskName;
        text += L" ";
        text += event.OpcodeName;
        text += L" ";
        text += event.ImagePath;
        text += L" ";
        text += event.TargetImageBase;
        text += L" ";
        text += event.RawPayloadHex;

        for (const TiPayloadField& field : event.Payload)
        {
            text += L" ";
            text += field.Name;
            text += L" ";
            text += field.Value;
            text += L" ";
            text += field.TypeName;
        }

        return TimelineToLower(text);
    }

    std::wstring TiEventCursorKey(const TiEventRecord& event)
    {
        std::wstring key;

        AppendEventKeyPart(&key, event.Timestamp);
        AppendEventKeyPart(&key, event.ProcessId);
        AppendEventKeyPart(&key, event.ThreadId);
        AppendEventKeyPart(&key, event.TargetProcessId);
        AppendEventKeyPart(&key, static_cast<uint64_t>(event.TaskId));
        AppendEventKeyPart(&key, static_cast<uint64_t>(event.Version));
        AppendEventKeyPart(&key, static_cast<uint64_t>(event.Level));
        AppendEventKeyPart(&key, static_cast<uint64_t>(event.Opcode));
        AppendEventKeyPart(&key, static_cast<uint64_t>(event.Channel));
        AppendEventKeyPart(&key, event.Keyword);
        AppendEventKeyPart(&key, event.TaskName);
        AppendEventKeyPart(&key, event.OpcodeName);
        AppendEventKeyPart(&key, event.ImagePath);
        AppendEventKeyPart(&key, event.TargetImageBase);
        AppendEventKeyPart(&key, event.RawPayloadHex);

        for (const TiPayloadField& field : event.Payload)
        {
            AppendEventKeyPart(&key, field.Name);
            AppendEventKeyPart(&key, field.Value);
            AppendEventKeyPart(&key, field.TypeName);
        }

        return key;
    }

    struct TiTimelineClassification
    {
        std::wstring Risk;
        std::wstring Category;
        std::wstring Reason;
    };

    TiTimelineClassification ClassifyTiTimelineEvent(const TiEventRecord& event)
    {
        TiTimelineClassification classification = {};
        classification.Risk = L"info";
        classification.Category = L"general";
        classification.Reason = L"default";

        static const wchar_t* const criticalTerms[] =
        {
            L"writevirtualmemory",
            L"writevm",
            L"ntwritevirtualmemory",
            L"queueuserapc",
            L"setthreadcontext",
            L"createremotethread",
            L"terminateprocess",
            L"suspendprocess",
            L"processimpairment"
        };
        static const wchar_t* const warningTerms[] =
        {
            L"allocvm",
            L"virtualalloc",
            L"protectvm",
            L"virtualprotect",
            L"mapview",
            L"openprocess",
            L"duplicatehandle",
            L"loadimage",
            L"imageload",
            L"image-load",
            L"load image",
            L"driver",
            L"deviceiocontrol",
            L"section"
        };

        std::wstring text = TiEventClassificationText(event);
        std::wstring matched;
        if (TimelineTextContainsAny(
                text,
                criticalTerms,
                sizeof(criticalTerms) / sizeof(criticalTerms[0]),
                &matched))
        {
            classification.Risk = L"critical";
            classification.Category = L"process-impairment";
            classification.Reason = matched;
        }
        else if (TimelineTextContainsAny(
                     text,
                     warningTerms,
                     sizeof(warningTerms) / sizeof(warningTerms[0]),
                     &matched))
        {
            classification.Risk = L"warning";
            classification.Category = L"process-or-image-operation";
            classification.Reason = matched;
        }

        if (!event.DecodedByTdh && classification.Risk == L"info" && !event.RawPayloadHex.empty())
        {
            classification.Category = L"raw-ti-event";
            classification.Reason = L"raw-payload";
        }

        return classification;
    }

    bool ParsePidFromText(const std::wstring& text, uint32_t* pid)
    {
        bool ok = false;
        do
        {
            if (pid == nullptr || text.empty())
            {
                break;
            }

            wchar_t* end = nullptr;
            errno = 0;
            unsigned long long value = wcstoull(text.c_str(), &end, 0);
            if (end == text.c_str() || *end != L'\0' || errno == ERANGE)
            {
                break;
            }
            if (value == 0 || value > 0xffffffffull)
            {
                break;
            }

            *pid = static_cast<uint32_t>(value);
            ok = true;
        } while (false);

        return ok;
    }

    uint32_t SnapshotRecordPid(const SnapshotRecord& record)
    {
        uint32_t pid = 0;
        static const wchar_t* kPidKeys[] =
        {
            L"pid",
            L"process_id",
            L"owner_pid",
            L"target_pid",
            L"source_pid"
        };

        for (const wchar_t* key : kPidKeys)
        {
            auto it = record.Evidence.find(key);
            if (it != record.Evidence.end() && ParsePidFromText(it->second, &pid))
            {
                break;
            }
        }

        return pid;
    }

    std::wstring SnapshotRecordSummary(const SnapshotRecord& record)
    {
        std::wstring summary = record.Display;
        if (summary.empty())
        {
            summary = record.Identity;
        }
        if (summary.empty())
        {
            summary = record.Domain;
        }
        return summary;
    }

    void AddEvidenceIfPresent(
        std::map<std::wstring, std::wstring>* evidence,
        const std::wstring& key,
        const std::wstring& value)
    {
        if (evidence != nullptr && !value.empty())
        {
            (*evidence)[key] = value;
        }
    }

    uint32_t TimelineRiskRankValue(const std::wstring& risk)
    {
        uint32_t rank = 0;
        std::wstring lowered = TimelineToLower(risk);
        if (lowered == L"critical" || lowered == L"high")
        {
            rank = 4;
        }
        else if (lowered == L"medium" || lowered == L"warning")
        {
            rank = 3;
        }
        else if (lowered == L"low")
        {
            rank = 2;
        }
        else if (lowered == L"info")
        {
            rank = 1;
        }
        return rank;
    }

    void RaiseTimelineEventRisk(TimelineEvent* event, const std::wstring& risk)
    {
        if (event != nullptr && TimelineRiskRankValue(risk) > TimelineRiskRankValue(event->Risk))
        {
            event->Risk = risk;
        }
    }

    std::wstring GraphNodeId(const std::wstring& kind, const std::wstring& label)
    {
        return TimelineToLower(kind) + L":" + TimelineToLower(label);
    }

    std::wstring ProcessLabel(uint32_t pid)
    {
        return std::to_wstring(pid);
    }

    struct TimelineImageRef
    {
        std::wstring Value;
        bool LinkSourceProcess = false;
        bool LinkTargetProcess = false;
    };

    bool EvidenceValueByKey(
        const TimelineEvent& event,
        const std::wstring& key,
        std::wstring* value)
    {
        bool found = false;
        std::wstring wanted = TimelineToLower(key);

        for (const auto& item : event.Evidence)
        {
            if (TimelineToLower(item.first) == wanted)
            {
                if (value != nullptr)
                {
                    *value = item.second;
                }
                found = true;
                break;
            }
        }

        return found;
    }

    std::wstring TimelineCanonicalEvidenceKey(const std::wstring& key)
    {
        std::wstring out;
        out.reserve(key.size());
        for (wchar_t c : key)
        {
            if (c >= L'A' && c <= L'Z')
            {
                c = static_cast<wchar_t>(c + (L'a' - L'A'));
            }
            if ((c >= L'a' && c <= L'z') ||
                (c >= L'0' && c <= L'9'))
            {
                out.push_back(c);
            }
        }
        return out;
    }

    bool CanonicalEvidenceKeyMatches(
        const std::wstring& candidate,
        const std::wstring& wanted)
    {
        bool matched = false;
        std::wstring candidateKey = TimelineCanonicalEvidenceKey(candidate);
        std::wstring wantedKey = TimelineCanonicalEvidenceKey(wanted);

        if (!candidateKey.empty() && !wantedKey.empty())
        {
            matched = candidateKey == wantedKey ||
                candidateKey == (L"payload" + wantedKey);
        }

        return matched;
    }

    bool EvidenceValueByAnyCanonicalKey(
        const TimelineEvent& event,
        const wchar_t* const* keys,
        size_t count,
        std::wstring* value)
    {
        bool found = false;

        for (const auto& item : event.Evidence)
        {
            for (size_t index = 0; index < count; ++index)
            {
                if (keys[index] != nullptr &&
                    CanonicalEvidenceKeyMatches(item.first, keys[index]))
                {
                    if (value != nullptr)
                    {
                        *value = item.second;
                    }
                    found = true;
                    break;
                }
            }
            if (found)
            {
                break;
            }
        }

        return found;
    }

    void AddEvidenceIfMissing(
        TimelineEvent* event,
        const std::wstring& key,
        const std::wstring& value)
    {
        if (event != nullptr && !value.empty())
        {
            std::wstring existing;
            if (!EvidenceValueByKey(*event, key, &existing) || existing.empty())
            {
                event->Evidence[key] = value;
            }
        }
    }

    bool EvidenceValueByAnyKey(
        const TimelineEvent& event,
        const wchar_t* const* keys,
        size_t count,
        std::wstring* value)
    {
        bool found = false;

        for (size_t index = 0; index < count; ++index)
        {
            if (keys[index] != nullptr && EvidenceValueByKey(event, keys[index], value))
            {
                found = true;
                break;
            }
        }

        return found;
    }

    bool TryGetEvidencePidAny(
        const TimelineEvent& event,
        const wchar_t* const* keys,
        size_t count,
        uint32_t* pid)
    {
        bool ok = false;
        std::wstring value;

        if (EvidenceValueByAnyKey(event, keys, count, &value))
        {
            ok = ParsePidFromText(value, pid);
        }

        return ok;
    }

    std::wstring TimelineEventTextLower(const TimelineEvent& event)
    {
        std::wstring text = event.Source;
        text += L" ";
        text += event.Domain;
        text += L" ";
        text += event.Action;
        text += L" ";
        text += event.Entity;
        text += L" ";
        text += event.Summary;
        for (const auto& item : event.Evidence)
        {
            text += L" ";
            text += item.first;
            text += L" ";
            text += item.second;
        }
        return TimelineToLower(text);
    }

    bool TimelineEventContainsAny(
        const TimelineEvent& event,
        const wchar_t* const* terms,
        size_t count,
        std::wstring* matched)
    {
        return TimelineTextContainsAny(TimelineEventTextLower(event), terms, count, matched);
    }

    bool TimelineLowerEndsWith(const std::wstring& value, const std::wstring& suffix)
    {
        bool matched = false;
        std::wstring lowered = TimelineToLower(value);
        std::wstring loweredSuffix = TimelineToLower(suffix);

        if (lowered.size() >= loweredSuffix.size() &&
            lowered.compare(lowered.size() - loweredSuffix.size(), loweredSuffix.size(), loweredSuffix) == 0)
        {
            matched = true;
        }

        return matched;
    }

    bool TimelinePathLooksExecutable(const std::wstring& value)
    {
        static const wchar_t* const extensions[] =
        {
            L".exe",
            L".dll",
            L".sys",
            L".scr",
            L".com",
            L".bat",
            L".cmd",
            L".ps1",
            L".vbs",
            L".js",
            L".msi"
        };
        bool matched = false;

        for (const wchar_t* extension : extensions)
        {
            if (TimelineLowerEndsWith(value, extension))
            {
                matched = true;
                break;
            }
        }

        return matched;
    }

    bool TimelineRegistryPathLooksPersistent(const std::wstring& value)
    {
        static const wchar_t* const terms[] =
        {
            L"\\run",
            L"\\runonce",
            L"\\services\\",
            L"image file execution options",
            L"\\ifeo\\",
            L"appinit_dlls",
            L"\\winlogon\\",
            L"\\winsock\\",
            L"\\shell\\open\\command",
            L"\\taskcache\\",
            L"\\policies\\explorer\\run"
        };
        std::wstring lowered = TimelineToLower(value);
        std::wstring matched;

        return TimelineTextContainsAny(lowered, terms, sizeof(terms) / sizeof(terms[0]), &matched);
    }

    void EnsureTimelineFamily(TimelineEvent* event, const std::wstring& family)
    {
        AddEvidenceIfMissing(event, L"analysis_family", family);
        AddEvidenceIfMissing(event, L"timeline_category", family);
    }

    std::wstring FirstEvidenceValue(
        const TimelineEvent& event,
        const wchar_t* const* keys,
        size_t count)
    {
        std::wstring value;
        EvidenceValueByAnyKey(event, keys, count, &value);
        return value;
    }

    std::wstring FirstEvidenceValueLoose(
        const TimelineEvent& event,
        const wchar_t* const* keys,
        size_t count)
    {
        std::wstring value;
        if (!EvidenceValueByAnyKey(event, keys, count, &value))
        {
            EvidenceValueByAnyCanonicalKey(event, keys, count, &value);
        }
        return value;
    }

    void AddEvidenceAliasIfPresent(
        TimelineEvent* event,
        const std::wstring& normalizedKey,
        const wchar_t* const* keys,
        size_t count)
    {
        do
        {
            if (event == nullptr)
            {
                break;
            }

            std::wstring value = FirstEvidenceValueLoose(*event, keys, count);
            if (!value.empty())
            {
                AddEvidenceIfMissing(event, normalizedKey, value);
            }
        } while (false);
    }

    bool TimelineSummaryContainsFragment(
        const std::wstring& summary,
        const std::wstring& name)
    {
        return TimelineToLower(summary).find(TimelineToLower(name) + L"=") != std::wstring::npos;
    }

    void AppendTimelineSummaryField(
        TimelineEvent* event,
        const std::wstring& name,
        const std::wstring& value)
    {
        if (event != nullptr &&
            !name.empty() &&
            !value.empty() &&
            !TimelineSummaryContainsFragment(event->Summary, name))
        {
            event->Summary += L" " + name + L"=" + value;
        }
    }

    void NormalizeTiPayloadAliases(TimelineEvent* event)
    {
        do
        {
            if (event == nullptr)
            {
                break;
            }

            static const wchar_t* const sourcePidKeys[] =
            {
                L"source_pid",
                L"calling_process_id",
                L"callingprocessid",
                L"caller_process_id",
                L"callerprocessid",
                L"source_process_id",
                L"sourceprocessid",
                L"client_process_id",
                L"clientprocessid"
            };
            static const wchar_t* const targetPidKeys[] =
            {
                L"target_pid",
                L"target_process_id",
                L"targetprocessid",
                L"victim_pid",
                L"victimprocessid",
                L"destination_pid",
                L"destinationprocessid"
            };
            static const wchar_t* const sourceTidKeys[] =
            {
                L"source_tid",
                L"calling_thread_id",
                L"callingthreadid",
                L"caller_thread_id",
                L"callerthreadid",
                L"source_thread_id",
                L"sourcethreadid"
            };
            static const wchar_t* const targetTidKeys[] =
            {
                L"target_tid",
                L"target_thread_id",
                L"targetthreadid"
            };
            static const wchar_t* const desiredAccessKeys[] =
            {
                L"desired_access",
                L"desiredaccess",
                L"requested_access",
                L"requestedaccess",
                L"access_mask",
                L"accessmask"
            };
            static const wchar_t* const grantedAccessKeys[] =
            {
                L"granted_access",
                L"grantedaccess",
                L"handle_access",
                L"handleaccess"
            };
            static const wchar_t* const startAddressKeys[] =
            {
                L"start_address",
                L"startaddress",
                L"thread_start_address",
                L"threadstartaddress",
                L"win32_start_address",
                L"win32startaddress"
            };
            static const wchar_t* const objectNameKeys[] =
            {
                L"object_name",
                L"objectname",
                L"target_object_name",
                L"targetobjectname",
                L"name"
            };
            static const wchar_t* const sectionKeys[] =
            {
                L"section_name",
                L"sectionname",
                L"section_object",
                L"sectionobject"
            };

            AddEvidenceAliasIfPresent(
                event,
                L"source_pid",
                sourcePidKeys,
                sizeof(sourcePidKeys) / sizeof(sourcePidKeys[0]));
            AddEvidenceAliasIfPresent(
                event,
                L"target_pid",
                targetPidKeys,
                sizeof(targetPidKeys) / sizeof(targetPidKeys[0]));
            AddEvidenceAliasIfPresent(
                event,
                L"source_tid",
                sourceTidKeys,
                sizeof(sourceTidKeys) / sizeof(sourceTidKeys[0]));
            AddEvidenceAliasIfPresent(
                event,
                L"target_tid",
                targetTidKeys,
                sizeof(targetTidKeys) / sizeof(targetTidKeys[0]));
            AddEvidenceAliasIfPresent(
                event,
                L"desired_access",
                desiredAccessKeys,
                sizeof(desiredAccessKeys) / sizeof(desiredAccessKeys[0]));
            AddEvidenceAliasIfPresent(
                event,
                L"granted_access",
                grantedAccessKeys,
                sizeof(grantedAccessKeys) / sizeof(grantedAccessKeys[0]));
            AddEvidenceAliasIfPresent(
                event,
                L"start_address",
                startAddressKeys,
                sizeof(startAddressKeys) / sizeof(startAddressKeys[0]));
            AddEvidenceAliasIfPresent(
                event,
                L"object_name",
                objectNameKeys,
                sizeof(objectNameKeys) / sizeof(objectNameKeys[0]));
            AddEvidenceAliasIfPresent(
                event,
                L"section_name",
                sectionKeys,
                sizeof(sectionKeys) / sizeof(sectionKeys[0]));
        } while (false);
    }

    void NormalizeProcessIdentity(TimelineEvent* event)
    {
        do
        {
            if (event == nullptr)
            {
                break;
            }

            static const wchar_t* const targetPidKeys[] =
            {
                L"target_pid",
                L"target_process_id",
                L"targetprocessid",
                L"victim_pid",
                L"destination_pid"
            };
            if (event->TargetProcessId == 0)
            {
                uint32_t targetPid = 0;
                if (TryGetEvidencePidAny(
                        *event,
                        targetPidKeys,
                        sizeof(targetPidKeys) / sizeof(targetPidKeys[0]),
                        &targetPid))
                {
                    event->TargetProcessId = targetPid;
                }
            }
            if (event->TargetProcessId != 0)
            {
                AddEvidenceIfMissing(event, L"target_pid", std::to_wstring(event->TargetProcessId));
            }

            if (event->ProcessId != 0)
            {
                std::wstring bootId;
                EvidenceValueByKey(*event, L"boot_id", &bootId);
                std::wstring createTime;
                EvidenceValueByKey(*event, L"create_time", &createTime);
                std::wstring sequence;
                EvidenceValueByKey(*event, L"sequence", &sequence);

                std::wstring id;
                if (!bootId.empty())
                {
                    id += L"boot:" + bootId + L"|";
                }
                id += L"pid:" + std::to_wstring(event->ProcessId);
                if (!createTime.empty())
                {
                    id += L"|create:" + createTime;
                    AddEvidenceIfMissing(event, L"process_instance_id_basis", L"pid-create-time");
                }
                else if (!sequence.empty() && TimelineToLower(event->Action) == L"process-create")
                {
                    id += L"|seq:" + sequence;
                    AddEvidenceIfMissing(event, L"process_instance_id_basis", L"pid-create-sequence");
                }
                else
                {
                    AddEvidenceIfMissing(event, L"process_instance_id_basis", L"pid-only");
                }
                AddEvidenceIfMissing(event, L"process_instance_id", id);
            }

            if (event->TargetProcessId != 0)
            {
                std::wstring bootId;
                EvidenceValueByKey(*event, L"boot_id", &bootId);
                std::wstring targetCreateTime;
                EvidenceValueByKey(*event, L"target_create_time", &targetCreateTime);

                std::wstring id;
                if (!bootId.empty())
                {
                    id += L"boot:" + bootId + L"|";
                }
                id += L"pid:" + std::to_wstring(event->TargetProcessId);
                if (!targetCreateTime.empty())
                {
                    id += L"|create:" + targetCreateTime;
                }
                AddEvidenceIfMissing(event, L"target_process_instance_id", id);
            }
        } while (false);
    }

    std::wstring DetectCrossProcessOperation(const TimelineEvent& event)
    {
        struct OperationTerm
        {
            const wchar_t* Term;
            const wchar_t* Operation;
        };
        static const OperationTerm terms[] =
        {
            {L"writevirtualmemory", L"writevm"},
            {L"writevm", L"writevm"},
            {L"ntwritevirtualmemory", L"writevm"},
            {L"readvirtualmemory", L"readvm"},
            {L"readvm", L"readvm"},
            {L"allocvm", L"allocvm"},
            {L"virtualalloc", L"allocvm"},
            {L"protectvm", L"protectvm"},
            {L"virtualprotect", L"protectvm"},
            {L"mapview", L"mapview"},
            {L"queueuserapc", L"queueuserapc"},
            {L"setthreadcontext", L"setthreadcontext"},
            {L"createremotethread", L"createremotethread"},
            {L"openprocess", L"openprocess"},
            {L"duplicatehandle", L"duplicatehandle"},
            {L"suspendprocess", L"suspend"},
            {L"resumeprocess", L"resume"},
            {L"terminateprocess", L"terminate"}
        };

        std::wstring operation;
        std::wstring text = TimelineEventTextLower(event);
        for (const OperationTerm& term : terms)
        {
            if (text.find(term.Term) != std::wstring::npos)
            {
                operation = term.Operation;
                break;
            }
        }
        return operation;
    }

    void NormalizeCrossProcessEvidence(TimelineEvent* event)
    {
        do
        {
            if (event == nullptr)
            {
                break;
            }

            std::wstring operation = DetectCrossProcessOperation(*event);
            if (operation.empty())
            {
                break;
            }
            if (event->TargetProcessId == 0)
            {
                std::wstring targetImage;
                if (!EvidenceValueByKey(*event, L"target_image", &targetImage) || targetImage.empty())
                {
                    break;
                }
            }

            AddEvidenceIfMissing(event, L"cross_process_operation", operation);
            EnsureTimelineFamily(event, L"cross-process");
            static const wchar_t* const criticalOps[] =
            {
                L"writevm",
                L"queueuserapc",
                L"setthreadcontext",
                L"createremotethread",
                L"terminate"
            };
            bool critical = false;
            for (const wchar_t* op : criticalOps)
            {
                if (operation == op)
                {
                    critical = true;
                    break;
                }
            }
            RaiseTimelineEventRisk(event, critical ? L"critical" : L"warning");
        } while (false);
    }

    void NormalizeNetworkEvidence(TimelineEvent* event)
    {
        do
        {
            if (event == nullptr)
            {
                break;
            }

            static const wchar_t* const hostKeys[] =
            {
                L"remote_host",
                L"remote_ip",
                L"destination_ip",
                L"dst_ip",
                L"dest_ip",
                L"server_ip",
                L"ip",
                L"address",
                L"payload.DestinationAddress",
                L"payload.RemoteAddress"
            };
            static const wchar_t* const portKeys[] =
            {
                L"remote_port",
                L"destination_port",
                L"dst_port",
                L"dest_port",
                L"server_port",
                L"port",
                L"payload.DestinationPort",
                L"payload.RemotePort"
            };
            static const wchar_t* const queryKeys[] =
            {
                L"dns_query",
                L"query_name",
                L"query",
                L"hostname",
                L"host",
                L"payload.QueryName"
            };

            std::wstring host = FirstEvidenceValue(*event, hostKeys, sizeof(hostKeys) / sizeof(hostKeys[0]));
            std::wstring port = FirstEvidenceValue(*event, portKeys, sizeof(portKeys) / sizeof(portKeys[0]));
            std::wstring query = FirstEvidenceValue(*event, queryKeys, sizeof(queryKeys) / sizeof(queryKeys[0]));
            std::wstring loweredDomain = TimelineToLower(event->Domain);
            std::wstring text = TimelineEventTextLower(*event);
            bool networkLike = loweredDomain == L"network" ||
                loweredDomain == L"dns" ||
                loweredDomain == L"socket" ||
                text.find(L"tcp") != std::wstring::npos ||
                text.find(L"udp") != std::wstring::npos ||
                text.find(L"connect") != std::wstring::npos ||
                text.find(L"accept") != std::wstring::npos ||
                text.find(L"listen") != std::wstring::npos ||
                text.find(L"dns") != std::wstring::npos;

            if (!host.empty())
            {
                AddEvidenceIfMissing(event, L"remote_host", host);
                std::wstring endpoint = host;
                if (!port.empty())
                {
                    endpoint += L":" + port;
                    AddEvidenceIfMissing(event, L"remote_port", port);
                }
                AddEvidenceIfMissing(event, L"network_endpoint", endpoint);
                if (event->Entity.empty() && networkLike)
                {
                    event->Entity = endpoint;
                }
            }

            if (!query.empty())
            {
                AddEvidenceIfMissing(event, L"dns_query", query);
                if (event->Entity.empty())
                {
                    event->Entity = query;
                }
            }

            if (networkLike && (!host.empty() || !query.empty()))
            {
                EnsureTimelineFamily(event, query.empty() ? L"network" : L"dns");
            }
        } while (false);
    }

    void NormalizeFileEvidence(TimelineEvent* event)
    {
        do
        {
            if (event == nullptr)
            {
                break;
            }

            static const wchar_t* const pathKeys[] =
            {
                L"file_path",
                L"path",
                L"target_file",
                L"filename",
                L"name",
                L"image_path",
                L"payload.FileName"
            };
            std::wstring path = FirstEvidenceValue(*event, pathKeys, sizeof(pathKeys) / sizeof(pathKeys[0]));
            std::wstring text = TimelineEventTextLower(*event);
            bool fileLike = TimelineToLower(event->Domain) == L"file" ||
                text.find(L"createfile") != std::wstring::npos ||
                text.find(L"writefile") != std::wstring::npos ||
                text.find(L"rename") != std::wstring::npos ||
                text.find(L"deletefile") != std::wstring::npos ||
                text.find(L"file-create") != std::wstring::npos ||
                text.find(L"file-write") != std::wstring::npos ||
                text.find(L"file-delete") != std::wstring::npos;

            if (!path.empty() && fileLike)
            {
                AddEvidenceIfMissing(event, L"file_path", path);
                if (event->Entity.empty())
                {
                    event->Entity = path;
                }
                EnsureTimelineFamily(event, L"file-artifact");
                if (TimelinePathLooksExecutable(path))
                {
                    AddEvidenceIfMissing(event, L"file_executable", L"true");
                    RaiseTimelineEventRisk(event, L"warning");
                }
                if (TimelineToLower(path).find(L"zone.identifier") != std::wstring::npos)
                {
                    AddEvidenceIfMissing(event, L"zone_identifier", L"true");
                }
            }
        } while (false);
    }

    void NormalizeRegistryEvidence(TimelineEvent* event)
    {
        do
        {
            if (event == nullptr)
            {
                break;
            }

            static const wchar_t* const keyKeys[] =
            {
                L"registry_key",
                L"key_path",
                L"key",
                L"path",
                L"payload.KeyName"
            };
            std::wstring key = FirstEvidenceValue(*event, keyKeys, sizeof(keyKeys) / sizeof(keyKeys[0]));
            bool registryLike = TimelineToLower(event->Domain) == L"registry" ||
                TimelineEventTextLower(*event).find(L"registry") != std::wstring::npos ||
                TimelineEventTextLower(*event).find(L"regset") != std::wstring::npos;

            if (!key.empty() && registryLike)
            {
                AddEvidenceIfMissing(event, L"registry_key", key);
                if (event->Entity.empty())
                {
                    event->Entity = key;
                }
                EnsureTimelineFamily(event, L"registry");
                if (TimelineRegistryPathLooksPersistent(key))
                {
                    event->Evidence[L"registry_persistence"] = L"true";
                    event->Evidence[L"analysis_family"] = L"registry-persistence";
                    event->Evidence[L"timeline_category"] = L"registry-persistence";
                    RaiseTimelineEventRisk(event, L"warning");
                }
            }
        } while (false);
    }

    void NormalizeServiceTaskWmiEvidence(TimelineEvent* event)
    {
        do
        {
            if (event == nullptr)
            {
                break;
            }

            static const wchar_t* const serviceKeys[] =
            {
                L"service_name",
                L"driver_service",
                L"payload.ServiceName"
            };
            static const wchar_t* const looseServiceKeys[] =
            {
                L"service"
            };
            static const wchar_t* const taskKeys[] =
            {
                L"scheduled_task",
                L"task_name",
                L"task_path"
            };
            static const wchar_t* const wmiKeys[] =
            {
                L"wmi_consumer",
                L"wmi_filter",
                L"wmi_binding",
                L"payload.Consumer",
                L"payload.Filter",
                L"payload.Binding"
            };
            static const wchar_t* const strictWmiKeys[] =
            {
                L"wmi_consumer",
                L"wmi_filter",
                L"wmi_binding"
            };

            std::wstring service = FirstEvidenceValue(*event, serviceKeys, sizeof(serviceKeys) / sizeof(serviceKeys[0]));
            std::wstring task;
            std::wstring wmi;
            std::wstring domain = TimelineToLower(event->Domain);
            std::wstring text = TimelineEventTextLower(*event);
            bool serviceLike = domain == L"service" ||
                text.find(L"createservice") != std::wstring::npos ||
                text.find(L"service-control") != std::wstring::npos ||
                text.find(L"service config") != std::wstring::npos;
            bool taskLike = domain == L"task" ||
                domain == L"scheduled-task" ||
                text.find(L"scheduled task") != std::wstring::npos ||
                text.find(L"register-task") != std::wstring::npos;
            bool wmiLike = domain == L"wmi" ||
                text.find(L"wmi") != std::wstring::npos ||
                text.find(L"__eventconsumer") != std::wstring::npos ||
                text.find(L"eventfilter") != std::wstring::npos ||
                text.find(L"filtertoconsumerbinding") != std::wstring::npos;

            if (taskLike)
            {
                task = FirstEvidenceValue(*event, taskKeys, sizeof(taskKeys) / sizeof(taskKeys[0]));
                if (task.empty())
                {
                    task = event->Entity;
                }
            }
            else
            {
                static const wchar_t* const strictTaskKeys[] =
                {
                    L"scheduled_task",
                    L"task_path"
                };
                task = FirstEvidenceValue(
                    *event,
                    strictTaskKeys,
                    sizeof(strictTaskKeys) / sizeof(strictTaskKeys[0]));
            }

            if (service.empty() && serviceLike)
            {
                service = FirstEvidenceValue(
                    *event,
                    looseServiceKeys,
                    sizeof(looseServiceKeys) / sizeof(looseServiceKeys[0]));
            }

            wmi = FirstEvidenceValue(*event, strictWmiKeys, sizeof(strictWmiKeys) / sizeof(strictWmiKeys[0]));
            if (wmi.empty() && wmiLike)
            {
                wmi = FirstEvidenceValue(*event, wmiKeys, sizeof(wmiKeys) / sizeof(wmiKeys[0]));
            }

            if (!service.empty() || serviceLike)
            {
                if (!service.empty())
                {
                    AddEvidenceIfMissing(event, L"service_name", service);
                    if (event->Entity.empty())
                    {
                        event->Entity = service;
                    }
                }
                EnsureTimelineFamily(event, L"service-persistence");
                RaiseTimelineEventRisk(event, L"warning");
            }

            if (!task.empty() || taskLike)
            {
                if (!task.empty())
                {
                    AddEvidenceIfMissing(event, L"scheduled_task", task);
                    if (event->Entity.empty())
                    {
                        event->Entity = task;
                    }
                }
                EnsureTimelineFamily(event, L"task-persistence");
                RaiseTimelineEventRisk(event, L"warning");
            }

            if (!wmi.empty() || wmiLike)
            {
                if (!wmi.empty())
                {
                    AddEvidenceIfMissing(event, L"wmi_entity", wmi);
                    if (event->Entity.empty())
                    {
                        event->Entity = wmi;
                    }
                }
                EnsureTimelineFamily(event, L"wmi-persistence");
                RaiseTimelineEventRisk(event, L"warning");
            }
        } while (false);
    }

    void NormalizeMemoryEvidence(TimelineEvent* event)
    {
        do
        {
            if (event == nullptr)
            {
                break;
            }

            static const wchar_t* const addressKeys[] =
            {
                L"vad_address",
                L"memory_address",
                L"base_address",
                L"baseaddress",
                L"allocation_base",
                L"allocationbase",
                L"allocation_base_address",
                L"allocationbaseaddress",
                L"virtual_address",
                L"virtualaddress",
                L"view_base",
                L"viewbase",
                L"payload.BaseAddress",
                L"payload.AllocationBase",
                L"payload.AllocationBaseAddress",
                L"payload.VirtualAddress",
                L"payload.ViewBase"
            };
            static const wchar_t* const sizeKeys[] =
            {
                L"allocation_size",
                L"allocationsize",
                L"region_size",
                L"regionsize",
                L"view_size",
                L"viewsize",
                L"number_of_bytes",
                L"numberofbytes",
                L"byte_count",
                L"bytecount",
                L"buffer_length",
                L"bufferlength",
                L"size",
                L"length",
                L"payload.RegionSize",
                L"payload.AllocationSize",
                L"payload.ViewSize",
                L"payload.NumberOfBytes",
                L"payload.Size",
                L"payload.Length"
            };
            static const wchar_t* const protectionKeys[] =
            {
                L"protection",
                L"protect",
                L"page_protection",
                L"pageprotection",
                L"memory_protection",
                L"memoryprotection",
                L"new_protection",
                L"newprotection",
                L"old_protection",
                L"oldprotection",
                L"win32_protect",
                L"win32protect",
                L"payload.Protection",
                L"payload.Protect",
                L"payload.NewProtection",
                L"payload.OldProtection",
                L"payload.Win32Protect"
            };
            static const wchar_t* const allocationTypeKeys[] =
            {
                L"allocation_type",
                L"allocationtype",
                L"alloc_type",
                L"alloctype",
                L"payload.AllocationType",
                L"payload.AllocType"
            };

            std::wstring address = FirstEvidenceValueLoose(*event, addressKeys, sizeof(addressKeys) / sizeof(addressKeys[0]));
            std::wstring allocationSize = FirstEvidenceValueLoose(*event, sizeKeys, sizeof(sizeKeys) / sizeof(sizeKeys[0]));
            std::wstring protection = FirstEvidenceValueLoose(*event, protectionKeys, sizeof(protectionKeys) / sizeof(protectionKeys[0]));
            std::wstring allocationType = FirstEvidenceValueLoose(
                *event,
                allocationTypeKeys,
                sizeof(allocationTypeKeys) / sizeof(allocationTypeKeys[0]));
            std::wstring domain = TimelineToLower(event->Domain);
            std::wstring text = TimelineEventTextLower(*event);
            bool memoryLike = domain == L"memory" ||
                domain == L"vad" ||
                domain == L"vad-dkom" ||
                text.find(L"allocvm") != std::wstring::npos ||
                text.find(L"virtualalloc") != std::wstring::npos ||
                text.find(L"protectvm") != std::wstring::npos ||
                text.find(L"virtualprotect") != std::wstring::npos ||
                text.find(L"writevm") != std::wstring::npos ||
                text.find(L"readvm") != std::wstring::npos ||
                text.find(L"mapview") != std::wstring::npos ||
                text.find(L"section") != std::wstring::npos ||
                text.find(L"rw->rx") != std::wstring::npos ||
                text.find(L"rwx") != std::wstring::npos ||
                text.find(L"private executable") != std::wstring::npos ||
                text.find(L"private_executable") != std::wstring::npos ||
                text.find(L"hollow") != std::wstring::npos ||
                text.find(L"module stomp") != std::wstring::npos;

            if (memoryLike)
            {
                if (!address.empty())
                {
                    AddEvidenceIfMissing(event, L"memory_address", address);
                    AppendTimelineSummaryField(event, L"addr", address);
                    if (event->Entity.empty())
                    {
                        event->Entity = address;
                    }
                }
                if (!allocationSize.empty())
                {
                    AddEvidenceIfMissing(event, L"allocation_size", allocationSize);
                    AppendTimelineSummaryField(event, L"size", allocationSize);
                }
                if (!protection.empty())
                {
                    AddEvidenceIfMissing(event, L"protection", protection);
                    AppendTimelineSummaryField(event, L"protect", protection);
                }
                if (!allocationType.empty())
                {
                    AddEvidenceIfMissing(event, L"allocation_type", allocationType);
                }
                EnsureTimelineFamily(event, L"memory-executable");
                RaiseTimelineEventRisk(event, L"warning");
            }
        } while (false);
    }

    void NormalizeSnapshotDiffEvidence(TimelineEvent* event)
    {
        do
        {
            if (event == nullptr)
            {
                break;
            }

            std::wstring diffKind;
            bool diffLike = TimelineToLower(event->Source) == L"snapshot-diff" ||
                TimelineToLower(event->Domain) == L"snapshot-diff" ||
                EvidenceValueByKey(*event, L"diff_kind", &diffKind);
            if (diffLike)
            {
                event->Evidence[L"analysis_family"] = L"snapshot-diff";
                event->Evidence[L"timeline_category"] = L"snapshot-diff";
                if (!diffKind.empty())
                {
                    AddEvidenceIfMissing(event, L"snapshot_diff_kind", diffKind);
                }
                if (!event->Entity.empty())
                {
                    AddEvidenceIfMissing(event, L"snapshot_diff_subject", event->Entity);
                }
                RaiseTimelineEventRisk(event, L"warning");
            }
        } while (false);
    }

    void NormalizeTimelineEvent(TimelineEvent* event)
    {
        do
        {
            if (event == nullptr)
            {
                break;
            }
            if (event->Risk.empty())
            {
                event->Risk = L"info";
            }
            if (event->Confidence.empty())
            {
                event->Confidence = L"observed";
            }

            NormalizeTiPayloadAliases(event);
            NormalizeProcessIdentity(event);
            NormalizeCrossProcessEvidence(event);
            NormalizeNetworkEvidence(event);
            NormalizeFileEvidence(event);
            NormalizeRegistryEvidence(event);
            NormalizeServiceTaskWmiEvidence(event);
            NormalizeMemoryEvidence(event);
            NormalizeSnapshotDiffEvidence(event);
        } while (false);
    }

    void AddImageRef(
        std::map<std::wstring, TimelineImageRef>* refs,
        const std::wstring& value,
        bool linkSourceProcess,
        bool linkTargetProcess)
    {
        if (refs != nullptr && !value.empty())
        {
            std::wstring key = TimelineToLower(value);
            auto it = refs->find(key);
            if (it == refs->end())
            {
                TimelineImageRef ref = {};
                ref.Value = value;
                it = refs->insert(std::make_pair(key, ref)).first;
            }
            it->second.LinkSourceProcess = it->second.LinkSourceProcess || linkSourceProcess;
            it->second.LinkTargetProcess = it->second.LinkTargetProcess || linkTargetProcess;
        }
    }

    std::vector<TimelineImageRef> TimelineEventImageRefs(const TimelineEvent& event)
    {
        std::map<std::wstring, TimelineImageRef> refs;
        std::vector<TimelineImageRef> values;
        std::wstring value;

        if (EvidenceValueByKey(event, L"image", &value))
        {
            AddImageRef(&refs, value, true, false);
        }
        if (EvidenceValueByKey(event, L"image_path", &value))
        {
            AddImageRef(&refs, value, true, false);
        }
        if (EvidenceValueByKey(event, L"target_image", &value))
        {
            AddImageRef(&refs, value, false, true);
        }
        if (EvidenceValueByKey(event, L"process_image_context", &value))
        {
            AddImageRef(&refs, value, true, false);
        }
        std::wstring loweredDomain = TimelineToLower(event.Domain);
        if (loweredDomain == L"process" ||
            loweredDomain == L"image" ||
            loweredDomain == L"driver" ||
            loweredDomain == L"module")
        {
            AddImageRef(&refs, event.Entity, true, false);
        }

        for (const auto& item : refs)
        {
            values.push_back(item.second);
        }

        return values;
    }

    void EnrichTimelineEventProcessContext(
        TimelineEvent* event,
        const std::deque<TimelineEvent>& existingEvents)
    {
        do
        {
            if (event == nullptr ||
                event->ProcessId == 0 ||
                TimelineToLower(event->Domain) != L"thread")
            {
                break;
            }

            std::wstring existingContext;
            if (EvidenceValueByKey(*event, L"process_image_context", &existingContext) &&
                !existingContext.empty())
            {
                break;
            }

            for (auto it = existingEvents.rbegin(); it != existingEvents.rend(); ++it)
            {
                if (it->ProcessId != event->ProcessId)
                {
                    continue;
                }

                std::vector<TimelineImageRef> images = TimelineEventImageRefs(*it);
                if (!images.empty())
                {
                    AddEvidenceIfMissing(event, L"process_image_context", images.front().Value);
                    break;
                }
                if (TimelineToLower(it->Domain) == L"process" && !it->Entity.empty())
                {
                    AddEvidenceIfMissing(event, L"process_image_context", it->Entity);
                    break;
                }
            }
        } while (false);
    }

    bool TimelineEventMatchesImage(const TimelineEvent& event, const std::wstring& image)
    {
        bool matched = false;
        std::wstring needle = TimelineToLower(image);

        do
        {
            if (needle.empty())
            {
                matched = true;
                break;
            }

            std::vector<TimelineImageRef> images = TimelineEventImageRefs(event);
            for (const TimelineImageRef& imageRef : images)
            {
                if (TimelineToLower(imageRef.Value).find(needle) != std::wstring::npos)
                {
                    matched = true;
                    break;
                }
            }
            if (matched)
            {
                break;
            }

            if (TimelineToLower(event.Entity).find(needle) != std::wstring::npos ||
                TimelineToLower(event.Summary).find(needle) != std::wstring::npos)
            {
                matched = true;
                break;
            }

            for (const auto& item : event.Evidence)
            {
                if (TimelineToLower(item.second).find(needle) != std::wstring::npos)
                {
                    matched = true;
                    break;
                }
            }
        } while (false);

        return matched;
    }

    bool TimelineEventMatchesGraphQuery(
        const TimelineEvent& event,
        const TimelineGraphQueryOptions& options)
    {
        bool matched = true;

        if (!options.Source.empty() &&
            TimelineToLower(event.Source) != TimelineToLower(options.Source))
        {
            matched = false;
        }
        if (matched &&
            !options.Domain.empty() &&
            TimelineToLower(event.Domain) != TimelineToLower(options.Domain))
        {
            matched = false;
        }
        if (matched &&
            options.HasProcessId &&
            event.ProcessId != options.ProcessId &&
            event.TargetProcessId != options.ProcessId)
        {
            matched = false;
        }
        if (matched &&
            !options.Image.empty() &&
            !TimelineEventMatchesImage(event, options.Image))
        {
            matched = false;
        }

        return matched;
    }

    void AddGraphNode(
        std::map<std::wstring, TimelineGraphNode>* nodes,
        std::set<std::wstring>* eventNodes,
        const std::wstring& kind,
        const std::wstring& label)
    {
        if (nodes != nullptr && eventNodes != nullptr && !label.empty())
        {
            std::wstring id = GraphNodeId(kind, label);
            auto it = nodes->find(id);
            if (it == nodes->end())
            {
                TimelineGraphNode node = {};
                node.Id = id;
                node.Kind = kind;
                node.Label = label;
                it = nodes->insert(std::make_pair(id, node)).first;
            }
            if (eventNodes->insert(id).second)
            {
                ++it->second.EventCount;
            }
        }
    }

    void AddGraphEdge(
        std::map<std::wstring, TimelineGraphEdge>* edges,
        std::set<std::wstring>* eventEdges,
        const std::wstring& from,
        const std::wstring& to,
        const std::wstring& kind,
        uint64_t eventId)
    {
        if (edges != nullptr &&
            eventEdges != nullptr &&
            !from.empty() &&
            !to.empty() &&
            from != to)
        {
            std::wstring key = from + L"\n" + to + L"\n" + kind;
            auto it = edges->find(key);
            if (it == edges->end())
            {
                TimelineGraphEdge edge = {};
                edge.From = from;
                edge.To = to;
                edge.Kind = kind;
                it = edges->insert(std::make_pair(key, edge)).first;
            }
            if (eventEdges->insert(key).second)
            {
                ++it->second.EventCount;
                if (it->second.FirstEventId == 0 || eventId < it->second.FirstEventId)
                {
                    it->second.FirstEventId = eventId;
                }
                if (eventId > it->second.LastEventId)
                {
                    it->second.LastEventId = eventId;
                }
            }
        }
    }

    bool TryGetEvidencePid(const TimelineEvent& event, const std::wstring& key, uint32_t* pid)
    {
        bool ok = false;
        std::wstring value;

        if (EvidenceValueByKey(event, key, &value))
        {
            ok = ParsePidFromText(value, pid);
        }

        return ok;
    }

    bool SnapshotEvidenceValueByKey(
        const SnapshotRecord& record,
        const std::wstring& key,
        std::wstring* value)
    {
        bool found = false;
        std::wstring wanted = TimelineToLower(key);

        for (const auto& item : record.Evidence)
        {
            if (TimelineToLower(item.first) == wanted)
            {
                if (value != nullptr)
                {
                    *value = item.second;
                }
                found = true;
                break;
            }
        }

        return found;
    }

    bool SnapshotRecordPid(const SnapshotRecord& record, const std::wstring& key, uint32_t* pid)
    {
        bool ok = false;
        std::wstring value;

        if (SnapshotEvidenceValueByKey(record, key, &value))
        {
            ok = ParsePidFromText(value, pid);
        }

        return ok;
    }

    uint32_t SnapshotRecordAnyPid(const SnapshotRecord& record)
    {
        uint32_t pid = 0;
        static const wchar_t* kKeys[] =
        {
            L"pid",
            L"process_id",
            L"owner_pid",
            L"target_pid",
            L"source_pid"
        };

        for (const wchar_t* key : kKeys)
        {
            if (SnapshotRecordPid(record, key, &pid))
            {
                break;
            }
        }

        return pid;
    }

    void AddLowerNonEmpty(std::set<std::wstring>* values, const std::wstring& value)
    {
        if (values != nullptr && !value.empty())
        {
            values->insert(TimelineToLower(value));
        }
    }

    void AddLowerImageVariants(std::set<std::wstring>* values, const std::wstring& value)
    {
        if (values != nullptr && !value.empty())
        {
            std::wstring lowered = TimelineToLower(value);
            values->insert(lowered);

            size_t slash = lowered.find_last_of(L"\\/");
            if (slash != std::wstring::npos && slash + 1 < lowered.size())
            {
                values->insert(lowered.substr(slash + 1));
            }
        }
    }

    void AddSnapshotRecordImages(const SnapshotRecord& record, std::set<std::wstring>* images)
    {
        std::wstring value;
        if (SnapshotEvidenceValueByKey(record, L"image", &value))
        {
            AddLowerImageVariants(images, value);
        }
        if (SnapshotEvidenceValueByKey(record, L"image_path", &value))
        {
            AddLowerImageVariants(images, value);
        }
        if (SnapshotEvidenceValueByKey(record, L"target_image", &value))
        {
            AddLowerImageVariants(images, value);
        }
        if (SnapshotEvidenceValueByKey(record, L"path", &value))
        {
            AddLowerImageVariants(images, value);
        }
    }

    bool TimelineEventMatchesReconcile(
        const TimelineEvent& event,
        const TimelineReconcileOptions& options)
    {
        bool matched = true;
        if (!options.Source.empty() &&
            TimelineToLower(event.Source) != TimelineToLower(options.Source))
        {
            matched = false;
        }
        if (matched &&
            !options.Domain.empty() &&
            TimelineToLower(event.Domain) != TimelineToLower(options.Domain))
        {
            matched = false;
        }
        if (matched &&
            options.HasProcessId &&
            event.ProcessId != options.ProcessId &&
            event.TargetProcessId != options.ProcessId)
        {
            matched = false;
        }
        return matched;
    }

    uint32_t ReconcileRiskRank(const std::wstring& risk)
    {
        uint32_t rank = 0;
        std::wstring lowered = TimelineToLower(risk);
        if (lowered == L"critical" || lowered == L"high")
        {
            rank = 3;
        }
        else if (lowered == L"medium")
        {
            rank = 2;
        }
        else if (lowered == L"low")
        {
            rank = 1;
        }
        return rank;
    }

    void AddReconcileFinding(
        std::vector<TimelineReconcileFinding>* findings,
        TimelineReconcileFinding finding,
        uint64_t liveDropped)
    {
        if (findings != nullptr)
        {
            if (liveDropped != 0 && finding.Confidence != L"event-backed")
            {
                finding.Confidence = L"loss-limited";
                finding.Evidence[L"live_dropped"] = std::to_wstring(liveDropped);
            }
            findings->push_back(std::move(finding));
        }
    }

    bool ReconcileFindingLess(
        const TimelineReconcileFinding& a,
        const TimelineReconcileFinding& b)
    {
        uint32_t ra = ReconcileRiskRank(a.Risk);
        uint32_t rb = ReconcileRiskRank(b.Risk);
        if (ra != rb)
        {
            return ra > rb;
        }
        if (a.Kind != b.Kind)
        {
            return a.Kind < b.Kind;
        }
        if (a.Domain != b.Domain)
        {
            return a.Domain < b.Domain;
        }
        return a.Subject < b.Subject;
    }

    uint32_t TimelineAnalysisRiskRank(const std::wstring& risk)
    {
        return TimelineRiskRankValue(risk);
    }

    bool TimelineAnalysisEventLess(const TimelineEvent& a, const TimelineEvent& b)
    {
        bool less = false;

        do
        {
            if (a.TimestampFileTime != 0 &&
                b.TimestampFileTime != 0 &&
                a.TimestampFileTime != b.TimestampFileTime)
            {
                less = a.TimestampFileTime < b.TimestampFileTime;
                break;
            }
            less = a.EventId < b.EventId;
        } while (false);

        return less;
    }

    uint64_t TimelineAnalysisDelta100ns(uint64_t a, uint64_t b)
    {
        uint64_t delta = static_cast<uint64_t>(-1);
        if (a != 0 && b != 0)
        {
            delta = a >= b ? a - b : b - a;
        }
        return delta;
    }

    std::wstring TimelineAnalysisDeltaMsText(uint64_t delta100ns)
    {
        std::wstring text;
        if (delta100ns != static_cast<uint64_t>(-1))
        {
            text = std::to_wstring(delta100ns / 10000);
        }
        return text;
    }

    std::wstring TimelineThreadKey(uint32_t pid, uint32_t tid)
    {
        return std::to_wstring(pid) + L":" + std::to_wstring(tid);
    }

    bool TimelineActionIs(const TimelineEvent& event, const std::wstring& action)
    {
        return TimelineToLower(event.Action) == action;
    }

    bool TimelineEventIsProcessCreate(const TimelineEvent& event)
    {
        return TimelineToLower(event.Domain) == L"process" &&
            TimelineActionIs(event, L"process-create");
    }

    bool TimelineEventIsProcessExit(const TimelineEvent& event)
    {
        return TimelineToLower(event.Domain) == L"process" &&
            TimelineActionIs(event, L"process-exit");
    }

    bool TimelineEventIsThreadCreate(const TimelineEvent& event)
    {
        return TimelineToLower(event.Domain) == L"thread" &&
            TimelineActionIs(event, L"thread-create");
    }

    bool TimelineEventIsThreadExit(const TimelineEvent& event)
    {
        return TimelineToLower(event.Domain) == L"thread" &&
            TimelineActionIs(event, L"thread-exit");
    }

    bool TimelineEventIsImageLoad(const TimelineEvent& event)
    {
        return TimelineToLower(event.Domain) == L"image" &&
            TimelineActionIs(event, L"image-load");
    }

    bool TimelineEventIsRiskyTi(const TimelineEvent& event)
    {
        bool risky = false;
        if (TimelineToLower(event.Source) == L"ti" &&
            TimelineAnalysisRiskRank(event.Risk) >= 3)
        {
            risky = true;
        }
        return risky;
    }

    uint32_t TimelineCorrelationPid(const TimelineEvent& event)
    {
        uint32_t pid = event.TargetProcessId;
        if (pid == 0)
        {
            pid = event.ProcessId;
        }
        return pid;
    }

    bool TimelineAnalysisFindingLess(
        const TimelineAnalysisFinding& a,
        const TimelineAnalysisFinding& b)
    {
        uint32_t ra = TimelineAnalysisRiskRank(a.Risk);
        uint32_t rb = TimelineAnalysisRiskRank(b.Risk);
        if (ra != rb)
        {
            return ra > rb;
        }
        if (a.FirstEventId != b.FirstEventId)
        {
            return a.FirstEventId < b.FirstEventId;
        }
        if (a.Kind != b.Kind)
        {
            return a.Kind < b.Kind;
        }
        return a.Summary < b.Summary;
    }

    void AddShortLifetimeFinding(
        std::vector<TimelineAnalysisFinding>* findings,
        const TimelineEvent& startEvent,
        const TimelineEvent& endEvent,
        const std::wstring& kind,
        const std::wstring& risk,
        uint64_t threshold100ns)
    {
        do
        {
            if (findings == nullptr ||
                startEvent.TimestampFileTime == 0 ||
                endEvent.TimestampFileTime == 0)
            {
                break;
            }

            uint64_t delta = TimelineAnalysisDelta100ns(
                startEvent.TimestampFileTime,
                endEvent.TimestampFileTime);
            if (delta > threshold100ns)
            {
                break;
            }

            TimelineAnalysisFinding finding = {};
            finding.Kind = kind;
            finding.Risk = risk;
            finding.Confidence = L"event-backed";
            finding.FirstEventId = startEvent.EventId;
            finding.LastEventId = endEvent.EventId;
            finding.ProcessId = startEvent.ProcessId != 0 ? startEvent.ProcessId : endEvent.ProcessId;
            finding.ThreadId = startEvent.ThreadId != 0 ? startEvent.ThreadId : endEvent.ThreadId;
            finding.Summary = kind + L" pid=" + std::to_wstring(finding.ProcessId);
            if (finding.ThreadId != 0)
            {
                finding.Summary += L" tid=" + std::to_wstring(finding.ThreadId);
            }
            finding.Evidence[L"delta_ms"] = TimelineAnalysisDeltaMsText(delta);
            finding.Evidence[L"start_action"] = startEvent.Action;
            finding.Evidence[L"end_action"] = endEvent.Action;
            findings->push_back(std::move(finding));
        } while (false);
    }

    void AddCorrelationFinding(
        std::vector<TimelineAnalysisFinding>* findings,
        const TimelineEvent& tiEvent,
        const TimelineEvent& liveEvent,
        const std::wstring& kind,
        uint64_t threshold100ns)
    {
        do
        {
            if (findings == nullptr ||
                tiEvent.TimestampFileTime == 0 ||
                liveEvent.TimestampFileTime == 0)
            {
                break;
            }

            uint64_t delta = TimelineAnalysisDelta100ns(
                tiEvent.TimestampFileTime,
                liveEvent.TimestampFileTime);
            if (delta > threshold100ns)
            {
                break;
            }

            TimelineAnalysisFinding finding = {};
            finding.Kind = kind;
            finding.Risk = TimelineAnalysisRiskRank(tiEvent.Risk) >= 4 ? L"critical" : L"warning";
            finding.Confidence = L"correlated";
            finding.FirstEventId = std::min(tiEvent.EventId, liveEvent.EventId);
            finding.LastEventId = std::max(tiEvent.EventId, liveEvent.EventId);
            finding.ProcessId = liveEvent.ProcessId;
            finding.ThreadId = liveEvent.ThreadId;
            finding.TargetProcessId = tiEvent.TargetProcessId;
            finding.Summary = kind + L" pid=" + std::to_wstring(TimelineCorrelationPid(tiEvent));
            finding.Evidence[L"delta_ms"] = TimelineAnalysisDeltaMsText(delta);
            finding.Evidence[L"ti_action"] = tiEvent.Action;
            finding.Evidence[L"ti_event_id"] = std::to_wstring(tiEvent.EventId);
            finding.Evidence[L"live_action"] = liveEvent.Action;
            finding.Evidence[L"live_event_id"] = std::to_wstring(liveEvent.EventId);
            if (!liveEvent.Entity.empty())
            {
                finding.Evidence[L"live_entity"] = liveEvent.Entity;
            }
            findings->push_back(std::move(finding));
        } while (false);
    }

    void AddGenericCorrelationFinding(
        std::vector<TimelineAnalysisFinding>* findings,
        const TimelineEvent& anchorEvent,
        const TimelineEvent& relatedEvent,
        const std::wstring& kind,
        uint64_t threshold100ns)
    {
        do
        {
            if (findings == nullptr ||
                anchorEvent.TimestampFileTime == 0 ||
                relatedEvent.TimestampFileTime == 0)
            {
                break;
            }

            uint64_t delta = TimelineAnalysisDelta100ns(
                anchorEvent.TimestampFileTime,
                relatedEvent.TimestampFileTime);
            if (delta > threshold100ns)
            {
                break;
            }

            TimelineAnalysisFinding finding = {};
            finding.Kind = kind;
            finding.Risk =
                TimelineAnalysisRiskRank(anchorEvent.Risk) >= TimelineAnalysisRiskRank(relatedEvent.Risk) ?
                anchorEvent.Risk :
                relatedEvent.Risk;
            if (finding.Risk.empty())
            {
                finding.Risk = L"warning";
            }
            finding.Confidence = L"correlated";
            finding.FirstEventId = std::min(anchorEvent.EventId, relatedEvent.EventId);
            finding.LastEventId = std::max(anchorEvent.EventId, relatedEvent.EventId);
            finding.ProcessId = anchorEvent.ProcessId != 0 ? anchorEvent.ProcessId : relatedEvent.ProcessId;
            finding.ThreadId = anchorEvent.ThreadId != 0 ? anchorEvent.ThreadId : relatedEvent.ThreadId;
            finding.TargetProcessId = anchorEvent.TargetProcessId != 0 ? anchorEvent.TargetProcessId : relatedEvent.TargetProcessId;
            finding.Summary = kind;
            if (finding.ProcessId != 0)
            {
                finding.Summary += L" pid=" + std::to_wstring(finding.ProcessId);
            }
            finding.Evidence[L"delta_ms"] = TimelineAnalysisDeltaMsText(delta);
            finding.Evidence[L"anchor_action"] = anchorEvent.Action;
            finding.Evidence[L"anchor_event_id"] = std::to_wstring(anchorEvent.EventId);
            finding.Evidence[L"related_action"] = relatedEvent.Action;
            finding.Evidence[L"related_event_id"] = std::to_wstring(relatedEvent.EventId);
            static const wchar_t* const familyKeys[] =
            {
                L"analysis_family"
            };
            AddEvidenceIfPresent(
                &finding.Evidence,
                L"anchor_family",
                FirstEvidenceValue(anchorEvent, familyKeys, sizeof(familyKeys) / sizeof(familyKeys[0])));
            AddEvidenceIfPresent(
                &finding.Evidence,
                L"related_family",
                FirstEvidenceValue(relatedEvent, familyKeys, sizeof(familyKeys) / sizeof(familyKeys[0])));
            findings->push_back(std::move(finding));
        } while (false);
    }

    void AddSemanticEventFinding(
        std::vector<TimelineAnalysisFinding>* findings,
        const TimelineEvent& event)
    {
        do
        {
            if (findings == nullptr)
            {
                break;
            }

            std::wstring family;
            if (!EvidenceValueByKey(event, L"analysis_family", &family) || family.empty())
            {
                break;
            }

            std::wstring kind;
            std::wstring summary;
            std::wstring risk = event.Risk.empty() ? L"info" : event.Risk;
            bool add = true;
            if (family == L"cross-process")
            {
                kind = L"cross-process-manipulation";
                std::wstring operation;
                EvidenceValueByKey(event, L"cross_process_operation", &operation);
                summary = L"cross-process " + (operation.empty() ? event.Action : operation);
            }
            else if (family == L"network" || family == L"dns")
            {
                if (TimelineAnalysisRiskRank(event.Risk) < 3)
                {
                    add = false;
                }
                kind = L"network-dns-activity";
                summary = family + L" activity";
            }
            else if (family == L"file-artifact")
            {
                std::wstring executable;
                if (TimelineAnalysisRiskRank(event.Risk) < 3 &&
                    (!EvidenceValueByKey(event, L"file_executable", &executable) || executable != L"true"))
                {
                    add = false;
                }
                kind = L"executable-file-artifact";
                summary = L"file artifact";
            }
            else if (family == L"registry-persistence")
            {
                kind = L"registry-persistence-change";
                summary = L"registry persistence change";
            }
            else if (family == L"service-persistence")
            {
                kind = L"service-persistence-change";
                summary = L"service persistence change";
            }
            else if (family == L"task-persistence")
            {
                kind = L"scheduled-task-change";
                summary = L"scheduled task change";
            }
            else if (family == L"wmi-persistence")
            {
                kind = L"wmi-persistence-change";
                summary = L"WMI persistence change";
            }
            else if (family == L"memory-executable")
            {
                kind = L"memory-executable-transition";
                summary = L"memory executable transition";
            }
            else if (family == L"snapshot-diff")
            {
                kind = L"snapshot-diff-milestone";
                summary = L"snapshot diff milestone";
            }
            else
            {
                add = false;
            }

            if (!add || kind.empty())
            {
                break;
            }

            TimelineAnalysisFinding finding = {};
            finding.Kind = kind;
            finding.Risk = risk;
            finding.Confidence = event.Confidence.empty() ? L"event-backed" : event.Confidence;
            finding.FirstEventId = event.EventId;
            finding.LastEventId = event.EventId;
            finding.ProcessId = event.ProcessId;
            finding.ThreadId = event.ThreadId;
            finding.TargetProcessId = event.TargetProcessId;
            finding.Summary = summary;
            if (event.ProcessId != 0)
            {
                finding.Summary += L" pid=" + std::to_wstring(event.ProcessId);
            }
            if (event.TargetProcessId != 0)
            {
                finding.Summary += L" target_pid=" + std::to_wstring(event.TargetProcessId);
            }
            if (!event.Entity.empty())
            {
                finding.Evidence[L"entity"] = event.Entity;
            }
            finding.Evidence[L"event_id"] = std::to_wstring(event.EventId);
            finding.Evidence[L"source"] = event.Source;
            finding.Evidence[L"domain"] = event.Domain;
            finding.Evidence[L"action"] = event.Action;
            for (const auto& item : event.Evidence)
            {
                if (finding.Evidence.size() >= 20)
                {
                    break;
                }
                AddEvidenceIfPresent(&finding.Evidence, item.first, item.second);
            }
            findings->push_back(std::move(finding));
        } while (false);
    }

    void AddTimelineGraphEvent(
        const TimelineEvent& event,
        std::map<std::wstring, TimelineGraphNode>* nodes,
        std::map<std::wstring, TimelineGraphEdge>* edges)
    {
        std::set<std::wstring> eventNodes;
        std::set<std::wstring> eventEdges;

        std::wstring sourceLabel = event.Source.empty() ? L"<unknown>" : event.Source;
        std::wstring domainLabel = event.Domain.empty() ? L"<unknown>" : event.Domain;
        std::wstring sourceId = GraphNodeId(L"source", sourceLabel);
        std::wstring domainId = GraphNodeId(L"domain", domainLabel);
        AddGraphNode(nodes, &eventNodes, L"source", sourceLabel);
        AddGraphNode(nodes, &eventNodes, L"domain", domainLabel);
        AddGraphEdge(edges, &eventEdges, sourceId, domainId, L"source-domain", event.EventId);

        std::wstring processId;
        if (event.ProcessId != 0)
        {
            std::wstring label = ProcessLabel(event.ProcessId);
            processId = GraphNodeId(L"process", label);
            AddGraphNode(nodes, &eventNodes, L"process", label);
            AddGraphEdge(edges, &eventEdges, sourceId, processId, L"source-observes-process", event.EventId);
            AddGraphEdge(
                edges,
                &eventEdges,
                processId,
                domainId,
                TimelineToLower(event.Source) == L"snapshot" ? L"snapshot-record" : L"process-domain",
                event.EventId);
        }

        std::wstring targetProcessId;
        if (event.TargetProcessId != 0)
        {
            std::wstring label = ProcessLabel(event.TargetProcessId);
            targetProcessId = GraphNodeId(L"process", label);
            AddGraphNode(nodes, &eventNodes, L"process", label);
            AddGraphEdge(edges, &eventEdges, sourceId, targetProcessId, L"source-observes-process", event.EventId);
            if (!processId.empty())
            {
                AddGraphEdge(
                    edges,
                    &eventEdges,
                    processId,
                    targetProcessId,
                    TimelineToLower(event.Source) == L"ti" ? L"ti-targets-process" : L"targets-process",
                    event.EventId);
            }

            std::wstring operation;
            if (!processId.empty() && EvidenceValueByKey(event, L"cross_process_operation", &operation))
            {
                AddGraphEdge(
                    edges,
                    &eventEdges,
                    processId,
                    targetProcessId,
                    L"cross-process-" + operation,
                    event.EventId);
            }
        }

        uint32_t sourcePid = 0;
        std::wstring sourceOperation;
        if ((TryGetEvidencePid(event, L"source_pid", &sourcePid) ||
             TryGetEvidencePid(event, L"creator_pid", &sourcePid)) &&
            sourcePid != 0 &&
            sourcePid != event.ProcessId)
        {
            std::wstring sourceProcessLabel = ProcessLabel(sourcePid);
            std::wstring sourceProcessId = GraphNodeId(L"process", sourceProcessLabel);
            std::wstring destinationProcessId = !targetProcessId.empty() ? targetProcessId : processId;
            AddGraphNode(nodes, &eventNodes, L"process", sourceProcessLabel);
            AddGraphEdge(edges, &eventEdges, sourceId, sourceProcessId, L"source-observes-process", event.EventId);
            if (!destinationProcessId.empty())
            {
                if (!EvidenceValueByKey(event, L"cross_process_operation", &sourceOperation) ||
                    sourceOperation.empty())
                {
                    sourceOperation = L"creator";
                }
                AddGraphEdge(
                    edges,
                    &eventEdges,
                    sourceProcessId,
                    destinationProcessId,
                    L"cross-process-" + sourceOperation,
                    event.EventId);
            }
        }

        uint32_t parentPid = 0;
        if (event.ProcessId != 0 &&
            (TryGetEvidencePid(event, L"parent_pid", &parentPid) ||
             TryGetEvidencePid(event, L"ppid", &parentPid) ||
             TryGetEvidencePid(event, L"parent_process_id", &parentPid) ||
             TryGetEvidencePid(event, L"inherited_from_pid", &parentPid)) &&
            parentPid != event.ProcessId)
        {
            std::wstring parentLabel = ProcessLabel(parentPid);
            std::wstring parentId = GraphNodeId(L"process", parentLabel);
            AddGraphNode(nodes, &eventNodes, L"process", parentLabel);
            AddGraphEdge(edges, &eventEdges, parentId, processId, L"parent-child", event.EventId);
        }

        std::vector<TimelineImageRef> images = TimelineEventImageRefs(event);
        for (const TimelineImageRef& imageRef : images)
        {
            std::wstring imageId = GraphNodeId(L"image", imageRef.Value);
            AddGraphNode(nodes, &eventNodes, L"image", imageRef.Value);
            AddGraphEdge(edges, &eventEdges, sourceId, imageId, L"source-observes-image", event.EventId);
            if (!processId.empty() && imageRef.LinkSourceProcess)
            {
                AddGraphEdge(edges, &eventEdges, processId, imageId, L"process-loads-image", event.EventId);
            }
            if (!targetProcessId.empty() && imageRef.LinkTargetProcess)
            {
                AddGraphEdge(edges, &eventEdges, targetProcessId, imageId, L"process-loads-image", event.EventId);
            }
        }

        auto addEvidenceEntity =
            [&](const wchar_t* const* keys, size_t keyCount, const std::wstring& kind, const std::wstring& edgeKind)
        {
            std::wstring value = FirstEvidenceValue(event, keys, keyCount);
            if (value.empty())
            {
                return;
            }

            std::wstring id = GraphNodeId(kind, value);
            AddGraphNode(nodes, &eventNodes, kind, value);
            AddGraphEdge(edges, &eventEdges, sourceId, id, L"source-observes-" + kind, event.EventId);
            if (!processId.empty())
            {
                AddGraphEdge(edges, &eventEdges, processId, id, edgeKind, event.EventId);
            }
            else if (!targetProcessId.empty())
            {
                AddGraphEdge(edges, &eventEdges, targetProcessId, id, edgeKind, event.EventId);
            }
        };

        static const wchar_t* const hostKeys[] = {L"network_endpoint", L"remote_host"};
        static const wchar_t* const dnsKeys[] = {L"dns_query"};
        static const wchar_t* const fileKeys[] = {L"file_path"};
        static const wchar_t* const registryKeys[] = {L"registry_key"};
        static const wchar_t* const serviceKeys[] = {L"service_name"};
        static const wchar_t* const taskKeys[] = {L"scheduled_task"};
        static const wchar_t* const wmiKeys[] = {L"wmi_entity"};
        static const wchar_t* const memoryKeys[] = {L"memory_address", L"vad_address"};
        static const wchar_t* const snapshotDiffKeys[] = {L"snapshot_diff_subject"};

        addEvidenceEntity(hostKeys, sizeof(hostKeys) / sizeof(hostKeys[0]), L"host", L"process-connects-host");
        addEvidenceEntity(dnsKeys, sizeof(dnsKeys) / sizeof(dnsKeys[0]), L"dns", L"process-queries-dns");
        addEvidenceEntity(fileKeys, sizeof(fileKeys) / sizeof(fileKeys[0]), L"file", L"process-touches-file");
        addEvidenceEntity(registryKeys, sizeof(registryKeys) / sizeof(registryKeys[0]), L"registry", L"process-modifies-registry");
        addEvidenceEntity(serviceKeys, sizeof(serviceKeys) / sizeof(serviceKeys[0]), L"service", L"process-controls-service");
        addEvidenceEntity(taskKeys, sizeof(taskKeys) / sizeof(taskKeys[0]), L"task", L"process-controls-task");
        addEvidenceEntity(wmiKeys, sizeof(wmiKeys) / sizeof(wmiKeys[0]), L"wmi", L"process-controls-wmi");
        addEvidenceEntity(memoryKeys, sizeof(memoryKeys) / sizeof(memoryKeys[0]), L"memory", L"process-changes-memory");
        addEvidenceEntity(snapshotDiffKeys, sizeof(snapshotDiffKeys) / sizeof(snapshotDiffKeys[0]), L"snapshot-diff", L"snapshot-diff-record");
    }
}

TimelineStore::TimelineStore() :
    TimelineStore(262144)
{
}

TimelineStore::TimelineStore(size_t capacity)
{
    SetCapacity(capacity);
}

void TimelineStore::Clear()
{
    std::lock_guard<std::mutex> lock(Mutex);
    Events.clear();
    EventKeysInOrder.clear();
    EventKeys.clear();
    NextEventId = 1;
    DroppedEvents = 0;
    TiRecentCursorInitialized = false;
    TiRecentCursorTimestamp = 0;
    TiRecentCursorBoundaryKeys.clear();
}

void TimelineStore::SetCapacity(size_t capacity)
{
    std::lock_guard<std::mutex> lock(Mutex);
    if (capacity < kMinTimelineCapacity)
    {
        capacity = kMinTimelineCapacity;
    }
    if (capacity > kMaxTimelineCapacity)
    {
        capacity = kMaxTimelineCapacity;
    }

    MaxEvents = capacity;
    while (Events.size() > MaxEvents)
    {
        DropOldestEventLocked();
        ++DroppedEvents;
    }
}

size_t TimelineStore::Capacity() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return MaxEvents;
}

uint64_t TimelineStore::GetTiRecentCursorTimestamp(bool* initialized) const
{
    std::lock_guard<std::mutex> lock(Mutex);
    if (initialized != nullptr)
    {
        *initialized = TiRecentCursorInitialized;
    }
    return TiRecentCursorTimestamp;
}

uint64_t TimelineStore::Dropped() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return DroppedEvents;
}

TimelineIngestResult TimelineStore::IngestThreatIntel(
    const std::vector<TiEventRecord>& events,
    const std::wstring& mode,
    size_t maxAdd)
{
    TimelineIngestResult result = {};

    std::lock_guard<std::mutex> lock(Mutex);
    uint64_t beforeDropped = DroppedEvents;
    bool useCursor = TimelineToLower(mode) != L"all";
    size_t skippedByCursor = 0;
    size_t truncatedByMaxAdd = 0;
    uint64_t maxTimestamp = TiRecentCursorTimestamp;
    std::set<std::wstring> maxTimestampKeys = TiRecentCursorBoundaryKeys;

    for (const TiEventRecord& item : events)
    {
        std::wstring cursorKey;
        if (useCursor &&
            TiRecentCursorInitialized &&
            item.Timestamp != 0)
        {
            if (item.Timestamp < TiRecentCursorTimestamp)
            {
                ++skippedByCursor;
                continue;
            }
            if (item.Timestamp == TiRecentCursorTimestamp)
            {
                cursorKey = TiEventCursorKey(item);
                if (TiRecentCursorBoundaryKeys.find(cursorKey) != TiRecentCursorBoundaryKeys.end())
                {
                    ++skippedByCursor;
                    continue;
                }
            }
        }

        // Cap newly added events. Stop before consuming this item so the
        // recent cursor does not jump past unprocessed ring records.
        if (maxAdd != 0 && result.Added >= maxAdd)
        {
            ++truncatedByMaxAdd;
            break;
        }

        ++result.SourceRecords;

        TimelineEvent event = {};
        event.TimestampFileTime = item.Timestamp;
        event.Source = L"ti";
        event.Domain = L"threat-intelligence";
        event.Action = TiTaskText(item);
        event.ProcessId = item.ProcessId;
        event.ThreadId = item.ThreadId;
        event.TargetProcessId = item.TargetProcessId;
        event.Entity = event.Action;
        event.Summary = event.Action;
        if (!item.ImagePath.empty())
        {
            event.Summary += L" image=" + item.ImagePath;
        }
        if (item.TargetProcessId != 0)
        {
            event.Summary += L" target_pid=" + std::to_wstring(item.TargetProcessId);
        }

        TiTimelineClassification classification = ClassifyTiTimelineEvent(item);
        event.Risk = classification.Risk;
        event.Confidence = item.DecodedByTdh ? L"tdh-decoded" : L"raw";
        event.Evidence[L"mode"] = mode;
        event.Evidence[L"ti_action"] = event.Action;
        event.Evidence[L"classification"] = classification.Category;
        event.Evidence[L"classification_reason"] = classification.Reason;
        event.Evidence[L"task_id"] = std::to_wstring(static_cast<uint32_t>(item.TaskId));
        event.Evidence[L"level"] = std::to_wstring(static_cast<uint32_t>(item.Level));
        event.Evidence[L"opcode"] = std::to_wstring(static_cast<uint32_t>(item.Opcode));
        event.Evidence[L"channel"] = std::to_wstring(static_cast<uint32_t>(item.Channel));
        if (item.Keyword != 0)
        {
            event.Evidence[L"keyword"] = HexU64(item.Keyword);
        }
        AddEvidenceIfPresent(&event.Evidence, L"task_name", item.TaskName);
        AddEvidenceIfPresent(&event.Evidence, L"opcode_name", item.OpcodeName);
        AddEvidenceIfPresent(&event.Evidence, L"image_path", item.ImagePath);
        AddEvidenceIfPresent(&event.Evidence, L"target_image", item.TargetImageBase);
        AddEvidenceIfPresent(&event.Evidence, L"raw_payload_hex", item.RawPayloadHex);

        event.Evidence[L"payload_field_count"] = std::to_wstring(item.Payload.size());
        for (size_t index = 0; index < item.Payload.size(); ++index)
        {
            std::wstring key = L"payload." + item.Payload[index].Name;
            if (!item.Payload[index].Value.empty())
            {
                event.Evidence[key] = item.Payload[index].Value;
            }
            if (!item.Payload[index].TypeName.empty())
            {
                event.Evidence[L"payload_type." + item.Payload[index].Name] = item.Payload[index].TypeName;
            }
        }

        if (AddEventLocked(std::move(event)))
        {
            ++result.Added;
        }

        if (item.Timestamp > maxTimestamp)
        {
            maxTimestamp = item.Timestamp;
            maxTimestampKeys.clear();
        }
        if (item.Timestamp != 0 && item.Timestamp == maxTimestamp)
        {
            if (cursorKey.empty())
            {
                cursorKey = TiEventCursorKey(item);
            }
            maxTimestampKeys.insert(cursorKey);
        }
    }

    if (maxTimestamp > TiRecentCursorTimestamp)
    {
        TiRecentCursorTimestamp = maxTimestamp;
        TiRecentCursorBoundaryKeys = std::move(maxTimestampKeys);
        TiRecentCursorInitialized = true;
    }
    else if (!TiRecentCursorInitialized && result.SourceRecords != 0)
    {
        TiRecentCursorInitialized = true;
        TiRecentCursorBoundaryKeys = std::move(maxTimestampKeys);
    }
    else if (TiRecentCursorInitialized && maxTimestamp == TiRecentCursorTimestamp)
    {
        TiRecentCursorBoundaryKeys = std::move(maxTimestampKeys);
    }

    if (skippedByCursor != 0)
    {
        result.Warnings.push_back(
            L"ti recent cursor skipped " + std::to_wstring(skippedByCursor) +
            L" previously ingested ring records; use '!timeline ingest ti all' to rescan the ring");
    }
    if (truncatedByMaxAdd != 0)
    {
        result.Warnings.push_back(
            L"ti ingest stopped after maxAdd=" + std::to_wstring(maxAdd) +
            L" added events; cursor advanced only through processed records so the remainder can be ingested next");
    }

    result.Dropped = DroppedEvents - beforeDropped;
    return result;
}

TimelineIngestResult TimelineStore::IngestSnapshot(
    const SnapshotDocument& document,
    const std::wstring& sourceName)
{
    TimelineIngestResult result = {};
    result.SourceRecords = document.Processes.size() + document.Records.size();

    std::lock_guard<std::mutex> lock(Mutex);
    uint64_t beforeDropped = DroppedEvents;

    for (const SnapshotProcessRecord& process : document.Processes)
    {
        TimelineEvent event = {};
        event.TimestampUtc = document.TimestampUtc;
        event.Source = L"snapshot";
        event.Domain = L"process";
        event.Action = L"observed";
        event.ProcessId = process.ProcessId;
        event.Entity = process.Identity.empty() ? process.ImageName : process.Identity;
        event.Summary = L"snapshot process " + process.ImageName;
        event.Risk = L"info";
        event.Confidence = L"snapshot";
        event.Evidence[L"source"] = sourceName;
        AddEvidenceIfPresent(&event.Evidence, L"label", document.Label);
        AddEvidenceIfPresent(&event.Evidence, L"boot_id", document.BootId);
        AddEvidenceIfPresent(&event.Evidence, L"image", process.ImageName);
        AddEvidenceIfPresent(&event.Evidence, L"identity", process.Identity);
        if (process.Eprocess != 0)
        {
            event.Evidence[L"eprocess"] = HexU64(process.Eprocess);
        }
        if (process.DirectoryTableBase != 0)
        {
            event.Evidence[L"dtb"] = HexU64(process.DirectoryTableBase);
        }
        if (process.UserDirectoryTableBase != 0)
        {
            event.Evidence[L"user_dtb"] = HexU64(process.UserDirectoryTableBase);
        }
        if (process.HasCreateTime)
        {
            event.Evidence[L"create_time"] = std::to_wstring(process.CreateTime);
        }

        if (AddEventLocked(std::move(event)))
        {
            ++result.Added;
        }
    }

    for (const SnapshotRecord& record : document.Records)
    {
        TimelineEvent event = {};
        event.TimestampUtc = document.TimestampUtc;
        event.Source = L"snapshot";
        event.Domain = record.Domain.empty() ? L"snapshot" : record.Domain;
        event.Action = L"observed";
        event.ProcessId = SnapshotRecordPid(record);
        event.Entity = record.Identity;
        event.Summary = SnapshotRecordSummary(record);
        event.Risk = record.Risk.empty() ? L"info" : record.Risk;
        event.Confidence = record.Volatile ? L"volatile-snapshot" : L"snapshot";
        event.Evidence = record.Evidence;
        event.Evidence[L"source"] = sourceName;
        AddEvidenceIfPresent(&event.Evidence, L"label", document.Label);
        AddEvidenceIfPresent(&event.Evidence, L"boot_id", document.BootId);
        AddEvidenceIfPresent(&event.Evidence, L"display", record.Display);
        if (!record.Tags.empty())
        {
            std::wstring tags;
            for (size_t i = 0; i < record.Tags.size(); ++i)
            {
                if (i > 0)
                {
                    tags += L",";
                }
                tags += record.Tags[i];
            }
            event.Evidence[L"tags"] = tags;
        }

        if (AddEventLocked(std::move(event)))
        {
            ++result.Added;
        }
    }

    for (const auto& item : document.DomainWarnings)
    {
        for (const std::wstring& warning : item.second)
        {
            result.Warnings.push_back(item.first + L": " + warning);
        }
    }

    result.Dropped = DroppedEvents - beforeDropped;
    return result;
}

TimelineIngestResult TimelineStore::IngestSnapshotDiff(
    const SnapshotDiffResult& diff,
    const std::wstring& sourceName)
{
    TimelineIngestResult result = {};
    result.SourceRecords = diff.Findings.size();

    std::lock_guard<std::mutex> lock(Mutex);
    uint64_t beforeDropped = DroppedEvents;

    for (const SnapshotDiffFinding& finding : diff.Findings)
    {
        const SnapshotRecord& record = finding.NewRecord;
        TimelineEvent event = {};
        event.Source = L"snapshot-diff";
        event.Domain = record.Domain.empty() ? L"snapshot-diff" : record.Domain;
        event.Action = finding.Kind.empty() ? L"diff" : finding.Kind;
        event.ProcessId = SnapshotRecordPid(record);
        event.Entity = record.Identity.empty() ? record.Display : record.Identity;
        event.Summary = L"snapshot-diff " + event.Action;
        if (!event.Domain.empty())
        {
            event.Summary += L" domain=" + event.Domain;
        }
        if (!event.Entity.empty())
        {
            event.Summary += L" " + event.Entity;
        }
        event.Risk = record.Risk.empty() ? L"warning" : record.Risk;
        event.Confidence = L"snapshot-diff";
        event.Evidence = record.Evidence;
        event.Evidence[L"source"] = sourceName;
        event.Evidence[L"diff_kind"] = event.Action;
        AddEvidenceIfPresent(&event.Evidence, L"baseline_label", diff.BaselineLabel);
        AddEvidenceIfPresent(&event.Evidence, L"current_label", diff.CurrentLabel);
        AddEvidenceIfPresent(&event.Evidence, L"display", record.Display);
        AddEvidenceIfPresent(&event.Evidence, L"identity", record.Identity);
        AddEvidenceIfPresent(&event.Evidence, L"snapshot_diff_subject", event.Entity);
        AddEvidenceIfPresent(&event.Evidence, L"old_risk", finding.OldRecord.Risk);
        AddEvidenceIfPresent(&event.Evidence, L"new_risk", record.Risk);

        if (AddEventLocked(std::move(event)))
        {
            ++result.Added;
        }
    }

    for (const std::wstring& warning : diff.Warnings)
    {
        result.Warnings.push_back(warning);
    }

    result.Dropped = DroppedEvents - beforeDropped;
    return result;
}

TimelineIngestResult TimelineStore::IngestEvents(
    const std::vector<TimelineEvent>& events)
{
    TimelineIngestResult result = {};
    result.SourceRecords = events.size();

    std::lock_guard<std::mutex> lock(Mutex);
    uint64_t beforeDropped = DroppedEvents;
    for (const TimelineEvent& item : events)
    {
        TimelineEvent event = item;
        if (AddEventLocked(std::move(event)))
        {
            ++result.Added;
        }
    }

    result.Dropped = DroppedEvents - beforeDropped;
    return result;
}

std::vector<TimelineEvent> TimelineStore::Query(const TimelineQueryOptions& options) const
{
    std::vector<TimelineEvent> out;
    std::lock_guard<std::mutex> lock(Mutex);

    auto matches = [&options](const TimelineEvent& event) -> bool
    {
        bool matched = true;
        if (!options.Source.empty() &&
            TimelineToLower(event.Source) != TimelineToLower(options.Source))
        {
            matched = false;
        }
        if (matched &&
            !options.Domain.empty() &&
            TimelineToLower(event.Domain) != TimelineToLower(options.Domain))
        {
            matched = false;
        }
        if (matched &&
            options.HasProcessId &&
            event.ProcessId != options.ProcessId &&
            event.TargetProcessId != options.ProcessId)
        {
            matched = false;
        }
        return matched;
    };

    size_t limit = options.Limit;
    if (options.NewestFirst)
    {
        for (auto it = Events.rbegin(); it != Events.rend(); ++it)
        {
            if (matches(*it))
            {
                out.push_back(*it);
                if (limit != 0 && out.size() >= limit)
                {
                    break;
                }
            }
        }
    }
    else
    {
        for (const TimelineEvent& event : Events)
        {
            if (matches(event))
            {
                out.push_back(event);
                if (limit != 0 && out.size() >= limit)
                {
                    break;
                }
            }
        }
    }

    return out;
}

std::vector<TimelineEvent> TimelineStore::AllEvents() const
{
    std::lock_guard<std::mutex> lock(Mutex);
    return std::vector<TimelineEvent>(Events.begin(), Events.end());
}

TimelineGraphResult TimelineStore::BuildGraph(const TimelineGraphQueryOptions& options) const
{
    TimelineGraphResult result = {};
    result.Options = options;
    std::map<std::wstring, TimelineGraphNode> nodes;
    std::map<std::wstring, TimelineGraphEdge> edges;
    std::vector<TimelineEvent> events;

    {
        std::lock_guard<std::mutex> lock(Mutex);
        events.assign(Events.begin(), Events.end());
    }
    result.TotalEvents = events.size();

    auto handleEvent = [&result, &nodes, &edges, &options](const TimelineEvent& event) -> bool
    {
        bool keepGoing = true;
        if (TimelineEventMatchesGraphQuery(event, options))
        {
            if (options.Limit != 0 && result.MatchedEvents >= options.Limit)
            {
                result.Truncated = true;
                keepGoing = false;
            }
            else
            {
                AddTimelineGraphEvent(event, &nodes, &edges);
                ++result.MatchedEvents;
            }
        }
        return keepGoing;
    };

    if (options.NewestFirst)
    {
        for (auto it = events.rbegin(); it != events.rend(); ++it)
        {
            if (!handleEvent(*it))
            {
                break;
            }
        }
    }
    else
    {
        for (const TimelineEvent& event : events)
        {
            if (!handleEvent(event))
            {
                break;
            }
        }
    }

    for (const auto& item : nodes)
    {
        result.Nodes.push_back(item.second);
    }
    for (const auto& item : edges)
    {
        result.Edges.push_back(item.second);
    }

    return result;
}

TimelineReconcileResult TimelineStore::ReconcileSnapshot(
    const SnapshotDocument& document,
    const TimelineReconcileOptions& options) const
{
    TimelineReconcileResult result = {};
    result.Options = options;
    result.SnapshotLabel = document.Label.empty() ? L"<snapshot>" : document.Label;
    result.SnapshotProcesses = document.Processes.size();
    result.SnapshotRecords = document.Records.size();
    result.LiveDropped = options.LiveDropped;

    std::set<uint32_t> snapshotPids;
    std::set<std::wstring> snapshotImages;
    for (const SnapshotProcessRecord& process : document.Processes)
    {
        if (process.ProcessId != 0)
        {
            snapshotPids.insert(process.ProcessId);
        }
        AddLowerImageVariants(&snapshotImages, process.ImageName);
    }
    for (const SnapshotRecord& record : document.Records)
    {
        uint32_t pid = SnapshotRecordAnyPid(record);
        if (pid != 0)
        {
            snapshotPids.insert(pid);
        }
        AddSnapshotRecordImages(record, &snapshotImages);
    }

    std::vector<TimelineEvent> events = AllEvents();
    result.TimelineEvents = events.size();
    std::set<uint32_t> eventPids;
    std::set<std::wstring> eventImages;
    for (const TimelineEvent& event : events)
    {
        if (!TimelineEventMatchesReconcile(event, options))
        {
            continue;
        }
        if (event.ProcessId != 0)
        {
            eventPids.insert(event.ProcessId);
        }
        if (event.TargetProcessId != 0)
        {
            eventPids.insert(event.TargetProcessId);
        }
        std::vector<TimelineImageRef> images = TimelineEventImageRefs(event);
        for (const TimelineImageRef& image : images)
        {
            AddLowerImageVariants(&eventImages, image.Value);
        }

        if (event.ProcessId != 0 &&
            event.Action != L"process-exit" &&
            snapshotPids.find(event.ProcessId) == snapshotPids.end())
        {
            TimelineReconcileFinding finding = {};
            finding.Kind = L"event-without-snapshot-process";
            finding.Domain = event.Domain;
            finding.Subject = L"pid:" + std::to_wstring(event.ProcessId);
            finding.Risk = event.Action == L"image-load" ? L"medium" : L"low";
            finding.Confidence = L"event-backed";
            finding.Summary = L"timeline event has no matching process in snapshot";
            finding.EventId = event.EventId;
            finding.ProcessId = event.ProcessId;
            finding.Evidence[L"action"] = event.Action;
            finding.Evidence[L"source"] = event.Source;
            AddEvidenceIfPresent(&finding.Evidence, L"entity", event.Entity);
            AddReconcileFinding(&result.Findings, std::move(finding), options.LiveDropped);
        }

        for (const TimelineImageRef& image : images)
        {
            if (!image.Value.empty() && snapshotImages.find(TimelineToLower(image.Value)) == snapshotImages.end())
            {
                TimelineReconcileFinding finding = {};
                finding.Kind = L"event-without-snapshot-image";
                finding.Domain = event.Domain;
                finding.Subject = image.Value;
                finding.Risk = event.Action == L"image-load" ? L"medium" : L"low";
                finding.Confidence = L"event-backed";
                finding.Summary = L"timeline image evidence has no matching image in snapshot";
                finding.EventId = event.EventId;
                finding.ProcessId = event.ProcessId;
                finding.Evidence[L"action"] = event.Action;
                finding.Evidence[L"source"] = event.Source;
                AddReconcileFinding(&result.Findings, std::move(finding), options.LiveDropped);
            }
        }
    }

    for (const SnapshotRecord& record : document.Records)
    {
        if (!options.Domain.empty() &&
            TimelineToLower(record.Domain) != TimelineToLower(options.Domain))
        {
            continue;
        }
        if (ReconcileRiskRank(record.Risk) < 2)
        {
            continue;
        }

        uint32_t pid = SnapshotRecordAnyPid(record);
        if (options.HasProcessId && pid != options.ProcessId)
        {
            continue;
        }

        bool pidSeen = pid != 0 && eventPids.find(pid) != eventPids.end();
        std::set<std::wstring> recordImages;
        AddSnapshotRecordImages(record, &recordImages);
        bool imageSeen = recordImages.empty();
        for (const std::wstring& image : recordImages)
        {
            if (eventImages.find(image) != eventImages.end())
            {
                imageSeen = true;
                break;
            }
        }

        if (!pidSeen && !imageSeen)
        {
            TimelineReconcileFinding finding = {};
            finding.Kind = L"snapshot-record-without-event";
            finding.Domain = record.Domain;
            finding.Subject = record.Identity.empty() ? record.Display : record.Identity;
            finding.Risk = record.Risk.empty() ? L"medium" : record.Risk;
            finding.Confidence = L"no-live-event";
            finding.Summary = L"snapshot state has no matching timeline event";
            finding.ProcessId = pid;
            AddEvidenceIfPresent(&finding.Evidence, L"display", record.Display);
            AddEvidenceIfPresent(&finding.Evidence, L"identity", record.Identity);
            AddReconcileFinding(&result.Findings, std::move(finding), options.LiveDropped);
        }
    }

    if (options.LiveDropped != 0)
    {
        result.Warnings.push_back(
            L"live event ring reported dropped events; absence findings are confidence-limited");
    }
    for (const auto& item : document.DomainWarnings)
    {
        for (const std::wstring& warning : item.second)
        {
            result.Warnings.push_back(item.first + L": " + warning);
        }
    }

    std::sort(result.Findings.begin(), result.Findings.end(), ReconcileFindingLess);
    if (options.Limit != 0 && result.Findings.size() > options.Limit)
    {
        result.Findings.resize(options.Limit);
        result.Truncated = true;
    }

    return result;
}

TimelineAnalysisResult TimelineStore::AnalyzeLiveSignals(size_t limit) const
{
    static const uint64_t kShortProcessLifetime100ns = 2ull * 1000ull * 1000ull * 10ull;
    static const uint64_t kShortThreadLifetime100ns = 500ull * 1000ull * 10ull;
    static const uint64_t kCorrelationWindow100ns = 5ull * 1000ull * 1000ull * 10ull;

    TimelineAnalysisResult result = {};
    result.Limit = limit;
    const size_t hardFindingLimit = limit == 0 ? 4096 : std::max<size_t>(limit * 4, 256);
    std::vector<TimelineEvent> events = AllEvents();
    result.TotalEvents = events.size();

    std::sort(events.begin(), events.end(), TimelineAnalysisEventLess);

    std::map<uint32_t, TimelineEvent> processCreates;
    std::map<std::wstring, TimelineEvent> threadCreates;
    std::map<uint32_t, std::vector<const TimelineEvent*>> threadActivityByPid;
    std::map<uint32_t, std::vector<const TimelineEvent*>> imageLoadsByPid;
    std::map<uint32_t, std::vector<const TimelineEvent*>> networkActivityByPid;
    std::map<uint32_t, std::vector<const TimelineEvent*>> suspiciousActivityByPid;
    std::vector<const TimelineEvent*> tiEvents;

    for (const TimelineEvent& event : events)
    {
        if (TimelineEventIsProcessCreate(event) && event.ProcessId != 0)
        {
            processCreates[event.ProcessId] = event;
        }
        else if (TimelineEventIsProcessExit(event) && event.ProcessId != 0)
        {
            auto it = processCreates.find(event.ProcessId);
            if (it != processCreates.end())
            {
                if (result.Findings.size() < hardFindingLimit)
                {
                    AddShortLifetimeFinding(
                        &result.Findings,
                        it->second,
                        event,
                        L"short-lived-process",
                        L"medium",
                        kShortProcessLifetime100ns);
                }
                else
                {
                    result.Truncated = true;
                }
                processCreates.erase(it);
            }
        }

        if (TimelineEventIsThreadCreate(event) && event.ProcessId != 0 && event.ThreadId != 0)
        {
            threadCreates[TimelineThreadKey(event.ProcessId, event.ThreadId)] = event;
            if (event.TimestampFileTime != 0)
            {
                threadActivityByPid[event.ProcessId].push_back(&event);
            }
        }
        else if (TimelineEventIsThreadExit(event) && event.ProcessId != 0 && event.ThreadId != 0)
        {
            std::wstring key = TimelineThreadKey(event.ProcessId, event.ThreadId);
            auto it = threadCreates.find(key);
            if (it != threadCreates.end())
            {
                if (result.Findings.size() < hardFindingLimit)
                {
                    AddShortLifetimeFinding(
                        &result.Findings,
                        it->second,
                        event,
                        L"short-lived-thread",
                        L"medium",
                        kShortThreadLifetime100ns);
                }
                else
                {
                    result.Truncated = true;
                }
                threadCreates.erase(it);
            }
            if (event.TimestampFileTime != 0)
            {
                threadActivityByPid[event.ProcessId].push_back(&event);
            }
        }

        if (TimelineEventIsImageLoad(event) && event.ProcessId != 0 && event.TimestampFileTime != 0)
        {
            imageLoadsByPid[event.ProcessId].push_back(&event);
        }

        if (TimelineEventIsRiskyTi(event))
        {
            tiEvents.push_back(&event);
        }

        std::wstring family;
        EvidenceValueByKey(event, L"analysis_family", &family);
        if (event.TimestampFileTime != 0 && event.ProcessId != 0)
        {
            if (family == L"network" || family == L"dns")
            {
                networkActivityByPid[event.ProcessId].push_back(&event);
            }
            else if (TimelineAnalysisRiskRank(event.Risk) >= 3)
            {
                suspiciousActivityByPid[event.ProcessId].push_back(&event);
            }
        }

        if (result.Findings.size() < hardFindingLimit)
        {
            AddSemanticEventFinding(&result.Findings, event);
        }
        else
        {
            result.Truncated = true;
        }
    }

    auto eventPointerLess = [](const TimelineEvent* a, const TimelineEvent* b) -> bool
    {
        return TimelineAnalysisEventLess(*a, *b);
    };
    for (auto& item : threadActivityByPid)
    {
        std::sort(item.second.begin(), item.second.end(), eventPointerLess);
    }
    for (auto& item : imageLoadsByPid)
    {
        std::sort(item.second.begin(), item.second.end(), eventPointerLess);
    }
    for (auto& item : networkActivityByPid)
    {
        std::sort(item.second.begin(), item.second.end(), eventPointerLess);
    }
    for (auto& item : suspiciousActivityByPid)
    {
        std::sort(item.second.begin(), item.second.end(), eventPointerLess);
    }

    auto addNearbyEvents =
        [&result, hardFindingLimit](
            const TimelineEvent& tiEvent,
            const std::vector<const TimelineEvent*>& liveEvents,
            const std::wstring& kind)
    {
        if (tiEvent.TimestampFileTime == 0)
        {
            return;
        }

        uint64_t minTime = 0;
        if (tiEvent.TimestampFileTime > kCorrelationWindow100ns)
        {
            minTime = tiEvent.TimestampFileTime - kCorrelationWindow100ns;
        }
        uint64_t maxTime = static_cast<uint64_t>(-1);
        if (tiEvent.TimestampFileTime <= static_cast<uint64_t>(-1) - kCorrelationWindow100ns)
        {
            maxTime = tiEvent.TimestampFileTime + kCorrelationWindow100ns;
        }

        auto it = std::lower_bound(
            liveEvents.begin(),
            liveEvents.end(),
            minTime,
            [](const TimelineEvent* event, uint64_t timestamp) -> bool
            {
                return event->TimestampFileTime < timestamp;
            });

        while (it != liveEvents.end())
        {
            const TimelineEvent* liveEvent = *it;
            if (liveEvent == nullptr || liveEvent->TimestampFileTime > maxTime)
            {
                break;
            }
            if (result.Findings.size() >= hardFindingLimit)
            {
                result.Truncated = true;
                break;
            }
            AddCorrelationFinding(
                &result.Findings,
                tiEvent,
                *liveEvent,
                kind,
                kCorrelationWindow100ns);
            ++it;
        }
    };

    auto addNearbyGenericEvents =
        [&result, hardFindingLimit](
            const TimelineEvent& anchorEvent,
            const std::vector<const TimelineEvent*>& relatedEvents,
            const std::wstring& kind)
    {
        if (anchorEvent.TimestampFileTime == 0)
        {
            return;
        }

        uint64_t minTime = 0;
        if (anchorEvent.TimestampFileTime > kCorrelationWindow100ns)
        {
            minTime = anchorEvent.TimestampFileTime - kCorrelationWindow100ns;
        }
        uint64_t maxTime = static_cast<uint64_t>(-1);
        if (anchorEvent.TimestampFileTime <= static_cast<uint64_t>(-1) - kCorrelationWindow100ns)
        {
            maxTime = anchorEvent.TimestampFileTime + kCorrelationWindow100ns;
        }

        auto it = std::lower_bound(
            relatedEvents.begin(),
            relatedEvents.end(),
            minTime,
            [](const TimelineEvent* event, uint64_t timestamp) -> bool
            {
                return event->TimestampFileTime < timestamp;
            });

        while (it != relatedEvents.end())
        {
            const TimelineEvent* relatedEvent = *it;
            if (relatedEvent == nullptr || relatedEvent->TimestampFileTime > maxTime)
            {
                break;
            }
            if (relatedEvent->EventId == anchorEvent.EventId)
            {
                ++it;
                continue;
            }
            if (result.Findings.size() >= hardFindingLimit)
            {
                result.Truncated = true;
                break;
            }
            AddGenericCorrelationFinding(
                &result.Findings,
                anchorEvent,
                *relatedEvent,
                kind,
                kCorrelationWindow100ns);
            ++it;
        }
    };

    for (const TimelineEvent* tiEvent : tiEvents)
    {
        if (tiEvent == nullptr)
        {
            continue;
        }
        if (result.Findings.size() >= hardFindingLimit)
        {
            result.Truncated = true;
            break;
        }

        uint32_t pid = TimelineCorrelationPid(*tiEvent);
        if (pid == 0)
        {
            continue;
        }

        auto threadIt = threadActivityByPid.find(pid);
        if (threadIt != threadActivityByPid.end())
        {
            addNearbyEvents(*tiEvent, threadIt->second, L"ti-near-thread-activity");
        }

        auto imageIt = imageLoadsByPid.find(pid);
        if (imageIt != imageLoadsByPid.end())
        {
            addNearbyEvents(*tiEvent, imageIt->second, L"ti-near-image-load");
        }
    }

    for (const auto& item : suspiciousActivityByPid)
    {
        auto networkIt = networkActivityByPid.find(item.first);
        if (networkIt == networkActivityByPid.end())
        {
            continue;
        }
        for (const TimelineEvent* suspiciousEvent : item.second)
        {
            if (suspiciousEvent == nullptr)
            {
                continue;
            }
            if (result.Findings.size() >= hardFindingLimit)
            {
                result.Truncated = true;
                break;
            }
            addNearbyGenericEvents(
                *suspiciousEvent,
                networkIt->second,
                L"network-near-suspicious-activity");
        }
    }

    std::sort(result.Findings.begin(), result.Findings.end(), TimelineAnalysisFindingLess);
    if (limit != 0 && result.Findings.size() > limit)
    {
        result.Findings.resize(limit);
        result.Truncated = true;
    }

    return result;
}

TimelineStats TimelineStore::GetStats() const
{
    TimelineStats stats = {};
    std::lock_guard<std::mutex> lock(Mutex);

    stats.Stored = Events.size();
    stats.Capacity = MaxEvents;
    stats.NextEventId = NextEventId;
    stats.Dropped = DroppedEvents;
    for (const TimelineEvent& event : Events)
    {
        ++stats.BySource[event.Source.empty() ? L"<unknown>" : event.Source];
        ++stats.ByDomain[event.Domain.empty() ? L"<unknown>" : event.Domain];
    }

    return stats;
}

bool TimelineStore::ExportJsonl(const std::wstring& path, std::wstring* error) const
{
    std::vector<TimelineEvent> events = AllEvents();
    return WriteSnapshotTextFile(path, BuildTimelineJsonl(events), error);
}

bool TimelineStore::AddEventLocked(TimelineEvent event)
{
    bool added = false;
    EnrichTimelineEventProcessContext(&event, Events);
    NormalizeTimelineEvent(&event);
    std::wstring key = TimelineEventKey(event);
    if (EventKeys.find(key) != EventKeys.end())
    {
        return false;
    }

    event.EventId = NextEventIdLocked();
    Events.push_back(std::move(event));
    EventKeys.insert(key);
    EventKeysInOrder.push_back(key);
    while (Events.size() > MaxEvents)
    {
        DropOldestEventLocked();
        ++DroppedEvents;
    }

    added = true;
    return added;
}

void TimelineStore::DropOldestEventLocked()
{
    if (!Events.empty())
    {
        Events.pop_front();
    }
    if (!EventKeysInOrder.empty())
    {
        EventKeys.erase(EventKeysInOrder.front());
        EventKeysInOrder.pop_front();
    }
}

uint64_t TimelineStore::NextEventIdLocked()
{
    uint64_t eventId = NextEventId;
    ++NextEventId;
    return eventId;
}
