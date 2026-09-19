#include "KernelMonitor.h"

#include <TlHelp32.h>
#include <algorithm>
#include <cstring>
#include <memory>

namespace
{
    std::wstring BytesHex(const std::vector<uint8_t>& bytes)
    {
        const wchar_t* hex = L"0123456789abcdef";
        std::wstring result;
        result.reserve(bytes.size() * 2);
        for (uint8_t value : bytes)
        {
            result.push_back(hex[value >> 4]);
            result.push_back(hex[value & 15]);
        }
        return result;
    }

    std::wstring ImageKey(const std::wstring& path, uint64_t base, const ObservationIdentity& identity)
    {
        return identity.BootId + L":" + std::to_wstring(identity.ProcessId) + L":" +
            std::to_wstring(identity.CreateTime) + L":" + std::to_wstring(base) + L":" + path;
    }

    std::wstring ReferenceKey(uint64_t target, uint64_t slot, const std::wstring& role,
        const ObservationIdentity& identity)
    {
        return ImageKey(role, target, identity) + L":" + std::to_wstring(slot);
    }

    std::vector<KernelModuleInfo> UserModules(uint32_t pid)
    {
        std::vector<KernelModuleInfo> modules;
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snapshot != INVALID_HANDLE_VALUE)
        {
            MODULEENTRY32W entry = {};
            entry.dwSize = sizeof(entry);
            if (Module32FirstW(snapshot, &entry))
            {
                do
                {
                    modules.push_back({reinterpret_cast<uint64_t>(entry.modBaseAddr),
                        entry.modBaseSize, entry.szExePath, entry.szModule});
                } while (modules.size() < 4096 && Module32NextW(snapshot, &entry));
                if (modules.size() >= 4096 || GetLastError() != ERROR_NO_MORE_FILES)
                {
                    modules.clear();
                }
            }
            CloseHandle(snapshot);
        }
        return modules;
    }
}

KernelMonitor::ImageVerificationWork* KernelMonitor::FindImageWork(const std::wstring& path,
    uint64_t base, const ObservationIdentity& identity)
{
    if (base == 0 || path.empty() || (identity.ProcessId != 0 && identity.CreateTime == 0))
    {
        return nullptr;
    }
    const auto key = ImageKey(path, base, identity);
    const uint64_t now = GetTickCount64();
    auto it = ImageWork.find(key);
    if (it == ImageWork.end())
    {
        if (ImageWork.size() >= 2048)
        {
            for (auto old = ImageWork.begin(); old != ImageWork.end();)
            {
                if (now - old->second.LastUsedMs > 300000 || old->second.Sweep.Coverage.TraversalComplete)
                {
                    old = ImageWork.erase(old);
                }
                else
                {
                    ++old;
                }
            }
        }
        if (ImageWork.size() >= 2048)
        {
            EmitUnique(L"coverage.image", L"scan_failed:image:cache_cap", path, L"image",
                L"image verification cache is full", L"new references deferred; existing cursors retained");
            return nullptr;
        }
        it = ImageWork.emplace(key, ImageVerificationWork{}).first;
        it->second.Identity = identity;
        it->second.Path = path;
        it->second.Base = base;
    }
    auto& work = it->second;
    work.LastUsedMs = now;
    if (work.Loaded && (work.LastReferenceCheckMs == 0 || now - work.LastReferenceCheckMs >= 1000))
    {
        work.LastReferenceCheckMs = now;
        HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        const bool stable = file != INVALID_HANDLE_VALUE && executable_image::DiskFileIdentityMatches(file, work.Reference);
        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }
        if (!stable)
        {
            // A DLL can be unloaded and replaced at the same base/path. Never
            // let a failed cached reference disable verification indefinitely.
            work.Loaded = false;
            work.LastAttemptMs = 0;
            work.ManifestChecked = false;
            work.ManifestMatches = false;
            work.ObjectCursor = 0;
            work.ObjectReports.clear();
            work.ReportedHashes.clear();
            work.Sweep = {};
        }
    }
    if (!work.Loaded && (work.LastAttemptMs == 0 || now - work.LastAttemptMs >= 30000))
    {
        work.LastAttemptMs = now;
        std::wstring error;
        work.Loaded = executable_image::ReadDiskPeMetadata(path, &work.Reference, &error) &&
            work.Sweep.Initialize(work.Reference);
        if (!work.Loaded)
        {
            EmitUnique(L"coverage.image", L"scan_failed:image:" + key, path, L"image",
                L"executable image reference unavailable", error, identity.ProcessId);
        }
    }
    return work.Loaded ? &work : nullptr;
}

CodeOwnership KernelMonitor::ScanExecutableImage(const std::wstring& path, uint64_t base,
    const ObservationIdentity& identity, const ObservationReader& reader, size_t pageBudget)
{
    auto work = FindImageWork(path, base, identity);
    if (work == nullptr)
    {
        return CodeOwnership::OwnedUnverified;
    }
    const uint64_t now = GetTickCount64();
    const auto pages = AdvanceExecutableSweep(path, work->Reference, base, reader, pageBudget, now, &work->Sweep);
    if (pages.empty() && !work->Sweep.Coverage.InventoryAvailable)
    {
        work->ReportedHashes.clear();
    }
    CodeOwnership state = CodeOwnership::OwnedUnverified;
    for (const auto& page : pages)
    {
        ExecutableRegionObservation observation;
        observation.Context.Identity = identity;
        observation.Context.Source = L"executable_page_compare";
        observation.Context.DependencyGroup = L"memory_vs_file";
        observation.Context.Coverage = page.Coverage;
        observation.Context.Ownership = page.Ownership;
        observation.Context.AllocationBase = base;
        observation.Range = {base + page.Rva, page.Coverage.RequestedBytes};
        observation.Executable = true;
        observation.ImageMapping = true;
        const uint64_t generation = ObserveExecutableRegion(observation);
        if (page.Ownership != CodeOwnership::OwnedModified)
        {
            if (page.Ownership == CodeOwnership::OwnedVerified)
            {
                work->ReportedHashes.erase(page.Rva);
            }
            continue;
        }
        state = CodeOwnership::OwnedModified;
        const uint64_t hash = KmonHashBytes64(page.Observed.data(), page.Observed.size());
        auto reported = work->ReportedHashes.find(page.Rva);
        if (reported != work->ReportedHashes.end() && reported->second == hash)
        {
            continue;
        }
        work->ReportedHashes[page.Rva] = hash;
        KmonEvent event;
        event.Kind = L"finding.code_modified";
        event.ProcessId = identity.ProcessId;
        event.Image = path;
        event.Summary = L"executable bytes differ from the qualified disk image";
        event.Observation.Identity = identity;
        event.Observation.Source = L"executable_page_compare";
        event.Observation.DependencyGroup = L"memory_vs_file";
        event.Observation.ReferenceSource = work->Reference.HasPdbIdentity ? L"disk_pe_pdb_identity" : L"disk_pe_identity";
        event.Observation.Ownership = page.Ownership;
        event.Observation.Coverage = page.Coverage;
        event.Observation.MappingGeneration = generation;
        event.Evidence[L"image_base"] = std::to_wstring(base);
        event.Evidence[L"rva"] = std::to_wstring(page.Rva);
        event.Evidence[L"cycle"] = std::to_wstring(work->Sweep.Cycle);
        event.Evidence[L"code_hash"] = std::to_wstring(hash);
        event.Evidence[L"observed_capture_id"] = std::to_wstring(QueueCapturedBytes(L"modified_code",
            base + page.Rva, event.Observation, page.Observed));
        event.Evidence[L"expected_capture_id"] = std::to_wstring(QueueCapturedBytes(L"expected_code",
            base + page.Rva, event.Observation, page.Expected));
        event.Evidence[L"observed_prefix"] = BytesHex(std::vector<uint8_t>(page.Observed.begin(),
            page.Observed.begin() + (std::min<size_t>)(64, page.Observed.size())));
        event.Evidence[L"reference_trust"] = L"local_file_identity; no publisher or maliciousness assertion";
        for (size_t i = 0; i < page.Changes.size() && i < 64; ++i)
        {
            event.Evidence[L"change_" + std::to_wstring(i)] = std::to_wstring(page.Changes[i].Address) +
                L":" + std::to_wstring(page.Changes[i].Size);
        }
        RecordEvent(std::move(event));
    }
    if (work->Sweep.Coverage.TraversalComplete || pages.empty())
    {
        KmonEvent coverage;
        coverage.Kind = L"coverage.image";
        coverage.ProcessId = identity.ProcessId;
        coverage.Image = path;
        coverage.Summary = work->Sweep.Coverage.Reason;
        coverage.Observation.Identity = identity;
        coverage.Observation.Source = L"executable_page_sweep";
        coverage.Observation.Coverage = work->Sweep.Coverage;
        coverage.Evidence[L"cycle"] = std::to_wstring(work->Sweep.Cycle);
        coverage.Evidence[L"cursor"] = std::to_wstring(work->Sweep.NextRange);
        coverage.Evidence[L"remaining_pages"] = std::to_wstring(work->Sweep.Ranges.size() - work->Sweep.NextRange);
        coverage.Evidence[L"last_completion_ms"] = std::to_wstring(work->Sweep.LastCompleteMs);
        coverage.Evidence[L"image_base"] = std::to_wstring(base);
        RecordEvent(std::move(coverage));
    }
    if (state != CodeOwnership::OwnedModified && work->Sweep.Coverage.Complete())
    {
        state = CodeOwnership::OwnedVerified;
        for (const auto& page : work->Sweep.Pages)
        {
            if (page.second == CodeOwnership::OwnedModified)
            {
                state = CodeOwnership::OwnedModified;
                break;
            }
        }
    }
    uint64_t remaining = 0;
    uint64_t lastComplete = 0;
    for (const auto& item : ImageWork)
    {
        remaining += item.second.Sweep.Ranges.size() - item.second.Sweep.NextRange;
        lastComplete = (std::max)(lastComplete, item.second.Sweep.LastCompleteMs);
    }
    ImageRemainingPages.store(remaining);
    ImageLastCompleteMs.store(lastComplete);
    return state;
}

void KernelMonitor::ScanKernelExecutableImages()
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    if (!GetLiveTargets(&device, &symbols))
    {
        return;
    }
    auto modules = symbols->CopyModules();
    std::sort(modules.begin(), modules.end(), [](const KernelModuleInfo& a, const KernelModuleInfo& b)
    {
        return a.Base < b.Base;
    });
    if (!modules.empty())
    {
        auto it = std::upper_bound(modules.begin(), modules.end(), KernelImageCursor,
            [](uint64_t base, const KernelModuleInfo& module)
            {
                return base < module.Base;
            });
        if (it == modules.end())
        {
            it = modules.begin();
        }
        KernelImageCursor = it->Base;
        const ObservationReader reader = [device](uint64_t address, size_t size, std::vector<uint8_t>* bytes)
        {
            return address >= 0xFFFF800000000000ull && size <= 4096 &&
                device->ReadMemory(address, static_cast<uint32_t>(size), bytes, nullptr);
        };
        ScanExecutableImage(KmonNormalizeDriverPath(it->ImagePath), it->Base, ObserveProcessIdentity(0), reader, 16);
    }
}

void KernelMonitor::QueueExecutionReference(uint64_t target, uint64_t slot,
    const std::wstring& role, const ObservationIdentity& identity)
{
    if (target == 0)
    {
        return;
    }
    ObservationIdentity actual = identity;
    if (actual.BootId.empty())
    {
        actual.BootId = ObservationBootId();
    }
    const auto key = ReferenceKey(target, slot, role, actual);
    const auto last = ExecutionReferenceLastChecked.find(key);
    if (last != ExecutionReferenceLastChecked.end() && GetTickCount64() - last->second < 10000)
    {
        return;
    }
    if (ExecutionReferenceKeys.count(key) != 0)
    {
        return;
    }
    if (ExecutionReferences.size() >= 1024)
    {
        ++ExecutionReferenceDropped;
        EmitUnique(L"coverage.references", L"scan_failed:references:queue_cap", L"", L"references",
            L"execution reference queue is full", L"reference dropped; a later source sweep may rediscover it");
        return;
    }
    ExecutionReferenceKeys.insert(key);
    ExecutionReferences.push_back({target, slot, ObservationFileTime(), GetTickCount64(), actual, role});
}

void KernelMonitor::ScanExecutionReferences()
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    if (!GetLiveTargets(&device, &symbols))
    {
        return;
    }
    for (size_t n = 0; n < 32 && !ExecutionReferences.empty() && !StopRequested.load(); ++n)
    {
        auto work = std::move(ExecutionReferences.front());
        ExecutionReferences.pop_front();
        const auto referenceKey = ReferenceKey(work.Target, work.Slot, work.Role, work.Identity);
        ExecutionReferenceKeys.erase(referenceKey);
        if (ExecutionReferenceLastChecked.size() >= 16384)
        {
            ExecutionReferenceLastChecked.erase(std::min_element(ExecutionReferenceLastChecked.begin(), ExecutionReferenceLastChecked.end(),
                [](const auto& a, const auto& b)
                {
                    return a.second < b.second;
                }));
        }
        ExecutionReferenceLastChecked[referenceKey] = GetTickCount64();
        const uint32_t pid = work.Identity.ProcessId;
        HANDLE process = pid == 0 ? nullptr : OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        const std::unique_ptr<void, decltype(&CloseHandle)> processOwner(process, &CloseHandle);
        if (pid != 0 && !work.Identity.SameInstance(ObserveProcessIdentity(pid, process)))
        {
            EmitUnique(L"coverage.references", L"scan_failed:references:identity:" + std::to_wstring(pid),
                L"", L"references", L"queued reference has stale or unknown process identity", L"", pid);
            continue;
        }
        BOOL wow64 = FALSE;
        if (pid != 0 && (process == nullptr || !IsWow64Process(process, &wow64) || wow64))
        {
            EmitUnique(L"coverage.references", L"scan_failed:references:architecture:" + std::to_wstring(pid),
                L"", L"references", L"static target decoding requires a confirmed native x64 process",
                L"image page comparisons remain available; target architecture is unsupported or unknown", pid);
            continue;
        }
        const auto modules = pid == 0 ? symbols->CopyModules() : UserModules(pid);
        const ObservationReader reader = [device, process, &work](uint64_t address, size_t size, std::vector<uint8_t>* bytes)
        {
            if (size > 4096 || address > UINT64_MAX - size)
            {
                return false;
            }
            if (work.Identity.ProcessId == 0)
            {
                return address >= 0xFFFF800000000000ull &&
                    device->ReadMemory(address, static_cast<uint32_t>(size), bytes, nullptr);
            }
            bytes->resize(size);
            SIZE_T read = 0;
            if (process != nullptr && ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address),
                bytes->data(), size, &read) && read == size)
            {
                return true;
            }
            return device->ReadProcessVirtual(work.Identity.ProcessId, work.Identity.Eprocess,
                work.Identity.CreateTime, address, static_cast<uint32_t>(size), bytes, nullptr);
        };
        const CodeTargetInspector inspect = [&](uint64_t address, const std::vector<uint8_t>& bytes)
        {
            for (const auto& module : modules)
            {
                if (address >= module.Base && address - module.Base < module.Size)
                {
                    const std::wstring path = pid == 0 ? KmonNormalizeDriverPath(module.ImagePath) : module.ImagePath;
                    auto image = FindImageWork(path, module.Base, work.Identity);
                    if (image == nullptr || !QualifyExecutableReference(image->Reference, module.Base, reader, nullptr))
                    {
                        return CodeOwnership::OwnedUnverified;
                    }
                    const ObservationReader captured = [&](uint64_t at, size_t count, std::vector<uint8_t>* out)
                    {
                        if (at == address && count == bytes.size())
                        {
                            *out = bytes;
                            return true;
                        }
                        return reader(at, count, out);
                    };
                    return CompareExecutableRange(path, image->Reference, module.Base,
                        static_cast<uint32_t>(address - module.Base), static_cast<uint32_t>(bytes.size()), captured).Ownership;
                }
            }
            if (modules.empty())
            {
                return CodeOwnership::Unknown;
            }
            if (pid == 0)
            {
                PhysicalTranslationInfo page = {};
                if (device->TranslateVirtual(0, address, 1, &page, nullptr))
                {
                    const uint64_t nx = (page.Pml5e | page.Pml4e | page.Pdpte | page.Pde | page.Pte) >> 63;
                    return nx == 0 ? CodeOwnership::UnownedExecutable : CodeOwnership::Unknown;
                }
            }
            else
            {
                MEMORY_BASIC_INFORMATION page = {};
                if (process != nullptr && VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &page, sizeof(page)) == sizeof(page) &&
                    page.State == MEM_COMMIT && (page.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0)
                {
                    return CodeOwnership::UnownedExecutable;
                }
            }
            return CodeOwnership::Unknown;
        };
        const bool pointerSlot = work.Slot != 0 && (work.Role == L"iat" || work.Role == L"vtable_candidate" ||
            work.Role == L"manifest_vtable" || work.Role == L"cfg_dispatch_slot" ||
            work.Role == L"graphics_data_pointer_candidate");
        const auto chain = pointerSlot ? ResolveReferencedCodeTarget(work.Target, work.Slot, reader, inspect) :
            ResolveCodeTarget(work.Target, reader, inspect);
        KmonEvent event;
        event.Kind = chain.HasModifiedCode || chain.HasUnownedExecutable ? L"finding.execution_path" : L"coverage.execution_path";
        event.ProcessId = pid;
        event.Summary = work.Role + L" target path: " + chain.Termination;
        event.Observation.Identity = work.Identity;
        event.Observation.Source = work.Role;
        event.Observation.Timestamp = work.ObservedAt;
        event.Evidence[L"relationship"] = L"address";
        event.Evidence[L"reference_role"] = work.Role;
        event.Evidence[L"slot"] = std::to_wstring(work.Slot);
        event.Evidence[L"termination"] = chain.Termination;
        event.Evidence[L"execution_observed"] = L"false";
        event.Evidence[L"reference_consistency"] = !chain.ReferenceChecked ? L"not_revalidated" :
            (chain.ReferenceStable ? L"slot_checked_before_and_after" : L"changed_or_unreadable");
        event.Evidence[L"path_read_at"] = std::to_wstring(ObservationFileTime());
        for (size_t i = 0; i < chain.Hops.size(); ++i)
        {
            const auto& hop = chain.Hops[i];
            ExecutableRegionLink link;
            if ((!chain.ReferenceChecked || chain.ReferenceStable) &&
                RegionCatalog.LinkAddress(work.Identity, work.Slot, hop.Address, work.Role, GetTickCount64(), &link,
                    chain.ReferenceStable ? GetTickCount64() : work.ObservedMs))
            {
                event.Evidence[L"hop_" + std::to_wstring(i) + L"_generation"] = std::to_wstring(link.ToGeneration);
            }
            const std::wstring key = L"hop_" + std::to_wstring(i) + L"_";
            event.Evidence[key + L"address"] = std::to_wstring(hop.Address);
            event.Evidence[key + L"target"] = std::to_wstring(hop.Target);
            event.Evidence[key + L"ownership"] = CodeOwnershipName(hop.Ownership);
            event.Evidence[key + L"bytes"] = BytesHex(hop.Bytes);
        }
        RecordEvent(std::move(event));
    }
}

void KernelMonitor::ScanGameObjectManifest(const std::wstring& path, uint64_t base,
    const ObservationIdentity& identity, const ObservationReader& reader)
{
    if (!GameManifestActive)
    {
        return;
    }
    auto image = FindImageWork(path, base, identity);
    if (image == nullptr)
    {
        return;
    }
    if (!image->ManifestChecked)
    {
        std::wstring error;
        image->ManifestMatches = MatchGameManifest(GameManifest, path, image->Reference, &error);
        image->ManifestChecked = true;
        KmonEvent event;
        event.Kind = L"coverage.manifest";
        event.ProcessId = identity.ProcessId;
        event.Image = path;
        event.Observation.Identity = identity;
        event.Observation.Source = L"game_build_manifest";
        event.Summary = image->ManifestMatches ? L"exact image and PDB identity match; object rules enabled" : error;
        event.Evidence[L"manifest_applied"] = image->ManifestMatches ? L"true" : L"false";
        event.Evidence[L"image_sha256"] = GameManifest.ImageSha256;
        event.Evidence[L"pdb_age"] = std::to_wstring(GameManifest.PdbAge);
        RecordEvent(std::move(event));
    }
    if (!image->ManifestMatches || !QualifyExecutableReference(image->Reference, base, reader, nullptr))
    {
        return;
    }
    // File identity is checked again so a changed reference never inherits a
    // previous exact-build match. The full hash is paid only at initial bind.
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    const bool stableFile = file != INVALID_HANDLE_VALUE && executable_image::DiskFileIdentityMatches(file, image->Reference);
    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }
    if (!stableFile)
    {
        image->ManifestMatches = false;
        EmitUnique(L"coverage.manifest", L"scan_failed:manifest:file_identity:" + path, path,
            L"manifest", L"manifest reference changed; object rules disabled", L"restart with a new qualified manifest", identity.ProcessId);
        return;
    }
    const auto observations = VerifyGameObjects(GameManifest, base, reader, 2, &image->ObjectCursor);
    size_t allowed = 0;
    size_t unknown = 0;
    for (const auto& observation : observations)
    {
        const auto reportKey = std::make_pair(observation.RuleIndex,
            observation.IsVptr ? UINT32_MAX : observation.SlotIndex);
        if (observation.Readable && !observation.IsVptr)
        {
            QueueExecutionReference(observation.Target, observation.SlotAddress, L"manifest_vtable", identity);
        }
        if (observation.Readable && !observation.Modified)
        {
            image->ObjectReports.erase(reportKey);
            ++allowed;
            continue;
        }
        if (!observation.Readable)
        {
            ++unknown;
        }
        const std::wstring signature = observation.Reason + L":" + std::to_wstring(observation.ObjectAddress) +
            L":" + std::to_wstring(observation.SlotAddress) + L":" + std::to_wstring(observation.Target);
        if (image->ObjectReports[reportKey] == signature)
        {
            continue;
        }
        image->ObjectReports[reportKey] = signature;
        const auto& rule = GameManifest.Vptrs[observation.RuleIndex];
        KmonEvent event;
        event.Kind = observation.Modified ? L"finding.game_object" : L"coverage.game_object";
        event.ProcessId = identity.ProcessId;
        event.Image = path;
        event.Summary = observation.Reason;
        event.Observation.Identity = identity;
        event.Observation.Source = L"game_build_manifest";
        event.Observation.ReferenceSource = L"sha256_and_private_pdb_object_rules";
        event.Evidence[L"object"] = GameManifest.Objects[rule.ObjectIndex].Name;
        event.Evidence[L"object_address"] = std::to_wstring(observation.ObjectAddress);
        event.Evidence[L"vptr_offset"] = std::to_wstring(rule.Offset);
        event.Evidence[L"slot_index"] = observation.IsVptr ? L"vptr" : std::to_wstring(observation.SlotIndex);
        event.Evidence[L"slot_address"] = std::to_wstring(observation.SlotAddress);
        event.Evidence[L"target"] = std::to_wstring(observation.Target);
        event.Evidence[L"relationship"] = L"object_and_address";
        event.Evidence[L"execution_observed"] = L"false";
        event.Evidence[L"manifest_sha256"] = GameManifest.ImageSha256;
        if (observation.Readable)
        {
            std::vector<uint8_t> bytes(sizeof(observation.Target));
            std::memcpy(bytes.data(), &observation.Target, bytes.size());
            event.Evidence[L"capture_id"] = std::to_wstring(QueueCapturedBytes(L"manifest_slot", observation.SlotAddress, event.Observation, bytes));
        }
        RecordEvent(std::move(event));
    }
    KmonEvent coverage;
    coverage.Kind = L"coverage.manifest";
    coverage.ProcessId = identity.ProcessId;
    coverage.Observation.Identity = identity;
    coverage.Observation.Source = L"game_object_sweep";
    coverage.Evidence[L"rule_cursor"] = std::to_wstring(image->ObjectCursor);
    coverage.Evidence[L"rules_total"] = std::to_wstring(GameManifest.Vptrs.size());
    coverage.Evidence[L"allowed_observations"] = std::to_wstring(allowed);
    coverage.Evidence[L"unreadable_observations"] = std::to_wstring(unknown);
    coverage.Summary = L"manifest object pass completed; target code is verified separately";
    RecordEvent(std::move(coverage));
}
