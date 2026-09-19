#include "KernelMonitor.h"
#include "ContentHash.h"
#include "KmonHuntingJson.h"
#include "ExecutableImagePermissions.h"
#include "ExecutionSurfaceScanner.h"

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
        const size_t count = (std::min<size_t>)(bytes.size(), 64);
        result.reserve(count * 2);
        for (size_t i = 0; i < count; ++i)
        {
            const uint8_t value = bytes[i];
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

    bool ResolveHuntAddressSpace(DeviceClient& device, SymbolEngine& symbols,
        const ObservationIdentity& identity, ProcessAddressContext* context)
    {
        TypeFieldInfo pcb = {}, dtb = {}, create = {};
        if (!symbols.FindField(L"nt!_EPROCESS", L"Pcb", &pcb, nullptr) ||
            !symbols.FindField(L"nt!_KPROCESS", L"DirectoryTableBase", &dtb, nullptr) ||
            !symbols.FindField(L"nt!_EPROCESS", L"CreateTime", &create, nullptr) ||
            pcb.IsBitField || dtb.IsBitField || create.IsBitField || dtb.Length != 8 || create.Length != 8 ||
            pcb.Offset >= 0x10000 || dtb.Offset >= 0x10000 || create.Offset >= 0x10000 ||
            pcb.Offset + dtb.Offset > 0x10000 - 8 ||
            !device.ResolveProcess(identity.ProcessId, static_cast<uint32_t>(pcb.Offset + dtb.Offset), 0, context, nullptr) ||
            context->Eprocess < 0xFFFF800000000000ull || context->Eprocess > UINT64_MAX - create.Offset - 8 ||
            (identity.Eprocess != 0 && identity.Eprocess != context->Eprocess))
        {
            return false;
        }
        std::vector<uint8_t> bytes;
        uint64_t creation = 0;
        if (!device.ReadMemory(context->Eprocess + create.Offset, 8, &bytes, nullptr) || bytes.size() != 8)
        {
            return false;
        }
        std::memcpy(&creation, bytes.data(), 8);
        return creation == identity.CreateTime && creation != 0 && context->DirectoryTableBase != 0;
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
            work.PermissionCursor = 0;
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

void KernelMonitor::ScanImagePermissionCandidates(const std::wstring& path, uint64_t base,
    const ObservationIdentity& identity, const ObservationReader& reader)
{
    DeviceClient* device = nullptr;
    SymbolEngine* symbols = nullptr;
    if (!GetLiveTargets(&device, &symbols) || ExecutionReferences.size() >= 64)
    {
        return;
    }
    auto work = FindImageWork(path, base, identity);
    if (work == nullptr || !QualifyExecutableReference(work->Reference, base, reader, nullptr))
    {
        return;
    }
    ProcessAddressContext context = {};
    if (identity.ProcessId != 0 && !ResolveHuntAddressSpace(*device, *symbols, identity, &context))
    {
        EmitUnique(L"coverage.image_permissions", L"image:permissions:identity:" + ImageKey(path, base, identity),
            path, L"image", L"image permission scan unavailable", L"process address-space identity unavailable", identity.ProcessId);
        return;
    }
    uint32_t checked = 0;
    uint32_t failed = 0;
    uint32_t candidates = 0;
    bool complete = false;
    for (uint32_t visited = 0; visited < 4096 && checked < 4 && !StopRequested.load(); ++visited)
    {
        const uint64_t rva = work->PermissionCursor;
        if (rva >= work->Reference.SizeOfImage || base > UINT64_MAX - rva)
        {
            work->PermissionCursor = 0;
            complete = true;
            break;
        }
        work->PermissionCursor += 4096;
        if (DeclaredExecutableImagePage(work->Reference, rva))
        {
            continue;
        }
        ++checked;
        PhysicalTranslationInfo mapping = {};
        if (!device->TranslateVirtual(identity.ProcessId == 0 ? 0 : context.DirectoryTableBase, base + rva, 1, &mapping, nullptr))
        {
            ++failed;
            continue;
        }
        if (KmonHardwareExecutable(mapping.Pml5e, mapping.Pml4e, mapping.Pdpte, mapping.Pde,
            mapping.Pte, mapping.PageSize, mapping.PagingLevels, identity.ProcessId != 0))
        {
            QueueExecutionReference(base + rva, 0, L"image_page_candidate", identity);
            ++candidates;
        }
    }
    KmonEvent event;
    event.Kind = L"coverage.image_permissions";
    event.ProcessId = identity.ProcessId;
    event.Image = path;
    event.Observation.Identity = identity;
    event.Observation.Source = L"image_pte_permissions";
    event.Summary = L"non-executable PE pages checked against current hardware permissions";
    event.Evidence[L"pages_checked"] = std::to_wstring(checked);
    event.Evidence[L"translations_unavailable"] = std::to_wstring(failed);
    event.Evidence[L"candidates"] = std::to_wstring(candidates);
    event.Evidence[L"cursor_rva"] = std::to_wstring(work->PermissionCursor);
    event.Evidence[L"cycle_finished"] = complete ? L"true" : L"false";
    RecordEvent(std::move(event));
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
        ScanImagePermissionCandidates(KmonNormalizeDriverPath(it->ImagePath), it->Base, ObserveProcessIdentity(0), reader);
    }
}

void KernelMonitor::QueueExecutionReference(uint64_t target, uint64_t slot,
    const std::wstring& role, const ObservationIdentity& identity, uint64_t observedAt,
    const std::vector<ObservationAnchor>& anchors, uint64_t expectedPeb)
{
    if ((target == 0 && !KmonPageRole(role)) || anchors.size() > 8)
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
    ExecutionReferences.push_back({target, slot, observedAt == 0 ? ObservationFileTime() : observedAt,
        GetTickCount64(), actual, role, anchors, expectedPeb});
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
        {
            std::lock_guard<std::mutex> lock(HuntMutex);
            HuntIndex.Retire(work.Identity, work.Target, work.Slot, work.Role);
        }
        if (GetTickCount64() - work.ObservedMs > 30000)
        {
            ++ExecutionReferenceDropped;
            EmitUnique(L"coverage.references", L"scan_failed:references:expired", L"", L"references",
                L"queued reference expired", L"reference older than 30 seconds was discarded", work.Identity.ProcessId);
            continue;
        }
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
        if (pid != 0 && process == nullptr)
        {
            process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        }
        const std::unique_ptr<void, decltype(&CloseHandle)> processOwner(process, &CloseHandle);
        const auto sameProcess = [&]()
        {
            if (pid == 0)
            {
                return true;
            }
            if (work.ExpectedPeb != 0)
            {
                uint64_t peb = 0;
                if (!QueryExecutionSurfacePeb(process, pid, &peb) || peb != work.ExpectedPeb)
                {
                    return false;
                }
            }
            if (process != nullptr)
            {
                return work.Identity.SameInstance(ObserveProcessIdentity(pid, process));
            }
            ProcessAddressContext current = {};
            return ResolveHuntAddressSpace(*device, *symbols, work.Identity, &current);
        };
        if (!sameProcess())
        {
            EmitUnique(L"coverage.references", L"scan_failed:references:identity:" + std::to_wstring(pid),
                L"", L"references", L"queued reference has stale or unknown process identity", L"", pid);
            continue;
        }
        BOOL wow64 = FALSE;
        const bool pageCheck = KmonPageRole(work.Role) || work.Role == L"etw_stack_return";
        if (pid != 0 && !pageCheck && (process == nullptr || !IsWow64Process(process, &wow64) || wow64))
        {
            EmitUnique(L"coverage.references", L"scan_failed:references:architecture:" + std::to_wstring(pid),
                L"", L"references", L"static target decoding requires a confirmed native x64 process",
                L"image page comparisons remain available; target architecture is unsupported or unknown", pid);
            continue;
        }
        const auto modules = pid == 0 ? symbols->CopyModules() : UserModules(pid);
        ProcessAddressContext addressSpace = {};
        bool addressSpaceTried = false;
        bool addressSpaceValid = false;
        const auto executableMapping = [&](uint64_t address, PhysicalTranslationInfo* mapping)
        {
            *mapping = {};
            MEMORY_BASIC_INFORMATION region = {};
            const bool regionKnown = pid != 0 && process != nullptr &&
                VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &region, sizeof(region)) == sizeof(region);
            if (pid != 0 && !addressSpaceTried)
            {
                addressSpaceTried = true;
                addressSpaceValid = ResolveHuntAddressSpace(*device, *symbols, work.Identity, &addressSpace);
            }
            if ((pid == 0 || addressSpaceValid) &&
                device->TranslateVirtual(pid == 0 ? 0 : addressSpace.DirectoryTableBase, address, 1, mapping, nullptr))
            {
                return KmonHardwareExecutable(mapping->Pml5e, mapping->Pml4e, mapping->Pdpte,
                    mapping->Pde, mapping->Pte, mapping->PageSize, mapping->PagingLevels, pid != 0);
            }
            *mapping = {};
            return regionKnown &&
                region.State == MEM_COMMIT && (region.Protect & PAGE_GUARD) == 0 &&
                (region.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
        };
        PhysicalTranslationInfo candidateMapping = {};
        if (KmonPageRole(work.Role) && !executableMapping(work.Target, &candidateMapping))
        {
            EmitUnique(L"coverage.execution_path", L"page:unavailable:" + referenceKey, L"", work.Role,
                L"candidate page is no longer executable or its mapping is unavailable", L"current mapping revalidation failed", pid);
            continue;
        }
        bool physicalPageRead = false;
        uint64_t lastReadPhysical = 0;
        uint64_t pageHeadPhysical = 0;
        const ObservationReader reader = [device, process, &work, &executableMapping, &physicalPageRead, &lastReadPhysical]
            (uint64_t address, size_t size, std::vector<uint8_t>* bytes)
        {
            lastReadPhysical = 0;
            if (size > 4096 || address > UINT64_MAX - size)
            {
                return false;
            }
            if (KmonPageRole(work.Role) && size == 4096 && (address & 4095) == 0)
            {
                PhysicalTranslationInfo mapping = {};
                if (executableMapping(address, &mapping) && mapping.PhysicalAddress != 0 &&
                    device->ReadPhysical(mapping.PhysicalAddress, 4096, bytes, nullptr) && bytes->size() == 4096)
                {
                    physicalPageRead = true;
                    lastReadPhysical = mapping.PhysicalAddress;
                    return true;
                }
            }
            if (work.Identity.ProcessId == 0)
            {
                return address >= 0xFFFF800000000000ull &&
                    device->ReadMemory(address, static_cast<uint32_t>(size), bytes, nullptr);
            }
            if (work.Role == L"instrumentation_callback" && work.Slot != 0 && address == work.Slot && size == 8)
            {
                return device->ReadMemory(address, 8, bytes, nullptr);
            }
            MEMORY_BASIC_INFORMATION protection = {};
            if (process != nullptr && VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &protection,
                sizeof(protection)) == sizeof(protection) && (protection.Protect & PAGE_GUARD) != 0)
            {
                return false;
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
        if (!ObservationAnchorsMatch(work.Anchors, reader))
        {
            EmitUnique(L"coverage.references", L"reference:anchor_changed:" + referenceKey, L"", work.Role,
                L"reference root or PE metadata changed before decoding", L"queued reference withheld", pid);
            continue;
        }
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
                    PhysicalTranslationInfo mapping = {};
                    if (UnexpectedExecutableImageAddress(image->Reference, address - module.Base) && executableMapping(address, &mapping))
                    {
                        return CodeOwnership::OwnedUnexpectedExecutable;
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
            PhysicalTranslationInfo page = {};
            return executableMapping(address, &page) ? CodeOwnership::UnownedExecutable : CodeOwnership::Unknown;
        };
        const bool pointerSlot = work.Slot != 0 && KmonPointerReference(work.Role);
        CodeTargetChain chain;
        if (pageCheck)
        {
            CodeTargetHop hop;
            hop.Address = work.Target & ~4095ull;
            if (reader(hop.Address, 4096, &hop.Bytes) && hop.Bytes.size() == 4096)
            {
                pageHeadPhysical = lastReadPhysical;
                hop.Ownership = inspect(hop.Address, hop.Bytes);
                chain.HasModifiedCode = hop.Ownership == CodeOwnership::OwnedModified;
                chain.HasUnownedExecutable = hop.Ownership == CodeOwnership::UnownedExecutable;
                chain.HasUnexpectedExecutable = hop.Ownership == CodeOwnership::OwnedUnexpectedExecutable;
                chain.Hops.push_back(std::move(hop));
                chain.Termination = work.Role == L"etw_stack_return" ?
                    L"historical_stack_page_checked; not_a_function_entry" : L"executable_page_checked; no_execution_reference";
            }
            else
            {
                chain.Termination = L"page_location_unreadable";
            }
        }
        else
        {
            chain = pointerSlot ? ResolveReferencedCodeTarget(work.Target, work.Slot, reader, inspect) :
                ResolveCodeTarget(work.Target, reader, inspect);
        }
        KmonEvent event;
        event.Kind = chain.HasModifiedCode || chain.HasUnownedExecutable ? L"finding.execution_path" : L"coverage.execution_path";
        if (KmonPageRole(work.Role) && (chain.HasModifiedCode || chain.HasUnownedExecutable))
        {
            event.Kind = L"finding.executable_memory";
        }
        if (chain.HasUnexpectedExecutable)
        {
            event.Kind = L"finding.executable_permission";
        }
        event.ProcessId = pid;
        event.Summary = work.Role + L" target path: " + chain.Termination;
        event.Observation.Identity = work.Identity;
        event.Observation.Source = work.Role;
        event.Observation.Timestamp = work.ObservedAt;
        event.Observation.MonotonicMs = work.ObservedMs;
        event.Observation.DependencyGroup = L"static_code_reference";
        event.Evidence[L"module_inventory"] = modules.empty() ? L"unavailable" : L"snapshot";
        event.Evidence[L"relationship"] = L"address";
        event.Evidence[L"reference_role"] = work.Role;
        event.Evidence[L"slot"] = std::to_wstring(work.Slot);
        event.Evidence[L"reference_target"] = std::to_wstring(work.Target);
        event.Evidence[L"termination"] = chain.Termination;
        event.Evidence[L"execution_observed"] = L"false";
        event.Evidence[L"reference_consistency"] = !chain.ReferenceChecked ? L"not_revalidated" :
            (chain.ReferenceStable ? L"slot_checked_before_and_after" : L"changed_or_unreadable");
        event.Evidence[L"path_read_at"] = std::to_wstring(ObservationFileTime());
        size_t captures = 0;
        size_t acceptedReferences = 0;
        bool referenceSnapshotValid = !chain.ReferenceChecked || chain.ReferenceStable;
        std::vector<std::pair<size_t, KmonHuntReference>> pendingReferences;
        for (size_t i = 0; i < chain.Hops.size(); ++i)
        {
            const auto& hop = chain.Hops[i];
            const std::wstring key = L"hop_" + std::to_wstring(i) + L"_";
            event.Evidence[key + L"address"] = std::to_wstring(hop.Address);
            event.Evidence[key + L"target"] = std::to_wstring(hop.Target);
            event.Evidence[key + L"ownership"] = CodeOwnershipName(hop.Ownership);
            event.Evidence[key + L"bytes"] = BytesHex(hop.Bytes);
            event.Evidence[key + L"bytes_read"] = std::to_wstring(hop.Bytes.size());
            event.Evidence[key + L"bytes_prefix_length"] = std::to_wstring((std::min<size_t>)(hop.Bytes.size(), 64));
            if ((KmonHuntOwnership(hop.Ownership) || (KmonPageRole(work.Role) &&
                (hop.Ownership == CodeOwnership::Unknown || hop.Ownership == CodeOwnership::OwnedUnverified))) &&
                (!chain.ReferenceChecked || chain.ReferenceStable))
            {
                KmonHuntReference reference;
                reference.Context.Identity = work.Identity;
                reference.Context.Source = work.Role;
                reference.Context.DependencyGroup = hop.Ownership == CodeOwnership::OwnedModified ?
                    L"memory_vs_file" : L"executable_memory_metadata";
                reference.Context.Ownership = hop.Ownership;
                reference.Address = hop.Address;
                reference.Root = work.Target;
                reference.Slot = work.Slot;
                reference.Role = work.Role;
                reference.ReferenceTimestamp = work.ObservedAt;
                reference.SlotStable = chain.ReferenceChecked && chain.ReferenceStable;
                const uint64_t base = hop.Address & ~4095ull;
                PhysicalTranslationInfo beforeMapping = {};
                const bool executableBefore = executableMapping(base, &beforeMapping);
                std::vector<uint8_t> page;
                uint64_t capturePhysical = 0;
                bool comparable = false;
                if (captures < 2 && reader(base, 4096, &page) && page.size() == 4096)
                {
                    capturePhysical = lastReadPhysical;
                    ++captures;
                    const size_t offset = static_cast<size_t>(hop.Address - base);
                    comparable = hop.Bytes.size() <= page.size() - offset &&
                        std::equal(hop.Bytes.begin(), hop.Bytes.end(), page.begin() + offset);
                }
                if (reference.SlotStable)
                {
                    std::vector<uint8_t> slotBytes;
                    uint64_t target = 0;
                    reference.SlotStable = reader(work.Slot, 8, &slotBytes) && slotBytes.size() == 8;
                    if (reference.SlotStable)
                    {
                        std::memcpy(&target, slotBytes.data(), 8);
                        reference.SlotStable = target == work.Target;
                    }
                    if (!reference.SlotStable)
                    {
                        referenceSnapshotValid = false;
                        event.Evidence[L"capture_reference_consistency"] = L"changed_or_unreadable";
                        continue;
                    }
                }
                if (!sameProcess())
                {
                    referenceSnapshotValid = false;
                    continue;
                }
                if (pid != 0 && addressSpaceValid)
                {
                    ProcessAddressContext current = {};
                    if (!ResolveHuntAddressSpace(*device, *symbols, work.Identity, &current) ||
                        current.Eprocess != addressSpace.Eprocess ||
                        current.DirectoryTableBase != addressSpace.DirectoryTableBase)
                    {
                        referenceSnapshotValid = false;
                        event.Evidence[key + L"page_mapping"] = L"address_space_changed_or_unavailable";
                        continue;
                    }
                }
                PhysicalTranslationInfo afterMapping = {};
                const bool executableAfter = executableMapping(base, &afterMapping);
                reference.PageExecutableVerified = executableBefore && executableAfter;
                if ((KmonPageRole(work.Role) || hop.Ownership == CodeOwnership::OwnedUnexpectedExecutable) &&
                    (!executableBefore || !executableAfter))
                {
                    event.Evidence[key + L"page_mapping"] = L"changed_or_unavailable";
                    continue;
                }
                if (KmonPageRole(work.Role) && !comparable)
                {
                    event.Evidence[key + L"page_mapping"] = L"page_bytes_changed_or_unreadable";
                    continue;
                }
                if (!KmonPhysicalPageSamplesAgree({candidateMapping.PhysicalAddress, pageHeadPhysical,
                    beforeMapping.PhysicalAddress, capturePhysical, afterMapping.PhysicalAddress}))
                {
                    event.Evidence[key + L"page_mapping"] = L"physical_page_changed";
                    continue;
                }
                if (beforeMapping.PhysicalAddress != 0 && afterMapping.PhysicalAddress != 0)
                {
                    reference.Context.PfnKnown = executableBefore && executableAfter;
                    reference.Context.Pfn = afterMapping.PhysicalAddress >> 12;
                }
                reference.Context.Timestamp = ObservationFileTime();
                reference.Context.MonotonicMs = GetTickCount64();
                if (comparable)
                {
                    ExecutableRegionObservation observation;
                    observation.Context = reference.Context;
                    // A page boundary is not an allocation boundary.
                    MEMORY_BASIC_INFORMATION region = {};
                    if (pid != 0 && process != nullptr && VirtualQueryEx(process, reinterpret_cast<LPCVOID>(base),
                        &region, sizeof(region)) == sizeof(region))
                    {
                        observation.Context.AllocationBase = reinterpret_cast<uint64_t>(region.AllocationBase);
                    }
                    observation.Range = {base, 4096};
                    observation.Executable = true;
                    observation.ContentSha256 = ContentHash::Bytes(page);
                    observation.ContentBytes = page.size();
                    reference.Context.MappingGeneration = ObserveExecutableRegion(observation);
                    reference.PageSha256 = observation.ContentSha256;
                    reference.PageComparable = KmonComparablePage(page);
                    event.Evidence[key + L"capture_id"] = std::to_wstring(
                        QueueCapturedBytes(L"hunt_reference", base, reference.Context, page));
                }
                pendingReferences.emplace_back(i, std::move(reference));
            }
        }
        referenceSnapshotValid = referenceSnapshotValid && sameProcess() &&
            ObservationAnchorsMatch(work.Anchors, reader) &&
            (!pointerSlot || CodeTargetSlotMatches(work.Target, work.Slot, reader));
        if (referenceSnapshotValid && pid != 0 && addressSpaceValid)
        {
            ProcessAddressContext current = {};
            referenceSnapshotValid = ResolveHuntAddressSpace(*device, *symbols, work.Identity, &current) &&
                current.Eprocess == addressSpace.Eprocess && current.DirectoryTableBase == addressSpace.DirectoryTableBase;
        }
        if (referenceSnapshotValid)
        {
            for (size_t i = 0; i < chain.Hops.size(); ++i)
            {
                ExecutableRegionLink link;
                if (RegionCatalog.LinkAddress(work.Identity, work.Slot, chain.Hops[i].Address, work.Role, GetTickCount64(), &link,
                    chain.ReferenceStable ? GetTickCount64() : work.ObservedMs))
                {
                    event.Evidence[L"hop_" + std::to_wstring(i) + L"_generation"] = std::to_wstring(link.ToGeneration);
                }
            }
            std::lock_guard<std::mutex> lock(HuntMutex);
            for (auto& pending : pendingReferences)
            {
                auto& reference = pending.second;
                reference.Id = HuntIndex.Observe(reference);
                if (reference.Id != 0)
                {
                    ++acceptedReferences;
                    event.Evidence[L"hop_" + std::to_wstring(pending.first) + L"_hunt_reference"] = KmonHuntReferenceJson(reference);
                }
            }
        }
        else
        {
            event.Evidence[L"capture_reference_consistency"] = L"changed_or_unreadable; path_references_withheld";
        }
        if (!referenceSnapshotValid || (KmonPageRole(work.Role) && acceptedReferences == 0))
        {
            event.Kind = L"coverage.execution_path";
        }
        else if (KmonPageRole(work.Role) && !chain.HasModifiedCode && !chain.HasUnownedExecutable && !chain.HasUnexpectedExecutable)
        {
            event.Kind = L"coverage.executable_memory";
        }
        event.Evidence[L"physical_page_reader_used"] = physicalPageRead ? L"true" : L"false";
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
