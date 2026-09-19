#include "ExecutionSurfaceScanner.h"
#include "NativeHandleSnapshot.h"
#include "ObservationWindows.h"
#include "McpJson.h"

#include <TlHelp32.h>
#include <winternl.h>
#include <memory>

namespace
{
    using HandleOwner = std::unique_ptr<void, decltype(&CloseHandle)>;

    struct Module
    {
        uint64_t Base = 0;
        uint32_t Size = 0;
        std::wstring Path;
    };

    // phnt ntexapi.h, WorkerFactoryBasicInformation. Query-only, native x64 ABI.
    struct WorkerFactoryInformation
    {
        LARGE_INTEGER Timeout;
        LARGE_INTEGER RetryTimeout;
        LARGE_INTEGER IdleTimeout;
        BOOLEAN Paused;
        BOOLEAN TimerSet;
        BOOLEAN QueuedToExWorker;
        BOOLEAN MayCreate;
        BOOLEAN CreateInProgress;
        BOOLEAN InsertedIntoQueue;
        BOOLEAN Shutdown;
        ULONG BindingCount;
        ULONG ThreadMinimum;
        ULONG ThreadMaximum;
        ULONG PendingWorkerCount;
        ULONG WaitingWorkerCount;
        ULONG TotalWorkerCount;
        ULONG ReleaseCount;
        LONGLONG InfiniteWaitGoal;
        PVOID StartRoutine;
        PVOID StartParameter;
        HANDLE ProcessId;
        SIZE_T StackReserve;
        SIZE_T StackCommit;
        LONG LastThreadCreationStatus;
    };

    static_assert(sizeof(WorkerFactoryInformation) == 120, "Worker factory ABI");
    static_assert(offsetof(WorkerFactoryInformation, StartRoutine) == 72, "Worker factory start ABI");
    static_assert(offsetof(WorkerFactoryInformation, ProcessId) == 88, "Worker factory process ABI");

    bool ExecutableProtection(DWORD protection)
    {
        return (protection & (PAGE_GUARD | PAGE_NOACCESS)) == 0 &&
            (protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    }

    void DescribeTarget(HANDLE process, const std::vector<Module>& modules, bool complete, ExecutionSurfaceRow* row)
    {
        row->Owner.clear();
        row->Protection = 0;
        row->MemoryType = 0;
        row->Executable = false;
        row->Unowned = false;
        if (!execution_surface::UserRange(row->Target, 1, row->PointerSize))
        {
            return;
        }
        MEMORY_BASIC_INFORMATION mbi = {};
        if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(row->Target), &mbi, sizeof(mbi)) == sizeof(mbi))
        {
            row->Protection = mbi.Protect;
            row->MemoryType = mbi.Type;
            row->Executable = mbi.State == MEM_COMMIT && ExecutableProtection(mbi.Protect);
        }
        for (const auto& module : modules)
        {
            if (row->Target >= module.Base && row->Target - module.Base < module.Size)
            {
                row->Owner = module.Path;
                break;
            }
        }
        row->Unowned = complete && row->Owner.empty() && row->Executable;
    }

    void AddTable(const ExecutionSurfaceTable& table, const std::wstring& kind, const std::wstring& name,
        const std::wstring& baseline, HANDLE process, const std::vector<Module>& modules, ExecutionSurfaceResult* result,
        uint64_t processPeb = 0)
    {
        ExecutionSurfaceRow root;
        root.Kind = kind + L"_table";
        root.Name = name;
        root.Status = table.Status;
        root.Baseline = baseline;
        root.ModuleBase = table.ImageBase;
        root.RootSlot = table.RootSlot;
        root.Table = table.Table;
        root.Slot = table.RootSlot;
        root.Target = table.Table;
        root.PointerSize = table.PointerSize;
        root.Stable = table.Stable;
        root.ProcessPeb = processPeb;
        root.TableComplete = table.Complete;
        root.TablePresent = table.Present;
        root.Anchors = table.Anchors;
        DescribeTarget(process, modules, result->ModuleInventoryComplete, &root);
        result->Rows.push_back(root);
        for (const auto& entry : table.Entries)
        {
            auto row = root;
            row.Kind = kind;
            row.Index = entry.Index;
            row.Slot = entry.Slot;
            row.Target = entry.Target;
            DescribeTarget(process, modules, result->ModuleInventoryComplete, &row);
            result->Rows.push_back(std::move(row));
        }
    }

    void WorkerFactories(HANDLE process, const ExecutionSurfaceOptions& options,
        const std::vector<Module>& modules, const std::function<bool()>& stopped, ExecutionSurfaceResult* result)
    {
        result->Coverage[L"worker_factory"] = L"unavailable";
        result->Coverage[L"thread_pool_graph"] = L"not_collected";
        using QueryFn = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        const auto query = reinterpret_cast<QueryFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationWorkerFactory"));
        HandleOwner duplicateProcess(OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE, result->Identity.ProcessId), &CloseHandle);
        if (query == nullptr || !duplicateProcess ||
            !result->Identity.SameInstance(ObserveProcessIdentity(result->Identity.ProcessId, duplicateProcess.get())))
        {
            result->Coverage[L"worker_factory"] = L"query_api_or_duplicate_access_unavailable";
            return;
        }
        std::vector<NativeHandleEntry> handles;
        std::wstring error;
        if (!QueryNativeHandleSnapshot(&handles, &error))
        {
            result->Coverage[L"worker_factory"] = error;
            return;
        }
        handles.erase(std::remove_if(handles.begin(), handles.end(), [&](const auto& entry)
        {
            return entry.UniqueProcessId != result->Identity.ProcessId;
        }), handles.end());
        std::sort(handles.begin(), handles.end(), [](const auto& a, const auto& b)
        {
            return a.HandleValue < b.HandleValue;
        });
        uint64_t attempted = 0;
        uint64_t failures = 0;
        bool exhausted = true;
        result->NextHandle = 0;
        for (const auto& handle : handles)
        {
            if (handle.HandleValue < options.HandleStart)
            {
                continue;
            }
            if (attempted >= options.HandleBudget || stopped())
            {
                exhausted = false;
                result->NextHandle = handle.HandleValue;
                break;
            }
            ++attempted;
            HANDLE raw = nullptr;
            // Request only WORKER_FACTORY_QUERY_INFORMATION. The kernel verifies object type.
            if (!DuplicateHandle(duplicateProcess.get(), reinterpret_cast<HANDLE>(handle.HandleValue),
                GetCurrentProcess(), &raw, 0x0008, FALSE, 0))
            {
                ++failures;
                continue;
            }
            HandleOwner owned(raw, &CloseHandle);
            WorkerFactoryInformation before = {}, after = {};
            ULONG returned = 0;
            const LONG status = query(raw, 7, &before, sizeof(before), &returned);
            if (static_cast<ULONG>(status) == 0xC0000024u)
            {
                continue;
            }
            if (status < 0 || returned != sizeof(before) ||
                reinterpret_cast<uintptr_t>(before.ProcessId) != result->Identity.ProcessId)
            {
                ++failures;
                continue;
            }
            ExecutionSurfaceRow row;
            row.Kind = L"worker_factory_start";
            row.Name = L"WorkerFactoryBasicInformation";
            row.HandleValue = handle.HandleValue;
            row.Target = reinterpret_cast<uintptr_t>(before.StartRoutine);
            returned = 0;
            row.Stable = query(raw, 7, &after, sizeof(after), &returned) >= 0 && returned == sizeof(after) &&
                before.ProcessId == after.ProcessId && before.StartRoutine == after.StartRoutine &&
                before.StartParameter == after.StartParameter;
            row.Status = row.Stable ? L"queried_twice" : L"changed_or_unreadable_on_recheck";
            DescribeTarget(process, modules, result->ModuleInventoryComplete, &row);
            result->Rows.push_back(std::move(row));
        }
        result->Coverage[L"worker_factory"] = exhausted ?
            (failures == 0 ? L"handle_snapshot_examined" : L"partial_handle_queries") : L"handle_or_time_budget_reached";
        result->Coverage[L"worker_handles_attempted"] = std::to_wstring(attempted);
        result->Coverage[L"worker_handle_queries_unavailable"] = std::to_wstring(failures);
        result->Coverage[L"worker_inventory_atomic"] = L"false";
    }
}

bool QueryExecutionSurfacePeb(HANDLE process, uint32_t pid, uint64_t* peb)
{
    if (peb == nullptr)
    {
        return false;
    }
    *peb = 0;
    using QueryProcess = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    const auto query = reinterpret_cast<QueryProcess>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    PROCESS_BASIC_INFORMATION basic = {};
    ULONG returned = 0;
    if (process == nullptr || query == nullptr || query(process, 0, &basic, sizeof(basic), &returned) < 0 ||
        returned != sizeof(basic) || basic.UniqueProcessId != pid ||
        !execution_surface::UserRange(reinterpret_cast<uintptr_t>(basic.PebBaseAddress), 1))
    {
        return false;
    }
    *peb = reinterpret_cast<uintptr_t>(basic.PebBaseAddress);
    return true;
}

ExecutionSurfaceResult ScanExecutionSurfaces(uint32_t pid, const ExecutionSurfaceOptions& options)
{
    ExecutionSurfaceResult result;
    result.Identity.BootId = ObservationBootId();
    result.Identity.ProcessId = pid;
    result.ObservedAt = ObservationFileTime();
    result.ObservedMs = GetTickCount64();
    result.Coverage[L"process"] = L"unavailable";
    result.Coverage[L"tls"] = L"not_collected";
    result.Coverage[L"kernel_callback_table"] = L"qualified_native_peb_layout_unavailable";
    result.Coverage[L"worker_factory"] = L"not_collected";
    result.Coverage[L"module_start"] = std::to_wstring(options.ModuleStart);
    result.Coverage[L"handle_start"] = std::to_wstring(options.HandleStart);
    result.Coverage[L"module_budget"] = std::to_wstring(options.ModuleBudget);
    result.Coverage[L"handle_budget"] = std::to_wstring(options.HandleBudget);
    result.Coverage[L"time_budget_ms"] = std::to_wstring(options.TimeBudgetMs);
    do
    {
        if (pid <= 4 || options.ModuleBudget == 0 || options.ModuleBudget > 512 ||
            options.HandleBudget == 0 || options.HandleBudget > 16384 || options.TimeBudgetMs == 0 || options.TimeBudgetMs > 10000 ||
            options.ImageCandidates.size() > 4096)
        {
            result.Coverage[L"process"] = L"invalid_pid_or_budget";
            break;
        }
        HandleOwner process(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid), &CloseHandle);
        if (!process)
        {
            result.Coverage[L"win32_error"] = std::to_wstring(GetLastError());
            break;
        }
        result.Identity = ObserveProcessIdentity(pid, process.get());
        if (result.Identity.BootId.empty() || result.Identity.CreateTime == 0)
        {
            result.Coverage[L"process"] = L"identity_unavailable";
            break;
        }
        const auto stopped = [&]()
        {
            return GetTickCount64() - result.ObservedMs >= options.TimeBudgetMs ||
                (options.Cancelled && options.Cancelled());
        };
        const ObservationReader reader = [&](uint64_t address, size_t size, std::vector<uint8_t>* bytes)
        {
            if (stopped() || !execution_surface::UserRange(address, size) || size > 4096)
            {
                return false;
            }
            MEMORY_BASIC_INFORMATION mbi = {};
            if (VirtualQueryEx(process.get(), reinterpret_cast<LPCVOID>(address), &mbi, sizeof(mbi)) != sizeof(mbi) ||
                mbi.State != MEM_COMMIT || (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0 ||
                address < reinterpret_cast<uintptr_t>(mbi.BaseAddress) ||
                address - reinterpret_cast<uintptr_t>(mbi.BaseAddress) >= mbi.RegionSize ||
                size > mbi.RegionSize - (address - reinterpret_cast<uintptr_t>(mbi.BaseAddress)))
            {
                return false;
            }
            bytes->resize(size);
            SIZE_T read = 0;
            return ReadProcessMemory(process.get(), reinterpret_cast<LPCVOID>(address), bytes->data(), size, &read) && read == size;
        };
        std::vector<Module> modules;
        HANDLE rawSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (rawSnapshot != INVALID_HANDLE_VALUE)
        {
            HandleOwner snapshot(rawSnapshot, &CloseHandle);
            MODULEENTRY32W entry = {};
            entry.dwSize = sizeof(entry);
            if (Module32FirstW(rawSnapshot, &entry))
            {
                do
                {
                    modules.push_back({reinterpret_cast<uintptr_t>(entry.modBaseAddr), entry.modBaseSize, entry.szExePath});
                }
                while (modules.size() < 4096 && Module32NextW(rawSnapshot, &entry));
                result.ModuleInventoryComplete = modules.size() < 4096 && GetLastError() == ERROR_NO_MORE_FILES;
            }
        }
        result.Coverage[L"module_inventory"] = result.ModuleInventoryComplete ? L"snapshot" : L"partial_or_unavailable";
        std::sort(modules.begin(), modules.end(), [](const Module& a, const Module& b)
        {
            return a.Base < b.Base;
        });
        auto images = modules;
        std::set<uint64_t> bases;
        for (const auto& module : images)
        {
            bases.insert(module.Base);
        }
        for (const auto& candidate : options.ImageCandidates)
        {
            if (images.size() >= 4096)
            {
                result.Coverage[L"image_candidates"] = L"candidate_capacity_reached";
                break;
            }
            if (candidate.second != 0 && execution_surface::UserRange(candidate.first, candidate.second) &&
                bases.insert(candidate.first).second)
            {
                images.push_back({candidate.first, candidate.second, L""});
            }
        }
        result.Coverage[L"extra_image_candidates"] = std::to_wstring(images.size() - modules.size());
        std::sort(images.begin(), images.end(), [](const Module& a, const Module& b)
        {
            return a.Base < b.Base;
        });
        BOOL wow64 = FALSE;
        if (options.HasKernelCallbackOffset && options.KernelCallbackOffset <= 0x1000 - 8 &&
            IsWow64Process(process.get(), &wow64) && !wow64 && !stopped())
        {
            uint64_t peb = 0;
            if (QueryExecutionSurfacePeb(process.get(), pid, &peb) &&
                execution_surface::UserRange(peb, options.KernelCallbackOffset + 8))
            {
                auto table = execution_surface::KernelCallbacks(peb + options.KernelCallbackOffset, reader);
                uint64_t afterPeb = 0;
                if (!QueryExecutionSurfacePeb(process.get(), pid, &afterPeb) || afterPeb != peb)
                {
                    table.Stable = false;
                    table.Status = L"process_peb_changed_or_unavailable";
                }
                result.Coverage[L"kernel_callback_table"] = table.Status;
                AddTable(table, L"kernel_callback_candidate", L"PEB.KernelCallbackTable", L"not_applicable",
                    process.get(), modules, &result, peb);
            }
            else
            {
                result.Coverage[L"kernel_callback_table"] = L"peb_query_unavailable";
            }
        }
        if (!stopped())
        {
            WorkerFactories(process.get(), options, modules, stopped, &result);
        }
        const size_t start = images.empty() ? 0 : options.ModuleStart % images.size();
        const size_t budget = (std::min)(images.size() - start, options.ModuleBudget);
        size_t scanned = 0;
        size_t partialTables = 0;
        size_t unverifiedBaselines = 0;
        size_t mismatches = 0;
        for (; scanned < budget && !stopped(); ++scanned)
        {
            if (result.Rows.size() + 65 > 32768)
            {
                result.Coverage[L"row_capacity"] = L"reached";
                break;
            }
            const auto& module = images[start + scanned];
            auto table = execution_surface::Tls(module.Base, module.Size, reader);
            std::wstring comparison = L"unverified";
            executable_image::DiskPeMetadata metadata;
            if (table.Stable && table.Complete && !module.Path.empty() && executable_image::ReadDiskPeMetadata(module.Path, &metadata, nullptr) &&
                metadata.SizeOfImage == module.Size && QualifyExecutableReference(metadata, module.Base, reader, nullptr))
            {
                std::map<uint32_t, std::vector<uint8_t>> pages;
                HANDLE rawReference = CreateFileW(module.Path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                HandleOwner reference(rawReference == INVALID_HANDLE_VALUE ? nullptr : rawReference, &CloseHandle);
                const ObservationReader disk = [&](uint64_t address, size_t size, std::vector<uint8_t>* bytes)
                {
                    if (stopped() || !reference || address < module.Base ||
                        address - module.Base >= metadata.SizeOfImage || size > metadata.SizeOfImage - (address - module.Base) ||
                        size > 4096 || !executable_image::DiskFileIdentityMatches(reference.get(), metadata))
                    {
                        return false;
                    }
                    bytes->resize(size);
                    for (size_t i = 0; i < size; ++i)
                    {
                        const auto rva = static_cast<uint32_t>(address - module.Base + i);
                        const uint32_t page = rva & ~4095u;
                        auto found = pages.find(page);
                        if (found == pages.end())
                        {
                            std::vector<uint8_t> data;
                            if (pages.size() >= 16 || !ReadNormalizedImageRange(module.Path, metadata, module.Base, page,
                                (std::min<uint32_t>)(4096, metadata.SizeOfImage - page), &data))
                            {
                                return false;
                            }
                            found = pages.emplace(page, std::move(data)).first;
                        }
                        (*bytes)[i] = found->second[rva - page];
                    }
                    return true;
                };
                const auto baseline = execution_surface::Tls(module.Base, module.Size, disk);
                const auto after = execution_surface::Tls(module.Base, module.Size, reader);
                if (std::wstring(execution_surface::CompareTls(table, after)) == L"match" &&
                    reference && executable_image::DiskFileIdentityMatches(reference.get(), metadata) &&
                    QualifyExecutableReference(metadata, module.Base, reader, nullptr))
                {
                    comparison = execution_surface::CompareTls(table, baseline);
                }
                if (std::wstring(execution_surface::CompareTls(table, after)) != L"match")
                {
                    table.Stable = false;
                    table.Status = L"changed_or_unreadable_during_baseline";
                }
            }
            AddTable(table, L"tls_callback", module.Path.empty() ? L"image_candidate_without_file_reference" : module.Path,
                comparison, process.get(), modules, &result);
            partialTables += !table.Complete || !table.Stable;
            unverifiedBaselines += comparison == L"unverified";
            mismatches += comparison == L"mismatch";
        }
        result.NextModule = start + scanned < images.size() ? start + scanned : 0;
        result.Coverage[L"tls"] = scanned == images.size() && start == 0 && result.ModuleInventoryComplete ?
            L"module_snapshot_examined" : L"partial_module_sweep";
        result.Coverage[L"tls_modules_scanned"] = std::to_wstring(scanned);
        result.Coverage[L"tls_tables_partial_or_unstable"] = std::to_wstring(partialTables);
        result.Coverage[L"tls_baselines_unverified"] = std::to_wstring(unverifiedBaselines);
        result.Coverage[L"tls_baseline_mismatches"] = std::to_wstring(mismatches);
        FILETIME created = {}, exited = {}, kernelTime = {}, userTime = {};
        result.IdentityStable = result.Identity.SameInstance(ObserveProcessIdentity(pid, process.get())) &&
            GetProcessTimes(process.get(), &created, &exited, &kernelTime, &userTime) &&
            exited.dwLowDateTime == 0 && exited.dwHighDateTime == 0;
        result.Coverage[L"process"] = result.IdentityStable ? L"retained_process_identity" : L"identity_changed";
        result.Coverage[L"time_budget_reached"] = stopped() ? L"true" : L"false";
        if (!result.IdentityStable)
        {
            for (auto& row : result.Rows)
            {
                row.Stable = false;
                row.Baseline = L"unverified";
            }
        }
    }
    while (false);
    return result;
}

std::wstring ExecutionSurfacesJson(const ExecutionSurfaceResult& result)
{
    const auto quote = [](const std::wstring& value)
    {
        return mcpjson::Quote(value);
    };
    std::wstring out = L"{\"schema\":\"kmon.surfaces.v1\",\"claim\":\"static_references\",\"execution_observed\":false";
    out += L",\"boot_id\":" + quote(result.Identity.BootId);
    out += L",\"pid\":" + std::to_wstring(result.Identity.ProcessId);
    out += L",\"create_time\":" + quote(std::to_wstring(result.Identity.CreateTime));
    out += L",\"observed_at\":" + quote(std::to_wstring(result.ObservedAt));
    out += L",\"observed_ms\":" + std::to_wstring(result.ObservedMs);
    out += L",\"identity_stable\":" + std::wstring(result.IdentityStable ? L"true" : L"false");
    out += L",\"module_inventory_complete\":" + std::wstring(result.ModuleInventoryComplete ? L"true" : L"false");
    out += L",\"next_module\":" + std::to_wstring(result.NextModule);
    out += L",\"next_handle\":" + quote(std::to_wstring(result.NextHandle));
    out += L",\"coverage\":{";
    bool first = true;
    for (const auto& item : result.Coverage)
    {
        out += (first ? L"" : L",") + quote(item.first) + L":" + quote(item.second);
        first = false;
    }
    out += L"},\"rows\":[";
    first = true;
    for (const auto& row : result.Rows)
    {
        out += first ? L"{" : L",{";
        first = false;
        out += L"\"kind\":" + quote(row.Kind) + L",\"name\":" + quote(row.Name);
        out += L",\"status\":" + quote(row.Status) + L",\"baseline\":" + quote(row.Baseline);
        out += L",\"owner\":" + quote(row.Owner);
        out += L",\"module_base\":" + quote(std::to_wstring(row.ModuleBase));
        out += L",\"root_slot\":" + quote(std::to_wstring(row.RootSlot));
        out += L",\"table\":" + quote(std::to_wstring(row.Table));
        out += L",\"slot\":" + quote(std::to_wstring(row.Slot));
        out += L",\"target\":" + quote(std::to_wstring(row.Target));
        out += L",\"handle\":" + quote(std::to_wstring(row.HandleValue));
        out += L",\"peb\":" + quote(std::to_wstring(row.ProcessPeb));
        out += L",\"index\":" + std::to_wstring(row.Index);
        out += L",\"pointer_size\":" + std::to_wstring(row.PointerSize);
        out += L",\"protection\":" + std::to_wstring(row.Protection);
        out += L",\"memory_type\":" + std::to_wstring(row.MemoryType);
        out += L",\"stable\":" + std::wstring(row.Stable ? L"true" : L"false");
        out += L",\"table_complete\":" + std::wstring(row.TableComplete ? L"true" : L"false");
        out += L",\"table_present\":" + std::wstring(row.TablePresent ? L"true" : L"false");
        out += L",\"executable\":" + std::wstring(row.Executable ? L"true" : L"false");
        out += L",\"unowned\":" + std::wstring(row.Unowned ? L"true" : L"false") + L"}";
    }
    return out + L"]}";
}
