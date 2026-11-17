#pragma once
#include "../user/KmonHandleTracking.h"
#include "../user/KmonUserModuleSource.h"
#include <charconv>
#include <iostream>

// A read-only measurement endpoint in the validation EXE. The controller
// passes one inherited query handle to its private job. No PID input is accepted.
namespace user_module_workload
{
    using Key = KmonUserModuleDebt::Key;
    using Handle = std::unique_ptr<void, decltype(&CloseHandle)>;

    inline uint64_t Creation(HANDLE process, uint32_t)
    {
        FILETIME created{}, exited{}, kernel{}, user{};
        if (!GetProcessTimes(process, &created, &exited, &kernel, &user)) { return 0; }
        return (static_cast<uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    }
    inline Handle OpenLiveMember(HANDLE job, DWORD pid, DWORD& error)
    {
        Handle process(OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid), &CloseHandle);
        if (!process) { error = GetLastError(); return process; }
        BOOL member = FALSE;
        if (!IsProcessInJob(process.get(), job, &member)) { error = GetLastError(); }
        else if (!member) { error = ERROR_NOT_FOUND; }
        else
        {
            const auto state = WaitForSingleObject(process.get(), 0);
            if (state == WAIT_TIMEOUT) { error = ERROR_SUCCESS; return process; }
            error = state == WAIT_FAILED ? GetLastError() : ERROR_NOT_FOUND;
        }
        process.reset();
        return process;
    }
    struct JobInventory
    {
        HANDLE Job;
        struct Membership
        {
            DWORD Assigned = 0, Count = 0;
            ULONG_PTR Pids[64]{};
        } Members;
        static_assert(offsetof(Membership, Pids) == offsetof(JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList));
        size_t NextIndex = 0;
        explicit JobInventory(HANDLE job) : Job(job) {}
        void Close() noexcept {}
        bool Open()
        {
            return QueryInformationJobObject(Job, JobObjectBasicProcessIdList, &Members, sizeof(Members), nullptr) &&
                Members.Count == Members.Assigned && Members.Count <= std::size(Members.Pids);
        }
        KmonUserInventoryRead Next(KmonUserTarget& target)
        {
            if (NextIndex == Members.Count) { return KmonUserInventoryRead::End; }
            target.Pid = static_cast<DWORD>(Members.Pids[NextIndex++]);
            return KmonUserInventoryRead::Row;
        }
        void Resolve(KmonUserTarget& target)
        {
            DWORD error = 0;
            const auto process = OpenLiveMember(Job, target.Pid, error);
            if (!process) { return; }
            target.CreateTime = Creation(process.get(), target.Pid);
            target.PinnedGeneration = target.CreateTime != 0;
            wchar_t path[32768]{};
            DWORD size = static_cast<DWORD>(std::size(path));
            if (QueryFullProcessImageNameW(process.get(), 0, path, &size))
            {
                const std::wstring image(path, size);
                target.Leaf = image.substr(image.find_last_of(L"\\/") + 1);
            }
        }
    };
    inline std::wstring KeyJson(Key key)
    { return L"[" + std::to_wstring(key.first) + L"," + mcpjson::Quote(std::to_wstring(key.second)) + L"]"; }
    inline std::wstring KeysJson(const std::vector<KmonUserTarget>& targets)
    {
        std::wstring keys;
        for (const auto& t : targets)
        {
            if (!keys.empty()) { keys += L","; }
            keys += KeyJson({t.Pid, t.CreateTime});
        }
        return L"[" + keys + L"]";
    }
    class Session
    {
        HANDLE Job;
        KmonUserModuleDebt Debt;
        Key Loan{};
        std::vector<KmonUserTarget> Selected;
        std::unique_ptr<KmonUserDeepScheduling> Deep;
        uint32_t Watched = 0, Priority = 0, Background = 0;
        const std::atomic<bool> Stop{false};

        std::wstring Inspect(const KmonUserTarget& target, KmonUserDeepResult& dispatch)
        {
            const Key key{target.Pid, target.CreateTime};
            KmonNativeModuleAttempt attempt(Debt, key, key == Loan);
            DWORD error = 0;
            const auto process = OpenLiveMember(Job, target.Pid, error);
            const auto before = process ? Creation(process.get(), target.Pid) : 0;
            if (process && !before) { error = GetLastError(); }
            KmonUserModuleView view;
            if (!before || before != target.CreateTime)
            {
                attempt.Fail(before ? KmonModuleResult::GenerationChanged :
                    error == ERROR_ACCESS_DENIED ? KmonModuleResult::AccessDenied : KmonModuleResult::IdentityUnavailable, error);
                dispatch = KmonUserDeepResult::IdentityRejected;
            }
            else
            {
                Debt.Pin(attempt.Visit, before, GetTickCount64());
                view = KmonReadFencedUserModules(attempt, target, before, process.get(), Stop, Creation,
                    [&](const MODULEENTRY32W& row) { return _wcsicmp(row.szModule, target.Leaf.c_str()) == 0; });
                dispatch = view.Stable ? KmonUserDeepResult::Returned : KmonUserDeepResult::IdentityRejected;
            }
            const auto* record = Debt.Find(key);
            if (!record || !attempt.Visit.Closed) { throw std::runtime_error("missing source receipt"); }
            return L"{\"kind\":\"dispatch\",\"key\":" + KeyJson(key) + L",\"start\":" + std::to_wstring(attempt.Visit.Start) +
                L",\"end\":" + std::to_wstring(GetTickCount64()) + L",\"before\":" + mcpjson::Quote(std::to_wstring(before)) +
                L",\"after\":" + mcpjson::Quote(std::to_wstring(view.AfterGeneration)) + L",\"rows\":" + std::to_wstring(view.Rows) +
                L",\"base\":" + std::to_wstring(view.Base) + L",\"terminal\":" + std::to_wstring(view.Error) +
                L",\"complete\":" + (view.Complete ? L"true" : L"false") + L",\"win32_error\":" +
                std::to_wstring(record->Error) + L",\"result\":" +
                mcpjson::Quote(KmonModuleResultName(record->Result)) + L",\"last_success\":" +
                (record->Successful ? std::to_wstring(record->LastSuccess) : L"null") + L"}";
        }
    public:
        explicit Session(HANDLE job) : Job(job) {}
        bool Pending() const { return Deep && !Deep->Complete(); }
        std::wstring Inventory()
        {
            if (Pending()) { throw std::runtime_error("undispatched cohort"); }
            const auto begin = GetTickCount64();
            KmonUserInventory<JobInventory> inventory(JobInventory{Job}, {}, {}, GetCurrentProcessId(), begin);
            while (inventory.Run(GetTickCount64, []() { return false; }) == KmonDiscoveryDispatch::Continued) {}
            if (!inventory.Complete() || inventory.WalkIncomplete() || inventory.Capped())
            { throw std::runtime_error("job census incomplete"); }
            auto targets = inventory.Take();
            std::map<uint32_t, uint64_t> generations;
            std::map<uint32_t, size_t> indices;
            std::array<std::vector<uint32_t>, 3> tiers;
            for (size_t i = 0; i < targets.size(); ++i)
            {
                const auto& t = targets[i];
                if (!t.PinnedGeneration || t.Leaf.empty()) { throw std::runtime_error("unresolved member during census"); }
                generations.emplace(t.Pid, t.CreateTime);
                indices.emplace(t.Pid, i);
                tiers[(t.Pid / 4) % 3].push_back(t.Pid);
            }
            const auto admitted = GetTickCount64();
            Loan = Debt.Refresh(targets, generations, true, admitted);
            const auto pids = KmonSelectUserPids(tiers[0], tiers[1], tiers[2], &Watched, &Priority, &Background, {}, nullptr, Loan.first);
            Selected.clear();
            for (const auto pid : pids) { Selected.push_back(targets[indices.at(pid)]); }
            Deep = std::make_unique<KmonUserDeepScheduling>(Selected.size(), GetTickCount64());
            return L"{\"kind\":\"inventory\",\"start\":" + std::to_wstring(begin) + L",\"admission\":" + std::to_wstring(admitted) +
                L",\"members\":" + KeysJson(targets) + L",\"selected\":" + KeysJson(Selected) + L",\"loan\":" + KeyJson(Loan) + L"}";
        }
        std::wstring Dispatch()
        {
            if (!Pending()) { throw std::runtime_error("no selected target"); }
            std::wstring receipt;
            Deep->Run(GetTickCount64, [&](size_t i)
            {
                auto result = KmonUserDeepResult::Returned;
                receipt = Inspect(Selected.at(i), result);
                return result;
            }, []() { return false; }, [](size_t, const char*) {});
            if (receipt.empty()) { throw std::runtime_error("dispatch fault"); }
            return receipt;
        }
        std::wstring Finish() const
        {
            if (Pending()) { throw std::runtime_error("incomplete final cohort"); }
            return L"{\"kind\":\"finish\",\"ledger\":" + Debt.Json(GetTickCount64()) + L"}";
        }
    };
    inline void Reply(const std::wstring& payload)
    {
        std::wcout << L"{\"schema\":\"kn.owned_module_workload.v1\",\"payload\":" << payload << L"}" << std::endl;
    }
    inline int Run(const std::string& argument)
    {
        uintptr_t value = 0;
        const auto parsed = std::from_chars(argument.data(), argument.data() + argument.size(), value);
        if (parsed.ec != std::errc{} || parsed.ptr != argument.data() + argument.size() || !value || value == UINTPTR_MAX) { return 2; }
        const auto inherited = reinterpret_cast<HANDLE>(value);
        JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
        if (!QueryInformationJobObject(inherited, JobObjectBasicAccountingInformation, &accounting, sizeof(accounting), nullptr)) { return 2; }
        Handle job(inherited, &CloseHandle);
        Session session(job.get());
        Reply(L"{\"kind\":\"ready\"}");
        try
        {
            for (std::string command; std::getline(std::cin, command);)
            {
                if (command == "inventory") { Reply(session.Inventory()); }
                else if (command == "dispatch") { Reply(session.Dispatch()); }
                else if (command == "finish") { Reply(session.Finish()); return 0; }
                else { return 2; }
            }
        }
        catch (const std::exception& ex) { std::cerr << ex.what() << '\n'; }
        return 1;
    }
}
