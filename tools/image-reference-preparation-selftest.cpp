#include "../user/ImageReferencePreparation.h"
#include "../user/McpJson.h"
#include "../user/ContentHash.h"
#include <chrono>
#include <iostream>
#include <mutex>
#include <thread>

namespace
{
    using Engine = ImageReferencePreparation;
    bool Wait(const std::function<bool()>& ready)
    {
        const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        for (;;)
        {
            if (ready()) { return true; }
            if (std::chrono::steady_clock::now() >= until) { return false; }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }
    std::wstring Text(const std::wstring& json, const wchar_t* key)
    { std::wstring value; mcpjson::GetString(json, key, &value); return value; }
    Engine::Request Work(uint32_t pid, uint64_t address, uint64_t first = 0)
    {
        Engine::Request request;
        request.Identity.BootId = L"synthetic:preparation-core"; request.Identity.ProcessId = pid; request.Identity.CreateTime = 1;
        request.Key = std::to_wstring(pid) + L":" + std::to_wstring(address);
        request.Path = L"synthetic:unopened.exe"; request.Base = address; request.Episode = address; request.FirstSeen = first;
        return request;
    }
}

int wmain(int argc, wchar_t** argv)
{
    unsigned checks = 0, failures = 0;
    const auto check = [&](bool ok, const char* name)
    { ++checks; if (!ok) { ++failures; std::cerr << "[reference.prepare] FAIL " << name << '\n'; } return ok; };
    std::wstring capacity, resultBound, native, admissions, dispatch, fixed, content, expired;
    try
    {
        {
            std::atomic<unsigned> running{0};
            Engine engine([&](const auto&, const auto& stop, auto&, auto&)
            { ++running; while (!stop.load()) { std::this_thread::yield(); } return Engine::Outcome::Cancelled; });
            for (unsigned i = 0; i < 64; ++i)
            {
                check(engine.Submit(Work(100 + i / 8, 0x1000 + i * 4096)).Status == Engine::Admission::Queued, "bounded admission");
                if (i == 7) { check(engine.Submit(Work(100, 0x100000)).Status == Engine::Admission::SubjectLimit, "inflight counts toward subject quota"); }
            }
            check(Wait([&] { return running.load() == 2; }), "observed actual workers before shutdown");
            check(engine.Submit(Work(999, 0x1000)).Status == Engine::Admission::GlobalLimit, "global includes queued and running");
            auto invalid = Work(999, 0x2000); invalid.FirstSeen = UINT64_MAX;
            check(engine.Submit(invalid).Status == Engine::Admission::Invalid, "future discovery rejected");
            invalid.FirstSeen = 0; invalid.Path.push_back(L'\0'); invalid.Path += L"different-file.exe";
            check(engine.Submit(invalid).Status == Engine::Admission::Invalid, "Win32 NUL truncation cannot change the requested path scope");
            engine.RequestStop(); engine.Join();
            capacity = engine.Json();
            check(Text(capacity, L"resident") == L"0" && Text(capacity, L"cancelled_queued") == L"62" &&
                engine.Submit(Work(999, 0x3000)).Status == Engine::Admission::Stopping, "join closes every admitted owner and rejects restart");
            engine.Reset();
            check(Text(engine.Json(), L"resident") == L"0" && Text(engine.Json(), L"admitted") == L"0", "owner reset opens a fresh ledger");
        }
        {
            Engine engine([](const auto&, const auto&, auto&, auto&) { return Engine::Outcome::Unavailable; });
            for (unsigned i = 0; i < 10; ++i) { check(engine.Submit(Work(200 + i, 0x1000 + i * 4096)).Status == Engine::Admission::Queued, "result-bound input"); }
            check(Wait([&] { return Text(engine.Json(), L"ready") == L"4"; }), "four completion slots reached");
            check(Text(engine.Json(), L"running") == L"0" && Text(engine.Json(), L"queued") == L"6", "ready backlog stops new parser work");
            auto first = engine.Take();
            check(first != nullptr && Wait([&] { return Text(engine.Json(), L"ready") == L"4"; }), "consumption releases exactly one completion slot");
            if (!first) { throw std::runtime_error("missing result"); }
            engine.Disposition(*first, true);
            engine.Abandon(10); // Still queued after at most five starts.
            engine.Abandon(first->Id == 1 ? 2 : 1); // One of the initial four ready results.
            check(Wait([&] { return Text(engine.Json(), L"ready") == L"4"; }), "ready abandonment releases capacity");
            resultBound = engine.Json();
            check(Text(resultBound, L"cancelled_queued") == L"1" && Text(resultBound, L"discarded_ready") == L"1", "queued and ready abandonment distinguished");
        }
        {
            std::atomic<unsigned> entered{0}; std::atomic<bool> release{false};
            std::mutex orderMutex; std::vector<std::pair<uint32_t, uint64_t>> order;
            Engine engine([&](const auto& work, const auto& stop, auto&, auto&)
            {
                if (work.Identity.ProcessId < 100)
                {
                    ++entered;
                    while (!stop.load() && !(work.Identity.ProcessId == 90 && release.load())) { std::this_thread::yield(); }
                    return stop.load() ? Engine::Outcome::Cancelled : Engine::Outcome::Unavailable;
                }
                std::lock_guard<std::mutex> lock(orderMutex);
                order.emplace_back(work.Identity.ProcessId, work.Base);
                return Engine::Outcome::Unavailable;
            });
            check(engine.Submit(Work(90, 0x1000)).Status == Engine::Admission::Queued &&
                engine.Submit(Work(91, 0x2000)).Status == Engine::Admission::Queued && Wait([&] { return entered.load() == 2; }), "two dispatch gates observed");
            const auto now = GetTickCount64();
            const auto origin = now > 1000 ? now - 1000 : 0;
            for (unsigned i = 0; i < 20; ++i)
            {
                const uint32_t pid = 100 + i % 4;
                const uint64_t address = 0x10000 + i * 4096, queued = origin + i;
                check(engine.Submit(Work(pid, address, origin), queued).Status == Engine::Admission::Queued, "fixed FIFO cohort admitted");
                if (!admissions.empty()) { admissions += L","; }
                admissions += L"{\"pid\":" + std::to_wstring(pid) + L",\"base\":" + std::to_wstring(address) + L",\"queued\":" + std::to_wstring(queued) + L"}";
            }
            release.store(true);
            unsigned consumed = 0;
            check(Wait([&]
            {
                while (auto value = engine.Take()) { engine.Disposition(*value, true); ++consumed; }
                return consumed == 21;
            }), "single free worker completes all admitted subjects");
            fixed = engine.Json();
            engine.RequestStop(); engine.Join();
            check(Text(engine.Json(), L"debt_loans") == Text(fixed, L"debt_loans"), "shutdown preserves dispatch history");
            check(order.size() == 20, "each cohort item dispatched exactly once");
            for (const auto& value : order)
            {
                if (!dispatch.empty()) { dispatch += L","; }
                dispatch += L"{\"pid\":" + std::to_wstring(value.first) + L",\"base\":" + std::to_wstring(value.second) + L"}";
            }
        }
        {
            wchar_t executable[32768]{};
            check(GetModuleFileNameW(nullptr, executable, 32768) != 0, "owned native reference path");
            Engine engine;
            auto request = Work(100, 0x140000000ull); request.Path = executable;
            check(engine.Submit(request).Status == Engine::Admission::Queued, "native preparation admitted");
            std::unique_ptr<Engine::Result> ready;
            check(Wait([&] { ready = engine.Take(); return ready != nullptr; }), "native preparation completion observed");
            check(ready && ready->Status == Engine::Outcome::Prepared && ready->Value &&
                ready->Value->Reference.HasFileIdentity && !ready->Value->Sweep.Ranges.empty(), "native metadata and unobserved executable ranges");
            if (ready) { engine.Disposition(*ready, true); }
            native = engine.Json();
            std::atomic<bool> cancelled{true}; executable_image::DiskPeMetadata metadata; metadata.SizeOfImage = 1;
            check(!executable_image::ReadDiskPeMetadataCancelable(executable, &metadata, nullptr, cancelled) && metadata.SizeOfImage == 0,
                "cancelled native parser cannot return stale caller metadata");
            check(executable_image::ReadDiskPeMetadata(executable, &metadata, nullptr) && metadata.SizeOfImage != 0,
                "cancellation scope does not contaminate later ordinary parsing");
        }
        {
            wchar_t executable[32768]{}, directory[MAX_PATH]{}, path[MAX_PATH]{};
            if (!GetModuleFileNameW(nullptr, executable, 32768) || !GetTempPathW(MAX_PATH, directory) ||
                !GetTempFileNameW(directory, L"knc", 0, path)) { throw std::runtime_error("owned content fixture"); }
            struct Cleanup { const wchar_t* Path; ~Cleanup() { DeleteFileW(Path); } } cleanup{path};
            if (!CopyFileW(executable, path, FALSE)) { throw std::runtime_error("owned executable copy"); }
            const auto writable = [&]
            {
                const auto file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    nullptr, OPEN_EXISTING, 0, nullptr);
                if (file == INVALID_HANDLE_VALUE) { return false; }
                CloseHandle(file); return true;
            };
            Engine engine(Engine::Kind::Content);
            auto work = Work(404, 0x140000000ull); work.Path = path;
            const auto first = engine.Submit(work);
            check(first.Status == Engine::Admission::Queued && Wait([&] { return engine.IsReady(first.Id); }), "native content ready");
            check(!engine.Take(first.Id + 1) && engine.Contains(first.Id) && !writable(), "exact-ticket take preserves neighbor and source lease");
            auto result = engine.Take(first.Id);
            ExecutableSweepReference snapshot;
            if (result && result->Value && result->Value->Content) { result->Value->Content->Capture(&snapshot); }
            check(result && result->Status == Engine::Outcome::Prepared && snapshot.Artifact &&
                snapshot.Artifact->Sha256 == ContentHash::Bytes(snapshot.Artifact->Bytes) && result->Value->Content->Unchanged(),
                "content worker retains and hashes actual source with final fence");
            if (result) { engine.Disposition(*result, true); }
            result.reset();
            check(writable() && snapshot.Artifact && !snapshot.Artifact->Bytes.empty(), "consumer release closes handles while immutable bytes survive");
            {
                const auto file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
                const std::unique_ptr<void, decltype(&CloseHandle)> owner(file == INVALID_HANDLE_VALUE ? nullptr : file, &CloseHandle);
                std::atomic<bool> cancel{true}; ReferenceArtifact cancelled, ordinary;
                check(owner && !cancelled.OpenHandleCancelable(file, nullptr, cancel) && !cancelled.Snapshot() &&
                    ordinary.OpenHandle(file, nullptr) && ordinary.Snapshot(), "cancelled retention publishes no partial bytes and ordinary retention stays available");
            }
            const auto aging = engine.Submit(work);
            check(Wait([&] { return engine.IsReady(aging.Id); }) && !writable(), "unconsumed content owns bounded ready lease");
            check(Wait(writable) && !engine.Contains(aging.Id), "idle dispatcher expiry closes file without consumer query or stop");
            expired = engine.Json();
            const auto large = CreateFileW(path, GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            LARGE_INTEGER end{}; end.QuadPart = ReferenceArtifactMaxBytes + 1;
            const bool enlarged = large != INVALID_HANDLE_VALUE && SetFilePointerEx(large, end, nullptr, FILE_BEGIN) && SetEndOfFile(large);
            if (large != INVALID_HANDLE_VALUE) { CloseHandle(large); }
            check(enlarged, "owned oversized reference control");
            const auto oversize = engine.Submit(work);
            check(Wait([&] { return engine.IsReady(oversize.Id); }), "oversized content attempt completes");
            result = engine.Take(oversize.Id); snapshot = {};
            if (result && result->Value && result->Value->Content) { result->Value->Content->Capture(&snapshot); }
            check(result && result->Status == Engine::Outcome::Prepared && !snapshot.Artifact &&
                snapshot.CaptureStatus == L"retention_unavailable", "oversized file preserves explicit unretained source lease");
            if (result) { engine.Disposition(*result, true); }
            result.reset(); content = engine.Json();
            engine.RequestStop(); engine.Join(); engine.Reset();
            check(Text(engine.Json(), L"phase") == L"content" && Text(engine.Json(), L"resident") == L"0", "content mode survives owner reset");
            check(DeleteFileW(path) != FALSE, "all owned content handles released before fixture cleanup");
        }
        {
            Engine engine([](const auto&, const auto&, auto&, auto&) -> Engine::Outcome { throw std::runtime_error("controlled loader fault"); });
            auto work = Work(42, 0x1000);
            const auto original = engine.Submit(work);
            std::unique_ptr<Engine::Result> result;
            check(Wait([&] { result = engine.Take(); return result != nullptr; }) && result->Status == Engine::Outcome::Fault,
                "loader exception is a failed result, not thread termination");
            work.Identity.CreateTime = 2;
            const auto reused = engine.Submit(work);
            check(reused.Status == Engine::Admission::Queued && reused.Id != original.Id &&
                Wait([&] { result = engine.Take(); return result != nullptr; }) && result->Work.Identity.CreateTime == 2 &&
                result->Status == Engine::Outcome::Fault, "later process generation keeps its own request after worker fault");
        }
    }
    catch (...) { check(false, "unexpected fixture exception"); }
    if (argc == 2 && std::wstring(argv[1]) == L"--json")
    {
        std::wcout << L"{\"schema\":\"kn.image_preparation_core.v1\",\"passed\":" << (failures == 0 ? L"true" : L"false") <<
            L",\"checks\":" << checks << L",\"initial_turns\":2,\"admissions\":[" << admissions << L"],\"dispatch\":[" << dispatch <<
            L"],\"fixed\":" << (fixed.empty() ? L"null" : fixed) << L",\"capacity\":" << (capacity.empty() ? L"null" : capacity) <<
            L",\"result_bound\":" << (resultBound.empty() ? L"null" : resultBound) << L",\"native\":" << (native.empty() ? L"null" : native) <<
            L",\"content\":" << (content.empty() ? L"null" : content) << L",\"expired\":" << (expired.empty() ? L"null" : expired) << L"}\n";
    }
    std::cerr << "[reference.prepare] checks=" << checks << " failed=" << failures << '\n';
    return failures == 0 ? 0 : 1;
}
