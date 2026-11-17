#pragma once

#include "ExecutableImageVerifier.h"
#include "ObservationModel.h"
#include <atomic>
#include <functional>
#include <memory>

// File preparation only. Results never qualify a live process, mapping or byte.
class ImageReferencePreparation
{
public:
    static constexpr size_t Capacity = 64, SubjectCapacity = 8, WorkerCount = 2, ResultSlots = 4;
    static constexpr uint64_t MaximumPreparedBytes = 128ull * 1024 * 1024;
    enum class Admission { Queued, GlobalLimit, SubjectLimit, Stopping, Invalid };
    enum class Outcome { Prepared, Unavailable, NoExecutableRanges, StorageLimit, Cancelled, Fault };
    struct Request
    {
        std::wstring Key, Path;
        ObservationIdentity Identity;
        uint64_t Base = 0, Episode = 0, FirstSeen = 0;
    };
    struct Prepared
    {
        executable_image::DiskPeMetadata Reference;
        ExecutableSweep Sweep;
    };
    struct Result
    {
        Request Work;
        uint64_t Id = 0, Queued = 0, Started = 0, Finished = 0, RetainedBytes = 0;
        Outcome Status = Outcome::Fault;
        std::wstring Error;
        std::unique_ptr<Prepared> Value;
    };
    struct Ticket { Admission Status = Admission::Invalid; uint64_t Id = 0; };
    using Loader = std::function<Outcome(const Request&, const std::atomic<bool>&, Prepared&, std::wstring&)>;

    explicit ImageReferencePreparation(Loader loader = {});
    ~ImageReferencePreparation();
    ImageReferencePreparation(const ImageReferencePreparation&) = delete;
    ImageReferencePreparation& operator=(const ImageReferencePreparation&) = delete;
    void Start();
    Ticket Submit(Request work, uint64_t now = GetTickCount64());
    std::unique_ptr<Result> Take();
    void Disposition(const Result& result, bool applied, uint64_t now = GetTickCount64());
    void Abandon(uint64_t id);
    void RequestStop();
    void Join();
    void Reset();
    std::wstring Json(uint64_t now = GetTickCount64()) const;
    static Outcome LoadNative(const Request&, const std::atomic<bool>&, Prepared&, std::wstring&);
    static const wchar_t* OutcomeName(Outcome);
    static const wchar_t* AdmissionName(Admission);
private:
    struct State;
    std::unique_ptr<State> Data;
    void Run();
};
