#pragma once

#include "ObservationSource.h"
#include "TranslationReceipt.h"
#include <functional>
#include <memory>
#include <optional>

using DumpPhysicalReader = std::function<ObservationReadState(uint64_t, uint32_t, std::vector<uint8_t>*)>;
using DumpObservedPhysicalReader = std::function<ObservationReadResult(uint64_t, uint32_t)>;

struct DumpReadObservation
{
    ObservationSourceCapabilities Source;
    ObservationReadRequest Request;
    ObservationReadResult Result;
    ObservationReadSet PhysicalReads;
    std::vector<TranslationReceipt> Translations;
};

// File offsets and digests describe the existing initialization reads. The
// caller owns this report; the opened source never retains a pointer to it.
struct DumpInitializationRead
{
    const wchar_t* Purpose = L"dump_header";
    uint32_t CandidateLevels = 0;
    uint32_t RequestedBytes = 0;
    std::optional<uint64_t> PhysicalAddress, FileOffset;
    ObservationReadState State = ObservationReadState::Failed;
    std::optional<uint32_t> SeekStatus, ReadStatus, TransferredBytes, IdentityFailureStatus;
    uint32_t DigestBytes = 0;
    std::wstring Sha256;
    uint64_t StartedMs = 0, FinishedMs = 0;
};

struct DumpInitializationProbeRead
{
    const wchar_t* Purpose = L"list_head";
    uint32_t CandidateLevels = 0, Length = 0;
    uint64_t Address = 0;
    uint32_t FirstFileSequence = 0, FileReadCount = 0;
    bool ParserAccepted = false;
    ObservationReadResult Original;
};

struct DumpInitializationObservation
{
    // The aligned 16-byte head can span two pages. Its two 8-byte
    // neighbors use one page each. Each page needs at most levels+1 reads.
    static constexpr uint32_t MaxReads = 1 + 4 * (4 + 1) + 4 * (5 + 1);
    static constexpr uint32_t MaxRequestedBytes = 8192 + (4 * (4 + 5) * 8) + 2 * (16 + 8 + 8);
    std::wstring SourceId;
    std::optional<uint64_t> FileBytes;
    const wchar_t* Decision = L"source_unavailable";
    const wchar_t* Probe4 = L"not_attempted";
    const wchar_t* Probe5 = L"not_attempted";
    std::optional<uint32_t> OpenStatus, QualificationError, ContextLevels, SelectedLevels, FinalIdentityStatus;
    std::optional<bool> FinalIdentityMatched;
    uint32_t Attempts = 0, ChargedBytes = 0;
    bool RecordingComplete = true;
    std::vector<DumpInitializationRead> Reads;
    std::vector<DumpInitializationProbeRead> ProbeReads;
};

struct DumpAddressTranslation
{
    ObservationReadState State = ObservationReadState::Unsupported;
    uint64_t PhysicalAddress = 0;
    uint64_t MappingBytes = 0;
};

DumpAddressTranslation TranslateDumpAddress(const DumpPhysicalReader& reader,
    uint64_t root, uint32_t pagingLevels, uint64_t address);

// The callback owns or outlives the source and serializes its underlying I/O.
class DumpObservationSource final : public IObservationSource
{
public:
    DumpObservationSource(std::wstring sourceId, uint64_t root, uint32_t pagingLevels,
        DumpPhysicalReader reader, DumpObservedPhysicalReader observedReader = {});
    const ObservationSourceCapabilities& Capabilities() const override;
    DumpReadObservation ReadWithReceipts(const ObservationReadRequest& request, ObservationOperationBudget budget = {});

protected:
    ObservationReadResult ReadSpans(const ObservationReadRequest& request) override;

private:
    friend std::unique_ptr<DumpObservationSource> OpenDumpObservationSource(const std::wstring&, std::wstring*, DumpInitializationObservation*);
    ObservationSourceCapabilities Caps;
    uint64_t Root;
    uint32_t PagingLevels;
    DumpPhysicalReader Reader;
    DumpObservedPhysicalReader ObservedReader;
    bool FileHandleBound = false;
};

// Opens a bounded PAGE/DU64 full-dump run layout; never opens a live device.
// A missing/contradictory paging mode is rejected instead of assuming LA48.
std::unique_ptr<DumpObservationSource> OpenDumpObservationSource(const std::wstring& path, std::wstring* error,
    DumpInitializationObservation* initialization = nullptr);
