#pragma once

#include "ObservationSource.h"
#include "TranslationReceipt.h"
#include <functional>
#include <memory>

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
    friend std::unique_ptr<DumpObservationSource> OpenDumpObservationSource(const std::wstring&, std::wstring*);
    ObservationSourceCapabilities Caps;
    uint64_t Root;
    uint32_t PagingLevels;
    DumpPhysicalReader Reader;
    DumpObservedPhysicalReader ObservedReader;
    bool FileHandleBound = false;
};

// Opens a bounded PAGE/DU64 full-dump run layout; never opens a live device.
// A missing/contradictory paging mode is rejected instead of assuming LA48.
std::unique_ptr<DumpObservationSource> OpenDumpObservationSource(const std::wstring& path, std::wstring* error);
