#pragma once

#include "ObservationSource.h"
#include <functional>
#include <memory>

using DumpPhysicalReader = std::function<ObservationReadState(uint64_t, uint32_t, std::vector<uint8_t>*)>;

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
        DumpPhysicalReader reader);
    const ObservationSourceCapabilities& Capabilities() const override;

protected:
    ObservationReadResult ReadSpans(const ObservationReadRequest& request) override;

private:
    ObservationSourceCapabilities Caps;
    uint64_t Root;
    uint32_t PagingLevels;
    DumpPhysicalReader Reader;
};

// Opens a bounded PAGE/DU64 full-dump run layout; never opens a live device.
// A missing/contradictory paging mode is rejected instead of assuming LA48.
std::unique_ptr<IObservationSource> OpenDumpObservationSource(const std::wstring& path, std::wstring* error);
