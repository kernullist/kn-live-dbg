#pragma once

#include "RecordingObservationSource.h"

// Syntax/canonical serialization only. Consumers must apply their own semantic
// admission policy before replay; this does not validate source or byte claims.
bool ParseObservationReadSet(const std::wstring& json, size_t maximumReceipts, ObservationReadSet* result,
    size_t maximumCharacters = 2 * 1024 * 1024);
