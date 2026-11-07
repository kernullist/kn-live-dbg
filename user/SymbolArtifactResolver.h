#pragma once

#include "TypeSchema.h"
#include <string>

// Acquires only artifacts named by the image's bounded RSDS identity and the
// configured local/SRV search roots. PDB contents are parsed only by the broker
// worker. A fetched file is published create-new only after that worker accepts
// the requested layout; failures never replace an existing cache entry.
bool ResolveBrokeredTypeSchema(const std::wstring& executable, const std::wstring& image,
    uint32_t expectedImageSize, const std::wstring& symbolPath, const std::wstring& typeName,
    TypeSchemaPackage* package, std::wstring* error);
