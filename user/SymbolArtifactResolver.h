#pragma once

#include "TypeSchema.h"
#include <string>
#include <functional>

struct AcceptedSymbolArtifacts { std::wstring ImageSha256, PdbSha256; };
using SymbolArtifactConsumer = std::function<bool(const std::wstring&, const std::wstring&, uint64_t,
    AcceptedSymbolArtifacts*, std::wstring*)>;

// The consumer runs the parent broker and supplies its independently accepted
// hashes. A successful call also finishes any required cache publication.
bool ResolveSymbolArtifacts(const std::wstring& executable, const std::wstring& image,
    uint32_t expectedImageSize, const std::wstring& symbolPath, const SymbolArtifactConsumer& consume, std::wstring* error,
    uint64_t timeoutMs = 60000);

// Acquires only artifacts named by the image's bounded RSDS identity and the
// configured local/SRV search roots. PDB contents are parsed only by the broker
// worker. A fetched file is published create-new only after that worker accepts
// the requested layout; failures never replace an existing cache entry.
bool ResolveBrokeredTypeSchema(const std::wstring& executable, const std::wstring& image,
    uint32_t expectedImageSize, const std::wstring& symbolPath, const std::wstring& typeName,
    TypeSchemaPackage* package, std::wstring* error);
