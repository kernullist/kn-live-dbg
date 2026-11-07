#pragma once

#include "TypeSchema.h"
#include <atomic>

struct TypeSchemaBinding
{
    std::wstring ImageSha256;
    std::wstring PdbSha256;
    std::wstring ProviderSha256;
    std::wstring PdbGuid;
    uint64_t PdbAge = 0;
    uint64_t Machine = 0;
    uint64_t ImageSize = 0;
    std::wstring TypeName;
};

// Validate untrusted child bytes against identities held independently by the
// parent. A matching checksum is not parser authenticity or runtime validation.
bool AcceptTypeSchemaWorkerOutput(const std::string& output, const TypeSchemaBinding& expected,
    TypeSchemaPackage* package, std::wstring* error);

// The executable and adjacent msdia140.dll are the trusted installed runtime.
// Image/PDB are brokered local files; no symbol-search path is passed to DIA.
bool GenerateBrokeredTypeSchema(const std::wstring& executable, const std::wstring& image,
    const std::wstring& pdb, const std::wstring& typeName, TypeSchemaPackage* package, std::wstring* error,
    uint64_t workerTimeoutMs = 60000, const std::atomic<bool>* cancellation = nullptr);
