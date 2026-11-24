#pragma once

#include "EtlCaptureStatement.h"
#include "SavedEtlCapability.h"
#include "SchemaArtifact.h"
#include "SymbolArtifactCache.h"

namespace etl_profile
{
    bool NormalizeDigest(const std::wstring& input, std::wstring& result);
    std::wstring ReportFileSha256(const std::wstring& report);
    CaptureStatement ReadCaptureStatement(const std::wstring& path, const StatementAuthority& key, const SchemaArtifact& etl);

    class SavedEtlInput
    {
    public:
        SchemaArtifact File;
        bool Open(const std::wstring& name, uint64_t maximum = MaxFileBytes, DWORD* apiError = nullptr);
        // An inventory binds length before hashing. Retain a differing observed size for the report.
        bool OpenMember(const std::wstring& name, uint64_t expectedBytes, std::optional<uint64_t>& observedBytes, DWORD& apiError);
        bool ReadStatement(std::vector<uint8_t>& bytes);
        // Path-only Windows readers must reopen the leased object on its pinned volume.
        const std::wstring& PinnedVolumePath() const { return VolumePath; }
        bool Revalidated();
        void Probe(SavedEtlCapabilityProbe& probe);
    private:
        symbol_artifacts::Directories Parents;
        std::wstring VolumePath;
    };
}
