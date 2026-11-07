#pragma once

#include <Windows.h>
#include <cstdint>
#include <string>
#include <vector>

constexpr size_t SymbolIndexMaxBytes = 32 * 1024 * 1024;
constexpr size_t SymbolIndexMaxRows = 200000;

struct IndexedSymbol
{
    uint32_t Rva = 0;
    uint32_t Tag = 0;
    uint64_t Bytes = 0;
    bool SizeKnown = false;
    std::wstring Name;
    std::wstring LinkageName;
};
struct IndexedType
{
    std::wstring Name;
    uint32_t ProviderId = 0;
    uint64_t Bytes = 0;
    bool SizeKnown = false;
};
struct SymbolIndex
{
    std::wstring ImageSha256, PdbSha256, ProviderSha256, PdbGuid;
    uint32_t PdbAge = 0, ImageSize = 0, Machine = 0;
    std::vector<IndexedSymbol> Symbols;
    std::vector<IndexedType> Types;
    // Computed by the recipient, not an authenticity or runtime-object claim.
    std::wstring IndexSha256;
};

bool SymbolIndexName(const std::wstring& name);
bool SymbolIndexRawName(const std::wstring& name);
std::wstring EscapeSymbolIndexName(const std::wstring& name);
bool IndexedSymbolLess(const IndexedSymbol& a, const IndexedSymbol& b);
bool IndexedTypeLess(const IndexedType& a, const IndexedType& b);
bool ValidateSymbolIndex(const SymbolIndex& index);
bool EncodeSymbolIndex(const SymbolIndex& index, std::string* output);
bool DecodeSymbolIndex(const std::string& input, SymbolIndex* index);
bool GenerateSymbolIndexFromHandles(HANDLE image, HANDLE pdb, HANDLE provider, SymbolIndex* index, uint32_t* failure = nullptr);
int RunSymbolIndexWorkerCommand(int argc, wchar_t** argv);
