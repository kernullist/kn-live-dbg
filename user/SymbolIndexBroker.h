#pragma once
#include "SymbolIndex.h"

bool AcceptSymbolIndexWorkerOutput(const std::string& output, const SymbolIndex& expected, SymbolIndex* index);
bool GenerateBrokeredSymbolIndex(const std::wstring& executable, const std::wstring& image, const std::wstring& pdb,
    SymbolIndex* index, std::wstring* error, uint64_t timeoutMs = 60000);
bool ResolveBrokeredSymbolIndex(const std::wstring& executable, const std::wstring& image, uint32_t expectedImageSize,
    const std::wstring& symbolPath, SymbolIndex* index, std::wstring* error, uint64_t timeoutMs = 60000);
