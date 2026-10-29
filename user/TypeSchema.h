#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct TypeSchemaField
{
    std::vector<std::wstring> Path;
    std::wstring TypeName;
    std::wstring Expansion;
    uint64_t SymbolTag = 0;
    uint64_t BaseType = 0;
    uint64_t Offset = 0;
    uint64_t StorageBytes = 0;
    uint64_t BitPosition = 0;
    uint64_t BitWidth = 0;
};

struct TypeSchemaGap
{
    std::vector<std::wstring> Path;
    std::wstring Reason;
};

struct TypeSchemaPackage
{
    std::wstring ImageSha256;
    std::wstring PdbSha256;
    std::wstring PdbGuid;
    uint64_t PdbAge = 0;
    uint64_t Machine = 0;
    uint64_t ImageSize = 0;
    std::wstring ProviderSha256;
    std::wstring ProviderVersion;
    std::wstring TypeName;
    uint64_t TypeBytes = 0;
    std::vector<TypeSchemaField> Fields;
    std::vector<TypeSchemaGap> Gaps;
};

constexpr size_t TypeSchemaMaxBytes = 2 * 1024 * 1024;
constexpr size_t TypeSchemaMaxFields = 4096;
constexpr size_t TypeSchemaMaxDepth = 8;

std::wstring TypeSchemaExpansion(uint64_t symbolTag, size_t depth);
bool ValidateTypeSchema(const TypeSchemaPackage& package, std::wstring* error);
std::wstring TypeSchemaJson(const TypeSchemaPackage& package);
bool ParseTypeSchema(const std::wstring& json, TypeSchemaPackage* package, std::wstring* error);
bool LoadTypeSchema(const std::wstring& path, TypeSchemaPackage* package, std::wstring* error);
bool SaveTypeSchema(const std::wstring& path, const TypeSchemaPackage& package, std::wstring* error);
bool GenerateTypeSchema(const std::wstring& image, const std::wstring& pdb, const std::wstring& typeName,
    const std::wstring& provider, TypeSchemaPackage* package, std::wstring* error);
int RunTypeSchemaCommand(int argc, wchar_t** argv);
