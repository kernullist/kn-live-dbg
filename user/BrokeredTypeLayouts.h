#pragma once

#include "SymbolEngine.h"
#include "TypeSchema.h"
#include <map>

// A bounded cache of parent-validated schemas. IDs are process-unique opaque
// references, not DIA/DbgHelp IDs, and are never reused after eviction/reset.
class BrokeredTypeLayouts
{
public:
    void Clear();
    bool Find(uint64_t moduleBase, const std::wstring& typeName, TypeLayoutInfo* layout) const;
    bool FindById(uint64_t moduleBase, ULONG id, const std::wstring& typeName, TypeLayoutInfo* layout) const;
    bool Insert(uint64_t moduleBase, const std::wstring& qualifiedName, const TypeSchemaPackage& schema,
        TypeLayoutInfo* layout, std::wstring* error);
private:
    std::map<std::pair<uint64_t, std::wstring>, ULONG> Roots;
    std::map<ULONG, TypeLayoutInfo> Nodes;
    size_t EncodedBytes = 0;
};
