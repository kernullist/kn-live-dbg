#include "BrokeredTypeLayouts.h"
#include "McpJson.h"
#include <algorithm>
#include <atomic>

namespace
{
    constexpr size_t MaximumRoots = 32;
    constexpr size_t MaximumEncodedBytes = 8 * 1024 * 1024;
    constexpr size_t MaximumNodes = 32768;
    std::atomic<uint64_t> NextId{0x80000000ull};
    bool AllocateIds(size_t count, ULONG* first)
    {
        auto current = NextId.load();
        do
        {
            if (count == 0 || current > UINT32_MAX || count > UINT32_MAX - current + 1) { return false; }
        } while (!NextId.compare_exchange_weak(current, current + count));
        *first = static_cast<ULONG>(current);
        return true;
    }
}

void BrokeredTypeLayouts::Clear() { Roots.clear(); Nodes.clear(); EncodedBytes = 0; }
bool BrokeredTypeLayouts::Find(uint64_t moduleBase, const std::wstring& typeName, TypeLayoutInfo* layout) const
{
    if (layout == nullptr) { return false; }
    *layout = {};
    const auto root = Roots.find({moduleBase, typeName});
    if (root == Roots.end()) { return false; }
    const auto node = Nodes.find(root->second);
    if (node == Nodes.end()) { return false; }
    *layout = node->second;
    return true;
}
bool BrokeredTypeLayouts::FindById(uint64_t moduleBase, ULONG id, const std::wstring& typeName, TypeLayoutInfo* layout) const
{
    if (layout == nullptr) { return false; }
    *layout = {};
    const auto found = Nodes.find(id);
    if (found == Nodes.end() || found->second.ModuleBase != moduleBase ||
        (!typeName.empty() && found->second.Name != typeName)) { return false; }
    *layout = found->second;
    return true;
}
bool BrokeredTypeLayouts::Insert(uint64_t moduleBase, const std::wstring& qualifiedName, const TypeSchemaPackage& schema,
    TypeLayoutInfo* layout, std::wstring* error)
{
    if (error != nullptr) { *error = L"isolated layout exceeds the cache or has invalid bounded schema metadata"; }
    if (layout == nullptr) { return false; }
    *layout = {};
    if (moduleBase == 0 || !schema.ParserIsolated || qualifiedName.empty() || qualifiedName.size() > 2048 ||
        !ValidateTypeSchema(schema, nullptr)) { return false; }
    const auto json = TypeSchemaJson(schema);
    const auto bytes = mcpjson::WideToUtf8(json).size();
    std::wstring digest;
    if (bytes == 0 || bytes > TypeSchemaMaxBytes || !mcpjson::GetString(json, L"package_sha256", &digest)) { return false; }
    using Path = std::vector<std::wstring>;
    struct Node { ULONG Id; uint64_t Offset; TypeLayoutInfo Layout; };
    const auto embedded = static_cast<size_t>(std::count_if(schema.Fields.begin(), schema.Fields.end(),
        [](const auto& f) { return f.Expansion == L"embedded"; }));
    ULONG first = 0;
    if (!AllocateIds(embedded + 1, &first)) { return false; }
    std::map<Path, Node> pending;
    const auto retained = std::make_shared<const TypeSchemaPackage>(schema);
    TypeLayoutInfo root;
    root.Name = qualifiedName;
    root.ModuleBase = moduleBase;
    root.TypeId = first;
    root.Size = schema.TypeBytes;
    root.SchemaPackageSha256 = digest;
    root.SchemaPackage = retained;
    root.FieldsComplete = true;
    pending.emplace(Path{}, Node{first, 0, std::move(root)});
    ULONG next = first;
    for (const auto& f : schema.Fields)
    {
        if (f.Expansion != L"embedded") { continue; }
        TypeLayoutInfo child;
        child.Name = f.TypeName;
        child.ModuleBase = moduleBase;
        child.TypeId = ++next;
        child.Size = f.StorageBytes;
        child.SchemaPackageSha256 = digest;
        child.SchemaPackage = retained;
        child.FieldsComplete = true;
        pending.emplace(f.Path, Node{next, f.Offset, std::move(child)});
    }
    for (const auto& f : schema.Fields)
    {
        auto parentPath = f.Path;
        parentPath.pop_back();
        const auto parent = pending.find(parentPath);
        if (parent == pending.end() || f.Offset < parent->second.Offset || f.Offset - parent->second.Offset > UINT32_MAX)
        { return false; }
        TypeFieldInfo field;
        field.Name = f.Path.back();
        field.TypeName = f.TypeName;
        field.ModuleBase = moduleBase;
        field.Offset = static_cast<ULONG>(f.Offset - parent->second.Offset);
        field.Length = f.BitWidth != 0 ? f.BitWidth : f.StorageBytes;
        field.StorageLength = f.StorageBytes;
        field.IsBitField = f.BitWidth != 0;
        field.BitPosition = static_cast<ULONG>(f.BitPosition);
        field.Tag = 7; // SymTagData
        field.ChildTag = static_cast<DWORD>(f.SymbolTag);
        field.BaseType = static_cast<DWORD>(f.BaseType);
        field.SchemaPackageSha256 = digest;
        const auto child = pending.find(f.Path);
        if (child != pending.end()) { field.ChildTypeId = child->second.Id; }
        parent->second.Layout.Fields.push_back(std::move(field));
    }
    for (const auto& gap : schema.Gaps)
    {
        auto path = gap.Path;
        auto node = pending.find(path);
        if (node == pending.end() && !path.empty()) { path.pop_back(); node = pending.find(path); }
        if (node != pending.end())
        {
            node->second.Layout.FieldsComplete = false;
            node->second.Layout.UnavailableFieldCountKnown = false;
        }
    }
    std::map<ULONG, TypeLayoutInfo> nodes;
    for (auto& entry : pending)
    {
        auto& fields = entry.second.Layout.Fields;
        std::stable_sort(fields.begin(), fields.end(), [](const auto& a, const auto& b)
        { return a.Offset != b.Offset ? a.Offset < b.Offset : a.BitPosition < b.BitPosition; });
        nodes.emplace(entry.second.Id, std::move(entry.second.Layout));
    }
    const auto key = std::make_pair(moduleBase, qualifiedName);
    // Prepare the allocating root node before evicting any retained state.
    std::map<std::pair<uint64_t, std::wstring>, ULONG> newRoot;
    newRoot.emplace(key, first);
    TypeLayoutInfo result = nodes.at(first);
    if (Roots.count(key) != 0 || Roots.size() >= MaximumRoots || bytes > MaximumEncodedBytes - EncodedBytes ||
        nodes.size() > MaximumNodes - Nodes.size()) { Clear(); }
    Roots.merge(newRoot);
    Nodes.merge(nodes);
    EncodedBytes += bytes;
    *layout = std::move(result);
    if (error != nullptr) { error->clear(); }
    return true;
}
