#pragma once

#include <Windows.h>
#include <DbgHelp.h>

#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

constexpr DWORD KNDBG_SYMTAG_UDT = 11;
constexpr DWORD KNDBG_SYMTAG_POINTER_TYPE = 14;
constexpr DWORD KNDBG_SYMTAG_ARRAY_TYPE = 15;
constexpr DWORD KNDBG_SYMTAG_BASE_TYPE = 16;
constexpr DWORD KNDBG_SYMTAG_TYPEDEF = 17;
constexpr DWORD KNDBG_SYMTAG_BASE_CLASS = 18;

class BrokeredTypeLayouts;
class BrokeredSymbolIndexes;
struct TypeSchemaPackage;

struct KernelModuleInfo
{
    uint64_t Base;
    uint32_t Size;
    std::wstring ImagePath;
    std::wstring ImageName;
};

struct TypeFieldInfo
{
    std::wstring Name;
    std::wstring TypeName;
    uint64_t ModuleBase = 0;
    ULONG TypeId = 0;
    ULONG ChildTypeId = 0;
    ULONG Offset = 0;
    ULONG64 Length = 0;
    DWORD Tag = 0;
    DWORD ChildTag = 0;
    DWORD BaseType = 0;
    bool IsBitField = false;
    ULONG BitPosition = 0;
    ULONG64 StorageLength = 0;
    // Present only for the isolated schema provider; not runtime-object proof.
    std::wstring SchemaPackageSha256;
};

struct TypeLayoutInfo
{
    std::wstring Name;
    uint64_t ModuleBase = 0;
    ULONG TypeId = 0;
    ULONG64 Size = 0;
    std::vector<TypeFieldInfo> Fields;
    // Data-member coverage only; providers without an explicit result leave it false.
    bool FieldsComplete = false;
    uint32_t UnavailableFields = 0;
    bool UnavailableFieldCountKnown = true;
    std::wstring SchemaPackageSha256;
    // Retain the complete parent-accepted root package, including identities,
    // field paths and gaps. Embedded layouts share the same immutable package.
    std::shared_ptr<const TypeSchemaPackage> SchemaPackage;
};

struct TypeMatchInfo
{
    std::wstring ModuleName;
    std::wstring Name;
    uint64_t ModuleBase;
    ULONG TypeId;
    ULONG64 Size;
    bool SizeKnown = false;
    std::wstring SymbolIndexSha256;
};

struct SymbolMatchInfo
{
    uint64_t Address;
    uint32_t Size;
    std::wstring Name;
    bool SizeKnown = false;
    std::wstring SymbolIndexSha256;
};

class SymbolEngine
{
public:
    SymbolEngine();
    ~SymbolEngine();

    bool Initialize(const std::wstring& symbolPath, std::wstring* error);
    void Shutdown();
    bool IsReady() const;

    const std::wstring& SymbolPath() const;
    void SetSymbolPath(const std::wstring& symbolPath);

    bool LoadKernelModules(std::wstring* error);
    bool PreloadKernelSymbols(size_t* loadedCount, std::wstring* error);
    std::vector<KernelModuleInfo> Modules() const;
    std::vector<KernelModuleInfo> CopyModules() const;

    bool ResolveSymbol(const std::wstring& name, uint64_t* address, std::wstring* error);
    bool FindNearestSymbol(uint64_t address, std::wstring* name, uint64_t* displacement, std::wstring* error);
    bool EnumerateSymbols(const std::wstring& mask, size_t limit, std::vector<SymbolMatchInfo>* matches, std::wstring* error);
    bool EnumerateTypes(const std::wstring& mask, size_t limit, std::vector<TypeMatchInfo>* matches, std::wstring* error);
    bool GetTypeLayout(const std::wstring& typeName, TypeLayoutInfo* layout, std::wstring* error);
    bool GetTypeLayoutById(uint64_t moduleBase, ULONG typeId, const std::wstring& typeName, TypeLayoutInfo* layout, std::wstring* error);
    bool GetTypeFields(const std::wstring& typeName, std::vector<TypeFieldInfo>* fields, ULONG64* typeSize, std::wstring* error);
    bool FindField(const std::wstring& typeName, const std::wstring& fieldName, TypeFieldInfo* field, std::wstring* error);
    std::optional<uint64_t> ParseAddressOrSymbol(const std::wstring& value, std::wstring* error);

private:
    friend struct SymbolEngineTestAccess;
    bool EnumKernelModules(std::vector<KernelModuleInfo>* modules, std::wstring* error);
    std::wstring ResolveModuleImagePath(const KernelModuleInfo& module) const;
    bool EnsureModuleSymbolsLoaded(const KernelModuleInfo& module, std::wstring* error, uint64_t timeoutMs = 60000);
    bool ReadyModules(std::wstring* error);
    void ClearMetadata();
    bool ShouldSearchTypeModule(const KernelModuleInfo& module, const std::wstring& moduleFilter) const;
    bool ready_;
    std::wstring symbolPath_;
    mutable std::mutex modulesMutex_;
    // Serialize broker requests and cache generations. Lock order is always
    // symbolMutex_ -> modulesMutex_; the parent never invokes a PDB provider.
    mutable std::recursive_mutex symbolMutex_;
    std::vector<KernelModuleInfo> modules_;
    // Broker-accepted artifact layouts, not runtime-object validation. Protected
    // by symbolMutex_; IDs expire on eviction or symbol/module-state changes.
    std::unique_ptr<BrokeredTypeLayouts> typeLayouts_;
    std::unique_ptr<BrokeredSymbolIndexes> symbolIndexes_;
    std::set<uint64_t> indexedModules_;
    std::set<uint64_t> admittedModules_;
    // Failed acquisitions are not retried per address in a scanner hot loop.
    // SetSymbolPath/LoadKernelModules/Initialize starts a new generation.
    std::map<uint64_t, std::wstring> indexFailures_;
};
