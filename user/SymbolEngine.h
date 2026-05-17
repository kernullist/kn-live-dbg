#pragma once

#include <Windows.h>
#include <DbgHelp.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

constexpr DWORD KNDBG_SYMTAG_UDT = 11;
constexpr DWORD KNDBG_SYMTAG_POINTER_TYPE = 14;
constexpr DWORD KNDBG_SYMTAG_ARRAY_TYPE = 15;
constexpr DWORD KNDBG_SYMTAG_BASE_TYPE = 16;

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
    uint64_t ModuleBase;
    ULONG TypeId;
    ULONG ChildTypeId;
    ULONG Offset;
    ULONG64 Length;
    DWORD Tag;
    DWORD ChildTag;
    DWORD BaseType;
    bool IsBitField;
    ULONG BitPosition;
};

struct TypeLayoutInfo
{
    std::wstring Name;
    uint64_t ModuleBase;
    ULONG TypeId;
    ULONG64 Size;
    std::vector<TypeFieldInfo> Fields;
};

struct SymbolMatchInfo
{
    uint64_t Address;
    uint32_t Size;
    std::wstring Name;
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
    const std::vector<KernelModuleInfo>& Modules() const;

    bool ResolveSymbol(const std::wstring& name, uint64_t* address, std::wstring* error);
    bool FindNearestSymbol(uint64_t address, std::wstring* name, uint64_t* displacement, std::wstring* error);
    bool EnumerateSymbols(const std::wstring& mask, size_t limit, std::vector<SymbolMatchInfo>* matches, std::wstring* error);
    bool GetTypeLayout(const std::wstring& typeName, TypeLayoutInfo* layout, std::wstring* error);
    bool GetTypeLayoutById(uint64_t moduleBase, ULONG typeId, const std::wstring& typeName, TypeLayoutInfo* layout, std::wstring* error);
    bool GetTypeFields(const std::wstring& typeName, std::vector<TypeFieldInfo>* fields, ULONG64* typeSize, std::wstring* error);
    bool FindField(const std::wstring& typeName, const std::wstring& fieldName, TypeFieldInfo* field, std::wstring* error);
    std::optional<uint64_t> ParseAddressOrSymbol(const std::wstring& value, std::wstring* error);

private:
    bool EnumKernelModules(std::vector<KernelModuleInfo>* modules, std::wstring* error);
    std::wstring ResolveModuleImagePath(const KernelModuleInfo& module) const;

    HANDLE process_;
    bool ready_;
    std::wstring symbolPath_;
    std::vector<KernelModuleInfo> modules_;
};
