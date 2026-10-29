#include "TypeSchema.h"
#include "ContentHash.h"
#include "DiaTypeLayout.h"
#include "ExecutableImage.h"
#include "McpJson.h"
#include "PdbIdentity.h"
#include <filesystem>
#include <iostream>
#include <memory>
#include <winver.h>

#pragma comment(lib, "version.lib")
#pragma comment(lib, "diaguids.lib")

using Microsoft::WRL::ComPtr;

namespace
{
    class ArtifactLease
    {
    public:
        ~ArtifactLease()
        {
            if (File != INVALID_HANDLE_VALUE)
            {
                CloseHandle(File);
            }
        }
        ArtifactLease() = default;
        ArtifactLease(const ArtifactLease&) = delete;
        ArtifactLease& operator=(const ArtifactLease&) = delete;

        bool Open(const std::wstring& path, uint64_t maximum)
        {
            if (path.empty() || path.size() > 30000 || path.find(L'\0') != std::wstring::npos ||
                path.rfind(L"\\\\", 0) == 0 || path.rfind(L"\\??\\", 0) == 0)
            {
                return false;
            }
            std::error_code ec;
            const auto absolute = std::filesystem::absolute(path, ec).wstring();
            if (ec || absolute.size() < 3 || absolute[1] != L':' || absolute.size() > 30000 ||
                absolute.find(L':', 2) != std::wstring::npos)
            {
                return false;
            }
            File = CreateFileW(absolute.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
            FILE_ATTRIBUTE_TAG_INFO attributes{};
            LARGE_INTEGER size{};
            if (File == INVALID_HANDLE_VALUE || GetFileType(File) != FILE_TYPE_DISK ||
                !GetFileInformationByHandleEx(File, FileAttributeTagInfo, &attributes, sizeof(attributes)) ||
                (attributes.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0 ||
                !GetFileSizeEx(File, &size) || size.QuadPart <= 0 || static_cast<uint64_t>(size.QuadPart) > maximum ||
                !GetFileInformationByHandleEx(File, FileIdInfo, &Identity, sizeof(Identity)))
            {
                return false;
            }
            std::vector<wchar_t> finalPath(32768);
            const DWORD length = GetFinalPathNameByHandleW(File, finalPath.data(), static_cast<DWORD>(finalPath.size()), 0);
            if (length == 0 || length >= finalPath.size())
            {
                return false;
            }
            Path.assign(finalPath.data(), length);
            Size = static_cast<uint64_t>(size.QuadPart);
            return Hash(&Sha256);
        }

        bool Unchanged()
        {
            HANDLE reopened = CreateFileW(Path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
            FILE_ID_INFO current{};
            const bool same = reopened != INVALID_HANDLE_VALUE &&
                GetFileInformationByHandleEx(reopened, FileIdInfo, &current, sizeof(current)) &&
                std::memcmp(&current, &Identity, sizeof(current)) == 0;
            if (reopened != INVALID_HANDLE_VALUE)
            {
                CloseHandle(reopened);
            }
            std::wstring after;
            return same && Hash(&after) && after == Sha256;
        }

        std::wstring Path;
        std::wstring Sha256;

    private:
        bool Hash(std::wstring* hash)
        {
            LARGE_INTEGER zero{}, currentSize{};
            if (!SetFilePointerEx(File, zero, nullptr, FILE_BEGIN) || !GetFileSizeEx(File, &currentSize) ||
                static_cast<uint64_t>(currentSize.QuadPart) != Size)
            {
                return false;
            }
            ContentHash digest;
            std::vector<uint8_t> buffer(65536);
            uint64_t remaining = Size;
            const uint64_t deadline = GetTickCount64() + 30000;
            while (remaining != 0)
            {
                DWORD received = 0;
                const DWORD requested = static_cast<DWORD>((std::min)(remaining, static_cast<uint64_t>(buffer.size())));
                if (GetTickCount64() >= deadline || !ReadFile(File, buffer.data(), requested, &received, nullptr) ||
                    received != requested || !digest.Add(buffer.data(), received))
                {
                    return false;
                }
                remaining -= received;
            }
            *hash = digest.Finish();
            return !hash->empty();
        }
        HANDLE File = INVALID_HANDLE_VALUE;
        FILE_ID_INFO Identity{};
        uint64_t Size = 0;
    };

    class DiaProvider
    {
    public:
        ~DiaProvider()
        {
            Source.Reset();
            if (Module != nullptr)
            {
                FreeLibrary(Module);
            }
            if (Initialized)
            {
                CoUninitialize();
            }
        }
        bool Open(const std::wstring& path)
        {
            const HRESULT initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
            Initialized = SUCCEEDED(initialized);
            if (!Initialized && initialized != RPC_E_CHANGED_MODE)
            {
                return false;
            }
            Module = LoadLibraryExW(path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
            using GetFactory = HRESULT(WINAPI*)(REFCLSID, REFIID, void**);
            const auto getFactory = Module == nullptr ? nullptr : reinterpret_cast<GetFactory>(GetProcAddress(Module, "DllGetClassObject"));
            ComPtr<IClassFactory> factory;
            return getFactory != nullptr && getFactory(__uuidof(DiaSource), IID_PPV_ARGS(&factory)) == S_OK && factory &&
                factory->CreateInstance(nullptr, IID_PPV_ARGS(&Source)) == S_OK && Source;
        }
        ComPtr<IDiaDataSource> Source;
    private:
        HMODULE Module = nullptr;
        bool Initialized = false;
    };

    std::wstring FileVersion(const std::wstring& path)
    {
        DWORD ignored = 0;
        const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &ignored);
        if (size == 0 || size > 1024 * 1024)
        {
            return L"";
        }
        std::vector<uint8_t> bytes(size);
        VS_FIXEDFILEINFO* info = nullptr;
        UINT length = 0;
        if (!GetFileVersionInfoW(path.c_str(), 0, size, bytes.data()) ||
            !VerQueryValueW(bytes.data(), L"\\", reinterpret_cast<void**>(&info), &length) ||
            info == nullptr || length < sizeof(*info) || info->dwSignature != 0xfeef04bd)
        {
            return L"";
        }
        return std::to_wstring(HIWORD(info->dwFileVersionMS)) + L"." + std::to_wstring(LOWORD(info->dwFileVersionMS)) +
            L"." + std::to_wstring(HIWORD(info->dwFileVersionLS)) + L"." + std::to_wstring(LOWORD(info->dwFileVersionLS));
    }

    std::wstring GuidText(const GUID& guid)
    {
        wchar_t text[33]{};
        swprintf_s(text, L"%08lx%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x", guid.Data1, guid.Data2, guid.Data3,
            guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3], guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
        return text;
    }

    bool FindUnique(IDiaSymbol* parent, enum SymTagEnum tag, const std::wstring& name, IDiaSymbol** output)
    {
        ComPtr<IDiaEnumSymbols> values;
        ComPtr<IDiaSymbol> value;
        LONG count = 0;
        ULONG fetched = 0;
        if (parent == nullptr || parent->findChildren(tag, name.c_str(), nsCaseSensitive, &values) != S_OK || !values ||
            values->get_Count(&count) != S_OK || count != 1 || values->Next(1, &value, &fetched) != S_OK ||
            fetched != 1 || !value || dia_layout::Name(value.Get()) != name)
        {
            return false;
        }
        *output = value.Detach();
        return true;
    }

    bool Walk(IDiaSymbol* type, uint64_t offset, const std::vector<std::wstring>& path, TypeSchemaPackage* package,
        uint64_t deadline)
    {
        TypeLayoutInfo layout;
        if (GetTickCount64() >= deadline || !dia_layout::ReadLayout(type, &layout))
        {
            return false;
        }
        if (layout.UnavailableFields != 0)
        {
            package->Gaps.push_back({path, L"member_properties_unavailable"});
        }
        ComPtr<IDiaEnumSymbols> bases;
        LONG baseCount = 0;
        if (type->findChildren(SymTagBaseClass, nullptr, nsNone, &bases) != S_OK || !bases ||
            bases->get_Count(&baseCount) != S_OK || baseCount < 0 || baseCount != 0)
        {
            package->Gaps.push_back({path, L"base_classes_not_expanded"});
        }
        std::sort(layout.Fields.begin(), layout.Fields.end(), [](const auto& a, const auto& b)
        {
            return a.Name < b.Name;
        });
        for (const auto& member : layout.Fields)
        {
            if (package->Fields.size() == TypeSchemaMaxFields || package->Gaps.size() >= TypeSchemaMaxFields ||
                GetTickCount64() >= deadline)
            {
                return false;
            }
            TypeSchemaField field;
            field.Path = path;
            field.Path.push_back(member.Name);
            field.TypeName = member.TypeName.empty() ? L"<unnamed>" : member.TypeName;
            field.SymbolTag = member.ChildTag;
            field.BaseType = member.BaseType;
            field.Offset = offset + member.Offset;
            field.StorageBytes = member.StorageLength;
            field.BitPosition = member.BitPosition;
            field.BitWidth = member.IsBitField ? member.Length : 0;
            field.Expansion = TypeSchemaExpansion(member.ChildTag, field.Path.size());
            package->Fields.push_back(field);
            if (field.Expansion == L"embedded")
            {
                ComPtr<IDiaSymbol> data, nested;
                if (!FindUnique(type, SymTagData, member.Name, &data) || data->get_type(&nested) != S_OK || !nested ||
                    !Walk(nested.Get(), field.Offset, field.Path, package, deadline))
                {
                    return false;
                }
            }
            else if (field.Expansion == L"unavailable" || field.Expansion == L"depth_limit")
            {
                package->Gaps.push_back({field.Path, field.Expansion});
            }
        }
        return true;
    }
}

bool GenerateTypeSchema(const std::wstring& image, const std::wstring& pdb, const std::wstring& typeName,
    const std::wstring& providerPath, TypeSchemaPackage* package, std::wstring* error)
{
    if (error != nullptr)
    {
        *error = L"schema generation requires stable local AMD64 PE/PDB/provider files and one exact, bounded UDT";
    }
    if (package == nullptr || typeName.empty() || typeName.size() > 1024 ||
        typeName.find(L'\0') != std::wstring::npos || mcpjson::SanitizeUtf16(typeName) != typeName)
    {
        return false;
    }
    ArtifactLease imageFile, pdbFile, providerFile;
    if (!imageFile.Open(image, 512 * 1024 * 1024) || !pdbFile.Open(pdb, 1024ull * 1024 * 1024) ||
        !providerFile.Open(providerPath, 64 * 1024 * 1024))
    {
        return false;
    }
    executable_image::DiskPeMetadata metadata;
    if (!executable_image::ReadDiskPeMetadata(imageFile.Path, &metadata, nullptr) ||
        metadata.Machine != IMAGE_FILE_MACHINE_AMD64 || !metadata.HasPdbIdentity)
    {
        return false;
    }
    DiaProvider provider;
    ComPtr<IDiaSession> session;
    ComPtr<IDiaSymbol> global, type;
    if (!provider.Open(providerFile.Path) ||
        symbol_identity::LoadMatchingPdb(provider.Source.Get(), pdbFile.Path, {metadata.PdbGuid, 0, metadata.PdbAge}) != S_OK ||
        provider.Source->openSession(&session) != S_OK || !session || session->get_globalScope(&global) != S_OK || !global ||
        !FindUnique(global.Get(), SymTagUDT, typeName, &type))
    {
        return false;
    }
    TypeSchemaPackage p;
    p.ImageSha256 = imageFile.Sha256;
    p.PdbSha256 = pdbFile.Sha256;
    p.PdbGuid = GuidText(metadata.PdbGuid);
    p.PdbAge = metadata.PdbAge;
    p.ImageSize = metadata.SizeOfImage;
    p.Machine = metadata.Machine;
    p.ProviderSha256 = providerFile.Sha256;
    p.ProviderVersion = FileVersion(providerFile.Path);
    p.TypeName = typeName;
    if (type->get_length(&p.TypeBytes) != S_OK || !Walk(type.Get(), 0, {}, &p, GetTickCount64() + 30000) ||
        !imageFile.Unchanged() || !pdbFile.Unchanged() || !providerFile.Unchanged() || !ValidateTypeSchema(p, nullptr))
    {
        return false;
    }
    *package = std::move(p);
    if (error != nullptr)
    {
        error->clear();
    }
    return true;
}

int RunTypeSchemaCommand(int argc, wchar_t** argv)
{
    TypeSchemaPackage package;
    std::wstring error;
    bool success = false;
    try
    {
        if (argc == 7 && std::wstring(argv[2]) == L"create")
        {
            std::vector<wchar_t> executable(32768);
            const DWORD length = GetModuleFileNameW(nullptr, executable.data(), static_cast<DWORD>(executable.size()));
            if (length != 0 && length < executable.size())
            {
                const auto provider = std::filesystem::path(std::wstring(executable.data(), length)).parent_path() / L"msdia140.dll";
                success = GenerateTypeSchema(argv[3], argv[4], argv[5], provider.wstring(), &package, &error) &&
                    SaveTypeSchema(argv[6], package, &error);
            }
        }
        else if (argc == 4 && std::wstring(argv[2]) == L"inspect")
        {
            success = LoadTypeSchema(argv[3], &package, &error);
        }
        else
        {
            error = L"usage: --schema create <image> <pdb> <exact-type> <new-output> | --schema inspect <package>";
        }
    }
    catch (const std::exception&)
    {
        error = L"schema operation failed while materializing bounded metadata";
    }
    if (!success)
    {
        std::wcerr << (error.empty() ? L"schema operation failed" : error) << L"\n";
        return 1;
    }
    std::wcout << TypeSchemaJson(package) << L"\n";
    return 0;
}
