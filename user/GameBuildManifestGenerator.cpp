#include "GameBuildManifest.h"
#include "ArtifactOutput.h"
#include "ContentHash.h"
#include "DiaTypeLayout.h"
#include "McpJson.h"
#include "ReferenceArtifact.h"

#include <dia2.h>
#include <wrl/client.h>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <memory>
#include <sstream>

using Microsoft::WRL::ComPtr;

namespace
{
    class PdbReader
    {
    public:
        PdbReader()
        {
            Initialized = SUCCEEDED(CoInitializeEx(nullptr, COINIT_MULTITHREADED));
        }

        ~PdbReader()
        {
            Session.Reset();
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

        bool Open(const std::wstring& path, const executable_image::DiskPeMetadata& image)
        {
            HRESULT hr = CoCreateInstance(CLSID_DiaSource, nullptr, CLSCTX_INPROC_SERVER,
                __uuidof(IDiaDataSource), reinterpret_cast<void**>(Source.GetAddressOf()));
            if (FAILED(hr))
            {
                wchar_t executable[32768] = {};
                GetModuleFileNameW(nullptr, executable, 32768);
                const auto dll = std::filesystem::path(executable).parent_path() / L"msdia140.dll";
                Module = LoadLibraryExW(dll.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH);
                if (Module == nullptr)
                {
                    return false;
                }
                using FactoryFunction = HRESULT (STDAPICALLTYPE*)(REFCLSID, REFIID, void**);
                auto create = reinterpret_cast<FactoryFunction>(GetProcAddress(Module, "DllGetClassObject"));
                ComPtr<IClassFactory> factory;
                if (create == nullptr || FAILED(create(CLSID_DiaSource, IID_IClassFactory,
                    reinterpret_cast<void**>(factory.GetAddressOf()))) ||
                    FAILED(factory->CreateInstance(nullptr, __uuidof(IDiaDataSource), reinterpret_cast<void**>(Source.GetAddressOf()))))
                {
                    return false;
                }
            }
            ComPtr<IDiaSymbol> global;
            GUID guid = {};
            DWORD age = 0;
            return Source != nullptr && SUCCEEDED(Source->loadDataFromPdb(path.c_str())) &&
                SUCCEEDED(Source->openSession(Session.GetAddressOf())) &&
                SUCCEEDED(Session->get_globalScope(global.GetAddressOf())) &&
                SUCCEEDED(global->get_guid(&guid)) && SUCCEEDED(global->get_age(&age)) &&
                image.HasPdbIdentity && std::memcmp(&guid, &image.PdbGuid, sizeof(guid)) == 0 && age == image.PdbAge;
        }

        ComPtr<IDiaSymbol> DataType(uint32_t rva, bool indirect)
        {
            ComPtr<IDiaSymbol> symbol, type;
            DWORD actual = 0;
            if (Session->findSymbolByRVA(rva, SymTagData, &symbol) != S_OK || !symbol ||
                symbol->get_relativeVirtualAddress(&actual) != S_OK || actual != rva ||
                symbol->get_type(&type) != S_OK || !type) { return {}; }
            if (indirect)
            {
                DWORD tag = 0;
                ComPtr<IDiaSymbol> pointee;
                if (type->get_symTag(&tag) != S_OK || tag != SymTagPointerType ||
                    type->get_type(&pointee) != S_OK) { return {}; }
                return pointee;
            }
            return type;
        }

        bool ObjectType(const GameObjectRule& rule)
        {
            auto type = DataType(rule.RootRva, rule.Indirect);
            ULONGLONG length = 0;
            return type && type->get_length(&length) == S_OK && length == rule.Size;
        }

        bool LifetimeSlot(uint32_t rva)
        {
            auto type = DataType(rva, false);
            TypeLayoutInfo layout;
            if (!type || !dia_layout::ReadLayout(type.Get(), &layout) || !layout.FieldsComplete ||
                layout.Name != L"KnGameObjectSlotV1" || layout.Size != sizeof(KnGameObjectSlotV1) || layout.Fields.size() != 5)
            { return false; }
            const wchar_t* names[] = {L"Sequence", L"Generation", L"ContainerId", L"MemberAddress", L"Phase"};
            for (size_t i = 0; i < std::size(names); ++i)
            {
                const auto member = std::find_if(layout.Fields.begin(), layout.Fields.end(), [&](const auto& f) { return f.Name == names[i]; });
                if (member == layout.Fields.end() || member->IsBitField || member->Offset != i * 8 ||
                    member->Length != 8 || member->ChildTag != SymTagBaseType || member->BaseType != btUInt) { return false; }
            }
            return true;
        }

        bool Subobject(const GameObjectRule& object, GameVptrRule& rule)
        {
            auto type = DataType(object.RootRva, object.Indirect);
            DWORD tag = 0;
            if (!type || type->get_symTag(&tag) != S_OK || tag != SymTagUDT) { return false; }
            const auto owner = dia_layout::Name(type.Get());
            if (owner.empty() || !Vtable(rule.TableRva, owner, rule.SubobjectType)) { return false; }
            if (!rule.Offset && owner == rule.SubobjectType)
            {
                rule.SubobjectSize = object.Size;
                return true;
            }
            ComPtr<IDiaEnumSymbols> bases;
            LONG count = 0;
            if (type->findChildren(SymTagBaseClass, nullptr, nsNone, &bases) != S_OK || !bases ||
                bases->get_Count(&count) != S_OK || count < 1 || count > 256) { return false; }
            for (LONG i = 0; i < count; ++i)
            {
                ComPtr<IDiaSymbol> base, baseType;
                ULONG fetched = 0;
                if (bases->Next(1, &base, &fetched) != S_OK || fetched != 1 || !base ||
                    base->get_type(&baseType) != S_OK || !baseType) { return false; }
                if (dia_layout::Name(baseType.Get()) != rule.SubobjectType) { continue; }
                BOOL isVirtual = FALSE, indirect = FALSE;
                LONG offset = -1;
                ULONGLONG length = 0;
                if (base->get_virtualBaseClass(&isVirtual) != S_OK || isVirtual ||
                    base->get_indirectVirtualBaseClass(&indirect) != S_OK || indirect ||
                    base->get_offset(&offset) != S_OK || offset < 0 || static_cast<uint32_t>(offset) != rule.Offset ||
                    baseType->get_length(&length) != S_OK || length < 8 || rule.Offset > object.Size || length > object.Size - rule.Offset ||
                    rule.SubobjectSize) { return false; }
                rule.SubobjectSize = static_cast<uint32_t>(length);
            }
            return rule.SubobjectSize != 0;
        }

        bool Vtable(uint32_t rva, const std::wstring& owner = {}, const std::wstring& subobject = {})
        {
            ComPtr<IDiaSymbol> symbol;
            DWORD actual = 0;
            BSTR name = nullptr;
            bool result = false;
            if (SUCCEEDED(Session->findSymbolByRVA(rva, SymTagPublicSymbol, symbol.GetAddressOf())) && symbol != nullptr &&
                SUCCEEDED(symbol->get_relativeVirtualAddress(&actual)) && actual == rva && SUCCEEDED(symbol->get_name(&name)) && name != nullptr)
            {
                const std::wstring text(name, SysStringLen(name));
                result = text.find(L"??_7") == 0 || text.find(L"vftable") != std::wstring::npos;
            }
            SysFreeString(name);
            if (!result || owner.empty()) { return result; }
            BSTR full = nullptr;
            result = symbol->get_undecoratedName(&full) == S_OK && full && SysStringLen(full) <= 2048;
            if (result)
            {
                std::wstring text(full, SysStringLen(full));
                if (text.rfind(L"const ", 0) == 0) { text.erase(0, 6); }
                const auto table = owner + L"::`vftable'";
                result = (owner == subobject && text == table) || text == table + L"{for `" + subobject + L"'}";
            }
            SysFreeString(full);
            return result;
        }

        bool Function(uint32_t target, ObservationRange* range)
        {
            ComPtr<IDiaSymbol> symbol;
            DWORD rva = 0;
            ULONGLONG length = 0;
            if (FAILED(Session->findSymbolByRVA(target, SymTagFunction, symbol.GetAddressOf())) || symbol == nullptr ||
                FAILED(symbol->get_relativeVirtualAddress(&rva)) || FAILED(symbol->get_length(&length)) ||
                length == 0 || target < rva || target - rva >= length)
            {
                return false;
            }
            *range = {rva, length};
            return true;
        }

    private:
        bool Initialized = false;
        HMODULE Module = nullptr;
        ComPtr<IDiaDataSource> Source;
        ComPtr<IDiaSession> Session;
    };
}

bool GenerateGameManifest(const std::wstring& image, const std::wstring& pdb,
    const std::wstring& layout, const std::wstring& output, std::wstring* error)
{
    bool ok = false;
    if (error != nullptr)
    {
        *error = L"manifest generation failed; exact private PDB/type/vftable/function information is required";
    }
    do
    {
        HANDLE imageFile = CreateFileW(image.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        const std::unique_ptr<void, decltype(&CloseHandle)> imageLease(
            imageFile == INVALID_HANDLE_VALUE ? nullptr : imageFile, &CloseHandle);
        HANDLE pdbFile = CreateFileW(pdb.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        const std::unique_ptr<void, decltype(&CloseHandle)> pdbLease(
            pdbFile == INVALID_HANDLE_VALUE ? nullptr : pdbFile, &CloseHandle);
        if (!imageLease || !pdbLease)
        {
            if (error != nullptr)
            {
                *error = L"image/PDB read lease failed; inputs must remain stable during manifest generation";
            }
            break;
        }
        executable_image::DiskPeMetadata metadata;
        if (!executable_image::ReadDiskPeMetadata(image, &metadata, error) || !metadata.HasPdbIdentity ||
            !metadata.BaseRelocationTableComplete || !metadata.DynamicRelocationTableComplete ||
            metadata.Machine != IMAGE_FILE_MACHINE_AMD64)
        {
            break;
        }
        PdbReader reader;
        if (!reader.Open(pdb, metadata))
        {
            if (error != nullptr)
            {
                *error = L"DIA could not load the PDB or its GUID/age differs from the image";
            }
            break;
        }
        GameBuildManifest manifest;
        manifest.ImageSha256 = ContentHash::File(image);
        manifest.PdbSha256 = ContentHash::File(pdb);
        manifest.PdbGuid = metadata.PdbGuid;
        manifest.PdbAge = metadata.PdbAge;
        manifest.ImageSize = metadata.SizeOfImage;
        manifest.Machine = metadata.Machine;
        manifest.Relocations = metadata.BaseRelocations;
        for (const auto& section : metadata.Sections)
        {
            if (section.Executable)
            {
                manifest.ExecutableRanges.push_back({section.VirtualAddress, (std::max)(section.VirtualSize, section.SizeOfRawData)});
            }
        }
        bool layoutOk = true;
        if (layout != L"-")
        {
            std::string bytes;
            if (!ReadGameManifestInput(layout, 1024 * 1024, bytes)) { break; }
            std::wistringstream lines(mcpjson::Utf8ToWide(bytes));
            std::wstring line;
            while (std::getline(lines, line))
            {
                if (line.empty() || line[0] == L'#')
                {
                    continue;
                }
                std::wistringstream in(line);
                std::wstring kind;
                in >> kind >> std::hex;
                if (kind == L"object")
                {
                    GameObjectRule object;
                    if (!(in >> object.Name >> object.RootRva >> object.Size >> object.Indirect) ||
                        manifest.Objects.size() >= 256 || !reader.ObjectType(object))
                    {
                        layoutOk = false;
                        break;
                    }
                    manifest.Objects.push_back(std::move(object));
                }
                else if (kind == L"lifetime")
                {
                    std::wstring objectName;
                    GameObjectLifetimeRule slot;
                    if (!(in >> objectName >> slot.SlotRva >> slot.ContainerId)) { layoutOk = false; break; }
                    auto object = std::find_if(manifest.Objects.begin(), manifest.Objects.end(), [&](const auto& item) { return item.Name == objectName; });
                    if (object == manifest.Objects.end() || object->Lifetime || !reader.LifetimeSlot(slot.SlotRva)) { layoutOk = false; break; }
                    object->Lifetime = slot;
                }
                else if (kind == L"vptr")
                {
                    std::wstring objectName;
                    GameVptrRule rule;
                    size_t slots = 0;
                    if (!(in >> objectName >> rule.Offset >> rule.TableRva >> slots) || slots == 0 || slots > 1024 ||
                        manifest.Vptrs.size() >= 1024)
                    {
                        layoutOk = false;
                        break;
                    }
                    const auto object = std::find_if(manifest.Objects.begin(), manifest.Objects.end(), [&](const auto& item)
                    {
                        return item.Name == objectName;
                    });
                    if (object == manifest.Objects.end())
                    {
                        layoutOk = false;
                        break;
                    }
                    rule.ObjectIndex = static_cast<uint32_t>(object - manifest.Objects.begin());
                    in >> std::ws;
                    const bool tableMatches = in.eof() ? reader.Vtable(rule.TableRva) :
                        ((in >> rule.SubobjectType) && reader.Subobject(*object, rule));
                    if (!tableMatches) { layoutOk = false; break; }
                    for (size_t slot = 0; slot < slots; ++slot)
                    {
                        const uint64_t rva = static_cast<uint64_t>(rule.TableRva) + slot * 8;
                        std::vector<uint8_t> page;
                        uint64_t target = 0;
                        ObservationRange function;
                        if (rva >= metadata.SizeOfImage || (rva & 4095) > 4088 ||
                            !executable_image::ReadDiskPageForRva(image, metadata, static_cast<uint32_t>(rva) & ~4095u, &page, error) ||
                            page.size() < (rva & 4095) + 8)
                        {
                            layoutOk = false;
                            break;
                        }
                        std::memcpy(&target, page.data() + (rva & 4095), 8);
                        if (target < metadata.ImageBase || target - metadata.ImageBase >= metadata.SizeOfImage ||
                            !reader.Function(static_cast<uint32_t>(target - metadata.ImageBase), &function))
                        {
                            layoutOk = false;
                            break;
                        }
                        rule.AllowedSlots.push_back(function);
                    }
                    manifest.Vptrs.push_back(std::move(rule));
                }
                else
                {
                    layoutOk = false;
                    break;
                }
                in >> std::ws;
                if (!in.eof())
                {
                    layoutOk = false;
                    break;
                }
            }
        }
        if (!layoutOk || !ValidateGameManifest(manifest, error) || !MatchGameManifest(manifest, image, metadata, error))
        {
            break;
        }
        const std::string serialized = mcpjson::WideToUtf8(SerializeGameManifest(manifest));
        std::error_code ec;
        const auto destination = std::filesystem::absolute(output, ec);
        ok = !ec && PublishNewArtifactAt(destination.wstring(), reinterpret_cast<const uint8_t*>(serialized.data()), serialized.size());
        if (error) { *error = ok ? L"" : L"could not publish a new manifest at the requested path"; }
    } while (false);
    return ok;
}

int RunGameManifestCommand(int argc, wchar_t** argv)
{
    bool ok = false;
    std::wstring error;
    const std::wstring verb = argc > 2 ? argv[2] : L"";
    const bool create = argc == 7 && verb == L"create";
    const bool verify = argc == 5 && verb == L"verify";
    const bool selfTest = argc == 3 && verb == L"self-test";
    const auto sink = GetStdHandle(create || verify || selfTest ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
    std::vector<DistinctArtifactInput> guards;
    if (argc > 3 && GetFileType(sink) == FILE_TYPE_DISK)
    {
        guards.resize(static_cast<size_t>(argc - 3));
        for (int i = 3; i < argc; ++i)
        {
            if (verb == L"create" && i == 5 && std::wstring(argv[i]) == L"-") { continue; }
            if (!guards[i - 3].Hold(sink, argv[i])) { return 2; }
        }
    }
    if (create)
    {
        ok = GenerateGameManifest(argv[3], argv[4], argv[5], argv[6], &error);
    }
    else if (verify)
    {
        GameBuildManifest manifest;
        executable_image::DiskPeMetadata metadata;
        ok = ReadGameManifest(argv[3], &manifest, &error) &&
            executable_image::ReadDiskPeMetadata(argv[4], &metadata, &error) && MatchGameManifest(manifest, argv[4], metadata, &error);
    }
    else if (selfTest)
    {
        ok = GameBuildManifestSelfTest() && KmonGameObjectPublicationSelfTest(error);
    }
    else
    {
        std::wcerr << L"usage: --game-manifest create <image> <pdb> <layout-or-dash> <new-output>\n"
            << L"       --game-manifest verify <manifest> <image>\n"
            << L"       --game-manifest self-test\n";
        return 2;
    }
    std::wcout << L"[game-manifest] " << (ok ? L"PASS" : L"FAIL") << L' ' << error << L'\n';
    std::wcout.flush();
    return std::wcout ? (ok ? 0 : 1) : 2;
}
