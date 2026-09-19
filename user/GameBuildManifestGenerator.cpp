#include "GameBuildManifest.h"
#include "ContentHash.h"
#include "McpJson.h"

#include <dia2.h>
#include <wrl/client.h>
#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
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

        bool ObjectType(const GameObjectRule& rule)
        {
            ComPtr<IDiaSymbol> symbol;
            ComPtr<IDiaSymbol> type;
            DWORD rva = 0;
            if (FAILED(Session->findSymbolByRVA(rule.RootRva, SymTagData, symbol.GetAddressOf())) || symbol == nullptr ||
                FAILED(symbol->get_relativeVirtualAddress(&rva)) || rva != rule.RootRva ||
                FAILED(symbol->get_type(type.GetAddressOf())) || type == nullptr)
            {
                return false;
            }
            if (rule.Indirect)
            {
                DWORD tag = 0;
                ComPtr<IDiaSymbol> pointee;
                if (FAILED(type->get_symTag(&tag)) || tag != SymTagPointerType ||
                    FAILED(type->get_type(pointee.GetAddressOf())) || pointee == nullptr)
                {
                    return false;
                }
                type = std::move(pointee);
            }
            ULONGLONG length = 0;
            return SUCCEEDED(type->get_length(&length)) && length == rule.Size;
        }

        bool Vtable(uint32_t rva)
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
            std::ifstream input(std::filesystem::path(layout), std::ios::binary | std::ios::ate);
            if (!input || input.tellg() > 1024 * 1024 || input.tellg() <= 0)
            {
                break;
            }
            std::string bytes(static_cast<size_t>(input.tellg()), '\0');
            input.seekg(0);
            input.read(bytes.data(), bytes.size());
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
                else if (kind == L"vptr")
                {
                    std::wstring objectName;
                    GameVptrRule rule;
                    size_t slots = 0;
                    if (!(in >> objectName >> rule.Offset >> rule.TableRva >> slots) || slots == 0 || slots > 1024 ||
                        manifest.Vptrs.size() >= 1024 || !reader.Vtable(rule.TableRva))
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
        HANDLE file = CreateFileW(output.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (file == INVALID_HANDLE_VALUE)
        {
            if (error != nullptr)
            {
                *error = L"output already exists or could not be created";
            }
            break;
        }
        DWORD written = 0;
        ok = WriteFile(file, serialized.data(), static_cast<DWORD>(serialized.size()), &written, nullptr) && written == serialized.size() &&
            FlushFileBuffers(file);
        CloseHandle(file);
        if (!ok)
        {
            DeleteFileW(output.c_str());
        }
    } while (false);
    return ok;
}

int RunGameManifestCommand(int argc, wchar_t** argv)
{
    bool ok = false;
    std::wstring error;
    if (argc == 7 && std::wstring(argv[2]) == L"create")
    {
        ok = GenerateGameManifest(argv[3], argv[4], argv[5], argv[6], &error);
    }
    else if (argc == 5 && std::wstring(argv[2]) == L"verify")
    {
        GameBuildManifest manifest;
        executable_image::DiskPeMetadata metadata;
        ok = ReadGameManifest(argv[3], &manifest, &error) &&
            executable_image::ReadDiskPeMetadata(argv[4], &metadata, &error) && MatchGameManifest(manifest, argv[4], metadata, &error);
    }
    else if (argc == 3 && std::wstring(argv[2]) == L"self-test")
    {
        ok = GameBuildManifestSelfTest();
    }
    else
    {
        std::wcerr << L"usage: --game-manifest create <image> <pdb> <layout-or-dash> <new-output>\n"
            << L"       --game-manifest verify <manifest> <image>\n"
            << L"       --game-manifest self-test\n";
        return 2;
    }
    std::wcout << L"[game-manifest] " << (ok ? L"PASS" : L"FAIL") << L' ' << error << L'\n';
    return ok ? 0 : 1;
}
