#pragma once

#include "SchemaArtifact.h"
#include "SchemaReadStream.h"
#include "ExecutableImage.h"
#include "PdbIdentity.h"
#include <wrl/client.h>

// Worker-only DIA session over already approved, read-only artifact handles.
class DiaArtifactSession
{
public:
    ~DiaArtifactSession()
    {
        Global.Reset(); Session.Reset(); Source.Reset(); Stream.Reset();
        if (Module != nullptr) { FreeLibrary(Module); }
        if (Initialized) { CoUninitialize(); }
    }
    bool Open(HANDLE image, HANDLE pdb, HANDLE provider)
    {
        if (!Image.OpenHandle(image, 512ull * 1024 * 1024) || !Pdb.OpenHandle(pdb, 1024ull * 1024 * 1024) ||
            !Provider.OpenHandle(provider, 64ull * 1024 * 1024) || !Provider.PinPath() ||
            !executable_image::ReadDiskPeIdentityHandle(Image.Handle(), &Metadata, nullptr) || !Metadata.HasPdbIdentity ||
            Metadata.Machine != IMAGE_FILE_MACHINE_AMD64) { return false; }
        const auto initialized = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        Initialized = SUCCEEDED(initialized);
        if (!Initialized && initialized != RPC_E_CHANGED_MODE) { return false; }
        Module = LoadLibraryExW(Provider.Path.c_str(), nullptr, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
        using Factory = HRESULT(WINAPI*)(REFCLSID, REFIID, void**);
        const auto factory = Module == nullptr ? nullptr : reinterpret_cast<Factory>(GetProcAddress(Module, "DllGetClassObject"));
        Microsoft::WRL::ComPtr<IClassFactory> creator;
        return factory != nullptr && factory(__uuidof(DiaSource), IID_PPV_ARGS(&creator)) == S_OK && creator &&
            creator->CreateInstance(nullptr, IID_PPV_ARGS(&Source)) == S_OK && Source &&
            SchemaReadStream::Create(Pdb.Handle(), &Stream) == S_OK && Stream && Source->loadDataFromIStream(Stream.Get()) == S_OK &&
            symbol_identity::VerifyDiaIdentity(Source.Get(), {Metadata.PdbGuid, 0, Metadata.PdbAge}) &&
            Source->openSession(&Session) == S_OK && Session && Session->get_globalScope(&Global) == S_OK && Global;
    }
    bool Unchanged() { return Image.Unchanged() && Pdb.Unchanged() && Provider.Unchanged(); }
    SchemaArtifact Image, Pdb, Provider;
    executable_image::DiskPeMetadata Metadata;
    Microsoft::WRL::ComPtr<IDiaSession> Session;
    Microsoft::WRL::ComPtr<IDiaSymbol> Global;
private:
    HMODULE Module = nullptr;
    bool Initialized = false;
    Microsoft::WRL::ComPtr<IDiaDataSource> Source;
    Microsoft::WRL::ComPtr<IStream> Stream;
};
