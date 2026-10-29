#pragma once

#include <Windows.h>
#include <DbgHelp.h>
#include <dia2.h>
#include <cstring>
#include <string>

namespace symbol_identity
{
    struct PdbIdentity
    {
        GUID Guid{};
        DWORD Signature = 0;
        DWORD Age = 0;

        bool HasGuid() const
        {
            const GUID empty{};
            return std::memcmp(&Guid, &empty, sizeof(Guid)) != 0;
        }

        bool Valid() const
        {
            return Age != 0 && (HasGuid() || Signature != 0);
        }

        bool Matches(const PdbIdentity& other) const
        {
            return Valid() && other.Valid() && Age == other.Age && HasGuid() == other.HasGuid() &&
                (HasGuid() ? std::memcmp(&Guid, &other.Guid, sizeof(Guid)) == 0 : Signature == other.Signature);
        }
    };

    inline PdbIdentity FromMatchedModule(const IMAGEHLP_MODULEW64& module)
    {
        PdbIdentity identity;
        if ((module.SymType == SymPdb || module.SymType == SymDia || module.SymType == SymCv) &&
            !module.PdbUnmatched && !module.DbgUnmatched)
        {
            identity.Guid = module.PdbSig70;
            identity.Signature = module.PdbSig;
            identity.Age = module.PdbAge;
        }
        return identity;
    }

    inline bool ModuleRecordMatches(const IMAGEHLP_MODULEW64& module, uint64_t base, uint32_t size)
    {
        return base != 0 && module.BaseOfImage == base && !module.PdbUnmatched && !module.DbgUnmatched &&
            (module.ImageSize == 0 || size == 0 || module.ImageSize == size);
    }

    inline bool VerifyDiaIdentity(IDiaDataSource* source, const PdbIdentity& expected)
    {
        bool matched = false;
        IDiaSession* session = nullptr;
        IDiaSymbol* global = nullptr;
        do
        {
            if (source == nullptr || !expected.Valid() || source->openSession(&session) != S_OK || session == nullptr ||
                session->get_globalScope(&global) != S_OK || global == nullptr)
            {
                break;
            }
            PdbIdentity actual;
            if (global->get_age(&actual.Age) != S_OK)
            {
                break;
            }
            if (expected.HasGuid())
            {
                if (global->get_guid(&actual.Guid) != S_OK)
                {
                    break;
                }
            }
            else if (global->get_signature(&actual.Signature) != S_OK)
            {
                break;
            }
            matched = expected.Matches(actual);
        }
        while (false);
        if (global != nullptr)
        {
            global->Release();
        }
        if (session != nullptr)
        {
            session->Release();
        }
        return matched;
    }

    inline HRESULT LoadMatchingPdb(IDiaDataSource* source, const std::wstring& path, const PdbIdentity& expected)
    {
        if (source == nullptr || !expected.Valid() || path.empty() || path.size() > 30000 ||
            path.find(L'\0') != std::wstring::npos)
        {
            return E_INVALIDARG;
        }
        GUID guid = expected.Guid;
        const HRESULT loaded = source->loadAndValidateDataFromPdb(path.c_str(),
            expected.HasGuid() ? &guid : nullptr, expected.Signature, expected.Age);
        if (loaded != S_OK)
        {
            return FAILED(loaded) ? loaded : E_FAIL;
        }
        return VerifyDiaIdentity(source, expected) ? S_OK : HRESULT_FROM_WIN32(ERROR_REVISION_MISMATCH);
    }
}
