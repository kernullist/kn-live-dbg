#pragma once

#include <cstdint>
#include <string>

#include "SymbolEngine.h"

// Shared PDB-first structure-field offset resolution with a guarded fallback.
//
// Scanners that walk kernel structures should prefer PDB/DIA-resolved field
// offsets and only fall back to a known-good hard-coded offset when the type
// or field is absent from the loaded symbols (common for internal,
// undocumented structures). This helper centralizes that pattern and records
// which source was used so a scanner can surface a warning whenever it runs on
// a fallback layout, instead of silently trusting offsets that may drift
// across Windows builds.

struct ResolvedFieldOffset
{
    uint32_t Offset = 0;
    bool FromPdb = false;
    bool UsedFallback = false;
};

// Resolve <typeName>.<fieldName> through the symbol engine, falling back to
// fallbackOffset when the symbols do not expose the field. typeName accepts the
// "nt!" alias spelling understood by SymbolEngine::FindField and supports the
// nested "Pcb.Field" path form.
inline ResolvedFieldOffset ResolveFieldOffset(
    SymbolEngine& symbols,
    const std::wstring& typeName,
    const std::wstring& fieldName,
    uint32_t fallbackOffset)
{
    ResolvedFieldOffset result = {};
    result.Offset = fallbackOffset;
    result.UsedFallback = true;
    result.FromPdb = false;

    do
    {
        TypeFieldInfo field = {};
        std::wstring ignored;
        if (!symbols.FindField(typeName, fieldName, &field, &ignored))
        {
            break;
        }

        result.Offset = field.Offset;
        result.FromPdb = true;
        result.UsedFallback = false;
    } while (false);

    return result;
}
