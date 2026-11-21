#pragma once

#include "../user/EtlReferenceImage.h"

namespace etl_reference_test
{
    // Known reference data in an executable section of this test's own PE.
    // It is never invoked as code.
#pragma section(".knref", read, execute)
    __declspec(allocate(".knref")) inline const char FileMarker[] = "KnLiveDbg owned ETL reference sample bytes.";

    inline bool CheckOwnedFile(const wchar_t* path)
    {
        using namespace etl_profile;
        ReferenceImage reference;
        if (!reference.file.Open(path, 64ull << 20) ||
            !executable_image::ReadDiskPeIdentityHandle(reference.file.Handle(), &reference.pe, nullptr)) { return false; }
        reference.leaf = std::filesystem::path(reference.file.Path).filename().wstring();
        ImageEvent source{};
        source.base = reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr));
        source.size = reference.pe.SizeOfImage;
        source.stamp = reference.pe.TimeDateStamp;
        source.checksum = reference.pe.CheckSum;
        source.preferred = reference.pe.ImageBase;
        const auto marker = reinterpret_cast<uintptr_t>(FileMarker);
        if (marker < source.base) { return false; }
        const auto sample = CompareReference(reference, &source, reference.leaf, marker - source.base);
        return sample.length == MaxReferenceWindow && ReferenceWindowHash(reference, sample) ==
            L"55d259a35c7037ed0fc6f70f47a108adba2773013baa1c5c136d4d25381bafee" && reference.file.Unchanged();
    }

    inline bool Check()
    {
        using namespace etl_profile;
        ReferenceImage reference;
        reference.leaf = L"Owned\u00d6.dll";
        auto& pe = reference.pe;
        pe.SizeOfImage = 0x5000;
        pe.SizeOfHeaders = 0x400;
        pe.TimeDateStamp = 42;
        pe.CheckSum = 86;
        pe.ImageBase = 0x100000;
        executable_image::DiskPeSection text;
        text.Executable = true;
        text.VirtualAddress = 0x1000;
        text.VirtualSize = 60;
        text.PointerToRawData = 0x400;
        text.SizeOfRawData = 64;
        pe.Sections.push_back(text);
        auto data = text;
        data.VirtualAddress = 0x3000;
        data.Executable = false;
        pe.Sections.push_back(data);

        ImageEvent record{};
        record.size = pe.SizeOfImage;
        record.stamp = pe.TimeDateStamp;
        record.checksum = pe.CheckSum;
        record.base = 0x200000;
        record.preferred = record.base;
        constexpr std::wstring_view name = L"ignored/ordinary\\owned\u00f6.DLL";
        auto at = [&](uint64_t rva) { return CompareReference(reference, &record, name, rva); };
        auto is = [](const wchar_t* got, const wchar_t* expected) { return std::wstring_view(got) == expected; };
        auto first = at(0x1000);
        if (!is(first.relation, L"recorded_fields_agree") || !is(first.defaultBase, L"recorded_load") ||
            first.offset != 0x400 || first.length != MaxReferenceWindow || at(0x103b).length != 1 ||
            !is(at(0x103c).location, L"outside_file_backed_extent") || !is(at(0x1040).location, L"section_gap") ||
            !is(at(0x3000).location, L"nonexecutable_section") || !is(at(0).location, L"pe_headers") ||
            !is(at(UINT64_MAX).location, L"outside_image") ||
            !is(CompareReference(reference, nullptr, name, 0x1000).relation, L"process_image_unavailable")) { return false; }
        pe.Sections[0].VirtualSize = 100;
        if (at(0x103f).length != 1 || !is(at(0x1040).location, L"outside_file_backed_extent")) { return false; }
        pe.Sections[0].VirtualSize = 0;
        if (at(0x1000).length) { return false; }
        pe.Sections[0].VirtualSize = 60;
        for (auto other : {L"", L"dir\\", L"Other.dll", L"Owned\u00d6.dll:alternate"})
        {
            auto candidate = CompareReference(reference, &record, other, 0x1000);
            if (candidate.name != FieldComparison::Different || candidate.length) { return false; }
        }
        ++record.size;
        if (at(0x1000).size != FieldComparison::Different || at(0x1000).length) { return false; }
        --record.size;
        ++record.stamp;
        if (at(0x1000).stamp != FieldComparison::Different || at(0x1000).length) { return false; }
        record.stamp = UINT32_MAX;
        if (at(0x1000).stamp != FieldComparison::Unavailable || !at(0x1000).length) { return false; }
        ++record.checksum;
        if (at(0x1000).checksum != FieldComparison::Different || at(0x1000).length) { return false; }
        record.checksum = 0;
        for (uint32_t stamp : {0u, UINT32_MAX})
        {
            record.stamp = stamp;
            auto unknown = at(0x1000);
            if (unknown.length || !is(unknown.relation, L"build_fields_unavailable")) { return false; }
        }
        record.stamp = pe.TimeDateStamp;
        record.preferred = 0;
        if (at(0x1000).checksum != FieldComparison::Unavailable || !is(at(0x1000).defaultBase, L"unavailable") ||
            !at(0x1000).length) { return false; }
        record.preferred = pe.ImageBase;
        if (!is(at(0x1000).defaultBase, L"file_preferred") || !at(0x1000).length) { return false; }
        record.base = pe.ImageBase;
        if (!is(at(0x1000).defaultBase, L"file_preferred_and_recorded_load")) { return false; }
        ++record.preferred;
        const auto unresolved = at(0x1000);
        return is(unresolved.defaultBase, L"unexplained") && is(unresolved.relation, L"default_base_unresolved") && !unresolved.length;
    }
}
