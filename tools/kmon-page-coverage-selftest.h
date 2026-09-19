#pragma once

#include "../user/UserExecutablePteWalker.h"
#include "../user/ExecutableImagePermissions.h"
#include "../user/KmonHunting.h"
#include <map>
#include <set>
#include <iostream>

inline bool KmonPageCoverageSelfTest()
{
    unsigned passed = 0;
    unsigned failed = 0;
    const auto check = [&](bool ok, const char* name)
    {
        if (ok)
        {
            ++passed;
        }
        else
        {
            ++failed;
            std::cerr << "[kmon.pages] FAIL " << name << "\n";
        }
    };
    std::map<uint64_t, std::vector<uint8_t>> tables;
    const auto put = [&](uint64_t table, size_t slot, uint64_t value)
    {
        auto& page = tables[table];
        page.resize(4096);
        std::memcpy(page.data() + slot * 8, &value, 8);
    };
    put(0x1000, 0, 0x2007);
    put(0x2000, 0, 0x3007);
    for (uint64_t i = 0; i < 12; ++i)
    {
        put(0x3000, static_cast<size_t>(i), 0x4007 + i * 4096);
        put(0x4000 + i * 4096, 16, 0x20000007 + i * 4096);
    }
    const UserPteTableReader reader = [&](uint64_t physical, std::vector<uint8_t>* bytes)
    {
        const auto row = tables.find(physical);
        if (row == tables.end())
        {
            return false;
        }
        *bytes = row->second;
        return true;
    };
    std::set<uint64_t> seen;
    uint64_t resume = 0;
    unsigned passes = 0;
    unsigned duplicates = 0;
    UserPteWalkResult result;
    do
    {
        result = WalkUserPtes(0x1000, 4, resume, 5, true, reader, [&](const UserPteLeaf& leaf)
        {
            if (!seen.insert(leaf.Address).second)
            {
                ++duplicates;
            }
            return true;
        });
        check(result.TablesAttempted <= 5 && result.ReadFailures == 0, "bounded table pass");
        resume = result.ResumeAddress;
        ++passes;
    } while (!result.Finished && passes < 20);
    check(result.Finished && passes == 6 && seen.size() == 12 && duplicates == 0,
        "budgeted passes reach every tail mapping exactly once");
    put(0x3000, 12, 0x4007);
    seen.clear();
    result = WalkUserPtes(0x1000, 4, 0, 128, true, reader, [&](const UserPteLeaf& leaf)
    {
        seen.insert(leaf.Address);
        return true;
    });
    check(result.Finished && seen.size() == 13 && seen.count((12ull << 21) + 0x10000) == 1,
        "shared page-table aliases retain both virtual mappings");
    put(0x2000, 0, 0x8000000000003007ull);
    result = WalkUserPtes(0x1000, 4, 0, 128, true, reader, [](const UserPteLeaf&)
    {
        return true;
    });
    check(result.Finished && result.Leaves == 0 && result.TablesRead == 2, "NX ancestor prunes subtree");
    put(0x2000, 0, 0x3003);
    result = WalkUserPtes(0x1000, 4, 0, 128, true, reader, [](const UserPteLeaf&)
    {
        return true;
    });
    check(result.Leaves == 0, "supervisor ancestor excludes user mappings");
    put(0x2000, 0, 0x3007);
    put(0x2000, 1, 0x40001087);
    uint64_t largePhysical = 0;
    result = WalkUserPtes(0x1000, 4, 1ull << 30, 128, true, reader, [&](const UserPteLeaf& leaf)
    {
        largePhysical = leaf.Physical;
        return false;
    });
    check(!result.Finished && result.ResumeAddress == (1ull << 30) && largePhysical == 0x40000000,
        "large-page PAT is not part of physical address and visitor stop resumes");
    put(0x2000, 1, 0x40002087);
    result = WalkUserPtes(0x1000, 4, 1ull << 30, 128, true, reader, [](const UserPteLeaf&)
    {
        return true;
    });
    check(result.ReadFailures == 1 && result.Leaves == 0, "reserved large-page address bits rejected");
    put(0x2000, 1, 0);
    tables[0x4000].resize(4095);
    result = WalkUserPtes(0x1000, 4, 0, 128, true, reader, [](const UserPteLeaf&)
    {
        return true;
    });
    check(result.ReadFailures == 2, "short table reads on both aliases are coverage failures");
    tables[0x4000].resize(4096);
    put(0x20000, 0, 0x1007);
    result = WalkUserPtes(0x20000, 5, 0, 128, true, reader, [](const UserPteLeaf&)
    {
        return true;
    });
    check(result.Finished && result.Leaves == 13, "five-level user walk");
    check(!WalkUserPtes(0x1000, 0, 0, 128, true, reader, [](const UserPteLeaf&)
    {
        return true;
    }).Finished, "unknown paging mode is not complete");
    executable_image::DiskPeMetadata image;
    image.SizeOfImage = 0x6000;
    executable_image::DiskPeSection code;
    code.VirtualAddress = 0x1000;
    code.VirtualSize = 0x1800;
    code.SizeOfRawData = 0x1000;
    code.Executable = true;
    image.Sections.push_back(code);
    check(!UnexpectedExecutableImageAddress(image, 0x17FF) && !UnexpectedExecutableImageAddress(image, 0x2FFF),
        "mixed section boundary page retains declared execution");
    check(UnexpectedExecutableImageAddress(image, 0x3000) && UnexpectedExecutableImageAddress(image, 0x100),
        "data and header pages lack declared execution");
    check(!UnexpectedExecutableImageAddress(image, 0x6000), "address outside image is not an image permission finding");
    KmonHuntReference unknown;
    unknown.Context.Identity.BootId = L"page_fixture";
    unknown.Context.Identity.ProcessId = 45;
    unknown.Context.Identity.CreateTime = 50;
    unknown.Context.MonotonicMs = 100;
    unknown.Context.MappingGeneration = 1;
    unknown.Role = L"user_hidden_pte_page";
    unknown.Context.Ownership = CodeOwnership::Unknown;
    KmonHuntIndex index;
    check(index.Observe(unknown) == 0, "unknown ownership alone cannot create a case");
    unknown.PageExecutableVerified = true;
    unknown.Address = 0;
    check(index.Observe(unknown) != 0 && index.Cases(100)[0].Kind == L"executable_ownership_unknown",
        "verified low-address PTE page retained with unknown ownership");
    unknown.Context.Ownership = CodeOwnership::OwnedUnexpectedExecutable;
    check(index.Observe(unknown) != 0 && index.Cases(100)[0].Kind == L"image_executable_permission",
        "unexpected image execution is not byte modification");
    unknown.Context.Ownership = CodeOwnership::OwnedUnverified;
    check(index.Observe(unknown) != 0 && index.Cases(100)[0].Kind == L"executable_image_unverified",
        "unavailable or mismatched image identity retains executable bytes for review");
    KmonExecutablePages lowPages(1);
    check(lowPages.Observe(unknown.Context.Identity, {0, 4096}, 0, L"user_hidden_pte_page", 100),
        "confirmed PTE source may schedule reserved low virtual addresses");
    check(!lowPages.Observe(unknown.Context.Identity, {0x10000, 4096}, 0, L"image_page_candidate", 101) &&
        lowPages.Size() == 1, "image sweep cannot evict an unowned PTE candidate");
    std::cout << "[kmon.pages] passed=" << passed << " failed=" << failed << " corpus=synthetic\n";
    return failed == 0;
}
