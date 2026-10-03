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
    KmonHuntIndex ownershipIndex;
    check(ownershipIndex.Observe(unknown) == 0, "unknown ownership alone cannot create a case");
    unknown.PageExecutableVerified = true;
    unknown.Address = 0;
    check(ownershipIndex.Observe(unknown) != 0 && ownershipIndex.Cases(100)[0].Kind == L"executable_ownership_unknown",
        "verified low-address PTE page retained with unknown ownership");
    unknown.Context.Ownership = CodeOwnership::OwnedUnexpectedExecutable;
    check(ownershipIndex.Observe(unknown) != 0 && ownershipIndex.Cases(100)[0].Kind == L"image_executable_permission",
        "unexpected image execution is not byte modification");
    unknown.Context.Ownership = CodeOwnership::OwnedUnverified;
    check(ownershipIndex.Observe(unknown) != 0 && ownershipIndex.Cases(100)[0].Kind == L"executable_image_unverified",
        "unavailable or mismatched image identity retains executable bytes for review");
    KmonExecutablePages lowPages(1);
    check(lowPages.Observe(unknown.Context.Identity, {0, 4096}, 0, L"user_hidden_pte_page", 100),
        "confirmed PTE source may schedule reserved low virtual addresses");
    check(!lowPages.Observe(unknown.Context.Identity, {0x10000, 4096}, 0, L"image_page_candidate", 101) &&
        lowPages.Size() == 1, "image sweep cannot evict an unowned PTE candidate");
    KmonExecutablePages pressure(2);
    std::set<uint64_t> scheduled;
    for (uint64_t tick = 100; tick < 136; ++tick)
    {
        for (uint64_t region = 0; region < 3; ++region)
        {
            pressure.Observe(unknown.Context.Identity, {0x10000 + region * 0x10000, 3 * 4096},
                0, L"user_page_candidate", tick);
        }
        KmonPageWork page;
        if (pressure.Next(tick, &page))
        {
            scheduled.insert(page.Range.Address);
        }
    }
    check(scheduled.size() == 9, "repeated over-capacity inventories reach every retained range tail");
    KmonHuntIndex newest;
    auto first = unknown;
    first.Address = first.Root = 0x10000;
    first.Context.MonotonicMs = 100;
    newest.Observe(first);
    auto second = first;
    second.Address = second.Root = 0x20000;
    second.Context.MonotonicMs = 101;
    newest.Observe(second);
    first.Context.MonotonicMs = 102;
    newest.Observe(first);
    check(newest.Cases(102, 1)[0].Primary.Address == first.Address,
        "refreshed evidence is visible before older evidence at the output limit");
    check(!KmonPhysicalPageSamplesAgree({0x12000, 0x23000, 0x12000}),
        "physical read from transient mapping cannot acquire the restored PFN");
    check(!KmonHardwareExecutable(0, 0x87, 7, 7, 7, 4096, 4, true) &&
        !KmonHardwareExecutable(0x87, 7, 7, 7, 7, 4096, 5, true),
        "reserved upper-level PS bits cannot establish executable mapping");
    check(!KmonHardwareExecutable(0, 7, 0x40002087, 0, 0, 1ull << 30, 4, true),
        "1G reserved address bits cannot establish executable mapping");
    check(!KmonHardwareExecutable(0, 7, 7, 0x202087, 0, 1ull << 21, 4, true),
        "2M reserved address bits cannot establish executable mapping");
    check(KmonHardwareExecutable(0, 7, 0x40001087, 0, 0, 1ull << 30, 4, true) &&
        KmonHardwareExecutable(0, 7, 7, 0x201087, 0, 1ull << 21, 4, true) &&
        KmonHardwareExecutable(0, 7, 7, 7, 0x87, 4096, 4, true),
        "PAT is allowed in its large-page and 4K leaf positions");
    check(KmonPhysicalPageSamplesAgree({0, 0x12000, 0x12FFF, 0x12000}) &&
        !KmonPhysicalPageSamplesAgree({0, 0x12000, 0, 0x23000}),
        "missing translations never mask contradictory known PFNs");
    KmonExecutablePages removal(3);
    auto processA = unknown.Context.Identity;
    auto processB = processA;
    auto processC = processA;
    ++processB.ProcessId;
    processC.ProcessId += 2;
    removal.Observe(processA, {0x10000, 3 * 4096}, 0, L"user_page_candidate", 100);
    removal.Observe(processB, {0x10000, 3 * 4096}, 0, L"user_page_candidate", 100);
    removal.Observe(processC, {0x10000, 3 * 4096}, 0, L"user_page_candidate", 100);
    KmonPageWork nextPage;
    removal.Next(100, &nextPage);
    ++processA.CreateTime;
    removal.Observe(processA, {0x20000, 3 * 4096}, 0, L"user_page_candidate", 101);
    check(removal.Next(101, &nextPage) && nextPage.Identity.ProcessId == processB.ProcessId,
        "retiring an earlier row preserves the next process turn");
    KmonExecutablePages priority(1);
    priority.Observe(processA, {0x10000, 3 * 4096}, 0, L"image_page_candidate", 100);
    priority.Next(100, &nextPage);
    check(priority.Observe(processB, {0x20000, 3 * 4096}, 0, L"user_page_candidate", 101) &&
        priority.Evicted == 1 && priority.Next(101, &nextPage) && nextPage.Identity.ProcessId == processB.ProcessId,
        "non-image candidate can preempt an unfinished lower-priority image sweep");
    for (size_t capacity = 1; capacity <= 4; ++capacity)
    {
        KmonExecutablePages rotating(capacity);
        std::set<uint64_t> covered;
        const size_t ranges = capacity + 3;
        size_t expected = 0;
        for (size_t region = 0; region < ranges; ++region)
        {
            expected += 2 + region % 3;
        }
        for (uint64_t tick = 100; tick < 700; ++tick)
        {
            for (size_t entry = 0; entry < ranges; ++entry)
            {
                const size_t region = (tick & 1) == 0 ? entry : ranges - entry - 1;
                rotating.Observe(processA, {0x10000 + region * 0x10000, (2 + region % 3) * 4096},
                    0, L"user_page_candidate", tick);
            }
            if (rotating.Next(tick, &nextPage))
            {
                covered.insert(nextPage.Range.Address);
            }
        }
        check(covered.size() == expected,
            "bounded admission covers every static range regardless of inventory order");
    }
    for (uint64_t seed = 1; seed <= 16; ++seed)
    {
        uint64_t state = seed;
        const auto random = [&]()
        {
            state = state * 6364136223846793005ull + 1442695040888963407ull;
            return state;
        };
        const size_t capacity = 1 + static_cast<size_t>(seed % 4);
        const size_t count = capacity + 1 + static_cast<size_t>(seed % 7);
        KmonExecutablePages shuffled(capacity);
        std::vector<size_t> order;
        std::vector<uint64_t> lengths;
        size_t expected = 0;
        for (size_t index = 0; index < count; ++index)
        {
            order.push_back(index);
            lengths.push_back(1 + random() % 7);
            expected += static_cast<size_t>(lengths.back());
        }
        std::set<uint64_t> covered;
        bool bounded = true;
        for (uint64_t tick = 100; tick < 1900; ++tick)
        {
            for (size_t index = count; index > 1; --index)
            {
                std::swap(order[index - 1], order[static_cast<size_t>(random() % index)]);
            }
            for (const auto index : order)
            {
                shuffled.Observe(processA, {0x10000 + index * 0x10000, lengths[index] * 4096},
                    0, L"user_page_candidate", tick);
            }
            if (shuffled.Next(tick, &nextPage))
            {
                covered.insert(nextPage.Range.Address);
            }
            bounded = bounded && shuffled.Size() <= capacity;
        }
        check(bounded && covered.size() == expected,
            "shuffled inventories with unequal ranges retain bounded forward progress");
    }
    std::cout << "[kmon.pages] passed=" << passed << " failed=" << failed << " corpus=synthetic\n";
    return failed == 0;
}
