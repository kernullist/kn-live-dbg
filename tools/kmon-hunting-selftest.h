#pragma once

#include "../user/KmonHuntingJson.h"
#include <iostream>

inline KmonHuntReference HuntFixture(uint32_t pid, uint64_t now = 100)
{
    KmonHuntReference row;
    row.Context.Identity.BootId = L"fixture_boot";
    row.Context.Identity.ProcessId = pid;
    row.Context.Identity.CreateTime = pid == 0 ? 0 : 50;
    row.Context.MonotonicMs = now;
    row.Context.Timestamp = now * 10000;
    row.Context.MappingGeneration = 1;
    row.Context.Ownership = CodeOwnership::UnownedExecutable;
    row.Context.Source = L"fixture";
    row.Context.DependencyGroup = L"fixture_memory";
    row.Address = pid == 0 ? 0xFFFF800000001020ull : 0x11020;
    row.Root = row.Address;
    row.Slot = pid == 0 ? 0xFFFF800000003000ull : 0;
    row.Role = pid == 0 ? L"firmware_table_handler" : L"thread_start";
    row.PageSha256 = std::wstring(64, L'a');
    row.PageComparable = true;
    row.SlotStable = pid == 0;
    return row;
}

inline bool KmonHuntingSelfTest()
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
            std::cerr << "[kmon.hunting] FAIL " << name << "\n";
        }
    };
    auto kernel = HuntFixture(0);
    auto user = HuntFixture(45, 101);
    const auto linked = [](const KmonHuntReference& a, const KmonHuntReference& b, uint64_t now)
    {
        KmonHuntIndex index;
        index.Observe(a);
        index.Observe(b);
        const auto cases = index.Cases(now);
        return std::count_if(cases.begin(), cases.end(), [](const auto& item)
        {
            return item.HasRelated;
        });
    };
    check(linked(kernel, user, 101) == 1, "full page content positive");
    for (unsigned mask = 0; mask < 256; ++mask)
    {
        auto a = kernel;
        auto b = user;
        if ((mask & 1) != 0)
        {
            a.SlotStable = false;
        }
        if ((mask & 2) != 0)
        {
            a.PageComparable = false;
        }
        if ((mask & 4) != 0)
        {
            b.PageSha256[0] = L'b';
        }
        if ((mask & 8) != 0)
        {
            b.Context.Identity.BootId = L"other_boot";
        }
        if ((mask & 16) != 0)
        {
            b.Context.Identity.CreateTime = 0;
        }
        if ((mask & 32) != 0)
        {
            b.Context.MappingGeneration = 0;
        }
        if ((mask & 64) != 0)
        {
            a.Role = L"etw_provider_candidate";
        }
        if ((mask & 128) != 0)
        {
            b.Context.Ownership = CodeOwnership::OwnedVerified;
        }
        check(linked(a, b, 101) == (mask == 0 ? 1 : 0), "negative evidence matrix");
    }
    check(linked(kernel, user, 30101) == 0, "expired kernel evidence");
    check(linked(kernel, user, 99) == 0, "future evidence");
    KmonHuntIndex index(2);
    check(index.Observe(kernel) != 0 && index.Observe(user) != 0, "accepted instances");
    auto replacement = user;
    replacement.Context.MonotonicMs = 102;
    replacement.Context.Identity.CreateTime = 60;
    replacement.PageSha256 = std::wstring(64, L'b');
    index.Observe(replacement);
    check(index.Size() == 2 && index.Cases(102).size() == 2, "PID reuse retires old user evidence");
    auto older = user;
    older.Context.MonotonicMs = 103;
    check(index.Observe(older) == 0, "late old process instance rejected");
    replacement.Context.MonotonicMs = 104;
    replacement.Context.MappingGeneration = 2;
    replacement.Address += 1;
    index.Observe(replacement);
    check(index.Size() == 2, "new mapping generation retires old page");
    index.Retire(replacement.Context.Identity, replacement.Root, replacement.Slot, replacement.Role);
    check(index.Size() == 1, "clean or unstable reference retires prior path");
    KmonHuntIndex slotIndex;
    slotIndex.Observe(kernel);
    slotIndex.Retire(kernel.Context.Identity, kernel.Root + 4096, kernel.Slot, kernel.Role);
    check(slotIndex.Size() == 0, "changed slot target retires old path");
    auto badAddress = kernel;
    badAddress.Address = 0x11000;
    check(slotIndex.Observe(badAddress) == 0, "kernel identity cannot name a user address");
    badAddress = user;
    badAddress.Address = kernel.Address;
    check(slotIndex.Observe(badAddress) == 0, "user identity cannot name a kernel address");
    auto physicalKernel = kernel;
    auto physicalUser = user;
    physicalKernel.Context.PfnKnown = physicalUser.Context.PfnKnown = true;
    physicalKernel.Context.Pfn = physicalUser.Context.Pfn = 99;
    KmonHuntIndex physical;
    physical.Observe(physicalKernel);
    physical.Observe(physicalUser);
    check(physical.Cases(101)[0].Relation == ObservationRelation::PhysicalPage, "same sampled PFN and content");
    physicalUser.Context.MonotonicMs = 1101;
    physical.Observe(physicalUser);
    check(physical.Cases(1101)[0].Relation == ObservationRelation::Content, "stale PFN only content relation");
    std::vector<uint8_t> page(4096, 0x90);
    check(!KmonComparablePage(page), "padding is not comparable content");
    for (size_t i = 0; i < 64; ++i)
    {
        page[i] = static_cast<uint8_t>(i + 1);
    }
    check(KmonComparablePage(page), "nonpadding page content");
    page.resize(4095);
    check(!KmonComparablePage(page), "short page is not a fingerprint");
    check(KmonFreshStack(user.Context.Identity, 50, 100) &&
        !KmonFreshStack(user.Context.Identity, 49, 100) &&
        !KmonFreshStack(user.Context.Identity, 101, 100) &&
        !KmonFreshStack(user.Context.Identity, 50, 50000051), "stack identity and timing");
    KmonHuntIndex bounded(4);
    for (uint32_t i = 0; i < 10000; ++i)
    {
        auto row = HuntFixture(50 + i, 200 + i);
        bounded.Observe(row);
        check(bounded.Size() <= 4 && bounded.Cases(200 + i, 2).size() <= 2, "capacity stress");
    }
    check(bounded.Evicted == 9996, "eviction accounting");
    const auto json = KmonHuntCasesJson(physical.Cases(1101), 1101, 0, 0);
    check(mcpjson::ValidateDocument(json) && json.find(L"\"communication_proven\":false") != std::wstring::npos,
        "JSON and claim boundary");
    std::cout << "[kmon.hunting] passed=" << passed << " failed=" << failed << " corpus=synthetic\n";
    return failed == 0;
}
