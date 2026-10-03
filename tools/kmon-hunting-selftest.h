#pragma once

#include "../user/KmonHuntingJson.h"
#include "kmon-page-coverage-selftest.h"
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
    KmonHuntIndex priorities(2);
    auto callback = kernel;
    callback.Role = L"callback:registry:pre";
    check(KmonPointerReference(callback.Role) && KmonChannelRole(callback.Role) &&
        !KmonPointerReference(L"callback_unverified:registry:pre"), "only verified callback roles use slots");
    priorities.Observe(callback);
    priorities.Observe(user);
    auto pageReference = user;
    pageReference.Role = L"user_page_candidate";
    check(priorities.Observe(pageReference) == 0 && priorities.Size() == 2,
        "page candidates cannot evict execution references");
    KmonHuntIndex pageIndex;
    pageIndex.Observe(pageReference);
    check(pageIndex.Cases(101)[0].Kind == L"user_executable_memory", "page candidate is not an execution reference");
    KmonExecutablePages pages(4);
    KmonPageWork sample;
    check(pages.Observe(user.Context.Identity, {0x10000, 3 * 4096}, 0x10000, L"user_page_candidate", 100),
        "full executable range accepted");
    check(pages.Next(100, &sample) && sample.Range.Address == 0x10000, "first page scheduled");
    pages.Observe(user.Context.Identity, {0x10000, 3 * 4096}, 0x10000, L"user_page_candidate", 101);
    check(pages.Next(101, &sample) && sample.Range.Address == 0x11000, "refresh preserves progress");
    check(pages.Next(102, &sample) && sample.Range.Address == 0x12000 && pages.CyclesScheduled == 1,
        "tail page scheduled without a PE header or callback");
    check(!pages.Next(103, &sample) && pages.Next(10102, &sample) && sample.Range.Address == 0x10000,
        "completed range cooldown and repeat");
    check(!pages.Observe(user.Context.Identity, {0x10000, 4096}, 0, L"user_page_candidate", 10101),
        "scheduler rejects retrograde observations");
    check(!pages.Observe(user.Context.Identity, {0x10001, 4096}, 0, L"user_page_candidate", 10102) &&
        !pages.Observe(user.Context.Identity, {0x10000, UINT64_MAX}, 0, L"user_page_candidate", 10102),
        "scheduler alignment and overflow");
    auto newerIdentity = user.Context.Identity;
    ++newerIdentity.CreateTime;
    pages.Observe(newerIdentity, {0x20000, 4096}, 0x20000, L"user_page_candidate", 10103);
    check(pages.Size() == 1 && !pages.Observe(user.Context.Identity, {0x10000, 4096}, 0,
        L"user_page_candidate", 10104), "PID reuse retires old ranges and rejects old instances");
    check(!pages.Next(310104, &sample) && pages.Size() == 0 && pages.Expired == 1, "unrefreshed range expiry");
    KmonExecutablePages fairPages;
    fairPages.Observe(user.Context.Identity, {0x10000, 64 * 4096}, 0x10000, L"user_page_candidate", 100);
    auto secondIdentity = user.Context.Identity;
    ++secondIdentity.ProcessId;
    fairPages.Observe(secondIdentity, {0x100000, 4096}, 0x100000, L"user_page_candidate", 100);
    fairPages.Next(100, &sample);
    check(fairPages.Next(100, &sample) && sample.Identity.ProcessId == secondIdentity.ProcessId,
        "large mappings do not starve small mappings");
    uint64_t tail = 0;
    for (unsigned i = 0; i < 63; ++i)
    {
        fairPages.Next(100, &sample);
        tail = sample.Range.Address;
    }
    check(tail == 0x10000 + 63 * 4096, "all pages of a large mapping are scheduled");
    KmonExecutablePages boundedPages(2);
    for (uint32_t i = 0; i < 1024; ++i)
    {
        auto identity = user.Context.Identity;
        identity.ProcessId += i;
        boundedPages.Observe(identity, {0x10000, 4096}, 0, L"user_page_candidate", 100 + i);
        check(boundedPages.Size() <= 2, "range scheduler bounded under pressure");
    }
    check(boundedPages.Evicted == 0 && boundedPages.Deferred == 1022,
        "unfinished ranges survive repeated admission pressure");
    const uint64_t presentUser = 7;
    const uint64_t nx = 1ull << 63;
    check(KmonHardwareExecutable(0, 7, 7, 7, 7, 4096, 4, true), "user 4K executable mapping");
    for (unsigned level = 0; level < 4; ++level)
    {
        uint64_t entries[] = {presentUser, presentUser, presentUser, presentUser};
        entries[level] |= nx;
        check(!KmonHardwareExecutable(0, entries[0], entries[1], entries[2], entries[3], 4096, 4, true),
            "NX at every paging level is enforced");
        entries[level] = 3;
        check(!KmonHardwareExecutable(0, entries[0], entries[1], entries[2], entries[3], 4096, 4, true),
            "supervisor-only ancestor rejects user execution");
    }
    check(KmonHardwareExecutable(0, 3, 3, 0x83, nx, 1ull << 21, 4, false),
        "2M leaf ignores absent child PTE");
    check(KmonHardwareExecutable(0, 7, 0x87, nx, nx, 1ull << 30, 4, true),
        "1G leaf ignores absent child tables");
    check(!KmonHardwareExecutable(0, 7, 7, 7, 0, 4096, 4, true) &&
        !KmonHardwareExecutable(7 | nx, 7, 7, 7, 7, 4096, 5, true), "nonpresent and LA57 NX rejected");
    const auto json = KmonHuntCasesJson(physical.Cases(1101), 1101, 0, 0);
    check(mcpjson::ValidateDocument(json) && json.find(L"\"communication_proven\":false") != std::wstring::npos,
        "JSON and claim boundary");
    std::cout << "[kmon.hunting] passed=" << passed << " failed=" << failed << " corpus=synthetic\n";
    const bool pagesPassed = KmonPageCoverageSelfTest();
    return failed == 0 && pagesPassed;
}
