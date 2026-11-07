#pragma once

#include "../user/KmonHuntingJson.h"
#include <iostream>
#include <set>

inline bool KmonOrderingSelfTest()
{
    unsigned passed = 0, failed = 0;
    const auto check = [&](bool value, const char* name)
    {
        if (value) { ++passed; }
        else { ++failed; std::cerr << "[kmon.ordering] FAIL " << name << "\n"; }
    };
    const auto row = [](uint32_t pid, uint64_t tick, uint64_t root = 0x11000)
    {
        KmonHuntReference value;
        value.Context.Identity = {L"ordering_fixture_boot", pid, 50};
        value.Context.MonotonicMs = tick;
        value.Context.MappingGeneration = 1;
        value.Context.Ownership = CodeOwnership::UnownedExecutable;
        value.Context.Source = L"owned_fixture_source";
        value.Address = value.Root = root;
        value.Role = L"thread_start";
        return value;
    };
    // All arrival permutations must retain the newest A plus independent B/C.
    // The oracle names expected original ticks; it does not emulate admission.
    std::array<unsigned, 4> permutation{0, 1, 2, 3};
    const std::array<KmonHuntReference, 4> originals{row(55, 200), row(55, 100), row(56, 150), row(57, 175)};
    do
    {
        KmonHuntIndex index;
        uint64_t arrival = 250;
        for (const auto ordinal : permutation) { index.Observe(originals[ordinal], ++arrival); }
        std::set<std::pair<uint32_t, uint64_t>> current;
        for (const auto& item : index.Cases(arrival))
        { current.emplace(item.Primary.Context.Identity.ProcessId, item.Primary.Context.MonotonicMs); }
        check(current == std::set<std::pair<uint32_t, uint64_t>>{{55, 200}, {56, 150}, {57, 175}},
            "independent targets survive every arrival order without same-path rollback");
        bool retained = index.History().size() == permutation.size();
        for (size_t i = 0; retained && i < permutation.size(); ++i)
        {
            retained = index.History()[i].Reference.Context.MonotonicMs == originals[permutation[i]].Context.MonotonicMs &&
                index.History()[i].Reference.Context.ArrivalSequence == i + 1 &&
                index.History()[i].Reference.Context.ArrivalMonotonicMs == 251 + i;
        }
        check(retained, "all original event/arrival values retained independently");
    } while (std::next_permutation(permutation.begin(), permutation.end()));

    KmonHuntIndex paths;
    KmonHuntReceipt receipt;
    check(paths.Observe(row(55, 200), 205) != 0 && paths.Observe(row(55, 150, 0x21000), 210) != 0 &&
        paths.Cases(210).size() == 2, "independent paths within one process do not share a latest-event floor");
    auto differentSource = row(55, 100);
    differentSource.Context.Source = L"another_local_producer";
    check(paths.Observe(differentSource, 211, &receipt) == 0 && receipt.Disposition == L"historical_only",
        "a producer label cannot bypass the same path's clock order");
    auto differentBoot = row(55, 160, 0x31000);
    differentBoot.Context.Identity.BootId = L"other_target_boot_same_collector_clock";
    check(paths.Observe(differentBoot, 212) != 0 && paths.Cases(212).size() == 3,
        "target boot scopes do not purge each other");
    auto wallClock = row(55, 180, 0x41000);
    wallClock.Context.Timestamp = UINT64_MAX;
    check(paths.Observe(wallClock, 213) != 0, "FILETIME changes cannot order independent monotonic observations");
    KmonHuntIndex kernel;
    auto kernelRow = row(0, 200, 0xFFFF800000001000ull);
    kernelRow.Context.Identity.CreateTime = 500;
    kernel.Observe(kernelRow, 205);
    kernelRow.Context.Identity.CreateTime = 0;
    kernelRow.Context.MonotonicMs = 210;
    check(kernel.Observe(kernelRow, 215) != 0 && kernel.Size() == 1,
        "kernel canonical identity does not acquire a process creation generation");

    KmonHuntIndex slots;
    auto oldSlot = row(55, 100);
    oldSlot.Slot = 0x40000;
    oldSlot.Role = L"iat";
    auto newSlot = oldSlot;
    newSlot.Context.MonotonicMs = 200;
    newSlot.Address = newSlot.Root = 0x21000;
    slots.Observe(newSlot, 205);
    check(slots.Observe(oldSlot, 210, &receipt) == 0 && receipt.Disposition == L"historical_only",
        "changed pointer root remains the same slot path for ordering");
    oldSlot.Slot += 8;
    check(slots.Observe(oldSlot, 211) != 0, "independent slots may arrive out of event-time order");
    slots.Retire(newSlot.Context.Identity, newSlot.Root, newSlot.Slot, newSlot.Role, 150);
    check(slots.Cases(211).size() == 2, "late retirement cannot remove a newer current path");
    slots.Retire(newSlot.Context.Identity, newSlot.Root, newSlot.Slot, newSlot.Role, 220);
    newSlot.Context.MonotonicMs = 215;
    check(slots.Observe(newSlot, 225, &receipt) == 0 && receipt.Disposition == L"historical_only" &&
        slots.Cases(225).size() == 1, "retirement tombstone blocks late resurrection");
    newSlot.Context.MonotonicMs = 230;
    check(slots.Observe(newSlot, 235) != 0, "new observation after retirement can requalify the path");

    KmonHuntIndex mapping(1);
    auto changed = row(55, 200);
    changed.Context.MappingGeneration = 2;
    mapping.Observe(changed, 205);
    mapping.Observe(row(56, 210), 211);
    auto oldMapping = row(55, 150, 0x11080);
    check(mapping.Observe(oldMapping, 215, &receipt) == 0 && receipt.Disposition == L"historical_only",
        "mapping guard survives hot eviction and covers another path on the page");
    oldMapping.Context.MappingGeneration = 2;
    check(mapping.Observe(oldMapping, 216) != 0,
        "same observed mapping version permits independent earlier path evidence");

    KmonHuntIndex generation(1);
    generation.Observe(row(55, 100), 105);
    auto born = row(55, 200);
    born.Context.Identity.CreateTime = 60;
    generation.Observe(born, 205);
    generation.Observe(row(56, 210), 211);
    check(generation.Observe(row(55, 220), 225, &receipt) == 0 && receipt.Disposition == L"prior_process_instance",
        "process generation guard survives current reference eviction");
    auto tooEarlyGeneration = row(56, 150);
    tooEarlyGeneration.Context.Identity.CreateTime = 70;
    check(generation.Observe(tooEarlyGeneration, 226, &receipt) == 0 && receipt.Disposition == L"historical_only",
        "an earlier event cannot replace a later observation with a new generation");
    KmonHuntIndex clockChange;
    clockChange.Observe(born, 205);
    auto backwardBirth = row(55, 220);
    backwardBirth.Context.Identity.CreateTime = 40;
    check(clockChange.Observe(backwardBirth, 225) != 0 && clockChange.Cases(225).size() == 1 &&
        clockChange.Cases(225)[0].Primary.Context.Identity.CreateTime == 40,
        "a new process generation can have a numerically earlier creation FILETIME");
    born.Context.MonotonicMs = 230;
    check(clockChange.Observe(born, 235, &receipt) == 0 && receipt.Disposition == L"prior_process_instance",
        "retired generation cannot reenter just because its creation FILETIME is larger");
    clockChange.Retire(born.Context.Identity, born.Root, born.Slot, born.Role, 240);
    check(clockChange.Cases(240).size() == 1 && clockChange.Query(240).OrderingStates == 2,
        "late old-generation retirement cannot acquire a new guard or remove the current process");
    KmonHuntIndex generationPressure(4, 1);
    generationPressure.Observe(row(55, 100), 105);
    born.Context.MonotonicMs = 200;
    check(generationPressure.Observe(born, 205, &receipt) == 0 && receipt.Disposition == L"current_capacity" &&
        generationPressure.Cases(205).empty(), "unretained process transition withdraws stale current rows");
    check(generationPressure.Observe(row(55, 210), 215, &receipt) == 0 && receipt.Disposition == L"prior_process_instance",
        "capacity denial still retires known prior generations without allocating a new guard");
    born.Context.MonotonicMs = 30200;
    check(generationPressure.Observe(born, 30300) != 0 && generationPressure.Cases(30300).size() == 1,
        "generation pressure recovers after protected observations expire");
    KmonHuntOrdering zeroPage;
    auto zero = row(55, 100, 0);
    zero.Role = L"user_page_candidate";
    zeroPage.Advance(105);
    check(*zeroPage.Observe(zero.Context, 0, 0, 0, zero.Role) == L'\0' &&
        zeroPage.Retire(zero.Context.Identity, 0, 0, zero.Role, 110) && zeroPage.Size() == 2,
        "a valid page-zero observation cannot alias its retirement tombstone");

    KmonHuntIndex assertions(1);
    auto known = row(55, 100);
    known.Context.Identity.Eprocess = 0xFFFF800000004000ull;
    assertions.Observe(known, 105);
    auto unknown = row(55, 110);
    assertions.Observe(unknown, 115);
    for (uint32_t pid = 100; pid < 615; ++pid) { assertions.Observe(row(pid, 120), 125); }
    known.Context.MonotonicMs = 130;
    known.Context.Identity.Eprocess += 4096;
    check(assertions.Observe(known, 135, &receipt) == 0 && receipt.Disposition == L"identity_conflict",
        "ordering guards preserve optional assertions after the smaller assertion cache evicts them");

    KmonHuntIndex bounded(4, 2);
    bounded.Observe(row(55, 100), 105);
    bounded.Observe(row(56, 110), 115);
    check(bounded.Observe(row(57, 120), 125, &receipt) == 0 && receipt.Disposition == L"current_capacity" &&
        bounded.Query(125).OrderingStates == 2 && bounded.Query(125).OrderingDeferred == 1,
        "full guard budget is explicit without forgetting protected current state");
    bounded.Retire(row(58, 140).Context.Identity, 0x11000, 0, L"thread_start", 140);
    check(bounded.Observe(row(55, 139), 145, &receipt) == 0 && receipt.Disposition == L"historical_only" &&
        bounded.Query(145).OrderingPressureFloorMs == 140 && bounded.Query(145).OrderingDeferred == 2,
        "untracked retirement under pressure establishes a reported conservative floor");
    check(bounded.Observe(row(55, 146), 150) != 0, "known keys can refresh while the ordering budget is full");
    check(bounded.Observe(row(57, 30200), 30300) != 0 && bounded.Query(30300).OrderingExpired == 2 &&
        bounded.Query(30300).OrderingStates == 1 && bounded.Cases(30300).size() == 1,
        "guard expiry uses arrival freshness and releases capacity without unsigned underflow");
    check(bounded.Observe(row(56, 110), 115, &receipt) == 0 && receipt.Disposition == L"historical_only",
        "retrograde arrival cannot reopen an expired freshness window");

    KmonHuntIndex extreme;
    extreme.Observe(row(55, UINT64_MAX - 4), UINT64_MAX - 3);
    check(extreme.Observe(row(56, UINT64_MAX - 6), UINT64_MAX - 2) != 0 && extreme.Cases(UINT64_MAX).size() == 2,
        "freshness arithmetic remains bounded at uint64 limits");
    const auto json = KmonHuntQueryJson(paths.Query(212), {}, paths.Evicted, paths.Rejected);
    check(mcpjson::ValidateDocument(json) && json.find(L"\"clock_scope\":\"single_collector_monotonic_ms\"") != std::wstring::npos &&
        json.find(L"\"same_tick_order_established\":false") != std::wstring::npos &&
        json.find(L"\"source_loss_coverage_established\":false") != std::wstring::npos,
        "query reports local clock, bounded states and ordering/loss limits");
    std::cout << "[kmon.ordering] passed=" << passed << " failed=" << failed << " corpus=synthetic\n";
    return failed == 0;
}
