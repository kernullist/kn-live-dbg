#include "HiddenProcessPolicy.h"

#include <functional>
#include <cstdio>
#include <vector>

namespace
{
    constexpr uint64_t kObject = 0xffff800000010000ull;
    constexpr uint64_t kHead = 0xffff800000020000ull;

    HiddenProcessLayout TestLayout()
    {
        HiddenProcessLayout layout;
        layout.Pid = {0x10, 8, 0, 0, true};
        layout.CreateTime = {0x18, 8, 0, 0, true};
        layout.ActiveThreads = {0x20, 4, 0, 0, true};
        layout.ExitTime = {0x28, 8, 0, 0, true};
        layout.Auxiliary = {0x30, 1, 2, 1, true};
        layout.ProcessExiting = {0x31, 1, 0, 1, true};
        layout.ProcessDelete = {0x32, 1, 0, 1, true};
        layout.ProcessRundown = {0x33, 1, 0, 1, true};
        layout.LinksOffset = 0x40;
        layout.ListHead = kHead;
        layout.LinksAvailable = true;
        return layout;
    }

    class FixtureReader final : public HiddenProcessReader
    {
    public:
        FixtureReader()
        {
            Memory[kObject + 0x10] = 100;
            Memory[kObject + 0x18] = 123456;
            Memory[kObject + 0x20] = 4;
            Memory[kObject + 0x28] = 0;
            Memory[kObject + 0x30] = 0;
            Memory[kObject + 0x31] = 0;
            Memory[kObject + 0x32] = 0;
            Memory[kObject + 0x33] = 0;
            Memory[kObject + 0x40] = kHead;
            Memory[kObject + 0x48] = kHead;
            Memory[kHead] = kObject + 0x40;
            Memory[kHead + 8] = kObject + 0x40;
        }

        bool Read(uint64_t address, uint8_t bytes, uint64_t* value) override
        {
            ++Reads;
            if (OnRead)
            {
                OnRead(*this, address);
            }
            const auto found = Memory.find(address);
            if (found == Memory.end())
            {
                return false;
            }
            *value = found->second;
            if (bytes < 8)
            {
                *value &= (uint64_t{1} << (bytes * 8)) - 1;
            }
            return true;
        }

        bool Resolve(uint32_t pid, uint64_t* object) override
        {
            ++Resolves;
            if (ResolveFailure || pid != 100)
            {
                return false;
            }
            *object = ReplacedOnResolve && Resolves == 2 ? kObject + 0x1000 : kObject;
            return true;
        }

        bool Stopped() const override
        {
            return StopAfter != 0 && Reads >= StopAfter;
        }

        std::map<uint64_t, uint64_t> Memory;
        std::function<void(FixtureReader&, uint64_t)> OnRead;
        uint32_t Reads = 0;
        uint32_t Resolves = 0;
        uint32_t StopAfter = 0;
        bool ResolveFailure = false;
        bool ReplacedOnResolve = false;
    };

    HiddenProcessQualification ValidQualification()
    {
        FixtureReader reader;
        HiddenProcessQualification q;
        q.Attempted = true;
        q.KernelComplete = true;
        q.SpiComplete = true;
        q.ToolhelpComplete = true;
        q.Before = ReadHiddenProcessLifetime(reader, {}, TestLayout(), 100);
        q.After = q.Before;
        return q;
    }
}

bool HiddenProcessPolicySelfTest(uint32_t* checks)
{
    uint32_t count = 0;
    bool passed = true;
    const auto check = [&](bool value)
    {
        ++count;
        passed = passed && value;
        if (!value)
        {
            std::fprintf(stderr, "hidden-process control failed: %u\n", count);
        }
    };
    const auto base = ValidQualification();
    HiddenProcessMembership discovery;
    discovery.Cid = true;
    const auto expect = [&](const HiddenProcessQualification& q,
        HiddenProcessDisposition state, const wchar_t* reason)
    {
        const auto decision = QualifyHiddenProcess(100, discovery, q);
        check(decision.Disposition == state && std::wstring(decision.Reason) == reason);
    };
    using State = HiddenProcessDisposition;
    expect(base, State::CrossViewDiscrepancy, L"cid_only");
    auto q = base;
    q.Views.Spi = true;
    expect(q, State::CrossViewDiscrepancy, L"api_only");
    q = base;
    q.Views.Kernel = true;
    q.KernelIdentity = {kObject, base.Before.CreateTime, true};
    expect(q, State::CrossViewDiscrepancy, L"kernel_only");
    const auto kernelOnly = q;
    q.Views.Toolhelp = true;
    expect(q, State::Reconciled, L"reconciled");
    q = kernelOnly;
    q.Before.Auxiliary = q.After.Auxiliary = true;
    expect(q, State::Auxiliary, L"auxiliary");
    q.After.Auxiliary = false;
    expect(q, State::Unverified, L"auxiliary_unavailable");
    for (unsigned side = 0; side < 2; ++side)
    {
        q = kernelOnly;
        (side == 0 ? q.Before : q.After).HasAuxiliary = false;
        expect(q, State::Unverified, L"auxiliary_unavailable");
        q = base;
        (side == 0 ? q.Before : q.After).HasExitTime = false;
        expect(q, State::Unverified, L"lifecycle_unavailable");
        q = base;
        (side == 0 ? q.Before : q.After).HasActiveThreads = false;
        expect(q, State::Unverified, L"lifecycle_unavailable");
        q = base;
        (side == 0 ? q.Before : q.After).HasStateFlags = false;
        expect(q, State::Unverified, L"lifecycle_unavailable");
        q = base;
        (side == 0 ? q.Before : q.After).StateTransition = true;
        expect(q, State::Unverified, L"lifecycle_transition");
        q = base;
        (side == 0 ? q.Before : q.After).IdentityValid = false;
        expect(q, State::Unverified, L"identity_unavailable");
        q = base;
        (side == 0 ? q.Before : q.After).CreateTime = 0;
        expect(q, State::Unverified, L"identity_unavailable");
        q = base;
        (side == 0 ? q.Before : q.After).Pid = 101;
        expect(q, State::Unverified, L"identity_unavailable");
        q = base;
        (side == 0 ? q.Before : q.After).Eprocess = 0;
        expect(q, State::Unverified, L"identity_unavailable");
        q = base;
        (side == 0 ? q.Before : q.After).ExitTime = 1;
        expect(q, State::Terminating, L"terminating");
        q = base;
        (side == 0 ? q.Before : q.After).ActiveThreads = 0;
        expect(q, State::Terminating, L"terminating");
    }
    q = base;
    q.After.Eprocess += 0x1000;
    expect(q, State::Unverified, L"identity_changed");
    q = base;
    ++q.After.CreateTime;
    expect(q, State::Unverified, L"identity_changed");
    q = kernelOnly;
    ++q.KernelIdentity.CreateTime;
    expect(q, State::Unverified, L"identity_changed");
    q = kernelOnly;
    q.KernelIdentity.Eprocess += 0x1000;
    expect(q, State::Unverified, L"identity_changed");
    q = kernelOnly;
    q.KernelIdentity.HasCreateTime = false;
    expect(q, State::Unverified, L"identity_changed");
    q = base;
    q.Attempted = false;
    expect(q, State::Unverified, L"comparison_unavailable");
    q = base;
    q.BudgetExceeded = true;
    expect(q, State::Unverified, L"qualification_budget");
    for (unsigned mask = 0; mask < 7; ++mask)
    {
        q = base;
        q.KernelComplete = (mask & 1) != 0;
        q.SpiComplete = (mask & 2) != 0;
        q.ToolhelpComplete = (mask & 4) != 0;
        expect(q, State::Unverified, L"incomplete_comparison");
    }
    // Discovery can nominate a candidate, but it never supplies current proof.
    for (unsigned bits = 0; bits < 32; ++bits)
    {
        HiddenProcessMembership d;
        d.Kernel = (bits & 1) != 0;
        d.Spi = (bits & 2) != 0;
        d.Toolhelp = (bits & 4) != 0;
        d.Cid = (bits & 8) != 0;
        d.Handles = (bits & 16) != 0;
        const auto decision = QualifyHiddenProcess(100, d, {});
        check(decision.Disposition == State::None || decision.Disposition == State::Unverified);
        check(QualifyHiddenProcess(4, d, base).Disposition == State::None);
        check(QualifyHiddenProcess(0, d, base).Disposition == State::None);
    }

    const auto layout = TestLayout();
    FixtureReader good;
    const auto lifetime = ReadHiddenProcessLifetime(good, {}, layout, 100);
    check(lifetime.IdentityValid && lifetime.Eprocess == kObject && lifetime.CreateTime == 123456 &&
        lifetime.HasExitTime && lifetime.ExitTime == 0 && lifetime.HasActiveThreads &&
        lifetime.ActiveThreads == 4 && lifetime.HasAuxiliary && !lifetime.Auxiliary && good.Resolves == 2);
    FixtureReader badResolve;
    badResolve.ResolveFailure = true;
    check(!ReadHiddenProcessLifetime(badResolve, {}, layout, 100).IdentityValid && badResolve.Reads == 0);
    FixtureReader reused;
    reused.ReplacedOnResolve = true;
    check(!ReadHiddenProcessLifetime(reused, {}, layout, 100).IdentityValid);
    for (uint64_t offset : {0x10ull, 0x18ull})
    {
        FixtureReader changed;
        unsigned hits = 0;
        changed.OnRead = [&](FixtureReader& r, uint64_t address)
        {
            if (address == kObject + offset && ++hits == 2)
            {
                ++r.Memory[address];
            }
        };
        check(!ReadHiddenProcessLifetime(changed, {}, layout, 100).IdentityValid);
    }
    for (uint64_t offset : {0x10ull, 0x18ull, 0x20ull, 0x28ull, 0x30ull, 0x31ull, 0x32ull, 0x33ull})
    {
        FixtureReader missing;
        missing.Memory.erase(kObject + offset);
        const auto sample = ReadHiddenProcessLifetime(missing, {}, layout, 100);
        if (offset == 0x10 || offset == 0x18)
        {
            check(!sample.IdentityValid);
        }
        else
        {
            q = kernelOnly;
            q.After = sample;
            check(QualifyHiddenProcess(100, discovery, q).Disposition == State::Unverified);
        }
    }
    for (uint64_t offset : {0x31ull, 0x32ull, 0x33ull})
    {
        FixtureReader transition;
        transition.Memory[kObject + offset] = 1;
        q = base;
        q.After = ReadHiddenProcessLifetime(transition, {}, layout, 100);
        expect(q, State::Unverified, L"lifecycle_transition");
    }
    for (uint32_t stop = 1; stop <= 10; ++stop)
    {
        FixtureReader stopped;
        stopped.StopAfter = stop;
        check(!ReadHiddenProcessLifetime(stopped, {}, layout, 100).IdentityValid);
    }
    for (unsigned fieldIndex = 0; fieldIndex < 8; ++fieldIndex)
    {
        for (uint8_t bytes : {uint8_t{0}, uint8_t{3}, uint8_t{9}, uint8_t{255}})
        {
            auto invalidLayout = layout;
            HiddenProcessField* fields[] = {&invalidLayout.Pid, &invalidLayout.CreateTime,
                &invalidLayout.ActiveThreads, &invalidLayout.ExitTime, &invalidLayout.Auxiliary,
                &invalidLayout.ProcessExiting, &invalidLayout.ProcessDelete, &invalidLayout.ProcessRundown};
            fields[fieldIndex]->Bytes = bytes;
            FixtureReader invalid;
            q = kernelOnly;
            q.After = ReadHiddenProcessLifetime(invalid, {}, invalidLayout, 100);
            check(QualifyHiddenProcess(100, discovery, q).Disposition == State::Unverified);
        }
    }
    FixtureReader listed;
    auto list = ReadHiddenProcessKernelView(listed, {}, layout);
    check(list.Complete && list.Entries.size() == 1 && list.Entries.at(100).Eprocess == kObject &&
        list.Entries.at(100).HasCreateTime && list.Entries.at(100).CreateTime == 123456);
    for (uint64_t address : {kHead, kHead + 8, kObject + 0x40, kObject + 0x48, kObject + 0x10})
    {
        FixtureReader unreadable;
        unreadable.Memory.erase(address);
        check(!ReadHiddenProcessKernelView(unreadable, {}, layout).Complete);
    }
    for (uint64_t invalidLink : {uint64_t{0}, kObject + 0x40, uint64_t{0x800000000000}, kHead + 1})
    {
        FixtureReader corrupt;
        corrupt.Memory[kObject + 0x40] = invalidLink;
        check(!ReadHiddenProcessKernelView(corrupt, {}, layout).Complete);
    }
    FixtureReader back;
    back.Memory[kObject + 0x48] = kObject;
    check(!ReadHiddenProcessKernelView(back, {}, layout).Complete);
    FixtureReader duplicate;
    const auto second = kObject + 0x1000;
    duplicate.Memory[kObject + 0x40] = second + 0x40;
    duplicate.Memory[second + 0x40] = kHead;
    duplicate.Memory[second + 0x48] = kObject + 0x40;
    duplicate.Memory[second + 0x10] = 100;
    duplicate.Memory[second + 0x18] = 789;
    duplicate.Memory[kHead + 8] = second + 0x40;
    check(!ReadHiddenProcessKernelView(duplicate, {}, layout).Complete);
    duplicate.Memory[second + 0x10] = 104;
    check(ReadHiddenProcessKernelView(duplicate, {}, layout).Complete);
    check(!ReadHiddenProcessKernelView(duplicate, {}, layout, 1).Complete);
    check(!ReadHiddenProcessKernelView(duplicate, {}, layout, 0).Complete);
    check(!ReadHiddenProcessKernelView(duplicate, {}, layout, 8193).Complete);
    for (uint64_t address : {kHead, kHead + 8})
    {
        FixtureReader changedHead;
        unsigned hits = 0;
        changedHead.OnRead = [&](FixtureReader& r, uint64_t readAddress)
        {
            if (readAddress == address && ++hits == 2)
            {
                r.Memory[address] += 0x1000;
            }
        };
        check(!ReadHiddenProcessKernelView(changedHead, {}, layout).Complete);
    }
    for (uint32_t stop = 1; stop <= 8; ++stop)
    {
        FixtureReader stopped;
        stopped.StopAfter = stop;
        check(!ReadHiddenProcessKernelView(stopped, {}, layout).Complete);
    }
    FixtureReader missingCreated;
    missingCreated.Memory.erase(kObject + 0x18);
    list = ReadHiddenProcessKernelView(missingCreated, {}, layout);
    check(list.Complete && !list.Entries.at(100).HasCreateTime);
    q = kernelOnly;
    q.KernelIdentity = list.Entries.at(100);
    expect(q, State::Unverified, L"identity_changed");
    // A qualified LA57 source accepts the extended high-half list. LA48 must not.
    FixtureReader extended;
    const uint64_t delta = 0x00ff000000000000ull;
    std::map<uint64_t, uint64_t> relocated;
    for (const auto& item : extended.Memory)
    {
        relocated[item.first - delta] = item.second >= kObject ? item.second - delta : item.second;
    }
    extended.Memory = std::move(relocated);
    auto extendedLayout = layout;
    extendedLayout.ListHead -= delta;
    check(ReadHiddenProcessKernelView(extended, AddressSpaceDescriptor::FromPagingLevels(5), extendedLayout).Complete);
    check(!ReadHiddenProcessKernelView(extended, AddressSpaceDescriptor::FromPagingLevels(4), extendedLayout).Complete);
    if (checks != nullptr)
    {
        *checks = count;
    }
    return passed;
}
