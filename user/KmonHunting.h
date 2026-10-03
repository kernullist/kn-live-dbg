#pragma once

#include "ObservationModel.h"
#include "KmonExecutablePages.h"
#include <algorithm>
#include <array>

struct KmonHuntReference
{
    ObservationContext Context;
    uint64_t Id = 0;
    uint64_t Address = 0;
    uint64_t Slot = 0;
    uint64_t Root = 0;
    uint64_t ReferenceTimestamp = 0;
    std::wstring Role;
    std::wstring PageSha256;
    bool PageComparable = false;
    bool SlotStable = false;
    bool PageExecutableVerified = false;
};

struct KmonHuntCase
{
    std::wstring Kind;
    ObservationRelation Relation = ObservationRelation::Address;
    KmonHuntReference Primary;
    KmonHuntReference Related;
    bool HasRelated = false;
};

inline bool KmonHuntOwnership(CodeOwnership ownership)
{
    return ownership == CodeOwnership::OwnedModified || ownership == CodeOwnership::UnownedExecutable ||
        ownership == CodeOwnership::OwnedUnexpectedExecutable;
}

inline bool KmonComparablePage(const std::vector<uint8_t>& bytes)
{
    if (bytes.size() != 4096)
    {
        return false;
    }
    std::array<bool, 256> seen = {};
    size_t distinct = 0;
    size_t nonPadding = 0;
    for (const auto value : bytes)
    {
        if (!seen[value])
        {
            seen[value] = true;
            ++distinct;
        }
        if (value != 0 && value != 0x90 && value != 0xCC && value != 0xFF)
        {
            ++nonPadding;
        }
    }
    return distinct >= 8 && nonPadding >= 64;
}

inline bool KmonHuntHash(const std::wstring& value)
{
    return value.size() == 64 && std::all_of(value.begin(), value.end(), [](wchar_t c)
    {
        return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f');
    });
}

inline bool KmonChannelRole(const std::wstring& role)
{
    return role == L"firmware_table_handler" || role == L"hive_get_cell" ||
        role == L"hive_release_cell" || role == L"hive_allocate" ||
        role == L"hive_free" || role == L"etw_logger_clock" ||
        role == L"callback:process:pre" || role == L"callback:thread:pre" ||
        role == L"callback:imageload:pre" || role == L"callback:registry:pre" ||
        role == L"callback:registry:post" || role == L"callback:ob:pre" ||
        role == L"callback:ob:post" || role == L"callback:minifilter:pre" ||
        role == L"callback:minifilter:post";
}

inline bool KmonPointerReference(const std::wstring& role)
{
    return KmonChannelRole(role) || role == L"iat" || role == L"tls_callback" ||
        role == L"kernel_callback_candidate" || role == L"vtable_candidate" ||
        role == L"manifest_vtable" || role == L"cfg_dispatch_slot" ||
        role == L"graphics_data_pointer_candidate" || role == L"instrumentation_callback";
}

inline bool KmonFreshStack(const ObservationIdentity& identity, uint64_t eventTime, uint64_t now)
{
    return !identity.BootId.empty() && identity.ProcessId > 4 && identity.CreateTime != 0 &&
        eventTime >= identity.CreateTime && eventTime <= now && now - eventTime <= 50000000ull;
}

inline bool KmonChannelCandidate(uint64_t target, uint64_t slot, bool layoutVerified)
{
    return layoutVerified && target >= 0xFFFF800000000000ull &&
        slot >= 0xFFFF800000000000ull && slot <= UINT64_MAX - sizeof(uint64_t);
}

// The caller serializes access. Cases are investigation leads, not verdicts.
class KmonHuntIndex
{
public:
    explicit KmonHuntIndex(size_t capacity = 512) : Capacity((std::max<size_t>)(1, (std::min<size_t>)(capacity, 512)))
    {
    }

    uint64_t Observe(KmonHuntReference reference)
    {
        const auto& context = reference.Context;
        const auto& identity = context.Identity;
        if (identity.BootId.empty() || identity.BootId.size() > 128 || reference.Role.empty() || reference.Role.size() > 64 ||
            context.MonotonicMs < LastMs || context.MonotonicMs == 0 || (reference.Address == 0 && !KmonPageRole(reference.Role)) ||
            (identity.ProcessId == 0 && reference.Address < 0xFFFF800000000000ull) ||
            (identity.ProcessId != 0 && ((reference.Address < 0x10000 && !KmonPageRole(reference.Role)) ||
                reference.Address >= 0x0000800000000000ull)) ||
            (!KmonHuntOwnership(context.Ownership) && !((context.Ownership == CodeOwnership::Unknown ||
                context.Ownership == CodeOwnership::OwnedUnverified) &&
                KmonPageRole(reference.Role) && reference.PageExecutableVerified && context.MappingGeneration != 0)) ||
            (identity.ProcessId != 0 && (identity.ProcessId <= 4 || identity.CreateTime == 0)))
        {
            ++Rejected;
            return 0;
        }
        LastMs = context.MonotonicMs;
        reference.PageComparable = reference.PageComparable && context.MappingGeneration != 0 && KmonHuntHash(reference.PageSha256);
        if (!reference.PageComparable)
        {
            reference.PageSha256.clear();
        }
        for (const auto& prior : References)
        {
            if (prior.Context.Identity.BootId == identity.BootId && prior.Context.Identity.ProcessId == identity.ProcessId &&
                prior.Context.Identity.CreateTime > identity.CreateTime)
            {
                ++Rejected;
                return 0;
            }
        }
        References.erase(std::remove_if(References.begin(), References.end(), [&](const auto& prior)
        {
            const auto& old = prior.Context;
            return LastMs - old.MonotonicMs > 30000 || old.Identity.BootId != identity.BootId ||
                (old.Identity.ProcessId == identity.ProcessId && old.Identity.CreateTime != identity.CreateTime) ||
                (old.Identity.SameInstance(identity) && (prior.Address & ~4095ull) == (reference.Address & ~4095ull) &&
                    old.MappingGeneration != 0 && context.MappingGeneration != 0 && old.MappingGeneration != context.MappingGeneration);
        }), References.end());
        for (auto prior = References.begin(); prior != References.end(); ++prior)
        {
            if (prior->Context.Identity.SameInstance(identity) && prior->Address == reference.Address &&
                prior->Root == reference.Root && prior->Slot == reference.Slot && prior->Role == reference.Role)
            {
                reference.Id = prior->Id;
                const uint64_t id = reference.Id;
                References.erase(prior);
                References.push_back(std::move(reference));
                return id;
            }
        }
        if (References.size() == Capacity)
        {
            const auto oldest = std::min_element(References.begin(), References.end(), [](const auto& a, const auto& b)
            {
                if (KmonPageRole(a.Role) != KmonPageRole(b.Role))
                {
                    return KmonPageRole(a.Role);
                }
                return a.Context.MonotonicMs < b.Context.MonotonicMs;
            });
            if (KmonPageRole(reference.Role) && !KmonPageRole(oldest->Role))
            {
                ++Rejected;
                return 0;
            }
            References.erase(oldest);
            ++Evicted;
        }
        reference.Id = ++NextId;
        References.push_back(std::move(reference));
        return NextId;
    }

    std::vector<KmonHuntCase> Cases(uint64_t now, size_t limit = 128) const
    {
        std::vector<KmonHuntCase> result;
        limit = (std::min<size_t>)(limit, 256);
        const auto fresh = [now](const auto& row)
        {
            return now >= row.Context.MonotonicMs && now - row.Context.MonotonicMs <= 30000;
        };
        // Exact content links come first. Time coincidence alone creates no edge.
        for (auto kernel = References.rbegin(); kernel != References.rend() && result.size() < limit; ++kernel)
        {
            if (kernel->Context.Identity.ProcessId != 0 || !KmonChannelRole(kernel->Role) ||
                !kernel->SlotStable || !kernel->PageComparable || !fresh(*kernel))
            {
                continue;
            }
            for (auto user = References.rbegin(); user != References.rend() && result.size() < limit; ++user)
            {
                if (user->Context.Identity.ProcessId == 0 || !fresh(*user) || !user->PageComparable ||
                    user->Context.Identity.BootId != kernel->Context.Identity.BootId || user->PageSha256 != kernel->PageSha256)
                {
                    continue;
                }
                const auto delta = kernel->Context.MonotonicMs > user->Context.MonotonicMs ?
                    kernel->Context.MonotonicMs - user->Context.MonotonicMs : user->Context.MonotonicMs - kernel->Context.MonotonicMs;
                const bool physical = delta <= 1000 && kernel->Context.PfnKnown && user->Context.PfnKnown &&
                    kernel->Context.Pfn == user->Context.Pfn;
                result.push_back({L"cross_domain_content", physical ? ObservationRelation::PhysicalPage : ObservationRelation::Content,
                    *kernel, *user, true});
            }
        }
        for (unsigned priority = 0; priority < 2 && result.size() < limit; ++priority)
        {
            for (auto row = References.rbegin(); row != References.rend() && result.size() < limit; ++row)
            {
                if (!fresh(*row) || KmonPageRole(row->Role) != (priority == 1))
                {
                    continue;
                }
                const bool kernel = row->Context.Identity.ProcessId == 0;
                std::wstring kind = KmonPageRole(row->Role) ?
                    (kernel ? L"kernel_executable_memory" : L"user_executable_memory") :
                    (kernel ? L"kernel_execution_reference" : L"user_execution_reference");
                if (row->Context.Ownership == CodeOwnership::Unknown)
                {
                    kind = L"executable_ownership_unknown";
                }
                else if (row->Context.Ownership == CodeOwnership::OwnedUnverified)
                {
                    kind = L"executable_image_unverified";
                }
                else if (row->Context.Ownership == CodeOwnership::OwnedUnexpectedExecutable)
                {
                    kind = L"image_executable_permission";
                }
                result.push_back({kind,
                    ObservationRelation::Address, *row, {}, false});
            }
        }
        return result;
    }

    size_t Size() const
    {
        return References.size();
    }

    void Retire(const ObservationIdentity& identity, uint64_t root, uint64_t slot, const std::wstring& role)
    {
        References.erase(std::remove_if(References.begin(), References.end(), [&](const auto& row)
        {
            return row.Context.Identity.SameInstance(identity) && (slot != 0 || row.Root == root) &&
                row.Slot == slot && row.Role == role;
        }), References.end());
    }

    uint64_t Evicted = 0;
    uint64_t Rejected = 0;

private:
    size_t Capacity;
    uint64_t LastMs = 0;
    uint64_t NextId = 0;
    std::vector<KmonHuntReference> References;
};

inline bool KmonHuntingPolicySelfTest()
{
    const uint64_t kernel = 0xFFFF800000002000ull;
    return KmonChannelCandidate(kernel, kernel + 8, true) &&
        !KmonChannelCandidate(kernel, kernel + 8, false) &&
        !KmonChannelCandidate(kernel, UINT64_MAX, true) &&
        !KmonChannelCandidate(0x1000, kernel, true) &&
        !KmonChannelCandidate(kernel, 0, true) &&
        KmonPointerReference(L"firmware_table_handler") &&
        KmonPointerReference(L"hive_get_cell") &&
        !KmonPointerReference(L"etw_provider_candidate") &&
        !KmonPointerReference(L"etw_stack_return");
}
