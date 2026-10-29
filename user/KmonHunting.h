#pragma once

#include "ObservationModel.h"
#include "KmonExecutablePages.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <deque>
#include <random>

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

struct KmonHuntReceipt
{
    KmonHuntReference Reference;
    std::wstring Disposition;
    bool ArrivalInferred = false;
};

struct KmonHuntFilter
{
    bool HasPid = false;
    uint32_t ProcessId = 0;
    std::wstring Role;

    bool Matches(const KmonHuntReference& row) const
    {
        return (!HasPid || row.Context.Identity.ProcessId == ProcessId) &&
            (Role.empty() || row.Role == Role);
    }
};

struct KmonHuntQueryOptions
{
    size_t Limit = 256;
    std::wstring Cursor;
};

struct KmonHuntQueryPage
{
    std::vector<KmonHuntCase> Cases;
    std::wstring Status = L"ok";
    std::wstring NextCursor;
    uint64_t AsOfMs = 0;
    uint64_t Epoch = 0;
    uint64_t Revision = 0;
    size_t Offset = 0;
    size_t Limit = 256;
    size_t Matched = 0;
    size_t RetainedReferences = 0;
    size_t ReferenceCapacity = 0;

    size_t Omitted() const { return Status == L"ok" ? Matched - Offset - Cases.size() : 0; }
    bool Complete() const { return Status == L"ok" && Offset == 0 && Omitted() == 0; }
};

// A cursor is a bounded continuation contract, not an authorization credential.
// Include the exact filter and limit so changing scope cannot silently skip rows.
inline std::wstring KmonHuntQueryScope(const KmonHuntFilter& filter, size_t limit)
{
    std::wstring out = std::to_wstring(limit) + L":" + (filter.HasPid ? L"1:" : L"0:") +
        std::to_wstring(filter.HasPid ? filter.ProcessId : 0) + L":";
    constexpr wchar_t hex[] = L"0123456789abcdef";
    for (const wchar_t c : filter.Role)
    {
        const uint32_t unit = static_cast<uint32_t>(c);
        for (int shift = 28; shift >= 0; shift -= 4)
        {
            out += hex[(unit >> shift) & 15];
        }
    }
    return out;
}

inline bool KmonHuntCursorNumber(const std::wstring& cursor, size_t* at, uint64_t* value)
{
    *value = 0;
    const size_t start = *at;
    while (*at < cursor.size() && cursor[*at] != L':')
    {
        const auto c = cursor[(*at)++];
        if (c < L'0' || c > L'9' || *at - start > 20 ||
            *value > (UINT64_MAX - static_cast<uint64_t>(c - L'0')) / 10)
        {
            return false;
        }
        *value = *value * 10 + static_cast<uint64_t>(c - L'0');
    }
    return *at > start && *at < cursor.size() && cursor[(*at)++] == L':';
}

inline uint64_t KmonHuntQueryEpochSeed()
{
    // Avoid restarting the cursor namespace at 1 in each new analyst process.
    std::random_device random;
    return (((static_cast<uint64_t>(random()) << 32) | random()) & (UINT64_MAX >> 1)) | 1;
}

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

    uint64_t Observe(KmonHuntReference reference, uint64_t arrivalMs = 0, KmonHuntReceipt* receipt = nullptr)
    {
        AdvanceRevision();
        if (receipt != nullptr) { *receipt = {}; }
        const auto& context = reference.Context;
        const auto& identity = context.Identity;
        if (identity.BootId.empty() || identity.BootId.size() > 128 || reference.Role.empty() || reference.Role.size() > 64 ||
            context.Source.size() > 128 || context.DependencyGroup.size() > 128 || context.ReferenceSource.size() > 128 ||
            context.MonotonicMs == 0 || (reference.Address == 0 && !KmonPageRole(reference.Role)) ||
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
        reference.Context.ArrivalSequence = ++ArrivalSequence;
        reference.Context.ArrivalMonotonicMs = arrivalMs == 0 ?
            (std::max)(LastArrivalMs, context.MonotonicMs) : arrivalMs;
        LastArrivalMs = (std::max)(LastArrivalMs, reference.Context.ArrivalMonotonicMs);
        std::wstring disposition;
        const uint64_t id = ObserveCurrent(reference, &disposition);
        KmonHuntReceipt recorded{reference, disposition, arrivalMs == 0};
        if (Receipts.size() == 2048) { Receipts.pop_front(); ++ReceiptsEvicted; }
        Receipts.push_back(recorded);
        if (receipt != nullptr) { *receipt = std::move(recorded); }
        return id;
    }

    const std::deque<KmonHuntReceipt>& History() const { return Receipts; }
    uint64_t ReceiptsEvicted = 0;
    uint64_t IdentityConflicts = 0;
    uint64_t IdentityStatesEvicted = 0;

private:
    uint64_t ObserveCurrent(KmonHuntReference& reference, std::wstring* disposition)
    {
        const auto& context = reference.Context;
        const auto& identity = context.Identity;
        const auto skip = [&](const wchar_t* reason)
        {
            *disposition = reason;
            reference.Id = 0;
            ++Rejected;
            return uint64_t{0};
        };
        if (context.MonotonicMs > context.ArrivalMonotonicMs) { return skip(L"future_event"); }
        if (context.MonotonicMs < LastMs || context.ArrivalMonotonicMs - context.MonotonicMs > 30000)
        {
            return skip(L"historical_only");
        }
        const auto assertion = IdentityAssertions.find(identity.CanonicalKey());
        if (assertion != IdentityAssertions.end() && !assertion->second.CompatibleWith(identity))
        {
            ++IdentityConflicts;
            return skip(L"identity_conflict");
        }
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
                return skip(L"prior_process_instance");
            }
        }
        LastMs = context.MonotonicMs;
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
                References.push_back(reference);
                RememberIdentity(identity);
                *disposition = L"current";
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
                return skip(L"current_capacity");
            }
            References.erase(oldest);
            ++Evicted;
        }
        reference.Id = ++NextId;
        References.push_back(reference);
        RememberIdentity(identity);
        *disposition = L"current";
        return NextId;
    }

    void RememberIdentity(const ObservationIdentity& identity)
    {
        const auto key = identity.CanonicalKey();
        auto found = IdentityAssertions.find(key);
        if (found != IdentityAssertions.end()) { found->second.MergeAssertions(identity); return; }
        if (IdentityAssertions.size() == 512)
        {
            const auto unused = std::find_if(IdentityAssertions.begin(), IdentityAssertions.end(), [&](const auto& item)
            {
                return std::none_of(References.begin(), References.end(), [&](const auto& row)
                {
                    return row.Context.Identity.CanonicalKey() == item.first;
                });
            });
            if (unused != IdentityAssertions.end()) { IdentityAssertions.erase(unused); ++IdentityStatesEvicted; }
        }
        IdentityAssertions.emplace(key, identity);
    }

public:

    KmonHuntQueryPage Query(uint64_t now, const KmonHuntFilter& filter = {},
        const KmonHuntQueryOptions& options = {}) const
    {
        KmonHuntQueryPage page;
        page.AsOfMs = now;
        page.Epoch = QueryEpoch;
        page.Revision = Revision;
        page.Limit = options.Limit;
        page.RetainedReferences = References.size();
        page.ReferenceCapacity = Capacity;
        if (options.Limit == 0 || options.Limit > 256 || filter.Role.size() > 128 ||
            filter.Role.find(L'\0') != std::wstring::npos)
        {
            page.Status = L"invalid_query";
            return page;
        }
        const auto scope = KmonHuntQueryScope(filter, options.Limit);
        if (!options.Cursor.empty())
        {
            size_t at = 0;
            uint64_t epoch = 0, revision = 0, asOf = 0, offset = 0;
            if (options.Cursor.size() > 1200 || options.Cursor.compare(0, 3, L"q1:") != 0 ||
                (at = 3, !KmonHuntCursorNumber(options.Cursor, &at, &epoch)) ||
                !KmonHuntCursorNumber(options.Cursor, &at, &revision) ||
                !KmonHuntCursorNumber(options.Cursor, &at, &asOf) ||
                !KmonHuntCursorNumber(options.Cursor, &at, &offset) ||
                offset == 0 || offset > 66048 || options.Cursor.substr(at) != scope)
            {
                page.Status = L"invalid_cursor";
                return page;
            }
            if (epoch != QueryEpoch || revision != Revision || Revision == UINT64_MAX ||
                asOf > now || now - asOf > 30000)
            {
                page.Status = L"stale_cursor";
                return page;
            }
            page.AsOfMs = asOf;
            page.Offset = static_cast<size_t>(offset);
        }
        const auto fresh = [&page](const auto& row)
        {
            return page.AsOfMs >= row.Context.MonotonicMs && page.AsOfMs - row.Context.MonotonicMs <= 30000;
        };
        const auto append = [&](const std::wstring& kind, ObservationRelation relation,
            const KmonHuntReference& primary, const KmonHuntReference* related)
        {
            if (!filter.Matches(primary) && (related == nullptr || !filter.Matches(*related)))
            {
                return;
            }
            if (page.Matched++ >= page.Offset && page.Cases.size() < page.Limit)
            {
                page.Cases.push_back({kind, relation, primary, related == nullptr ? KmonHuntReference{} : *related,
                    related != nullptr});
            }
        };
        // Exact content links come first. Time coincidence alone creates no edge.
        for (auto kernel = References.rbegin(); kernel != References.rend(); ++kernel)
        {
            if (kernel->Context.Identity.ProcessId != 0 || !KmonChannelRole(kernel->Role) ||
                !kernel->SlotStable || !kernel->PageComparable || !fresh(*kernel))
            {
                continue;
            }
            for (auto user = References.rbegin(); user != References.rend(); ++user)
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
                append(L"cross_domain_content", physical ? ObservationRelation::PhysicalPage : ObservationRelation::Content,
                    *kernel, &*user);
            }
        }
        for (unsigned priority = 0; priority < 2; ++priority)
        {
            for (auto row = References.rbegin(); row != References.rend(); ++row)
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
                append(kind, ObservationRelation::Address, *row, nullptr);
            }
        }
        if (page.Offset > page.Matched || (page.Offset != 0 && page.Offset == page.Matched))
        {
            page.Status = L"invalid_cursor";
            page.Cases.clear();
        }
        else if (page.Omitted() != 0)
        {
            page.NextCursor = L"q1:" + std::to_wstring(QueryEpoch) + L":" + std::to_wstring(Revision) +
                L":" + std::to_wstring(page.AsOfMs) + L":" + std::to_wstring(page.Offset + page.Cases.size()) + L":" + scope;
        }
        return page;
    }

    std::vector<KmonHuntCase> Cases(uint64_t now, size_t limit = 128) const
    {
        return limit == 0 ? std::vector<KmonHuntCase>{} : Query(now, {}, {(std::min<size_t>)(limit, 256), {}}).Cases;
    }

    size_t Size() const
    {
        return References.size();
    }

    void Retire(const ObservationIdentity& identity, uint64_t root, uint64_t slot, const std::wstring& role)
    {
        AdvanceRevision();
        const auto assertion = IdentityAssertions.find(identity.CanonicalKey());
        if (assertion != IdentityAssertions.end() && !assertion->second.CompatibleWith(identity)) { return; }
        References.erase(std::remove_if(References.begin(), References.end(), [&](const auto& row)
        {
            return row.Context.Identity.SameInstance(identity) && (slot != 0 || row.Root == root) &&
                row.Slot == slot && row.Role == role;
        }), References.end());
    }

    uint64_t Evicted = 0;
    uint64_t Rejected = 0;

private:
    void AdvanceRevision() { if (Revision != UINT64_MAX) { ++Revision; } }
    inline static std::atomic<uint64_t> NextQueryEpoch{KmonHuntQueryEpochSeed()};
    uint64_t QueryEpoch = NextQueryEpoch.fetch_add(1);
    uint64_t Revision = 0;
    size_t Capacity;
    uint64_t LastMs = 0;
    uint64_t LastArrivalMs = 0;
    uint64_t ArrivalSequence = 0;
    std::deque<KmonHuntReceipt> Receipts;
    std::map<ObservationIdentity::Key, ObservationIdentity> IdentityAssertions;
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
