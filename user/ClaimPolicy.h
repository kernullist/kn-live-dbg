#pragma once

#include <algorithm>
#include <string>
#include <vector>

namespace claim_policy
{
    enum class State { Supported, Contradicted, Unfulfilled, NotApplicable };
    enum class Observation { Missing, Met, Contrary };
    inline const wchar_t* Name(State value)
    {
        switch (value)
        {
        case State::Supported: return L"supported";
        case State::Contradicted: return L"contradicted";
        case State::NotApplicable: return L"not_applicable";
        default: return L"unfulfilled";
        }
    }
    struct Evidence
    {
        std::wstring Sha256, Pointer;
        bool Valid() const
        {
            return Sha256.size() == 64 && Sha256.find_first_not_of(L"0123456789abcdef") == std::wstring::npos &&
                !Pointer.empty() && Pointer.size() <= 512 && Pointer.front() == L'/' && Pointer.find(L'\0') == std::wstring::npos;
        }
    };
    struct Requirement
    {
        std::wstring Id, NextObservation, Mode;
        bool Gate = false;
    };
    struct Policy { std::wstring Id; std::vector<Requirement> Requires; };
    struct Fact { std::wstring RequirementId; Observation Value = Observation::Missing; Evidence Origin; };
    struct Result
    {
        State Status = State::Unfulfilled;
        std::wstring Issue;
        std::vector<Fact> Supports, Contradicts;
        std::vector<Requirement> Missing;
        Evidence NotApplicableBasis;
    };

    // Policies are code-owned; external assertions are never accepted as facts.
    // Gates qualify the observation scope before any negative or N/A conclusion.
    inline Result Evaluate(const Policy& policy, const std::vector<Fact>& facts, const Evidence& notApplicable = {})
    {
        Result result;
        if (policy.Id.empty() || policy.Requires.empty() || policy.Requires.size() > 32 || facts.size() > 32)
        { result.Issue = L"invalid_policy_or_fact_bound"; return result; }
        for (size_t i = 0; i < policy.Requires.size(); ++i)
        {
            const auto& id = policy.Requires[i].Id;
            if (id.empty() || std::any_of(policy.Requires.begin(), policy.Requires.begin() + i,
                [&](const auto& r) { return r.Id == id; }))
            { result.Issue = L"invalid_or_duplicate_requirement"; return result; }
        }
        std::wstring capture = notApplicable.Valid() ? notApplicable.Sha256 : L"";
        for (size_t i = 0; i < facts.size(); ++i)
        {
            const auto& id = facts[i].RequirementId;
            if (std::none_of(policy.Requires.begin(), policy.Requires.end(), [&](const auto& r) { return r.Id == id; }) ||
                std::any_of(facts.begin(), facts.begin() + i, [&](const auto& f) { return f.RequirementId == id; }))
            { result.Issue = L"unknown_or_duplicate_fact"; return result; }
            if (facts[i].Origin.Valid())
            {
                if (!capture.empty() && capture != facts[i].Origin.Sha256)
                { result.Issue = L"mixed_capture_evidence"; return result; }
                capture = facts[i].Origin.Sha256;
            }
        }
        bool gates = true;
        for (const auto& requirement : policy.Requires)
        {
            const auto found = std::find_if(facts.begin(), facts.end(), [&](const auto& f) { return f.RequirementId == requirement.Id; });
            const bool known = found != facts.end() && found->Origin.Valid();
            if (known && found->Value == Observation::Met) { result.Supports.push_back(*found); }
            else if (!requirement.Gate && known && found->Value == Observation::Contrary) { result.Contradicts.push_back(*found); }
            else { result.Missing.push_back(requirement); }
            if (requirement.Gate && (!known || found->Value != Observation::Met)) { gates = false; }
        }
        if (!gates) { result.Issue = L"observation_scope_unqualified"; }
        else if (notApplicable.Valid())
        { result.Status = State::NotApplicable; result.NotApplicableBasis = notApplicable; result.Missing.clear(); }
        else if (!result.Contradicts.empty()) { result.Status = State::Contradicted; }
        else if (result.Missing.empty()) { result.Status = State::Supported; }
        return result;
    }
}
