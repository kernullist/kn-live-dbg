#pragma once

#include "../user/ExecutionEvidenceJson.h"

#include <iostream>
#include <vector>

inline NativeExecutionEvidence ExecutionEvidenceFixture(NativeExecutionEvidenceKind kind)
{
    NativeExecutionEvidence input;
    input.Kind = kind;
    input.ProcessId = 100;
    input.ProcessCreateTime = 1000;
    input.ProcessIdentityStable = true;
    input.ThreadId = 104;
    input.ThreadCreateTime = 1100;
    input.CaptureTime = 1200;
    input.Address = 0x20000;
    return input;
}

inline std::wstring ExecutionEvidenceFixturesJson()
{
    std::wstring out = L"[";
    for (uint8_t i = 0; i < 10; ++i)
    {
        if (i != 0)
        {
            out += L",";
        }
        auto input = ExecutionEvidenceFixture(static_cast<NativeExecutionEvidenceKind>(i));
        if (i == 9)
        {
            input.Kind = NativeExecutionEvidenceKind::CapturedThreadContext;
            input.CaptureTime = 0;
            input.ThreadCreateTime = 0;
        }
        out += NativeExecutionEvidenceJson(input, L"synthetic \"native\" source");
    }
    out += L"]";
    return out;
}

inline bool ExecutionEvidenceSelfTest()
{
    uint32_t checks = 0;
    uint32_t failed = 0;
    const auto check = [&](bool value)
    {
        ++checks;
        if (!value)
        {
            ++failed;
            std::cerr << "execution evidence control failed: " << checks << "\n";
        }
    };
    for (unsigned i = 0; i < 256; ++i)
    {
        const auto input = ExecutionEvidenceFixture(static_cast<NativeExecutionEvidenceKind>(i));
        const auto value = AssessNativeExecutionEvidence(input);
        check(!value.ExecutionObserved && !value.ActorAttributed);
        check(std::wstring(value.Level) != L"X2" && std::wstring(value.Level) != L"X3" && std::wstring(value.Level) != L"X4");
        if (i >= static_cast<unsigned>(NativeExecutionEvidenceKind::Unknown))
        {
            check(std::wstring(value.Level) == L"unqualified");
        }
    }
    const wchar_t* expected[] = {L"X0", L"X1", L"X1", L"X1", L"X0", L"X1", L"X1", L"X0"};
    for (uint8_t i = 0; i < 8; ++i)
    {
        const auto base = ExecutionEvidenceFixture(static_cast<NativeExecutionEvidenceKind>(i));
        check(std::wstring(AssessNativeExecutionEvidence(base).Level) == expected[i]);
        for (unsigned failure = 0; failure < 7; ++failure)
        {
            auto input = base;
            switch (failure)
            {
            case 0:
                input.ProcessId = 0;
                break;
            case 1:
                input.ProcessCreateTime = 0;
                break;
            case 2:
                input.ProcessIdentityStable = false;
                break;
            case 3:
                input.Address = 0;
                break;
            case 4:
                input.Address = 0x800000000000ull;
                break;
            case 5:
                input.PointerBytes = 3;
                break;
            case 6:
                input.PointerBytes = 4;
                input.Address = 0x100000000ull;
                break;
            }
            check(std::wstring(AssessNativeExecutionEvidence(input).Level) == L"unqualified");
        }
    }
    for (const auto kind : {NativeExecutionEvidenceKind::ThreadStart, NativeExecutionEvidenceKind::RawStackValue,
        NativeExecutionEvidenceKind::QueuedApcRoutine, NativeExecutionEvidenceKind::CapturedThreadContext,
        NativeExecutionEvidenceKind::SavedTrapContext})
    {
        auto input = ExecutionEvidenceFixture(kind);
        input.ThreadId = 0;
        check(std::wstring(AssessNativeExecutionEvidence(input).Level) == L"unqualified");
    }
    auto context = ExecutionEvidenceFixture(NativeExecutionEvidenceKind::CapturedThreadContext);
    context.ThreadCreateTime = 0;
    check(std::wstring(AssessNativeExecutionEvidence(context).Level) == L"unqualified");
    context = ExecutionEvidenceFixture(NativeExecutionEvidenceKind::CapturedThreadContext);
    context.CaptureTime = 0;
    check(std::wstring(AssessNativeExecutionEvidence(context).Level) == L"unqualified");
    context.CaptureTime = context.ThreadCreateTime - 1;
    check(std::wstring(AssessNativeExecutionEvidence(context).Level) == L"unqualified");
    context.CaptureTime = context.ThreadCreateTime;
    check(std::wstring(AssessNativeExecutionEvidence(context).Level) == L"X1");
    context.AddressSpace = AddressSpaceDescriptor::FromPagingLevels(5);
    context.Address = 0x1000000000000ull;
    check(std::wstring(AssessNativeExecutionEvidence(context).Level) == L"X1");
    context.AddressSpace = AddressSpaceDescriptor::FromPagingLevels(4);
    check(std::wstring(AssessNativeExecutionEvidence(context).Level) == L"unqualified");
    std::cout << "[execution.evidence] passed=" << checks - failed << " failed=" << failed << "\n";
    return failed == 0;
}
