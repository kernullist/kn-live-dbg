#include "kmon-hunting-selftest.h"
#include "../user/ExecutableImageVerifier.h"

#include <filesystem>
#include <fstream>
#include <limits>
#include <memory>

namespace
{
    bool Unsigned(const std::wstring& text, uint64_t* value)
    {
        *value = 0;
        if (text.empty() || text.size() > 20)
        {
            return false;
        }
        for (const auto ch : text)
        {
            if (ch < L'0' || ch > L'9' || *value > (UINT64_MAX - static_cast<uint64_t>(ch - L'0')) / 10)
            {
                return false;
            }
            *value = *value * 10 + static_cast<uint64_t>(ch - L'0');
        }
        return true;
    }

    bool Number(const std::wstring& json, const wchar_t* key, uint64_t* value)
    {
        std::wstring raw;
        return (mcpjson::GetString(json, key, &raw) || mcpjson::FindRawValue(json, key, &raw)) && Unsigned(raw, value);
    }

    bool Boolean(const std::wstring& json, const wchar_t* key, bool* value)
    {
        std::wstring raw;
        if (!mcpjson::FindRawValue(json, key, &raw) || (raw != L"true" && raw != L"false"))
        {
            return false;
        }
        *value = raw == L"true";
        return true;
    }

    bool ParseReference(const std::wstring& json, KmonHuntReference* row)
    {
        uint64_t pid = 0;
        std::wstring ownership;
        auto& context = row->Context;
        if (!mcpjson::ValidateDocument(json) ||
            !mcpjson::GetString(json, L"boot_id", &context.Identity.BootId) ||
            !Number(json, L"pid", &pid) || pid > UINT32_MAX ||
            !Number(json, L"create_time", &context.Identity.CreateTime) ||
            !Number(json, L"eprocess", &context.Identity.Eprocess) ||
            !Number(json, L"address", &row->Address) || !Number(json, L"root", &row->Root) ||
            !Number(json, L"slot", &row->Slot) || !Number(json, L"mapping_generation", &context.MappingGeneration) ||
            !Number(json, L"observed_ms", &context.MonotonicMs) || !Number(json, L"observed_at", &context.Timestamp) ||
            !Number(json, L"reference_at", &row->ReferenceTimestamp) ||
            !Number(json, L"pfn", &context.Pfn) || !Boolean(json, L"pfn_known", &context.PfnKnown) ||
            !Boolean(json, L"slot_stable", &row->SlotStable) || !Boolean(json, L"page_comparable", &row->PageComparable) ||
            !mcpjson::GetString(json, L"role", &row->Role) || !mcpjson::GetString(json, L"ownership", &ownership) ||
            !mcpjson::GetString(json, L"source", &context.Source) ||
            !mcpjson::GetString(json, L"dependency_group", &context.DependencyGroup) ||
            !mcpjson::GetString(json, L"page_sha256", &row->PageSha256) ||
            context.Source.size() > 128 || context.DependencyGroup.size() > 128 || row->PageSha256.size() > 64)
        {
            return false;
        }
        context.Identity.ProcessId = static_cast<uint32_t>(pid);
        std::wstring pageVerified;
        if (mcpjson::FindRawValue(json, L"page_executable_verified", &pageVerified) &&
            !Boolean(json, L"page_executable_verified", &row->PageExecutableVerified))
        {
            return false;
        }
        std::wstring sessionRaw;
        const bool hasSession = mcpjson::FindRawValue(json, L"session_id", &sessionRaw);
        const bool hasSessionKnown = mcpjson::FindRawValue(json, L"session_known", &sessionRaw);
        uint64_t session = 0;
        if (hasSession != hasSessionKnown || (hasSession &&
            (!Number(json, L"session_id", &session) || session > UINT32_MAX ||
                !Boolean(json, L"session_known", &context.Identity.SessionKnown))))
        {
            return false;
        }
        context.Identity.SessionId = static_cast<uint32_t>(session);
        if (ownership == L"owned_modified")
        {
            context.Ownership = CodeOwnership::OwnedModified;
        }
        else if (ownership == L"unowned_executable")
        {
            context.Ownership = CodeOwnership::UnownedExecutable;
        }
        else if (ownership == L"owned_verified")
        {
            context.Ownership = CodeOwnership::OwnedVerified;
        }
        else if (ownership == L"unknown")
        {
            context.Ownership = CodeOwnership::Unknown;
        }
        else if (ownership == L"owned_unverified")
        {
            context.Ownership = CodeOwnership::OwnedUnverified;
        }
        else if (ownership == L"owned_unexpected_executable")
        {
            context.Ownership = CodeOwnership::OwnedUnexpectedExecutable;
        }
        else
        {
            return false;
        }
        return true;
    }

    int Replay(const wchar_t* path)
    {
        if (std::filesystem::file_size(path) > 1024 * 1024)
        {
            return 2;
        }
        std::ifstream input(path, std::ios::binary);
        if (!input)
        {
            return 2;
        }
        KmonHuntIndex index;
        std::string line;
        uint64_t now = 0;
        size_t count = 0;
        const auto consume = [&]()
        {
            if (line.empty() || line.size() > 8192 || ++count > 4096)
            {
                return false;
            }
            KmonHuntReference row;
            if (!ParseReference(mcpjson::Utf8ToWide(line), &row) || row.Context.MonotonicMs < now)
            {
                return false;
            }
            now = row.Context.MonotonicMs;
            index.Retire(row.Context.Identity, row.Root, row.Slot, row.Role);
            index.Observe(std::move(row));
            line.clear();
            return true;
        };
        char ch = 0;
        size_t total = 0;
        while (input.get(ch))
        {
            if (++total > 1024 * 1024)
            {
                return 2;
            }
            if (ch == '\n')
            {
                if (!consume())
                {
                    return 2;
                }
            }
            else
            {
                if (line.size() == 8192)
                {
                    return 2;
                }
                line.push_back(ch);
            }
        }
        if (!line.empty() && !consume())
        {
            return 2;
        }
        if (!input.eof() || count == 0)
        {
            return 2;
        }
        std::cout << mcpjson::WideToUtf8(KmonHuntCasesJson(index.Cases(now), now, index.Evicted, index.Rejected,
            L"offline_unverified")) << "\n";
        return 0;
    }

    int ImageProbe(uint32_t pid, const wchar_t* path, uint64_t base)
    {
        HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        const std::unique_ptr<void, decltype(&CloseHandle)> owner(process, &CloseHandle);
        executable_image::DiskPeMetadata reference;
        const ObservationReader reader = [process](uint64_t address, size_t count, std::vector<uint8_t>* bytes)
        {
            bytes->resize(count);
            SIZE_T read = 0;
            return process != nullptr && ReadProcessMemory(process, reinterpret_cast<LPCVOID>(address), bytes->data(), count, &read) && read == count;
        };
        if (!executable_image::ReadDiskPeMetadata(path, &reference, nullptr) || !QualifyExecutableReference(reference, base, reader, nullptr))
        {
            return 2;
        }
        ExecutableSweep sweep;
        if (!sweep.Initialize(reference))
        {
            return 2;
        }
        uint64_t modified = 0;
        for (size_t i = 0; i < 4096 && !sweep.Coverage.TraversalComplete; ++i)
        {
            const auto pages = AdvanceExecutableSweep(path, reference, base, reader, 1, GetTickCount64(), &sweep);
            for (const auto& page : pages)
            {
                if (page.Ownership == CodeOwnership::OwnedModified)
                {
                    ++modified;
                }
            }
        }
        std::cout << "{\"scope\":\"main_image_executable_pages\",\"modified_pages\":" << modified
            << ",\"complete\":" << (sweep.Coverage.Complete() ? "true" : "false") << "}\n";
        return sweep.Coverage.Complete() ? 0 : 2;
    }
}

int wmain(int argc, wchar_t** argv)
{
    int result = 2;
    try
    {
        if (argc == 2 && std::wstring(argv[1]) == L"--self-test")
        {
            result = KmonHuntingSelfTest() ? 0 : 1;
        }
        else if (argc == 3 && std::wstring(argv[1]) == L"--replay")
        {
            result = Replay(argv[2]);
        }
        else if (argc == 3 && std::wstring(argv[1]) == L"--fixture")
        {
            std::ofstream out(argv[2], std::ios::binary);
            out << mcpjson::WideToUtf8(KmonHuntReferenceJson(HuntFixture(0))) << "\n";
            out << mcpjson::WideToUtf8(KmonHuntReferenceJson(HuntFixture(45, 101))) << "\n";
            result = out.good() ? 0 : 2;
        }
        else if (argc == 5 && std::wstring(argv[1]) == L"--image")
        {
            uint64_t pid = 0;
            uint64_t base = 0;
            if (Unsigned(argv[2], &pid) && pid > 4 && pid <= UINT32_MAX && Unsigned(argv[4], &base))
            {
                result = ImageProbe(static_cast<uint32_t>(pid), argv[3], base);
            }
        }
    }
    catch (const std::exception&)
    {
        result = 2;
    }
    if (result == 2)
    {
        std::cerr << "[kmon.hunting] invalid input, incomplete scan, or IO failure\n";
    }
    return result;
}
