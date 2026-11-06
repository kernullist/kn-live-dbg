#include "../user/EvidencePrivacy.h"
#include "../user/AnalystSnapshot.h"
#include "../user/ContentHash.h"
#include <filesystem>
#include <iostream>
#include <io.h>
#include <fcntl.h>

int wmain(int argc, wchar_t** argv)
{
    _setmode(_fileno(stdout), _O_U8TEXT);
    if (argc < 3) { return 2; }
    const std::wstring action = argv[1], root = argv[2];
    if (action == L"init")
    {
        const bool efs = argc < 4 || std::wstring(argv[3]) != L"acl";
        const std::wstring stage = argc < 5 ? L"" : argv[4];
        const auto result = InitializeEvidencePrivateStore(root, efs, [&](const wchar_t* observed)
        {
            if (stage == observed)
            {
                std::wcout << L"[privacy.stage] " << observed << std::endl;
                std::string input;
                if (std::getline(std::cin, input) && input == "continue") { return; }
                ExitProcess(91); // The parent terminates only after observing this exact stage.
            }
        });
        std::wcout << EvidencePrivacyJson(result) << L"\n";
        return result.Status == L"ready" ? 0 : 1;
    }
    if (action == L"inspect")
    {
        const auto result = InspectEvidencePrivacy(root, argc > 3 && std::wstring(argv[3]) == L"audit");
        std::wcout << EvidencePrivacyJson(result) << L"\n";
        return result.Status == L"ready" ? 0 : 1;
    }
    if (action == L"guard")
    {
        EvidencePrivacyGuard guard; EvidencePrivacyReport report;
        if (!guard.Open(root, true, &report)) { return 1; }
        if (guard.Open(root, true, &report) || report.Issue != L"privacy_guard_already_open") { return 3; }
        // A rejected second Open must retain the first guard's leases.
        std::wcout << L"[privacy.stage] guarded" << std::endl;
        std::string input; std::getline(std::cin, input); return 0;
    }
    if (action == L"write")
    {
        const auto path = std::filesystem::path(root) / L"owned.kncase";
        const std::wstring value = L"{\"schema\":\"kn.privacy_fixture.v1\",\"bytes\":\"001122\"}";
        if (!SaveObservationJson(path.wstring(), value, nullptr)) { return 1; }
        std::wstring read;
        if (!ReadAnalystSnapshot(path.wstring(), &read, nullptr) || read != value) { return 1; }
        std::wcout << ContentHash::File(path.wstring()) << L"\n"; return 0;
    }
    return 2;
}
