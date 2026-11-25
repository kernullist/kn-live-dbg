// Driver-free fixture for the production snapshot file writer, reader and diff.
#include "../user/SnapshotDiff.h"
#include "../user/SnapshotJson.h"
#include <Windows.h>
#include <iostream>

namespace
{
    bool CheckBootPolicy()
    {
        SnapshotDiffOptions options;
        SnapshotDocument first, second;
        first.BootId = second.BootId = std::wstring(32, L'1');
        first.BootSource = second.BootSource = SnapshotBootSource::LocalReceipt;
        const auto expect = [&](bool same, const wchar_t* basis) {
            SnapshotDiffResult result;
            std::wstring error;
            return BuildSnapshotDiff(first, second, options, &result, &error) && result.SameBoot == same && result.BootBasis == basis;
        };
        if (!expect(true, L"local_boot_receipts")) { return false; }
        second.BootId.assign(32, L'2');
        if (!expect(false, L"different_local_boots")) { return false; }
        second.BootId.assign(32, L'0');
        if (!expect(false, L"origin_unverified")) { return false; }
        first.BootSource = second.BootSource = SnapshotBootSource::LocalCapture;
        options.InMemoryBaseline = true;
        second.BootId = L"boot-unknown";
        if (!expect(true, L"collector_session")) { return false; }
        second.BootId.assign(32, L'2');
        if (!expect(false, L"different_local_boots")) { return false; }
        second.SameBootOnly = false;
        if (!expect(false, L"comparison_disabled")) { return false; }
        second.SameBootOnly = true;
        second.BootId = first.BootId;
        second.BootSource = SnapshotBootSource::NoReceipt;
        return expect(false, L"origin_unverified");
    }

    bool Capture(const wchar_t* path, bool after)
    {
        SnapshotDocument doc;
        doc.Schema = L"kn-live-dbg.snapshot.v1";
        doc.BootId = SnapshotCurrentBootId();
        doc.BootSource = SnapshotBootSource::LocalCapture;
        doc.TimestampUtc = SnapshotCurrentUtcTimestamp();
        doc.Label = after ? L"after" : L"before";
        FILETIME created{}, exit{}, kernel{}, user{};
        if (!GetProcessTimes(GetCurrentProcess(), &created, &exit, &kernel, &user)) { return false; }
        SnapshotProcessRecord self;
        self.ProcessId = GetCurrentProcessId();
        self.HasCreateTime = true;
        self.CreateTime = (uint64_t(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        self.ImageName = L"snapshot-boot-selftest.exe";
        self.Identity = BuildSnapshotProcessIdentity(self, nullptr);
        doc.Processes.push_back(self);
        // The fixed rows exercise boot-scoped transitions without a live device.
        for (const auto domain : {L"cpu-state", L"pool", L"vad-dkom"})
        {
            SnapshotRecord row;
            row.Domain = domain;
            row.Identity = L"fixture";
            row.Display = L"fixture";
            row.Risk = L"info";
            row.Evidence[L"value"] = after ? L"b" : L"a";
            if (after) { row.Tags = {L"wx", L"hidden-pte"}; }
            doc.Records.push_back(row);
        }
        std::wstring error;
        return WriteSnapshotJsonFile(path, doc, &error);
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc == 2 && std::wstring(argv[1]) == L"policy-check") { return CheckBootPolicy() ? 0 : 1; }
    if (argc == 3 && std::wstring(argv[1]) == L"oversize")
    {
        std::wstring original, error;
        if (!ReadSnapshotTextFile(argv[2], &original, &error) || original != L"snapshot-size-fixture") { return 2; }
        SnapshotDocument doc;
        doc.Metadata[L"fixture"].assign(23u << 20, L'\uac00');
        bool receipt = true;
        return !WriteSnapshotJsonFile(argv[2], doc, &error, &receipt) && !receipt &&
            error.find(L"64 MiB") != std::wstring::npos ? 0 : 1;
    }
    if (argc != 4) { return 2; }
    const std::wstring action = argv[1];
    if (action == L"capture" && (std::wstring(argv[3]) == L"before" || std::wstring(argv[3]) == L"after"))
        { return Capture(argv[2], std::wstring(argv[3]) == L"after") ? 0 : 1; }
    SnapshotDocument first, second;
    std::wstring error;
    if (!ReadSnapshotJsonFile(argv[2], &first, &error)) { return 1; }
    if (action == L"resave") { return WriteSnapshotJsonFile(argv[3], first, &error) ? 0 : 1; }
    if (action != L"diff" && action != L"session-option") { return 2; }
    if (!ReadSnapshotJsonFile(argv[3], &second, &error)) { return 1; }
    SnapshotDiffOptions options;
    options.InMemoryBaseline = action == L"session-option";
    SnapshotDiffResult result;
    if (!BuildSnapshotDiff(first, second, options, &result, &error)) { return 1; }
    std::wcout << result.BootBasis << L" " << result.SameBoot << L" " << result.Escalated << L" "
        << SnapshotBootSourceName(first.BootSource) << L" " << SnapshotBootSourceName(second.BootSource) << L"\n";
    return 0;
}
