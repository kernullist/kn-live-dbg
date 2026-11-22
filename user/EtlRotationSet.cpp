#include "EtlProfile.h"
#include "ArtifactOutput.h"
#include "EtlCaptureStatement.h"
#include "SavedEtlInput.h"
#include "RuntimeCapabilities.h"
#include "TraceJsonFields.h"

#include <array>
#include <iostream>

namespace
{
    using namespace etl_profile;
    using mcpjson::Quote;
    constexpr size_t MaxArgs = 6 + 3 * MaxRotationMembers;

    struct Options
    {
        std::wstring Digest;
        StatementAuthority Authority;
        std::array<std::wstring, MaxRotationMembers + 1> Paths;
        uint32_t Highest = 0;
    };

    bool Parse(const std::vector<std::wstring>& args, Options& options)
    {
        if (args.size() < 6 || args.size() > MaxArgs || (args.size() - 6) % 3 || args[0].empty() ||
            args[1] != L"--sha256" || !NormalizeDigest(args[2], options.Digest) || args[3] != L"--authority" ||
            !ParseStatementAuthority(args[4], args[5], options.Authority)) { return false; }
        for (size_t i = 6; i < args.size(); i += 3)
        {
            uint64_t value = 0;
            if (args[i] != L"--member" || !trace_json::Decimal(args[i + 1], &value) || !value || value > MaxRotationMembers ||
                args[i + 2].empty() || !options.Paths[static_cast<size_t>(value)].empty()) { return false; }
            const auto ordinal = static_cast<uint32_t>(value);
            options.Paths[ordinal] = args[i + 2];
            options.Highest = (std::max)(options.Highest, ordinal);
        }
        return true;
    }

    const wchar_t* JsonBool(bool value) { return value ? L"true" : L"false"; }

    std::wstring NumberOrNull(std::optional<uint32_t> value)
    {
        return value ? std::to_wstring(*value) : L"null";
    }

    struct MemberRead
    {
        const RotationMember* Declared = nullptr;
        SavedEtlInput Input;
        SavedEtlCapabilityProbe Probe;
        std::optional<uint64_t> ObservedBytes;
        DWORD OpenError = ERROR_SUCCESS;
        const wchar_t* Status = L"not_in_inventory";
        bool Probed = false, Verified = false;

        void Read(const std::wstring& path)
        {
            if (!Declared) { Status = path.empty() ? L"not_in_inventory" : L"unexpected_input"; return; }
            if (path.empty()) { Status = L"not_supplied"; return; }
            if (!Input.OpenMember(path, Declared->Bytes, ObservedBytes, OpenError))
            {
                Status = ObservedBytes && *ObservedBytes != Declared->Bytes ? L"size_mismatch" : L"source_unavailable";
                return;
            }
            Probe.ExpectedSha256 = Declared->Sha256;
            Input.Probe(Probe);
            Probed = true;
            if (!Probe.Coverage) { Status = Probe.Status; return; }
            Verified = (Probe.Coverage->LogMode & EVENT_TRACE_FILE_MODE_NEWFILE) != 0;
            Status = Verified ? L"verified" : L"not_rotating";
        }

        void Recheck()
        {
            if (Probed && !Input.Revalidated())
            {
                Status = L"source_changed";
                Verified = false;
                Probed = false;
            }
        }

        std::wstring Json(uint32_t ordinal, bool supplied) const
        {
            return L"{\"ordinal\":" + std::to_wstring(ordinal) + L",\"supplied\":" + JsonBool(supplied) +
                L",\"expected_sha256\":" + (Declared ? Quote(Declared->Sha256) : L"null") +
                L",\"expected_bytes\":" + (Declared ? std::to_wstring(Declared->Bytes) : L"null") +
                L",\"observed_bytes\":" + (ObservedBytes ? std::to_wstring(*ObservedBytes) : L"null") +
                L",\"open_win32_error\":" + (OpenError ? std::to_wstring(OpenError) : L"null") +
                L",\"status\":" + Quote(Status) + L",\"probe\":" + (Probed ? Probe.Json() : L"null") + L"}";
        }
    };

    std::wstring Report(const Options& options, const std::wstring& actual, const wchar_t* status,
        const RotationInventory& inventory, DWORD openError = ERROR_SUCCESS)
    {
        const bool accepted = inventory.Accepted;
        return L"{\"schema\":\"kn.etl_rotation_set.v1\",\"status\":" + Quote(status) +
            L",\"expected_inventory_sha256\":" + Quote(options.Digest) +
            L",\"inventory_sha256\":" + (actual.empty() ? L"null" : Quote(actual)) +
            L",\"inventory_open_win32_error\":" + (openError ? std::to_wstring(openError) : L"null") +
            L",\"trusted_key_sha256\":" + Quote(options.Authority.Sha256) + L",\"expected_role\":" + Quote(options.Authority.Role) +
            L",\"signature_verified\":" + (inventory.SignatureValid ? JsonBool(*inventory.SignatureValid) : L"null") +
            L",\"inventory_authenticated\":" + JsonBool(accepted) + L",\"signed_role\":" + (accepted ? Quote(inventory.Role) : L"null") +
            L",\"session_id\":" + (accepted ? inventory.SessionJson : L"null") +
            L",\"controller_stop\":" + (!accepted || !inventory.StopWin32 ? L"null" :
                L"{\"win32_status\":" + std::to_wstring(*inventory.StopWin32) +
                L",\"final_ordinal\":" + NumberOrNull(inventory.FinalOrdinal) +
                L",\"events_lost\":" + NumberOrNull(inventory.EventsLost) + L",\"log_buffers_lost\":" + NumberOrNull(inventory.LogBuffersLost) + L"}") +
            L",\"session_membership_independently_verified\":false,\"lossless_session_verified\":false,\"cross_member_timing_checked\":false";
    }

    int Failure(const Options& options, const std::wstring& actual, const wchar_t* status, const RotationInventory& inventory = {}, DWORD openError = ERROR_SUCCESS)
    {
        return WriteCapabilityJson(Report(options, actual, status, inventory, openError) +
            L",\"verified_members\":null,\"contiguous_inventory_verified\":null,\"closed_controller_inventory_verified\":null,\"members\":null}") ? 1 : 2;
    }

    int Verify(const std::wstring& name, const Options& options)
    {
        SavedEtlInput statement;
        DWORD error = ERROR_SUCCESS;
        if (!statement.Open(name, MaxInventoryBytes, &error)) { return Failure(options, {}, L"inventory_unavailable", {}, error); }
        const auto& actual = statement.File.Sha256;
        if (actual != options.Digest) { return Failure(options, actual, L"inventory_digest_mismatch"); }
        std::vector<uint8_t> bytes;
        if (!statement.ReadStatement(bytes)) { return Failure(options, {}, L"inventory_changed"); }
        const auto inventory = VerifyRotationInventory(bytes, options.Authority);
        if (!inventory.Accepted) { return Failure(options, actual, inventory.Status, inventory); }

        const auto declaredEnd = inventory.FinalOrdinal ? *inventory.FinalOrdinal : inventory.Members.back().Ordinal;
        const uint32_t highest = (std::max)(options.Highest, declaredEnd);
        std::array<MemberRead, MaxRotationMembers + 1> rows;
        for (const auto& m : inventory.Members) { rows[m.Ordinal].Declared = &m; }
        for (uint32_t i = 1; i <= highest; ++i) { rows[i].Read(options.Paths[i]); }

        // Keep all leases until publication. A closure claim covers the whole set at this check.
        uint32_t verified = 0;
        std::wstring members = L"[";
        for (uint32_t i = 1; i <= highest; ++i)
        {
            rows[i].Recheck();
            if (rows[i].Verified) { ++verified; }
            if (i > 1) { members += L','; }
            members += rows[i].Json(i, !options.Paths[i].empty());
        }
        if (!statement.Revalidated()) { return Failure(options, {}, L"inventory_changed"); }
        const bool contiguous = verified == highest;
        const bool stopFailed = inventory.StopWin32.value_or(0) != ERROR_SUCCESS;
        const auto status = !contiguous ? L"incomplete_set" : stopFailed ? L"controller_stop_failed" :
            inventory.FinalOrdinal ? L"closed_controller_inventory" : L"ordered_members_verified";
        const auto report = Report(options, actual, status, inventory) + L",\"verified_members\":" + std::to_wstring(verified) +
            L",\"contiguous_inventory_verified\":" + JsonBool(contiguous) +
            L",\"closed_controller_inventory_verified\":" + (inventory.FinalOrdinal ? JsonBool(contiguous) : L"null") +
            L",\"members\":" + members + L"]}";
        if (!WriteCapabilityJson(report)) { return 2; }
        return contiguous && !stopFailed ? 0 : 1;
    }
}

int RunEtlRotationSet(const std::vector<std::wstring>& args)
{
    Options options;
    const bool valid = Parse(args, options);
    const auto sink = GetStdHandle(valid ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
    const bool disk = GetFileType(sink) == FILE_TYPE_DISK;
    if (disk && args.size() > MaxArgs) { return 2; }
    std::vector<DistinctArtifactInput> guards(disk ? args.size() : 0);
    for (size_t i = 0; i < guards.size(); ++i)
    {
        if ((!valid || i == 0 || (i >= 8 && (i - 8) % 3 == 0)) && !guards[i].Hold(sink, args[i], valid)) { return 2; }
    }
    if (!valid)
    {
        std::wcerr << L"usage: KnLiveDbg.exe --etl-rotation-set <inventory.jws> --sha256 <digest> --authority <capture_controller|archive_witness> <trusted-p256-point> [--member <ordinal> <local.etl>]...\n";
        return 2;
    }
    return Verify(args[0], options);
}
