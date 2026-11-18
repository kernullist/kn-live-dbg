#include "McpOperationJournal.h"
#include "McpServer.h"
#include "ContentHash.h"
#include "EvidencePrivacy.h"
#include "EvidenceStore.h"
#include <wincrypt.h>
#include <algorithm>
#include <array>
#include <cstring>
#include <string_view>

#pragma comment(lib, "crypt32.lib")

namespace
{
    constexpr size_t MaxImage = 1024 * 1024;
    constexpr char Header[] = "KnLiveDbg.observe.operations.1\n";
    constexpr char Envelope[] = "KNMCPJ1"; // includes NUL, also recognized by the publication scanner
    using Handle = std::unique_ptr<void, decltype(&CloseHandle)>;

    std::string Hex(const uint8_t* bytes, size_t count)
    {
        std::string result;
        for (size_t i = 0; i < count; ++i)
        {
            result += "0123456789abcdef"[bytes[i] >> 4];
            result += "0123456789abcdef"[bytes[i] & 15];
        }
        return result;
    }

    std::string RandomHex(size_t count)
    {
        std::array<uint8_t, 32> bytes{};
        if (count > bytes.size() || BCryptGenRandom(nullptr, bytes.data(), static_cast<ULONG>(count),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) { return {}; }
        auto text = Hex(bytes.data(), count);
        SecureZeroMemory(bytes.data(), bytes.size());
        return text;
    }

    struct PrivateText
    {
        std::string Bytes;
        ~PrivateText() { if (!Bytes.empty()) { SecureZeroMemory(Bytes.data(), Bytes.size()); } }
    };

    struct ProtectedBuffer
    {
        DATA_BLOB Value{};
        ~ProtectedBuffer()
        {
            if (Value.pbData) { SecureZeroMemory(Value.pbData, Value.cbData); LocalFree(Value.pbData); }
        }
    };
}

struct McpOperationJournal::Impl
{
    EvidencePrivacyGuard Guard;
    EvidenceStoreLease Lease;
    std::wstring Path, Principal;
    PrivateText Key;
    std::array<uint8_t, 32> Entropy{};
    struct Row { std::wstring Id, Owner, Receipt; };
    std::vector<Row> Rows; // admission order, including previous controller generations
    bool Ready = false;
    bool Scoped = false;
    bool Tls = false;

    ~Impl() { SecureZeroMemory(Entropy.data(), Entropy.size()); }

    DATA_BLOB Salt() { return {static_cast<DWORD>(Entropy.size()), Entropy.data()}; }
    std::wstring Mac(const std::string& frame) const
    {
        std::array<uint8_t, 32> digest{};
        if (frame.empty() || frame.size() > UINT32_MAX || BCryptHash(BCRYPT_HMAC_SHA256_ALG_HANDLE,
            reinterpret_cast<PUCHAR>(const_cast<char*>(Key.Bytes.data())), static_cast<ULONG>(Key.Bytes.size()),
            reinterpret_cast<PUCHAR>(const_cast<char*>(frame.data())), static_cast<ULONG>(frame.size()),
            digest.data(), static_cast<ULONG>(digest.size())) < 0) { return {}; }
        return mcpjson::Utf8ToWide(Hex(digest.data(), digest.size()));
    }
    static std::wstring LifetimeFrame(const ObservationIdentity& target)
    {
        return target.BootId + L"\n" + std::to_wstring(target.ProcessId) + L"\n" + std::to_wstring(target.CreateTime);
    }
    std::wstring Owner(const McpObserveGrant& grant) const
    {
        if (!Scoped) { return grant.Fingerprint.empty() && grant.Source.empty() && !grant.Target &&
            grant.Access == McpObserveAccess::Both ? Principal : L""; }
        if (grant.Fingerprint.empty() || grant.Source.empty()) { return {}; }
        if (grant.Target)
        {
            if (grant.Source != L"ti" || !IsRetainedProcessLifetime(*grant.Target)) { return {}; }
            return Mac(mcpjson::WideToUtf8(L"grant.target.v1\n" + grant.Fingerprint + L"\n" + grant.Source +
                L"\n" + LifetimeFrame(*grant.Target))).substr(0, 32);
        }
        return Mac(mcpjson::WideToUtf8(L"grant.v1\n" + grant.Fingerprint + L"\n" + grant.Source)).substr(0, 32);
    }
    bool SetPrincipal()
    {
        ContentHash hash;
        if (Key.Bytes.size() != 64 || Key.Bytes.find_first_not_of("0123456789abcdef") != std::string::npos ||
            !hash.Add(reinterpret_cast<const uint8_t*>(Key.Bytes.data()), Key.Bytes.size())) { return false; }
        Principal = hash.Finish().substr(0, 32);
        return IsMcpOperationId(Principal);
    }

    bool Write(const std::vector<Row>& rows)
    {
        PrivateText clear;
        clear.Bytes.reserve(sizeof(Header) + Key.Bytes.size() + rows.size() * 1600);
        clear.Bytes.append(Header).append(Key.Bytes).push_back('\n');
        for (const auto& row : rows)
        {
            const auto receipt = mcpjson::WideToUtf8(row.Receipt);
            if (receipt.empty() || receipt.size() > 4096) { return false; }
            clear.Bytes.append(receipt).push_back('\n');
        }
        if (clear.Bytes.size() > MaxImage) { return false; }
        DATA_BLOB in{static_cast<DWORD>(clear.Bytes.size()), reinterpret_cast<BYTE*>(clear.Bytes.data())};
        auto salt = Salt();
        ProtectedBuffer sealed;
        if (!CryptProtectData(&in, nullptr, &salt, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &sealed.Value) ||
            sealed.Value.cbData > MaxImage) { return false; }
        std::string image(Envelope, sizeof(Envelope));
        image.append(reinterpret_cast<const char*>(&sealed.Value.cbData), sizeof(DWORD));
        image.append(reinterpret_cast<const char*>(sealed.Value.pbData), sealed.Value.cbData);
        if (image.size() > MaxImage) { return false; }
        return WriteMcpSensitiveFile(Path, image, nullptr, &Guard);
    }

    bool Read()
    {
        HANDLE raw = CreateFileW(Path.c_str(), GENERIC_READ | READ_CONTROL, FILE_SHARE_READ, nullptr,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        Handle file(raw == INVALID_HANDLE_VALUE ? nullptr : raw, &CloseHandle);
        LARGE_INTEGER size{};
        if (!file || !Guard.CheckFile(file.get()) || !GetFileSizeEx(file.get(), &size) ||
            size.QuadPart <= 0 || size.QuadPart > MaxImage) { return false; }
        std::vector<uint8_t> bytes(static_cast<size_t>(size.QuadPart));
        DWORD read = 0;
        if (!ReadFile(file.get(), bytes.data(), static_cast<DWORD>(bytes.size()), &read, nullptr) || read != bytes.size()) { return false; }
        constexpr size_t prefix = sizeof(Envelope) + sizeof(DWORD);
        if (read <= prefix || std::memcmp(bytes.data(), Envelope, sizeof(Envelope)) != 0) { return false; }
        DWORD sealedBytes = 0;
        std::memcpy(&sealedBytes, bytes.data() + sizeof(Envelope), sizeof(sealedBytes));
        if (sealedBytes != read - prefix) { return false; }
        DATA_BLOB in{sealedBytes, bytes.data() + prefix};
        auto salt = Salt();
        ProtectedBuffer clear;
        if (!CryptUnprotectData(&in, nullptr, &salt, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &clear.Value) ||
            clear.Value.cbData > MaxImage) { return false; }
        const std::string_view image(reinterpret_cast<const char*>(clear.Value.pbData), clear.Value.cbData);
        size_t pos = sizeof(Header) - 1;
        if (image.substr(0, pos) != Header || image.size() < pos + 65 || image[pos + 64] != '\n') { return false; }
        Key.Bytes = image.substr(pos, 64);
        if (!SetPrincipal()) { return false; }
        pos += 65;
        while (pos < image.size())
        {
            const auto end = image.find('\n', pos);
            if (end == image.npos || end - pos > 4096 || Rows.size() >= McpOperationLedger::Capacity) { return false; }
            const auto text = mcpjson::Utf8ToWide(std::string(image.substr(pos, end - pos)));
            std::wstring id, schema, journal, principal, recovered, scope;
            if (!mcpjson::ValidateDocument(text) || !mcpjson::GetString(text, L"schema", &schema) || schema != L"kn.mcp_operation.v1" ||
                !mcpjson::GetString(text, L"operation_id", &id) || !IsMcpOperationId(id) ||
                !mcpjson::FindRawValue(text, L"journal", &journal) || !mcpjson::GetString(journal, L"principal_id", &principal) ||
                !(Scoped ? IsMcpOperationId(principal) : principal == Principal) ||
                !mcpjson::GetString(journal, L"approved_scope", &scope) ||
                (Scoped ? (scope != McpScopedJournalName(Tls, false) && scope != McpScopedJournalName(Tls, true)) : scope != L"loopback_observe") ||
                !mcpjson::FindRawValue(journal, L"recovered", &recovered) || recovered != L"true" ||
                std::any_of(Rows.begin(), Rows.end(), [&](const Row& row) { return row.Id == id; })) { return false; }
            std::wstring controller, target;
            const bool targetScoped = Scoped && scope == McpScopedJournalName(Tls, true);
            if (!mcpjson::GetString(journal, L"target_generation", &target) || !IsMcpOperationId(target) ||
                mcpjson::FindRawValue(journal, L"controller_generation", &controller) != targetScoped ||
                (targetScoped && (!mcpjson::GetString(journal, L"controller_generation", &controller) || !IsMcpOperationId(controller))))
            {
                return false;
            }
            std::wstring access;
            if (mcpjson::FindRawValue(journal, L"approved_access", &access) &&
                (!Scoped || !mcpjson::GetString(journal, L"approved_access", &access) ||
                    (access != L"evidence" && access != L"both"))) { return false; }
            Rows.push_back({std::move(id), std::move(principal), text});
            pos = end + 1;
        }
        return true;
    }
};

McpOperationJournal::McpOperationJournal() : Data(std::make_unique<Impl>()) {}
McpOperationJournal::~McpOperationJournal() = default;

bool McpOperationJournal::Open(const std::wstring& directory, const std::wstring& password, std::wstring* error, McpJournalMode mode)
{
    if (error) { *error = L"cannot open private operation journal with this credential"; }
    if (Data->Ready || password.empty()) { return false; }
    try
    {
        auto candidate = std::make_unique<Impl>();
        candidate->Scoped = mode != McpJournalMode::SharedLoopback;
        candidate->Tls = mode == McpJournalMode::ScopedHttps;
        EvidencePrivacyReport policy;
        bool fresh = false;
        if (!candidate->Guard.Open(directory, false, &policy))
        {
            fresh = InitializeEvidencePrivateStore(directory, false).Initialized;
            if (!fresh || !candidate->Guard.Open(directory, false, &policy)) { return false; }
        }
        if (!candidate->Lease.Acquire(policy.RootPath, true, nullptr)) { return false; }
        candidate->Path = L"\\\\?\\" + policy.RootPath + L"\\operations.knmcpjournal";
        PrivateText binding;
        const std::wstring domain = candidate->Tls ? L"KnLiveDbg.observe.https.journal.v1\n" :
            (candidate->Scoped ? L"KnLiveDbg.observe.source.journal.v1\n" : L"KnLiveDbg.observe.journal.v1\n");
        binding.Bytes = mcpjson::WideToUtf8(domain + policy.RootIdentity + L"\n");
        auto credential = mcpjson::WideToUtf8(password);
        binding.Bytes.append(credential);
        SecureZeroMemory(credential.data(), credential.size());
        if (BCryptHash(BCRYPT_SHA256_ALG_HANDLE, nullptr, 0, reinterpret_cast<PUCHAR>(binding.Bytes.data()),
            static_cast<ULONG>(binding.Bytes.size()), candidate->Entropy.data(), static_cast<ULONG>(candidate->Entropy.size())) < 0) { return false; }
        if (fresh)
        {
            candidate->Key.Bytes = RandomHex(32);
            if (!candidate->SetPrincipal() || !candidate->Write({})) { return false; }
        }
        else if (!candidate->Read()) { return false; }
        candidate->Ready = true;
        Data = std::move(candidate);
        if (error) { error->clear(); }
        return true;
    }
    catch (...) { return false; }
}

std::optional<McpJournalIdentity> McpOperationJournal::Identify(const McpEngineRequest& request) const
{
    static const std::wstring generation = mcpjson::Utf8ToWide(RandomHex(16));
    if (!Data->Ready || !IsMcpOperationId(generation) || !request.Grant.ReadsEvidence()) { return std::nullopt; }
    const auto frame = mcpjson::WideToUtf8((request.Kind == McpRequestKind::ToolCall ? L"tool\n" : L"resource\n") +
        request.Name + L"\n" + request.ArgumentsJson);
    const auto owner = Data->Owner(request.Grant);
    if (owner.empty() || frame.empty()) { return std::nullopt; }
    const auto digest = Data->Mac(Data->Scoped ? mcpjson::WideToUtf8(owner) + "\n" + frame : frame);
    if (digest.empty()) { return std::nullopt; }
    McpJournalIdentity identity{owner, generation, digest, McpUtcFileTime()};
    identity.Tls = Data->Tls;
    if (Data->Scoped) { identity.ApprovedAccess = request.Grant.AccessName(); }
    if (request.Grant.Target)
    {
        const auto target = Data->Mac(mcpjson::WideToUtf8(L"target.v1\n" + Impl::LifetimeFrame(*request.Grant.Target))).substr(0, 32);
        if (!IsMcpOperationId(target)) { return std::nullopt; }
        identity.TargetGeneration = target;
        identity.ControllerGeneration = generation;
    }
    return identity;
}

bool McpOperationJournal::Persist(const McpOperationSnapshot& operation) noexcept
{
    if (!Data->Ready) { return false; }
    try
    {
        auto next = Data->Rows;
        const auto at = std::find_if(next.begin(), next.end(), [&](const Impl::Row& row) { return row.Id == operation.Id; });
        const bool admission = !operation.Dispatched && !operation.Finished;
        if (admission == (at == next.end()) && operation.Journal && operation.Journal->Tls == Data->Tls &&
            (Data->Scoped ? (!operation.OwnerFingerprint.empty() && IsMcpOperationId(operation.Journal->PrincipalId)) :
                operation.OwnerFingerprint.empty() && operation.Journal->PrincipalId == Data->Principal) &&
            (admission || at->Owner == operation.Journal->PrincipalId))
        {
            auto receipt = McpOperationJson(operation, true);
            if (admission)
            {
                if (next.size() == McpOperationLedger::Capacity) { next.erase(next.begin()); }
                next.push_back({operation.Id, operation.Journal->PrincipalId, std::move(receipt)});
            }
            else { at->Receipt = std::move(receipt); }
            if (Data->Write(next)) { Data->Rows.swap(next); return true; }
        }
    }
    catch (...) {}
    Data->Ready = false;
    return false;
}

bool McpOperationJournal::Healthy() const { return Data->Ready; }

bool McpOperationJournal::Lookup(const std::wstring& id, const McpObserveGrant& grant, std::wstring* receipt) const
{
    if (!Data->Ready || !receipt || !grant.ReadsOperations()) { return false; }
    const auto owner = Data->Owner(grant);
    const auto at = std::find_if(Data->Rows.begin(), Data->Rows.end(),
        [&](const Impl::Row& row) { return row.Id == id && row.Owner == owner; });
    if (at == Data->Rows.end()) { return false; }
    *receipt = at->Receipt;
    return true;
}
