#include "SymbolArtifactResolver.h"
#include "TypeSchemaBroker.h"
#include "SymbolArtifactCache.h"
#include "ExecutableImage.h"
#include "McpJson.h"
#include <WinHttp.h>
#include <objbase.h>
#include <algorithm>
#include <cwctype>
#include <filesystem>
#include <functional>
#include <set>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ole32.lib")

namespace
{
    constexpr uint64_t MaximumPdbBytes = 1024ull * 1024 * 1024;
    struct Internet
    {
        HINTERNET Value = nullptr;
        ~Internet() { if (Value != nullptr) { WinHttpCloseHandle(Value); } }
    };
    struct SearchRoot { std::wstring Cache; std::wstring Server; };
    std::wstring Lower(std::wstring text)
    {
        std::transform(text.begin(), text.end(), text.begin(), [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
        return text;
    }
    std::vector<std::wstring> Split(const std::wstring& value, wchar_t separator)
    {
        std::vector<std::wstring> values;
        size_t begin = 0;
        while (begin <= value.size() && values.size() < 128)
        {
            const auto end = value.find(separator, begin);
            values.push_back(value.substr(begin, end == std::wstring::npos ? end : end - begin));
            if (end == std::wstring::npos) { return values; }
            begin = end + 1;
        }
        return {};
    }
    bool FileName(const SchemaArtifact& image, const executable_image::DiskPeMetadata& metadata, std::wstring* name)
    {
        if (!metadata.HasPdbIdentity || metadata.PdbRecordBytes <= 24 || metadata.PdbRva > UINT32_MAX - 24) { return false; }
        std::vector<uint8_t> raw;
        if (!executable_image::ReadDiskBytesForRva(image.Handle(), metadata, metadata.PdbRva + 24,
            (std::min)(metadata.PdbRecordBytes - 24, uint32_t{4096}), &raw)) { return false; }
        const auto end = std::find(raw.begin(), raw.end(), uint8_t{0});
        if (end == raw.end()) { return false; }
        std::string path(raw.begin(), end);
        const auto slash = path.find_last_of("/\\");
        if (slash != std::string::npos) { path.erase(0, slash + 1); }
        *name = mcpjson::Utf8ToWide(path);
        if (name->empty() || name->size() > 240 || mcpjson::WideToUtf8(*name) != path ||
            name->find_first_of(L"<>:\"/\\|?*") != std::wstring::npos ||
            std::any_of(name->begin(), name->end(), [](wchar_t c) { return c < 32; }) ||
            name->back() == L' ' || name->back() == L'.' || name->size() < 5 ||
            Lower(name->substr(name->size() - 4)) != L".pdb") { return false; }
        return true;
    }
    std::wstring UrlSegment(const std::wstring& value)
    {
        const auto utf8 = mcpjson::WideToUtf8(value);
        std::wstring result;
        for (const unsigned char c : utf8)
        {
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')
            { result += static_cast<wchar_t>(c); }
            else { result += L'%'; result += L"0123456789ABCDEF"[c >> 4]; result += L"0123456789ABCDEF"[c & 15]; }
        }
        return result;
    }
    bool Download(const std::wstring& url, HANDLE file, uint64_t started, uint64_t timeoutMs)
    {
        if (url.size() > 16000) { return false; }
        URL_COMPONENTS parts{};
        parts.dwStructSize = sizeof(parts);
        parts.dwHostNameLength = parts.dwUrlPathLength = parts.dwExtraInfoLength = parts.dwUserNameLength = parts.dwPasswordLength = DWORD(-1);
        if (!WinHttpCrackUrl(url.c_str(), static_cast<DWORD>(url.size()), 0, &parts) ||
            parts.nScheme != INTERNET_SCHEME_HTTPS || parts.dwHostNameLength == 0 ||
            parts.dwUserNameLength != 0 || parts.dwPasswordLength != 0 || parts.dwExtraInfoLength != 0) { return false; }
        Internet session, connection, request;
        session.Value = WinHttpOpen(L"KnLiveDbg-SymbolArtifact/1", WINHTTP_ACCESS_TYPE_NO_PROXY,
            WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (session.Value == nullptr || !WinHttpSetTimeouts(session.Value, 5000, 5000, 5000, 5000)) { return false; }
        const std::wstring host(parts.lpszHostName, parts.dwHostNameLength), path(parts.lpszUrlPath, parts.dwUrlPathLength);
        connection.Value = WinHttpConnect(session.Value, host.c_str(), parts.nPort, 0);
        if (connection.Value == nullptr) { return false; }
        request.Value = WinHttpOpenRequest(connection.Value, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (request.Value == nullptr) { return false; }
        DWORD disabled = WINHTTP_DISABLE_COOKIES | WINHTTP_DISABLE_AUTHENTICATION;
        DWORD auth = WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH;
        DWORD redirects = WINHTTP_OPTION_REDIRECT_POLICY_DISALLOW_HTTPS_TO_HTTP, maximumRedirects = 3;
        BOOL rejectCredentials = TRUE;
        if (!WinHttpSetOption(request.Value, WINHTTP_OPTION_DISABLE_FEATURE, &disabled, sizeof(disabled)) ||
            !WinHttpSetOption(request.Value, WINHTTP_OPTION_AUTOLOGON_POLICY, &auth, sizeof(auth)) ||
            !WinHttpSetOption(request.Value, WINHTTP_OPTION_REDIRECT_POLICY, &redirects, sizeof(redirects)) ||
            !WinHttpSetOption(request.Value, WINHTTP_OPTION_MAX_HTTP_AUTOMATIC_REDIRECTS, &maximumRedirects, sizeof(maximumRedirects)) ||
            !WinHttpSetOption(request.Value, WINHTTP_OPTION_REJECT_USERPWD_IN_URL, &rejectCredentials, sizeof(rejectCredentials)) ||
            GetTickCount64() - started >= timeoutMs ||
            !WinHttpSendRequest(request.Value, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
            !WinHttpReceiveResponse(request.Value, nullptr)) { return false; }
        DWORD status = 0, size = sizeof(status);
        if (!WinHttpQueryHeaders(request.Value, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX) || status != 200) { return false; }
        uint64_t total = 0;
        std::vector<uint8_t> buffer(65536);
        for (;;)
        {
            DWORD received = 0, written = 0;
            if (GetTickCount64() - started >= timeoutMs || !WinHttpReadData(request.Value, buffer.data(),
                static_cast<DWORD>(buffer.size()), &received)) { return false; }
            if (received == 0) { return total != 0 && FlushFileBuffers(file); }
            if (received > MaximumPdbBytes - total || !WriteFile(file, buffer.data(), received, &written, nullptr) || written != received)
            { return false; }
            total += received;
        }
    }
}

bool ResolveSymbolArtifacts(const std::wstring& executable, const std::wstring& image,
    uint32_t expectedImageSize, const std::wstring& symbolPath, const SymbolArtifactConsumer& consume, std::wstring* error, uint64_t timeoutMs)
{
    if (error != nullptr) { *error = L"brokered symbol artifacts unavailable: no matching approved local or HTTPS PDB"; }
    if (!consume || symbolPath.size() > 30000 || symbolPath.find(L'\0') != std::wstring::npos || expectedImageSize == 0 ||
        timeoutMs == 0 || timeoutMs > 60000) { return false; }
    const auto started = GetTickCount64();
    SchemaArtifact imageFile;
    executable_image::DiskPeMetadata metadata;
    std::wstring name;
    if (!imageFile.Open(image, 512ull * 1024 * 1024) ||
        !executable_image::ReadDiskPeIdentityHandle(imageFile.Handle(), &metadata, nullptr) ||
        metadata.SizeOfImage != expectedImageSize || !FileName(imageFile, metadata, &name)) { return false; }
    std::filesystem::path checkedName;
    if (!symbol_artifacts::LocalRoot((std::filesystem::path(imageFile.Path).parent_path() / name).wstring(), &checkedName)) { return false; }
    const auto index = symbol_artifacts::Index(metadata.PdbGuid, metadata.PdbAge);
    const auto defaultCache = (std::filesystem::path(executable).parent_path() / L"symbols").wstring();
    std::vector<SearchRoot> roots{{std::filesystem::path(imageFile.Path).parent_path().wstring(), L""}};
    for (const auto& item : Split(symbolPath, L';'))
    {
        if (item.empty()) { continue; }
        const auto pieces = Split(item, L'*');
        if (pieces.size() == 1) { roots.push_back({item, L""}); }
        else if (Lower(pieces[0]) == L"cache" && pieces.size() == 2 && !pieces[1].empty()) { roots.push_back({pieces[1], L""}); }
        else if (Lower(pieces[0]) == L"srv" && pieces.size() >= 2 && pieces.size() <= 3)
        {
            const auto& last = pieces.back();
            const bool https = Lower(last).rfind(L"https://", 0) == 0;
            roots.push_back({pieces.size() == 3 && !pieces[1].empty() ? pieces[1] :
                https ? defaultCache : last, https ? last : L""});
        }
    }
    std::set<std::wstring> tried;
    AcceptedSymbolArtifacts accepted;
    const auto parse = [&](const std::wstring& pdb) -> bool
    {
        const auto elapsed = GetTickCount64() - started;
        if (elapsed >= timeoutMs || !tried.insert(Lower(pdb)).second) { return false; }
        AcceptedSymbolArtifacts result;
        std::wstring parseError;
        if (!consume(imageFile.Path, pdb, timeoutMs - elapsed, &result, &parseError))
        { if (error != nullptr) { *error = std::move(parseError); } return false; }
        if (result.ImageSha256 != imageFile.Sha256 || !imageFile.Unchanged())
        { if (error != nullptr) { *error = L"module image artifact changed during schema resolution"; } return false; }
        accepted = std::move(result);
        return true;
    };
    for (const auto& root : roots)
    {
        std::filesystem::path base;
        symbol_artifacts::Directories pinned;
        if (!symbol_artifacts::LocalRoot(root.Cache, &base) || !pinned.Pin(base, false)) { continue; }
        for (const auto& candidate : {base / name / index / name, base / name})
        {
            symbol_artifacts::Directories candidateDirectories;
            if (!candidateDirectories.Pin(candidate.parent_path(), false)) { continue; }
            const auto attrs = GetFileAttributesW(candidate.c_str());
            if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 && parse(candidate.wstring()))
            { if (error != nullptr) { error->clear(); } return true; }
        }
    }
    for (const auto& root : roots)
    {
        if (root.Server.empty() || GetTickCount64() - started >= timeoutMs) { continue; }
        std::filesystem::path base;
        if (!symbol_artifacts::LocalRoot(root.Cache, &base)) { continue; }
        const auto directory = base / name / index;
        symbol_artifacts::Directories pinned;
        if (!pinned.Pin(directory, true)) { continue; }
        const auto final = directory / name;
        if (GetFileAttributesW(final.c_str()) != INVALID_FILE_ATTRIBUTES) { continue; }
        GUID unique{};
        wchar_t suffix[40]{};
        if (FAILED(CoCreateGuid(&unique)) || StringFromGUID2(unique, suffix, static_cast<int>(std::size(suffix))) == 0) { continue; }
        symbol_artifacts::TemporaryFile temporary;
        if (!temporary.Create(final.wstring() + L".pending-" + suffix)) { continue; }
        auto server = root.Server;
        while (!server.empty() && server.back() == L'/') { server.pop_back(); }
        if (!Download(server + L"/" + UrlSegment(name) + L"/" + index + L"/" + UrlSegment(name), temporary.File, started, timeoutMs)) { continue; }
        temporary.Close();
        SchemaArtifact approved;
        if (!approved.Open(temporary.Path, MaximumPdbBytes) || !temporary.Same(approved.Handle()) ||
            !parse(temporary.Path)) { continue; }
        if (approved.Sha256 != accepted.PdbSha256 || !symbol_artifacts::Publish(approved, final)) { continue; }
        if (error != nullptr) { error->clear(); }
        return true;
    }
    return false;
}

bool ResolveBrokeredTypeSchema(const std::wstring& executable, const std::wstring& image,
    uint32_t expectedImageSize, const std::wstring& symbolPath, const std::wstring& typeName,
    TypeSchemaPackage* package, std::wstring* error)
{
    if (package == nullptr) { return false; }
    *package = {};
    TypeSchemaPackage result;
    const auto consume = [&](const std::wstring& approvedImage, const std::wstring& pdb, uint64_t timeout,
        AcceptedSymbolArtifacts* accepted, std::wstring* issue)
    {
        if (!GenerateBrokeredTypeSchema(executable, approvedImage, pdb, typeName, &result, issue, timeout, nullptr, true)) { return false; }
        *accepted = {result.ImageSha256, result.PdbSha256}; return true;
    };
    if (!ResolveSymbolArtifacts(executable, image, expectedImageSize, symbolPath, consume, error)) { return false; }
    *package = std::move(result); return true;
}
