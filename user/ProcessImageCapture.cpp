#include "ProcessImageCapture.h"
#include "ArtifactOutput.h"
#include "ProcessObservationSource.h"
#include "ImageVerificationRecipe.h"
#include "ImageLoaderWindow.h"
#include "RuntimeCapabilities.h"
#include <cstring>
#include <iostream>
#include <string_view>

namespace
{
    constexpr size_t MaxCaptureOperands = 9;

    bool Unsigned(const std::wstring& text, uint32_t radix, uint64_t* result)
    {
        size_t start = radix == 16 && text.size() > 2 && text[0] == L'0' && (text[1] == L'x' || text[1] == L'X') ? 2 : 0;
        if (start == text.size()) { return false; }
        *result = 0;
        for (size_t i = start; i < text.size(); ++i)
        {
            const auto c = text[i];
            const uint32_t digit = c >= L'0' && c <= L'9' ? c - L'0' :
                c >= L'a' && c <= L'f' ? c - L'a' + 10 : c >= L'A' && c <= L'F' ? c - L'A' + 10 : 16;
            if (digit >= radix || *result > (UINT64_MAX - digit) / radix) { return false; }
            *result = *result * radix + digit;
        }
        return true;
    }
    struct CloseHandleDeleter
    {
        void operator()(void* handle) const { CloseHandle(handle); }
    };

    std::wstring VolumePath(HANDLE file)
    {
        std::wstring path(32768, L'\0');
        const DWORD n = GetFinalPathNameByHandleW(file, path.data(), static_cast<DWORD>(path.size()), VOLUME_NAME_GUID);
        if (!n || n >= path.size()) { return {}; }
        path.resize(n);
        return path;
    }

    bool InDirectory(std::wstring_view directory, std::wstring_view path)
    {
        return path.size() >= directory.size() && (path.size() == directory.size() || path[directory.size()] == L'\\') &&
            CompareStringOrdinal(directory.data(), static_cast<int>(directory.size()), path.data(),
                static_cast<int>(directory.size()), TRUE) == CSTR_EQUAL;
    }

    // The output may have been opened through a hard link outside a prior case.
    // Inspect the output's names, independently of the size or validity of that case.
    bool OutsideCaptureDirectory(HANDLE sink, HANDLE occupied)
    {
        if (!occupied) { return true; }
        FILE_STANDARD_INFO object{}, output{};
        if (!GetFileInformationByHandleEx(occupied, FileStandardInfo, &object, sizeof(object))) { return false; }
        if (!object.Directory) { return true; } // Hold already compared the two file IDs.
        if (!GetFileInformationByHandleEx(sink, FileStandardInfo, &output, sizeof(output)) ||
            output.Directory || output.DeletePending || !output.NumberOfLinks) { return false; }
        auto directory = VolumePath(occupied);
        const auto file = VolumePath(sink);
        if (directory.empty() || file.empty()) { return false; }
        if (directory.back() == L'\\') { directory.pop_back(); }
        if (InDirectory(directory, file)) { return false; }
        if (output.NumberOfLinks == 1) { return true; }

        const auto volumeEnd = file.find(L"}\\");
        if (file.rfind(L"\\\\?\\Volume{", 0) != 0 || volumeEnd == std::wstring::npos) { return false; }
        const auto volume = file.substr(0, volumeEnd + 1);
        if (!InDirectory(volume, directory)) { return true; } // Hard links cannot cross volumes.
        // The link enumeration accepts a name. Pin that name to the inherited
        // file object before using any of its returned names to admit output.
        const auto opened = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
            OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL, nullptr);
        if (opened == INVALID_HANDLE_VALUE) { return false; }
        const std::unique_ptr<void, CloseHandleDeleter> anchor(opened);
        FILE_ID_INFO actual{}, expected{};
        if (!GetFileInformationByHandleEx(anchor.get(), FileIdInfo, &actual, sizeof(actual)) ||
            !GetFileInformationByHandleEx(sink, FileIdInfo, &expected, sizeof(expected)) ||
            std::memcmp(&actual, &expected, sizeof(actual)) != 0) { return false; }
        std::vector<wchar_t> link(32768);
        DWORD capacity = static_cast<DWORD>(link.size());
        const auto raw = FindFirstFileNameW(file.c_str(), 0, &capacity, link.data());
        if (raw == INVALID_HANDLE_VALUE) { return false; }
        const std::unique_ptr<void, decltype(&FindClose)> search(raw, &FindClose);
        DWORD count = 0;
        do
        {
            if (++count > output.NumberOfLinks || link[0] != L'\\') { return false; }
            const std::wstring relative(link.data());
            const auto slash = relative.find_last_of(L'\\');
            const auto parent = volume + (slash ? relative.substr(0, slash) : L"\\");
            const auto parentFile = CreateFileW(parent.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE |
                FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            if (parentFile == INVALID_HANDLE_VALUE) { return false; }
            const std::unique_ptr<void, CloseHandleDeleter> handle(parentFile);
            const auto normalized = VolumePath(handle.get());
            if (normalized.empty() || InDirectory(directory, normalized)) { return false; }
            capacity = static_cast<DWORD>(link.size());
        } while (FindNextFileNameW(search.get(), &capacity, link.data()));
        FILE_STANDARD_INFO final{};
        return GetLastError() == ERROR_HANDLE_EOF && count == output.NumberOfLinks &&
            GetFileInformationByHandleEx(sink, FileStandardInfo, &final, sizeof(final)) &&
            !final.DeletePending && final.NumberOfLinks == count;
    }

    bool ProtectCaptureOutput(HANDLE sink, const std::vector<std::wstring>& args, bool valid,
        std::vector<DistinctArtifactInput>& leases)
    {
        if (GetFileType(sink) != FILE_TYPE_DISK) { return true; }
        if (args.size() > MaxCaptureOperands) { return false; }
        for (size_t i = 0; i < args.size(); ++i)
        {
            if (valid && i != 2 && i != 6) { continue; }
            auto& lease = leases.emplace_back();
            if (!lease.Hold(sink, args[i], true) || !OutsideCaptureDirectory(sink, lease.PinnedHandle())) { return false; }
        }
        return true;
    }
}

int RunProcessImageCaptureCommand(const std::vector<std::wstring>& args, const std::atomic<bool>* cancellation)
{
    uint64_t pid = 0, creation = 0, base = 0, rva = 0, length = 0;
    const bool traceLoader = args.size() == MaxCaptureOperands && args[8] == L"--trace-loader";
    const bool valid = (args.size() == 8 || traceLoader) && Unsigned(args[0], 10, &pid) && pid && pid <= UINT32_MAX &&
        Unsigned(args[1], 10, &creation) && creation && !args[2].empty() &&
        Unsigned(args[3], 16, &base) && base && Unsigned(args[4], 16, &rva) && rva <= UINT32_MAX &&
        Unsigned(args[5], 10, &length) && length && length <= 4096 && !args[6].empty() &&
        args[7] == L"--allow-residency" && base <= UINT64_MAX - rva && base + rva <= UINT64_MAX - length;
    const auto sink = GetStdHandle(valid ? STD_OUTPUT_HANDLE : STD_ERROR_HANDLE);
    std::vector<DistinctArtifactInput> leases;
    if (!ProtectCaptureOutput(sink, args, valid, leases)) { return 2; }
    if (!valid)
    {
        std::wcerr << L"usage: --verify-process-image <pid> <creation-filetime> <reference> <hex-base> <hex-rva> <length 1..4096> <new-directory> --allow-residency [--trace-loader]\n";
        return 2;
    }
    std::wstring error;
    ImageVerificationRecipe recipe;
    bool captured = false;
    uint32_t openStatus = ERROR_SUCCESS;
    image_loader::Window window;
    image_loader::Registration registration;
    ULONG markerStatus = ERROR_NOT_READY;
    std::wstring recipeDigest;
    try
    {
        std::unique_ptr<void, CloseHandleDeleter> process(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            FALSE, static_cast<DWORD>(pid)));
        if (process == nullptr)
        {
            openStatus = GetLastError();
            error = L"could not open the requested process";
        }
        else
        {
            SYSTEM_INFO info{};
            GetNativeSystemInfo(&info);
            // Win32 reports an OS user ceiling, not active CR4.LA57. Keep the
            // explicit legacy LA48 assumption in the retained source contract.
            AddressSpaceDescriptor space;
            space.UserMaximum = reinterpret_cast<uint64_t>(info.lpMaximumApplicationAddress);
            ProcessObservationSource source(process.get(), static_cast<uint32_t>(pid), creation, space);
            if (source.Capabilities().SourceId.empty())
            {
                error = L"process handle identity or supported address shape did not match";
            }
            else if (traceLoader && (markerStatus = registration.Open(window)) != ERROR_SUCCESS)
            {
                error = L"loader-window trace provider is unavailable";
            }
            else
            {
                markerStatus = ERROR_NOT_READY;
                ImageRecipeCaptureOptions options;
                options.TargetId = L"process:" + std::to_wstring(pid) + L":" + std::to_wstring(creation);
                options.AddressSpaceId = options.TargetId + L":user";
                options.AllowResidencyChanges = true;
                options.MappingObserver = &source;
                if (traceLoader) { options.LoaderWindow = &window; }
                captured = CaptureObservedImageRecipe(args[2], source, base, static_cast<uint32_t>(rva),
                    static_cast<uint32_t>(length), args[6], options, &recipe, &error, cancellation);
                if (traceLoader && captured)
                {
                    mcpjson::GetString(ImageRecipeJson(recipe), L"recipe_sha256", &recipeDigest);
                    markerStatus = registration.Publish(window, recipeDigest, recipe.Reads.size());
                }
            }
        }
    }
    catch (const std::exception&)
    {
        error = L"image capture could not materialize bounded artifacts";
    }
    const auto json = L"{\"schema\":\"kn.image_capture.v3\",\"status\":" + mcpjson::Quote(captured ? L"recorded" : L"failed") +
        L",\"reference_sha256\":" + mcpjson::Quote(recipe.ReferenceSha256) + L",\"source_id\":" + mcpjson::Quote(recipe.SourceId) +
        L",\"operation_id\":" + mcpjson::Quote(recipe.ReadSet.OperationId) + L",\"target_id\":" + mcpjson::Quote(recipe.ReadSet.TargetId) +
        L",\"policy\":" + mcpjson::Quote(recipe.Policy) + L",\"consistency\":" + mcpjson::Quote(recipe.SourceConsistency) +
        L",\"original_claim_recorded\":" + (captured ? L"true" : L"false") +
        L",\"collector_authenticated\":false,\"execution_observed\":false,\"residency_consent\":true,\"open_status\":" +
        std::to_wstring(openStatus) + L",\"error\":" + mcpjson::Quote(error) + L",\"result\":" +
        (captured ? recipe.RecordedResult : L"null") +
        (traceLoader ? L",\"loader_marker_status\":" + std::to_wstring(markerStatus) +
            L",\"loader_marker_submitted\":" + (captured && markerStatus == ERROR_SUCCESS ? L"true" : L"false") +
            L",\"recipe_sha256\":" + mcpjson::Quote(recipeDigest) : L"") + L"}";
    // A previously absent name can have acquired an identity during the operation.
    if (!ProtectCaptureOutput(sink, args, true, leases)) { return 2; }
    if (!WriteCapabilityJson(json)) { return 3; }
    return captured && (!traceLoader || markerStatus == ERROR_SUCCESS) ? 0 : 1;
}
