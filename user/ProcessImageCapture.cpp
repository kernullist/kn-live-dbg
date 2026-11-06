#include "ProcessImageCapture.h"
#include "ProcessObservationSource.h"
#include "ImageVerificationRecipe.h"
#include "RuntimeCapabilities.h"
#include <iostream>

namespace
{
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
}

int RunProcessImageCaptureCommand(const std::vector<std::wstring>& args, const std::atomic<bool>* cancellation)
{
    uint64_t pid = 0, creation = 0, base = 0, rva = 0, length = 0;
    if (args.size() != 8 || !Unsigned(args[0], 10, &pid) || pid == 0 || pid > UINT32_MAX ||
        !Unsigned(args[1], 10, &creation) || creation == 0 || args[2].empty() ||
        !Unsigned(args[3], 16, &base) || base == 0 || !Unsigned(args[4], 16, &rva) || rva > UINT32_MAX ||
        !Unsigned(args[5], 10, &length) || length == 0 || length > 4096 || args[6].empty() ||
        args[7] != L"--allow-residency" || base > UINT64_MAX - rva || base + rva > UINT64_MAX - length)
    {
        std::wcerr << L"usage: --verify-process-image <pid> <creation-filetime> <reference> <hex-base> <hex-rva> <length 1..4096> <new-directory> --allow-residency\n";
        return 2;
    }
    std::wstring error;
    ImageVerificationRecipe recipe;
    bool captured = false;
    uint32_t openStatus = ERROR_SUCCESS;
    try
    {
        std::unique_ptr<void, CloseHandleDeleter> process(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,
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
            else
            {
                ImageRecipeCaptureOptions options;
                options.TargetId = L"process:" + std::to_wstring(pid) + L":" + std::to_wstring(creation);
                options.AddressSpaceId = options.TargetId + L":user";
                options.AllowResidencyChanges = true;
                captured = CaptureObservedImageRecipe(args[2], source, base, static_cast<uint32_t>(rva),
                    static_cast<uint32_t>(length), args[6], options, &recipe, &error, cancellation);
            }
        }
    }
    catch (const std::exception&)
    {
        error = L"image capture could not materialize bounded artifacts";
    }
    const auto json = L"{\"schema\":\"kn.image_capture.v2\",\"status\":" + mcpjson::Quote(captured ? L"recorded" : L"failed") +
        L",\"reference_sha256\":" + mcpjson::Quote(recipe.ReferenceSha256) + L",\"source_id\":" + mcpjson::Quote(recipe.SourceId) +
        L",\"operation_id\":" + mcpjson::Quote(recipe.ReadSet.OperationId) + L",\"target_id\":" + mcpjson::Quote(recipe.ReadSet.TargetId) +
        L",\"policy\":" + mcpjson::Quote(recipe.Policy) + L",\"consistency\":" + mcpjson::Quote(recipe.SourceConsistency) +
        L",\"collector_authenticated\":false,\"execution_observed\":false,\"residency_consent\":true,\"open_status\":" +
        std::to_wstring(openStatus) + L",\"error\":" + mcpjson::Quote(error) + L",\"result\":" +
        (captured ? recipe.RecordedResult : L"null") + L"}";
    if (!WriteCapabilityJson(json)) { return 3; }
    return captured ? 0 : 1;
}
