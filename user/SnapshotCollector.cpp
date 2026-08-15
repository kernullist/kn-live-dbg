#include "SnapshotCollector.h"

#include "AlpcScanner.h"
#include "ByovdScanner.h"
#include "CallbackScanner.h"
#include "EtwScanner.h"
#include "FirmwareTableScanner.h"
#include "HalDispatchScanner.h"
#include "HiveScanner.h"
#include "IntegrityScanner.h"
#include "MapperRemnantScanner.h"
#include "MinifilterAttachmentScanner.h"
#include "NmiScanner.h"
#include "MsrScanner.h"
#include "CrScanner.h"
#include "SsdtScanner.h"
#include "IdtScanner.h"
#include "DpcTimerScanner.h"
#include "TokenPrivilegeScanner.h"
#include "PoolPeHunter.h"
#include "PoolScanner.h"
#include "ProcessTriageScanner.h"
#include "VbsScanner.h"
#include "WfpScanner.h"
#include "WnfScanner.h"

#include <Windows.h>

#include <algorithm>
#include <fstream>
#include <limits>
#include <set>
#include <sstream>
#include <vector>

namespace
{
    constexpr uint64_t kLargePoolThreshold = 0x100000ull;

    std::wstring BoolText(bool value)
    {
        return value ? L"true" : L"false";
    }

    std::wstring DecText(uint64_t value)
    {
        return std::to_wstring(value);
    }

    void AddWarning(SnapshotDocument* document, const std::wstring& domain, const std::wstring& warning)
    {
        if (document != nullptr && !domain.empty() && !warning.empty())
        {
            document->DomainWarnings[domain].push_back(warning);
        }
    }

    void AddWarnings(SnapshotDocument* document, const std::wstring& domain, const std::vector<std::wstring>& warnings)
    {
        for (const std::wstring& warning : warnings)
        {
            AddWarning(document, domain, warning);
        }
    }

    void AddRecord(SnapshotDocument* document, SnapshotRecord record)
    {
        if (document != nullptr && !record.Domain.empty() && !record.Identity.empty())
        {
            record.Risk = SnapshotRiskNormalize(record.Risk);
            document->Records.push_back(std::move(record));
        }
    }

    std::wstring ModuleIdentityForAddress(SymbolEngine& symbols, uint64_t address)
    {
        std::wstring identity = SnapshotHex(address, 16);

        for (const KernelModuleInfo& module : symbols.Modules())
        {
            uint64_t start = module.Base;
            uint64_t end = module.Base + module.Size;
            if (address >= start && address < end)
            {
                std::wstringstream stream;
                stream << SnapshotToLower(module.ImageName) << L"+"
                       << SnapshotHex(address - module.Base, 0);
                identity = stream.str();
                break;
            }
        }

        return identity;
    }

    std::wstring ModuleOffsetIdentity(SymbolEngine& symbols, const std::wstring& moduleName, uint64_t address)
    {
        std::wstring identity = SnapshotToLower(moduleName);
        std::wstring loweredModuleName = SnapshotToLower(moduleName);

        for (const KernelModuleInfo& module : symbols.Modules())
        {
            uint64_t start = module.Base;
            uint64_t end = module.Base + module.Size;
            if (SnapshotToLower(module.ImageName) == loweredModuleName &&
                address >= start &&
                address < end)
            {
                identity += L"+";
                identity += SnapshotHex(address - module.Base, 0);
                return identity;
            }
        }

        std::wstring resolved = ModuleIdentityForAddress(symbols, address);
        if (resolved != SnapshotHex(address, 16))
        {
            identity = resolved;
        }
        else
        {
            identity += L"+";
            identity += SnapshotHex(address, 16);
        }

        return identity;
    }

    std::wstring SymbolOrAddressIdentity(
        SymbolEngine& symbols,
        const std::wstring& module,
        const std::wstring& symbol,
        uint64_t address)
    {
        std::wstring identity;

        if (!module.empty())
        {
            identity = SnapshotToLower(module);
            if (!symbol.empty())
            {
                identity += L"!";
                identity += SnapshotToLower(symbol);
            }
            else if (address != 0)
            {
                identity = ModuleOffsetIdentity(symbols, module, address);
            }
        }
        else if (address != 0)
        {
            identity = ModuleIdentityForAddress(symbols, address);
        }
        else
        {
            identity = L"null";
        }

        return identity;
    }

    std::wstring JoinTags(const std::vector<std::wstring>& tags)
    {
        std::wstring text;
        for (size_t i = 0; i < tags.size(); ++i)
        {
            if (i != 0)
            {
                text += L",";
            }
            text += tags[i];
        }
        return text;
    }

    std::wstring SnapshotIdentityPart(
        const std::wstring& value)
    {
        const std::wstring normalized =
            SnapshotToLower(value);
        return std::to_wstring(
                   normalized.size()) +
            L":" +
            normalized;
    }

    std::wstring FingerprintFileFnv64(const std::wstring& path)
    {
        std::wstring result;
        HANDLE file = INVALID_HANDLE_VALUE;

        do
        {
            if (path.empty())
            {
                break;
            }

            file = CreateFileW(
                path.c_str(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (file == INVALID_HANDLE_VALUE)
            {
                break;
            }

            uint64_t hash = 14695981039346656037ull;
            std::vector<uint8_t> buffer(32768);
            DWORD read = 0;
            bool readComplete = false;
            for (;;)
            {
                if (!ReadFile(
                        file,
                        buffer.data(),
                        static_cast<DWORD>(buffer.size()),
                        &read,
                        nullptr))
                {
                    break;
                }
                if (read == 0)
                {
                    readComplete = true;
                    break;
                }

                for (DWORD i = 0; i < read; ++i)
                {
                    hash ^= buffer[i];
                    hash *= 1099511628211ull;
                }
            }

            if (readComplete)
            {
                result = SnapshotHex(hash, 16);
            }
        } while (false);

        if (file != INVALID_HANDLE_VALUE)
        {
            CloseHandle(file);
        }

        return result;
    }

    bool RecordHasHighByovdMatch(const ByovdModuleRecord& record)
    {
        bool high = false;
        for (const ByovdMatch& match : record.Matches)
        {
            if (match.Confidence == L"HIGH")
            {
                high = true;
                break;
            }
        }
        return high;
    }

    std::wstring ByovdMatchSummary(const ByovdModuleRecord& record)
    {
        std::wstring summary;
        for (size_t i = 0; i < record.Matches.size(); ++i)
        {
            if (i != 0)
            {
                summary += L";";
            }
            summary += record.Matches[i].Confidence;
            summary += L":";
            summary += record.Matches[i].Entry.Source;
            summary += L":";
            summary += record.Matches[i].Entry.MatchType;
        }
        return summary;
    }

    std::set<std::wstring> BuildBaselineProcessSet(const SnapshotDocument& baseline)
    {
        std::set<std::wstring> identities;
        for (const SnapshotProcessRecord& process : baseline.Processes)
        {
            if (!process.Identity.empty())
            {
                identities.insert(process.Identity);
            }
        }
        return identities;
    }

    ProcessTriageTarget BuildTriageTarget(const SnapshotProcessRecord& process)
    {
        ProcessTriageTarget target = {};
        target.ProcessId = process.ProcessId;
        target.Eprocess = process.Eprocess;
        target.DirectoryTableBase = process.DirectoryTableBase;
        target.UserDirectoryTableBase = process.UserDirectoryTableBase;
        target.Peb = process.Peb;
        target.HasPeb = process.HasPeb;
        target.CreateTime = process.CreateTime;
        target.HasCreateTime = process.HasCreateTime;
        target.ImageName = process.ImageName;
        return target;
    }

    bool ResolveProcessProtectionField(
        SymbolEngine& symbols,
        TypeFieldInfo* field,
        std::wstring* error)
    {
        if (field == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid _EPROCESS.Protection field output";
            }
            return false;
        }

        std::wstring firstError;
        if (symbols.FindField(
                L"nt!_EPROCESS",
                L"Protection",
                field,
                &firstError))
        {
            return true;
        }

        std::wstring secondError;
        if (symbols.FindField(
                L"_EPROCESS",
                L"Protection",
                field,
                &secondError))
        {
            return true;
        }

        if (error != nullptr)
        {
            *error = !secondError.empty() ? secondError : firstError;
        }
        return false;
    }

    void CaptureProcessInventory(
        DeviceClient& device,
        SymbolEngine& symbols,
        const SnapshotCaptureOptions& options,
        SnapshotDocument* document)
    {
        if (document == nullptr)
        {
            return;
        }

        TypeFieldInfo protectionField = {};
        std::wstring protectionFieldError;
        const bool protectionFieldResolved =
            ResolveProcessProtectionField(
                symbols,
                &protectionField,
                &protectionFieldError);
        document->Metadata[L"process_security_protection_resolved"] =
            BoolText(protectionFieldResolved);

        uint64_t protectionReadsAttempted = 0;
        uint64_t protectionReadsSucceeded = 0;
        uint64_t tokenReadsAttempted = 0;
        uint64_t tokenReadsSucceeded = 0;
        document->Processes = options.Processes;
        for (SnapshotProcessRecord& process : document->Processes)
        {
            std::vector<std::wstring> warnings;
            if (process.Identity.empty())
            {
                process.Identity = BuildSnapshotProcessIdentity(process, &warnings);
            }
            AddWarnings(document, L"process", warnings);

            SnapshotRecord record;
            record.Domain = L"process";
            record.Identity = process.Identity;
            record.Display = process.ImageName + L" pid=" + std::to_wstring(process.ProcessId);
            record.Risk = L"info";
            record.Tags = {L"process-inventory"};
            record.Evidence[L"pid"] = DecText(process.ProcessId);
            record.Evidence[L"image"] = process.ImageName;
            record.Evidence[L"eprocess"] = SnapshotHex(process.Eprocess, 16);
            record.Evidence[L"dtb"] = SnapshotHex(process.DirectoryTableBase, 16);
            record.Evidence[L"user_dtb"] = SnapshotHex(process.UserDirectoryTableBase, 16);
            if (process.HasActiveThreads)
            {
                record.Evidence[L"active_threads"] = DecText(process.ActiveThreads);
            }
            if (process.HasExitTime)
            {
                record.Evidence[L"exit_time"] = SnapshotHex(process.ExitTime, 16);
            }
            record.Evidence[L"has_create_time"] = BoolText(process.HasCreateTime);
            record.Evidence[L"create_time"] = SnapshotHex(process.CreateTime, 16);
            AddRecord(document, std::move(record));

            ++tokenReadsAttempted;
            TokenPrivilegeScanner tokenScanner(device, symbols);
            TokenPrivilegeScanner::Options tokenOptions = {};
            tokenOptions.HasEprocess = true;
            tokenOptions.Eprocess = process.Eprocess;
            tokenOptions.TreatCommonAdminPrivilegesAsSuspicious = false;
            tokenOptions.RequirePdbLayoutForPrivilegeFindings = true;
            TokenPrivilegeScanResult tokenResult = {};
            std::wstring tokenError;
            const bool tokenScanOk =
                tokenScanner.Scan(tokenOptions, &tokenResult, &tokenError);
            const bool tokenIdentityMatches =
                tokenScanOk &&
                !tokenResult.Records.empty() &&
                tokenResult.Records[0].IdentityResolved &&
                tokenResult.Records[0].ProcessId == process.ProcessId &&
                SnapshotToLower(tokenResult.Records[0].ImageName) ==
                    SnapshotToLower(process.ImageName);
            const bool tokenAvailable =
                tokenScanOk &&
                tokenIdentityMatches &&
                tokenResult.CoverageComplete &&
                tokenResult.Records[0].PrivilegesResolved &&
                tokenResult.LayoutFromPdb;
            if (tokenAvailable)
            {
                ++tokenReadsSucceeded;
            }

            bool protectionAvailable = false;
            uint8_t protection = 0;
            if (protectionFieldResolved)
            {
                ++protectionReadsAttempted;
                if (process.Eprocess != 0 &&
                    process.Eprocess <=
                        std::numeric_limits<uint64_t>::max() -
                            protectionField.Offset)
                {
                    const uint64_t protectionAddress =
                        process.Eprocess + protectionField.Offset;
                    std::vector<uint8_t> protectionBytes;
                    std::wstring readError;
                    if (device.ReadMemory(
                            protectionAddress,
                            sizeof(uint8_t),
                            &protectionBytes,
                            &readError) &&
                        protectionBytes.size() == sizeof(uint8_t))
                    {
                        protection = protectionBytes[0];
                        protectionAvailable = true;
                        ++protectionReadsSucceeded;
                    }
                }
            }

            if (!protectionAvailable && !tokenAvailable)
            {
                continue;
            }

            SnapshotRecord securityRecord;
            securityRecord.Domain = L"process-security";
            securityRecord.Identity =
                L"process-security:" + process.Identity;
            securityRecord.Display =
                process.ImageName + L" pid=" +
                std::to_wstring(process.ProcessId);
            securityRecord.Risk = L"info";
            securityRecord.Tags = {L"process-security"};
            securityRecord.Evidence[L"pid"] =
                DecText(process.ProcessId);
            securityRecord.Evidence[L"image"] =
                process.ImageName;
            securityRecord.Evidence[L"eprocess"] =
                SnapshotHex(process.Eprocess, 16);
            if (protectionAvailable)
            {
                securityRecord.Display +=
                    L" protection=" + SnapshotHex(protection, 2);
                securityRecord.Tags.push_back(L"process-protection");
                securityRecord.Evidence[L"protection_raw"] =
                    DecText(protection);
                securityRecord.Evidence[L"protection_hex"] =
                    SnapshotHex(protection, 2);
                securityRecord.Evidence[L"protection_type"] =
                    DecText(protection & 0x7u);
                securityRecord.Evidence[L"protection_audit"] =
                    DecText((protection >> 3) & 0x1u);
                securityRecord.Evidence[L"protection_signer"] =
                    DecText((protection >> 4) & 0xfu);
            }

            // Preserve the full privilege fingerprint for temporal diffs, but
            // promote only a structural Enabled-vs-Present inconsistency.
            // Legitimate high-risk privileges are telemetry, not corruption.
            if (tokenAvailable)
            {
                const TokenPrivilegeRecord& token = tokenResult.Records[0];
                securityRecord.Tags.push_back(L"token-privilege");
                securityRecord.Evidence[L"token_fingerprint"] = token.PrivilegeFingerprint;
                securityRecord.Evidence[L"token_present"] = SnapshotHex(token.PresentMask, 16);
                securityRecord.Evidence[L"token_enabled"] = SnapshotHex(token.EnabledMask, 16);
                if (token.StructuralInconsistency)
                {
                    securityRecord.Risk = L"high";
                    securityRecord.Tags.push_back(L"suspicious");
                }
            }

            AddRecord(document, std::move(securityRecord));
        }

        document->Metadata[L"process_security_reads_attempted"] =
            DecText(protectionReadsAttempted);
        document->Metadata[L"process_security_reads_succeeded"] =
            DecText(protectionReadsSucceeded);
        const bool protectionCoverageComplete =
            protectionFieldResolved &&
            protectionReadsAttempted == protectionReadsSucceeded;
        const bool tokenCoverageComplete =
            tokenReadsAttempted == tokenReadsSucceeded;
        document->Metadata[L"token_privilege_reads_attempted"] =
            DecText(tokenReadsAttempted);
        document->Metadata[L"token_privilege_reads_succeeded"] =
            DecText(tokenReadsSucceeded);
        document->Metadata[L"token_privilege_coverage_complete"] =
            BoolText(tokenCoverageComplete);
        document->Metadata[L"process_security_coverage_complete"] =
            BoolText(protectionCoverageComplete && tokenCoverageComplete);
        if (!protectionFieldResolved)
        {
            AddWarning(
                document,
                L"process-security",
                L"_EPROCESS.Protection unavailable; process protection "
                L"delta detection is disabled: " +
                    protectionFieldError);
        }
        else if (!protectionCoverageComplete)
        {
            AddWarning(
                document,
                L"process-security",
                L"_EPROCESS.Protection coverage incomplete: read " +
                    DecText(protectionReadsSucceeded) +
                    L" of " +
                    DecText(protectionReadsAttempted) +
                    L" process records");
        }
        if (!tokenCoverageComplete)
        {
            AddWarning(
                document,
                L"process-security",
                L"token privilege coverage incomplete: read " +
                    DecText(tokenReadsSucceeded) +
                    L" of " +
                    DecText(tokenReadsAttempted) +
                    L" process records");
        }
    }

    void CaptureModules(DeviceClient& device, SymbolEngine& symbols, SnapshotDocument* document)
    {
        if (document == nullptr)
        {
            return;
        }

        IntegrityScanner scanner(device, symbols);
        ModuleIntegrityOptions options = {};
        ModuleIntegrityResult result = {};
        std::wstring error;

        document->Metadata[L"modules_coverage_complete"] =
            L"false";
        if (!scanner.ScanModules(options, &result, &error))
        {
            AddWarning(document, L"modules", error);
            AddWarnings(document, L"modules", result.Warnings);
            return;
        }

        document->Metadata[L"modules_coverage_complete"] =
            BoolText(!result.Truncated);
        AddWarnings(document, L"modules", result.Warnings);
        for (const ModuleIntegrityRecord& module : result.Records)
        {
            SnapshotRecord record;
            record.Domain = L"modules";
            record.Identity = L"module:" + SnapshotToLower(module.ImageName);
            record.Display = module.ImageName;
            record.Risk = module.WxEvidence ? L"high" : (module.Suspicious ? L"medium" : L"low");
            record.Tags = {L"module"};
            if (module.Suspicious)
            {
                record.Tags.push_back(L"suspicious");
            }
            if (module.WxEvidence)
            {
                record.Tags.push_back(L"wx");
            }
            if (module.MismatchEvidence)
            {
                record.Tags.push_back(L"mismatch");
            }
            record.Evidence[L"image"] = module.ImageName;
            record.Evidence[L"path"] = module.ImagePath;
            record.Evidence[L"base"] = SnapshotHex(module.Base, 16);
            record.Evidence[L"size"] = DecText(module.Size);
            record.Evidence[L"sizeof_image"] = DecText(module.SizeOfImage);
            record.Evidence[L"reason_codes"] = JoinTags(module.ReasonCodes);
            AddRecord(document, std::move(record));
        }
    }

    void CaptureDrivers(DeviceClient& device, SymbolEngine& symbols, SnapshotDocument* document)
    {
        IntegrityScanner scanner(device, symbols);
        DriverIntegrityOptions options = {};
        DriverIntegrityResult result = {};
        std::wstring error;

        if (!scanner.ScanDrivers(options, &result, &error))
        {
            AddWarning(document, L"drivers", error);
            AddWarnings(document, L"drivers", result.Warnings);
            return;
        }

        AddWarnings(document, L"drivers", result.Warnings);
        for (const DriverIntegrityRecord& driver : result.Records)
        {
            SnapshotRecord record;
            record.Domain = L"drivers";
            record.Identity = L"driver:" + SnapshotToLower(driver.Name);
            record.Display = driver.Name;
            record.Risk = driver.Suspicious ? L"high" : L"low";
            record.Tags = {L"driver"};
            if (driver.Suspicious)
            {
                record.Tags.push_back(L"suspicious");
            }
            record.Evidence[L"name"] = driver.Name;
            record.Evidence[L"object"] = SnapshotHex(driver.DriverObject, 16);
            record.Evidence[L"start"] = SnapshotHex(driver.DriverStart, 16);
            record.Evidence[L"size"] = DecText(driver.DriverSize);
            record.Evidence[L"owning_module"] = driver.OwningModule;
            record.Evidence[L"suspicious_dispatch_count"] = DecText(driver.SuspiciousDispatchCount);
            AddRecord(document, std::move(record));

            for (const DriverDispatchRecord& dispatch : driver.Dispatch)
            {
                SnapshotRecord dispatchRecord;
                dispatchRecord.Domain = L"drivers";
                dispatchRecord.Identity = L"driver-dispatch:" + SnapshotToLower(driver.Name) +
                    L":" + std::to_wstring(dispatch.Index);
                dispatchRecord.Display = driver.Name + L" " + dispatch.Name;
                dispatchRecord.Risk = dispatch.Suspicious ? L"high" : L"low";
                dispatchRecord.Tags = {L"dispatch"};
                if (dispatch.Suspicious)
                {
                    dispatchRecord.Tags.push_back(L"suspicious");
                }
                dispatchRecord.Evidence[L"driver"] = driver.Name;
                dispatchRecord.Evidence[L"driver_object"] =
                    SnapshotHex(driver.DriverObject, 16);
                dispatchRecord.Evidence[L"driver_start"] =
                    SnapshotHex(driver.DriverStart, 16);
                dispatchRecord.Evidence[L"irp"] = DecText(dispatch.Index);
                dispatchRecord.Evidence[L"name"] = dispatch.Name;
                dispatchRecord.Evidence[L"function"] = SnapshotHex(dispatch.Function, 16);
                dispatchRecord.Evidence[L"module"] = dispatch.ModuleName;
                dispatchRecord.Evidence[L"symbol"] = dispatch.SymbolName;
                dispatchRecord.Evidence[L"in_loaded_module"] = BoolText(dispatch.InLoadedModule);
                dispatchRecord.Evidence[L"in_owning_image"] = BoolText(dispatch.InOwningImage);
                dispatchRecord.Evidence[L"delegated_to_loaded_module"] =
                    BoolText(dispatch.DelegatedToLoadedModule);
                AddRecord(document, std::move(dispatchRecord));
            }
        }
    }

    void CaptureCallbacks(DeviceClient& device, SymbolEngine& symbols, SnapshotDocument* document)
    {
        if (document == nullptr)
        {
            return;
        }

        KernelCallbackScanner scanner(device, symbols);
        KernelCallbackScanResult result = {};
        std::wstring error;

        document->Metadata[L"callbacks_coverage_complete"] =
            L"false";
        document->Metadata[L"callbacks_record_count"] =
            L"0";
        if (!scanner.Scan(L"all", &result, &error))
        {
            AddWarning(document, L"callbacks", error);
            AddWarnings(document, L"callbacks", result.Warnings);
            return;
        }

        document->Metadata[L"callbacks_coverage_complete"] =
            BoolText(!result.Incomplete);
        document->Metadata[L"callbacks_record_count"] =
            DecText(result.Records.size());
        AddWarnings(document, L"callbacks", result.Warnings);
        for (const KernelCallbackRecord& cb : result.Records)
        {
            std::wstring owner = SymbolOrAddressIdentity(symbols, cb.FunctionModule, cb.FunctionSymbol, cb.Function);

            SnapshotRecord record;
            record.Domain = L"callbacks";
            record.Identity = L"callback:" + SnapshotToLower(cb.Kind) + L":" +
                SnapshotToLower(cb.Target) + L":" + owner + L":" +
                SnapshotHex(cb.Entry != 0 ? cb.Entry : cb.CallbackBlock, 16);
            record.Display = cb.Kind + L" " + cb.Target + L" " + owner;
            record.Risk = cb.FunctionModule.empty() ? L"high" : L"medium";
            record.Tags = {L"callback"};
            if (cb.FunctionModule.empty())
            {
                record.Tags.push_back(L"unknown-owner");
            }
            record.Evidence[L"kind"] = cb.Kind;
            record.Evidence[L"target"] = cb.Target;
            record.Evidence[L"function"] = SnapshotHex(cb.Function, 16);
            record.Evidence[L"function_module"] = cb.FunctionModule;
            record.Evidence[L"function_symbol"] = cb.FunctionSymbol;
            record.Evidence[L"post_function"] = SnapshotHex(cb.PostFunction, 16);
            record.Evidence[L"entry"] = SnapshotHex(cb.Entry, 16);
            record.Evidence[L"callback_block"] = SnapshotHex(cb.CallbackBlock, 16);
            record.Evidence[L"notes"] = cb.Notes;
            AddRecord(document, std::move(record));
        }
    }

    void CaptureMinifilterAttachments(
        SnapshotDocument* document)
    {
        if (document == nullptr)
        {
            return;
        }

        document->Metadata[
            L"minifilter_attachments_coverage_complete"] =
                L"false";
        document->Metadata[
            L"minifilter_attachment_record_count"] =
                L"0";
        document->Metadata[
            L"minifilter_attachment_volume_count"] =
                L"0";
        document->Metadata[
            L"minifilter_attachment_detached_count"] =
                L"0";

        MinifilterAttachmentScanner scanner;
        MinifilterAttachmentScanResult result = {};
        std::wstring error;
        if (!scanner.Scan(
                &result,
                &error))
        {
            AddWarning(
                document,
                L"minifilter-attachments",
                error.empty()
                    ? L"Filter Manager attachment enumeration failed"
                    : error);
            return;
        }

        document->Metadata[
            L"minifilter_attachments_coverage_complete"] =
                BoolText(!result.Incomplete);
        document->Metadata[
            L"minifilter_attachment_record_count"] =
                DecText(result.Records.size());
        document->Metadata[
            L"minifilter_attachment_volume_count"] =
                DecText(result.Volumes.size());
        AddWarnings(
            document,
            L"minifilter-attachments",
            result.Warnings);

        for (const std::wstring& volume :
             result.Volumes)
        {
            SnapshotRecord record;
            record.Domain =
                L"minifilter-attachments";
            record.Identity =
                L"minifilter-volume:" +
                SnapshotIdentityPart(volume);
            record.Display =
                L"Filter Manager volume " +
                volume;
            record.Risk = L"low";
            record.Tags =
                {L"minifilter-volume"};
            record.Evidence[L"volume_name"] =
                volume;
            AddRecord(
                document,
                std::move(record));
        }

        uint64_t detachedCount = 0;
        for (const MinifilterAttachmentRecord&
                 attachment :
             result.Records)
        {
            SnapshotRecord record;
            record.Domain =
                L"minifilter-attachments";
            record.Identity =
                L"minifilter-attachment:" +
                SnapshotIdentityPart(
                    attachment.IsMinifilter
                        ? L"minifilter"
                        : L"legacy") +
                SnapshotIdentityPart(
                    attachment.FilterName) +
                SnapshotIdentityPart(
                    attachment.InstanceName) +
                SnapshotIdentityPart(
                    attachment.VolumeName) +
                SnapshotIdentityPart(
                    attachment.Altitude);
            record.Display =
                (attachment.IsMinifilter
                     ? L"minifilter "
                     : L"legacy filter ") +
                attachment.FilterName +
                (attachment.InstanceName.empty()
                     ? L""
                     : L" [" +
                           attachment.InstanceName +
                           L"]") +
                L" on " +
                attachment.VolumeName;
            // DETACHED_VOLUME can occur during legitimate teardown. Preserve
            // the raw state here and promote only a same-boot transition or a
            // coverage-gated removal while the filter and volume persist.
            record.Risk = L"low";
            record.Tags =
                {L"minifilter-attachment"};
            record.Tags.push_back(
                attachment.IsMinifilter
                    ? L"minifilter"
                    : L"legacy-filter");
            if (attachment.DetachedVolume)
            {
                ++detachedCount;
                record.Tags.push_back(
                    L"detached-volume");
            }
            record.Evidence[L"kind"] =
                attachment.IsMinifilter
                    ? L"minifilter"
                    : L"legacy";
            record.Evidence[L"filter_name"] =
                attachment.FilterName;
            record.Evidence[L"instance_name"] =
                attachment.InstanceName;
            record.Evidence[L"altitude"] =
                attachment.Altitude;
            record.Evidence[L"volume_name"] =
                attachment.VolumeName;
            record.Evidence[L"detached_volume"] =
                BoolText(
                    attachment.DetachedVolume);
            record.Evidence[L"aggregate_flags"] =
                SnapshotHex(
                    attachment.AggregateFlags,
                    8);
            record.Evidence[L"instance_flags"] =
                SnapshotHex(
                    attachment.InstanceFlags,
                    8);
            record.Evidence[L"frame_id"] =
                DecText(
                    attachment.FrameId);
            record.Evidence[
                L"volume_filesystem_type"] =
                    DecText(
                        attachment.
                            VolumeFileSystemType);
            record.Evidence[
                L"supported_features"] =
                    SnapshotHex(
                        attachment.
                            SupportedFeatures,
                        8);
            AddRecord(
                document,
                std::move(record));
        }
        document->Metadata[
            L"minifilter_attachment_detached_count"] =
                DecText(detachedCount);
    }

    void CaptureHal(DeviceClient& device, SymbolEngine& symbols, SnapshotDocument* document)
    {
        HalDispatchScanner scanner(device, symbols);
        HalDispatchScanResult result = {};
        std::wstring error;
        if (!scanner.Scan(HalDispatchScanner::Options{}, &result, &error))
        {
            AddWarning(document, L"hal", error);
            AddWarnings(document, L"hal", result.Warnings);
            return;
        }
        AddWarnings(document, L"hal", result.Warnings);
        document->Metadata[L"hal_coverage_complete"] =
            BoolText(result.CoverageComplete);
        for (const HalDispatchTable& table : result.Tables)
        {
            for (const HalDispatchSlot& slot : table.Slots)
            {
                if (slot.NullSlot && !slot.Suspicious)
                {
                    continue;
                }
                SnapshotRecord record;
                record.Domain = L"hal";
                record.Identity =
                    L"hal:" + SnapshotToLower(table.Name) + L":" +
                    (slot.Name.empty() ? std::to_wstring(slot.Index) : SnapshotToLower(slot.Name));
                record.Display = table.Name + L"." +
                    (slot.Name.empty() ? std::to_wstring(slot.Index) : slot.Name);
                record.Risk = slot.Suspicious ? L"high" : L"info";
                record.Tags = {L"hal", L"dispatch"};
                if (slot.Suspicious)
                {
                    record.Tags.push_back(L"suspicious");
                }
                record.Evidence[L"table"] = table.Name;
                record.Evidence[L"index"] = DecText(slot.Index);
                record.Evidence[L"field"] = slot.Name;
                record.Evidence[L"routine"] = SnapshotHex(slot.Routine, 16);
                record.Evidence[L"module"] = slot.Module;
                record.Evidence[L"symbol"] = slot.Symbol;
                record.Evidence[L"notes"] = slot.Notes;
                AddRecord(document, std::move(record));
            }
        }
    }

    void CaptureHive(DeviceClient& device, SymbolEngine& symbols, SnapshotDocument* document)
    {
        HiveScanner scanner(device, symbols);
        HiveScanResult result = {};
        std::wstring error;
        if (!scanner.Scan(HiveScanner::Options{}, &result, &error))
        {
            AddWarning(document, L"hive", error);
            AddWarnings(document, L"hive", result.Warnings);
            document->Metadata[L"hive_coverage_complete"] = L"false";
            return;
        }
        AddWarnings(document, L"hive", result.Warnings);
        document->Metadata[L"hive_coverage_complete"] = BoolText(result.CoverageComplete);
        for (const HiveRecord& hive : result.Hives)
        {
            SnapshotRecord record;
            record.Domain = L"hive";
            record.Identity = L"hive:" + SnapshotHex(hive.HiveAddress, 16);
            record.Display = L"hive " + SnapshotHex(hive.HiveAddress, 16);
            record.Risk = hive.Suspicious ? L"high" : L"info";
            record.Tags = {L"hive", L"getcell"};
            if (hive.Suspicious)
            {
                record.Tags.push_back(L"suspicious");
            }
            record.Evidence[L"hive"] = SnapshotHex(hive.HiveAddress, 16);
            record.Evidence[L"get_cell"] = SnapshotHex(hive.GetCellRoutine, 16);
            record.Evidence[L"module"] = hive.GetCellModule;
            record.Evidence[L"symbol"] = hive.GetCellSymbol;
            record.Evidence[L"notes"] = hive.Notes;
            AddRecord(document, std::move(record));
        }
    }

    void CaptureDpcTimer(DeviceClient& device, SymbolEngine& symbols, SnapshotDocument* document)
    {
        DpcTimerScanner scanner(device, symbols);
        DpcTimerScanner::Options options = {};
        options.Target = DpcTimerScanner::Scope::All;
        DpcTimerScanResult result = {};
        std::wstring error;
        if (!scanner.Scan(options, &result, &error))
        {
            AddWarning(document, L"dpc-timer", error);
            AddWarnings(document, L"dpc-timer", result.Warnings);
            document->Metadata[L"dpc_timer_coverage_complete"] = L"false";
            return;
        }
        AddWarnings(document, L"dpc-timer", result.Warnings);
        document->Metadata[L"dpc_coverage_complete"] = BoolText(result.DpcCoverageComplete);
        document->Metadata[L"timer_coverage_complete"] = BoolText(result.TimerCoverageComplete);
        document->Metadata[L"workitem_coverage_complete"] = BoolText(result.WorkItemCoverageComplete);

        for (const DpcRoutineRecord& dpc : result.Dpcs)
        {
            if (!dpc.Suspicious)
            {
                continue;
            }
            SnapshotRecord record;
            record.Domain = L"dpc-timer";
            record.Identity =
                L"dpc:" + SnapshotHex(dpc.ObjectAddress, 16) + L":" +
                SnapshotHex(dpc.Routine, 16);
            record.Display = L"dpc " + dpc.Symbol;
            record.Risk = L"high";
            record.Tags = {L"dpc", L"suspicious"};
            record.Evidence[L"routine"] = SnapshotHex(dpc.Routine, 16);
            record.Evidence[L"object"] = SnapshotHex(dpc.ObjectAddress, 16);
            record.Evidence[L"module"] = dpc.Module;
            record.Evidence[L"symbol"] = dpc.Symbol;
            record.Evidence[L"source"] = dpc.Source;
            record.Evidence[L"notes"] = dpc.Notes;
            AddRecord(document, std::move(record));
        }
        for (const TimerRoutineRecord& timer : result.Timers)
        {
            if (!timer.Suspicious)
            {
                continue;
            }
            SnapshotRecord record;
            record.Domain = L"dpc-timer";
            record.Identity =
                L"timer:" + SnapshotHex(timer.TimerAddress, 16) + L":" +
                SnapshotHex(timer.Routine, 16);
            record.Display = L"timer " + timer.Symbol;
            record.Risk = L"high";
            record.Tags = {L"timer", L"suspicious"};
            record.Evidence[L"routine"] = SnapshotHex(timer.Routine, 16);
            record.Evidence[L"timer"] = SnapshotHex(timer.TimerAddress, 16);
            record.Evidence[L"dpc"] = SnapshotHex(timer.DpcAddress, 16);
            record.Evidence[L"module"] = timer.Module;
            record.Evidence[L"symbol"] = timer.Symbol;
            record.Evidence[L"notes"] = timer.Notes;
            AddRecord(document, std::move(record));
        }
    }

    void CaptureEtw(DeviceClient& device, SymbolEngine& symbols, SnapshotDocument* document)
    {
        EtwScanner scanner(device, symbols);
        EtwScanner::Options options = {};
        options.Target = EtwScanner::Scope::Loggers;
        EtwScanResult result = {};
        std::wstring error;

        if (scanner.Scan(options, &result, &error))
        {
            AddWarnings(document, L"etw", result.Warnings);
            for (const EtwLoggerRecord& logger : result.Loggers)
            {
                SnapshotRecord record;
                record.Domain = L"etw";
                record.Identity = L"etw-logger:" + std::to_wstring(logger.Slot) +
                    L":" + SnapshotToLower(logger.Name);
                record.Display = logger.Name.empty()
                    ? (L"logger slot " + std::to_wstring(logger.Slot))
                    : logger.Name;
                record.Risk = logger.Suspicious ? L"high" : L"low";
                record.Tags = {L"logger"};
                if (logger.Suspicious)
                {
                    record.Tags.push_back(L"suspicious");
                }
                record.Evidence[L"slot"] = DecText(logger.Slot);
                record.Evidence[L"context"] = SnapshotHex(logger.ContextAddress, 16);
                record.Evidence[L"name"] = logger.Name;
                record.Evidence[L"get_cpu_clock"] = SnapshotHex(logger.GetCpuClockCallback, 16);
                record.Evidence[L"get_cpu_clock_module"] = logger.GetCpuClockModule;
                record.Evidence[L"get_cpu_clock_symbol"] = logger.GetCpuClockSymbol;
                record.Evidence[L"notes"] = logger.Notes;
                AddRecord(document, std::move(record));
            }
        }
        else
        {
            AddWarning(document, L"etw", error);
            AddWarnings(document, L"etw", result.Warnings);
        }

        EtwProviderScanResult providers = {};
        EtwScanner::Options providerOptions = {};
        if (scanner.ScanProviders(providerOptions, &providers, &error))
        {
            AddWarnings(document, L"etw", providers.Warnings);
            document->Metadata[L"etw_provider_coverage_complete"] =
                BoolText(providers.CoverageComplete);
            for (const EtwProviderRecord& provider : providers.Providers)
            {
                if (!provider.Suspicious && providers.Providers.size() > 64)
                {
                    continue;
                }
                SnapshotRecord record;
                record.Domain = L"etw";
                record.Identity = L"etw-provider:" + SnapshotToLower(provider.GuidText);
                record.Display = provider.GuidText;
                record.Risk = provider.Suspicious ? L"high" : L"info";
                record.Tags = {L"provider"};
                if (provider.Suspicious)
                {
                    record.Tags.push_back(L"suspicious");
                }
                record.Evidence[L"guid"] = provider.GuidText;
                record.Evidence[L"entry"] = SnapshotHex(provider.EntryAddress, 16);
                record.Evidence[L"callback"] = SnapshotHex(provider.EnableCallback, 16);
                record.Evidence[L"module"] = provider.EnableCallbackModule;
                record.Evidence[L"symbol"] = provider.EnableCallbackSymbol;
                record.Evidence[L"notes"] = provider.Notes;
                AddRecord(document, std::move(record));
            }
        }
        else if (!error.empty())
        {
            AddWarning(document, L"etw", L"providers: " + error);
        }

        EtwIntegrityResult integrity = {};
        if (scanner.ScanIntegrity(&integrity, &error))
        {
            AddWarnings(document, L"etw", integrity.Warnings);
            for (const EtwIntegrityRecord& item : integrity.Records)
            {
                SnapshotRecord record;
                record.Domain = L"etw";
                record.Identity = L"etw-integrity:" + SnapshotToLower(item.Symbol);
                record.Display = item.Symbol;
                record.Risk = item.Findings.empty() ? L"low" : L"high";
                record.Tags = {L"integrity"};
                if (!item.Findings.empty())
                {
                    record.Tags.push_back(L"suspicious");
                }
                record.Evidence[L"symbol"] = item.Symbol;
                record.Evidence[L"address"] = SnapshotHex(item.Address, 16);
                record.Evidence[L"findings"] = DecText(item.Findings.size());
                record.Evidence[L"head_bytes"] = item.HeadBytesHex;
                AddRecord(document, std::move(record));
            }
        }
        else
        {
            AddWarning(document, L"etw", error);
            AddWarnings(document, L"etw", integrity.Warnings);
        }
    }

    void CaptureNmi(DeviceClient& device, SymbolEngine& symbols, SnapshotDocument* document)
    {
        NmiScanner scanner(device, symbols);
        NmiScanResult result = {};
        std::wstring error;

        if (!scanner.Scan(&result, &error))
        {
            AddWarning(document, L"nmi", error);
            AddWarnings(document, L"nmi", result.Warnings);
            return;
        }

        AddWarnings(document, L"nmi", result.Warnings);
        for (const NmiCallbackRecord& nmi : result.Callbacks)
        {
            std::wstring owner = SymbolOrAddressIdentity(symbols, nmi.CallbackModule, nmi.CallbackSymbol, nmi.Callback);
            SnapshotRecord record;
            record.Domain = L"nmi";
            record.Identity = L"nmi:" + owner + L":" + SnapshotHex(nmi.NodeAddress, 16);
            record.Display = owner;
            record.Risk = nmi.Suspicious ? L"high" : L"medium";
            record.Tags = {L"nmi"};
            if (nmi.Suspicious)
            {
                record.Tags.push_back(L"suspicious");
            }
            record.Evidence[L"slot"] = DecText(nmi.Slot);
            record.Evidence[L"node"] = SnapshotHex(nmi.NodeAddress, 16);
            record.Evidence[L"callback"] = SnapshotHex(nmi.Callback, 16);
            record.Evidence[L"module"] = nmi.CallbackModule;
            record.Evidence[L"symbol"] = nmi.CallbackSymbol;
            record.Evidence[L"notes"] = nmi.Notes;
            AddRecord(document, std::move(record));
        }
    }

    void CaptureMapperRemnants(DeviceClient& device, SymbolEngine& symbols, SnapshotDocument* document)
    {
        MapperRemnantScanner scanner(device, symbols);
        MapperScanOptions options = {};
        MapperScanResult result = {};
        std::wstring error;
        if (!scanner.Scan(options, &result, &error))
        {
            AddWarning(document, L"leftover-mapper", error);
            AddWarnings(document, L"leftover-mapper", result.Warnings);
            return;
        }

        AddWarnings(document, L"leftover-mapper", result.Warnings);
        document->Metadata[L"leftover_mapper_unloaded_complete"] =
            BoolText(result.UnloadedComplete);
        document->Metadata[L"leftover_mapper_piddb_complete"] =
            BoolText(result.PiddbComplete);
        document->Metadata[L"leftover_mapper_hash_complete"] =
            BoolText(result.HashComplete);

        for (const MapperUnloadedRecord& item : result.Unloaded)
        {
            SnapshotRecord record;
            record.Domain = L"leftover-mapper";
            record.Identity = L"unloaded:" + SnapshotToLower(item.Name) + L":" +
                SnapshotHex(item.StartAddress, 16);
            record.Display = item.Name.empty() ? L"<unnamed unloaded>" : item.Name;
            record.Risk = item.Suspicious ? L"high" : L"medium";
            record.Tags = {L"unloaded"};
            if (item.Suspicious)
            {
                record.Tags.push_back(L"suspicious");
            }
            record.Evidence[L"start"] = SnapshotHex(item.StartAddress, 16);
            record.Evidence[L"end"] = SnapshotHex(item.EndAddress, 16);
            record.Evidence[L"still_executable"] = BoolText(item.StillExecutable);
            record.Evidence[L"notes"] = item.Notes;
            AddRecord(document, std::move(record));
        }

        for (const MapperPiddbRecord& item : result.Piddb)
        {
            if (item.InLoadedModules && !item.Suspicious)
            {
                continue;
            }
            SnapshotRecord record;
            record.Domain = L"leftover-mapper";
            record.Identity = L"piddb:" + SnapshotToLower(item.DriverName) + L":" +
                DecText(item.TimeDateStamp);
            record.Display = item.DriverName;
            record.Risk = item.Suspicious ? L"high" : L"medium";
            record.Tags = {L"piddb"};
            record.Tags.push_back(item.Suspicious ? L"suspicious" : L"stale");
            record.Evidence[L"time_date_stamp"] = DecText(item.TimeDateStamp);
            record.Evidence[L"notes"] = item.Notes;
            AddRecord(document, std::move(record));
        }

        for (const MapperHashRecord& item : result.HashEntries)
        {
            if (item.InLoadedModules && !item.Suspicious)
            {
                continue;
            }
            SnapshotRecord record;
            record.Domain = L"leftover-mapper";
            record.Identity = L"cihash:" + SnapshotToLower(item.DriverName);
            record.Display = item.DriverName;
            record.Risk = item.Suspicious ? L"high" : L"medium";
            record.Tags = {L"cihash"};
            record.Tags.push_back(item.Suspicious ? L"suspicious" : L"stale");
            record.Evidence[L"notes"] = item.Notes;
            AddRecord(document, std::move(record));
        }
    }

    uint64_t Fnv1aFold(uint64_t hash, uint64_t value)
    {
        for (int i = 0; i < 8; ++i)
        {
            uint8_t b = static_cast<uint8_t>((value >> (i * 8)) & 0xFFull);
            hash ^= b;
            hash *= 0x100000001b3ull;
        }
        return hash;
    }

    // Captures the CPU-state detection surface (SYSCALL MSRs, control
    // registers, SSDT, IDT) into the snapshot. Records use stable identities
    // with the entry-pointer value or a routine-set fingerprint in evidence, so
    // an in-image change between a same-boot baseline and a later snapshot
    // surfaces as an escalation; suspicious findings are emitted as high-risk
    // records that surface as additions. Reuses the native CPU-state scanners;
    // no new driver IOCTL is involved here.
    void CaptureCpuState(DeviceClient& device, SymbolEngine& symbols, SnapshotDocument* document)
    {
        {
            MsrScanner scanner(device, symbols);
            MsrScanResult result = {};
            std::wstring error;
            if (!scanner.Scan(&result, &error))
            {
                AddWarning(document, L"cpu-state", L"msr: " + error);
                AddWarnings(document, L"cpu-state", result.Warnings);
            }
            else
            {
                AddWarnings(document, L"cpu-state", result.Warnings);
                for (const MsrReading& msr : result.Readings)
                {
                    if (msr.PerCpuValues.empty())
                    {
                        continue;
                    }
                    uint64_t value = msr.PerCpuValues.front();
                    SnapshotRecord record;
                    record.Domain = L"cpu-state";
                    record.Identity = L"cpu-state:msr:" + msr.MsrName;
                    record.Display = msr.MsrName;
                    record.Risk = msr.Suspicious ? L"high" : L"info";
                    record.Tags = {L"cpu-state", L"msr"};
                    if (msr.Suspicious)
                    {
                        record.Tags.push_back(L"suspicious");
                    }
                    record.Evidence[L"msr"] = msr.MsrName;
                    record.Evidence[L"value"] = SnapshotHex(value, 16);
                    if (!msr.OwningModule.empty())
                    {
                        record.Evidence[L"module"] = msr.OwningModule;
                    }
                    if (!msr.NearestSymbol.empty())
                    {
                        record.Evidence[L"symbol"] = msr.NearestSymbol;
                    }
                    if (msr.Divergent)
                    {
                        record.Evidence[L"divergent"] = L"true";
                    }
                    if (!msr.Notes.empty())
                    {
                        record.Evidence[L"notes"] = msr.Notes;
                    }
                    AddRecord(document, std::move(record));
                }
            }
        }

        {
            CrScanner scanner(device);
            CrScanResult result = {};
            std::wstring error;
            if (!scanner.Scan(&result, &error))
            {
                AddWarning(document, L"cpu-state", L"cr: " + error);
                AddWarnings(document, L"cpu-state", result.Warnings);
            }
            else
            {
                AddWarnings(document, L"cpu-state", result.Warnings);
                for (const CrReading& cr : result.Readings)
                {
                    if (cr.Name == L"CR8" || cr.PerCpuValues.empty())
                    {
                        continue; // CR8 is TPR, not integrity-relevant
                    }
                    uint64_t value = cr.PerCpuValues.front();
                    SnapshotRecord record;
                    record.Domain = L"cpu-state";
                    record.Identity = L"cpu-state:cr:" + cr.Name;
                    record.Display = cr.Name;
                    record.Risk = cr.Suspicious ? L"high" : L"info";
                    record.Tags = {L"cpu-state", L"cr"};
                    if (cr.Suspicious)
                    {
                        record.Tags.push_back(L"suspicious");
                    }
                    record.Evidence[L"register"] = cr.Name;
                    record.Evidence[L"value"] = SnapshotHex(value, 16);
                    if (cr.Divergent)
                    {
                        record.Evidence[L"divergent"] = L"true";
                    }
                    if (!cr.Notes.empty())
                    {
                        record.Evidence[L"notes"] = cr.Notes;
                    }
                    AddRecord(document, std::move(record));
                }
            }
        }

        {
            SsdtScanner scanner(device, symbols);
            SsdtScanResult result = {};
            std::wstring error;
            if (!scanner.Scan(&result, &error))
            {
                AddWarning(document, L"cpu-state", L"ssdt: " + error);
                AddWarnings(document, L"cpu-state", result.Warnings);
            }
            else
            {
                AddWarnings(document, L"cpu-state", result.Warnings);
                for (const SsdtTable& table : result.Tables)
                {
                    if (!table.Resolved)
                    {
                        continue;
                    }

                    uint64_t fingerprint = 0xcbf29ce484222325ull;
                    for (const SsdtEntry& entry : table.Entries)
                    {
                        fingerprint = Fnv1aFold(fingerprint, entry.Routine);
                    }

                    SnapshotRecord summary;
                    summary.Domain = L"cpu-state";
                    summary.Identity = L"cpu-state:ssdt:" + table.Name;
                    summary.Display = L"SSDT " + table.Name;
                    summary.Risk = table.SuspiciousCount > 0 ? L"high" : L"info";
                    summary.Tags = {L"cpu-state", L"ssdt"};
                    summary.Evidence[L"table"] = table.Name;
                    summary.Evidence[L"base"] = SnapshotHex(table.TableBase, 16);
                    summary.Evidence[L"count"] = DecText(table.Limit);
                    summary.Evidence[L"suspicious"] = DecText(table.SuspiciousCount);
                    summary.Evidence[L"fingerprint"] = SnapshotHex(fingerprint, 16);
                    AddRecord(document, std::move(summary));

                    for (const SsdtEntry& entry : table.Entries)
                    {
                        if (!entry.Suspicious)
                        {
                            continue;
                        }
                        SnapshotRecord record;
                        record.Domain = L"cpu-state";
                        record.Identity = L"cpu-state:ssdt-hook:" + table.Name + L":" + DecText(entry.Index) +
                            L":" + SnapshotHex(entry.Routine, 16);
                        record.Display = L"SSDT hook #" + DecText(entry.Index);
                        record.Risk = L"high";
                        record.Tags = {L"cpu-state", L"ssdt", L"suspicious"};
                        record.Evidence[L"index"] = DecText(entry.Index);
                        record.Evidence[L"routine"] = SnapshotHex(entry.Routine, 16);
                        record.Evidence[L"module"] = entry.Module;
                        record.Evidence[L"symbol"] = entry.Symbol;
                        record.Evidence[L"notes"] = entry.Notes;
                        AddRecord(document, std::move(record));
                    }
                }
            }
        }

        {
            IdtScanner scanner(device, symbols);
            IdtScanResult result = {};
            std::wstring error;
            if (!scanner.Scan(&result, &error))
            {
                AddWarning(document, L"cpu-state", L"idt: " + error);
                AddWarnings(document, L"cpu-state", result.Warnings);
            }
            else
            {
                AddWarnings(document, L"cpu-state", result.Warnings);

                uint64_t fingerprint = 0xcbf29ce484222325ull;
                for (const IdtEntry& entry : result.Entries)
                {
                    if (entry.Present)
                    {
                        fingerprint = Fnv1aFold(fingerprint, entry.Handler);
                    }
                }

                SnapshotRecord summary;
                summary.Domain = L"cpu-state";
                summary.Identity = L"cpu-state:idt";
                summary.Display = L"IDT (cpu " + DecText(result.ProcessorNumber) + L")";
                summary.Risk = result.AnySuspicious ? L"high" : L"info";
                summary.Tags = {L"cpu-state", L"idt"};
                summary.Evidence[L"base"] = SnapshotHex(result.IdtBase, 16);
                summary.Evidence[L"entries"] = DecText(result.EntryCount);
                summary.Evidence[L"suspicious"] = DecText(result.SuspiciousCount);
                summary.Evidence[L"fingerprint"] = SnapshotHex(fingerprint, 16);
                AddRecord(document, std::move(summary));

                for (const IdtEntry& entry : result.Entries)
                {
                    if (!entry.Suspicious)
                    {
                        continue;
                    }
                    SnapshotRecord record;
                    record.Domain = L"cpu-state";
                    record.Identity = L"cpu-state:idt-hook:" + DecText(entry.Vector) + L":" + SnapshotHex(entry.Handler, 16);
                    record.Display = L"IDT hook vector " + DecText(entry.Vector);
                    record.Risk = L"high";
                    record.Tags = {L"cpu-state", L"idt", L"suspicious"};
                    record.Evidence[L"vector"] = DecText(entry.Vector);
                    record.Evidence[L"handler"] = SnapshotHex(entry.Handler, 16);
                    record.Evidence[L"module"] = entry.Module;
                    record.Evidence[L"symbol"] = entry.Symbol;
                    record.Evidence[L"notes"] = entry.Notes;
                    AddRecord(document, std::move(record));
                }
            }
        }
    }

    void CaptureFirmwareTables(DeviceClient& device, SymbolEngine& symbols, SnapshotDocument* document)
    {
        FirmwareTableScanner scanner(device, symbols);
        FirmwareTableScanResult result = {};
        std::wstring error;

        if (!scanner.Scan(&result, &error))
        {
            AddWarning(document, L"fwtable", error);
            AddWarnings(document, L"fwtable", result.Warnings);
            return;
        }

        AddWarnings(document, L"fwtable", result.Warnings);
        for (const FirmwareTableProviderRecord& provider : result.Records)
        {
            SnapshotRecord record;
            record.Domain = L"fwtable";
            record.Identity = L"fwtable:" + provider.ProviderText + L":" +
                SnapshotHex(provider.NodeAddress, 16);
            record.Display = provider.ProviderText;
            record.Risk = provider.Suspicious ? L"high" : L"low";
            record.Tags = {L"fwtable"};
            if (provider.Suspicious)
            {
                record.Tags.push_back(L"suspicious");
            }
            record.Evidence[L"provider"] = provider.ProviderText;
            record.Evidence[L"signature"] = SnapshotHex(provider.ProviderSignature, 8);
            record.Evidence[L"node"] = SnapshotHex(provider.NodeAddress, 16);
            record.Evidence[L"handler"] = SnapshotHex(provider.FirmwareTableHandler, 16);
            record.Evidence[L"handler_module"] = provider.HandlerModule;
            if (provider.HandlerModule.empty() && provider.FirmwareTableHandler != 0)
            {
                record.Evidence[L"handler_module_address"] = SnapshotHex(provider.FirmwareTableHandler, 16);
            }
            record.Evidence[L"handler_symbol"] = provider.HandlerSymbol;
            record.Evidence[L"driver_object"] = SnapshotHex(provider.DriverObject, 16);
            record.Evidence[L"driver"] = provider.DriverName.empty() && provider.DriverObject != 0 ?
                SnapshotHex(provider.DriverObject, 16) :
                provider.DriverName;
            record.Evidence[L"driver_start"] = SnapshotHex(provider.DriverStart, 16);
            record.Evidence[L"driver_module"] = provider.DriverModule;
            if (provider.DriverModule.empty() && provider.DriverStart != 0)
            {
                record.Evidence[L"driver_module_address"] = SnapshotHex(provider.DriverStart, 16);
            }
            record.Evidence[L"notes"] = provider.Notes;
            AddRecord(document, std::move(record));
        }
    }

    void CapturePool(DeviceClient& device, SymbolEngine& symbols, SnapshotDocument* document)
    {
        PoolScanner scanner(device, symbols);
        PoolScanner::Options options = {};
        options.Target = PoolScanner::Scope::Big;
        options.Paged = PoolScanner::PagedFilter::NonPagedOnly;
        options.AnnotateAttributes = true;
        PoolScanResult result = {};
        std::wstring error;

        if (!scanner.Scan(options, &result, &error))
        {
            AddWarning(document, L"pool", error);
            AddWarnings(document, L"pool", result.Warnings);
            return;
        }

        AddWarnings(document, L"pool", result.Warnings);
        for (const BigPoolEntryRecord& entry : result.Entries)
        {
            bool wx = entry.AttributesQueried && entry.IsWritable && entry.IsExecutable;
            bool large = entry.SizeInBytes >= kLargePoolThreshold;
            SnapshotRecord record;
            record.Domain = L"pool";
            record.Identity = L"pool:" + entry.TagText + L":" +
                SnapshotHex(entry.VirtualAddress, 16) + L":" + DecText(entry.SizeInBytes);
            record.Display = entry.TagText + L" " + SnapshotHex(entry.VirtualAddress, 16);
            record.Risk = wx ? L"high" : (large ? L"medium" : L"low");
            record.Volatile = true;
            record.Tags = {L"pool"};
            if (entry.NonPaged)
            {
                record.Tags.push_back(L"nonpaged");
            }
            if (wx)
            {
                record.Tags.push_back(L"wx");
            }
            if (large)
            {
                record.Tags.push_back(L"large");
            }
            record.Evidence[L"address"] = SnapshotHex(entry.VirtualAddress, 16);
            record.Evidence[L"size"] = DecText(entry.SizeInBytes);
            record.Evidence[L"tag"] = entry.TagText;
            record.Evidence[L"nonpaged"] = BoolText(entry.NonPaged);
            record.Evidence[L"attributes_queried"] = BoolText(entry.AttributesQueried);
            record.Evidence[L"readable"] = BoolText(entry.IsReadable);
            record.Evidence[L"writable"] = BoolText(entry.IsWritable);
            record.Evidence[L"executable"] = BoolText(entry.IsExecutable);
            AddRecord(document, std::move(record));
        }
    }

    void CapturePoolPe(DeviceClient& device, SnapshotDocument* document)
    {
        PoolPeHunter hunter(device);
        PoolPeHunter::Options options = {};
        options.Paged = PoolPeHunter::PagedFilter::NonPagedOnly;
        options.HasMinSize = true;
        options.MinSize = 0x1000;
        PoolPeHunterResult result = {};
        std::wstring error;

        if (!hunter.Scan(options, &result, &error))
        {
            AddWarning(document, L"pool", error);
            AddWarnings(document, L"pool", result.Warnings);
            return;
        }

        AddWarnings(document, L"pool", result.Warnings);
        for (const PoolPeHit& hit : result.Hits)
        {
            bool wiped = hit.Probe.MzWiped || hit.Probe.PeSignatureWiped || hit.Probe.ELfanewMismatch;
            SnapshotRecord record;
            record.Domain = L"pool";
            record.Identity = L"pool-pe:" + SnapshotHex(hit.Address, 16) + L":" +
                DecText(hit.SizeInBytes);
            record.Display = L"pool PE " + hit.TagText + L" " + SnapshotHex(hit.Address, 16);
            record.Risk = wiped ? L"high" : L"medium";
            record.Volatile = true;
            record.Tags = {L"pool-pe"};
            if (wiped)
            {
                record.Tags.push_back(L"pool-pe-suspect");
            }
            record.Evidence[L"address"] = SnapshotHex(hit.Address, 16);
            record.Evidence[L"size"] = DecText(hit.SizeInBytes);
            record.Evidence[L"tag"] = hit.TagText;
            record.Evidence[L"nonpaged"] = BoolText(hit.NonPaged);
            record.Evidence[L"mz_wiped"] = BoolText(hit.Probe.MzWiped);
            record.Evidence[L"pe_wiped"] = BoolText(hit.Probe.PeSignatureWiped);
            record.Evidence[L"elfanew_mismatch"] = BoolText(hit.Probe.ELfanewMismatch);
            record.Evidence[L"size_of_image"] = DecText(hit.Probe.SizeOfImage);
            record.Evidence[L"sections"] = DecText(hit.Probe.NumberOfSections);
            AddRecord(document, std::move(record));
        }
    }

    void CaptureWfpScope(WfpScanner& scanner, WfpScanner::Scope scope, const std::wstring& scopeName, SnapshotDocument* document)
    {
        WfpScanner::Options options = {};
        options.Target = scope;
        WfpScanResult result = {};
        std::wstring error;

        if (!scanner.Scan(options, &result, &error))
        {
            AddWarning(document, L"wfp", scopeName + L": " + error);
            AddWarnings(document, L"wfp", result.Warnings);
            return;
        }

        AddWarnings(document, L"wfp", result.Warnings);
        for (const WfpRecord& item : result.Records)
        {
            std::wstring key = !item.Key.empty()
                ? item.Key
                : (item.HasId ? std::to_wstring(item.Id) : item.Name);
            SnapshotRecord record;
            record.Domain = L"wfp";
            record.Identity = L"wfp:" + SnapshotToLower(scopeName) + L":" + SnapshotToLower(key);
            record.Display = scopeName + L" " + item.Name;
            record.Risk = (scope == WfpScanner::Scope::Callouts || scope == WfpScanner::Scope::Filters) ? L"medium" : L"low";
            record.Tags = {L"wfp", scopeName};
            record.Evidence[L"kind"] = item.Kind;
            record.Evidence[L"name"] = item.Name;
            record.Evidence[L"key"] = item.Key;
            record.Evidence[L"id"] = DecText(item.Id);
            record.Evidence[L"provider"] = item.ProviderName;
            record.Evidence[L"provider_key"] = item.ProviderKey;
            record.Evidence[L"layer"] = item.LayerName;
            record.Evidence[L"layer_key"] = item.LayerKey;
            record.Evidence[L"action"] = item.ActionText;
            record.Evidence[L"notes"] = item.Notes;
            AddRecord(document, std::move(record));
        }
    }

    void CaptureWfp(SnapshotDocument* document)
    {
        WfpScanner scanner;
        CaptureWfpScope(scanner, WfpScanner::Scope::Providers, L"providers", document);
        CaptureWfpScope(scanner, WfpScanner::Scope::SubLayers, L"sublayers", document);
        CaptureWfpScope(scanner, WfpScanner::Scope::Callouts, L"callouts", document);
        CaptureWfpScope(scanner, WfpScanner::Scope::Filters, L"filters", document);
        CaptureWfpScope(scanner, WfpScanner::Scope::Layers, L"layers", document);
    }

    void CaptureAlpc(DeviceClient& device, SymbolEngine& symbols, SnapshotDocument* document)
    {
        AlpcScanner scanner(device, symbols);
        AlpcScanner::Options options = {};
        options.Target = AlpcScanner::Scope::Connections;
        AlpcScanResult result = {};
        std::wstring error;

        if (!scanner.Scan(options, &result, &error))
        {
            AddWarning(document, L"alpc", error);
            AddWarnings(document, L"alpc", result.Warnings);
            return;
        }

        AddWarnings(document, L"alpc", result.Warnings);
        for (const AlpcPortRecord& port : result.Records)
        {
            SnapshotRecord record;
            record.Domain = L"alpc";
            record.Identity = L"alpc:" + SnapshotHex(port.Address, 16);
            record.Display = port.Name.empty() ? SnapshotHex(port.Address, 16) : port.Name;
            record.Risk = port.IsNamedDirectoryPort ? L"medium" : L"low";
            record.Volatile = true;
            record.Tags = {L"alpc"};
            if (port.IsConnectionPort)
            {
                record.Tags.push_back(L"connection-port");
            }
            record.Evidence[L"address"] = SnapshotHex(port.Address, 16);
            record.Evidence[L"name"] = port.Name;
            record.Evidence[L"directory"] = port.DirectoryPath;
            record.Evidence[L"owner_pid"] = DecText(port.OwnerProcessId);
            record.Evidence[L"owner_image"] = port.OwnerImageName;
            record.Evidence[L"connection_port"] = SnapshotHex(port.ConnectionPort, 16);
            record.Evidence[L"queues"] = DecText(
                static_cast<uint64_t>(port.MainQueueLength) +
                port.PendingQueueLength +
                port.LargeMessageQueueLength +
                port.CanceledQueueLength +
                port.WaitQueueLength);
            AddRecord(document, std::move(record));
        }
    }

    void CaptureWnf(DeviceClient& device, SymbolEngine& symbols, SnapshotDocument* document)
    {
        WnfScanner scanner(device, symbols);
        WnfScanner::Options options = {};
        options.Target = WnfScanner::Scope::Instances;
        WnfScanResult result = {};
        std::wstring error;

        if (!scanner.Scan(options, &result, &error))
        {
            AddWarning(document, L"wnf", error);
            AddWarnings(document, L"wnf", result.Warnings);
            return;
        }

        AddWarnings(document, L"wnf", result.Warnings);
        for (const WnfInstanceRecord& instance : result.Instances)
        {
            SnapshotRecord record;
            record.Domain = L"wnf";
            record.Identity = L"wnf:" + SnapshotHex(instance.Address, 16);
            record.Display = SnapshotHex(instance.StateName, 16);
            record.Risk = L"low";
            record.Volatile = true;
            record.Tags = {L"wnf"};
            record.Evidence[L"address"] = SnapshotHex(instance.Address, 16);
            record.Evidence[L"state"] = SnapshotHex(instance.StateName, 16);
            record.Evidence[L"owner_pid"] = DecText(instance.OwningPid);
            record.Evidence[L"owner_image"] = instance.OwningImageName;
            record.Evidence[L"subscriber_count"] = DecText(instance.Subscribers.size());
            record.Evidence[L"data_size"] = DecText(instance.DataSize);
            AddRecord(document, std::move(record));
        }
    }

    void CaptureVbs(DeviceClient& device, SymbolEngine& symbols, SnapshotDocument* document)
    {
        VbsScanner scanner(device, symbols);
        VbsScanner::Options options = {};
        options.Target = VbsScanner::Scope::Vbs;
        VbsScanResult result = {};
        std::wstring error;

        if (!scanner.Scan(options, &result, &error))
        {
            AddWarning(document, L"vbs", error);
            AddWarnings(document, L"vbs", result.Warnings);
            return;
        }

        AddWarnings(document, L"vbs", result.Warnings);

        SnapshotRecord vbs;
        vbs.Domain = L"vbs";
        vbs.Identity = L"vbs:state";
        vbs.Display = L"VBS state";
        vbs.Risk = L"info";
        vbs.Tags = {L"vbs"};
        vbs.Evidence[L"vbs_active"] = BoolText(result.VbsActive);
        vbs.Evidence[L"secure_kernel_loaded"] = BoolText(result.SecureKernelLoaded);
        vbs.Evidence[L"skci_loaded"] = BoolText(result.SkciLoaded);
        vbs.Evidence[L"hypervisor_present"] = BoolText(result.Hypervisor.HypervisorPresent);
        vbs.Evidence[L"hypervisor_vendor"] = result.Hypervisor.VendorSignature;
        AddRecord(document, std::move(vbs));

        SnapshotRecord ci;
        ci.Domain = L"vbs";
        ci.Identity = L"ci:options";
        ci.Display = L"Code Integrity options";
        ci.Risk = L"info";
        ci.Tags = {L"ci"};
        ci.Evidence[L"resolved"] = BoolText(result.CiOptions.Resolved);
        ci.Evidence[L"raw"] = SnapshotHex(result.CiOptions.Raw, 8);
        ci.Evidence[L"ci_enabled"] = BoolText(result.CiOptions.CodeIntegrityEnabled);
        ci.Evidence[L"testsign"] = BoolText(result.CiOptions.TestSign);
        ci.Evidence[L"umci"] = BoolText(result.CiOptions.UmciEnabled);
        ci.Evidence[L"hvci"] = BoolText(result.CiOptions.HvciEnforced);
        ci.Evidence[L"hvci_debug"] = BoolText(result.CiOptions.HvciDebugMode);
        AddRecord(document, std::move(ci));
    }

    void CaptureByovdCatalogMetadata(ByovdScanner& scanner, SnapshotDocument* document)
    {
        ByovdCatalogStatus status = {};
        std::wstring error;

        if (scanner.QueryCatalogStatus(&status, &error))
        {
            document->Metadata[L"byovd_catalog_path"] = status.CatalogPath;
            document->Metadata[L"byovd_catalog_entries"] = DecText(status.EntryCount);
            document->Metadata[L"byovd_catalog_age_seconds"] = DecText(status.AgeSeconds);
            document->Metadata[L"byovd_catalog_stale"] = BoolText(status.Stale);
            document->Metadata[L"byovd_catalog_fingerprint"] = FingerprintFileFnv64(status.CatalogPath);
        }
        else
        {
            AddWarning(document, L"byovd", error);
        }
    }

    void CaptureByovd(SymbolEngine& symbols, const SnapshotCaptureOptions& options, SnapshotDocument* document)
    {
        ByovdScanner scanner(symbols, options.ExecutableDirectory);
        std::wstring error;
        ByovdScanOptions scanOptions = {};
        scanOptions.AutoUpdate = options.AllowByovdAutoUpdate;
        scanOptions.ForceUpdate = false;
        scanOptions.EnableYara = false;
        ByovdScanResult result = {};

        if (!scanner.Scan(scanOptions, &result, &error))
        {
            AddWarning(document, L"byovd", error);
            AddWarnings(document, L"byovd", result.Warnings);
            CaptureByovdCatalogMetadata(scanner, document);
            return;
        }

        CaptureByovdCatalogMetadata(scanner, document);
        AddWarnings(document, L"byovd", result.Warnings);
        for (const ByovdModuleRecord& module : result.Records)
        {
            if (module.Matches.empty())
            {
                continue;
            }

            bool high = RecordHasHighByovdMatch(module);
            SnapshotRecord record;
            record.Domain = L"byovd";
            record.Identity = L"byovd:" + SnapshotToLower(module.ImageName) + L":" +
                SnapshotToLower(module.Sha256);
            record.Display = module.ImageName;
            record.Risk = high ? L"high" : L"medium";
            record.Tags = {L"byovd"};
            if (high)
            {
                record.Tags.push_back(L"high-confidence");
            }
            record.Evidence[L"image"] = module.ImageName;
            record.Evidence[L"path"] = module.DiskPath;
            record.Evidence[L"base"] = SnapshotHex(module.Base, 16);
            record.Evidence[L"size"] = DecText(module.Size);
            record.Evidence[L"sha256"] = module.Sha256;
            record.Evidence[L"file_version"] = module.FileVersion;
            record.Evidence[L"matches"] = ByovdMatchSummary(module);
            AddRecord(document, std::move(record));
        }
    }

    void CaptureVadDkomForNewProcesses(DeviceClient& device, SymbolEngine& symbols, const SnapshotCaptureOptions& options, SnapshotDocument* document)
    {
        if (options.BaselineForVadDkom == nullptr || document == nullptr)
        {
            return;
        }

        std::set<std::wstring> baselineProcesses = BuildBaselineProcessSet(*options.BaselineForVadDkom);
        ProcessTriageScanner scanner(device, symbols);

        for (const SnapshotProcessRecord& process : document->Processes)
        {
            if (process.Identity.empty() ||
                baselineProcesses.find(process.Identity) != baselineProcesses.end())
            {
                continue;
            }

            SnapshotRecord scanned;
            scanned.Domain = L"vad-dkom";
            scanned.Identity = L"vad-scan:" + process.Identity;
            scanned.Display = process.ImageName + L" pid=" + std::to_wstring(process.ProcessId);
            scanned.Risk = L"info";
            scanned.Tags = {L"vad-dkom", L"process-scanned"};
            scanned.Evidence[L"pid"] = DecText(process.ProcessId);
            scanned.Evidence[L"image"] = process.ImageName;
            scanned.Evidence[L"eprocess"] = SnapshotHex(process.Eprocess, 16);
            scanned.Evidence[L"dtb"] = SnapshotHex(process.DirectoryTableBase, 16);

            ProcessVadScanOptions vadOptions = {};
            vadOptions.Target = BuildTriageTarget(process);
            vadOptions.ScanHiddenPtes = true;
            vadOptions.SummaryOnly = true;
            ProcessVadScanResult vadResult = {};
            std::wstring error;
            if (!scanner.ScanVad(vadOptions, &vadResult, &error))
            {
                scanned.Risk = L"low";
                scanned.Tags.push_back(L"scan-failed");
                scanned.Evidence[L"scan_failed"] = L"true";
                scanned.Evidence[L"error"] = error;
                AddWarning(document, L"vad-dkom", process.ImageName + L" pid=" +
                    std::to_wstring(process.ProcessId) + L": " + error);
                AddRecord(document, std::move(scanned));
                continue;
            }

            scanned.Evidence[L"hidden_pte_ranges"] = DecText(vadResult.HiddenPteRanges);
            scanned.Evidence[L"hidden_pte_bytes"] = DecText(vadResult.HiddenPteBytes);
            scanned.Evidence[L"hidden_pte_wx"] = DecText(vadResult.HiddenPteWxCount);
            scanned.Evidence[L"hidden_pte_exec"] = DecText(vadResult.HiddenPteExecutableCount);
            AddWarnings(document, L"vad-dkom", vadResult.Warnings);
            AddRecord(document, std::move(scanned));

            for (const ProcessHiddenVadPteRecord& hidden : vadResult.HiddenPteRecords)
            {
                SnapshotRecord record;
                record.Domain = L"vad-dkom";
                record.Identity = L"hidden-pte:" + process.Identity + L":" +
                    SnapshotHex(hidden.StartAddress, 16) + L":" + SnapshotHex(hidden.EndAddress, 16);
                record.Display = process.ImageName + L" hidden PTE " + SnapshotHex(hidden.StartAddress, 16);
                record.Risk = (hidden.Writable && hidden.Executable) ? L"high" :
                    (hidden.Executable ? L"medium" : L"low");
                record.Tags = {L"vad-dkom", L"hidden-pte"};
                if (hidden.Writable && hidden.Executable)
                {
                    record.Tags.push_back(L"wx");
                }
                if (hidden.Executable)
                {
                    record.Tags.push_back(L"executable");
                }
                record.Evidence[L"pid"] = DecText(process.ProcessId);
                record.Evidence[L"image"] = process.ImageName;
                record.Evidence[L"eprocess"] = SnapshotHex(process.Eprocess, 16);
                record.Evidence[L"start"] = SnapshotHex(hidden.StartAddress, 16);
                record.Evidence[L"end"] = SnapshotHex(hidden.EndAddress, 16);
                record.Evidence[L"size"] = DecText(hidden.Size);
                record.Evidence[L"pages"] = DecText(hidden.PageCount);
                record.Evidence[L"physical"] = SnapshotHex(hidden.PhysicalAddress, 16);
                record.Evidence[L"leaf_entry_address"] = SnapshotHex(hidden.LeafEntryAddress, 16);
                record.Evidence[L"leaf_entry"] = SnapshotHex(hidden.LeafEntry, 16);
                record.Evidence[L"writable"] = BoolText(hidden.Writable);
                record.Evidence[L"executable"] = BoolText(hidden.Executable);
                record.Evidence[L"user_accessible"] = BoolText(hidden.UserAccessible);
                record.Evidence[L"notes"] = hidden.Notes;
                AddRecord(document, std::move(record));
            }
        }
    }
}

SnapshotCollector::SnapshotCollector(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool SnapshotCollector::Capture(const SnapshotCaptureOptions& options, SnapshotDocument* document, std::wstring* error)
{
    bool ok = false;
    if (error != nullptr)
    {
        error->clear();
    }

    do
    {
        if (document == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid snapshot output buffer";
            }
            break;
        }

        *document = SnapshotDocument{};
        document->Schema = L"kn-live-dbg.snapshot.v1";
        document->Label = options.Label.empty() ? L"snapshot" : options.Label;
        document->TimestampUtc = SnapshotCurrentUtcTimestamp();
        document->SameBootOnly = true;
        document->BootId = SnapshotCurrentBootId();
        document->Metadata[L"include_all"] = BoolText(options.IncludeAll);
        document->Metadata[L"vad_dkom_new_process_mode"] = BoolText(options.CaptureVadDkomForNewProcesses);
        document->Metadata[L"byovd_auto_update"] = BoolText(options.AllowByovdAutoUpdate);

        CaptureProcessInventory(device_, symbols_, options, document);

        if (!options.IncludeAll)
        {
            ok = true;
            break;
        }

        CaptureModules(device_, symbols_, document);
        CaptureDrivers(device_, symbols_, document);
        CaptureCallbacks(device_, symbols_, document);
        CaptureMinifilterAttachments(document);
        CaptureEtw(device_, symbols_, document);
        CaptureNmi(device_, symbols_, document);
        CaptureMapperRemnants(device_, symbols_, document);
        CaptureCpuState(device_, symbols_, document);
        CaptureHal(device_, symbols_, document);
        CaptureHive(device_, symbols_, document);
        CaptureDpcTimer(device_, symbols_, document);
        CaptureFirmwareTables(device_, symbols_, document);
        CapturePool(device_, symbols_, document);
        CapturePoolPe(device_, document);
        CaptureWfp(document);
        CaptureAlpc(device_, symbols_, document);
        CaptureWnf(device_, symbols_, document);
        CaptureVbs(device_, symbols_, document);
        CaptureByovd(symbols_, options, document);

        if (options.CaptureVadDkomForNewProcesses)
        {
            CaptureVadDkomForNewProcesses(device_, symbols_, options, document);
        }

        ok = true;
    } while (false);

    return ok;
}
