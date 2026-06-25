#include "EtwScanner.h"
#include "McpJson.h"

#include <Zydis.h>

#include <algorithm>
#include <cstdio>
#include <cwctype>
#include <iomanip>
#include <sstream>

namespace
{
    constexpr uint64_t kKernelSpaceMin       = 0xffff800000000000ull;
    // Reject sign-extended small negatives such as ffffffff`fffe79e8.
    // They pass a broad kernel-half test but are not useful ETW structure VAs.
    constexpr uint64_t kKernelSpaceGuardMin  = 0xffffffff00000000ull;
    constexpr uint32_t kEtwLoggerSlotCount   = 64;
    constexpr uint64_t kLoggerArrayOffset    = 0x10;
    constexpr uint64_t kFallbackLoggerName   = 0x68;
    constexpr uint64_t kFallbackGetCpuClock  = 0x28;
    constexpr uint32_t kMaxRawBytesPerRead   = 0x1000;
    constexpr uint32_t kMaxNameByteLength    = 2048;

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelSpaceMin && value < kKernelSpaceGuardMin;
    }

    bool TryAdd(uint64_t left, uint64_t right, uint64_t* result)
    {
        bool ok = false;

        do
        {
            if (result == nullptr)
            {
                break;
            }

            if (left > (~0ull - right))
            {
                break;
            }

            *result = left + right;
            ok = true;
        } while (false);

        return ok;
    }

    bool ReadKernelBytes(
        DeviceClient& device,
        uint64_t address,
        uint32_t length,
        std::vector<uint8_t>* bytes,
        std::wstring* error)
    {
        bool ok = false;

        do
        {
            if (bytes == nullptr || length == 0 || length > kMaxRawBytesPerRead)
            {
                if (error != nullptr)
                {
                    *error = L"invalid read request";
                }
                break;
            }

            if (!device.ReadMemory(address, length, bytes, error, 0))
            {
                break;
            }

            if (bytes->size() != length)
            {
                if (error != nullptr)
                {
                    *error = L"short kernel read";
                }
                break;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool ReadU16(DeviceClient& device, uint64_t address, uint16_t* value, std::wstring* error)
    {
        bool ok = false;
        do
        {
            if (value == nullptr)
            {
                break;
            }
            std::vector<uint8_t> bytes;
            if (!ReadKernelBytes(device, address, sizeof(uint16_t), &bytes, error))
            {
                break;
            }
            memcpy(value, bytes.data(), sizeof(uint16_t));
            ok = true;
        } while (false);
        return ok;
    }

    bool ReadU64(DeviceClient& device, uint64_t address, uint64_t* value, std::wstring* error)
    {
        bool ok = false;
        do
        {
            if (value == nullptr)
            {
                break;
            }
            std::vector<uint8_t> bytes;
            if (!ReadKernelBytes(device, address, sizeof(uint64_t), &bytes, error))
            {
                break;
            }
            memcpy(value, bytes.data(), sizeof(uint64_t));
            ok = true;
        } while (false);
        return ok;
    }

    bool ReadUnicodeStringAt(
        DeviceClient& device,
        uint64_t address,
        std::wstring* value)
    {
        bool ok = false;

        do
        {
            if (value == nullptr || !IsKernelAddress(address))
            {
                break;
            }

            uint16_t length16 = 0;
            if (!ReadU16(device, address, &length16, nullptr))
            {
                break;
            }

            uint64_t bufferFieldAddress = 0;
            if (!TryAdd(address, 8, &bufferFieldAddress))
            {
                break;
            }

            uint64_t bufferValue = 0;
            if (!ReadU64(device, bufferFieldAddress, &bufferValue, nullptr))
            {
                break;
            }

            if (length16 == 0 || bufferValue == 0)
            {
                value->clear();
                ok = true;
                break;
            }

            if (!IsKernelAddress(bufferValue))
            {
                break;
            }

            uint32_t length = length16;
            if (length > kMaxNameByteLength)
            {
                length = kMaxNameByteLength;
            }

            std::vector<uint8_t> bytes;
            if (!ReadKernelBytes(device, bufferValue, length, &bytes, nullptr))
            {
                break;
            }

            value->assign(reinterpret_cast<const wchar_t*>(bytes.data()), bytes.size() / sizeof(wchar_t));
            ok = true;
        } while (false);

        return ok;
    }

    struct CandidateScore
    {
        uint64_t Base = 0;
        std::wstring Source;
        uint32_t LoggerCount = 0;
        uint32_t NullCount = 0;
        uint32_t GarbageCount = 0;
        bool ReadOk = false;
    };

    bool AutoDetectLoggerArrayBase(
        DeviceClient& device,
        uint64_t debuggerData,
        uint64_t loggerNameOffset,
        CandidateScore* bestOut,
        uint64_t* siloPointerOut);

    bool ResolveLoggerLayout(
        SymbolEngine& symbols,
        uint64_t* loggerNameOffset,
        uint64_t* getCpuClockOffset,
        bool* fromPdb)
    {
        bool ok = false;

        do
        {
            if (loggerNameOffset == nullptr || getCpuClockOffset == nullptr || fromPdb == nullptr)
            {
                break;
            }

            *fromPdb = false;
            *loggerNameOffset = kFallbackLoggerName;
            *getCpuClockOffset = kFallbackGetCpuClock;

            TypeFieldInfo nameField = {};
            TypeFieldInfo clockField = {};
            std::wstring localError;

            bool gotName = symbols.FindField(L"nt!_WMI_LOGGER_CONTEXT", L"LoggerName", &nameField, &localError);
            bool gotClock = symbols.FindField(L"nt!_WMI_LOGGER_CONTEXT", L"GetCpuClock", &clockField, &localError);

            if (gotName && gotClock)
            {
                *loggerNameOffset = nameField.Offset;
                *getCpuClockOffset = clockField.Offset;
                *fromPdb = true;
            }

            ok = true;
        } while (false);

        return ok;
    }

    bool ResolveLoggerArrayBase(
        DeviceClient& device,
        SymbolEngine& symbols,
        uint64_t debuggerData,
        uint64_t loggerNameOffset,
        uint64_t* loggerArrayBase,
        uint64_t* siloStateOut,
        std::wstring* sourceLabel,
        bool* usedSiloPath)
    {
        bool ok = false;

        do
        {
            if (loggerArrayBase == nullptr || sourceLabel == nullptr || usedSiloPath == nullptr || siloStateOut == nullptr)
            {
                break;
            }

            *usedSiloPath = false;
            *siloStateOut = 0;

            TypeFieldInfo siloField = {};
            bool gotSiloField = false;
            for (const wchar_t* fieldName : {L"EtwpDebuggerDataSilo", L"SiloGlobals", L"Reserved3"})
            {
                if (symbols.FindField(L"nt!_ETW_DEBUGGER_DATA", fieldName, &siloField, nullptr))
                {
                    gotSiloField = true;
                    break;
                }
            }

            if (gotSiloField)
            {
                uint64_t siloPointerAddress = 0;
                if (TryAdd(debuggerData, siloField.Offset, &siloPointerAddress))
                {
                    uint64_t siloAddress = 0;
                    if (ReadU64(device, siloPointerAddress, &siloAddress, nullptr) &&
                        siloAddress != 0 &&
                        IsKernelAddress(siloAddress))
                    {
                        TypeFieldInfo loggerArrayField = {};
                        bool gotLoggerArray = false;
                        for (const wchar_t* fieldName : {L"EtwpLoggerContext", L"LoggerContext", L"EtwpLoggers", L"Loggers"})
                        {
                            if (symbols.FindField(L"nt!_ETW_DEBUGGER_DATA_SILODRIVERSTATE", fieldName, &loggerArrayField, nullptr))
                            {
                                gotLoggerArray = true;
                                break;
                            }
                        }

                        if (gotLoggerArray)
                        {
                            uint64_t base = 0;
                            if (TryAdd(siloAddress, loggerArrayField.Offset, &base))
                            {
                                *loggerArrayBase = base;
                                *siloStateOut = siloAddress;
                                *sourceLabel = L"silo-pdb";
                                *usedSiloPath = true;
                                ok = true;
                                break;
                            }
                        }
                    }
                }
            }

            TypeFieldInfo directField = {};
            for (const wchar_t* fieldName : {L"EtwpLoggerContext", L"Loggers", L"EtwpLoggers"})
            {
                if (symbols.FindField(L"nt!_ETW_DEBUGGER_DATA", fieldName, &directField, nullptr))
                {
                    uint64_t base = 0;
                    if (TryAdd(debuggerData, directField.Offset, &base))
                    {
                        *loggerArrayBase = base;
                        *sourceLabel = L"direct-pdb";
                        ok = true;
                        break;
                    }
                }
            }

            if (ok)
            {
                break;
            }

            // Step 3: heuristic auto-detect - search offsets within EtwpDebuggerData
            // and within candidate silo pointers, score by valid logger contexts.
            CandidateScore best = {};
            uint64_t siloFromHeuristic = 0;
            if (AutoDetectLoggerArrayBase(device, debuggerData, loggerNameOffset, &best, &siloFromHeuristic))
            {
                *loggerArrayBase = best.Base;
                *sourceLabel = L"auto:" + best.Source;
                if (siloFromHeuristic != 0)
                {
                    *siloStateOut = siloFromHeuristic;
                    *usedSiloPath = true;
                }
                ok = true;
                break;
            }

            uint64_t legacy = 0;
            if (!TryAdd(debuggerData, kLoggerArrayOffset, &legacy))
            {
                break;
            }

            *loggerArrayBase = legacy;
            *sourceLabel = L"legacy-fallback(+0x10)";
            ok = true;
        } while (false);

        return ok;
    }

    int RankCandidate(const CandidateScore& score)
    {
        // Loggers heavily preferred; nulls neutral-positive; garbage punished.
        return static_cast<int>(score.LoggerCount) * 100
            + static_cast<int>(score.NullCount)
            - static_cast<int>(score.GarbageCount) * 5;
    }

    bool ValidateLoggerContext(
        DeviceClient& device,
        uint64_t loggerContext,
        uint64_t loggerNameOffset);

    void EvaluateLoggerArrayCandidate(
        DeviceClient& device,
        uint64_t base,
        uint64_t loggerNameOffset,
        const std::wstring& sourceLabel,
        CandidateScore* score)
    {
        if (score == nullptr)
        {
            return;
        }

        score->Base = base;
        score->Source = sourceLabel;
        score->LoggerCount = 0;
        score->NullCount = 0;
        score->GarbageCount = 0;
        score->ReadOk = false;

        std::vector<uint8_t> bytes;
        if (!ReadKernelBytes(device, base, kEtwLoggerSlotCount * sizeof(uint64_t), &bytes, nullptr))
        {
            return;
        }

        score->ReadOk = true;

        for (uint32_t slot = 0; slot < kEtwLoggerSlotCount; ++slot)
        {
            uint64_t value = 0;
            memcpy(&value, bytes.data() + slot * sizeof(uint64_t), sizeof(uint64_t));

            if (value == 0)
            {
                ++score->NullCount;
                continue;
            }
            if (!IsKernelAddress(value))
            {
                ++score->GarbageCount;
                continue;
            }
            if (ValidateLoggerContext(device, value, loggerNameOffset))
            {
                ++score->LoggerCount;
            }
            else
            {
                ++score->GarbageCount;
            }
        }
    }

    std::wstring FormatHexOffset(uint64_t offset)
    {
        wchar_t buf[32];
        swprintf_s(buf, L"0x%llx", static_cast<unsigned long long>(offset));
        return std::wstring(buf);
    }

    bool AutoDetectLoggerArrayBase(
        DeviceClient& device,
        uint64_t debuggerData,
        uint64_t loggerNameOffset,
        CandidateScore* bestOut,
        uint64_t* siloPointerOut)
    {
        bool found = false;

        do
        {
            if (bestOut == nullptr || siloPointerOut == nullptr)
            {
                break;
            }

            *bestOut = CandidateScore{};
            *siloPointerOut = 0;

            CandidateScore best = {};
            bool haveBest = false;

            // Step 1: scan direct offsets within EtwpDebuggerData
            for (uint64_t offset = 0x10; offset <= 0x100; offset += sizeof(uint64_t))
            {
                uint64_t base = 0;
                if (!TryAdd(debuggerData, offset, &base))
                {
                    continue;
                }

                CandidateScore score = {};
                EvaluateLoggerArrayCandidate(
                    device, base, loggerNameOffset, L"debuggerData+" + FormatHexOffset(offset), &score);
                if (!score.ReadOk || score.LoggerCount == 0)
                {
                    continue;
                }

                if (!haveBest || RankCandidate(score) > RankCandidate(best))
                {
                    best = score;
                    haveBest = true;
                }
            }

            // Step 2: follow potential silo pointers and scan within
            for (uint64_t siloFieldOffset : {0x08ull, 0x10ull, 0x18ull, 0x20ull})
            {
                uint64_t siloPointerAddress = 0;
                if (!TryAdd(debuggerData, siloFieldOffset, &siloPointerAddress))
                {
                    continue;
                }

                uint64_t siloAddress = 0;
                if (!ReadU64(device, siloPointerAddress, &siloAddress, nullptr))
                {
                    continue;
                }

                if (siloAddress == 0 || !IsKernelAddress(siloAddress))
                {
                    continue;
                }

                for (uint64_t offset = 0x00; offset <= 0x100; offset += sizeof(uint64_t))
                {
                    uint64_t base = 0;
                    if (!TryAdd(siloAddress, offset, &base))
                    {
                        continue;
                    }

                    CandidateScore score = {};
                    EvaluateLoggerArrayCandidate(
                        device, base, loggerNameOffset,
                        L"silo(@debuggerData+" + FormatHexOffset(siloFieldOffset) + L")+" + FormatHexOffset(offset),
                        &score);
                    if (!score.ReadOk || score.LoggerCount == 0)
                    {
                        continue;
                    }

                    if (!haveBest || RankCandidate(score) > RankCandidate(best))
                    {
                        best = score;
                        haveBest = true;
                        *siloPointerOut = siloAddress;
                    }
                }
            }

            if (haveBest)
            {
                *bestOut = best;
                found = true;
            }
        } while (false);

        return found;
    }

    bool ValidateLoggerContext(
        DeviceClient& device,
        uint64_t loggerContext,
        uint64_t loggerNameOffset)
    {
        bool plausible = false;

        do
        {
            uint64_t nameAddress = 0;
            if (!TryAdd(loggerContext, loggerNameOffset, &nameAddress))
            {
                break;
            }

            uint16_t length16 = 0;
            if (!ReadU16(device, nameAddress, &length16, nullptr))
            {
                break;
            }

            if (length16 == 0)
            {
                plausible = true;
                break;
            }

            if ((length16 & 0x1) != 0 || length16 > 512)
            {
                break;
            }

            uint64_t bufferFieldAddress = 0;
            if (!TryAdd(nameAddress, 8, &bufferFieldAddress))
            {
                break;
            }

            uint64_t bufferValue = 0;
            if (!ReadU64(device, bufferFieldAddress, &bufferValue, nullptr))
            {
                break;
            }

            if (bufferValue != 0 && !IsKernelAddress(bufferValue))
            {
                break;
            }

            plausible = true;
        } while (false);

        return plausible;
    }

    std::wstring SanitizeForConsole(const std::wstring& input)
    {
        std::wstring result;
        result.reserve(input.size());

        for (wchar_t ch : input)
        {
            if (ch == 0)
            {
                continue;
            }
            if (ch < 0x20 || ch == 0x7f)
            {
                wchar_t buf[8];
                int written = swprintf_s(buf, L"\\x%02x", static_cast<unsigned int>(static_cast<uint16_t>(ch)));
                if (written > 0)
                {
                    result.append(buf, static_cast<size_t>(written));
                }
                continue;
            }
            if (ch >= 0xd800 && ch <= 0xdfff)
            {
                result.push_back(L'?');
                continue;
            }
            result.push_back(ch);
        }

        return result;
    }

    void AnnotateAddress(
        SymbolEngine& symbols,
        uint64_t address,
        std::wstring* moduleName,
        std::wstring* symbolName)
    {
        if (moduleName != nullptr)
        {
            moduleName->clear();
        }
        if (symbolName != nullptr)
        {
            symbolName->clear();
        }

        do
        {
            if (address == 0 || !IsKernelAddress(address))
            {
                break;
            }

            for (const KernelModuleInfo& module : symbols.Modules())
            {
                uint64_t end = module.Base + module.Size;
                if (end < module.Base)
                {
                    continue;
                }
                if (address >= module.Base && address < end)
                {
                    if (moduleName != nullptr)
                    {
                        *moduleName = module.ImageName;
                    }
                    break;
                }
            }

            std::wstring nearest;
            uint64_t displacement = 0;
            std::wstring ignored;
            if (symbols.FindNearestSymbol(address, &nearest, &displacement, &ignored))
            {
                if (symbolName != nullptr)
                {
                    std::wstringstream stream;
                    stream << nearest;
                    if (displacement != 0)
                    {
                        stream << L"+0x" << std::hex << displacement;
                    }
                    *symbolName = stream.str();
                }
            }
        } while (false);
    }

    bool AddressInLoadedModule(SymbolEngine& symbols, uint64_t address)
    {
        bool inside = false;

        for (const KernelModuleInfo& module : symbols.Modules())
        {
            uint64_t end = module.Base + module.Size;
            if (end < module.Base)
            {
                continue;
            }
            if (address >= module.Base && address < end)
            {
                inside = true;
                break;
            }
        }

        return inside;
    }
}

EtwScanner::EtwScanner(DeviceClient& device, SymbolEngine& symbols) :
    device_(device),
    symbols_(symbols)
{
}

bool EtwScanner::Scan(const Options& options, EtwScanResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid scan result output";
            }
            break;
        }

        *result = EtwScanResult{};

        uint64_t debuggerDataAddress = 0;
        std::wstring resolveError;
        if (!symbols_.ResolveSymbol(L"nt!EtwpDebuggerData", &debuggerDataAddress, &resolveError))
        {
            if (error != nullptr)
            {
                *error = L"nt!EtwpDebuggerData symbol not resolved: " + resolveError;
            }
            break;
        }

        result->DebuggerDataAddress = debuggerDataAddress;
        result->DebuggerDataResolved = true;

        uint64_t loggerNameOffset = kFallbackLoggerName;
        uint64_t getCpuClockOffset = kFallbackGetCpuClock;
        bool layoutFromPdb = false;
        ResolveLoggerLayout(symbols_, &loggerNameOffset, &getCpuClockOffset, &layoutFromPdb);
        result->LoggerNameOffset = loggerNameOffset;
        result->GetCpuClockOffset = getCpuClockOffset;
        result->LayoutFromPdb = layoutFromPdb;

        if (!layoutFromPdb)
        {
            result->Warnings.push_back(
                L"_WMI_LOGGER_CONTEXT LoggerName/GetCpuClock not exposed by current PDB; using fallback offsets which may drift across builds");
        }

        uint64_t loggerArrayBase = 0;
        uint64_t siloStateAddress = 0;
        std::wstring sourceLabel;
        bool usedSiloPath = false;
        if (!ResolveLoggerArrayBase(
                device_,
                symbols_,
                debuggerDataAddress,
                loggerNameOffset,
                &loggerArrayBase,
                &siloStateAddress,
                &sourceLabel,
                &usedSiloPath))
        {
            if (error != nullptr)
            {
                *error = L"failed to resolve ETW logger array base";
            }
            break;
        }

        result->LoggerArrayBase = loggerArrayBase;
        result->LoggerArraySource = sourceLabel;
        result->UsedSiloPath = usedSiloPath;
        result->SiloStateAddress = siloStateAddress;

        if (sourceLabel == L"legacy-fallback(+0x10)")
        {
            result->Warnings.push_back(
                L"_ETW_DEBUGGER_DATA logger array field not exposed by current PDB and heuristic auto-detect found no valid logger contexts; using legacy +0x10 fallback");
        }

        uint32_t nonCanonicalSlotCount = 0;
        for (uint32_t slot = 0; slot < kEtwLoggerSlotCount; ++slot)
        {
            uint64_t slotAddress = 0;
            if (!TryAdd(loggerArrayBase, static_cast<uint64_t>(slot) * sizeof(uint64_t), &slotAddress))
            {
                break;
            }

            uint64_t loggerContext = 0;
            if (!ReadU64(device_, slotAddress, &loggerContext, nullptr))
            {
                continue;
            }

            if (loggerContext == 0)
            {
                continue;
            }

            if (!IsKernelAddress(loggerContext))
            {
                ++nonCanonicalSlotCount;
                continue;
            }

            if (!ValidateLoggerContext(device_, loggerContext, loggerNameOffset))
            {
                ++nonCanonicalSlotCount;
                continue;
            }

            EtwLoggerRecord record = {};
            record.Slot = slot;
            record.ContextAddress = loggerContext;

            uint64_t nameAddress = 0;
            if (TryAdd(loggerContext, loggerNameOffset, &nameAddress))
            {
                std::wstring rawName;
                if (ReadUnicodeStringAt(device_, nameAddress, &rawName))
                {
                    record.Name = SanitizeForConsole(rawName);
                }
            }

            uint64_t getCpuClockAddress = 0;
            if (TryAdd(loggerContext, getCpuClockOffset, &getCpuClockAddress))
            {
                std::vector<uint8_t> rawBytes;
                if (ReadKernelBytes(device_, getCpuClockAddress, sizeof(uint64_t), &rawBytes, nullptr))
                {
                    uint64_t pointer = 0;
                    memcpy(&pointer, rawBytes.data(), sizeof(uint64_t));
                    record.GetCpuClockRaw = pointer;
                    record.HasGetCpuClockRaw = true;

                    if (IsKernelAddress(pointer))
                    {
                        record.GetCpuClockCallback = pointer;
                        record.HasGetCpuClockCallback = true;
                        record.GetCpuClockCallbackSource = L"GetCpuClock";
                        AnnotateAddress(symbols_, pointer, &record.GetCpuClockModule, &record.GetCpuClockSymbol);
                        if (!AddressInLoadedModule(symbols_, pointer))
                        {
                            record.Suspicious = true;
                            record.Notes = L"GetCpuClock callback target lies outside loaded kernel modules";
                        }
                    }
                    else
                    {
                        uint32_t mode = 0;
                        memcpy(&mode, rawBytes.data(), sizeof(uint32_t));
                        if (mode <= 3)
                        {
                            record.GetCpuClockMode = mode;
                            record.HasGetCpuClockMode = true;
                            switch (mode)
                            {
                            case 0:
                                record.GetCpuClockModeText = L"PerfCounter";
                                break;
                            case 1:
                                record.GetCpuClockModeText = L"SystemTime";
                                break;
                            case 2:
                                record.GetCpuClockModeText = L"CpuCycleCount";
                                break;
                            case 3:
                                record.GetCpuClockModeText = L"Custom";
                                break;
                            default:
                                break;
                            }
                        }
                    }
                }
            }

            // Step 1: look for a separately named callback field (some builds split mode from callback)
            if (!record.HasGetCpuClockCallback)
            {
                const wchar_t* callbackFieldNames[] =
                {
                    L"GetCpuClockCallback",
                    L"CustomGetCpuClock",
                    L"GetCpuClockEx",
                    L"GetCpuClockFunction",
                    L"GetCpuClockRoutine",
                    L"GetCpuClockProc",
                    L"ClockCallback",
                    L"ClockFunction",
                    L"CustomTimer"
                };

                for (const wchar_t* fieldName : callbackFieldNames)
                {
                    TypeFieldInfo callbackField = {};
                    if (!symbols_.FindField(L"nt!_WMI_LOGGER_CONTEXT", fieldName, &callbackField, nullptr))
                    {
                        continue;
                    }

                    uint64_t callbackAddress = 0;
                    if (!TryAdd(loggerContext, callbackField.Offset, &callbackAddress))
                    {
                        continue;
                    }

                    uint64_t pointer = 0;
                    if (!ReadU64(device_, callbackAddress, &pointer, nullptr))
                    {
                        continue;
                    }

                    if (pointer == 0 || !IsKernelAddress(pointer))
                    {
                        continue;
                    }

                    record.GetCpuClockCallback = pointer;
                    record.HasGetCpuClockCallback = true;
                    record.GetCpuClockCallbackSource = fieldName;
                    AnnotateAddress(symbols_, pointer, &record.GetCpuClockModule, &record.GetCpuClockSymbol);
                    if (!AddressInLoadedModule(symbols_, pointer))
                    {
                        record.Suspicious = true;
                        record.Notes = std::wstring(fieldName) + L" callback target lies outside loaded kernel modules";
                    }
                    break;
                }
            }

            // Step 2: heuristic structural scan when mode=Custom but no named PDB field found.
            // Only accept candidates that resolve to a kernel function whose symbol name
            // contains timing-related keywords; raw kernel pointers without symbol context
            // produce too many false positives (queue/buffer heads etc. share the same pool).
            if (record.HasGetCpuClockMode &&
                record.GetCpuClockMode == 3 &&
                !record.HasGetCpuClockCallback)
            {
                uint64_t scanStart = getCpuClockOffset + sizeof(uint64_t);
                uint64_t scanEnd = getCpuClockOffset + 0x80;

                for (uint64_t scanOff = scanStart; scanOff <= scanEnd; scanOff += sizeof(uint64_t))
                {
                    uint64_t addr = 0;
                    if (!TryAdd(loggerContext, scanOff, &addr))
                    {
                        continue;
                    }

                    uint64_t value = 0;
                    if (!ReadU64(device_, addr, &value, nullptr))
                    {
                        continue;
                    }

                    if (value == 0 || !IsKernelAddress(value))
                    {
                        continue;
                    }

                    if (!AddressInLoadedModule(symbols_, value))
                    {
                        continue;
                    }

                    std::wstring moduleName;
                    std::wstring symbolName;
                    AnnotateAddress(symbols_, value, &moduleName, &symbolName);

                    bool looksLikeClockFn = false;
                    if (!symbolName.empty())
                    {
                        std::wstring lowered = symbolName;
                        for (wchar_t& ch : lowered)
                        {
                            ch = static_cast<wchar_t>(std::towlower(ch));
                        }
                        looksLikeClockFn =
                            lowered.find(L"getcpu") != std::wstring::npos ||
                            lowered.find(L"cpuclock") != std::wstring::npos ||
                            lowered.find(L"queryperformancecounter") != std::wstring::npos ||
                            lowered.find(L"querysystemtime") != std::wstring::npos ||
                            lowered.find(L"cyclecount") != std::wstring::npos ||
                            lowered.find(L"hpet") != std::wstring::npos ||
                            lowered.find(L"tsc") != std::wstring::npos ||
                            lowered.find(L"perfcounter") != std::wstring::npos;
                    }

                    if (looksLikeClockFn)
                    {
                        record.GetCpuClockCallback = value;
                        record.HasGetCpuClockCallback = true;
                        wchar_t labelBuf[64];
                        swprintf_s(labelBuf, L"heuristic-scan(+0x%llx)",
                            static_cast<unsigned long long>(scanOff));
                        record.GetCpuClockCallbackSource = labelBuf;
                        record.GetCpuClockModule = moduleName;
                        record.GetCpuClockSymbol = symbolName;
                        break;
                    }
                }
            }

            if (record.HasGetCpuClockMode && record.GetCpuClockMode == 3 && !record.HasGetCpuClockCallback)
            {
                record.Notes = record.Notes.empty()
                    ? std::wstring(L"mode=Custom; no callback pointer field exposed and no timing-symbol match in adjacent slots. Modern Windows often dispatches by mode value internally (no separate callback storage) -- not inherently suspicious for Circular Kernel Context Logger.")
                    : record.Notes + L"; mode=Custom callback location not resolved";
            }

            result->Loggers.push_back(std::move(record));
        }

        result->NonCanonicalSlotCount = nonCanonicalSlotCount;
        if (nonCanonicalSlotCount > 0 && result->Loggers.empty())
        {
            result->Warnings.push_back(
                L"every logger slot read produced non-canonical data; layout source \"" + sourceLabel + L"\" may not match this build");
        }

        result->SlotCount = static_cast<uint32_t>(result->Loggers.size());

        if (options.Target == Scope::Logger)
        {
            std::vector<EtwLoggerRecord> filtered;
            filtered.reserve(result->Loggers.size());
            for (const EtwLoggerRecord& record : result->Loggers)
            {
                if (options.HasIndexFilter && record.Slot != options.IndexFilter)
                {
                    continue;
                }
                if (!options.NameFilter.empty())
                {
                    std::wstring lowered = record.Name;
                    for (wchar_t& ch : lowered)
                    {
                        ch = static_cast<wchar_t>(std::towlower(ch));
                    }
                    std::wstring needle = options.NameFilter;
                    for (wchar_t& ch : needle)
                    {
                        ch = static_cast<wchar_t>(std::towlower(ch));
                    }
                    if (lowered.find(needle) == std::wstring::npos)
                    {
                        continue;
                    }
                }
                filtered.push_back(record);
            }
            result->Loggers = std::move(filtered);
        }

        ok = true;
    } while (false);

    return ok;
}

namespace
{
    struct IntegrityTarget
    {
        const wchar_t* Symbol;
        const wchar_t* Description;
    };

    static const IntegrityTarget kIntegrityTargets[] =
    {
        // Core ETW dispatch functions (primary InfinityHook surface)
        {L"nt!EtwpReserveTraceBuffer",                L"primary ETW kernel buffer reservation"},
        {L"nt!EtwpReserveTraceBufferAtomic",          L"atomic-variant ETW buffer reservation"},
        {L"nt!EtwpLogKernelEvent",                    L"kernel event logger entry"},
        {L"nt!EtwpReleaseTraceBuffer",                L"ETW trace buffer release"},
        {L"nt!EtwpFinalizeTraceBuffer",               L"ETW trace buffer finalisation"},
        {L"nt!EtwpCommitTraceBuffer",                 L"ETW trace buffer commit"},
        {L"nt!EtwSendTraceBuffer",                    L"ETW send trace buffer (provider->logger)"},
        {L"nt!EtwpEventDispatcher",                   L"ETW event dispatcher"},

        // Classic InfinityHook cycle-count surface
        {L"nt!EtwpGetCycleCount",                     L"cycle count provider (classic InfinityHook target)"},
        {L"nt!EtwpReceiveCycleCount",                 L"cycle count receive path"},

        // PMC interrupt / HAL surface
        {L"nt!HalpCollectPmcCounters",                L"HAL PMC counter collection (PMC-hook target)"},
        {L"nt!HalCollectPmcCounters",                 L"HAL PMC counter collection (newer alias)"},
        {L"nt!HalpProcessorPerfCounter",              L"HAL processor performance counter"},
        {L"nt!HalpInterruptHandle",                   L"HAL interrupt handler entry"},

        // Timing source functions (alternate hook surfaces)
        {L"nt!KeQueryPerformanceCounter",             L"performance counter query"},
        {L"nt!KeQuerySystemTimePrecise",              L"precise system time query"},
        {L"nt!KeQueryInterruptTimePrecise",           L"precise interrupt time query"},
        {L"nt!KeQueryUnbiasedInterruptTimePrecise",   L"precise unbiased interrupt time query"},
        {L"nt!RtlGetSystemTimePrecise",               L"RTL precise system time"},
        {L"nt!HalpTimerQueryHostPerformanceCounter",  L"HPET host performance counter"},

        // Syscall path (broad rootkit surface; integrity check applies same way)
        {L"nt!KiSystemCall64",                        L"x64 SYSCALL entry (primary syscall hook surface)"},
        {L"nt!KiSystemCall64Shadow",                  L"x64 SYSCALL entry with KVA shadow"},
        {L"nt!KiSystemServiceUser",                   L"per-thread system service dispatcher"}
    };

    constexpr uint32_t kIntegrityBytesPerFunction = 0x100;
    constexpr uint32_t kIntegrityMaxInstructions  = 16;

    bool ExtractRelativeBranchTarget(const ZydisDisassembledInstruction& inst, uint64_t pc, uint64_t* target)
    {
        if (target == nullptr)
        {
            return false;
        }

        if (inst.info.operand_count < 1)
        {
            return false;
        }

        const ZydisDecodedOperand& op = inst.operands[0];
        if (op.type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
        {
            return false;
        }

        if (op.imm.is_relative == 0)
        {
            return false;
        }

        int64_t signedImm = op.imm.is_signed
            ? static_cast<int64_t>(op.imm.value.s)
            : static_cast<int64_t>(op.imm.value.u);

        *target = pc + inst.info.length + static_cast<uint64_t>(signedImm);
        return true;
    }

    std::wstring FormatHexBytes(const uint8_t* data, size_t length)
    {
        std::wstringstream stream;
        for (size_t i = 0; i < length; ++i)
        {
            if (i > 0)
            {
                stream << L" ";
            }
            stream << std::hex << std::setw(2) << std::setfill(L'0')
                   << static_cast<uint32_t>(data[i]);
        }
        return stream.str();
    }

    std::wstring HexAddress(uint64_t address)
    {
        std::wstringstream stream;
        stream << L"0x" << std::hex << std::setw(16) << std::setfill(L'0') << address << std::dec;
        return stream.str();
    }

    std::wstring AsciiToWideZ(const char* text)
    {
        std::wstring result;
        if (text == nullptr)
        {
            return result;
        }
        while (*text != 0)
        {
            unsigned char ch = static_cast<unsigned char>(*text);
            if (ch >= 0x20 && ch < 0x7f)
            {
                result.push_back(static_cast<wchar_t>(ch));
            }
            else
            {
                result.push_back(L'?');
            }
            ++text;
        }
        return result;
    }

    const KernelModuleInfo* FindOwningModule(SymbolEngine& symbols, uint64_t address)
    {
        for (const KernelModuleInfo& module : symbols.Modules())
        {
            uint64_t end = module.Base + module.Size;
            if (end < module.Base)
            {
                continue;
            }
            if (address >= module.Base && address < end)
            {
                return &module;
            }
        }
        return nullptr;
    }

    void AnalyzeIntegrityFunction(
        SymbolEngine& symbols,
        uint64_t funcAddress,
        const std::vector<uint8_t>& bytes,
        EtwIntegrityRecord* record)
    {
        if (record == nullptr || bytes.empty())
        {
            return;
        }

        std::vector<ZydisDisassembledInstruction> decoded;
        decoded.reserve(kIntegrityMaxInstructions);

        size_t offset = 0;
        uint64_t pc = funcAddress;
        std::wstringstream summary;

        for (uint32_t i = 0; i < kIntegrityMaxInstructions && offset < bytes.size(); ++i)
        {
            ZydisDisassembledInstruction inst = {};
            ZyanStatus status = ZydisDisassembleIntel(
                ZYDIS_MACHINE_MODE_LONG_64,
                pc,
                bytes.data() + offset,
                bytes.size() - offset,
                &inst);
            if (!ZYAN_SUCCESS(status))
            {
                break;
            }
            if (inst.info.length == 0 || inst.info.length > 15 ||
                offset + inst.info.length > bytes.size())
            {
                break;
            }

            summary << HexAddress(pc) << L"  "
                    << std::left << std::setw(24) << std::setfill(L' ')
                    << FormatHexBytes(bytes.data() + offset, inst.info.length)
                    << L"  " << AsciiToWideZ(inst.text) << L"\n";

            decoded.push_back(inst);
            offset += inst.info.length;
            pc += inst.info.length;

            ZydisMnemonic m = inst.info.mnemonic;
            if (m == ZYDIS_MNEMONIC_RET || m == ZYDIS_MNEMONIC_INT3 ||
                m == ZYDIS_MNEMONIC_UD2 || m == ZYDIS_MNEMONIC_HLT)
            {
                break;
            }
        }

        record->InstructionsAnalyzed = static_cast<uint32_t>(decoded.size());
        record->DecodeOk = !decoded.empty();
        record->DisassemblySummary = summary.str();

        if (decoded.empty())
        {
            return;
        }

        auto AddTargetAnnotation = [&](uint64_t target, EtwIntegrityFinding* finding)
        {
            finding->HasTarget = true;
            finding->Target = target;
            const KernelModuleInfo* module = FindOwningModule(symbols, target);
            if (module != nullptr)
            {
                finding->TargetModule = module->ImageName;
                finding->TargetInLoadedModule = true;
            }
            std::wstring nearest;
            uint64_t displacement = 0;
            std::wstring ignored;
            if (symbols.FindNearestSymbol(target, &nearest, &displacement, &ignored))
            {
                std::wstringstream sym;
                sym << nearest;
                if (displacement != 0)
                {
                    sym << L"+0x" << std::hex << displacement << std::dec;
                }
                finding->TargetSymbol = sym.str();
            }
        };

        const ZydisDisassembledInstruction& first = decoded[0];
        ZydisMnemonic firstMnemonic = first.info.mnemonic;

        // Check 1: function head replaced with unconditional jump (classic trampoline)
        if (firstMnemonic == ZYDIS_MNEMONIC_JMP)
        {
            EtwIntegrityFinding finding = {};
            finding.InstructionIndex = 0;
            finding.InstructionOffset = 0;
            finding.Mnemonic = L"jmp";
            finding.Reason = L"function head replaced with unconditional jump (trampoline pattern)";

            uint64_t target = 0;
            if (ExtractRelativeBranchTarget(first, funcAddress, &target))
            {
                AddTargetAnnotation(target, &finding);
            }
            else if (first.info.operand_count > 0)
            {
                if (first.operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY)
                {
                    finding.Reason += L" (indirect jmp through memory)";
                }
                else if (first.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER)
                {
                    finding.Reason += L" (register-indirect jmp)";
                }
            }
            record->Findings.push_back(std::move(finding));
        }

        // Check 2: function head replaced with debug-trap instruction
        if (firstMnemonic == ZYDIS_MNEMONIC_INT3 || firstMnemonic == ZYDIS_MNEMONIC_UD2)
        {
            EtwIntegrityFinding finding = {};
            finding.InstructionIndex = 0;
            finding.InstructionOffset = 0;
            finding.Mnemonic = firstMnemonic == ZYDIS_MNEMONIC_INT3 ? L"int3" : L"ud2";
            finding.Reason = L"function head replaced with debug-trap instruction";
            record->Findings.push_back(std::move(finding));
        }

        // Check 3: mov rax, imm64 + jmp rax indirect trampoline
        if (decoded.size() >= 2)
        {
            const ZydisDisassembledInstruction& a = decoded[0];
            const ZydisDisassembledInstruction& b = decoded[1];
            bool movImm64 = a.info.mnemonic == ZYDIS_MNEMONIC_MOV &&
                            a.info.length == 10 &&
                            a.info.operand_count >= 2 &&
                            a.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                            a.operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
            bool jmpReg = b.info.mnemonic == ZYDIS_MNEMONIC_JMP &&
                          b.info.operand_count >= 1 &&
                          b.operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER;
            if (movImm64 && jmpReg &&
                a.operands[0].reg.value == b.operands[0].reg.value)
            {
                EtwIntegrityFinding finding = {};
                finding.InstructionIndex = 0;
                finding.InstructionOffset = 0;
                finding.Mnemonic = L"mov-imm64+jmp-reg";
                finding.Reason = L"function head matches mov reg,imm64 + jmp reg indirect trampoline";
                AddTargetAnnotation(a.operands[1].imm.value.u, &finding);
                record->Findings.push_back(std::move(finding));
            }
        }

        // Check 4: push imm32 + ret trampoline
        if (decoded.size() >= 2)
        {
            const ZydisDisassembledInstruction& a = decoded[0];
            const ZydisDisassembledInstruction& b = decoded[1];
            bool pushImm = a.info.mnemonic == ZYDIS_MNEMONIC_PUSH &&
                           a.info.operand_count >= 1 &&
                           a.operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
            bool retInst = b.info.mnemonic == ZYDIS_MNEMONIC_RET;
            if (pushImm && retInst)
            {
                EtwIntegrityFinding finding = {};
                finding.InstructionIndex = 0;
                finding.InstructionOffset = 0;
                finding.Mnemonic = L"push-imm+ret";
                finding.Reason = L"function head matches push imm + ret trampoline (32-bit target)";
                uint64_t target = a.operands[0].imm.is_signed
                    ? static_cast<uint64_t>(static_cast<int64_t>(a.operands[0].imm.value.s))
                    : a.operands[0].imm.value.u;
                AddTargetAnnotation(target, &finding);
                record->Findings.push_back(std::move(finding));
            }
        }

        // Check 5: any unconditional branch (call/jmp) within first N instructions
        // whose target is kernel-canonical but outside any loaded module.
        size_t curOffset = 0;
        uint64_t curPc = funcAddress;
        for (size_t i = 0; i < decoded.size(); ++i)
        {
            const ZydisDisassembledInstruction& inst = decoded[i];
            ZydisMnemonic mn = inst.info.mnemonic;
            bool isCallOrJmp = (mn == ZYDIS_MNEMONIC_CALL || mn == ZYDIS_MNEMONIC_JMP);
            if (isCallOrJmp)
            {
                uint64_t target = 0;
                if (ExtractRelativeBranchTarget(inst, curPc, &target))
                {
                    if (target >= 0xffff800000000000ull)
                    {
                        const KernelModuleInfo* module = FindOwningModule(symbols, target);
                        if (module == nullptr)
                        {
                            bool alreadyReported = (i == 0 && mn == ZYDIS_MNEMONIC_JMP);
                            if (!alreadyReported)
                            {
                                EtwIntegrityFinding finding = {};
                                finding.InstructionIndex = static_cast<uint32_t>(i);
                                finding.InstructionOffset = static_cast<uint32_t>(curOffset);
                                finding.Mnemonic = (mn == ZYDIS_MNEMONIC_CALL) ? L"call" : L"jmp";
                                finding.Reason = L"branches to kernel address outside any loaded module";
                                AddTargetAnnotation(target, &finding);
                                record->Findings.push_back(std::move(finding));
                            }
                        }
                    }
                }
            }

            curOffset += inst.info.length;
            curPc += inst.info.length;
        }
    }
}

bool EtwScanner::ScanIntegrity(EtwIntegrityResult* result, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (result == nullptr)
        {
            if (error != nullptr)
            {
                *error = L"invalid integrity result output";
            }
            break;
        }

        *result = EtwIntegrityResult{};

        if (symbols_.Modules().empty())
        {
            std::wstring loadError;
            if (!symbols_.LoadKernelModules(&loadError))
            {
                if (error != nullptr)
                {
                    *error = L"kernel module list unavailable: " + loadError;
                }
                break;
            }
        }

        for (const IntegrityTarget& target : kIntegrityTargets)
        {
            EtwIntegrityRecord record = {};
            record.Symbol = target.Symbol;
            record.Description = target.Description;

            uint64_t address = 0;
            std::wstring resolveError;
            if (!symbols_.ResolveSymbol(target.Symbol, &address, &resolveError))
            {
                result->Records.push_back(std::move(record));
                continue;
            }

            record.SymbolResolved = true;
            record.Address = address;

            const KernelModuleInfo* owning = FindOwningModule(symbols_, address);
            if (owning != nullptr)
            {
                record.OwningModule = owning->ImageName;
            }

            std::vector<uint8_t> bytes;
            if (!ReadKernelBytes(device_, address, kIntegrityBytesPerFunction, &bytes, nullptr))
            {
                result->Warnings.push_back(std::wstring(target.Symbol) + L": kernel code read failed");
                result->Records.push_back(std::move(record));
                continue;
            }
            record.BytesRead = true;
            record.HeadBytesHex = FormatHexBytes(bytes.data(), std::min<size_t>(24, bytes.size()));

            AnalyzeIntegrityFunction(symbols_, address, bytes, &record);

            result->Records.push_back(std::move(record));
        }

        ok = true;
    } while (false);

    return ok;
}

namespace
{
    std::wstring EtwIntegrityJsonHex(uint64_t value)
    {
        wchar_t buffer[32];
        swprintf_s(buffer, L"0x%llx", static_cast<unsigned long long>(value));
        return buffer;
    }
}

std::wstring BuildEtwIntegrityJson(const EtwIntegrityResult& result)
{
    std::wstring out = L"{\"schema\":\"kn-live-dbg.etw-integrity.v1\",\"count\":";
    out += std::to_wstring(result.Records.size());
    out += L",\"records\":[";

    for (size_t index = 0; index < result.Records.size(); ++index)
    {
        const EtwIntegrityRecord& record = result.Records[index];
        if (index > 0)
        {
            out += L",";
        }

        out += L"{\"symbol\":" + mcpjson::Quote(record.Symbol);
        out += L",\"description\":" + mcpjson::Quote(record.Description);
        out += L",\"address\":" + mcpjson::Quote(EtwIntegrityJsonHex(record.Address));
        if (!record.OwningModule.empty())
        {
            out += L",\"owningModule\":" + mcpjson::Quote(record.OwningModule);
        }
        out += L",\"symbolResolved\":";
        out += record.SymbolResolved ? L"true" : L"false";
        out += L",\"bytesRead\":";
        out += record.BytesRead ? L"true" : L"false";
        out += L",\"decodeOk\":";
        out += record.DecodeOk ? L"true" : L"false";
        out += L",\"instructionsAnalyzed\":" + std::to_wstring(record.InstructionsAnalyzed);
        if (!record.HeadBytesHex.empty())
        {
            out += L",\"headBytesHex\":" + mcpjson::Quote(record.HeadBytesHex);
        }
        if (!record.DisassemblySummary.empty())
        {
            out += L",\"disassemblySummary\":" + mcpjson::Quote(record.DisassemblySummary);
        }

        out += L",\"findings\":[";
        for (size_t findingIndex = 0; findingIndex < record.Findings.size(); ++findingIndex)
        {
            const EtwIntegrityFinding& finding = record.Findings[findingIndex];
            if (findingIndex > 0)
            {
                out += L",";
            }

            out += L"{\"instructionIndex\":" + std::to_wstring(finding.InstructionIndex);
            out += L",\"instructionOffset\":" + std::to_wstring(finding.InstructionOffset);
            out += L",\"mnemonic\":" + mcpjson::Quote(finding.Mnemonic);
            if (finding.HasTarget)
            {
                out += L",\"target\":" + mcpjson::Quote(EtwIntegrityJsonHex(finding.Target));
            }
            if (!finding.TargetModule.empty())
            {
                out += L",\"targetModule\":" + mcpjson::Quote(finding.TargetModule);
            }
            if (!finding.TargetSymbol.empty())
            {
                out += L",\"targetSymbol\":" + mcpjson::Quote(finding.TargetSymbol);
            }
            out += L",\"reason\":" + mcpjson::Quote(finding.Reason);
            out += L",\"targetInLoadedModule\":";
            out += finding.TargetInLoadedModule ? L"true" : L"false";
            out += L"}";
        }
        out += L"]";

        out += L"}";
    }

    out += L"],\"warnings\":[";
    for (size_t index = 0; index < result.Warnings.size(); ++index)
    {
        if (index > 0)
        {
            out += L",";
        }
        out += mcpjson::Quote(result.Warnings[index]);
    }
    out += L"]}";

    return out;
}
