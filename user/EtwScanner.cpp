#include "EtwScanner.h"

#include <algorithm>
#include <cwctype>
#include <sstream>

namespace
{
    constexpr uint64_t kKernelSpaceMin       = 0xffff800000000000ull;
    constexpr uint32_t kEtwLoggerSlotCount   = 64;
    constexpr uint64_t kLoggerArrayOffset    = 0x10;
    constexpr uint64_t kFallbackLoggerName   = 0x68;
    constexpr uint64_t kFallbackGetCpuClock  = 0x28;
    constexpr uint32_t kMaxRawBytesPerRead   = 0x1000;
    constexpr uint32_t kMaxNameByteLength    = 2048;

    bool IsKernelAddress(uint64_t value)
    {
        return value >= kKernelSpaceMin;
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

            if (!device.ReadMemory(address, length, bytes, error))
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

            // Step 3: heuristic auto-detect — search offsets within EtwpDebuggerData
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
