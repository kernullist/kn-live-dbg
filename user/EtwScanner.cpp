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

        uint64_t loggerArrayBase = 0;
        if (!TryAdd(debuggerDataAddress, kLoggerArrayOffset, &loggerArrayBase))
        {
            if (error != nullptr)
            {
                *error = L"EtwpDebuggerData logger array offset overflow";
            }
            break;
        }

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
                result->Warnings.push_back(L"failed to read logger pointer at slot " + std::to_wstring(slot));
                continue;
            }

            if (loggerContext == 0)
            {
                continue;
            }

            if (!IsKernelAddress(loggerContext))
            {
                result->Warnings.push_back(L"slot " + std::to_wstring(slot) + L" pointer not in kernel canonical range");
                continue;
            }

            EtwLoggerRecord record = {};
            record.Slot = slot;
            record.ContextAddress = loggerContext;

            uint64_t nameAddress = 0;
            if (TryAdd(loggerContext, loggerNameOffset, &nameAddress))
            {
                ReadUnicodeStringAt(device_, nameAddress, &record.Name);
            }

            uint64_t getCpuClockAddress = 0;
            if (TryAdd(loggerContext, getCpuClockOffset, &getCpuClockAddress))
            {
                uint64_t pointer = 0;
                if (ReadU64(device_, getCpuClockAddress, &pointer, nullptr))
                {
                    if (IsKernelAddress(pointer))
                    {
                        record.GetCpuClock = pointer;
                        record.HasGetCpuClock = true;
                        AnnotateAddress(symbols_, pointer, &record.GetCpuClockModule, &record.GetCpuClockSymbol);
                        if (!AddressInLoadedModule(symbols_, pointer))
                        {
                            record.Suspicious = true;
                            record.Notes = L"GetCpuClock points outside loaded kernel modules";
                        }
                    }
                    else if (pointer == 0)
                    {
                        // mode is non-callback (0/1/2 numeric mode); HasGetCpuClock stays false
                    }
                }
            }

            result->Loggers.push_back(std::move(record));
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
