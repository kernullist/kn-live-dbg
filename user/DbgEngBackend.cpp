#include "DbgEngBackend.h"

#include <DbgEng.h>
#include <Objbase.h>

#include <sstream>
#include <string>
#include <vector>

#pragma comment(lib, "Dbgeng.lib")

static std::wstring HResultText(const wchar_t* prefix, HRESULT result)
{
    wchar_t buffer[512] = {};
    FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        static_cast<DWORD>(result),
        0,
        buffer,
        static_cast<DWORD>(std::size(buffer)),
        nullptr);

    std::wstringstream stream;
    stream << prefix << L": 0x" << std::hex << static_cast<unsigned long>(result);
    if (buffer[0] != 0)
    {
        stream << L" " << buffer;
    }

    return stream.str();
}

static std::wstring FormatDbgEngHex64(uint64_t value)
{
    std::wstringstream stream;

    stream << L"0x" << std::hex << value << std::dec;
    return stream.str();
}

class CapturingOutputCallbacks : public IDebugOutputCallbacksWide
{
public:
    CapturingOutputCallbacks() :
        refCount_(1),
        output_(nullptr)
    {
    }

    void SetOutput(std::wstring* output)
    {
        output_ = output;
    }

    STDMETHOD(QueryInterface)(REFIID InterfaceId, PVOID* Interface) override
    {
        HRESULT result = E_NOINTERFACE;

        do
        {
            if (Interface == nullptr)
            {
                result = E_POINTER;
                break;
            }

            *Interface = nullptr;
            if (IsEqualIID(InterfaceId, __uuidof(IUnknown)) ||
                IsEqualIID(InterfaceId, __uuidof(IDebugOutputCallbacksWide)))
            {
                *Interface = static_cast<IDebugOutputCallbacksWide*>(this);
                AddRef();
                result = S_OK;
            }
        } while (false);

        return result;
    }

    STDMETHOD_(ULONG, AddRef)() override
    {
        return static_cast<ULONG>(InterlockedIncrement(&refCount_));
    }

    STDMETHOD_(ULONG, Release)() override
    {
        LONG count = InterlockedDecrement(&refCount_);
        if (count == 0)
        {
            delete this;
        }

        return static_cast<ULONG>(count);
    }

    STDMETHOD(Output)(ULONG Mask, PCWSTR Text) override
    {
        UNREFERENCED_PARAMETER(Mask);

        if (output_ != nullptr && Text != nullptr)
        {
            *output_ += Text;
        }

        return S_OK;
    }

private:
    volatile LONG refCount_;
    std::wstring* output_;
};

struct DbgEngBackend::Impl
{
    Impl() :
        Client(nullptr),
        Control(nullptr),
        Symbols(nullptr),
        Callbacks(nullptr),
        CoInitialized(false),
        Ready(false)
    {
    }

    IDebugClient5* Client;
    IDebugControl4* Control;
    IDebugSymbols3* Symbols;
    CapturingOutputCallbacks* Callbacks;
    bool CoInitialized;
    bool Ready;
};

DbgEngBackend::DbgEngBackend() :
    impl_(new Impl())
{
}

DbgEngBackend::~DbgEngBackend()
{
    Shutdown();
    delete impl_;
    impl_ = nullptr;
}

bool DbgEngBackend::Initialize(
    const std::wstring& symbolPath,
    const std::wstring& connectOptions,
    bool remoteKernel,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (impl_->Ready)
        {
            ok = true;
            break;
        }

        HRESULT result = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        if (SUCCEEDED(result))
        {
            impl_->CoInitialized = true;
        }
        else if (result != RPC_E_CHANGED_MODE)
        {
            if (error != nullptr)
            {
                *error = HResultText(L"CoInitializeEx failed", result);
            }
            break;
        }

        result = DebugCreate(__uuidof(IDebugClient5), reinterpret_cast<void**>(&impl_->Client));
        if (FAILED(result))
        {
            if (error != nullptr)
            {
                *error = HResultText(L"DebugCreate failed", result);
            }
            break;
        }

        result = impl_->Client->QueryInterface(__uuidof(IDebugControl4), reinterpret_cast<void**>(&impl_->Control));
        if (FAILED(result))
        {
            if (error != nullptr)
            {
                *error = HResultText(L"IDebugControl4 query failed", result);
            }
            break;
        }

        result = impl_->Client->QueryInterface(__uuidof(IDebugSymbols3), reinterpret_cast<void**>(&impl_->Symbols));
        if (FAILED(result))
        {
            if (error != nullptr)
            {
                *error = HResultText(L"IDebugSymbols3 query failed", result);
            }
            break;
        }

        impl_->Callbacks = new CapturingOutputCallbacks();
        result = impl_->Client->SetOutputCallbacksWide(impl_->Callbacks);
        if (FAILED(result))
        {
            if (error != nullptr)
            {
                *error = HResultText(L"SetOutputCallbacksWide failed", result);
            }
            break;
        }

        ULONG engineOptions = 0;
        if (SUCCEEDED(impl_->Control->GetEngineOptions(&engineOptions)))
        {
            engineOptions &= ~DEBUG_ENGOPT_INITIAL_BREAK;
            impl_->Control->SetEngineOptions(engineOptions | DEBUG_ENGOPT_NO_EXECUTE_REPEAT);
        }

        if (!symbolPath.empty())
        {
            result = impl_->Symbols->SetSymbolPathWide(symbolPath.c_str());
            if (FAILED(result))
            {
                if (error != nullptr)
                {
                    *error = HResultText(L"SetSymbolPathWide failed", result);
                }
                break;
            }
        }

        if (remoteKernel && connectOptions.empty())
        {
            if (error != nullptr)
            {
                *error = L"remote KD requires connection options";
            }
            break;
        }

        const wchar_t* options = connectOptions.empty() ? nullptr : connectOptions.c_str();
        result = impl_->Client->AttachKernelWide(
            remoteKernel ? DEBUG_ATTACH_KERNEL_CONNECTION : DEBUG_ATTACH_LOCAL_KERNEL,
            options);
        if (FAILED(result))
        {
            if (error != nullptr)
            {
                *error = HResultText(remoteKernel ? L"AttachKernelWide remote kernel failed" : L"AttachKernelWide local kernel failed", result);
            }
            break;
        }

        impl_->Ready = true;
        ok = true;
    } while (false);

    if (!ok)
    {
        Shutdown();
    }

    return ok;
}

void DbgEngBackend::Shutdown()
{
    if (impl_ == nullptr)
    {
        return;
    }

    if (impl_->Client != nullptr)
    {
        if (impl_->Ready)
        {
            impl_->Client->EndSession(DEBUG_END_PASSIVE);
        }

        impl_->Client->SetOutputCallbacksWide(nullptr);
    }

    if (impl_->Callbacks != nullptr)
    {
        impl_->Callbacks->Release();
        impl_->Callbacks = nullptr;
    }

    if (impl_->Symbols != nullptr)
    {
        impl_->Symbols->Release();
        impl_->Symbols = nullptr;
    }

    if (impl_->Control != nullptr)
    {
        impl_->Control->Release();
        impl_->Control = nullptr;
    }

    if (impl_->Client != nullptr)
    {
        impl_->Client->Release();
        impl_->Client = nullptr;
    }

    if (impl_->CoInitialized)
    {
        CoUninitialize();
        impl_->CoInitialized = false;
    }

    impl_->Ready = false;
}

bool DbgEngBackend::IsReady() const
{
    return impl_ != nullptr && impl_->Ready;
}

bool DbgEngBackend::Execute(const std::wstring& command, std::wstring* output, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (!IsReady())
        {
            if (error != nullptr)
            {
                *error = L"DbgEng backend is not initialized. Run kdinit or backend dbgeng first.";
            }
            break;
        }

        if (output != nullptr)
        {
            output->clear();
        }

        impl_->Callbacks->SetOutput(output);
        HRESULT result = impl_->Control->ExecuteWide(
            DEBUG_OUTCTL_THIS_CLIENT,
            command.c_str(),
            DEBUG_EXECUTE_DEFAULT);
        impl_->Callbacks->SetOutput(nullptr);

        if (FAILED(result))
        {
            if (error != nullptr)
            {
                *error = HResultText(L"IDebugControl::ExecuteWide failed", result);
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool DbgEngBackend::Disassemble(
    uint64_t offset,
    uint32_t instructionCount,
    std::wstring* output,
    uint64_t* nextOffset,
    std::wstring* error)
{
    bool ok = false;

    do
    {
        if (!IsReady())
        {
            if (error != nullptr)
            {
                *error = L"DbgEng backend is not initialized. Run kdinit or backend dbgeng first.";
            }
            break;
        }

        if (output == nullptr || nextOffset == nullptr || instructionCount == 0)
        {
            if (error != nullptr)
            {
                *error = L"Invalid disassemble request";
            }
            break;
        }

        output->clear();
        ULONG64 endOffset = offset;
        ULONG flags = DEBUG_DISASM_EFFECTIVE_ADDRESS | DEBUG_DISASM_MATCHING_SYMBOLS;
        std::wstring firstError;

        std::vector<ULONG64> lineOffsets(instructionCount);
        impl_->Callbacks->SetOutput(output);
        HRESULT result = impl_->Control->OutputDisassemblyLines(
            DEBUG_OUTCTL_THIS_CLIENT,
            0,
            instructionCount,
            offset,
            flags,
            nullptr,
            nullptr,
            &endOffset,
            lineOffsets.data());
        impl_->Callbacks->SetOutput(nullptr);

        if (SUCCEEDED(result) && !output->empty())
        {
            ULONG64 computedNextOffset = endOffset;
            if (computedNextOffset <= offset)
            {
                ULONG64 nearOffset = 0;
                if (SUCCEEDED(impl_->Control->GetNearInstruction(offset, static_cast<LONG>(instructionCount), &nearOffset)) &&
                    nearOffset > offset)
                {
                    computedNextOffset = nearOffset;
                }
                else
                {
                    computedNextOffset = offset;
                }
            }

            *nextOffset = computedNextOffset;
            ok = true;
            break;
        }

        if (FAILED(result))
        {
            firstError = HResultText(L"IDebugControl::OutputDisassemblyLines failed", result);
        }
        output->clear();

        ULONG64 current = offset;
        for (uint32_t index = 0; index < instructionCount; ++index)
        {
            wchar_t buffer[1024] = {};
            ULONG disassemblySize = 0;
            result = impl_->Control->DisassembleWide(
                current,
                0,
                buffer,
                static_cast<ULONG>(std::size(buffer)),
                &disassemblySize,
                &endOffset);
            if (FAILED(result))
            {
                if (firstError.empty())
                {
                    firstError = HResultText(L"IDebugControl::DisassembleWide failed", result);
                }
                if (output->empty() && error != nullptr)
                {
                    *error = firstError;
                }
                break;
            }

            if (buffer[0] != 0)
            {
                *output += buffer;
                if (output->back() != L'\n')
                {
                    *output += L"\n";
                }
            }

            if (endOffset <= current)
            {
                if (error != nullptr)
                {
                    *error = L"Disassembler did not advance";
                }
                break;
            }

            current = endOffset;
        }

        if (output->empty())
        {
            std::wstringstream command;
            command << L"u " << FormatDbgEngHex64(offset) << L" L" << std::dec << instructionCount;

            impl_->Callbacks->SetOutput(output);
            result = impl_->Control->ExecuteWide(
                DEBUG_OUTCTL_THIS_CLIENT,
                command.str().c_str(),
                DEBUG_EXECUTE_DEFAULT);
            impl_->Callbacks->SetOutput(nullptr);

            if (FAILED(result))
            {
                if (error != nullptr)
                {
                    std::wstring executeError = HResultText(L"IDebugControl::ExecuteWide fallback failed", result);
                    *error = firstError.empty() ? executeError : firstError + L"; " + executeError;
                }
                break;
            }

            if (output->empty())
            {
                if (error != nullptr)
                {
                    *error = firstError.empty() ? L"DbgEng disassembly produced no output" : firstError;
                }
                break;
            }

            ULONG64 nearOffset = 0;
            if (SUCCEEDED(impl_->Control->GetNearInstruction(offset, static_cast<LONG>(instructionCount), &nearOffset)) &&
                nearOffset > offset)
            {
                current = nearOffset;
            }
            else
            {
                current = offset;
            }
        }

        *nextOffset = current;
        ok = true;
    } while (false);

    return ok;
}

bool DbgEngBackend::SetSymbolPath(const std::wstring& symbolPath, std::wstring* error)
{
    bool ok = false;

    do
    {
        if (!IsReady())
        {
            if (error != nullptr)
            {
                *error = L"DbgEng backend is not initialized";
            }
            break;
        }

        HRESULT result = impl_->Symbols->SetSymbolPathWide(symbolPath.c_str());
        if (FAILED(result))
        {
            if (error != nullptr)
            {
                *error = HResultText(L"SetSymbolPathWide failed", result);
            }
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

bool DbgEngBackend::Reload(std::wstring* output, std::wstring* error)
{
    return Execute(L".reload", output, error);
}
