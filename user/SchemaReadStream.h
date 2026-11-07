#pragma once

#include <Windows.h>
#include <objidl.h>
#include <algorithm>
#include <atomic>
#include <memory>
#include <mutex>

// DIA receives only this read-only stream over a broker-approved file object.
// Clones have independent cursors; the underlying handle is never resolved by path.
class SchemaReadStream final : public IStream
{
    struct FileState
    {
        HANDLE File = INVALID_HANDLE_VALUE;
        uint64_t Size = 0;
        std::mutex Mutex;
        ~FileState() { if (File != INVALID_HANDLE_VALUE) { CloseHandle(File); } }
    };
public:
    static HRESULT Create(HANDLE file, IStream** output)
    {
        if (output == nullptr) { return E_POINTER; }
        *output = nullptr;
        try
        {
            auto state = std::make_shared<FileState>();
            state->File = ReOpenFile(file, GENERIC_READ, FILE_SHARE_READ, FILE_FLAG_SEQUENTIAL_SCAN);
            LARGE_INTEGER size{};
            if (state->File == INVALID_HANDLE_VALUE || !GetFileSizeEx(state->File, &size) || size.QuadPart <= 0)
            {
                return STG_E_READFAULT;
            }
            state->Size = static_cast<uint64_t>(size.QuadPart);
            *output = new SchemaReadStream(std::move(state), 0);
            return S_OK;
        }
        catch (...) { return E_OUTOFMEMORY; }
    }
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID iid, void** output) override
    {
        if (output == nullptr) { return E_POINTER; }
        *output = nullptr;
        if (iid != IID_IUnknown && iid != IID_IStream && iid != IID_ISequentialStream) { return E_NOINTERFACE; }
        *output = static_cast<IStream*>(this);
        AddRef();
        return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override { return ++References; }
    ULONG STDMETHODCALLTYPE Release() override
    {
        const auto left = --References;
        if (left == 0) { delete this; }
        return left;
    }
    HRESULT STDMETHODCALLTYPE Read(void* buffer, ULONG bytes, ULONG* received) override
    {
        if (received != nullptr) { *received = 0; }
        if (buffer == nullptr && bytes != 0) { return STG_E_INVALIDPOINTER; }
        std::lock_guard<std::mutex> lock(State->Mutex);
        const auto available = Position < State->Size ? State->Size - Position : 0;
        const auto count = static_cast<DWORD>((std::min)(available, static_cast<uint64_t>(bytes)));
        DWORD read = 0;
        LARGE_INTEGER offset{};
        offset.QuadPart = static_cast<LONGLONG>(Position);
        if (count != 0 && (!SetFilePointerEx(State->File, offset, nullptr, FILE_BEGIN) ||
            !ReadFile(State->File, buffer, count, &read, nullptr))) { return STG_E_READFAULT; }
        Position += read;
        if (received != nullptr) { *received = read; }
        return read == bytes ? S_OK : S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE Seek(LARGE_INTEGER distance, DWORD origin, ULARGE_INTEGER* result) override
    {
        std::lock_guard<std::mutex> lock(State->Mutex);
        if (origin > STREAM_SEEK_END) { return STG_E_INVALIDFUNCTION; }
        const uint64_t base = origin == STREAM_SEEK_SET ? 0 : origin == STREAM_SEEK_CUR ? Position : State->Size;
        const uint64_t magnitude = distance.QuadPart < 0 ? uint64_t{0} - static_cast<uint64_t>(distance.QuadPart) :
            static_cast<uint64_t>(distance.QuadPart);
        if ((distance.QuadPart < 0 && magnitude > base) ||
            (distance.QuadPart >= 0 && magnitude > INT64_MAX - base)) { return STG_E_INVALIDFUNCTION; }
        Position = distance.QuadPart < 0 ? base - magnitude : base + magnitude;
        if (result != nullptr) { result->QuadPart = Position; }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Stat(STATSTG* result, DWORD flags) override
    {
        if (result == nullptr) { return STG_E_INVALIDPOINTER; }
        if (flags != STATFLAG_DEFAULT && flags != STATFLAG_NONAME) { return STG_E_INVALIDFLAG; }
        *result = {};
        result->type = STGTY_STREAM;
        result->cbSize.QuadPart = State->Size;
        result->grfMode = STGM_READ;
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Clone(IStream** result) override
    {
        if (result == nullptr) { return E_POINTER; }
        *result = nullptr;
        try
        {
            std::lock_guard<std::mutex> lock(State->Mutex);
            *result = new SchemaReadStream(State, Position);
            return S_OK;
        }
        catch (...) { return E_OUTOFMEMORY; }
    }
    HRESULT STDMETHODCALLTYPE Write(const void*, ULONG, ULONG* written) override
    { if (written != nullptr) { *written = 0; } return STG_E_ACCESSDENIED; }
    HRESULT STDMETHODCALLTYPE SetSize(ULARGE_INTEGER) override { return STG_E_ACCESSDENIED; }
    HRESULT STDMETHODCALLTYPE CopyTo(IStream*, ULARGE_INTEGER, ULARGE_INTEGER*, ULARGE_INTEGER*) override { return E_NOTIMPL; }
    HRESULT STDMETHODCALLTYPE Commit(DWORD) override { return STG_E_ACCESSDENIED; }
    HRESULT STDMETHODCALLTYPE Revert() override { return STG_E_ACCESSDENIED; }
    HRESULT STDMETHODCALLTYPE LockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) override { return STG_E_INVALIDFUNCTION; }
    HRESULT STDMETHODCALLTYPE UnlockRegion(ULARGE_INTEGER, ULARGE_INTEGER, DWORD) override { return STG_E_INVALIDFUNCTION; }
private:
    SchemaReadStream(std::shared_ptr<FileState> state, uint64_t position) : State(std::move(state)), Position(position) {}
    std::atomic<ULONG> References{1};
    std::shared_ptr<FileState> State;
    uint64_t Position = 0;
};
