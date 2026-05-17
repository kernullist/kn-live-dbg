#pragma once

#include <Windows.h>

#include <string>

class DbgEngBackend
{
public:
    DbgEngBackend();
    ~DbgEngBackend();

    bool Initialize(const std::wstring& symbolPath, const std::wstring& connectOptions, std::wstring* error);
    void Shutdown();
    bool IsReady() const;

    bool Execute(const std::wstring& command, std::wstring* output, std::wstring* error);
    bool SetSymbolPath(const std::wstring& symbolPath, std::wstring* error);
    bool Reload(std::wstring* output, std::wstring* error);

private:
    struct Impl;
    Impl* impl_;
};
