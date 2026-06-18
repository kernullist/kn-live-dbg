#include <Windows.h>

extern "C" __declspec(dllexport) DWORD WINAPI HuntTargetDllProbe()
{
    volatile DWORD value = GetTickCount();
    value ^= 0x4b4c4454u;
    value += 0x13579bdfu;
    return value;
}

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID)
{
    return TRUE;
}
