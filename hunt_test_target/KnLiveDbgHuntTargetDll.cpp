#include <Windows.h>

extern "C" __declspec(dllexport) DWORD WINAPI HuntTargetDllProbe()
{
    volatile DWORD value = GetTickCount();
    value ^= 0x4b4c4454u;
    value += 0x13579bdfu;
    return value;
}

#pragma code_seg(push, ".late")
extern "C" __declspec(dllexport) __declspec(noinline) DWORD WINAPI HuntTargetDllLateProbe()
{
    volatile DWORD value = GetTickCount();
    value ^= 0x4c415445u;
    value += 0x2468ace0u;
    return value;
}

extern "C" __declspec(dllexport) __declspec(noinline) DWORD WINAPI HuntTargetDllLateThreadProc(LPVOID)
{
    for (;;)
    {
        Sleep(1000);
    }
}

extern "C" __declspec(dllexport) __declspec(noinline) VOID CALLBACK HuntTargetDllLateApcRoutine(ULONG_PTR)
{
    volatile DWORD value = GetTickCount();
    value ^= 0x41504331u;
}
#pragma code_seg(pop)

BOOL WINAPI DllMain(HINSTANCE, DWORD, LPVOID)
{
    return TRUE;
}
