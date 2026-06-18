#include <Windows.h>

#pragma section(".hrwx", read, execute)
#pragma comment(linker, "/SECTION:.hrwx,ERW")
extern "C" __declspec(dllexport) __declspec(allocate(".hrwx")) volatile unsigned char HuntTargetDllRwxSectionAnchor[16] =
{
    0x48, 0x55, 0x4e, 0x54, 0x52, 0x57, 0x58, 0x31,
    0x90, 0x90, 0x90, 0x90, 0xc3, 0x90, 0x90, 0x90
};

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
