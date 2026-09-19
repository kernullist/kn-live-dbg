#include <Windows.h>
#include <cstdint>
#include <fstream>
#include <string>

#pragma section(".knprobe", read, execute)
__declspec(allocate(".knprobe")) __declspec(align(4096)) const uint8_t ImageProbe[8192] = {0xC3};

__declspec(noinline) int ImageTextProbe()
{
    volatile int value = 17;
    return value;
}

int wmain(int argc, wchar_t** argv)
{
    int result = 2;
    void* privatePage = nullptr;
    do
    {
        if (argc != 3)
        {
            break;
        }
        const std::wstring mode = argv[1];
        if (mode != L"clean" && mode != L"modified" && mode != L"text" && mode != L"jit")
        {
            break;
        }
        if (mode == L"modified")
        {
            auto* page = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(ImageProbe) + 4096);
            DWORD protection = 0;
            if (!VirtualProtect(page, 4096, PAGE_READWRITE, &protection))
            {
                break;
            }
            reinterpret_cast<volatile uint8_t*>(page)[2048] = 0x42;
            DWORD ignored = 0;
            if (!VirtualProtect(page, 4096, protection, &ignored))
            {
                break;
            }
        }
        if (mode == L"jit")
        {
            privatePage = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (privatePage == nullptr)
            {
                break;
            }
            // Benign return-only code; this fixture never calls the page.
            reinterpret_cast<uint8_t*>(privatePage)[0] = 0xC3;
            DWORD ignored = 0;
            if (!VirtualProtect(privatePage, 4096, PAGE_EXECUTE_READ, &ignored))
            {
                break;
            }
        }
        if (mode == L"text")
        {
            auto* code = reinterpret_cast<volatile uint8_t*>(&ImageTextProbe);
            DWORD protection = 0;
            if (!VirtualProtect(const_cast<uint8_t*>(code), 16, PAGE_EXECUTE_READWRITE, &protection))
            {
                break;
            }
            // This function is never invoked. Keep the changed byte in .text.
            code[0] ^= 0x01;
            DWORD ignored = 0;
            if (!VirtualProtect(const_cast<uint8_t*>(code), 16, protection, &ignored))
            {
                break;
            }
            FlushInstructionCache(GetCurrentProcess(), const_cast<uint8_t*>(code), 16);
        }
        std::ofstream ready(argv[2], std::ios::binary);
        ready << "{\"pid\":" << GetCurrentProcessId() << ",\"base\":\""
            << reinterpret_cast<uintptr_t>(GetModuleHandleW(nullptr)) << "\",\"private_page\":\""
            << reinterpret_cast<uintptr_t>(privatePage) << "\"}\n";
        ready.close();
        if (!ready.good())
        {
            break;
        }
        Sleep(60000);
        result = 0;
    } while (false);
    if (privatePage != nullptr)
    {
        VirtualFree(privatePage, 0, MEM_RELEASE);
    }
    return result;
}
