// Owned, never-invoked probe data in an executable image section. The pointer
// creates a real DIR64 relocation so loader ASLR has an independent byte oracle.
#include <cstdint>
#pragma section(".text$probe", read, execute)
struct OwnedProbeData { const void* Self; uint8_t Bytes[56]; };
extern "C" __declspec(dllexport) __declspec(allocate(".text$probe")) const OwnedProbeData KnOwnedImageProbe =
    {&KnOwnedImageProbe, {0x41, 0x42, 0x43, 0x44, 0x51, 0x52, 0x53, 0x54}};
