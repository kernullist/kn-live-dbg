#include "../user/KmonHandleTracking.h"
#include "../user/ObservationWindows.h"
#include "../user/ExecutableImageVerifier.h"

#include "../user/CodeTargetResolver.h"

#include "../user/ExecutableRegionCatalog.h"

#include "../user/GameBuildManifest.h"
#include "../user/KmonWorkQueue.h"
#include "../user/KmonHunting.h"
#include "kmon-hunting-selftest.h"
#include "kmon-fp-selftest.h"

#include <iostream>

#pragma section(".knexec", read, execute)
__declspec(allocate(".knexec")) __declspec(align(4096)) const uint8_t ExecutableProbe[8192] = {0xC3};

bool ArbitraryImageSelfTest()
{
    wchar_t path[32768] = {};
    GetModuleFileNameW(nullptr, path, 32768);
    executable_image::DiskPeMetadata reference;
    const uint64_t base = reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
    const uint64_t address = reinterpret_cast<uint64_t>(ExecutableProbe) + 4096;
    const auto rva = static_cast<uint32_t>(address - base);
    const ObservationReader reader = [](uint64_t at, size_t count, std::vector<uint8_t>* bytes)
    {
        bytes->resize(count);
        SIZE_T read = 0;
        return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(at), bytes->data(), count, &read) && read == count;
    };
    if (!executable_image::ReadDiskPeMetadata(path, &reference, nullptr) ||
        !QualifyExecutableReference(reference, base, reader, nullptr))
    {
        return false;
    }
    const auto clean = CompareExecutableRange(path, reference, base, rva, 4096, reader);
    DWORD previous = 0;
    if (clean.Ownership != CodeOwnership::OwnedVerified ||
        !VirtualProtect(reinterpret_cast<void*>(address), 4096, PAGE_EXECUTE_READWRITE, &previous))
    {
        return false;
    }
    auto* changed = reinterpret_cast<volatile uint8_t*>(address + 0x800);
    const uint8_t saved = *changed;
    *changed = saved ^ 0xA5;
    const auto modified = CompareExecutableRange(path, reference, base, rva, 4096, reader);
    *changed = saved;
    DWORD ignored = 0;
    const bool restored = VirtualProtect(reinterpret_cast<void*>(address), 4096, previous, &ignored) != FALSE;
    return restored && modified.Ownership == CodeOwnership::OwnedModified && modified.Changes.size() == 1 &&
        modified.Changes[0].Address == static_cast<uint64_t>(rva) + 0x800 && modified.Changes[0].Size == 1;
}

int main()
{
    const bool pure = KmonHandleTrackingSelfTest() && ObservationModelSelfTest() && KmonHuntingPolicySelfTest();
    std::cout << "[kmon.core] handle ABI, rotation, lifecycle, channel controls: "
        << (pure ? "PASS" : "FAIL") << "\n";
    HANDLE file = CreateFileW(L"NUL", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr, OPEN_EXISTING, 0, nullptr);
    std::vector<NativeHandleEntry> entries;
    bool found = false;
    if (file != INVALID_HANDLE_VALUE && QueryNativeHandleSnapshot(&entries, nullptr))
    {
        for (const auto& entry : entries)
        {
            if (entry.UniqueProcessId == GetCurrentProcessId() &&
                entry.HandleValue == reinterpret_cast<ULONG_PTR>(file) && entry.ObjectTypeIndex != 0)
            {
                found = true;
            }
        }
    }
    if (file != INVALID_HANDLE_VALUE)
    {
        CloseHandle(file);
    }
    std::cout << "[kmon.core] native x64 File handle snapshot: " << (found ? "PASS" : "FAIL") << "\n";
    const bool image = ExecutableImageVerifierSelfTest();
    std::cout << "[kmon.core] executable sections, relocation, coverage controls: " << (image ? "PASS" : "FAIL") << "\n";
    const bool branches = CodeTargetResolverSelfTest();
    std::cout << "[kmon.core] bounded branch chains and unknown controls: " << (branches ? "PASS" : "FAIL") << "\n";
    const bool catalog = ExecutableRegionCatalogSelfTest();
    std::cout << "[kmon.core] catalog, COW, identity and mapping reuse: " << (catalog ? "PASS" : "FAIL") << "\n";
    const bool manifest = GameBuildManifestSelfTest() && KmonWorkQueueSelfTest();
    std::cout << "[kmon.core] manifest bounds, secondary vptr, slot and queue controls: " << (manifest ? "PASS" : "FAIL") << "\n";
    const bool actualImage = ArbitraryImageSelfTest();
    std::cout << "[kmon.core] arbitrary-name EXE, second executable page and mid-page change: " << (actualImage ? "PASS" : "FAIL") << "\n";
    const bool hunting = KmonHuntingSelfTest();
    const bool falsePositives = KmonFalsePositiveSelfTest();
    return pure && found && image && branches && catalog && manifest && actualImage && hunting && falsePositives ? 0 : 1;
}
