// Shared lab contract between the !kmon test fixture (KnLiveDbgKmonTarget.exe)
// and the KnLiveDbg console self-test (KernelMonitorArtifactSelfTest).
//
// The fixture's /overwrite scenario fills the head of its own executable
// section with a 0x90 sled, and the self-test observes that patch through
// ReadProcessMemory. Both sides therefore have to agree on how many bytes it
// writes. Defining the number once, here, removes the second hard-coded copy:
// the observer measures the child's head against this value and reports a hard
// failure when the fixture wrote a different length, instead of quietly
// skipping the comparison and losing the coverage.
#pragma once

#include <cstdint>

namespace KmonTestTargetContract
{
    // Bytes of the executable section that /overwrite fills with 0x90.
    constexpr uint32_t kOverwritePatchBytes = 64;

    // A head whose leading 0x90 run is below this is ordinary code rather than
    // a partial patch. Anything at or above it, but below kOverwritePatchBytes,
    // is a contract mismatch between the fixture and the observer.
    constexpr uint32_t kMinObservedSledBytes = 8;
}
