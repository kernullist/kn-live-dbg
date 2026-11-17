#pragma once
#include "KernelMonitor.h"
#include <chrono>
#include <stdexcept>

// Existing byte/replay fixtures explicitly wait for asynchronous preparation
// before their single intended target observation. Production never waits here.
// The separate preparation fixture tests the pending and overlap paths directly.
struct KmonImageTestAccess
{
    static KernelMonitor::ImageVerificationWork* Find(KernelMonitor& monitor, const std::wstring& path,
        uint64_t base, const ObservationIdentity& identity, bool* unavailable = nullptr, bool discovery = true)
    {
        KernelMonitor::ImageVerificationWork* admitted = nullptr;
        auto ready = monitor.FindImageWork(path, base, identity, unavailable, &admitted, discovery);
        if (ready != nullptr || admitted == nullptr) { return ready; }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (admitted->PreparationId != 0 && std::chrono::steady_clock::now() < deadline)
        {
            monitor.ApplyImageReferenceResults();
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        if (admitted->PreparationId != 0) { throw std::runtime_error("image reference preparation did not finish"); }
        if (unavailable != nullptr) { *unavailable = admitted->PreparationFailed; }
        return admitted->Loaded ? admitted : nullptr;
    }
    static CodeOwnership Scan(KernelMonitor& monitor, const std::wstring& path, uint64_t base,
        const ObservationIdentity& identity, const ObservationReader& reader, size_t pages,
        const ObservationReadRouting* routing = nullptr, bool discovery = true)
    {
        Find(monitor, path, base, identity, nullptr, discovery);
        return monitor.ScanExecutableImage(path, base, identity, reader, pages, routing, false);
    }
};
