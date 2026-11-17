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
        const auto work = Find(monitor, path, base, identity, nullptr, discovery);
        if (work != nullptr && routing != nullptr && GetTickCount64() >= work->NextSweepDueMs)
        { PrepareContent(monitor, *work); }
        return monitor.ScanExecutableImage(path, base, identity, reader, pages, routing, false);
    }
    static void PrepareContent(KernelMonitor& monitor, KernelMonitor::ImageVerificationWork& work)
    {
        monitor.QueueImageReferenceContent(work);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (work.ContentPreparationId != 0 && !monitor.ImageContents->IsReady(work.ContentPreparationId) &&
            monitor.ImageContents->Contains(work.ContentPreparationId) && std::chrono::steady_clock::now() < deadline)
        { std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
        if (work.ContentPreparationId != 0 && !monitor.ImageContents->IsReady(work.ContentPreparationId))
        { throw std::runtime_error("image content preparation did not finish"); }
    }
};
