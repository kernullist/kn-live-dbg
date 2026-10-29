#include "../user/DumpObservationSource.h"
#include "../user/ObservationSourceJson.h"
#include "../user/MemoryDumper.h"
#include <mindumpdef.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>

namespace
{
    unsigned Passed = 0, Failed = 0;
    void Check(bool ok, const char* name)
    {
        if (ok)
        {
            ++Passed;
        }
        else
        {
            ++Failed;
            std::cerr << "[dump.source] FAIL " << name << "\n";
        }
    }

    struct Fixture
    {
        DUMP_HEADER64 Header{};
        std::vector<uint8_t> Bytes = std::vector<uint8_t>(0x2000 + 6 * 4096, 0);
        uint64_t Virtual = 0;
        uint64_t Physical = 0;
        size_t NextPte = 0;

        Fixture(uint32_t levels, uint32_t leaf, uint64_t address = 0)
        {
            Virtual = address != 0 ? address : levels == 5 ? 0x0010000000100000ull : 0x100000;
            const uint64_t base = leaf == 3 ? 0x40000000 : leaf == 2 ? 0x200000 : 0x9000;
            const uint64_t mapping = 1ull << (12 + (leaf - 1) * 9);
            Physical = base + (Virtual & (mapping - 1));
            Header.Signature = DUMP_SIGNATURE64;
            Header.ValidDump = DUMP_VALID_DUMP64;
            Header.MachineImageType = IMAGE_FILE_MACHINE_AMD64;
            Header.DumpType = DUMP_TYPE_FULL;
            Header.DirectoryTableBase = 0x1000;
            Header.KdSecondaryVersion = 2;
            const uint64_t cr4 = (1ull << 5) | (levels == 5 ? 1ull << 12 : 0);
            std::memcpy(Header.ContextRecord + 0x4d0 + 0x10, &Header.DirectoryTableBase, 8);
            std::memcpy(Header.ContextRecord + 0x4d0 + 0x18, &cr4, 8);
            Header.PhysicalMemoryBlock.NumberOfRuns = 2;
            Header.PhysicalMemoryBlock.NumberOfPages = 6;
            Header.PhysicalMemoryBlock.Run[0].BasePage = 1;
            Header.PhysicalMemoryBlock.Run[0].PageCount = 5;
            Header.PhysicalMemoryBlock.Run[1].BasePage = Physical / 4096;
            Header.PhysicalMemoryBlock.Run[1].PageCount = 1;
            uint64_t table = 0x1000;
            for (uint32_t level = levels; level >= leaf; --level)
            {
                const uint64_t index = (Virtual >> (12 + (level - 1) * 9)) & 511;
                const uint64_t entry = level == leaf ? (base | 3 | (leaf == 1 ? 0 : 0x80)) : (table + 4096) | 3;
                const auto position = static_cast<size_t>(0x2000 + table - 0x1000 + index * 8);
                std::memcpy(Bytes.data() + position, &entry, 8);
                if (level == leaf && leaf == 1)
                {
                    NextPte = position + 8;
                    const uint64_t next = (base + 4096) | 3;
                    std::memcpy(Bytes.data() + NextPte, &next, 8);
                }
                table += 4096;
            }
            std::fill(Bytes.end() - 4096, Bytes.end(), uint8_t{0x42});
        }

        bool Save(const std::filesystem::path& path)
        {
            std::memcpy(Bytes.data(), &Header, sizeof(Header));
            std::ofstream file(path, std::ios::binary | std::ios::trunc);
            file.write(reinterpret_cast<const char*>(Bytes.data()), static_cast<std::streamsize>(Bytes.size()));
            file.close();
            return !file.fail();
        }
    };
}

int wmain(int argc, wchar_t** argv)
{
    if (argc != 2)
    {
        return 2;
    }
    const std::filesystem::path root(argv[1]);
    std::wstring error;
    for (uint32_t levels : {4u, 5u})
    {
        for (uint32_t leaf : {1u, 2u, 3u})
        {
            Fixture fixture(levels, leaf);
            const auto path = root / (L"la" + std::to_wstring(levels == 5 ? 57 : 48) + L"-leaf" + std::to_wstring(leaf) + L".dmp");
            Check(fixture.Save(path), "owned full-dump fixture saved");
            auto source = OpenDumpObservationSource(path.wstring(), &error);
            Check(source != nullptr, "qualified LA48/LA57 and 4K/2M/1G source opened");
            if (!source)
            {
                continue;
            }
            Check(source->Capabilities().AddressSpace.VirtualAddressBits == (levels == 5 ? 57 : 48) &&
                !source->Capabilities().MayChangeResidency, "source preserves paging width without residency effects");
            std::vector<uint8_t> bytes;
            Check(ReadObservationExact(*source, fixture.Virtual + 0x234, 8, &bytes) &&
                bytes == std::vector<uint8_t>(8, 0x42), "independent fixture marker survives each page-table shape");
            ObservationReadRequest request;
            request.SourceId = source->Capabilities().SourceId;
            request.Address = fixture.Virtual + 0xff8;
            request.Length = 16;
            request.ByteBudget = 16;
            const auto partial = source->Read(request);
            Check(partial.State == ObservationReadState::Partial && partial.Spans.size() == 2 &&
                partial.Spans[0].Bytes == std::vector<uint8_t>(8, 0x42) &&
                partial.Spans[1].State == ObservationReadState::NotCaptured && partial.Spans[1].Bytes.empty(),
                "cross-page holes retain valid bytes without synthesizing a missing page");
            Check(!ReadObservationExact(*source, request.Address, request.Length, &bytes) && bytes.empty(),
                "all-or-nothing parsers discard incomplete input");
            Check(mcpjson::ValidateDocument(ObservationReadJson(source->Capabilities(), request, partial)),
                "common read schema is valid JSON");
            request.ByteBudget = 15;
            Check(source->Read(request).State == ObservationReadState::BudgetDeferred, "data byte budget enforced");
            request.ByteBudget = 16;
            request.SourceId += L":stale";
            Check(source->Read(request).State == ObservationReadState::IdentityChanged, "source-token substitution denied");
            request.SourceId = source->Capabilities().SourceId;
            std::atomic<bool> cancel{true};
            request.Cancellation = &cancel;
            Check(source->Read(request).State == ObservationReadState::Cancelled, "cancellation prevents acquisition");
            request.Cancellation = nullptr;
            std::atomic<bool> concurrent{true};
            const auto readMany = [&]()
            {
                for (unsigned i = 0; i < 25; ++i)
                {
                    std::vector<uint8_t> observed;
                    if (!ReadObservationExact(*source, fixture.Virtual + i, 16, &observed) ||
                        observed != std::vector<uint8_t>(16, 0x42))
                    {
                        concurrent = false;
                    }
                }
            };
            std::thread first(readMany), second(readMany);
            first.join();
            second.join();
            Check(concurrent, "concurrent readers serialize file-offset operations");
            HANDLE writer = CreateFileW(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            Check(writer == INVALID_HANDLE_VALUE && DeleteFileW(path.c_str()) == FALSE,
                "owned open source rejects ordinary file mutation and replacement");
            if (writer != INVALID_HANDLE_VALUE)
            {
                CloseHandle(writer);
            }
            const auto oldId = source->Capabilities().SourceId;
            source.reset();
            source = OpenDumpObservationSource(path.wstring(), &error);
            Check(source && source->Capabilities().SourceId != oldId, "reopened source receives a new connection identity");
        }
    }
    Fixture fixture(4, 1);
    std::memset(fixture.Bytes.data() + fixture.NextPte, 0, 8);
    const auto unmapped = root / L"not-present.dmp";
    Check(fixture.Save(unmapped), "nonpresent control saved");
    auto source = OpenDumpObservationSource(unmapped.wstring(), &error);
    Check(source != nullptr, "nonpresent control opens");
    if (source)
    {
        ObservationReadRequest request{source->Capabilities().SourceId, fixture.Virtual + 4096, 8, 8};
        Check(source->Read(request).State == ObservationReadState::NotPresent, "nonpresent mapping differs from uncaptured physical bytes");
        request.Address = 0x0000800000000000ull;
        Check(source->Read(request).State == ObservationReadState::Unsupported, "LA48 canonical hole rejected before translation");
    }
    source.reset();

    for (uint32_t levels : {4u, 5u})
    {
        Fixture probed(levels, 1, levels == 5 ? 0xff01000000100000ull : 0xffff800000100000ull);
        probed.Header.KdSecondaryVersion = 0;
        probed.Header.PsLoadedModuleList = probed.Virtual;
        std::memcpy(probed.Bytes.data() + probed.Bytes.size() - 4096, &probed.Virtual, 8);
        std::memcpy(probed.Bytes.data() + probed.Bytes.size() - 4096 + 8, &probed.Virtual, 8);
        auto path = root / (L"probed-" + std::to_wstring(levels) + L".dmp");
        Check(probed.Save(path), "probe-only fixture saved");
        auto qualified = OpenDumpObservationSource(path.wstring(), &error);
        Check(qualified && qualified->Capabilities().AddressSpace.VirtualAddressBits == (levels == 5 ? 57 : 48),
            "unique reciprocal list probe qualifies missing CR4 evidence");
        probed.Header.KdSecondaryVersion = 2;
        const uint64_t wrongCr4 = (1ull << 5) | (levels == 4 ? 1ull << 12 : 0);
        std::memcpy(probed.Header.ContextRecord + 0x4d0 + 0x18, &wrongCr4, 8);
        path = root / (L"contradictory-" + std::to_wstring(levels) + L".dmp");
        Check(probed.Save(path) && !OpenDumpObservationSource(path.wstring(), &error),
            "contradictory CR4 and unique page-table evidence cannot silently select a mode");
    }
    Fixture ambiguous(5, 1, 0xffffffffffffe000ull);
    ambiguous.Header.KdSecondaryVersion = 0;
    ambiguous.Header.PsLoadedModuleList = ambiguous.Virtual;
    const uint64_t alternate = 0x9003;
    std::memcpy(ambiguous.Bytes.data() + 0x2000 + 0x3000 + 510 * 8, &alternate, 8);
    std::memcpy(ambiguous.Bytes.data() + ambiguous.Bytes.size() - 4096, &ambiguous.Virtual, 8);
    std::memcpy(ambiguous.Bytes.data() + ambiguous.Bytes.size() - 4096 + 8, &ambiguous.Virtual, 8);
    const auto ambiguousPath = root / L"ambiguous.dmp";
    Check(ambiguous.Save(ambiguousPath) && !OpenDumpObservationSource(ambiguousPath.wstring(), &error),
        "two successful paging probes without CR4 remain ambiguous");
    Check(!OpenDumpObservationSource(unmapped.wstring() + std::wstring(1, L'\0') + L"suffix", &error) &&
        !OpenDumpObservationSource(L"\\\\.\\pipe\\owned-control", &error) &&
        !OpenDumpObservationSource(L"\\\\?\\globalroot\\Device\\Null", &error),
        "NUL and device namespace paths rejected before opening a different target");

    for (unsigned mutation = 0; mutation != 13; ++mutation)
    {
        Fixture bad(4, 1);
        switch (mutation)
        {
        case 0: bad.Header.MachineImageType = IMAGE_FILE_MACHINE_I386; break;
        case 1: bad.Header.DumpType = DUMP_TYPE_TRIAGE; break;
        case 2: bad.Header.PhysicalMemoryBlock.Run[1].BasePage = 1; break;
        case 3: ++bad.Header.PhysicalMemoryBlock.NumberOfPages; break;
        case 4: bad.Bytes.pop_back(); break;
        case 5: bad.Header.KdSecondaryVersion = 0; break;
        case 6: bad.Header.DirectoryTableBase = 0x8000000000001000ull; break;
        case 7: bad.Header.PhysicalMemoryBlock.Run[1].BasePage = UINT64_MAX; break;
        case 8: bad.Header.PhysicalMemoryBlock.Run[1].PageCount = 0; break;
        case 9: bad.Header.PhysicalMemoryBlock.NumberOfRuns = kCrashDumpMaxPhysicalRuns + 1; break;
        case 10: bad.Header.DirectoryTableBase = 0; break;
        case 11: bad.Header.ContextRecord[0x4d0 + 0x11] = 0x20; break;
        case 12: bad.Header.Signature = 0; break;
        }
        const auto path = root / (L"invalid-" + std::to_wstring(mutation) + L".dmp");
        Check(bad.Save(path) && !OpenDumpObservationSource(path.wstring(), &error),
            "invalid format, run inventory or unsupported paging provenance rejected");
    }
    unsigned physicalCalls = 0;
    const DumpPhysicalReader broken = [&](uint64_t, uint32_t, std::vector<uint8_t>* out)
    {
        ++physicalCalls;
        out->assign(1, 0xff);
        return ObservationReadState::Complete;
    };
    Check(TranslateDumpAddress(broken, 0x1000, 4, 0x100000).State == ObservationReadState::Failed && physicalCalls == 1,
        "malformed physical-reader completion cannot become a PTE");
    const DumpPhysicalReader absent = [](uint64_t, uint32_t, std::vector<uint8_t>* out)
    {
        out->clear();
        return ObservationReadState::NotCaptured;
    };
    Check(TranslateDumpAddress(absent, 0x1000, 4, 0x100000).State == ObservationReadState::NotCaptured,
        "missing page-table bytes remain capture holes");
    const DumpPhysicalReader failed = [](uint64_t, uint32_t, std::vector<uint8_t>* out)
    {
        out->clear();
        return ObservationReadState::Failed;
    };
    Check(TranslateDumpAddress(failed, 0x1000, 4, 0x100000).State == ObservationReadState::Failed,
        "I/O failure is distinct from absent captures");
    Fixture changed(4, 1);
    unsigned dataReads = 0;
    DumpObservationSource replaced(L"synthetic_changed_source", 0x1000, 4,
        [&](uint64_t address, uint32_t length, std::vector<uint8_t>* out)
        {
            out->clear();
            if (dataReads != 0)
            {
                return ObservationReadState::IdentityChanged;
            }
            if (address >= 0x1000 && address < 0x6000)
            {
                const size_t at = static_cast<size_t>(0x2000 + address - 0x1000);
                out->assign(changed.Bytes.begin() + at, changed.Bytes.begin() + at + length);
            }
            else
            {
                ++dataReads;
                out->assign(length, 0x42);
            }
            return ObservationReadState::Complete;
        });
    ObservationReadRequest changedRequest{replaced.Capabilities().SourceId, changed.Virtual + 0xff8, 16, 16};
    const auto invalidated = replaced.Read(changedRequest);
    Check(invalidated.State == ObservationReadState::IdentityChanged && invalidated.Spans.size() == 1 &&
        invalidated.Spans[0].Bytes.empty(), "source replacement discards bytes already collected in the same read");
    std::cout << "[dump.source] passed=" << Passed << " failed=" << Failed << " corpus=synthetic\n";
    return Failed == 0 ? 0 : 1;
}
