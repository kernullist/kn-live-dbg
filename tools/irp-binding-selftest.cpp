#include "../user/PendingIrpBinding.h"
#include "../user/PendingIrpReport.h"
#include "../user/BrokeredTypeLayouts.h"
#include "../user/TypeSchemaBroker.h"
#include "../user/SchemaArtifact.h"
#include "../user/ExecutableImageVerifier.h"
#include "../user/ObservationReadRoutingJson.h"
#include "../user/PendingIrpEvidence.h"
#include "irp-binding-fixture.h"
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>

namespace
{
    unsigned Passed = 0, Failed = 0;
    constexpr uint64_t Image = 0xfffff80000000000ull, Thread = 0xffff900000001000ull, Irp = 0xffff900000004000ull;
    void Check(bool value, const char* description)
    { if (value) { ++Passed; } else { ++Failed; std::cerr << "[irp.binding] FAIL " << description << '\n'; } }

    class Memory final : public IObservationSource
    {
    public:
        ObservationSourceCapabilities Caps;
        std::map<uint64_t, std::vector<uint8_t>> Regions;
        std::function<void(const ObservationReadRequest&)> Before;
        uint64_t Calls = 0, Missing = 0;
        Memory()
        {
            Caps.SourceId = L"owned_irp_fixture:1"; Caps.Consistency = L"single_read";
            Caps.KernelOnly = true; Caps.AddressSpace = AddressSpaceDescriptor::FromPagingLevels(4);
        }
        const ObservationSourceCapabilities& Capabilities() const override { return Caps; }
        template<class T> void Put(uint64_t address, const T& value)
        { auto& bytes = Regions[address]; bytes.resize(sizeof(value)); memcpy(bytes.data(), &value, sizeof(value)); }
    protected:
        ObservationReadResult ReadSpans(const ObservationReadRequest& q) override
        {
            ++Calls;
            if (Before) { Before(q); }
            ObservationReadResult result;
            result.BackendContract = L"owned_synthetic_kernel_address_map";
            ObservationReadSpan span{q.Address, q.Length, ObservationReadState::NotPresent, {}};
            const auto next = Regions.upper_bound(q.Address);
            if (next != Regions.begin() && q.Address != Missing)
            {
                const auto& region = *std::prev(next);
                const auto offset = q.Address - region.first;
                if (offset <= region.second.size() && q.Length <= region.second.size() - offset)
                {
                    span.State = ObservationReadState::Complete;
                    span.Bytes.assign(region.second.begin() + static_cast<size_t>(offset), region.second.begin() + static_cast<size_t>(offset + q.Length));
                }
            }
            result.State = span.State; result.Spans.push_back(std::move(span));
            return result;
        }
    };

    bool Initialize(Memory& memory, const std::wstring& path, executable_image::DiskPeMetadata* m)
    {
        SchemaArtifact image;
        if (!image.Open(path, 512ull * 1024 * 1024) || !executable_image::ReadDiskPeIdentityHandle(image.Handle(), m, nullptr)) { return false; }
        auto& mapped = memory.Regions[Image]; mapped.resize(m->SizeOfImage);
        std::vector<uint8_t> bytes;
        if (!executable_image::ReadFileBytesAt(image.Handle(), 0, m->SizeOfHeaders, &bytes)) { return false; }
        memcpy(mapped.data(), bytes.data(), bytes.size());
        for (const auto& section : m->Sections)
        {
            if (section.SizeOfRawData == 0) { continue; }
            if (!executable_image::ReadFileBytesAt(image.Handle(), section.PointerToRawData, section.SizeOfRawData, &bytes) ||
                section.VirtualAddress > mapped.size() || bytes.size() > mapped.size() - section.VirtualAddress) { return false; }
            memcpy(mapped.data() + section.VirtualAddress, bytes.data(), bytes.size());
        }
        _ETHREAD thread{};
        thread.Cid = {reinterpret_cast<void*>(100), reinterpret_cast<void*>(200)};
        thread.CreateTime = 132000000000000001ull;
        thread.IrpList = {Irp + offsetof(_IRP, ThreadListEntry), Irp + offsetof(_IRP, ThreadListEntry)};
        memory.Put(Thread, thread);
        _IRP irp{};
        irp.Type = 6; irp.Size = sizeof(_IRP) + sizeof(_IO_STACK_LOCATION);
        irp.ThreadListEntry = {Thread + offsetof(_ETHREAD, IrpList), Thread + offsetof(_ETHREAD, IrpList)};
        irp.StackCount = irp.CurrentLocation = 1; irp.PendingReturned = 1;
        irp.Tail.Overlay = {reinterpret_cast<void*>(Irp + sizeof(_IRP)), reinterpret_cast<void*>(Thread)};
        memory.Put(Irp, irp);
        _IO_STACK_LOCATION stack{};
        stack.MajorFunction = 3; stack.Control = 0xe0;
        stack.CompletionRoutine = reinterpret_cast<void*>(Image + 0x1000);
        stack.Context = reinterpret_cast<void*>(0xffff900000009000ull);
        auto& packet = memory.Regions[Irp]; const auto old = packet.size(); packet.resize(old + sizeof(stack));
        memcpy(packet.data() + old, &stack, sizeof(stack));
        return true;
    }

    std::wstring Json(const PendingIrpScanResult& r)
    {
        if (!r.Evidence) { return L""; }
        return mcpjson::Utf8ToWide(std::string(r.Evidence->Bytes.begin(), r.Evidence->Bytes.end()));
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc >= 2 && std::wstring(argv[1]) == L"--schema-worker") { return RunTypeSchemaWorkerCommand(argc, argv); }
    if (argc == 3 && std::wstring(argv[1]) == L"--replay-irp")
    {
        const auto replay = ReplayPendingIrpCapture(argv[2]);
        std::wcout << PendingIrpReplayJson(replay) << L'\n';
        return replay.SummaryMatched ? 0 : 1;
    }
    if (argc != 2) { return 2; }
    const std::filesystem::path root = argv[1];
    wchar_t own[32768]{}; GetModuleFileNameW(nullptr, own, 32768);
    PendingIrpSchemaBinding binding;
    binding.ImageBase = Image; binding.ImagePath = (root / L"fixture.exe").wstring();
    const wchar_t* types[] = {L"_ETHREAD", L"_IRP", L"_IO_STACK_LOCATION"};
    std::wstring error;
    BrokeredTypeLayouts cache;
    for (size_t i = 0; i < 3; ++i)
    {
        TypeSchemaPackage package;
        const bool generated = GenerateBrokeredTypeSchema(own, binding.ImagePath, (root / L"fixture.pdb").wstring(), types[i], &package, &error);
        Check(generated, "actual isolated DIA schema generated");
        if (!generated) { std::wcerr << error << '\n'; return 1; }
        TypeLayoutInfo layout;
        Check(cache.Insert(Image, types[i], package, &layout, &error) && layout.SchemaPackage &&
            TypeSchemaJson(*layout.SchemaPackage) == TypeSchemaJson(package), "full canonical package retained by cache");
        binding.Schemas[i] = layout.SchemaPackage;
        package.Fields.clear();
        Check(!binding.Schemas[i]->Fields.empty(), "retained package has independent immutable ownership");
    }
    cache.Clear();
    pending_irp::IrpLayout layout;
    Check(BuildPendingIrpLayout(binding, &layout, &error), "three retained schemas build layout after cache eviction");
    Check(layout.ThreadSize == sizeof(_ETHREAD) && layout.IrpSize == sizeof(_IRP) && layout.StackSize == sizeof(_IO_STACK_LOCATION) &&
        layout.ThreadIrpList == offsetof(_ETHREAD, IrpList) && layout.ThreadCreateTime == offsetof(_ETHREAD, CreateTime) &&
        layout.ThreadPid == offsetof(_ETHREAD, Cid) + offsetof(IrpFixtureCid, UniqueProcess) &&
        layout.ThreadTid == offsetof(_ETHREAD, Cid) + offsetof(IrpFixtureCid, UniqueThread) &&
        layout.Completion == offsetof(_IO_STACK_LOCATION, CompletionRoutine) && layout.Context == offsetof(_IO_STACK_LOCATION, Context) &&
        layout.CurrentStack == offsetof(_IRP, Tail) + offsetof(IrpFixtureTail, Overlay) + offsetof(IrpFixtureOverlay, CurrentStackLocation),
        "DIA fields agree with independent C++ sizeof/offsetof");
    Memory baseline; executable_image::DiskPeMetadata metadata;
    Check(Initialize(baseline, binding.ImagePath, &metadata), "owned PE mapping and typed objects initialized");
    const std::vector<PendingIrpThreadInput> threads{{Thread, 100, 200}};
    PendingIrpScanOptions options; options.ThreadInventoryComplete = true;
    uint32_t captureSequence = 0;
    const auto run = [&](Memory& memory, const PendingIrpSchemaBinding& selected, PendingIrpScanResult* result,
        const std::atomic<bool>* cancel = nullptr)
    {
        const auto captured = CaptureBoundPendingIrps(memory, selected, threads, options, result, &error, cancel);
        if (result->Evidence)
        {
            const auto path = (root / (L"case-" + std::to_wstring(++captureSequence) + L".knirp")).wstring();
            Check(PublishReferenceArtifact(path, result->Evidence->Bytes, &error), "negative and positive original capture preserved");
            const auto replay = ReplayPendingIrpCapture(path);
            Check(replay.SummaryMatched && replay.Recomputed.RuntimeQualified == result->RuntimeQualified &&
                replay.Recomputed.Records.size() == result->Records.size(), "same parser reproduces saved capture including negative outcomes");
            if (!replay.SummaryMatched) { std::wcerr << L"[irp.replay] case=" << captureSequence << L" issue=" << replay.Issue << L'\n'; }
        }
        return captured;
    };
    PendingIrpScanResult good;
    Check(run(baseline, binding, &good) && good.RuntimeQualified && good.CoverageComplete && good.Records.size() == 1 &&
        good.Requests.size() == 1 && !good.ReferencedLifetime, "schema image owner list and IRP invariants qualify bounded observation");
    if (!good.RuntimeQualified || good.Requests.empty() || !good.Evidence) { std::wcerr << error << '\n'; return 1; }
    const auto json = Json(good);
    std::wstring raw;
    ObservationRoutedReadSet readset;
    Check(mcpjson::ValidateDocument(json) && mcpjson::FindRawValue(json, L"reads", &raw) &&
        ParseObservationRoutedReadSet(raw, &readset) && readset.ParserReads.size() == baseline.Calls &&
        readset.Attempts.Reads.size() == baseline.Calls && baseline.Calls > 20,
        "all original target reads retained in canonical parseable readset");
    Check(good.Evidence && ContentHash::Bytes(good.Evidence->Bytes) == good.Evidence->Sha256 &&
        PendingIrpObservationJson(good.Requests.front(), good).find(good.Evidence->Sha256) != std::wstring::npos,
        "request references exact original capture digest without lifetime promotion");
    if (good.Evidence)
    {
        Check(PublishReferenceArtifact((root / L"positive.knirp").wstring(), good.Evidence->Bytes, &error), "capture written create-new");
        const auto missing = ReplayPendingIrpCapture((root / L"positive.knirp").wstring());
        Check(missing.SummaryMatched && !missing.QualifiedObservation && missing.ReferenceStatus == L"missing_or_unreadable",
            "metadata replay does not promote a missing reference image");
        Check(good.Evidence->Reference && good.Evidence->Reference->Sha256 == binding.Schemas[0]->ImageSha256 &&
            PublishReferenceArtifact((root / (L"irp-reference-" + good.Evidence->Reference->Sha256 + L".knblob")).wstring(),
                good.Evidence->Reference->Bytes, &error), "exact leased image bytes retained for offline replay");
        const auto verified = ReplayPendingIrpCapture((root / L"positive.knirp").wstring());
        Check(verified.SummaryMatched && verified.QualifiedObservation && verified.ReferenceStatus == L"verified" &&
            !verified.Recomputed.ReferencedLifetime, "saved image and ordered reads reproduce qualified observation without lifetime claim");
        Check(!PublishReferenceArtifact((root / L"positive.knirp").wstring(), std::vector<uint8_t>{1,2,3}, &error) &&
            ContentHash::File((root / L"positive.knirp").wstring()) == good.Evidence->Sha256, "collision leaves original capture intact");
        bool emptyAtAdmission = false;
        Check(!PublishReferenceArtifact((root / L"denied.knirp").wstring(), good.Evidence->Bytes, &error, [&](HANDLE file)
            { LARGE_INTEGER size{}; emptyAtAdmission = GetFileSizeEx(file, &size) && size.QuadPart == 0; return false; }) &&
            emptyAtAdmission && !std::filesystem::exists(root / L"denied.knirp"), "output admission rejects actual empty file before raw bytes are written");
        Check(!PublishReferenceArtifact((root / L"throwing.knirp").wstring(), good.Evidence->Bytes, &error,
            [](HANDLE) -> bool { throw std::runtime_error("owned admission exception"); }) &&
            !std::filesystem::exists(root / L"throwing.knirp"), "admission exception cannot publish or strand an owned pending file");
        bool pending = false;
        for (const auto& entry : std::filesystem::directory_iterator(root))
        { pending |= entry.path().filename().wstring().find(L".knirp.pending-") != std::wstring::npos; }
        Check(!pending, "failed publication disposes only exact owned pending handles");
    }
    for (int changed = 0; changed < 6; ++changed)
    {
        auto selected = binding; auto schema = std::make_shared<TypeSchemaPackage>(*selected.Schemas[1]);
        if (changed == 0) { schema->ImageSha256[0] = schema->ImageSha256[0] == L'a' ? L'b' : L'a'; }
        if (changed == 1) { schema->PdbSha256[0] = schema->PdbSha256[0] == L'a' ? L'b' : L'a'; }
        if (changed == 2) { ++schema->PdbAge; }
        if (changed == 3) { schema->ProviderVersion += L"-other"; }
        if (changed == 4) { schema->ProviderSha256[0] = schema->ProviderSha256[0] == L'a' ? L'b' : L'a'; }
        if (changed == 5) { schema->PdbGuid[0] = schema->PdbGuid[0] == L'a' ? L'b' : L'a'; }
        selected.Schemas[1] = schema;
        auto memory = baseline; memory.Calls = 0; PendingIrpScanResult rejected;
        Check(!run(memory, selected, &rejected) && !rejected.RuntimeQualified && memory.Calls == 0 && rejected.Records.empty(),
            "mixed schema artifact identities rejected before target reads");
    }
    {
        auto selected = binding; auto schema = std::make_shared<TypeSchemaPackage>(*selected.Schemas[1]);
        schema->Fields.erase(std::remove_if(schema->Fields.begin(), schema->Fields.end(), [](const auto& f) { return f.Path.back() == L"Cancel"; }), schema->Fields.end());
        selected.Schemas[1] = schema;
        auto memory = baseline; PendingIrpScanResult result;
        Check(run(memory, selected, &result) && result.RuntimeQualified && result.Records.size() == 1 && !result.Requests.front().CancelFlag.has_value(),
            "missing optional cancellation does not erase completion reference");
        schema->Fields.erase(std::remove_if(schema->Fields.begin(), schema->Fields.end(), [](const auto& f) { return f.Path.back() == L"Thread"; }), schema->Fields.end());
        memory.Calls = 0;
        Check(!run(memory, selected, &result) && memory.Calls == 0 && !result.RuntimeQualified, "missing required owner withholds qualification");
    }
    {
        auto selected = binding; auto schema = std::make_shared<TypeSchemaPackage>(*selected.Schemas[0]);
        TypeSchemaField parent; parent.Path = {L"<unnamed-fixture>"}; parent.TypeName = L"Anonymous"; parent.SymbolTag = 11;
        parent.StorageBytes = schema->TypeBytes; parent.Expansion = L"embedded";
        auto duplicate = *std::find_if(schema->Fields.begin(), schema->Fields.end(), [](const auto& f) { return f.Path.back() == L"CreateTime"; });
        duplicate.Path.insert(duplicate.Path.begin(), parent.Path.front());
        schema->Fields.push_back(parent); schema->Fields.push_back(duplicate); selected.Schemas[0] = schema;
        Check(ValidateTypeSchema(*schema, nullptr) && !BuildPendingIrpLayout(selected, &layout, &error), "ambiguous anonymous field rejected despite valid bounds");
    }
    for (int changed = 0; changed < 3; ++changed)
    {
        auto memory = baseline; memory.Calls = 0; PendingIrpScanResult result;
        if (changed == 0) { memory.Regions[Image][0] ^= 1; }
        if (changed == 1) { memory.Regions[Image][metadata.PdbRva + 4] ^= 1; }
        if (changed == 2) { memory.Missing = Image; }
        Check(!run(memory, binding, &result) && !result.RuntimeQualified && result.Records.empty() && result.Evidence,
            "wrong or unavailable initial loaded image preserves rejection evidence without decoding objects");
    }
    {
        auto memory = baseline; unsigned headers = 0;
        memory.Before = [&](const auto& q) { if (q.Address == Image && ++headers == 2) { memory.Regions[Image][0] ^= 1; } };
        PendingIrpScanResult result;
        Check(run(memory, binding, &result) && !result.RuntimeQualified && !result.CoverageComplete && result.Records.size() == 1 && result.Evidence &&
            PendingIrpObservationJson(result.Requests.front(), result).find(L"decoded_candidate") != std::wstring::npos,
            "late loaded-image change keeps raw candidate and evidence but removes qualification");
    }
    {
        auto memory = baseline; unsigned owners = 0;
        memory.Before = [&](const auto& q)
        {
            if (q.Address == Thread + offsetof(_ETHREAD, CreateTime) && ++owners == 2)
            { memory.Regions[Thread][offsetof(_ETHREAD, CreateTime)] ^= 1; }
        };
        PendingIrpScanResult result;
        Check(run(memory, binding, &result) && result.Records.empty() && result.Requests.empty() && !result.CoverageComplete && result.Evidence,
            "changed owner generation removes object relation while retaining original reads");
    }
    {
        auto memory = baseline;
        memory.Before = [&](const auto& q) { if (q.Address == Irp) { memory.Caps.SourceId = L"replacement_source"; } };
        PendingIrpScanResult result;
        Check(run(memory, binding, &result) && !result.RuntimeQualified && result.Records.empty() && result.Evidence,
            "source replacement cannot silently reuse schema image binding");
    }
    {
        auto memory = baseline; memory.Missing = Irp;
        PendingIrpScanResult result;
        Check(run(memory, binding, &result) && result.Records.empty() && !result.CoverageComplete && result.Evidence &&
            Json(result).find(L"not_present") != std::wstring::npos, "failed object read keeps original failure and no false empty inventory claim");
        std::atomic<bool> cancelled{true}; memory.Calls = 0;
        Check(!run(memory, binding, &result, &cancelled) && !result.RuntimeQualified && memory.Calls == 0 && result.Evidence,
            "pre-cancellation preserved without source invocation");
    }
    {
        auto memory = baseline;
        const uint64_t invalid = 0x1234;
        memcpy(memory.Regions[Irp].data() + sizeof(_IRP) + offsetof(_IO_STACK_LOCATION, CompletionRoutine), &invalid, sizeof(invalid));
        PendingIrpScanResult result;
        Check(run(memory, binding, &result) && result.Records.empty() && result.Requests.empty() && !result.CoverageComplete && result.Evidence,
            "non-kernel completion cannot enter callback targets despite equal IRP reads");
    }
    {
        auto memory = baseline;
        constexpr uint64_t secondIrp = Irp + 0x4000;
        memory.Regions[secondIrp] = memory.Regions[Irp];
        auto* thread = reinterpret_cast<_ETHREAD*>(memory.Regions[Thread].data());
        auto* first = reinterpret_cast<_IRP*>(memory.Regions[Irp].data());
        auto* second = reinterpret_cast<_IRP*>(memory.Regions[secondIrp].data());
        thread->IrpList.Blink = secondIrp + offsetof(_IRP, ThreadListEntry);
        first->ThreadListEntry.Flink = thread->IrpList.Blink;
        second->ThreadListEntry.Blink = Irp + offsetof(_IRP, ThreadListEntry);
        second->Tail.Overlay.CurrentStackLocation = reinterpret_cast<void*>(secondIrp + sizeof(_IRP));
        options.MaxIrps = 1;
        PendingIrpScanResult page1, page2;
        const bool firstPage = run(memory, binding, &page1);
        options.Cursor = page1.NextCursor;
        const bool secondPage = run(memory, binding, &page2);
        Check(firstPage && secondPage && page1.Requests.size() == 1 && page2.Requests.size() == 1 &&
            page1.Requests[0].Irp == Irp && page2.Requests[0].Irp == secondIrp && page1.NextCursor.IrpAddress == Irp &&
            !page1.CoverageComplete && !page2.CoverageComplete, "nonzero continuation cursor replays distinct bounded pages");
        options = {}; options.ThreadInventoryComplete = true;
    }
    {
        auto memory = baseline;
        std::atomic<bool> cancelled{false};
        memory.Before = [&](const auto& q) { if (q.Address == Irp) { cancelled.store(true); } };
        PendingIrpScanResult result;
        Check(run(memory, binding, &result, &cancelled) && !result.RuntimeQualified && result.Requests.empty(),
            "cancellation during a source read preserves the rejected complete receipt for replay");
    }
    {
        auto memory = baseline;
        memory.Caps.MaximumReadBytes = 1;
        memory.Calls = 0;
        auto& packet = memory.Regions[Irp];
        packet.resize(sizeof(_IRP) + 64 * sizeof(_IO_STACK_LOCATION));
        const auto bytes = static_cast<uint16_t>(packet.size());
        memcpy(packet.data() + offsetof(_IRP, Size), &bytes, sizeof(bytes));
        packet[offsetof(_IRP, StackCount)] = 64;
        PendingIrpScanResult result;
        Check(run(memory, binding, &result) && !result.RuntimeQualified && !result.CoverageComplete &&
            result.Records.empty() && memory.Calls == 2048 && result.Evidence && Json(result).find(L"budget_deferred") != std::wstring::npos,
            "shared source-call budget bounds repeated object reads and retains denials");
        std::wstring large;
        ObservationRoutedReadSet imported;
        Check(mcpjson::FindRawValue(Json(result), L"reads", &large) && large.size() > 2 * 1024 * 1024 &&
            !ParseObservationRoutedReadSet(large, &imported) && ParseObservationRoutedReadSet(large, &imported, PendingIrpEvidenceMaximumBytes),
            "large IRP import is explicit and leaves generic two MiB default intact");
    }
    std::cout << "[irp.binding] passed=" << Passed << " failed=" << Failed << '\n';
    return Failed == 0 ? 0 : 1;
}
