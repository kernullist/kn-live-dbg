#include "../user/GameBuildManifest.h"
#include "../user/McpJson.h"

#include <chrono>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <new>

struct Primary
{
    virtual int First() = 0;
};

namespace game
{
    struct Secondary
    {
        virtual int Second() = 0;
    };
}
using game::Secondary;

struct Fixture : Primary, Secondary
{
    __declspec(noinline) int First() override
    {
        return 11;
    }

    __declspec(noinline) int Second() override
    {
        return 22;
    }
};

Fixture ManifestFixture;
Fixture OtherFixture;
Fixture* CurrentFixture = &ManifestFixture;
KnGameObjectSlotV1 DirectRegistry{}, IndirectRegistry{};

template<class T> uint64_t AddressOf(T* value) { return reinterpret_cast<uintptr_t>(value); }

uint64_t Word(uint64_t address)
{
    uint64_t value = 0;
    std::memcpy(&value, reinterpret_cast<const void*>(address), sizeof(value));
    return value;
}

int WriteLayout(const wchar_t* path, bool withLifetime)
{
    const uint64_t base = AddressOf(GetModuleHandleW(nullptr));
    const uint64_t object = AddressOf(&ManifestFixture);
    auto* primary = static_cast<Primary*>(&ManifestFixture);
    auto* secondary = static_cast<Secondary*>(&ManifestFixture);
    std::ofstream out{std::filesystem::path(path)};
    out << std::hex;
    const auto describe = [&](const char* name, uint64_t root, bool indirect, uint64_t slot, uint64_t container)
    {
        out << "object " << name << ' ' << root - base << ' ' << sizeof(Fixture) << ' ' << indirect << '\n';
        if (withLifetime) { out << "lifetime " << name << ' ' << slot - base << ' ' << container << '\n'; }
        out << "vptr " << name << " 0 " << Word(AddressOf(primary)) - base << (withLifetime ? " 1 Primary\n" : " 1\n");
        out << "vptr " << name << ' ' << AddressOf(secondary) - object << ' ' << Word(AddressOf(secondary)) - base
            << (withLifetime ? " 1 game::Secondary\n" : " 1\n");
    };
    describe("fixture", object, false, AddressOf(&DirectRegistry), 17);
    if (withLifetime) { describe("indirect", AddressOf(&CurrentFixture), true, AddressOf(&IndirectRegistry), 23); }
    out.close();
    return out && primary->First() == 11 && secondary->Second() == 22 ? 0 : 1;
}

void Advance(KnGameObjectSlotV1& slot) { InterlockedIncrement64(reinterpret_cast<volatile LONG64*>(&slot.Sequence)); }

void Publish(uint64_t generation, KnGameObjectPhase phase, bool reuse = false)
{
    Advance(DirectRegistry);
    Advance(IndirectRegistry);
    if (reuse)
    {
        CurrentFixture->~Fixture();
        CurrentFixture = new (&ManifestFixture) Fixture;
    }
    for (auto* record : {&DirectRegistry, &IndirectRegistry})
    {
        record->Generation = generation;
        record->ContainerId = record == &DirectRegistry ? 17 : 23;
        record->MemberAddress = AddressOf(CurrentFixture);
        record->Phase = static_cast<uint64_t>(phase);
    }
    Advance(IndirectRegistry);
    Advance(DirectRegistry);
}

int Exercise(const wchar_t* path, const std::wstring& scenario)
{
    wchar_t executable[32768]{};
    GameBuildManifest manifest;
    executable_image::DiskPeMetadata image;
    if (!GetModuleFileNameW(nullptr, executable, static_cast<DWORD>(std::size(executable))) ||
        !ReadGameManifest(path, &manifest, nullptr) || !executable_image::ReadDiskPeMetadata(executable, &image, nullptr) ||
        !MatchGameManifest(manifest, executable, image, nullptr)) { return 1; }
    const bool legacy = scenario == L"legacy";
    if (manifest.Vptrs.size() != (legacy ? 2u : 4u) || manifest.Objects.size() != (legacy ? 1u : 2u)) { return 1; }
    size_t cursor = legacy || scenario == L"direct_secondary" ? 1 : scenario == L"direct_primary" ? 0 :
        scenario == L"indirect_primary" ? 2 : 3;
    const auto index = cursor;
    const auto& object = manifest.Objects[manifest.Vptrs[index].ObjectIndex];
    auto& rule = manifest.Vptrs[index];
    auto& registry = object.Indirect ? IndirectRegistry : DirectRegistry;
    const auto base = AddressOf(GetModuleHandleW(nullptr));
    const uint64_t address = AddressOf(CurrentFixture);
    const uint64_t subobject = index % 2 ? AddressOf(static_cast<Secondary*>(CurrentFixture)) : AddressOf(static_cast<Primary*>(CurrentFixture));
    const uint64_t table = Word(subobject), target = Word(table);
    const bool race = scenario == L"reuse_during_read";
    if (scenario == L"wrong_table" || race) { rule.TableRva = manifest.Vptrs[0].TableRva; }
    if (scenario == L"wrong_slot") { rule.AllowedSlots = manifest.Vptrs[0].AllowedSlots; }
    auto phase = KnGameObjectPhase::Live;
    if (scenario == L"constructing") { phase = KnGameObjectPhase::Constructing; }
    if (scenario == L"destroying") { phase = KnGameObjectPhase::Destroying; }
    if (scenario == L"collecting") { phase = KnGameObjectPhase::Collecting; }
    if (scenario == L"vacant") { phase = KnGameObjectPhase::Vacant; }
    if (scenario == L"unknown_phase") { phase = static_cast<KnGameObjectPhase>(99); }
    if (scenario != L"unpublished") { Publish(scenario == L"zero_generation" ? 0 : UINT64_C(0x100000001), phase); }
    if (scenario == L"updating") { Advance(registry); }
    if (scenario == L"wrong_container") { registry.ContainerId = 99; }
    if (scenario == L"wrong_member") { registry.MemberAddress = AddressOf(&OtherFixture); }

    std::promise<void> permit;
    std::future<bool> writer;
    if (race)
    {
        writer = std::async(std::launch::async, [ready = permit.get_future()] {
            if (ready.wait_for(std::chrono::seconds(10)) != std::future_status::ready) { return false; }
            Publish(UINT64_C(0x100000002), KnGameObjectPhase::Live, true);
            return true;
        });
    }
    unsigned registryReads = 0, bodyReads = 0;
    bool overlapped = false;
    const ObservationReader reader = [&](uint64_t source, size_t bytes, std::vector<uint8_t>* data)
    {
        if (source == AddressOf(&registry))
        {
            ++registryReads;
            if (scenario == L"missing_after" && registryReads == 4) { return false; }
            if (scenario == L"short_record" && bytes == sizeof(registry)) { data->resize(bytes - 1); return true; }
            if (scenario == L"split_publication" && registryReads == 2) { Publish(7, KnGameObjectPhase::Live); }
        }
        else if (source == subobject || source == table) { ++bodyReads; }
        else if (source != AddressOf(&CurrentFixture)) { return false; }
        SIZE_T copied = 0;
        data->resize(bytes);
        if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<const void*>(source), data->data(), bytes, &copied) || copied != bytes)
        { return false; }
        if (source == table)
        {
            if (race && !overlapped)
            {
                overlapped = true;
                permit.set_value();
                if (!writer.get()) { return false; }
            }
            if (scenario == L"silent_generation_change") { ++registry.Generation; }
            if (scenario == L"root_changed") { CurrentFixture = &OtherFixture; }
        }
        return true;
    };
    const auto rows = VerifyGameObjects(manifest, base, reader, 1, &cursor);
    if (race && !overlapped) { permit.set_value(); writer.get(); return 1; }
    using mcpjson::Quote;
    std::wcout << L"{\"case\":" << Quote(scenario) << L",\"manifest_sha256\":" << Quote(manifest.FileSha256)
        << L",\"index\":" << index << L",\"cursor\":" << cursor << L",\"object\":" << address << L",\"subobject\":" << subobject
        << L",\"table\":" << table << L",\"target\":" << target << L",\"current_root\":" << AddressOf(CurrentFixture)
        << L",\"current_table\":" << Word(subobject) << L",\"registry_reads\":" << registryReads << L",\"body_reads\":" << bodyReads
        << L",\"overlapped\":" << (overlapped ? L"true" : L"false") << L",\"rows\":[";
    bool first = true;
    for (const auto& row : rows)
    {
        if (!first) { std::wcout << L','; }
        first = false;
        std::wcout << L"{\"readable\":" << (row.Readable ? L"true" : L"false") << L",\"modified\":" << (row.Modified ? L"true" : L"false")
            << L",\"vptr\":" << (row.IsVptr ? L"true" : L"false") << L",\"reason\":" << Quote(row.Reason)
            << L",\"object\":" << row.ObjectAddress << L",\"slot\":" << row.SlotAddress << L",\"target\":" << row.Target << L",\"fields\":{";
        bool firstField = true;
        for (const auto& field : GameObjectLifetimeEvidence(object, rule, row))
        {
            if (!firstField) { std::wcout << L','; }
            firstField = false;
            std::wcout << Quote(field.first) << L':' << Quote(field.second);
        }
        std::wcout << L"}}";
    }
    std::wcout << L"]}\n";
    return std::wcout.good() ? 0 : 1;
}

int wmain(int argc, wchar_t** argv)
{
    if (argc == 2) { return WriteLayout(argv[1], false); }
    if (argc == 3 && std::wstring(argv[1]) == L"--lifetime-layout") { return WriteLayout(argv[2], true); }
    if (argc == 4 && std::wstring(argv[1]) == L"--observe") { return Exercise(argv[2], argv[3]); }
    return 2;
}
