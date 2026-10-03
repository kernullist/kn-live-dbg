#include <Windows.h>

#include <cstdint>
#include <fstream>
#include <iomanip>

struct Primary
{
    virtual int First() = 0;
};

struct Secondary
{
    virtual int Second() = 0;
};

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

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        return 2;
    }
    const uint64_t base = reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr));
    const uint64_t object = reinterpret_cast<uint64_t>(&ManifestFixture);
    auto* primary = static_cast<Primary*>(&ManifestFixture);
    auto* secondary = static_cast<Secondary*>(&ManifestFixture);
    const uint64_t primaryTable = *reinterpret_cast<const uint64_t*>(primary);
    const uint64_t secondaryTable = *reinterpret_cast<const uint64_t*>(secondary);
    std::ofstream out(argv[1]);
    out << std::hex << "object fixture " << object - base << ' ' << sizeof(ManifestFixture) << " 0\n";
    out << "vptr fixture 0 " << primaryTable - base << " 1\n";
    out << "vptr fixture " << reinterpret_cast<uint64_t>(secondary) - object << ' ' << secondaryTable - base << " 1\n";
    return out.good() && primary->First() == 11 && secondary->Second() == 22 ? 0 : 1;
}
