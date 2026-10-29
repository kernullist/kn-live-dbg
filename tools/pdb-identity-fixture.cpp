#ifndef FIXTURE_VARIANT
#define FIXTURE_VARIANT 1
#endif

struct PdbIdentityFixture
{
    unsigned long Version;
    unsigned char Padding[FIXTURE_VARIANT * 16];
    unsigned long long Value;
};

__declspec(dllexport) volatile PdbIdentityFixture FixtureValue{};

int main()
{
    return static_cast<int>(FixtureValue.Version);
}
