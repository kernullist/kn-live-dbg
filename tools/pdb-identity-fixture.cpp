#include "pdb-identity-fixture.h"

__declspec(dllexport) volatile PdbIdentityFixture FixtureValue{};
unsigned long PdbIdentityFixture::StaticValue = 42;
__declspec(dllexport) volatile PdbDerivedFixture DerivedValue{};
__declspec(dllexport) volatile PdbDepthFixture<10> DeepValue{};

int main()
{
    return static_cast<int>(FixtureValue.Version);
}
