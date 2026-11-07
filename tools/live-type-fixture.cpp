#include "live-type-fixture.h"
__declspec(dllexport) volatile PdbIdentityFixture FixtureValue{};
unsigned long PdbIdentityFixture::StaticValue = 42;
__declspec(dllexport) volatile PdbDerivedFixture DerivedValue{};
__declspec(dllexport) volatile PdbDepthFixture<10> DeepValue{};
__declspec(dllexport) volatile _LiveAlias AliasValue{};
__declspec(dllexport) volatile _LiveCollision CollisionOne{};
__declspec(dllexport) volatile LiveCollision CollisionTwo{};
__declspec(dllexport) volatile LiveArray ArrayValue{};
int main() { return static_cast<int>(FixtureValue.Version); }
