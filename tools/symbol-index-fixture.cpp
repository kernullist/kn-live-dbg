#include "symbol-index-fixture.h"
extern "C" __declspec(dllexport) volatile PdbIdentityFixture SymbolFixture{};
unsigned long PdbIdentityFixture::StaticValue = 42;
static volatile SymbolFixtureCount PrivateSymbolState = 19;
static volatile SymbolFixtureMode PrivateMode = SymbolFixtureMode::First;
static __declspec(noinline) SymbolFixtureCount PrivateSymbolFunction(SymbolFixtureCount value)
{ return value + PrivateSymbolState + static_cast<SymbolFixtureCount>(PrivateMode); }
extern "C" __declspec(dllexport) __declspec(noinline) SymbolFixtureCount SymbolFixtureAdd(SymbolFixtureCount value)
{ return PrivateSymbolFunction(value) + SymbolFixture.Version; }
namespace SymbolFixtureScope
{
    __declspec(dllexport) __declspec(noinline) int Overload(int value) { return value + 7; }
    __declspec(dllexport) __declspec(noinline) int Overload(double value) { return static_cast<int>(value) + 13; }
}
int main() { return static_cast<int>(SymbolFixtureAdd(1)) + SymbolFixtureScope::Overload(1) + SymbolFixtureScope::Overload(1.5); }
