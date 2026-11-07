#pragma once
#include "pdb-identity-fixture.h"

struct _LiveAlias
{
    int Exact;
    int exact;
    PdbNestedFixture Nested;
};
struct _LiveCollision { int Value; };
struct LiveCollision { long long Value; };
struct LiveArray { PdbNestedFixture Items[2]; };
