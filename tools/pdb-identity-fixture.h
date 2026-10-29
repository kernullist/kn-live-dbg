#pragma once

#ifndef FIXTURE_VARIANT
#define FIXTURE_VARIANT 1
#endif

struct PdbNestedFixture
{
    unsigned short Code;
    unsigned long long Counter;
};

struct PdbIdentityFixture
{
    unsigned long Version;
    unsigned char Padding[FIXTURE_VARIANT * 16];
    unsigned long long Value;
    unsigned int Flags : 3;
    unsigned int Reserved : 5;
    PdbNestedFixture Nested;
    PdbIdentityFixture* Next;
    static unsigned long StaticValue;
};

struct PdbDerivedFixture : PdbNestedFixture
{
    unsigned long Tail;
};

template<unsigned Depth>
struct PdbDepthFixture
{
    PdbDepthFixture<Depth - 1> Child;
};

template<>
struct PdbDepthFixture<0>
{
    unsigned char Value;
};
