#pragma once
#include <cstdint>

// Owned user-mode PDB fixture, deliberately unrelated to a Windows build's
// offsets. Live structures are simulated at canonical kernel addresses.
struct IrpFixtureLink { uint64_t Flink, Blink; };
struct IrpFixtureCid { void* UniqueProcess; void* UniqueThread; };
struct _ETHREAD
{
    uint8_t Padding[40];
    IrpFixtureLink IrpList;
    IrpFixtureCid Cid;
    uint64_t CreateTime;
};
struct IrpFixtureOverlay { void* CurrentStackLocation; void* Thread; };
struct IrpFixtureTail { IrpFixtureOverlay Overlay; };
struct IrpFixtureStatus { int32_t Status; };
struct _IRP
{
    uint16_t Type, Size;
    uint8_t Padding[12];
    IrpFixtureLink ThreadListEntry;
    uint8_t StackCount, CurrentLocation, Cancel, PendingReturned;
    IrpFixtureStatus IoStatus;
    IrpFixtureTail Tail;
};
struct _IO_STACK_LOCATION
{
    uint8_t MajorFunction, MinorFunction, Control;
    uint8_t Padding[13];
    void* CompletionRoutine;
    void* Context;
    void* DeviceObject;
    void* FileObject;
};
