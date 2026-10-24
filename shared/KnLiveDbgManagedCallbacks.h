#pragma once

// Cooperative control of our test provider only. No addresses to patch, arbitrary
// callback pointers, or third-party driver targets are accepted by this protocol.
#define KNDBG_MANAGED_CALLBACK_PORT L"\\KnLiveDbgMiniFilterFixtureControl"
#define KNDBG_MANAGED_CALLBACK_FILTER L"KnLiveDbgMiniFilterFixture"
#define KNDBG_MANAGED_CALLBACK_MAGIC 0x4B4D4342u
#define KNDBG_MANAGED_CALLBACK_VERSION 1u
#define KNDBG_MANAGED_PRE 1u
#define KNDBG_MANAGED_POST 2u
#define KNDBG_MANAGED_BOTH 3u
#define KNDBG_MANAGED_QUERY 0u
#define KNDBG_MANAGED_DISABLE 1u
#define KNDBG_MANAGED_ENABLE 2u
#define KNDBG_MANAGED_RELEASE 3u
// A bounded, one-shot delay in our harmless CREATE body, for rundown testing.
#define KNDBG_MANAGED_TEST_HOLD 4u
// Test the gap before the body acquires its own rundown. The registered wrapper
// is still protected by FltMgr; this must never be used to justify raw hooks.
#define KNDBG_MANAGED_TEST_HOLD_BEFORE_BODY 5u

struct KNDBG_MANAGED_CALLBACK_REQUEST
{
    unsigned int Magic;
    unsigned int Version;
    unsigned int Size;
    unsigned int Action;
    unsigned int Mask;
    unsigned int HoldMilliseconds;
    unsigned int HoldProcessId;
    unsigned int Reserved;
    unsigned __int64 ExpectedFilter;
};

struct KNDBG_MANAGED_CALLBACK_STATUS
{
    unsigned int Magic;
    unsigned int Version;
    unsigned int Size;
    unsigned int SupportedMask;
    unsigned int EnabledMask;
    unsigned int PreviousEnabledMask;
    unsigned int DrainingMask;
    unsigned int Stopping;
    unsigned int OwnerPid;
    unsigned int Connections;
    unsigned int ActivePre;
    unsigned int ActivePost;
    unsigned __int64 OwnerConnection;
    unsigned __int64 Filter;
    unsigned __int64 Generation;
    unsigned __int64 AutomaticRestores;
    unsigned __int64 PreEntered;
    unsigned __int64 PostEntered;
    unsigned __int64 PreSkipped;
    unsigned __int64 PostSkipped;
    unsigned __int64 HoldEntered;
    unsigned __int64 HoldCompleted;
};

static_assert(sizeof(KNDBG_MANAGED_CALLBACK_REQUEST) == 40, "managed request ABI");
static_assert(sizeof(KNDBG_MANAGED_CALLBACK_STATUS) == 128, "managed status ABI");
