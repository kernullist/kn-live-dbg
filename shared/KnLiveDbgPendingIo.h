#pragma once

// Test-provider protocol only. No external callbacks, pointers or paths accepted.
#define KNDBG_PENDING_PORT L"\\KnLiveDbgMiniFilterFixturePendingIo"
#define KNDBG_PENDING_MAGIC 0x4B50494Fu
#define KNDBG_PENDING_VERSION 1u
#define KNDBG_PENDING_QUERY 0u
#define KNDBG_PENDING_ARM 1u
#define KNDBG_PENDING_RESUME 2u
#define KNDBG_PENDING_RELEASE 3u
#define KNDBG_PENDING_PRE 1u
#define KNDBG_PENDING_POST 2u
#define KNDBG_PENDING_BOTH 3u
#define KNDBG_PENDING_DRAIN_PAIR 4u // Async READ: upper context + lower pending pre.
#define KNDBG_PENDING_FAIL_PRE_QUEUE 5u
#define KNDBG_PENDING_FAIL_POST_QUEUE 6u
#define KNDBG_PENDING_FAIL_ALLOC 7u
#define KNDBG_PENDING_FAIL_READ_LOCK 8u // Paired READ, injected MDL-lock failure.

struct KNDBG_PENDING_REQUEST
{
    unsigned int Magic, Version, Size, Action;
    unsigned int Mode, TargetPid, DelayMilliseconds, Reserved;
};

struct KNDBG_PENDING_STATUS
{
    unsigned int Magic, Version, Size, Stopping;
    unsigned int ArmedMode, OwnerPid, Connections, WorkerAlive;
    unsigned int ActiveWorkers, QueueDepth, LiveContexts, LiveInstances;
    unsigned __int64 Created, Freed, LogicalCompleted;
    unsigned __int64 PreQueued, PreCompleted, PostCalled, PostQueued, PostCompleted;
    unsigned __int64 PostDrained, PreCancelled, AllocFailed, QueueFailed;
    unsigned __int64 OwnerRestores, InstanceStarts, InstanceCompletes;
    unsigned __int64 BufferLocks, BufferLockFailures, Violations;
};

static_assert(sizeof(KNDBG_PENDING_REQUEST) == 32, "pending request ABI");
static_assert(sizeof(KNDBG_PENDING_STATUS) == 192, "pending status ABI");
