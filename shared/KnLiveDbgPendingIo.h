#pragma once

// Test-provider protocol only. No external callbacks, pointers or paths accepted.
#define KNDBG_PENDING_PORT L"\\KnLiveDbgMiniFilterFixturePendingIo"
#define KNDBG_PENDING_MAGIC 0x4B50494Fu
#define KNDBG_PENDING_VERSION 6u
#define KNDBG_PENDING_QUERY 0u
#define KNDBG_PENDING_ARM 1u
#define KNDBG_PENDING_RESUME 2u
#define KNDBG_PENDING_RELEASE 3u
#define KNDBG_PENDING_ARM_RACE 4u // DelayMilliseconds=50..500, Reserved=one gate below.
#define KNDBG_PENDING_ARM_READ_BATCH 5u // DRAIN_PAIR only, Reserved=2..8 READs, first worker gate=50..500ms.
#define KNDBG_PENDING_GATE_PRE 1u
#define KNDBG_PENDING_GATE_POST 2u
#define KNDBG_PENDING_GATE_BEFORE_LOWER 4u
#define KNDBG_PENDING_GATE_EXIT_TAIL 8u // DRAIN_PAIR only; hold target exit after notification cleanup.
#define KNDBG_PENDING_GATE_WATCH_SNAPSHOT 16u // DRAIN_PAIR only; hold watch snapshot before probing.
#define KNDBG_PENDING_GATE_WATCH_RESULT 32u // DRAIN_PAIR only; hold an unsuccessful watch result before retirement.
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
    unsigned __int64 RaceEntered, RaceCompleted, RaceCancelSeen, RaceStopSeen;
    unsigned __int64 BeforeLowerEntered, BeforeLowerCompleted, StaleLowerRejected, OtherReadSkipped;
    unsigned __int64 ArmedRemaining, BatchArms, ManualTeardowns, UnloadTeardowns;
    unsigned __int64 RaceTeardownSeen, BeforeLowerCancelSeen, BeforeLowerStopSeen, BeforeLowerTeardownSeen;
    unsigned __int64 TopologyGeneration, ArmedGeneration, TopologyDisarms, GenerationLowerRejected;
    unsigned __int64 ArmDuringTeardownRejected, SetupDuringStopRejected;
    unsigned __int64 TargetArmRejected, TargetWatchRetires;
    unsigned __int64 TargetExitGateEntered, TargetExitGateCompleted, TargetExitGateStopSeen;
    unsigned __int64 TargetWatchProbes, TargetWatchStaleResults, WatchGateEntered, WatchGateCompleted;
    unsigned __int64 WatchGateKind, WatchGateTargetPid, WatchGateGeneration, WatchGateStatus;
};

static_assert(sizeof(KNDBG_PENDING_REQUEST) == 32, "pending request ABI");
static_assert(sizeof(KNDBG_PENDING_STATUS) == 472, "pending status ABI");
