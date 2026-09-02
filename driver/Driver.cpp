#include <ntifs.h>
#include <wdmsec.h>
#include <intrin.h>
#include "../shared/KnLiveDbgIoctl.h"

extern "C"
NTKERNELAPI
VOID
KeFlushEntireTb(
    BOOLEAN Invalid,
    BOOLEAN AllProcessors);

#if defined(_M_X64)
#pragma intrinsic(__readcr0)
#pragma intrinsic(__readcr2)
#pragma intrinsic(__readcr3)
#pragma intrinsic(__readcr4)
#pragma intrinsic(__readcr8)
#pragma intrinsic(__invlpg)
#pragma intrinsic(__readmsr)
#pragma intrinsic(__writecr3)
#endif

// CR4.PCIDE enables process-context identifiers in CR3[11:0].
static const ULONGLONG KNDBG_CR4_PCIDE = 0x20000ull;

typedef struct _KNDBG_FILE_CONTEXT
{
    ULONG OwnerPid;
    BOOLEAN WriteEnabled;
    BOOLEAN OwnsController;
} KNDBG_FILE_CONTEXT, *PKNDBG_FILE_CONTEXT;

static DRIVER_UNLOAD KnDbgUnload;
static DRIVER_DISPATCH KnDbgCreateClose;
static DRIVER_DISPATCH KnDbgDeviceControl;
static DRIVER_DISPATCH KnDbgNotSupportedDispatch;

static const ULONGLONG KNDBG_PAGE_OFFSET_MASK = 0xfffull;
static const ULONGLONG KNDBG_PTE_PRESENT = 0x1ull;
static const ULONGLONG KNDBG_PTE_LARGE_PAGE = 0x80ull;
static const ULONGLONG KNDBG_PTE_4K_BASE_MASK = 0x000ffffffffff000ull;
static const ULONGLONG KNDBG_PTE_2MB_BASE_MASK = 0x000fffffffe00000ull;
static const ULONGLONG KNDBG_PTE_1GB_BASE_MASK = 0x000fffffc0000000ull;
static const ULONGLONG KNDBG_2MB_PAGE_SIZE = 0x200000ull;
static const ULONGLONG KNDBG_1GB_PAGE_SIZE = 0x40000000ull;
static const ULONGLONG KNDBG_CR4_LA57 = 0x1000ull;
static const GUID KNDBG_DEVICE_CLASS_GUID =
{
    0x4c2d7102,
    0xd0b5,
    0x4e3f,
    {0x95, 0x92, 0x6f, 0x9f, 0xb0, 0x2d, 0x46, 0x78}
};

static WCHAR g_KnDbgDeviceNameChars[96] = KNDBG_DEVICE_NAME;
static WCHAR g_KnDbgSymbolicLinkChars[96] = KNDBG_DOS_DEVICE_NAME;
static UNICODE_STRING g_KnDbgDeviceName = RTL_CONSTANT_STRING(KNDBG_DEVICE_NAME);
static UNICODE_STRING g_KnDbgSymbolicLink = RTL_CONSTANT_STRING(KNDBG_DOS_DEVICE_NAME);

static FAST_MUTEX g_KnDbgOwnerLock;
static ULONG g_KnDbgOwnerPid = 0;
static ULONG g_KnDbgOwnerOpenCount = 0;
static FAST_MUTEX g_KnDbgTimelineControlLock;
static KSPIN_LOCK g_KnDbgTimelineLock;
static volatile LONG g_KnDbgTimelineEnabled = 0;
static BOOLEAN g_KnDbgTimelineProcessRegistered = FALSE;
static BOOLEAN g_KnDbgTimelineImageRegistered = FALSE;
static BOOLEAN g_KnDbgTimelineThreadRegistered = FALSE;
static KNDBG_TIMELINE_EVENT_RECORD* g_KnDbgTimelineRing = nullptr;
static ULONG g_KnDbgTimelineCapacity = 0;
static ULONG g_KnDbgTimelineHead = 0;
static ULONG g_KnDbgTimelineCount = 0;
static ULONGLONG g_KnDbgTimelineDropped = 0;
static ULONGLONG g_KnDbgTimelineNextSequence = 1;

// Iotrace: single-target IRP_MJ_DEVICE_CONTROL interposition. The target
// DRIVER_OBJECT is referenced for the lifetime of the hook so it cannot be
// freed while a dispatch entry still points at our trampoline; disarm
// restores the original entry, waits for in-flight trampolines, and only
// then drops the reference.
static FAST_MUTEX g_KnDbgIotraceControlLock;
static KSPIN_LOCK g_KnDbgIotraceLock;
static PDRIVER_OBJECT g_KnDbgIotraceTarget = nullptr;
static PDRIVER_DISPATCH volatile g_KnDbgIotraceOriginalDispatch = nullptr;
static volatile LONG g_KnDbgIotraceArmed = 0;
static volatile LONG g_KnDbgIotraceActive = 0;
static KNDBG_IOTRACE_RECORD* g_KnDbgIotraceRing = nullptr;
static ULONG g_KnDbgIotraceHead = 0;
static ULONG g_KnDbgIotraceCount = 0;
static ULONGLONG g_KnDbgIotraceDropped = 0;
static ULONGLONG g_KnDbgIotraceNextSequence = 1;
static ULONGLONG g_KnDbgIotraceTotalRecorded = 0;

// CFG-valid minifilter Pre stand-in.
// Must return 1 (FLT_PREOP_SUCCESS_NO_CALLBACK). Return 0 is
// FLT_PREOP_SUCCESS_WITH_CALLBACK and drains FastIO to IRP.
// Keep these as C exports so /guard:cf emits GFIDS entries. Kernel MSVC
// has no _mm_endbr64 intrinsic; CET/IBT landing pads stay a known gap.
extern "C"
__declspec(dllexport)
__declspec(noinline)
ULONG_PTR
NTAPI
KnDbgMinifilterPreCallbackNop(
    PVOID Unused1,
    PVOID Unused2,
    PVOID Unused3,
    PVOID Unused4)
{
    UNREFERENCED_PARAMETER(Unused1);
    UNREFERENCED_PARAMETER(Unused2);
    UNREFERENCED_PARAMETER(Unused3);
    UNREFERENCED_PARAMETER(Unused4);
    return 1;
}

// CFG-valid return-0 stand-in.
// Minifilter Post: FLT_POSTOP_FINISHED_PROCESSING.
// Ob Pre: OB_PREOP_SUCCESS. Cm/Ps: STATUS_SUCCESS or ignored VOID.
// Return 1 is FLT_POSTOP_MORE_PROCESSING_REQUIRED and hangs I/O.
// Do not use this thunk as a minifilter Pre (that must return 1).
extern "C"
__declspec(dllexport)
__declspec(noinline)
ULONG_PTR
NTAPI
KnDbgMinifilterPostCallbackNop(
    PVOID Unused1,
    PVOID Unused2,
    PVOID Unused3,
    PVOID Unused4)
{
    UNREFERENCED_PARAMETER(Unused1);
    UNREFERENCED_PARAMETER(Unused2);
    UNREFERENCED_PARAMETER(Unused3);
    UNREFERENCED_PARAMETER(Unused4);
    return 0;
}

// Legacy alias with the Post contract (return 0). Do not use for Pre.
extern "C"
__declspec(dllexport)
__declspec(noinline)
ULONG_PTR
NTAPI
KnDbgMinifilterCallbackNop(
    PVOID Unused1,
    PVOID Unused2,
    PVOID Unused3,
    PVOID Unused4)
{
    return KnDbgMinifilterPostCallbackNop(Unused1, Unused2, Unused3, Unused4);
}

static bool KnDbgIsLa57Active();
static bool KnDbgIsCanonicalAddress(ULONGLONG VirtualAddress, bool La57Active);
static VOID KnDbgTimelineProcessNotify(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo);
static VOID KnDbgTimelineImageNotify(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo);
static VOID KnDbgTimelineThreadNotify(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create);

typedef struct _KNDBG_TLB_FLUSH_CONTEXT
{
    ULONGLONG StartAddress;
    SIZE_T PageCount;
    // Full CR3 value to load before invlpg (includes PCID when PCIDE is on).
    // 0 = flush against each CPU's current CR3.
    ULONGLONG Cr3Value;
    // When TRUE and PCIDE is enabled, also invalidate the VA across all PCIDs
    // (INVPCID type 2) because only a physical DTB was supplied.
    BOOLEAN InvalidateAllContexts;
} KNDBG_TLB_FLUSH_CONTEXT, *PKNDBG_TLB_FLUSH_CONTEXT;

static ULONGLONG KnDbgNormalizeDirectoryTableBase(ULONGLONG DirectoryTableBase)
{
    return DirectoryTableBase & KNDBG_PTE_4K_BASE_MASK;
}

static BOOLEAN KnDbgIsPlausibleDirectoryTableBase(ULONGLONG DirectoryTableBase)
{
    const ULONGLONG normalized = KnDbgNormalizeDirectoryTableBase(DirectoryTableBase);
    // Reject zero and values with non-address junk outside the PFN field after
    // normalization would still be zero/identity for a page-aligned DTB.
    if (normalized == 0)
    {
        return FALSE;
    }

    // Allow software bits in [11:0] (PCID / OS flags) but reject non-canonical
    // high junk above the physical address field.
    if ((DirectoryTableBase & ~KNDBG_PTE_4K_BASE_MASK & ~0xfffull) != 0)
    {
        return FALSE;
    }

    return TRUE;
}

static BOOLEAN KnDbgIsPcideEnabled()
{
#if defined(_M_X64)
    return (__readcr4() & KNDBG_CR4_PCIDE) != 0;
#else
    return FALSE;
#endif
}

static BOOLEAN KnDbgCpuSupportsInvpcid()
{
    int cpuInfo[4] = {};
    __cpuidex(cpuInfo, 7, 0);
    // CPUID.(EAX=7,ECX=0):EBX.INVPCID[bit 10]
    return (cpuInfo[1] & (1 << 10)) != 0;
}

static void KnDbgInvpcidAllContexts()
{
#if defined(_M_X64)
    // Type 2: all-context invalidation (non-global mappings for every PCID).
    // Descriptor is ignored; pass zeros.
    unsigned __int64 descriptor[2] = {};
    _invpcid(2, descriptor);
#endif
}

static NTSTATUS KnDbgCompleteIrp(PIRP Irp, NTSTATUS Status, ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static bool KnDbgCheckInputHeader(PVOID Buffer, ULONG InputLength, ULONG MinimumLength)
{
    bool ok = false;

    do
    {
        if (Buffer == nullptr)
        {
            break;
        }

        if (InputLength < sizeof(KNDBG_UINT32))
        {
            break;
        }

        KNDBG_UINT32 size = *(reinterpret_cast<KNDBG_UINT32*>(Buffer));
        if (size < MinimumLength)
        {
            break;
        }

        if (InputLength < size)
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static bool KnDbgRangeOverflows(ULONGLONG Address, SIZE_T Length)
{
    bool overflows = true;

    do
    {
        if (Length == 0)
        {
            break;
        }

        ULONGLONG lastOffset = static_cast<ULONGLONG>(Length - 1);
        overflows = Address > (~0ull - lastOffset);
    } while (false);

    return overflows;
}

static bool KnDbgIsCanonicalSystemRange(ULONGLONG Address, SIZE_T Length)
{
    bool valid = false;

    do
    {
        if (Length == 0)
        {
            break;
        }

        if (KnDbgRangeOverflows(Address, Length))
        {
            break;
        }

        bool la57Active = KnDbgIsLa57Active();
        if (!KnDbgIsCanonicalAddress(Address, la57Active))
        {
            break;
        }

        ULONGLONG endAddress = Address + Length - 1;
        if (!KnDbgIsCanonicalAddress(endAddress, la57Active))
        {
            break;
        }

        ULONGLONG systemRangeStart = static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(MmSystemRangeStart));
        if (Address < systemRangeStart)
        {
            break;
        }

        if (endAddress < systemRangeStart)
        {
            break;
        }

        valid = true;
    } while (false);

    return valid;
}

static bool KnDbgPreflightResidentSystemRange(PVOID Address, SIZE_T Length)
{
    bool resident = false;

    do
    {
        if (Address == nullptr || Length == 0)
        {
            break;
        }

        ULONGLONG startAddress = static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(Address));
        if (!KnDbgIsCanonicalSystemRange(startAddress, Length))
        {
            break;
        }

        ULONGLONG endAddress = startAddress + Length - 1;
        ULONGLONG page = startAddress & ~KNDBG_PAGE_OFFSET_MASK;
        ULONGLONG endPage = endAddress & ~KNDBG_PAGE_OFFSET_MASK;
        bool allPagesResident = true;

        while (page <= endPage)
        {
            BOOLEAN pageValid = FALSE;
            __try
            {
                pageValid = MmIsAddressValid(reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(page)));
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                pageValid = FALSE;
            }

            if (pageValid == FALSE)
            {
                allPagesResident = false;
                break;
            }

            if (page == endPage)
            {
                break;
            }

            if (page > (~0ull - PAGE_SIZE))
            {
                allPagesResident = false;
                break;
            }

            page += PAGE_SIZE;
        }

        if (!allPagesResident)
        {
            break;
        }

        resident = true;
    } while (false);

    return resident;
}

static ULONG KnDbgTimelineNormalizeCapacity(ULONG Capacity)
{
    ULONG value = Capacity;

    if (value == 0)
    {
        value = KNDBG_TIMELINE_DEFAULT_CAPACITY;
    }
    if (value < KNDBG_TIMELINE_MIN_CAPACITY)
    {
        value = KNDBG_TIMELINE_MIN_CAPACITY;
    }
    if (value > KNDBG_TIMELINE_MAX_CAPACITY)
    {
        value = KNDBG_TIMELINE_MAX_CAPACITY;
    }

    return value;
}

static void KnDbgTimelineCopyPath(KNDBG_TIMELINE_EVENT_RECORD* Record, PCUNICODE_STRING Path)
{
    if (Record != nullptr && Path != nullptr && Path->Buffer != nullptr && Path->Length != 0)
    {
        USHORT chars = static_cast<USHORT>(Path->Length / sizeof(wchar_t));
        if (chars >= KNDBG_TIMELINE_IMAGE_PATH_CHARS)
        {
            chars = KNDBG_TIMELINE_IMAGE_PATH_CHARS - 1;
        }

        RtlCopyMemory(Record->ImagePath, Path->Buffer, chars * sizeof(wchar_t));
        Record->ImagePath[chars] = L'\0';
        Record->ImagePathLength = chars;
    }
}

static void KnDbgTimelinePushEvent(const KNDBG_TIMELINE_EVENT_RECORD* Event)
{
    KIRQL oldIrql = PASSIVE_LEVEL;

    if (Event == nullptr || InterlockedCompareExchange(&g_KnDbgTimelineEnabled, 0, 0) == 0)
    {
        return;
    }

    KeAcquireSpinLock(&g_KnDbgTimelineLock, &oldIrql);
    if (g_KnDbgTimelineRing != nullptr && g_KnDbgTimelineCapacity != 0)
    {
        const BOOLEAN threadNoise =
            Event->Type == KNDBG_TIMELINE_EVENT_THREAD_CREATE ||
            Event->Type == KNDBG_TIMELINE_EVENT_THREAD_EXIT;
        // Thread create/exit dwarfs image-load. Drop the noise first when
        // the ring is under pressure so a post-arm driver map is not
        // overwritten before user mode drains it.
        if (threadNoise != FALSE &&
            g_KnDbgTimelineCount * 4ul >= g_KnDbgTimelineCapacity * 3ul)
        {
            ++g_KnDbgTimelineDropped;
        }
        else
        {
            KNDBG_TIMELINE_EVENT_RECORD* slot = &g_KnDbgTimelineRing[g_KnDbgTimelineHead];
            RtlCopyMemory(slot, Event, sizeof(*slot));
            slot->Size = sizeof(*slot);
            slot->Sequence = g_KnDbgTimelineNextSequence;
            ++g_KnDbgTimelineNextSequence;

            ++g_KnDbgTimelineHead;
            if (g_KnDbgTimelineHead >= g_KnDbgTimelineCapacity)
            {
                g_KnDbgTimelineHead = 0;
            }

            if (g_KnDbgTimelineCount < g_KnDbgTimelineCapacity)
            {
                ++g_KnDbgTimelineCount;
            }
            else
            {
                ++g_KnDbgTimelineDropped;
            }
        }
    }
    KeReleaseSpinLock(&g_KnDbgTimelineLock, oldIrql);
}

static void KnDbgTimelineClearLocked()
{
    if (g_KnDbgTimelineRing != nullptr && g_KnDbgTimelineCapacity != 0)
    {
        RtlZeroMemory(g_KnDbgTimelineRing, sizeof(KNDBG_TIMELINE_EVENT_RECORD) * g_KnDbgTimelineCapacity);
    }
    g_KnDbgTimelineHead = 0;
    g_KnDbgTimelineCount = 0;
    g_KnDbgTimelineDropped = 0;
    g_KnDbgTimelineNextSequence = 1;
}

static NTSTATUS KnDbgTimelineEnsureRing(ULONG Capacity)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    KNDBG_TIMELINE_EVENT_RECORD* newRing = nullptr;
    ULONG normalized = KnDbgTimelineNormalizeCapacity(Capacity);
    SIZE_T bytes = sizeof(KNDBG_TIMELINE_EVENT_RECORD) * static_cast<SIZE_T>(normalized);

    do
    {
        if (g_KnDbgTimelineRing != nullptr && g_KnDbgTimelineCapacity == normalized)
        {
            KIRQL oldIrql = PASSIVE_LEVEL;
            KeAcquireSpinLock(&g_KnDbgTimelineLock, &oldIrql);
            KnDbgTimelineClearLocked();
            KeReleaseSpinLock(&g_KnDbgTimelineLock, oldIrql);
            status = STATUS_SUCCESS;
            break;
        }

        newRing = reinterpret_cast<KNDBG_TIMELINE_EVENT_RECORD*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, 'tLnK'));
        if (newRing == nullptr)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }
        RtlZeroMemory(newRing, bytes);

        KIRQL oldIrql = PASSIVE_LEVEL;
        KeAcquireSpinLock(&g_KnDbgTimelineLock, &oldIrql);
        KNDBG_TIMELINE_EVENT_RECORD* oldRing = g_KnDbgTimelineRing;
        g_KnDbgTimelineRing = newRing;
        g_KnDbgTimelineCapacity = normalized;
        KnDbgTimelineClearLocked();
        KeReleaseSpinLock(&g_KnDbgTimelineLock, oldIrql);

        if (oldRing != nullptr)
        {
            ExFreePoolWithTag(oldRing, 'tLnK');
        }
        newRing = nullptr;
        status = STATUS_SUCCESS;
    } while (false);

    if (newRing != nullptr)
    {
        ExFreePoolWithTag(newRing, 'tLnK');
    }

    return status;
}

static void KnDbgTimelineUnregisterCallbacks()
{
    InterlockedExchange(&g_KnDbgTimelineEnabled, 0);

    if (g_KnDbgTimelineThreadRegistered != FALSE)
    {
        PsRemoveCreateThreadNotifyRoutine(KnDbgTimelineThreadNotify);
        g_KnDbgTimelineThreadRegistered = FALSE;
    }
    if (g_KnDbgTimelineProcessRegistered != FALSE)
    {
        PsSetCreateProcessNotifyRoutineEx(KnDbgTimelineProcessNotify, TRUE);
        g_KnDbgTimelineProcessRegistered = FALSE;
    }
    if (g_KnDbgTimelineImageRegistered != FALSE)
    {
        PsRemoveLoadImageNotifyRoutine(KnDbgTimelineImageNotify);
        g_KnDbgTimelineImageRegistered = FALSE;
    }
}

static NTSTATUS KnDbgTimelineRegisterCallbacks()
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    do
    {
        if (g_KnDbgTimelineProcessRegistered != FALSE &&
            g_KnDbgTimelineImageRegistered != FALSE &&
            g_KnDbgTimelineThreadRegistered != FALSE)
        {
            InterlockedExchange(&g_KnDbgTimelineEnabled, 1);
            status = STATUS_SUCCESS;
            break;
        }

        if (g_KnDbgTimelineProcessRegistered != FALSE ||
            g_KnDbgTimelineImageRegistered != FALSE ||
            g_KnDbgTimelineThreadRegistered != FALSE)
        {
            KnDbgTimelineUnregisterCallbacks();
        }

        status = PsSetCreateProcessNotifyRoutineEx(KnDbgTimelineProcessNotify, FALSE);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        g_KnDbgTimelineProcessRegistered = TRUE;

        status = PsSetLoadImageNotifyRoutine(KnDbgTimelineImageNotify);
        if (!NT_SUCCESS(status))
        {
            KnDbgTimelineUnregisterCallbacks();
            break;
        }
        g_KnDbgTimelineImageRegistered = TRUE;

        status = PsSetCreateThreadNotifyRoutine(KnDbgTimelineThreadNotify);
        if (!NT_SUCCESS(status))
        {
            KnDbgTimelineUnregisterCallbacks();
            break;
        }
        g_KnDbgTimelineThreadRegistered = TRUE;

        InterlockedExchange(&g_KnDbgTimelineEnabled, 1);
        status = STATUS_SUCCESS;
    } while (false);

    return status;
}

static VOID KnDbgTimelineProcessNotify(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    KNDBG_TIMELINE_EVENT_RECORD record = {};
    LARGE_INTEGER now = {};
    KeQuerySystemTime(&now);

    record.Size = sizeof(record);
    record.Timestamp100ns = static_cast<KNDBG_UINT64>(now.QuadPart);
    record.ProcessId = HandleToULong(ProcessId);
    record.ThreadId = HandleToULong(PsGetCurrentThreadId());
    if (CreateInfo != nullptr)
    {
        record.Type = KNDBG_TIMELINE_EVENT_PROCESS_CREATE;
        record.ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);
        KnDbgTimelineCopyPath(&record, CreateInfo->ImageFileName);
    }
    else
    {
        record.Type = KNDBG_TIMELINE_EVENT_PROCESS_EXIT;
    }

    KnDbgTimelinePushEvent(&record);
}

static VOID KnDbgTimelineThreadNotify(
    HANDLE ProcessId,
    HANDLE ThreadId,
    BOOLEAN Create)
{
    KNDBG_TIMELINE_EVENT_RECORD record = {};
    LARGE_INTEGER now = {};
    KeQuerySystemTime(&now);

    record.Size = sizeof(record);
    record.Type = Create != FALSE ? KNDBG_TIMELINE_EVENT_THREAD_CREATE : KNDBG_TIMELINE_EVENT_THREAD_EXIT;
    record.Timestamp100ns = static_cast<KNDBG_UINT64>(now.QuadPart);
    record.ProcessId = HandleToULong(ProcessId);
    record.ThreadId = HandleToULong(ThreadId);
    if (Create != FALSE)
    {
        record.CreatorProcessId = HandleToULong(PsGetCurrentProcessId());
        record.CreatorThreadId = HandleToULong(PsGetCurrentThreadId());
    }

    KnDbgTimelinePushEvent(&record);
}

static VOID KnDbgTimelineImageNotify(
    PUNICODE_STRING FullImageName,
    HANDLE ProcessId,
    PIMAGE_INFO ImageInfo)
{
    KNDBG_TIMELINE_EVENT_RECORD record = {};
    LARGE_INTEGER now = {};
    KeQuerySystemTime(&now);

    record.Size = sizeof(record);
    record.Type = KNDBG_TIMELINE_EVENT_IMAGE_LOAD;
    record.Timestamp100ns = static_cast<KNDBG_UINT64>(now.QuadPart);
    record.ProcessId = HandleToULong(ProcessId);
    record.ThreadId = HandleToULong(PsGetCurrentThreadId());
    if (ImageInfo != nullptr)
    {
        record.ImageBase = reinterpret_cast<KNDBG_UINT64>(ImageInfo->ImageBase);
        record.ImageSize = static_cast<KNDBG_UINT64>(ImageInfo->ImageSize);
        if (ImageInfo->SystemModeImage != 0)
        {
            record.Flags |= KNDBG_TIMELINE_IMAGE_FLAG_SYSTEM_MODE;
        }
        if (ImageInfo->ImagePartialMap != 0)
        {
            record.Flags |= KNDBG_TIMELINE_IMAGE_FLAG_PARTIAL_MAP;
        }
        record.Flags |= (ImageInfo->ImageSignatureLevel & 0xFu) <<
            KNDBG_TIMELINE_IMAGE_SIGLEVEL_SHIFT;
        record.Flags |= (ImageInfo->ImageSignatureType & 0x7u) <<
            KNDBG_TIMELINE_IMAGE_SIGTYPE_SHIFT;
        if (ImageInfo->ExtendedInfoPresent != 0)
        {
            const IMAGE_INFO_EX* imageInfoEx =
                CONTAINING_RECORD(ImageInfo, IMAGE_INFO_EX, ImageInfo);
            if (imageInfoEx != nullptr &&
                imageInfoEx->Size >= sizeof(IMAGE_INFO_EX))
            {
                record.Flags |= KNDBG_TIMELINE_IMAGE_FLAG_EXTENDED;
                if (imageInfoEx->FileObject != nullptr)
                {
                    record.FileObject =
                        reinterpret_cast<KNDBG_UINT64>(imageInfoEx->FileObject);
                }
            }
        }
    }
    KnDbgTimelineCopyPath(&record, FullImageName);

    KnDbgTimelinePushEvent(&record);
}

// MDL-based read used only when the caller explicitly allows the fallback.
// MmProbeAndLockPages can bugcheck on arbitrary invalid system VAs, so this
// path is intentionally conservative: only canonical system ranges whose pages
// are already resident pass the preflight. Everything else stays on the safer
// MmCopyMemory result and surfaces as a failed or partial read to user mode.
static NTSTATUS KnDbgReadVirtualAddressViaMdl(PVOID Address, PVOID Output, SIZE_T Length, PSIZE_T BytesCopied)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PMDL mdl = nullptr;
    BOOLEAN locked = FALSE;

    do
    {
        if (BytesCopied != nullptr)
        {
            *BytesCopied = 0;
        }

        if (KeGetCurrentIrql() > APC_LEVEL)
        {
            status = STATUS_INVALID_DEVICE_STATE;
            break;
        }

        // MmProbeAndLockPages(KernelMode, ...) treats Address as kernel-space.
        // If a user-mode VA slips through here it could bugcheck the box (the
        // probe would access user-mode page tables under the system DTB). We
        // are a kernel-debug helper and only read kernel ranges, so refuse
        // anything below MmSystemRangeStart up front.
        ULONGLONG inputAddress = static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(Address));
        ULONGLONG systemRangeStart = static_cast<ULONGLONG>(reinterpret_cast<ULONG_PTR>(MmSystemRangeStart));
        if (inputAddress < systemRangeStart)
        {
            status = STATUS_INVALID_ADDRESS;
            break;
        }

        if (!KnDbgPreflightResidentSystemRange(Address, Length))
        {
            status = STATUS_INVALID_ADDRESS;
            break;
        }

        // Defensive cap on the cast to ULONG. KNDBG_MAX_TRANSFER_SIZE is the
        // upstream guard at 1 MB, so this is theoretical, but the explicit
        // cast above would silently truncate if anyone ever raises that gate
        // past 4 GB and the resulting RtlCopyMemory would read past the end
        // of the locked range.
        if (Length > MAXULONG)
        {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        mdl = IoAllocateMdl(Address, static_cast<ULONG>(Length), FALSE, FALSE, NULL);
        if (mdl == nullptr)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        __try
        {
            MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);
            locked = TRUE;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
            if (NT_SUCCESS(status))
            {
                status = STATUS_INVALID_ADDRESS;
            }
            break;
        }

        // After probing-and-locking, the pages are guaranteed resident and the
        // original kernel VA can be read directly without aliasing through
        // MmGetSystemAddressForMdlSafe. Wrap in __try for the rare case where
        // the underlying mapping changes mid-copy (e.g. a concurrent unload).
        __try
        {
            RtlCopyMemory(Output, Address, Length);
            if (BytesCopied != nullptr)
            {
                *BytesCopied = Length;
            }
            status = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
            if (NT_SUCCESS(status))
            {
                status = STATUS_INVALID_ADDRESS;
            }
        }
    } while (false);

    if (locked)
    {
        MmUnlockPages(mdl);
    }
    if (mdl != nullptr)
    {
        IoFreeMdl(mdl);
    }

    return status;
}

static NTSTATUS KnDbgReadVirtualAddress(ULONGLONG Address, PVOID Output, SIZE_T Length, ULONG Flags, PSIZE_T BytesCopied)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    do
    {
        if (Output == nullptr || BytesCopied == nullptr)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (Length == 0 || Length > KNDBG_MAX_TRANSFER_SIZE)
        {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        if (KnDbgRangeOverflows(Address, Length))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        PVOID sourceVa = reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(Address));

        MM_COPY_ADDRESS source = {};
        source.VirtualAddress = sourceVa;

        *BytesCopied = 0;
        status = MmCopyMemory(Output, source, Length, MM_COPY_MEMORY_VIRTUAL, BytesCopied);

        // MDL fallback can page in valid pageable driver sections, but it is
        // too aggressive for scanners that probe untrusted callback/list
        // pointers. Keep it opt-in for explicit dump paths only.
        if (!NT_SUCCESS(status) &&
            ((Flags & KNDBG_READ_FLAG_ALLOW_MDL_FALLBACK) != 0))
        {
            NTSTATUS savedStatus = status;
            // Preserve any partial bytes MmCopyMemory copied before failing
            // so we can hand them back on full fallback failure. The MDL
            // helper zeroes *BytesCopied at entry, so without this snapshot
            // we would drop partial successes.
            SIZE_T savedBytesCopied = *BytesCopied;
            SIZE_T mdlCopied = 0;
            NTSTATUS mdlStatus = KnDbgReadVirtualAddressViaMdl(sourceVa, Output, Length, &mdlCopied);
            if (NT_SUCCESS(mdlStatus))
            {
                *BytesCopied = mdlCopied;
                status = mdlStatus;
            }
            else
            {
                *BytesCopied = savedBytesCopied;
                status = savedStatus;
            }
        }
    } while (false);

    return status;
}

static NTSTATUS KnDbgWriteVirtualAddress(ULONGLONG Address, const VOID* Input, SIZE_T Length, PSIZE_T BytesCopied)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    do
    {
        if (Input == nullptr || BytesCopied == nullptr)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (Length == 0 || Length > KNDBG_MAX_TRANSFER_SIZE)
        {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        if (KnDbgRangeOverflows(Address, Length))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        *BytesCopied = 0;

        __try
        {
            RtlCopyMemory(reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(Address)), Input, Length);
            *BytesCopied = Length;
            status = STATUS_SUCCESS;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
        }
    } while (false);

    return status;
}

static SIZE_T KnDbgMinSize(SIZE_T Left, SIZE_T Right)
{
    return Left < Right ? Left : Right;
}

static bool KnDbgIsLa57Active()
{
    bool active = false;

    do
    {
#if defined(_M_X64)
        active = (__readcr4() & KNDBG_CR4_LA57) != 0;
#endif
    } while (false);

    return active;
}

static bool KnDbgIsCanonicalAddress(ULONGLONG VirtualAddress, bool La57Active)
{
    bool canonical = false;

    do
    {
        ULONG signBit = La57Active ? 56u : 47u;
        ULONG highShift = La57Active ? 57u : 48u;
        ULONGLONG high = VirtualAddress >> highShift;
        ULONGLONG sign = (VirtualAddress >> signBit) & 0x1ull;
        ULONGLONG expectedHigh = La57Active ? 0x7full : 0xffffull;

        if (sign == 0)
        {
            canonical = high == 0;
        }
        else
        {
            canonical = high == expectedHigh;
        }
    } while (false);

    return canonical;
}

static ULONG_PTR KnDbgFlushVirtualRangeWorker(ULONG_PTR Context)
{
    PKNDBG_TLB_FLUSH_CONTEXT flushContext = reinterpret_cast<PKNDBG_TLB_FLUSH_CONTEXT>(Context);

    do
    {
        if (flushContext == nullptr)
        {
            break;
        }

#if defined(_M_X64)
        // IPI runs at IPI_LEVEL. Load the caller's CR3 (with PCID when present)
        // so invlpg hits the same tagged translations the target process uses.
        ULONGLONG previousCr3 = 0;
        BOOLEAN switched = FALSE;
        if (flushContext->Cr3Value != 0)
        {
            previousCr3 = __readcr3();
            if (previousCr3 != flushContext->Cr3Value)
            {
                __writecr3(flushContext->Cr3Value);
                switched = TRUE;
            }
        }

        for (SIZE_T index = 0; index < flushContext->PageCount; ++index)
        {
            ULONGLONG address = flushContext->StartAddress + index * PAGE_SIZE;
            __invlpg(reinterpret_cast<void*>(static_cast<ULONG_PTR>(address)));
        }

        if (switched != FALSE)
        {
            __writecr3(previousCr3);
        }

        // Physical-DTB-only flushes cannot recover the live PCID. When PCIDE is
        // on, broaden invalidation so stale tagged entries cannot retain a
        // temporary Write-bit view.
        if (flushContext->InvalidateAllContexts != FALSE &&
            KnDbgIsPcideEnabled() &&
            KnDbgCpuSupportsInvpcid())
        {
            KnDbgInvpcidAllContexts();
        }
#endif
    } while (false);

    return 0;
}

static NTSTATUS KnDbgFlushVirtualRange(
    ULONGLONG VirtualAddress,
    SIZE_T Length,
    ULONGLONG Cr3Value,
    BOOLEAN InvalidateAllContexts)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    do
    {
        if (Length == 0 || Length > KNDBG_MAX_TRANSFER_SIZE)
        {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        if (KnDbgRangeOverflows(VirtualAddress, Length))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        bool la57Active = KnDbgIsLa57Active();
        if (!KnDbgIsCanonicalAddress(VirtualAddress, la57Active))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        ULONGLONG endAddress = VirtualAddress + Length - 1;
        if (!KnDbgIsCanonicalAddress(endAddress, la57Active))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        ULONGLONG startPage = VirtualAddress & ~KNDBG_PAGE_OFFSET_MASK;
        ULONGLONG endPage = endAddress & ~KNDBG_PAGE_OFFSET_MASK;
        SIZE_T pageCount = static_cast<SIZE_T>(((endPage - startPage) / PAGE_SIZE) + 1);
        KNDBG_TLB_FLUSH_CONTEXT context = {};
        context.StartAddress = startPage;
        context.PageCount = pageCount;
        context.Cr3Value = Cr3Value;
        context.InvalidateAllContexts = InvalidateAllContexts;

#if defined(_M_X64)
        KeIpiGenericCall(KnDbgFlushVirtualRangeWorker, reinterpret_cast<ULONG_PTR>(&context));
#endif
        status = STATUS_SUCCESS;
    } while (false);

    return status;
}

static NTSTATUS KnDbgAcquireController(PKNDBG_FILE_CONTEXT FileContext)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    do
    {
        if (FileContext == nullptr)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        ULONG currentPid = HandleToULong(PsGetCurrentProcessId());
        ExAcquireFastMutex(&g_KnDbgOwnerLock);

        if (g_KnDbgOwnerPid != 0 && g_KnDbgOwnerPid != currentPid)
        {
            status = STATUS_DEVICE_BUSY;
        }
        else
        {
            g_KnDbgOwnerPid = currentPid;
            ++g_KnDbgOwnerOpenCount;
            FileContext->OwnerPid = currentPid;
            FileContext->OwnsController = TRUE;
            status = STATUS_SUCCESS;
        }

        ExReleaseFastMutex(&g_KnDbgOwnerLock);
    } while (false);

    return status;
}

static void KnDbgReleaseController(PKNDBG_FILE_CONTEXT FileContext)
{
    do
    {
        if (FileContext == nullptr || FileContext->OwnsController == FALSE)
        {
            break;
        }

        ExAcquireFastMutex(&g_KnDbgOwnerLock);

        if (g_KnDbgOwnerPid == FileContext->OwnerPid)
        {
            if (g_KnDbgOwnerOpenCount > 0)
            {
                --g_KnDbgOwnerOpenCount;
            }

            if (g_KnDbgOwnerOpenCount == 0)
            {
                g_KnDbgOwnerPid = 0;
            }
        }

        ExReleaseFastMutex(&g_KnDbgOwnerLock);
        FileContext->OwnsController = FALSE;
    } while (false);
}

static NTSTATUS KnDbgReadPhysicalAddress(ULONGLONG PhysicalAddress, PVOID Output, SIZE_T Length, PSIZE_T BytesCopied)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    do
    {
        if (Output == nullptr || BytesCopied == nullptr)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (Length == 0 || Length > KNDBG_MAX_TRANSFER_SIZE)
        {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        if (KnDbgRangeOverflows(PhysicalAddress, Length))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        MM_COPY_ADDRESS source = {};
        source.PhysicalAddress.QuadPart = static_cast<LONGLONG>(PhysicalAddress);

        *BytesCopied = 0;
        status = MmCopyMemory(Output, source, Length, MM_COPY_MEMORY_PHYSICAL, BytesCopied);
    } while (false);

    return status;
}

static NTSTATUS KnDbgReadPhysicalU64(ULONGLONG PhysicalAddress, PULONGLONG Value)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    do
    {
        if (Value == nullptr)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        ULONGLONG localValue = 0;
        SIZE_T bytesCopied = 0;
        status = KnDbgReadPhysicalAddress(PhysicalAddress, &localValue, sizeof(localValue), &bytesCopied);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        if (bytesCopied != sizeof(localValue))
        {
            status = STATUS_PARTIAL_COPY;
            break;
        }

        *Value = localValue;
        status = STATUS_SUCCESS;
    } while (false);

    return status;
}

static NTSTATUS KnDbgWritePhysicalAddress(ULONGLONG PhysicalAddress, const VOID* Input, SIZE_T Length, PSIZE_T BytesCopied)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    do
    {
        if (Input == nullptr || BytesCopied == nullptr)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (Length == 0 || Length > KNDBG_MAX_TRANSFER_SIZE)
        {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        if (KnDbgRangeOverflows(PhysicalAddress, Length))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        *BytesCopied = 0;
        SIZE_T offset = 0;

        while (offset < Length)
        {
            ULONGLONG currentPhysical = PhysicalAddress + offset;
            ULONGLONG alignedPhysical = currentPhysical & ~KNDBG_PAGE_OFFSET_MASK;
            SIZE_T pageOffset = static_cast<SIZE_T>(currentPhysical & KNDBG_PAGE_OFFSET_MASK);
            SIZE_T chunk = KnDbgMinSize(Length - offset, static_cast<SIZE_T>(PAGE_SIZE) - pageOffset);
            SIZE_T mapLength = pageOffset + chunk;

            PHYSICAL_ADDRESS mapAddress = {};
            mapAddress.QuadPart = static_cast<LONGLONG>(alignedPhysical);

            PVOID mapped = MmMapIoSpaceEx(mapAddress, mapLength, PAGE_READWRITE);
            bool mappedWithIoSpace = true;
            if (mapped == nullptr)
            {
                PHYSICAL_ADDRESS exactAddress = {};
                exactAddress.QuadPart = static_cast<LONGLONG>(currentPhysical);
                mapped = MmGetVirtualForPhysical(exactAddress);
                mappedWithIoSpace = false;
            }

            if (mapped == nullptr)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            __try
            {
                PUCHAR destination = mappedWithIoSpace ?
                    reinterpret_cast<PUCHAR>(mapped) + pageOffset :
                    reinterpret_cast<PUCHAR>(mapped);
                RtlCopyMemory(destination, reinterpret_cast<const UCHAR*>(Input) + offset, chunk);
                KeMemoryBarrier();
                status = STATUS_SUCCESS;
            }
            __except (EXCEPTION_EXECUTE_HANDLER)
            {
                status = GetExceptionCode();
            }

            if (mappedWithIoSpace)
            {
                MmUnmapIoSpace(mapped, mapLength);
            }

            if (!NT_SUCCESS(status))
            {
                break;
            }

            offset += chunk;
            *BytesCopied = offset;
        }
    } while (false);

    return status;
}

static NTSTATUS KnDbgTranslateVirtualAddress(
    ULONGLONG DirectoryTableBase,
    ULONGLONG VirtualAddress,
    ULONG Length,
    KNDBG_TRANSLATE_VIRTUAL_RESPONSE* Response)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    do
    {
        if (Response == nullptr)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (Length == 0 || Length > KNDBG_MAX_TRANSFER_SIZE)
        {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        bool la57Active = KnDbgIsLa57Active();
        if (!KnDbgIsCanonicalAddress(VirtualAddress, la57Active))
        {
            status = STATUS_ACCESS_VIOLATION;
            break;
        }

        ULONG flags = 0;
        ULONGLONG directoryTableBase = DirectoryTableBase;
        if (directoryTableBase == 0)
        {
#if defined(_M_X64)
            directoryTableBase = __readcr3();
            flags |= KNDBG_TRANSLATE_FLAG_CURRENT_CR3;
#else
            status = STATUS_NOT_SUPPORTED;
            break;
#endif
        }

        directoryTableBase &= KNDBG_PTE_4K_BASE_MASK;
        if (directoryTableBase == 0)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        RtlZeroMemory(Response, sizeof(KNDBG_TRANSLATE_VIRTUAL_RESPONSE));
        Response->Size = sizeof(KNDBG_TRANSLATE_VIRTUAL_RESPONSE);
        Response->Flags = flags;
        if (la57Active)
        {
            Response->Flags |= KNDBG_TRANSLATE_FLAG_LA57_ACTIVE;
        }
        Response->DirectoryTableBase = directoryTableBase;
        Response->VirtualAddress = VirtualAddress;
        Response->RequestedLength = Length;
        Response->PagingLevels = la57Active ? 5u : 4u;

        ULONGLONG pml4Base = directoryTableBase;
        if (la57Active)
        {
            ULONGLONG pml5Index = (VirtualAddress >> 48) & 0x1ffull;
            ULONGLONG pml5eAddress = directoryTableBase + pml5Index * sizeof(ULONGLONG);
            Response->Pml5eAddress = pml5eAddress;
            status = KnDbgReadPhysicalU64(pml5eAddress, &Response->Pml5e);
            if (!NT_SUCCESS(status))
            {
                break;
            }

            if ((Response->Pml5e & KNDBG_PTE_PRESENT) == 0)
            {
                status = STATUS_ACCESS_VIOLATION;
                break;
            }

            pml4Base = Response->Pml5e & KNDBG_PTE_4K_BASE_MASK;
        }

        ULONGLONG pml4Index = (VirtualAddress >> 39) & 0x1ffull;
        ULONGLONG pdptIndex = (VirtualAddress >> 30) & 0x1ffull;
        ULONGLONG pdIndex = (VirtualAddress >> 21) & 0x1ffull;
        ULONGLONG ptIndex = (VirtualAddress >> 12) & 0x1ffull;

        ULONGLONG pml4eAddress = pml4Base + pml4Index * sizeof(ULONGLONG);
        Response->Pml4eAddress = pml4eAddress;
        status = KnDbgReadPhysicalU64(pml4eAddress, &Response->Pml4e);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        if ((Response->Pml4e & KNDBG_PTE_PRESENT) == 0)
        {
            status = STATUS_ACCESS_VIOLATION;
            break;
        }

        ULONGLONG pdpteAddress = (Response->Pml4e & KNDBG_PTE_4K_BASE_MASK) + pdptIndex * sizeof(ULONGLONG);
        Response->PdpteAddress = pdpteAddress;
        status = KnDbgReadPhysicalU64(pdpteAddress, &Response->Pdpte);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        if ((Response->Pdpte & KNDBG_PTE_PRESENT) == 0)
        {
            status = STATUS_ACCESS_VIOLATION;
            break;
        }

        if ((Response->Pdpte & KNDBG_PTE_LARGE_PAGE) != 0)
        {
            ULONGLONG pageOffset = VirtualAddress & (KNDBG_1GB_PAGE_SIZE - 1);
            ULONGLONG pageBytes = KNDBG_1GB_PAGE_SIZE - pageOffset;

            Response->Flags |= KNDBG_TRANSLATE_FLAG_LARGE_PAGE;
            Response->PageSize = KNDBG_1GB_PAGE_SIZE;
            Response->PageOffset = pageOffset;
            Response->PageBytes = pageBytes;
            Response->PhysicalAddress = (Response->Pdpte & KNDBG_PTE_1GB_BASE_MASK) + pageOffset;
            Response->TranslatedLength = static_cast<KNDBG_UINT32>(
                KnDbgMinSize(static_cast<SIZE_T>(Length), static_cast<SIZE_T>(pageBytes)));
            status = STATUS_SUCCESS;
            break;
        }

        ULONGLONG pdeAddress = (Response->Pdpte & KNDBG_PTE_4K_BASE_MASK) + pdIndex * sizeof(ULONGLONG);
        Response->PdeAddress = pdeAddress;
        status = KnDbgReadPhysicalU64(pdeAddress, &Response->Pde);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        if ((Response->Pde & KNDBG_PTE_PRESENT) == 0)
        {
            status = STATUS_ACCESS_VIOLATION;
            break;
        }

        if ((Response->Pde & KNDBG_PTE_LARGE_PAGE) != 0)
        {
            ULONGLONG pageOffset = VirtualAddress & (KNDBG_2MB_PAGE_SIZE - 1);
            ULONGLONG pageBytes = KNDBG_2MB_PAGE_SIZE - pageOffset;

            Response->Flags |= KNDBG_TRANSLATE_FLAG_LARGE_PAGE;
            Response->PageSize = KNDBG_2MB_PAGE_SIZE;
            Response->PageOffset = pageOffset;
            Response->PageBytes = pageBytes;
            Response->PhysicalAddress = (Response->Pde & KNDBG_PTE_2MB_BASE_MASK) + pageOffset;
            Response->TranslatedLength = static_cast<KNDBG_UINT32>(
                KnDbgMinSize(static_cast<SIZE_T>(Length), static_cast<SIZE_T>(pageBytes)));
            status = STATUS_SUCCESS;
            break;
        }

        ULONGLONG pteAddress = (Response->Pde & KNDBG_PTE_4K_BASE_MASK) + ptIndex * sizeof(ULONGLONG);
        Response->PteAddress = pteAddress;
        status = KnDbgReadPhysicalU64(pteAddress, &Response->Pte);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        if ((Response->Pte & KNDBG_PTE_PRESENT) == 0)
        {
            status = STATUS_ACCESS_VIOLATION;
            break;
        }

        ULONGLONG pageOffset = VirtualAddress & KNDBG_PAGE_OFFSET_MASK;
        ULONGLONG pageBytes = PAGE_SIZE - pageOffset;

        Response->PageSize = PAGE_SIZE;
        Response->PageOffset = pageOffset;
        Response->PageBytes = pageBytes;
        Response->PhysicalAddress = (Response->Pte & KNDBG_PTE_4K_BASE_MASK) + pageOffset;
        Response->TranslatedLength = static_cast<KNDBG_UINT32>(
            KnDbgMinSize(static_cast<SIZE_T>(Length), static_cast<SIZE_T>(pageBytes)));
        status = STATUS_SUCCESS;
    } while (false);

    return status;
}

static NTSTATUS KnDbgHandleGetVersion(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;

    do
    {
        if (Buffer == nullptr || Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(KNDBG_VERSION_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlZeroMemory(Buffer, Stack->Parameters.DeviceIoControl.OutputBufferLength);

        KNDBG_VERSION_RESPONSE* response = reinterpret_cast<KNDBG_VERSION_RESPONSE*>(Buffer);
        response->Size = sizeof(KNDBG_VERSION_RESPONSE);
        response->AbiVersion = KNDBG_ABI_VERSION;
        response->DriverMajor = 0;
        response->DriverMinor = 6;
        response->MaxTransferSize = KNDBG_MAX_TRANSFER_SIZE;
        response->Flags = KNDBG_VERSION_FLAG_SINGLE_CONTROLLER;
        if (KnDbgIsLa57Active())
        {
            response->Flags |= KNDBG_VERSION_FLAG_LA57_ACTIVE;
        }

        information = sizeof(KNDBG_VERSION_RESPONSE);
        status = STATUS_SUCCESS;
    } while (false);

    return KnDbgCompleteIrp(Irp, status, information);
}

static NTSTATUS KnDbgHandleSessionStatus(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;

    do
    {
        if (Buffer == nullptr || Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(KNDBG_SESSION_STATUS_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlZeroMemory(Buffer, Stack->Parameters.DeviceIoControl.OutputBufferLength);

        KNDBG_SESSION_STATUS_RESPONSE* response = reinterpret_cast<KNDBG_SESSION_STATUS_RESPONSE*>(Buffer);
        response->Size = sizeof(KNDBG_SESSION_STATUS_RESPONSE);
        response->CurrentPid = HandleToULong(PsGetCurrentProcessId());

        PKNDBG_FILE_CONTEXT fileContext = reinterpret_cast<PKNDBG_FILE_CONTEXT>(Stack->FileObject->FsContext);
        if (fileContext != nullptr && fileContext->WriteEnabled != FALSE)
        {
            response->Flags |= KNDBG_SESSION_FLAG_WRITE_ENABLED;
        }

        ExAcquireFastMutex(&g_KnDbgOwnerLock);
        response->OwnerPid = g_KnDbgOwnerPid;
        response->OpenHandleCount = g_KnDbgOwnerOpenCount;
        if (g_KnDbgOwnerPid != 0)
        {
            response->Flags |= KNDBG_SESSION_FLAG_OWNER_ACTIVE;
        }
        ExReleaseFastMutex(&g_KnDbgOwnerLock);

        information = sizeof(KNDBG_SESSION_STATUS_RESPONSE);
        status = STATUS_SUCCESS;
    } while (false);

    return KnDbgCompleteIrp(Irp, status, information);
}

static NTSTATUS KnDbgHandleTimelineControl(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;

    do
    {
        ULONG inputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
        if (!KnDbgCheckInputHeader(Buffer, inputLength, sizeof(KNDBG_TIMELINE_CONTROL_REQUEST)))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        PKNDBG_FILE_CONTEXT fileContext = reinterpret_cast<PKNDBG_FILE_CONTEXT>(Stack->FileObject->FsContext);
        if (fileContext == nullptr || fileContext->WriteEnabled == FALSE)
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        KNDBG_TIMELINE_CONTROL_REQUEST request = {};
        RtlCopyMemory(&request, Buffer, sizeof(request));
        if (request.Acknowledge != KNDBG_WRITE_ACK_MAGIC)
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        ExAcquireFastMutex(&g_KnDbgTimelineControlLock);
        if (request.Action == KNDBG_TIMELINE_CONTROL_START)
        {
            status = KnDbgTimelineEnsureRing(request.Capacity);
            if (NT_SUCCESS(status))
            {
                status = KnDbgTimelineRegisterCallbacks();
            }
        }
        else if (request.Action == KNDBG_TIMELINE_CONTROL_STOP)
        {
            KnDbgTimelineUnregisterCallbacks();
            status = STATUS_SUCCESS;
        }
        else if (request.Action == KNDBG_TIMELINE_CONTROL_CLEAR)
        {
            KIRQL oldIrql = PASSIVE_LEVEL;
            KeAcquireSpinLock(&g_KnDbgTimelineLock, &oldIrql);
            KnDbgTimelineClearLocked();
            KeReleaseSpinLock(&g_KnDbgTimelineLock, oldIrql);
            status = STATUS_SUCCESS;
        }
        else
        {
            status = STATUS_INVALID_PARAMETER;
        }
        ExReleaseFastMutex(&g_KnDbgTimelineControlLock);

        if (NT_SUCCESS(status))
        {
            information = sizeof(KNDBG_TIMELINE_CONTROL_REQUEST);
        }
    } while (false);

    return KnDbgCompleteIrp(Irp, status, information);
}

static NTSTATUS KnDbgHandleTimelineStatus(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;

    do
    {
        if (Buffer == nullptr || Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(KNDBG_TIMELINE_STATUS_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlZeroMemory(Buffer, Stack->Parameters.DeviceIoControl.OutputBufferLength);

        KNDBG_TIMELINE_STATUS_RESPONSE* response = reinterpret_cast<KNDBG_TIMELINE_STATUS_RESPONSE*>(Buffer);
        response->Size = sizeof(*response);

        KIRQL oldIrql = PASSIVE_LEVEL;
        KeAcquireSpinLock(&g_KnDbgTimelineLock, &oldIrql);
        response->Capacity = g_KnDbgTimelineCapacity;
        response->Count = g_KnDbgTimelineCount;
        response->Dropped = g_KnDbgTimelineDropped;
        response->NextSequence = g_KnDbgTimelineNextSequence;
        KeReleaseSpinLock(&g_KnDbgTimelineLock, oldIrql);

        if (InterlockedCompareExchange(&g_KnDbgTimelineEnabled, 0, 0) != 0)
        {
            response->Flags |= KNDBG_TIMELINE_STATUS_ACTIVE;
        }
        if (g_KnDbgTimelineProcessRegistered != FALSE)
        {
            response->Flags |= KNDBG_TIMELINE_STATUS_PROCESS_CALLBACK;
        }
        if (g_KnDbgTimelineImageRegistered != FALSE)
        {
            response->Flags |= KNDBG_TIMELINE_STATUS_IMAGE_CALLBACK;
        }
        if (g_KnDbgTimelineThreadRegistered != FALSE)
        {
            response->Flags |= KNDBG_TIMELINE_STATUS_THREAD_CALLBACK;
        }

        information = sizeof(*response);
        status = STATUS_SUCCESS;
    } while (false);

    return KnDbgCompleteIrp(Irp, status, information);
}

static NTSTATUS KnDbgHandleTimelineDrain(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;

    do
    {
        ULONG inputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
        ULONG headerLength = FIELD_OFFSET(KNDBG_TIMELINE_DRAIN_RESPONSE, Events);

        if (!KnDbgCheckInputHeader(Buffer, inputLength, sizeof(KNDBG_TIMELINE_DRAIN_REQUEST)))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (outputLength < headerLength)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PKNDBG_FILE_CONTEXT fileContext = reinterpret_cast<PKNDBG_FILE_CONTEXT>(Stack->FileObject->FsContext);
        if (fileContext == nullptr || fileContext->WriteEnabled == FALSE)
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        KNDBG_TIMELINE_DRAIN_REQUEST request = {};
        RtlCopyMemory(&request, Buffer, sizeof(request));

        ULONG maxByOutput = (outputLength - headerLength) / sizeof(KNDBG_TIMELINE_EVENT_RECORD);
        ULONG maxEvents = request.MaxEvents;
        if (maxEvents == 0 || maxEvents > maxByOutput)
        {
            maxEvents = maxByOutput;
        }
        if (maxEvents == 0)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlZeroMemory(Buffer, outputLength);
        KNDBG_TIMELINE_DRAIN_RESPONSE* response = reinterpret_cast<KNDBG_TIMELINE_DRAIN_RESPONSE*>(Buffer);
        KIRQL oldIrql = PASSIVE_LEVEL;
        KeAcquireSpinLock(&g_KnDbgTimelineLock, &oldIrql);
        ULONG toCopy = g_KnDbgTimelineCount < maxEvents ? g_KnDbgTimelineCount : maxEvents;
        if (g_KnDbgTimelineRing != nullptr && g_KnDbgTimelineCapacity != 0)
        {
            ULONG oldest = (g_KnDbgTimelineHead + g_KnDbgTimelineCapacity - g_KnDbgTimelineCount) % g_KnDbgTimelineCapacity;
            for (ULONG index = 0; index < toCopy; ++index)
            {
                ULONG ringIndex = oldest + index;
                if (ringIndex >= g_KnDbgTimelineCapacity)
                {
                    ringIndex -= g_KnDbgTimelineCapacity;
                }
                RtlCopyMemory(&response->Events[index], &g_KnDbgTimelineRing[ringIndex], sizeof(KNDBG_TIMELINE_EVENT_RECORD));
            }
            g_KnDbgTimelineCount -= toCopy;
        }
        response->Count = toCopy;
        response->Remaining = g_KnDbgTimelineCount;
        response->Dropped = g_KnDbgTimelineDropped;
        response->NextSequence = g_KnDbgTimelineNextSequence;
        KeReleaseSpinLock(&g_KnDbgTimelineLock, oldIrql);

        information = headerLength + static_cast<ULONG_PTR>(toCopy) * sizeof(KNDBG_TIMELINE_EVENT_RECORD);
        response->Size = static_cast<KNDBG_UINT32>(information);
        status = STATUS_SUCCESS;
    } while (false);

    return KnDbgCompleteIrp(Irp, status, information);
}

// SEH probe: the caller-supplied address must really point at a
// DRIVER_OBJECT before any field is dereferenced. Kept free of C++
// objects so __try is legal here.
// Declared in some WDK wdm.h variants only; always exported by ntoskrnl
// as a C symbol.
extern "C" extern POBJECT_TYPE IoDriverObjectType;

static BOOLEAN KnDbgIotraceValidateDriverObject(PVOID Address)
{
    BOOLEAN ok = FALSE;

    __try
    {
        PDRIVER_OBJECT target = reinterpret_cast<PDRIVER_OBJECT>(Address);
        // DRIVER_OBJECT.Type == IO_TYPE_DRIVER (4); Size is the structure
        // size in bytes on every supported build.
        if (target->Type == 4 && target->Size >= sizeof(DRIVER_OBJECT))
        {
            ok = TRUE;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        ok = FALSE;
    }

    return ok;
}

static VOID KnDbgIotracePush(PIRP Irp, PIO_STACK_LOCATION Stack)
{
    KIRQL oldIrql = PASSIVE_LEVEL;
    KNDBG_IOTRACE_RECORD record = {};

    record.Timestamp100ns = KeQueryInterruptTime();
    record.IoctlCode =
        Stack->Parameters.DeviceIoControl.IoControlCode;
    record.InputLength =
        Stack->Parameters.DeviceIoControl.InputBufferLength;
    record.OutputLength =
        Stack->Parameters.DeviceIoControl.OutputBufferLength;
    record.ProcessId = IoGetRequestorProcessId(Irp);

    KeAcquireSpinLock(&g_KnDbgIotraceLock, &oldIrql);
    if (g_KnDbgIotraceRing != nullptr)
    {
        KNDBG_IOTRACE_RECORD* slot =
            &g_KnDbgIotraceRing[g_KnDbgIotraceHead];
        record.Sequence = g_KnDbgIotraceNextSequence;
        ++g_KnDbgIotraceNextSequence;
        RtlCopyMemory(slot, &record, sizeof(*slot));

        ++g_KnDbgIotraceHead;
        if (g_KnDbgIotraceHead >= KNDBG_IOTRACE_RING_CAPACITY)
        {
            g_KnDbgIotraceHead = 0;
        }
        if (g_KnDbgIotraceCount < KNDBG_IOTRACE_RING_CAPACITY)
        {
            ++g_KnDbgIotraceCount;
        }
        else
        {
            ++g_KnDbgIotraceDropped;
        }
        ++g_KnDbgIotraceTotalRecorded;
    }
    KeReleaseSpinLock(&g_KnDbgIotraceLock, oldIrql);
}

static NTSTATUS KnDbgIotraceDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    // Capture the original before leaving the active window: disarm only
    // nulls it after every in-flight trampoline has returned, so the call
    // target stays valid even if disarm races this entry.
    InterlockedIncrement(&g_KnDbgIotraceActive);
    PDRIVER_DISPATCH original = reinterpret_cast<PDRIVER_DISPATCH>(
        InterlockedCompareExchangePointer(
            reinterpret_cast<PVOID volatile*>(
                &g_KnDbgIotraceOriginalDispatch),
            nullptr,
            nullptr));

    NTSTATUS status = STATUS_DEVICE_NOT_READY;
    if (original != nullptr)
    {
        PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
        KnDbgIotracePush(Irp, stack);
        status = original(DeviceObject, Irp);
    }
    else
    {
        // Unreachable while armed: arm installs the original before the
        // dispatch pointer, disarm removes the dispatch pointer first.
        status = KnDbgCompleteIrp(Irp, STATUS_DEVICE_NOT_READY, 0);
    }

    InterlockedDecrement(&g_KnDbgIotraceActive);
    return status;
}

// Restores the target's dispatch entry and drops the reference only after
// every in-flight trampoline has returned. Runs at PASSIVE under the
// control mutex.
static NTSTATUS KnDbgIotraceDisarmLocked(BOOLEAN Wait)
{
    NTSTATUS status = STATUS_SUCCESS;

    do
    {
        PDRIVER_OBJECT target = g_KnDbgIotraceTarget;
        if (target == nullptr)
        {
            break;
        }

        PDRIVER_DISPATCH original = g_KnDbgIotraceOriginalDispatch;
        if (original != nullptr)
        {
            InterlockedExchangePointer(
                reinterpret_cast<PVOID volatile*>(
                    &target->MajorFunction[IRP_MJ_DEVICE_CONTROL]),
                original);
        }
        InterlockedExchange(&g_KnDbgIotraceArmed, 0);

        if (Wait)
        {
            for (ULONG attempt = 0; attempt < 4000; ++attempt)
            {
                if (InterlockedCompareExchange(&g_KnDbgIotraceActive, 0, 0) == 0)
                {
                    break;
                }
                LARGE_INTEGER interval = {};
                interval.QuadPart = -1000; // 100us
                KeDelayExecutionThread(KernelMode, FALSE, &interval);
            }
        }

        if (InterlockedCompareExchange(&g_KnDbgIotraceActive, 0, 0) != 0)
        {
            // A trampoline is still inside the original dispatch (a
            // pended IRP). The restored entry keeps future calls safe;
            // keep the reference and report the race instead of freeing.
            status = STATUS_DEVICE_BUSY;
            break;
        }

        g_KnDbgIotraceOriginalDispatch = nullptr;
        g_KnDbgIotraceTarget = nullptr;
        ObDereferenceObject(target);
    } while (false);

    return status;
}

static NTSTATUS KnDbgHandleIotraceControl(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;

    do
    {
        ULONG inputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (!KnDbgCheckInputHeader(Buffer, inputLength, sizeof(KNDBG_IOTRACE_CONTROL_REQUEST)) ||
            outputLength < sizeof(KNDBG_IOTRACE_CONTROL_RESPONSE))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        PKNDBG_FILE_CONTEXT fileContext = reinterpret_cast<PKNDBG_FILE_CONTEXT>(Stack->FileObject->FsContext);
        if (fileContext == nullptr || fileContext->WriteEnabled == FALSE)
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        KNDBG_IOTRACE_CONTROL_REQUEST request = {};
        RtlCopyMemory(&request, Buffer, sizeof(request));
        if (request.Acknowledge != KNDBG_WRITE_ACK_MAGIC)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        ExAcquireFastMutex(&g_KnDbgIotraceControlLock);

        do
        {
            if (request.Mode == KNDBG_IOTRACE_MODE_DISARM)
            {
                status = KnDbgIotraceDisarmLocked(TRUE);
                break;
            }

            if (request.Mode == KNDBG_IOTRACE_MODE_STATUS)
            {
                status = STATUS_SUCCESS;
                break;
            }

            if (request.Mode != KNDBG_IOTRACE_MODE_ARM)
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            if (g_KnDbgIotraceTarget != nullptr)
            {
                status = STATUS_DEVICE_BUSY;
                break;
            }

            // Lazy ring allocation keeps a failed DriverEntry free of
            // cleanup obligations for this feature.
            if (g_KnDbgIotraceRing == nullptr)
            {
                g_KnDbgIotraceRing = reinterpret_cast<KNDBG_IOTRACE_RECORD*>(
                    ExAllocatePool2(
                        POOL_FLAG_NON_PAGED,
                        sizeof(KNDBG_IOTRACE_RECORD) * KNDBG_IOTRACE_RING_CAPACITY,
                        'oInK'));
                if (g_KnDbgIotraceRing == nullptr)
                {
                    status = STATUS_INSUFFICIENT_RESOURCES;
                    break;
                }
            }

            if (!MmIsAddressValid(reinterpret_cast<PVOID>(request.DriverObjectAddress)) ||
                request.DriverObjectAddress < (ULONGLONG)MmHighestUserAddress ||
                !KnDbgIotraceValidateDriverObject(
                    reinterpret_cast<PVOID>(request.DriverObjectAddress)))
            {
                status = STATUS_INVALID_ADDRESS;
                break;
            }

            PDRIVER_OBJECT target =
                reinterpret_cast<PDRIVER_OBJECT>(request.DriverObjectAddress);
            NTSTATUS refStatus = ObReferenceObjectByPointer(
                target,
                0,
                IoDriverObjectType,
                KernelMode);
            if (!NT_SUCCESS(refStatus))
            {
                status = refStatus;
                break;
            }

            PDRIVER_DISPATCH current = target->MajorFunction[IRP_MJ_DEVICE_CONTROL];
            if (current == nullptr || current == KnDbgIotraceDispatch)
            {
                ObDereferenceObject(target);
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            g_KnDbgIotraceTarget = target;
            g_KnDbgIotraceOriginalDispatch = current;
            InterlockedExchangePointer(
                reinterpret_cast<PVOID volatile*>(
                    &target->MajorFunction[IRP_MJ_DEVICE_CONTROL]),
                KnDbgIotraceDispatch);
            InterlockedExchange(&g_KnDbgIotraceArmed, 1);
            status = STATUS_SUCCESS;
        } while (false);

        KNDBG_IOTRACE_CONTROL_RESPONSE response = {};
        response.Size = sizeof(response);
        response.Flags = 0;
        response.Armed = g_KnDbgIotraceTarget != nullptr ? 1u : 0u;
        response.NtStatus = static_cast<KNDBG_UINT32>(status);
        response.DriverObjectAddress =
            reinterpret_cast<KNDBG_UINT64>(g_KnDbgIotraceTarget);
        response.OriginalDispatch =
            reinterpret_cast<KNDBG_UINT64>(g_KnDbgIotraceOriginalDispatch);
        {
            KIRQL oldIrql = PASSIVE_LEVEL;
            KeAcquireSpinLock(&g_KnDbgIotraceLock, &oldIrql);
            response.EventsRecorded = g_KnDbgIotraceTotalRecorded;
            response.EventsDropped = g_KnDbgIotraceDropped;
            KeReleaseSpinLock(&g_KnDbgIotraceLock, oldIrql);
        }

        ExReleaseFastMutex(&g_KnDbgIotraceControlLock);

        RtlCopyMemory(Buffer, &response, sizeof(response));
        information = sizeof(response);
    } while (false);

    return KnDbgCompleteIrp(Irp, status, information);
}

static NTSTATUS KnDbgHandleIotraceDrain(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;

    do
    {
        ULONG inputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
        ULONG headerLength = FIELD_OFFSET(KNDBG_IOTRACE_DRAIN_RESPONSE, Records);

        if (!KnDbgCheckInputHeader(Buffer, inputLength, sizeof(KNDBG_IOTRACE_DRAIN_REQUEST)) ||
            outputLength < headerLength)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        PKNDBG_FILE_CONTEXT fileContext = reinterpret_cast<PKNDBG_FILE_CONTEXT>(Stack->FileObject->FsContext);
        if (fileContext == nullptr || fileContext->WriteEnabled == FALSE)
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        KNDBG_IOTRACE_DRAIN_REQUEST request = {};
        RtlCopyMemory(&request, Buffer, sizeof(request));

        ULONG maxByOutput = (outputLength - headerLength) / sizeof(KNDBG_IOTRACE_RECORD);
        ULONG maxRecords = request.MaxRecords;
        if (maxRecords == 0 || maxRecords > KNDBG_IOTRACE_DRAIN_MAX)
        {
            maxRecords = KNDBG_IOTRACE_DRAIN_MAX;
        }
        if (maxRecords > maxByOutput)
        {
            maxRecords = maxByOutput;
        }
        if (maxRecords == 0)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlZeroMemory(Buffer, outputLength);
        KNDBG_IOTRACE_DRAIN_RESPONSE* response =
            reinterpret_cast<KNDBG_IOTRACE_DRAIN_RESPONSE*>(Buffer);
        KIRQL oldIrql = PASSIVE_LEVEL;
        KeAcquireSpinLock(&g_KnDbgIotraceLock, &oldIrql);
        ULONG toCopy = g_KnDbgIotraceCount < maxRecords
            ? g_KnDbgIotraceCount
            : maxRecords;
        if (g_KnDbgIotraceRing != nullptr)
        {
            ULONG oldest = (g_KnDbgIotraceHead + KNDBG_IOTRACE_RING_CAPACITY -
                g_KnDbgIotraceCount) % KNDBG_IOTRACE_RING_CAPACITY;
            for (ULONG index = 0; index < toCopy; ++index)
            {
                ULONG ringIndex = oldest + index;
                if (ringIndex >= KNDBG_IOTRACE_RING_CAPACITY)
                {
                    ringIndex -= KNDBG_IOTRACE_RING_CAPACITY;
                }
                RtlCopyMemory(
                    &response->Records[index],
                    &g_KnDbgIotraceRing[ringIndex],
                    sizeof(KNDBG_IOTRACE_RECORD));
            }
            g_KnDbgIotraceCount -= toCopy;
        }
        response->RecordCount = toCopy;
        response->TotalRecorded = g_KnDbgIotraceTotalRecorded;
        response->TotalDropped = g_KnDbgIotraceDropped;
        KeReleaseSpinLock(&g_KnDbgIotraceLock, oldIrql);

        information = headerLength + static_cast<ULONG_PTR>(toCopy) * sizeof(KNDBG_IOTRACE_RECORD);
        response->Size = static_cast<KNDBG_UINT32>(information);
        status = STATUS_SUCCESS;
    } while (false);

    return KnDbgCompleteIrp(Irp, status, information);
}

static NTSTATUS KnDbgHandleResolveProcess(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;
    PEPROCESS process = nullptr;

    do
    {
        ULONG inputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (!KnDbgCheckInputHeader(Buffer, inputLength, sizeof(KNDBG_PROCESS_RESOLVE_REQUEST)))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (outputLength < sizeof(KNDBG_PROCESS_RESOLVE_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        KNDBG_PROCESS_RESOLVE_REQUEST request = {};
        RtlCopyMemory(&request, Buffer, sizeof(request));
        if (request.ProcessId == 0 || request.DirectoryTableBaseOffset == 0 || request.DirectoryTableBaseOffset > 0x4000)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (request.UserDirectoryTableBaseOffset > 0x4000)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        status = PsLookupProcessByProcessId(ULongToHandle(request.ProcessId), &process);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        ULONGLONG directoryTableBase = 0;
        ULONGLONG userDirectoryTableBase = 0;
        __try
        {
            PUCHAR base = reinterpret_cast<PUCHAR>(process);
            RtlCopyMemory(&directoryTableBase, base + request.DirectoryTableBaseOffset, sizeof(directoryTableBase));
            if (request.UserDirectoryTableBaseOffset != 0)
            {
                RtlCopyMemory(&userDirectoryTableBase, base + request.UserDirectoryTableBaseOffset, sizeof(userDirectoryTableBase));
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
            break;
        }

        if (directoryTableBase == 0)
        {
            status = STATUS_INVALID_ADDRESS;
            break;
        }

        RtlZeroMemory(Buffer, outputLength);
        KNDBG_PROCESS_RESOLVE_RESPONSE* response = reinterpret_cast<KNDBG_PROCESS_RESOLVE_RESPONSE*>(Buffer);
        response->Size = sizeof(KNDBG_PROCESS_RESOLVE_RESPONSE);
        response->ProcessId = request.ProcessId;
        response->Eprocess = reinterpret_cast<KNDBG_UINT64>(process);
        response->DirectoryTableBase = directoryTableBase & KNDBG_PTE_4K_BASE_MASK;
        response->UserDirectoryTableBase = userDirectoryTableBase & KNDBG_PTE_4K_BASE_MASK;
        if (response->UserDirectoryTableBase != 0)
        {
            response->Flags |= KNDBG_PROCESS_FLAG_USER_DTB_AVAILABLE;
        }

        information = sizeof(KNDBG_PROCESS_RESOLVE_RESPONSE);
        status = STATUS_SUCCESS;
    } while (false);

    if (process != nullptr)
    {
        ObDereferenceObject(process);
    }

    return KnDbgCompleteIrp(Irp, status, information);
}

static NTSTATUS KnDbgHandleReadVirtual(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;

    do
    {
        ULONG inputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (!KnDbgCheckInputHeader(Buffer, inputLength, FIELD_OFFSET(KNDBG_READ_REQUEST, Data)))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        KNDBG_READ_REQUEST request = {};
        RtlCopyMemory(&request, Buffer, FIELD_OFFSET(KNDBG_READ_REQUEST, Data));

        if (request.Length == 0 || request.Length > KNDBG_MAX_TRANSFER_SIZE)
        {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        if ((request.Flags & ~KNDBG_READ_FLAG_ALLOW_MDL_FALLBACK) != 0)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        ULONG requiredLength = FIELD_OFFSET(KNDBG_READ_REQUEST, Data) + request.Length;
        if (outputLength < requiredLength)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlZeroMemory(Buffer, outputLength);

        KNDBG_READ_REQUEST* response = reinterpret_cast<KNDBG_READ_REQUEST*>(Buffer);
        response->Size = requiredLength;
        response->Address = request.Address;
        response->Length = request.Length;
        response->Flags = request.Flags;

        SIZE_T bytesCopied = 0;
        status = KnDbgReadVirtualAddress(request.Address, response->Data, request.Length, request.Flags, &bytesCopied);
        response->Length = static_cast<KNDBG_UINT32>(bytesCopied);
        information = FIELD_OFFSET(KNDBG_READ_REQUEST, Data) + bytesCopied;
        if (!NT_SUCCESS(status) && bytesCopied != 0)
        {
            status = STATUS_SUCCESS;
        }
    } while (false);

    return KnDbgCompleteIrp(Irp, status, information);
}

static NTSTATUS KnDbgHandleReadProcessVirtual(
    PIRP Irp,
    PIO_STACK_LOCATION Stack,
    PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;
    PEPROCESS process = nullptr;

    do
    {
        const ULONG inputLength =
            Stack->Parameters.DeviceIoControl.InputBufferLength;
        const ULONG outputLength =
            Stack->Parameters.DeviceIoControl.OutputBufferLength;
        const ULONG headerLength =
            FIELD_OFFSET(KNDBG_PROCESS_VIRTUAL_READ_REQUEST, Data);

        if (!KnDbgCheckInputHeader(
                Buffer,
                inputLength,
                headerLength))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        KNDBG_PROCESS_VIRTUAL_READ_REQUEST request = {};
        RtlCopyMemory(&request, Buffer, headerLength);
        if (request.Flags != 0 ||
            request.Reserved != 0 ||
            request.Reserved2 != 0 ||
            request.ProcessId == 0 ||
            request.ExpectedEprocess == 0 ||
            request.ExpectedCreateTime == 0)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        if (request.Length == 0 ||
            request.Length > KNDBG_MAX_TRANSFER_SIZE)
        {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }
        if (request.Address == 0 ||
            KnDbgRangeOverflows(request.Address, request.Length))
        {
            status = STATUS_INVALID_ADDRESS;
            break;
        }

        const ULONGLONG highestUserAddress =
            static_cast<ULONGLONG>(
                reinterpret_cast<ULONG_PTR>(
                    MmHighestUserAddress));
        if (request.Address > highestUserAddress ||
            static_cast<ULONGLONG>(request.Length - 1) >
                highestUserAddress - request.Address)
        {
            status = STATUS_INVALID_ADDRESS;
            break;
        }
        if (KeGetCurrentIrql() > APC_LEVEL)
        {
            // MmCopyMemory is documented only through APC_LEVEL, and this
            // request also attaches to the target process address space.
            status = STATUS_INVALID_DEVICE_STATE;
            break;
        }

        const ULONG requiredLength =
            headerLength + request.Length;
        if (requiredLength < headerLength ||
            outputLength < requiredLength)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        status = PsLookupProcessByProcessId(
            ULongToHandle(request.ProcessId),
            &process);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        if ((request.ExpectedEprocess != 0 &&
             request.ExpectedEprocess !=
                reinterpret_cast<KNDBG_UINT64>(process)) ||
            (request.ExpectedCreateTime != 0 &&
             request.ExpectedCreateTime !=
                static_cast<KNDBG_UINT64>(
                    PsGetProcessCreateTimeQuadPart(process))))
        {
            status = STATUS_NOT_FOUND;
            break;
        }
        if (PsGetProcessExitStatus(process) !=
            STATUS_PENDING)
        {
            status = STATUS_PROCESS_IS_TERMINATING;
            break;
        }

        RtlZeroMemory(Buffer, outputLength);
        KNDBG_PROCESS_VIRTUAL_READ_REQUEST* response =
            reinterpret_cast<
                KNDBG_PROCESS_VIRTUAL_READ_REQUEST*>(Buffer);
        response->Size = requiredLength;
        response->ProcessId = request.ProcessId;
        response->ExpectedEprocess = request.ExpectedEprocess;
        response->ExpectedCreateTime =
            request.ExpectedCreateTime;
        response->Address = request.Address;
        response->Length = request.Length;

        KAPC_STATE apcState = {};
        BOOLEAN attached = FALSE;
        SIZE_T bytesCopied = 0;
        __try
        {
            KeStackAttachProcess(
                reinterpret_cast<PRKPROCESS>(process),
                &apcState);
            attached = TRUE;
            status = KnDbgReadVirtualAddress(
                request.Address,
                response->Data,
                request.Length,
                0,
                &bytesCopied);
        }
        __finally
        {
            if (attached != FALSE)
            {
                KeUnstackDetachProcess(&apcState);
            }
        }

        response->Length =
            static_cast<KNDBG_UINT32>(bytesCopied);
        if (NT_SUCCESS(status) &&
            bytesCopied == request.Length)
        {
            information = headerLength + bytesCopied;
        }
        else if (NT_SUCCESS(status))
        {
            status = STATUS_PARTIAL_COPY;
        }
    } while (false);

    if (process != nullptr)
    {
        ObDereferenceObject(process);
    }

    return KnDbgCompleteIrp(Irp, status, information);
}

static NTSTATUS KnDbgHandleWriteVirtual(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;

    do
    {
        ULONG inputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;

        if (!KnDbgCheckInputHeader(Buffer, inputLength, FIELD_OFFSET(KNDBG_WRITE_REQUEST, Data)))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        PKNDBG_FILE_CONTEXT fileContext = reinterpret_cast<PKNDBG_FILE_CONTEXT>(Stack->FileObject->FsContext);
        if (fileContext == nullptr || fileContext->WriteEnabled == FALSE)
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        KNDBG_WRITE_REQUEST* request = reinterpret_cast<KNDBG_WRITE_REQUEST*>(Buffer);
        if (request->Acknowledge != KNDBG_WRITE_ACK_MAGIC)
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        if (request->Length == 0 || request->Length > KNDBG_MAX_TRANSFER_SIZE)
        {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        ULONG requiredLength = FIELD_OFFSET(KNDBG_WRITE_REQUEST, Data) + request->Length;
        if (inputLength < requiredLength)
        {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        SIZE_T bytesCopied = 0;
        status = KnDbgWriteVirtualAddress(request->Address, request->Data, request->Length, &bytesCopied);
        request->Length = static_cast<KNDBG_UINT32>(bytesCopied);
        if (NT_SUCCESS(status))
        {
            information = FIELD_OFFSET(KNDBG_WRITE_REQUEST, Data);
        }
    } while (false);

    return KnDbgCompleteIrp(Irp, status, information);
}

static NTSTATUS KnDbgHandleWriteMode(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;

    do
    {
        ULONG inputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
        if (!KnDbgCheckInputHeader(Buffer, inputLength, sizeof(KNDBG_WRITE_MODE_REQUEST)))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        PKNDBG_FILE_CONTEXT fileContext = reinterpret_cast<PKNDBG_FILE_CONTEXT>(Stack->FileObject->FsContext);
        if (fileContext == nullptr)
        {
            status = STATUS_INVALID_DEVICE_STATE;
            break;
        }

        KNDBG_WRITE_MODE_REQUEST* request = reinterpret_cast<KNDBG_WRITE_MODE_REQUEST*>(Buffer);
        if (request->Acknowledge != KNDBG_WRITE_ACK_MAGIC)
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        fileContext->WriteEnabled = request->EnableWrite != 0 ? TRUE : FALSE;
        information = sizeof(KNDBG_WRITE_MODE_REQUEST);
        status = STATUS_SUCCESS;
    } while (false);

    return KnDbgCompleteIrp(Irp, status, information);
}

static NTSTATUS KnDbgHandleQueryAddress(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;

    do
    {
        ULONG inputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (!KnDbgCheckInputHeader(Buffer, inputLength, sizeof(KNDBG_ADDRESS_QUERY_REQUEST)))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (outputLength < sizeof(KNDBG_ADDRESS_QUERY_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        KNDBG_ADDRESS_QUERY_REQUEST request = {};
        RtlCopyMemory(&request, Buffer, sizeof(request));
        RtlZeroMemory(Buffer, outputLength);

        KNDBG_ADDRESS_QUERY_RESPONSE* response = reinterpret_cast<KNDBG_ADDRESS_QUERY_RESPONSE*>(Buffer);
        response->Size = sizeof(KNDBG_ADDRESS_QUERY_RESPONSE);
        response->Address = request.Address;
        response->RequestedLength = request.Length;
        response->ProbedLength = 0;
        response->IsReadable = 0;
        response->IsWritable = 0;
        response->Reserved = 0;

        // IsWritable / Reserved WRITE_GATE = session write mode only.
        // This is not a PTE.W / page-attribute probe (see user-mode query path).
        PKNDBG_FILE_CONTEXT fileContext = reinterpret_cast<PKNDBG_FILE_CONTEXT>(Stack->FileObject->FsContext);
        if (fileContext != nullptr && fileContext->WriteEnabled != FALSE)
        {
            response->IsWritable = 1;
            response->Reserved |= KNDBG_ADDRESS_QUERY_RESERVED_WRITE_GATE;
        }

        // First-byte probe in the *current* address space (typically System).
        // Process-aware VA probes are performed in user-mode via translate+physical.
        UCHAR scratch = 0;
        SIZE_T copied = 0;
        status = KnDbgReadVirtualAddress(request.Address, &scratch, sizeof(scratch), 0, &copied);
        if (NT_SUCCESS(status) && copied == sizeof(scratch))
        {
            response->IsReadable = 1;
            response->ProbedLength = sizeof(scratch);
        }

        status = STATUS_SUCCESS;
        information = sizeof(KNDBG_ADDRESS_QUERY_RESPONSE);
    } while (false);

    return KnDbgCompleteIrp(Irp, status, information);
}

static NTSTATUS KnDbgHandleTranslateVirtual(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;

    do
    {
        ULONG inputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (!KnDbgCheckInputHeader(Buffer, inputLength, sizeof(KNDBG_TRANSLATE_VIRTUAL_REQUEST)))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (outputLength < sizeof(KNDBG_TRANSLATE_VIRTUAL_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        KNDBG_TRANSLATE_VIRTUAL_REQUEST request = {};
        RtlCopyMemory(&request, Buffer, sizeof(request));

        RtlZeroMemory(Buffer, outputLength);

        KNDBG_TRANSLATE_VIRTUAL_RESPONSE* response =
            reinterpret_cast<KNDBG_TRANSLATE_VIRTUAL_RESPONSE*>(Buffer);

        status = KnDbgTranslateVirtualAddress(
            request.DirectoryTableBase,
            request.VirtualAddress,
            request.Length,
            response);

        if (!NT_SUCCESS(status))
        {
            break;
        }

        response->Flags |= request.Flags;
        information = sizeof(KNDBG_TRANSLATE_VIRTUAL_RESPONSE);
    } while (false);

    return KnDbgCompleteIrp(Irp, status, information);
}

static NTSTATUS KnDbgHandleReadPhysical(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;

    do
    {
        ULONG inputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (!KnDbgCheckInputHeader(Buffer, inputLength, FIELD_OFFSET(KNDBG_PHYSICAL_READ_REQUEST, Data)))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        KNDBG_PHYSICAL_READ_REQUEST request = {};
        RtlCopyMemory(&request, Buffer, FIELD_OFFSET(KNDBG_PHYSICAL_READ_REQUEST, Data));

        if (request.Length == 0 || request.Length > KNDBG_MAX_TRANSFER_SIZE)
        {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        ULONG requiredLength = FIELD_OFFSET(KNDBG_PHYSICAL_READ_REQUEST, Data) + request.Length;
        if (outputLength < requiredLength)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlZeroMemory(Buffer, outputLength);

        KNDBG_PHYSICAL_READ_REQUEST* response = reinterpret_cast<KNDBG_PHYSICAL_READ_REQUEST*>(Buffer);
        response->Size = requiredLength;
        response->Flags = request.Flags;
        response->PhysicalAddress = request.PhysicalAddress;
        response->Length = request.Length;

        SIZE_T bytesCopied = 0;
        status = KnDbgReadPhysicalAddress(request.PhysicalAddress, response->Data, request.Length, &bytesCopied);
        response->Length = static_cast<KNDBG_UINT32>(bytesCopied);
        information = FIELD_OFFSET(KNDBG_PHYSICAL_READ_REQUEST, Data) + bytesCopied;
        if (!NT_SUCCESS(status) && bytesCopied != 0)
        {
            status = STATUS_SUCCESS;
        }
    } while (false);

    return KnDbgCompleteIrp(Irp, status, information);
}

static NTSTATUS KnDbgHandleWritePhysical(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;

    do
    {
        ULONG inputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;

        if (!KnDbgCheckInputHeader(Buffer, inputLength, FIELD_OFFSET(KNDBG_PHYSICAL_WRITE_REQUEST, Data)))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        PKNDBG_FILE_CONTEXT fileContext = reinterpret_cast<PKNDBG_FILE_CONTEXT>(Stack->FileObject->FsContext);
        if (fileContext == nullptr || fileContext->WriteEnabled == FALSE)
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        KNDBG_PHYSICAL_WRITE_REQUEST* request = reinterpret_cast<KNDBG_PHYSICAL_WRITE_REQUEST*>(Buffer);
        if (request->Acknowledge != KNDBG_WRITE_ACK_MAGIC)
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        if (request->Length == 0 || request->Length > KNDBG_MAX_TRANSFER_SIZE)
        {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        ULONG requiredLength = FIELD_OFFSET(KNDBG_PHYSICAL_WRITE_REQUEST, Data) + request->Length;
        if (inputLength < requiredLength)
        {
            status = STATUS_INVALID_BUFFER_SIZE;
            break;
        }

        SIZE_T bytesCopied = 0;
        status = KnDbgWritePhysicalAddress(request->PhysicalAddress, request->Data, request->Length, &bytesCopied);
        request->Length = static_cast<KNDBG_UINT32>(bytesCopied);
        if (NT_SUCCESS(status))
        {
            information = FIELD_OFFSET(KNDBG_PHYSICAL_WRITE_REQUEST, Data);
        }
    } while (false);

    return KnDbgCompleteIrp(Irp, status, information);
}

static NTSTATUS KnDbgHandleFlushVirtual(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;

    do
    {
        ULONG inputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;

        if (!KnDbgCheckInputHeader(Buffer, inputLength, sizeof(KNDBG_FLUSH_VIRTUAL_REQUEST)))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        PKNDBG_FILE_CONTEXT fileContext = reinterpret_cast<PKNDBG_FILE_CONTEXT>(Stack->FileObject->FsContext);
        if (fileContext == nullptr || fileContext->WriteEnabled == FALSE)
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        KNDBG_FLUSH_VIRTUAL_REQUEST* request = reinterpret_cast<KNDBG_FLUSH_VIRTUAL_REQUEST*>(Buffer);
        if (request->Acknowledge != KNDBG_WRITE_ACK_MAGIC)
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        ULONGLONG cr3Value = 0;
        BOOLEAN invalidateAllContexts = FALSE;
        PEPROCESS process = nullptr;
        // Oversized opaque APC state: never depend on a re-declared layout.
        DECLSPEC_ALIGN(16) UCHAR apcStateStorage[128] = {};
        PKAPC_STATE apcState = reinterpret_cast<PKAPC_STATE>(apcStateStorage);
        BOOLEAN attached = FALSE;

        if ((request->Flags & KNDBG_FLUSH_FLAG_PROCESS_DTB) != 0)
        {
            if (!KnDbgIsPlausibleDirectoryTableBase(request->DirectoryTableBase) &&
                request->ProcessId == 0)
            {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            // Preferred path: attach to the target process so CR3 includes the
            // live PCID Windows assigned. That keeps invlpg PCID-correct without
            // refusing the shared-frame physical write workflow.
            if (request->ProcessId != 0)
            {
                status = PsLookupProcessByProcessId(ULongToHandle(request->ProcessId), &process);
                if (!NT_SUCCESS(status))
                {
                    break;
                }

                KeStackAttachProcess(reinterpret_cast<PRKPROCESS>(process), apcState);
                attached = TRUE;
                cr3Value = __readcr3();

                if (request->DirectoryTableBase != 0)
                {
                    const ULONGLONG liveFrame = KnDbgNormalizeDirectoryTableBase(cr3Value);
                    const ULONGLONG requestedFrame =
                        KnDbgNormalizeDirectoryTableBase(request->DirectoryTableBase);
                    if (requestedFrame != 0 && liveFrame != 0 && requestedFrame != liveFrame)
                    {
                        // Supplied DTB is a different page-table root than the
                        // attached CR3 (e.g. user vs kernel DTB). Flush that
                        // root at PCID 0 and broaden invalidation under PCIDE.
                        cr3Value = requestedFrame;
                        invalidateAllContexts = KnDbgIsPcideEnabled() ? TRUE : FALSE;
                    }
                }
            }
            else
            {
                if (!KnDbgIsPlausibleDirectoryTableBase(request->DirectoryTableBase))
                {
                    status = STATUS_INVALID_PARAMETER;
                    break;
                }

                cr3Value = KnDbgNormalizeDirectoryTableBase(request->DirectoryTableBase);
                invalidateAllContexts = KnDbgIsPcideEnabled() ? TRUE : FALSE;
            }
        }

        status = KnDbgFlushVirtualRange(
            request->VirtualAddress,
            request->Length,
            cr3Value,
            invalidateAllContexts);

        // INVPCID may be unavailable on PCIDE systems. Fall back to a full TB
        // flush at PASSIVE/APC after the IPI returns (never from IPI_LEVEL).
        if (NT_SUCCESS(status) &&
            invalidateAllContexts != FALSE &&
            KnDbgIsPcideEnabled() &&
            !KnDbgCpuSupportsInvpcid())
        {
            KeFlushEntireTb(TRUE, TRUE);
        }

        if (attached != FALSE)
        {
            KeUnstackDetachProcess(apcState);
        }

        if (process != nullptr)
        {
            ObDereferenceObject(process);
        }

        if (NT_SUCCESS(status))
        {
            information = sizeof(KNDBG_FLUSH_VIRTUAL_REQUEST);
        }
    } while (false);

    return KnDbgCompleteIrp(Irp, status, information);
}

// Patches the byte at <Eprocess + ProtectionFieldOffset>. The offset is
// supplied by user mode after resolving _EPROCESS.Protection via PDB symbols,
// so the driver does not have to track per-build layout drift. The caller
// must hold the device session and pass the standard write acknowledge magic
// just like the virtual/physical write paths.
static NTSTATUS KnDbgHandleSetProcessProtection(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;
    PEPROCESS process = nullptr;
    BOOLEAN dereference = FALSE;

    do
    {
        ULONG inputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (!KnDbgCheckInputHeader(Buffer, inputLength, sizeof(KNDBG_SET_PROCESS_PROTECTION_REQUEST)))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (outputLength < sizeof(KNDBG_SET_PROCESS_PROTECTION_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PKNDBG_FILE_CONTEXT fileContext = reinterpret_cast<PKNDBG_FILE_CONTEXT>(Stack->FileObject->FsContext);
        if (fileContext == nullptr || fileContext->WriteEnabled == FALSE)
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        KNDBG_SET_PROCESS_PROTECTION_REQUEST request = {};
        RtlCopyMemory(&request, Buffer, sizeof(request));

        if (request.Acknowledge != KNDBG_WRITE_ACK_MAGIC)
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        if (request.ProcessId == 0)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        // Plausibility bound on the field offset. _EPROCESS is well under
        // 0x2000 bytes on every supported Windows build, so anything outside
        // that range is a caller bug and must not turn into a wild write.
        if (request.ProtectionFieldOffset == 0 || request.ProtectionFieldOffset > 0x2000)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        status = PsLookupProcessByProcessId(ULongToHandle(request.ProcessId), &process);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        dereference = TRUE;

        UCHAR oldByte = 0;
        UCHAR readBack = 0;
        __try
        {
            PUCHAR field = reinterpret_cast<PUCHAR>(process) + request.ProtectionFieldOffset;
            oldByte = *field;
            *field = request.NewProtection;
            readBack = *field;
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            status = GetExceptionCode();
            if (NT_SUCCESS(status))
            {
                status = STATUS_ACCESS_VIOLATION;
            }
            break;
        }

        KNDBG_SET_PROCESS_PROTECTION_RESPONSE* response =
            reinterpret_cast<KNDBG_SET_PROCESS_PROTECTION_RESPONSE*>(Buffer);
        RtlZeroMemory(response, sizeof(*response));
        response->Size = sizeof(*response);
        response->Flags = 0;
        response->ProcessId = request.ProcessId;
        response->ProtectionFieldOffset = request.ProtectionFieldOffset;
        response->OldProtection = oldByte;
        response->NewProtection = request.NewProtection;
        response->ReadBackProtection = readBack;
        response->EprocessAddress = reinterpret_cast<KNDBG_UINT64>(process);

        information = sizeof(*response);
        status = STATUS_SUCCESS;
    } while (false);

    if (dereference && process != nullptr)
    {
        ObDereferenceObject(process);
    }

    return KnDbgCompleteIrp(Irp, status, information);
}

#ifndef PROCESS_SET_INFORMATION
#define PROCESS_SET_INFORMATION 0x0200
#endif

typedef NTSTATUS (NTAPI *KNDBG_ZW_SET_INFORMATION_PROCESS)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength);

static KNDBG_ZW_SET_INFORMATION_PROCESS KnDbgResolveZwSetInformationProcess()
{
    static KNDBG_ZW_SET_INFORMATION_PROCESS routine = nullptr;
    static BOOLEAN resolved = FALSE;

    if (resolved == FALSE)
    {
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, L"ZwSetInformationProcess");
        routine = reinterpret_cast<KNDBG_ZW_SET_INFORMATION_PROCESS>(
            MmGetSystemRoutineAddress(&name));
        resolved = TRUE;
    }

    return routine;
}

static NTSTATUS KnDbgHandleSetProcessLogging(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;
    PEPROCESS process = nullptr;
    BOOLEAN dereference = FALSE;
    HANDLE processHandle = nullptr;

    do
    {
        ULONG inputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (!KnDbgCheckInputHeader(Buffer, inputLength, sizeof(KNDBG_SET_PROCESS_LOGGING_REQUEST)))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (outputLength < sizeof(KNDBG_SET_PROCESS_LOGGING_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        PKNDBG_FILE_CONTEXT fileContext = reinterpret_cast<PKNDBG_FILE_CONTEXT>(Stack->FileObject->FsContext);
        if (fileContext == nullptr || fileContext->WriteEnabled == FALSE)
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        KNDBG_SET_PROCESS_LOGGING_REQUEST request = {};
        RtlCopyMemory(&request, Buffer, sizeof(request));

        if (request.Acknowledge != KNDBG_WRITE_ACK_MAGIC)
        {
            status = STATUS_ACCESS_DENIED;
            break;
        }

        if (request.ProcessId == 0)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        KNDBG_ZW_SET_INFORMATION_PROCESS setInfo = KnDbgResolveZwSetInformationProcess();
        if (setInfo == nullptr)
        {
            status = STATUS_NOT_SUPPORTED;
            break;
        }

        status = PsLookupProcessByProcessId(ULongToHandle(request.ProcessId), &process);
        if (!NT_SUCCESS(status))
        {
            break;
        }
        dereference = TRUE;

        status = ObOpenObjectByPointer(
            process,
            OBJ_KERNEL_HANDLE,
            nullptr,
            PROCESS_SET_INFORMATION,
            nullptr,
            KernelMode,
            &processHandle);
        if (!NT_SUCCESS(status) || processHandle == nullptr)
        {
            if (NT_SUCCESS(status))
            {
                status = STATUS_UNSUCCESSFUL;
            }
            break;
        }

        if ((request.Flags & ~KNDBG_SET_PROCESS_LOGGING_FLAG_DISABLE) != 0)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        ULONG loggingFlags = request.LoggingFlags;
        if ((request.Flags & KNDBG_SET_PROCESS_LOGGING_FLAG_DISABLE) != 0)
        {
            loggingFlags = 0;
        }
        else if (loggingFlags == 0)
        {
            loggingFlags = KNDBG_PROCESS_LOG_DEFAULT;
        }

        ULONG classUsed = KNDBG_PROCESS_INFO_ENABLE_LOGGING;
        NTSTATUS setStatus = setInfo(
            processHandle,
            KNDBG_PROCESS_INFO_ENABLE_LOGGING,
            &loggingFlags,
            sizeof(loggingFlags));
        if (!NT_SUCCESS(setStatus))
        {
            UCHAR smallFlags = static_cast<UCHAR>(loggingFlags & 0x3u);
            classUsed = KNDBG_PROCESS_INFO_ENABLE_READWRITEVM_LOGGING;
            setStatus = setInfo(
                processHandle,
                KNDBG_PROCESS_INFO_ENABLE_READWRITEVM_LOGGING,
                &smallFlags,
                sizeof(smallFlags));
        }

        KNDBG_SET_PROCESS_LOGGING_RESPONSE* response =
            reinterpret_cast<KNDBG_SET_PROCESS_LOGGING_RESPONSE*>(Buffer);
        RtlZeroMemory(response, sizeof(*response));
        response->Size = sizeof(*response);
        response->ProcessId = request.ProcessId;
        response->LoggingFlagsApplied = loggingFlags;
        response->InformationClassUsed = classUsed;
        response->NtStatus = static_cast<KNDBG_UINT32>(setStatus);
        response->EprocessAddress = reinterpret_cast<KNDBG_UINT64>(process);

        information = sizeof(*response);
        status = setStatus;
    } while (false);

    if (processHandle != nullptr)
    {
        ZwClose(processHandle);
    }

    if (dereference && process != nullptr)
    {
        ObDereferenceObject(process);
    }

    return KnDbgCompleteIrp(Irp, status, information);
}

static bool KnDbgIsValidNameLeaf(const WCHAR* Leaf)
{
    bool ok = false;

    do
    {
        if (Leaf == nullptr || *Leaf == L'\0')
        {
            break;
        }

        size_t length = 0;
        while (Leaf[length] != L'\0')
        {
            const WCHAR ch = Leaf[length];
            const bool letter = (ch >= L'A' && ch <= L'Z') || (ch >= L'a' && ch <= L'z');
            const bool digit = (ch >= L'0' && ch <= L'9');
            if (!letter && !digit)
            {
                break;
            }
            ++length;
            if (length > 16)
            {
                break;
            }
        }

        if (Leaf[length] != L'\0' || length < 8)
        {
            break;
        }

        if (!((Leaf[0] >= L'A' && Leaf[0] <= L'Z') || (Leaf[0] >= L'a' && Leaf[0] <= L'z')))
        {
            break;
        }

        ok = true;
    } while (false);

    return ok;
}

static NTSTATUS KnDbgQueryRegistrySz(
    HANDLE Key,
    const WCHAR* ValueName,
    WCHAR* Buffer,
    USHORT BufferChars)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    do
    {
        if (Key == nullptr || ValueName == nullptr || Buffer == nullptr || BufferChars < 8)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        UNICODE_STRING name = {};
        RtlInitUnicodeString(&name, ValueName);

        UCHAR infoBuffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 96 * sizeof(WCHAR)] = {};
        ULONG resultLength = 0;
        status = ZwQueryValueKey(
            Key,
            &name,
            KeyValuePartialInformation,
            infoBuffer,
            sizeof(infoBuffer),
            &resultLength);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        const KEY_VALUE_PARTIAL_INFORMATION* info =
            reinterpret_cast<const KEY_VALUE_PARTIAL_INFORMATION*>(infoBuffer);
        if (info->Type != REG_SZ || info->DataLength < sizeof(WCHAR))
        {
            status = STATUS_OBJECT_TYPE_MISMATCH;
            break;
        }

        const USHORT wcharCount = static_cast<USHORT>(info->DataLength / sizeof(WCHAR));
        if (wcharCount == 0 || wcharCount >= BufferChars)
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlCopyMemory(Buffer, info->Data, wcharCount * sizeof(WCHAR));
        Buffer[wcharCount] = L'\0';
        if (Buffer[wcharCount - 1] == L'\0')
        {
            // already terminated inside DataLength
        }
        status = STATUS_SUCCESS;
    } while (false);

    return status;
}

static void KnDbgLoadNamesFromRegistry(PUNICODE_STRING RegistryPath)
{
    HANDLE key = nullptr;

    do
    {
        if (RegistryPath == nullptr || RegistryPath->Buffer == nullptr)
        {
            break;
        }

        UNICODE_STRING suffix = RTL_CONSTANT_STRING(L"\\Parameters");
        WCHAR pathChars[256] = {};
        UNICODE_STRING path = {};
        path.Buffer = pathChars;
        path.MaximumLength = sizeof(pathChars);
        path.Length = 0;
        if (!NT_SUCCESS(RtlAppendUnicodeStringToString(&path, RegistryPath)) ||
            !NT_SUCCESS(RtlAppendUnicodeStringToString(&path, &suffix)))
        {
            break;
        }

        OBJECT_ATTRIBUTES attributes;
        InitializeObjectAttributes(
            &attributes,
            &path,
            OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
            nullptr,
            nullptr);

        if (!NT_SUCCESS(ZwOpenKey(&key, KEY_READ, &attributes)))
        {
            break;
        }

        WCHAR deviceChars[96] = {};
        WCHAR linkChars[96] = {};
        if (!NT_SUCCESS(KnDbgQueryRegistrySz(key, L"DeviceName", deviceChars, 96)) ||
            !NT_SUCCESS(KnDbgQueryRegistrySz(key, L"SymbolicLink", linkChars, 96)))
        {
            break;
        }

        const WCHAR devicePrefix[] = L"\\Device\\";
        const WCHAR dosPrefix[] = L"\\DosDevices\\";
        if (RtlCompareMemory(deviceChars, devicePrefix, sizeof(devicePrefix) - sizeof(WCHAR)) !=
                (sizeof(devicePrefix) - sizeof(WCHAR)) ||
            RtlCompareMemory(linkChars, dosPrefix, sizeof(dosPrefix) - sizeof(WCHAR)) !=
                (sizeof(dosPrefix) - sizeof(WCHAR)))
        {
            break;
        }

        if (!KnDbgIsValidNameLeaf(deviceChars + 8) ||
            !KnDbgIsValidNameLeaf(linkChars + 12))
        {
            break;
        }

        RtlCopyMemory(g_KnDbgDeviceNameChars, deviceChars, sizeof(g_KnDbgDeviceNameChars));
        RtlCopyMemory(g_KnDbgSymbolicLinkChars, linkChars, sizeof(g_KnDbgSymbolicLinkChars));
        RtlInitUnicodeString(&g_KnDbgDeviceName, g_KnDbgDeviceNameChars);
        RtlInitUnicodeString(&g_KnDbgSymbolicLink, g_KnDbgSymbolicLinkChars);
    } while (false);

    if (key != nullptr)
    {
        ZwClose(key);
    }
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    KnDbgLoadNamesFromRegistry(RegistryPath);

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING defaultSddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    PDEVICE_OBJECT deviceObject = nullptr;
    bool symbolicLinkCreated = false;

    do
    {
        // Keep the nop exports live so /guard:cf emits GFIDS entries.
        if (KnDbgMinifilterPreCallbackNop(nullptr, nullptr, nullptr, nullptr) != 1)
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }
        if (KnDbgMinifilterPostCallbackNop(nullptr, nullptr, nullptr, nullptr) != 0)
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }
        if (KnDbgMinifilterCallbackNop(nullptr, nullptr, nullptr, nullptr) != 0)
        {
            status = STATUS_UNSUCCESSFUL;
            break;
        }

        ExInitializeFastMutex(&g_KnDbgOwnerLock);
        ExInitializeFastMutex(&g_KnDbgTimelineControlLock);
        KeInitializeSpinLock(&g_KnDbgTimelineLock);
        g_KnDbgOwnerPid = 0;
        g_KnDbgOwnerOpenCount = 0;
        g_KnDbgTimelineEnabled = 0;
        g_KnDbgTimelineProcessRegistered = FALSE;
        g_KnDbgTimelineImageRegistered = FALSE;
        g_KnDbgTimelineThreadRegistered = FALSE;
        g_KnDbgTimelineRing = nullptr;
        g_KnDbgTimelineCapacity = 0;
        g_KnDbgTimelineHead = 0;
        g_KnDbgTimelineCount = 0;
        g_KnDbgTimelineDropped = 0;
        g_KnDbgTimelineNextSequence = 1;

        ExInitializeFastMutex(&g_KnDbgIotraceControlLock);
        KeInitializeSpinLock(&g_KnDbgIotraceLock);
        g_KnDbgIotraceTarget = nullptr;
        g_KnDbgIotraceOriginalDispatch = nullptr;
        g_KnDbgIotraceArmed = 0;
        g_KnDbgIotraceActive = 0;
        g_KnDbgIotraceHead = 0;
        g_KnDbgIotraceCount = 0;
        g_KnDbgIotraceDropped = 0;
        g_KnDbgIotraceNextSequence = 1;
        g_KnDbgIotraceTotalRecorded = 0;
        // The ring is allocated lazily on the first ARM (audit: allocating
        // here would leak on any later DriverEntry failure step, since a
        // failed DriverEntry never reaches KnDbgUnload).
        g_KnDbgIotraceRing = nullptr;

        for (ULONG index = 0; index <= IRP_MJ_MAXIMUM_FUNCTION; ++index)
        {
            DriverObject->MajorFunction[index] = KnDbgNotSupportedDispatch;
        }

        DriverObject->MajorFunction[IRP_MJ_CREATE] = KnDbgCreateClose;
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = KnDbgCreateClose;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KnDbgDeviceControl;
        DriverObject->DriverUnload = KnDbgUnload;

        status = IoCreateDeviceSecure(
            DriverObject,
            0,
            &g_KnDbgDeviceName,
            FILE_DEVICE_UNKNOWN,
            FILE_DEVICE_SECURE_OPEN,
            FALSE,
            &defaultSddl,
            &KNDBG_DEVICE_CLASS_GUID,
            &deviceObject);

        if (!NT_SUCCESS(status))
        {
            break;
        }

        deviceObject->Flags |= DO_BUFFERED_IO;

        status = IoCreateSymbolicLink(&g_KnDbgSymbolicLink, &g_KnDbgDeviceName);
        if (!NT_SUCCESS(status))
        {
            break;
        }

        symbolicLinkCreated = true;
        deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
        status = STATUS_SUCCESS;
    } while (false);

    if (!NT_SUCCESS(status))
    {
        if (symbolicLinkCreated)
        {
            IoDeleteSymbolicLink(&g_KnDbgSymbolicLink);
        }

        if (deviceObject != nullptr)
        {
            IoDeleteDevice(deviceObject);
        }
    }

    return status;
}

static VOID KnDbgUnload(PDRIVER_OBJECT DriverObject)
{
    // Unhook any interposed target before anything else: a live dispatch
    // entry pointing into this image would crash the moment we unload.
    // Retry because a stuck in-flight dispatch would otherwise race the
    // unload; dispatch calls are short, so 2s total is generous.
    for (ULONG attempt = 0; attempt < 5; ++attempt)
    {
        ExAcquireFastMutex(&g_KnDbgIotraceControlLock);
        NTSTATUS disarmStatus = KnDbgIotraceDisarmLocked(TRUE);
        ExReleaseFastMutex(&g_KnDbgIotraceControlLock);
        if (disarmStatus != STATUS_DEVICE_BUSY)
        {
            break;
        }
    }

    ExAcquireFastMutex(&g_KnDbgTimelineControlLock);
    KnDbgTimelineUnregisterCallbacks();
    ExReleaseFastMutex(&g_KnDbgTimelineControlLock);

    if (g_KnDbgTimelineRing != nullptr)
    {
        ExFreePoolWithTag(g_KnDbgTimelineRing, 'tLnK');
        g_KnDbgTimelineRing = nullptr;
    }

    if (g_KnDbgIotraceRing != nullptr)
    {
        ExFreePoolWithTag(g_KnDbgIotraceRing, 'oInK');
        g_KnDbgIotraceRing = nullptr;
    }

    IoDeleteSymbolicLink(&g_KnDbgSymbolicLink);

    if (DriverObject->DeviceObject != nullptr)
    {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

static NTSTATUS KnDbgCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR information = 0;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

    do
    {
        if (stack->MajorFunction == IRP_MJ_CREATE)
        {
            PKNDBG_FILE_CONTEXT fileContext = reinterpret_cast<PKNDBG_FILE_CONTEXT>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KNDBG_FILE_CONTEXT), 'gDnK'));

            if (fileContext == nullptr)
            {
                status = STATUS_INSUFFICIENT_RESOURCES;
                break;
            }

            RtlZeroMemory(fileContext, sizeof(KNDBG_FILE_CONTEXT));
            fileContext->WriteEnabled = TRUE;
            status = KnDbgAcquireController(fileContext);
            if (!NT_SUCCESS(status))
            {
                ExFreePoolWithTag(fileContext, 'gDnK');
                break;
            }

            stack->FileObject->FsContext = fileContext;
        }
        else
        {
            PKNDBG_FILE_CONTEXT fileContext = reinterpret_cast<PKNDBG_FILE_CONTEXT>(stack->FileObject->FsContext);
            if (fileContext != nullptr)
            {
                stack->FileObject->FsContext = nullptr;
                KnDbgReleaseController(fileContext);
                ExFreePoolWithTag(fileContext, 'gDnK');
            }

            // The controlling client is going away (including abrupt
            // process termination): never leave an interposed dispatch
            // entry behind pointing into this driver.
            ExAcquireFastMutex(&g_KnDbgIotraceControlLock);
            KnDbgIotraceDisarmLocked(TRUE);
            ExReleaseFastMutex(&g_KnDbgIotraceControlLock);
        }
    } while (false);

    return KnDbgCompleteIrp(Irp, status, information);
}

// Pins the calling thread to the system-wide logical processor 'Index'
// (across all processor groups) so callers can sample per-CPU register state
// on machines with more than 64 logical processors. Returns the previous
// group affinity for the caller to restore via KeRevertToUserGroupAffinityThread;
// *ActualProcessor receives the processor the thread actually landed on. Must
// run at PASSIVE_LEVEL.
static GROUP_AFFINITY KnDbgPinToProcessor(ULONG Index, ULONG* ActualProcessor)
{
    PROCESSOR_NUMBER processorNumber = {};
    if (!NT_SUCCESS(KeGetProcessorNumberFromIndex(Index, &processorNumber)))
    {
        RtlZeroMemory(&processorNumber, sizeof(processorNumber));
        KeGetProcessorNumberFromIndex(0, &processorNumber);
    }

    GROUP_AFFINITY target = {};
    target.Group = processorNumber.Group;
    target.Mask = (KAFFINITY)1 << processorNumber.Number;

    GROUP_AFFINITY previous = {};
    KeSetSystemGroupAffinityThread(&target, &previous);

    if (ActualProcessor != NULL)
    {
        *ActualProcessor = KeGetCurrentProcessorNumberEx(NULL);
    }

    return previous;
}

// Reads one architectural MSR on a caller-selected logical processor. This is
// a read-only primitive: only the fixed SYSCALL/segment MSR whitelist is
// permitted (all guaranteed present in x64 long mode, so __readmsr cannot
// #GP), and no write-mode gate is required. The caller iterates processors to
// surface per-CPU divergence such as a single-core SYSCALL hook.
static NTSTATUS KnDbgHandleReadMsr(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;

    do
    {
        ULONG inputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (!KnDbgCheckInputHeader(Buffer, inputLength, sizeof(KNDBG_READ_MSR_REQUEST)))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (outputLength < sizeof(KNDBG_READ_MSR_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        KNDBG_READ_MSR_REQUEST request = {};
        RtlCopyMemory(&request, Buffer, sizeof(request));

        BOOLEAN permitted = FALSE;
        switch (request.MsrIndex)
        {
        case KNDBG_MSR_IA32_EFER:
        case KNDBG_MSR_IA32_STAR:
        case KNDBG_MSR_IA32_LSTAR:
        case KNDBG_MSR_IA32_CSTAR:
        case KNDBG_MSR_IA32_FMASK:
        case KNDBG_MSR_IA32_FS_BASE:
        case KNDBG_MSR_IA32_GS_BASE:
        case KNDBG_MSR_IA32_KERNEL_GS_BASE:
            permitted = TRUE;
            break;
        default:
            permitted = FALSE;
            break;
        }

        if (!permitted)
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        RtlZeroMemory(Buffer, outputLength);

        // Pin to the requested system-wide processor (across all groups) so a
        // per-CPU MSR divergence is observable on >64-processor machines too.
        // The dispatch runs at PASSIVE_LEVEL, required for affinity migration.
        ULONG activeCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
        if (activeCount == 0)
        {
            activeCount = 1;
        }

        ULONG targetProcessor = request.ProcessorNumber;
        if (targetProcessor >= activeCount)
        {
            targetProcessor = 0;
        }

        ULONG actualProcessor = 0;
        GROUP_AFFINITY previousAffinity = KnDbgPinToProcessor(targetProcessor, &actualProcessor);
        ULONG64 value = __readmsr(request.MsrIndex);
        KeRevertToUserGroupAffinityThread(&previousAffinity);

        KNDBG_READ_MSR_RESPONSE* response = reinterpret_cast<KNDBG_READ_MSR_RESPONSE*>(Buffer);
        response->Size = sizeof(KNDBG_READ_MSR_RESPONSE);
        response->Flags = 0;
        response->MsrIndex = request.MsrIndex;
        response->ProcessorNumber = actualProcessor;
        response->Value = value;

        information = sizeof(KNDBG_READ_MSR_RESPONSE);
        status = STATUS_SUCCESS;
    } while (false);

    return KnDbgCompleteIrp(Irp, status, information);
}

// Reads the x64 control registers on a caller-selected logical processor.
// Read-only and whitelist-free (the CR set is fixed); no write-mode gate is
// required. The caller iterates processors to surface per-CPU divergence of
// CR0/CR4 (the kernel keeps these uniform across cores).
static NTSTATUS KnDbgHandleReadControlRegisters(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;

    do
    {
        ULONG inputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (!KnDbgCheckInputHeader(Buffer, inputLength, sizeof(KNDBG_READ_CR_REQUEST)))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (outputLength < sizeof(KNDBG_READ_CR_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        KNDBG_READ_CR_REQUEST request = {};
        RtlCopyMemory(&request, Buffer, sizeof(request));

        RtlZeroMemory(Buffer, outputLength);

        ULONG activeCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
        if (activeCount == 0)
        {
            activeCount = 1;
        }

        ULONG targetProcessor = request.ProcessorNumber;
        if (targetProcessor >= activeCount)
        {
            targetProcessor = 0;
        }

        ULONG actualProcessor = 0;
        GROUP_AFFINITY previousAffinity = KnDbgPinToProcessor(targetProcessor, &actualProcessor);
        ULONG64 cr0 = __readcr0();
        ULONG64 cr2 = __readcr2();
        ULONG64 cr3 = __readcr3();
        ULONG64 cr4 = __readcr4();
        ULONG64 cr8 = __readcr8();
        KeRevertToUserGroupAffinityThread(&previousAffinity);

        KNDBG_READ_CR_RESPONSE* response = reinterpret_cast<KNDBG_READ_CR_RESPONSE*>(Buffer);
        response->Size = sizeof(KNDBG_READ_CR_RESPONSE);
        response->ProcessorNumber = actualProcessor;
        response->Cr0 = cr0;
        response->Cr2 = cr2;
        response->Cr3 = cr3;
        response->Cr4 = cr4;
        response->Cr8 = cr8;

        information = sizeof(KNDBG_READ_CR_RESPONSE);
        status = STATUS_SUCCESS;
    } while (false);

    return KnDbgCompleteIrp(Irp, status, information);
}

#pragma pack(push, 1)
typedef struct _KNDBG_IDTR_RAW
{
    unsigned short Limit;
    unsigned __int64 Base;
} KNDBG_IDTR_RAW;
#pragma pack(pop)

// Reads the IDTR (limit + base) on a caller-selected logical processor via
// __sidt. Read-only; no write-mode gate. Each processor has its own IDT base,
// so the caller selects the processor; user mode then reads and validates the
// gate descriptors through the existing memory-read primitive.
static NTSTATUS KnDbgHandleReadIdt(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;

    do
    {
        ULONG inputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
        ULONG outputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;

        if (!KnDbgCheckInputHeader(Buffer, inputLength, sizeof(KNDBG_READ_IDT_REQUEST)))
        {
            status = STATUS_INVALID_PARAMETER;
            break;
        }

        if (outputLength < sizeof(KNDBG_READ_IDT_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        KNDBG_READ_IDT_REQUEST request = {};
        RtlCopyMemory(&request, Buffer, sizeof(request));

        RtlZeroMemory(Buffer, outputLength);

        ULONG activeCount = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
        if (activeCount == 0)
        {
            activeCount = 1;
        }

        ULONG targetProcessor = request.ProcessorNumber;
        if (targetProcessor >= activeCount)
        {
            targetProcessor = 0;
        }

        ULONG actualProcessor = 0;
        GROUP_AFFINITY previousAffinity = KnDbgPinToProcessor(targetProcessor, &actualProcessor);
        KNDBG_IDTR_RAW idtr = {};
        __sidt(&idtr);
        KeRevertToUserGroupAffinityThread(&previousAffinity);

        KNDBG_READ_IDT_RESPONSE* response = reinterpret_cast<KNDBG_READ_IDT_RESPONSE*>(Buffer);
        response->Size = sizeof(KNDBG_READ_IDT_RESPONSE);
        response->ProcessorNumber = actualProcessor;
        response->IdtBase = idtr.Base;
        response->IdtLimit = idtr.Limit;

        information = sizeof(KNDBG_READ_IDT_RESPONSE);
        status = STATUS_SUCCESS;
    } while (false);

    return KnDbgCompleteIrp(Irp, status, information);
}

static NTSTATUS KnDbgHandleGetPhysicalRanges(PIRP Irp, PIO_STACK_LOCATION Stack, PVOID Buffer)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG_PTR information = 0;
    PPHYSICAL_MEMORY_RANGE ranges = nullptr;

    do
    {
        if (Buffer == nullptr ||
            Stack->Parameters.DeviceIoControl.OutputBufferLength < sizeof(KNDBG_PHYSICAL_RANGES_RESPONSE))
        {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }

        RtlZeroMemory(Buffer, Stack->Parameters.DeviceIoControl.OutputBufferLength);

        ranges = MmGetPhysicalMemoryRanges();
        if (ranges == nullptr)
        {
            status = STATUS_INSUFFICIENT_RESOURCES;
            break;
        }

        ULONG count = 0;
        ULONGLONG totalBytes = 0;
        BOOLEAN tooMany = FALSE;
        BOOLEAN overflow = FALSE;
        BOOLEAN unterminated = FALSE;
        const ULONG kMaxScanEntries = KNDBG_MAX_PHYSICAL_RANGES + 8u;
        for (ULONG index = 0; index < kMaxScanEntries; ++index)
        {
            const PHYSICAL_MEMORY_RANGE entry = ranges[index];
            if (entry.BaseAddress.QuadPart == 0 && entry.NumberOfBytes.QuadPart == 0)
            {
                unterminated = FALSE;
                break;
            }

            unterminated = TRUE;
            if (entry.NumberOfBytes.QuadPart <= 0)
            {
                continue;
            }

            if (count >= KNDBG_MAX_PHYSICAL_RANGES)
            {
                tooMany = TRUE;
                break;
            }

            const ULONGLONG byteCount = static_cast<ULONGLONG>(entry.NumberOfBytes.QuadPart);
            if (totalBytes > (~0ull - byteCount))
            {
                overflow = TRUE;
                break;
            }

            KNDBG_PHYSICAL_RANGES_RESPONSE* response =
                reinterpret_cast<KNDBG_PHYSICAL_RANGES_RESPONSE*>(Buffer);
            response->Ranges[count].BaseAddress =
                static_cast<ULONGLONG>(entry.BaseAddress.QuadPart);
            response->Ranges[count].ByteCount = byteCount;
            totalBytes += byteCount;
            ++count;
        }

        if (overflow)
        {
            status = STATUS_INTEGER_OVERFLOW;
            break;
        }

        if (tooMany || unterminated)
        {
            status = STATUS_BUFFER_OVERFLOW;
            break;
        }

        KNDBG_PHYSICAL_RANGES_RESPONSE* response =
            reinterpret_cast<KNDBG_PHYSICAL_RANGES_RESPONSE*>(Buffer);
        response->Size = sizeof(KNDBG_PHYSICAL_RANGES_RESPONSE);
        response->Flags = 0;
        response->RangeCount = count;
        response->Reserved = 0;
        response->TotalBytes = totalBytes;

        information = sizeof(KNDBG_PHYSICAL_RANGES_RESPONSE);
        status = STATUS_SUCCESS;
    } while (false);

    if (ranges != nullptr)
    {
        ExFreePool(ranges);
    }

    return KnDbgCompleteIrp(Irp, status, information);
}

static NTSTATUS KnDbgDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;

    switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case IOCTL_KNDBG_GET_VERSION:
        status = KnDbgHandleGetVersion(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_READ_VIRTUAL:
        status = KnDbgHandleReadVirtual(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_WRITE_VIRTUAL:
        status = KnDbgHandleWriteVirtual(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_SET_WRITE_MODE:
        status = KnDbgHandleWriteMode(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_QUERY_ADDRESS:
        status = KnDbgHandleQueryAddress(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_TRANSLATE_VIRTUAL:
        status = KnDbgHandleTranslateVirtual(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_READ_PHYSICAL:
        status = KnDbgHandleReadPhysical(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_WRITE_PHYSICAL:
        status = KnDbgHandleWritePhysical(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_GET_SESSION_STATUS:
        status = KnDbgHandleSessionStatus(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_RESOLVE_PROCESS:
        status = KnDbgHandleResolveProcess(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_FLUSH_VIRTUAL:
        status = KnDbgHandleFlushVirtual(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_SET_PROCESS_PROTECTION:
        status = KnDbgHandleSetProcessProtection(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_READ_MSR:
        status = KnDbgHandleReadMsr(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_READ_CONTROL_REGISTERS:
        status = KnDbgHandleReadControlRegisters(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_READ_IDT:
        status = KnDbgHandleReadIdt(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_TIMELINE_CONTROL:
        status = KnDbgHandleTimelineControl(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_TIMELINE_STATUS:
        status = KnDbgHandleTimelineStatus(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_TIMELINE_DRAIN:
        status = KnDbgHandleTimelineDrain(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_READ_PROCESS_VIRTUAL:
        status = KnDbgHandleReadProcessVirtual(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_GET_PHYSICAL_RANGES:
        status = KnDbgHandleGetPhysicalRanges(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_SET_PROCESS_LOGGING:
        status = KnDbgHandleSetProcessLogging(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_IOTRACE_CONTROL:
        status = KnDbgHandleIotraceControl(Irp, stack, buffer);
        break;
    case IOCTL_KNDBG_IOTRACE_DRAIN:
        status = KnDbgHandleIotraceDrain(Irp, stack, buffer);
        break;
    default:
        status = KnDbgCompleteIrp(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
        break;
    }

    return status;
}

static NTSTATUS KnDbgNotSupportedDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return KnDbgCompleteIrp(Irp, STATUS_NOT_SUPPORTED, 0);
}
