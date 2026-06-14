#include <ntddk.h>
#include <wdmsec.h>
#include <intrin.h>
#include "../shared/KnLiveDbgIoctl.h"

extern "C"
NTKERNELAPI
NTSTATUS
PsLookupProcessByProcessId(
    HANDLE ProcessId,
    PEPROCESS* Process);

#if defined(_M_X64)
#pragma intrinsic(__readcr0)
#pragma intrinsic(__readcr2)
#pragma intrinsic(__readcr3)
#pragma intrinsic(__readcr4)
#pragma intrinsic(__readcr8)
#pragma intrinsic(__invlpg)
#pragma intrinsic(__readmsr)
#endif

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

static FAST_MUTEX g_KnDbgOwnerLock;
static ULONG g_KnDbgOwnerPid = 0;
static ULONG g_KnDbgOwnerOpenCount = 0;

static bool KnDbgIsLa57Active();
static bool KnDbgIsCanonicalAddress(ULONGLONG VirtualAddress, bool La57Active);

typedef struct _KNDBG_TLB_FLUSH_CONTEXT
{
    ULONGLONG StartAddress;
    SIZE_T PageCount;
} KNDBG_TLB_FLUSH_CONTEXT, *PKNDBG_TLB_FLUSH_CONTEXT;

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
        for (SIZE_T index = 0; index < flushContext->PageCount; ++index)
        {
            ULONGLONG address = flushContext->StartAddress + index * PAGE_SIZE;
            __invlpg(reinterpret_cast<void*>(static_cast<ULONG_PTR>(address)));
        }
#endif
    } while (false);

    return 0;
}

static NTSTATUS KnDbgFlushVirtualRange(ULONGLONG VirtualAddress, SIZE_T Length)
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
        response->DriverMinor = 4;
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
        response->IsWritable = 0;

        PKNDBG_FILE_CONTEXT fileContext = reinterpret_cast<PKNDBG_FILE_CONTEXT>(Stack->FileObject->FsContext);
        if (fileContext != nullptr && fileContext->WriteEnabled != FALSE)
        {
            response->IsWritable = 1;
        }

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

        status = KnDbgFlushVirtualRange(request->VirtualAddress, request->Length);
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

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status = STATUS_UNSUCCESSFUL;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(KNDBG_DEVICE_NAME);
    UNICODE_STRING symbolicLinkName = RTL_CONSTANT_STRING(KNDBG_DOS_DEVICE_NAME);
    UNICODE_STRING defaultSddl = RTL_CONSTANT_STRING(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    PDEVICE_OBJECT deviceObject = nullptr;
    bool symbolicLinkCreated = false;

    do
    {
        ExInitializeFastMutex(&g_KnDbgOwnerLock);
        g_KnDbgOwnerPid = 0;
        g_KnDbgOwnerOpenCount = 0;

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
            &deviceName,
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

        status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);
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
            IoDeleteSymbolicLink(&symbolicLinkName);
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
    UNICODE_STRING symbolicLinkName = RTL_CONSTANT_STRING(KNDBG_DOS_DEVICE_NAME);

    IoDeleteSymbolicLink(&symbolicLinkName);

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
        }
    } while (false);

    return KnDbgCompleteIrp(Irp, status, information);
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

        // Pin to the requested processor (clamped to the active count in group
        // 0) so a per-CPU MSR divergence is observable. The dispatch runs at
        // PASSIVE_LEVEL, which is required for the affinity migration.
        ULONG activeCount = KeQueryActiveProcessorCountEx(0);
        if (activeCount == 0)
        {
            activeCount = 1;
        }

        ULONG targetProcessor = request.ProcessorNumber;
        if (targetProcessor >= activeCount)
        {
            targetProcessor = 0;
        }

        KAFFINITY affinity = (KAFFINITY)1 << targetProcessor;
        KAFFINITY previousAffinity = KeSetSystemAffinityThreadEx(affinity);
        ULONG actualProcessor = KeGetCurrentProcessorNumberEx(NULL);
        ULONG64 value = __readmsr(request.MsrIndex);
        KeRevertToUserAffinityThreadEx(previousAffinity);

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

        ULONG activeCount = KeQueryActiveProcessorCountEx(0);
        if (activeCount == 0)
        {
            activeCount = 1;
        }

        ULONG targetProcessor = request.ProcessorNumber;
        if (targetProcessor >= activeCount)
        {
            targetProcessor = 0;
        }

        KAFFINITY affinity = (KAFFINITY)1 << targetProcessor;
        KAFFINITY previousAffinity = KeSetSystemAffinityThreadEx(affinity);
        ULONG actualProcessor = KeGetCurrentProcessorNumberEx(NULL);
        ULONG64 cr0 = __readcr0();
        ULONG64 cr2 = __readcr2();
        ULONG64 cr3 = __readcr3();
        ULONG64 cr4 = __readcr4();
        ULONG64 cr8 = __readcr8();
        KeRevertToUserAffinityThreadEx(previousAffinity);

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

        ULONG activeCount = KeQueryActiveProcessorCountEx(0);
        if (activeCount == 0)
        {
            activeCount = 1;
        }

        ULONG targetProcessor = request.ProcessorNumber;
        if (targetProcessor >= activeCount)
        {
            targetProcessor = 0;
        }

        KAFFINITY affinity = (KAFFINITY)1 << targetProcessor;
        KAFFINITY previousAffinity = KeSetSystemAffinityThreadEx(affinity);
        ULONG actualProcessor = KeGetCurrentProcessorNumberEx(NULL);
        KNDBG_IDTR_RAW idtr = {};
        __sidt(&idtr);
        KeRevertToUserAffinityThreadEx(previousAffinity);

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
