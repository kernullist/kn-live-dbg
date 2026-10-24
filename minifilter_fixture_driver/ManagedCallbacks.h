#pragma once
#include <fltKernel.h>

void ManagedCallbacksInitialize();
NTSTATUS ManagedCallbacksStart(PFLT_FILTER filter);
void ManagedCallbacksStop();
void ManagedCallbacksUnregistered();
FLT_PREOP_CALLBACK_STATUS FLTAPI ManagedPreCreate(
    PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID* completionContext);
FLT_POSTOP_CALLBACK_STATUS FLTAPI ManagedPostCreate(
    PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS objects, PVOID completionContext,
    FLT_POST_OPERATION_FLAGS flags);
