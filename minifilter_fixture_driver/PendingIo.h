#pragma once
#include <fltKernel.h>

void PendingIoInitialize();
const FLT_CONTEXT_REGISTRATION* PendingIoContextRegistration();
NTSTATUS PendingIoStart(PFLT_FILTER filter, PCUNICODE_STRING registryPath);
void PendingIoStop();
void PendingIoUnregistered();
void PendingIoProcessExit(PEPROCESS process);
NTSTATUS PendingIoInstanceSetup(PCFLT_RELATED_OBJECTS objects);
void PendingIoInstanceTeardownStart(PCFLT_RELATED_OBJECTS objects);
void PendingIoInstanceTeardownComplete(PCFLT_RELATED_OBJECTS objects);
FLT_PREOP_CALLBACK_STATUS FLTAPI PendingIoPreOperation(PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS objects, PVOID* completionContext);
FLT_POSTOP_CALLBACK_STATUS FLTAPI PendingIoPostOperation(PFLT_CALLBACK_DATA data,
    PCFLT_RELATED_OBJECTS objects, PVOID completionContext, FLT_POST_OPERATION_FLAGS flags);
