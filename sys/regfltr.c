/*++
Copyright (c) Microsoft Corporation.  All rights reserved.

    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY
    KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
    IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR
    PURPOSE.

Module Name:

    regfltr.c

Abstract: 

    Sample driver used to run the kernel mode registry callback samples.

Environment:

    Kernel mode only

--*/

#include "regfltr.h"

//
// The root key used in the samples
//
HANDLE g_RootKey;


typedef NTSTATUS(*QUERY_INFO_PROCESS) (
    __in HANDLE ProcessHandle,
    __in PROCESSINFOCLASS ProcessInformationClass,
    __out_bcount(ProcessInformationLength) PVOID ProcessInformation,
    __in ULONG ProcessInformationLength,
    __out_opt PULONG ReturnLength
    );
QUERY_INFO_PROCESS ZwQueryInformationProcess;

NTSTATUS
GetProcessImageName(
    PEPROCESS eProcess,
    PUNICODE_STRING* ProcessImageName
)
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    ULONG returnedLength;
    HANDLE hProcess = NULL;

    PAGED_CODE(); // this eliminates the possibility of the IDLE Thread/Process

    if (eProcess == NULL)
    {
        return STATUS_INVALID_PARAMETER_1;
    }

    status = ObOpenObjectByPointer(eProcess,
        0, NULL, 0, 0, KernelMode, &hProcess);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("ObOpenObjectByPointer Failed: %08x\n", status);
        return status;
    }

    if (ZwQueryInformationProcess == NULL)
    {
        UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");

        ZwQueryInformationProcess =
            (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

        if (ZwQueryInformationProcess == NULL)
        {
            DbgPrint("Cannot resolve ZwQueryInformationProcess\n");
            status = STATUS_UNSUCCESSFUL;
            goto cleanUp;
        }
    }

    /* Query the actual size of the process path */
    status = ZwQueryInformationProcess(hProcess,
        ProcessImageFileName,
        NULL, // buffer
        0,    // buffer size
        &returnedLength);

    if (STATUS_INFO_LENGTH_MISMATCH != status) {
        DbgPrint("ZwQueryInformationProcess status = %x\n", status);
        goto cleanUp;
    }

    *ProcessImageName = ExAllocatePoolWithTag(NonPagedPoolNx, returnedLength, '2gat');

    if (ProcessImageName == NULL)
    {
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto cleanUp;
    }
    /* Retrieve the process path from the handle to the process */
    status = ZwQueryInformationProcess(hProcess,
        ProcessImageFileName,
        *ProcessImageName,
        returnedLength,
        &returnedLength);

    if (!NT_SUCCESS(status)) ExFreePoolWithTag(*ProcessImageName, '2gat');

cleanUp:

    ZwClose(hProcess);
    return status;
}



LPCWSTR 
GetTransactionNotifyClassString (
    _In_ ULONG TransactionNotifcation
    );

LPCWSTR 
GetNotifyClassString (
    _In_ REG_NOTIFY_CLASS NotifyClass
    );

VOID
DeleteTestKeys(
    );



NTSTATUS 
Callback (
    _In_     PVOID CallbackContext,
    _In_opt_ PVOID Argument1,
    _In_opt_ PVOID Argument2
)
/*++

Routine Description:

    This is the registry callback we'll register to intercept all registry
    operations. 

Arguments:

    CallbackContext - The value that the driver passed to the Context parameter
        of CmRegisterCallbackEx when it registers this callback routine.

    Argument1 - A REG_NOTIFY_CLASS typed value that identifies the type of 
        registry operation that is being performed and whether the callback
        is being called in the pre or post phase of processing.

    Argument2 - A pointer to a structure that contains information specific
        to the type of the registry operation. The structure type depends
        on the REG_NOTIFY_CLASS value of Argument1. Refer to MSDN for the 
        mapping from REG_NOTIFY_CLASS to REG_XXX_KEY_INFORMATION.

Return Value:

    Status returned from the helper callback routine or STATUS_SUCCESS if
    the registry operation did not originate from this process.

--*/
{

    NTSTATUS Status = STATUS_SUCCESS;
    REG_NOTIFY_CLASS NotifyClass;
    PCALLBACK_CONTEXT CallbackCtx;

    CallbackCtx = (PCALLBACK_CONTEXT)CallbackContext;
    NotifyClass = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

    //
    // Ignore registry activity from other processes. If this callback 
    // wasn't registered by the current process, simply return success.
    //
     
    int noFoundProc = 1, levelProc = -1, i;
    PUNICODE_STRING processName = NULL;

    if (CallbackCtx->ProcessId != PsGetCurrentProcessId()) {
        GetProcessImageName(PsGetCurrentProcess(), &processName);
        if (processName != NULL) {
            for (i = 0; i < countRecords; i++) {
                if (wcsstr(processName->Buffer, pointerConfiguration[i].wName) != NULL) {
                    noFoundProc = 0;
                    InfoPrint("Found Process");
                    levelProc = pointerConfiguration[i].levelIntegrity;
                    break;
                }
            }
        }

        //return STATUS_SUCCESS;
    }
    /*
    InfoPrint("\tCallback: Altitude-%S, NotifyClass-%S.",
               CallbackCtx->AltitudeBuffer,
               GetNotifyClassString(NotifyClass));*/

    //
    // Invoke a helper method depending on the value of CallbackMode in 
    // CallbackCtx.
    //

    if (Argument2 == NULL) {
        ErrorPrint("\tCallback: Argument 2 unexpectedly 0. Filter will "
                    "abort and return success.");
        return STATUS_SUCCESS;
    }


    //PUNICODE_STRING keyName = NULL;
    //switch (NotifyClass) {
    //    case RegNtPreOpenKeyEx:
    //        //InfoPrint("Open key!");
    //        keyName = NULL;
    //        REG_OPEN_KEY_INFORMATION* open_inf = (REG_OPEN_KEY_INFORMATION*)Argument2;
    //        memcpy(&keyName, &open_inf->CompleteName, sizeof(PUNICODE_STRING));
    //        break;
    //    case RegNtPreCreateKey:
    //        //InfoPrint("Create key!");
    //        keyName = NULL;
    //        REG_OPEN_KEY_INFORMATION* create_inf = (REG_OPEN_KEY_INFORMATION*)Argument2;
    //        memcpy(&keyName, &create_inf->CompleteName, sizeof(PUNICODE_STRING));
    //        break;
    //    default:
    //        //ErrorPrint("Unknown Callback Mode: %d", CallbackCtx->CallbackMode);
    //        Status = STATUS_INVALID_PARAMETER;
    //}
    /*ANSI_STRING Name;
    RtlUnicodeStringToAnsiString(&Name, keyName->Buffer, TRUE);*/
    

   /* if (processName != NULL) {
        for (i = 0; i < countRecords; i++) {
            if (wcsstr(processName->Buffer, (PWSTR)(pointerConfiguration[i].name)) != NULL) {
                noFoundProc = 0;
                InfoPrint("Found Process");
                levelProc = pointerConfiguration[i].levelIntegrity;
                break;
            }
        }
    }*/

    int levelKey;
    if (noFoundProc == 0 && levelProc != -1) {
        REG_PRE_OPEN_KEY_INFORMATION* pRegPreCreateKey = (REG_PRE_OPEN_KEY_INFORMATION*)Argument2;
        if (pRegPreCreateKey != NULL && pRegPreCreateKey->CompleteName != NULL && pRegPreCreateKey->CompleteName->Length > 0) {
            for (i = 0; i < countRecords; i++) {
                if (wcsstr(pRegPreCreateKey->CompleteName->Buffer, pointerConfiguration[i].wName) != NULL) {
                    levelKey = pointerConfiguration[i].levelIntegrity;
                    if (!(levelProc >= levelKey)) {
                        Status = STATUS_ACCESS_DENIED;
                        InfoPrint("Access Denied");
                    }
                    InfoPrint("Found Key");
                    break;
                }
            }
        }
    }

    return Status;
    
}


NTSTATUS  
RMCallback(
    _In_    PKENLISTMENT   EnlistmentObject,
    _In_    PVOID          RMContext,    
    _In_    PVOID          TransactionContext,    
    _In_    ULONG          TransactionNotification,    
    _Inout_ PLARGE_INTEGER TMVirtualClock,
    _In_    ULONG          ArgumentLength,
    _In_    PVOID          Argument
    )
/*++

Routine Description:

    This callback recieves transaction notifications.

Arguments:

    EnlistmentObject - Enlistment that this notification is about

    RMContext - The value specified for the RMKey parameter of the 
        TmEnableCallbacks routine

    TransactionContext - Value specified for the EnlistmentKey parameter 
        of the ZwCreateEnlistment routine

    TransactionNotification - Type of notification 

    TmVirtualClock - Pointer to virtual clock value of time when KTM prepared
        the notification.

    ArgumentLength - Length in bytes of the Argument buffer. 

    Argument - Buffer containing notification-spcefic arguments. 

Return Value:

    Always STATUS_SUCCESS

--*/
{
    PRMCALLBACK_CONTEXT Context = (PRMCALLBACK_CONTEXT) TransactionContext;
    NTSTATUS Status = STATUS_SUCCESS;
    
    UNREFERENCED_PARAMETER(EnlistmentObject);
    UNREFERENCED_PARAMETER(RMContext);
    UNREFERENCED_PARAMETER(ArgumentLength);
    UNREFERENCED_PARAMETER(Argument);

    InfoPrint("\tRMCallback: NotifyClass-%S.",
               GetTransactionNotifyClassString(TransactionNotification));

    //
    // Transaction notifications are bit masks. Record which one(s)
    // this callback received.
    //
    
    Context->Notification |= TransactionNotification;

    //
    // Call the Tm*Complete methods to inform KTM that we have completed
    // processing. (Note: It is possible to use the Zw version of
    // these APIs as well).
    //
    // Make sure that all the notifications you request are handled. The
    // type of notification this routine gets is specified when you enlist
    // in a transaction.
    //
    
    switch(TransactionNotification) {
        case TRANSACTION_NOTIFY_COMMIT:         
            Status = TmCommitComplete(EnlistmentObject,
                                      TMVirtualClock);
            break;
        case TRANSACTION_NOTIFY_ROLLBACK:
            Status = TmRollbackComplete(EnlistmentObject,
                                        TMVirtualClock);
            break;
        default:
            ErrorPrint("Unsupported Transaction Notification: %x", 
                       TransactionNotification);
            NT_ASSERT(FALSE);
    }
    
    //
    // It is safe to close the enlistment handle here.
    // Closing it before the transaction aborts or commits will abort 
    // the transaction.
    //
    
    if (Context->Enlistment != NULL) {
        ZwClose(Context->Enlistment);
        Context->Enlistment = NULL;
    }

    return Status;

}



//NTSTATUS 
//DoCallbackSamples(
//    _In_ PDEVICE_OBJECT DeviceObject,
//    _In_ PIRP Irp
//    )
/*++

Routine Description:

    This routine creates the root test key and then invokes the sample.
    It records the results of each sample in an array that it returns to
    the usermode program.

Arguments:

    DeviceObject - The device object receiving the request.

    Irp - The request packet.
    
Return Value:

    NTSTATUS

--*/
//{
//    NTSTATUS Status;
//    PIO_STACK_LOCATION IrpStack;
//    ULONG OutputBufferLength;
//    PDO_KERNELMODE_SAMPLES_OUTPUT Output;
//    UNICODE_STRING KeyPath;
//    OBJECT_ATTRIBUTES KeyAttributes;
//
//    UNREFERENCED_PARAMETER(DeviceObject);
//
//    //
//    // Get the output buffer from the irp and check it is as large as expected.
//    //
//    
//    IrpStack = IoGetCurrentIrpStackLocation(Irp);
//
//    OutputBufferLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;
//
//    if (OutputBufferLength < sizeof (DO_KERNELMODE_SAMPLES_OUTPUT)) {
//        Status = STATUS_INVALID_PARAMETER;
//        goto Exit;
//    }
//
//    Output = (PDO_KERNELMODE_SAMPLES_OUTPUT) Irp->AssociatedIrp.SystemBuffer;
//
//    //
//    // Clean up test keys in case the sample terminated uncleanly.
//    //
//
//    DeleteTestKeys();
//
//    //
//    // Create the root key and the modified root key
//    //
//    
//    RtlInitUnicodeString(&KeyPath, ROOT_KEY_ABS_PATH);
//    InitializeObjectAttributes(&KeyAttributes,
//                               &KeyPath,
//                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
//                               NULL,
//                               NULL);
//
//    Status = ZwCreateKey(&g_RootKey,
//                         KEY_ALL_ACCESS,
//                         &KeyAttributes,
//                         0,
//                         NULL,
//                         0,
//                         NULL);
//
//    if (!NT_SUCCESS(Status)) {
//        ErrorPrint("ZwCreateKey failed. Status 0x%x", Status);
//        return Status;
//    }
//
//    //
//    // Call each demo and record the results in the Output->SampleResults
//    // array
//    //
//
//    Output->SampleResults[KERNELMODE_SAMPLE_PRE_NOTIFICATION_BLOCK] =
//        PreNotificationBlockSample();
//
//    Output->SampleResults[KERNELMODE_SAMPLE_PRE_NOTIFICATION_BYPASS] =
//        PreNotificationBypassSample();
//
//    Output->SampleResults[KERNELMODE_SAMPLE_POST_NOTIFICATION_OVERRIDE_SUCCESS] =
//        PostNotificationOverrideSuccessSample();
//
//    Output->SampleResults[KERNELMODE_SAMPLE_POST_NOTIFICATION_OVERRIDE_ERROR] =
//        PostNotificationOverrideErrorSample();
//
//    Output->SampleResults[KERNELMODE_SAMPLE_TRANSACTION_ENLIST] =
//        TransactionEnlistSample();
//
//    Output->SampleResults[KERNELMODE_SAMPLE_TRANSACTION_REPLAY] =
//        TransactionReplaySample();
//
//    Output->SampleResults[KERNELMODE_SAMPLE_SET_CALL_CONTEXT] =
//        SetObjectContextSample();
//
//    Output->SampleResults[KERNELMODE_SAMPLE_SET_OBJECT_CONTEXT] =
//        SetCallContextSample();
//
//    Output->SampleResults[KERNELMODE_SAMPLE_MULTIPLE_ALTITUDE_BLOCK_DURING_PRE] =
//        MultipleAltitudeBlockDuringPreSample();
//
//    Output->SampleResults[KERNELMODE_SAMPLE_MULTIPLE_ALTITUDE_INTERNAL_INVOCATION] =
//        MultipleAltitudeInternalInvocationSample();
//
//    Output->SampleResults[KERNELMODE_SAMPLE_VERSION_CREATE_OPEN_V1] =
//        CreateOpenV1Sample();
//
//    Irp->IoStatus.Information = sizeof(DO_KERNELMODE_SAMPLES_OUTPUT);
//
//  Exit:
//
//    if (g_RootKey) {
//        ZwDeleteKey(g_RootKey);
//        ZwClose(g_RootKey);
//    }
//
//    InfoPrint("");
//    InfoPrint("Kernel Mode Samples End");
//    InfoPrint("");
//    
//    return Status;
//}


NTSTATUS
RegisterCallback(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    ) 
/*++

Routine Description:

    Registers a callback with the specified callback mode and altitude

Arguments:

    DeviceObject - The device object receiving the request.

    Irp - The request packet.

Return Value:

    Status from CmRegisterCallbackEx

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PIO_STACK_LOCATION IrpStack;
    ULONG InputBufferLength;
    ULONG OutputBufferLength;
    PREGISTER_CALLBACK_INPUT  RegisterCallbackInput;
    PREGISTER_CALLBACK_OUTPUT RegisterCallbackOutput;
    PCALLBACK_CONTEXT CallbackCtx = NULL;

    //
    // Get the input and output buffer from the irp and
    // check they are the expected size
    //
    
    IrpStack = IoGetCurrentIrpStackLocation(Irp);

    InputBufferLength  = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
    OutputBufferLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;

    if ((InputBufferLength < sizeof(REGISTER_CALLBACK_INPUT)) || 
       (OutputBufferLength < sizeof (REGISTER_CALLBACK_OUTPUT))) {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    RegisterCallbackInput = (PREGISTER_CALLBACK_INPUT) Irp->AssociatedIrp.SystemBuffer;

    //
    // Create the callback context from the specified callback mode and altitude
    //
    
    CallbackCtx = CreateCallbackContext(RegisterCallbackInput->CallbackMode,
                                         RegisterCallbackInput->Altitude);
                                         
    if (CallbackCtx == NULL) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // Register the callback
    //

    Status = CmRegisterCallbackEx(Callback,
                                  &CallbackCtx->Altitude,
                                  DeviceObject->DriverObject,
                                  (PVOID) CallbackCtx,
                                  &CallbackCtx->Cookie, 
                                  NULL);
    if (!NT_SUCCESS(Status)) {
        ErrorPrint("CmRegisterCallback failed. Status 0x%x", Status);
        goto Exit;
    }

    if (!InsertCallbackContext(CallbackCtx)) {
        Status = STATUS_UNSUCCESSFUL;
        goto Exit;
    }
    
    //
    // Fill the output buffer with the Cookie received from registering the 
    // callback and the pointer to the callback context.
    //
    
    RegisterCallbackOutput = (PREGISTER_CALLBACK_OUTPUT)Irp->AssociatedIrp.SystemBuffer;
    RegisterCallbackOutput->Cookie = CallbackCtx->Cookie;
    Irp->IoStatus.Information = sizeof(REGISTER_CALLBACK_OUTPUT);

  Exit:
    if (!NT_SUCCESS(Status)) {
        ErrorPrint("RegisterCallback failed. Status 0x%x", Status);
        if (CallbackCtx != NULL) {
            DeleteCallbackContext(CallbackCtx);
        }
    } else {
        InfoPrint("RegisterCallback succeeded");
    }

    return Status;
}



NTSTATUS
UnRegisterCallback(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    ) 
/*++

Routine Description:

    Unregisters a callback with the specified cookie and clean up the
    callback context.

Arguments:

    DeviceObject - The device object receiving the request.

    Irp - The request packet.

Return Value:

    Status from CmUnRegisterCallback

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PIO_STACK_LOCATION IrpStack;
    ULONG InputBufferLength;
    PUNREGISTER_CALLBACK_INPUT UnRegisterCallbackInput;
    PCALLBACK_CONTEXT CallbackCtx;

    UNREFERENCED_PARAMETER(DeviceObject);

    //
    // Get the input buffer and check its size
    //
    
    IrpStack = IoGetCurrentIrpStackLocation(Irp);

    InputBufferLength  = IrpStack->Parameters.DeviceIoControl.InputBufferLength;

    if (InputBufferLength < sizeof(UNREGISTER_CALLBACK_INPUT)) {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    UnRegisterCallbackInput = (PUNREGISTER_CALLBACK_INPUT) Irp->AssociatedIrp.SystemBuffer;
    
    //
    // Unregister the callback with the cookie
    //

    Status = CmUnRegisterCallback(UnRegisterCallbackInput->Cookie);

    if (!NT_SUCCESS(Status)) {
        ErrorPrint("CmUnRegisterCallback failed. Status 0x%x", Status);
        goto Exit;
    }

    //
    // Free the callback context buffer
    //
    CallbackCtx = FindAndRemoveCallbackContext(UnRegisterCallbackInput->Cookie);
    if (CallbackCtx != NULL) {
        DeleteCallbackContext(CallbackCtx);
    }

  Exit:

    if (!NT_SUCCESS(Status)) {
        ErrorPrint("UnRegisterCallback failed. Status 0x%x", Status);
    } else {
        InfoPrint("UnRegisterCallback succeeded");
    }
    InfoPrint("");

    return Status;

}


NTSTATUS
GetCallbackVersion(
    _In_ PDEVICE_OBJECT DeviceObject,
    _In_ PIRP Irp
    ) 
/*++

Routine Description:

    Calls CmGetCallbackVersion

Arguments:

    DeviceObject - The device object receiving the request.

    Irp - The request packet.

Return Value:

    NTSTATUS

--*/
{
    NTSTATUS Status = STATUS_SUCCESS;
    PIO_STACK_LOCATION IrpStack;
    ULONG OutputBufferLength;
    PGET_CALLBACK_VERSION_OUTPUT GetCallbackVersionOutput;

    UNREFERENCED_PARAMETER(DeviceObject);

    //
    // Get the output buffer and verify its size
    //
    
    IrpStack = IoGetCurrentIrpStackLocation(Irp);

    OutputBufferLength = IrpStack->Parameters.DeviceIoControl.OutputBufferLength;

    if (OutputBufferLength < sizeof(GET_CALLBACK_VERSION_OUTPUT)) {
        Status = STATUS_INVALID_PARAMETER;
        goto Exit;
    }

    GetCallbackVersionOutput = (PGET_CALLBACK_VERSION_OUTPUT) Irp->AssociatedIrp.SystemBuffer;

    //
    // Call CmGetCallbackVersion and store the results in the output buffer
    //
    
    CmGetCallbackVersion(&GetCallbackVersionOutput->MajorVersion, 
                         &GetCallbackVersionOutput->MinorVersion);   

    Irp->IoStatus.Information = sizeof(GET_CALLBACK_VERSION_OUTPUT);

  Exit:

    if (!NT_SUCCESS(Status)) {
        ErrorPrint("GetCallbackVersion failed. Status 0x%x", Status);
    } else {
        InfoPrint("GetCallbackVersion succeeded");
    }

    return Status;
}


LPCWSTR 
GetNotifyClassString (
    _In_ REG_NOTIFY_CLASS NotifyClass
    )
/*++

Routine Description:

    Converts from NotifyClass to a string

Arguments:

    NotifyClass - value that identifies the type of registry operation that 
        is being performed

Return Value:

    Returns a string of the name of NotifyClass.
    
--*/
{
    switch (NotifyClass) {
        case RegNtPreDeleteKey:                 return L"RegNtPreDeleteKey";
        case RegNtPreSetValueKey:               return L"RegNtPreSetValueKey";
        case RegNtPreDeleteValueKey:            return L"RegNtPreDeleteValueKey";
        case RegNtPreSetInformationKey:         return L"RegNtPreSetInformationKey";
        case RegNtPreRenameKey:                 return L"RegNtPreRenameKey";
        case RegNtPreEnumerateKey:              return L"RegNtPreEnumerateKey";
        case RegNtPreEnumerateValueKey:         return L"RegNtPreEnumerateValueKey";
        case RegNtPreQueryKey:                  return L"RegNtPreQueryKey";
        case RegNtPreQueryValueKey:             return L"RegNtPreQueryValueKey";
        case RegNtPreQueryMultipleValueKey:     return L"RegNtPreQueryMultipleValueKey";
        case RegNtPreKeyHandleClose:            return L"RegNtPreKeyHandleClose";
        case RegNtPreCreateKeyEx:               return L"RegNtPreCreateKeyEx";
        case RegNtPreOpenKeyEx:                 return L"RegNtPreOpenKeyEx";
        case RegNtPreFlushKey:                  return L"RegNtPreFlushKey";
        case RegNtPreLoadKey:                   return L"RegNtPreLoadKey";
        case RegNtPreUnLoadKey:                 return L"RegNtPreUnLoadKey";
        case RegNtPreQueryKeySecurity:          return L"RegNtPreQueryKeySecurity";
        case RegNtPreSetKeySecurity:            return L"RegNtPreSetKeySecurity";
        case RegNtPreRestoreKey:                return L"RegNtPreRestoreKey";
        case RegNtPreSaveKey:                   return L"RegNtPreSaveKey";
        case RegNtPreReplaceKey:                return L"RegNtPreReplaceKey";

        case RegNtPostDeleteKey:                return L"RegNtPostDeleteKey";
        case RegNtPostSetValueKey:              return L"RegNtPostSetValueKey";
        case RegNtPostDeleteValueKey:           return L"RegNtPostDeleteValueKey";
        case RegNtPostSetInformationKey:        return L"RegNtPostSetInformationKey";
        case RegNtPostRenameKey:                return L"RegNtPostRenameKey";
        case RegNtPostEnumerateKey:             return L"RegNtPostEnumerateKey";
        case RegNtPostEnumerateValueKey:        return L"RegNtPostEnumerateValueKey";
        case RegNtPostQueryKey:                 return L"RegNtPostQueryKey";
        case RegNtPostQueryValueKey:            return L"RegNtPostQueryValueKey";
        case RegNtPostQueryMultipleValueKey:    return L"RegNtPostQueryMultipleValueKey";
        case RegNtPostKeyHandleClose:           return L"RegNtPostKeyHandleClose";
        case RegNtPostCreateKeyEx:              return L"RegNtPostCreateKeyEx";
        case RegNtPostOpenKeyEx:                return L"RegNtPostOpenKeyEx";
        case RegNtPostFlushKey:                 return L"RegNtPostFlushKey";
        case RegNtPostLoadKey:                  return L"RegNtPostLoadKey";
        case RegNtPostUnLoadKey:                return L"RegNtPostUnLoadKey";
        case RegNtPostQueryKeySecurity:         return L"RegNtPostQueryKeySecurity";
        case RegNtPostSetKeySecurity:           return L"RegNtPostSetKeySecurity";
        case RegNtPostRestoreKey:               return L"RegNtPostRestoreKey";
        case RegNtPostSaveKey:                  return L"RegNtPostSaveKey";
        case RegNtPostReplaceKey:               return L"RegNtPostReplaceKey";

        case RegNtCallbackObjectContextCleanup: return L"RegNtCallbackObjectContextCleanup";

        default:
            return L"Unsupported REG_NOTIFY_CLASS";
    }
}


LPCWSTR 
GetTransactionNotifyClassString (
    _In_ ULONG TransactionNotifcation
    )
/*++

Routine Description:

    Converts from TransactionNotification to a string

Arguments:

    TransactionNotification - value that identifies the type of 
        transaction notification

Return Value:

    Returns a string of the name of TransactionNotification
    
--*/
{
    switch (TransactionNotifcation) {
        case TRANSACTION_NOTIFY_COMMIT:         return L"TRANSACTION_NOTIFY_COMMIT";
        case TRANSACTION_NOTIFY_ROLLBACK:       return L"TRANSACTION_NOTIFY_ROLLBACK";
        
        default:
            return L"Unsupported Transaction Notification";
    }
}



VOID
DeleteTestKeys(
    )
/*++


--*/
{
    NTSTATUS Status;
    UNICODE_STRING KeyPath;
    OBJECT_ATTRIBUTES KeyAttributes;
    HANDLE RootKey = NULL;
    HANDLE ChildKey = NULL;

    //
    // Check if the root key can be opened. If it can be opened, a previous
    // run must have not completed cleanly. Delete the key and recreate the 
    // root key.
    //

    RtlInitUnicodeString(&KeyPath, ROOT_KEY_ABS_PATH);
    InitializeObjectAttributes(&KeyAttributes,
                               &KeyPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL,
                               NULL);

    Status = ZwOpenKey(&RootKey,
                       KEY_ALL_ACCESS,
                       &KeyAttributes);

    if (Status == STATUS_OBJECT_NAME_NOT_FOUND) {
        return;
    } else if (!NT_SUCCESS(Status)) {
        ErrorPrint("Opening root key fails with unexpected status %x.", Status);
    }

    RtlInitUnicodeString(&KeyPath, KEY_NAME);
    InitializeObjectAttributes(&KeyAttributes,
                               &KeyPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               RootKey,
                               NULL);

    Status = ZwOpenKey(&ChildKey,
                       KEY_ALL_ACCESS,
                       &KeyAttributes);

    if (NT_SUCCESS(Status)) {
        ZwDeleteKey(ChildKey);
        ZwClose(ChildKey);
        ChildKey = NULL;
    } else if (Status != STATUS_OBJECT_NAME_NOT_FOUND) {
        ErrorPrint("Opening %S key fails with unexpected status %x.", 
                   KEY_NAME,
                   Status);
    }

    RtlInitUnicodeString(&KeyPath, NOT_MODIFIED_KEY_NAME);
    InitializeObjectAttributes(&KeyAttributes,
                               &KeyPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               RootKey,
                               NULL);

    Status = ZwOpenKey(&ChildKey,
                       KEY_ALL_ACCESS,
                       &KeyAttributes);

    if (NT_SUCCESS(Status)) {
        ZwDeleteKey(ChildKey);
        ZwClose(ChildKey);
        ChildKey = NULL;
    } else if (Status != STATUS_OBJECT_NAME_NOT_FOUND) {
        ErrorPrint("Opening %S key fails with unexpected status %x.", 
                   NOT_MODIFIED_KEY_NAME,
                   Status);
    }

    RtlInitUnicodeString(&KeyPath, MODIFIED_KEY_NAME);
    InitializeObjectAttributes(&KeyAttributes,
                               &KeyPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               RootKey,
                               NULL);

    Status = ZwOpenKey(&ChildKey,
                       KEY_ALL_ACCESS,
                       &KeyAttributes);

    if (NT_SUCCESS(Status)) {
        ZwDeleteKey(ChildKey);
        ZwClose(ChildKey);
        ChildKey = NULL;
    } else if (Status != STATUS_OBJECT_NAME_NOT_FOUND) {
        ErrorPrint("Opening %S key fails with unexpected status %x.", 
                   MODIFIED_KEY_NAME,
                   Status);
    }

    ZwDeleteKey(RootKey);
    ZwClose(RootKey);

    return;

}
