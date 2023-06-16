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
int countRecords = 0;
PCALLBACK_CONTEXT CallbackCtx = NULL;
HANDLE log_file;

void sCreateThreadNotifyRoutine(HANDLE pid, HANDLE tid, BOOLEAN create)
{
    LARGE_INTEGER currTimeStamp;
    TIME_FIELDS time_fileds;
    ULONG timeIncrement;
    IO_STATUS_BLOCK     IoStatus;
    timeIncrement = KeQueryTimeIncrement();

    KeQuerySystemTime(&currTimeStamp);
    RtlTimeToTimeFields(&currTimeStamp, &time_fileds);
    int sec = time_fileds.Second;
    int minutes = time_fileds.Minute;
    int hour = time_fileds.Hour + 3;
    char buf[100] = { 0 };
    NTSTATUS Status;
    if (create) {
        sprintf(buf, "(%d:%d:%d) %d created thread %d;\n", hour, minutes, sec, pid, tid);
        Status = NtWriteFile(log_file,
            0, NULL, NULL,
            &IoStatus,
            (PCHAR)buf,
            (ULONG)strlen(buf),
            NULL, NULL);
    }
    else {
        sprintf(buf, "(%d:%d:%d) %d exited;\n", hour, minutes, sec, tid);
        Status = NtWriteFile(log_file,
            0, NULL, NULL,
            &IoStatus,
            (PCHAR)buf,
            (ULONG)strlen(buf),
            NULL, NULL);
    }
    return;
}

NTSTATUS enable_notification() {
    OBJECT_ATTRIBUTES obj_attr;
    UNICODE_STRING name;
    RtlInitUnicodeString(&name, L"\\??\\C:\\Users\\labs\\Desktop\\CreateThreads.log");
    InitializeObjectAttributes(&obj_attr, &name, OBJ_KERNEL_HANDLE, 0, NULL);
    IO_STATUS_BLOCK file_status;
    NTSTATUS Status = ZwCreateFile(&log_file, FILE_WRITE_DATA + SYNCHRONIZE, &obj_attr, &file_status, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE || FILE_SHARE_READ, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "RegFltr: Error created file!\n");
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "RegFltr: File exist! Everything will be written to a file \n");
    }
    return PsSetCreateThreadNotifyRoutine(sCreateThreadNotifyRoutine);
}

NTSTATUS disable_notification() {
    NTSTATUS Status = PsRemoveCreateThreadNotifyRoutine(sCreateThreadNotifyRoutine);
    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "RegFltr: Error remove CreateThreadNotifyRoutine!\n");
        return Status;
    }
    NtClose(log_file);
    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "RegFltr: Error close file!\n");
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "RegFltr: File is closed!\n");
    }
    return Status;
}



NTSTATUS get_configuration(_In_ PIRP Irp) {
    NTSTATUS Status = STATUS_SUCCESS;
    PIO_STACK_LOCATION IrpStack;
    ULONG InputBufferLength;
    // Get the input and output buffer from the irp and
    // check they are the expected size
    IrpStack = IoGetCurrentIrpStackLocation(Irp);

    InputBufferLength = IrpStack->Parameters.DeviceIoControl.InputBufferLength;
    struct config* output = (struct config*)Irp->AssociatedIrp.SystemBuffer;
    memcpy(&pointerConfiguration[countRecords], output, InputBufferLength);
    InfoPrint("%d: %s with %d level", countRecords, pointerConfiguration[countRecords].name, pointerConfiguration[countRecords].levelIntegrity);
    countRecords++;
    return Status;
}



DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     DeviceUnload;

_Dispatch_type_(IRP_MJ_CREATE)         DRIVER_DISPATCH DeviceCreate;
_Dispatch_type_(IRP_MJ_CLOSE)          DRIVER_DISPATCH DeviceClose;
_Dispatch_type_(IRP_MJ_CLEANUP)        DRIVER_DISPATCH DeviceCleanup;
_Dispatch_type_(IRP_MJ_DEVICE_CONTROL) DRIVER_DISPATCH DeviceControl;

//
// Pointer to the device object used to register registry callbacks
//
PDEVICE_OBJECT g_DeviceObj;

//
// Registry callback version
//
ULONG g_MajorVersion;
ULONG g_MinorVersion;

//
// Set to TRUE if TM and RM were successfully created and the transaction
// callback was successfully enabled. 
//
BOOLEAN g_RMCreated;


//
// OS version globals initialized in driver entry 
//

BOOLEAN g_IsWin8OrGreater = FALSE;

VOID
DetectOSVersion()
/*++

Routine Description:

    This routine determines the OS version and initializes some globals used
    in the sample. 

Arguments:
    
    None
    
Return value:

    None. On failure, global variables stay at default value

--*/
{

    RTL_OSVERSIONINFOEXW VersionInfo = {0};
    NTSTATUS Status;
    ULONGLONG ConditionMask = 0;

    //
    // Set VersionInfo to Win7's version number and then use
    // RtlVerifVersionInfo to see if this is win8 or greater.
    //
    
    VersionInfo.dwOSVersionInfoSize = sizeof(VersionInfo);
    VersionInfo.dwMajorVersion = 6;
    VersionInfo.dwMinorVersion = 1;

    VER_SET_CONDITION(ConditionMask, VER_MAJORVERSION, VER_LESS_EQUAL);
    VER_SET_CONDITION(ConditionMask, VER_MINORVERSION, VER_LESS_EQUAL);



    Status = RtlVerifyVersionInfo(&VersionInfo,
                                  VER_MAJORVERSION | VER_MINORVERSION,
                                  ConditionMask);
    if (NT_SUCCESS(Status)) {
        g_IsWin8OrGreater = FALSE;
        InfoPrint("DetectOSVersion: This machine is running Windows 7 or an older OS.");
    } else if (Status == STATUS_REVISION_MISMATCH) {
        g_IsWin8OrGreater = TRUE;
        InfoPrint("DetectOSVersion: This machine is running Windows 8 or a newer OS.");
    } else {
        ErrorPrint("RtlVerifyVersionInfo returned unexpected error status 0x%x.",
            Status);

        //
        // default action is to assume this is not win8
        //
        g_IsWin8OrGreater = FALSE;  
    }
    
}



NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
/*++

Routine Description:

    This routine is called by the operating system to initialize the driver. 
    It allocates a device object, initializes the supported Io callbacks, and
    creates a symlink to make the device accessible to Win32.

    It gets the registry callback version and stores it in the global
    variables g_MajorVersion and g_MinorVersion. It also calls
    CreateKTMResourceManager to create a resource manager that is used in 
    the transaction samples.

Arguments:
    
    DriverObject - Supplies the system control object for this test driver.

    RegistryPath - The string location of the driver's corresponding services 
                   key in the registry.

Return value:

    Success or appropriate failure code.

--*/
{
    NTSTATUS Status;
    UNICODE_STRING NtDeviceName;
    UNICODE_STRING DosDevicesLinkName;
    UNICODE_STRING DeviceSDDLString;

    UNREFERENCED_PARAMETER(RegistryPath);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 
               DPFLTR_ERROR_LEVEL,
               "RegFltr: DriverEntry()\n");

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 
               DPFLTR_ERROR_LEVEL,
               "RegFltr: Use ed nt!Kd_IHVDRIVER_Mask 8 to enable more detailed printouts\n");

    //
    //  Default to NonPagedPoolNx for non paged pool allocations where supported.
    //

    ExInitializeDriverRuntime(DrvRtPoolNxOptIn);

    //
    // Create our device object.
    //

    RtlInitUnicodeString(&NtDeviceName, NT_DEVICE_NAME);
    RtlInitUnicodeString(&DeviceSDDLString, DEVICE_SDDL);

    Status = IoCreateDeviceSecure(
                            DriverObject,                 // pointer to driver object
                            0,                            // device extension size
                            &NtDeviceName,                // device name
                            FILE_DEVICE_UNKNOWN,          // device type
                            0,                            // device characteristics
                            TRUE,                         // not exclusive
                            &DeviceSDDLString,            // SDDL string specifying access
                            NULL,                         // device class guid
                            &g_DeviceObj);                // returned device object pointer

    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    //
    // Set dispatch routines.
    //

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = DeviceCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = DeviceClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP]        = DeviceCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    DriverObject->DriverUnload                         = DeviceUnload;

    //
    // Create a link in the Win32 namespace.
    //
    

    RtlInitUnicodeString(&DosDevicesLinkName, DOS_DEVICES_LINK_NAME);

    Status = IoCreateSymbolicLink(&DosDevicesLinkName, &NtDeviceName);

    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(DriverObject->DeviceObject);
        return Status;
    }

    //
    // Get callback version.
    //

   /* CmGetCallbackVersion(&g_MajorVersion, &g_MinorVersion);
    InfoPrint("Callback version %u.%u", g_MajorVersion, g_MinorVersion);*/

    //
    // Some variations depend on knowing if the OS is win8 or above
    //
    
    //DetectOSVersion();

    //
    // Set up KTM resource manager and pass in RMCallback as our
    // callback routine.
    //

    /*Status = CreateKTMResourceManager(RMCallback, NULL);

    if (NT_SUCCESS(Status)) {
        g_RMCreated = TRUE;
    }*/

    //
    // Initialize the callback context list
    //

    InitializeListHead(&g_CallbackCtxListHead);
    ExInitializeFastMutex(&g_CallbackCtxListLock);
    g_NumCallbackCtxListEntries = 0;


    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "RegFltr: Driver was created!\n");

    BOOLEAN Success = FALSE;

    CallbackCtx = CreateCallbackContext(CALLBACK_MODE_PRE_NOTIFICATION_BYPASS,
        CALLBACK_ALTITUDE);
    if (CallbackCtx == NULL) {
        ErrorPrint("Error create Callback");
        // goto Exit;
    }

    Status = CmRegisterCallbackEx(Callback,
        &CallbackCtx->Altitude,
        g_DeviceObj->DriverObject,
        (PVOID)CallbackCtx,
        &CallbackCtx->Cookie,
        NULL);

    if (!NT_SUCCESS(Status)) {
        ErrorPrint("CmRegisterCallback failed. Status 0x%x", Status);
        // goto Exit;
    }

    return STATUS_SUCCESS;
    
}



NTSTATUS
DeviceCreate (
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
/*++

Routine Description:

    Dispatches file create requests.  
    
Arguments:

    DeviceObject - The device object receiving the request.

    Irp - The request packet.

Return Value:

    STATUS_NOT_IMPLEMENTED

--*/
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}



NTSTATUS
DeviceClose (
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
/*++

Routine Description:

    Dispatches close requests.

Arguments:

    DeviceObject - The device object receiving the request.

    Irp - The request packet.

Return Value:

    STATUS_SUCCESS

--*/
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}



NTSTATUS
DeviceCleanup (
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
/*++

Routine Description:

    Dispatches cleanup requests.  Does nothing right now.

Arguments:

    DeviceObject - The device object receiving the request.

    Irp - The request packet.

Return Value:

    STATUS_SUCCESS

--*/
{
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}



NTSTATUS
DeviceControl (
    _In_ PDEVICE_OBJECT DeviceObject,
    _Inout_ PIRP Irp
    )
/*++

Routine Description:

    Dispatches ioctl requests. 

Arguments:

    DeviceObject - The device object receiving the request.

    Irp - The request packet.

Return Value:

    Status returned from the method called.

--*/
{
    PIO_STACK_LOCATION IrpStack;
    ULONG Ioctl;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(DeviceObject);

    Status = STATUS_SUCCESS;

    IrpStack = IoGetCurrentIrpStackLocation(Irp);
    Ioctl = IrpStack->Parameters.DeviceIoControl.IoControlCode;

    switch (Ioctl)
    {

    case IOCTL_REGISTER_CALLBACK:
        Status = RegisterCallback(DeviceObject, Irp);
        break;

    case IOCTL_UNREGISTER_CALLBACK:
        Status = UnRegisterCallback(DeviceObject, Irp);
        break;
    case IOCTL_ENABLE_NOTIFICATION:
        InfoPrint("(DeviceControl)  Enable Notification...");
        Status = enable_notification();
        break;
    case IOCTL_DISABLE_NOTIFICATION:
        InfoPrint("(DeviceControl)  Disable Notification...");
        Status = disable_notification();
        break;

    case IOCTL_DATA:
        InfoPrint("(DeviceControl)  Read Data...");
        Status = get_configuration(Irp);
        break;

    default:
        ErrorPrint("Unrecognized ioctl code 0x%x", Ioctl);
    }

    //
    // Complete the irp and return.
    //

    Irp->IoStatus.Status = Status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
    
}


VOID
DeviceUnload (
    _In_ PDRIVER_OBJECT DriverObject
    )
/*++

Routine Description:

    Cleans up any driver-level allocations and prepares for unload. All 
    this driver needs to do is to delete the device object and the 
    symbolic link between our device name and the Win32 visible name.

Arguments:

    DeviceObject - The device object receiving the request.

    Irp - The request packet.

Return Value:

    STATUS_NOT_IMPLEMENTED

--*/
{
    UNICODE_STRING  DosDevicesLinkName;

    //
    // Clean up the KTM data structures
    //

    //DeleteKTMResourceManager();
    //
    ////
    //// Delete the link from our device name to a name in the Win32 namespace.
    ////

    //RtlInitUnicodeString(&DosDevicesLinkName, DOS_DEVICES_LINK_NAME);
    //IoDeleteSymbolicLink(&DosDevicesLinkName);

    ////
    //// Finally delete our device object
    ////

    //IoDeleteDevice(DriverObject->DeviceObject);

    //DbgPrintEx(DPFLTR_IHVDRIVER_ID, 
    //           DPFLTR_ERROR_LEVEL,
    //           "RegFltr: DeviceUnload\n");


    //UNICODE_STRING DosDevicesLinkName;
    NTSTATUS Status;
    Status = CmUnRegisterCallback(CallbackCtx->Cookie);

    if (!NT_SUCCESS(Status)) {
        ErrorPrint("CmUnRegisterCallback failed. Status 0x%x", Status);
    }

    if (CallbackCtx != NULL) {
        ExFreePoolWithTag(CallbackCtx, REGFLTR_CONTEXT_POOL_TAG);
    }

    RtlInitUnicodeString(&DosDevicesLinkName, DOS_DEVICES_LINK_NAME);
    IoDeleteSymbolicLink(&DosDevicesLinkName);

    // Finally delete our device object
    IoDeleteDevice(DriverObject->DeviceObject);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID,
        DPFLTR_ERROR_LEVEL,
        "RegFltr: DeviceUnload\n");
}

