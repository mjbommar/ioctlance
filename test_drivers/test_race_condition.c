/*
 * Test driver for race condition (double-fetch/TOCTOU) vulnerabilities
 * 
 * This driver demonstrates several race condition patterns:
 * 1. Classic double-fetch where size is read twice
 * 2. TOCTOU with ProbeForRead followed by unsafe access
 * 3. Double validation where data is checked then used
 */

#include <ntddk.h>

// IOCTL codes for testing
#define IOCTL_DOUBLE_FETCH    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_TOCTOU_PROBE    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_DOUBLE_CHECK    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_NEITHER, FILE_ANY_ACCESS)

// User request structure
typedef struct _USER_REQUEST {
    ULONG Size;
    ULONG Command;
    PVOID Data;
} USER_REQUEST, *PUSER_REQUEST;

NTSTATUS ProcessDoubleFetch(PVOID UserBuffer)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUSER_REQUEST request;
    PVOID kernelBuffer = NULL;
    ULONG bufferSize;
    
    // Cast user buffer to request structure
    request = (PUSER_REQUEST)UserBuffer;
    
    if (!request) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // VULNERABILITY: First read of Size field
    bufferSize = request->Size;
    
    // Validate size
    if (bufferSize > 0x10000) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Allocate kernel buffer based on first read
    kernelBuffer = ExAllocatePoolWithTag(NonPagedPool, bufferSize, 'RACE');
    if (!kernelBuffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // VULNERABILITY: Second read of Size field (double-fetch)
    // Attacker can change Size between the two reads!
    RtlCopyMemory(kernelBuffer, request->Data, request->Size);
    
    // Process the data...
    
    ExFreePoolWithTag(kernelBuffer, 'RACE');
    
    return status;
}

NTSTATUS ProcessTOCTOUProbe(PVOID UserBuffer, ULONG InputBufferLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUSER_REQUEST request;
    PVOID kernelBuffer = NULL;
    
    request = (PUSER_REQUEST)UserBuffer;
    
    if (!request) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Check with ProbeForRead
    ProbeForRead(request, sizeof(USER_REQUEST), sizeof(ULONG));
    ProbeForRead(request->Data, request->Size, sizeof(UCHAR));
    
    // Allocate buffer
    kernelBuffer = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'TOCT');
    if (!kernelBuffer) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // VULNERABILITY: TOCTOU - request->Size could change after ProbeForRead
    // This creates a classic time-of-check-time-of-use vulnerability
    RtlCopyMemory(kernelBuffer, request->Data, request->Size);
    
    // Another TOCTOU: request->Command could change
    if (request->Command == 1) {
        // Do something privileged
        DbgPrint("Executing privileged command\n");
    }
    
    ExFreePoolWithTag(kernelBuffer, 'TOCT');
    
    return status;
}

NTSTATUS ProcessDoubleCheck(PVOID UserBuffer)
{
    NTSTATUS status = STATUS_SUCCESS;
    PUSER_REQUEST request;
    ULONG command;
    
    request = (PUSER_REQUEST)UserBuffer;
    
    if (!request) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // VULNERABILITY: First read for validation
    command = request->Command;
    
    // Validate command
    if (command > 10) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Some processing...
    DbgPrint("Processing command...\n");
    
    // VULNERABILITY: Second read for use (could be different!)
    switch (request->Command) {
        case 0:
            DbgPrint("Command 0\n");
            break;
        case 1:
            DbgPrint("Command 1\n");
            break;
        case 99:  // This should have been blocked!
            // Privileged operation that should never execute
            DbgPrint("PRIVILEGED: Executing admin command!\n");
            break;
        default:
            DbgPrint("Unknown command\n");
            break;
    }
    
    return status;
}

NTSTATUS DeviceIoControlHandler(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    PIO_STACK_LOCATION ioStack;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG ioControlCode;
    PVOID inputBuffer;
    ULONG inputBufferLength;
    
    UNREFERENCED_PARAMETER(DeviceObject);
    
    ioStack = IoGetCurrentIrpStackLocation(Irp);
    ioControlCode = ioStack->Parameters.DeviceIoControl.IoControlCode;
    inputBuffer = ioStack->Parameters.DeviceIoControl.Type3InputBuffer;
    inputBufferLength = ioStack->Parameters.DeviceIoControl.InputBufferLength;
    
    switch (ioControlCode) {
        case IOCTL_DOUBLE_FETCH:
            status = ProcessDoubleFetch(inputBuffer);
            break;
            
        case IOCTL_TOCTOU_PROBE:
            status = ProcessTOCTOUProbe(inputBuffer, inputBufferLength);
            break;
            
        case IOCTL_DOUBLE_CHECK:
            status = ProcessDoubleCheck(inputBuffer);
            break;
            
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
    
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return status;
}

NTSTATUS CreateCloseHandler(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\RaceConditionTest");
    
    IoDeleteSymbolicLink(&symLink);
    IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverEntry(
    PDRIVER_OBJECT DriverObject,
    PUNICODE_STRING RegistryPath
)
{
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\RaceConditionTest");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\RaceConditionTest");
    
    UNREFERENCED_PARAMETER(RegistryPath);
    
    // Create device
    status = IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );
    
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Create symbolic link
    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }
    
    // Set up dispatch routines
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateCloseHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControlHandler;
    DriverObject->DriverUnload = DriverUnload;
    
    return STATUS_SUCCESS;
}