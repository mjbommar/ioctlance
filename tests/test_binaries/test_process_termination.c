/*
 * IOCTLance Test Driver - Process Termination Vulnerabilities
 * For testing ProcessTerminationDetector
 * Built with mingw-w64 + DDK headers
 */

#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DeviceControl;
DRIVER_DISPATCH CreateClose;

// IOCTL codes for testing different vulnerability patterns
#define IOCTL_TERMINATE_PROCESS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x920, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LOOKUP_PROCESS_BY_PID  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x921, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OPEN_PROCESS_DANGEROUS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x922, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DEREF_TAINTED_OBJECT   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x923, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Process access rights (PROCESS_ALL_ACCESS is already defined in DDK)
#define PROCESS_TERMINATE         0x0001
#define PROCESS_VM_WRITE         0x0020

// Note: These kernel APIs would normally be imported from ntoskrnl.exe
// For testing purposes, IOCTLance will hook these functions during analysis

// Forward declaration for PsLookupProcessByProcessId (not in standard DDK headers)
NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PVOID *Process);

typedef struct _TERMINATE_REQUEST {
    HANDLE ProcessHandle;
    NTSTATUS ExitStatus;
} TERMINATE_REQUEST, *PTERMINATE_REQUEST;

typedef struct _LOOKUP_REQUEST {
    HANDLE ProcessId;
    PVOID ProcessObject;  // Output
} LOOKUP_REQUEST, *PLOOKUP_REQUEST;

typedef struct _OPEN_REQUEST {
    HANDLE ProcessId;
    ACCESS_MASK DesiredAccess;
    HANDLE ProcessHandle;  // Output
} OPEN_REQUEST, *POPEN_REQUEST;

NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return STATUS_SUCCESS;
}

NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    NTSTATUS status = STATUS_SUCCESS;
    ULONG info = 0;
    
    PVOID systemBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    
    switch (ioControlCode) {
        case IOCTL_TERMINATE_PROCESS:
        {
            // VULNERABILITY: User controls process handle for termination
            if (inputLength >= sizeof(TERMINATE_REQUEST)) {
                PTERMINATE_REQUEST request = (PTERMINATE_REQUEST)systemBuffer;
                
                // BUG: Directly using user-provided handle!
                // User can terminate any process including security software
                status = ZwTerminateProcess(
                    request->ProcessHandle,  // User-controlled!
                    request->ExitStatus
                );
                
                DbgPrint("Terminated process with handle %p\n", request->ProcessHandle);
            }
            break;
        }
        
        case IOCTL_LOOKUP_PROCESS_BY_PID:
        {
            // VULNERABILITY: User controls PID for lookup
            if (inputLength >= sizeof(LOOKUP_REQUEST)) {
                PLOOKUP_REQUEST request = (PLOOKUP_REQUEST)systemBuffer;
                PVOID process = NULL;
                
                // BUG: User can lookup any process including SYSTEM
                status = PsLookupProcessByProcessId(
                    request->ProcessId,  // User-controlled!
                    &process
                );
                
                if (NT_SUCCESS(status) && process) {
                    // Even worse: Return the process object to user
                    request->ProcessObject = process;
                    info = sizeof(LOOKUP_REQUEST);
                    
                    DbgPrint("Looked up PID %p, got process %p\n", 
                            request->ProcessId, process);
                    
                    // This process object could be used for token stealing!
                }
            }
            break;
        }
        
        case IOCTL_OPEN_PROCESS_DANGEROUS:
        {
            // VULNERABILITY: Open process with dangerous access rights
            if (inputLength >= sizeof(OPEN_REQUEST)) {
                POPEN_REQUEST request = (POPEN_REQUEST)systemBuffer;
                HANDLE processHandle = NULL;
                
                // BUG: User specifies both PID and access rights!
                // Could open SYSTEM process with PROCESS_ALL_ACCESS
                CLIENT_ID clientId;
                clientId.UniqueProcess = request->ProcessId;
                clientId.UniqueThread = NULL;
                
                status = ZwOpenProcess(
                    &processHandle,
                    request->DesiredAccess,  // User-controlled access mask!
                    NULL,
                    &clientId               // User-controlled PID!
                );
                
                if (NT_SUCCESS(status)) {
                    request->ProcessHandle = processHandle;
                    info = sizeof(OPEN_REQUEST);
                    
                    // Check if dangerous access was requested
                    if (request->DesiredAccess & PROCESS_ALL_ACCESS) {
                        DbgPrint("CRITICAL: Opened PID %p with PROCESS_ALL_ACCESS!\n",
                                request->ProcessId);
                    }
                    if (request->DesiredAccess & PROCESS_VM_WRITE) {
                        DbgPrint("WARNING: Opened PID %p with VM_WRITE access!\n",
                                request->ProcessId);
                    }
                }
            }
            break;
        }
        
        case IOCTL_DEREF_TAINTED_OBJECT:
        {
            // VULNERABILITY: Dereference user-controlled object
            if (inputLength >= sizeof(PVOID)) {
                PVOID* objectPtr = (PVOID*)systemBuffer;
                
                // BUG: Dereferencing user-provided pointer!
                // Could cause reference counting issues
                ObDereferenceObject(*objectPtr);  // User-controlled!
                
                DbgPrint("Dereferenced object %p from user\n", *objectPtr);
            }
            break;
        }
        
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
    
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return status;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\ProcessTest");
    IoDeleteSymbolicLink(&symbolicLink);
    
    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\ProcessTest");
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\ProcessTest");
    PDEVICE_OBJECT deviceObject = NULL;
    NTSTATUS status;
    
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
    
    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }
    
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    DriverObject->DriverUnload = DriverUnload;
    
    return STATUS_SUCCESS;
}