/*
 * Test driver for Use-After-Free (UAF) vulnerabilities
 * 
 * This driver demonstrates several UAF patterns:
 * 1. Classic UAF - free then use
 * 2. Double-free vulnerability
 * 3. UAF with function pointers
 */

#include <ntddk.h>

// IOCTL codes for testing
#define IOCTL_CLASSIC_UAF     CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA00, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_DOUBLE_FREE     CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA01, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_UAF_FUNC_PTR    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA02, METHOD_NEITHER, FILE_ANY_ACCESS)

// Structure with function pointer
typedef struct _OBJECT_DATA {
    ULONG Magic;
    PVOID Data;
    VOID (*ProcessFunc)(PVOID);
    ULONG Size;
} OBJECT_DATA, *POBJECT_DATA;

// Global pointer for demonstrating UAF
POBJECT_DATA g_Object = NULL;

VOID DefaultProcessFunc(PVOID Data)
{
    UNREFERENCED_PARAMETER(Data);
    DbgPrint("Processing data...\n");
}

NTSTATUS ProcessClassicUAF(PVOID UserBuffer, ULONG InputBufferLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    POBJECT_DATA object = NULL;
    PULONG userCommand;
    
    UNREFERENCED_PARAMETER(InputBufferLength);
    
    userCommand = (PULONG)UserBuffer;
    
    if (!userCommand) {
        return STATUS_INVALID_PARAMETER;
    }
        
        switch (*userCommand) {
            case 1:  // Allocate
                object = (POBJECT_DATA)ExAllocatePoolWithTag(NonPagedPool, sizeof(OBJECT_DATA), 'UAF1');
                if (object) {
                    object->Magic = 0xDEADBEEF;
                    object->ProcessFunc = DefaultProcessFunc;
                    object->Size = sizeof(OBJECT_DATA);
                    object->Data = NULL;
                    g_Object = object;
                    DbgPrint("Object allocated at %p\n", object);
                }
                break;
                
            case 2:  // Free
                if (g_Object) {
                    DbgPrint("Freeing object at %p\n", g_Object);
                    ExFreePoolWithTag(g_Object, 'UAF1');
                    // BUG: Not setting g_Object to NULL after free!
                    // g_Object = NULL;  // This line is intentionally commented out
                }
                break;
                
            case 3:  // Use
                if (g_Object) {
                    // VULNERABILITY: Use-After-Free - accessing freed memory
                    DbgPrint("Using object at %p\n", g_Object);
                    DbgPrint("Object magic: 0x%X\n", g_Object->Magic);
                    
                    // Even worse - calling function pointer from freed memory!
                    if (g_Object->ProcessFunc) {
                        g_Object->ProcessFunc(g_Object->Data);
                    }
                }
                break;
                
            default:
                status = STATUS_INVALID_PARAMETER;
                break;
        }
    
    return status;
}

NTSTATUS ProcessDoubleFree(PVOID UserBuffer, ULONG InputBufferLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    POBJECT_DATA object = NULL;
    PULONG userCommand;
    static POBJECT_DATA savedPointer = NULL;
    
    UNREFERENCED_PARAMETER(InputBufferLength);
    
    userCommand = (PULONG)UserBuffer;
    
    if (!userCommand) {
        return STATUS_INVALID_PARAMETER;
    }
        
        switch (*userCommand) {
            case 1:  // Allocate and save
                object = (POBJECT_DATA)ExAllocatePoolWithTag(NonPagedPool, sizeof(OBJECT_DATA), 'DBL2');
                if (object) {
                    object->Magic = 0xCAFEBABE;
                    savedPointer = object;
                    DbgPrint("Object allocated at %p\n", object);
                }
                break;
                
            case 2:  // First free
                if (savedPointer) {
                    DbgPrint("First free of object at %p\n", savedPointer);
                    ExFreePoolWithTag(savedPointer, 'DBL2');
                    // Not clearing savedPointer!
                }
                break;
                
            case 3:  // Second free (double-free)
                if (savedPointer) {
                    // VULNERABILITY: Double-free - freeing already freed memory
                    DbgPrint("Second free of object at %p (DOUBLE FREE!)\n", savedPointer);
                    ExFreePoolWithTag(savedPointer, 'DBL2');
                    savedPointer = NULL;
                }
                break;
                
            default:
                status = STATUS_INVALID_PARAMETER;
                break;
        }
    
    return status;
}

NTSTATUS ProcessUAFFuncPtr(PVOID UserBuffer, ULONG InputBufferLength)
{
    NTSTATUS status = STATUS_SUCCESS;
    POBJECT_DATA object = NULL;
    PULONG userCommand;
    static POBJECT_DATA funcObject = NULL;
    
    UNREFERENCED_PARAMETER(InputBufferLength);
    
    userCommand = (PULONG)UserBuffer;
    
    if (!userCommand) {
        return STATUS_INVALID_PARAMETER;
    }
        
        switch (*userCommand) {
            case 1:  // Allocate with function pointer
                object = (POBJECT_DATA)ExAllocatePoolWithTag(NonPagedPool, sizeof(OBJECT_DATA), 'FUNC');
                if (object) {
                    object->Magic = 0x41414141;
                    object->ProcessFunc = DefaultProcessFunc;
                    object->Data = ExAllocatePoolWithTag(NonPagedPool, 0x100, 'DATA');
                    object->Size = 0x100;
                    funcObject = object;
                    DbgPrint("Function object allocated at %p\n", object);
                }
                break;
                
            case 2:  // Free object but not data
                if (funcObject) {
                    DbgPrint("Freeing function object at %p\n", funcObject);
                    // Free the main object
                    ExFreePoolWithTag(funcObject, 'FUNC');
                    // BUG: Not freeing funcObject->Data (memory leak)
                    // BUG: Not clearing funcObject pointer
                }
                break;
                
            case 3:  // Use freed function pointer
                if (funcObject) {
                    // VULNERABILITY: UAF with function pointer - extremely dangerous!
                    // If attacker can control the freed memory, they can execute arbitrary code
                    DbgPrint("Calling function from freed object at %p\n", funcObject);
                    funcObject->ProcessFunc(funcObject->Data);
                }
                break;
                
            case 4:  // Write to freed object
                if (funcObject) {
                    // VULNERABILITY: Writing to freed memory
                    DbgPrint("Writing to freed object at %p\n", funcObject);
                    funcObject->Magic = 0xDEADC0DE;
                    funcObject->Size = 0x200;
                }
                break;
                
            default:
                status = STATUS_INVALID_PARAMETER;
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
        case IOCTL_CLASSIC_UAF:
            status = ProcessClassicUAF(inputBuffer, inputBufferLength);
            break;
            
        case IOCTL_DOUBLE_FREE:
            status = ProcessDoubleFree(inputBuffer, inputBufferLength);
            break;
            
        case IOCTL_UAF_FUNC_PTR:
            status = ProcessUAFFuncPtr(inputBuffer, inputBufferLength);
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
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\UAFTest");
    
    // Clean up any remaining allocations
    if (g_Object) {
        ExFreePoolWithTag(g_Object, 'UAF1');
        g_Object = NULL;
    }
    
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
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\UAFTest");
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\UAFTest");
    
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