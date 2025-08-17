/*
 * IOCTLance Test Driver - Double-Free and Use-After-Free Vulnerabilities
 * For testing DoubleFreeDetector
 * Built with mingw-w64 + DDK headers
 */

#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DeviceControl;
DRIVER_DISPATCH CreateClose;

// IOCTL codes for testing different vulnerability patterns
#define IOCTL_DOUBLE_FREE            CTL_CODE(FILE_DEVICE_UNKNOWN, 0x930, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_USE_AFTER_FREE         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x931, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FREE_TAINTED_PTR       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x932, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UAF_WRITE              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x933, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Note: Pool allocation APIs would normally be imported from ntoskrnl.exe
// For testing purposes, IOCTLance will hook these functions during analysis

typedef struct _ALLOC_REQUEST {
    ULONG Size;
    PVOID AllocatedPtr;  // Output
} ALLOC_REQUEST, *PALLOC_REQUEST;

typedef struct _FREE_REQUEST {
    PVOID PtrToFree;
} FREE_REQUEST, *PFREE_REQUEST;

typedef struct _UAF_REQUEST {
    PVOID Address;
    ULONG Value;
} UAF_REQUEST, *PUAF_REQUEST;

// Global pointers for demonstrating vulnerabilities
static PVOID g_allocatedBuffer = NULL;
static PVOID g_freedBuffer = NULL;

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
    ULONG outputLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    
    switch (ioControlCode) {
        case IOCTL_DOUBLE_FREE:
        {
            // VULNERABILITY: Double-free
            DbgPrint("Double-free vulnerability test\n");
            
            // Allocate a buffer
            PVOID buffer = ExAllocatePoolWithTag(NonPagedPool, 0x100, 'tseT');
            
            if (buffer) {
                // First free - legitimate
                ExFreePoolWithTag(buffer, 'tseT');
                DbgPrint("First free completed\n");
                
                // BUG: Second free of the same pointer - DOUBLE FREE!
                ExFreePoolWithTag(buffer, 'tseT');
                DbgPrint("VULNERABILITY: Double-free triggered!\n");
            }
            break;
        }
        
        case IOCTL_USE_AFTER_FREE:
        {
            // VULNERABILITY: Use-after-free
            DbgPrint("Use-after-free vulnerability test\n");
            
            // Allocate a buffer
            PVOID buffer = ExAllocatePool(NonPagedPool, 0x100);
            
            if (buffer) {
                // Store the pointer
                g_freedBuffer = buffer;
                
                // Free the buffer
                ExFreePool(buffer);
                DbgPrint("Buffer freed at %p\n", buffer);
                
                // BUG: Use the buffer after freeing - USE AFTER FREE!
                RtlZeroMemory(g_freedBuffer, 0x100);  // Writing to freed memory!
                DbgPrint("VULNERABILITY: Use-after-free triggered!\n");
                
                // Even worse: Read from freed memory
                ULONG value = *(PULONG)g_freedBuffer;
                DbgPrint("Read value 0x%x from freed memory\n", value);
            }
            break;
        }
        
        case IOCTL_FREE_TAINTED_PTR:
        {
            // VULNERABILITY: Free user-controlled pointer
            if (inputLength >= sizeof(FREE_REQUEST)) {
                PFREE_REQUEST request = (PFREE_REQUEST)systemBuffer;
                
                // BUG: Freeing user-provided pointer!
                // User can free any kernel memory
                ExFreePool(request->PtrToFree);  // User-controlled!
                
                DbgPrint("VULNERABILITY: Freed user-controlled ptr %p\n", 
                        request->PtrToFree);
            }
            break;
        }
        
        case IOCTL_UAF_WRITE:
        {
            // VULNERABILITY: Complex UAF with allocation tracking
            if (inputLength >= sizeof(UAF_REQUEST) && 
                outputLength >= sizeof(PVOID)) {
                
                PUAF_REQUEST request = (PUAF_REQUEST)systemBuffer;
                
                if (request->Address == NULL) {
                    // Step 1: Allocate and return pointer to user
                    g_allocatedBuffer = ExAllocatePoolWithTag(
                        NonPagedPool, 0x200, 'fauT'
                    );
                    
                    *(PVOID*)systemBuffer = g_allocatedBuffer;
                    info = sizeof(PVOID);
                    
                    DbgPrint("Allocated buffer at %p\n", g_allocatedBuffer);
                    
                } else if (request->Address == (PVOID)1) {
                    // Step 2: Free the allocation
                    if (g_allocatedBuffer) {
                        ExFreePoolWithTag(g_allocatedBuffer, 'fauT');
                        DbgPrint("Freed buffer at %p\n", g_allocatedBuffer);
                        // Note: g_allocatedBuffer still holds the pointer!
                    }
                    
                } else if (request->Address == (PVOID)2) {
                    // Step 3: BUG - Use after free!
                    if (g_allocatedBuffer) {
                        *(PULONG)g_allocatedBuffer = request->Value;
                        DbgPrint("VULNERABILITY: UAF write value 0x%x to %p\n",
                                request->Value, g_allocatedBuffer);
                    }
                    
                } else if (request->Address == (PVOID)3) {
                    // Step 4: BUG - Double free!
                    if (g_allocatedBuffer) {
                        ExFreePoolWithTag(g_allocatedBuffer, 'fauT');
                        DbgPrint("VULNERABILITY: Double-free of %p\n", 
                                g_allocatedBuffer);
                    }
                }
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
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\DoubleFreeTest");
    IoDeleteSymbolicLink(&symbolicLink);
    
    // Clean up any remaining allocations
    if (g_allocatedBuffer) {
        ExFreePool(g_allocatedBuffer);
        g_allocatedBuffer = NULL;
    }
    
    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\DoubleFreeTest");
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\DoubleFreeTest");
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