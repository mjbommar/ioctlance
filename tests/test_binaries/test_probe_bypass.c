/*
 * IOCTLance Test Driver - ProbeForRead/Write Bypass Vulnerabilities
 * For testing ProbeBypassDetector
 * Built with mingw-w64 + DDK headers
 */

#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DeviceControl;
DRIVER_DISPATCH CreateClose;

// IOCTL codes for testing different vulnerability patterns
#define IOCTL_PROBE_ZERO_LENGTH      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x910, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_PROBE_SIZE_MISMATCH    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x911, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_PROBE_DOUBLE_FETCH     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x912, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_PROBE_KERNEL_ADDR      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x913, METHOD_NEITHER, FILE_ANY_ACCESS)

// Note: ProbeForRead and ProbeForWrite are declared in ntddk.h
// We'll use the declarations from there and let the linker handle it

typedef struct _USER_REQUEST {
    PVOID UserBuffer;
    SIZE_T BufferSize;
    ULONG Value;
} USER_REQUEST, *PUSER_REQUEST;

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
    
    PVOID userBuffer = irpSp->Parameters.DeviceIoControl.Type3InputBuffer;
    ULONG inputLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    
    switch (ioControlCode) {
        case IOCTL_PROBE_ZERO_LENGTH:
        {
            // VULNERABILITY: Zero-length probe bypass (MS08-066 style)
            if (inputLength >= sizeof(USER_REQUEST)) {
                PUSER_REQUEST request = (PUSER_REQUEST)userBuffer;
                
                // BUG: Probe with length from user - could be 0!
                ProbeForRead(request->UserBuffer, request->BufferSize, 1);
                
                // If BufferSize was 0, probe does nothing!
                // Now we read without validation
                if (request->UserBuffer) {
                    ULONG value = *(PULONG)request->UserBuffer;  // Unvalidated read!
                    DbgPrint("Read value: 0x%x\n", value);
                }
            }
            break;
        }
        
        case IOCTL_PROBE_SIZE_MISMATCH:
        {
            // VULNERABILITY: Probe size doesn't match actual access
            if (inputLength >= sizeof(USER_REQUEST)) {
                PUSER_REQUEST request = (PUSER_REQUEST)userBuffer;
                
                // BUG: Probe for 4 bytes but copy more!
                ProbeForRead(request->UserBuffer, sizeof(ULONG), 1);
                
                // Copy using user-controlled size instead!
                CHAR localBuffer[256];
                RtlCopyMemory(localBuffer, request->UserBuffer, 
                             request->BufferSize);  // Could be > sizeof(ULONG)!
                
                DbgPrint("Copied %llu bytes (only probed %lu)\n", 
                        (ULONGLONG)request->BufferSize, sizeof(ULONG));
            }
            break;
        }
        
        case IOCTL_PROBE_DOUBLE_FETCH:
        {
            // VULNERABILITY: TOCTOU - Double fetch from user memory
            if (inputLength >= sizeof(USER_REQUEST)) {
                PUSER_REQUEST request = (PUSER_REQUEST)userBuffer;
                
                // First fetch - check the size
                ProbeForRead(request->UserBuffer, sizeof(SIZE_T), 1);
                SIZE_T size = *(PSIZE_T)request->UserBuffer;
                
                if (size <= 256) {
                    // BUG: TOCTOU - user can change the value between checks!
                    CHAR localBuffer[256];
                    
                    // Second fetch - use the size (could have changed!)
                    SIZE_T copySize = *(PSIZE_T)request->UserBuffer;
                    RtlCopyMemory(localBuffer, 
                                 (PUCHAR)request->UserBuffer + sizeof(SIZE_T),
                                 copySize);  // Race condition!
                    
                    DbgPrint("Double fetch vulnerability triggered\n");
                }
            }
            break;
        }
        
        case IOCTL_PROBE_KERNEL_ADDR:
        {
            // VULNERABILITY: ProbeForWrite with kernel address
            if (inputLength >= sizeof(USER_REQUEST)) {
                PUSER_REQUEST request = (PUSER_REQUEST)userBuffer;
                
                // BUG: User controls the address - could be kernel!
                ProbeForWrite(request->UserBuffer, request->BufferSize, 1);
                
                // ProbeForWrite should fail for kernel addresses
                // but what if user tricks us with 0xFFFF... addresses?
                if (request->UserBuffer) {
                    *(PULONG)request->UserBuffer = 0x41414141;
                    DbgPrint("Wrote to address %p\n", request->UserBuffer);
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
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\ProbeTest");
    IoDeleteSymbolicLink(&symbolicLink);
    
    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\ProbeTest");
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\ProbeTest");
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