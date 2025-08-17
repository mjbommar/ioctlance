/*
 * IOCTLance Test Driver - Built with mingw-w64-dpp
 * Contains intentional vulnerabilities for testing
 */

#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DeviceControl;
DRIVER_DISPATCH CreateClose;

#define IOCTL_TEST_BUFFER_OVERFLOW  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TEST_NULL_DEREF       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TEST_INTEGER_OVERFLOW CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_TEST_ARBITRARY_WRITE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)

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
        case IOCTL_TEST_BUFFER_OVERFLOW:
        {
            // VULNERABILITY: Stack buffer overflow
            CHAR localBuffer[32];
            DbgPrint("IOCTLance Test: Buffer overflow test (size=%lu)\n", inputLength);
            
            // BUG: No bounds check! Overflow if inputLength > 32
            if (systemBuffer && inputLength > 0) {
                RtlCopyMemory(localBuffer, systemBuffer, inputLength);
                // Use the buffer to prevent optimization
                localBuffer[0] = localBuffer[0] + 1;
            }
            break;
        }
        
        case IOCTL_TEST_NULL_DEREF:
        {
            // VULNERABILITY: Null pointer dereference
            DbgPrint("IOCTLance Test: Null pointer test\n");
            
            if (inputLength == 0) {
                // BUG: Using potentially NULL systemBuffer
                *(PULONG)systemBuffer = 0x41414141;
            }
            break;
        }
        
        case IOCTL_TEST_INTEGER_OVERFLOW:
        {
            // VULNERABILITY: Integer overflow in allocation
            DbgPrint("IOCTLance Test: Integer overflow test\n");
            
            if (systemBuffer && inputLength >= 8) {
                PULONG params = (PULONG)systemBuffer;
                ULONG count = params[0];
                ULONG size = params[1];
                
                // BUG: Can overflow!
                ULONG total = count * size;
                
                // Would allocate with overflowed size
                if (total < 0x10000) {
                    PVOID buffer = ExAllocatePool(NonPagedPool, total);
                    if (buffer) {
                        // Use original values - buffer overflow!
                        for (ULONG i = 0; i < count && i < 100; i++) {
                            RtlFillMemory((PCHAR)buffer + (i * size), size, 0x41);
                        }
                        ExFreePool(buffer);
                    }
                }
            }
            break;
        }
        
        case IOCTL_TEST_ARBITRARY_WRITE:
        {
            // VULNERABILITY: Arbitrary kernel write (METHOD_NEITHER)
            DbgPrint("IOCTLance Test: Arbitrary write test\n");
            
            PVOID inputBuffer = irpSp->Parameters.DeviceIoControl.Type3InputBuffer;
            if (inputBuffer && inputLength >= 12) {
                PULONG params = (PULONG)inputBuffer;
                PVOID* targetAddr = (PVOID*)(ULONG_PTR)params[0];
                ULONG value = params[2];
                
                // BUG: Writing to user-controlled address!
                *targetAddr = (PVOID)(ULONG_PTR)value;
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

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\IOCTLanceTest");
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\IOCTLanceTest");
    
    DbgPrint("IOCTLance Test Driver: Loading...\n");
    
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
        DbgPrint("IOCTLance Test Driver: Failed to create device (0x%08X)\n", status);
        return status;
    }
    
    // Create symbolic link
    status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        DbgPrint("IOCTLance Test Driver: Failed to create symbolic link (0x%08X)\n", status);
        IoDeleteDevice(deviceObject);
        return status;
    }
    
    // Set up dispatch routines
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
    DriverObject->DriverUnload = DriverUnload;
    
    DbgPrint("IOCTLance Test Driver: Loaded successfully\n");
    DbgPrint("IOCTLance Test Driver: DeviceControl handler at %p\n", DeviceControl);
    
    return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\IOCTLanceTest");
    
    DbgPrint("IOCTLance Test Driver: Unloading...\n");
    
    IoDeleteSymbolicLink(&symbolicLink);
    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
    
    DbgPrint("IOCTLance Test Driver: Unloaded\n");
}