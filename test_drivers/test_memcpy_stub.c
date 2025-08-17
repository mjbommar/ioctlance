/*
 * Test driver for controllable memcpy with minimal stubs
 * Build with: x86_64-w64-mingw32-gcc -shared -nostdlib -fno-builtin -I/usr/share/mingw-w64/include/ddk -o test_memcpy_stub.sys test_memcpy_stub.c -Wl,--subsystem,native -Wl,--entry,DriverEntry
 */

#include <ntddk.h>

#define IOCTL_ARBITRARY_READ  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_ARBITRARY_WRITE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _COPY_REQUEST {
    PVOID Address;      // User-controlled address
    ULONG Size;         // Size to copy
    UCHAR Data[256];    // Data buffer
} COPY_REQUEST, *PCOPY_REQUEST;

// Stub implementations for linking
void IoCompleteRequest(PIRP Irp, CCHAR PriorityBoost) {
    // Stub - angr will hook this
}

// Minimal memcpy stub
void* memcpy(void* dst, const void* src, size_t n) {
    // Stub - angr will hook this
    return dst;
}

NTSTATUS IoctlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
    PCOPY_REQUEST request = (PCOPY_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_SUCCESS;
    
    if (!request) {
        status = STATUS_INVALID_PARAMETER;
    } else {
        switch (ioctl) {
            case IOCTL_ARBITRARY_READ:
                // VULNERABILITY: User controls source address
                // Arbitrary kernel memory read primitive
                if (request->Size <= sizeof(request->Data)) {
                    memcpy(
                        request->Data,         // dst (output buffer)
                        request->Address,      // src (user-controlled!)
                        request->Size
                    );
                    Irp->IoStatus.Information = request->Size;
                }
                break;
                
            case IOCTL_ARBITRARY_WRITE:
                // VULNERABILITY: User controls destination address  
                // Arbitrary kernel memory write primitive
                if (request->Size <= sizeof(request->Data)) {
                    memcpy(
                        request->Address,      // dst (user-controlled!)
                        request->Data,         // src (input buffer)
                        request->Size
                    );
                }
                break;
                
            default:
                status = STATUS_INVALID_DEVICE_REQUEST;
                break;
        }
    }
    
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlHandler;
    return STATUS_SUCCESS;
}

// Minimal stub for unload
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    // Stub
}