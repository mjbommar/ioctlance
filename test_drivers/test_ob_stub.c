/*
 * Test driver for ObOpenObjectByPointer with minimal stubs
 * Build with: x86_64-w64-mingw32-gcc -shared -nostdlib -fno-builtin -I/usr/share/mingw-w64/include/ddk -o test_ob_stub.sys test_ob_stub.c -Wl,--subsystem,native -Wl,--entry,DriverEntry
 */

#include <ntddk.h>

#define IOCTL_OPEN_OBJECT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _OBJECT_REQUEST {
    PVOID Object;
    ACCESS_MASK DesiredAccess;
    HANDLE ResultHandle;
} OBJECT_REQUEST, *POBJECT_REQUEST;

// Stub implementations for linking
void IoCompleteRequest(PIRP Irp, CCHAR PriorityBoost) {
    // Stub - angr will hook this
}

// Stub for ObOpenObjectByPointer - angr will hook this
NTSTATUS ObOpenObjectByPointer(
    PVOID Object,
    ULONG HandleAttributes,
    PVOID PassedAccessState,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectType,
    KPROCESSOR_MODE AccessMode,
    PHANDLE Handle
) {
    // Stub - angr will hook this
    return STATUS_SUCCESS;
}

NTSTATUS IoctlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
    POBJECT_REQUEST request = (POBJECT_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    
    if (ioctl == IOCTL_OPEN_OBJECT && request) {
        HANDLE handle = (HANDLE)0;
        
        // VULNERABILITY: User controls Object parameter
        status = ObOpenObjectByPointer(
            request->Object,              // User-controlled! Privilege escalation
            OBJ_KERNEL_HANDLE,           
            NULL,
            request->DesiredAccess ? request->DesiredAccess : PROCESS_ALL_ACCESS,
            NULL,                        
            KernelMode,
            &handle
        );
        
        if (NT_SUCCESS(status)) {
            request->ResultHandle = handle;
        }
    }
    
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
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