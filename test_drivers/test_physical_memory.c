/*
 * Test driver for PhysicalMemoryDetector
 * Vulnerable to arbitrary physical memory mapping via MmMapIoSpace
 * Build with: x86_64-w64-mingw32-gcc -shared -nostdlib -fno-builtin -I/usr/share/mingw-w64/include/ddk -o test_physical_memory.sys test_physical_memory.c -Wl,--subsystem,native -Wl,--entry,DriverEntry
 */

#include <ntddk.h>

#define IOCTL_MAP_PHYSICAL   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MAP_SECTION    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_COPY_MEMORY    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _PHYS_MEM_REQUEST {
    PHYSICAL_ADDRESS PhysicalAddress;
    SIZE_T Size;
    PVOID VirtualAddress;
} PHYS_MEM_REQUEST, *PPHYS_MEM_REQUEST;

typedef struct _COPY_MEM_REQUEST {
    PVOID TargetAddress;
    PVOID SourceAddress;
    SIZE_T Size;
} COPY_MEM_REQUEST, *PCOPY_MEM_REQUEST;

// MmMapIoSpace and MmUnmapIoSpace are already declared in ntddk.h
// MmCopyMemory may not be available in all versions

NTSTATUS IoctlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    
    switch(ioctl) {
        case IOCTL_MAP_PHYSICAL: {
            PPHYS_MEM_REQUEST request = (PPHYS_MEM_REQUEST)buffer;
            PVOID mappedAddress;
            
            // VULNERABILITY: User controls physical address and size
            mappedAddress = MmMapIoSpace(
                request->PhysicalAddress,  // User-controlled physical address
                request->Size,              // User-controlled size
                MmNonCached
            );
            
            if (mappedAddress) {
                // Return mapped virtual address to user
                request->VirtualAddress = mappedAddress;
                status = STATUS_SUCCESS;
                
                // In real exploit, attacker would read/write here
                // For testing, just unmap
                MmUnmapIoSpace(mappedAddress, request->Size);
            }
            break;
        }
        
        case IOCTL_MAP_SECTION: {
            HANDLE sectionHandle = NULL;
            PVOID baseAddress = NULL;
            SIZE_T viewSize = ((PPHYS_MEM_REQUEST)buffer)->Size;
            LARGE_INTEGER sectionOffset;
            OBJECT_ATTRIBUTES objAttr;
            
            sectionOffset.QuadPart = ((PPHYS_MEM_REQUEST)buffer)->PhysicalAddress.QuadPart;
            
            // Create section from user input
            InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
            
            // VULNERABILITY: User controls section parameters
            status = ZwMapViewOfSection(
                sectionHandle,           // Potentially tainted handle
                NtCurrentProcess(),
                &baseAddress,            // User-influenced
                0,
                0,
                &sectionOffset,          // User-controlled offset
                &viewSize,               // User-controlled size
                ViewShare,
                0,
                PAGE_READWRITE
            );
            break;
        }
        
        case IOCTL_COPY_MEMORY: {
            PCOPY_MEM_REQUEST request = (PCOPY_MEM_REQUEST)buffer;
            
            // VULNERABILITY: User controls source and target addresses
            // Simplified version using RtlCopyMemory (memcpy)
            // WARNING: This is vulnerable and will crash if addresses are invalid!
            RtlCopyMemory(
                request->TargetAddress,  // User-controlled target
                request->SourceAddress,  // User-controlled source
                request->Size            // User-controlled size
            );
            status = STATUS_SUCCESS;
            break;
        }
    }
    
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = (status == STATUS_SUCCESS) ? stack->Parameters.DeviceIoControl.OutputBufferLength : 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING DeviceName;
    
    RtlInitUnicodeString(&DeviceName, L"\\Device\\VulnPhysMem");
    IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
    
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlHandler;
    
    return STATUS_SUCCESS;
}