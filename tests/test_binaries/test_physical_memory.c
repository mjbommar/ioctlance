/*
 * IOCTLance Test Driver - Physical Memory Mapping Vulnerabilities
 * For testing PhysicalMemoryDetector
 * Built with mingw-w64 + DDK headers
 */

#include <ntddk.h>

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH DeviceControl;
DRIVER_DISPATCH CreateClose;

// IOCTL codes for testing different vulnerability patterns
#define IOCTL_MAP_PHYSICAL_TAINTED_ADDR  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MAP_PHYSICAL_TAINTED_SIZE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_MAP_PHYSICAL_BOTH_TAINTED  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Simulated MmMapIoSpace for testing
PVOID MmMapIoSpace(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes, MEMORY_CACHING_TYPE CacheType)
{
    // In real driver, this would map physical memory
    // For testing, we just simulate the call
    DbgPrint("MmMapIoSpace called: Addr=%llx, Size=%llx\n", 
             PhysicalAddress.QuadPart, (ULONGLONG)NumberOfBytes);
    return (PVOID)0xDEADBEEF;
}

typedef struct _MAP_REQUEST {
    PHYSICAL_ADDRESS PhysicalAddress;
    SIZE_T NumberOfBytes;
    ULONG CacheType;
} MAP_REQUEST, *PMAP_REQUEST;

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
        case IOCTL_MAP_PHYSICAL_TAINTED_ADDR:
        {
            // VULNERABILITY: User controls physical address
            if (inputLength >= sizeof(MAP_REQUEST)) {
                PMAP_REQUEST request = (PMAP_REQUEST)systemBuffer;
                
                // BUG: Directly using user-controlled physical address!
                // This allows mapping arbitrary physical memory
                PVOID mappedAddr = MmMapIoSpace(
                    request->PhysicalAddress,  // User-controlled!
                    0x1000,                    // Fixed size
                    MmNonCached
                );
                
                DbgPrint("Mapped physical memory at %p\n", mappedAddr);
            }
            break;
        }
        
        case IOCTL_MAP_PHYSICAL_TAINTED_SIZE:
        {
            // VULNERABILITY: User controls mapping size
            if (inputLength >= sizeof(MAP_REQUEST)) {
                PMAP_REQUEST request = (PMAP_REQUEST)systemBuffer;
                PHYSICAL_ADDRESS fixedAddr;
                fixedAddr.QuadPart = 0x80000000;  // Fixed address
                
                // BUG: User-controlled size allows mapping huge regions!
                PVOID mappedAddr = MmMapIoSpace(
                    fixedAddr,
                    request->NumberOfBytes,    // User-controlled!
                    MmNonCached
                );
                
                DbgPrint("Mapped %llu bytes at %p\n", 
                        (ULONGLONG)request->NumberOfBytes, mappedAddr);
            }
            break;
        }
        
        case IOCTL_MAP_PHYSICAL_BOTH_TAINTED:
        {
            // VULNERABILITY: User controls both address and size
            if (inputLength >= sizeof(MAP_REQUEST)) {
                PMAP_REQUEST request = (PMAP_REQUEST)systemBuffer;
                
                // CRITICAL BUG: Complete control over physical memory mapping!
                // Attacker can map any physical memory region
                PVOID mappedAddr = MmMapIoSpace(
                    request->PhysicalAddress,  // User-controlled!
                    request->NumberOfBytes,    // User-controlled!
                    (MEMORY_CACHING_TYPE)request->CacheType
                );
                
                // Even worse: Let user read/write the mapped memory
                if (mappedAddr) {
                    // This would allow reading/writing physical memory
                    DbgPrint("User has full access to physical memory at %p\n", mappedAddr);
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
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\PhysMemTest");
    IoDeleteSymbolicLink(&symbolicLink);
    
    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\PhysMemTest");
    UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\PhysMemTest");
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