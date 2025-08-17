/*
 * PROPER Windows driver structure for testing
 * This follows the actual Windows Driver Model
 */

#include <stdint.h>
#include <string.h>

// Windows types
typedef void* PVOID;
typedef uint32_t ULONG;
typedef int NTSTATUS;
#define STATUS_SUCCESS 0

// IRP Major Function codes
#define IRP_MJ_DEVICE_CONTROL 0x0E

// Driver Object structure (simplified but correct offsets)
typedef struct _DRIVER_OBJECT {
    uint16_t Type;
    uint16_t Size;
    PVOID DeviceObject;
    uint32_t Flags;
    PVOID DriverStart;
    uint32_t DriverSize;
    PVOID DriverSection;
    PVOID DriverExtension;
    PVOID DriverName;
    PVOID HardwareDatabase;
    PVOID FastIoDispatch;
    PVOID DriverInit;
    PVOID DriverStartIo;
    PVOID DriverUnload;
    PVOID MajorFunction[28];  // IRP_MJ_MAXIMUM_FUNCTION + 1
} DRIVER_OBJECT, *PDRIVER_OBJECT;

// IRP structure
typedef struct _IRP {
    uint16_t Type;
    uint16_t Size;
    PVOID MdlAddress;
    uint32_t Flags;
    union {
        PVOID SystemBuffer;
    } AssociatedIrp;
    PVOID IoStatus;
    char RequestorMode;
    uint8_t PendingReturned;
    uint8_t StackCount;
    uint8_t CurrentLocation;
    uint8_t Cancel;
    // Simplified - we need Tail.Overlay.CurrentStackLocation
    char padding[0x40];
    PVOID CurrentStackLocation;
    PVOID UserBuffer;
} IRP, *PIRP;

// IO_STACK_LOCATION structure
typedef struct _IO_STACK_LOCATION {
    uint8_t MajorFunction;
    uint8_t MinorFunction;
    uint8_t Flags;
    uint8_t Control;
    union {
        struct {
            ULONG OutputBufferLength;
            ULONG InputBufferLength;
            ULONG IoControlCode;
            PVOID Type3InputBuffer;
        } DeviceIoControl;
    } Parameters;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;

// Get current stack location from IRP
PIO_STACK_LOCATION IoGetCurrentIrpStackLocation(PIRP Irp) {
    // In real driver, this would be: Irp->Tail.Overlay.CurrentStackLocation
    // For our test, assume it's at a fixed offset
    return (PIO_STACK_LOCATION)((char*)Irp + 0xB8);
}

// IOCTL Handler - THE ACTUAL VULNERABLE CODE
__declspec(dllexport)
NTSTATUS DriverDispatch(PVOID DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    
    // Only handle IOCTL requests
    if (stack->MajorFunction != IRP_MJ_DEVICE_CONTROL) {
        return STATUS_SUCCESS;
    }
    
    ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
    PVOID SystemBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG InputLength = stack->Parameters.DeviceIoControl.InputBufferLength;
    
    // VULNERABILITY 1: Stack buffer overflow
    if (ioctl == 0x222000) {
        char buffer[32];
        // BUG: No bounds check!
        memcpy(buffer, SystemBuffer, InputLength);  // OVERFLOW if InputLength > 32!
    }
    
    // VULNERABILITY 2: Null pointer dereference
    if (ioctl == 0x222004) {
        if (InputLength == 0) {
            // BUG: Using SystemBuffer without checking if it's NULL!
            *(ULONG*)SystemBuffer = 0x41414141;  // NULL DEREF!
        }
    }
    
    // VULNERABILITY 3: Integer overflow
    if (ioctl == 0x222008) {
        ULONG* params = (ULONG*)SystemBuffer;
        ULONG size = params[0];
        ULONG count = params[1];
        ULONG total = size * count;  // INTEGER OVERFLOW!
        
        // This would cause heap overflow if we actually allocated
        // For testing, just use the overflowed value
        if (total < size || total < count) {
            // Overflow detected (but we'd miss this check)
        }
    }
    
    return STATUS_SUCCESS;
}

// Driver Entry Point - PROPERLY SETS UP DISPATCH TABLE
__declspec(dllexport)
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PVOID RegistryPath) {
    // THIS IS THE KEY: Set the IRP_MJ_DEVICE_CONTROL handler
    // This is what IOCTLance is looking for!
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PVOID)DriverDispatch;
    
    // Also set other common handlers to the same function
    DriverObject->MajorFunction[0] = (PVOID)DriverDispatch;  // IRP_MJ_CREATE
    DriverObject->MajorFunction[2] = (PVOID)DriverDispatch;  // IRP_MJ_CLOSE
    
    return STATUS_SUCCESS;
}