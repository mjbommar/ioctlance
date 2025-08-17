/*
 * Proper WDM (Windows Driver Model) driver for IOCTLance testing
 * This matches what IOCTLance expects from analyzing real drivers like RtDashPt.sys
 */

#include <stdint.h>
#include <string.h>

typedef void* PVOID;
typedef uint32_t ULONG;
typedef int32_t NTSTATUS;
typedef struct _DEVICE_OBJECT *PDEVICE_OBJECT;

#define STATUS_SUCCESS 0
#define IRP_MJ_CREATE 0x00
#define IRP_MJ_CLOSE 0x02  
#define IRP_MJ_DEVICE_CONTROL 0x0E

// Correct DRIVER_OBJECT layout for Windows x64
typedef struct _DRIVER_OBJECT {
    uint16_t Type;                          // 0x00
    uint16_t Size;                          // 0x02
    uint32_t padding1;                      // 0x04
    PDEVICE_OBJECT DeviceObject;            // 0x08
    uint32_t Flags;                         // 0x10
    uint32_t padding2;                      // 0x14
    PVOID DriverStart;                      // 0x18
    uint32_t DriverSize;                    // 0x20
    uint32_t padding3;                      // 0x24
    PVOID DriverSection;                    // 0x28
    PVOID DriverExtension;                  // 0x30
    PVOID DriverName;                       // 0x38
    PVOID HardwareDatabase;                 // 0x40
    PVOID FastIoDispatch;                   // 0x48
    PVOID DriverInit;                       // 0x50
    PVOID DriverStartIo;                    // 0x58
    PVOID DriverUnload;                     // 0x60
    PVOID MajorFunction[28];                // 0x68 - This is at offset 0x70 on x64!
} DRIVER_OBJECT, *PDRIVER_OBJECT;

// IRP structure
typedef struct _IRP {
    int16_t Type;
    uint16_t Size;
    uint32_t padding1;
    PVOID MdlAddress;
    uint32_t Flags;
    uint32_t padding2;
    union {
        struct {
            PVOID SystemBuffer;
            uint32_t padding[2];
        } s1;
    } AssociatedIrp;
    char padding3[0x30];
    char RequestorMode;
    uint8_t PendingReturned;
    char StackCount;
    char CurrentLocation;
    uint8_t Cancel;
    uint8_t CancelIrql;
    char ApcEnvironment;
    uint8_t AllocationFlags;
    char padding4[0x10];
    PVOID UserBuffer;
    char padding5[0x30];
    struct {
        union {
            struct {
                PVOID CurrentStackLocation;
            } s2;
        } Overlay;
    } Tail;
} IRP, *PIRP;

// IO_STACK_LOCATION
typedef struct _IO_STACK_LOCATION {
    uint8_t MajorFunction;
    uint8_t MinorFunction;
    uint8_t Flags;
    uint8_t Control;
    uint32_t padding;
    union {
        struct {
            ULONG OutputBufferLength;
            ULONG padding1;
            ULONG InputBufferLength;
            ULONG padding2;
            ULONG IoControlCode;
            uint32_t padding3;
            PVOID Type3InputBuffer;
        } DeviceIoControl;
        char padding[32];
    } Parameters;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;

// Get stack location - simplified
PIO_STACK_LOCATION IoGetCurrentIrpStackLocation(PIRP Irp) {
    // In a real driver this calculates from CurrentLocation
    // For testing, use a fixed offset that IOCTLance might expect
    return (PIO_STACK_LOCATION)((char*)Irp + 0xB8);
}

// The IOCTL dispatch routine - CONTAINS VULNERABILITIES
__declspec(dllexport)
NTSTATUS DriverIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    
    // Check if this is a device control request
    if (irpSp->MajorFunction != IRP_MJ_DEVICE_CONTROL) {
        Irp->AssociatedIrp.s1.SystemBuffer = 0;
        return STATUS_SUCCESS;
    }
    
    ULONG ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    PVOID systemBuffer = Irp->AssociatedIrp.s1.SystemBuffer;
    ULONG inputLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    
    // Process different IOCTL codes
    switch (ioControlCode) {
        case 0x222000: {
            // VULNERABILITY: Stack buffer overflow
            char localBuffer[32];
            if (systemBuffer && inputLength > 0) {
                // BUG: No bounds check! Can overflow if inputLength > 32
                memcpy(localBuffer, systemBuffer, inputLength);
            }
            break;
        }
        
        case 0x222004: {
            // VULNERABILITY: Null pointer dereference
            if (inputLength == 0) {
                // BUG: Writing to systemBuffer without checking if NULL
                *(ULONG*)systemBuffer = 0x41414141;
            }
            break;
        }
        
        case 0x222008: {
            // VULNERABILITY: Integer overflow in size calculation
            if (systemBuffer && inputLength >= 8) {
                ULONG* params = (ULONG*)systemBuffer;
                ULONG count = params[0];
                ULONG size = params[1];
                ULONG total = count * size;  // Can overflow!
                
                // Would use 'total' for allocation...
                if (total != 0) {
                    // Pretend to use it
                    volatile ULONG dummy = total;
                }
            }
            break;
        }
        
        case 0x22200C: {
            // VULNERABILITY: Arbitrary write
            if (systemBuffer && inputLength >= 12) {
                ULONG* params = (ULONG*)systemBuffer;
                PVOID* addr = (PVOID*)(params[0]);  // User-controlled address
                ULONG value = params[2];
                
                // BUG: Writing to user-controlled address!
                *addr = (PVOID)value;
            }
            break;
        }
    }
    
    return STATUS_SUCCESS;
}

// Driver entry point - SETS UP DISPATCH TABLE PROPERLY
__declspec(dllexport)
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PVOID RegistryPath) {
    // Set up the dispatch routines
    // This is what IOCTLance is looking for!
    
    // Set IRP_MJ_DEVICE_CONTROL handler at the correct offset
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PVOID)DriverIoControl;
    
    // Also set CREATE and CLOSE for completeness
    DriverObject->MajorFunction[IRP_MJ_CREATE] = (PVOID)DriverIoControl;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = (PVOID)DriverIoControl;
    
    return STATUS_SUCCESS;
}