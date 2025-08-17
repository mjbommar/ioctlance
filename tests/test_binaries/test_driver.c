/*
 * Test driver with correct Windows x64 DRIVER_OBJECT layout for IOCTLance
 * Contains intentional vulnerabilities for detector validation
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// Windows types
typedef void* PVOID;
typedef uint32_t ULONG;
typedef int32_t NTSTATUS;
typedef uint16_t USHORT;
typedef struct _DEVICE_OBJECT *PDEVICE_OBJECT;

#define STATUS_SUCCESS 0
#define IRP_MJ_CREATE 0x00
#define IRP_MJ_CLOSE 0x02  
#define IRP_MJ_DEVICE_CONTROL 0x0E

// CRITICAL: Correct DRIVER_OBJECT layout for Windows x64
// MajorFunction array MUST be at offset 0x70!
typedef struct _DRIVER_OBJECT {
    USHORT Type;                         // 0x00 - Must be 0x0002
    USHORT Size;                         // 0x02 - Size of this structure
    PDEVICE_OBJECT DeviceObject;         // 0x08
    ULONG Flags;                         // 0x10
    PVOID DriverStart;                   // 0x18
    ULONG DriverSize;                    // 0x20
    PVOID DriverSection;                 // 0x28
    PVOID DriverExtension;               // 0x30
    PVOID DriverName;                    // 0x38
    PVOID HardwareDatabase;              // 0x40
    PVOID FastIoDispatch;                // 0x48
    PVOID DriverInit;                    // 0x50
    PVOID DriverStartIo;                 // 0x58
    PVOID DriverUnload;                  // 0x60
    PVOID Reserved;                      // 0x68 - padding to align MajorFunction
    PVOID MajorFunction[28];             // 0x70 - CRITICAL: Must be at offset 0x70!
} DRIVER_OBJECT, *PDRIVER_OBJECT;

// Simplified IRP structure
typedef struct _IRP {
    USHORT Type;
    USHORT Size;
    PVOID padding1;
    PVOID MdlAddress;
    ULONG Flags;
    ULONG padding2;
    union {
        struct {
            PVOID SystemBuffer;
        } s1;
    } AssociatedIrp;
    char padding3[0x48];  // Padding to get to stack location area
    PVOID CurrentStackLocation;  // Points to IO_STACK_LOCATION
    PVOID UserBuffer;
} IRP, *PIRP;

// IO_STACK_LOCATION
typedef struct _IO_STACK_LOCATION {
    uint8_t MajorFunction;
    uint8_t MinorFunction;
    uint8_t Flags;
    uint8_t Control;
    ULONG padding;
    union {
        struct {
            ULONG OutputBufferLength;
            ULONG padding1;
            ULONG InputBufferLength;
            ULONG padding2;
            ULONG IoControlCode;
            ULONG padding3;
            PVOID Type3InputBuffer;
        } DeviceIoControl;
    } Parameters;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;

// Helper to get current stack location
PIO_STACK_LOCATION IoGetCurrentIrpStackLocation(PIRP Irp) {
    // IOCTLance expects this at offset 0xB8 for analysis
    return (PIO_STACK_LOCATION)((char*)Irp + 0xB8);
}

// Format string functions for detector testing
__declspec(dllexport)
int sprintf(char* buffer, const char* format, ...) {
    // Stub implementation for testing
    strcpy(buffer, "test");
    return 4;
}

__declspec(dllexport)  
int swprintf(wchar_t* buffer, const wchar_t* format, ...) {
    // Stub for testing
    return 0;
}

// THE IOCTL HANDLER - Contains intentional vulnerabilities
__declspec(dllexport)
NTSTATUS DeviceIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    
    // Only process device control requests
    if (irpSp->MajorFunction != IRP_MJ_DEVICE_CONTROL) {
        return STATUS_SUCCESS;
    }
    
    ULONG ioControlCode = irpSp->Parameters.DeviceIoControl.IoControlCode;
    PVOID systemBuffer = Irp->AssociatedIrp.s1.SystemBuffer;
    ULONG inputLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;
    
    // Process IOCTL codes with vulnerabilities
    switch (ioControlCode) {
        case 0x222000: {
            // VULNERABILITY 1: Stack buffer overflow
            char localBuffer[32];
            if (systemBuffer && inputLength > 0) {
                // BUG: No bounds check! Overflow if inputLength > 32
                memcpy(localBuffer, systemBuffer, inputLength);
                
                // Use the buffer to prevent optimization
                volatile char dummy = localBuffer[0];
            }
            break;
        }
        
        case 0x222004: {
            // VULNERABILITY 2: Null pointer dereference
            if (inputLength == 0) {
                // BUG: Write to potentially NULL systemBuffer
                *(ULONG*)systemBuffer = 0x41414141;
            }
            break;
        }
        
        case 0x222008: {
            // VULNERABILITY 3: Integer overflow
            if (systemBuffer && inputLength >= 8) {
                ULONG* params = (ULONG*)systemBuffer;
                ULONG count = params[0];
                ULONG size = params[1];
                
                // BUG: Integer overflow in multiplication
                ULONG total = count * size;
                
                // Simulate allocation with overflowed size
                if (total != 0 && total < 0x10000) {
                    char* buffer = (char*)malloc(total);
                    if (buffer) {
                        // Use original values - could overflow buffer!
                        for (ULONG i = 0; i < count; i++) {
                            memset(buffer + (i * size), 0x41, size);
                        }
                        free(buffer);
                    }
                }
            }
            break;
        }
        
        case 0x22200C: {
            // VULNERABILITY 4: Format string
            if (systemBuffer && inputLength > 0) {
                char output[256];
                // BUG: User-controlled format string!
                sprintf(output, (char*)systemBuffer);
            }
            break;
        }
        
        case 0x222010: {
            // VULNERABILITY 5: Arbitrary write
            if (systemBuffer && inputLength >= 12) {
                ULONG* params = (ULONG*)systemBuffer;
                PVOID* targetAddr = (PVOID*)(uintptr_t)params[0];
                ULONG value = params[2];
                
                // BUG: Write to user-controlled address!
                *targetAddr = (PVOID)(uintptr_t)value;
            }
            break;
        }
        
        case 0x222014: {
            // VULNERABILITY 6: Double free
            static PVOID lastFreed = NULL;
            if (systemBuffer && inputLength >= 8) {
                PVOID* ptr = (PVOID*)systemBuffer;
                if (*ptr == lastFreed && lastFreed != NULL) {
                    // BUG: Double free!
                    free(*ptr);
                }
                free(*ptr);
                lastFreed = *ptr;
            }
            break;
        }
    }
    
    return STATUS_SUCCESS;
}

// DRIVER ENTRY POINT - Sets up dispatch table at correct offsets
__declspec(dllexport)
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PVOID RegistryPath) {
    // Initialize driver object fields
    DriverObject->Type = 0x0002;  // Driver object type
    DriverObject->Size = sizeof(DRIVER_OBJECT);
    
    // CRITICAL: Set IRP_MJ_DEVICE_CONTROL handler at index 0x0E
    // This will be at offset 0x70 + (0x0E * 8) = 0xE0 in the structure
    // IOCTLance sets a breakpoint at exactly this address!
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = (PVOID)DeviceIoControl;
    
    // Also set CREATE and CLOSE handlers
    DriverObject->MajorFunction[IRP_MJ_CREATE] = (PVOID)DeviceIoControl;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = (PVOID)DeviceIoControl;
    
    return STATUS_SUCCESS;
}

// Export table helper for mingw
#ifdef __GNUC__
__asm__(".section .drectve");
__asm__(".ascii \"-export:DriverEntry\"");
#endif