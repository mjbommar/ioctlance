#include <stdint.h>

// Minimal Windows driver structure for testing
typedef struct _IRP {
    void* Type;
    uint16_t Size;
    void* MdlAddress;
    uint32_t Flags;
    void* AssociatedIrp;
    void* IoStatus;
    char RequestorMode;
    char PendingReturned;
    char StackCount;
    char CurrentLocation;
    char Cancel;
    // ... simplified
} IRP, *PIRP;

typedef struct _IO_STACK_LOCATION {
    char MajorFunction;
    char MinorFunction;
    char Flags;
    char Control;
    union {
        struct {
            uint32_t OutputBufferLength;
            uint32_t InputBufferLength;
            uint32_t IoControlCode;
            void* Type3InputBuffer;
        } DeviceIoControl;
    } Parameters;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;

// IRP Major Function Codes
#define IRP_MJ_DEVICE_CONTROL 0x0E

// Simple IOCTL handler for testing
__declspec(dllexport) 
int DriverDispatch(void* DeviceObject, PIRP Irp) {
    // Get current stack location (simplified)
    PIO_STACK_LOCATION stack = (PIO_STACK_LOCATION)((char*)Irp + 0x100); // Fake offset
    
    if (stack->MajorFunction == IRP_MJ_DEVICE_CONTROL) {
        uint32_t ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
        void* buffer = Irp->AssociatedIrp;
        
        // Simple vulnerable patterns for testing
        switch(ioctl) {
            case 0x800: {
                // Pattern 1: Unchecked buffer copy
                char local[64];
                __builtin_memcpy(local, buffer, 256); // Stack overflow!
                break;
            }
            case 0x801: {
                // Pattern 2: Null pointer deref
                if (stack->Parameters.DeviceIoControl.InputBufferLength == 0) {
                    *(int*)buffer = 0x41414141; // Possible null deref
                }
                break;
            }
            case 0x802: {
                // Pattern 3: Integer overflow in allocation
                uint32_t size = *(uint32_t*)buffer;
                uint32_t count = *((uint32_t*)buffer + 1);
                void* alloc = __builtin_malloc(size * count); // Integer overflow
                __builtin_free(alloc);
                break;
            }
        }
    }
    return 0;
}

__declspec(dllexport)
int DriverEntry(void* DriverObject, void* RegistryPath) {
    // Set dispatch routine
    void** MajorFunction = (void**)((char*)DriverObject + 0x70); // Simplified offset
    MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverDispatch;
    return 0;
}
