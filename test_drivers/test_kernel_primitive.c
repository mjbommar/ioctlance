/*
 * test_kernel_primitive.c - Test driver for kernel exploitation primitives
 * 
 * This driver demonstrates arbitrary increment/decrement and bit operation
 * primitives that should be detected by the KernelPrimitiveDetector.
 */

#include <ntddk.h>

// Device name for our test driver
#define DEVICE_NAME L"\\Device\\KernelPrimitiveTest"
#define SYMLINK_NAME L"\\??\\KernelPrimitiveTest"

// IOCTL codes for different primitive scenarios
#define IOCTL_ARBITRARY_INCREMENT  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_ARBITRARY_DECREMENT  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_ARBITRARY_OR         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x903, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_ARBITRARY_AND        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x904, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_ARBITRARY_XOR        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x905, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_INTERLOCKED_OPS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x906, METHOD_NEITHER, FILE_ANY_ACCESS)

// Structure for user input
typedef struct _PRIMITIVE_INPUT {
    PVOID TargetAddress;    // User-controlled target address
    ULONG Value;            // Value for operations
    ULONG Operation;        // Operation type
} PRIMITIVE_INPUT, *PPRIMITIVE_INPUT;

// Forward declarations
DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH CreateClose;
DRIVER_DISPATCH DeviceIoControl;

// Global variable for demonstration
volatile LONG g_RefCount = 0;

// Vulnerability: Arbitrary increment at user-controlled address
NTSTATUS ArbitraryIncrement(PVOID UserBuffer, ULONG BufferLength) {
    if (BufferLength >= sizeof(PRIMITIVE_INPUT)) {
        PPRIMITIVE_INPUT input = (PPRIMITIVE_INPUT)UserBuffer;
        
        // VULNERABILITY: Incrementing at user-controlled address
        if (input->TargetAddress) {
            // Direct increment - arbitrary write primitive
            (*(PULONG)input->TargetAddress)++;  // BAD: User controls address
            
            // Also vulnerable with different sizes
            if (input->Value == 1) {
                (*(PUCHAR)input->TargetAddress)++;  // Byte increment
            } else if (input->Value == 2) {
                (*(PUSHORT)input->TargetAddress)++;  // Word increment
            } else {
                (*(PULONG)input->TargetAddress) += input->Value;  // Arbitrary add
            }
        }
    }
    return STATUS_SUCCESS;
}

// Vulnerability: Arbitrary decrement at user-controlled address
NTSTATUS ArbitraryDecrement(PVOID UserBuffer, ULONG BufferLength) {
    if (BufferLength >= sizeof(PRIMITIVE_INPUT)) {
        PPRIMITIVE_INPUT input = (PPRIMITIVE_INPUT)UserBuffer;
        
        // VULNERABILITY: Decrementing at user-controlled address
        if (input->TargetAddress) {
            // Direct decrement - can be used for refcount attacks
            (*(PULONG)input->TargetAddress)--;  // BAD: User controls address
            
            // Decrement by value
            if (input->Value > 0) {
                (*(PULONG)input->TargetAddress) -= input->Value;
            }
            
            // This could target reference counts, leading to UAF
            DbgPrint("Decremented value at %p\n", input->TargetAddress);
        }
    }
    return STATUS_SUCCESS;
}

// Vulnerability: Arbitrary OR operation
NTSTATUS ArbitraryOr(PVOID UserBuffer, ULONG BufferLength) {
    if (BufferLength >= sizeof(PRIMITIVE_INPUT)) {
        PPRIMITIVE_INPUT input = (PPRIMITIVE_INPUT)UserBuffer;
        
        // VULNERABILITY: OR operation at user-controlled address
        if (input->TargetAddress && input->Value) {
            // Arbitrary OR - can set specific bits
            (*(PULONG)input->TargetAddress) |= input->Value;  // BAD: Arbitrary bit set
            
            // This could be used to set privilege bits
            DbgPrint("OR operation at %p with 0x%X\n", input->TargetAddress, input->Value);
        }
    }
    return STATUS_SUCCESS;
}

// Vulnerability: Arbitrary AND operation
NTSTATUS ArbitraryAnd(PVOID UserBuffer, ULONG BufferLength) {
    if (BufferLength >= sizeof(PRIMITIVE_INPUT)) {
        PPRIMITIVE_INPUT input = (PPRIMITIVE_INPUT)UserBuffer;
        
        // VULNERABILITY: AND operation at user-controlled address
        if (input->TargetAddress) {
            // Arbitrary AND - can clear specific bits
            (*(PULONG)input->TargetAddress) &= input->Value;  // BAD: Arbitrary bit clear
            
            // This could be used to clear security flags
            DbgPrint("AND operation at %p with 0x%X\n", input->TargetAddress, input->Value);
        }
    }
    return STATUS_SUCCESS;
}

// Vulnerability: Arbitrary XOR operation
NTSTATUS ArbitraryXor(PVOID UserBuffer, ULONG BufferLength) {
    if (BufferLength >= sizeof(PRIMITIVE_INPUT)) {
        PPRIMITIVE_INPUT input = (PPRIMITIVE_INPUT)UserBuffer;
        
        // VULNERABILITY: XOR operation at user-controlled address
        if (input->TargetAddress && input->Value) {
            // Arbitrary XOR - can flip specific bits
            (*(PULONG)input->TargetAddress) ^= input->Value;  // BAD: Arbitrary bit flip
            
            // XOR is particularly powerful for bit manipulation
            DbgPrint("XOR operation at %p with 0x%X\n", input->TargetAddress, input->Value);
        }
    }
    return STATUS_SUCCESS;
}

// Vulnerability: Interlocked operations with user-controlled address
NTSTATUS InterlockedOperations(PVOID UserBuffer, ULONG BufferLength) {
    if (BufferLength >= sizeof(PRIMITIVE_INPUT)) {
        PPRIMITIVE_INPUT input = (PPRIMITIVE_INPUT)UserBuffer;
        
        // VULNERABILITY: Interlocked operations at user-controlled address
        if (input->TargetAddress) {
                switch (input->Operation) {
                    case 1:
                        // VULNERABILITY: InterlockedIncrement with user address
                        InterlockedIncrement((PLONG)input->TargetAddress);  // BAD
                        break;
                    
                    case 2:
                        // VULNERABILITY: InterlockedDecrement with user address
                        InterlockedDecrement((PLONG)input->TargetAddress);  // BAD
                        break;
                    
                    case 3:
                        // VULNERABILITY: InterlockedAdd with user address
                        InterlockedAdd((PLONG)input->TargetAddress, input->Value);  // BAD
                        break;
                    
                    case 4:
                        // VULNERABILITY: InterlockedExchange with user address
                        InterlockedExchange((PLONG)input->TargetAddress, input->Value);  // BAD
                        break;
                    
                    case 5:
                        // VULNERABILITY: InterlockedOr with user address
                        InterlockedOr((PLONG)input->TargetAddress, input->Value);  // BAD
                        break;
                    
                    case 6:
                        // VULNERABILITY: InterlockedAnd with user address
                        InterlockedAnd((PLONG)input->TargetAddress, input->Value);  // BAD
                        break;
                    
                    case 7:
                        // VULNERABILITY: InterlockedXor with user address
                        InterlockedXor((PLONG)input->TargetAddress, input->Value);  // BAD
                        break;
                    
                    default:
                        // Safe operation on global variable
                        InterlockedIncrement(&g_RefCount);  // OK: Known safe address
                        break;
                }
                
                DbgPrint("Interlocked operation %lu at %p\n", input->Operation, input->TargetAddress);
        }
    }
    return STATUS_SUCCESS;
}

// Main IOCTL handler
NTSTATUS DeviceIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioControlCode = ioStack->Parameters.DeviceIoControl.IoControlCode;
    PVOID userBuffer = Irp->UserBuffer;  // Using METHOD_NEITHER for direct access
    ULONG inputLength = ioStack->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS status = STATUS_SUCCESS;
    
    switch (ioControlCode) {
        case IOCTL_ARBITRARY_INCREMENT:
            status = ArbitraryIncrement(userBuffer, inputLength);
            break;
            
        case IOCTL_ARBITRARY_DECREMENT:
            status = ArbitraryDecrement(userBuffer, inputLength);
            break;
            
        case IOCTL_ARBITRARY_OR:
            status = ArbitraryOr(userBuffer, inputLength);
            break;
            
        case IOCTL_ARBITRARY_AND:
            status = ArbitraryAnd(userBuffer, inputLength);
            break;
            
        case IOCTL_ARBITRARY_XOR:
            status = ArbitraryXor(userBuffer, inputLength);
            break;
            
        case IOCTL_INTERLOCKED_OPS:
            status = InterlockedOperations(userBuffer, inputLength);
            break;
            
        default:
            status = STATUS_INVALID_DEVICE_REQUEST;
            break;
    }
    
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    
    return status;
}

// Create/Close handler
NTSTATUS CreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

// Driver unload routine
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK_NAME);
    
    IoDeleteSymbolicLink(&symLink);
    if (DriverObject->DeviceObject) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

// Driver entry point
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName = RTL_CONSTANT_STRING(DEVICE_NAME);
    UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK_NAME);
    
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
        return status;
    }
    
    // Create symbolic link
    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        return status;
    }
    
    // Set up dispatch routines
    DriverObject->DriverUnload = DriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControl;
    
    DbgPrint("KernelPrimitiveTest driver loaded\n");
    
    return STATUS_SUCCESS;
}