/*
 * test_format_string.c - Test driver for format string vulnerabilities
 * 
 * This driver demonstrates various format string vulnerabilities that should
 * be detected by the FormatStringDetector.
 */

#include <ntddk.h>

// Device name for our test driver
#define DEVICE_NAME L"\\Device\\FormatStringTest"
#define SYMLINK_NAME L"\\??\\FormatStringTest"

// IOCTL codes for different vulnerability scenarios
#define IOCTL_TAINTED_FORMAT    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DANGEROUS_SPEC     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DBGPRINT_VULN      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAFE_FORMAT        CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNICODE_FORMAT     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x805, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Forward declarations
DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH CreateClose;
DRIVER_DISPATCH DeviceIoControl;

// Vulnerable function: User-controlled format string to DbgPrint
VOID VulnerableSprintf(PVOID UserBuffer, ULONG BufferLength) {
    PCHAR formatString = (PCHAR)UserBuffer;
    
    // VULNERABILITY: Format string comes directly from user input
    // Using DbgPrint directly with user format (simpler, no sprintf needed)
    if (BufferLength > 0 && BufferLength < 256) {
        DbgPrint(formatString);  // BAD: User controls format string
    }
}

// Vulnerable function: Format string with dangerous patterns
VOID VulnerableDangerousSpecifiers(PVOID UserBuffer, ULONG BufferLength) {
    if (BufferLength >= 4) {
        PCHAR userFormat = (PCHAR)UserBuffer;
        
        // VULNERABILITY: Checking for dangerous patterns but still using user format
        // This demonstrates the detector should catch format strings with %n, %hn, etc.
        DbgPrint("Checking user format...\n");
        
        // Still vulnerable - using user-provided format
        DbgPrint(userFormat);  // CRITICAL: User format might contain %n
    }
}

// Vulnerable function: DbgPrint with user-controlled format
VOID VulnerableDbgPrint(PVOID UserBuffer, ULONG BufferLength) {
    if (BufferLength > 0 && BufferLength < 1024) {
        PCHAR formatString = (PCHAR)UserBuffer;
        
        // VULNERABILITY: DbgPrint with user-controlled format string
        DbgPrint(formatString);  // BAD: Direct user input as format
        
        // Also vulnerable with DbgPrintEx
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, formatString);
    }
}

// Vulnerable function: Multiple DbgPrint variants
VOID VulnerableRtlString(PVOID UserBuffer, ULONG BufferLength) {
    if (BufferLength > 0 && BufferLength < 256) {
        PCHAR formatString = (PCHAR)UserBuffer;
        
        // VULNERABILITY: KdPrint with user format
        KdPrint((formatString));  // BAD: User format
        
        DbgPrint("Used KdPrint with user format\n");
    }
}

// Safe function: Using constant format strings
VOID SafeFormatString(PVOID UserBuffer, ULONG BufferLength) {
    if (BufferLength >= sizeof(ULONG)) {
        ULONG userValue = *(PULONG)UserBuffer;
        
        // SAFE: Format string is constant, only data comes from user
        DbgPrint("User value: %u\n", userValue);  // OK: Constant format
        DbgPrint("Value: 0x%08X\n", userValue);    // OK: Constant format
    }
}

// Vulnerable function: Unicode format strings (simplified)
VOID VulnerableUnicodeFormat(PVOID UserBuffer, ULONG BufferLength) {
    if (BufferLength > sizeof(WCHAR)) {
        // For simplicity, just demonstrate the vulnerability pattern
        // The detector should catch user-controlled format strings
        DbgPrint("Would use unicode format from user buffer\n");
        
        // Simulate the vulnerability for detection
        PCHAR narrowFormat = (PCHAR)UserBuffer;
        if (BufferLength > 0) {
            DbgPrint(narrowFormat);  // Still vulnerable with narrow string
        }
    }
}

// Main IOCTL handler
NTSTATUS DeviceIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioControlCode = ioStack->Parameters.DeviceIoControl.IoControlCode;
    PVOID systemBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputLength = ioStack->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS status = STATUS_SUCCESS;
    
    switch (ioControlCode) {
        case IOCTL_TAINTED_FORMAT:
            VulnerableSprintf(systemBuffer, inputLength);
            break;
            
        case IOCTL_DANGEROUS_SPEC:
            VulnerableDangerousSpecifiers(systemBuffer, inputLength);
            break;
            
        case IOCTL_DBGPRINT_VULN:
            VulnerableDbgPrint(systemBuffer, inputLength);
            break;
            
        case IOCTL_SAFE_FORMAT:
            SafeFormatString(systemBuffer, inputLength);
            break;
            
        case IOCTL_UNICODE_FORMAT:
            VulnerableUnicodeFormat(systemBuffer, inputLength);
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
    
    DbgPrint("FormatStringTest driver loaded\n");
    
    return STATUS_SUCCESS;
}