/*
 * test_symlink_attack.c - Test driver for symlink and TOCTOU vulnerabilities
 * 
 * This driver demonstrates symbolic link race conditions and Time-of-Check-Time-of-Use
 * vulnerabilities that should be detected by the SymlinkAttackDetector.
 */

#include <ntddk.h>

// Device name for our test driver
#define DEVICE_NAME L"\\Device\\SymlinkAttackTest"
#define SYMLINK_NAME L"\\??\\SymlinkAttackTest"

// IOCTL codes for different vulnerability scenarios
#define IOCTL_TOCTOU_RACE         CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA01, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UNSAFE_SYMLINK      CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA02, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_PREDICTABLE_TEMP    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA03, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_FILE_CREATION_RACE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA04, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SAFE_FILE_OPEN      CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA05, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Forward declarations
DRIVER_UNLOAD DriverUnload;
DRIVER_DISPATCH CreateClose;
DRIVER_DISPATCH DeviceIoControl;

// Helper function to get file attributes (for TOCTOU demonstration)
NTSTATUS CheckFileExists(PUNICODE_STRING FilePath) {
    OBJECT_ATTRIBUTES objAttr;
    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    
    InitializeObjectAttributes(&objAttr, FilePath, 
                              OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                              NULL, NULL);
    
    // Check if file exists (TIME OF CHECK) - try to open it
    status = ZwOpenFile(&fileHandle, GENERIC_READ, &objAttr, &ioStatus,
                       FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE);
    
    if (NT_SUCCESS(status)) {
        ZwClose(fileHandle);
    }
    
    return status;
}

// Vulnerability: TOCTOU - Check file then use it
NTSTATUS VulnerableTOCTOU(PVOID UserBuffer, ULONG BufferLength) {
    UNICODE_STRING filePath;
    PWCHAR userPath = (PWCHAR)UserBuffer;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    
    if (BufferLength < sizeof(WCHAR) * 2) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    
    // Initialize path from user input
    RtlInitUnicodeString(&filePath, userPath);
    
    // VULNERABILITY: Classic TOCTOU pattern
    // TIME OF CHECK: Verify file is safe
    status = CheckFileExists(&filePath);
    if (NT_SUCCESS(status)) {
        DbgPrint("File exists, proceeding to open...\n");
        
        // Simulate some processing delay (makes race window larger)
        // In real vulnerable code, this might be validation logic
        for (int i = 0; i < 1000; i++) {
            // Processing...
        }
        
        // TIME OF USE: Open and write to file
        // Between check and use, attacker could replace file with symlink!
        InitializeObjectAttributes(&objAttr, &filePath,
                                  OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                                  NULL, NULL);
        
        status = ZwCreateFile(&fileHandle,
                            GENERIC_WRITE,
                            &objAttr,
                            &ioStatus,
                            NULL,
                            FILE_ATTRIBUTE_NORMAL,
                            0,
                            FILE_OPEN_IF,  // Opens existing or creates new
                            FILE_NON_DIRECTORY_FILE,
                            NULL,
                            0);
        
        if (NT_SUCCESS(status)) {
            // Write sensitive data
            CHAR data[] = "SENSITIVE_KERNEL_DATA";
            ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatus,
                       data, sizeof(data), NULL, NULL);
            ZwClose(fileHandle);
        }
    }
    
    return status;
}

// Vulnerability: Following symlinks without FILE_FLAG_OPEN_REPARSE_POINT
NTSTATUS VulnerableSymlinkFollow(PVOID UserBuffer, ULONG BufferLength) {
    UNICODE_STRING filePath;
    PWCHAR userPath = (PWCHAR)UserBuffer;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    
    if (BufferLength < sizeof(WCHAR) * 2) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    
    RtlInitUnicodeString(&filePath, userPath);
    InitializeObjectAttributes(&objAttr, &filePath,
                              OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                              NULL, NULL);
    
    // VULNERABILITY: Not using FILE_OPEN_REPARSE_POINT flag
    // This will follow symlinks, potentially accessing unintended files
    status = ZwCreateFile(&fileHandle,
                        GENERIC_READ | GENERIC_WRITE,
                        &objAttr,
                        &ioStatus,
                        NULL,
                        FILE_ATTRIBUTE_NORMAL,
                        0,
                        FILE_OPEN_IF,
                        FILE_NON_DIRECTORY_FILE,  // Missing FILE_OPEN_REPARSE_POINT!
                        NULL,
                        0);
    
    if (NT_SUCCESS(status)) {
        DbgPrint("Opened file (followed symlinks if present)\n");
        ZwClose(fileHandle);
    }
    
    return status;
}

// Vulnerability: Creating predictable temporary files
NTSTATUS VulnerablePredictableTemp(PVOID UserBuffer, ULONG BufferLength) {
    UNICODE_STRING tempPath;
    WCHAR tempFile[256];
    OBJECT_ATTRIBUTES objAttr;
    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    LARGE_INTEGER systemTime;
    
    // VULNERABILITY: Predictable temp file name
    // Using timestamp makes it guessable
    KeQuerySystemTime(&systemTime);
    swprintf(tempFile, L"\\SystemRoot\\Temp\\driver_temp_%lld.tmp", 
             systemTime.QuadPart);
    
    RtlInitUnicodeString(&tempPath, tempFile);
    InitializeObjectAttributes(&objAttr, &tempPath,
                              OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                              NULL, NULL);
    
    // VULNERABILITY: Creating temp file without exclusive access
    status = ZwCreateFile(&fileHandle,
                        GENERIC_WRITE,
                        &objAttr,
                        &ioStatus,
                        NULL,
                        FILE_ATTRIBUTE_NORMAL,
                        0,  // Not exclusive!
                        FILE_CREATE,  
                        FILE_NON_DIRECTORY_FILE,
                        NULL,
                        0);
    
    if (NT_SUCCESS(status)) {
        DbgPrint("Created predictable temp file: %S\n", tempFile);
        
        // Write sensitive data to temp file
        CHAR sensitiveData[] = "KERNEL_SECRETS";
        ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatus,
                   sensitiveData, sizeof(sensitiveData), NULL, NULL);
        ZwClose(fileHandle);
    }
    
    return status;
}

// Vulnerability: File creation race condition
NTSTATUS VulnerableFileCreationRace(PVOID UserBuffer, ULONG BufferLength) {
    UNICODE_STRING filePath;
    PWCHAR userPath = (PWCHAR)UserBuffer;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    
    if (BufferLength < sizeof(WCHAR) * 2) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    
    RtlInitUnicodeString(&filePath, userPath);
    InitializeObjectAttributes(&objAttr, &filePath,
                              OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                              NULL, NULL);
    
    // VULNERABILITY: FILE_OPEN_IF without exclusive access
    // Race condition: Multiple processes can create/open simultaneously
    status = ZwCreateFile(&fileHandle,
                        GENERIC_WRITE | FILE_WRITE_DATA,
                        &objAttr,
                        &ioStatus,
                        NULL,
                        FILE_ATTRIBUTE_NORMAL,
                        FILE_SHARE_READ | FILE_SHARE_WRITE,  // Shared access!
                        FILE_OPEN_IF,  // Opens if exists, creates if not
                        FILE_NON_DIRECTORY_FILE,
                        NULL,
                        0);
    
    if (NT_SUCCESS(status)) {
        // Race: Another process might have created/modified the file
        DbgPrint("File opened/created with race condition\n");
        
        // Write data that could be raced
        CHAR data[] = "RACY_DATA";
        ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatus,
                   data, sizeof(data), NULL, NULL);
        ZwClose(fileHandle);
    }
    
    return status;
}

// Safe function: Proper symlink handling
NTSTATUS SafeFileOpen(PVOID UserBuffer, ULONG BufferLength) {
    UNICODE_STRING filePath;
    PWCHAR userPath = (PWCHAR)UserBuffer;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE fileHandle;
    IO_STATUS_BLOCK ioStatus;
    NTSTATUS status;
    
    if (BufferLength < sizeof(WCHAR) * 2) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    
    RtlInitUnicodeString(&filePath, userPath);
    InitializeObjectAttributes(&objAttr, &filePath,
                              OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                              NULL, NULL);
    
    // SAFE: Using FILE_OPEN_REPARSE_POINT to prevent symlink following
    status = ZwCreateFile(&fileHandle,
                        GENERIC_READ,
                        &objAttr,
                        &ioStatus,
                        NULL,
                        FILE_ATTRIBUTE_NORMAL,
                        0,
                        FILE_OPEN,
                        FILE_NON_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT,  // Safe!
                        NULL,
                        0);
    
    if (NT_SUCCESS(status)) {
        DbgPrint("Safely opened file without following symlinks\n");
        ZwClose(fileHandle);
    }
    
    return status;
}

// Main IOCTL handler
NTSTATUS DeviceIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION ioStack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioControlCode = ioStack->Parameters.DeviceIoControl.IoControlCode;
    PVOID systemBuffer = Irp->AssociatedIrp.SystemBuffer;
    ULONG inputLength = ioStack->Parameters.DeviceIoControl.InputBufferLength;
    NTSTATUS status = STATUS_SUCCESS;
    
    switch (ioControlCode) {
        case IOCTL_TOCTOU_RACE:
            status = VulnerableTOCTOU(systemBuffer, inputLength);
            break;
            
        case IOCTL_UNSAFE_SYMLINK:
            status = VulnerableSymlinkFollow(systemBuffer, inputLength);
            break;
            
        case IOCTL_PREDICTABLE_TEMP:
            status = VulnerablePredictableTemp(systemBuffer, inputLength);
            break;
            
        case IOCTL_FILE_CREATION_RACE:
            status = VulnerableFileCreationRace(systemBuffer, inputLength);
            break;
            
        case IOCTL_SAFE_FILE_OPEN:
            status = SafeFileOpen(systemBuffer, inputLength);
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
    
    DbgPrint("SymlinkAttackTest driver loaded\n");
    
    return STATUS_SUCCESS;
}