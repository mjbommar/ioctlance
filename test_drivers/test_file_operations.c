/*
 * Test driver for FileOperationDetector
 * Vulnerable to arbitrary file operations with user-controlled paths
 * Build with: x86_64-w64-mingw32-gcc -shared -nostdlib -fno-builtin -I/usr/share/mingw-w64/include/ddk -o test_file_operations.sys test_file_operations.c -Wl,--subsystem,native -Wl,--entry,DriverEntry
 */

#include <ntddk.h>

#define IOCTL_CREATE_FILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OPEN_FILE   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WRITE_FILE  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DELETE_FILE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _FILE_OP_REQUEST {
    WCHAR Path[256];
    ULONG DesiredAccess;
    ULONG CreateDisposition;
    PVOID Buffer;
    ULONG BufferSize;
} FILE_OP_REQUEST, *PFILE_OP_REQUEST;

NTSTATUS IoctlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
    PFILE_OP_REQUEST request = (PFILE_OP_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    HANDLE fileHandle;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING fileName;
    IO_STATUS_BLOCK ioStatus;
    
    switch(ioctl) {
        case IOCTL_CREATE_FILE:
            // VULNERABILITY: User-controlled path and access rights
            RtlInitUnicodeString(&fileName, request->Path);
            InitializeObjectAttributes(&objAttr, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
            
            // Create file with user-controlled parameters
            status = ZwCreateFile(
                &fileHandle,
                request->DesiredAccess,  // User-controlled access
                &objAttr,                 // User-controlled path
                &ioStatus,
                NULL,
                FILE_ATTRIBUTE_NORMAL,
                0,
                request->CreateDisposition, // User-controlled disposition
                FILE_SYNCHRONOUS_IO_NONALERT,
                NULL,
                0
            );
            
            if (NT_SUCCESS(status)) {
                ZwClose(fileHandle);
            }
            break;
            
        case IOCTL_OPEN_FILE:
            // VULNERABILITY: User-controlled path with dangerous access
            RtlInitUnicodeString(&fileName, request->Path);
            InitializeObjectAttributes(&objAttr, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
            
            status = ZwOpenFile(
                &fileHandle,
                GENERIC_ALL,  // Full access
                &objAttr,     // User-controlled path
                &ioStatus,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_SYNCHRONOUS_IO_NONALERT
            );
            
            if (NT_SUCCESS(status)) {
                ZwClose(fileHandle);
            }
            break;
            
        case IOCTL_WRITE_FILE:
            // VULNERABILITY: Write user data to user-controlled file
            RtlInitUnicodeString(&fileName, request->Path);
            InitializeObjectAttributes(&objAttr, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
            
            status = ZwCreateFile(
                &fileHandle,
                GENERIC_WRITE,
                &objAttr,
                &ioStatus,
                NULL,
                FILE_ATTRIBUTE_NORMAL,
                0,
                FILE_OVERWRITE_IF,
                FILE_SYNCHRONOUS_IO_NONALERT,
                NULL,
                0
            );
            
            if (NT_SUCCESS(status)) {
                // Write user-controlled data
                status = ZwWriteFile(
                    fileHandle,
                    NULL,
                    NULL,
                    NULL,
                    &ioStatus,
                    request->Buffer,      // User-controlled buffer
                    request->BufferSize,  // User-controlled size
                    NULL,
                    NULL
                );
                ZwClose(fileHandle);
            }
            break;
            
        case IOCTL_DELETE_FILE:
            // VULNERABILITY: Delete file with user-controlled path
            RtlInitUnicodeString(&fileName, request->Path);
            InitializeObjectAttributes(&objAttr, &fileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
            
            status = ZwDeleteFile(&objAttr);
            break;
    }
    
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING DeviceName;
    
    RtlInitUnicodeString(&DeviceName, L"\\Device\\VulnFileOps");
    IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
    
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlHandler;
    
    return STATUS_SUCCESS;
}