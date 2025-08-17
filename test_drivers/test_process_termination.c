/*
 * Test driver for ProcessTerminationDetector
 * Vulnerable to arbitrary process termination and handle abuse
 * Build with: x86_64-w64-mingw32-gcc -shared -nostdlib -fno-builtin -I/usr/share/mingw-w64/include/ddk -o test_process_termination.sys test_process_termination.c -Wl,--subsystem,native -Wl,--entry,DriverEntry
 */

#include <ntddk.h>

#define IOCTL_TERMINATE_PROCESS  CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA00, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_OPEN_PROCESS      CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA01, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_LOOKUP_PROCESS    CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA02, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DEREF_OBJECT      CTL_CODE(FILE_DEVICE_UNKNOWN, 0xA03, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _PROCESS_REQUEST {
    HANDLE ProcessHandle;
    ULONG ProcessId;
    ACCESS_MASK DesiredAccess;
    PVOID ProcessObject;
    NTSTATUS ExitStatus;
} PROCESS_REQUEST, *PPROCESS_REQUEST;

// External function declarations
NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);
// ObDereferenceObject is already declared
// ZwTerminateProcess and ZwOpenProcess are already declared

NTSTATUS IoctlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
    PPROCESS_REQUEST request = (PPROCESS_REQUEST)Irp->AssociatedIrp.SystemBuffer;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PEPROCESS process = NULL;
    
    switch(ioctl) {
        case IOCTL_TERMINATE_PROCESS:
            // VULNERABILITY: User-controlled process handle
            status = ZwTerminateProcess(
                request->ProcessHandle,  // User-controlled handle
                request->ExitStatus      // User-controlled exit status
            );
            break;
            
        case IOCTL_OPEN_PROCESS: {
            CLIENT_ID clientId;
            OBJECT_ATTRIBUTES objAttr;
            HANDLE processHandle;
            
            clientId.UniqueProcess = (HANDLE)(ULONG_PTR)request->ProcessId;  // User-controlled PID
            clientId.UniqueThread = NULL;
            
            InitializeObjectAttributes(&objAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
            
            // VULNERABILITY: Open process with user-controlled PID and dangerous access rights
            status = ZwOpenProcess(
                &processHandle,
                request->DesiredAccess ? request->DesiredAccess : PROCESS_ALL_ACCESS,  // Dangerous access
                &objAttr,
                &clientId  // User-controlled PID
            );
            
            if (NT_SUCCESS(status)) {
                request->ProcessHandle = processHandle;
                
                // Additional vulnerability: Could use this handle for token stealing
                // In a real exploit, attacker would:
                // 1. Open System process (PID 4)
                // 2. Steal its token
                // 3. Assign to current process for privilege escalation
            }
            break;
        }
        
        case IOCTL_LOOKUP_PROCESS:
            // VULNERABILITY: Lookup process by user-controlled PID
            status = PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)request->ProcessId,  // User-controlled PID
                &process
            );
            
            if (NT_SUCCESS(status)) {
                // Return process object pointer (dangerous!)
                request->ProcessObject = process;
                
                // In real exploit, this could be used for:
                // - Token stealing from SYSTEM process
                // - Direct memory manipulation
                // - Process structure corruption
                
                // Should dereference, but vulnerability leaves reference
                // ObDereferenceObject(process);
            }
            break;
            
        case IOCTL_DEREF_OBJECT:
            // VULNERABILITY: Dereference user-controlled object pointer
            if (request->ProcessObject) {
                ObDereferenceObject(request->ProcessObject);  // User-controlled pointer
                status = STATUS_SUCCESS;
            }
            break;
    }
    
    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = (status == STATUS_SUCCESS) ? sizeof(PROCESS_REQUEST) : 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING DeviceName;
    
    RtlInitUnicodeString(&DeviceName, L"\\Device\\VulnProcess");
    IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
    
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlHandler;
    
    return STATUS_SUCCESS;
}