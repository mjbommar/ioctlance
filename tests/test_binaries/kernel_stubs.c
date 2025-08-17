/*
 * Stub implementations for kernel functions
 * These allow test drivers to compile with mingw-w64
 */

// Undefine the imports to provide our own stubs
#define _NTDDK_
#undef __imp_IofCompleteRequest
#undef __imp_ExAllocatePool
#undef __imp_ExFreePool
#undef __imp_IoCreateDevice
#undef __imp_IoDeleteDevice
#undef __imp_IoCreateSymbolicLink
#undef __imp_IoDeleteSymbolicLink

#include <ntddk.h>

// Stub implementations for testing
ULONG DbgPrint(const char* format, ...) {
    (void)format;
    return 0;
}

void* memcpy(void* dest, const void* src, size_t n) {
    unsigned char* d = dest;
    const unsigned char* s = src;
    while(n--) *d++ = *s++;
    return dest;
}

void* memset(void* s, int c, size_t n) {
    unsigned char* p = s;
    while(n--) *p++ = (unsigned char)c;
    return s;
}

// Stub IoCompleteRequest
void IofCompleteRequest(PIRP Irp, CCHAR PriorityBoost) {
    (void)Irp;
    (void)PriorityBoost;
}
// Export the import pointer
void (*__imp_IofCompleteRequest)(PIRP, CCHAR) = IofCompleteRequest;

// Stub ExAllocatePool
PVOID ExAllocatePool(POOL_TYPE PoolType, SIZE_T NumberOfBytes) {
    (void)PoolType;
    (void)NumberOfBytes;
    return (PVOID)0x80000000;
}
// Export the import pointer
PVOID (*__imp_ExAllocatePool)(POOL_TYPE, SIZE_T) = ExAllocatePool;

// Stub ExFreePool
void ExFreePool(PVOID P) {
    (void)P;
}
// Export the import pointer
void (*__imp_ExFreePool)(PVOID) = ExFreePool;

// Stub IoCreateDevice
NTSTATUS IoCreateDevice(
    PDRIVER_OBJECT DriverObject,
    ULONG DeviceExtensionSize,
    PUNICODE_STRING DeviceName,
    DEVICE_TYPE DeviceType,
    ULONG DeviceCharacteristics,
    BOOLEAN Exclusive,
    PDEVICE_OBJECT *DeviceObject
) {
    (void)DriverObject;
    (void)DeviceExtensionSize;
    (void)DeviceName;
    (void)DeviceType;
    (void)DeviceCharacteristics;
    (void)Exclusive;
    *DeviceObject = (PDEVICE_OBJECT)0xDEADBEEF;
    return STATUS_SUCCESS;
}
// Export the import pointer
NTSTATUS (*__imp_IoCreateDevice)(PDRIVER_OBJECT, ULONG, PUNICODE_STRING, DEVICE_TYPE, ULONG, BOOLEAN, PDEVICE_OBJECT*) = IoCreateDevice;

// Stub IoDeleteDevice
void IoDeleteDevice(PDEVICE_OBJECT DeviceObject) {
    (void)DeviceObject;
}
// Export the import pointer
void (*__imp_IoDeleteDevice)(PDEVICE_OBJECT) = IoDeleteDevice;

// Stub IoCreateSymbolicLink
NTSTATUS IoCreateSymbolicLink(
    PUNICODE_STRING SymbolicLinkName,
    PUNICODE_STRING DeviceName
) {
    (void)SymbolicLinkName;
    (void)DeviceName;
    return STATUS_SUCCESS;
}
// Export the import pointer
NTSTATUS (*__imp_IoCreateSymbolicLink)(PUNICODE_STRING, PUNICODE_STRING) = IoCreateSymbolicLink;

// Stub IoDeleteSymbolicLink
NTSTATUS IoDeleteSymbolicLink(PUNICODE_STRING SymbolicLinkName) {
    (void)SymbolicLinkName;
    return STATUS_SUCCESS;
}
// Export the import pointer
NTSTATUS (*__imp_IoDeleteSymbolicLink)(PUNICODE_STRING) = IoDeleteSymbolicLink;

// Additional kernel function stubs for test drivers

// ProbeForRead/Write (normally imported from ntoskrnl)
void ProbeForRead(const void *Address, SIZE_T Length, ULONG Alignment) {
    DbgPrint("ProbeForRead: Addr=%p, Len=%llu, Align=%lu\n", 
             Address, (ULONGLONG)Length, Alignment);
}
// Export the import pointer
void (*__imp_ProbeForRead)(const void*, SIZE_T, ULONG) = ProbeForRead;

void ProbeForWrite(PVOID Address, SIZE_T Length, ULONG Alignment) {
    DbgPrint("ProbeForWrite: Addr=%p, Len=%llu, Align=%lu\n",
             Address, (ULONGLONG)Length, Alignment);
}
// Export the import pointer
void (*__imp_ProbeForWrite)(PVOID, SIZE_T, ULONG) = ProbeForWrite;

// Process management APIs
NTSTATUS ZwTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
    DbgPrint("ZwTerminateProcess: Handle=%p, ExitStatus=0x%x\n", ProcessHandle, ExitStatus);
    return STATUS_SUCCESS;
}
// Export the import pointer
NTSTATUS (*__imp_ZwTerminateProcess)(HANDLE, NTSTATUS) = ZwTerminateProcess;

NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PVOID *Process) {
    DbgPrint("PsLookupProcessByProcessId: PID=%p\n", ProcessId);
    *Process = (PVOID)0xDEADBEEF;
    return STATUS_SUCCESS;
}

// ZwOpenProcess needs proper OBJECT_ATTRIBUTES and CLIENT_ID structs
NTSTATUS ZwOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, 
                       POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    DbgPrint("ZwOpenProcess: DesiredAccess=0x%x, ClientId=%p\n", DesiredAccess, ClientId);
    *ProcessHandle = (HANDLE)0xCAFEBABE;
    return STATUS_SUCCESS;
}
// Export the import pointer
NTSTATUS (*__imp_ZwOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID) = ZwOpenProcess;

// ObDereferenceObject is actually a macro for ObfDereferenceObject
LONG_PTR ObfDereferenceObject(PVOID Object) {
    DbgPrint("ObDereferenceObject: Object=%p\n", Object);
    return 0;
}
// Export the import pointer
LONG_PTR (*__imp_ObfDereferenceObject)(PVOID) = ObfDereferenceObject;

// Pool allocation with tags
PVOID ExAllocatePoolWithTag(POOL_TYPE PoolType, SIZE_T NumberOfBytes, ULONG Tag) {
    DbgPrint("ExAllocatePoolWithTag: Type=%lu, Size=%llu, Tag=0x%x\n", 
             PoolType, (ULONGLONG)NumberOfBytes, Tag);
    return ExAllocatePool(PoolType, NumberOfBytes);
}
// Export the import pointer
PVOID (*__imp_ExAllocatePoolWithTag)(POOL_TYPE, SIZE_T, ULONG) = ExAllocatePoolWithTag;

void ExFreePoolWithTag(PVOID P, ULONG Tag) {
    DbgPrint("ExFreePoolWithTag: Ptr=%p, Tag=0x%x\n", P, Tag);
    ExFreePool(P);
}
// Export the import pointer
void (*__imp_ExFreePoolWithTag)(PVOID, ULONG) = ExFreePoolWithTag;

// MmMapIoSpace for physical memory mapping
PVOID MmMapIoSpace(PHYSICAL_ADDRESS PhysicalAddress, SIZE_T NumberOfBytes, MEMORY_CACHING_TYPE CacheType) {
    (void)CacheType;
    DbgPrint("MmMapIoSpace called: Addr=%llx, Size=%llx\n", 
             PhysicalAddress.QuadPart, (ULONGLONG)NumberOfBytes);
    return (PVOID)0xDEADBEEF;
}