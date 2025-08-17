/*
 * Working test driver for IOCTLance - minimal implementation
 * This creates vulnerabilities that IOCTLance can detect
 */

#include <stdint.h>
#include <string.h>

// Windows types
typedef void* PVOID;
typedef uint32_t ULONG;
typedef int32_t NTSTATUS;
#define STATUS_SUCCESS 0

// Simple vulnerable functions that IOCTLance can analyze
__attribute__((noinline))
void vuln_memcpy(PVOID dst, PVOID src, ULONG size) {
    // Direct memcpy - will trigger hooks
    memcpy(dst, src, size);
}

__attribute__((noinline)) 
void vuln_null_deref(PVOID ptr) {
    // Potential null pointer dereference
    *(ULONG*)ptr = 0x41414141;
}

__attribute__((noinline))
void vuln_integer_overflow(ULONG a, ULONG b) {
    ULONG result = a * b;  // Can overflow
    char buffer[100];
    if (result < 100) {
        memcpy(buffer, (void*)0x1000, result);
    }
}

// Main dispatch function - this is what we'll point IOCTLance to
__declspec(dllexport)
NTSTATUS VulnDispatch(PVOID DeviceObject, PVOID Irp, ULONG IoControlCode) {
    // Get some pointers that look like IRP structure
    PVOID SystemBuffer = (PVOID)((char*)Irp + 0x18);  // Fake offset
    ULONG InputLength = *(ULONG*)((char*)Irp + 0x10);
    
    // Simple IOCTL dispatch
    switch (IoControlCode) {
        case 0x222000: {
            // Stack buffer overflow vulnerability
            char localBuffer[32];
            vuln_memcpy(localBuffer, SystemBuffer, InputLength);
            break;
        }
        
        case 0x222004: {
            // Null pointer dereference
            if (InputLength == 0) {
                vuln_null_deref(SystemBuffer);
            }
            break;
        }
        
        case 0x222008: {
            // Integer overflow
            if (SystemBuffer) {
                ULONG* params = (ULONG*)SystemBuffer;
                vuln_integer_overflow(params[0], params[1]);
            }
            break;
        }
    }
    
    return STATUS_SUCCESS;
}

// Entry point - not used but needed for PE structure
__declspec(dllexport)
NTSTATUS DriverEntry(PVOID DriverObject, PVOID RegistryPath) {
    return STATUS_SUCCESS;
}