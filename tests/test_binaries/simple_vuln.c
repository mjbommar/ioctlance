/*
 * Simple vulnerable driver to test detector capabilities
 * This has clear, intentional vulnerabilities for testing
 */

#include <stdint.h>
#include <string.h>

// Windows types
typedef void* PVOID;
typedef uint32_t ULONG;
typedef uint64_t ULONG_PTR;

// IRP structure (simplified)
typedef struct _IRP {
    PVOID SystemBuffer;
    PVOID UserBuffer;
} IRP, *PIRP;

// Stack buffer overflow - VERY OBVIOUS
void vuln_stack_overflow(char* input, ULONG size) {
    char buffer[32];  // Small buffer
    memcpy(buffer, input, size);  // No bounds check! Will overflow if size > 32
}

// Format string vulnerability - VERY OBVIOUS  
void vuln_format_string(char* user_fmt) {
    char output[256];
    sprintf(output, user_fmt);  // Direct user format string!
}

// Null pointer dereference - VERY OBVIOUS
void vuln_null_deref(PVOID ptr, ULONG check) {
    if (check == 0) {
        // Forgot to check if ptr is NULL!
        *(ULONG*)ptr = 0x41414141;  // Write to potentially NULL pointer
    }
}

// Integer overflow - VERY OBVIOUS
void vuln_integer_overflow(ULONG count, ULONG size) {
    ULONG total = count * size;  // Can overflow!
    char* buf = (char*)malloc(total);  // Allocate with overflowed size
    memset(buf, 0, count * size);  // Use original calculation - buffer overflow!
    free(buf);
}

// Main dispatch function
__declspec(dllexport)
int DriverDispatch(PVOID DeviceObject, PIRP Irp, ULONG IoControlCode) {
    // Get buffers from IRP
    PVOID SystemBuffer = Irp->SystemBuffer;
    PVOID UserBuffer = Irp->UserBuffer;
    
    // Route based on IOCTL code
    switch(IoControlCode) {
        case 0x800:  // Stack overflow test
            vuln_stack_overflow((char*)SystemBuffer, 100);  // Pass size > 32
            break;
            
        case 0x801:  // Format string test
            vuln_format_string((char*)SystemBuffer);
            break;
            
        case 0x802:  // Null pointer test
            vuln_null_deref(UserBuffer, 0);  // Pass 0 to trigger
            break;
            
        case 0x803:  // Integer overflow test
            vuln_integer_overflow(0x10000, 0x10000);  // Large values
            break;
    }
    
    return 0;
}

// Entry point
__declspec(dllexport)
int DriverEntry(PVOID DriverObject, PVOID RegistryPath) {
    // Register dispatch routine (simplified)
    return 0;
}