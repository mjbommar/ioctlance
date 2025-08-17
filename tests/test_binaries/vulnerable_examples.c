/*
 * Simplified vulnerability test cases
 * Compile with: x86_64-w64-mingw32-gcc -shared -o test_vulns.sys vulnerable_examples.c
 * 
 * These are simplified examples that can be compiled to Windows PE format
 * for testing vulnerability detectors without full driver complexity
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

// Simulate Windows types
typedef void* PVOID;
typedef uint32_t ULONG;
typedef uint64_t ULONG_PTR;

// Test 1: Integer overflow
int test_integer_overflow(ULONG user_size, ULONG user_count) {
    // Vulnerable: user_size * user_count can overflow
    ULONG total = user_size * user_count;  // <-- Integer overflow
    char* buffer = (char*)malloc(total);
    if (!buffer) return -1;
    
    // Use the undersized buffer...
    memset(buffer, 0, user_size * user_count);  // <-- Heap overflow
    free(buffer);
    return 0;
}

// Test 2: Format string vulnerability  
void test_format_string(char* user_format, int value) {
    char buffer[256];
    sprintf(buffer, user_format, value);  // <-- Format string vulnerability
    // Use buffer...
}

// Test 3: Stack buffer overflow
void test_stack_overflow(char* user_input, ULONG input_len) {
    char stack_buffer[64];
    // Vulnerable: no bounds check
    memcpy(stack_buffer, user_input, input_len);  // <-- Stack overflow
    // Process buffer...
}

// Test 4: Null pointer dereference
int test_null_pointer(PVOID user_buffer, ULONG buffer_len) {
    if (buffer_len == 0) {
        // Forgot to check if user_buffer is NULL
        *(int*)user_buffer = 0x41414141;  // <-- Null pointer deref
    }
    return 0;
}

// Test 5: Arbitrary write
void test_arbitrary_write(ULONG_PTR user_address, ULONG value) {
    // Vulnerable: writes to user-controlled address
    *(ULONG*)user_address = value;  // <-- Arbitrary write
}

// Simulate a simple IOCTL dispatcher
int ioctl_dispatcher(ULONG ioctl_code, PVOID input_buffer, ULONG input_len) {
    switch(ioctl_code) {
        case 0x800:  // Integer overflow test
            return test_integer_overflow(
                *(ULONG*)input_buffer, 
                *((ULONG*)input_buffer + 1)
            );
            
        case 0x801:  // Format string test
            test_format_string((char*)input_buffer, 42);
            return 0;
            
        case 0x802:  // Stack overflow test
            test_stack_overflow((char*)input_buffer, input_len);
            return 0;
            
        case 0x803:  // Null pointer test
            return test_null_pointer(input_buffer, input_len);
            
        case 0x804:  // Arbitrary write test
            test_arbitrary_write(
                *(ULONG_PTR*)input_buffer,
                *((ULONG*)input_buffer + 8)
            );
            return 0;
            
        default:
            return -1;
    }
}

// Entry point for testing
__declspec(dllexport) int DriverEntry(void* driver_object, void* registry_path) {
    // Simulate driver initialization
    return 0;
}