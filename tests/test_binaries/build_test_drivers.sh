#!/bin/bash
# Build test drivers for IOCTLance vulnerability detector testing
# Requires: mingw-w64 cross-compiler

# Install on Ubuntu 24.04/25.04:
# sudo apt-get update
# sudo apt-get install -y mingw-w64 gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64

echo "Building test drivers with mingw-w64..."

# Check if mingw is installed
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "Error: mingw-w64 not found. Install with:"
    echo "  sudo apt-get install -y mingw-w64 gcc-mingw-w64-x86-64"
    exit 1
fi

# Build directory
mkdir -p build

# Compile vulnerable test driver (64-bit Windows PE)
echo "Compiling vulnerable_examples.c -> test_vulns.sys (64-bit)..."
x86_64-w64-mingw32-gcc \
    -shared \
    -Wall \
    -O0 \
    -fno-stack-protector \
    -D_WIN64 \
    -o build/test_vulns_x64.sys \
    vulnerable_examples.c

# Compile 32-bit version too
echo "Compiling vulnerable_examples.c -> test_vulns.sys (32-bit)..."
i686-w64-mingw32-gcc \
    -shared \
    -Wall \
    -O0 \
    -fno-stack-protector \
    -o build/test_vulns_x86.sys \
    vulnerable_examples.c 2>/dev/null || echo "32-bit compiler not installed (optional)"

# Create a minimal driver that just has IOCTL dispatch
cat > minimal_driver.c << 'EOF'
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
EOF

echo "Compiling minimal_driver.c -> minimal.sys..."
x86_64-w64-mingw32-gcc \
    -shared \
    -Wall \
    -O0 \
    -fno-stack-protector \
    -D_WIN64 \
    -o build/minimal_x64.sys \
    minimal_driver.c

# Build our new test_driver.c with correct DRIVER_OBJECT offsets
if [ -f "test_driver.c" ]; then
    echo "Compiling test_driver.c -> test_driver.sys (correct offsets)..."
    x86_64-w64-mingw32-gcc \
        -shared \
        -Wall \
        -O0 \
        -fno-stack-protector \
        -D_WIN64 \
        -o build/test_driver.sys \
        test_driver.c
fi

# Build other test drivers if they exist
for driver in simple_vuln.c proper_driver.c wdm_driver.c; do
    if [ -f "$driver" ]; then
        output="${driver%.c}.sys"
        echo "Compiling $driver -> $output..."
        x86_64-w64-mingw32-gcc \
            -shared \
            -Wall \
            -O0 \
            -fno-stack-protector \
            -D_WIN64 \
            -o "build/$output" \
            "$driver"
    fi
done

echo ""
echo "Build complete! Test drivers created:"
ls -la build/*.sys 2>/dev/null || echo "No drivers built"

echo ""
echo "To test with IOCTLance:"
echo "  uv run python -m ioctlance.cli build/test_driver.sys"
echo "  uv run python -m ioctlance.cli build/test_vulns_x64.sys"
echo "  uv run python -m ioctlance.cli build/minimal_x64.sys"