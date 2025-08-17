#!/bin/bash
# Build all IOCTLance test drivers using mingw-w64-dpp framework

set -e

DPP_ROOT="../../tmp/mingw-w64-dpp"
BUILD_DIR="build"

# Test drivers to build
DRIVERS=(
    "ioctlance_test"
    "test_physical_memory"
    "test_probe_bypass"
    "test_process_termination"
    "test_double_free"
)

# Check if mingw-w64-dpp exists
if [ ! -d "$DPP_ROOT" ]; then
    echo "Error: mingw-w64-dpp not found at $DPP_ROOT"
    exit 1
fi

# Check if mingw-w64 is installed
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "Error: mingw-w64 not found"
    exit 1
fi

# Find DDK headers
DDK_INCLUDE="/usr/share/mingw-w64/include/ddk"
if [ ! -d "$DDK_INCLUDE" ]; then
    echo "Error: DDK headers not found at $DDK_INCLUDE"
    exit 1
fi

echo "Found DDK headers at: $DDK_INCLUDE"
echo ""

# Create build directory
mkdir -p "$BUILD_DIR"

# Build each driver
for DRIVER_NAME in "${DRIVERS[@]}"; do
    echo "Building $DRIVER_NAME.sys..."
    
    # Compile driver with kernel stubs
    x86_64-w64-mingw32-gcc \
        -Wall -Wextra \
        -m64 -fPIC -fvisibility=hidden \
        -fno-builtin -ffreestanding \
        -fno-stack-protector -mno-stack-arg-probe \
        -I"$DPP_ROOT/CRT" \
        -I"$DDK_INCLUDE" \
        -D__INTRINSIC_DEFINED_InterlockedBitTestAndSet \
        -D__INTRINSIC_DEFINED_InterlockedBitTestAndReset \
        -c "$DRIVER_NAME.c" -o "$BUILD_DIR/$DRIVER_NAME.o" 2>&1 | grep -v "warning: unused variable" || true
    
    # Also compile kernel stubs
    x86_64-w64-mingw32-gcc \
        -Wall -Wextra \
        -m64 -fPIC -fvisibility=hidden \
        -fno-builtin -ffreestanding \
        -fno-stack-protector -mno-stack-arg-probe \
        -I"$DPP_ROOT/CRT" \
        -I"$DDK_INCLUDE" \
        -D__INTRINSIC_DEFINED_InterlockedBitTestAndSet \
        -D__INTRINSIC_DEFINED_InterlockedBitTestAndReset \
        -c "kernel_stubs.c" -o "$BUILD_DIR/kernel_stubs.o" 2>&1 | grep -v "warning:" || true
    
    # Link driver with kernel stubs
    x86_64-w64-mingw32-gcc \
        -shared \
        -Wl,--subsystem,native \
        -Wl,--image-base,0x140000000 \
        -Wl,--dynamicbase -Wl,--nxcompat \
        -Wl,--file-alignment,0x200 \
        -Wl,--section-alignment,0x1000 \
        -Wl,--stack,0x100000 \
        -Wl,--gc-sections \
        -Wl,--entry,DriverEntry \
        -Wl,--allow-multiple-definition \
        -nostartfiles -nodefaultlibs -nostdlib \
        "$BUILD_DIR/$DRIVER_NAME.o" "$BUILD_DIR/kernel_stubs.o" \
        -o "$BUILD_DIR/$DRIVER_NAME.sys"
    
    echo "✓ Built $BUILD_DIR/$DRIVER_NAME.sys"
done

echo ""
echo "All drivers built successfully!"
echo ""
echo "To test with IOCTLance:"
for DRIVER_NAME in "${DRIVERS[@]}"; do
    echo "  uv run python -m ioctlance.cli build/$DRIVER_NAME.sys"
done