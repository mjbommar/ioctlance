#!/bin/bash
# Build IOCTLance test driver using mingw-w64-dpp framework

set -e

DPP_ROOT="../../tmp/mingw-w64-dpp"
DRIVER_NAME="ioctlance_test"

# Check if mingw-w64-dpp exists
if [ ! -d "$DPP_ROOT" ]; then
    echo "Error: mingw-w64-dpp not found at $DPP_ROOT"
    echo "Run: git clone https://github.com/utoni/mingw-w64-dpp.git tmp/mingw-w64-dpp"
    exit 1
fi

# Check if mingw-w64 is installed
if ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "Error: mingw-w64 not found. Install with:"
    echo "  sudo apt-get install -y mingw-w64 gcc-mingw-w64-x86-64"
    exit 1
fi

echo "Building $DRIVER_NAME.sys with mingw-w64-dpp..."

# Try to find DDK headers in mingw installation
DDK_INCLUDE=""
for dir in /usr/share/mingw-w64/include /usr/x86_64-w64-mingw32/include /usr/lib/gcc/x86_64-w64-mingw32/*/include; do
    if [ -d "$dir/ddk" ]; then
        DDK_INCLUDE="$dir/ddk"
        break
    fi
done

if [ -z "$DDK_INCLUDE" ]; then
    echo "Warning: DDK headers not found in system mingw-w64"
    echo "Using basic compilation without full DDK support"
    
    # Compile without DDK - will fail but shows what's missing
    x86_64-w64-mingw32-gcc \
        -Wall -Wextra \
        -m64 -fPIC -fvisibility=hidden \
        -fno-builtin -ffreestanding \
        -fno-stack-protector -mno-stack-arg-probe \
        -I"$DPP_ROOT/CRT" \
        -c "$DRIVER_NAME.c" -o "$DRIVER_NAME.o" 2>&1 | head -20
    
    echo ""
    echo "As expected, compilation fails without DDK headers."
    echo "mingw-w64-dpp provides these headers, but requires building their toolchain."
    echo ""
    echo "Options:"
    echo "1. Build mingw-w64-dpp toolchain (requires time and dependencies)"
    echo "2. Use our simpler test drivers with --address option"
    echo "3. Install Windows DDK headers separately"
    exit 1
fi

echo "Found DDK headers at: $DDK_INCLUDE"

# Compile driver
x86_64-w64-mingw32-gcc \
    -Wall -Wextra \
    -m64 -fPIC -fvisibility=hidden \
    -fno-builtin -ffreestanding \
    -fno-stack-protector -mno-stack-arg-probe \
    -I"$DPP_ROOT/CRT" \
    -I"$DDK_INCLUDE" \
    -D__INTRINSIC_DEFINED_InterlockedBitTestAndSet \
    -D__INTRINSIC_DEFINED_InterlockedBitTestAndReset \
    -c "$DRIVER_NAME.c" -o "$DRIVER_NAME.o"

# Link driver
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
    -nostartfiles -nodefaultlibs -nostdlib \
    "$DRIVER_NAME.o" \
    -lntoskrnl -lhal \
    -o "build/$DRIVER_NAME.sys"

echo "Successfully built build/$DRIVER_NAME.sys"
echo ""
echo "To test with IOCTLance:"
echo "  uv run python -m ioctlance.cli build/$DRIVER_NAME.sys"