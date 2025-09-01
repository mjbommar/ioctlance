#!/bin/bash
# Compile new test drivers for vulnerability detectors

set -e

echo "Compiling test drivers for new detectors..."

# Compile format string test driver
echo "Compiling test_format_string.sys..."
x86_64-w64-mingw32-gcc -shared -nostdlib -fno-builtin \
    -I/usr/share/mingw-w64/include/ddk \
    -o ../samples/test_format_string.sys test_format_string.c \
    -Wl,--subsystem,native -Wl,--entry,DriverEntry \
    -lntoskrnl -lhal

# Compile kernel primitive test driver
echo "Compiling test_kernel_primitive.sys..."
x86_64-w64-mingw32-gcc -shared -nostdlib -fno-builtin \
    -I/usr/share/mingw-w64/include/ddk \
    -o ../samples/test_kernel_primitive.sys test_kernel_primitive.c \
    -Wl,--subsystem,native -Wl,--entry,DriverEntry \
    -lntoskrnl -lhal

# Compile symlink attack test driver
echo "Compiling test_symlink_attack.sys..."
x86_64-w64-mingw32-gcc -shared -nostdlib -fno-builtin \
    -I/usr/share/mingw-w64/include/ddk \
    -o ../samples/test_symlink_attack.sys test_symlink_attack.c \
    -Wl,--subsystem,native -Wl,--entry,DriverEntry \
    -lntoskrnl -lhal

echo "Compilation complete! Drivers saved to samples/"
ls -la ../samples/test_*.sys