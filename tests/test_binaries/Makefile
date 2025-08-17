# Makefile for building IOCTLance test drivers with mingw-w64
# Requires mingw-w64 with DDK headers installed

CC = x86_64-w64-mingw32-gcc
CFLAGS = -I/usr/share/mingw-w64/include/ddk -Wall -Wextra -O2 -nostdlib -ffreestanding -fno-builtin
LDFLAGS = -shared -Wl,--subsystem,native -Wl,--entry,DriverEntry -Wl,--allow-multiple-definition

# Test driver targets
DRIVERS = ioctlance_test.sys \
          test_physical_memory.sys \
          test_probe_bypass.sys \
          test_process_termination.sys \
          test_double_free.sys

all: $(DRIVERS)

# Original test driver
ioctlance_test.sys: ioctlance_test.c kernel_stubs.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "Built: $@"

# Physical memory mapping test
test_physical_memory.sys: test_physical_memory.c kernel_stubs.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "Built: $@"

# ProbeForRead/Write bypass test
test_probe_bypass.sys: test_probe_bypass.c kernel_stubs.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "Built: $@"

# Process termination test
test_process_termination.sys: test_process_termination.c kernel_stubs.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "Built: $@"

# Double-free test
test_double_free.sys: test_double_free.c kernel_stubs.c
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
	@echo "Built: $@"

# Check if drivers are valid PE files
check: $(DRIVERS)
	@for driver in $(DRIVERS); do \
		echo "Checking $$driver:"; \
		file $$driver; \
		x86_64-w64-mingw32-objdump -h $$driver | grep -E "(\.text|\.data|\.rdata)" || true; \
		echo ""; \
	done

# Clean build artifacts
clean:
	rm -f $(DRIVERS)
	@echo "Cleaned all drivers"

# Build and test with IOCTLance
test: $(DRIVERS)
	@echo "Running IOCTLance on test drivers..."
	@for driver in $(DRIVERS); do \
		echo "Testing $$driver:"; \
		cd ../.. && uv run python -m ioctlance.cli --address 0x140001000 $$driver || true; \
		echo ""; \
	done

.PHONY: all clean check test