"""KMDF (WDF) hooks to enable IOCTL discovery and buffer retrieval in KMDF drivers.

These hooks are heuristic and aim to bridge KMDF request handling to the
existing WDM-oriented detectors by:
- Discovering EvtIoDeviceControl via WdfIoQueueCreate (by scanning the config)
- Populating SystemBuffer/InputBufferLength via WdfRequestRetrieveInputBuffer
- Populating Output buffer via WdfRequestRetrieveOutputBuffer (best-effort)
- Setting IoControlCode via WdfRequestGetParameters (symbolic fallback)
"""

from typing import Any

import claripy

from .base import BaseHook


def _main_text_bounds(state) -> tuple[int, int] | None:
    try:
        obj = state.project.loader.main_object
        lo = getattr(obj, "min_addr", None)
        hi = getattr(obj, "max_addr", None)
        if lo is not None and hi is not None:
            return int(lo), int(hi)
    except Exception:
        pass
    return None


class HookWdfIoQueueCreate(BaseHook):
    """Heuristically extract EvtIoDeviceControl from WDF_IO_QUEUE_CONFIG."""

    def run(self, Device, QueueConfig, Attributes, Queue) -> int:
        context = self.get_context()
        bounds = _main_text_bounds(self.state)
        evt_addr = None
        if bounds is not None:
            lo, hi = bounds
            arch_bytes = self.state.arch.bytes
            # Scan first 0x100 bytes for a pointer into .text
            for off in range(0, 0x100, arch_bytes):
                try:
                    ptr = self.state.memory.load(QueueConfig + off, arch_bytes)
                    val = self.safe_eval(ptr, 0)
                    if isinstance(val, int) and lo <= val < hi:
                        evt_addr = val
                        break
                except Exception:
                    continue

        # Record the candidate handler
        if evt_addr and context:
            context.ioctl_handler = int(evt_addr)
            # Mirror IOCTLHandlerFinder convention
            self.state.globals["ioctl_handler"] = int(evt_addr)
            # Optionally, write back a non-null Queue to avoid divergence
            try:
                if Queue is not None:
                    qaddr = context.next_base_addr()
                    self.state.memory.store(Queue, claripy.BVV(qaddr, self.state.arch.bits), self.state.arch.bytes)
            except Exception:
                pass

        # STATUS_SUCCESS
        return 0


class HookWdfRequestRetrieveInputBuffer(BaseHook):
    """Populate SystemBuffer and InputBufferLength via KMDF API."""

    def run(self, Request, MinimumRequiredSize, Buffer, BufferLength) -> int:
        context = self.get_context()
        if context:
            # Pointer to input buffer
            sysbuf = claripy.BVS("SystemBuffer", self.state.arch.bits)
            in_len = claripy.BVS("InputBufferLength", 32)
            # Return symbolic buffer pointer to caller
            try:
                self.state.memory.store(Buffer, sysbuf, self.state.arch.bytes, disable_actions=True, inspect=False)
                self.state.memory.store(
                    BufferLength,
                    in_len.zero_extend(self.state.arch.bits - 32),
                    self.state.arch.bytes,
                    disable_actions=True,
                    inspect=False,
                )
            except Exception:
                pass
            context.system_buffer = sysbuf
            context.input_buffer_length = in_len
        return 0


class HookWdfRequestRetrieveOutputBuffer(BaseHook):
    """Best-effort population of output buffer as UserBuffer analogue."""

    def run(self, Request, MinimumRequiredSize, Buffer, BufferLength) -> int:
        context = self.get_context()
        if context:
            outbuf = claripy.BVS("UserBuffer", self.state.arch.bits)
            out_len = claripy.BVS("OutputBufferLength", 32)
            try:
                self.state.memory.store(Buffer, outbuf, self.state.arch.bytes, disable_actions=True, inspect=False)
                self.state.memory.store(
                    BufferLength,
                    out_len.zero_extend(self.state.arch.bits - 32),
                    self.state.arch.bytes,
                    disable_actions=True,
                    inspect=False,
                )
            except Exception:
                pass
            context.user_buffer = outbuf
            context.output_buffer_length = out_len
        return 0


class HookWdfRequestGetParameters(BaseHook):
    """Set a symbolic IoControlCode to drive detectors and pruning.

    Accurate field extraction is version/offset dependent, so we provide a
    symbolic fallback that still enables grouping and display.
    """

    def run(self, Request, Parameters) -> int:
        context = self.get_context()
        if context and getattr(context, "io_control_code", None) is None:
            context.io_control_code = claripy.BVS("IoControlCode", 32)
        return 0


def register_hooks(project) -> None:
    cc = BaseHook.get_calling_convention(project)
    hooks: dict[str, type[BaseHook]] = {
        "WdfIoQueueCreate": HookWdfIoQueueCreate,
        "WdfRequestRetrieveInputBuffer": HookWdfRequestRetrieveInputBuffer,
        "WdfRequestRetrieveOutputBuffer": HookWdfRequestRetrieveOutputBuffer,
        "WdfRequestGetParameters": HookWdfRequestGetParameters,
    }
    for name, cls in hooks.items():
        try:
            project.hook_symbol(name, cls(cc=cc), replace=True)
        except (KeyError, AttributeError):
            # Symbol not present; ignore
            pass


__all__ = [
    "HookWdfIoQueueCreate",
    "HookWdfRequestRetrieveInputBuffer",
    "HookWdfRequestRetrieveOutputBuffer",
    "HookWdfRequestGetParameters",
]
