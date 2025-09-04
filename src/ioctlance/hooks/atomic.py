"""Atomic/Interlocked operation hooks for Windows kernel API simulation."""

from typing import Any

from .base import BaseHook


class _InterlockedBase(BaseHook):
    """Base for Interlocked hooks to notify detectors."""

    _func_name: str = "Interlocked"

    def _notify(self, target: Any = None, *args: Any) -> None:
        context = self.get_context()
        if not context:
            return
        for detector in getattr(context, "detectors", []) or []:
            if hasattr(detector, "check_state") and detector.enabled:
                try:
                    kw = {"func_name": self._func_name}
                    if target is not None:
                        kw["target_addr"] = target
                    result = detector.check_state(self.state, "call", **kw)
                    if result:
                        context.add_vulnerability(result)
                except Exception:
                    # Detectors must be resilient
                    continue


class HookInterlockedIncrement(_InterlockedBase):
    _func_name = "InterlockedIncrement"

    def run(self, Target):
        self._notify(Target)
        return Target


class HookInterlockedDecrement(_InterlockedBase):
    _func_name = "InterlockedDecrement"

    def run(self, Target):
        self._notify(Target)
        return Target


class HookInterlockedAdd(_InterlockedBase):
    _func_name = "InterlockedAdd"

    def run(self, Addend, Value):
        self._notify(Addend, Value)
        return Addend


class HookInterlockedExchange(_InterlockedBase):
    _func_name = "InterlockedExchange"

    def run(self, Target, Value):
        self._notify(Target, Value)
        return Target


class HookInterlockedCompareExchange(_InterlockedBase):
    _func_name = "InterlockedCompareExchange"

    def run(self, Destination, ExChange, Comperand):
        self._notify(Destination, ExChange, Comperand)
        return Destination


class HookInterlockedOr(_InterlockedBase):
    _func_name = "InterlockedOr"

    def run(self, Destination, Value):
        self._notify(Destination, Value)
        return Destination


class HookInterlockedAnd(_InterlockedBase):
    _func_name = "InterlockedAnd"

    def run(self, Destination, Value):
        self._notify(Destination, Value)
        return Destination


class HookInterlockedXor(_InterlockedBase):
    _func_name = "InterlockedXor"

    def run(self, Destination, Value):
        self._notify(Destination, Value)
        return Destination


def register_hooks(project) -> None:
    """Register interlocked hooks if symbols are available."""
    cc = BaseHook.get_calling_convention(project)
    hooks = {
        "InterlockedIncrement": HookInterlockedIncrement,
        "InterlockedDecrement": HookInterlockedDecrement,
        "InterlockedAdd": HookInterlockedAdd,
        "InterlockedExchange": HookInterlockedExchange,
        "InterlockedCompareExchange": HookInterlockedCompareExchange,
        "InterlockedOr": HookInterlockedOr,
        "InterlockedAnd": HookInterlockedAnd,
        "InterlockedXor": HookInterlockedXor,
        # Underscored variants
        "_InterlockedIncrement": HookInterlockedIncrement,
        "_InterlockedDecrement": HookInterlockedDecrement,
        "_InterlockedAdd": HookInterlockedAdd,
        "_InterlockedExchange": HookInterlockedExchange,
    }

    for name, cls in hooks.items():
        try:
            project.hook_symbol(name, cls(cc=cc), replace=True)
        except (KeyError, AttributeError):
            continue


__all__ = [
    "HookInterlockedIncrement",
    "HookInterlockedDecrement",
    "HookInterlockedAdd",
    "HookInterlockedExchange",
    "HookInterlockedCompareExchange",
    "HookInterlockedOr",
    "HookInterlockedAnd",
    "HookInterlockedXor",
]
