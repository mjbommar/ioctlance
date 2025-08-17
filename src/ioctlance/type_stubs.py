"""Type stubs and helpers for external libraries."""

from typing import Any, TypeVar, Protocol, runtime_checkable

# Type variable for generic dict-like behavior
K = TypeVar('K')
V = TypeVar('V')

@runtime_checkable
class DictLikeGlobals(Protocol):
    """Protocol for dict-like state.globals behavior."""
    
    def __getitem__(self, key: str) -> Any: ...
    def __setitem__(self, key: str, value: Any) -> None: ...
    def __contains__(self, key: str) -> bool: ...
    def get(self, key: str, default: Any = None) -> Any: ...


def cast_globals(globals_obj: Any) -> DictLikeGlobals:
    """Cast state.globals to dict-like interface.
    
    This is a workaround for type checkers not understanding
    that SimStateGlobals has dict-like methods.
    """
    return globals_obj  # type: ignore