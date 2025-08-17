"""Windows kernel API hooks for symbolic execution."""

from .base import BaseHook
from .executive import *
from .io_manager import *
from .kernel import *
from .memcpy import *
from .memory import *
from .native_api import *
from .object_manager import *
from .process import *
from .registry import *
from .runtime import *
from .utility import *

__all__ = [
    "BaseHook",
    "register_all_hooks",
    "get_hook_by_name",
]


def register_all_hooks(project) -> None:
    """Register all hooks with the angr project.

    Args:
        project: angr project to register hooks with
    """
    from . import (
        executive,
        file_operations,
        io_manager,
        kernel,
        memcpy,
        memory,
        native_api,
        object_manager,
        process,
        registry,
        runtime,
        utility,
    )

    modules = [
        io_manager,
        memcpy,
        memory,
        kernel,
        registry,
        process,
        object_manager,
        executive,
        native_api,
        runtime,
        utility,
        file_operations,
    ]

    for module in modules:
        if hasattr(module, "register_hooks"):
            module.register_hooks(project)


def get_hook_by_name(name: str):
    """Get a hook class by its name.

    Args:
        name: Name of the hook class

    Returns:
        Hook class or None if not found
    """
    from . import (
        executive,
        file_operations,
        io_manager,
        kernel,
        memcpy,
        memory,
        native_api,
        object_manager,
        process,
        registry,
        runtime,
        utility,
    )

    modules = [
        io_manager,
        memcpy,
        memory,
        kernel,
        registry,
        process,
        object_manager,
        executive,
        native_api,
        runtime,
        utility,
        file_operations,
    ]

    for module in modules:
        if hasattr(module, name):
            return getattr(module, name)

    return None
