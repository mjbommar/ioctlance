"""File operation hooks for IOCTLance."""

import logging

import claripy

from .base import BaseHook

logger = logging.getLogger(__name__)


def register_hooks(project) -> None:
    """Register file operation hooks.

    Args:
        project: angr project to register hooks with
    """
    # Use common calling convention helper
    cc = BaseHook.get_calling_convention(project)

    # Register ZwCreateFile
    try:
        project.hook_symbol("ZwCreateFile", ZwCreateFile(cc=cc), replace=True)
        logger.debug("Hooked ZwCreateFile")
    except Exception as e:
        logger.debug(f"Failed to hook ZwCreateFile: {e}")

    # Register ZwOpenFile
    try:
        project.hook_symbol("ZwOpenFile", ZwOpenFile(cc=cc), replace=True)
        logger.debug("Hooked ZwOpenFile")
    except Exception as e:
        logger.debug(f"Failed to hook ZwOpenFile: {e}")

    # Register ZwWriteFile
    try:
        project.hook_symbol("ZwWriteFile", ZwWriteFile(cc=cc), replace=True)
        logger.debug("Hooked ZwWriteFile")
    except Exception as e:
        logger.debug(f"Failed to hook ZwWriteFile: {e}")
    # Register ZwReadFile
    try:
        project.hook_symbol("ZwReadFile", ZwReadFile(cc=cc), replace=True)
        logger.debug("Hooked ZwReadFile")
    except Exception as e:
        logger.debug(f"Failed to hook ZwReadFile: {e}")

    # Register ZwDeleteFile
    try:
        project.hook_symbol("ZwDeleteFile", ZwDeleteFile(cc=cc), replace=True)
        logger.debug("Hooked ZwDeleteFile")
    except Exception as e:
        logger.debug(f"Failed to hook ZwDeleteFile: {e}")


class ZwCreateFile(BaseHook):
    """Hook for ZwCreateFile."""

    def run(
        self,
        file_handle,
        desired_access,
        object_attributes,
        io_status_block,
        allocation_size,
        file_attributes,
        share_access,
        create_disposition,
        create_options,
        ea_buffer,
        ea_length,
    ):
        """Execute ZwCreateFile hook."""
        logger.debug(f"[ZwCreateFile] Called at {hex(self.state.addr)}")

        context = self.get_context()
        if context:
            for detector in getattr(context, "detectors", []) or []:
                # Prefer unified event interface
                try:
                    if hasattr(detector, "check_state"):
                        vuln = detector.check_state(
                            self.state,
                            "function_call",
                            function_name="ZwCreateFile",
                            file_handle=file_handle,
                            desired_access=desired_access,
                            object_attributes=object_attributes,
                            io_status_block=io_status_block,
                            allocation_size=allocation_size,
                            file_attributes=file_attributes,
                            share_access=share_access,
                            create_disposition=create_disposition,
                            create_options=create_options,
                            ea_buffer=ea_buffer,
                            ea_length=ea_length,
                        )
                        if vuln:
                            context.add_vulnerability(vuln)
                            logger.info(f"[ZwCreateFile] Vulnerability detected: {vuln['title']}")
                            # Don't break to let other detectors run
                except Exception:
                    pass
                # Back-compat: call any legacy detector-specific methods
                try:
                    if hasattr(detector, "check_zwcreatefile"):
                        vuln = detector.check_zwcreatefile(
                            self.state,
                            file_handle,
                            desired_access,
                            object_attributes,
                            io_status_block,
                            allocation_size,
                            file_attributes,
                            share_access,
                            create_disposition,
                            create_options,
                            ea_buffer,
                            ea_length,
                        )
                        if vuln:
                            context.add_vulnerability(vuln)
                            logger.info(f"[ZwCreateFile] Vulnerability detected: {vuln['title']}")
                except Exception:
                    pass

        # Return STATUS_SUCCESS
        return claripy.BVV(0, self.state.arch.bits)


class ZwOpenFile(BaseHook):
    """Hook for ZwOpenFile."""

    def run(
        self,
        file_handle,
        desired_access,
        object_attributes,
        io_status_block,
        share_access,
        open_options,
    ):
        """Execute ZwOpenFile hook."""
        logger.debug(f"[ZwOpenFile] Called at {hex(self.state.addr)}")

        context = self.get_context()
        if context:
            for detector in getattr(context, "detectors", []) or []:
                try:
                    if hasattr(detector, "check_state"):
                        vuln = detector.check_state(
                            self.state,
                            "function_call",
                            function_name="ZwOpenFile",
                            file_handle=file_handle,
                            desired_access=desired_access,
                            object_attributes=object_attributes,
                            io_status_block=io_status_block,
                            share_access=share_access,
                            open_options=open_options,
                        )
                        if vuln:
                            context.add_vulnerability(vuln)
                            logger.info(f"[ZwOpenFile] Vulnerability detected: {vuln['title']}")
                except Exception:
                    pass
                try:
                    if hasattr(detector, "check_zwopenfile"):
                        vuln = detector.check_zwopenfile(
                            self.state,
                            file_handle,
                            desired_access,
                            object_attributes,
                            io_status_block,
                            share_access,
                            open_options,
                        )
                        if vuln:
                            context.add_vulnerability(vuln)
                            logger.info(f"[ZwOpenFile] Vulnerability detected: {vuln['title']}")
                except Exception:
                    pass

        # Return STATUS_SUCCESS
        return claripy.BVV(0, self.state.arch.bits)


class ZwWriteFile(BaseHook):
    """Hook for ZwWriteFile."""

    def run(
        self,
        file_handle,
        event,
        apc_routine,
        apc_context,
        io_status_block,
        buffer,
        length,
        byte_offset,
        key,
    ):
        """Execute ZwWriteFile hook."""
        logger.debug(f"[ZwWriteFile] Called at {hex(self.state.addr)}")

        context = self.get_context()
        if context:
            for detector in getattr(context, "detectors", []) or []:
                try:
                    if hasattr(detector, "check_state"):
                        vuln = detector.check_state(
                            self.state,
                            "function_call",
                            function_name="ZwWriteFile",
                            file_handle=file_handle,
                            event=event,
                            apc_routine=apc_routine,
                            apc_context=apc_context,
                            io_status_block=io_status_block,
                            buffer=buffer,
                            length=length,
                            byte_offset=byte_offset,
                            key=key,
                        )
                        if vuln:
                            context.add_vulnerability(vuln)
                            logger.info(f"[ZwWriteFile] Vulnerability detected: {vuln['title']}")
                except Exception:
                    pass
                try:
                    if hasattr(detector, "check_zwwritefile"):
                        vuln = detector.check_zwwritefile(
                            self.state,
                            file_handle,
                            event,
                            apc_routine,
                            apc_context,
                            io_status_block,
                            buffer,
                            length,
                            byte_offset,
                            key,
                        )
                        if vuln:
                            context.add_vulnerability(vuln)
                            logger.info(f"[ZwWriteFile] Vulnerability detected: {vuln['title']}")
                except Exception:
                    pass

        # Return STATUS_SUCCESS
        return claripy.BVV(0, self.state.arch.bits)


class ZwReadFile(BaseHook):
    """Hook for ZwReadFile."""

    def run(
        self,
        file_handle,
        event,
        apc_routine,
        apc_context,
        io_status_block,
        buffer,
        length,
        byte_offset,
        key,
    ):
        """Execute ZwReadFile hook."""
        logger.debug(f"[ZwReadFile] Called at {hex(self.state.addr)}")

        context = self.get_context()
        if context:
            for detector in getattr(context, "detectors", []) or []:
                try:
                    if hasattr(detector, "check_state"):
                        vuln = detector.check_state(
                            self.state,
                            "function_call",
                            function_name="ZwReadFile",
                            file_handle=file_handle,
                            event=event,
                            apc_routine=apc_routine,
                            apc_context=apc_context,
                            io_status_block=io_status_block,
                            buffer=buffer,
                            length=length,
                            byte_offset=byte_offset,
                            key=key,
                        )
                        if vuln:
                            context.add_vulnerability(vuln)
                            logger.info(f"[ZwReadFile] Vulnerability detected: {vuln['title']}")
                except Exception:
                    pass

        # Return STATUS_SUCCESS
        return claripy.BVV(0, self.state.arch.bits)


class ZwDeleteFile(BaseHook):
    """Hook for ZwDeleteFile."""

    def run(self, object_attributes):
        """Execute ZwDeleteFile hook."""
        logger.debug(f"[ZwDeleteFile] Called at {hex(self.state.addr)}")

        context = self.get_context()
        if context:
            for detector in getattr(context, "detectors", []) or []:
                try:
                    if hasattr(detector, "check_state"):
                        vuln = detector.check_state(
                            self.state,
                            "function_call",
                            function_name="ZwDeleteFile",
                            object_attributes=object_attributes,
                        )
                        if vuln:
                            context.add_vulnerability(vuln)
                            logger.info(f"[ZwDeleteFile] Vulnerability detected: {vuln['title']}")
                except Exception:
                    pass
                try:
                    if hasattr(detector, "check_zwdeletefile"):
                        vuln = detector.check_zwdeletefile(self.state, object_attributes)
                        if vuln:
                            context.add_vulnerability(vuln)
                            logger.info(f"[ZwDeleteFile] Vulnerability detected: {vuln['title']}")
                except Exception:
                    pass

        # Return STATUS_SUCCESS
        return claripy.BVV(0, self.state.arch.bits)
