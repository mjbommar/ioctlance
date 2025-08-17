"""File operation hooks for IOCTLance."""

import logging

import angr

logger = logging.getLogger(__name__)


def register_hooks(project) -> None:
    """Register file operation hooks.

    Args:
        project: angr project to register hooks with
    """
    from angr import SimCC

    # Get the default calling convention
    try:
        cc = project.factory.cc()
    except:
        cc = SimCC[project.arch.name]()

    # Register ZwCreateFile
    try:
        project.hook_symbol("ZwCreateFile", ZwCreateFile(cc=cc), replace=True)
        logger.debug("Hooked ZwCreateFile")
    except:
        pass

    # Register ZwOpenFile
    try:
        project.hook_symbol("ZwOpenFile", ZwOpenFile(cc=cc), replace=True)
        logger.debug("Hooked ZwOpenFile")
    except:
        pass

    # Register ZwWriteFile
    try:
        project.hook_symbol("ZwWriteFile", ZwWriteFile(cc=cc), replace=True)
        logger.debug("Hooked ZwWriteFile")
    except:
        pass

    # Register ZwDeleteFile
    try:
        project.hook_symbol("ZwDeleteFile", ZwDeleteFile(cc=cc), replace=True)
        logger.debug("Hooked ZwDeleteFile")
    except:
        pass


class ZwCreateFile(angr.SimProcedure):
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

        # Check with file operation detector
        if hasattr(self.state, "ioctlance_context"):
            context = self.state.ioctlance_context
            for detector in context.detectors:
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
                        context.vulnerabilities.append(vuln)
                        logger.info(f"[ZwCreateFile] Vulnerability detected: {vuln['title']}")

        # Return STATUS_SUCCESS
        return self.state.solver.BVV(0, self.state.arch.bits)


class ZwOpenFile(angr.SimProcedure):
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

        # Check with file operation detector
        if hasattr(self.state, "ioctlance_context"):
            context = self.state.ioctlance_context
            for detector in context.detectors:
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
                        context.vulnerabilities.append(vuln)
                        logger.info(f"[ZwOpenFile] Vulnerability detected: {vuln['title']}")

        # Return STATUS_SUCCESS
        return self.state.solver.BVV(0, self.state.arch.bits)


class ZwWriteFile(angr.SimProcedure):
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

        # Check with file operation detector
        if hasattr(self.state, "ioctlance_context"):
            context = self.state.ioctlance_context
            for detector in context.detectors:
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
                        context.vulnerabilities.append(vuln)
                        logger.info(f"[ZwWriteFile] Vulnerability detected: {vuln['title']}")

        # Return STATUS_SUCCESS
        return self.state.solver.BVV(0, self.state.arch.bits)


class ZwDeleteFile(angr.SimProcedure):
    """Hook for ZwDeleteFile."""

    def run(self, object_attributes):
        """Execute ZwDeleteFile hook."""
        logger.debug(f"[ZwDeleteFile] Called at {hex(self.state.addr)}")

        # Check with file operation detector
        if hasattr(self.state, "ioctlance_context"):
            context = self.state.ioctlance_context
            for detector in context.detectors:
                if hasattr(detector, "check_zwdeletefile"):
                    vuln = detector.check_zwdeletefile(self.state, object_attributes)
                    if vuln:
                        context.vulnerabilities.append(vuln)
                        logger.info(f"[ZwDeleteFile] Vulnerability detected: {vuln['title']}")

        # Return STATUS_SUCCESS
        return self.state.solver.BVV(0, self.state.arch.bits)
