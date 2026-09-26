# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Engine-free Nexus lease adapter. Never imports idapro or ida_* modules."""

from __future__ import annotations

import copy
import functools
import os
import site
import sys
import tempfile
import threading
import time
from pathlib import Path

import re_mcp
from ida_nexus import DatabaseHandle, DatabaseOpenOptions, RemoteModule

from re_mcp_ida.cli_options import parse_ida_options
from re_mcp_ida.exceptions import (
    IDAError,
    check_fat_binary,
    check_processor_ambiguity,
    slice_sidecar_stem,
)

_remote = RemoteModule(
    Path(__file__).with_name("nexus_runtime.py"), operation_label="RE-MCP", codec="json"
)


@_remote.function()
def invoke(
    paths: list,
    python_version: list,
    name: str,
    arguments: dict,
    kind: str = "tool",
    allow_scripts: bool = False,
) -> dict: ...


def open_options(
    file_path: str,
    run_auto_analysis: bool = False,
    force_new: bool = False,
    processor: str = "",
    loader: str = "",
    base_address: str = "",
    fat_arch: str = "",
    options: str = "",
) -> DatabaseOpenOptions:
    """Translate our public import settings to Nexus's typed spawn options."""
    extra = parse_ida_options(options)
    for field, supplied, parameter in (
        ("processor", processor, "processor"),
        ("file_type", loader or fat_arch, "loader/fat_arch"),
        ("image_base", base_address, "base_address"),
    ):
        if supplied and field in extra:
            raise IDAError(
                f"options duplicates {parameter}; use only the structured parameter",
                error_type="InvalidArgument",
            )
    if run_auto_analysis and extra.get("auto_analysis") is False:
        raise IDAError("-a conflicts with run_auto_analysis=True", error_type="InvalidArgument")
    force_new = force_new or extra.pop("new_database", False)
    processor = extra.pop("processor", processor)
    loader = extra.pop("file_type", loader)
    check_processor_ambiguity(processor, file_path, force_new, fat_arch)
    index = check_fat_binary(file_path, fat_arch, force_new)
    if index is not None and loader:
        raise IDAError(
            "loader and fat_arch cannot both be specified: fat_arch selects the loader",
            error_type="InvalidArgument",
        )
    try:
        image_base = int(base_address, 0) if base_address else extra.pop("image_base", None)
        return DatabaseOpenOptions(
            auto_analysis=extra.pop("auto_analysis", run_auto_analysis),
            new_database=force_new,
            processor=processor or None,
            # Fat Mach-O is a loader selector, NOT an archive member (-Ttype:member).
            file_type=f"Fat Mach-O file, {index}" if index is not None else loader or None,
            image_base=image_base,
            output_database=slice_sidecar_stem(file_path, fat_arch) + ".i64" if fat_arch else None,
            **extra,
        )
    except (TypeError, ValueError) as exc:
        raise IDAError(str(exc), error_type="InvalidArgument") from exc


class NexusSession:
    """One adapter owns exactly one Nexus lease, not the underlying process."""

    def __init__(self):
        self.handle: DatabaseHandle | None = None
        self.allow_scripts = os.environ.get("IDA_MCP_ALLOW_SCRIPTS", "").lower() in (
            "1",
            "true",
            "yes",
        )
        self.paths = [
            [str(Path(__file__).resolve().parents[1]), False],
            [str(Path(re_mcp.__file__).resolve().parents[1]), False],
            *[[path, True] for path in site.getsitepackages()],
        ]

    def _require_handle(self) -> DatabaseHandle:
        if self.handle is None:
            raise IDAError("No database is open. Use open_database first.", error_type="NoDatabase")
        return self.handle

    def _invoke(self, name: str, arguments: dict, kind: str = "tool"):
        result = invoke(
            self._require_handle(),
            self.paths,
            list(sys.version_info[:2]),
            name,
            arguments,
            kind,
            self.allow_scripts,
        )
        if "error" in result:
            # Preserve the existing JSON error taxonomy exactly across the RPC.
            from fastmcp.exceptions import ToolError  # noqa: PLC0415

            raise ToolError(result["error"])
        return result["result"]

    def open_database(self, file_path: str, **kwargs) -> dict:
        options = open_options(file_path, **kwargs)
        if self.handle is not None:
            raise IDAError("This adapter already has a database lease", error_type="AlreadyOpen")
        handle = DatabaseHandle.open(
            os.path.realpath(os.path.expanduser(file_path)), options=options
        )
        self.handle = handle
        try:
            result = self._invoke("", {}, "open_info")
            # No process belongs to this in-process adapter. In particular,
            # never expose Nexus's or the GUI's PID to supervisor kill logic.
            result["pid"] = None
            return result
        except BaseException:
            self.handle = None
            handle.close(wait_for_database=True)
            raise

    def close_database(self, save: bool = True) -> dict:
        handle = self.handle
        if handle is None:
            return {"status": "no_database_open"}
        try:
            if save and not handle.save_database()["saved"]:
                raise IDAError("Failed to save database", error_type="SaveFailed")
        finally:
            try:
                handle.close(wait_for_database=True)
            finally:
                self.handle = None
        # save=False skips the explicit save; Nexus can still save on final
        # managed-worker release. It never discards another client's changes.
        return {"status": "released", "path": handle.instance.idb_path, "saved": save}

    def call(self, name: str, arguments: dict, kind: str = "tool"):
        if kind == "schemas":
            return discover_schemas()
        if kind == "tool":
            if name == "open_database":
                return self.open_database(**arguments)
            if name == "close_database":
                return self.close_database(**arguments)
            if name == "wait_for_analysis":
                start = time.monotonic()
                self._require_handle().wait_autoanalysis()
                result = self._invoke("", {}, "analysis_summary")
                result["elapsed_seconds"] = round(time.monotonic() - start, 1)
                return result
            if (
                name == "save_database"
                and not arguments.get("outfile")
                and arguments.get("flags", -1) < 0
            ):
                result = self._require_handle().save_database()
                if not result["saved"]:
                    raise IDAError("Failed to save database", error_type="SaveFailed")
                return {"status": "saved", "path": result["idb_path"]}
            if name == "restore_snapshot":
                raise IDAError(
                    "Restoring a snapshot would replace a shared database. Open the snapshot "
                    "as a separate database instead.",
                    error_type="Unsupported",
                )
            if name == "run_script" and not self.allow_scripts:
                raise IDAError("run_script is disabled", error_type="Unsupported")
        return self._invoke(name, arguments, kind)

    def cancel(self):
        handle = self.handle
        if handle is not None:
            handle.cancel_active()


_discovery_lock = threading.Lock()


@functools.cache
def _discover_schemas_once() -> dict:
    """Discover tools in a temporary licensed Nexus instance, as at startup before.

    Nexus's execution API requires an IDB, so use a private throwaway binary.
    No tool is run and no user database is modified during discovery. Metadata
    is cached only for this supervisor's lifetime, like WorkerPoolProvider.
    """
    session = NexusSession()
    with tempfile.TemporaryDirectory(prefix="re-mcp-ida-discovery-") as directory:
        binary = Path(directory) / "probe.bin"
        binary.write_bytes(b"\x90\xc3")
        session.handle = DatabaseHandle.open(
            str(binary),
            options=DatabaseOpenOptions(
                processor="metapc",
                file_type="Binary file",
                auto_analysis=False,
            ),
        )
        try:
            return session._invoke("", {}, "schemas")
        finally:
            session.close_database(save=False)


def discover_schemas() -> dict:
    with _discovery_lock:
        return copy.deepcopy(_discover_schemas_once())
