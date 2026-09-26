# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Tool dispatcher installed by RemoteModule in Nexus's IDA interpreter.

No IDA imports at module load time. All engine work, including coroutine bodies,
executes synchronously on the IDA thread selected by Nexus, never a thread pool.
The registry is interpreter-local; it owns no database or client lease.
"""

from __future__ import annotations

# Imports inside functions deliberately run only after remote dependency setup.
# ruff: noqa: PLC0415
import asyncio
import importlib
import inspect
import pkgutil
import sys
import typing

_registry = None


class _Progress:
    async def report_progress(self, *args, **kwargs):
        # MCP transport/context lives in the adapter, not the IDA interpreter.
        pass


class _Registry:
    # Register once, authorize per invocation; never change the GUI environment.
    allow_scripts = True

    def __init__(self):
        from re_mcp.server import BackendServer

        from re_mcp_ida.server import _UPPERCASE_WORDS

        self.tools = {}
        self.resources = {}
        self.server = BackendServer("IDA tool discovery", on_duplicate="error")
        self.server._uppercase_words = _UPPERCASE_WORDS

    def tool(self, **kwargs):
        def register(fn):
            self.tools[fn.__name__] = fn
            self.server.tool(**kwargs)(fn)
            return fn

        return register

    def resource(self, uri, **kwargs):
        def register(fn):
            self.resources[fn.__name__] = fn
            self.server.resource(uri, **kwargs)(fn)
            return fn

        return register


def _load(paths, python_version):
    global _registry  # noqa: PLW0603
    if sys.version_info < (3, 12):  # noqa: UP036 — remote GUI may use older Python
        raise RuntimeError("RE-MCP tools require Python 3.12+ in the IDA interpreter")
    if _registry is not None:
        return _registry
    # Nexus is local-only. Expose our source roots without initializing idalib.
    # Dependency paths are usable only with the same Python ABI; GUI users with
    # another Python version must install re-mcp-ida in that interpreter.
    for path, dependency in paths:
        if dependency and list(sys.version_info[:2]) != python_version:
            continue
        if path not in sys.path:
            sys.path.append(path)
    try:
        from re_mcp_ida import resources, tools

        registry = _Registry()
        resources.register(registry)
        for entry in pkgutil.iter_modules(tools.__path__):
            module = importlib.import_module(f"re_mcp_ida.tools.{entry.name}")
            if hasattr(module, "register"):
                module.register(registry)
    except ImportError as exc:
        raise RuntimeError(
            "Cannot load RE-MCP tools in the Nexus IDA interpreter. Install "
            "re-mcp-ida and its dependencies in IDA's Python environment "
            "(Python >=3.12), then restart that instance. " + str(exc)
        ) from exc
    _registry = registry
    return registry


async def _describe(registry):
    """Get schemas from the same live registrations used for execution."""
    fields = {
        "name",
        "uri",
        "uri_template",
        "description",
        "title",
        "mime_type",
        "annotations",
        "tags",
        "meta",
        "version",
        "icons",
        "parameters",
    }
    return {
        "tools": [
            tool.to_mcp_tool().model_dump(mode="json", by_alias=True)
            for tool in await registry.server.list_tools()
        ],
        "resources": [
            resource.model_dump(mode="json", include=fields)
            for resource in await registry.server.list_resources()
        ],
        "templates": [
            template.model_dump(mode="json", include=fields)
            for template in await registry.server.list_resource_templates()
        ],
    }


def _call(fn, arguments):
    from pydantic import TypeAdapter

    # Resolve annotations in the original tool's module, not the decorator's.
    original = inspect.unwrap(fn)
    bound = inspect.signature(original).bind(**arguments)
    bound.apply_defaults()
    hints = typing.get_type_hints(original, include_extras=True)
    for name, value in bound.arguments.items():
        if name == "ctx":
            bound.arguments[name] = _Progress()
        elif name in hints:
            bound.arguments[name] = TypeAdapter(hints[name]).validate_python(value)
    result = fn(*bound.args, **bound.kwargs)
    if inspect.isawaitable(result):
        result = asyncio.run(result)
    if hasattr(result, "model_dump"):
        return result.model_dump(mode="json", by_alias=True)
    return result


def invoke(
    paths: list,
    python_version: list,
    name: str,
    arguments: dict,
    kind: str = "tool",
    allow_scripts: bool = False,
) -> dict:
    registry = _load(paths, python_version)
    from re_mcp.exceptions import BackendError

    from re_mcp_ida.exceptions import IDAError

    try:
        if kind == "schemas":
            result = asyncio.run(_describe(registry))
        elif kind == "open_info":
            from re_mcp_ida.session import session

            result = _call(registry.tools["get_database_info"], {})
            result.update(status="ok", capabilities=session.capabilities, warnings=[])
        elif kind == "analysis_summary":
            from re_mcp_ida.helpers import build_strlist

            info = _call(registry.tools["get_database_info"], {})
            result = {
                key: info[key]
                for key in (
                    "function_count",
                    "segment_count",
                    "entry_point_count",
                    "min_address",
                    "max_address",
                )
            }
            result.update(status="analysis_complete", string_count=build_strlist())
        else:
            if kind not in {"tool", "resource"}:
                raise IDAError("Invalid dispatch kind", error_type="InvalidArgument")
            if name in {"open_database", "close_database", "wait_for_analysis", "restore_snapshot"}:
                raise IDAError(
                    "This operation must use the Nexus lifecycle API", error_type="Unsupported"
                )
            if name == "run_script" and not allow_scripts:
                raise IDAError("run_script is disabled", error_type="Unsupported")
            functions = registry.tools if kind == "tool" else registry.resources
            result = _call(functions[name], arguments)
        return {"result": result}
    except BackendError as exc:
        return {"error": str(exc)}
