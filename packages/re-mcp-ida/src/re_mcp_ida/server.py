# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""In-process MCP adapter backed by a shared IDA Nexus lease.

Tools and resources are discovered at runtime from a licensed Nexus instance.
The supervisor hosts these adapters; Nexus exclusively owns engine processes
and dispatches code on the IDA thread.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from typing import Any

import anyio
from fastmcp import FastMCP
from fastmcp.resources.base import Resource, ResourceContent, ResourceResult
from fastmcp.resources.template import ResourceTemplate
from fastmcp.tools.base import Tool, ToolResult
from ida_nexus import NexusError, RemoteError
from jsonschema import Draft202012Validator, ValidationError
from mcp.types import TextContent
from pydantic import PrivateAttr

from re_mcp_ida.exceptions import IDAError
from re_mcp_ida.nexus import NexusSession

_UPPERCASE_WORDS = frozenset(
    {"abi", "asm", "cfg", "elf", "exe", "flirt", "ida", "idc", "ids", "io", "mcp", "pat"}
)


class NexusTool(Tool):
    _server: Any = PrivateAttr()

    async def run(self, arguments: dict[str, Any]) -> ToolResult:
        # Custom Tool subclasses do not get FunctionTool's Pydantic argument
        # validation. Validate before lifecycle calls as well as remote dispatch.
        try:
            Draft202012Validator(self.parameters).validate(arguments)
        except ValidationError as exc:
            raise IDAError(exc.message, error_type="InvalidArgument") from exc
        result = await self._server.dispatch(self.name, arguments)
        # FastMCP wraps unions/non-object returns at the worker boundary. The
        # supervisor recognizes this marker and unwraps them for routed tools.
        wrap = bool(self.output_schema and self.output_schema.get("x-fastmcp-wrap-result"))
        return ToolResult(
            content=[TextContent(type="text", text=json.dumps(result))],
            structured_content={"result": result} if wrap else result,
            meta={"fastmcp": {"wrap_result": True}} if wrap else None,
        )


class NexusResource(Resource):
    _server: Any = PrivateAttr()

    async def read(self) -> ResourceResult:
        result = await self._server.dispatch(self.name, {}, "resource")
        return ResourceResult([ResourceContent(result, mime_type=self.mime_type)])


class NexusTemplate(ResourceTemplate):
    _server: Any = PrivateAttr()

    async def _read(self, uri: str, params: dict[str, Any], task_meta=None) -> ResourceResult:
        result = await self._server.dispatch(self.name, params, "resource")
        return ResourceResult([ResourceContent(result, mime_type=self.mime_type)])


class IDAServer(FastMCP):
    """Expose live IDA tool registrations while dispatching through Nexus."""

    def __init__(self, *args, session: NexusSession | None = None, **kwargs):
        self.session = session if session is not None else NexusSession()
        self._dispatch_lock = asyncio.Lock()
        self._initialize_lock = asyncio.Lock()
        self._initialized = False
        super().__init__(*args, lifespan=self._lease_lifespan, **kwargs)

    def _register_schemas(self, schemas):
        for spec in schemas["tools"]:
            if spec["name"] == "run_script" and not self.session.allow_scripts:
                continue
            meta = spec.get("_meta") or {}
            tool = NexusTool(
                name=spec["name"],
                title=spec.get("title"),
                description=spec.get("description"),
                parameters=spec["inputSchema"],
                output_schema=spec.get("outputSchema"),
                annotations=spec.get("annotations"),
                icons=spec.get("icons"),
                meta=meta,
                tags=set(meta.get("fastmcp", {}).get("tags", [])),
            )
            tool._server = self
            self.add_tool(tool)
        for spec in schemas["resources"]:
            resource = NexusResource(**spec)
            resource._server = self
            self.add_resource(resource)
        for spec in schemas["templates"]:
            template = NexusTemplate(**spec)
            template._server = self
            self.add_template(template)

    @contextlib.asynccontextmanager
    async def _lease_lifespan(self, _app):
        try:
            async with self._initialize_lock:
                if not self._initialized:
                    schemas = await self.dispatch("", {}, "schemas")
                    self._register_schemas(schemas)
                    self._initialized = True
            yield
        finally:
            with anyio.CancelScope(shield=True):
                async with self._dispatch_lock:
                    await asyncio.to_thread(self.session.close_database, save=True)

    async def dispatch(self, name: str, arguments: dict, kind: str = "tool"):
        # Blocking HTTP belongs off the MCP loop. Cancelling the await alone
        # would orphan a mutating call: cancel through Nexus and drain it before
        # admitting another request or releasing the lease. Never retry a call.
        async with self._dispatch_lock:
            task = asyncio.create_task(asyncio.to_thread(self.session.call, name, arguments, kind))
            try:
                return await asyncio.shield(task)
            except asyncio.CancelledError:
                with anyio.CancelScope(shield=True):
                    await asyncio.to_thread(self.session.cancel)
                    with contextlib.suppress(Exception):
                        await asyncio.shield(task)
                raise
            except NexusError as exc:
                error_type = exc.code if isinstance(exc, RemoteError) else type(exc).__name__
                raise IDAError(str(exc), error_type=error_type) from exc
            except (OSError, ValueError, TypeError) as exc:
                raise IDAError(str(exc), error_type=type(exc).__name__) from exc
