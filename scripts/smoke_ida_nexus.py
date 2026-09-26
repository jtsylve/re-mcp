# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Live Nexus/MCP smoke test; mutates ONLY a temporary copy of the input.

uv run python scripts/smoke_ida_nexus.py path/to/small/executable
Requires configured IDA/idalib (and Hex-Rays unless --skip-decompiler is set).
Launches the installed re-mcp-ida CLI over stdio, exercising initialization,
live schema discovery, analysis, tools, resources, shared leases and persistence.
"""

import argparse
import asyncio
import json
import os
import shutil
import tempfile
from pathlib import Path

from fastmcp import Client
from fastmcp.client import StdioTransport
from ida_nexus import DatabaseHandle


async def smoke(binary: str, function: str | None = None, *, decompile: bool = True):
    executable = shutil.which("re-mcp-ida")
    if executable is None:
        raise RuntimeError("re-mcp-ida is not installed; run uv sync first")
    transport = StdioTransport(
        command=executable,
        args=["stdio"],
        env={**os.environ, "RE_MCP_BACKEND": "ida"},
        keep_alive=False,
    )
    observer = None
    try:
        async with Client(transport, init_timeout=180, timeout=180) as client:
            tools = {tool.name for tool in await client.list_tools()}
            assert {"open_database", "list_functions", "decompile_function"} <= tools
            assert await client.list_prompts()
            assert await client.list_resource_templates()
            opened = await client.call_tool(
                "open_database", {"file_path": binary, "options": "-a- -P+"}
            )
            database = opened.structured_content["database"]
            await client.call_tool("wait_for_analysis", {"database": database})
            info = (
                await client.call_tool("get_database_info", {"database": database})
            ).structured_content
            observer = await asyncio.to_thread(DatabaseHandle.open, binary)
            functions = (
                await client.call_tool("list_functions", {"database": database, "limit": 2})
            ).structured_content
            assert functions["items"]
            grouped = await client.call_tool(
                "list_functions",
                {"database": database, "filters": [{"pattern": ".", "limit": 1}]},
            )
            assert grouped.structured_content["groups"][0]["matches"]
            exported = await client.call_tool(
                "call",
                {"tool": "export_all_disassembly", "arguments": {"database": database, "limit": 1}},
            )
            assert not exported.is_error
            address = function or functions["items"][0]["start"]
            disassembly = await client.call_tool(
                "disassemble_function", {"database": database, "address": address}
            )
            assert disassembly.structured_content["instructions"]
            address = disassembly.structured_content["address"]
            if decompile:
                result = await client.call_tool(
                    "decompile_function", {"database": database, "address": address}
                )
                assert result.structured_content["pseudocode"].strip()
            strings = await client.call_tool("get_strings", {"database": database, "limit": 2})
            assert "items" in strings.structured_content
            xrefs = await client.call_tool(
                "get_xrefs_to", {"database": database, "address": address}
            )
            assert "items" in xrefs.structured_content
            invalid = await client.call_tool(
                "disassemble_function",
                {"database": database, "address": "__re_mcp_nonexistent_function__"},
                raise_on_error=False,
            )
            assert invalid.is_error
            await client.call_tool(
                "set_comment",
                {
                    "database": database,
                    "address": address,
                    "comment": "RE-MCP Nexus smoke test",
                },
            )
            read_code = f"import idc\nidc.get_cmt({int(address, 16)}, False)"
            assert (await asyncio.to_thread(observer.execute_python, read_code))[
                "result"
            ] == "RE-MCP Nexus smoke test"
            resource = await client.read_resource(f"ida://{database}/idb/entrypoints?limit=2")
            assert "entries" in json.loads(resource[0].text)
            await client.call_tool("save_database", {"database": database})
            await client.call_tool("close_database", {"database": database})
            # Closing our MCP adapter must leave another client's lease usable.
            assert (await asyncio.to_thread(observer.execute_python, read_code))[
                "result"
            ] == "RE-MCP Nexus smoke test"
            await asyncio.to_thread(observer.close, wait_for_database=True)
            observer = None
            reopened = await client.call_tool("open_database", {"file_path": info["file_path"]})
            database = reopened.structured_content["database"]
            await client.call_tool("wait_for_analysis", {"database": database})
            check = await client.call_tool(
                "call",
                {
                    "tool": "get_comment",
                    "arguments": {"database": database, "address": address},
                },
            )
            assert "RE-MCP Nexus smoke test" in str(check)
            await client.call_tool("close_database", {"database": database})
            databases = await client.call_tool("list_databases", {})
            assert databases.structured_content["database_count"] == 0
        decompiler_status = "decompilation" if decompile else "decompilation skipped"
        print(
            f"PASS: CLI stdio, schemas, analysis, {decompiler_status}, queries, mutations, resources, shared leases, save/reopen and shutdown"
        )
    finally:
        if observer is not None:
            await asyncio.to_thread(observer.close, wait_for_database=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument(
        "--function", help="Function address/name to test; defaults to the first function"
    )
    parser.add_argument(
        "--skip-decompiler", action="store_true", help="For licenses without Hex-Rays"
    )
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="re-mcp-nexus-smoke-") as directory:
        binary = shutil.copyfile(args.binary, Path(directory) / args.binary.name)
        asyncio.run(smoke(str(binary), args.function, decompile=not args.skip_decompiler))
