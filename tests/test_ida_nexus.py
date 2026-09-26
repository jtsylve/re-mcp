# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Engine-free Nexus adapter tests. Real lifecycle smoke test lives in scripts/."""

from __future__ import annotations

import asyncio
import json
import os
import struct
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError
from ida_nexus import DatabaseBusyError, RemoteError
from pydantic import BaseModel, ValidationError
from re_mcp_ida import nexus, nexus_runtime
from re_mcp_ida.exceptions import IDAError
from re_mcp_ida.server import IDAServer


@pytest.fixture(scope="module")
def schemas():
    # Generate schemas from the real tool registrations with conftest's IDA
    # stubs. Production obtains the same metadata in a licensed Nexus process.
    registry = nexus_runtime._load([], list(sys.version_info[:2]))
    return asyncio.run(nexus_runtime._describe(registry))


def _server(session, schemas):
    server = IDAServer("test", session=session)
    server._register_schemas(schemas)
    server._initialized = True
    return server


def test_importing_adapter_does_not_initialize_ida():
    # A subprocess avoids the test suite's global IDAPython stubs.
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
import sys
from re_mcp_ida.server import IDAServer
IDAServer('test')
assert 'idapro' not in sys.modules
assert 're_mcp_ida.helpers' not in sys.modules
assert not any(n.startswith('ida_') and not n.startswith('ida_nexus') for n in sys.modules)
""",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr


def test_legacy_engine_bootstrap_and_worker_entry_point_are_removed():
    from importlib.metadata import distribution  # noqa: PLC0415

    import re_mcp_ida  # noqa: PLC0415
    from re_mcp_ida import helpers, server  # noqa: PLC0415

    assert not hasattr(re_mcp_ida, "bootstrap")
    assert not hasattr(re_mcp_ida, "_find_idapro_wheel")
    assert not hasattr(server, "main")
    assert not hasattr(helpers, "set_main_executor")
    scripts = {
        entry.name
        for entry in distribution("re-mcp-ida").entry_points
        if entry.group == "console_scripts"
    }
    assert scripts == {"re-mcp-ida"}


def test_ida_helpers_never_use_the_old_executor(monkeypatch):
    from re_mcp import helpers as core_helpers  # noqa: PLC0415
    from re_mcp_ida.helpers import async_paginate_iter, call_ida  # noqa: PLC0415

    executor = Mock()
    executor.submit.side_effect = AssertionError("IDA must execute through Nexus, not an executor")
    monkeypatch.setattr(core_helpers, "_main_executor", executor)
    thread_ids = []

    def items():
        for index in range(3):
            thread_ids.append(threading.get_ident())
            yield index

    async def execute():
        assert await call_ida(threading.get_ident) == threading.get_ident()
        assert (await async_paginate_iter(items(), limit=2))["items"] == [0, 1]
        assert set(thread_ids) == {threading.get_ident()}

    # Run on a non-main thread, where the old dispatch_to_main would submit to
    # the executor. No engine APIs are called in this regression test.
    with ThreadPoolExecutor() as pool:
        pool.submit(lambda: asyncio.run(execute())).result(timeout=5)
    executor.submit.assert_not_called()


def test_missing_transport_cannot_fall_back_to_removed_worker():
    from re_mcp.exceptions import BackendError  # noqa: PLC0415
    from re_mcp.worker_provider import WorkerPoolProvider  # noqa: PLC0415
    from re_mcp_ida.backend import IDABackend  # noqa: PLC0415

    class MissingTransport:
        info = staticmethod(IDABackend.info)

    with pytest.raises(BackendError, match="ConfigurationError"):
        WorkerPoolProvider(MissingTransport)._worker_transport()


def test_remote_registration_is_non_owning(monkeypatch):
    import signal  # noqa: PLC0415

    monkeypatch.setattr(nexus_runtime, "_registry", None)
    monkeypatch.delitem(sys.modules, "idapro", raising=False)
    install_signal = Mock(side_effect=AssertionError("remote tools must not install signals"))
    monkeypatch.setattr(signal, "signal", install_signal)
    registry = nexus_runtime._load([], list(sys.version_info[:2]))
    assert "list_functions" in registry.tools
    assert "run_script" in registry.tools
    assert "idapro" not in sys.modules
    install_signal.assert_not_called()


@pytest.mark.asyncio
async def test_startup_discovers_live_schemas(monkeypatch, schemas):
    discover = Mock(return_value=schemas)
    monkeypatch.setattr(nexus, "discover_schemas", discover)
    server = IDAServer("test")
    for _ in range(2):
        async with Client(server) as client:
            tools = {tool.name for tool in await client.list_tools()}
            assert "list_functions" in tools
            assert len(await client.list_resource_templates()) == 6
    discover.assert_called_once_with()


def test_discovery_releases_temporary_lease_and_files(lease, monkeypatch, schemas):
    _, handle = lease
    monkeypatch.setattr(nexus, "invoke", Mock(return_value={"result": schemas}))
    # Bypass the process-lifetime metadata cache for this resource-lifecycle test.
    result = nexus._discover_schemas_once.__wrapped__()
    assert result == schemas
    path = nexus.DatabaseHandle.open.call_args.args[0]
    assert not os.path.exists(os.path.dirname(path))
    handle.close.assert_called_once_with(wait_for_database=True)
    handle.save_database.assert_not_called()


def test_discovery_failure_releases_temporary_lease(lease, monkeypatch):
    _, handle = lease
    monkeypatch.setattr(nexus, "invoke", Mock(side_effect=RuntimeError("registration failed")))
    with pytest.raises(RuntimeError, match="registration failed"):
        nexus._discover_schemas_once.__wrapped__()
    path = nexus.DatabaseHandle.open.call_args.args[0]
    assert not os.path.exists(os.path.dirname(path))
    handle.close.assert_called_once_with(wait_for_database=True)


def test_open_options(tmp_path):
    binary = tmp_path / "firmware.bin"
    binary.write_bytes(b"\x00" * 64)
    options = nexus.open_options(
        str(binary),
        processor="arm:ARMv7-M",
        loader="Binary file",
        base_address="0x8000000",
        force_new=True,
    )
    assert options.processor == "arm:ARMv7-M"
    assert options.file_type == "Binary file"
    assert options.image_base == 0x8000000
    assert options.new_database
    assert not options.auto_analysis
    assert options.output_database is None
    assert binary.exists()  # the adapter never deletes sidecars or source files
    with pytest.raises(IDAError, match="Unsupported IDA option"):
        nexus.open_options(str(binary), options="-A")
    with pytest.raises(IDAError, match="aligned"):
        nexus.open_options(str(binary), base_address="0x123")
    with pytest.raises(IDAError, match="InvalidArgument"):
        nexus.open_options(str(binary) + ".i64", force_new=True)


@pytest.mark.parametrize(
    ("base_address", "expected"),
    [("", None), ("0", 0), ("0x20000", 0x20000), ("131072", 0x20000)],
)
def test_structured_base_address_is_translated_to_bytes(tmp_path, base_address, expected):
    options = nexus.open_options(str(tmp_path / "input.bin"), base_address=base_address)
    assert options.image_base == expected


@pytest.mark.parametrize("base_address", ["not_a_number", "0x20001", "-16"])
def test_invalid_structured_base_address(tmp_path, base_address):
    with pytest.raises(IDAError, match="InvalidArgument"):
        nexus.open_options(str(tmp_path / "input.bin"), base_address=base_address)


def test_fat_slice_options(tmp_path):
    binary = tmp_path / "fat"
    binary.write_bytes(
        struct.pack(">II", 0xCAFEBABE, 2)
        + struct.pack(">IIIII", 0x01000007, 3, 4096, 100, 12)
        + struct.pack(">IIIII", 0x0100000C, 0, 8192, 100, 12)
    )
    options = nexus.open_options(str(binary), fat_arch="arm64")
    assert options.file_type == "Fat Mach-O file, 2"
    assert options.file_member is None
    assert options.output_database == str(binary.resolve()) + ".arm64.i64"
    with pytest.raises(IDAError, match="AmbiguousFatBinary"):
        nexus.open_options(str(binary))
    with pytest.raises(IDAError, match="loader and fat_arch"):
        nexus.open_options(str(binary), fat_arch="arm64", loader="Binary file")
    with pytest.raises(IDAError, match="loader/fat_arch"):
        nexus.open_options(str(binary), fat_arch="arm64", options="-TELF")
    with pytest.raises(IDAError, match="-o"):
        nexus.open_options(str(binary), fat_arch="arm64", options="-osomewhere")
    combined = nexus.open_options(
        str(binary), fat_arch="arm64", processor="arm:ARMv8-A", base_address="0x100000000"
    )
    assert combined.file_type == "Fat Mach-O file, 2"
    assert combined.processor == "arm:ARMv8-A"
    assert combined.image_base == 0x100000000


@pytest.fixture
def lease(monkeypatch):
    handle = Mock()
    handle.instance = SimpleNamespace(idb_path="test.i64", pid=os.getpid() + 10000, backend="gui")
    handle.save_database.return_value = {"saved": True, "idb_path": "test.i64"}
    monkeypatch.setattr(nexus.DatabaseHandle, "open", Mock(return_value=handle))
    monkeypatch.setattr(nexus, "invoke", Mock(return_value={"result": {"status": "ok"}}))
    session = nexus.NexusSession()
    return session, handle


def test_open_exposes_no_pid_and_closes_only_lease(lease):
    session, handle = lease
    result = session.open_database("test.i64")
    assert result["pid"] is None
    assert session.handle is handle
    assert session.close_database() == {"status": "released", "path": "test.i64", "saved": True}
    handle.save_database.assert_called_once()
    handle.close.assert_called_once_with(wait_for_database=True)
    handle.shutdown_database.assert_not_called()
    assert session.handle is None
    assert session.close_database() == {"status": "no_database_open"}


def test_open_failure_releases_lease(lease, monkeypatch):
    session, handle = lease
    monkeypatch.setattr(nexus, "invoke", Mock(side_effect=RuntimeError("install failed")))
    with pytest.raises(RuntimeError, match="install failed"):
        session.open_database("test.i64")
    handle.close.assert_called_once_with(wait_for_database=True)
    assert session.handle is None


def test_open_busy_does_not_delete_or_retry(lease, monkeypatch):
    session, handle = lease
    opening = Mock(side_effect=DatabaseBusyError("in use"))
    monkeypatch.setattr(nexus.DatabaseHandle, "open", opening)
    with pytest.raises(DatabaseBusyError):
        session.open_database("test.bin", force_new=True)
    opening.assert_called_once()
    handle.close.assert_not_called()
    assert session.handle is None


def test_close_without_save_does_not_shutdown_shared_instance(lease):
    session, handle = lease
    session.handle = handle
    session.close_database(save=False)
    handle.save_database.assert_not_called()
    handle.shutdown_database.assert_not_called()
    handle.close.assert_called_once_with(wait_for_database=True)


def test_save_failure_still_releases_lease(lease):
    session, handle = lease
    session.handle = handle
    handle.save_database.return_value = {"saved": False, "idb_path": "test.i64"}
    with pytest.raises(IDAError, match="SaveFailed"):
        session.close_database()
    handle.close.assert_called_once_with(wait_for_database=True)
    assert session.handle is None


def test_wait_uses_nexus_analysis_lifecycle(lease):
    session, handle = lease
    session.handle = handle
    result = session.call("wait_for_analysis", {})
    handle.wait_autoanalysis.assert_called_once_with()
    assert nexus.invoke.call_args.args[-2] == "analysis_summary"
    assert "elapsed_seconds" in result


def test_script_and_snapshot_policies(lease):
    session, handle = lease
    session.handle = handle
    session.allow_scripts = False
    for name in ("run_script", "restore_snapshot"):
        with pytest.raises(IDAError, match="Unsupported"):
            session.call(name, {})
    nexus.invoke.assert_not_called()


def test_structured_errors_preserved(lease, monkeypatch):
    session, handle = lease
    session.handle = handle
    error = '{"error":"bad address","error_type":"InvalidAddress"}'
    monkeypatch.setattr(nexus, "invoke", Mock(return_value={"error": error}))
    with pytest.raises(ToolError) as exc:
        session.call("read_bytes", {"address": "bad", "size": 1})
    assert str(exc.value) == error


def test_coroutines_and_argument_models_run_on_caller_thread():
    # All awaits in existing tools dispatch IDA work synchronously when already
    # on the engine thread. Pydantic input models still need materialization.
    from re_mcp_ida.helpers import call_ida  # noqa: PLC0415

    class Item(BaseModel):
        value: int

    async def function(items):
        thread_id = await call_ida(threading.get_ident)
        return {"thread": thread_id, "values": [item.value for item in items]}

    function.__annotations__["items"] = list[Item]
    assert nexus_runtime._call(function, {"items": [{"value": 42}]}) == {
        "thread": threading.get_ident(),
        "values": [42],
    }
    with pytest.raises(ValidationError):
        nexus_runtime._call(function, {"items": [{"value": "not an integer"}]})


@pytest.mark.asyncio
async def test_mcp_tools_and_resources_preserve_shapes(lease, schemas):
    session, _ = lease
    session.call = Mock(
        side_effect=lambda name, args, kind: (
            json.dumps({"entries": []})
            if kind == "resource"
            else {"status": "saved", "path": "test.i64"}
        )
    )
    session.allow_scripts = False
    async with Client(_server(session, schemas)) as client:
        tools = {tool.name: tool for tool in await client.list_tools()}
        assert "run_script" not in tools
        assert "filters" in tools["list_functions"].inputSchema["properties"]
        assert tools["list_functions"].outputSchema
        result = await client.call_tool("save_database", {})
        assert result.structured_content == {"status": "saved", "path": "test.i64"}
        resource = await client.read_resource("ida://idb/entrypoints?offset=0&limit=10")
        assert json.loads(resource[0].text) == {"entries": []}
        assert session.call.call_args.args[2] == "resource"


@pytest.mark.asyncio
async def test_union_outputs_keep_fastmcp_wrapper(lease, schemas):
    session, _ = lease
    page = {"items": [], "total": 0, "offset": 0, "limit": 2, "has_more": False}
    session.call = Mock(return_value=page)
    async with Client(_server(session, schemas)) as client:
        result = await client.call_tool("list_functions", {"limit": 2})
        assert result.structured_content == {"result": page}


@pytest.mark.asyncio
async def test_invalid_arguments_never_reach_adapter(lease, schemas):
    session, _ = lease
    session.call = Mock()
    async with Client(_server(session, schemas)) as client:
        with pytest.raises(ToolError, match="InvalidArgument"):
            await client.call_tool("open_database", {"file_path": "test.bin", "force_new": "false"})
        with pytest.raises(ToolError, match="InvalidArgument"):
            await client.call_tool("list_functions", {"limit": -1})
    session.call.assert_not_called()


@pytest.mark.asyncio
async def test_backend_uses_inprocess_transport():
    from fastmcp.client.transports import FastMCPTransport  # noqa: PLC0415
    from re_mcp.worker_provider import WorkerPoolProvider  # noqa: PLC0415
    from re_mcp_ida.backend import IDABackend  # noqa: PLC0415

    assert IDABackend.info().worker_module is None
    assert isinstance(WorkerPoolProvider(IDABackend)._worker_transport(), FastMCPTransport)


@pytest.mark.asyncio
async def test_nexus_errors_are_tool_errors_without_retry(lease):
    session, _ = lease
    session.call = Mock(side_effect=RemoteError("cancelled", "cancelled by client", 409))
    server = IDAServer("test", session=session)
    with pytest.raises(IDAError, match="cancelled"):
        await server.dispatch("rename_address", {"address": "0x1000", "name": "test"})
    session.call.assert_called_once()


@pytest.mark.asyncio
async def test_cancellation_drains_inflight_mutation(lease):
    session, _ = lease
    started, stopped = threading.Event(), threading.Event()

    def call(*args):
        started.set()
        assert stopped.wait(5)
        return {"status": "cancelled"}

    session.call = Mock(side_effect=call)
    session.cancel = Mock(side_effect=stopped.set)
    server = IDAServer("test", session=session)
    task = asyncio.create_task(server.dispatch("rename_address", {}))
    assert await asyncio.to_thread(started.wait, 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    session.cancel.assert_called_once()
    session.call.assert_called_once()
    assert not server._dispatch_lock.locked()
