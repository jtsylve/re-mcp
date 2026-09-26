# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Multi-backend reverse-engineering MCP server. Python + FastMCP, stdio and streamable HTTP transports. Backends: IDA Pro (idalib) and Ghidra (pyghidra).

## Commands

```bash
uv sync                              # Install dependencies
uv run re-mcp-ida                    # Run IDA backend (direct stdio mode)
uv run re-mcp-ghidra                 # Run Ghidra backend (direct stdio mode)
uv run ruff check packages/          # Lint
uv run ruff format packages/         # Format
uv run ruff check --fix packages/    # Lint with auto-fix
```

Pre-commit hooks run REUSE compliance checks, ruff lint (with `--fix --exit-non-zero-on-fix`), ruff format, idalib threading lint (`scripts/lint_ida_threading.py`), and pytest on commit.

## Architecture

See `docs/architecture.md` for full details. The project is a monorepo with three packages:

- **`re-mcp-core`** (`packages/re-mcp-core/src/re_mcp/`): generic MCP supervisor infrastructure — `supervisor.py`, `daemon.py`, `proxy.py`, `worker_provider.py`, `backend.py`, `server.py`, `context.py`, `exceptions.py`, `helpers.py`, `models.py`, `sandbox.py`, `transforms.py`, `_process.py`
- **`re-mcp-ida`** (`packages/re-mcp-ida/src/re_mcp_ida/`): IDA-specific backend — `backend.py`, `server.py`, `session.py`, `helpers.py`, `exceptions.py`, `models.py`, `transforms.py`, `_cli.py`, `tools/`, `resources.py`, `prompts/`
- **`re-mcp-ghidra`** (`packages/re-mcp-ghidra/src/re_mcp_ghidra/`): Ghidra-specific backend — `backend.py`, `server.py`, `session.py`, `helpers.py`, `exceptions.py`, `models.py`, `transforms.py`, `_cli.py`, `tools/`, `resources.py`, `prompts/`

Key points for editing:

- **Supervisor** (`re_mcp.supervisor`): entry point, `ProxyMCP(FastMCP)` + `WorkerPoolProvider`. Registers generic management tools (`close_database`, `save_database`, `list_databases`, `wait_for_analysis`, `list_targets`); each backend registers `open_database` via `backend.py`. Management tools use `try_get_session_id()` (from `re_mcp.context`). Most omit `ctx` from their signature; `save_database` is the exception (it accepts `ctx` for heartbeat progress notifications, but FastMCP strips it from the JSON schema).
- **Backends** (`re_mcp_ida.backend`, `re_mcp_ghidra.backend`): implement the `Backend` protocol — register `open_database`, prompts, backend-specific instructions, and target listing. Discovered via `re_mcp.backends` entry points.
- **Worker provider** (`re_mcp.worker_provider`): `WorkerPoolProvider(Provider)`, `RoutingTool(Tool)`, `RoutingTemplate(ResourceTemplate)`, `Worker` dataclass. Session-scoped ownership under `_lock` — `close_for_session()` and `detach_all()` are atomic. `ensure_session_cleanup()` registers a disconnect callback on the MCP session's exit stack.
- **Workers/adapters**: Ghidra uses one stdio subprocess per database. IDA uses an in-process `IDAServer` via the optional backend `create_worker_transport()` hook; `NexusSession` owns a shared `DatabaseHandle` lease. IDA has no subprocess worker entry point or local idalib bootstrap. Never signal/kill a Nexus or GUI PID. See `docs/ida-nexus.md`.
- **Engine-independent modules** (importable without initializing an engine): all `re_mcp` modules, plus `<backend>.exceptions`, `<backend>.models`, `<backend>.transforms`, `<backend>.prompts/`. The supervisor never imports backend-engine-required modules.
- **Engine-required modules**: `<backend>.helpers`, `<backend>.session`, `<backend>.tools/`, `<backend>.resources`. Backend-specific imports — only loaded in worker processes.
- IDA adapters discover schemas at startup from live tool registrations in a temporary licensed Nexus instance. `nexus_runtime.py` handles registration and remote execution; there are no generated schema files or regeneration steps.
- `@session.require_open` (no parens) — decorator on nearly every tool
- All tools return Pydantic models on success; raise `BackendError` subclass on failure (`IDAError` / `GhidraError`)

## Adding a New Tool

1. Create `packages/<backend>/src/<backend_pkg>/tools/newtool.py` with a `register(mcp: FastMCP)` function
2. Define tool functions inside `register()` using `@mcp.tool()` and `@session.require_open`
3. Add `annotations=` (`ANNO_READ_ONLY`, `ANNO_MUTATE`, `ANNO_MUTATE_NON_IDEMPOTENT`, or `ANNO_DESTRUCTIVE`) and `tags=` to `@mcp.tool()`
4. Use `Annotated` type aliases for parameters: `Address`, `Offset`, `Limit`, `FilterPattern`, `HexBytes` (from core helpers); `OperandIndex` is IDA-only
5. Tool modules are auto-discovered — any `tools/*.py` with a `register()` function is loaded automatically
6. Use helpers from `helpers.py` — `resolve_address`, `resolve_function`, `paginate`, etc.
7. Return Pydantic model instances on success; raise the backend's error type on failure (do not return error dicts)
8. Add any new third-party imports to the `known-third-party` list in `pyproject.toml` under `[tool.ruff.lint.isort]`
9. Ideally add the tool to both backends with matching names and parameters for portability

## IDA 9 API

- `ida_ida.get_inf_structure()` is **removed** — use free functions: `ida_ida.inf_get_min_ea()`, `ida_ida.inf_get_max_ea()`, `ida_ida.inf_get_start_ea()`, `ida_ida.inf_get_app_bitness()`, `ida_ida.inf_is_64bit()`, etc.
- All IDA calls must run through Nexus on its selected IDA thread. Do not introduce local engine executors or initialize idalib in the supervisor.
- Use Nexus `DatabaseHandle` leases and typed `DatabaseOpenOptions`; do not call idapro database open/close functions or manage IDA process lifetimes. Fresh imports need a writable output directory.

## Lint / Style

- ruff configured in `pyproject.toml` — line-length 100, target py312
- isort knows `ida_*`, `pyghidra`, `ghidra`, `java`, `idapro`, `idc`, `idautils`, `fastmcp`, and `mcp` modules as third-party (configured in `[tool.ruff.lint.isort]`)
- Do not credit Claude in commit messages
