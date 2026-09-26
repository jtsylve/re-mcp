# IDA Nexus backend

The IDA backend uses the public API of [IDA Nexus](https://github.com/HexRaysSA/ida-nexus).
The dependency is installed from PyPI; a local Nexus checkout is not required:

```bash
uv sync
uv run re-mcp-ida
```

The structured tools, prompts, database IDs, resources, progressive disclosure,
and stdio/proxy/HTTP entry points remain available. Ghidra is unchanged.

## Database ownership

`open_database` acquires a `DatabaseHandle` lease. Nexus reuses a registered IDA
GUI or headless instance for that path, or starts a managed idalib worker.
`wait_for_analysis` uses Nexus's analysis lifecycle when analysis is requested;
ordinary tools are dispatched with `RemoteModule` on the owning IDA thread.
The supervisor's existing `run_auto_analysis=False` behavior is unchanged: waiting
for readiness only waits for opening unless analysis was requested.

Each supervisor database has an **in-process MCP adapter**, not another engine
process. This is important on Windows: the MCP SDK's stdio child Job Object
would otherwise kill a shared Nexus worker when the adapter closes. Ghidra
continues to use isolated stdio workers. IDA has no standalone worker entry point,
local idalib bootstrap, engine executor, or process signal handlers. Use the
`re-mcp-ida` CLI; the supervisor manages only Nexus leases.

Closing saves when requested, releases only this adapter's lease, and waits for
final managed shutdown if necessary. It never calls Nexus's forced shutdown API
or kills a Nexus/GUI PID. The supervisor's `force=True` overrides only its own
MCP session bookkeeping, not other Nexus leases. Cancellation targets this
lease's active request; mutating requests are never retried after RPC failures.
After a Nexus disconnect/crash, close the failed MCP database and reopen it.

**Windows host containment:** an external launcher can itself place the entire
supervisor in a kill-on-close Job Object. Nexus 0.13 does not break newly spawned
workers out of that outer job. For workers that must survive that launcher's
shutdown, start `re-mcp-ida serve` independently and connect with `proxy`, or
attach to an already-running Nexus GUI/worker.

## GUI setup

Install the Nexus GUI plugin as described in the
[Nexus README](https://github.com/HexRaysSA/ida-nexus#gui), then open
the binary in IDA and pass its binary or IDB path to `open_database`.

RE-MCP's existing tools use Pydantic and FastMCP imports inside IDA. IDA's Python
must be **3.12+**, with compatible `re-mcp-ida` dependencies available. The adapter
exposes its local source roots and, when Python major/minor versions match, its
site-packages paths to the local Nexus interpreter. If the GUI uses a different
Python version, install `re-mcp-core` and `re-mcp-ida` (and their dependencies)
into that interpreter. No package installation is performed inside the GUI.
Restart the supervisor and GUI after updating tool sources so their live
registrations are refreshed. No `idapro` import or signal handler installation
is performed by remote tool registration.

## Compatibility differences

- `options` accepts IDA CLI switches and translates them to `DatabaseOpenOptions`.
  Unknown switches, malformed values, and duplicate/conflicting settings fail
  before opening a database. Import options apply only to new imports, not reused
  databases. Fat slices retain separate sidecar paths.
- `force_new=True` uses Nexus's guarded fresh-import policy. No sidecars are
  manually deleted, and live owners are never overwritten.
- `close_database(save=False)` skips an explicit save. It does **not** discard
  changes: Nexus may save on final managed-worker release.
- `restore_snapshot` returns `Unsupported`: replacing a live shared database
  would invalidate other leases. Open the snapshot file as another database.
- `generate_signatures` requires a headless instance with `idapro.make_signatures`;
  it does not import idalib into a GUI.
- `run_script` is still opt-in (`IDA_MCP_ALLOW_SCRIPTS=1`) and checked per adapter,
  even when other clients share the same remote tool registry.
- Remote batch exports do not stream per-function MCP progress. Supervisor-level
  batch/save progress remains available.
- `list_databases` lists this supervisor's databases, not all Nexus instances.
  Opening a known GUI/worker path still reuses it automatically.

## CLI options

Supported switches: `-a`, `-a-`, `-b`, `-c`, `-C`, `-d`, `-D`, `-f`, `-i`,
`-I0`/`-I1`, `-L`, `-M`, `-O`, `-p`, `-P`/`-P+`/`-P-`, `-r`, `-R`, `-S`,
`-T`, `-t`, `-W`, `-x`, and `-z`. `-d` and `-D` may repeat; scalar options may not.
As before, `-o` is reserved for database/slice identity. Switches not represented
by Nexus's typed API (such as `-A` and `-B`) are rejected, never ignored.

IDA uses **double quotes**, not shell single quotes. Windows path backslashes
are preserved. Values may be attached (`-Cgcc`) or separated (`-C gcc`). The raw
`-b` value is **hex paragraphs**: `-b1000` means byte address `0x10000`, whereas
RE-MCP's structured `base_address` is already a byte address. `-i` and `-z` values
are hexadecimal too. Do not duplicate `processor`, `loader`/`fat_arch`, or
`base_address` in `options`. `-a` conflicts with `run_auto_analysis=True`.

Examples:

```text
-Cgcc -dMACRO=1 -DOTHER=2 -P+ -z800
-parm:ARMv7-M -T"Binary file" -b800000
-L"C:\\analysis logs\\ida.log"
-S"script.py arg1 arg2"
```

`-S` accepts an existing quoted script path (including spaces), or a script
command line. Script paths with spaces **plus arguments**, and literal quotes
in script arguments, are explicitly rejected because the current upstream
argument builder cannot preserve them reliably.

## Development and verification

Tools and resources are discovered from the existing registrations at runtime,
using a temporary licensed Nexus instance. Nexus needs an IDB for execution, so
the probe uses a private throwaway binary and closes/deletes it after discovery.
Only in-memory metadata is cached for the supervisor's lifetime. There is no
schema snapshot, source digest, generator, or regeneration step. Change the
existing `tools/*.py` registrations and restart the server as before.

```bash
# No IDA required (unit tests use engine stubs):
uv run pytest -q tests/test_ida_nexus.py tests/test_ida_cli_options.py

# End-to-end test of the installed re-mcp-ida CLI over stdio.
# Operates only on a temporary copy of the supplied executable:
uv run python scripts/smoke_ida_nexus.py path/to/small/executable --function main
# For licenses without Hex-Rays, add --skip-decompiler.
```

The smoke test launches the installed CLI as a separate process and exercises
MCP initialization, live tool/resource schemas, prompts, analysis, decompilation,
disassembly, strings/xrefs, error responses, comments visible through a second
independent lease, resource reads, saves, release without disrupting that lease,
persistence after reopening, and clean stdio shutdown.
