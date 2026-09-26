# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""IDA CLI-to-Nexus translation, without initializing IDA."""

import struct
from unittest.mock import AsyncMock

import pytest
from fastmcp import Client, FastMCP
from re_mcp_ida.backend import IDABackend
from re_mcp_ida.cli_options import parse_ida_options, split_ida_arguments
from re_mcp_ida.exceptions import IDAError
from re_mcp_ida.nexus import open_options


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("-a", {"auto_analysis": False}),
        ("-a-", {"auto_analysis": True}),
        ("-c", {"new_database": True}),
        ("-Cgcc", {"compiler": "gcc"}),
        ("-f", {"disable_fpp": True}),
        ("-i1234", {"entry_point": 0x1234}),
        ("-I0", {"jit_debugger": False}),
        ("-I1", {"jit_debugger": True}),
        ("-Lanalysis.log", {"log_file": "analysis.log"}),
        ("-M", {"disable_mouse": True}),
        ("-Oplugin:value", {"plugin_options": "plugin:value"}),
        ("-parm:ARMv7-M", {"processor": "arm:ARMv7-M"}),
        ("-P", {"db_compression": "pack"}),
        ("-P+", {"db_compression": "compress"}),
        ("-P-", {"db_compression": "no_pack"}),
        ("-rwin32", {"run_debugger": "win32"}),
        ("-R", {"load_resources": True}),
        ("-t", {"empty_database": True}),
        ('-T"ELF:member.o"', {"file_type": "ELF:member.o"}),
        ('-T"Fat Mach-O file, 2"', {"file_type": "Fat Mach-O file, 2"}),
        (r"-WC:\Windows", {"windows_dir": r"C:\Windows"}),
        ("-x", {"no_segmentation": True}),
        ("-z800", {"debug_flags": 0x800}),
        ("-z0x800", {"debug_flags": 0x800}),
        ("-b1000", {"image_base": 0x10000}),
        ("-b0x1000", {"image_base": 0x10000}),
    ],
)
def test_supported_switches(text, expected):
    assert parse_ida_options(text) == expected


def test_separated_values_and_repeatable_directives():
    assert parse_ida_options("-C gcc -dNAME=1 -d OTHER=2 -DX=3 -D Y=4 -b 100") == {
        "compiler": "gcc",
        "first_pass_directives": ("NAME=1", "OTHER=2"),
        "second_pass_directives": ("X=3", "Y=4"),
        "image_base": 0x1000,
    }


def test_windows_paths_and_quotes_are_preserved():
    assert parse_ida_options(r'-L"C:\some folder\analysis.log" -WC:\Windows') == {
        "log_file": r"C:\some folder\analysis.log",
        "windows_dir": r"C:\Windows",
    }
    assert split_ida_arguments(r'-O"plugin:two words" -L"C:\folder\\"') == [
        "-Oplugin:two words",
        "-LC:\\folder\\",
    ]
    options = parse_ida_options(r'-O"plugin:two words" -d"NAME=\"two words\""')
    # ida-domain inserts these fields without quoting. Confirm our quoting
    # reconstructs one IDA argument with the original value, including quotes.
    rendered = "-O" + options["plugin_options"] + " -d" + options["first_pass_directives"][0]
    assert split_ida_arguments(rendered) == ["-Oplugin:two words", '-dNAME="two words"']


def test_script_arguments(tmp_path):
    assert parse_ida_options(r'-S"script.py --flag \"two words\""') == {
        "script_file": "script.py",
        "script_args": ("--flag", "two words"),
    }
    script = tmp_path / "a script.py"
    script.touch()
    assert parse_ida_options(f'-S"{script}"') == {
        "script_file": str(script),
        "script_args": (),
    }
    assert parse_ida_options(r'-S"\"a script.py\""') == {
        "script_file": "a script.py",
        "script_args": (),
    }
    with pytest.raises(IDAError, match="Unsupported -S"):
        parse_ida_options(r'-S"\"a script.py\" argument"')


@pytest.mark.parametrize(
    "options",
    [
        "-A",
        "-B",
        "--unknown",
        "-Qanything",
        "-fextra",
        "-Pextra",
        "-a+",
        "positional.bin",
        "-Llog.txt positional.bin",
        "-ooutput.i64",
        "-L",
        '-L""',
        "-C -pmetapc",
        '-L"unclosed',
        "-I2",
        "-bxyz",
        "-i-1",
        "-z0xZZ",
        "-i+1",
        "-P+ -P-",
        "-c -c",
        "-pfoo -pbar",
        "-Oone -Otwo",
        "-Sone.py -Stwo.py",
        "\0",
    ],
)
def test_reject_unsupported_malformed_and_duplicate_options(options):
    with pytest.raises(IDAError, match="InvalidArgument"):
        parse_ida_options(options)


@pytest.mark.parametrize(
    ("kwargs", "options"),
    [
        ({"processor": "metapc"}, "-parm:ARMv7-M"),
        ({"loader": "ELF"}, '-T"Binary file"'),
        ({"base_address": "0x10000"}, "-b1000"),
        ({"fat_arch": "arm64"}, '-T"Mach-O"'),
        ({"run_auto_analysis": True}, "-a"),
    ],
)
def test_structured_and_cli_conflicts(kwargs, options):
    with pytest.raises(IDAError, match="InvalidArgument"):
        open_options("test.bin", options=options, **kwargs)


def test_effective_options_are_validated_and_mapped(tmp_path):
    binary = tmp_path / "firmware.bin"
    binary.write_bytes(b"\0" * 32)
    options = open_options(
        str(binary), options='-parm:ARMv7-M -T"Binary file" -b800000 -c -Cgcc -z800'
    )
    assert options.processor == "arm:ARMv7-M"
    assert options.file_type == "Binary file"
    assert options.image_base == 0x8000000
    assert options.new_database
    assert options.compiler == "gcc"
    assert options.debug_flags == 0x800
    assert open_options(str(binary), options="-a-").auto_analysis
    with pytest.raises(IDAError, match="AmbiguousProcessor"):
        open_options(str(binary), options="-parm")
    with pytest.raises(IDAError, match="InvalidArgument"):
        open_options(str(binary) + ".i64", options="-c")


def test_fat_slice_uses_loader_comma_not_archive_colon(tmp_path):
    binary = tmp_path / "fat"
    binary.write_bytes(
        struct.pack(">II", 0xCAFEBABE, 1) + struct.pack(">IIIII", 0x0100000C, 0, 4096, 100, 12)
    )
    options = open_options(str(binary), fat_arch="arm64")
    assert options.file_type == "Fat Mach-O file, 1"
    assert options.file_member is None
    with pytest.raises(IDAError, match="duplicates"):
        open_options(str(binary), fat_arch="arm64", options='-T"Fat Mach-O file, 1"')


@pytest.mark.asyncio
async def test_supervisor_preserves_cli_analysis_and_fresh_import_flags(tmp_path):
    binary = tmp_path / "source.bin"
    binary.write_bytes(b"\0" * 32)
    pool = AsyncMock()
    pool.open_database.return_value = {"status": "opening"}
    server = FastMCP("options test")
    IDABackend.register_management_tools(server, pool)
    async with Client(server) as client:
        await client.call_tool("open_database", {"file_path": str(binary), "options": "-a- -c"})
    args = pool.open_database.call_args.args
    assert args[1] is True  # supervisor must schedule the analysis wait
    assert args[4] is True  # raw -c goes through the same guarded fresh-import path
