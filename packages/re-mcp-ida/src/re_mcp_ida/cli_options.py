# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Translate IDA CLI switches to Nexus's public typed import options.

This is IDA's double-quoted command-line syntax, not a shell: backslashes in
Windows paths are preserved, single quotes have no special meaning, and no
expansion or shell execution takes place. Unknown switches are never ignored.
"""

from __future__ import annotations

from pathlib import Path
from typing import Never

from re_mcp_ida.exceptions import IDAError

# These ida-domain fields are inserted into its IDA argument string verbatim.
_VERBATIM_FIELDS = {
    "compiler",
    "first_pass_directives",
    "second_pass_directives",
    "plugin_options",
    "processor",
    "run_debugger",
}
_VALUE_FLAGS = {
    "b": "image_base",
    "C": "compiler",
    "d": "first_pass_directives",
    "D": "second_pass_directives",
    "i": "entry_point",
    "I": "jit_debugger",
    "L": "log_file",
    "O": "plugin_options",
    "p": "processor",
    "r": "run_debugger",
    "S": "script_file",
    "T": "file_type",
    "W": "windows_dir",
    "z": "debug_flags",
}
_SWITCHES = {
    "-a": ("auto_analysis", False),
    "-a-": ("auto_analysis", True),
    "-c": ("new_database", True),
    "-f": ("disable_fpp", True),
    "-M": ("disable_mouse", True),
    "-P": ("db_compression", "pack"),
    "-P+": ("db_compression", "compress"),
    "-P-": ("db_compression", "no_pack"),
    "-R": ("load_resources", True),
    "-t": ("empty_database", True),
    "-x": ("no_segmentation", True),
}


def _invalid(message: str) -> Never:
    raise IDAError(message, error_type="InvalidArgument")


def split_ida_arguments(text: str) -> list[str]:
    """Split IDA arguments, including attached values and escaped double quotes."""
    if "\0" in text:
        _invalid("IDA options must not contain NUL bytes")
    result = []
    token = []
    quoted = started = False
    index = 0
    while index < len(text):
        char = text[index]
        if char.isspace() and not quoted:
            if started:
                result.append("".join(token))
                token = []
                started = False
            index += 1
            continue
        started = True
        if char == "\\":
            end = index
            while end < len(text) and text[end] == "\\":
                end += 1
            count = end - index
            if end < len(text) and text[end] == '"':
                token.append("\\" * (count // 2))
                if count % 2:
                    token.append('"')
                else:
                    quoted = not quoted
                index = end + 1
            else:
                token.append("\\" * count)
                index = end
        elif char == '"':
            quoted = not quoted
            index += 1
        else:
            token.append(char)
            index += 1
    if quoted:
        _invalid("Unterminated double quote in IDA options")
    if started:
        result.append("".join(token))
    return result


def _quote_verbatim(value: str) -> str:
    """Protect values that ida-domain's argument builder does not itself quote."""
    if not any(char.isspace() or char == '"' for char in value):
        return value
    # Double backslashes only before quotes and the closing quote. Ordinary
    # backslashes are literal in IDA paths, unlike POSIX shell escaping.
    output = []
    slashes = 0
    for char in value:
        if char == "\\":
            slashes += 1
            continue
        output.append("\\" * (slashes * 2 + 1 if char == '"' else slashes))
        output.append(char)
        slashes = 0
    output.append("\\" * (slashes * 2))
    return '"' + "".join(output) + '"'


def _hex_number(value: str, flag: str) -> int:
    try:
        # IDA CLI addresses/masks are hex even without 0x. In particular -b is
        # in paragraphs, unlike Nexus.image_base which is a byte address.
        if value.startswith(("-", "+")):
            raise ValueError
        number = int(value, 16)
    except ValueError:
        _invalid(f"{flag} requires a non-negative hexadecimal integer, got {value!r}")
    return number


def parse_ida_options(options: str) -> dict:
    """Translate supported flags; reject unknown, repeated, or malformed options."""
    tokens = iter(split_ida_arguments(options))
    result = {}
    for token in tokens:
        if token.startswith("-o"):
            _invalid(
                "options contains '-o': the output path is reserved for database/slice identity"
            )
        if token in _SWITCHES:
            field, value = _SWITCHES[token]
        elif len(token) >= 2 and token[0] == "-" and token[1] in _VALUE_FLAGS:
            flag = token[:2]
            field = _VALUE_FLAGS[token[1]]
            value = token[2:] or next(tokens, "")
            if not value or value.startswith("-"):
                _invalid(f"{flag} requires a value")
            if field in {"image_base", "entry_point", "debug_flags"}:
                value = _hex_number(value, flag)
                if field == "image_base":
                    value *= 16
            elif field == "jit_debugger":
                if value not in {"0", "1"}:
                    _invalid("-I accepts only 0 or 1")
                value = value == "1"
            elif field == "script_file":
                # -S"script.py arg1 arg2" contains a second command line.
                # A quoted, existing filename with spaces and no arguments is
                # also a valid IDA -S value, so recognize that case first.
                script = [value] if Path(value).is_file() else split_ida_arguments(value)
                if not script or not script[0]:
                    _invalid("-S requires a script filename")
                if (
                    len(script) > 1
                    and not value.startswith('"')
                    and Path(script[0]).suffix.lower() not in {".py", ".idc"}
                ):
                    _invalid(
                        "Ambiguous -S value: quote the script filename inside the script command line"
                    )
                if len(script) > 1 and any(char.isspace() for char in script[0]):
                    _invalid(
                        "Unsupported -S: ida-domain cannot encode a script path with spaces plus arguments"
                    )
                if any('"' in argument for argument in script):
                    _invalid("Unsupported -S: literal quotes in script filenames/arguments")
                value = script[0]
                result["script_args"] = tuple(script[1:])
            elif field in _VERBATIM_FIELDS:
                value = _quote_verbatim(value)
        else:
            _invalid(f"Unsupported IDA option: {token!r}")
        if field in {"first_pass_directives", "second_pass_directives"}:
            result[field] = (*result.get(field, ()), value)
        else:
            if field in result:
                _invalid(f"Duplicate IDA option for {field}: {token!r}")
            result[field] = value
    return result
