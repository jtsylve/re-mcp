# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""View of the database owned by Nexus, used only inside the IDA interpreter.

This module never opens/closes idalib or installs process signal handlers. In
particular, importing tools into a GUI must not take over the GUI's lifecycle.
"""

from __future__ import annotations

import functools
import inspect

import ida_hexrays
import ida_idp
import ida_loader

from re_mcp_ida.helpers import Cancelled, IDAError


class Session:
    """Non-owning view of Nexus's current database."""

    @property
    def current_path(self) -> str | None:
        return ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or None

    def is_open(self) -> bool:
        return self.current_path is not None

    @property
    def capabilities(self) -> dict[str, bool]:
        return {
            "decompiler": bool(ida_hexrays.init_hexrays_plugin()),
            "assembler": ida_idp.get_idp_name() == "metapc",
        }

    def require_open(self, fn):
        def check():
            if not self.is_open():
                raise IDAError("No database is open", error_type="NoDatabase")
            # Do not clear IDA's cancellation flag: Nexus owns cancellation.

        if inspect.iscoroutinefunction(fn):

            @functools.wraps(fn)
            async def async_wrapper(*args, **kwargs):
                check()
                try:
                    return await fn(*args, **kwargs)
                except Cancelled as exc:
                    raise IDAError("Operation cancelled", error_type="Cancelled") from exc

            return async_wrapper

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            check()
            try:
                return fn(*args, **kwargs)
            except Cancelled as exc:
                raise IDAError("Operation cancelled", error_type="Cancelled") from exc

        return wrapper


session = Session()
