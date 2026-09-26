# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Signature generation tools."""

from __future__ import annotations

import sys

from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ida.helpers import ANNO_MUTATE, META_WRITES_FILES, IDAError
from re_mcp_ida.session import session


class GenerateSignaturesResult(BaseModel):
    """Result of generating signatures."""

    status: str = Field(description="Status message.")
    only_pat: bool = Field(description="Whether only .pat file was generated.")


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"signatures"},
        meta=META_WRITES_FILES,
    )
    @session.require_open
    def generate_signatures(only_pat: bool = False) -> GenerateSignaturesResult:
        """Generate FLIRT .sig and .pat files from the current database for library identification.

        Args:
            only_pat: If True, only generate .pat file (no .sig compilation).
        """
        # Importing idapro into a GUI would initialize a second IDA kernel.
        # Only use it when Nexus already loaded it for a managed idalib worker.
        idapro = sys.modules.get("idapro")
        if idapro is None or not hasattr(idapro, "make_signatures"):
            raise IDAError(
                "Signature generation requires an idalib instance with make_signatures support",
                error_type="NotAvailable",
            )

        try:
            success = idapro.make_signatures(only_pat)
        except Exception as e:
            raise IDAError(str(e), error_type="SignatureGenerationFailed") from e

        if not success:
            raise IDAError("Signature generation failed", error_type="SignatureGenerationFailed")

        return GenerateSignaturesResult(status="ok", only_pat=only_pat)
