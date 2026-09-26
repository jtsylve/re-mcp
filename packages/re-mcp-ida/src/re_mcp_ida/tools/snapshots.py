# SPDX-FileCopyrightText: © 2026 Joe T. Sylve, Ph.D. <joe.sylve@gmail.com>
#
# SPDX-License-Identifier: MIT OR Apache-2.0

"""Database snapshot management tools."""

from __future__ import annotations

import ida_kernwin
import ida_loader
from fastmcp import FastMCP
from pydantic import BaseModel, Field

from re_mcp_ida.helpers import (
    ANNO_DESTRUCTIVE,
    ANNO_MUTATE,
    ANNO_READ_ONLY,
    META_READS_FILES,
    META_WRITES_FILES,
    IDAError,
)
from re_mcp_ida.session import session


class TakeSnapshotResult(BaseModel):
    """Result of taking a snapshot."""

    id: str = Field(description="Snapshot ID.")
    description: str = Field(description="Snapshot description.")
    filename: str = Field(description="Snapshot filename.")


class SnapshotInfo(BaseModel):
    """Snapshot information."""

    id: str = Field(description="Snapshot ID.")
    description: str = Field(description="Snapshot description.")
    filename: str = Field(description="Snapshot filename.")
    depth: int = Field(description="Snapshot depth.")


class ListSnapshotsResult(BaseModel):
    """List of database snapshots."""

    snapshots: list[SnapshotInfo] = Field(description="Available snapshots.")
    count: int = Field(description="Number of snapshots.")


class RestoreSnapshotResult(BaseModel):
    """Result of restoring a snapshot."""

    action: str = Field(description="Action performed.")
    snapshot_id: str = Field(description="Restored snapshot ID.")
    description: str = Field(description="Snapshot description.")
    file: str = Field(description="Snapshot filename.")


def _snapshot_to_dict(snap: ida_loader.snapshot_t) -> dict:
    """Convert a snapshot_t to a serializable dict."""
    return {
        "id": str(snap.id),
        "description": snap.desc,
        "filename": snap.filename,
    }


def _collect_tree(node: ida_loader.snapshot_t, depth: int = 0) -> list[dict]:
    """Recursively flatten the snapshot tree into a list."""
    entry = _snapshot_to_dict(node)
    entry["depth"] = depth
    items = [entry]
    if node.children:
        for child in node.children:
            items.extend(_collect_tree(child, depth + 1))
    return items


def register(mcp: FastMCP):
    @mcp.tool(
        annotations=ANNO_MUTATE,
        tags={"metadata", "snapshots"},
        meta=META_WRITES_FILES,
    )
    @session.require_open
    def take_snapshot(description: str = "") -> TakeSnapshotResult:
        """Create a persistent restore point (survives sessions; stronger than undo).

        Creates a point-in-time snapshot that can be restored later.
        Unlike undo, snapshots persist across sessions and can capture
        the full database state at a specific moment.

        Args:
            description: Optional description for the snapshot.
        """
        snap = ida_loader.snapshot_t()
        if description:
            snap.desc = description

        result = ida_kernwin.take_database_snapshot(snap)
        success, error_msg = result
        if not success:
            raise IDAError(error_msg or "Failed to take snapshot", error_type="SnapshotFailed")

        return TakeSnapshotResult(**_snapshot_to_dict(snap))

    @mcp.tool(
        annotations=ANNO_READ_ONLY,
        tags={"metadata", "snapshots"},
    )
    @session.require_open
    def list_snapshots() -> ListSnapshotsResult:
        """List all database snapshots.

        Returns the snapshot tree flattened into a list with depth
        information indicating parent-child relationships.
        """
        root = ida_loader.snapshot_t()
        if not ida_loader.build_snapshot_tree(root):
            return ListSnapshotsResult(snapshots=[], count=0)

        snapshots = _collect_tree(root)
        return ListSnapshotsResult(snapshots=snapshots, count=len(snapshots))

    @mcp.tool(
        annotations=ANNO_DESTRUCTIVE,
        tags={"metadata", "snapshots"},
        meta=META_READS_FILES,
    )
    @session.require_open
    def restore_snapshot(snapshot_id: str) -> RestoreSnapshotResult:
        """Unsupported for shared Nexus databases; open the snapshot separately.

        Replacing the database in-place would invalidate other clients' leases.
        Use list_snapshots to find its file, then open_database with that path.

        Args:
            snapshot_id: ID of the snapshot (string from list_snapshots).
        """
        raise IDAError(
            "Open the snapshot as a separate database; shared Nexus databases "
            "cannot be replaced in-place.",
            error_type="Unsupported",
        )
