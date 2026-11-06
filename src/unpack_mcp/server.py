"""unpack-mcp: an MCP server for looking inside archives and extracting them safely."""

from __future__ import annotations

import argparse
import functools
import os
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any, TypeVar

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import ops
from .core import MiB, Limits, UnpackError

mcp = MCPServer(
    "unpack",
    instructions=(
        "Inspect, search, safely extract and create archives (zip, tar, tar.gz/bz2/xz, bare "
        "gz/bz2/xz; no 7z/rar). Start with archive_info (format, sizes, encryption, suspicious "
        "entries, and whether extraction would be refused), then list_entries, read_entry or "
        "search_in_archive to look inside WITHOUT extracting. extract_archive refuses path "
        "traversal, absolute paths, link escapes, device files, duplicate names and "
        "decompression bombs, never overwrites unless overwrite=true, and supports dry_run=true. "
        "All paths must be inside the directories the server was started with (--dir). "
        "Nested archives are reported, never extracted automatically."
    ),
)


@dataclass
class Config:
    roots: list[str] = field(default_factory=list)
    limits: Limits = field(default_factory=Limits)

    def resolved_roots(self) -> list[str]:
        return [os.path.realpath(r) for r in (self.roots or [os.getcwd()])]


CONFIG = Config()

F = TypeVar("F", bound=Callable[..., Any])
# Only these reach the client with their text; anything else is a genuine bug
# and MCPServer reports it as a bare "Error executing tool".
_EXPECTED = (UnpackError, OSError, ValueError)


def tool(fn: F) -> F:
    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            return fn(*args, **kwargs)
        except _EXPECTED as e:
            raise ToolError(str(e)) from e

    mcp.tool()(wrapper)
    return fn


def sandbox(path: str, what: str) -> str:
    """Resolve `path` (relative to the first allowed dir) and require it to be inside one."""
    roots = CONFIG.resolved_roots()
    if not path:
        raise UnpackError(f"{what} path is empty")
    joined = path if os.path.isabs(path) else os.path.join(roots[0], path)
    real = os.path.realpath(joined)
    if not any(ops.is_inside(real, r) for r in roots):
        raise UnpackError(
            f"{what} {path!r} is outside the allowed directories ({', '.join(roots)}). "
            "The server operator controls this with --dir."
        )
    return real


@tool
def archive_info(path: str, password: str | None = None, encoding: str | None = None) -> str:
    """Summarize an archive without extracting anything. Call this first.

    Reports format (zip, tar, tar.gz/bz2/xz, gz/bz2/xz), entry counts by kind, compressed and
    uncompressed totals and ratio, encryption, zip comment, top-level layout, nested archives
    (reported only), suspicious entries (path traversal, absolute paths, links that escape,
    device files, duplicates, Windows-reserved names) and an "Extraction verdict" saying whether
    extract_archive would accept it.

    password: only for ZipCrypto zips (standard-library limit; AES zips are unsupported).
    encoding: re-decode legacy zip names that are not flagged UTF-8, e.g. cp857 or cp1254 for
    Turkish, cp932 Japanese, gbk Chinese, cp1251 Russian (default cp437, as zip specifies).
    """
    return ops.info(sandbox(path, "archive"), CONFIG.limits, password, encoding)


@tool
def list_entries(
    path: str,
    glob: str | None = None,
    tree: bool = False,
    limit: int = 200,
    encoding: str | None = None,
    password: str | None = None,
) -> str:
    """List archive members without extracting.

    glob filters by full path or, when it has no '/', by file name (e.g. '*.py', 'src/*').
    tree=true renders an indented tree instead of one line per entry
    (kind, size, mtime, name; '!!' marks entries extract_archive would refuse).
    limit caps the output (default 200); the rest is summarized as a count.
    """
    return ops.list_entries(
        sandbox(path, "archive"), CONFIG.limits, glob, tree, limit, encoding, password
    )


@tool
def read_entry(
    path: str,
    member: str,
    max_bytes: int = 65536,
    password: str | None = None,
    encoding: str | None = None,
) -> str:
    """Preview ONE member without extracting the rest.

    Returns UTF-8 text when the member is text, otherwise a hex dump of the first 512 bytes.
    max_bytes caps what is read (default 64 KiB, hard cap 1 MiB); the header says if it was
    truncated. member is the exact name shown by list_entries.
    """
    return ops.read_entry(
        sandbox(path, "archive"), member, CONFIG.limits, max_bytes, password, encoding
    )


@tool
def search_in_archive(
    path: str,
    pattern: str,
    glob: str | None = None,
    ignore_case: bool = False,
    max_matches: int = 100,
    password: str | None = None,
    encoding: str | None = None,
) -> str:
    """Grep text members inside an archive without extracting it.

    pattern is a Python regular expression, matched per line. glob narrows which members are
    searched. Binary members are skipped and counted; each member is read at most 5 MiB and the
    whole search at most 64 MiB, and the result says when a cap was hit.
    Output lines look like 'member/name:LINE: text'.
    """
    return ops.search(
        sandbox(path, "archive"), pattern, CONFIG.limits, glob, ignore_case, max_matches,
        password, encoding,
    )  # fmt: skip


@tool
def extract_archive(
    path: str,
    dest: str,
    members: list[str] | None = None,
    overwrite: bool = False,
    dry_run: bool = False,
    symlinks: str = "skip",
    password: str | None = None,
    encoding: str | None = None,
    max_total_mb: float | None = None,
    max_ratio: float | None = None,
    max_entries: int | None = None,
) -> str:
    """Safely extract an archive (all of it, or selected members) into dest.

    Everything is checked BEFORE the first byte is written; if anything is unsafe the whole
    call is refused and nothing is written. Refused: '..' traversal, absolute and drive-letter
    paths, backslash tricks, symlinks that point outside dest (or through a link), hardlinks,
    device/FIFO files, duplicate names, and decompression bombs (too large, too high a
    compression ratio, too many entries). Nested archives are NOT extracted.

    members: names, directory prefixes ('src/') or globs ('*.txt'); use it to take only the safe
    entries from an archive that was refused. Existing files are never overwritten unless
    overwrite=true. dry_run=true validates and lists what would be written without touching
    the disk. symlinks='skip' (default) reports links instead of creating them; 'create' makes
    in-bounds links (needs privileges on Windows). If a failure happens mid-way, files created
    by this call are removed. max_total_mb / max_ratio / max_entries can only make the server's
    limits stricter, never looser.
    """
    limits = CONFIG.limits.tightened(max_total_mb, max_ratio, max_entries)
    return ops.extract(
        sandbox(path, "archive"), sandbox(dest, "destination"), limits, members, overwrite,
        dry_run, symlinks, password, encoding,
    ).render()  # fmt: skip


@tool
def create_archive(
    output: str,
    sources: list[str],
    format: str = "zip",
    excludes: list[str] | None = None,
    deterministic: bool = False,
    overwrite: bool = False,
) -> str:
    """Create an archive from files and directories.

    format: zip (default), tar, tar.gz, tar.bz2 or tar.xz. Each source is stored under its own
    base name (directories recursively). excludes are globs matched against the stored path and
    against every path component (e.g. ['*.pyc', '__pycache__', '.git']). deterministic=true
    fixes timestamps, owners, permissions and ordering, so the same inputs give byte-identical
    output (the sha256 is returned). Symlinks in the sources are refused; the output file is
    never overwritten unless overwrite=true. Zips cannot be encrypted (standard-library limit).
    """
    return ops.create(
        sandbox(output, "output"), [sandbox(s, "source") for s in sources], CONFIG.limits,
        format, excludes, deterministic, overwrite,
    ).render()  # fmt: skip


@tool
def verify_archive(path: str, password: str | None = None, encoding: str | None = None) -> str:
    """Test archive integrity by decompressing every file and checking CRCs/checksums.

    Writes nothing. Returns 'OK ...' or 'FAILED ...' with the bad members. Encrypted members
    are only verified when password is given.
    """
    return ops.verify(sandbox(path, "archive"), CONFIG.limits, password, encoding)


def main(argv: Sequence[str] | None = None) -> None:
    p = argparse.ArgumentParser(
        prog="unpack-mcp", description="MCP server for safe archive handling."
    )
    d = Limits()
    p.add_argument(
        "--dir", action="append", default=[], metavar="PATH",
        help="allowed directory for sources and destinations (repeatable; default: current directory)",
    )  # fmt: skip
    p.add_argument(
        "--max-total-mb", type=float, default=d.max_total_bytes / MiB,
        help="max total uncompressed MiB (default %(default)s)",
    )  # fmt: skip
    p.add_argument(
        "--max-ratio", type=float, default=d.max_ratio,
        help="max compression ratio (default %(default)s)",
    )  # fmt: skip
    p.add_argument(
        "--max-entries", type=int, default=d.max_entries,
        help="max entries per archive (default %(default)s)",
    )  # fmt: skip
    a = p.parse_args(argv)
    for r in a.dir:
        if not os.path.isdir(r):
            p.error(f"--dir {r!r} is not a directory")
    CONFIG.roots = [os.path.abspath(r) for r in a.dir]
    CONFIG.limits = Limits(int(a.max_total_mb * MiB), a.max_ratio, a.max_entries)
    mcp.run()


if __name__ == "__main__":
    main()
