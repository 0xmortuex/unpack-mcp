"""Archive reading primitives: format detection, entries, path safety, limits.

Nothing here writes to disk. The adapters (zip, tar, single-stream gz/bz2/xz)
all produce the same `Entry` records, and every entry is classified up front:
`problems` block extraction, `warnings` are only reported.
"""

from __future__ import annotations

import bz2
import contextlib
import fnmatch
import gzip
import lzma
import os
import posixpath
import re
import stat
import tarfile
import unicodedata
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import IO, Any

CHUNK = 64 * 1024
GZ_MAGIC = bytes([0x1F, 0x8B])
XZ_MAGIC = bytes([0xFD]) + b"7zXZ" + bytes([0])
# Ratio checks only apply from this size up: a 100 KiB file of zeros is
# legitimately 1000:1 and harmless, a 20 MiB one is how bombs start.
RATIO_FLOOR = 1024 * 1024
MiB = 1024 * 1024

WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)
ARCHIVE_SUFFIXES = (
    ".zip", ".jar", ".war", ".apk", ".whl", ".tar", ".tgz", ".tar.gz", ".tbz2",
    ".tar.bz2", ".txz", ".tar.xz", ".gz", ".bz2", ".xz", ".7z", ".rar",
)  # fmt: skip


class UnpackError(Exception):
    """An expected failure with a message the agent can act on."""


class UnsafeArchiveError(UnpackError):
    """The archive (or a member) was refused for safety reasons."""


class LimitError(UnpackError):
    """A decompression-bomb limit was hit."""


@dataclass(frozen=True)
class Limits:
    max_total_bytes: int = 1024 * MiB
    max_ratio: float = 200.0
    max_entries: int = 10_000

    def tightened(
        self, total_mb: float | None, ratio: float | None, entries: int | None
    ) -> Limits:
        """Per-call limits may only be stricter than the server's."""
        return Limits(
            min(self.max_total_bytes, int(total_mb * MiB)) if total_mb is not None else self.max_total_bytes,
            min(self.max_ratio, ratio) if ratio is not None else self.max_ratio,
            min(self.max_entries, entries) if entries is not None else self.max_entries,
        )  # fmt: skip


def fmt_bytes(n: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{int(n)} B" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    raise AssertionError("unreachable")


@dataclass
class Entry:
    name: str  # the name as stored (decoded), for display and matching
    path: str  # normalized relative posix path; "" when unusable
    kind: str  # file | dir | symlink | hardlink | special
    size: int = 0
    csize: int | None = None
    link: str | None = None
    encrypted: bool = False
    mode: int | None = None
    mtime: str = ""
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    ref: Any = None


# ---------------------------------------------------------------- path safety


def normalize_name(name: str, windows: bool) -> tuple[str, list[str], list[str]]:
    """Return (relative posix path, problems, warnings) for a stored member name.

    Backslashes count as separators on every OS: an archive built on Windows
    (or by an attacker) must not mean something different on the machine that
    extracts it.
    """
    problems: list[str] = []
    warnings: list[str] = []
    if "\0" in name:
        problems.append("name contains a NUL byte")
    s = name.replace("\\", "/")
    if "\\" in name:
        warnings.append("uses backslash separators")
    if s.startswith("/"):
        problems.append("absolute path")
    elif re.match(r"^[A-Za-z]:", s):
        problems.append("drive-letter path")
    parts = [p for p in s.split("/") if p not in ("", ".")]
    if ".." in parts:
        problems.append("path traversal ('..')")
    bad: list[str] = []
    for p in parts:
        base = p.split(".")[0].rstrip(" ").upper()
        if base in WINDOWS_RESERVED:
            bad.append(f"reserved Windows device name {p!r}")
        elif p.endswith((".", " ")) and p not in ("..",):
            bad.append(f"name {p!r} ends with a dot or space")
        elif re.search(r'[<>:"|?*\x00-\x1f]', p):
            bad.append(f"name {p!r} has characters invalid on Windows")
    for b in bad:
        (problems if windows else warnings).append(b if windows else b + " (invalid on Windows)")
    return "/".join(parts), problems, warnings


def check_link(path: str, target: str | None) -> tuple[list[str], list[str]]:
    """Problems/warnings for a symlink at `path` pointing to `target`."""
    if not target:
        return ["symlink with an unknown or empty target"], []
    t = target.replace("\\", "/")
    if "\0" in t:
        return ["symlink target contains a NUL byte"], []
    if t.startswith("/") or re.match(r"^[A-Za-z]:", t):
        return [f"symlink to absolute path {target!r}"], []
    resolved = posixpath.normpath(posixpath.join(posixpath.dirname(path), t))
    if resolved == ".." or resolved.startswith("../"):
        return [f"symlink {target!r} escapes the destination"], []
    if ".." in t.split("/"):
        return [], [f"symlink target {target!r} contains '..'"]
    return [], []


def dup_key(path: str) -> str:
    return unicodedata.normalize("NFC", path).casefold()


def match_member(entry: Entry, pattern: str) -> bool:
    """Exact name, directory prefix, or glob (against the full path)."""
    pat = pattern.replace("\\", "/").strip("/")
    for cand in {entry.path, entry.name.replace("\\", "/").strip("/")}:
        if not cand:
            continue
        if cand == pat or cand.startswith(pat + "/"):
            return True
        if fnmatch.fnmatchcase(cand, pat):
            return True
    return False


def match_glob(entry: Entry, glob: str) -> bool:
    """Glob filter used by list/search: full path, or basename when no '/'."""
    cand = entry.path or entry.name
    if fnmatch.fnmatchcase(cand, glob):
        return True
    return "/" not in glob and fnmatch.fnmatchcase(posixpath.basename(cand), glob)


def _classify(entry: Entry, windows: bool) -> None:
    path, problems, warnings = normalize_name(entry.name, windows)
    entry.path = path
    entry.problems += problems
    entry.warnings += warnings
    if entry.kind == "hardlink":
        entry.problems.append("hardlink member")
    elif entry.kind == "special":
        entry.problems.append("device/FIFO/special file member")
    elif entry.kind == "symlink":
        p, w = check_link(path, entry.link)
        entry.problems += p
        entry.warnings += w
    if entry.kind != "dir" and not path and not problems:
        entry.problems.append("empty file name")


def _iso(ts: float | None) -> str:
    if ts is None:
        return ""
    try:
        return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M")
    except (OverflowError, OSError, ValueError):
        return ""


# ------------------------------------------------------------------ adapters


class Archive:
    format = ""
    comment = ""

    def __init__(self, path: str, limits: Limits, windows: bool) -> None:
        self.path = path
        self.limits = limits
        self.windows = windows
        self.size = os.path.getsize(path)

    def entries(self, password: str | None = None) -> list[Entry]:
        raise NotImplementedError

    def open_member(self, entry: Entry, password: str | None = None) -> IO[bytes]:
        raise NotImplementedError

    def close(self) -> None:
        pass

    @property
    def encoding_hint(self) -> str:
        return ""


def _too_many(count: int, limits: Limits) -> LimitError:
    return LimitError(
        f"archive has more than {limits.max_entries} entries ({count}); refusing as a "
        "possible entry-count bomb. The server operator can raise --max-entries."
    )


class ZipArchive(Archive):
    format = "zip"

    def __init__(self, path: str, limits: Limits, windows: bool, encoding: str | None) -> None:
        super().__init__(path, limits, windows)
        self.encoding = encoding
        try:
            self.zf = zipfile.ZipFile(path)
        except (zipfile.BadZipFile, OSError) as e:
            raise UnpackError(f"cannot read zip: {e}") from e
        self.comment = self.zf.comment.decode("utf-8", errors="replace")
        self._legacy_names = False

    def close(self) -> None:
        self.zf.close()

    @property
    def encoding_hint(self) -> str:
        if self._legacy_names and not self.encoding:
            return (
                "some names are non-ASCII and not flagged UTF-8, so they were decoded as cp437; "
                "if they look wrong pass encoding= (cp857/cp1254 for Turkish, cp932 for Japanese, "
                "gbk for Chinese, cp1251 for Russian)"
            )
        return ""

    def _name(self, zi: zipfile.ZipInfo) -> str:
        raw = zi.orig_filename  # zipfile mangles .filename (NUL, os.sep); .orig_filename is as stored
        if not zi.flag_bits & 0x800 and not raw.isascii():
            self._legacy_names = True
            if self.encoding:
                try:
                    return raw.encode("cp437").decode(self.encoding)
                except (UnicodeError, LookupError) as e:
                    raise UnpackError(f"cannot decode member names as {self.encoding!r}: {e}") from e
        return raw

    def entries(self, password: str | None = None) -> list[Entry]:
        infos = self.zf.infolist()
        if len(infos) > self.limits.max_entries:
            raise _too_many(len(infos), self.limits)
        out: list[Entry] = []
        for zi in infos:
            mode = (zi.external_attr >> 16) & 0xFFFF if zi.create_system == 3 else 0
            if zi.orig_filename.endswith(("/", "\\")) or stat.S_ISDIR(mode):
                kind = "dir"
            elif stat.S_ISLNK(mode):
                kind = "symlink"
            elif stat.S_IFMT(mode) and not stat.S_ISREG(mode):
                # Permission-only modes (type bits 0, e.g. 0o600 as written by Python's zipfile
                # on Unix) are ordinary files; only an explicit non-regular type is special.
                kind = "special"
            else:
                kind = "file"
            e = Entry(
                self._name(zi), "", kind, zi.file_size, zi.compress_size, None,
                bool(zi.flag_bits & 0x1), mode or None,
                "%04d-%02d-%02d %02d:%02d" % zi.date_time[:5], ref=zi,
            )  # fmt: skip
            if kind == "symlink":
                if e.size > 4096:
                    e.problems.append("symlink target is implausibly long")
                elif not e.encrypted or password:
                    with contextlib.suppress(UnpackError):
                        with self.open_member(e, password) as fh:
                            e.link = fh.read(4097).decode("utf-8", errors="replace")
            _classify(e, self.windows)
            out.append(e)
        return out

    def open_member(self, entry: Entry, password: str | None = None) -> IO[bytes]:
        zi: zipfile.ZipInfo = entry.ref
        if entry.encrypted and not password:
            raise UnpackError(f"{entry.name!r} is password-protected: pass password=")
        try:
            return self.zf.open(zi, "r", pwd=password.encode("utf-8") if password else None)
        except NotImplementedError as e:
            raise UnpackError(
                f"{entry.name!r} uses an unsupported method ({e}); the standard library "
                "cannot read AES-encrypted or exotic-compression zips, only ZipCrypto and "
                "stored/deflate/bzip2/lzma"
            ) from e
        except RuntimeError as e:
            raise UnpackError(f"cannot open {entry.name!r}: wrong password or unsupported encryption") from e
        except (zipfile.BadZipFile, OSError) as e:
            raise UnpackError(f"cannot open {entry.name!r}: {e}") from e


class TarArchive(Archive):
    def __init__(self, path: str, limits: Limits, windows: bool, tf: tarfile.TarFile) -> None:
        super().__init__(path, limits, windows)
        self.tf = tf
        with open(path, "rb") as fh:
            head = fh.read(6)
        self.format = (
            "tar.gz" if head[:2] == b"\x1f\x8b" else "tar.bz2" if head[:3] == b"BZh"
            else "tar.xz" if head[:6] == b"\xfd7zXZ\x00" else "tar"
        )  # fmt: skip

    def close(self) -> None:
        self.tf.close()

    def entries(self, password: str | None = None) -> list[Entry]:
        out: list[Entry] = []
        declared = 0
        try:
            for ti in self.tf:
                if len(out) >= self.limits.max_entries:
                    raise _too_many(len(out) + 1, self.limits)
                if ti.isdir():
                    kind = "dir"
                elif ti.issym():
                    kind = "symlink"
                elif ti.islnk():
                    kind = "hardlink"
                elif ti.isreg():
                    kind = "file"
                else:
                    kind = "special"
                e = Entry(
                    ti.name, "", kind, ti.size if kind == "file" else 0, None,
                    ti.linkname if kind in ("symlink", "hardlink") else None,
                    False, ti.mode, _iso(ti.mtime), ref=ti,
                )  # fmt: skip
                _classify(e, self.windows)
                out.append(e)
                declared += e.size
                # Walking a compressed tar decompresses it all, so stop early.
                if declared > self.limits.max_total_bytes or (
                    declared >= RATIO_FLOOR and declared / max(self.size, 1) > self.limits.max_ratio
                ):
                    raise LimitError(
                        f"tar members declare {fmt_bytes(declared)} so far from a {fmt_bytes(self.size)} "
                        f"file (limits: {fmt_bytes(self.limits.max_total_bytes)}, "
                        f"{self.limits.max_ratio:.0f}:1); refusing as a decompression bomb"
                    )
        except (tarfile.TarError, EOFError, zlib.error, lzma.LZMAError, OSError) as e:
            raise UnpackError(f"tar archive is truncated or corrupt: {e}") from e
        return out

    def open_member(self, entry: Entry, password: str | None = None) -> IO[bytes]:
        try:
            fh = self.tf.extractfile(entry.ref)
        except (tarfile.TarError, OSError, EOFError, zlib.error, lzma.LZMAError) as e:
            raise UnpackError(f"cannot read {entry.name!r}: {e}") from e
        if fh is None:
            raise UnpackError(f"{entry.name!r} is a {entry.kind}, not a regular file")
        return fh


class SingleArchive(Archive):
    """A bare .gz / .bz2 / .xz stream holding one file."""

    def __init__(self, path: str, limits: Limits, windows: bool, kind: str) -> None:
        super().__init__(path, limits, windows)
        self.format = kind
        self._opener: Any = {"gz": gzip.open, "bz2": bz2.open, "xz": lzma.open}[kind]

    def entries(self, password: str | None = None) -> list[Entry]:
        base = os.path.basename(self.path)
        stem, ext = os.path.splitext(base)
        name = stem if ext.lower() in (".gz", ".bz2", ".xz") and stem else base + ".out"
        total = 0
        try:
            with self._opener(self.path, "rb") as fh:
                while chunk := fh.read(CHUNK):
                    total += len(chunk)
                    if total > self.limits.max_total_bytes:
                        break
        except (OSError, EOFError, zlib.error, lzma.LZMAError) as e:
            raise UnpackError(f"{self.format} stream is truncated or corrupt: {e}") from e
        ent = Entry(name, "", "file", total, self.size, ref=None)
        if total > self.limits.max_total_bytes:
            ent.warnings.append(f"decompresses past the {fmt_bytes(self.limits.max_total_bytes)} limit (size is a lower bound)")
        _classify(ent, self.windows)
        return [ent]

    def open_member(self, entry: Entry, password: str | None = None) -> IO[bytes]:
        try:
            fh: IO[bytes] = self._opener(self.path, "rb")
        except OSError as e:
            raise UnpackError(f"cannot read {self.path}: {e}") from e
        return fh


def open_archive(
    path: str, limits: Limits, encoding: str | None = None, windows: bool | None = None
) -> Archive:
    win = os.name == "nt" if windows is None else windows
    if not os.path.isfile(path):
        raise UnpackError(f"no such file: {path}")
    with open(path, "rb") as fh:
        head = fh.read(8)
    if zipfile.is_zipfile(path):
        return ZipArchive(path, limits, win, encoding)
    try:
        tf = tarfile.open(path, "r:*")
    except (tarfile.TarError, EOFError, zlib.error, lzma.LZMAError, OSError):
        pass
    else:
        # A compressed stream of zeros parses as a valid *empty* tar. Treat an
        # empty "tar" inside a compression wrapper as a plain compressed file,
        # otherwise a zero-filled bomb would sail through as "no entries".
        compressed = head[:2] == GZ_MAGIC or head[:3] == b"BZh" or head[:6] == XZ_MAGIC
        try:
            empty = tf.next() is None
        except (tarfile.TarError, EOFError, zlib.error, lzma.LZMAError, OSError):
            empty = False
        if not (empty and compressed):
            return TarArchive(path, limits, win, tf)
        tf.close()
    if head[:2] == b"\x1f\x8b":
        return SingleArchive(path, limits, win, "gz")
    if head[:3] == b"BZh":
        return SingleArchive(path, limits, win, "bz2")
    if head[:6] == b"\xfd7zXZ\x00":
        return SingleArchive(path, limits, win, "xz")
    if head[:6] == b"7z\xbc\xaf\x27\x1c" or head[:4] in (b"Rar!",):
        raise UnpackError("7z and RAR archives are not supported (stdlib only, no external binaries)")
    raise UnpackError(
        "not a recognized archive: supported formats are zip, tar, tar.gz/bz2/xz and bare gz/bz2/xz"
    )


@contextlib.contextmanager
def archive(
    path: str, limits: Limits, encoding: str | None = None, windows: bool | None = None
) -> Iterator[Archive]:
    a = open_archive(path, limits, encoding, windows)
    try:
        yield a
    finally:
        a.close()


# -------------------------------------------------------------------- limits


def check_limits(entries: list[Entry], archive_size: int, limits: Limits) -> None:
    """Reject bombs from the declared sizes, before any byte is written."""
    total = 0
    for e in entries:
        if e.kind != "file":
            continue
        total += e.size
        if e.size >= RATIO_FLOOR and e.csize is not None:
            ratio = e.size / max(e.csize, 1)
            if ratio > limits.max_ratio:
                raise LimitError(
                    f"{e.name!r} expands {ratio:.0f}:1 ({fmt_bytes(e.csize)} -> {fmt_bytes(e.size)}), "
                    f"over the {limits.max_ratio:.0f}:1 limit; refusing as a decompression bomb"
                )
    if total > limits.max_total_bytes:
        raise LimitError(
            f"archive expands to {fmt_bytes(total)}, over the {fmt_bytes(limits.max_total_bytes)} "
            "limit; refusing as a decompression bomb (the server operator can raise --max-total-mb)"
        )
    if total >= RATIO_FLOOR and total / max(archive_size, 1) > limits.max_ratio:
        raise LimitError(
            f"archive expands {total / max(archive_size, 1):.0f}:1 ({fmt_bytes(archive_size)} -> "
            f"{fmt_bytes(total)}), over the {limits.max_ratio:.0f}:1 limit; refusing as a decompression bomb"
        )


class Budget:
    """Counts bytes actually decompressed, regardless of what headers claimed."""

    def __init__(self, limits: Limits) -> None:
        self.limits = limits
        self.total = 0

    def copy(self, src: IO[bytes], dst: IO[bytes] | None, entry: Entry) -> int:
        written = 0
        while chunk := src.read(CHUNK):
            written += len(chunk)
            self.total += len(chunk)
            if written > entry.size:
                raise LimitError(
                    f"{entry.name!r} decompresses past its declared size of {entry.size} bytes "
                    "(the header lies); refusing as a decompression bomb"
                )
            if self.total > self.limits.max_total_bytes:
                raise LimitError(
                    f"decompressed output passed the {fmt_bytes(self.limits.max_total_bytes)} limit "
                    "while processing; refusing as a decompression bomb"
                )
            if dst is not None:
                dst.write(chunk)
        if written != entry.size:
            raise UnpackError(f"{entry.name!r} is corrupt: expected {entry.size} bytes, got {written}")
        return written


def read_errors() -> tuple[type[BaseException], ...]:
    return (
        zipfile.BadZipFile, tarfile.TarError, EOFError, zlib.error, lzma.LZMAError,
        OSError, gzip.BadGzipFile, RuntimeError, NotImplementedError,
    )  # fmt: skip


def verify_errors() -> tuple[type[BaseException], ...]:
    return (UnpackError, *read_errors())
