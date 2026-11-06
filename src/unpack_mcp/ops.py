"""The seven operations. Every function takes real, sandbox-checked paths."""

from __future__ import annotations

import gzip
import fnmatch
import hashlib
import os
import re
import shutil
import stat
import tarfile
import zipfile
from dataclasses import dataclass, field
from typing import IO

from .core import (
    ARCHIVE_SUFFIXES,
    Archive,
    Budget,
    Entry,
    LimitError,
    Limits,
    UnpackError,
    UnsafeArchiveError,
    archive,
    check_limits,
    dup_key,
    fmt_bytes,
    match_glob,
    match_member,
    normalize_name,
    read_errors,
    verify_errors,
)

DETERMINISTIC_MTIME = 315532800  # 1980-01-01T00:00:00Z, the earliest zip can store


def is_inside(path: str, base: str) -> bool:
    try:
        b = os.path.normcase(base)
        return os.path.commonpath([os.path.normcase(path), b]) == b
    except ValueError:
        return False


def layout_conflicts(entries: list[Entry]) -> list[str]:
    """Duplicate names (case/Unicode-insensitive) and file-vs-directory clashes."""
    problems: list[str] = []
    files: dict[str, str] = {}
    dirs: dict[str, str] = {}
    for e in entries:
        if not e.path:
            continue
        k = dup_key(e.path)
        if e.kind == "dir":
            dirs.setdefault(k, e.name)
            continue
        if k in files:
            problems.append(f"duplicate entry {e.name!r} (same path as {files[k]!r})")
        files[k] = e.name
    for e in entries:
        if not e.path:
            continue
        parts = e.path.split("/")
        for i in range(1, len(parts)):
            anc = dup_key("/".join(parts[:i]))
            if anc in files:
                problems.append(f"{e.name!r} needs {files[anc]!r} to be a directory, but it is a file")
                break
    if (both := set(files) & set(dirs)):
        problems.append(f"entry {files[min(both)]!r} is both a file and a directory")
    return problems


def _nested(entries: list[Entry]) -> list[str]:
    return [e.name for e in entries if e.kind == "file" and e.name.lower().endswith(ARCHIVE_SUFFIXES)]


def _safe_open(a: Archive, e: Entry, password: str | None) -> IO[bytes]:
    return a.open_member(e, password)


# ----------------------------------------------------------------- info/list


def info(path: str, limits: Limits, password: str | None = None, encoding: str | None = None) -> str:
    with archive(path, limits, encoding) as a:
        entries = a.entries(password)
        files = [e for e in entries if e.kind == "file"]
        total = sum(e.size for e in files)
        lines = [f"Archive: {path}", f"Format: {a.format}", f"Archive size: {fmt_bytes(a.size)}"]
        counts = {k: sum(1 for e in entries if e.kind == k) for k in ("file", "dir", "symlink", "hardlink", "special")}
        lines.append(
            "Entries: %d (%d files, %d dirs, %d symlinks, %d hardlinks, %d special)"
            % (len(entries), counts["file"], counts["dir"], counts["symlink"], counts["hardlink"], counts["special"])
        )
        lines.append(f"Uncompressed size: {fmt_bytes(total)}")
        if a.format == "zip":
            csum = sum(e.csize or 0 for e in files)
            lines.append(f"Compressed size of entries: {fmt_bytes(csum)}")
            if csum > a.size:
                lines.append("  WARNING: entries' compressed sizes add up to more than the file: overlapping entries (zip quine bomb)")
        lines.append(f"Ratio: {total / max(a.size, 1):.1f}:1 (limit {limits.max_ratio:.0f}:1)")
        enc = [e for e in entries if e.encrypted]
        lines.append(f"Encrypted: {'yes, %d entries (pass password=)' % len(enc) if enc else 'no'}")
        if a.comment:
            lines.append(f"Comment: {a.comment[:500]!r}")
        top: dict[str, int] = {}
        for e in entries:
            if e.path:
                top[e.path.split("/")[0]] = top.get(e.path.split("/")[0], 0) + 1
        shown = sorted(top.items())[:15]
        lines.append(f"Top-level ({len(top)}): " + ", ".join(f"{n} ({c})" for n, c in shown) + (" ..." if len(top) > 15 else ""))
        if len(top) > 1:
            lines.append("  note: several top-level items - extract into an empty directory (tar-bomb style layout)")
        nested = _nested(entries)
        if nested:
            lines.append(f"Nested archives (reported, never auto-extracted): {', '.join(nested[:10])}" + (" ..." if len(nested) > 10 else ""))
        flagged = [e for e in entries if e.problems or e.warnings]
        dups = layout_conflicts(entries)
        if flagged or dups:
            lines.append("Suspicious entries:")
            for e in flagged[:20]:
                lines.append(f"  {e.name!r}: " + "; ".join(e.problems + e.warnings) + ("  [BLOCKS EXTRACTION]" if e.problems else ""))
            for d in dups[:10]:
                lines.append(f"  {d}  [BLOCKS EXTRACTION]")
            if len(flagged) > 20:
                lines.append(f"  ... and {len(flagged) - 20} more")
        else:
            lines.append("Suspicious entries: none")
        if a.encoding_hint:
            lines.append(f"Names: {a.encoding_hint}")
        try:
            check_limits(entries, a.size, limits)
        except LimitError as e:
            lines.append(f"Extraction verdict: WOULD BE REFUSED - {e}")
        else:
            blocked = sum(1 for e in entries if e.problems) + len(dups)
            lines.append(
                "Extraction verdict: safe to extract" if not blocked
                else f"Extraction verdict: WOULD BE REFUSED - {blocked} blocking problem(s); extract members=[...] to take only safe entries"
            )  # fmt: skip
        return "\n".join(lines)


def list_entries(
    path: str, limits: Limits, glob: str | None = None, tree: bool = False, limit: int = 200,
    encoding: str | None = None, password: str | None = None,
) -> str:  # fmt: skip
    with archive(path, limits, encoding) as a:
        entries = a.entries(password)
        sel = [e for e in entries if glob is None or match_glob(e, glob)]
        out = [f"{a.format}: {len(sel)} of {len(entries)} entries" + (f" matching {glob!r}" if glob else "")]
        shown = sel[: max(limit, 0)]
        if tree:
            out += _tree(shown)
        else:
            for e in shown:
                flag = ""
                if e.problems:
                    flag = "  !! " + "; ".join(e.problems)
                elif e.warnings:
                    flag = "  ! " + "; ".join(e.warnings)
                extra = f" -> {e.link}" if e.link else ""
                lock = " [encrypted]" if e.encrypted else ""
                out.append(f"{e.kind[0]} {e.size:>12} {e.mtime:<16} {e.name}{extra}{lock}{flag}")
        if len(sel) > len(shown):
            out.append(f"... {len(sel) - len(shown)} more not shown (raise limit or narrow glob)")
        return "\n".join(out)


def _tree(entries: list[Entry]) -> list[str]:
    root: dict[str, dict] = {}  # type: ignore[type-arg]
    sizes: dict[str, int] = {}
    for e in entries:
        node = root
        for part in (e.path or e.name).split("/"):
            node = node.setdefault(part, {})
        if e.kind != "dir":
            sizes[e.path or e.name] = e.size
    out: list[str] = []

    def walk(node: dict, prefix: str, trail: str) -> None:  # type: ignore[type-arg]
        for name in sorted(node):
            full = f"{trail}{name}"
            child = node[name]
            label = f"{name}/" if child else f"{name}  ({fmt_bytes(sizes[full])})" if full in sizes else name
            out.append(f"{prefix}{label}")
            walk(child, prefix + "  ", full + "/")

    walk(root, "", "")
    return out


# --------------------------------------------------------------- read/search


def _find(entries: list[Entry], member: str) -> Entry:
    want = member.replace("\\", "/").strip("/")
    hits = [e for e in entries if e.name == member or e.path == want or e.name.replace("\\", "/").strip("/") == want]
    if not hits:
        near = [e.name for e in entries if want.lower() in (e.path or e.name).lower()][:5]
        raise UnpackError(f"no member named {member!r}" + (f"; similar: {near}" if near else "; use list_entries to see names"))
    return hits[-1]


def read_entry(
    path: str, member: str, limits: Limits, max_bytes: int = 65536, password: str | None = None,
    encoding: str | None = None,
) -> str:  # fmt: skip
    max_bytes = max(1, min(max_bytes, 1024 * 1024))
    with archive(path, limits, encoding) as a:
        entries = a.entries(password)
        check_limits(entries, a.size, limits)
        e = _find(entries, member)
        if e.kind != "file":
            raise UnpackError(f"{e.name!r} is a {e.kind}" + (f" -> {e.link}" if e.link else "") + ", not a regular file")
        with _safe_open(a, e, password) as fh:
            try:
                data = fh.read(max_bytes + 1)
            except read_errors() as ex:
                raise UnpackError(f"cannot read {e.name!r}: {ex}") from ex
        truncated = len(data) > max_bytes
        data = data[:max_bytes]
        head = f"{e.name} ({fmt_bytes(e.size)}), showing {len(data)} bytes" + (" (truncated; raise max_bytes)" if truncated else "")
        if b"\0" not in data[:8192]:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError as ex:
                # A multi-byte character cut by the byte cap is still text.
                if truncated and ex.start >= len(data) - 3:
                    text = data[: ex.start].decode("utf-8")
                else:
                    text = ""
            if text or not data:
                return f"{head}, text:\n{text}"
        return f"{head}, binary, hex dump of first {min(len(data), 512)} bytes:\n{_hexdump(data[:512])}"


def _hexdump(data: bytes) -> str:
    rows = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        rows.append(f"{i:08x}  {hexs:<47}  {''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)}")
    return "\n".join(rows)


def search(
    path: str, pattern: str, limits: Limits, glob: str | None = None, ignore_case: bool = False,
    max_matches: int = 100, password: str | None = None, encoding: str | None = None,
    per_file_bytes: int = 5 * 1024 * 1024, total_bytes: int = 64 * 1024 * 1024,
) -> str:  # fmt: skip
    try:
        rx = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    except re.error as ex:
        raise UnpackError(f"invalid regular expression {pattern!r}: {ex}") from ex
    with archive(path, limits, encoding) as a:
        entries = a.entries(password)
        check_limits(entries, a.size, limits)
        matches: list[str] = []
        scanned = binary = capped = locked = 0
        budget = 0
        stop = ""
        for e in entries:
            if e.kind != "file" or (glob and not match_glob(e, glob)):
                continue
            if e.encrypted and not password:
                locked += 1
                continue
            if budget >= total_bytes:
                stop = f"stopped after scanning {fmt_bytes(budget)}; narrow with glob="
                break
            with _safe_open(a, e, password) as fh:
                try:
                    data = fh.read(per_file_bytes + 1)
                except read_errors() as ex:
                    raise UnpackError(f"cannot read {e.name!r}: {ex}") from ex
            budget += len(data)
            if len(data) > per_file_bytes:
                capped += 1
                data = data[:per_file_bytes]
            if b"\0" in data[:8192]:
                binary += 1
                continue
            scanned += 1
            for n, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
                if rx.search(line[:4000]):
                    matches.append(f"{e.name}:{n}: {line[:300]}")
                    if len(matches) >= max_matches:
                        stop = f"stopped at max_matches={max_matches}"
                        break
            if len(matches) >= max_matches:
                break
        out = [f"{len(matches)} match(es) in {scanned} text file(s)"]
        notes = [
            s for s in (
                f"{binary} binary skipped" if binary else "",
                f"{capped} larger than {fmt_bytes(per_file_bytes)} (only the first part searched)" if capped else "",
                f"{locked} encrypted skipped (pass password=)" if locked else "",
                stop,
            ) if s
        ]  # fmt: skip
        if notes:
            out.append("notes: " + "; ".join(notes))
        return "\n".join(out + matches)


# -------------------------------------------------------------------- verify


def verify(path: str, limits: Limits, password: str | None = None, encoding: str | None = None) -> str:
    with archive(path, limits, encoding) as a:
        entries = a.entries(password)
        check_limits(entries, a.size, limits)
        budget = Budget(limits)
        failures: list[str] = []
        locked: list[str] = []
        checked = 0
        for e in entries:
            if e.kind != "file":
                continue
            if e.encrypted and not password:
                locked.append(e.name)
                continue
            try:
                with _safe_open(a, e, password) as fh:
                    budget.copy(fh, None, e)
                checked += 1
            except LimitError:
                raise
            except verify_errors() as ex:
                failures.append(f"{e.name}: {ex}")
        head = f"{path}: "
        if failures:
            return head + f"FAILED - {len(failures)} bad entr{'y' if len(failures) == 1 else 'ies'}, {checked} OK:\n" + "\n".join(failures[:20])
        msg = head + f"OK - {checked} file(s), {fmt_bytes(budget.total)} decompressed, all checksums match"
        if locked:
            msg += f"; {len(locked)} encrypted file(s) NOT verified (pass password=)"
        return msg


# ------------------------------------------------------------------- extract


@dataclass
class ExtractResult:
    dest: str
    fmt: str
    dry_run: bool
    files: list[str] = field(default_factory=list)
    dirs: list[str] = field(default_factory=list)
    links: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    conflicts: list[str] = field(default_factory=list)
    nbytes: int = 0

    def render(self) -> str:
        verb = "Would extract" if self.dry_run else "Extracted"
        out = [f"{verb} {len(self.files)} file(s) ({fmt_bytes(self.nbytes)}), {len(self.dirs)} dir(s), {len(self.links)} symlink(s) to {self.dest}"]
        for title, items in (("files", self.files), ("symlinks", self.links), ("skipped", self.skipped)):
            if items:
                out.append(f"{title}:")
                out += [f"  {i}" for i in items[:50]]
                if len(items) > 50:
                    out.append(f"  ... {len(items) - 50} more")
        if self.conflicts:
            out.append(f"WOULD REFUSE: {len(self.conflicts)} existing path(s) would be overwritten (pass overwrite=true):")
            out += [f"  {c}" for c in self.conflicts[:20]]
        return "\n".join(out)


def _select(entries: list[Entry], members: list[str] | None) -> list[Entry]:
    if members is None:
        return entries
    chosen: list[Entry] = []
    for pat in members:
        hit = [e for e in entries if match_member(e, pat)]
        if not hit:
            raise UnpackError(f"members pattern {pat!r} matches nothing; use list_entries to see names")
        chosen += [e for e in hit if e not in chosen]
    return chosen


def _safe_parent(base: str, parts: list[str], created_dirs: list[str], make: bool = True) -> str:
    """Walk/create parent dirs one component at a time, refusing links."""
    cur = base
    for part in parts:
        cur = os.path.join(cur, part)
        if os.path.lexists(cur):
            st = os.lstat(cur)
            if stat.S_ISLNK(st.st_mode) or getattr(os.path, "isjunction", lambda _p: False)(cur):
                raise UnsafeArchiveError(f"refusing to write through link {cur!r} (symlink escape attempt)")
            if not stat.S_ISDIR(st.st_mode):
                raise UnpackError(f"cannot create directory {cur!r}: a file is in the way")
        elif make:
            os.mkdir(cur)
            created_dirs.append(cur)
    if not is_inside(os.path.realpath(cur), base):
        raise UnsafeArchiveError(f"{cur!r} resolves outside the destination")
    return cur


def extract(
    path: str, dest: str, limits: Limits, members: list[str] | None = None, overwrite: bool = False,
    dry_run: bool = False, symlinks: str = "skip", password: str | None = None,
    encoding: str | None = None,
) -> ExtractResult:  # fmt: skip
    if symlinks not in ("skip", "create"):
        raise UnpackError("symlinks must be 'skip' or 'create'")
    if os.path.lexists(dest) and not os.path.isdir(dest):
        raise UnpackError(f"destination {dest} exists and is not a directory")
    with archive(path, limits, encoding) as a:
        entries = a.entries(password)
        sel = _select(entries, members)
        refusals: list[str] = []
        for e in sel:
            probs = list(e.problems)
            if e.kind == "symlink" and symlinks == "create":
                probs += [f"symlink target contains '..': not created ({e.link!r})"] if any("contains '..'" in w for w in e.warnings) else []
            if probs:
                refusals.append(f"{e.name!r}: " + "; ".join(probs))
        refusals += layout_conflicts(sel)
        if refusals:
            more = f" (+{len(refusals) - 10} more)" if len(refusals) > 10 else ""
            raise UnsafeArchiveError(
                f"refusing to extract {path}: {len(refusals)} unsafe item(s), nothing was written:\n  "
                + "\n  ".join(refusals[:10]) + more
                + "\nTo take only the safe entries, pass members=[...] (see list_entries)."
            )  # fmt: skip
        check_limits(sel, a.size, limits)

        res = ExtractResult(dest, a.format, dry_run)
        dest_abs = os.path.abspath(dest)
        base = os.path.realpath(dest_abs)
        for e in sel:
            if not e.path:
                continue
            target = os.path.join(base, *e.path.split("/"))
            if e.kind == "dir":
                res.dirs.append(e.path)
            elif e.kind == "symlink" and symlinks == "skip":
                res.skipped.append(f"{e.path} -> {e.link} (symlink skipped; symlinks='create' to create)")
                continue
            else:
                (res.links if e.kind == "symlink" else res.files).append(e.path)
                res.nbytes += e.size if e.kind == "file" else 0
                if os.path.lexists(target):
                    if os.path.islink(target) or os.path.isdir(target):
                        raise UnsafeArchiveError(f"{target!r} already exists as a link or directory; refusing to replace it")
                    if not overwrite:
                        res.conflicts.append(e.path)
        if dry_run:
            return res
        if res.conflicts:
            raise UnpackError(
                f"{len(res.conflicts)} file(s) already exist in {dest}, nothing was written; pass overwrite=true "
                f"to replace them: {', '.join(res.conflicts[:10])}"
            )
        _do_extract(a, sel, base, symlinks, overwrite, password, limits)
        return res


def _do_extract(
    a: Archive, sel: list[Entry], base: str, symlinks: str, overwrite: bool, password: str | None, limits: Limits
) -> None:
    created_files: list[str] = []
    created_dirs: list[str] = []
    budget = Budget(limits)
    tmp = ""
    try:
        if not os.path.isdir(base):
            os.makedirs(base)
            created_dirs.append(base)
        for e in sel:
            if not e.path:
                continue
            parts = e.path.split("/")
            if e.kind == "dir":
                _safe_parent(base, parts, created_dirs)
                continue
            if e.kind == "symlink" and symlinks == "skip":
                continue
            parent = _safe_parent(base, parts[:-1], created_dirs)
            target = os.path.join(parent, parts[-1])
            existed = os.path.lexists(target)
            if existed and (not overwrite or os.path.islink(target) or os.path.isdir(target)):
                raise UnpackError(f"{target!r} appeared during extraction; refusing to overwrite")
            if e.kind == "symlink":
                try:
                    link = e.link or ""
                    # Windows wants backslashes in a link target and must be told if it is a directory.
                    os.symlink(link.replace("/", os.sep), target, target_is_directory=os.path.isdir(os.path.join(parent, link)))
                except (OSError, NotImplementedError) as ex:
                    raise UnpackError(
                        f"cannot create symlink {e.path!r}: {ex}. On Windows symlinks need Developer Mode or "
                        "an elevated process; use symlinks='skip'. Nothing was left behind."
                    ) from ex
                created_files.append(target)
                continue
            with _safe_open(a, e, password) as src:
                if existed:
                    tmp = os.path.join(parent, f".{parts[-1]}.unpack-{os.getpid()}.tmp")
                    with open(tmp, "xb") as dst:
                        budget.copy(src, dst, e)
                    os.replace(tmp, target)
                    tmp = ""
                else:
                    created_files.append(target)
                    with open(target, "xb") as dst:
                        budget.copy(src, dst, e)
            if e.mode and e.mode & 0o111 and os.name != "nt":
                os.chmod(target, 0o755)
    except BaseException as ex:
        if tmp and os.path.lexists(tmp):
            os.unlink(tmp)
        for f in reversed(created_files):
            if os.path.lexists(f):
                os.unlink(f)
        for d in reversed(created_dirs):
            try:
                os.rmdir(d)
            except OSError:
                pass  # not empty: something else put files there, leave it
        if isinstance(ex, (OSError, *read_errors())) and not isinstance(ex, UnpackError):
            raise UnpackError(f"extraction failed and was rolled back: {ex}") from ex
        raise


# -------------------------------------------------------------------- create


@dataclass
class CreateResult:
    output: str
    fmt: str
    files: int
    dirs: int
    nbytes: int
    size: int
    sha256: str
    deterministic: bool

    def render(self) -> str:
        return (
            f"Created {self.output} ({self.fmt}): {self.files} file(s), {self.dirs} dir(s), "
            f"{fmt_bytes(self.nbytes)} -> {fmt_bytes(self.size)}\nsha256: {self.sha256}"
            + (" (deterministic: same inputs give the same bytes)" if self.deterministic else "")
        )


def _excluded(arc: str, excludes: list[str]) -> bool:
    return any(
        fnmatch.fnmatchcase(arc, p) or any(fnmatch.fnmatchcase(part, p) for part in arc.split("/"))
        for p in excludes
    )


def _collect(sources: list[str], excludes: list[str], output: str, limits: Limits) -> list[tuple[str, str, bool]]:
    items: dict[str, tuple[str, str, bool]] = {}

    def add(fs: str, arc: str, is_dir: bool) -> None:
        if os.path.islink(fs):
            raise UnpackError(f"{fs} is a symlink; archives made here never contain links (exclude it with excludes=)")
        _, probs, _w = normalize_name(arc, False)
        if probs:
            raise UnsafeArchiveError(f"cannot store {arc!r}: {'; '.join(probs)}")
        if dup_key(arc) in {dup_key(k) for k in items}:
            raise UnpackError(f"two sources would both be stored as {arc!r}")
        items[arc] = (fs, arc, is_dir)
        if len(items) > limits.max_entries:
            raise LimitError(f"more than {limits.max_entries} entries to archive; refusing (server --max-entries)")

    out_real = os.path.realpath(output)
    for src in sources:
        if not os.path.lexists(src):
            raise UnpackError(f"source does not exist: {src}")
        base = os.path.basename(src.rstrip("/\\"))
        if _excluded(base, excludes):
            continue
        if os.path.isdir(src) and not os.path.islink(src):
            add(src, base, True)
            for root, dirs, files in os.walk(src):
                dirs.sort()
                rel = os.path.relpath(root, src)
                prefix = base if rel == "." else base + "/" + rel.replace(os.sep, "/")
                for d in list(dirs):
                    arc = f"{prefix}/{d}"
                    if _excluded(arc, excludes):
                        dirs.remove(d)
                    else:
                        add(os.path.join(root, d), arc, True)
                for f in sorted(files):
                    arc = f"{prefix}/{f}"
                    fs = os.path.join(root, f)
                    if _excluded(arc, excludes) or os.path.realpath(fs) == out_real:
                        continue
                    add(fs, arc, False)
        else:
            if os.path.realpath(src) == out_real:
                continue
            add(src, base, False)
    total = sum(os.path.getsize(fs) for fs, _a, d in items.values() if not d)
    if total > limits.max_total_bytes:
        raise LimitError(f"sources total {fmt_bytes(total)}, over the {fmt_bytes(limits.max_total_bytes)} limit")
    return sorted(items.values(), key=lambda t: t[1])


def create(
    output: str, sources: list[str], limits: Limits, fmt: str = "zip", excludes: list[str] | None = None,
    deterministic: bool = False, overwrite: bool = False,
) -> CreateResult:  # fmt: skip
    if fmt not in ("zip", "tar", "tar.gz", "tar.bz2", "tar.xz"):
        raise UnpackError("format must be one of zip, tar, tar.gz, tar.bz2, tar.xz")
    if not sources:
        raise UnpackError("sources is empty")
    if os.path.lexists(output) and not overwrite:
        raise UnpackError(f"{output} already exists; pass overwrite=true to replace it")
    if os.path.isdir(output):
        raise UnpackError(f"{output} is a directory; give a file name")
    items = _collect(sources, excludes or [], output, limits)
    if not items:
        raise UnpackError("nothing to archive: every source was excluded")
    parent = os.path.dirname(os.path.abspath(output))
    os.makedirs(parent, exist_ok=True)
    part = output + ".part"
    try:
        if fmt == "zip":
            _write_zip(part, items, deterministic)
        else:
            _write_tar(part, items, fmt, deterministic)
        os.replace(part, output)
    finally:
        if os.path.lexists(part):
            os.unlink(part)
    h = hashlib.sha256()
    with open(output, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    nfiles = sum(1 for _f, _a, d in items if not d)
    nbytes = sum(os.path.getsize(f) for f, _a, d in items if not d)
    return CreateResult(output, fmt, nfiles, len(items) - nfiles, nbytes, os.path.getsize(output), h.hexdigest(), deterministic)


def _mode_for(fs: str, is_dir: bool) -> int:
    if is_dir:
        return 0o755
    return 0o755 if os.name != "nt" and os.stat(fs).st_mode & 0o111 else 0o644


def _write_zip(out: str, items: list[tuple[str, str, bool]], deterministic: bool) -> None:
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, strict_timestamps=False) as zf:
        for fs, arc, is_dir in items:
            if not deterministic:
                zf.write(fs, arc)
                continue
            zi = zipfile.ZipInfo(arc + "/" if is_dir else arc, (1980, 1, 1, 0, 0, 0))
            zi.create_system = 3
            zi.compress_type = zipfile.ZIP_STORED if is_dir else zipfile.ZIP_DEFLATED
            mode = _mode_for(fs, is_dir)
            zi.external_attr = ((stat.S_IFDIR if is_dir else stat.S_IFREG) | mode) << 16
            if is_dir:
                zf.writestr(zi, b"")
            else:
                zi.file_size = os.path.getsize(fs)
                with open(fs, "rb") as src, zf.open(zi, "w", force_zip64=zi.file_size > 0x7FFFFFFF) as dst:
                    shutil.copyfileobj(src, dst, 65536)


def _write_tar(out: str, items: list[tuple[str, str, bool]], fmt: str, deterministic: bool) -> None:
    raw = open(out, "wb")  # noqa: SIM115 - closed in finally
    gz: gzip.GzipFile | None = None
    try:
        if fmt == "tar.gz" and deterministic:
            gz = gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0)
            tf = tarfile.open(fileobj=gz, mode="w", format=tarfile.PAX_FORMAT)
        else:
            mode = {"tar": "w", "tar.gz": "w:gz", "tar.bz2": "w:bz2", "tar.xz": "w:xz"}[fmt]
            tf = tarfile.open(fileobj=raw, mode=mode, format=tarfile.PAX_FORMAT)  # type: ignore[call-overload]
        with tf:
            for fs, arc, is_dir in items:
                ti = tf.gettarinfo(fs, arc)
                if deterministic:
                    ti.uid = ti.gid = 0
                    ti.uname = ti.gname = ""
                    ti.mtime = DETERMINISTIC_MTIME
                    ti.mode = _mode_for(fs, is_dir)
                if is_dir:
                    tf.addfile(ti)
                else:
                    with open(fs, "rb") as src:
                        tf.addfile(ti, src)
        if gz is not None:
            gz.close()
    finally:
        raw.close()

