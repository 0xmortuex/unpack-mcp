from __future__ import annotations

import gzip
import os
import tarfile
import time
import zipfile
from pathlib import Path

import pytest
from helpers import RawEntry, make_tar, raw_zip

from unpack_mcp import ops, server
from unpack_mcp.core import Limits, UnpackError, normalize_name

LIM = Limits()


def tree(root: Path) -> dict[str, bytes | None]:
    out: dict[str, bytes | None] = {}
    for p in sorted(root.rglob("*")):
        out[p.relative_to(root).as_posix()] = p.read_bytes() if p.is_file() else None
    return out


@pytest.fixture
def src(tmp_path: Path) -> Path:
    s = tmp_path / "proj"
    (s / "pkg" / "__pycache__").mkdir(parents=True)
    (s / "pkg" / "a.py").write_bytes(b"print('hello')\nTODO: fix\n")
    (s / "pkg" / "__pycache__" / "a.pyc").write_bytes(b"\0\1\2junk")
    (s / "README.md").write_bytes(b"# demo\nNothing to TODO here\n")
    (s / "data.bin").write_bytes(bytes(range(256)) * 4)
    (s / "empty-dir").mkdir()
    return s


# ----------------------------------------------------------------- names


def test_normalize_name_windows_rules() -> None:
    for bad in ("CON", "aux.txt", "dir/NUL.tar.gz", "lpt1", "dir/a:b", "trail.", "sp ", "q?.txt", "x\x01y"):
        path, problems, warnings = normalize_name(bad, windows=True)
        assert problems, bad
        _, p2, w2 = normalize_name(bad, windows=False)
        assert not p2 and w2, bad  # only a warning off Windows
    assert normalize_name("./a//b/./c.txt", True) == ("a/b/c.txt", [], [])
    assert normalize_name("COM10.txt", True)[1] == []  # COM10 is not reserved
    assert normalize_name("dir\\file.txt", False) == ("dir/file.txt", [], ["uses backslash separators"])


def test_turkish_names_round_trip_via_zip_and_tar(tmp_path: Path) -> None:
    names = ["çağrı-şüöİı.txt", "Ğüzel/ışık.md"]
    s = tmp_path / "tr"
    for n in names:
        (s / Path(n).parent).mkdir(parents=True, exist_ok=True)
        (s / n).write_text("merhaba dünya", encoding="utf-8")
    for fmt in ("zip", "tar.gz"):
        out = tmp_path / f"tr.{fmt}"
        ops.create(str(out), [str(s)], LIM, fmt)
        dest = tmp_path / f"out-{fmt}"
        ops.extract(str(out), str(dest), LIM)
        for n in names:
            assert (dest / "tr" / n).read_text(encoding="utf-8") == "merhaba dünya"
        listing = ops.list_entries(str(out), LIM)
        assert "çağrı-şüöİı.txt" in listing


def test_legacy_cp857_names_need_encoding(tmp_path: Path) -> None:
    z = tmp_path / "legacy.zip"
    raw_zip(z, [RawEntry("dağ-şeker.txt".encode("cp857"), b"tatli")])  # no UTF-8 flag
    default = ops.list_entries(str(z), LIM)
    assert "dağ-şeker.txt" not in default  # cp437 mojibake
    assert "encoding=" in ops.info(str(z), LIM)
    assert "dağ-şeker.txt" in ops.list_entries(str(z), LIM, encoding="cp857")
    ops.extract(str(z), str(tmp_path / "o"), LIM, encoding="cp857")
    assert (tmp_path / "o" / "dağ-şeker.txt").read_text() == "tatli"
    with pytest.raises(UnpackError, match="decode"):
        ops.list_entries(str(z), LIM, encoding="ascii")


def test_utf8_flagged_names_are_not_redecoded(tmp_path: Path) -> None:
    z = tmp_path / "u.zip"
    raw_zip(z, [RawEntry("ışık.txt".encode(), b"x", flags=0x800)])
    assert "ışık.txt" in ops.list_entries(str(z), LIM, encoding="cp857")


# -------------------------------------------------------------- passwords


def test_zipcrypto_password(tmp_path: Path) -> None:
    secret = "hunter2-correct-horse"
    z = tmp_path / "locked.zip"
    raw_zip(z, [RawEntry(b"s.txt", b"top secret", password=secret, method=8), RawEntry(b"plain.txt", b"plain")])
    assert "Encrypted: yes, 1 entries" in ops.info(str(z), LIM)
    with pytest.raises(UnpackError, match="password"):
        ops.read_entry(str(z), "s.txt", LIM)
    with pytest.raises(UnpackError) as ei:
        ops.read_entry(str(z), "s.txt", LIM, password="wrong-password")
    assert "wrong-password" not in str(ei.value) and secret not in str(ei.value)
    assert "top secret" in ops.read_entry(str(z), "s.txt", LIM, password=secret)
    assert "NOT verified" in ops.verify(str(z), LIM)
    assert ops.verify(str(z), LIM, password=secret).startswith(str(z) + ": OK")
    assert "1 match" in ops.search(str(z), "secret", LIM, password=secret)
    ops.extract(str(z), str(tmp_path / "o"), LIM, password=secret)
    assert (tmp_path / "o" / "s.txt").read_bytes() == b"top secret"


def test_aes_zip_is_reported_clearly(tmp_path: Path) -> None:
    z = tmp_path / "aes.zip"
    raw_zip(z, [RawEntry(b"x.txt", b"data", method=99, flags=1)])
    with pytest.raises(UnpackError, match="unsupported|AES|password"):
        ops.read_entry(str(z), "x.txt", LIM, password="pw")


# ------------------------------------------------------------ zip64, misc


def test_zip64_archive(tmp_path: Path) -> None:
    z = tmp_path / "z64.zip"
    with zipfile.ZipFile(z, "w") as zf, zf.open("big.txt", "w", force_zip64=True) as fh:
        fh.write(b"zip64 payload")
    assert z.read_bytes()[30 + len("big.txt"):][:2] == bytes([1, 0])  # local header has a zip64 extra field
    assert "big.txt" in ops.list_entries(str(z), LIM)
    assert "OK" in ops.verify(str(z), LIM)
    ops.extract(str(z), str(tmp_path / "o"), LIM)
    assert (tmp_path / "o" / "big.txt").read_bytes() == b"zip64 payload"


def test_zip_comment_and_layout(tmp_path: Path) -> None:
    z = tmp_path / "c.zip"
    raw_zip(z, [RawEntry(b"a/x.txt", b"x"), RawEntry(b"b.txt", b"y")], comment=b"built by hand")
    text = ops.info(str(z), LIM)
    assert "Comment: 'built by hand'" in text and "Top-level (2): a (1), b.txt (1)" in text
    assert "safe to extract" in text


def test_info_flags_hostile_archive(tmp_path: Path) -> None:
    z = tmp_path / "h.zip"
    raw_zip(z, [RawEntry(b"../../x", b"x"), RawEntry(b"ok", b"o")])
    text = ops.info(str(z), LIM)
    assert "BLOCKS EXTRACTION" in text and "WOULD BE REFUSED" in text


# ---------------------------------------------------------- read / search


def test_read_entry_text_binary_and_truncation(tmp_path: Path, src: Path) -> None:
    z = tmp_path / "p.zip"
    ops.create(str(z), [str(src)], LIM)
    t = ops.read_entry(str(z), "proj/README.md", LIM)
    assert t.endswith("# demo\nNothing to TODO here\n") and "text:" in t
    b = ops.read_entry(str(z), "proj/data.bin", LIM)
    assert "binary" in b and "00 01 02 03" in b
    cut = ops.read_entry(str(z), "proj/README.md", LIM, max_bytes=6)
    assert "truncated" in cut and cut.endswith("# demo\n"[:6])
    with pytest.raises(UnpackError, match="similar"):
        ops.read_entry(str(z), "README.md", LIM)
    with pytest.raises(UnpackError, match="is a dir"):
        ops.read_entry(str(z), "proj/pkg/", LIM)


def test_read_entry_does_not_split_a_multibyte_character(tmp_path: Path) -> None:
    z = tmp_path / "m.zip"
    raw_zip(z, [RawEntry(b"t.txt", "aş".encode())])  # 'ş' is 2 bytes
    out = ops.read_entry(str(z), "t.txt", LIM, max_bytes=2)
    assert "text:\na" in out and "binary" not in out


def test_search_in_zip_and_tar_gz(tmp_path: Path, src: Path) -> None:
    for fmt in ("zip", "tar.gz"):
        a = tmp_path / f"s.{fmt}"
        ops.create(str(a), [str(src)], LIM, fmt)
        r = ops.search(str(a), "todo", LIM, ignore_case=True)
        assert "2 match" in r and "proj/pkg/a.py:2: TODO: fix" in r and "binary skipped" in r
        r = ops.search(str(a), "TODO", LIM, glob="*.md")
        assert "1 match" in r and "README.md:2" in r
        assert "1 match" in ops.search(str(a), "TODO", LIM, glob="*.py")
        assert "stopped at max_matches=1" in ops.search(str(a), "TODO", LIM, max_matches=1)
    with pytest.raises(UnpackError, match="regular expression"):
        ops.search(str(tmp_path / "s.zip"), "(", LIM)


def test_list_entries_glob_tree_and_limit(tmp_path: Path, src: Path) -> None:
    z = tmp_path / "l.zip"
    ops.create(str(z), [str(src)], LIM)
    assert "proj/pkg/a.py" in ops.list_entries(str(z), LIM, glob="*.py")
    assert "README" not in ops.list_entries(str(z), LIM, glob="*.py")
    t = ops.list_entries(str(z), LIM, tree=True)
    assert "proj/\n  README.md" in t and "    a.py" in t
    assert "more not shown" in ops.list_entries(str(z), LIM, limit=2)


# ----------------------------------------------------------- round trips


@pytest.mark.parametrize("fmt", ["zip", "tar", "tar.gz", "tar.bz2", "tar.xz"])
def test_round_trip_with_excludes(tmp_path: Path, src: Path, fmt: str) -> None:
    out = tmp_path / f"rt.{fmt}"
    res = ops.create(str(out), [str(src)], LIM, fmt, excludes=["__pycache__", "*.bin"])
    assert res.files == 2 and res.sha256
    assert ops.verify(str(out), LIM).startswith(str(out) + ": OK")
    dest = tmp_path / "x"
    ops.extract(str(out), str(dest), LIM)
    expected = {k: v for k, v in tree(tmp_path / "proj").items() if "__pycache__" not in k and not k.endswith(".bin")}
    assert tree(dest / "proj") == expected
    assert "pyc" not in ops.list_entries(str(out), LIM)


def test_round_trip_keeps_empty_dirs_and_multiple_sources(tmp_path: Path, src: Path) -> None:
    other = tmp_path / "notes.txt"
    other.write_text("n")
    out = tmp_path / "multi.tar.gz"
    ops.create(str(out), [str(src), str(other)], LIM, "tar.gz")
    ops.extract(str(out), str(tmp_path / "x"), LIM)
    assert (tmp_path / "x" / "proj" / "empty-dir").is_dir()
    assert (tmp_path / "x" / "notes.txt").read_text() == "n"


@pytest.mark.parametrize("fmt", ["zip", "tar", "tar.gz"])
def test_deterministic_output_is_byte_identical(tmp_path: Path, src: Path, fmt: str) -> None:
    a = ops.create(str(tmp_path / f"a.{fmt}"), [str(src)], LIM, fmt, deterministic=True)
    for p in src.rglob("*"):  # change every mtime
        os.utime(p, (time.time() + 5000, time.time() + 5000))
    b = ops.create(str(tmp_path / f"b.{fmt}"), [str(src)], LIM, fmt, deterministic=True)
    assert a.sha256 == b.sha256
    assert (tmp_path / f"a.{fmt}").read_bytes() == (tmp_path / f"b.{fmt}").read_bytes()
    n = ops.create(str(tmp_path / f"n.{fmt}"), [str(src)], LIM, fmt, deterministic=False)
    assert n.sha256  # non-deterministic mode is allowed to differ, only check it works
    if fmt == "tar.gz":
        with tarfile.open(tmp_path / "a.tar.gz") as tf:
            assert {m.mtime for m in tf.getmembers()} == {315532800}


def test_create_refuses_overwrite_symlinks_and_self_inclusion(tmp_path: Path, src: Path) -> None:
    out = tmp_path / "o.zip"
    ops.create(str(out), [str(src)], LIM)
    with pytest.raises(UnpackError, match="overwrite=true"):
        ops.create(str(out), [str(src)], LIM)
    ops.create(str(out), [str(src)], LIM, overwrite=True)
    inside = src / "self.zip"
    ops.create(str(inside), [str(src)], LIM)
    assert "self.zip" not in ops.list_entries(str(inside), LIM)
    with pytest.raises(UnpackError, match="empty|nothing"):
        ops.create(str(tmp_path / "e.zip"), [str(src)], LIM, excludes=["proj"])
    try:
        os.symlink(str(src / "README.md"), str(src / "ln"))
    except (OSError, NotImplementedError):
        return
    with pytest.raises(UnpackError, match="symlink"):
        ops.create(str(tmp_path / "s.zip"), [str(src)], LIM, overwrite=True)
    assert not (tmp_path / "s.zip.part").exists()


# --------------------------------------------------------- gz / verify


def test_bare_gz_bz2_xz(tmp_path: Path) -> None:
    import bz2
    import lzma

    for name, opener in (("n.txt.gz", gzip.open), ("n.txt.bz2", bz2.open), ("n.txt.xz", lzma.open)):
        p = tmp_path / name
        with opener(p, "wb") as fh:
            fh.write(b"hello single\n")
        assert "n.txt" in ops.list_entries(str(p), LIM)
        assert "hello single" in ops.read_entry(str(p), "n.txt", LIM)
        assert "OK" in ops.verify(str(p), LIM)
        ops.extract(str(p), str(tmp_path / ("o-" + name)), LIM)
        assert (tmp_path / ("o-" + name) / "n.txt").read_bytes() == b"hello single\n"


def test_verify_detects_corruption_and_truncation(tmp_path: Path) -> None:
    z = tmp_path / "v.zip"
    raw_zip(z, [RawEntry(b"a.txt", b"alpha alpha"), RawEntry(b"b.txt", b"bravo bravo")])
    assert "OK - 2 file(s)" in ops.verify(str(z), LIM)
    blob = bytearray(z.read_bytes())
    blob[blob.index(b"bravo")] ^= 1
    z.write_bytes(bytes(blob))
    res = ops.verify(str(z), LIM)
    assert "FAILED" in res and "b.txt" in res and "1 OK" in res
    t = tmp_path / "t.tar.gz"
    make_tar(t, [("big.bin", "file", os.urandom(200_000))], "w:gz")
    t.write_bytes(t.read_bytes()[:-40_000])
    with pytest.raises(UnpackError, match="truncated|corrupt"):
        ops.verify(str(t), LIM)


def test_unsupported_and_missing(tmp_path: Path) -> None:
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not an archive at all" * 50)
    with pytest.raises(UnpackError, match="not a recognized archive"):
        ops.info(str(junk), LIM)
    sevenz = tmp_path / "a.7z"
    sevenz.write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\0" * 40)
    with pytest.raises(UnpackError, match="7z"):
        ops.info(str(sevenz), LIM)
    with pytest.raises(UnpackError, match="no such file"):
        ops.info(str(tmp_path / "nope.zip"), LIM)


# --------------------------------------------------------------- sandbox


def test_sandbox_blocks_paths_outside_dir(tmp_path: Path) -> None:
    box = tmp_path / "box"
    box.mkdir()
    old = server.CONFIG.roots
    server.CONFIG.roots = [str(box)]
    try:
        assert server.sandbox("a.zip", "archive") == os.path.realpath(str(box / "a.zip"))
        for bad in ("../x.zip", str(tmp_path / "x.zip"), "sub/../../x.zip"):
            with pytest.raises(UnpackError, match="outside the allowed"):
                server.sandbox(bad, "archive")
        try:
            os.symlink(str(tmp_path), str(box / "esc"), target_is_directory=True)
        except (OSError, NotImplementedError):
            return
        with pytest.raises(UnpackError, match="outside the allowed"):
            server.sandbox("esc/x.zip", "archive")
    finally:
        server.CONFIG.roots = old


def test_per_call_limits_can_only_tighten() -> None:
    base = Limits(max_total_bytes=100 * 1024 * 1024, max_ratio=100, max_entries=50)
    t = base.tightened(1000, 5000, 9999)
    assert (t.max_total_bytes, t.max_ratio, t.max_entries) == (100 * 1024 * 1024, 100, 50)
    t = base.tightened(1, 10, 5)
    assert (t.max_total_bytes, t.max_ratio, t.max_entries) == (1024 * 1024, 10, 5)


@pytest.mark.parametrize(
    ("mode", "ok"),
    [
        (0o600, True),  # permissions only: what Python's zipfile writes on Unix
        (0o100644, True),  # explicit regular file
        (0o020644, False),  # character device
        (0o010644, False),  # FIFO
    ],
)
def test_unix_mode_bits_decide_special_files(tmp_path: Path, mode: int, ok: bool) -> None:
    # Windows writes zip entries as FAT (mode ignored), Linux/macOS as Unix; build the Unix
    # form explicitly so this behaves the same on every OS.
    z = tmp_path / "m.zip"
    zi = zipfile.ZipInfo("f.txt")
    zi.create_system = 3
    zi.external_attr = mode << 16
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr(zi, b"data")
    if ok:
        ops.extract(str(z), str(tmp_path / "o"), LIM)
        assert (tmp_path / "o" / "f.txt").read_bytes() == b"data"
    else:
        with pytest.raises(UnpackError, match="special file"):
            ops.extract(str(z), str(tmp_path / "o"), LIM)
        assert not (tmp_path / "o").exists() or not any((tmp_path / "o").iterdir())
