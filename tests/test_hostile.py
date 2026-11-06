"""Every attack below is a real archive built by hand. Each must be refused AND
leave the whole filesystem (including a canary outside the destination)
byte-for-byte unchanged."""

from __future__ import annotations

import gzip
import os
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
from helpers import RawEntry, make_tar, raw_zip, snapshot

from unpack_mcp import ops
from unpack_mcp.core import LimitError, Limits, UnpackError, UnsafeArchiveError

LIM = Limits()


@dataclass
class World:
    root: Path
    box: Path
    dest: Path
    outside: Path

    def refuse(self, archive: Path, exc: type[Exception] = UnsafeArchiveError, match: str | None = None, **kw: Any) -> None:
        before = snapshot(self.root)
        with pytest.raises(exc, match=match):
            ops.extract(str(archive), str(self.dest), kw.pop("limits", LIM), **kw)
        assert snapshot(self.root) == before, "the filesystem changed during a refused extraction"
        assert not self.dest.exists()


@pytest.fixture
def world(tmp_path: Path) -> World:
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "canary.txt").write_text("canary")
    box = tmp_path / "box"
    box.mkdir()
    return World(tmp_path, box, box / "out", outside)


def can_symlink(tmp: Path) -> bool:
    try:
        os.symlink(str(tmp), str(tmp / "probe-link"))
    except (OSError, NotImplementedError):
        return False
    os.unlink(str(tmp / "probe-link"))
    return True


# ----------------------------------------------------------------- traversal


@pytest.mark.parametrize(
    "name, why",
    [
        (b"../../outside/pwned.txt", "traversal"),
        (b"good/../../../outside/pwned.txt", "traversal"),
        (b"..\\..\\outside\\pwned.txt", "traversal"),
        (b"/etc/pwned.txt", "absolute"),
        (b"\\windows\\pwned.txt", "absolute"),
        (b"C:\\pwned.txt", "drive-letter"),
        (b"C:/pwned.txt", "drive-letter"),
        (b"//server/share/pwned.txt", "absolute"),
        (b"ok.txt\x00../../outside/pwned.txt", "NUL"),
    ],
)
def test_zip_name_attacks_are_refused(world: World, name: bytes, why: str) -> None:
    z = world.box / "evil.zip"
    raw_zip(z, [RawEntry(b"fine.txt", b"fine"), RawEntry(name, b"pwned")])
    world.refuse(z, match=why)


@pytest.mark.parametrize("name", ["../../outside/pwned.txt", "/tmp/pwned.txt", "a/../../pwned.txt"])
def test_tar_name_attacks_are_refused(world: World, name: str) -> None:
    t = world.box / "evil.tar"
    make_tar(t, [("fine.txt", "file", b"fine"), (name, "file", b"pwned")])
    world.refuse(t)


def test_safe_entries_can_still_be_taken_from_a_refused_archive(world: World) -> None:
    z = world.box / "mixed.zip"
    raw_zip(z, [RawEntry(b"docs/a.txt", b"a"), RawEntry(b"../../outside/pwned.txt", b"x")])
    world.refuse(z)
    res = ops.extract(str(z), str(world.dest), LIM, members=["docs/"])
    assert (world.dest / "docs" / "a.txt").read_text() == "a"
    assert res.files == ["docs/a.txt"]
    assert not (world.outside / "pwned.txt").exists()


# -------------------------------------------------------------------- links


def test_tar_symlink_escape_then_write_through_it(world: World) -> None:
    t = world.box / "slip.tar"
    make_tar(t, [("link", "sym", "../outside"), ("link/pwned.txt", "file", b"pwned")])
    for mode in ("skip", "create"):
        world.refuse(t, symlinks=mode, match="escapes")


def test_tar_symlink_absolute_target(world: World) -> None:
    t = world.box / "abs.tar"
    make_tar(t, [("passwd", "sym", "/etc/passwd")])
    world.refuse(t, match="absolute")


def test_zip_symlink_member_pointing_outside(world: World) -> None:
    z = world.box / "symzip.zip"
    raw_zip(z, [RawEntry(b"link", b"../../outside", ext_attr=0o120777)])
    world.refuse(z, match="escapes")


def test_tar_hardlink_and_special_files_are_refused(world: World) -> None:
    t = world.box / "hard.tar"
    make_tar(t, [("a.txt", "file", b"a"), ("b.txt", "hard", "a.txt")])
    world.refuse(t, match="hardlink")
    d = world.box / "dev.tar"
    make_tar(d, [("dev0", "chr", b"")])
    world.refuse(d, match="special")
    f = world.box / "fifo.tar"
    make_tar(f, [("pipe", "fifo", b"")])
    world.refuse(f, match="special")


def test_dotdot_symlink_chain_is_never_created(world: World) -> None:
    # Each link looks fine alone, but `l2 -> d/l1/..` resolves through l1.
    t = world.box / "chain.tar"
    make_tar(t, [("d", "dir", b""), ("d/l1", "sym", ".."), ("l2", "sym", "d/l1/.."), ("l2/x", "file", b"x")])
    world.refuse(t, symlinks="create", match="contains '..'")
    world.refuse(t, symlinks="skip", match="needs 'l2' to be a directory")
    # Taking only the harmless parts works, and nothing escapes.
    ops.extract(str(t), str(world.dest), LIM, members=["d"], symlinks="skip")
    assert not any(p.is_symlink() for p in world.dest.rglob("*"))
    assert not (world.box / "x").exists()


def test_preexisting_symlink_in_destination_is_not_followed(world: World) -> None:
    if not can_symlink(world.root):
        pytest.skip("this runner cannot create symlinks")
    world.dest.mkdir()
    os.symlink(str(world.outside), str(world.dest / "inner"), target_is_directory=True)
    z = world.box / "viaresident.zip"
    raw_zip(z, [RawEntry(b"inner/pwned.txt", b"pwned"), RawEntry(b"other.txt", b"o")])
    before = snapshot(world.root)
    with pytest.raises(UnsafeArchiveError, match="link"):
        ops.extract(str(z), str(world.dest), LIM)
    assert snapshot(world.root) == before  # incl. rollback of other.txt
    assert not (world.outside / "pwned.txt").exists()


def test_legit_in_bounds_symlink_create_or_clear_failure(world: World) -> None:
    t = world.box / "ok.tar"
    make_tar(t, [("real.txt", "file", b"hi"), ("alias", "sym", "real.txt")])
    res = ops.extract(str(t), str(world.dest), LIM)  # default skip: reported, not created
    assert res.skipped and "alias" in res.skipped[0] and not (world.dest / "alias").exists()
    (world.dest / "real.txt").unlink()
    world.dest.rmdir()
    try:
        ops.extract(str(t), str(world.dest), LIM, symlinks="create")
    except UnpackError as e:
        # Windows without Developer Mode: a clear message and nothing left behind.
        assert "Developer Mode" in str(e) and os.name == "nt"
        assert not world.dest.exists()
    else:
        assert os.readlink(str(world.dest / "alias")) == "real.txt"


# --------------------------------------------------------------------- bombs


def test_zip_bomb_by_ratio(world: World) -> None:
    z = world.box / "bomb.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.bin", b"\0" * (30 * 1024 * 1024))
    assert z.stat().st_size < 100_000  # ~1000:1 or better, and tiny on disk
    world.refuse(z, LimitError, match="decompression bomb")


def test_tar_gz_bomb_by_ratio(world: World) -> None:
    t = world.box / "bomb.tar.gz"
    make_tar(t, [("zeros.bin", "file", b"\0" * (30 * 1024 * 1024))], "w:gz")
    assert t.stat().st_size < 100_000
    world.refuse(t, LimitError, match="decompression bomb")


def test_single_gz_bomb(world: World) -> None:
    g = world.box / "zeros.gz"
    with gzip.open(g, "wb") as fh:
        fh.write(b"\0" * (30 * 1024 * 1024))
    world.refuse(g, LimitError, match="decompression bomb")


def test_total_size_limit(world: World) -> None:
    z = world.box / "big.zip"
    import random

    rnd = random.Random(1)
    raw_zip(z, [RawEntry(b"r.bin", rnd.randbytes(2 * 1024 * 1024))])  # incompressible: ratio is fine
    world.refuse(z, LimitError, match="expands to", limits=Limits(max_total_bytes=1024 * 1024))


def test_entry_count_bomb(world: World) -> None:
    z = world.box / "many.zip"
    raw_zip(z, [RawEntry(f"f{i}".encode()) for i in range(500)])
    world.refuse(z, LimitError, match="entries", limits=Limits(max_entries=100))
    t = world.box / "many.tar"
    make_tar(t, [(f"f{i}", "file", b"") for i in range(500)])
    world.refuse(t, LimitError, match="entries", limits=Limits(max_entries=100))


def test_default_entry_limit_refuses_10001_entries(world: World) -> None:
    z = world.box / "huge.zip"
    raw_zip(z, [RawEntry(f"f{i}".encode()) for i in range(10_001)])
    world.refuse(z, LimitError, match="entries")


def test_declared_size_lie_is_caught_and_rolled_back(world: World) -> None:
    z = world.box / "lie.zip"
    raw_zip(z, [RawEntry(b"a.txt", b"a" * 100), RawEntry(b"lie.bin", b"b" * 5000, method=8, usize=10)])
    before = snapshot(world.root)
    with pytest.raises((UnpackError, LimitError)):
        ops.extract(str(z), str(world.dest), LIM)
    assert snapshot(world.root) == before and not world.dest.exists()


def test_corrupt_member_mid_extraction_rolls_back(world: World) -> None:
    z = world.box / "corrupt.zip"
    raw_zip(z, [RawEntry(b"d/a.txt", b"first file"), RawEntry(b"d/b.txt", b"second file")])
    blob = bytearray(z.read_bytes())
    blob[blob.index(b"second file")] ^= 0xFF  # CRC no longer matches
    z.write_bytes(bytes(blob))
    before = snapshot(world.root)
    with pytest.raises(UnpackError, match="rolled back"):
        ops.extract(str(z), str(world.dest), LIM)
    assert snapshot(world.root) == before and not world.dest.exists()


# ------------------------------------------------------------ names & layout


def test_duplicate_entries_are_refused(world: World) -> None:
    z = world.box / "dup.zip"
    raw_zip(z, [RawEntry(b"a.txt", b"one"), RawEntry(b"a.txt", b"two")])
    world.refuse(z, match="duplicate")
    c = world.box / "case.zip"
    raw_zip(c, [RawEntry(b"A.txt", b"one"), RawEntry(b"a.txt", b"two")])
    world.refuse(c, match="duplicate")
    u = world.box / "uni.zip"
    raw_zip(u, [RawEntry("strasse.txt".encode()), RawEntry("STRASSE.txt".encode()), RawEntry("straße.txt".encode(), flags=0x800)])
    world.refuse(u, match="duplicate")


def test_file_and_directory_clash(world: World) -> None:
    z = world.box / "clash.zip"
    raw_zip(z, [RawEntry(b"x", b"file"), RawEntry(b"x/y.txt", b"under")])
    world.refuse(z, match="directory")


def test_existing_files_are_never_overwritten(world: World) -> None:
    z = world.box / "o.zip"
    raw_zip(z, [RawEntry(b"new.txt", b"new"), RawEntry(b"keep.txt", b"from archive")])
    world.dest.mkdir()
    (world.dest / "keep.txt").write_text("precious")
    before = snapshot(world.root)
    with pytest.raises(UnpackError, match="overwrite=true"):
        ops.extract(str(z), str(world.dest), LIM)
    assert snapshot(world.root) == before  # new.txt was not written either
    dry = ops.extract(str(z), str(world.dest), LIM, dry_run=True)
    assert dry.conflicts == ["keep.txt"] and "WOULD REFUSE" in dry.render()
    assert snapshot(world.root) == before
    ops.extract(str(z), str(world.dest), LIM, overwrite=True)
    assert (world.dest / "keep.txt").read_text() == "from archive"
    assert not [p for p in world.dest.iterdir() if p.name.endswith(".tmp")]


def test_dry_run_writes_nothing_and_lists(world: World) -> None:
    z = world.box / "d.zip"
    raw_zip(z, [RawEntry(b"a/b.txt", b"b"), RawEntry(b"c.txt", b"c")])
    before = snapshot(world.root)
    res = ops.extract(str(z), str(world.dest), LIM, dry_run=True)
    assert sorted(res.files) == ["a/b.txt", "c.txt"] and res.dry_run
    assert snapshot(world.root) == before and not world.dest.exists()


def test_dry_run_of_hostile_archive_still_refuses(world: World) -> None:
    z = world.box / "e.zip"
    raw_zip(z, [RawEntry(b"../x", b"x")])
    with pytest.raises(UnsafeArchiveError):
        ops.extract(str(z), str(world.dest), LIM, dry_run=True)


def test_nested_archives_are_reported_not_unpacked(world: World) -> None:
    inner = world.box / "inner.zip"
    raw_zip(inner, [RawEntry(b"secret.txt", b"s")])
    outer = world.box / "outer.zip"
    raw_zip(outer, [RawEntry(b"inner.zip", inner.read_bytes())])
    assert "Nested archives" in ops.info(str(outer), LIM) and "inner.zip" in ops.info(str(outer), LIM)
    ops.extract(str(outer), str(world.dest), LIM)
    assert sorted(p.name for p in world.dest.iterdir()) == ["inner.zip"]


@pytest.mark.skipif(os.name != "nt", reason="reserved device names are only dangerous on Windows")
def test_windows_reserved_name_is_refused_on_windows(world: World) -> None:
    z = world.box / "con.zip"
    raw_zip(z, [RawEntry(b"aux.txt", b"x")])
    world.refuse(z, match="reserved Windows device name")


def test_directory_symlink_create_or_clear_failure(world: World) -> None:
    t = world.box / "dirlink.tar"
    make_tar(t, [("sub", "dir", b""), ("sub/f.txt", "file", b"f"), ("lnk", "sym", "sub")])
    try:
        ops.extract(str(t), str(world.dest), LIM, symlinks="create")
    except UnpackError as e:
        assert "Developer Mode" in str(e) and os.name == "nt"
        assert not world.dest.exists()
    else:
        assert (world.dest / "lnk" / "f.txt").read_bytes() == b"f"
        assert (world.dest / "lnk").is_dir()
