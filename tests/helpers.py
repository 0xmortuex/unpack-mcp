"""Hand-built hostile archives and a filesystem fingerprint.

The zip writer here is deliberately NOT zipfile: zipfile sanitizes names (it
cuts at NUL, rewrites os.sep) and cannot write encrypted entries, so the
nastiest fixtures are assembled byte by byte.
"""

from __future__ import annotations

import hashlib
import io
import os
import struct
import tarfile
import zlib
from dataclasses import dataclass


def snapshot(root: str | os.PathLike[str]) -> dict[str, str]:
    """Fingerprint a whole tree: path -> content hash / link target / 'dir'."""
    out: dict[str, str] = {}
    root = str(root)
    for dp, dns, fns in os.walk(root):
        for n in dns + fns:
            p = os.path.join(dp, n)
            rel = os.path.relpath(p, root)
            if os.path.islink(p):
                out[rel] = "link:" + os.readlink(p)
            elif os.path.isdir(p):
                out[rel] = "dir"
            else:
                with open(p, "rb") as fh:
                    out[rel] = hashlib.sha256(fh.read()).hexdigest()
    return out


@dataclass
class RawEntry:
    name: bytes
    data: bytes = b""
    method: int = 0  # 0 stored, 8 deflate
    flags: int = 0  # bit 0 encrypted, bit 11 utf-8
    ext_attr: int = 0
    usize: int | None = None  # override the declared uncompressed size (a lie)
    password: str | None = None  # ZipCrypto
    create_system: int = 3


class _ZipCrypto:
    """PKWARE traditional encryption (the only scheme the stdlib can read)."""

    def __init__(self, password: bytes) -> None:
        self.k = [0x12345678, 0x23456789, 0x34567890]
        for c in password:
            self.update(c)

    def update(self, c: int) -> None:
        k = self.k
        k[0] = zlib.crc32(bytes([c]), k[0] ^ 0xFFFFFFFF) ^ 0xFFFFFFFF
        k[1] = ((k[1] + (k[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k[2] = zlib.crc32(bytes([k[1] >> 24]), k[2] ^ 0xFFFFFFFF) ^ 0xFFFFFFFF

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray()
        for p in data:
            t = (self.k[2] | 2) & 0xFFFF
            out.append(p ^ (((t * (t ^ 1)) >> 8) & 0xFF))
            self.update(p)
        return bytes(out)


def zipcrypto_encrypt(data: bytes, password: str, crc: int) -> bytes:
    header = bytes(range(1, 12)) + bytes([crc >> 24])
    return _ZipCrypto(password.encode("utf-8")).encrypt(header + data)


def raw_zip(path: str | os.PathLike[str], entries: list[RawEntry], comment: bytes = b"") -> None:
    body = bytearray()
    central = bytearray()
    for e in entries:
        crc = zlib.crc32(e.data) & 0xFFFFFFFF
        if e.method == 8:
            co = zlib.compressobj(9, zlib.DEFLATED, -15)
            payload = co.compress(e.data) + co.flush()
        else:
            payload = e.data
        flags = e.flags
        if e.password is not None:
            flags |= 1
            payload = zipcrypto_encrypt(payload, e.password, crc)
        usize = len(e.data) if e.usize is None else e.usize
        offset = len(body)
        common = struct.pack("<HHHHHIII", 20, flags, e.method, 0, 0x21, crc, len(payload), usize)
        body += b"PK\x03\x04" + common[:] + struct.pack("<HH", len(e.name), 0) + e.name + payload
        central += (
            b"PK\x01\x02"
            + struct.pack("<BB", 20, e.create_system)
            + common
            + struct.pack("<HHHHHII", len(e.name), 0, 0, 0, 0, e.ext_attr << 16, offset)
            + e.name
        )
    eocd = struct.pack(
        "<4sHHHHIIH", b"PK\x05\x06", 0, 0, len(entries), len(entries), len(central), len(body), len(comment)
    )
    with open(path, "wb") as fh:
        fh.write(bytes(body) + bytes(central) + eocd + comment)


def make_tar(
    path: str | os.PathLike[str],
    members: list[tuple[str, str, bytes | str]],
    mode: str = "w",
) -> None:
    """members: (name, kind, payload). kind: file|dir|sym|hard|chr|fifo; payload is data or link target."""
    kinds = {
        "file": tarfile.REGTYPE, "dir": tarfile.DIRTYPE, "sym": tarfile.SYMTYPE,
        "hard": tarfile.LNKTYPE, "chr": tarfile.CHRTYPE, "fifo": tarfile.FIFOTYPE,
    }  # fmt: skip
    with tarfile.open(str(path), mode) as tf:  # type: ignore[call-overload]
        for name, kind, payload in members:
            ti = tarfile.TarInfo(name)
            ti.type = kinds[kind]
            ti.mtime = 1_700_000_000
            if kind in ("sym", "hard"):
                assert isinstance(payload, str)
                ti.linkname = payload
                tf.addfile(ti)
            elif kind == "file":
                assert isinstance(payload, bytes)
                ti.size = len(payload)
                tf.addfile(ti, io.BytesIO(payload))
            else:
                ti.mode = 0o755 if kind == "dir" else 0o644
                tf.addfile(ti)
