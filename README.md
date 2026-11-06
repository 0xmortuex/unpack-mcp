# unpack-mcp

**Let your AI agent look inside zip and tar archives, and extract them without getting hacked.**

<!-- mcp-name: io.github.0xmortuex/unpack-mcp -->

unpack-mcp is an [MCP](https://modelcontextprotocol.io) server for archives. The agent can
inspect an archive, list it, read one file out of it, grep through it, verify it, create new
ones, and extract them, all without shelling out to `unzip`/`tar` and without trusting what is
inside.

**What is different from the other archive MCP servers** (such as the PyPI `archive-mcp`,
`zipnative-mcp`, or the various zip/tar toolboxes): this one treats the archive as hostile
input and proves it. The safety rules are checked *before the first byte is written*, and the
test suite builds real malicious archives by hand (zip-slip, symlink escape, hardlinks, device
files, 1000:1 bombs, entry-count bombs, lying headers) and asserts that each is refused **and
that a hash of the whole filesystem, including a canary outside the destination, is unchanged
afterwards**. It also reads and greps members *without extracting*, handles legacy zip name
encodings (Turkish, Japanese, ...), ZipCrypto passwords, and has a directory sandbox. The only
dependency is `mcp`; compression comes from the Python standard library.

## Install

Claude Code:

```bash
claude mcp add unpack -- uvx unpack-mcp --dir .
```

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "unpack": {
      "command": "uvx",
      "args": ["unpack-mcp", "--dir", "C:\\Users\\you\\Downloads", "--dir", "C:\\Users\\you\\projects"]
    }
  }
}
```

`--dir` (repeatable) is the sandbox: every archive, destination, output and source path must
resolve (after symlinks) inside one of these directories. With no `--dir`, the server's
current directory is used. Relative paths are relative to the first `--dir`.

Optional server limits: `--max-total-mb` (default 1024), `--max-ratio` (default 200),
`--max-entries` (default 10000).

## Tools

| Tool | What it does |
|------|--------------|
| `archive_info` | Format, entry counts by kind, sizes and ratio, encryption, comment, top-level layout, nested archives, suspicious entries, and an "Extraction verdict". Call first. |
| `list_entries` | Flat or `tree=true` listing, `glob` filter, output cap. Entries that would be refused are marked `!!`. |
| `read_entry` | Preview one member: text, or a hex dump if binary. Size-capped. No extraction. |
| `search_in_archive` | Regex grep through text members, with a glob filter and caps. No extraction. |
| `extract_archive` | Whole archive or `members=[...]` into `dest`. `dry_run`, `overwrite` (default off), `symlinks='skip'|'create'`, `password`, `encoding`. |
| `create_archive` | zip / tar / tar.gz / tar.bz2 / tar.xz from files and dirs, with `excludes` and `deterministic=true` (byte-identical output, sha256 returned). |
| `verify_archive` | Decompress everything and check CRCs. Writes nothing. |

Supported: zip (stored/deflate/bzip2/lzma, zip64, ZipCrypto passwords), tar, tar.gz, tar.bz2,
tar.xz, and bare `.gz` / `.bz2` / `.xz`. **Not supported** (stdlib only, no external
binaries): 7z, RAR, AES-encrypted zips. These give a clear error.

## Try asking

- "What's inside `~/Downloads/release.zip`? Is it safe to extract?"
- "Find every file in `backup.tar.gz` that mentions `API_KEY`, without extracting it."
- "Show me `config/settings.yaml` from `app.zip`."
- "Do a dry run of extracting `site.tar.xz` into `./site` and tell me what would be written."
- "This zip has garbled Turkish file names. Try cp857."
- "Pack `src/` into a deterministic `tar.gz`, excluding `__pycache__` and `.git`."
- "Is `data.zip` corrupted?"

## Security

Extraction runs a fixed algorithm, and the first failure refuses the **whole** call:

1. Open the archive and read all member headers (never `tarfile.extractall`/`zipfile.extractall`).
2. Normalize every name. Reject `..` components, absolute paths, drive letters (`C:`), UNC
   paths, NUL bytes. A backslash is a separator on every OS, so `..\..\x` is traversal
   even when extracting on Linux. On Windows, reserved device names (`CON`, `aux.txt`, ...),
   trailing dots/spaces and invalid characters are refused (elsewhere they only warn).
3. Reject hardlinks, device and FIFO files. Reject symlinks that are absolute or whose target
   leaves the destination. `symlinks='skip'` (default) never creates links; `'create'` also
   refuses any target containing `..`, so link chains cannot be built to escape.
4. Reject duplicate names (case- and Unicode-insensitive) and a path that is a file in one
   entry and a directory in another.
5. Check bomb limits from the declared sizes: total uncompressed size, compression ratio (per
   entry and overall, from 1 MiB up), entry count. While writing, count the bytes actually
   produced, so a header that lies about its size is caught too.
6. Check for conflicts: an existing file is never overwritten unless `overwrite=true`, and a
   link or directory is never replaced.
7. Write one file at a time, walking each parent directory component by component and
   refusing to pass through any symlink or junction (so a link already sitting in the
   destination cannot redirect a write), then confirm the real path is still inside the
   destination. If anything fails mid-way, everything this call created is removed.

Limits on the server are an operator decision: per-call `max_total_mb` / `max_ratio` /
`max_entries` can only be stricter than the server's, never looser. Passwords are used to
decrypt and never appear in output or error messages. Nested archives are reported by
`archive_info`, never extracted automatically.

Known limits: `overwrite=true` replaces files in place, and a later failure cannot restore a
file that was already replaced. On Windows, creating symlinks needs Developer Mode or an
elevated process; with `symlinks='create'` you get a clear error and nothing is left behind.
A bare zero-filled `.gz` is treated as a compressed file rather than an empty tar.
Names beginning with a letter and a colon (`a:b`) are refused as drive-letter paths.

## Tests

```bash
uv sync --extra test
uv run pytest
```

The hostile-archive tests (`tests/test_hostile.py`) build every archive byte by byte
(`tests/helpers.py` contains a minimal zip writer, because `zipfile` itself sanitizes names
and cannot write encrypted entries) and compare a SHA-256 fingerprint of the whole tree before
and after each refused extraction. `tests/test_stdio_handshake.py` launches the installed server
and drives it over real MCP stdio.

## Learn how it's built

[unpack-mcp-the-hard-way](https://github.com/0xmortuex/unpack-mcp-the-hard-way) builds a minimal
version of this server in seven modules: formats, listing, path traversal, bombs, the safe
extraction algorithm, the MCP wrapper, and testing with hostile archives.

## License

MIT. Built by [0xmortuex](https://github.com/0xmortuex).
