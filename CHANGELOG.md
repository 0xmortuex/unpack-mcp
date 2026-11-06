# Changelog

## 0.1.0 - 2026-11-06

First release.

- Tools: `archive_info`, `list_entries`, `read_entry`, `search_in_archive`,
  `extract_archive`, `create_archive`, `verify_archive`.
- Formats (standard library only): zip (ZipCrypto passwords, zip64, legacy-codepage name
  decoding), tar, tar.gz/bz2/xz, bare gz/bz2/xz.
- Extraction refuses path traversal, absolute and drive-letter paths, backslash tricks, NUL
  names, links that escape, hardlinks, device/FIFO files, duplicate names (case and Unicode
  insensitive), file/directory clashes, and decompression bombs (size, ratio, entry count,
  lying headers). Everything is validated before the first write; failures roll back.
- `--dir` sandbox for every source and destination; `--max-total-mb`, `--max-ratio`,
  `--max-entries` server limits that per-call arguments can only tighten.
