"""MCP stdio smoke test: spawns the real server, lists tools, and checks that
refusals reach the agent as readable errors."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp")

from helpers import RawEntry, raw_zip  # noqa: E402
from mcp import ClientSession  # noqa: E402
from mcp.client.stdio import StdioServerParameters, stdio_client  # noqa: E402

EXPECTED_TOOLS = {
    "archive_info",
    "list_entries",
    "read_entry",
    "search_in_archive",
    "extract_archive",
    "create_archive",
    "verify_archive",
}


def params(box: Path) -> StdioServerParameters:
    return StdioServerParameters(command=sys.executable, args=["-m", "unpack_mcp", "--dir", str(box)])


@pytest.mark.anyio
async def test_tools_and_a_session_over_stdio(tmp_path: Path) -> None:
    box = tmp_path / "box"
    (box / "src").mkdir(parents=True)
    (box / "src" / "hello.txt").write_text("hello from the archive\n")
    async with stdio_client(params(box)) as (read, write), ClientSession(read, write) as session:
        init = await session.initialize()
        assert init.server_info.name == "unpack"
        tools = (await session.list_tools()).tools
        assert {t.name for t in tools} == EXPECTED_TOOLS
        assert all(t.description and len(t.description) > 80 for t in tools)

        res = await session.call_tool(
            "create_archive", {"output": "out.tar.gz", "sources": ["src"], "format": "tar.gz", "deterministic": True}
        )
        assert not res.is_error and "sha256:" in res.content[0].text  # type: ignore[union-attr]
        res = await session.call_tool("archive_info", {"path": "out.tar.gz"})
        assert "Format: tar.gz" in res.content[0].text and "safe to extract" in res.content[0].text  # type: ignore[union-attr]
        res = await session.call_tool("search_in_archive", {"path": "out.tar.gz", "pattern": "archive"})
        assert "src/hello.txt:1:" in res.content[0].text  # type: ignore[union-attr]
        res = await session.call_tool("extract_archive", {"path": "out.tar.gz", "dest": "x"})
        assert not res.is_error
        assert (box / "x" / "src" / "hello.txt").read_text() == "hello from the archive\n"
        res = await session.call_tool("verify_archive", {"path": "out.tar.gz"})
        assert ": OK" in res.content[0].text  # type: ignore[union-attr]


@pytest.mark.anyio
async def test_refusals_reach_the_agent(tmp_path: Path) -> None:
    box = tmp_path / "box"
    box.mkdir()
    raw_zip(box / "evil.zip", [RawEntry(b"../../escape.txt", b"x")])
    async with stdio_client(params(box)) as (read, write), ClientSession(read, write) as session:
        await session.initialize()
        res = await session.call_tool("extract_archive", {"path": "evil.zip", "dest": "out"})
        assert res.is_error and "path traversal" in res.content[0].text  # type: ignore[union-attr]
        assert "nothing was written" in res.content[0].text  # type: ignore[union-attr]
        assert not (box / "out").exists() and not (tmp_path / "escape.txt").exists()
        res = await session.call_tool("archive_info", {"path": str(tmp_path / "other.zip")})
        assert res.is_error and "outside the allowed" in res.content[0].text  # type: ignore[union-attr]
        res = await session.call_tool("extract_archive", {"path": "evil.zip", "dest": "../out"})
        assert res.is_error and "outside the allowed" in res.content[0].text  # type: ignore[union-attr]
        res = await session.call_tool("read_entry", {"path": "nope.zip", "member": "a"})
        assert res.is_error and "no such file" in res.content[0].text  # type: ignore[union-attr]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
