from __future__ import annotations
import asyncio
from typing import TYPE_CHECKING, Sequence, Optional, Mapping
import os

if TYPE_CHECKING:
    from mcp.server.fastmcp import Context


class CLIRuntimeError(Exception):
    def __init__(self, msg: str, exit_code: int | None = None, stdout: str = ""):
        super().__init__(msg)
        self.exit_code = exit_code
        self.stdout = stdout


async def run_cli(
    base_cmd: Sequence[str],
    *,
    ctx: Context | None = None,
    timeout_s: float = 60.0,
    max_bytes: int = 256_000,
    stdin_data: Optional[bytes] = None,
    extra_env: Optional[Mapping[str, str]] = None,
) -> str:
    """
    Run a command asynchronously with timeouts and bounded output.
    Returns stdout as text; raises CLIRuntimeError on non-zero exit or timeout.
    When ctx is provided, emits MCP progress notifications per stdout line.
    """
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)

    proc = await asyncio.create_subprocess_exec(
        *base_cmd,
        stdin=asyncio.subprocess.PIPE if stdin_data is not None else None,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )

    stderr_task = asyncio.create_task(proc.stderr.read())
    chunks: list[bytes] = []
    total_bytes = 0
    truncated = False

    try:
        async with asyncio.timeout(timeout_s):
            if stdin_data is not None:
                proc.stdin.write(stdin_data)
                await proc.stdin.drain()
                proc.stdin.close()
            async for line in proc.stdout:
                chunks.append(line)
                total_bytes += len(line)
                if ctx is not None:
                    await ctx.report_progress(
                        float(total_bytes),
                        total=None,
                        message=line.decode(errors="replace").rstrip(),
                    )
                if total_bytes > max_bytes:
                    truncated = True
                    await proc.stdout.read(-1)  # drain and discard remainder to prevent pipe deadlock
                    break
            stderr_bytes = await stderr_task
            await proc.wait()
    except asyncio.TimeoutError:
        proc.kill()
        raise CLIRuntimeError(f"Command timed out after {timeout_s}s")

    out = b"".join(chunks).decode(errors="replace")
    if truncated:
        out = out.encode()[:max_bytes].decode(errors="replace") + "\n[truncated]"

    rc = proc.returncode
    if rc != 0:
        raise CLIRuntimeError(
            msg=f"exit code {rc}: {stderr_bytes.decode(errors='replace')[:2000]}",
            exit_code=rc,
            stdout=out,
        )
    return out
