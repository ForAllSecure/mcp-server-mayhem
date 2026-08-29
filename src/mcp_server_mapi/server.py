from __future__ import annotations
from pathlib import Path
import asyncio
import os
import sys
import logging

from mcp.server.fastmcp import FastMCP

# --- Logging: IMPORTANT ---
# Never write to stdout on stdio servers (keeps JSON-RPC clean).
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("mcp_server_mapi")

from .cli_runner import run_cli
from .common import _assert_under_cwd, _load_prompt_template, _render

MAPI_BIN = os.environ.get("MAPI_BIN", "/usr/local/bin/mapi")  # override in env if needed
MAYHEM_BIN = os.environ.get("MAYHEM_BIN", "/usr/local/bin/mayhem")  # override in env if needed
mcp = FastMCP("MAPI Server")


@mcp.tool(
    description=(
        "Read a file from the server's working directory. "
        "NOTE: when mcp-server-mapi runs inside a Docker container this tool reads from the "
        "container filesystem — it cannot access the user's local machine. "
        "For local source files, prefer the LLM's built-in file reading capability. "
        "This tool is most useful when the server runs locally via `uv run`."
    )
)
def read_file(
    file_path: str, line_start: int | None = None, line_end: int | None = None
) -> str:
    """Read contents of a file, optionally specifying line range.

    Args:
        file_path: Path to the file to read
        line_start: Starting line number (1-based, optional)
        line_end: Ending line number (1-based, optional)
    """
    try:
        try:
            path = _assert_under_cwd(Path(file_path))
        except PermissionError as e:
            return f"Error: {e}"
        if not path.exists():
            return f"Error: File not found at {file_path}"

        if not path.is_file():
            return f"Error: {file_path} is not a file"

        content = path.read_text()

        if line_start is not None or line_end is not None:
            lines = content.splitlines()
            start_idx = (line_start - 1) if line_start else 0
            end_idx = line_end if line_end else len(lines)

            if start_idx < 0 or start_idx >= len(lines):
                return f"Error: Starting line {line_start} is out of range (file has {len(lines)} lines)"

            if end_idx < start_idx:
                return f"Error: End line {line_end} cannot be before start line {line_start}"

            selected_lines = lines[start_idx:end_idx]
            return "\n".join(
                f"{i + start_idx + 1:4d}→{line}"
                for i, line in enumerate(selected_lines)
            )

        # Return full file with line numbers
        lines = content.splitlines()
        return "\n".join(f"{i + 1:4d}→{line}" for i, line in enumerate(lines))

    except Exception as e:
        return f"Error reading file: {str(e)}"


@mcp.tool(description="Edit a file on the MAPI server host with find-and-replace operations.")
def edit_file(
    file_path: str, old_text: str, new_text: str, replace_all: bool = False
) -> str:
    """Edit a file with find-and-replace operations.

    IMPORTANT: You should read the file first using read_file() before editing
    to understand the context and ensure the old_text exists.

    Args:
        file_path: Path to the file to edit
        old_text: Text to find and replace (must match exactly including whitespace)
        new_text: Text to replace with
        replace_all: If True, replace all occurrences; if False, replace only first occurrence
    """
    try:
        try:
            path = _assert_under_cwd(Path(file_path))
        except PermissionError as e:
            return f"Error: {e}"
        if not path.exists():
            return f"Error: File not found at {file_path}"

        if not path.is_file():
            return f"Error: {file_path} is not a file"

        # Read current content
        content = path.read_text()

        # Check if old_text exists
        if old_text not in content:
            return f"Error: Text to replace not found in {file_path}. Please read the file first to verify the exact text to replace."

        # Count occurrences for informative output
        occurrence_count = content.count(old_text)

        # Perform replacement
        if replace_all:
            new_content = content.replace(old_text, new_text)
            replaced_count = occurrence_count
        else:
            new_content = content.replace(old_text, new_text, 1)
            replaced_count = 1

        # Validate that content actually changed
        if new_content == content:
            return f"Warning: No changes made to {file_path} (old_text and new_text are identical)"

        # Write the updated content
        path.write_text(new_content)

        return f"Successfully replaced {replaced_count} occurrence(s) of text in {file_path} (found {occurrence_count} total occurrences)"

    except Exception as e:
        return f"Error editing file: {str(e)}"


# -----------------------------
# MCP prompt: onboard-mapi-scan
# -----------------------------
@mcp.prompt(
    name="onboard-mapi-scan",
    description="Orchestrate the mapi onboarding and tune loop: walk through setup, run a scan, evaluate quality, suggest tuning changes, and emit a final leave-behind scan script.",
)
async def onboard_mapi_scan(
    workspace: str,
    project: str,
    specification: str,
    url: str,
    target_name: str = "",
    duration: str = "30s",
    max_iterations: int = 3,
    min_covered_pct: int = 25,
) -> str:
    api_target = f"{workspace}/{project}/{target_name}" if target_name else f"{workspace}/{project}"
    har_path = f"/tmp/mapi-onboard-{workspace}-{project}.har"
    return _render(
        _load_prompt_template("onboard_mapi_scan.md"),
        workspace=workspace,
        project=project,
        target_name=target_name if target_name else "(none)",
        api_target=api_target,
        specification=specification,
        url=url,
        duration=duration,
        max_iterations=str(max_iterations),
        min_covered_pct=str(min_covered_pct),
        har_path=har_path,
    )


# -----------------------------
# MCP prompt: generate-exploit
# -----------------------------
@mcp.prompt(
    name="generate-exploit",
    description="Generate exploit suggestions for defects found by a mapi run. For each defect, confirms reproduction, crafts a targeted HTTP request the user can run to demonstrate impact, and emits a leave-behind markdown report.",
)
async def generate_exploit(
    run_id: str,
    url: str,
    specification: str = "",
    source_dir: str = "",
    output_path: str = "exploit-report.md",
) -> str:
    return _render(
        _load_prompt_template("generate_exploit.md"),
        run_id=run_id,
        url=url,
        specification=specification if specification else "(none)",
        source_dir=source_dir if source_dir else "(none)",
        output_path=output_path,
    )


# -----------------------------
# MCP prompt: onboard-mayhem-run
# -----------------------------
@mcp.prompt(
    name="onboard-mayhem-run",
    description="Orchestrate a simplified mayhem onboarding flow: verify login, diagnose target packaging state (Docker image ready / local binary / not yet built), package and validate if needed, run the target, and monitor for completion. No tuning loop or exploit-generation step.",
)
async def onboard_mayhem_run(
    url: str,
    project: str = "",
    target: str = "",
    owner: str = "",
) -> str:
    return _render(
        _load_prompt_template("onboard_mayhem_run.md"),
        url=url,
        project=project if project else "(none)",
        target=target if target else "(none)",
        owner=owner if owner else "(none)",
    )


async def version() -> str:
    try:
        out = await run_cli([MAPI_BIN, "--version"], timeout_s=10.0, max_bytes=32_000)
    except Exception as e:
        out = f"(error retrieving version) {e}"
    return f"server=MAPI Server; mapi_bin={MAPI_BIN}; mapi_version={out.strip()}"


# Import for @mcp.tool/@mcp.prompt registration side effects (fires the decorators when this module loads).
from . import mapi_tools  # noqa: F401
from . import mayhem_tools  # noqa: F401


def main():
    if os.environ.get("MAYHEM_TOKEN") is None:
        log.error("MAYHEM_TOKEN not set; cannot start MAPI server")
        sys.exit(1)
    log.info("Starting MAPI Server on stdio...")
    mcp.run(transport="stdio")
