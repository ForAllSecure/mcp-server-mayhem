from __future__ import annotations
import shlex
from typing import List, Literal, Optional

from pydantic import BaseModel, Field, model_validator
from mcp.server.fastmcp import Context

from .cli_runner import run_cli, CLIRuntimeError
from .common import _add_flag, _add_opt, _add_repeat, _comma_join, _redact_cmd
from .server import mcp, MAYHEM_BIN, log


# -----------------------------
# Pydantic schema for `mayhem login`
# -----------------------------
class MayhemLoginArgs(BaseModel):
    url: str = Field(..., description="--url <url>: URL to running Mayhem API")
    token: str = Field(..., description="--token <token>: the Mayhem PLATFORM login token (persisted to ~/.config/mayhem and used to log into the Mayhem Docker registry) - this is a platform secret, not a target-under-test credential like basic/header/cookie auth used by other tools in this codebase")
    insecure: bool = Field(False, description="-k/--insecure: disable SSL verification")
    cacert: Optional[str] = Field(None, description="--cacert <path>: path to the mayhem server's certificate")
    timeout: Optional[int] = Field(None, description="--timeout <seconds>: seconds to wait for API responses (useful for slow connections)")


# -----------------------------
# MCP tool for `mayhem login`
# -----------------------------
@mcp.tool(
    description="""
    Run `mayhem login` to authenticate with a Mayhem server.
    This persists credentials to the ~/.config/mayhem XDG dir and also logs into
    the Mayhem Docker registry. Required before packaging or running targets
    against a Mayhem server that isn't already authenticated via MAYHEM_TOKEN.
    """
)
async def mayhem_login(args: MayhemLoginArgs, ctx: Context | None = None) -> str:
    cmd: list[str] = [MAYHEM_BIN, "login"]

    _add_opt(cmd, "--url", args.url)
    _add_opt(cmd, "--token", args.token)
    _add_flag(cmd, args.insecure, "--insecure")
    _add_opt(cmd, "--cacert", args.cacert)
    _add_opt(cmd, "--timeout", args.timeout)

    cmd_str = "$ " + shlex.join(_redact_cmd(cmd))
    log.info("Running: %s", cmd_str[2:])
    try:
        out = await run_cli(cmd, ctx=ctx)
        return f"{cmd_str}\n\n{out}"
    except CLIRuntimeError as e:
        raise RuntimeError(f"{cmd_str}\n\n{e}") from None


# -----------------------------
# MCP tool for `mayhem logout`
# -----------------------------
@mcp.tool(
    description="Run `mayhem logout` to log out of the currently authenticated Mayhem server."
)
async def mayhem_logout(ctx: Context | None = None) -> str:
    cmd: list[str] = [MAYHEM_BIN, "logout"]

    cmd_str = "$ " + shlex.join(_redact_cmd(cmd))
    log.info("Running: %s", cmd_str[2:])
    try:
        out = await run_cli(cmd, ctx=ctx)
        return f"{cmd_str}\n\n{out}"
    except CLIRuntimeError as e:
        raise RuntimeError(f"{cmd_str}\n\n{e}") from None


# -----------------------------
# Pydantic schema for `mayhem init`
# -----------------------------
class MayhemInitArgs(BaseModel):
    # Positional (mutually exclusive)
    image_url: Optional[str] = Field(None, description="positional: Docker image tag or hash to generate a Mayhemfile for")
    template_name: Optional[str] = Field(None, description="positional: name of the target for the template generated code (used together with --template)")

    output: Optional[str] = Field(None, description="-o/--output <path>: file path of the generated Mayhemfile")
    template: Optional[Literal[
        "c-uninstrumented", "c-honggfuzz", "c-libfuzzer",
        "cpp-uninstrumented", "cpp-honggfuzz", "cpp-libfuzzer",
        "opensut",
    ]] = Field(None, description="--template <choice>: language to generate template code for; requires template_name as well")
    project: Optional[str] = Field(None, description="--project <name>: name of the project")
    owner: Optional[str] = Field(None, description="--owner <owner>: the owner for this project")
    target: Optional[str] = Field(None, description="--target <name>: name of the target")
    image: Optional[str] = Field(None, description="--image <image>: Docker image you want to analyze")
    duration: Optional[int] = Field(None, description="--duration <seconds>: how long to run for in seconds (wall clock time)")
    uid: Optional[int] = Field(None, description="--uid <int>: user id for running the target")
    gid: Optional[int] = Field(None, description="--gid <int>: group id for running the target")
    advanced_triage: Optional[str] = Field(None, description="--advanced-triage <value>: set extra advanced triage analysis - increases the number of CWEs Mayhem finds but also increases test case processing time")
    cmd: Optional[str] = Field(None, description="--cmd <cmd>: command to invoke the target")
    cwd: Optional[str] = Field(None, description="--cwd <path>: current working directory for running the target")
    env: List[str] = Field(default_factory=list, description="--env KEY=VALUE: environment variable to include while running (repeatable)")
    filepath: Optional[str] = Field(None, description="--filepath <path>: input file path where the target reads from")
    network_url: Optional[str] = Field(None, description="--network-url <uri>: network URI where the target reads from")
    network_timeout: Optional[int] = Field(None, description="--network-timeout <seconds>: time for Mayhem to wait for the target to accept network input")
    network_client: Optional[str] = Field(None, description="--network-client <value>: whether this network target is a client or server")
    libfuzzer: Optional[str] = Field(None, description="--libfuzzer <value>: whether this is a libfuzzer target or not")
    honggfuzz: Optional[str] = Field(None, description="--honggfuzz <value>: whether this is a honggfuzz target or not")
    sanitizer: Optional[str] = Field(None, description="--sanitizer <value>: whether sanitization is compiled in or not")
    max_length: Optional[int] = Field(None, description="--max-length <int>: maximum length for test cases")
    memory_limit: Optional[int] = Field(None, description="--memory-limit <MB>: how much memory to allow the target in megabytes")

    @model_validator(mode="after")
    def _validate_positional(self):
        if self.image_url and self.template_name:
            raise ValueError("Choose at most one of: image_url, template_name")
        return self


# -----------------------------
# MCP tool for `mayhem init`
# -----------------------------
@mcp.tool(
    description="""
    Run `mayhem init` to generate a Mayhemfile.
    Provide either `image_url` (an existing Docker image to analyze) or
    `template_name` (with `template` set) to scaffold template code -
    these are mutually exclusive. A pre-packaged Docker image target is
    preferred when one already exists; use this together with `mayhem_package`
    for the fallback path of packaging a local, non-Docker target.
    """
)
async def mayhem_init(args: MayhemInitArgs, ctx: Context | None = None) -> str:
    cmd: list[str] = [MAYHEM_BIN, "init"]

    _add_opt(cmd, "--output", args.output)
    _add_opt(cmd, "--template", args.template)
    _add_opt(cmd, "--project", args.project)
    _add_opt(cmd, "--owner", args.owner)
    _add_opt(cmd, "--target", args.target)
    _add_opt(cmd, "--image", args.image)
    _add_opt(cmd, "--duration", args.duration)
    _add_opt(cmd, "--uid", args.uid)
    _add_opt(cmd, "--gid", args.gid)
    _add_opt(cmd, "--advanced-triage", args.advanced_triage)
    _add_opt(cmd, "--cmd", args.cmd)
    _add_opt(cmd, "--cwd", args.cwd)
    _add_repeat(cmd, "--env", args.env)
    _add_opt(cmd, "--filepath", args.filepath)
    _add_opt(cmd, "--network-url", args.network_url)
    _add_opt(cmd, "--network-timeout", args.network_timeout)
    _add_opt(cmd, "--network-client", args.network_client)
    _add_opt(cmd, "--libfuzzer", args.libfuzzer)
    _add_opt(cmd, "--honggfuzz", args.honggfuzz)
    _add_opt(cmd, "--sanitizer", args.sanitizer)
    _add_opt(cmd, "--max-length", args.max_length)
    _add_opt(cmd, "--memory-limit", args.memory_limit)

    if args.image_url:
        cmd.append(args.image_url)
    elif args.template_name:
        cmd.append(args.template_name)

    cmd_str = "$ " + shlex.join(_redact_cmd(cmd))
    log.info("Running: %s", cmd_str[2:])
    try:
        out = await run_cli(cmd, ctx=ctx)
        return f"{cmd_str}\n\n{out}"
    except CLIRuntimeError as e:
        raise RuntimeError(f"{cmd_str}\n\n{e}") from None


# -----------------------------
# Pydantic schema for `mayhem package`
# -----------------------------
class MayhemPackageArgs(BaseModel):
    binary: str = Field(..., description="positional: path to local target to package")
    output: Optional[str] = Field(None, description="-o/--output <dir>: output directory for the package")
    depdirs: List[str] = Field(default_factory=list, description="-d/--depdirs: comma-separated list of directories to search for dependencies")


# -----------------------------
# MCP tool for `mayhem package`
# -----------------------------
@mcp.tool(
    description="""
    Run `mayhem package` to package a local target binary and its dependencies for Mayhem.
    This and `mayhem_init` back the fallback path for targets that aren't already a Docker
    image - prefer a pre-packaged Docker image target over this when one already exists.
    """
)
async def mayhem_package(args: MayhemPackageArgs, ctx: Context | None = None) -> str:
    cmd: list[str] = [MAYHEM_BIN, "package"]

    _add_opt(cmd, "--output", args.output)
    if args.depdirs:
        _add_opt(cmd, "--depdirs", _comma_join(args.depdirs))

    cmd.append(args.binary)

    cmd_str = "$ " + shlex.join(_redact_cmd(cmd))
    log.info("Running: %s", cmd_str[2:])
    try:
        out = await run_cli(cmd, ctx=ctx)
        return f"{cmd_str}\n\n{out}"
    except CLIRuntimeError as e:
        raise RuntimeError(f"{cmd_str}\n\n{e}") from None


# -----------------------------
# Pydantic schema for `mayhem validate`
# -----------------------------
class MayhemValidateArgs(BaseModel):
    package: str = Field(..., description="positional: path to the directory containing the packaged target")
    file: Optional[str] = Field(None, description="-f/--file <path>: path to the Mayhemfile used (default: <package>/Mayhemfile)")
    no_docker: bool = Field(False, description="--no-docker: skip intrusive validation tests that require docker")
    owner: Optional[str] = Field(None, description="--owner <owner>: filter to only show results for the provided owner (user or organization)")

    url: Optional[str] = Field(None, description="--url <url>: URL to running Mayhem API")
    token: Optional[str] = Field(None, description="--token <token>: the Mayhem PLATFORM login token - this is a platform secret, not a target-under-test credential like basic/header/cookie auth used by other tools in this codebase")
    insecure: bool = Field(False, description="-k/--insecure: disable SSL verification")
    cacert: Optional[str] = Field(None, description="--cacert <path>: path to the mayhem server's certificate")
    timeout: Optional[int] = Field(None, description="--timeout <seconds>: seconds to wait for API responses (useful for slow connections)")


# -----------------------------
# MCP tool for `mayhem validate`
# -----------------------------
@mcp.tool(
    description="Run `mayhem validate` to validate a packaged target's Mayhemfile."
)
async def mayhem_validate(args: MayhemValidateArgs, ctx: Context | None = None) -> str:
    cmd: list[str] = [MAYHEM_BIN, "validate"]

    _add_opt(cmd, "--file", args.file)
    _add_flag(cmd, args.no_docker, "--no-docker")
    _add_opt(cmd, "--owner", args.owner)
    _add_opt(cmd, "--url", args.url)
    _add_opt(cmd, "--token", args.token)
    _add_flag(cmd, args.insecure, "--insecure")
    _add_opt(cmd, "--cacert", args.cacert)
    _add_opt(cmd, "--timeout", args.timeout)

    cmd.append(args.package)

    cmd_str = "$ " + shlex.join(_redact_cmd(cmd))
    log.info("Running: %s", cmd_str[2:])
    try:
        out = await run_cli(cmd, ctx=ctx)
        return f"{cmd_str}\n\n{out}"
    except CLIRuntimeError as e:
        raise RuntimeError(f"{cmd_str}\n\n{e}") from None
