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


# -----------------------------
# Pydantic schema for `mayhem run`
# -----------------------------
class MayhemRunArgs(BaseModel):
    package: str = Field(..., description="positional: path to the directory containing the packaged target (or a Docker image tag/hash if `docker` is set)")

    # Analysis selection
    regression: bool = Field(False, description="--regression: run regression tests on available test cases")
    static: bool = Field(False, description="--static: run static checks on the entrypoint of the target")
    dynamic: bool = Field(False, description="--dynamic: run dynamic analysis on the target")
    coverage: bool = Field(False, description="--coverage: perform coverage analysis on the target")
    all: bool = Field(False, description="--all: enable all supported analyses")

    file: Optional[str] = Field(None, description="-f/--file <path>: path to the Mayhemfile used (default: <package>/Mayhemfile)")
    build_id: Optional[str] = Field(None, description="-b/--build-id <id>: build id to associate with this specific run")
    docker: bool = Field(False, description="--docker: indicates the `package` argument is a Docker image tag/hash rather than a packaged directory")
    warning_as_error: bool = Field(False, description="--warning-as-error: have the warnings be treated as errors")
    testsuite: Optional[str] = Field(None, description="--testsuite <dir>: specify a tests directory")
    ci_url: Optional[str] = Field(None, description="--ci-url <url>: URL to the Continuous Integration build you wish to associate with this run")

    # SCM metadata (canonical spelling chosen; each flag also accepts an --scm-* alias not exposed here)
    merge_base_branch_name: Optional[str] = Field(None, description="--merge-base-branch-name <name>: the destination branch of a changeset (e.g. the destination branch in a GitHub PR or GitLab MR)")
    branch_name: Optional[str] = Field(None, description="--branch-name <name>: the source control branch for the code under test")
    revision: Optional[str] = Field(None, description="--revision <sha>: the source control commit hash for the current code under test")
    parent_revision: Optional[str] = Field(None, description="--parent-revision <sha>: the source control parent commit hash on the current branch (or on a different branch if the current branch has no run history yet)")
    scm_remote: Optional[str] = Field(None, description="--scm-remote <url>: the source control remote origin for the current code under test (e.g. git@github.com:cli/cli.git)")

    # Target definition (mirrors MayhemInitArgs)
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

    # Connection
    url: Optional[str] = Field(None, description="--url <url>: URL to running Mayhem API")
    token: Optional[str] = Field(None, description="--token <token>: the Mayhem PLATFORM login token - this is a platform secret, not a target-under-test credential like basic/header/cookie auth used by other tools in this codebase")
    insecure: bool = Field(False, description="-k/--insecure: disable SSL verification")
    cacert: Optional[str] = Field(None, description="--cacert <path>: path to the mayhem server's certificate")
    timeout: Optional[int] = Field(None, description="--timeout <seconds>: seconds to wait for API responses (useful for slow connections)")


# -----------------------------
# MCP tool for `mayhem run`
# -----------------------------
@mcp.tool(
    description="""
    Run `mayhem run` to run a target through Mayhem (regression/static/dynamic/coverage analysis).
    `package` is a path to a packaged target directory, or a Docker image tag/hash if `docker` is set.
    Use `mayhem_wait` afterward to block for completion and retrieve results.
    """
)
async def mayhem_run(args: MayhemRunArgs, ctx: Context | None = None) -> str:
    cmd: list[str] = [MAYHEM_BIN, "run"]

    _add_flag(cmd, args.regression, "--regression")
    _add_flag(cmd, args.static, "--static")
    _add_flag(cmd, args.dynamic, "--dynamic")
    _add_flag(cmd, args.coverage, "--coverage")
    _add_flag(cmd, args.all, "--all")

    _add_opt(cmd, "--file", args.file)
    _add_opt(cmd, "--build-id", args.build_id)
    _add_flag(cmd, args.docker, "--docker")
    _add_flag(cmd, args.warning_as_error, "--warning-as-error")
    _add_opt(cmd, "--testsuite", args.testsuite)
    _add_opt(cmd, "--ci-url", args.ci_url)

    _add_opt(cmd, "--merge-base-branch-name", args.merge_base_branch_name)
    _add_opt(cmd, "--branch-name", args.branch_name)
    _add_opt(cmd, "--revision", args.revision)
    _add_opt(cmd, "--parent-revision", args.parent_revision)
    _add_opt(cmd, "--scm-remote", args.scm_remote)

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


# -----------------------------
# Pydantic schema for `mayhem wait`
# -----------------------------
class MayhemWaitArgs(BaseModel):
    run: str = Field(..., description="positional: run to wait for, in '[owner/]project/target/run_number' format")

    verbose: bool = Field(False, description="-v/--verbose: print status information while waiting")
    regression: bool = Field(False, description="--regression: wait on regression tests")
    static: bool = Field(False, description="--static: wait on static analysis")
    dynamic: bool = Field(False, description="--dynamic: wait on dynamic analysis")
    coverage: bool = Field(False, description="--coverage: perform coverage analysis on the target")
    all: bool = Field(False, description="--all: wait for all analyses")
    junit: Optional[str] = Field(None, description="--junit <path>: generate junit XML report and write to the specified file")
    sarif: Optional[str] = Field(None, description="--sarif <path>: generate SARIF JSON report and write to the specified file")
    fail_on_defects: bool = Field(False, description="--fail-on-defects: exit with non-zero exit code if defect(s) are present. When set, `mayhem_wait` treats a resulting exit code of 1 as a normal 'defects present' result rather than an error - it does not raise.")
    disable_github_report_comment: bool = Field(False, description="--disable-github-report-comment: disables the creation or update of a report on a GitHub pull request")
    github_token: Optional[str] = Field(None, description="--github-token <token>: a GitHub bearer token, used with github_repository/github_run_id to authenticate inside mcode-action GitHub Action runs - this is a platform secret (GitHub API token), not a target-under-test credential, and is redacted the same way as the Mayhem token")
    github_repository: Optional[str] = Field(None, description="--github-repository <owner>/<repo>: e.g. 'foo/bar' or 'aws/aws-cli'")
    github_run_id: Optional[str] = Field(None, description="--github-run-id <id>: the run ID from a GitHub Action run")
    github_issue_id: Optional[str] = Field(None, description="--github-issue-id <id>: the issue ID from a GitHub repo issue - if present along with github_run_id/github_repository/github_token, a comment is automatically posted to the issue (a GitHub PR is also an issue)")
    github_api_url: Optional[str] = Field(None, description="--github-api-url <url>: GitHub API URL used to upload results")
    owner: Optional[str] = Field(None, description="--owner <owner>: filter to only show results for the provided owner (user or organization)")

    url: Optional[str] = Field(None, description="--url <url>: URL to running Mayhem API")
    token: Optional[str] = Field(None, description="--token <token>: the Mayhem PLATFORM login token - this is a platform secret, not a target-under-test credential like basic/header/cookie auth used by other tools in this codebase")
    insecure: bool = Field(False, description="-k/--insecure: disable SSL verification")
    cacert: Optional[str] = Field(None, description="--cacert <path>: path to the mayhem server's certificate")
    timeout: Optional[int] = Field(None, description="--timeout <seconds>: seconds to wait for API responses (useful for slow connections)")

    poll_timeout_s: int = Field(1800, description="How long, in seconds, this call is allowed to block waiting for the run to finish before giving up locally (independent of the platform's own run duration) — defaults to 30 minutes. Raise this if the run's configured --duration is expected to exceed it.")


# -----------------------------
# MCP tool for `mayhem wait`
# -----------------------------
@mcp.tool(
    description="""
    Run `mayhem wait` to block until a Mayhem run finishes, then return its results.
    When `fail_on_defects` is set, a run that completes with defects present is still
    a normal (non-error) result from this tool's perspective - it is returned, not raised.
    """
)
async def mayhem_wait(args: MayhemWaitArgs, ctx: Context | None = None) -> str:
    cmd: list[str] = [MAYHEM_BIN, "wait"]

    _add_flag(cmd, args.verbose, "--verbose")
    _add_flag(cmd, args.regression, "--regression")
    _add_flag(cmd, args.static, "--static")
    _add_flag(cmd, args.dynamic, "--dynamic")
    _add_flag(cmd, args.coverage, "--coverage")
    _add_flag(cmd, args.all, "--all")
    _add_opt(cmd, "--junit", args.junit)
    _add_opt(cmd, "--sarif", args.sarif)
    _add_flag(cmd, args.fail_on_defects, "--fail-on-defects")
    _add_flag(cmd, args.disable_github_report_comment, "--disable-github-report-comment")
    _add_opt(cmd, "--github-token", args.github_token)
    _add_opt(cmd, "--github-repository", args.github_repository)
    _add_opt(cmd, "--github-run-id", args.github_run_id)
    _add_opt(cmd, "--github-issue-id", args.github_issue_id)
    _add_opt(cmd, "--github-api-url", args.github_api_url)
    _add_opt(cmd, "--owner", args.owner)

    _add_opt(cmd, "--url", args.url)
    _add_opt(cmd, "--token", args.token)
    _add_flag(cmd, args.insecure, "--insecure")
    _add_opt(cmd, "--cacert", args.cacert)
    _add_opt(cmd, "--timeout", args.timeout)

    cmd.append(args.run)

    cmd_str = "$ " + shlex.join(_redact_cmd(cmd))
    log.info("Running: %s", cmd_str[2:])
    try:
        out = await run_cli(cmd, ctx=ctx, timeout_s=args.poll_timeout_s)
        return f"{cmd_str}\n\n{out}"
    except CLIRuntimeError as e:
        if args.fail_on_defects and e.exit_code == 1:
            return f"{cmd_str}\n\n{e.stdout}"
        raise RuntimeError(f"{cmd_str}\n\n{e}") from None


# -----------------------------
# Pydantic schema for `mayhem show`
# -----------------------------
class MayhemShowArgs(BaseModel):
    run: Optional[str] = Field(None, description="positional: run specifier in [<owner>/]<project>/<target>/<run> format. Omit to show all runs for the connected user.")
    status: Optional[str] = Field(None, description="--status <regex>: filter runs based on status as a regular expression (default: '.*')")
    format: Optional[Literal["pretty", "json", "csv"]] = Field(None, description="--format <choice>: format for returned results")
    owner: Optional[str] = Field(None, description="--owner <owner>: filter to only show results for the provided owner (user or organization)")

    url: Optional[str] = Field(None, description="--url <url>: URL to running Mayhem API")
    token: Optional[str] = Field(None, description="--token <token>: the Mayhem PLATFORM login token - this is a platform secret, not a target-under-test credential like basic/header/cookie auth used by other tools in this codebase")
    insecure: bool = Field(False, description="-k/--insecure: disable SSL verification")
    cacert: Optional[str] = Field(None, description="--cacert <path>: path to the mayhem server's certificate")
    timeout: Optional[int] = Field(None, description="--timeout <seconds>: seconds to wait for API responses (useful for slow connections)")


# -----------------------------
# MCP tool for `mayhem show`
# -----------------------------
@mcp.tool(
    description="Run `mayhem show` to show one or more Mayhem runs. Omit `run` to show all runs for the connected user."
)
async def mayhem_show(args: MayhemShowArgs, ctx: Context | None = None) -> str:
    cmd: list[str] = [MAYHEM_BIN, "show"]

    _add_opt(cmd, "--status", args.status)
    _add_opt(cmd, "--format", args.format)
    _add_opt(cmd, "--owner", args.owner)

    _add_opt(cmd, "--url", args.url)
    _add_opt(cmd, "--token", args.token)
    _add_flag(cmd, args.insecure, "--insecure")
    _add_opt(cmd, "--cacert", args.cacert)
    _add_opt(cmd, "--timeout", args.timeout)

    if args.run:
        cmd.append(args.run)

    cmd_str = "$ " + shlex.join(_redact_cmd(cmd))
    log.info("Running: %s", cmd_str[2:])
    try:
        out = await run_cli(cmd, ctx=ctx)
        return f"{cmd_str}\n\n{out}"
    except CLIRuntimeError as e:
        raise RuntimeError(f"{cmd_str}\n\n{e}") from None


# -----------------------------
# Pydantic schema for `mayhem stop`
# -----------------------------
class MayhemStopArgs(BaseModel):
    run_path: str = Field(..., description="positional: name of the run in [<owner>/]<project>/<target>/<run_number> format. To stop ALL runs for a target, omit <run_number> (e.g. 'my-project/target'). To stop runs for all targets, omit both <run_number> AND <target> (e.g. 'my-project').")
    owner: Optional[str] = Field(None, description="--owner <owner>: filter to only show results for the provided owner (user or organization)")

    url: Optional[str] = Field(None, description="--url <url>: URL to running Mayhem API")
    token: Optional[str] = Field(None, description="--token <token>: the Mayhem PLATFORM login token - this is a platform secret, not a target-under-test credential like basic/header/cookie auth used by other tools in this codebase")
    insecure: bool = Field(False, description="-k/--insecure: disable SSL verification")
    cacert: Optional[str] = Field(None, description="--cacert <path>: path to the mayhem server's certificate")
    timeout: Optional[int] = Field(None, description="--timeout <seconds>: seconds to wait for API responses (useful for slow connections)")


# -----------------------------
# MCP tool for `mayhem stop`
# -----------------------------
@mcp.tool(
    description="Run `mayhem stop` to stop a running Mayhem run (or all runs for a target/project, per `run_path`)."
)
async def mayhem_stop(args: MayhemStopArgs, ctx: Context | None = None) -> str:
    cmd: list[str] = [MAYHEM_BIN, "stop"]

    _add_opt(cmd, "--owner", args.owner)

    _add_opt(cmd, "--url", args.url)
    _add_opt(cmd, "--token", args.token)
    _add_flag(cmd, args.insecure, "--insecure")
    _add_opt(cmd, "--cacert", args.cacert)
    _add_opt(cmd, "--timeout", args.timeout)

    cmd.append(args.run_path)

    cmd_str = "$ " + shlex.join(_redact_cmd(cmd))
    log.info("Running: %s", cmd_str[2:])
    try:
        out = await run_cli(cmd, ctx=ctx)
        return f"{cmd_str}\n\n{out}"
    except CLIRuntimeError as e:
        raise RuntimeError(f"{cmd_str}\n\n{e}") from None


# -----------------------------
# Pydantic schema for `mayhem list`
# -----------------------------
class MayhemListArgs(BaseModel):
    owner: Optional[str] = Field(None, description="--owner <owner>: filter to only show results for the provided owner (user or organization)")

    url: Optional[str] = Field(None, description="--url <url>: URL to running Mayhem API")
    token: Optional[str] = Field(None, description="--token <token>: the Mayhem PLATFORM login token - this is a platform secret, not a target-under-test credential like basic/header/cookie auth used by other tools in this codebase")
    insecure: bool = Field(False, description="-k/--insecure: disable SSL verification")
    cacert: Optional[str] = Field(None, description="--cacert <path>: path to the mayhem server's certificate")
    timeout: Optional[int] = Field(None, description="--timeout <seconds>: seconds to wait for API responses (useful for slow connections)")


# -----------------------------
# MCP tool for `mayhem list`
# -----------------------------
@mcp.tool(
    description="Run `mayhem list` to list the projects and targets you have run."
)
async def mayhem_list(args: MayhemListArgs, ctx: Context | None = None) -> str:
    cmd: list[str] = [MAYHEM_BIN, "list"]

    _add_opt(cmd, "--owner", args.owner)
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
# Pydantic schema for `mayhem download`
# -----------------------------
class MayhemDownloadArgs(BaseModel):
    target: str = Field(..., description="positional: target to download, specified as <project>/<target>")
    output: Optional[str] = Field(None, description="-o/--output <dir>: output directory for the target")
    run_number: Optional[str] = Field(None, description="-r/--run_number <n>: specify exact run number to download from")
    owner: Optional[str] = Field(None, description="--owner <owner>: filter to only show results for the provided owner (user or organization)")

    url: Optional[str] = Field(None, description="--url <url>: URL to running Mayhem API")
    token: Optional[str] = Field(None, description="--token <token>: the Mayhem PLATFORM login token - this is a platform secret, not a target-under-test credential like basic/header/cookie auth used by other tools in this codebase")
    insecure: bool = Field(False, description="-k/--insecure: disable SSL verification")
    cacert: Optional[str] = Field(None, description="--cacert <path>: path to the mayhem server's certificate")
    timeout: Optional[int] = Field(None, description="--timeout <seconds>: seconds to wait for API responses (useful for slow connections)")


# -----------------------------
# MCP tool for `mayhem download`
# -----------------------------
@mcp.tool(
    description="Run `mayhem download` to download a target and its test cases."
)
async def mayhem_download(args: MayhemDownloadArgs, ctx: Context | None = None) -> str:
    cmd: list[str] = [MAYHEM_BIN, "download"]

    _add_opt(cmd, "--output", args.output)
    _add_opt(cmd, "--run_number", args.run_number)
    _add_opt(cmd, "--owner", args.owner)
    _add_opt(cmd, "--url", args.url)
    _add_opt(cmd, "--token", args.token)
    _add_flag(cmd, args.insecure, "--insecure")
    _add_opt(cmd, "--cacert", args.cacert)
    _add_opt(cmd, "--timeout", args.timeout)

    cmd.append(args.target)

    cmd_str = "$ " + shlex.join(_redact_cmd(cmd))
    log.info("Running: %s", cmd_str[2:])
    try:
        out = await run_cli(cmd, ctx=ctx)
        return f"{cmd_str}\n\n{out}"
    except CLIRuntimeError as e:
        raise RuntimeError(f"{cmd_str}\n\n{e}") from None


# -----------------------------
# Pydantic schema for `mayhem sync`
# -----------------------------
class MayhemSyncArgs(BaseModel):
    package: str = Field(..., description="positional: path to the package directory to sync")
    run_number: Optional[str] = Field(None, description="-r/--run_number <n>: specify exact run number to sync with")
    owner: Optional[str] = Field(None, description="--owner <owner>: filter to only show results for the provided owner (user or organization)")

    url: Optional[str] = Field(None, description="--url <url>: URL to running Mayhem API")
    token: Optional[str] = Field(None, description="--token <token>: the Mayhem PLATFORM login token - this is a platform secret, not a target-under-test credential like basic/header/cookie auth used by other tools in this codebase")
    insecure: bool = Field(False, description="-k/--insecure: disable SSL verification")
    cacert: Optional[str] = Field(None, description="--cacert <path>: path to the mayhem server's certificate")
    timeout: Optional[int] = Field(None, description="--timeout <seconds>: seconds to wait for API responses (useful for slow connections)")


# -----------------------------
# MCP tool for `mayhem sync`
# -----------------------------
@mcp.tool(
    description="""
    Run `mayhem sync` to sync a package to its latest state - retrieves the latest
    test cases from a target you have previously packaged and run.
    """
)
async def mayhem_sync(args: MayhemSyncArgs, ctx: Context | None = None) -> str:
    cmd: list[str] = [MAYHEM_BIN, "sync"]

    _add_opt(cmd, "--run_number", args.run_number)
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


# -----------------------------
# Pydantic schema for `mayhem check`
# -----------------------------
class MayhemCheckArgs(BaseModel):
    file: List[str] = Field(..., min_length=1, description="positional: one or more paths to local file(s) to check for Mayhem eligibility")
    format: Optional[Literal["pretty", "json"]] = Field(None, description="--format <choice>: format for returned results")


# -----------------------------
# MCP tool for `mayhem check`
# -----------------------------
@mcp.tool(
    description="Run `mayhem check` to check whether one or more local targets are Mayhem-eligible."
)
async def mayhem_check(args: MayhemCheckArgs, ctx: Context | None = None) -> str:
    cmd: list[str] = [MAYHEM_BIN, "check"]

    _add_opt(cmd, "--format", args.format)

    # `file` is a bare repeatable positional ("file [file ...]"), not a repeatable
    # `--flag value` pair like --env - _add_repeat would incorrectly interleave a
    # flag before each value, so the paths are appended directly instead.
    cmd.extend(args.file)

    cmd_str = "$ " + shlex.join(_redact_cmd(cmd))
    log.info("Running: %s", cmd_str[2:])
    try:
        out = await run_cli(cmd, ctx=ctx)
        return f"{cmd_str}\n\n{out}"
    except CLIRuntimeError as e:
        raise RuntimeError(f"{cmd_str}\n\n{e}") from None


# -----------------------------
# MCP tool for `mayhem docker-registry`
# -----------------------------
@mcp.tool(
    description="Run `mayhem docker-registry` to get the URI for Mayhem's Docker registry."
)
async def mayhem_docker_registry(ctx: Context | None = None) -> str:
    cmd: list[str] = [MAYHEM_BIN, "docker-registry"]

    cmd_str = "$ " + shlex.join(_redact_cmd(cmd))
    log.info("Running: %s", cmd_str[2:])
    try:
        out = await run_cli(cmd, ctx=ctx)
        return f"{cmd_str}\n\n{out}"
    except CLIRuntimeError as e:
        raise RuntimeError(f"{cmd_str}\n\n{e}") from None
