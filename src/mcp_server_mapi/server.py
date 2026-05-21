from __future__ import annotations
from pathlib import Path
import asyncio
import json
import os
import re
import sys
import logging
from typing import Literal, List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, model_validator, field_validator
from mcp.server.fastmcp import FastMCP, Context

# --- Logging: IMPORTANT ---
# Never write to stdout on stdio servers (keeps JSON-RPC clean).
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("mcp_server_mapi")

from .cli_runner import run_cli, CLIRuntimeError

MAPI_BIN = os.environ.get("MAPI_BIN", "/usr/local/bin/mapi")  # override in env if needed
mcp = FastMCP("MAPI Server")


# -----------------------------
# Pydantic schema for `mapi discover`
# -----------------------------
class DiscoverArgs(BaseModel):
    # FLAGS
    verify_tls: bool = Field(False, description="--verify-tls")
    disable_oauth2: bool = Field(False, description="--disable-oauth2")
    disable_auth_mutations: bool = Field(False, description="--disable-auth-mutations")
    no_builtin_endpoints: bool = Field(False, description="--no-builtin-endpoints")

    # OPTIONS (single)
    url: Optional[str] = Field(None, description="--url <parsed-url>")
    cacert: Optional[str] = Field(None, description="--cacert <ca-cert>")
    cert: Optional[str] = Field(None, description="--cert <cert>")
    key: Optional[str] = Field(None, description="--key <key>")
    p12cert: Optional[str] = Field(None, description="--p12cert <p12cert>")
    p12password: Optional[str] = Field(None, description="--p12password <p12password>")

    basic_auth: Optional[str] = Field(None, description='--basic-auth "username:password"')
    endpoints_file: Optional[str] = Field(None, description="--endpoints-file <file>")
    output_dir: str = Field("api-specs", description="--output <output-dir> (default api-specs)")
    request_timeout: str = Field("5 seconds", description='--request-timeout (e.g., "1m42s", "5s") - only required for very slow hosts')
    rate_limit: int = Field(1000, ge=1, description="--rate-limit <int> (default 1000)")

    # OPTIONS (repeatable)
    header: List[str] = Field(default_factory=list, description='-H/--header "k:v" (repeatable)')
    cookie_auth: List[str] = Field(default_factory=list, description='--cookie-auth "k=v"...')
    header_auth: List[str] = Field(default_factory=list, description='--header-auth "k:v"...')
    query_auth: List[str] = Field(default_factory=list, description='--query-auth "k:v"...')
    redact_header: List[str] = Field(default_factory=list, description='--redact-header "name"...')

    # Target selection (mutually exclusive)
    hosts: Optional[List[str]] = Field(None, description='-h/--hosts "host1,host2" (best option to start with, just make sure to *NOT* include schemes/ports/paths when specifying the option, e.g., if the URL is https://localhost the host is just "localhost")')
    cidrs: Optional[List[str]] = Field(None, description='--cidrs "10.0.0.0/24,10.0.1.0/24"')
    domains: Optional[List[str]] = Field(None, description='--domains "example.com,foo.com"')

    # Network tuning (comma-separated in CLI; model as lists)
    ports: List[int] = Field(default_factory=lambda: [80, 443], description="--ports 80,443")
    schemes: List[Literal["http", "https"]] = Field(default_factory=lambda: ["http", "https"],
                                                    description="--schemes http,https")

    # OAuth2 (optional; many fields)
    oauth2_client_data: Optional[str] = Field(None, description='--oauth2-client-data "id:secret"')
    oauth2_credentials: Optional[str] = Field(None, description='--oauth2-credentials "user:pass"')

    oauth2_auth_code_auth_url: Optional[str] = None
    oauth2_auth_code_token_url: Optional[str] = None
    oauth2_auth_code_refresh_url: Optional[str] = None
    oauth2_auth_code_scopes: List[str] = Field(default_factory=list)

    oauth2_implicit_auth_url: Optional[str] = None
    oauth2_implicit_refresh_url: Optional[str] = None
    oauth2_implicit_scopes: List[str] = Field(default_factory=list)

    oauth2_cc_token_url: Optional[str] = None
    oauth2_cc_refresh_url: Optional[str] = None
    oauth2_cc_scopes: List[str] = Field(default_factory=list)

    oauth2_password_token_url: Optional[str] = None
    oauth2_password_refresh_url: Optional[str] = None
    oauth2_password_scopes: List[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _validate_targets(self):
        # hosts vs cidrs vs domains are mutually exclusive (but all optional)
        groups = [bool(self.hosts), bool(self.cidrs), bool(self.domains)]
        if sum(groups) > 1:
            raise ValueError("Choose at most one of: hosts, cidrs, domains")
        return self


def _add_flag(argv: list[str], cond: bool, flag: str):
    if cond:
        argv.append(flag)


def _add_opt(argv: list[str], flag: str, val: Optional[str | int]):
    if val is None:
        return
    argv += [flag, str(val)]


def _add_repeat(argv: list[str], flag: str, values: List[str | int]):
    for v in values:
        argv += [flag, str(v)]


def _comma_join(values: List[str | int]) -> str:
    return ",".join(str(v) for v in values)


_DURATION_RE = re.compile(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$")


def parse_duration(raw: str) -> float:
    """Parse a human duration string like '30s', '2h20m', '1m42s' into seconds."""
    m = _DURATION_RE.match(raw.strip())
    if not m or not any(m.groups()):
        raise ValueError(f"Cannot parse duration: {raw!r}")
    h, mn, s = (int(g) if g else 0 for g in m.groups())
    return h * 3600.0 + mn * 60.0 + s


# -----------------------------
# MCP tool for `mapi discover`
# -----------------------------
@mcp.tool(
    description="""
    Run `mapi discover` with the provided options.
    Use `mapi discover` to discover API specifications that you
    can scan later on with `mapi run`.

    Recommended first step is to provide `--hosts` with a comma-separated
    list of hostnames or IPs to scan along with `--ports` for a comma-separated
    list of ports (e.g., `80,443`).

    """
)
async def mapi_discover(args: DiscoverArgs, ctx: Context | None = None) -> str:
    cmd: list[str] = [MAPI_BIN, "discover"]

    # FLAGS
    _add_flag(cmd, args.verify_tls, "--verify-tls")
    _add_flag(cmd, args.disable_oauth2, "--disable-oauth2")
    _add_flag(cmd, args.disable_auth_mutations, "--disable-auth-mutations")
    _add_flag(cmd, args.no_builtin_endpoints, "--no-builtin-endpoints")

    # SIMPLE OPTIONS
    _add_opt(cmd, "--url", args.url)
    _add_opt(cmd, "--cacert", args.cacert)
    _add_opt(cmd, "--cert", args.cert)
    _add_opt(cmd, "--key", args.key)
    _add_opt(cmd, "--p12cert", args.p12cert)
    _add_opt(cmd, "--p12password", args.p12password)
    _add_opt(cmd, "--basic-auth", args.basic_auth)
    _add_opt(cmd, "--endpoints-file", args.endpoints_file)
    _add_opt(cmd, "--output", args.output_dir)
    _add_opt(cmd, "--request-timeout", args.request_timeout)
    _add_opt(cmd, "--rate-limit", args.rate_limit)

    # REPEATABLES
    _add_repeat(cmd, "--header", args.header)
    _add_repeat(cmd, "--cookie-auth", args.cookie_auth)
    _add_repeat(cmd, "--header-auth", args.header_auth)
    _add_repeat(cmd, "--query-auth", args.query_auth)
    _add_repeat(cmd, "--redact-header", args.redact_header)

    # TARGET SELECTION (mutually exclusive)
    if args.hosts:
        _add_opt(cmd, "--hosts", _comma_join(args.hosts))
    if args.cidrs:
        _add_opt(cmd, "--cidrs", _comma_join(args.cidrs))
    if args.domains:
        _add_opt(cmd, "--domains", _comma_join(args.domains))

    # NETWORK
    if args.ports:
        _add_opt(cmd, "--ports", _comma_join(args.ports))
    if args.schemes:
        _add_opt(cmd, "--schemes", _comma_join(args.schemes))

    # OAUTH2 (Authorization Code)
    _add_opt(cmd, "--oauth2-client-data", args.oauth2_client_data)
    _add_opt(cmd, "--oauth2-credentials", args.oauth2_credentials)

    _add_opt(cmd, "--oauth2-authorization-code-auth-url", args.oauth2_auth_code_auth_url)
    _add_opt(cmd, "--oauth2-authorization-code-token-url", args.oauth2_auth_code_token_url)
    _add_opt(cmd, "--oauth2-authorization-code-refresh-url", args.oauth2_auth_code_refresh_url)
    _add_repeat(cmd, "--oauth2-authorization-code-scopes", args.oauth2_auth_code_scopes)

    # OAUTH2 (Implicit)
    _add_opt(cmd, "--oauth2-implicit-auth-url", args.oauth2_implicit_auth_url)
    _add_opt(cmd, "--oauth2-implicit-refresh-url", args.oauth2_implicit_refresh_url)
    _add_repeat(cmd, "--oauth2-implicit-scopes", args.oauth2_implicit_scopes)

    # OAUTH2 (Client Credentials)
    _add_opt(cmd, "--oauth2-client-credentials-token-url", args.oauth2_cc_token_url)
    _add_opt(cmd, "--oauth2-client-credentials-refresh-url", args.oauth2_cc_refresh_url)
    _add_repeat(cmd, "--oauth2-client-credentials-scopes", args.oauth2_cc_scopes)

    # OAUTH2 (Password)
    _add_opt(cmd, "--oauth2-password-token-url", args.oauth2_password_token_url)
    _add_opt(cmd, "--oauth2-password-refresh-url", args.oauth2_password_refresh_url)
    _add_repeat(cmd, "--oauth2-password-scopes", args.oauth2_password_scopes)

    # Run it
    log.info("Running: %s", " ".join(cmd))
    try:
        return await run_cli(cmd, timeout_s=600.0, ctx=ctx)
    except CLIRuntimeError as e:
        raise RuntimeError(str(e)) from None


# -----------------------------
# Pydantic schema for `mapi run`
# -----------------------------
class RunArgs(BaseModel):
    # --- required positional args ---
    api_target: str = Field(..., description="<api-target> (project/target name to push results to, e.g., 'projectname/targetname')")
    duration: str = Field(..., description="<duration> e.g., 'auto', '30s', '2h20m' - strongly recommend '30s' to get started")
    specification: str = Field(..., description="<specification> path to OpenAPI/Swagger/Postman/HAR file on disk")

    # --- flags ---
    verify_tls: bool = False
    skip_sanity_check_abort: bool = False
    no_replay: bool = False
    disable_oauth2: bool = False
    disable_auth_mutations: bool = False
    experimental_rules: bool = False
    no_auto_ignore_rules: bool = False
    warn_as_error: bool = Field(False, description="--warnaserror")
    interactive: bool = False
    disable_github_report_comment: bool = False
    skip_scm_detection: bool = False
    mutable_postman_variables: bool = False
    zap: bool = False
    local: bool = Field(False, description="--local (for local scans, requires enterprise plan)")

    # --- simple options ---
    url: str = Field(..., description="--url <parsed-url> (base URL for the API, e.g., https://localhost:8000)")
    min_request_count: Optional[int] = Field(None, ge=1)
    concurrency: Optional[int] = Field(None, ge=1)
    rate_limit: Optional[int] = Field(None, ge=1)
    max_memory_usage: Optional[str] = Field(None, description='e.g., "60%" or "6GB"')
    max_response_size: Optional[str] = Field(None, description='e.g., "100B", "500KB"')
    cacert: Optional[str] = None
    cert: Optional[str] = None
    key: Optional[str] = None
    previous_job: Optional[str] = None

    junit: Optional[str] = None
    html: Optional[str] = None
    sarif: Optional[str] = None

    config: Optional[str] = None
    har: Optional[str] = None
    github_api_url: Optional[str] = Field(None, description="--github-api-url <url> (typically not required to be set)")
    scm_remote: Optional[str] = None
    scm_branch: Optional[str] = None
    scm_parent_sha: Optional[str] = None
    scm_commit_sha: Optional[str] = None
    scm_tag: Optional[str] = None

    rewrite_plugin: Optional[str] = None
    classify_plugin: Optional[str] = None

    postman_api_key: Optional[str] = None
    postman_environment_id: Optional[str] = None
    postman_global_variables: Optional[str] = None

    zap_min_risk_code: Optional[int] = Field(None, ge=0, le=3)
    zap_import_json_results: Optional[str] = None
    zap_docker_tag: Optional[str] = Field(None, description="Docker image tag for ZAP (default: 'zaproxy/zap-stable:2.14.0')")

    upload_sample_requests_per_endpoint: Optional[int] = Field(None, ge=0)

    request_timeout: Optional[str] = Field("5 seconds")

    basic_auth: Optional[str] = None

    # --- repeatables ---
    header: List[str] = Field(default_factory=list)                # -H/--header
    cookie_auth: List[str] = Field(default_factory=list)           # --cookie-auth
    header_auth: List[str] = Field(default_factory=list)           # --header-auth
    query_auth: List[str] = Field(default_factory=list)            # --query-auth
    resource_hint: List[str] = Field(default_factory=list)         # --resource-hint
    include_endpoint: List[str] = Field(default_factory=list)      # --include-endpoint
    ignore_endpoint: List[str] = Field(default_factory=list)       # --ignore-endpoint
    include_endpoints_by_tag: List[str] = Field(default_factory=list)
    ignore_endpoints_by_tag: List[str] = Field(default_factory=list)
    include_rule: List[str] = Field(default_factory=list)          # --include-rule
    ignore_rule: List[str] = Field(default_factory=list)           # --ignore-rule
    redact_header: List[str] = Field(default_factory=list)         # --redact-header

    # --- OAuth2 family (mirrors discover) ---
    oauth2_client_data: Optional[str] = None
    oauth2_credentials: Optional[str] = None

    oauth2_auth_code_auth_url: Optional[str] = None
    oauth2_auth_code_token_url: Optional[str] = None
    oauth2_auth_code_refresh_url: Optional[str] = None
    oauth2_auth_code_scopes: List[str] = Field(default_factory=list)

    oauth2_implicit_auth_url: Optional[str] = None
    oauth2_implicit_refresh_url: Optional[str] = None
    oauth2_implicit_scopes: List[str] = Field(default_factory=list)

    oauth2_cc_token_url: Optional[str] = None
    oauth2_cc_refresh_url: Optional[str] = None
    oauth2_cc_scopes: List[str] = Field(default_factory=list)

    oauth2_password_token_url: Optional[str] = None
    oauth2_password_refresh_url: Optional[str] = None
    oauth2_password_scopes: List[str] = Field(default_factory=list)

    p12cert: Optional[str] = None
    p12password: Optional[str] = None

    process_timeout: Optional[float] = Field(None, ge=30, description="Maximum seconds to wait for the mapi process to complete (dynamically set from duration if not provided)")

    @field_validator("duration")
    @classmethod
    def _duration_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("duration must be non-empty (e.g., 'auto', '30s', '2h20m')")
        return v

    @model_validator(mode="after")
    def _set_timeout(self):
        if self.process_timeout is not None:
            return self
        if self.duration == "auto":
            self.process_timeout = 1800.0
        else:
            self.process_timeout = parse_duration(self.duration) + 30.0
        return self

# -----------------------------
# MCP tool for `mapi run`
# -----------------------------
@mcp.tool(
    description="""
    Run `mapi run` with the provided options.
    Use `mapi run` to scan an API specification and push results to
    the specified project/target. Make sure to run `mapi discover` first
    to generate or refine your API specifications that you scan.

    If you want to review findings after the scan, use the html/junit/sarif
    options to generate reports locally.

    A non-zero exit code from `mapi run` indicates that vulnerability findings were
    present - this is not necessarily an error condition (check the stderr output).
    Specifically the following mapping is true:
        // - 1: Mapi found issues for the target API
        // - 2: A mapi logic error happened (e.g: too many inconsecutive requests)
        // - 3: An actual error (not related to mapi happened)
    Read the output reports to understand what was found and compile a security
    report at the end.
    """
)
async def mapi_run(args: RunArgs, ctx: Context | None = None) -> str:
    cmd: list[str] = [MAPI_BIN, "run"]

    # first, the required positionals:
    cmd += [args.api_target, args.duration, args.specification]

    # flags
    _add_flag(cmd, args.verify_tls, "--verify-tls")
    _add_flag(cmd, args.skip_sanity_check_abort, "--skip-sanity-check-abort")
    _add_flag(cmd, args.no_replay, "--no-replay")
    _add_flag(cmd, args.disable_oauth2, "--disable-oauth2")
    _add_flag(cmd, args.disable_auth_mutations, "--disable-auth-mutations")
    _add_flag(cmd, args.experimental_rules, "--experimental-rules")
    _add_flag(cmd, args.no_auto_ignore_rules, "--no-auto-ignore-rules")
    _add_flag(cmd, args.warn_as_error, "--warnaserror")
    _add_flag(cmd, args.interactive, "--interactive")
    _add_flag(cmd, args.disable_github_report_comment, "--disable-github-report-comment")
    _add_flag(cmd, args.skip_scm_detection, "--skip-scm-detection")
    _add_flag(cmd, args.mutable_postman_variables, "--mutable-postman-variables")
    _add_flag(cmd, args.zap, "--zap")
    _add_flag(cmd, args.local, "--local")

    # options
    _add_opt(cmd, "--url", args.url)
    _add_opt(cmd, "--min-request-count", args.min_request_count)
    _add_opt(cmd, "--concurrency", args.concurrency)
    _add_opt(cmd, "--rate-limit", args.rate_limit)
    _add_opt(cmd, "--max-memory-usage", args.max_memory_usage)
    _add_opt(cmd, "--max-response-size", args.max_response_size)
    _add_opt(cmd, "--cacert", args.cacert)
    _add_opt(cmd, "--cert", args.cert)
    _add_opt(cmd, "--key", args.key)
    _add_opt(cmd, "--previous-job", args.previous_job)

    _add_opt(cmd, "--junit", args.junit)
    _add_opt(cmd, "--html", args.html)
    _add_opt(cmd, "--sarif", args.sarif)

    _add_opt(cmd, "--config", args.config)
    _add_opt(cmd, "--har", args.har)
    _add_opt(cmd, "--github-api-url", args.github_api_url)

    _add_opt(cmd, "--scm-remote", args.scm_remote)
    _add_opt(cmd, "--scm-branch", args.scm_branch)
    _add_opt(cmd, "--scm-parent-sha", args.scm_parent_sha)
    _add_opt(cmd, "--scm-commit-sha", args.scm_commit_sha)
    _add_opt(cmd, "--scm-tag", args.scm_tag)

    _add_opt(cmd, "--rewrite-plugin", args.rewrite_plugin)
    _add_opt(cmd, "--classify-plugin", args.classify_plugin)

    _add_opt(cmd, "--postman-api-key", args.postman_api_key)
    _add_opt(cmd, "--postman-environment-id", args.postman_environment_id)
    _add_opt(cmd, "--postman-global-variables", args.postman_global_variables)

    _add_opt(cmd, "--zap-min-risk-code", args.zap_min_risk_code)
    _add_opt(cmd, "--zap-import-json-results", args.zap_import_json_results)
    _add_opt(cmd, "--zap-docker-tag", args.zap_docker_tag)

    _add_opt(cmd, "--upload-sample-requests-per-endpoint", args.upload_sample_requests_per_endpoint)

    _add_opt(cmd, "--request-timeout", args.request_timeout)

    _add_opt(cmd, "--basic-auth", args.basic_auth)

    # repeatables
    _add_repeat(cmd, "--header", args.header)
    _add_repeat(cmd, "--cookie-auth", args.cookie_auth)
    _add_repeat(cmd, "--header-auth", args.header_auth)
    _add_repeat(cmd, "--query-auth", args.query_auth)
    _add_repeat(cmd, "--resource-hint", args.resource_hint)

    _add_repeat(cmd, "--include-endpoint", args.include_endpoint)
    _add_repeat(cmd, "--ignore-endpoint", args.ignore_endpoint)
    _add_repeat(cmd, "--include-endpoints-by-tag", args.include_endpoints_by_tag)
    _add_repeat(cmd, "--ignore-endpoints-by-tag", args.ignore_endpoints_by_tag)

    _add_repeat(cmd, "--include-rule", args.include_rule)
    _add_repeat(cmd, "--ignore-rule", args.ignore_rule)
    _add_repeat(cmd, "--redact-header", args.redact_header)

    # OAuth2
    _add_opt(cmd, "--oauth2-client-data", args.oauth2_client_data)
    _add_opt(cmd, "--oauth2-credentials", args.oauth2_credentials)

    _add_opt(cmd, "--oauth2-authorization-code-auth-url", args.oauth2_auth_code_auth_url)
    _add_opt(cmd, "--oauth2-authorization-code-token-url", args.oauth2_auth_code_token_url)
    _add_opt(cmd, "--oauth2-authorization-code-refresh-url", args.oauth2_auth_code_refresh_url)
    _add_repeat(cmd, "--oauth2-authorization-code-scopes", args.oauth2_auth_code_scopes)

    _add_opt(cmd, "--oauth2-implicit-auth-url", args.oauth2_implicit_auth_url)
    _add_opt(cmd, "--oauth2-implicit-refresh-url", args.oauth2_implicit_refresh_url)
    _add_repeat(cmd, "--oauth2-implicit-scopes", args.oauth2_implicit_scopes)

    _add_opt(cmd, "--oauth2-client-credentials-token-url", args.oauth2_cc_token_url)
    _add_opt(cmd, "--oauth2-client-credentials-refresh-url", args.oauth2_cc_refresh_url)
    _add_repeat(cmd, "--oauth2-client-credentials-scopes", args.oauth2_cc_scopes)

    _add_opt(cmd, "--oauth2-password-token-url", args.oauth2_password_token_url)
    _add_opt(cmd, "--oauth2-password-refresh-url", args.oauth2_password_refresh_url)
    _add_repeat(cmd, "--oauth2-password-scopes", args.oauth2_password_scopes)

    _add_opt(cmd, "--p12cert", args.p12cert)
    _add_opt(cmd, "--p12password", args.p12password)

    log.info("Running: %s", " ".join(cmd))
    try:
        return await run_cli(cmd, timeout_s=args.process_timeout, ctx=ctx)
    except CLIRuntimeError as e:
        if e.exit_code == 1:
            return e.stdout
        raise RuntimeError(str(e)) from None


# -----------------------------
# Pydantic schema for `mapi target list`
# -----------------------------
class TargetListArgs(BaseModel):
    show_dates: bool = Field(False, description="--show-dates: display the date each target was added and last updated")
    max_items: int = Field(100, ge=1, description="--max-items <int>: maximum number of targets to return (default: 100)")


# -----------------------------
# MCP tool for `mapi target list`
# -----------------------------
@mcp.tool(
    description="""
    List the mapi targets registered for the current user account.
    Returns a table of project/target pairs available for scanning with `mapi run`.
    Use this to discover existing targets before starting a new scan.
    """
)
async def mapi_target_list(args: TargetListArgs, ctx: Context | None = None) -> str:
    cmd: list[str] = [MAPI_BIN, "target", "list"]
    _add_flag(cmd, args.show_dates, "--show-dates")
    _add_opt(cmd, "--max-items", args.max_items)
    log.info("Running: %s", " ".join(cmd))
    try:
        return await run_cli(cmd, ctx=ctx)
    except CLIRuntimeError as e:
        raise RuntimeError(str(e)) from None


# -----------------------------
# Helpers for evaluate_scan_quality
# -----------------------------
def _spec_path_regex(spec_path: str) -> re.Pattern:
    """Compile a spec path with {param} placeholders into a regex for HAR path matching."""
    parts = spec_path.split("/")
    pattern_parts = []
    for part in parts:
        if part.startswith("{") and part.endswith("}"):
            pattern_parts.append("[^/]+")
        elif part:
            pattern_parts.append(re.escape(part))
    pattern = "/".join(pattern_parts)
    return re.compile(f"(?:^|/){pattern}(?:/|$)")


# -----------------------------
# Pydantic schema for evaluate_scan_quality
# -----------------------------
class EvaluateScanQualityArgs(BaseModel):
    scan_output: str = Field(..., description="stdout captured from mapi run")
    har_path: str = Field(..., description="filesystem path to the HAR file produced by the scan (requires --har <path> on the mapi run invocation)")
    spec_path: str = Field(..., description="filesystem path to the OpenAPI/Swagger/Postman spec used for the scan")


# -----------------------------
# MCP tool: evaluate_scan_quality
# -----------------------------
@mcp.tool(
    description="""
    Evaluate the quality of a completed mapi scan by parsing the HAR file and API spec.
    Returns a JSON string with endpoint coverage percentage, auth hints extracted from
    401/403 responses, and per-endpoint request/2xx/status stats.
    Use this after mapi_run to decide whether to tune scan parameters further.
    Requires the scan to have been run with --har <path> to produce a HAR file.
    """
)
async def evaluate_scan_quality(args: EvaluateScanQualityArgs, ctx: Context | None = None) -> str:
    # 1. Extract spec endpoints via mapi describe specification
    try:
        spec_output = await run_cli(
            [MAPI_BIN, "describe", "specification", args.spec_path],
            timeout_s=30.0,
        )
    except CLIRuntimeError as e:
        raise RuntimeError(str(e)) from None

    seen: set[tuple[str, str]] = set()
    spec_endpoints: list[tuple[str, str]] = []
    for line in spec_output.strip().splitlines():
        parts = line.split()
        if len(parts) >= 2:
            key = (parts[0].upper(), parts[1])
            if key not in seen:
                seen.add(key)
                spec_endpoints.append(key)

    # Compile path matchers for each unique spec endpoint
    spec_patterns = [(m, p, _spec_path_regex(p)) for m, p in spec_endpoints]

    # 2. Parse HAR
    har_file = Path(args.har_path)
    if not har_file.exists():
        raise RuntimeError(f"HAR file not found: {args.har_path}")
    try:
        har = json.loads(har_file.read_text())
        entries = har.get("log", {}).get("entries", [])
    except (json.JSONDecodeError, KeyError) as e:
        raise RuntimeError(f"Failed to parse HAR file: {e}") from None

    # 3. Per-endpoint stats
    stats: dict[tuple[str, str], dict] = {
        (m, p): {"request_count": 0, "ok_count": 0, "status_breakdown": {}}
        for m, p in spec_endpoints
    }
    auth_hints_set: set[str] = set()
    total_requests = len(entries)

    for entry in entries:
        req = entry.get("request", {})
        resp = entry.get("response", {})
        method = req.get("method", "").upper()
        raw_url = req.get("url", "")
        status = resp.get("status", 0)
        path = urlparse(raw_url).path

        # Collect WWW-Authenticate hints from 401/403 responses
        if status in (401, 403):
            for hdr in resp.get("headers", []):
                if hdr.get("name", "").lower() == "www-authenticate":
                    val = hdr.get("value", "").strip()
                    if val:
                        auth_hints_set.add(val)

        # Match to best-fitting spec endpoint
        for spec_method, spec_path, pattern in spec_patterns:
            if spec_method == method and pattern.search(path):
                key = (spec_method, spec_path)
                stats[key]["request_count"] += 1
                if 200 <= status < 300:
                    stats[key]["ok_count"] += 1
                s_key = str(status)
                stats[key]["status_breakdown"][s_key] = (
                    stats[key]["status_breakdown"].get(s_key, 0) + 1
                )
                break

    # 4. Coverage: endpoints that received at least one 2xx response
    endpoints_with_2xx = sum(1 for v in stats.values() if v["ok_count"] > 0)
    total = len(spec_endpoints)
    covered_pct = round(endpoints_with_2xx / total * 100, 1) if total > 0 else 0.0

    # 5. Unreachable endpoints flagged by mapi ([C] in scan output)
    unreachable = [
        line.strip()
        for line in args.scan_output.splitlines()
        if "[C]" in line
    ]

    # 6. Filtered scan output summary
    _summary_kw = {"[c]", "error", "duration", "coverage", "auth", "fail", "time limit"}
    summary_lines = [
        line for line in args.scan_output.splitlines()
        if any(kw in line.lower() for kw in _summary_kw)
    ]

    endpoint_stats = [
        {
            "method": m,
            "path": p,
            "request_count": stats[(m, p)]["request_count"],
            "ok_count": stats[(m, p)]["ok_count"],
            "status_breakdown": stats[(m, p)]["status_breakdown"],
        }
        for m, p in spec_endpoints
    ]

    return json.dumps({
        "total_endpoints": total,
        "covered_pct": covered_pct,
        "total_requests": total_requests,
        "auth_hints": sorted(auth_hints_set),
        "unreachable_endpoints": unreachable,
        "endpoint_stats": endpoint_stats,
        "scan_output_summary": "\n".join(summary_lines[:20]),
    }, indent=2)


# -----------------------------
# Pydantic schema for emit_scan_script
# -----------------------------
class EmitScanScriptArgs(BaseModel):
    api_target: str = Field(..., description="project/target name (e.g., 'myproject/api')")
    duration: str = Field(..., description="scan duration (e.g., '30s', '2m', '10m')")
    specification: str = Field(..., description="path to the OpenAPI/Swagger/Postman spec file")
    url: str = Field(..., description="base URL for the API (e.g., 'https://localhost:8000')")
    output_path: str = Field(..., description="filesystem path to write the script; overwrites if already exists")
    extra_flags: List[str] = Field(default_factory=list, description="additional mapi run flags in argv order (e.g., ['--header-auth', 'Authorization: Bearer ${MAPI_TOKEN}'])")
    har_output_path: str = Field("scan.har", description="path for the --har output file embedded in the script (default: scan.har)")


# -----------------------------
# MCP tool: emit_scan_script
# -----------------------------
@mcp.tool(
    description="""
    Write a parameterized bash script wrapping the final tuned mapi run invocation.
    The script uses set -euo pipefail and validates required environment variables at startup.
    Pass auth credentials as ${ENV_VAR} references in extra_flags — never inline secrets.
    Overwrites output_path if it already exists. Returns the path the script was written to.
    """
)
def emit_scan_script(args: EmitScanScriptArgs) -> str:
    # Detect ${VAR_NAME} references in extra_flags for env-var guards
    _var_re = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)\}")
    seen_vars: set[str] = set()
    extra_vars: list[str] = []
    for flag in args.extra_flags:
        for var in _var_re.findall(flag):
            if var != "MAYHEM_TOKEN" and var not in seen_vars:
                seen_vars.add(var)
                extra_vars.append(var)

    env_guards = [': "${MAYHEM_TOKEN:?MAYHEM_TOKEN must be set}"']
    for var in extra_vars:
        env_guards.append(f': "${{{var}:?{var} must be set}}"')

    # Build mapi run invocation with backslash continuation
    all_flags = args.extra_flags
    positional_and_opts = [
        f"  {args.api_target} \\",
        f"  {args.duration} \\",
        f"  {args.specification} \\",
        f"  --url {args.url} \\",
        f"  --har {args.har_output_path}",
    ]
    if all_flags:
        positional_and_opts[-1] += " \\"
        for i, flag in enumerate(all_flags):
            suffix = " \\" if i < len(all_flags) - 1 else ""
            positional_and_opts.append(f"  {flag}{suffix}")

    script = "\n".join([
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        "",
        *env_guards,
        "",
        "mapi run \\",
        *positional_and_opts,
        "",
    ])

    Path(args.output_path).write_text(script)
    os.chmod(args.output_path, 0o755)
    return f"Script written to {args.output_path}"


# -----------------------------
# Heuristic rule helpers for suggest_tune_changes
# -----------------------------
def _rule_auth(quality: dict, current: dict) -> dict | None:
    """Rule 1: auth failure signal → suggest auth flags."""
    auth_hints = quality.get("auth_hints", [])
    summary = quality.get("scan_output_summary", "").lower()
    auth_signal = bool(auth_hints) or any(
        kw in summary for kw in ("auth", "401", "403", "unauthorized", "forbidden")
    )
    if not auth_signal:
        return None
    if current.get("header_auth") or current.get("basic_auth") or current.get("cookie_auth"):
        return None  # auth flag already set
    hint_text = " ".join(auth_hints).lower()
    if "basic" in hint_text:
        flag, value = "--basic-auth", "${MAPI_USER}:${MAPI_PASS}"
    else:
        flag, value = "--header-auth", "Authorization: Bearer ${MAPI_TOKEN}"
    return {
        "flag": flag,
        "value": value,
        "reason": "Auth failure detected — 401/403 responses or auth error in scan output",
        "warning": None,
    }


def _rule_min_requests(quality: dict, current: dict, min_covered_pct: int) -> dict | None:
    """Rule 2: low coverage + not duration-limited → raise --min-request-count."""
    covered_pct = quality.get("covered_pct", 0)
    summary = quality.get("scan_output_summary", "").lower()
    if covered_pct >= min_covered_pct:
        return None
    if "duration" in summary or "time limit" in summary:
        return None  # duration-limited case handled by Rule 3
    total_endpoints = max(quality.get("total_endpoints", 1), 1)
    suggested = max(50, total_endpoints * 20)
    current_min = current.get("min_request_count")
    if current_min and int(current_min) >= suggested:
        return None
    return {
        "flag": "--min-request-count",
        "value": str(suggested),
        "reason": f"Low endpoint coverage ({covered_pct}%) with time remaining — increase per-endpoint request budget",
        "warning": None,
    }


def _rule_duration(quality: dict, current: dict, min_covered_pct: int) -> dict | None:
    """Rule 3: low coverage + duration-limited → increase duration."""
    covered_pct = quality.get("covered_pct", 0)
    summary = quality.get("scan_output_summary", "").lower()
    if covered_pct >= min_covered_pct:
        return None
    if "duration" not in summary and "time limit" not in summary:
        return None
    current_duration = current.get("duration", "30s")
    if current_duration == "auto":
        return None
    try:
        secs = parse_duration(current_duration)
    except ValueError:
        return None
    doubled = secs * 2
    if doubled >= 3600:
        next_dur = f"{int(doubled / 3600)}h"
    elif doubled >= 60:
        next_dur = f"{int(doubled / 60)}m"
    else:
        next_dur = f"{int(doubled)}s"
    if current_duration == next_dur:
        return None
    return {
        "flag": "duration",
        "value": next_dur,
        "reason": f"Low endpoint coverage ({covered_pct}%) and scan hit time limit — increase duration from {current_duration} to {next_dur}",
        "warning": None,
    }


def _rule_ignore_endpoint(quality: dict, current: dict, iteration: int) -> dict | None:
    """Rule 4: chronically 5xx endpoint → --ignore-endpoint with narrowing warning."""
    if iteration < 2:
        return None
    existing_ignores = current.get("ignore_endpoint", [])
    for ep in quality.get("endpoint_stats", []):
        count = ep.get("request_count", 0)
        ok = ep.get("ok_count", 0)
        if count < 10 or ok > 0:
            continue
        breakdown = ep.get("status_breakdown", {})
        five_xx = sum(v for k, v in breakdown.items() if k.startswith("5"))
        if count > 0 and five_xx / count > 0.8:
            target = f"{ep['method']}:{ep['path']}"
            if target in existing_ignores:
                continue
            return {
                "flag": "--ignore-endpoint",
                "value": target,
                "reason": f"{ep['method']} {ep['path']} returned 5xx on {five_xx}/{count} attempts with 0 successes",
                "warning": "[FUZZING NARROWING WARNING] Ignoring this endpoint reduces the fuzzer's attack surface. Confirm this endpoint is intentionally excluded before applying.",
            }
    return None


def _rule_validation_errors(quality: dict, min_covered_pct: int) -> dict | None:
    """Rule 5: high 400/422 rate → informational note about resource hints."""
    total = quality.get("total_requests", 0)
    covered_pct = quality.get("covered_pct", 0)
    if total == 0 or covered_pct < min_covered_pct / 2:
        return None
    val_errors = sum(
        ep.get("status_breakdown", {}).get("400", 0) + ep.get("status_breakdown", {}).get("422", 0)
        for ep in quality.get("endpoint_stats", [])
    )
    if val_errors / total <= 0.4:
        return None
    return {
        "flag": None,
        "value": None,
        "reason": (
            f"High validation-error rate ({val_errors}/{total} requests returned 400/422). "
            "Resource hints can seed valid parameter values — support coming in Capability 2."
        ),
        "warning": None,
    }


# -----------------------------
# Pydantic schema for suggest_tune_changes
# -----------------------------
class SuggestTuneChangesArgs(BaseModel):
    quality_json: str = Field(..., description="JSON string returned by evaluate_scan_quality")
    current_args_json: str = Field(..., description="JSON object of the current mapi run arguments (keys match RunArgs fields, e.g. {\"duration\": \"30s\", \"header_auth\": []})")
    iteration: int = Field(1, ge=1, description="current tune-loop iteration number (1-indexed)")
    min_covered_pct: int = Field(25, ge=1, le=100, description="minimum % of spec endpoints with ≥1 2xx response to consider the scan good (default: 25)")


# -----------------------------
# MCP tool: suggest_tune_changes
# -----------------------------
@mcp.tool(
    description="""
    Analyze mapi scan quality metrics and suggest flag changes to improve coverage.
    Applies 6 deterministic heuristic rules in priority order.
    Returns a JSON object with a suggestions list, exhausted flag, and rationale.
    Rule 4 (--ignore-endpoint suggestions) always carries a [FUZZING NARROWING WARNING] —
    present this warning to the user and require explicit approval before applying.
    When exhausted=true, quality thresholds are met or heuristics are exhausted.
    """
)
def suggest_tune_changes(args: SuggestTuneChangesArgs) -> str:
    try:
        quality = json.loads(args.quality_json)
        current = json.loads(args.current_args_json)
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON input: {e}") from None

    covered_pct = quality.get("covered_pct", 0)

    # Rule 6: convergence check — fast exit if threshold met
    if covered_pct >= args.min_covered_pct:
        return json.dumps({
            "suggestions": [],
            "exhausted": True,
            "rationale": f"Quality threshold met — coverage {covered_pct}% ≥ {args.min_covered_pct}%. Ready to emit scan script.",
        }, indent=2)

    # Rules 1–5
    suggestions = [
        s for s in [
            _rule_auth(quality, current),
            _rule_min_requests(quality, current, args.min_covered_pct),
            _rule_duration(quality, current, args.min_covered_pct),
            _rule_ignore_endpoint(quality, current, args.iteration),
            _rule_validation_errors(quality, args.min_covered_pct),
        ]
        if s is not None
    ]

    # LLM fallback: no new actionable suggestions after 3+ iterations
    actionable = [s for s in suggestions if s.get("flag") is not None]
    if args.iteration >= 3 and not actionable:
        return json.dumps({
            "suggestions": suggestions,
            "exhausted": True,
            "rationale": (
                f"Heuristic suggestions exhausted after {args.iteration} iterations. "
                "LLM should evaluate the quality data and propose alternative strategies, "
                "or accept the current configuration."
            ),
        }, indent=2)

    rationale = (
        f"{len(suggestions)} suggestion(s) generated. "
        f"Coverage: {covered_pct}% (threshold: {args.min_covered_pct}%)."
        if suggestions
        else f"No applicable heuristics triggered. Coverage: {covered_pct}% (threshold: {args.min_covered_pct}%)."
    )
    return json.dumps({
        "suggestions": suggestions,
        "exhausted": False,
        "rationale": rationale,
    }, indent=2)


# -----------------------------
# MCP prompt: onboard-mapi-scan
# -----------------------------
@mcp.prompt(
    name="onboard-mapi-scan",
    description="Orchestrate the mapi onboarding and tune loop: walk through setup, run a scan, evaluate quality, suggest tuning changes, and emit a final leave-behind scan script.",
)
async def onboard_mapi_scan(
    api_target: str,
    specification: str,
    url: str,
    duration: str = "30s",
    max_iterations: int = 3,
    min_covered_pct: int = 25,
) -> str:
    har_path = f"/tmp/mapi-onboard-{api_target.replace('/', '-')}.har"
    script_path = f"./mapi-scan-{api_target.replace('/', '-')}.sh"
    return f"""You are following the mapi onboarding and tune loop for target `{api_target}`.
Complete each step in order. Surface progress to the user as you go.

**Scan parameters:**
- api_target: {api_target}
- specification: {specification}
- url: {url}
- duration: {duration} (initial — may change after tuning)
- max_iterations: {max_iterations}
- min_covered_pct: {min_covered_pct}%
- HAR output path: {har_path}

---

## Step 1 — Verify environment

Call `mapi_target_list` with default arguments (empty TargetListArgs).
Confirm the response lists at least one target and contains no authentication error.
If the call fails or MAYHEM_TOKEN appears unset, tell the user and stop.

## Step 2 — Confirm spec file

Call `read_file("{specification}")` to read the first lines of the spec.
Confirm the file exists and looks like an OpenAPI/Swagger/Postman spec.
If the file is missing or unreadable, tell the user and stop.

## Step 3 — Run initial scan

Call `mapi_run` with these arguments:
  api_target = "{api_target}"
  duration = "{duration}"
  specification = "{specification}"
  url = "{url}"
  har = "{har_path}"

Capture the full output as `scan_output`.
A non-zero mapi exit (exit code 1 = findings present) is normal — the output is still returned.
Exit codes 2 or 3 indicate real errors — surface them to the user and stop.

## Step 4 — Evaluate quality

Call `evaluate_scan_quality` with:
  scan_output = <full output from Step 3>
  har_path = "{har_path}"
  spec_path = "{specification}"

Parse the returned JSON and show the user:
- covered_pct (% of spec endpoints with at least one 2xx response)
- total_endpoints and total_requests
- auth_hints (if non-empty — these indicate auth is blocking the fuzzer)
- unreachable_endpoints (if non-empty)

Store this quality JSON for Step 5.

## Step 5 — Tune loop (up to {max_iterations} total scan iterations)

Maintain `current_args` as a JSON object tracking the mapi_run arguments in use.
Start with: {{"api_target": "{api_target}", "duration": "{duration}", "specification": "{specification}", "url": "{url}"}}
Update it after each iteration when suggestions are applied.

The initial scan (Step 3) is iteration 1. For each subsequent iteration:

  a. Call `suggest_tune_changes` with:
       quality_json       = <JSON string from the most recent evaluate_scan_quality>
       current_args_json  = <JSON string of current_args>
       iteration          = <current iteration number>
       min_covered_pct    = {min_covered_pct}

  b. If `exhausted == true` OR iteration >= {max_iterations}: proceed to Step 6.

  c. Present each suggestion to the user (flag, value, reason).
     **If any suggestion has a non-null `warning` field containing "[FUZZING NARROWING WARNING]":
     display the warning prominently and ask the user explicitly:
     "Apply --ignore-endpoint for <endpoint>? (yes/no)"
     Do NOT apply the suggestion without an explicit yes.**

  d. Apply all approved suggestions to current_args:
     - If flag is "duration": update the duration value in current_args.
     - If flag starts with "--": add or update the corresponding snake_case field in current_args
       (e.g., "--header-auth" → "header_auth", "--min-request-count" → "min_request_count").
     - If flag is null (informational): note it to the user, no change to current_args.

  e. Run the next scan: call `mapi_run` with the updated current_args, keeping
     har = "{har_path}". Capture the full output as scan_output.

  f. Call `evaluate_scan_quality` again with the new scan_output,
     har_path = "{har_path}", spec_path = "{specification}".
     Show the updated covered_pct and request count to the user.
     Increment the iteration counter and return to step (a).

## Step 6 — Emit scan script

Call `emit_scan_script` with:
  api_target      = "{api_target}"
  duration        = <final duration from current_args>
  specification   = "{specification}"
  url             = "{url}"
  output_path     = "{script_path}"
  har_output_path = "{har_path}"
  extra_flags     = <list of flag-value pairs from current_args that are not positional args,
                    in argv order — e.g. ["--header-auth", "Authorization: Bearer ${{MAPI_TOKEN}}",
                    "--min-request-count", "200"]>

Confirm the script was written and show the user the output path.

## Step 7 — Summary

Present a final summary to the user:
1. Final quality metrics from the last evaluate_scan_quality: covered_pct, total_endpoints, total_requests.
2. Path to the emitted script: `{script_path}`
3. How many iterations ran and what changed between them.
4. Any endpoints that remained unreachable (unreachable_endpoints from the last quality JSON).
5. If covered_pct < {min_covered_pct}% after {max_iterations} iterations:
   note that thresholds were not met and suggest the user review the script manually or
   run the loop again with a longer duration or higher max_iterations.

---

**Important implementation notes:**
- Always pass `har = "{har_path}"` to every mapi_run call. Without it, evaluate_scan_quality
  cannot parse the HAR and will fail.
- RunArgs has a `har` field directly — do not use extra_flags for the HAR path.
- The `current_args_json` for suggest_tune_changes should use Python-style snake_case key names
  matching RunArgs fields (e.g., "header_auth", "min_request_count", "duration").
- emit_scan_script's extra_flags takes argv-order tokens (["--flag", "value", ...]),
  not a dict. Construct this list from current_args before calling emit_scan_script.
"""


@mcp.tool(description="Execute arbitrary bash commands on the MAPI server host - this is useful to inspect or manipulate mapi findings.")
async def bash(command: str, cwd: str | None = None) -> str:
    """Execute bash commands.

    Args:
        command: The bash command to execute
        cwd: Working directory for the command (optional)
    """
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            exit_code = proc.returncode or 0
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return "Error: Command timed out after 1 minute"

        output = f"Command executed with exit code: {exit_code}\n\n"
        if stdout:
            output += f"STDOUT:\n{stdout.decode()}\n"
        if stderr:
            output += f"STDERR:\n{stderr.decode()}\n"

        return output

    except Exception as e:
        return f"Error executing command: {str(e)}"


@mcp.tool(description="Read contents of a file on the MAPI server host, optionally specifying line range.")
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
        path = Path(file_path)
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
        path = Path(file_path)
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


async def version() -> str:
    try:
        out = await run_cli([MAPI_BIN, "--version"], timeout_s=10.0, max_bytes=32_000)
    except Exception as e:
        out = f"(error retrieving version) {e}"
    return f"server=MAPI Server; mapi_bin={MAPI_BIN}; mapi_version={out.strip()}"


def main():
    if os.environ.get("MAYHEM_TOKEN") is None:
        log.error("MAYHEM_TOKEN not set; cannot start MAPI server")
        sys.exit(1)
    log.info("Starting MAPI Server on stdio...")
    mcp.run(transport="stdio")
