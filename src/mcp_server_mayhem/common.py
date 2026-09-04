from __future__ import annotations
from pathlib import Path
import re
from importlib.resources import files as _pkg_files
from typing import List, Optional


def _load_prompt_template(name: str, subdir: str = "prompts") -> str:
    """Read a packaged text template out of `subdir` within the package.

    Resolution goes through importlib.resources so loading works from an
    installed wheel and inside the Docker image, not just from a source
    checkout. `subdir` defaults to "prompts" so existing call sites are
    unchanged; pass "templates" for the CI/CD templates.
    """
    return (
        _pkg_files("mcp_server_mayhem")
        .joinpath(subdir)
        .joinpath(name)
        .read_text(encoding="utf-8")
    )


def _render(template: str, **kwargs: str) -> str:
    for key, value in kwargs.items():
        template = template.replace(f"<<{key}>>", value)
    return template


def _optional_region(template: str, name: str, keep: bool) -> str:
    """Keep or drop a `<<#name>> ... <</name>>` region, dropping the markers either way.

    `_render` is plain string replacement with no conditional, so a template
    cannot itself express an optional section. Marker lines are matched whole
    (leading whitespace and trailing newline included) so removing a region
    leaves no blank line behind.
    """
    pattern = re.compile(
        rf"^[ \t]*<<#{re.escape(name)}>>[ \t]*\n(.*?)^[ \t]*<</{re.escape(name)}>>[ \t]*\n",
        re.MULTILINE | re.DOTALL,
    )
    return pattern.sub((lambda m: m.group(1)) if keep else "", template)


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


def _assert_under_cwd(p: Path) -> Path:
    resolved = p.resolve()
    cwd = Path.cwd().resolve()
    if not resolved.is_relative_to(cwd):
        raise PermissionError(
            f"Path '{p}' resolves to '{resolved}', which is outside the "
            f"project root '{cwd}'. Paths must be relative to the working directory."
        )
    return resolved


_CREDENTIAL_FLAGS: frozenset[str] = frozenset({
    "--basic-auth",
    "--header-auth",
    "--cookie-auth",
    "--p12password",
    "--oauth2-client-data",
    "--oauth2-credentials",
    "--postman-api-key",
    "--token",
    "--github-token",
})


def _redact_cmd(cmd: list[str]) -> list[str]:
    result: list[str] = []
    redact_next = False
    for token in cmd:
        if redact_next:
            result.append("<redacted>")
            redact_next = False
        elif token in _CREDENTIAL_FLAGS:
            result.append(token)
            redact_next = True
        else:
            result.append(token)
    return result
