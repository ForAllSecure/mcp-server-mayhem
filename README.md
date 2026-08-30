# MCP Server for `mayhem`

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for
the [Mayhem](https://docs.mayhem.security/) CLI
(`mayhem`).

> [!NOTE]
> The code in this repository is provided as-is and is intended only for
> demonstration purposes. This project is not officially supported or actively
> maintained.

## Capabilities

> [!NOTE]
> Not all MCP clients surface prompts as slash commands. VS Code Copilot shows
> slash commands in the prompt picker. Claude
> Desktop, Claude Code, and most other clients require asking the model to run
> the prompt by name (e.g., "Run the onboard-mapi-scan prompt") or using the
> individual tools directly.

### `mapi discover`

Discover APIs running on a single host, multiple hosts, CIDR blocks, or domains.

### `mapi run`

Run a scan to check an API for defects.

### Capability 1 - Agentic Onboarding & Tune Loop

The `/onboard-mapi-scan` prompt runs an end-to-end fuzzing workflow. It verifies
your environment, runs an initial scan, evaluates endpoint coverage, suggests
configuration improvements, and emits a bash script you can commit to CI. The
loop iterates until coverage meets a target threshold or the iteration limit is
reached.

**Tools used:**

- `evaluate_scan_quality` - parses the HAR output and spec to compute endpoint
  coverage (`covered_pct`), surface auth hints, and identify unreachable endpoints
- `suggest_tune_changes` - applies heuristic rules (auth headers, request count,
  duration, endpoint exclusions, validation errors) to propose the next tuning step
- `emit_scan_script` - writes a `set -euo pipefail` bash script with all finalized
  flags and env-var guards for the leave-behind artifact

**Invoking the prompt:**

In your MCP client, invoke `/onboard-mapi-scan` with the following arguments:

| Argument | Required | Default | Description |
|---|---|---|---|
| `workspace` | yes | — | Mayhem workspace name (e.g. `myorg`) |
| `project` | yes | — | Mayhem project name (e.g. `my-api`) |
| `target_name` | no | `""` | Specific target within the project; omit to use the project default |
| `specification` | yes | - | Path to an OpenAPI/Swagger/Postman spec file |
| `url` | yes | - | Base URL of the API under test |
| `duration` | no | `30s` | Initial scan duration |
| `max_iterations` | no | `3` | Maximum tune-loop iterations |
| `min_covered_pct` | no | `25` | Coverage threshold that stops the loop early |

The `--har` flag is handled automatically. mapi writes HAR output to `/tmp`;
`evaluate_scan_quality` reads it from there.

> [!NOTE]
> Any suggestion to add `--ignore-endpoint` (which narrows the fuzzer's attack
> surface) will be surfaced with a `[FUZZING NARROWING WARNING]` and requires
> explicit confirmation before it is applied.

### Capability 2 - Source-Aware Fuzzing

After the first quality evaluation, the `/onboard-mapi-scan` prompt optionally
analyzes the API spec and source code to propose targeted configuration improvements:
resource hints for low-coverage PATH parameters, rule prioritization based on
observed code patterns, and endpoint or tag filters where appropriate.

**Tools used:**

- `mapi_describe_specification` - fetches the full parameter table from a spec
  (used internally by the prompt to identify which parameters need seeding)
- `suggest_source_aware_changes` - applies heuristic rules to spec parameters and
  source-extracted values to propose `--resource-hint`, `--include-rule`, and
  `--experimental-rules` changes
- `emit_mapi_config` - generates a `.mapi` YAML configuration file with correlated
  resource hint groups and issue suppressions for team sharing or SCM storage

**How it works:**

Capability 2 runs as an optional **Step 4.5** inside the `/onboard-mapi-scan`
flow, after the first scan quality evaluation. The prompt identifies PATH parameters
with zero coverage, asks you to point to relevant source files (fixture data, enum
definitions, seed files), reads them, and generates a small number of targeted
hints. It also detects code patterns (SQL queries, subprocess calls, file operations,
PII fields) and suggests enabling the corresponding mapi rules.

You don't need a separate invocation. It runs inside the standard
`/onboard-mapi-scan` flow.

**Fuzziness guardrail:**

- `--resource-hint` and `--include-rule` suggestions are applied without extra
  confirmation - they expand mapi's reach, not narrow it
- Any suggestion involving `--ignore-endpoint`, `--ignore-endpoints-by-tag`, or
  `--ignore-rule` carries a `[FUZZING NARROWING WARNING]` and requires explicit
  confirmation before it is applied
- Resource hints are capped at 3-5 per session to preserve fuzzer input entropy
  (mapi applies hints on the majority of generated requests)

**`.mapi` config file:**

At the end of the flow, the prompt optionally offers to generate a `.mapi` YAML
config file via `emit_mapi_config`. This is most useful when you need correlated
parameter groups (multiple parameters seeded together consistently) or want to
commit suppressions to source control for team sharing. For one-off scans, the
emitted bash script is sufficient.

### Capability 3 - Exploit Generation

> [!WARNING]
> The server **never sends** exploit requests. All output is text for the user
> to review and decide whether to run. Obtain appropriate authorization before
> executing any suggested request.

For each defect found by a mapi run, the `/generate-exploit` prompt confirms
the defect still reproduces, crafts a targeted HTTP request demonstrating its
impact, and emits a leave-behind markdown report.

**How to invoke:**

In your MCP client, invoke `/generate-exploit` with:

| Argument | Required | Default | Description |
|---|---|---|---|
| `run_id` | yes | - | Mayhem run ID containing the defects (e.g. `myorg/api/42`) |
| `url` | yes | - | Base URL of the API under test |
| `specification` | no | `""` | Spec path for endpoint context |
| `source_dir` | no | `""` | Source root for higher-fidelity exploit crafting |
| `output_path` | no | `exploit-report.md` | Path for the leave-behind report |

> [!NOTE]
> The server resolves `output_path` on its own filesystem. When the server runs
> in a Docker container (the default for all client configurations shown below),
> that path lives inside the ephemeral container and disappears when it exits.
> Two options:
> - The inline chat output from the prompt is the reliable artifact and works
>   regardless of how you launch the server.
> - To write a file to the host, add a volume mount to the Docker args
>   (`-v /path/to/workspace:/work`) and set `output_path` to a path under `/work`.
>
> For a local `uv run` launch (see [Local Development](#local-development)),
> `output_path` writes to the host directly.

**Leave-behind tool:**

`emit_exploit_report` generates a markdown file with one section per defect:
the reproducing request, the suggested exploit, and source code references if
available.

**Safety boundary:**

- The server never issues HTTP requests to the API. The exploit suggestion is
  text only; the user manually copies and runs it.
- Any suggestion that would mutate or delete server state (account changes, data
  deletion, DoS) is tagged **`[DESTRUCTIVE]`** and requires explicit user
  confirmation before it is included in the report.
- The prompt replaces any credentials or tokens observed in defect data with
  typed placeholders (`<BEARER_TOKEN>`, `<PASSWORD>`, etc.). Real values never
  reach the report.
- Safety warnings appear at four points: prompt start, before each exploit is
  crafted, at the destructive-action gate, and after the report is generated.

## Code Testing with `mayhem`

This is a parallel capability to the API-testing tools above: fuzz testing of
binaries and Docker images via the [`mayhem`](https://docs.mayhem.security/)
CLI. Unlike the `mapi` capabilities, this is a straightforward sequential
lifecycle - there's no iterative coverage-tuning loop or exploit-generation
step, since neither has a meaningful mayhem equivalent.

### Core lifecycle

The typical path through a mayhem run:

```
mayhem_login → mayhem_validate → mayhem_run → mayhem_wait / mayhem_show
```

- `mayhem_login` - authenticates with a Mayhem server. Persists credentials to
  the `~/.config/mayhem` XDG dir and logs into the Mayhem Docker registry.
- `mayhem_validate` - checks that a packaged target's Mayhemfile is correct
  before running it. Operates on a packaged directory, not a bare Docker
  image tag.
- `mayhem_run` - starts a run (regression/static/dynamic/coverage analysis)
  against a packaged target directory or, with `docker = true`, directly
  against a Docker image tag/hash. This tool has the largest flag surface in
  the project - full parity with `mayhem run --help`, no trimming.
- `mayhem_wait` - blocks until a run finishes and returns its results. Takes
  a `poll_timeout_s` field (default 1800s / 30 minutes) that controls how
  long the tool call itself is allowed to block, independent of the run's
  own `--duration` - raise it for long-running targets. When `fail_on_defects`
  is set, a run that completes with defects present is returned as a normal
  result rather than raised as an error.
- `mayhem_show` - a non-blocking snapshot of one or all runs, as an
  alternative to `mayhem_wait` when you don't want to block.

### Packaging a target

Mayhem fuzzes Docker image contents directly, so a Docker-based target needs
no local packaging step - it's the preferred path when a suitable image
already exists. For targets that aren't already a Docker image:

- `mayhem_package` - packages a local target binary and its dependencies for
  Mayhem. This is the fallback path.
- `mayhem_init` - scaffolds a Mayhemfile (from a Docker image, a language
  template, or explicit flags) - the `mayhem_package` path's counterpart, and
  the tool the `/onboard-mayhem-run` prompt points you to if you haven't
  built or packaged a target yet.

> [!NOTE]
> Neither this server nor its prompts will author a fuzz harness, Dockerfile,
> or Mayhemfile on your behalf. If a target isn't packaged or built yet,
> `mayhem_init`/`mayhem_package` expect you to supply one - they package and
> validate existing targets, they don't create them.

### Other utility tools

The remaining subcommands round out full `mayhem` CLI coverage:
`mayhem_logout`, `mayhem_list` (projects/targets you've run), `mayhem_download`
(a target and its test cases), `mayhem_sync` (refresh a package with the
latest test cases), `mayhem_stop` (stop one or all runs for a target/project),
`mayhem_check` (check whether local files are Mayhem-eligible), and
`mayhem_docker_registry` (get the URI for Mayhem's Docker registry).

### Onboarding prompt

The `/onboard-mayhem-run` prompt walks through the lifecycle above end-to-end:
it verifies login, asks whether you have a Docker image ready, an unpackaged
local binary, or nothing built yet (stopping if the latter, since building a
target is out of scope), packages and validates if needed, starts the run,
and monitors it to completion.

**Invoking the prompt:**

In your MCP client, invoke `/onboard-mayhem-run` with the following arguments:

| Argument | Required | Default | Description |
|---|---|---|---|
| `url` | yes | — | Base URL of the Mayhem server |
| `project` | no | `""` | Mayhem project name, if already known |
| `target` | no | `""` | Mayhem target name, if already known |
| `owner` | no | `""` | Owner (user or organization) to scope calls to |

## Usage

MCP servers connect to AI applications like Claude, Cursor, or VS Code Copilot.
The sections below cover setup for each supported client.

### Dependencies

- [Docker](https://docs.docker.com/get-started/get-docker/)

#### Login to the GitHub Container Registry

If necessary, follow
[the steps](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#authenticating-with-a-personal-access-token-classic)
to authenticate to the GitHub Container registry with a personal access token
(classic). You only need the `read:packages` scope.

> [!NOTE]
> To check login status, run `docker login ghcr.io`.

### Use with Visual Studio Code

Visual Studio Code has
[native MCP support](https://code.visualstudio.com/docs/copilot/customization/mcp-servers).
This repository includes a reference [`.vscode/mcp.json`](.vscode/mcp.json).

To add the server to a project, copy `.vscode/mcp.json` to the same location in
your target project. If your project already has a `.vscode/mcp.json`, merge the
`mapi` entry into it. To apply it across all projects in a
[VS Code profile](https://code.visualstudio.com/docs/configure/profiles), place
the file in the profile directory instead.

Once configured, open the Copilot Chat window, start the server, and use the tool
picker to enable the `mapi` server. See the
[official documentation](https://code.visualstudio.com/docs/copilot/customization/mcp-servers#_use-mcp-tools-in-chat)
for details.

VS Code supports prompted input via `${input:promptString}`. The included
`.vscode/mcp.json` prompts for `MAYHEM_TOKEN` and `MAYHEM_URL` on first use
and stores them in VS Code's secret storage.

### Use with Cursor

Add the following to `.cursor/mcp.json` in your project (or `~/.cursor/mcp.json`
for global access):

```json
{
  "mcpServers": {
    "mayhem": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "--network", "host",
        "-e", "MAYHEM_URL",
        "-e", "MAYHEM_TOKEN",
        "ghcr.io/forallsecure/mcp-server-mayhem:latest",
        "uv", "run", "mcp-server-mayhem", "mcp"
      ]
    }
  }
}
```

Both come from the host environment via the `-e` flags in the Docker args.
Cursor does not support prompted input. Export both before launching:

```sh
export MAYHEM_TOKEN=your-token-here
export MAYHEM_URL=https://app.mayhem.security
```

Add these lines to your shell startup file (`~/.zshrc`, `~/.bashrc`, etc.) to
avoid setting them manually each session.

This repository also includes a reference [`.cursor/mcp.json`](.cursor/mcp.json).

### Use with Windsurf

Add the following to `.windsurf/mcp.json` in your project (or
`~/.codeium/windsurf/mcp_config.json` for global access):

```json
{
  "mcpServers": {
    "mayhem": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "--network", "host",
        "-e", "MAYHEM_URL",
        "-e", "MAYHEM_TOKEN",
        "ghcr.io/forallsecure/mcp-server-mayhem:latest",
        "uv", "run", "mcp-server-mayhem", "mcp"
      ]
    }
  }
}
```

Like Cursor, Windsurf picks up `MAYHEM_TOKEN` and `MAYHEM_URL` from the host
environment. Export both before launching:

```sh
export MAYHEM_TOKEN=your-token-here
export MAYHEM_URL=https://app.mayhem.security
```

This repository also includes a reference [`.windsurf/mcp.json`](.windsurf/mcp.json).

### Use with Claude Code

Add the following to `.mcp.json` at your project root (project-scoped), or
configure globally with `claude mcp add`:

```json
{
  "mcpServers": {
    "mayhem": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "--network", "host",
        "-e", "MAYHEM_URL",
        "-e", "MAYHEM_TOKEN",
        "ghcr.io/forallsecure/mcp-server-mayhem:latest",
        "uv", "run", "mcp-server-mayhem", "mcp"
      ]
    }
  }
}
```

Like Cursor and Windsurf, both come from the host shell. Export them before
launching:

```sh
export MAYHEM_TOKEN=your-token-here
export MAYHEM_URL=https://app.mayhem.security
```

> [!NOTE]
> Claude Code does not surface MCP prompts as slash commands. To run
> `/onboard-mapi-scan` or `/generate-exploit`, ask the model to invoke the prompt
> by name, or use the individual tools directly.

A reference `.mcp.json` is not included in this repository.

### Use with Claude Desktop

Add the following to your Claude Desktop config file.

**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "mayhem": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "--network", "host",
        "-e", "MAYHEM_URL",
        "-e", "MAYHEM_TOKEN",
        "ghcr.io/forallsecure/mcp-server-mayhem:latest",
        "uv", "run", "mcp-server-mayhem", "mcp"
      ]
    }
  }
}
```

Both come from the shell you launched Claude Desktop from. On macOS, start it
from a terminal with both exported:

```sh
export MAYHEM_TOKEN=your-token-here
export MAYHEM_URL=https://app.mayhem.security
open -a "Claude"
```

This repository includes a reference
[`claude_desktop_config.json`](./claude_desktop_config.json).

> [!NOTE]
> Claude Desktop does not surface MCP prompts as slash commands. To run
> `/onboard-mapi-scan` or `/generate-exploit`, ask the model to invoke the prompt
> by name, or use the individual tools directly.

## Local Development

This section describes how to acquire and run the code locally for development purposes.

### Dependencies

- [git](https://git-scm.com/)
- [uv](https://docs.astral.sh/uv/)

### Acquire the Code

Clone this repository:

```sh
git clone git@github.com:ForAllSecure/mcp-server-mayhem.git
```

### Run

Use uv to run the MCP server for `mapi`:

```sh
MAYHEM_TOKEN=your-token-here uv run mcp-server-mayhem mcp
```
