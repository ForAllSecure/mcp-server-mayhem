# MCP Server for `mapi`

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server for
the [Mayhem for API](https://docs.mayhem.security/api-testing/summary/) CLI
(`mapi`)

> [!NOTE]
> The code in this repository is provided as-is and is intended only for
> demonstration purposes. This project is not officially supported or actively
> maintained.

## Capabilities

The MCP server for `mapi` supports the following capabilities:

### `mapi discover`

Discover APIs running on a single host, multiple hosts, CIDR blocks, or domains.

### `mapi run`

Run a scan to check an API for defects.

### Capability 1 - Agentic Onboarding & Tune Loop

The `/onboard-mapi-scan` prompt orchestrates an end-to-end fuzzing onboarding
workflow: it verifies your environment, runs an initial scan, evaluates endpoint
coverage, suggests configuration improvements, iterates until coverage meets a
target threshold or the iteration limit is reached, and emits a final bash script
you can commit to CI.

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
| `api_target` | yes | - | Mayhem project target (e.g. `myorg/api`) |
| `specification` | yes | - | Path to an OpenAPI/Swagger/Postman spec file |
| `url` | yes | - | Base URL of the API under test |
| `duration` | no | `30s` | Initial scan duration |
| `max_iterations` | no | `3` | Maximum tune-loop iterations |
| `min_covered_pct` | no | `25` | Coverage threshold that stops the loop early |

The `--har` flag is handled automatically - HAR output is written to `/tmp` and
threaded through `evaluate_scan_quality` without any manual configuration.

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
definitions, seed files), reads them, and generates a small number
of targeted hints. It also detects code patterns (SQL queries, subprocess calls,
file operations, PII fields) and suggests enabling the corresponding mapi rules.

No additional prompt invocation is needed - it is part of the standard
`/onboard-mapi-scan` flow.

**Fuzziness guardrail:**

- `--resource-hint` and `--include-rule` suggestions are applied without extra
  confirmation - they expand mapi's reach, not narrow it
- Any suggestion involving `--ignore-endpoint`, `--ignore-endpoints-by-tag`, or
  `--ignore-rule` carries a `[FUZZING NARROWING WARNING]` and requires explicit
  confirmation before it is applied
- Resource hints are capped at 3–5 per session to preserve fuzzer input entropy
  (mapi applies hints on the majority of generated requests)

**`.mapi` config file:**

At the end of the flow, the prompt optionally offers to generate a `.mapi` YAML
config file via `emit_mapi_config`. This is most useful when you need correlated
parameter groups (multiple parameters seeded together consistently) or want to
commit suppressions to source control for team sharing. For one-off scans, the
emitted bash script is sufficient.

### Capability 3 — Exploit Generation

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
| `run_id` | yes | — | Mayhem run ID containing the defects (e.g. `myorg/api/42`) |
| `url` | yes | — | Base URL of the API under test |
| `specification` | no | `""` | Spec path for endpoint context |
| `source_dir` | no | `""` | Source root for higher-fidelity exploit crafting |
| `output_path` | no | `exploit-report.md` | Path for the leave-behind report |

**Leave-behind tool:**

`emit_exploit_report` generates a markdown file with one section per defect:
the reproducing request, the suggested exploit, and source code references if
available.

**Safety boundary:**

- The server never issues HTTP requests to the API — the exploit suggestion is
  text only; the user manually copies and runs it
- Any suggestion that would mutate or delete server state (account changes, data
  deletion, DoS) is tagged **`[DESTRUCTIVE]`** and requires explicit user
  confirmation before it is included in the report
- Credentials or tokens observed in defect data are replaced with typed
  placeholders (`<BEARER_TOKEN>`, `<PASSWORD>`, etc.) — real values are never
  written to the report
- Safety warnings appear at four points: prompt start, before each exploit is
  crafted, at the destructive-action gate, and after the report is generated

## Usage

MCP servers are designed to be used with AI applications like Claude, Cursor, or
ChatGPT. This usage guide explains how to use this project with AI applications.

### Dependencies

- [Docker](https://docs.docker.com/get-started/get-docker/)

#### Login to the GitHub Container Registry

If necessary, follow
[the steps](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#authenticating-with-a-personal-access-token-classic)
to authenticate to the GitHub Container registry with a personal access token
(classic). Only the `read:packages` scope is required to use this project.

> [!NOTE]
> To check login status, run `docker login ghcr.io`.

### Use with Visual Studio Code

Visual Studio Code provides
[native support](https://code.visualstudio.com/docs/copilot/customization/mcp-servers)
for MCP servers and this project includes a file
([`.vscode/mcp.json`](.vscode/mcp.json)) that can be used to configure Visual
Studio Code to use the MCP server for `mapi`.

> [!NOTE]
> The next paragraph describes how to add the MCP server for `mapi` to a single
> project or a profile in Visual Studio Code. These steps are also outlined in
> the
> [official documentation](https://code.visualstudio.com/docs/copilot/customization/mcp-servers#_other-options-to-add-an-mcp-server)
> for using MCP servers with Visual Studio Code.

To add the MCP server for `mapi` to a single Visual Studio Code project, copy
the `.vscode/mcp.json` file to the same location in the target project; or, if
the target project is already configured to use other MCP servers, add the
details from the `.vscode/mcp.json` file provided in this project to the
`.vscode/mcp.json` file for the target project. To add the MCP server for `mapi`
to all Visual Studio Code projects associated with a
[profile](https://code.visualstudio.com/docs/configure/profiles) add the
`.vscode/mcp.json` file to the target profile's directory; or, if the target
profile is already configured to use other MCP servers, add the details from the
`.vscode/mcp.json` file provided in this project to the `mcp.json` file for the
target profile.

Once the MCP server for `mapi` has been added to a project or profile, start the server and open your default chat window. Then use the tool picker to enable the MCP server for `mapi`. These steps are outlined in the [official documentation](https://code.visualstudio.com/docs/copilot/customization/mcp-servers#_use-mcp-tools-in-chat) for using MCP servers with Visual Studio code.

### Use with Cursor

Add the following to `.cursor/mcp.json` in your project (or `~/.cursor/mcp.json`
for global access):

```json
{
  "mcpServers": {
    "mapi": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "--network", "host",
        "-e", "MAYHEM_TOKEN",
        "ghcr.io/forallsecure/mcp-server-mapi:latest",
        "uv", "run", "mcp-server-mapi", "mcp"
      ]
    }
  }
}
```

`MAYHEM_TOKEN` is passed through from the host environment - Cursor does not
support prompted input like VS Code does. Export the token in your shell before
launching Cursor:

```sh
export MAYHEM_TOKEN=your-token-here
```

Add this line to your shell startup file (`~/.zshrc`, `~/.bashrc`, etc.) to
avoid setting it manually each session.

A reference [`.cursor/mcp.json`](.cursor/mcp.json) file is also included in this
repository.

### Use with Windsurf

Add the following to `.windsurf/mcp.json` in your project (or
`~/.codeium/windsurf/mcp_config.json` for global access):

```json
{
  "mcpServers": {
    "mapi": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "--network", "host",
        "-e", "MAYHEM_TOKEN",
        "ghcr.io/forallsecure/mcp-server-mapi:latest",
        "uv", "run", "mcp-server-mapi", "mcp"
      ]
    }
  }
}
```

Like Cursor, Windsurf inherits `MAYHEM_TOKEN` from the host environment. Export
it in your shell before launching Windsurf:

```sh
export MAYHEM_TOKEN=your-token-here
```

A reference [`.windsurf/mcp.json`](.windsurf/mcp.json) file is also included in
this repository.

### Use with Claude

If you're using Claude Desktop you can hook the MCP server to it using the
[`claude_desktop_config.json`](./claude_desktop_config.json) file - just make
sure you include your API token in it.

## Local Development

This section describes how to acquire and run the code locally for development purposes.

### Dependencies

- [git](https://git-scm.com/)
- [uv](https://docs.astral.sh/uv/)

### Acquire the Code

Clone this repository:

```sh
git clone git@github.com:ForAllSecure/mcp-server-mapi.git
```

### Run

Use uv to run the MCP server for `mapi`:

```sh
MAYHEM_TOKEN=your-token-here uv run mcp-server-mapi mcp
```
