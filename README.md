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

### Capability 1 — Agentic Onboarding & Tune Loop

The `/onboard-mapi-scan` prompt orchestrates an end-to-end fuzzing onboarding
workflow: it verifies your environment, runs an initial scan, evaluates endpoint
coverage, suggests configuration improvements, iterates until coverage meets a
target threshold or the iteration limit is reached, and emits a final bash script
you can commit to CI.

**Tools used:**

- `evaluate_scan_quality` — parses the HAR output and spec to compute endpoint
  coverage (`covered_pct`), surface auth hints, and identify unreachable endpoints
- `suggest_tune_changes` — applies heuristic rules (auth headers, request count,
  duration, endpoint exclusions, validation errors) to propose the next tuning step
- `emit_scan_script` — writes a `set -euo pipefail` bash script with all finalized
  flags and env-var guards for the leave-behind artifact

**Invoking the prompt:**

In your MCP client, invoke `/onboard-mapi-scan` with the following arguments:

| Argument | Required | Default | Description |
|---|---|---|---|
| `api_target` | yes | — | Mayhem project target (e.g. `myorg/api`) |
| `specification` | yes | — | Path to an OpenAPI/Swagger/Postman spec file |
| `url` | yes | — | Base URL of the API under test |
| `duration` | no | `30s` | Initial scan duration |
| `max_iterations` | no | `3` | Maximum tune-loop iterations |
| `min_covered_pct` | no | `25` | Coverage threshold that stops the loop early |

The `--har` flag is handled automatically — HAR output is written to `/tmp` and
threaded through `evaluate_scan_quality` without any manual configuration.

> [!NOTE]
> Any suggestion to add `--ignore-endpoint` (which narrows the fuzzer's attack
> surface) will be surfaced with a `[FUZZING NARROWING WARNING]` and requires
> explicit confirmation before it is applied.

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

Once the MCP server for `mapi` has been added to a project or profile, open the
Chat view and use the tool picker to enable the MCP server for `mapi`. These
steps are outlined in the
[official documentation](https://code.visualstudio.com/docs/copilot/customization/mcp-servers#_use-mcp-tools-in-chat)
for using MCP servers with Visual Studio code.

### Use with Cursor

Add the following to `.cursor/mcp.json` in your project (or `~/.cursor/mcp.json`
for global access), replacing `your-token-here` with your Mayhem API token:

```json
{
  "mcpServers": {
    "mapi": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "MAYHEM_TOKEN",
        "ghcr.io/forallsecure/mcp-server-mapi:latest",
        "uv", "run", "mcp-server-mapi", "mcp"
      ],
      "env": {
        "MAYHEM_TOKEN": "your-token-here"
      }
    }
  }
}
```

A reference [`.cursor/mcp.json`](.cursor/mcp.json) file is also included in this
repository.

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
