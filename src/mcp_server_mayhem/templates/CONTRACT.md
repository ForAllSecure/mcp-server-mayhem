# CI/CD template placeholder contract

Every file in this directory is rendered by the `emit_cicd_config` tool in
`../mayhem_tools.py`. This document defines the placeholders a template may use,
the exact format of the value each one receives, and the rules a template author
must follow. It is the contract between the tool and the four platform templates.

Templates are plain text. Rendering is `_render` in `../common.py`, which performs
literal `str.replace` of `<<name>>` tokens. **There is no template engine.** There
are no loops, no conditionals, no expressions, and no filters. Anything requiring
logic is computed in the tool and arrives as a finished value.

## Substitution model

Two mechanisms, and only two:

1. **`<<name>>` tokens** are replaced by their value. Substitution is literal and
   context-free — it happens whether the token sits in a comment, a quoted string,
   or a YAML key.
2. **`<<#build_job>> ... <</build_job>>` regions** are kept or removed as a unit by
   `_optional_region` in `../common.py`. See "Conditional regions" below.

A `<<name>>` token that the tool does not supply is left in the output verbatim.
Nothing warns you. A typo'd placeholder therefore ships a literal `<<typo>>` into
the user's pipeline file — check your rendered output rather than assuming.

## The list-to-syntax decision

**The tool performs the transformation, not the template.** This is forced rather
than chosen: `_render` cannot iterate, so a template physically cannot turn a list
of paths into a sequence.

`<<targets_list>>` therefore arrives as a **JSON array on a single line**, produced
by `json.dumps`:

```
["mayhem/Mayhemfile.server", "mayhem/Mayhemfile.client"]
```

This one form is valid in all four platforms, because a JSON array is
simultaneously a YAML flow sequence and a Groovy list literal. Use it inline:

```yaml
        mayhemfile: <<targets_list>>          # GitHub Actions matrix
      - MAYHEMFILE: <<targets_list>>          # GitLab parallel:matrix
```

```groovy
    def mayhemfiles = <<targets_list>>        // Jenkins
```

A single-line flow form was chosen deliberately over an indented block sequence.
A pre-rendered multi-line block only receives indentation on its first line, so
every template embedding one would have to agree with the tool on an exact indent
column. The flow form removes that coupling: it is correct at any indentation.

Element values are escaped by `json.dumps`, so paths containing quotes or
backslashes are safe. Do not add your own quoting around the placeholder — it is
already a complete, quoted array.

**Known limitation, Azure DevOps.** Azure's `strategy: matrix:` takes a *mapping*
of named legs, not a sequence, so `<<targets_list>>` will not drop into it the way
it does for GitHub and GitLab. Consuming it through a `parameters` object with an
`${{ each }}` expression is the expected route. If that proves unworkable, report a
gap rather than inventing a second placeholder — see "Reporting a gap".

## Placeholders

Every placeholder below is always substituted; none are ever absent. Optional
inputs that the caller omitted arrive as an **empty string**, not as the token and
not as the word "None". A template that must degrade gracefully should account for
an empty value.

| Placeholder | Format | Meaning |
|---|---|---|
| `<<workflow_name>>` | plain scalar, defaults to `Mayhem` | Display name for the pipeline. Unquoted and unescaped — do not use it where a YAML special character would break parsing. |
| `<<targets_list>>` | **pre-rendered** JSON array, single line | The Mayhemfile paths driving fan-out. Never empty; the tool rejects an empty list. |
| `<<duration_seconds>>` | bare integer, no unit suffix | Per-target run duration in seconds. `300`, not `300s` and not `5m`. Append a literal `s` yourself if your platform's flag wants one. |
| `<<image>>` | plain scalar, may be empty | Docker image reference the fuzz job runs. When `include_build_job` is set this is also the tag the build job pushes. |
| `<<token_secret_ref>>` | **pre-rendered** platform-specific expression | How this platform references the Mayhem token from its secret store. See below. |
| `<<mayhem_url>>` | plain scalar, may be empty | Mayhem API URL, for self-hosted installs. Empty means the CLI default applies. |
| `<<dockerfile>>` | plain scalar, defaults to `Dockerfile` | Dockerfile path for the build job. Meaningless when the build region is dropped. |
| `<<build_context>>` | plain scalar, defaults to `.` | Docker build context for the build job. Meaningless when the build region is dropped. |

### `<<token_secret_ref>>`

This is pre-rendered because getting it wrong has a security consequence, and four
authors independently inventing a token reference is exactly how a literal token
ends up in a generated file. Values by platform:

| Platform | Value | Requires |
|---|---|---|
| `github-actions` | `${{ secrets.MAYHEM_TOKEN }}` | repository or org secret named `MAYHEM_TOKEN` |
| `gitlab-ci` | `$MAYHEM_TOKEN` | masked CI/CD variable named `MAYHEM_TOKEN` |
| `jenkins` | `$MAYHEM_TOKEN` | credentials binding, e.g. `credentials('mayhem-token')` |
| `azure-devops` | `$(MAYHEM_TOKEN)` | secret pipeline variable named `MAYHEM_TOKEN` |

**A rendered template containing a real token value is a defect**, regardless of
how it got there. Never write a token literal into a template, and never echo the
token in a pipeline step — CI logs are frequently world-readable. Assign it to an
environment variable and let the CLI read it.

## Conditional regions

`include_build_job` cannot be expressed by substitution, so the build job is
wrapped in a region:

```yaml
<<#build_job>>
  build:
    ...
<</build_job>>
```

Both markers must sit on their own line. Leading whitespace on a marker line is
allowed and ignored. The whole marker line — including its newline — is consumed,
so dropping a region leaves no stray blank line and keeping one leaves no stray
marker. Regions do not nest, and `build_job` is currently the only region name
defined.

Everything the build job needs must live inside the region. A template that
references `<<image>>` outside the region still renders when the region is
dropped, which is intended — the fuzz job needs the image regardless of whether
this pipeline built it.

## Platform-to-file mapping

| `platform` value | File |
|---|---|
| `github-actions` | `github-actions.yml` |
| `gitlab-ci` | `gitlab-ci.yml` |
| `jenkins` | `jenkins.groovy` |
| `azure-devops` | `azure-devops.yml` |

The mapping is an explicit dict in `../mayhem_tools.py`. Adding a platform means
adding a `Literal` value, a dict entry, a `<<token_secret_ref>>` value, and a file.

## Scope boundary

These templates generate configuration that **invokes the Mayhem CLI or its
official GitHub Action**. They do not author fuzz harnesses and do not author
Dockerfiles. A template that emits a `Dockerfile` heredoc or a harness source file
is out of scope for this server, even though the agent driving it may write those
freely by other means.

## Reporting a gap

If you need something this contract does not provide, **report the gap — do not
invent a placeholder.** An undeclared `<<token>>` is not an error; it is silently
passed through into the user's pipeline file, so an invented placeholder fails
quietly and ships broken output.

A gap report should state: the platform, what the template needs to express, why
an existing placeholder cannot carry it, and what value format would work. Adding
a placeholder is a change to this file plus the tool's render call, and it affects
every template — so it goes through review rather than being added locally.
