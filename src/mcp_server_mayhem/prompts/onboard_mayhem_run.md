You are following a simplified mayhem onboarding flow.
Complete each step in order. Surface progress to the user as you go.
There is no tuning loop and no exploit-generation step here - this flow ends
once a run is confirmed started/completed, or a blocking issue is surfaced.

**Run parameters:**
- url: <<url>>
- project: <<project>> (may be unknown yet - confirm with the user in Step 3 if so)
- target: <<target>> (may be unknown yet - confirm with the user in Step 3 if so)
- owner: <<owner>>

---

## Step 1 - Verify environment

Call `mayhem_list` (pass `owner = "<<owner>>"` if it is not "(none)").
Confirm the response lists projects/targets (or an empty-but-successful result) and
contains no authentication error.
If the call fails with an auth error, or a login token appears unset, tell the user
and stop.

## Step 2 - Assess repository layout (advisory)

This step reports and recommends. It never creates directories, moves files, or
writes configuration. Do not act on anything here without the user's explicit
agreement.

Mayhem's documentation specifies no required location for Mayhemfiles and says
nothing about repositories holding several of them, so this is a convention worth
offering, not a rule to enforce.

Inspect the repository with your own file-reading tools. The Mayhem tools run in a
container with no view of the user's working tree, so they cannot see it. Answer
three questions:

1. Are Mayhemfiles discoverable in a predictable location, or scattered?
2. Is each target's configuration separable from every other target's?
3. Is harness source distinct from Mayhem configuration?

Call `mayhem_check` with `file` set to the Mayhemfile paths you found - it accepts
several paths in one call - to confirm they are Mayhem-eligible.

If all three hold, say so and move on. Where one does not, show the layout below
and name which of the three properties it would fix:

```
mayhem/
├── target_1/
│   ├── Mayhemfile
│   └── testsuite/
└── Dockerfile
test/
└── harness/
    ├── some_harness.c
    └── CMakeLists.txt
```

The separation is the point; the exact directory names are not. Working
repositories use different trees, so do not present this as the correct one.

Where the language already has a convention, follow it instead of the tree above:
- **Go:** fuzz targets live in `_test.go` files via `testing.F`. There is no
  separate harness directory to recommend.
- **Rust:** `cargo-fuzz` standardizes `fuzz/fuzz_targets/`. Leave it as it is.

Then ask whether the user wants to reorganize. If they decline or do not answer,
continue with the layout as it stands - nothing later in this flow depends on it.
If they agree, make the changes with your own file tools; the Mayhem tools do not
move files.

## Step 3 - Diagnose target readiness (ask, don't assume or build)

Ask the user directly which of these best describes their target right now:
  (a) A Docker image is already built and available (locally or in a registry).
  (b) A local, unpackaged binary/target exists but has not been packaged for Mayhem yet.
  (c) No target has been built yet.

Prefer (a) when available - Mayhem fuzzes Docker image contents directly, so a
Docker-based target needs no local packaging step. (b) requires `mayhem_package`
first (Step 4). Confirm with the user rather than guessing from context.

**If (c): stop here.** Tell the user that building a fuzz harness, Dockerfile, or
target is out of scope for this flow - **never author one on the user's behalf**,
even if asked to help. Point them to `mayhem init` / `mayhem_init` as the tool for
scaffolding a Mayhemfile once they have something to package, and end the flow.

## Step 4 - Package the target if needed

If the user chose (b) in Step 3: call `mayhem_package` with `binary` set to the
local target path the user gave you. Capture the resulting package output
directory as `package_dir` and use it as the `package` argument in Steps 5-6.

If the user chose (a) (Docker image ready): no packaging call is needed here -
the image tag/hash itself is the `package` argument for Steps 5-6; `mayhem_run`
treats it as docker-backed automatically, no extra flag needed.

## Step 5 - Validate

If you have a packaged directory (from Step 4, or the user already had one):
call `mayhem_validate` with `package = <package_dir>` (add `owner = "<<owner>>"`
if set) to confirm the Mayhemfile is correct before running. If validation fails,
show the user exactly what failed and attempt the fix described in Step 9 before
proceeding.

If you are running directly against a Docker image tag with no package directory
(pure Docker path from Step 4), there is no Mayhemfile to validate - skip this
step and proceed to Step 6.

## Step 6 - Run the target

Before calling `mayhem_run`, determine whether a duration is already set for
this target: check `mayhem_validate`'s Step 5 output (or read `<package>/Mayhemfile`
directly) for an existing `duration` field. If none is set anywhere and you are
not passing one here, ask the user for a `duration` (in seconds) before running -
see Step 7 for why this matters.

Call `mayhem_run` with:
  package  = <package_dir, or the Docker image tag/hash from Step 4>
  duration = <seconds, if known or just obtained from the user>
  project  = "<<project>>" (if known)
  target   = "<<target>>" (if known)
  owner    = "<<owner>>" (if set)

Capture the run identifier from the output - you will need it for Step 7.

## Step 7 - Monitor for completion

First check whether a duration is known for this run: passed to `mayhem_run` in
Step 6, or already present in the Mayhemfile (per the Step 6 check).

- **Duration known:** call `mayhem_wait` with `run = <run identifier from Step 6>`.
  Use the default `poll_timeout_s` (1800s / 30 minutes) unless the duration is
  expected to exceed it, in which case set `poll_timeout_s` higher up front
  rather than waiting for a timeout to occur. Once `mayhem_wait` returns, present
  the result to the user: whether the run completed, and (if `fail_on_defects`
  was used) whether defects were present.
- **No duration known:** do not call `mayhem_wait` - the run has no natural end,
  so the call would just consume the full `poll_timeout_s` waiting for something
  that never happens. Instead, tell the user the run is open-ended/continuous,
  call `mayhem_show` with the run identifier for a non-blocking status snapshot,
  and mention `mayhem_stop` as how they end it whenever they're ready.

`mayhem_show` is always safe to call on demand for a non-blocking snapshot,
regardless of whether a duration is set.

## Step 8 - Offer to make the run repeatable (CI/CD)

Only reach this step once a run has actually worked. A pipeline that encodes a
broken invocation is worse than no pipeline.

Ask whether the user wants CI/CD configuration that reruns this automatically. If
they decline, go to Step 10.

Establish each of these, confirming rather than guessing:
- Which platform. Exactly one of `github-actions`, `gitlab-ci`, `jenkins`, or
  `azure-devops`; no other value is accepted.
- Which Mayhemfiles to run, from Step 2. Each becomes one parallel leg.
- The per-target duration. Reuse the duration from Step 6 unless the user wants a
  different one for CI.
- Whether a Docker image already exists. Prefer one that does, and only build in
  the pipeline when there is genuinely no published image.

Then call `emit_cicd_config` with:
  platform          = <one of the four values above>
  mayhemfiles       = <list of Mayhemfile paths>
  duration          = <"300s", "5m", or a bare "300" meaning seconds>
  image             = <image reference, if one exists>
  include_build_job = <true only if the pipeline must build the image itself>
  dockerfile        = <path to an existing Dockerfile; used only when include_build_job is true>
  build_context     = <build context directory; used only when include_build_job is true>
  mayhem_url        = "<<url>>" (omit to use the default Mayhem service)
  workflow_name     = <display name for the pipeline>

`image` is required whenever `include_build_job` is true - the build job needs a
tag to push.

If no Dockerfile exists, say so and leave `include_build_job` false. Writing one
is outside what these tools do; the user can add it and rerun this step.

`emit_cicd_config` returns the configuration as text and writes nothing. Show it
to the user, agree where it should live, and write it with your own file tools -
the Mayhem tools cannot write into the repository. Do not write it anywhere
without the user's agreement.

Tell the user to add `MAYHEM_TOKEN` to their platform's secret store. The
generated configuration references it from there and never contains the value.

## Step 9 - Fix obvious errors

When any tool call in Steps 1-8 fails, distinguish two categories:

**Fixable invocation mistakes - retry once with a corrected parameter:**
- A malformed `--duration` value.
- A missing required Mayhemfile field that `mayhem_validate` already reported.
- An ambiguous project/target that needs `owner` to disambiguate.
- A `mayhem_wait` call that timed out locally because the run's configured
  duration exceeds the default `poll_timeout_s` - retry with a larger
  `poll_timeout_s`, not by giving up or asking the user to intervene.

**Platform-side or environment issues - surface to the user, do not guess further:**
- Authentication or network failures.
- Host environment problems (e.g. a broken system library or shell) unrelated
  to the Mayhemfile or run arguments.
- Account or permission errors.

Retry the fixable category at most once per failure. For the platform-side
category, stop and clearly explain what failed and why it requires the user's
attention.

## Step 10 - Summary

Present a final summary to the user:
1. Whether the run started successfully and its identifier.
2. The final status from `mayhem_wait`/`mayhem_show` (completed / defects present / stopped).
3. Whether CI/CD configuration was generated, and where it was written.
4. Any issues hit along the way and how they were resolved (or why they were
   surfaced instead of retried).

---

**Important implementation notes:**
- This prompt intentionally has no iterative coverage-tuning loop and no
  exploit-generation step - those are `mapi`-specific (`onboard-mapi-scan`)
  and have no mayhem equivalent. End the flow once a run is confirmed
  started/completed, or a blocking issue has been surfaced.
- Never author a fuzz harness, Dockerfile, or Mayhemfile `cmds` entry on the
  user's behalf. If the target isn't built yet, stop at Step 3 and say so.
- A bare Docker image tag/hash used directly as `package` (no packaged
  directory) - do not also call `mayhem_package` or `mayhem_validate` against
  it; those operate on a packaged directory containing a Mayhemfile.
- `poll_timeout_s` on `mayhem_wait` is a local Python-side timeout controlling
  how long the tool call itself blocks - it is independent of the platform's
  own `--duration` for the run. Raise it proactively when a long duration is
  known upfront, per Step 7.
- Never call `mayhem_wait` on a run with no duration set anywhere (not passed
  to `mayhem_run`, not present in the Mayhemfile) - it will never complete on
  its own, and the call would just burn the full `poll_timeout_s` for nothing.
  Use `mayhem_show` for status on these runs instead, per Step 7.
- Only retry the "fixable invocation mistake" category from Step 9, and only
  once per failure. Platform-side/environment issues always go to the user.
- Steps 2 and 8 need to see or change the user's repository. The Mayhem server
  runs in a container with no access to it, so use your own file tools for both.
