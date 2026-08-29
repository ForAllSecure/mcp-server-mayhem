You are following a simplified mayhem onboarding flow.
Complete each step in order. Surface progress to the user as you go.
There is no tuning loop and no exploit-generation step here - this flow ends
once a run is confirmed started/completed, or a blocking issue is surfaced.

**Run parameters:**
- url: <<url>>
- project: <<project>> (may be unknown yet - confirm with the user in Step 2 if so)
- target: <<target>> (may be unknown yet - confirm with the user in Step 2 if so)
- owner: <<owner>>

---

## Step 1 - Verify environment

Call `mayhem_list` (pass `owner = "<<owner>>"` if it is not "(none)").
Confirm the response lists projects/targets (or an empty-but-successful result) and
contains no authentication error.
If the call fails with an auth error, or a login token appears unset, tell the user
and stop.

## Step 2 - Diagnose target readiness (ask, don't assume or build)

Ask the user directly which of these best describes their target right now:
  (a) A Docker image is already built and available (locally or in a registry).
  (b) A local, unpackaged binary/target exists but has not been packaged for Mayhem yet.
  (c) No target has been built yet.

Prefer (a) when available - Mayhem fuzzes Docker image contents directly, so a
Docker-based target needs no local packaging step. (b) requires `mayhem_package`
first (Step 3). Confirm with the user rather than guessing from context.

**If (c): stop here.** Tell the user that building a fuzz harness, Dockerfile, or
target is out of scope for this flow - **never author one on the user's behalf**,
even if asked to help. Point them to `mayhem init` / `mayhem_init` as the tool for
scaffolding a Mayhemfile once they have something to package, and end the flow.

## Step 3 - Package the target if needed

If the user chose (b) in Step 2: call `mayhem_package` with `binary` set to the
local target path the user gave you. Capture the resulting package output
directory as `package_dir` and use it as the `package` argument in Steps 4-5.

If the user chose (a) (Docker image ready): no packaging call is needed here -
the image tag/hash itself is the `package` argument for Steps 4-5, and `mayhem_run`
will be called with `docker = true`.

## Step 4 - Validate

If you have a packaged directory (from Step 3, or the user already had one):
call `mayhem_validate` with `package = <package_dir>` (add `owner = "<<owner>>"`
if set) to confirm the Mayhemfile is correct before running. If validation fails,
show the user exactly what failed and attempt the fix described in Step 6 before
proceeding.

If you are running directly against a Docker image tag with no package directory
(pure Docker path from Step 3), there is no Mayhemfile to validate - skip this
step and proceed to Step 5.

## Step 5 - Run the target

Call `mayhem_run` with:
  package = <package_dir, or the Docker image tag/hash from Step 3>
  docker  = <true only if running directly against a Docker image tag/hash>
  project = "<<project>>" (if known)
  target  = "<<target>>" (if known)
  owner   = "<<owner>>" (if set)

Capture the run identifier from the output - you will need it for Step 6.

## Step 6 - Monitor for completion

Call `mayhem_wait` with `run = <run identifier from Step 5>`.
Use the default `poll_timeout_s` (1800s / 30 minutes) unless the target's
configured `--duration` is expected to exceed it, in which case set
`poll_timeout_s` higher up front rather than waiting for a timeout to occur.

If you need a snapshot of run status without blocking further, use `mayhem_show`
with the same run identifier instead.

Once `mayhem_wait` returns, present the result to the user: whether the run
completed, and (if `fail_on_defects` was used) whether defects were present.

## Step 7 - Fix obvious errors

When any tool call in Steps 1-6 fails, distinguish two categories:

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

## Step 8 - Summary

Present a final summary to the user:
1. Whether the run started successfully and its identifier.
2. The final status from `mayhem_wait`/`mayhem_show` (completed / defects present / stopped).
3. Any issues hit along the way and how they were resolved (or why they were
   surfaced instead of retried).

---

**Important implementation notes:**
- This prompt intentionally has no iterative coverage-tuning loop and no
  exploit-generation step - those are `mapi`-specific (`onboard-mapi-scan`)
  and have no mayhem equivalent. End the flow once a run is confirmed
  started/completed, or a blocking issue has been surfaced.
- Never author a fuzz harness, Dockerfile, or Mayhemfile `cmds` entry on the
  user's behalf. If the target isn't built yet, stop at Step 2 and say so.
- `docker = true` on `mayhem_run` means the `package` argument is a Docker
  image tag/hash, not a directory - do not also call `mayhem_package` or
  `mayhem_validate` against a bare image tag; those operate on a packaged
  directory containing a Mayhemfile.
- `poll_timeout_s` on `mayhem_wait` is a local Python-side timeout controlling
  how long the tool call itself blocks - it is independent of the platform's
  own `--duration` for the run. Raise it proactively when a long duration is
  known upfront, per Step 6.
- Only retry the "fixable invocation mistake" category from Step 7, and only
  once per failure. Platform-side/environment issues always go to the user.
