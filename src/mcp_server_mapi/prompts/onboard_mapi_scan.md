You are following the mapi onboarding and tune loop for `<<workspace>>/<<project>>`.
Complete each step in order. Surface progress to the user as you go.

**Scan parameters:**
- workspace: <<workspace>>
- project: <<project>>
- target_name: <<target_name>>
- api_target: <<api_target>> (workspace/project[/target_name] — used in all mapi tool calls)
- specification: <<specification>>
- url: <<url>>
- duration: <<duration>> (initial - may change after tuning)
- max_iterations: <<max_iterations>>
- min_covered_pct: <<min_covered_pct>>%
- HAR output path: <<har_path>>

---

## Step 1 - Verify environment

Call `mapi_target_list` with default arguments (empty TargetListArgs).
Confirm the response lists at least one target and contains no authentication error.
If the call fails or MAYHEM_TOKEN appears unset, tell the user and stop.

## Step 2 - Confirm spec file

If `<<specification>>` starts with `http://` or `https://`, skip this step (the spec will be
fetched by mapi directly). Otherwise, call `read_file("<<specification>>")` to confirm the
file exists and looks like an OpenAPI/Swagger/Postman spec. If unreadable, tell the user
and stop.

## Step 2b - TLS state

Track a boolean `insecure = false` for the rest of this session.
You will set it to `true` only if Step 3 or Step 4 fails with a TLS or certificate error
(see Step 3 error handling below). Do nothing here - proceed to Step 3.

## Step 3 - Run initial scan

Call `mapi_run` with these arguments:
  api_target = "<<api_target>>"
  duration = "<<duration>>"
  specification = "<<specification>>"
  url = "<<url>>"
  har = "<<har_path>>"

Capture the full output as `scan_output`.
A non-zero mapi exit (exit code 1 = findings present) is normal - the output is still returned.
Exit codes 2 or 3 indicate real errors - surface them to the user and stop.

**TLS error handling (applies to Step 3 and all evaluate_scan_quality calls):**
If any tool call fails with an error mentioning TLS, certificate, "insecure", or
"self-signed":
- Do NOT attempt to download the spec to a local file as a workaround.
- Do NOT retry with a different spec path.
- Ask the user exactly this:
  "The target uses a self-signed or untrusted certificate. Proceed with TLS
   verification disabled? (yes/no)"
- If yes: set `insecure = true`. Pass `insecure = true` to every `evaluate_scan_quality`
  call for the rest of the session. Then retry the failed step with `insecure = true`.
- If no: stop and tell the user to configure a trusted certificate.

## Step 4 - Evaluate quality

Call `evaluate_scan_quality` with:
  scan_output = <full output from Step 3>
  har_path = "<<har_path>>"
  spec_path = "<<specification>>"
  insecure = <value of `insecure` set in Step 2b>

Also call `mapi_describe_specification` with:
  spec_path = "<<specification>>"
  insecure = <value of `insecure` set in Step 2b>
Store the raw text output as `spec_param_table` for use in Step 4.5.

Parse the evaluate_scan_quality JSON and show the user:
- covered_pct (% of spec endpoints with at least one 2xx response)
- total_endpoints and total_requests
- auth_hints (if non-empty - these indicate auth is blocking the fuzzer)
- unreachable_endpoints (if non-empty)

Store this quality JSON for Step 4.5 and Step 5.

## Step 4.5 - Source-aware seeding (optional)

After showing quality metrics, ask the user:
"Is source code for this API available locally? If so, I can look for fixture
data, enum definitions, or seed values to help mapi cover low-coverage endpoints."

If the user says yes or provides a path:

  a. Look at endpoint_stats from the quality JSON. Identify endpoints where
     ok_count == 0 and param_type includes PATH - these most need real entity values.
     Show the user the specific PATH parameters you found.

  b. Ask: "I found these PATH parameters that likely need real entity values:
     [list them]. Can you point me to files with valid values - fixture files,
     enum definitions, test seeds, or database seeders?"

  c. For each file path the user provides, call read_file(<path>) and extract values
     for the identified parameters. Also note any of these source patterns:
     - SQL query strings → add "sql" to source_patterns
     - subprocess/exec/system calls → add "subprocess" to source_patterns
     - File path operations (open, fs.read, os.path) → add "file_ops" to source_patterns
     - PII field names (ssn, email, dob, phone, nhs_number) → add "pii" to source_patterns
     - MongoDB/Redis/DynamoDB usage → add "nosql" to source_patterns

  d. Build source_context_json:
     {"param_name": ["value1", "value2"], ..., "__source_patterns__": [...]}

  e. Call `suggest_source_aware_changes` with:
       spec_output         = `spec_param_table` (from Step 4)
       source_context_json = <built above>
       current_args_json   = <JSON string of current_args>

  f. Present suggestions to the user:
     - For each `--resource-hint` suggestion: explain it seeds a specific parameter
       with a known-good value. Apply approved hints to current_args.
       **Do NOT apply more than 3-5 resource hints total** - too many compress
       the fuzzer's input entropy and reduce coverage diversity.
       **IMPORTANT: hint values must be concrete examples, not patterns or regexes.
       For example, use 'FLEET-NA-001' not 'FLEET-[A-Z]{2}-[0-9]{3}'.
       Extract a real value from the source file the user pointed to.**
     - For each `--include-rule` or `--experimental-rules` suggestion: apply directly
       to current_args (these expand detection, no confirmation needed).
     - For any `--ignore-rule` suggestion: show the [FUZZING NARROWING WARNING] and
       ask explicit yes/no before applying.
     - For informational suggestions (flag=null): note them to the user, no change.

If the user skips: proceed directly to Step 5.

## Step 5 - Tune loop (up to <<max_iterations>> total scan iterations)

Maintain `current_args` as a JSON object tracking the mapi_run arguments in use.
Start with: {"api_target": "<<api_target>>", "duration": "<<duration>>", "specification": "<<specification>>", "url": "<<url>>"}
Update it after each iteration when suggestions are applied.

The initial scan (Step 3) is iteration 1. For each subsequent iteration:

  a. Call `suggest_tune_changes` with:
       quality_json       = <JSON string from the most recent evaluate_scan_quality>
       current_args_json  = <JSON string of current_args>
       iteration          = <current iteration number>
       min_covered_pct    = <<min_covered_pct>>

  b. If `exhausted == true` OR iteration >= <<max_iterations>>: proceed to Step 6.

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
     har = "<<har_path>>". Capture the full output as scan_output.

  f. Call `evaluate_scan_quality` again with the new scan_output,
     har_path = "<<har_path>>", spec_path = "<<specification>>",
     insecure = <value of `insecure` from Step 2b>.
     Show the updated covered_pct and request count to the user.
     Increment the iteration counter and return to step (a).

## Step 6 - Emit scan script

Call `emit_scan_script` with:
  api_target      = "<<api_target>>"
  duration        = <final duration from current_args>
  specification   = "<<specification>>"
  url             = "<<url>>"
  har_output_path = "<<har_path>>"
  extra_flags     = <list of flag-value pairs from current_args that are not positional args,
                    in argv order - e.g. ["--header-auth", "Authorization: Bearer ${TARGET_API_TOKEN}",
                    "--min-request-count", "200"]>

**Before building extra_flags:** scan current_args for any header_auth, basic_auth, or
cookie_auth values. If a value does not already contain a `${VAR}` reference (i.e. it is
a literal token, password, or session string), replace it with the appropriate placeholder:
- Bearer/API key headers: `Authorization: Bearer ${TARGET_API_TOKEN}`
- Basic auth: `${TARGET_API_USER}:${TARGET_API_PASS}`
- Cookie auth: `${SESSION_COOKIE}`
Never write a literal credential value into extra_flags. The emitted script must read
secrets from the environment, not contain them inline.

Do not pass output_path - the script will be returned as text in the tool output.
Show the script to the user and tell them to save it to a file of their choosing.

After showing the script, ask:
"Would you like a .mapi config file for reuse or to commit to source control?
This is most useful if (a) you want correlated parameter groups - e.g., username
and userStatus always seeded together, or (b) you want to store suppressions in SCM
so the team shares the same ignore rules. If you just need to run the scan once,
the bash script is sufficient."

If yes: call `emit_mapi_config` with:
  resource_hint_groups = <list of hint groups - put correlated hints in the same group,
                          unrelated hints each in their own single-item group>
  suppressed_rules     = <list of any --ignore-rule values the user confirmed>
  (omit output_path - return as text so the user can save it)
Show the YAML and tell the user to save it as `.mapi` in their project root.

If no or skipping: proceed to Step 7.

## Step 7 - Summary

Present a final summary to the user:
1. Final quality metrics from the last evaluate_scan_quality: covered_pct, total_endpoints, total_requests.
2. Remind the user to save the script shown in Step 6 to a file (e.g. `mapi-scan.sh`).
3. How many iterations ran and what changed between them.
4. Any endpoints that remained unreachable (unreachable_endpoints from the last quality JSON).
5. If covered_pct < <<min_covered_pct>>% after <<max_iterations>> iterations:
   note that thresholds were not met and suggest the user review the script manually or
   run the loop again with a longer duration or higher max_iterations.

---

**Important implementation notes:**
- Always pass `har = "<<har_path>>"` to every mapi_run call. Without it, evaluate_scan_quality
  cannot parse the HAR and will fail.
- RunArgs has a `har` field directly - do not use extra_flags for the HAR path.
- The `current_args_json` for suggest_tune_changes should use Python-style snake_case key names
  matching RunArgs fields (e.g., "header_auth", "min_request_count", "duration").
- emit_scan_script's extra_flags takes argv-order tokens (["--flag", "value", ...]),
  not a dict. Construct this list from current_args before calling emit_scan_script.
- TLS errors: never work around them by downloading the spec to a local file.
  Always ask the user, then set `insecure = true` and retry with that flag.
  Once set, pass `insecure = true` to every evaluate_scan_quality and
  mapi_describe_specification call for the remainder of the session. Do not reset it.
- Step 4.5 resource hints: keep the total count at 3-5 maximum. More hints compress
  fuzzer entropy - mapi applies them on >90% of requests.
- suggest_source_aware_changes returns rule suggestions in the same schema as
  suggest_tune_changes. --include-rule and --experimental-rules need no confirmation;
  --ignore-rule always requires explicit yes/no (carries [FUZZING NARROWING WARNING]).
- emit_mapi_config is optional and conditional - only offer it when correlated groups
  or SCM-stored suppressions genuinely add value over the bash script alone.
- Auth values in extra_flags must always be env-var references (e.g. `${TARGET_API_TOKEN}`),
  never literal tokens or passwords. Replace any literal values before calling emit_scan_script.
  The emit_scan_script tool auto-generates :? env guards for every ${VAR} it detects.
