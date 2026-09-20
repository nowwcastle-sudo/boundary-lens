# Local incident companion (source-build candidate)

## Physical output boundary and failure classification

The writer checks both the declared paths and their current local physical
targets before creating an output. It inspects supported local directory-link
targets before following them and rejects unknown or remote targets. A missing
failed target is allowed only when its nearest existing parent can be verified;
the missing suffix remains part of the excluded boundary. Known NT physical
paths saved in the core report are additional exclusions, not authenticated
proof of current identity or report origin. If the real workspace boundary
cannot be established, companion export is unavailable with
INCIDENT_OUTPUT_INVALID and exit 2. The original core report remains usable
and its UNKNOWN evidence is unchanged. This fail-closed choice can prevent a
handoff for some incomplete core reports.

A locked or unreadable valid input returns fixed INCIDENT_FILE_IO_FAILED and
exit 1. Invalid paths, schemas and resource limits remain exit 2. A failure
after a fresh output file is opened retains the partial artifact. Physical
checks are repeated before creation and the opened output path is checked
before bytes are written; privileged namespace replacement between these
steps is outside the guarantee.

HTML has separate core-evidence, core-results, incident-context, observation
and handoff-summary tables. The core-results table keeps minimized result
status and reason code, so a cause-candidate stays distinct from a proved
cause; UNKNOWN remains visible. The observation table shows source, status
and observed-at time, with unavailable shown for a null time. Every variable
cell is HTML-encoded; the page has no script, form, external asset or
automatic request.

The companion consumes an explicitly saved `BoundaryLens.ps1 -Format Json` report. It does not run the original collector, another product, a URI request, or a repair. Keep the full core report and incident input locally. The published `v0.2.0-experimental.1` ZIP is unchanged and does not contain this companion.

Run these lines in PowerShell 7 from a source-build candidate directory containing all five runtime files. `$existingReport` must be a full saved core JSON report produced by the original diagnostic. `$boundaryOutput` must be a separate local directory outside the investigated paths.

```powershell
$incidentPath = Join-Path $boundaryOutput ("incident-$([guid]::NewGuid().ToString('N')).json")
if (Test-Path -LiteralPath $incidentPath) { throw 'Incident file exists; stop.' }
[IO.File]::WriteAllText($incidentPath, '{"schema":"boundary-incident/1","product":"synthetic example"}', [Text.UTF8Encoding]::new($false))
$handoffPath = Join-Path $boundaryOutput ("handoff-$([guid]::NewGuid().ToString('N')).json")
pwsh -NoProfile -NonInteractive -File .\BoundaryIncident.ps1 -CoreReport $existingReport -Incident $incidentPath -Output $handoffPath -Format Json
$handoffExit = $LASTEXITCODE
$handoffExit
```

The incident file may also have `version`, `error_code`, `occurred_at` (UTC), `runtime_uri`, one positive `process_id`, and `supplied_observations` (`filter` or `runtime`, each with `value` and nullable UTC `observed_at`). Optional repeated `-LogPath FILE` pairs select local JSON or JSONL logs. Only their `error_code`, `occurred_at`, `component`, and `level` fields are read into the working model; messages are not copied. URI text is parsed for syntax only. No logs are found automatically. `-Format Html` writes static HTML with encoded content, inline style, and no scripts, forms, external assets, or automatic requests.

Exit `0` means the requested handoff was written with no unavailable optional observation. Exit `1` means collection/export failed or an incomplete handoff was written; inspect whether a new output file exists and retain it. Exit `2` means usage, schema, or path rejection. Fixed support codes do not include raw exception details. No output file is silently replaced.

The export envelope contains only `core_summary`, `incident_context`, `observations`, and `handoff_summary`. The core report's raw paths, identity fingerprints, descriptions, and next-observation prose are not copied. Known public result/failure codes and observation status/error codes are retained; unrecognized codes become `UNRECOGNIZED_CODE`. Investigated paths become `workspace` and `failed-target`. Product, version, arbitrary error, process name/PID, filter, runtime, and log strings become local aliases or presence indicators. That privacy choice loses the original product/error detail from the default shared handoff. Keep that detail in the separate local input, and disclose it only through a separately approved route. Supplied metadata remains labelled `operator-supplied`; it cannot establish observed runtime enforcement, safety, or cause. `RUNTIME_ENFORCEMENT_UNKNOWN` remains visible. The file is minimized, not anonymous: timestamps and filesystem size may identify an incident. A generic string cannot be guaranteed secret-free if copied outside the allowlist. Review the actual output before sharing.

Input files must be explicit, local, regular, and unchanged during each bounded read. Each is limited to 1 MiB; selected logs total at most 4 MiB and 10,000 records. JSON nesting, nodes, and strings are also bounded. The writer requires a fresh output path outside the investigated paths, rejects existing files and reparse ancestors, and uses an exclusive create. It validates paths again immediately before opening and verifies the opened destination path before writing. These checks do not prove atomic state against arbitrary privileged filesystem or namespace replacement. Preserve failed artifacts and original evidence. The tool makes no claim of network isolation for the whole PowerShell process; use a separately verified external boundary if that is required.
