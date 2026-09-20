# Boundary Lens Incident Companion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Attach bounded incident, selected process/log/volume and URI evidence to existing path diagnostics and export a minimized local handoff.

**Architecture:** A separate companion consumes an explicitly saved core JSON report, avoiding any change to the core native collector or its read-only audit. Three companion modules handle strict input, observations and minimized export. Collection is local and opt-in; no child-product execution or repair.

**Tech Stack:** PowerShell 7, .NET built-ins, existing assertion-based PowerShell tests; no new dependencies or service.

**Spec:** `docs/superpowers/specs/2026-09-20-local-completion-design.md` (approved 2026-09-20).

## Global Constraints

- Preserve `BoundaryLens.ps1 -Workspace -FailedPath -Format`, schema 1, native source/hash and existing read-only gate. Do not add companion writes to the original collector's allowlist.
- Input files <=1 MiB each; aggregate logs <=4 MiB; <=10000 records; each string <=4096 characters. Reject duplicate JSON keys, unknown fields/schema, wrong types and excess resources without partial success.
- Explicit local regular inputs only; reject UNC/remote drive/reparse inputs and changed files. No URI access, command-line/environment/memory scraping, process launch/kill, ACL writes, elevation or remote discovery.
- Output is explicit, separate and fresh; reject existing/hardlinked/reparse targets, input aliases and investigated-path descendants. Preserve originals and failed artifacts.
- Export only `core_summary,incident_context,observations,handoff_summary`; raw core_report remains local. No raw usernames/SIDs/hostnames/tokens/home paths/command lines/log messages. No SAFE verdict or causal certainty from supplied metadata.
- Read official PowerShell/.NET API documentation or Context7 before coding. Apply ponytail full/karpathy-guidelines; back up changed existing files outside package source. Tests -> credential scan -> commit. No old tag/asset replacement.

## Review Focus

1. Case-insensitive PowerShell keys and escaped JSON duplicate keys must not hide unsupported fields (Task 1).
2. Parent junction, hardlink or file replacement during read must not expose a different input (Tasks 1/3).
3. PID exits/reuse/access denial must remain unavailable evidence, not fresh fabricated metadata (Task 2).
4. A supplied field claiming SAFE/observed must never become a measured conclusion (Tasks 1/2).
5. Tokens, local paths or markup placed inside ostensibly harmless product/error strings must not leak to HTML/JSON (Task 3).

## File/interface map

Create `src/BoundaryIncident.ps1` (entrypoint), `src/IncidentInput.psm1` (strict read/validate), `src/IncidentObservations.psm1` (bounded local metadata), `src/IncidentHandoff.psm1` (minimize/render/save). New files ship beside BoundaryLens.ps1 at ZIP root. Do not alter core functions to expose private native handles. Test modules can import new modules; entrypoint has strict command-line parsing and fixed sanitized error codes like the existing core.

## Task 1: Strict local inputs and incident contract

**Files:** Create `src/IncidentInput.psm1`, `tests/incident-input.ps1`.

**Interfaces:** `Read-IncidentFile -LiteralPath [string] -MaxBytes [long] -> [byte[]]`; `ConvertFrom-IncidentJson -Bytes [byte[]] -> [hashtable]`; `Read-IncidentContext -LiteralPath [string] -> [hashtable]`; `Read-IncidentCoreReport -LiteralPath [string] -> [hashtable]`; `Read-IncidentLogs -LiteralPath [string[]] -> [object[]]`. Throw only fixed InvalidDataException message codes for expected errors. No implicit pipeline progress/text from these functions.

- [ ] Add assertion script, beginning with strict mode and `$ErrorActionPreference='Stop'`, that imports missing module and checks duplicate-key rejection:

```powershell
Import-Module "$PSScriptRoot/../src/IncidentInput.psm1" -Force
$duplicate = [Text.Encoding]::UTF8.GetBytes('{"schema":"boundary-incident/1","product":"a","product":"b"}')
$rejected = $false
try { ConvertFrom-IncidentJson -Bytes $duplicate | Out-Null }
catch { $rejected = $_.Exception.Message -eq 'INCIDENT_JSON_INVALID' }
if (-not $rejected) { throw 'Duplicate key was accepted.' }
```

- [ ] Run `pwsh -NoProfile -File tests/incident-input.ps1`; expect missing module failure before implementation.
- [ ] Use System.Text.Json.JsonDocument with MaxDepth 32, no comments/trailing commas; recursively enumerate properties before converting to PowerShell maps. Detect case-insensitive duplicate property names including decoded escapes, reject nonfinite numbers and oversized strings; maximum 100000 JSON nodes. Decode UTF-8 strictly. Reject unsupported shapes before querying anything.

```powershell
$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
foreach ($property in $element.EnumerateObject()) {
    if (-not $seen.Add($property.Name)) {
        throw [IO.InvalidDataException]::new('INCIDENT_JSON_INVALID')
    }
}
```

`$element` is each JsonElement object during the recursive walk. Preserve exact schema field casing; the case-insensitive duplicate guard is stricter than JSON because PowerShell consumers are case-insensitive.
- [ ] Incident exact fields: `schema` required boundary-incident/1; optional strings product/version/error_code/occurred_at/runtime_uri; optional positive Int32 process_id (not bool); optional supplied_observations array. Require UTC ISO timestamp when provided. Supplied entries exact `{kind,value,observed_at}` with kind `filter|runtime`, value string and nullable UTC observed_at; callers cannot set provenance/status. Empty optional strings rejected; absent means missing, not measured now.
- [ ] Read local files by explicit absolute drive path; inspect every ancestor for reparse, resolve drive type fixed/removable, refuse UNC/network and nonregular files. Open one FileStream read-only with sharing that denies replacement/writes; verify handle/path identity, length and timestamps before/after. File sharing is a bounded observation, not a guarantee about all kernel writers. Discard changed reads. No Get-Content convenience on unchecked paths.
- [ ] Core validator accepts only current schema-1 envelope and nested types observed in BoundaryLens.ps1; keep original bytes read-only, limit 1 MiB, reject malformed/extra schema. Do not require successful observations. Logs accept JSON object/array or JSONL by explicit extension, capped aggregate bytes/records. Extract only `error_code,occurred_at,component,level`; unknown log fields are discarded, never copied (incident unknown fields remain errors). Entire malformed line or budget excess invalidates the selected log batch. No arbitrary message fields or automatic directory discovery.
- [ ] Add normal/missing/type/case-duplicate/escaped-duplicate/UTF-8/NaN/depth tests, exact byte/record/string bounds, log allowlist, inaccessible/changed files, parent junction and UNC/drive rejection. Assert input hashes unchanged and zero extra stdout. Run `pwsh -NoProfile -File tests/incident-input.ps1`; require assertion count >0 and exit 0. Scan credentials then `git add src/IncidentInput.psm1 tests/incident-input.ps1`; `git commit -m "feat: validate bounded local incident inputs"`.

## Task 2: Provenance-labelled process, volume, URI and imported evidence

**Files:** Create `src/IncidentObservations.psm1`, `tests/incident-observations.ps1`.

**Interfaces:** `Get-IncidentProcessObservation -ProcessId [int] -ExpectedStartTime [Nullable[datetime]] -> [hashtable]`; `Get-IncidentVolumeObservation -LocalPath [string] -> [hashtable]`; `Get-IncidentUriObservation -Value [string] -> [hashtable]`; `Get-IncidentObservations -Context [hashtable] -CoreReport [hashtable] -Logs [object[]] -> [object[]]`. ExpectedStartTime is internal/test identity pin from initial process capture, not an unapproved new incident field. All return observation fields `kind,provenance,status,value,observed_at,error_code`. Status `observed|supplied|unavailable`; provenance `local-query|operator-supplied`.

- [ ] Add failing no-network URI test:

```powershell
Import-Module "$PSScriptRoot/../src/IncidentObservations.psm1" -Force
$value = Get-IncidentUriObservation -Value 'ssh://example.invalid/private/file'
if ($value.value.scheme -ne 'ssh') { throw 'URI scheme missing.' }
if ($value.value.relationship -ne 'unknown') { throw 'URI identity was guessed.' }
if ($value.provenance -ne 'operator-supplied') { throw 'Supplied URI became measured evidence.' }
```

- [ ] Run `pwsh -NoProfile -File tests/incident-observations.ps1`; expect missing module.
- [ ] Implement process read using System.Diagnostics.Process.GetProcessById for exactly one PID. Capture start time before/after reading ProcessName and HasExited; mismatch produces `PROCESS_IDENTITY_CHANGED`, exited `PROCESS_EXITED`, access denial `PROCESS_ACCESS_DENIED`. Dispose handles. Do not request MainModule, environment, command line, memory or every process. Values/time null on failure. Without prior incident start identity, explicitly retain `incident_identity_unconfirmed=true` even for a currently observed PID; cannot infer the PID was the same process at occurred_at.
- [ ] Obtain declared local path's volume using DriveInfo after input path qualification; collect filesystem type/readiness and available size only, no volume label/serial/host identifiers. Unsupported/unready/access denied -> unavailable with fixed error. Do not query filter drivers automatically: supplied filter/runtime records stay operator-supplied/status supplied, observed_at only the provided value.
- [ ] Parse URI via System.Uri.TryCreate only. Return scheme and `representation=local|remote|unknown`, `relationship=unknown`, no authority/userinfo/query/fragment/raw path. `file` with remote authority is remote, not local identity. Syntax analysis is labelled operator-supplied; no resolver, Test-Path, socket, HTTP or process calls on URI text.

```powershell
@{ kind='runtime-uri'; provenance='operator-supplied'; status='supplied'
   value=@{ scheme=$uri.Scheme; representation=$representation; relationship='unknown' }
   observed_at=$null; error_code=$null }
```

`$uri` and `$representation` are local validated values in Get-IncidentUriObservation; malformed strings produce unavailable with `URI_INVALID`.
- [ ] Compose context/log records without changing any core result. Logs are operator-supplied evidence even though bytes were locally read. Add deterministic tests with module-scoped test doubles for exit/access denied/start-time change, real current-process metadata probe, missing PID, volume unready/denied, remote URI syntax and poisoned supplied SAFE claims. Audit new module AST for network/process launch/mutation APIs; positive control deliberately forbidden synthetic AST must be caught. Test a supplied false claim never enters core results or local-query.
- [ ] Run input and observation scripts and require counts/exit 0. Credential-scan then `git add src/IncidentObservations.psm1 tests/incident-observations.ps1`; `git commit -m "feat: attach provenance-labelled incident observations"`.

## Task 3: Minimized no-clobber handoff, CLI and package closure

**Files:** Create `src/IncidentHandoff.psm1`, `src/BoundaryIncident.ps1`, `tests/incident-handoff.ps1`, `tests/incident-interface.ps1`; modify `tests/package.ps1`, `.github/workflows/ci.yml`, `README.md`, `README.ko.md`; create `docs/local-incident.md`, `docs/local-completion-verification.md`. Update existing documentation/packaging assertion files only where exact current member contracts reference the changed candidate; do not loosen old read-only gate.

**Interfaces:** `New-IncidentHandoff -CoreReport [hashtable] -Context [hashtable] -Observations [object[]] -> [hashtable]`; `ConvertTo-IncidentHtml -Handoff [hashtable] -> [string]`; `Write-IncidentHandoff -LiteralPath [string] -Payload [string] -InputPaths [string[]] -InvestigatedPaths [string[]] -> [void]`. CLI `BoundaryIncident.ps1 -CoreReport FILE -Incident FILE [-LogPath FILE ...] -Output NEW_FILE -Format Json|Html`. Explicit parser consumes repeated -LogPath pairs; no wildcard expansion. Exit 0 complete requested handoff, 2 usage/schema/path errors, 1 collection/export failure. Unavailable optional observations may be exported with visible incomplete handoff_summary and exit 1; never silent full success.

- [ ] Add failing privacy and rendering tests with a complete synthetic core report plus incident strings deliberately containing a home path, SID, host, token and HTML. Assert those exact sentinel strings absent from both serialized handoff and HTML; assert RUNTIME_ENFORCEMENT_UNKNOWN retained. Basic rendering assertion:

```powershell
$handoff = New-IncidentHandoff -CoreReport $core -Context $context -Observations @()
$json = $handoff | ConvertTo-Json -Depth 32
if ($json.Contains('core_report')) { throw 'Raw core was exported.' }
if (@($handoff.Keys).Count -ne 4) { throw 'Unexpected export envelope.' }
$html = ConvertTo-IncidentHtml -Handoff $handoff
if ($html -match '<script|<iframe|<img|<link') { throw 'Active or remote HTML resource.' }
```

Build `$core` in the test using the existing core on a fresh synthetic directory, not a guessed nested schema:

```powershell
. "$PSScriptRoot/../src/BoundaryLens.ps1"
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('boundary-incident-test-' + [guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
$fixtureFile = Join-Path $fixtureRoot 'synthetic.txt'
[IO.File]::WriteAllText($fixtureFile, 'synthetic incident test only')
$core = Invoke-BoundaryLens -Workspace $fixtureRoot -FailedPath $fixtureFile -Format Json | ConvertFrom-Json -AsHashtable
$context = @{schema='boundary-incident/1';product='<script>secret-sentinel</script>'}
```

Inject sensitive sentinels into copies of existing evidence fields, not unsupported report fields. Only the core setup queries the disposable synthetic directory; export itself does not query live user paths. Retain the synthetic directory on failure. The original regression fixtures are classifier inputs, not full core reports, and must not be used as the latter.
- [ ] Run `pwsh -NoProfile -File tests/incident-handoff.ps1`; expect missing handoff module.
- [ ] Implement positive export allowlist: core_summary only schema version, known result reason/status codes and known observation status/error codes; map investigated paths to `workspace`/`failed-target` labels, never raw strings. incident_context retains validated occurred_at and field-presence indicators; arbitrary product/version/error strings default to local aliases, with raw values kept only in user's incident file. Document this deliberate privacy tradeoff: generic strings cannot be guaranteed secret-free. Known public error codes may be retained only from an explicit fixed vocabulary. Process observation export removes ProcessName/PID in favor of `selected-process`; log component/error arbitrary strings use numbered aliases. Supplied filter/runtime values similarly local aliases plus provenance/status. Times and filesystem sizes are potentially identifying; label handoff minimized, not anonymous.
- [ ] HTML calls WebUtility.HtmlEncode for every variable text/attribute and uses static inline CSS/table structure with no scripts/resources/forms. Initial version has no clickable arbitrary external references; known HTTPS documentation reference may be hardcoded only after source verification. Show unavailable/supplied distinctly; raw core findings are never replaced by context conclusions.
- [ ] Implement explicit write only after complete serialization: validate every input/output ancestor; reject investigated descendants using normalized path component comparisons, not prefix substring. Recheck parents before exclusive FileMode.CreateNew/FileAccess.Write/FileShare.None open; verify opened destination identity/path before payload writes where supported, flush/close. Existing target is always rejected, including hardlinks; preserve failed output on write failure and report fixed code. State path checks' bounded race limits; no claim of security against arbitrary privileged filesystem replacement.
- [ ] Implement entrypoint import via PSScriptRoot and exact flag parser. Validate all requested inputs before composing; process/volume optional collection gaps retained, malformed inputs stop without output. CLI never invokes core or other product process automatically; README demonstrates user-run core JSON capture first. Reject unknown/repeated singleton flags, mixed stdout spill, missing values and output inside investigation paths.
- [ ] Test output collision/alias/hardlink/parent junction, changed input, component-boundary sibling path, failed write preservation, HTML injection, all sentinel secrets, case-insensitive paths, missing core observations, forged supplied safe claims, unsupported flags, no URI network call, original bytes unchanged. Verify actual process exits and assertion counts for all four new scripts.
- [ ] New ZIP exact members (8): `BoundaryLens.ps1`, `BoundaryIncident.ps1`, `IncidentInput.psm1`, `IncidentObservations.psm1`, `IncidentHandoff.psm1`, `LICENSE`, `README.md`, `SHA256SUMS.txt`. Update tests/package.ps1 copy/hash/zip list and CI extracted exact-member assertions. Keep original core standalone and extracted UX tests; add companion run from extracted package with synthetic inputs and fresh output. Old 4-member released ZIP remains unchanged. Keep candidate under fresh system-temp `boundary-lens-package-*` as required by packager.
- [ ] Document CLI examples and privacy alias tradeoff in both READMEs and docs/local-incident.md; use humanize-korean/no-ai-slop before Korean prose edits. Fill BL-L01/03 -> Task 1, BL-L02/04/05 -> Task 2, BL-L06 -> Task 3 evidence table with each positive/negative scenario, source, command, assertion count, exit and actual results. Unsupported/denied environment checks remain not-verified, not pass.
- [ ] Run all existing CI-listed suites unchanged: repro, interface, read-only, final-review-regressions, residual-correctness, psdrive-backing, local-final-chain, evidence-references, documentation-contract, operational-ux, repository-privacy; then native-collector -Group race, native-review-regressions, report-handoff, package and standalone/extracted UX with the workflow's fresh-temp arguments. Run four new incident suites. Record each exit separately; do not use only the last exit. Remote two-Windows CI must subsequently be observed after authorized branch publication. Scan staged credentials then `git add src/BoundaryIncident.ps1 src/IncidentHandoff.psm1 tests .github/workflows/ci.yml README.md README.ko.md docs/local-incident.md docs/local-completion-verification.md`; `git commit -m "feat: export minimized local incident handoffs"` only after local checks pass.

## Self-review / execution boundary

BL-L01–06 map to named tasks and all five Review Focus classes have negative cases. Core read-only/native code stays unchanged; only companion output writes are authorized. Package list names every new runtime file. This plan records no implementation, test success or public release. Plan review and execution-method selection precede code. If masking raw arbitrary strings conflicts with a needed real support workflow, present that specific privacy tradeoff before allowing raw export; do not silently weaken minimization.
