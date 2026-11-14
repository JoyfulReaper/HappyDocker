# HappyDocker.Web — Phase 1

HappyDocker.Web is a .NET 10 ASP.NET Core Razor Pages application for receiving
agent snapshots and displaying known image updates. It runs independently of the
CLI, requires no Docker installation or socket, and has no container management
or command execution endpoints. DeepDish is the intended future host; this phase
does not deploy there or implement reporting in the CLI.

## Projects and boundaries

- `src/HappyDocker`: existing CLI, registry checks, scanner SQLite state, ntfy.
- `src/HappyDocker.Contracts`: portable v1 report DTOs and JSON options, existing
  finding enums, and the existing stable-version parser/classifier. Sharing this
  small library lets the future sender and web app use the same semantics without
  referencing the CLI executable or its Docker/registry/notification machinery.
  The parser and enums were extracted with no CLI command or database change.
- `src/HappyDocker.Web`: authenticated ingestion, separate SQLite store, Razor
  dashboard, local CSS. No frontend build, CDN, JavaScript framework, or required
  JavaScript.
- `tests/HappyDocker.Web.Tests`: HTTP integration tests with `WebApplicationFactory`,
  isolated temporary SQLite databases, and no external service requests.

## Local development

Use a .NET SDK that can build `net10.0` and the .NET 10 ASP.NET Core runtime.
From the repository root in PowerShell:

```powershell
dotnet restore HappyDocker.slnx
# Fresh random development credential, held only in this process environment.
$env:Web__Agents__0__HostId = 'clanker'
$env:Web__Agents__0__Token = [Convert]::ToHexString([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
dotnet run --project src/HappyDocker.Web --no-launch-profile
```

Visit `http://localhost:5080`. By default the server binds only to localhost, and
`AllowedHosts` permits only localhost/loopback host names. No agents are configured
in tracked settings; an empty installation still serves a useful dashboard and
rejects every ingestion request. Registered hosts without reports appear as
awaiting their first report.

`Web:DatabasePath` defaults to `App_Data/dashboard.db`, relative to the **web
project content root**, and can be overridden with `Web__DatabasePath`. Never
point it at scanner history. The web store rejects databases with a different
application ID, unsupported schema version, or an unrelated existing schema.
Database files and `App_Data` are ignored by Git. On Linux new files are mode
`0600`, new directories are `0700`, and shared existing database files are rejected.
Keep an existing parent directory private too; SQLite journals contain private
data. Restrict the data directory with appropriate ACLs on Windows.

## Authentication configuration

Each entry in `Web:Agents` has `HostId` and `Token`. Add further environment
variables such as `Web__Agents__1__HostId` and `Web__Agents__1__Token` for another
host. Host IDs are case-sensitive, 1–128 ASCII letters, digits, `.`, `_`, or `-`.
They should match the stable host labels chosen for CLI state.

Tokens must be unique across hosts and contain 32–256 printable non-space ASCII
characters. Generate independent high-entropy random tokens. Invalid or duplicate
configuration fails startup. Tokens can also come from a private configuration
provider or .NET user secrets; do not put credentials in tracked JSON. Environment
variables use .NET's `__` separator for nested configuration. This phase reads
agent configuration at startup: restart after adding/removing a host or rotating
its token. No token management UI or token overlap period is implemented.

Send `Authorization: Bearer <that host's token>`. Token hashes are compared in
constant time, and each token maps to exactly one case-sensitive host. The server
does not save tokens to SQLite or log headers, report bodies, or exception details.
Do not enable HTTP header/body logging at a proxy or in custom middleware.

Agent credentials authorize **only ingestion**. Browser requests do not need or
use agent tokens. **Browser authentication is not implemented in Phase 1.**
Production requires private-network/WireGuard restrictions, appropriate separate
browser authentication (for example at an authenticated reverse proxy), and a
review of binding, allowed hosts, TLS, secret storage, backups, and filesystem
permissions. Loopback defaults are for development, not a production access
control system. WireGuard alone does not select which browser users may read
the dashboard. No CORS access is enabled.

## Version 1 wire contract

See [sample-report.json](sample-report.json) for a hypothetical update, not a
claim about published tags. This JSON format is independent of either SQLite
schema. It carries only the update findings that HappyDocker currently produces,
not CVEs. Serialize with `ReportJson.CreateOptions()` when using .NET.

Top-level fields are required:

| Field | Meaning |
| --- | --- |
| `schemaVersion` | Integer `1`; unsupported versions are rejected. |
| `hostId` | Stable registered host ID authorized by the token. |
| `reportId` | Nonempty UUID for this immutable snapshot. Reuse it on retries. |
| `scannedAt` | UTC scan completion/snapshot time, not retry/send time. |
| `status` | `complete`, `partial`, `failed`, or `deferred`. |
| `findings` | Full relevant known finding snapshot, at most 1,000 entries. |

Finding fields:

| Field | Meaning / limits |
| --- | --- |
| `kind` | Required `mutableTag` or `versionCandidate`. |
| `containerName` | Required stable logical name, 1–256 characters. Strip Docker's leading `/` consistently in the future sender. |
| `repository` | Required registry-qualified repository, up to 255 characters; no tag, digest, credentials, URL scheme, or query. |
| `containerId`, `imageId` | Optional deployment identities, up to 256 characters each; do not form the logical finding key. |
| `configuredImage` | Optional original configured reference, up to 1,024 characters. Never send secrets embedded in references. |
| `configuredTag` | Docker tag, up to 128 ASCII characters; required for both current finding kinds. |
| `deployedDigest` | Optional lowercase SHA-256/384/512 digest of exact supported length. |
| `available` | Required candidate tag or mutable-tag manifest digest (up to 256 characters). |
| `platformVerified` | Required boolean for the newest candidate; `false` preserves an unverified candidate. |
| `platform` | Optional OS/architecture/variant description, up to 128 characters. |
| `verifiedAlternative` | Optional lower platform-verified version tag, still above the configured tag. Version candidates only. |
| `upgrade`, `alternativeUpgrade` | `major`, `minor`, or `patch`, required when the corresponding version candidate exists; otherwise omit/null. Validated against the CLI's shared parser, including exact prefix/variant and stable-version rules. |
| `state` | Required `new`, `known`, `changed`, or `resolved`; the first three are active. |
| `observedAt` | Required UTC time of the actual finding observation, which can predate this snapshot. |

Dates must be UTC with zero offset, on/after the Unix epoch, and no more than
five minutes ahead of the server clock. An observation cannot follow `scannedAt`.
Synchronize host clocks; server ordering depends on the agent scan timestamp,
not network arrival time. Plain text fields reject control characters, empty
values, and leading/trailing whitespace. Optional unavailable values should be
null/omitted. Unknown fields, missing required fields, invalid/numeric enums,
invalid version candidates, and duplicate logical finding keys are rejected.
Send UTF-8 JSON with a maximum nesting depth of 16. The request limit is 1 MiB,
also enforced for streams without `Content-Length`.

The logical key is `(hostId, containerName, repository, kind)`, matching CLI
history semantics. Container recreation retains the key; a rename or repository
change creates a different key. IDs and digests remain optional where unknown.
Verification means a platform match, not an application compatibility or security
guarantee. Finding states describe the agent's history; ingestion does not invent
New/Changed transitions or send notifications.

## Snapshot and storage semantics

- **Complete:** authoritative full host snapshot of all relevant finding kinds
  and containers. Omitted active findings are resolved at `scannedAt`; explicitly
  resolved findings are accepted. Do not label a repository-only diagnostic or a
  scan with unchecked/deferred work as complete. Unlike the CLI's targeted
  observation writes, complete web snapshots explicitly assert host-wide coverage.
- **Partial/deferred:** merge positive findings whose `observedAt` is at least as
  recent as the stored observation. Preserve omitted findings and ignore explicit
  resolution claims. These conservative rules can leave stale findings visible
  until a complete scan; uncertainty is shown on the dashboard.
- **Failed:** requires an empty findings list. Advance host report/status only;
  retain all previously known findings. An initially failed host is not presented
  as healthy merely because no findings are known.
- A retained finding carries its original observation time and platform evidence.
  A successful newer observation may update those details; a stale observation
  embedded in a newer snapshot cannot overwrite newer evidence or resurrect a
  more recently resolved finding. The latest **submitted report** and the merged
  **known findings** are stored separately because they may differ after a partial
  or failed scan.
- An immediate SQLite transaction checks report identity/time, updates the latest
  report and findings, and saves a compact receipt together. Concurrent requests
  cannot split these steps. SQLite failures roll back everything, allowing retry.
- Exact retries return `duplicate`, including after later scans or a restart.
  IDs are scoped per host. Reusing an accepted ID with different parsed content
  returns `409`. Fingerprints normalize JSON object property order through the
  DTO serializer; keep array order/content stable when retrying.
- A report older than the latest accepted `scannedAt` returns `older` without
  changing report, receive time, or findings. A different ID at the same scan
  timestamp returns `409`; first accepted wins. Duplicate retries also leave the
  last received time unchanged. That time means receipt of the latest accepted
  snapshot, not a heartbeat or retry attempt.
- Storage keeps one latest report per reporting host and one known row per
  logical finding, including resolved state, plus compact `(host, report ID,
  payload hash)` receipts for accepted reports. It does not keep historical report
  payloads or a scan event log. Receipts and resolved keys can grow over time;
  bounded retention requires an explicit future retry/retention policy.

## API responses

`POST /api/agents/reports` requires JSON and a host bearer token.

| Status | Meaning |
| --- | --- |
| `200` | `{ "outcome": "accepted" }`, `duplicate`, or `older`. |
| `400` | Malformed JSON, unsupported schema, or invalid report/finding fields. |
| `401` | Missing/invalid bearer authentication. |
| `403` | Valid token attempting to report for a different host. |
| `409` | Accepted report ID reused with different content, or occupied scan timestamp. |
| `413` | Request exceeds 1 MiB. |
| `415` | Unsupported content type. |
| `503` | SQLite unavailable; retry the same immutable report with backoff. |

Authentication is checked before deserializing a report. Browser cookies never
authorize POST. There are no management, registry proxy, shell, or Docker API
endpoints. Responses disable caching and set a restrictive Content Security
Policy; Razor encodes submitted text. Only trusted infrastructure metadata
belongs in reports, and all dashboard data should be treated as private.

## Submit a local sample

In the PowerShell process that holds the development token, start the server in
another terminal configured with the same environment, or stop it and relaunch
while retaining the token. Then:

```powershell
$report = Get-Content docs/sample-report.json -Raw | ConvertFrom-Json
$report.reportId = [Guid]::NewGuid().ToString()
$report.scannedAt = [DateTimeOffset]::UtcNow.ToString('O')
$report.findings[0].observedAt = $report.scannedAt
$body = $report | ConvertTo-Json -Depth 10
Invoke-RestMethod -Uri 'http://localhost:5080/api/agents/reports' -Method Post `
  -ContentType 'application/json' -Headers @{ Authorization = "Bearer $env:Web__Agents__0__Token" } -Body $body
# Repeat the exact same $body to see duplicate; then refresh the homepage.
```

For easier two-terminal development, inject the same token through a private
configuration provider in both terminals. Do not print it or save it in the repo.
Clear the development token environment variable when finished.

## Dashboard and verification

The homepage lists configured hosts plus previously reporting hosts, last
accepted receive time, scan time/status, active findings, container names,
repositories, configured/deployed and available tags/digests, upgrade class,
agent finding state, platform verification, optional verified alternative, and
per-finding observation time. Resolved findings are retained but not counted as
outstanding. Empty installation, awaiting first report, no outstanding findings,
and incomplete/failed/deferred states have distinct messages. The dark layout
adapts to narrow screens; wide finding tables scroll horizontally. Refresh
manually; no polling, filters, sorting controls, or maintenance checkboxes yet.

```powershell
dotnet test HappyDocker.slnx
dotnet build HappyDocker.slnx --configuration Debug
dotnet build HappyDocker.slnx --configuration Release
git diff --check
```

The HTTP tests exercise the actual Razor and ingestion pipeline with a test
client and temporary SQLite files. See Microsoft's
[ASP.NET Core integration testing guidance](https://learn.microsoft.com/en-us/aspnet/core/test/integration-tests?view=aspnetcore-10.0).

## Deferred work and architectural concerns

Phase 2 must implement agent-side HTTP reporting and durable full-snapshot
construction, including an honest definition of complete coverage across mutable
tag checks and version discovery. CLI observations, history, diagnostics, and
cached candidates cannot simply be serialized as new events or all relabeled
complete. Preserve actual per-finding observation times and use immutable IDs and
payloads for retries. Define retry/backoff and clock handling before operational
multi-host synchronization.

Production deployment on DeepDish, WireGuard/firewall/reverse-proxy/browser-auth
setup, scheduling/health/staleness policies, receipt/resolved-finding retention,
advanced dashboard features, and actual vulnerability scanning remain planned.
The Phase 1 ingestion protocol accepts independently authenticated hosts; this
does not mean operational multi-host reporting or synchronization is complete.
