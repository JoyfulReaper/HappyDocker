# HappyDocker — development plan

Created: 2026-10-22

## Problem

Self-hosted services can continue running an outdated image even when a safer or newer image exists. A tag can change without its name changing; alternatively, a fixed version can be published under a *new* tag while the old versioned tag remains unchanged. Vulnerability announcements can also appear independently of image updates.

HappyDocker should provide **actionable awareness, not unattended deployment**.

## Scope for v0.1

- One Docker host, beginning with Clanker.
- List running containers, image references, immutable image IDs, relevant repo digests, and platform where available.
- Explicitly classify locally built, registry-backed, pinned-by-digest, and ambiguous image references.
- Produce a local readable report without mutating Docker state.
- Handle missing information without crashing or silently making up updates.

**Definition of done:** `happydocker scan` prints a truthful, read-only inventory of Clanker's currently running containers, with tests for reference parsing and mocked inspection results.

## Milestone 1 — inventory (WSIWOT #274)

**Implemented:** local read-only `scan`, reference normalization/classification, graceful image metadata handling, and fixture-based tests. Clanker testing with `io.containerd.snapshotter.v1` exposed index IDs and synthetic build digests; those observations now inform the image-store compatibility and provenance regression fixtures. Validation of this revised implementation against Clanker remains a manual follow-up; no SSH access is assumed.

Image inspection captures optional `Descriptor` and `Identity`, and container inspection captures optional `ImageManifestDescriptor`, using map access that tolerates absent properties. Pull/build origin is assessed independently from reference syntax and digest identity. Repository-digest names alone never establish a registry-backed image. Build-only images remain local; missing, contradictory, or mixed origin metadata is reported conservatively.

- Choose a Docker API access pattern; start as a locally invoked CLI rather than a privileged always-on service.
- List running containers and inspect their image metadata.
- Normalize references: `ubuntu`, `library/nats:2.14.8-alpine`, `ghcr.io/org/name:tag`, `name@sha256:...`, etc.
- Preserve the original configured reference as well as normalized registry/repository/tag/digest/platform.
- Identify locally built images with no meaningful registry update comparison.
- Unit-test parsing and output using fixtures; no running Docker needed for the unit tests.

## Milestone 2 — registry updates (WSIWOT #275–276)

**First stage implemented:** `check` compares only each running container's configured mutable tag on Docker Hub or GHCR. Registry HTTP communication is separate from Docker inventory. Anonymous bearer authentication, bounded HTTPS redirects, request deadlines, response limits, and rate-limit cooldowns are implemented with `HttpClient` and mocked HTTP tests.

The comparison resolves deployed content and the current tag to exact platform manifests. Legacy images without descriptor/identity metadata retain configuration-digest verification against Docker's image ID, without inferring pull provenance. Containerd images require matching daemon pull records and a valid descriptor binding the image ID to an index, platform manifest, or configuration. Descriptor-backed deployed configs are also verified; image IDs are not blindly treated as configuration digests.

Index IDs require the running container's platform manifest descriptor to avoid selecting the daemon's default platform accidentally. Supplied container platform metadata drives selection, and its digest/size/media type must agree with the manifest selected from the deployed index. Any candidate repository digest must resolve consistently with the descriptor. An index changing only for another architecture does not imply an update. Digest pins, build-only identities, and local-only references are skipped; mixed or contradictory provenance and insufficient platform/identity evidence produce `Unknown`. Digest, size, media-type, and configuration verification remain mandatory.

Reports distinguish up to date, update available, unknown/insufficient metadata, unsupported registry, authentication required, registry unavailable, and skipped references. Registry and auth destinations are restricted to supported hosts and documented config CDN redirects. Bearer tokens stay on their registry host.

`check` supports optional private GHCR access through `HAPPYDOCKER_GHCR_USERNAME` and a classic PAT with `read:packages`. `HAPPYDOCKER_GHCR_TOKEN_FILE` is preferred and works with a future systemd credential file. `HAPPYDOCKER_GHCR_TOKEN` is an alternative for secret injection. Anonymous access remains the default. The PAT is used only for the validated GHCR token exchange, with redirects disabled and a repository-specific `pull` scope. Invalid startup configuration, denied credentials, unsafe challenges, and registry outages have separate diagnostics. See the Linux `0600` token-file example and limitations in the [README](../README.md#private-ghcr-packages).

**Automatic version discovery implemented:** `check` uses one Docker inventory for mutable-tag comparisons and stable-version discovery on Docker Hub and GHCR repositories with matching pull provenance. `ImageVersion` compares major, minor, and patch numerically while preserving the lowercase-v prefix and exact opaque image variant. Reports and notifications classify each upgrade. The newest candidate stays visible when platform verification fails, with a verified lower alternative where one is found among the next four candidates. A version and platform match still require application compatibility and security review. `versions --repo <repository>` remains optional. See the [normal monitoring command](../README.md#normal-monitoring) and [diagnostic examples](../README.md#diagnose-version-discovery).

Complete tag lists are cached for 24 hours with registry-qualified keys. Candidate platforms are checked again, while cached absence cannot resolve a finding. Snapshot timestamps protect newer findings from older cached observations. Enumeration failures remain retryable and Retry-After is persisted. The ten-listing and one-minute discovery budgets, metadata size limits, and repository fairness remain in place. GHCR listing uses its existing bearer exchange, including explicitly configured private-package credentials, with fixed HTTPS destinations and validated pagination.

Schema v4 migrates v1/v2/v3 history and renames `PatchCandidate` rows to `VersionCandidate` in place logically. Finding identity, pending eligibility, outbox payloads and delivery retry history survive migration. A nullable verified-alternative column preserves distinct evidence for the newest tag and the lower platform-verified candidate. Upgrade classification is derived from stored tags. Existing known patch findings stay Known, while genuinely newer minor or major candidates can become Changed. Prerelease ordering, arbitrary aliases, differing variants, and additional registries remain unsupported for semantic discovery.

Automatic discovery orders repositories by a durable `last_attempt` value in the existing cache table. Never-attempted and least-recently-attempted repositories take precedence, so repeated failures cannot monopolize successive runs. Attempts are recorded before listing or cached platform verification and advance monotonically independently of successful cache timestamps. Existing v3 databases gain the nullable field without a schema-version bump. Budget deferrals have separate evidence and reporting, preserve findings, and return state-enabled exit code 4 when no genuine check failure occurred. Explicit `versions --repo` diagnostics retain their existing order and error behavior.

Remaining milestone work:

- Validate the revised Docker Hub/GHCR comparisons against legacy and containerd Docker stores, including Clanker's pulled NATS and locally built HappyQOTD, cross-platform containers, and registry/platform failures. The supplied NATS digest/identity excerpt is preserved in a metadata fixture; comparison fixtures use generated content with real computed digests rather than invented payloads for that digest.
- Validate private GHCR access with a least-privilege PAT in a deployed environment and evaluate additional documented CDN endpoints as needed.
- Retain digest-pinned images for future vulnerability scanning while continuing to skip mutable-tag comparisons.
- Validate unified monitoring and discovery caching against live Docker Hub metadata, including large tag sets and containerd platform descriptors.

**Regression fixtures:** The NATS configured-tag check reports up to date when its deployed manifest is unchanged. Version-discovery fixtures cover all three upgrade levels, ntfy's lowercase-v tags, variant boundaries, lower platform alternatives, GHCR authentication/pagination, cache behavior, and representative production-v3 migration and delivery retry data.

## Milestone 3 — vulnerabilities (new task to add to WSIWOT)

- Integrate Trivy or another maintained scanner as a replaceable adapter; don't build our own CVE database.
- Scan the **specific deployed image digest**, and record scanner database timestamp, distribution, package/fixed versions, advisory ID, and source.
- Handle images that lack standard OS packages and distroless or scratch images.
- A vulnerability may be newly disclosed even when the image digest has not changed. Schedule rescans accordingly.
- Differentiate `vulnerability in installed package`, `fix available`, `no fix known`, and `known reachable/exploitable` only where evidence supports it.
- Avoid publishing private image names or raw scan results to external services without explicit configuration.
- Rate-limit scanning and cap disk/cache use.

**Definition of done:** A fixture can flag an affected Alpine musl package, show the fixed package/version, and explicitly avoid asserting that NATS exercises the vulnerable libc function.

## Milestone 4 — state and notifications (WSIWOT #277–278)

**Finding history implemented:** `check` and `versions` can take `--state <database-path>` and optional `--host <id>`. Without a label, the Docker daemon ID scopes findings across hosts. A versioned SQLite findings table tracks mutable-tag changes and version candidates by host, container name, repository, and finding type. The CLI writes observations in a transaction using UTC timestamps and retains resolved rows. Linux database files are private, and the CLI uses SQLite's default rollback journal. See the [README state directory and usage examples](../README.md#keep-finding-history).

Structured observations distinguish a conclusive absence, incomplete evidence, and expected skips. Only conclusive absence resolves a finding. Expected skips stay outside the incomplete count, and independently successful observations can be recorded in a partial run. Platform verification can improve for a known version candidate, and a temporary registry failure leaves earlier verification in history while the current report identifies the candidate as unverified. Container removal, renaming, or a repository switch does not automatically resolve a previous finding. History tracks the latest finding per key without an event log or retention policy.

**Optional ntfy delivery implemented:** `--notify-ntfy <topic-url>` requires state tracking. New or changed verified findings are grouped per invocation and saved in a transactional outbox alongside finding transitions. Schema version 2 adds the outbox and migrates version 1 history intact. Known findings stay quiet when delivery is enabled later. HTTP success removes a pending entry, failures retain it, and subsequent enabled commands retry pending work, including runs with no new findings. Bounded batches, persisted backoff, server Retry-After, and delivery leases coordinate concurrent commands and interrupted runs. HTTP delivery provides at-least-once semantics, with possible duplicates across an acceptance/commit interruption.

Unverified New/Changed version candidates observed with delivery enabled retain their destination hash and original event in nullable finding columns. Verification of the same candidate and deployment can then consume that eligibility and enqueue one alert while the finding remains Known. Changes or resolution clear obsolete eligibility, and pre-existing Known findings acquire no retroactive eligibility. Marker consumption and outbox insertion share the finding transaction. These columns were introduced in schema version 2 and are preserved by version 4, including initialization for earlier development v2 files.

The optional token comes from `HAPPYDOCKER_NTFY_TOKEN_FILE`, authenticated delivery requires HTTPS, and redirects are disabled. Credentials are excluded from Docker's child environment and SQLite. Delivery failures have a separate summary and exit code while completed Docker/registry observations remain stored. See the [notification usage and limits](../README.md#send-ntfy-alerts). Mocked tests cover Clanker-style inventory, migration, delivery failures, rate limits, concurrency, retry recovery, and credential isolation.

Remaining milestone work:

- Define advisory finding storage and notification eligibility after the scanner adapter exists.
- Evaluate permanent delivery audit and retention policies if operational needs justify them.
- Validate explicitly configured delivery with a private topic in the deployed environment.

## Milestone 5 — deployment (WSIWOT #280 and optionally #279)

### Central web dashboard — Phase 1 implemented

The separate `HappyDocker.Web` .NET 10 Razor Pages application accepts versioned
full-host snapshots at `POST /api/agents/reports` using unique configured per-host
bearer tokens. A small `HappyDocker.Contracts` library shares report DTOs and
existing finding/version semantics without pulling Docker code into the web app.
The web-owned SQLite database stores latest host reports, known findings, and
compact idempotency receipts; it never shares the scanner database. Complete
snapshots can resolve omissions. Partial, failed, and deferred scans preserve
previously outstanding findings; older reports and observations cannot overwrite
newer state. Tests use temporary databases and HTTP test clients.

The dark, responsive dashboard shows host status, timestamps, update candidates,
Major/Minor/Patch classifications, finding state, and verified/unverified platform
evidence. It has no Docker access or container controls. Local development binds
only to localhost. See [the web contract and setup guide](WEB.md).

**Remaining Phase 2 work:** agent-side HTTP reporting and durable full snapshot
construction, retries/clock/coverage policies, operational multi-host
synchronization, and production deployment on DeepDish over private WireGuard.
Production needs private-network restrictions and separate browser authentication;
browser authentication is not part of Phase 1. Receipt/resolved-finding retention,
advanced filtering/sorting, and temporary maintenance checkboxes remain deferred.
Vulnerability scanning is still planned independently.

### Remaining deployment work

- Add a configurable scan interval, log output, health/status, and clean shutdown.
- Evaluate a constrained Docker socket proxy or host-agent pattern before running unattended; a Docker socket mounted `:ro` still exposes privileged API operations unless requests are restricted.
- Start with one host; later use a separate local agent per host and central aggregation only if necessary.
- Optional human-reviewed Compose change suggestions; never automatically change Compose files, restart containers, or apply updates.
- Provide instructions for backups, rollback, registry failure modes, and scanner database updates.

## Explicit non-goals for first release

- Watchtower-style automatic updates
- Managing all Docker hosts from an exposed unrestricted remote Docker socket
- CVE exploit development or proving runtime exploitability automatically
- An elaborate web dashboard, public API, or multi-user authentication system (the minimal private Phase 1 dashboard and agent-only ingestion API are implemented)
- Replacing Docker Compose, registry scanners, or existing monitoring

## Architecture sketch (provisional)

```text
Local CLI / scheduled worker
        |
        +--> Docker inventory (read-only queries)
        |
        +--> Registry checker (Docker Hub, GHCR)
        |
        +--> Vulnerability scanner adapter
        |
        +--> SQLite state and event deduplication
        |
        +--> Console / ntfy output

Future agent HTTP sender (not implemented)
        |
        +--> Private WireGuard network --> HappyDocker.Web (Phase 1 receiver)
                                           |
                                           +--> Separate web SQLite
                                           +--> Razor Pages dashboard
```

Interfaces should be testable independently. Early development uses mocked registry responses to avoid rate limits and flaky network-based tests.

## Decisions to revisit before implementation

1. Does the initial CLI use the Docker Engine API through a library, or invoke `docker` for its read-only commands? Consider maintenance and permission boundaries.
2. Should stable-version discovery expand beyond Docker Hub and GHCR after their tag-list and authentication behavior is validated?
3. Should initial security findings require `fix available` before notifying, while still keeping unfixed findings in reports?
4. Which Trivy invocation and image-access mode avoids unnecessarily elevating the scanning service?
5. What minimum inventory information may safely be sent in ntfy messages from private hosts?
6. Public or private repository? The project uses the MIT license; see [LICENSE](../LICENSE).

## WSIWOT alignment

- Work Item **#28** — Docker Update Notification Bot
- **#274**: inventory
- **#275**: registry checks
- **#276**: digest pinning / version jumps
- **#277**: state/deduplication
- **#278**: ntfy
- **#279**: optional Compose suggestions
- **#280**: packaging/scheduling/health
- **New proposed todo:** Integrate a maintained image vulnerability scanner to identify actionable CVEs for deployed image digests, including fix availability and rescanning on advisory database changes.

## Next session (smallest worthwhile coding slice)

The read-only inventory and first-stage registry comparisons are implemented; see [README](../README.md) for usage, limitations, and test instructions. Validate `scan` and `check` against a locally accessible Docker daemon and representative Docker Hub/GHCR containers before expanding scope. A Docker CLI is installed in the development environment, but its Docker Desktop Linux engine pipe was absent during this implementation, so the real-container smoke test could not run. No images were pulled and no containers were changed. Clanker validation remains a separate manual follow-up.
