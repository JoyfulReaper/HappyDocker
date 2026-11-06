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

**Implemented:** local read-only `scan`, reference normalization/classification, graceful image metadata handling, and fixture-based tests. Validation against Clanker remains a manual follow-up; no SSH access is assumed.

- Choose a Docker API access pattern; start as a locally invoked CLI rather than a privileged always-on service.
- List running containers and inspect their image metadata.
- Normalize references: `ubuntu`, `library/nats:2.14.8-alpine`, `ghcr.io/org/name:tag`, `name@sha256:...`, etc.
- Preserve the original configured reference as well as normalized registry/repository/tag/digest/platform.
- Identify locally built images with no meaningful registry update comparison.
- Unit-test parsing and output using fixtures; no running Docker needed for the unit tests.

## Milestone 2 — registry updates (WSIWOT #275–276)

**First stage implemented:** `check` compares only each running container's configured mutable tag on Docker Hub or GHCR. Registry HTTP communication is separate from Docker inventory. Anonymous bearer authentication, bounded HTTPS redirects, request deadlines, response limits, and rate-limit cooldowns are implemented with `HttpClient` and mocked HTTP tests.

The comparison resolves both the deployed repository digest and the current tag to an exact platform manifest, binds the deployed manifest's config digest to Docker's image ID, and validates changed image config/platform metadata. An index changing only for another architecture does not imply an update. Digest pins and ambiguous/local-only references are skipped. Missing or inconsistent identity/platform information produces `Unknown`.

Reports distinguish up to date, update available, unknown/insufficient metadata, unsupported registry, authentication required, registry unavailable, and skipped references. Only supported registry/auth endpoints and documented config CDN redirects are allowed; bearer tokens never cross hosts. Private registry credentials, persistent state, scheduling, and newer-version discovery remain out of scope for this stage. See [README](../README.md#comparison-rules-and-limits) for behavior and limitations.

Remaining milestone work:

- Validate the implemented Docker Hub/GHCR comparisons against real containers, including registry and platform failure cases.
- Consider explicit credential support and additional documented CDN endpoints if needed for deployed workloads; preserve the supported-host boundary.
- **Newer-version suggestion:** where safe to infer from a recognized tag family (e.g. `2.14.3-alpine` -> `2.14.8-alpine`), suggest a candidate but never assume semantic version tags exist or that a higher version is compatible.
- Keep any future version suggestions conservative with `latest`, `dev`, moving major tags, prereleases, and variant suffixes.
- Retain digest-pinned images for future vulnerability scanning while continuing to skip mutable-tag comparisons.
- Add a distinct `candidate newer tag` result only when newer-version discovery is implemented.

**First-stage regression fixture:** The NATS `2.14.3-alpine` tag is unchanged while a patched `2.14.8-alpine` tag exists elsewhere. The implemented checker reports up to date, never lists tags, and never requests the newer tag. Qualified newer-version suggestions remain future work.

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

- Use SQLite to remember host/container/image identifiers, scan times, relevant digests, advisory findings, and notification history.
- Notify once for a meaningful new state; notify again when a newer update or a materially changed security finding appears.
- Separate alerts for `image update`, `newer version candidate`, and `security finding`.
- Include host, container, image, current/available version or digest, affected package/advisory, fix availability, and confidence/uncertainty.
- Send through existing ntfy infrastructure using ordinary HTTPS or configured internal URL; store credentials outside git.
- Include a manual `scan --no-notify` mode for diagnostics.

## Milestone 5 — deployment (WSIWOT #280 and optionally #279)

- Add a configurable scan interval, log output, health/status, and clean shutdown.
- Evaluate a constrained Docker socket proxy or host-agent pattern before running unattended; a Docker socket mounted `:ro` still exposes privileged API operations unless requests are restricted.
- Start with one host; later use a separate local agent per host and central aggregation only if necessary.
- Optional human-reviewed Compose change suggestions; never automatically change Compose files, restart containers, or apply updates.
- Provide instructions for backups, rollback, registry failure modes, and scanner database updates.

## Explicit non-goals for first release

- Watchtower-style automatic updates
- Managing all Docker hosts from an exposed unrestricted remote Docker socket
- CVE exploit development or proving runtime exploitability automatically
- An elaborate web dashboard, public API, or multi-user authentication system
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
```

Interfaces should be testable independently. Early development uses mocked registry responses to avoid rate limits and flaky network-based tests.

## Decisions to revisit before implementation

1. Does the initial CLI use the Docker Engine API through a library, or invoke `docker` for its read-only commands? Consider maintenance and permission boundaries.
2. Should detection of newer tags be limited to explicit opt-in rules per repository? Default conservative.
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
