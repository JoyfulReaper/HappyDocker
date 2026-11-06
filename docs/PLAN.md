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

- Choose a Docker API access pattern; start as a locally invoked CLI rather than a privileged always-on service.
- List running containers and inspect their image metadata.
- Normalize references: `ubuntu`, `library/nats:2.14.8-alpine`, `ghcr.io/org/name:tag`, `name@sha256:...`, etc.
- Preserve the original configured reference as well as normalized registry/repository/tag/digest/platform.
- Identify locally built images with no meaningful registry update comparison.
- Unit-test parsing and output using fixtures; no running Docker needed for the unit tests.

## Milestone 2 — registry updates (WSIWOT #275–276)

- Support Docker Hub and GHCR, including token-auth challenges, rate limits, and transient failures.
- Compare appropriate platform-specific image manifest digests, not merely tag strings.
- **Mutable-tag update:** alert when the deployed image differs from the image currently published under the configured tag.
- **Newer-version suggestion:** where safe to infer from a recognized tag family (e.g. `2.14.3-alpine` -> `2.14.8-alpine`), suggest a candidate but never assume semantic version tags exist or that a higher version is compatible.
- Be conservative with `latest`, `dev`, moving major tags, prereleases, and variant suffixes.
- Treat digest-pinned images as intentionally pinned for automatic update suggestions; retain them for vulnerability scanning.
- Distinguish `update available`, `candidate newer tag`, `up-to-date`, `unknown`, and `not comparable`.

**Definition of done:** A test fixture models the NATS situation: the `2.14.3-alpine` tag is unchanged while a patched `2.14.8-alpine` tag exists. The tool must not report that the old tag has been updated, but may suggest the newer compatible candidate with a qualification.

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

The read-only Docker inventory CLI and image-reference parsing are implemented; see [README](../README.md) for current behavior and test instructions. Validate the inventory against Clanker's running containers before beginning registry update checks.
