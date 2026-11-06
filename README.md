# HappyDocker

**Read-only Docker image update and vulnerability monitoring.**

HappyDocker is a .NET 10 tool with a working read-only Docker inventory CLI and mutable-tag update checks for Docker Hub and GHCR. Vulnerability monitoring is planned. It **does not** automatically update or restart production containers.

## Goals

- Inventory running containers and the exact image references/digests deployed.
- Detect changes to mutable image tags and discover plausible newer version tags where supported.
- Scan image contents for known vulnerabilities using an established scanner rather than maintaining a CVE database.
- Distinguish an affected package from a demonstrated exploitable application path.
- Send useful, deduplicated notifications through ntfy.
- Start on one Docker host and expand to multiple hosts after the single-host workflow is reliable.

## Current status

Implemented:

- `scan` lists running containers, their original configured image references, immutable image IDs, platforms, and repository digests where available.
- Image-reference parsing supports Docker Hub defaults (`ubuntu` → `docker.io/library/ubuntu:latest`), namespace-qualified names, GHCR, explicit registry hosts and ports (including localhost and bracketed IPv6), tags, and digest pins.
- References retain the original configured text alongside normalized registry, repository, tag, and digest fields. A digest pin does not acquire an implicit `latest` tag; an explicitly configured tag alongside a digest is preserved.
- Classification separates registry-backed references, ambiguous names, content IDs, invalid references, and missing references. Explicit registry names and named digest pins identify a registry target; matching repository-digest metadata can also identify an unqualified name. This does not verify remote existence or prove that an image was pulled.
- Unqualified names normalize using Docker naming rules but remain ambiguous without matching metadata: a name such as `team/app:dev` could be a local tag. Missing repository digests alone do not prove a local build. Content IDs identify no configured registry repository; unrelated repository digests are never used to guess one.
- Missing image metadata is reported as unknown. Conflicting duplicate image inspection records are rejected with a diagnostic. Partial image-inspection failures still produce an inventory from available metadata and retain Docker's nonzero exit code.
- Unit tests cover parsing, normalization, classification, metadata handling, and scan commands/output using fixtures, without a Docker daemon.
- `check` determines whether the configured tag resolves to a different image for the deployed platform, using anonymous Docker Registry HTTP API access to Docker Hub and GHCR.
- Registry tests use mocked HTTP responses, including authentication, redirects, rate limits, timeouts, multi-architecture indexes, unchanged NATS version tags, and incomplete or inconsistent metadata.

Newer-version discovery, vulnerability scanning, persistence, scheduling, notifications, and automatic updates are not implemented.

### Run locally

Install the .NET 10 SDK and Docker CLI, and ensure the local Docker daemon is accessible:

```sh
dotnet run --project src/HappyDocker -- scan
```

The scan invokes only `docker ps`, `docker inspect --type container`, and `docker image inspect`. The report keeps the configured reference and image ID columns, followed by repository digests, normalized reference, classification, and its reason. It never pulls images or changes Docker state.

To check the tags used by running containers:

```sh
dotnet run --project src/HappyDocker -- check
```

`check` uses the same read-only Docker inventory and additionally requests registry manifests and, when needed, small image-configuration blobs. It does not download image layers, pull images into Docker, change tags, or modify containers. `scan` makes no registry requests and retains its existing output.

Each container receives one result:

| Result | Meaning |
| --- | --- |
| Up to date | The tag resolves to the deployed platform manifest. |
| Update available | The tag resolves to a different platform manifest and image configuration for the deployed platform. |
| Unknown / insufficient metadata | A trustworthy comparison cannot be made. |
| Unsupported registry | The reference targets a registry other than Docker Hub or GHCR. |
| Authentication required | Anonymous access cannot read the required metadata. |
| Registry unavailable | A network failure, timeout, rate limit, service failure, or unsupported redirect prevents checking. |
| Skipped | The reference is digest-pinned, ambiguous, or identifies only local content. |

Results include an explanation and, for completed comparisons, the deployed and current **platform manifest** digests. Results are report data: the command exits zero when inventory succeeds, including when a check is inconclusive or an update is available. Docker inventory failures retain a nonzero exit code.

### Comparison rules and limits

- Only the configured tag is checked. An unchanged `nats:2.14.3-alpine` is up to date even if `2.14.8-alpine` exists; no tag listing or newer-version discovery occurs.
- A matching repository digest and complete deployed platform metadata are required. Unqualified names need matching repository-digest evidence before registry access. Multiple distinct matching repository digests are treated as insufficient metadata.
- Both the deployed repository digest and the current tag are resolved through OCI indexes or Docker manifest lists to a unique exact OS/architecture/variant match. Changes affecting only other architectures do not imply an update. Missing or ambiguous platform matches produce `Unknown`; variant compatibility is not guessed. OS version/feature constraints absent from inventory also produce `Unknown`.
- Docker image IDs are used only to verify the deployed manifest's **configuration digest**. They are never compared directly to index or platform manifest digests. Stores whose IDs cannot be tied to configuration digests return `Unknown`.
- Returned bytes are checked against requested digests, advertised digest headers, and descriptor sizes. SHA-256 platform-manifest hashes are computed from the returned bytes for comparison. A manifest changing while its configuration stays the same produces `Unknown`, since repackaging is not reliable evidence of a different deployed image.
- The deployed manifest must still be readable in the registry. Missing/removed manifests, unsupported schemas or digest algorithms, malformed metadata, and config/platform inconsistencies produce `Unknown`.
- Only anonymous access is supported, including a bounded bearer-token challenge exchange with repository-scoped, pull-only tokens. Docker login credentials and credential helpers are not read; private images usually report `Authentication required`. Tokens, response bodies, signed URLs, and raw network exception details are not printed.
- Initial requests target only `registry-1.docker.io` or `ghcr.io`; token requests target only `auth.docker.io/token` or `ghcr.io/token`. HTTPS redirects within the same host are bounded to three hops. Configuration blobs may additionally redirect to Docker's documented `production.cloudfront.docker.com` or GitHub's `pkg-containers.githubusercontent.com`; bearer tokens are removed on that hop. All other cross-host redirects, non-HTTPS URLs, credentials in URLs, and nonstandard ports are rejected. Other vendor CDN endpoints may therefore report `Registry unavailable`.
- Each metadata request, including its authentication and redirect exchange, has a 15-second deadline and bounded response size. HTTP 429 is reported without an immediate retry; `Retry-After` (or a default one-minute cooldown) suppresses further requests to that registry for the remainder of the cooldown within this command. There are no background retries or persistent state.

Protocol references: [Registry HTTP API](https://distribution.github.io/distribution/spec/api/), [bearer-token authentication](https://distribution.github.io/distribution/spec/auth/token/), [OCI image indexes](https://github.com/opencontainers/image-spec/blob/main/image-index.md), [Docker service endpoints](https://docs.docker.com/desktop/enterprise/allow-list/), and [GitHub package endpoints](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#communication-requirements-for-github-hosted-runners).

```sh
dotnet test HappyDocker.slnx
```

Naming follows the [Docker distribution reference rules](https://github.com/distribution/reference). Digest validation currently supports lowercase hexadecimal SHA-256, SHA-384, and SHA-512 with their exact encoded lengths. Unsupported algorithms and malformed references are reported as invalid without interrupting the inventory.

See [the project plan](docs/PLAN.md) for scope, milestones, design constraints, and open questions.

## Initial technology choices

- **Runtime:** C# / .NET 10
- **Interface:** Local read-only console report; JSON output planned
- **State:** SQLite when change tracking is introduced
- **Notifications:** ntfy
- **Security scanning:** Existing scanner (Trivy or equivalent), with exact digest/version reported
- **Registries:** Docker Hub and GitHub Container Registry (GHCR) first

## Safety principles

1. **Never auto-update, pull over, restart, or delete running containers.**
2. Docker Engine access is privileged: do not assume a `:ro` Docker socket mount is read-only API access.
3. Favor least privilege and avoid exposing the Docker API over the network.
4. Do not leak registry credentials, image-auth headers, or internal metadata in logs or notifications.
5. Report uncertainty clearly: finding a vulnerable package is not proof that the workload exposes the vulnerable function.

## Related planning item

WSIWOT **Work Item #28 — Docker Update Notification Bot** (existing tasks #274–#280).

## License

[MIT](LICENSE), copyright (c) 2026 Kyle Givler.
