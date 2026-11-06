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

- `scan` lists running containers, their original configured image references, immutable image IDs, platforms, and repository digests where available. Inspection also captures optional image `Descriptor`/`Identity` and container `ImageManifestDescriptor` metadata without requiring new Docker flags.
- Image-reference parsing supports Docker Hub defaults (`ubuntu` → `docker.io/library/ubuntu:latest`), namespace-qualified names, GHCR, explicit registry hosts and ports (including localhost and bracketed IPv6), tags, and digest pins.
- References retain the original configured text alongside normalized registry, repository, tag, and digest fields. A digest pin does not acquire an implicit `latest` tag; an explicitly configured tag alongside a digest is preserved.
- Classification separates registry-backed references, locally built images, ambiguous names, content IDs, invalid references, and missing references. Explicit registry names and named digest pins identify a registry target, but provenance assessment requires daemon identity records: matching `Identity.Pull` repositories provide registry-origin evidence; build-only identities are classified as locally built.
- Unqualified names normalize using Docker naming rules: a name such as `team/app:dev` could be a local tag. Repository digests alone never promote a name to registry-backed; containerd can synthesize them for local builds. Missing digests do not prove a build, and missing, malformed, nonmatching, or mixed pull/build identity records do not prove a pull. Content IDs identify no configured registry repository.
- Missing image metadata is reported as unknown. Conflicting duplicate image inspection records are rejected with a diagnostic. Partial image-inspection failures still produce an inventory from available metadata and retain Docker's nonzero exit code.
- Unit tests cover parsing, normalization, classification, metadata handling, and scan commands/output using fixtures, without a Docker daemon.
- `check` determines whether the configured tag resolves to a different image for the deployed platform, using anonymous Docker Registry HTTP API access to Docker Hub and GHCR.
- Registry tests use mocked HTTP responses, including authentication, redirects, rate limits, timeouts, multi-architecture indexes, unchanged NATS version tags, both Docker image stores, synthetic local repository digests, and incomplete or inconsistent metadata. Clanker's pulled NATS and build-only HappyQOTD identity examples are regression fixtures.

Newer-version discovery, vulnerability scanning, persistence, scheduling, notifications, and automatic updates are not implemented.

### Run locally

Install the .NET 10 SDK and Docker CLI, and ensure the local Docker daemon is accessible:

```sh
dotnet run --project src/HappyDocker -- scan
```

The scan invokes only `docker ps`, `docker inspect --type container`, and `docker image inspect`. The report keeps the configured reference and image ID columns, followed by repository digests, the image ID's descriptor kind where available, normalized reference, provenance classification, and its reason. Raw identity records and build references are not printed. It never pulls images or changes Docker state.

To check the tags used by running containers:

```sh
dotnet run --project src/HappyDocker -- check
```

`check` uses the same read-only Docker inventory and additionally requests registry manifests and, when needed, small image-configuration blobs. It does not download image layers, pull images into Docker, change tags, or modify containers. `scan` makes no registry requests and retains its inventory columns and command syntax.

Each container receives one result:

| Result | Meaning |
| --- | --- |
| Up to date | The tag resolves to the deployed platform manifest. |
| Update available | The tag resolves to a different platform manifest and image configuration for the deployed platform. |
| Unknown / insufficient metadata | A trustworthy comparison cannot be made. |
| Unsupported registry | The reference targets a registry other than Docker Hub or GHCR. |
| Authentication required | Anonymous access cannot read the required metadata. |
| Registry unavailable | A network failure, timeout, rate limit, service failure, or unsupported redirect prevents checking. |
| Skipped | The reference is digest-pinned, has a build-only identity, is ambiguous without usable deployment evidence, or identifies only local content. |

Results include an explanation and, for completed comparisons, the deployed and current **platform manifest** digests. Results are report data: the command exits zero when inventory succeeds, including when a check is inconclusive or an update is available. Docker inventory failures retain a nonzero exit code.

### Docker image store compatibility

- **Legacy image store:** when `Descriptor` and `Identity` are absent/null, a matching repository digest is only a candidate for content verification. The checker fetches and resolves it, then requires its configuration digest to equal the Docker image ID. This preserves legacy checks, including unqualified names with candidate repository digests, without claiming pull provenance. Successful results explicitly say that provenance remains unavailable; `scan` keeps those references ambiguous. A locally named digest that cannot be verified against registry content cannot produce an update result.
- **Containerd image store:** an image ID can name an OCI index or platform manifest. A valid image descriptor must agree with that ID, and matching `Identity.Pull` repository records are required. The checker verifies the descriptor's digest, size, and media type against fetched bytes before resolving its platform manifest. A matching pull record plus a descriptor can establish deployed content even when `RepoDigests` is absent. Any matching repository digest that is present must resolve consistently with the descriptor.
- **Running platform:** an index describes several images, and ordinary image inspection can describe the daemon's default platform rather than the running container's platform. Index IDs therefore require the container's `ImageManifestDescriptor`. Its platform metadata selects the deployed platform when supplied, and its digest/size/media type must match the selected manifest. Missing or contradictory container descriptors return `Unknown`. For descriptor-backed images, the deployed config blob is also digest/size checked and its platform/filesystem metadata validated before any result, including `Up to date`.
- **Provenance:** a build-only identity is skipped even if its name is fully qualified and repository digests exist. Mixed pull/build identities, nonmatching pull records, empty identity objects, and malformed records return `Unknown` without registry requests. Multiple valid pull repositories may describe aliases; one must match the configured repository. No fallback from contradictory or malformed descriptor/identity metadata to the legacy model occurs. `Identity.Pull` is daemon evidence of a remote repository association (Docker may also record it after a successful push), not a claim that the image was never built locally.

Missing optional properties on older Docker versions are accepted through map-based template access. Descriptor metadata is experimental in Docker; incomplete or unsupported forms remain inconclusive rather than being reinterpreted as configuration digests.

### Comparison rules and limits

- Only the configured tag is checked. An unchanged `nats:2.14.3-alpine` is up to date even if `2.14.8-alpine` exists; no tag listing or newer-version discovery occurs.
- Complete deployed platform metadata and a verifiable deployed content identity are required, using the store-specific rules above. Multiple distinct matching repository digests remain insufficient metadata; unrelated repositories never establish the configured image's identity.
- Both the deployed repository digest and the current tag are resolved through OCI indexes or Docker manifest lists to a unique exact OS/architecture/variant match. Changes affecting only other architectures do not imply an update. Missing or ambiguous platform matches produce `Unknown`; variant compatibility is not guessed. OS version/feature constraints absent from inventory also produce `Unknown`.
- Configuration digests, platform manifest digests, and index digests are separate identities. Legacy IDs bind to configuration digests; descriptor-backed IDs bind to the exact descriptor content. Update comparisons always use the resolved platform manifests, never an index digest versus a configuration digest or child manifest.
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
