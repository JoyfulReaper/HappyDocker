# HappyDocker

**Read-only Docker image update and vulnerability monitoring.**

HappyDocker is a .NET 10 tool for read-only Docker inventory, mutable-tag update checks for Docker Hub and GHCR, and local-image vulnerability scanning with Trivy.

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
- `check` determines whether the configured tag resolves to a different image for the deployed platform. Docker Hub and GHCR use anonymous access by default. Private GHCR packages can use explicitly configured credentials.
- Registry tests use mocked HTTP responses, including authentication, redirects, rate limits, timeouts, multi-architecture indexes, unchanged NATS version tags, both Docker image stores, synthetic local repository digests, and incomplete or inconsistent metadata. Clanker's pulled NATS and build-only HappyQOTD identity examples are regression fixtures.

- `vulnerabilities` scans verified local images for known package vulnerabilities and reports results per running container.

Newer-version discovery, persistence, scheduling, notifications, and automatic updates remain planned.

### Scan deployed images for vulnerabilities

Install the standalone Trivy CLI using the instructions for your OS, then verify that `trivy --version` works for the user running HappyDocker. Use a release that supports `--disable-telemetry`, `--skip-version-check`, and `--image-src docker`. [Trivy installation](https://trivy.dev/docs/latest/getting-started/installation/) · [Trivy image options](https://trivy.dev/docs/latest/references/configuration/cli/trivy_image/)

```sh
happydocker vulnerabilities
# Or from the source checkout:
dotnet run --project src/HappyDocker -- vulnerabilities
```

- HappyDocker reuses the Docker inventory and scans each verified immutable image and platform once per command, including locally built and digest-pinned images. Each container gets its own summary and HIGH/CRITICAL details, including findings with no known fix.
- The Trivy image source is Docker only. HappyDocker verifies the reported OS and architecture, and checks the variant when both sides provide one. Legacy scans verify the configuration ID. For descriptor-less images, HappyDocker requires a recognized classic `overlay2` driver and backing filesystem status. Missing or unrecognized driver metadata leaves the scan incomplete. [Docker classic overlay2 driver](https://docs.docker.com/engine/storage/drivers/overlayfs-driver/) · [Docker containerd store detection](https://docs.docker.com/engine/storage/containerd/)
- Trivy's Docker backend populates `Metadata.ImageID` from Docker inspect. On the containerd store, HappyDocker verifies a directly inspectable platform manifest by digest, descriptor, platform, and ordered uncompressed layer IDs. Docker inspect does not expose the manifest's configuration digest, so a report that supplies a different config ID remains incomplete even when its layers match. For a containerd index, the deployed child manifest must be independently addressable in Docker's local image store. If Docker exposes only the parent index, the result is incomplete. A platform-specific inspect of that index can identify a child but does not give Trivy's Docker backend a directly scannable child ID. [Trivy Docker image implementation](https://github.com/aquasecurity/trivy/blob/main/pkg/fanal/image/daemon/image.go) · [Docker image lookup implementation](https://github.com/moby/moby/blob/master/daemon/containerd/image.go)
- Trivy performs package vulnerability analysis with telemetry, version checks, and optional dependency resolution disabled. It uses its normal vulnerability database cache and can download or refresh the vulnerability and Java databases as needed. A first run needs an existing usable cache or access to Trivy's database distribution endpoints. Offline runs can fail when a database is missing, unusable, or due for refresh. HappyDocker reads the cache timestamp from `trivy version --format json` when available. Older releases that reject the subcommand use `trivy --version --format json`. [Trivy database behavior](https://trivy.dev/docs/latest/configuration/db/) · [Trivy version command](https://trivy.dev/docs/latest/references/configuration/cli/trivy_version/)
- Allow disk space for Trivy's persistent databases and temporary local image exports, which can be large. HappyDocker keeps analysis caching in memory and does not save raw reports. `TRIVY_CACHE_DIR` can point to a writable cache directory. The scanner inherits only selected OS, Docker connection, proxy, certificate, and cache settings. HappyDocker credentials are excluded, and Trivy YAML and other `TRIVY_*` overrides are disabled. [Trivy Docker export implementation](https://github.com/aquasecurity/trivy/blob/main/pkg/fanal/image/daemon/image.go)
- Trivy needs access to the same Docker daemon and local image contents as the inventory command. Docker socket access is privileged even for a read-only workflow. The command distinguishes findings, no findings for recognized packages, unsupported or unrecognized packages, and incomplete scans. Findings identify vulnerable packages present in an image. Application reachability and exploitability require separate analysis. The command returns a nonzero exit code for incomplete scans or inventory failures. Findings and unsupported package coverage are reported as scan results.

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

### Private GHCR packages

Use a GitHub personal access token (classic) with `read:packages` and an account that can read the package. Authorize the token for your organization if it requires SSO. [GitHub Container Registry authentication](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry#authenticating-with-a-personal-access-token-classic)

On Linux, create the token file as the user who runs HappyDocker. Keep it owned by that user with mode `0600`.

```sh
umask 077
mkdir -p "$HOME/.config/happydocker"
touch "$HOME/.config/happydocker/ghcr.pat"
chmod 0600 "$HOME/.config/happydocker/ghcr.pat"
```

Save the PAT alone in that file using a trusted editor or secret manager, then set the username and file path in the process environment.

```sh
export HAPPYDOCKER_GHCR_USERNAME='your-github-username'
export HAPPYDOCKER_GHCR_TOKEN_FILE="$HOME/.config/happydocker/ghcr.pat"
happydocker check
```

`HAPPYDOCKER_GHCR_TOKEN` is an alternative for environments that inject secrets directly. Set exactly one token source. The file is read at `check` startup and only trailing CR/LF characters are removed. Whitespace inside the token, leading or trailing spaces, and a byte order mark are rejected. A future systemd service can point `HAPPYDOCKER_GHCR_TOKEN_FILE` at a file supplied by `LoadCredential=` through its credentials directory. [systemd credentials documentation](https://systemd.io/CREDENTIALS/)

Leave all three variables unset for anonymous access. Metadata requests start anonymously and use a cached bearer token when available. If GHCR challenges the request, configured credentials are sent as Basic authentication only to `https://ghcr.io/token`. That request never follows redirects and requests only the repository's `pull` scope. A cached bearer rejected with HTTP 401 can be replaced through one challenge exchange per metadata request. HTTP 403 ends the request and evicts any rejected cached bearer.

Invalid configuration, including an unreadable or missing token file, fails `check` at startup. Private packages without credentials and packages that reject the configured credentials report `Authentication required` with distinct explanations. Check PAT expiry, scope, and package permissions if access is denied. Unsafe challenges or credential exchange redirects also report `Authentication required`. Rate limits and network failures report `Registry unavailable`.

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
- Docker Hub uses anonymous access. GHCR optionally uses the credential exchange described above, with one configured account per command. HappyDocker uses explicit configuration and does not read Docker login credentials or credential helpers. Tokens, authorization headers, response bodies, signed URLs, and raw network exception details are omitted from reports.
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
- **Security scanning:** Trivy CLI, with immutable local image identity and database freshness where available
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
