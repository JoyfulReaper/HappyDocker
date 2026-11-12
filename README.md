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
- `check` determines whether the configured tag resolves to a different image for the deployed platform. Docker Hub and GHCR use anonymous access by default. Private GHCR packages can use explicitly configured credentials.
- `versions` discovers newer patch-tag candidates for running containers in explicitly selected Docker Hub repositories.
- `check` and `versions` can record finding history in an opt-in local SQLite database.
- State-enabled commands can send explicitly configured ntfy alerts through a transactional notification outbox.
- Registry tests use mocked HTTP responses, including authentication, redirects, rate limits, timeouts, multi-architecture indexes, unchanged NATS version tags, both Docker image stores, synthetic local repository digests, and incomplete or inconsistent metadata. Clanker's pulled NATS and build-only HappyQOTD identity examples are regression fixtures.

Vulnerability scanning, scheduling, and automatic updates remain planned.

### Discover newer patch tags

```sh
happydocker versions --repo docker.io/library/nats
happydocker versions --repo nats --repo docker.io/library/redis
# From the source checkout:
dotnet run --project src/HappyDocker -- versions --repo docker.io/library/nats
```

Each `--repo` opts in a repository without a tag or digest. Unqualified repository names use Docker Hub defaults. HappyDocker lists tags only for selected Docker Hub repositories used by running containers with recognized version tags and matching Docker pull provenance. Local builds, ambiguous provenance, missing image identity, digest pins, and unsupported registries are reported as skips. Older Docker metadata without pull provenance can therefore be insufficient for discovery. Shared repositories and candidate platform checks are reused across containers.

Candidates must have the same numeric major and minor version, a greater numeric patch, and exactly the same suffix, including case. The suffix is an opaque variant. For example, hypothetical `2.14.9-alpine` would match `2.14.8-alpine`, while `2.15.0-alpine` and `2.14.9` would be excluded. The command rejects moving aliases, commit-like tags, recognizable prerelease markers, and ambiguous numeric formats. The example does not assert that a tag has been published.

HappyDocker uses anonymous bearer authentication with Docker Hub's Registry API. It caps enumeration at 20 pages, 100 tags and 64 KiB per page, and 2,000 total tags. Continuation links must point to the same HTTPS tag-list endpoint with a valid cursor. A limit, invalid or missing continuation for a full page, or registry error produces an incomplete-enumeration notice. Rate-limit notices include Retry-After when available. [OCI registry tag listing and pagination](https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-tags)

The report shows each container's configured tag and the greatest matching patch observed, if any. It checks the candidate's manifest and config metadata for the deployed OS, architecture, and variant where available. Missing evidence is labeled **platform unverified**. The result is a candidate for review. A matching platform and patch number establish neither application compatibility nor security. A scan with no candidate reports only what was found among the tags examined.

`versions` reports registry failures and incomplete enumeration in its output. Without state tracking, invalid options and Docker inventory failures return a nonzero exit code.

### Keep finding history

On Linux, create a private state directory and use the same database path on subsequent runs.

```sh
install -d -m 700 "$HOME/.local/state/happydocker"
state="$HOME/.local/state/happydocker/findings.db"
happydocker check --state "$state"
happydocker versions --repo docker.io/library/nats --state "$state"
```

HappyDocker creates the database on first use. It creates new database files with mode `0600` on Linux and rejects existing files accessible to group or other users. Keep the parent directory private as well, since SQLite may create a rollback journal there during writes. HappyDocker uses transactions and leaves SQLite's default rollback journaling in place for new databases. The state database contains container and repository names, so keep it out of source control.

By default, history is keyed to the daemon ID returned by `docker info`. If that ID is unavailable or you need history to survive daemon replacement, add a unique, stable `--host clanker` to each state-enabled invocation for that host. Explicit host labels allow ASCII letters, digits, periods, hyphens, and underscores. Switching between a label and the daemon ID starts a separate history.

Schema version 2 keeps one finding row per host, logical container name, normalized repository, and finding type, plus a notification outbox. Version 1 databases migrate transactionally, preserving existing finding history. Finding rows store the latest finding's container and image IDs, configured tag, deployed digest when available, available manifest digest or patch tag, platform verification, state, and first and last observation times in UTC. Ordinary container recreation preserves the logical key. Registry credentials and responses are excluded. The database retains resolved findings and does not keep a per-run event log or prune old finding rows.

The state summary counts new, known, changed, resolved, and incomplete observations. A different candidate tag or relevant image digest can change a finding. A finding that returns after resolution counts as new. Verification confidence is tracked separately, and complete tag enumeration can record an unverified candidate. If authentication, rate limiting, or a registry outage prevents rechecking the same candidate for the same deployment, the current report marks it unverified and history retains the earlier verification. Successful verification can strengthen a known finding.

Expected skips, including local builds, digest pins, unsupported registries, and unrecognized version tags in `versions`, are outside the incomplete count. Truncated enumeration leaves prior state intact, even when the report shows a candidate from the pages examined. Only a conclusive check for the same logical container, repository, and finding type can resolve a finding. Successful observations are saved when an independent check fails.

With `--state`, exit code `0` means the relevant checks completed, `2` means some findings could be evaluated alongside incomplete checks, and `1` means the run could not evaluate any checks or save state. A Docker inventory failure retains Docker's exit code. Finding an update or verified patch candidate does not itself cause an error. Omitting `--state` keeps the existing report and exit behavior.

### Send ntfy alerts

Add a topic URL to a state-enabled command to publish new or changed mutable-tag updates and platform-verified patch candidates.

```sh
state="$HOME/.local/state/happydocker/findings.db"
happydocker check --state "$state" --host clanker \
  --notify-ntfy https://ntfy.example.com/docker-alerts
happydocker versions --repo docker.io/library/nats --state "$state" --host clanker \
  --notify-ntfy https://ntfy.example.com/docker-alerts
```

For an authenticated topic, put its bearer token in a private file and set `HAPPYDOCKER_NTFY_TOKEN_FILE` to that file's path. Use mode `0600` for the file and a private parent directory. A trailing newline is accepted. Authenticated requests require HTTPS. An explicitly selected HTTP topic can be used anonymously on an internal network. URLs accept a topic path without embedded credentials, query parameters, or fragments. HappyDocker uses ntfy's documented text POST and bearer authentication. [ntfy publishing documentation](https://docs.ntfy.sh/publish/)

Alerts include the host, container names, repository, configured tag, available digest or patch tag, finding type, platform verification, and observation time. Matching findings from a command are grouped, showing up to ten container names and a count for the remainder. Patch candidates still require application compatibility and security review. An unverified New/Changed patch candidate observed with notifications enabled retains eligibility for its selected destination. Once the same candidate and deployment are verified, its finding state remains Known and one alert is queued for the original New/Changed event. Findings already known before notifications were enabled stay quiet.

Finding transitions and pending alerts are committed together before delivery. An ntfy outage leaves successful observations saved. The outbox stores bounded message snapshots, a hash of the destination URL, attempt counts, retry deadlines, and delivery leases. Tokens, authentication headers, raw responses, and the destination URL are excluded. Successful HTTP responses remove the pending entry. Failed entries remain available on subsequent invocations using the same database, host identifier, and topic URL. Changing the host label or topic selects a separate queue. A queued alert describes the observation when it was created, so a delayed message may describe an earlier deployment.

Deferred eligibility is stored on each finding in nullable `pending_notification_destination` and `pending_notification_state` columns. These hold the destination hash and original New/Changed event while verification is pending. They are cleared atomically when an alert is queued, the candidate or deployment changes, or the finding resolves. Temporary verification failures retain eligibility. Schema version 2 initializes these columns without backfilling alerts when opening version 1 or earlier development version 2 databases.

Each enabled invocation attempts at most ten messages within a 30-second delivery budget, with an eight-second timeout per request. Delivery stops after the first failure. Retry delays start at one minute and grow to one hour, and a longer server `Retry-After` is honored. A destination cooldown also applies to newly queued messages. Commands use SQLite transactions and 60-second leases to coordinate delivery, and expired leases can be retried after an interrupted process. HTTP redirects are disabled. Messages are capped at 3,800 UTF-8 bytes, and response bodies are discarded.

The notification summary reports sent, failed, and pending counts separately. Exit code `3` indicates notification failure or remaining pending work, including delayed retries and batches exceeding the delivery limit. This takes precedence over the finding outcome, while a nonzero Docker inventory exit code is retained. Pending alerts are retried even when the enabled command observes no new findings. Use another invocation after the retry deadline to continue delivery.

HTTP delivery is **at least once**. A process can stop after the server accepts a message and before SQLite records success, so a later retry can send it again. Completed messages are removed from the outbox, and there is no permanent delivery audit log.

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
- **Local and transferred images:** with no identity record, a bare configured name can be classified as `LocalOrImported` when a valid manifest/index descriptor matches the image ID and all repository digests are bare aliases for that same ID, including the configured repository. These images remain visible as `Skipped` and `NotApplicable`, leave finding history intact, and cause no registry requests. Descriptor name annotations are labels and supply no pull provenance. Explicit registry references, canonical registry digest names, missing supporting aliases, and conflicting metadata remain inconclusive.

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
- Each metadata request, including its authentication and redirect exchange, has a 15-second deadline and bounded response size. HTTP 429 is reported without an immediate retry; `Retry-After` (or a default one-minute cooldown) suppresses further requests to that registry for the remainder of the cooldown within this command.

Protocol references: [Registry HTTP API](https://distribution.github.io/distribution/spec/api/), [bearer-token authentication](https://distribution.github.io/distribution/spec/auth/token/), [OCI image indexes](https://github.com/opencontainers/image-spec/blob/main/image-index.md), [Docker service endpoints](https://docs.docker.com/desktop/enterprise/allow-list/), and [GitHub package endpoints](https://docs.github.com/en/actions/reference/runners/github-hosted-runners#communication-requirements-for-github-hosted-runners).

```sh
dotnet test HappyDocker.slnx
```

Naming follows the [Docker distribution reference rules](https://github.com/distribution/reference). Digest validation currently supports lowercase hexadecimal SHA-256, SHA-384, and SHA-512 with their exact encoded lengths. Unsupported algorithms and malformed references are reported as invalid without interrupting the inventory.

See [the project plan](docs/PLAN.md) for scope, milestones, design constraints, and open questions.

## Initial technology choices

- **Runtime:** C# / .NET 10
- **Interface:** Local read-only console report; JSON output planned
- **State:** Opt-in local SQLite finding history for `check` and `versions`
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
