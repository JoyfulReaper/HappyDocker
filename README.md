# HappyDocker

**Read-only Docker image update and vulnerability monitoring.**

HappyDocker is a planned .NET 10 tool for identifying out-of-date container images and actionable security findings across self-hosted Docker servers. It reports what needs attention; it **does not** automatically update or restart production containers.

## Goals

- Inventory running containers and the exact image references/digests deployed.
- Detect changes to mutable image tags and discover plausible newer version tags where supported.
- Scan image contents for known vulnerabilities using an established scanner rather than maintaining a CVE database.
- Distinguish an affected package from a demonstrated exploitable application path.
- Send useful, deduplicated notifications through ntfy.
- Start on one Docker host and expand to multiple hosts after the single-host workflow is reliable.

## Current status

**Planning only. No application code or automated changes.**

See [the project plan](docs/PLAN.md) for scope, milestones, design constraints, and open questions.

## Initial technology choices

- **Runtime:** C# / .NET 10
- **First interface:** Local read-only console report; JSON output later
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

To be decided before public release.
