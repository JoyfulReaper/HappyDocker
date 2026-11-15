# Security advisories

HappyDocker.Web serves `/security/advisories`, linked from the fleet homepage.
This is general security information from authoritative public feeds. It does
**not** correlate advisories with Docker images, containers, packages installed
on a VPS, or agent findings. An entry does not establish that any monitored
system is affected. Actual vulnerability scanning remains planned.

## Sources and meaning

- [CISA Known Exploited Vulnerabilities JSON](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json),
  with the [official CISA GitHub mirror](https://github.com/cisagov/kev-data)
  as a fallback for unavailable, invalid, or oversized primary responses.
  CISA records carry **Known exploited** attribution and the catalog date added.
  KEV does not provide a severity classification here; no CVSS scores or
  High/Critical labels are inferred from exploitation status.
- [GitHub Global Security Advisories API](https://docs.github.com/en/rest/security-advisories/global-advisories).
  Requests use API version `2026-03-10`, `type=reviewed`, `is_withdrawn=false`,
  `sort=published`, `direction=desc`, `per_page=100`, and a `published` lower
  bound for the past 90 days. High and Critical are fetched in separate
  `severity=high` / `severity=critical` queries. The API documents severity as a
  single string with those values; no unsupported comma-separated severity
  query or numbered-page parameter is used.

The service follows GitHub's documented `Link` header `rel="next"` cursors, up
to five pages per severity. Each next URL must be HTTPS on `api.github.com`,
port 443, path `/advisories`, with the original filters intact and a single
bounded `after` cursor. Credentials, fragments, unexpected parameters, changed
filters, repeated cursors, and other destinations are rejected. See
[GitHub pagination](https://docs.github.com/en/rest/using-the-rest-api/using-pagination-in-the-rest-api).
If the page cap is reached, the UI labels the cache as a limited recent subset.
It is not an exhaustive advisory catalog.

No NVD integration, CVSS calculations, infrastructure matching, or automatic
remediation is implemented. CISA catalog links and GitHub advisory links are
attribution links, not additional feeds fetched by HappyDocker.

## Retrieval and caching

`AdvisoryService` uses an injected ASP.NET Core `IHttpClientFactory` and
`TimeProvider`. `AdvisoryRefreshWorker` starts a refresh in the background and
checks due times once per minute. Each source is refreshed approximately one
hour after its previous refresh finishes. Page requests and filter submissions
only read the current cache: they never initiate network requests. The first
page may show a pending/loading state while the initial refresh runs.

The two source caches refresh independently, so failure of GitHub does not block
a CISA update, or vice versa. Each source's replacement is atomic. If a GitHub
page or severity query fails, its partially downloaded replacement is discarded
and the whole previous GitHub snapshot remains available. A single refresh gate
prevents overlapping refreshes.

Bounds:

| Resource | Limit |
| --- | --- |
| Recent window | Past 90 days, also applied to cached data when reading |
| HTTP response headers/request timeout | 10 seconds |
| Response body deadline | 10 seconds |
| Total refresh budget per source | 45 seconds, including pagination/fallback |
| CISA JSON response | 8 MiB; at most 25,000 catalog records parsed |
| GitHub JSON response | 2 MiB per page; at most 100 records per page |
| GitHub page requests | Five pages for each of two severities |
| Cached normalized records | At most 1,000 per source, newest first |
| Displayed merged results | At most 100 matching entries, newest first |
| Titles / descriptions | 500 / 600 characters |
| Package labels | At most 20 normalized labels per GitHub record |
| Search | At most 200 characters |

Size limits apply while reading streams, even without `Content-Length`, and
after automatic decompression. Redirects and cookies are disabled. Requests use
only a fixed application User-Agent and public-feed headers. No Docker or host
inventory, registry/agent credentials, or user search text is sent to the feeds.
No remote URL can be supplied through the page or configuration.

The service uses anonymous GitHub access; it needs no new credentials. Rate limits
are handled conservatively for `429` and GitHub `403` responses. Retry-After
delta/date and GitHub `X-RateLimit-Reset` deadlines are honored, with at least an
hour between attempts after a failure. An upstream Retry-After also defers retries
on other error statuses. A rate-limited CISA primary is not immediately retried
through the mirror. Otherwise an inaccessible primary, including ordinary CISA
403 responses, can fall back to the fixed official mirror. See
[GitHub rate limits](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api).
Multiple app instances or other clients sharing the outbound IP can consume the
same anonymous GitHub quota.

Last successful refresh times are shown separately for each source in UTC.
A source is stale after one hour without success, or when its latest refresh
failed. Failed refreshes preserve the previous normalized records and success
timestamp. Successful recovery clears the error. Invalid records in an otherwise
valid response are skipped and counted visibly. Malformed documents or nonempty
feeds consisting entirely of invalid records fail refresh rather than clearing
good data. A valid empty recent result can replace an old snapshot.

Only normalized display fields are kept **in process memory**; full JSON
documents are discarded after parsing. The cache resets on application restart.
No scanner or web database schema changes were needed. An outage spanning a
restart has no previous in-memory snapshot to show. Persistent caching and
cross-instance cache coordination would need a separate follow-up if required.

## Deduplication and filtering

Entries merge by normalized CVE ID when available. GitHub CVE aliases can supply
an ID when `cve_id` is absent. Advisories without a CVE retain their GHSA identity
and are explicitly labeled as having no CVE. Duplicate source IDs are collapsed,
while distinct GHSA records and CISA attribution remain in a merged entry.

The title/brief description comes from the highest reported GitHub severity,
falling back to CISA for a CISA-only entry. If multiple GitHub advisories share
a CVE, the badge shows the highest reported severity among them. Products/packages,
source links, and original source dates are preserved. Any severity is labeled
as coming from GitHub; a CISA-only entry says **Severity not reported**.

Search matches IDs, titles, descriptions, and product/package labels in the
bounded cache, case-insensitively. Severity filtering uses the merged GitHub
severity or “Not reported.” Source filtering matches entries containing that
source and retains other attributions in the displayed merged card. Dates are
inclusive UTC dates; combined source/date filters must match the same source
record. Results are ordered by the newest source publication/date-added time.
Filters cannot retrieve uncached older records or bypass feed/result caps.

The page provides separate states for initial loading, feed outages, successful
empty recent caches, no filter matches, invalid filters, stale data, and limited
feed/display results. It uses Razor GET forms and existing dark-theme CSS,
without JavaScript, frontend frameworks, external fonts, or CDN dependencies.

## Security and tests

All feed text is untrusted plain text. Razor HTML-encodes it, including search
values; descriptions are never passed to raw HTML or Markdown rendering. Links
are constructed from validated identifiers: a fixed CISA catalog URL or a
canonical `https://github.com/advisories/GHSA-…` URL. Untrusted `html_url`,
references, notes, and description links are never rendered as clickable links.
Dates/IDs/severities are validated and display text is bounded. Errors shown to
readers are generic, without upstream bodies, exception details, or application
configuration.

Existing localhost binding, private-network requirements, and the absence of
built-in browser authentication remain unchanged. Production still requires
separate browser access controls. There are no Docker controls, new agent APIs,
or changes to report ingestion or finding history.

`AdvisoryParserTests`, `AdvisoryServiceTests`, and `AdvisoryPageTests` use mocked
HTTP responses and a controlled clock. They cover parsing, honest severity,
CVE merging, malformed fields, outages/timeouts, rate limits, pagination bounds
and destination restrictions, cache refresh/recovery/staleness, cancellation,
response sizes, background refresh, search/filters, result bounds, and HTML/link
safety. Existing HTTP tests disable the production feed worker so no automated
test calls a live external service.

```powershell
dotnet test HappyDocker.slnx
dotnet build HappyDocker.slnx --configuration Debug
dotnet build HappyDocker.slnx --configuration Release
git diff --check
```
