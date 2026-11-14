using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.WebUtilities;

namespace HappyDocker.Web.Advisories;

public sealed class AdvisoryService(IHttpClientFactory clients, TimeProvider clock, ILogger<AdvisoryService> logger)
{
    public const string ClientName = "SecurityAdvisories";
    public const int LookbackDays = 90;
    public const int MaximumPagesPerSeverity = 5;
    public const int MaximumItemsPerSource = 1000;
    public const int MaximumGitHubBytes = 2 * 1024 * 1024;
    public const int MaximumCisaBytes = 8 * 1024 * 1024;
    private static readonly Uri Cisa = new("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
    private static readonly Uri Mirror = new("https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json");
    private readonly SemaphoreSlim refreshGate = new(1, 1);
    private readonly object stateLock = new();
    private AdvisoryFeedState cisa = new(AdvisorySource.CisaKev, [], null, null, DateTimeOffset.MinValue, null);
    private AdvisoryFeedState github = new(AdvisorySource.GitHub, [], null, null, DateTimeOffset.MinValue, null);

    public AdvisorySnapshot GetSnapshot()
    {
        AdvisoryFeedState[] feeds;
        lock (stateLock) feeds = [cisa, github];
        DateTimeOffset now = clock.GetUtcNow();
        return new(AdvisoryParser.Merge(feeds.SelectMany(feed => feed.Items)
            .Where(item => item.PublishedAt >= now.AddDays(-LookbackDays))), feeds, now);
    }

    public async Task RefreshAsync(CancellationToken cancellationToken)
    {
        if (!await refreshGate.WaitAsync(0, cancellationToken)) return;
        try
        {
            AdvisoryFeedState previousCisa, previousGitHub;
            lock (stateLock) { previousCisa = cisa; previousGitHub = github; }
            await Task.WhenAll(RefreshFeedAsync(previousCisa, cancellationToken), RefreshFeedAsync(previousGitHub, cancellationToken));
        }
        finally { refreshGate.Release(); }
    }

    private async Task RefreshFeedAsync(AdvisoryFeedState previous, CancellationToken cancellationToken)
    {
        DateTimeOffset now = clock.GetUtcNow();
        if (now < previous.NextAttempt) return;
        AdvisoryFeedState next;
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        budget.CancelAfter(TimeSpan.FromSeconds(45));
        try
        {
            var fetched = previous.Source == AdvisorySource.CisaKev
                ? await FetchCisaAsync(now, budget.Token) : await FetchGitHubAsync(now, budget.Token);
            DateTimeOffset finished = clock.GetUtcNow();
            next = new(previous.Source, fetched.Items.GroupBy(item => item.SourceId, StringComparer.Ordinal)
                .Select(group => group.OrderByDescending(item => item.PublishedAt).First()).OrderByDescending(item => item.PublishedAt)
                .ThenBy(item => item.SourceId, StringComparer.Ordinal).Take(MaximumItemsPerSource).ToArray(),
                finished, now, finished.AddHours(1), null,
                fetched.Limited || fetched.Items.Count > MaximumItemsPerSource, fetched.Skipped, fetched.ViaMirror);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { throw; }
        catch (FeedException exception)
        {
            next = previous with { LastAttempt = now, NextAttempt = Later(now.AddHours(1), exception.RetryAt), Error = exception.Message };
            logger.LogWarning("Advisory refresh failed for {Source}: {Category}; next retry at {NextAttempt}",
                previous.Source, exception.Category, next.NextAttempt);
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException or JsonException or OperationCanceledException)
        {
            next = previous with { LastAttempt = now, NextAttempt = now.AddHours(1),
                Error = exception is JsonException ? "The feed returned invalid data." : "The feed is unavailable or timed out." };
            string category = exception is JsonException ? "Parsing" : exception is OperationCanceledException ? "Timeout" : "HTTP";
            logger.LogWarning("Advisory refresh failed for {Source}: {Category}; next retry at {NextAttempt}",
                previous.Source, category, next.NextAttempt);
        }
        lock (stateLock)
        {
            if (previous.Source == AdvisorySource.CisaKev) cisa = next; else github = next;
        }
        if (previous.Error is not null && next.Error is null)
            logger.LogInformation("Advisory refresh recovered for {Source}; next refresh at {NextAttempt}", previous.Source, next.NextAttempt);
    }

    private sealed record FetchResult(IReadOnlyList<AdvisoryItem> Items, int Skipped, bool Limited = false, bool ViaMirror = false);

    private async Task<FetchResult> FetchCisaAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        try { return await ReadCisaAsync(Cisa, now, false, cancellationToken); }
        catch (FeedException exception) when (exception.RetryAt is null) { }
        catch (Exception exception) when (exception is HttpRequestException or IOException or JsonException
            || exception is OperationCanceledException && !cancellationToken.IsCancellationRequested) { }
        return await ReadCisaAsync(Mirror, now, true, cancellationToken);
    }

    private async Task<FetchResult> ReadCisaAsync(Uri uri, DateTimeOffset now, bool mirror, CancellationToken cancellationToken)
    {
        using var response = await GetAsync(uri, github: false, cancellationToken);
        using var document = await ReadJsonAsync(response, MaximumCisaBytes, cancellationToken);
        var parsed = AdvisoryParser.ParseCisa(document.RootElement, now.AddDays(-LookbackDays), now);
        return new(parsed.Items, parsed.Skipped, ViaMirror: mirror);
    }

    private async Task<FetchResult> FetchGitHubAsync(DateTimeOffset now, CancellationToken cancellationToken)
    {
        var items = new List<AdvisoryItem>();
        int skipped = 0;
        bool limited = false;
        foreach (string severity in new[] { "high", "critical" })
        {
            var parameters = new Dictionary<string, string?>
            {
                ["type"] = "reviewed", ["severity"] = severity, ["is_withdrawn"] = "false",
                ["published"] = ">=" + now.AddDays(-LookbackDays).UtcDateTime.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture),
                ["sort"] = "published", ["direction"] = "desc", ["per_page"] = "100"
            };
            Uri? uri = new(QueryHelpers.AddQueryString("https://api.github.com/advisories", parameters));
            var visited = new HashSet<string>(StringComparer.Ordinal);
            for (int page = 0; page < MaximumPagesPerSeverity && uri is not null; page++)
            {
                if (!visited.Add(uri.AbsoluteUri)) throw new FeedException("GitHub returned repeated pagination.");
                using var response = await GetAsync(uri, github: true, cancellationToken);
                using var document = await ReadJsonAsync(response, MaximumGitHubBytes, cancellationToken);
                var parsed = AdvisoryParser.ParseGitHub(document.RootElement, now.AddDays(-LookbackDays), now);
                items.AddRange(parsed.Items);
                skipped += parsed.Skipped;
                uri = NextPage(response, parameters);
                if (uri is not null && page == MaximumPagesPerSeverity - 1) limited = true;
            }
        }
        return new(items, skipped, limited);
    }

    private async Task<HttpResponseMessage> GetAsync(Uri uri, bool github, CancellationToken cancellationToken)
    {
        // Request targets are fixed constants or previously validated same-endpoint pagination links.
        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        request.Headers.UserAgent.ParseAdd("HappyDocker.Web/1.0");
        request.Headers.Accept.ParseAdd(github ? "application/vnd.github+json" : "application/json");
        if (github) request.Headers.Add("X-GitHub-Api-Version", "2026-03-10");
        var response = await clients.CreateClient(ClientName).SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        if (response.IsSuccessStatusCode) return response;
        using (response)
        {
            DateTimeOffset now = clock.GetUtcNow();
            if (response.StatusCode == HttpStatusCode.TooManyRequests || github && response.StatusCode == HttpStatusCode.Forbidden
                || response.Headers.RetryAfter is not null)
            {
                TimeSpan delay = response.Headers.RetryAfter?.Delta ?? TimeSpan.FromHours(1);
                DateTimeOffset retry = response.Headers.RetryAfter?.Date
                    ?? (delay >= DateTimeOffset.MaxValue - now ? DateTimeOffset.MaxValue : now.Add(delay));
                if (response.Headers.TryGetValues("X-RateLimit-Reset", out var values)
                    && long.TryParse(values.FirstOrDefault(), out long seconds) && seconds is >= 0 and <= 253402300799)
                    retry = Later(retry, DateTimeOffset.FromUnixTimeSeconds(seconds));
                throw new FeedException("The feed is rate limited; cached data is retained.", retry, "Rate limit");
            }
            throw new FeedException("The feed is unavailable; cached data is retained.", category: "HTTP");
        }
    }

    private static async Task<JsonDocument> ReadJsonAsync(HttpResponseMessage response, int limit, CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength > limit) throw new FeedException("The feed exceeded its response size limit.");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(10));
        using var stream = await response.Content.ReadAsStreamAsync(deadline.Token);
        using var buffer = new MemoryStream();
        byte[] chunk = new byte[8192];
        int count;
        while ((count = await stream.ReadAsync(chunk, deadline.Token)) > 0)
        {
            if (buffer.Length + count > limit) throw new FeedException("The feed exceeded its response size limit.");
            buffer.Write(chunk, 0, count);
        }
        return JsonDocument.Parse(buffer.GetBuffer().AsMemory(0, (int)buffer.Length), new JsonDocumentOptions { MaxDepth = 32 });
    }

    private static Uri? NextPage(HttpResponseMessage response, Dictionary<string, string?> expected)
    {
        if (!response.Headers.TryGetValues("Link", out var values)) return null;
        string header = string.Join(",", values);
        if (header.Length > 16384) throw new FeedException("GitHub returned invalid pagination.");
        Uri? next = null;
        foreach (string part in header.Split(','))
        {
            if (!Regex.IsMatch(part, @";\s*rel=""next""", RegexOptions.NonBacktracking)) continue;
            var match = Regex.Match(part, @"\A\s*<([^>]+)>;\s*rel=""next""\s*\z", RegexOptions.NonBacktracking);
            if (next is not null || !match.Success || !Uri.TryCreate(match.Groups[1].Value, UriKind.Absolute, out var target)
                || target.Scheme != "https" || target.Host != "api.github.com" || target.Port != 443
                || target.UserInfo.Length != 0 || target.Fragment.Length != 0 || target.AbsolutePath != "/advisories")
                throw new FeedException("GitHub returned unsafe pagination.");
            var query = QueryHelpers.ParseQuery(target.Query);
            if (query.Count != expected.Count + 1 || expected.Any(pair => !query.TryGetValue(pair.Key, out var value)
                    || value.Count != 1 || value[0] != pair.Value)
                || !query.TryGetValue("after", out var cursor) || cursor.Count != 1
                || string.IsNullOrWhiteSpace(cursor[0]) || cursor[0]!.Length > 1024)
                throw new FeedException("GitHub returned unexpected pagination parameters.");
            next = target;
        }
        return next;
    }

    private static DateTimeOffset Later(DateTimeOffset first, DateTimeOffset? second) => second > first ? second.Value : first;

    private sealed class FeedException(string message, DateTimeOffset? retryAt = null, string category = "Parsing") : Exception(message)
    {
        public DateTimeOffset? RetryAt { get; } = retryAt;
        public string Category { get; } = category;
    }
}
