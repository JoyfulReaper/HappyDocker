using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using HappyDocker.Web.Advisories;
using Microsoft.Extensions.Logging;

namespace HappyDocker.Web.Tests;

internal sealed class AdvisoryFixture : IDisposable
{
    public ManualClock Clock { get; } = new();
    public ConcurrentQueue<Uri> Requests { get; } = new();
    public Func<HttpRequestMessage, HttpResponseMessage>? Respond { get; set; }
    public Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>>? RespondAsync { get; set; }
    public AdvisoryService Service { get; }
    public TestLogger Logger { get; } = new();
    private readonly HttpClient client;

    public AdvisoryFixture()
    {
        client = new HttpClient(new FeedHandler(this)) { Timeout = TimeSpan.FromSeconds(10) };
        Service = new(new Factory(client), Clock, Logger);
    }

    public Task Refresh() => Service.RefreshAsync(CancellationToken.None);
    public AdvisoryFeedState Feed(AdvisorySource source) => Service.GetSnapshot().Feeds.Single(feed => feed.Source == source);
    public void Dispose() => client.Dispose();

    public static JsonObject CisaEntry(string cve = "CVE-2026-1234", string title = "Widget vulnerability", string date = "2026-11-13") => new()
    {
        ["cveID"] = cve, ["vendorProject"] = "Example Vendor", ["product"] = "Widget Server",
        ["vulnerabilityName"] = title, ["dateAdded"] = date, ["shortDescription"] = "A flaw in the example widget.",
        ["requiredAction"] = "Apply vendor mitigations.", ["dueDate"] = "2026-12-01"
    };

    public static JsonObject GitHubEntry(string id = "GHSA-2345-6789-cfgh", string? cve = "CVE-2026-1234",
        string severity = "high", string title = "Widget package advisory", string date = "2026-11-12T10:00:00Z") => new()
    {
        ["ghsa_id"] = id, ["cve_id"] = cve, ["summary"] = title, ["description"] = "Package description.",
        ["severity"] = severity, ["published_at"] = date, ["withdrawn_at"] = null,
        ["html_url"] = $"https://github.com/advisories/{id}",
        ["vulnerabilities"] = new JsonArray(new JsonObject
        { ["package"] = new JsonObject { ["ecosystem"] = "npm", ["name"] = "widget-package" } })
    };

    public static HttpResponseMessage Cisa(params JsonObject[] entries)
    {
        if (entries.Length == 0) entries = [CisaEntry(date: "2020-01-01")];
        return Json(new JsonObject { ["count"] = entries.Length,
            ["vulnerabilities"] = new JsonArray(entries.Select(entry => (JsonNode)entry).ToArray()) });
    }
    public static HttpResponseMessage GitHub(params JsonObject[] entries) => Json(new JsonArray(entries.Select(entry => (JsonNode)entry).ToArray()));
    public static HttpResponseMessage Json(JsonNode node) => new(HttpStatusCode.OK)
    { Content = new StringContent(node.ToJsonString(), Encoding.UTF8, "application/json") };

    public static ParsedAdvisories ParseCisa(JsonObject entry)
    {
        using var response = Cisa(entry);
        using var json = JsonDocument.Parse(response.Content.ReadAsStringAsync().GetAwaiter().GetResult());
        return AdvisoryParser.ParseCisa(json.RootElement, new DateTimeOffset(2026, 8, 16, 0, 0, 0, TimeSpan.Zero), new ManualClock().GetUtcNow());
    }

    public static ParsedAdvisories ParseGitHub(params JsonObject[] entries)
    {
        using var response = GitHub(entries);
        using var json = JsonDocument.Parse(response.Content.ReadAsStringAsync().GetAwaiter().GetResult());
        return AdvisoryParser.ParseGitHub(json.RootElement, new DateTimeOffset(2026, 8, 16, 0, 0, 0, TimeSpan.Zero), new ManualClock().GetUtcNow());
    }

    private sealed class FeedHandler(AdvisoryFixture fixture) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            fixture.Requests.Enqueue(request.RequestUri!);
            if (fixture.RespondAsync is not null) return await fixture.RespondAsync(request, cancellationToken);
            return fixture.Respond?.Invoke(request) ?? (request.RequestUri!.Host == "api.github.com" ? GitHub() : Cisa());
        }
    }

    private sealed class Factory(HttpClient client) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name)
        {
            Assert.AreEqual(AdvisoryService.ClientName, name);
            return client;
        }
    }
}

internal sealed class TestLogger : ILogger<AdvisoryService>
{
    public ConcurrentQueue<(LogLevel Level, IReadOnlyDictionary<string, object?> Properties)> Entries { get; } = new();
    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;
    public bool IsEnabled(LogLevel logLevel) => true;
    public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        => Entries.Enqueue((logLevel, ((IEnumerable<KeyValuePair<string, object?>>)(object)state!).ToDictionary(pair => pair.Key, pair => pair.Value)));
}

internal sealed class ManualClock : TimeProvider
{
    public DateTimeOffset Now { get; private set; } = new(2026, 11, 14, 12, 0, 0, TimeSpan.Zero);
    public TaskCompletionSource<TimeSpan> TimerScheduled { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
    public override DateTimeOffset GetUtcNow() => Now;
    public void Advance(TimeSpan elapsed) => Now += elapsed;
    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = System.CreateTimer(callback, state, dueTime, period);
        TimerScheduled.TrySetResult(dueTime);
        return timer;
    }
}
