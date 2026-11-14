using System.Net;
using System.Net.Http.Headers;
using System.Text;
using HappyDocker.Web.Advisories;
using Microsoft.AspNetCore.WebUtilities;

namespace HappyDocker.Web.Tests;

[TestClass]
public sealed class AdvisoryServiceTests
{
    [TestMethod]
    public async Task BackgroundWorkerLoadsFeedsBeforeAnyPageRequestAndStopsCleanly()
    {
        using var fixture = new AdvisoryFixture();
        using var worker = new AdvisoryRefreshWorker(fixture.Service, fixture.Clock);
        await worker.StartAsync(CancellationToken.None);
        Assert.AreEqual(TimeSpan.FromMinutes(1), await fixture.Clock.TimerScheduled.Task.WaitAsync(TimeSpan.FromSeconds(5)));
        Assert.HasCount(3, fixture.Requests);
        Assert.IsTrue(fixture.Service.GetSnapshot().Feeds.All(feed => feed.LastSuccess is not null));
        await worker.StopAsync(CancellationToken.None);
    }

    [TestMethod]
    public async Task RefreshUsesDocumentedSingleSeverityQueriesAndHourlyCache()
    {
        using var fixture = new AdvisoryFixture();
        fixture.Respond = request =>
        {
            Assert.AreEqual(HttpMethod.Get, request.Method);
            Assert.IsTrue(request.Headers.UserAgent.Any());
            if (request.RequestUri!.Host != "api.github.com") return AdvisoryFixture.Cisa(AdvisoryFixture.CisaEntry());
            Assert.AreEqual("2026-03-10", request.Headers.GetValues("X-GitHub-Api-Version").Single());
            Assert.AreEqual("application/vnd.github+json", request.Headers.Accept.Single().MediaType);
            var query = QueryHelpers.ParseQuery(request.RequestUri.Query);
            Assert.AreEqual("reviewed", query["type"].ToString());
            Assert.AreEqual("false", query["is_withdrawn"].ToString());
            Assert.AreEqual("100", query["per_page"].ToString());
            Assert.AreEqual("published", query["sort"].ToString());
            Assert.AreEqual("desc", query["direction"].ToString());
            StringAssert.StartsWith(query["published"].ToString(), ">=");
            Assert.Contains(query["severity"].ToString(), new[] { "high", "critical" });
            return AdvisoryFixture.GitHub(AdvisoryFixture.GitHubEntry(severity: query["severity"].ToString()));
        };
        await fixture.Refresh();
        Assert.HasCount(3, fixture.Requests);
        Assert.AreEqual(fixture.Clock.GetUtcNow(), fixture.Feed(AdvisorySource.GitHub).LastSuccess);
        Assert.IsFalse(fixture.Feed(AdvisorySource.CisaKev).IsStale(fixture.Clock.GetUtcNow()));
        await fixture.Refresh();
        fixture.Clock.Advance(TimeSpan.FromMinutes(59));
        await fixture.Refresh();
        Assert.HasCount(3, fixture.Requests);
        fixture.Clock.Advance(TimeSpan.FromMinutes(1));
        Assert.IsTrue(fixture.Feed(AdvisorySource.GitHub).IsStale(fixture.Clock.GetUtcNow()));
        await fixture.Refresh();
        Assert.HasCount(6, fixture.Requests);
    }

    [TestMethod]
    public async Task FollowsCursorLinkHeaderAndPreservesCveAttribution()
    {
        using var fixture = new AdvisoryFixture();
        fixture.Respond = request =>
        {
            if (request.RequestUri!.Host != "api.github.com") return AdvisoryFixture.Cisa(AdvisoryFixture.CisaEntry());
            var query = QueryHelpers.ParseQuery(request.RequestUri.Query);
            if (query["severity"] == "critical") return AdvisoryFixture.GitHub();
            if (query.ContainsKey("after")) return AdvisoryFixture.GitHub(AdvisoryFixture.GitHubEntry(id: "GHSA-jmpq-rvwx-2345", cve: null));
            var response = AdvisoryFixture.GitHub(AdvisoryFixture.GitHubEntry());
            response.Headers.Add("Link", $"<{QueryHelpers.AddQueryString(request.RequestUri.AbsoluteUri, "after", "cursor-2")}>; rel=\"next\"");
            return response;
        };
        await fixture.Refresh();
        Assert.HasCount(4, fixture.Requests);
        var snapshot = fixture.Service.GetSnapshot();
        Assert.HasCount(2, snapshot.Advisories);
        Assert.HasCount(2, snapshot.Advisories.Single(item => item.CveId is not null).Items);
        Assert.IsNull(fixture.Feed(AdvisorySource.GitHub).Error);
    }

    [TestMethod]
    public async Task PaginationIsBoundedAndMarksTheRecentSubset()
    {
        using var fixture = new AdvisoryFixture();
        int cursors = 0;
        fixture.Respond = request =>
        {
            if (request.RequestUri!.Host != "api.github.com") return AdvisoryFixture.Cisa();
            var response = AdvisoryFixture.GitHub(AdvisoryFixture.GitHubEntry());
            var query = QueryHelpers.ParseQuery(request.RequestUri.Query).ToDictionary(pair => pair.Key, pair => (string?)pair.Value.ToString());
            query["after"] = $"cursor-{++cursors}";
            response.Headers.Add("Link", $"<{QueryHelpers.AddQueryString("https://api.github.com/advisories", query)}>; rel=\"next\"");
            return response;
        };
        await fixture.Refresh();
        Assert.AreEqual(2 * AdvisoryService.MaximumPagesPerSeverity, fixture.Requests.Count(uri => uri.Host == "api.github.com"));
        Assert.IsTrue(fixture.Feed(AdvisorySource.GitHub).Limited);
        Assert.IsNotNull(fixture.Feed(AdvisorySource.GitHub).LastSuccess);
    }

    [TestMethod]
    [DataRow("https://evil.example/advisories")]
    [DataRow("http://api.github.com/advisories")]
    [DataRow("https://api.github.com/repos/private/project")]
    [DataRow("https://api.github.com:444/advisories")]
    [DataRow("https://user@api.github.com/advisories")]
    public async Task UnsafePaginationDestinationsAreNeverFetched(string target)
    {
        using var fixture = new AdvisoryFixture();
        fixture.Respond = request =>
        {
            if (request.RequestUri!.Host != "api.github.com") return AdvisoryFixture.Cisa();
            var response = AdvisoryFixture.GitHub();
            response.Headers.Add("Link", $"<{target}?after=cursor>; rel=\"next\"");
            return response;
        };
        await fixture.Refresh();
        Assert.HasCount(2, fixture.Requests);
        Assert.IsNotNull(fixture.Feed(AdvisorySource.GitHub).Error);
        Assert.IsNull(fixture.Feed(AdvisorySource.GitHub).LastSuccess);
    }

    [TestMethod]
    public async Task RepeatedOrChangedPaginationParametersFailWithoutPublishingPartialData()
    {
        foreach (bool repeat in new[] { false, true })
        {
            using var fixture = new AdvisoryFixture();
            fixture.Respond = request =>
            {
                if (request.RequestUri!.Host != "api.github.com") return AdvisoryFixture.Cisa();
                var query = QueryHelpers.ParseQuery(request.RequestUri.Query).ToDictionary(pair => pair.Key, pair => (string?)pair.Value.ToString());
                query["after"] = "same-cursor";
                if (!repeat) query["severity"] = "low";
                var response = AdvisoryFixture.GitHub(AdvisoryFixture.GitHubEntry());
                response.Headers.Add("Link", $"<{QueryHelpers.AddQueryString("https://api.github.com/advisories", query)}>; rel=\"next\"");
                return response;
            };
            await fixture.Refresh();
            Assert.IsEmpty(fixture.Feed(AdvisorySource.GitHub).Items);
            Assert.IsNotNull(fixture.Feed(AdvisorySource.GitHub).Error);
            Assert.HasCount(repeat ? 3 : 2, fixture.Requests);
        }
    }

    [TestMethod]
    public async Task CisaFallsBackToItsOfficialMirror()
    {
        using var fixture = new AdvisoryFixture();
        fixture.Respond = request => request.RequestUri!.Host switch
        {
            "www.cisa.gov" => new(HttpStatusCode.Forbidden),
            "raw.githubusercontent.com" => AdvisoryFixture.Cisa(AdvisoryFixture.CisaEntry()),
            _ => AdvisoryFixture.GitHub()
        };
        await fixture.Refresh();
        var feed = fixture.Feed(AdvisorySource.CisaKev);
        Assert.IsTrue(feed.ViaMirror);
        Assert.IsNull(feed.Error);
        Assert.HasCount(1, feed.Items);
        Assert.Contains(new Uri("https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"), fixture.Requests);
    }

    [TestMethod]
    public async Task CisaRateLimitDateIsHonoredWithoutImmediatelyTryingTheMirror()
    {
        using var fixture = new AdvisoryFixture();
        fixture.Respond = request =>
        {
            if (request.RequestUri!.Host == "api.github.com") return AdvisoryFixture.GitHub();
            var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
            response.Headers.RetryAfter = new RetryConditionHeaderValue(fixture.Clock.GetUtcNow().AddHours(4));
            return response;
        };
        await fixture.Refresh();
        Assert.AreEqual(fixture.Clock.GetUtcNow().AddHours(4), fixture.Feed(AdvisorySource.CisaKev).NextAttempt);
        Assert.IsFalse(fixture.Requests.Any(uri => uri.Host == "raw.githubusercontent.com"));
    }

    [TestMethod]
    public async Task RecoveryPublishesNewSnapshotAndClearsStaleError()
    {
        using var fixture = new AdvisoryFixture();
        fixture.Respond = _ => new(HttpStatusCode.ServiceUnavailable);
        await fixture.Refresh();
        Assert.IsTrue(fixture.Service.GetSnapshot().Feeds.All(feed => feed.Error is not null));
        fixture.Clock.Advance(TimeSpan.FromHours(1));
        fixture.Respond = request => request.RequestUri!.Host == "api.github.com"
            ? AdvisoryFixture.GitHub(AdvisoryFixture.GitHubEntry()) : AdvisoryFixture.Cisa();
        await fixture.Refresh();
        Assert.IsTrue(fixture.Service.GetSnapshot().Feeds.All(feed => feed.Error is null && !feed.IsStale(fixture.Clock.GetUtcNow())));
        Assert.HasCount(1, fixture.Service.GetSnapshot().Advisories);
    }

    [TestMethod]
    public async Task RedirectsAreNotFollowedAndDoNotImportTheirBodies()
    {
        using var fixture = new AdvisoryFixture();
        fixture.Respond = request =>
        {
            if (request.RequestUri!.Host != "api.github.com") return AdvisoryFixture.Cisa();
            var response = AdvisoryFixture.GitHub(AdvisoryFixture.GitHubEntry());
            response.StatusCode = HttpStatusCode.Redirect;
            response.Headers.Location = new Uri("https://evil.example/feed");
            return response;
        };
        await fixture.Refresh();
        Assert.IsEmpty(fixture.Feed(AdvisorySource.GitHub).Items);
        Assert.IsFalse(fixture.Requests.Any(uri => uri.Host == "evil.example"));
        Assert.IsNotNull(fixture.Feed(AdvisorySource.GitHub).Error);
    }

    [TestMethod]
    [DataRow("http")]
    [DataRow("network")]
    [DataRow("timeout")]
    [DataRow("json")]
    [DataRow("invalid-records")]
    public async Task FailedRefreshRetainsLastSuccessfulCacheAndBecomesStale(string failure)
    {
        using var fixture = new AdvisoryFixture();
        fixture.Respond = request => request.RequestUri!.Host == "api.github.com"
            ? AdvisoryFixture.GitHub(AdvisoryFixture.GitHubEntry()) : AdvisoryFixture.Cisa(AdvisoryFixture.CisaEntry());
        await fixture.Refresh();
        var previous = fixture.Service.GetSnapshot();
        fixture.Clock.Advance(TimeSpan.FromHours(1));
        fixture.Respond = _ => failure switch
        {
            "http" => new(HttpStatusCode.ServiceUnavailable),
            "network" => throw new HttpRequestException("Sensitive upstream detail"),
            "timeout" => throw new TaskCanceledException(),
            "invalid-records" => AdvisoryFixture.GitHub(new System.Text.Json.Nodes.JsonObject()),
            _ => new(HttpStatusCode.OK) { Content = new StringContent("{invalid-json") }
        };
        await fixture.Refresh();
        var current = fixture.Service.GetSnapshot();
        foreach (var feed in current.Feeds)
        {
            Assert.AreEqual(previous.Feeds.Single(old => old.Source == feed.Source).LastSuccess, feed.LastSuccess);
            Assert.IsTrue(feed.IsStale(fixture.Clock.GetUtcNow()));
            Assert.IsNotNull(feed.Error);
            Assert.DoesNotContain("Sensitive", feed.Error);
            Assert.HasCount(1, feed.Items);
        }
        int requests = fixture.Requests.Count;
        await fixture.Refresh();
        Assert.HasCount(requests, fixture.Requests);
    }

    [TestMethod]
    [DataRow(429, false)]
    [DataRow(403, true)]
    public async Task GitHubRateLimitsHonorRetryAfterAndReset(int status, bool resetHeader)
    {
        using var fixture = new AdvisoryFixture();
        fixture.Respond = request =>
        {
            if (request.RequestUri!.Host != "api.github.com") return AdvisoryFixture.Cisa();
            var response = new HttpResponseMessage((HttpStatusCode)status);
            response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromHours(2));
            if (resetHeader) response.Headers.Add("X-RateLimit-Reset", fixture.Clock.GetUtcNow().AddHours(3).ToUnixTimeSeconds().ToString());
            return response;
        };
        await fixture.Refresh();
        var feed = fixture.Feed(AdvisorySource.GitHub);
        Assert.AreEqual(fixture.Clock.GetUtcNow().AddHours(resetHeader ? 3 : 2), feed.NextAttempt);
        fixture.Clock.Advance(TimeSpan.FromHours(1));
        await fixture.Refresh();
        Assert.AreEqual(1, fixture.Requests.Count(uri => uri.Host == "api.github.com"));
        fixture.Clock.Advance(TimeSpan.FromHours(resetHeader ? 2 : 1));
        await fixture.Refresh();
        Assert.AreEqual(2, fixture.Requests.Count(uri => uri.Host == "api.github.com"));
    }

    [TestMethod]
    public async Task GithubFailureDoesNotPreventCisaRefreshOrOverwriteGithubWithPartialPages()
    {
        using var fixture = new AdvisoryFixture();
        fixture.Respond = request => request.RequestUri!.Host == "api.github.com"
            ? AdvisoryFixture.GitHub(AdvisoryFixture.GitHubEntry()) : AdvisoryFixture.Cisa(AdvisoryFixture.CisaEntry());
        await fixture.Refresh();
        var initial = fixture.Feed(AdvisorySource.GitHub);
        fixture.Clock.Advance(TimeSpan.FromHours(1));
        fixture.Respond = request => request.RequestUri!.Host != "api.github.com"
            ? AdvisoryFixture.Cisa(AdvisoryFixture.CisaEntry(cve: "CVE-2026-9999"))
            : QueryHelpers.ParseQuery(request.RequestUri.Query)["severity"] == "high"
                ? AdvisoryFixture.GitHub(AdvisoryFixture.GitHubEntry(cve: "CVE-2026-8888")) : new(HttpStatusCode.ServiceUnavailable);
        await fixture.Refresh();
        Assert.AreEqual(initial.LastSuccess, fixture.Feed(AdvisorySource.GitHub).LastSuccess);
        Assert.AreEqual("CVE-2026-1234", fixture.Feed(AdvisorySource.GitHub).Items.Single().CveId);
        Assert.AreEqual("CVE-2026-9999", fixture.Feed(AdvisorySource.CisaKev).Items.Single().CveId);
    }

    [TestMethod]
    public async Task ResponseSizeIsEnforcedWithAndWithoutContentLength()
    {
        foreach (bool knownLength in new[] { true, false })
        {
            using var fixture = new AdvisoryFixture();
            fixture.Respond = request =>
            {
                if (request.RequestUri!.Host != "api.github.com") return AdvisoryFixture.Cisa();
                HttpContent content = knownLength
                    ? new StringContent(new string('x', AdvisoryService.MaximumGitHubBytes + 1), Encoding.UTF8, "application/json")
                    : new StreamContent(new GeneratedStream(AdvisoryService.MaximumGitHubBytes + 1));
                return new(HttpStatusCode.OK) { Content = content };
            };
            await fixture.Refresh();
            Assert.IsNotNull(fixture.Feed(AdvisorySource.GitHub).Error);
            StringAssert.Contains(fixture.Feed(AdvisorySource.GitHub).Error!, "size limit");
            Assert.IsEmpty(fixture.Feed(AdvisorySource.GitHub).Items);
        }
    }

    [TestMethod]
    public async Task RefreshGatePreventsConcurrentFetchesAndReadsNeverFetch()
    {
        using var fixture = new AdvisoryFixture();
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        fixture.RespondAsync = async (request, token) =>
        {
            await release.Task.WaitAsync(token);
            return request.RequestUri!.Host == "api.github.com" ? AdvisoryFixture.GitHub() : AdvisoryFixture.Cisa();
        };
        var first = fixture.Refresh();
        await fixture.Refresh();
        Assert.IsEmpty(fixture.Service.GetSnapshot().Advisories);
        Assert.HasCount(2, fixture.Requests);
        release.SetResult();
        await first;
        Assert.HasCount(3, fixture.Requests);
        fixture.Service.GetSnapshot();
        fixture.Service.GetSnapshot();
        Assert.HasCount(3, fixture.Requests);
    }

    [TestMethod]
    public async Task ShutdownCancellationDoesNotReplaceCacheOrMarkItAsFailed()
    {
        using var fixture = new AdvisoryFixture();
        await fixture.Refresh();
        var before = fixture.Feed(AdvisorySource.GitHub);
        fixture.Clock.Advance(TimeSpan.FromHours(1));
        fixture.RespondAsync = async (_, token) =>
        {
            await Task.Delay(Timeout.Infinite, token);
            return AdvisoryFixture.GitHub();
        };
        using var cancellation = new CancellationTokenSource();
        var refresh = fixture.Service.RefreshAsync(cancellation.Token);
        cancellation.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() => refresh);
        Assert.AreEqual(before, fixture.Feed(AdvisorySource.GitHub));
    }

    private sealed class GeneratedStream(int size) : Stream
    {
        private int remaining = size;
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override int Read(byte[] buffer, int offset, int count)
        {
            int length = Math.Min(count, remaining);
            buffer.AsSpan(offset, length).Fill((byte)'x');
            remaining -= length;
            return length;
        }
        public override void Flush() => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
