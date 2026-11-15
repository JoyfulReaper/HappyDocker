using System.Net;
using HappyDocker.Web.Advisories;

namespace HappyDocker.Web.Tests;

[TestClass]
public sealed class AdvisoryPageTests
{
    [TestMethod]
    public async Task PageShowsBothSourcesWithoutClaimingInfrastructureImpact()
    {
        using var feeds = new AdvisoryFixture();
        feeds.Respond = request => request.RequestUri!.Host == "api.github.com"
            ? AdvisoryFixture.GitHub(AdvisoryFixture.GitHubEntry()) : AdvisoryFixture.Cisa(AdvisoryFixture.CisaEntry());
        await feeds.Refresh();
        using var factory = new DashboardFactory { AdvisoryCache = feeds.Service };
        using var client = factory.CreateClient();
        string html = await client.GetStringAsync("/security/advisories");
        foreach (string expected in new[] { "CVE-2026-1234", "Widget package advisory", "Package description.",
            "High · GitHub", "Known exploited · CISA KEV", "npm: widget-package", "Example Vendor / Widget Server",
            "2026-11-12", "2026-11-13", "GHSA-2345-6789-cfgh", "CISA KEV catalog", "Last successful refresh:",
            "2026-11-14 12:00:00 UTC", "not matched to your containers or VPS infrastructure", "Vulnerability scanning is still planned" })
            StringAssert.Contains(WebUtility.HtmlDecode(html), expected);
        Assert.AreEqual(1, Count(html, "<article "));
        Assert.DoesNotContain(factory.TokenA, html);
        StringAssert.Contains(await client.GetStringAsync("/"), "href=\"/security/advisories\"");
    }

    [TestMethod]
    public async Task SearchSeveritySourceAndInclusiveDatesFilterCachedRecords()
    {
        using var feeds = new AdvisoryFixture();
        feeds.Respond = request => request.RequestUri!.Host != "api.github.com"
            ? AdvisoryFixture.Cisa(AdvisoryFixture.CisaEntry(cve: "CVE-2026-1111", title: "CISA widget issue", date: "2026-11-13"))
            : Microsoft.AspNetCore.WebUtilities.QueryHelpers.ParseQuery(request.RequestUri.Query)["severity"] == "high"
                ? AdvisoryFixture.GitHub(AdvisoryFixture.GitHubEntry(title: "High package issue"))
                : AdvisoryFixture.GitHub(AdvisoryFixture.GitHubEntry(id: "GHSA-jmpq-rvwx-2345", cve: "CVE-2026-9999", severity: "critical", title: "Critical parser issue", date: "2026-11-10T22:00:00Z"));
        await feeds.Refresh();
        int requests = feeds.Requests.Count;
        using var factory = new DashboardFactory { AdvisoryCache = feeds.Service };
        using var client = factory.CreateClient();
        foreach (var (query, included, excluded) in new[]
        {
            ("Search=cve-2026-9999", "Critical parser issue", "CISA widget issue"),
            ("Search=PARSER", "Critical parser issue", "High package issue"),
            ("Search=widget-package&Severity=high", "High package issue", "Critical parser issue"),
            ("Severity=critical", "Critical parser issue", "High package issue"),
            ("Severity=unknown", "CISA widget issue", "Critical parser issue"),
            ("Source=cisa", "CISA widget issue", "High package issue"),
            ("Source=github&From=2026-11-12&To=2026-11-12", "High package issue", "Critical parser issue"),
            ("From=2026-11-13&To=2026-11-13", "CISA widget issue", "High package issue")
        })
        {
            string html = await client.GetStringAsync("/security/advisories?" + query);
            StringAssert.Contains(html, included);
            Assert.DoesNotContain(excluded, html);
        }
        string none = await client.GetStringAsync("/security/advisories?Search=nonexistent");
        StringAssert.Contains(none, "No matching advisories");
        Assert.HasCount(requests, feeds.Requests);
    }

    [TestMethod]
    public async Task SourceAndDateFiltersApplyToTheSameSourceRecordAfterMerging()
    {
        using var feeds = new AdvisoryFixture();
        feeds.Respond = request => request.RequestUri!.Host == "api.github.com"
            ? AdvisoryFixture.GitHub(AdvisoryFixture.GitHubEntry()) : AdvisoryFixture.Cisa(AdvisoryFixture.CisaEntry());
        await feeds.Refresh();
        using var factory = new DashboardFactory { AdvisoryCache = feeds.Service };
        using var client = factory.CreateClient();
        string noCisa = await client.GetStringAsync("/security/advisories?Source=cisa&To=2026-11-12");
        StringAssert.Contains(noCisa, "No matching advisories");
        string github = await client.GetStringAsync("/security/advisories?Source=github&To=2026-11-12");
        StringAssert.Contains(github, "CVE-2026-1234");
        StringAssert.Contains(github, "Known exploited · CISA KEV");
    }

    [TestMethod]
    [DataRow("Severity=invented")]
    [DataRow("Source=https://evil.example/feed")]
    [DataRow("From=bad-date")]
    [DataRow("From=2026-11-14&To=2026-11-01")]
    public async Task InvalidFiltersAreClearlyReportedWithoutFetching(string query)
    {
        using var feeds = new AdvisoryFixture();
        using var factory = new DashboardFactory { AdvisoryCache = feeds.Service };
        using var client = factory.CreateClient();
        string html = await client.GetStringAsync("/security/advisories?" + query);
        StringAssert.Contains(html, "Check your filters");
        Assert.IsEmpty(feeds.Requests);
    }

    [TestMethod]
    public async Task EmptyLoadingOutageAndFreshEmptyStatesAreDistinct()
    {
        using var feeds = new AdvisoryFixture();
        using var factory = new DashboardFactory { AdvisoryCache = feeds.Service };
        using var client = factory.CreateClient();
        string loading = await client.GetStringAsync("/security/advisories");
        StringAssert.Contains(loading, "No advisory data available yet");
        StringAssert.Contains(loading, "background refresh is pending");
        Assert.IsEmpty(feeds.Requests);
        feeds.Respond = _ => new(HttpStatusCode.ServiceUnavailable);
        await feeds.Refresh();
        string outage = await client.GetStringAsync("/security/advisories");
        StringAssert.Contains(outage, "No advisory data available yet");
        StringAssert.Contains(outage, "feed is unavailable");
        feeds.Clock.Advance(TimeSpan.FromHours(1));
        feeds.Respond = null;
        await feeds.Refresh();
        string empty = await client.GetStringAsync("/security/advisories");
        StringAssert.Contains(empty, "No recent advisories in the cache");
        StringAssert.Contains(empty, "Current cache");
    }

    [TestMethod]
    public async Task StalePageRetainsLastSuccessAndRecordsUntilTheyAgeOutOfRecentWindow()
    {
        using var feeds = new AdvisoryFixture();
        feeds.Respond = request => request.RequestUri!.Host == "api.github.com"
            ? AdvisoryFixture.GitHub(AdvisoryFixture.GitHubEntry()) : AdvisoryFixture.Cisa();
        await feeds.Refresh();
        using var factory = new DashboardFactory { AdvisoryCache = feeds.Service };
        using var client = factory.CreateClient();
        feeds.Clock.Advance(TimeSpan.FromHours(1));
        feeds.Respond = _ => new(HttpStatusCode.ServiceUnavailable);
        await feeds.Refresh();
        string html = await client.GetStringAsync("/security/advisories");
        StringAssert.Contains(html, "Stale cache");
        StringAssert.Contains(html, "2026-11-14 12:00:00 UTC");
        StringAssert.Contains(html, "CVE-2026-1234");
        feeds.Clock.Advance(TimeSpan.FromDays(91));
        Assert.IsEmpty(feeds.Service.GetSnapshot().Advisories);
    }

    [TestMethod]
    public async Task FeedTextAndSearchAreEncodedAndUntrustedLinksAreNeverRendered()
    {
        using var feeds = new AdvisoryFixture();
        feeds.Respond = request =>
        {
            if (request.RequestUri!.Host != "api.github.com") return AdvisoryFixture.Cisa();
            var entry = AdvisoryFixture.GitHubEntry(title: "<script>alert('title')</script>");
            entry["description"] = "<img src=x onerror=alert('description')> **plain markdown**";
            entry["html_url"] = "javascript:alert('link')";
            entry["references"] = new System.Text.Json.Nodes.JsonArray("https://evil.example/advisory");
            entry["vulnerabilities"]![0]!["package"]!["name"] = "<svg/onload=alert('package')>";
            return AdvisoryFixture.GitHub(entry);
        };
        await feeds.Refresh();
        using var factory = new DashboardFactory { AdvisoryCache = feeds.Service };
        using var client = factory.CreateClient();
        string html = await client.GetStringAsync("/security/advisories");
        foreach (string expected in new[] { "&lt;script&gt;", "&lt;img", "&lt;svg", "**plain markdown**", "https://github.com/advisories/GHSA-2345-6789-cfgh" })
            StringAssert.Contains(html, expected);
        foreach (string forbidden in new[] { "<script>", "<img", "<svg", "javascript:", "evil.example", "<strong>plain markdown</strong>" })
            Assert.DoesNotContain(forbidden, html);
        string query = await client.GetStringAsync("/security/advisories?Search=" + Uri.EscapeDataString("\"><script>alert(1)</script>"));
        Assert.DoesNotContain("<script>", query);
        StringAssert.Contains(query, "&lt;script&gt;");
    }

    [TestMethod]
    public async Task DisplayIsBoundedAndSearchCanFindCachedEntriesBeyondInitialDisplay()
    {
        using var feeds = new AdvisoryFixture();
        feeds.Respond = request => request.RequestUri!.Host == "api.github.com" ? AdvisoryFixture.GitHub()
            : AdvisoryFixture.Cisa(Enumerable.Range(0, 150).Select(index => AdvisoryFixture.CisaEntry(cve: $"CVE-2026-{1000 + index}", title: $"Issue number {index}")).ToArray());
        await feeds.Refresh();
        using var factory = new DashboardFactory { AdvisoryCache = feeds.Service };
        using var client = factory.CreateClient();
        string html = await client.GetStringAsync("/security/advisories");
        Assert.AreEqual(100, Count(html, "<article "));
        StringAssert.Contains(html, "100 shown · 150 matching");
        StringAssert.Contains(html, "Narrow the filters");
        string specific = await client.GetStringAsync("/security/advisories?Search=CVE-2026-1149");
        StringAssert.Contains(specific, "Issue number 149");
        Assert.AreEqual(1, Count(specific, "<article "));
    }

    private static int Count(string text, string value) => (text.Length - text.Replace(value, "", StringComparison.Ordinal).Length) / value.Length;
}
