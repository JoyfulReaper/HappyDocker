using System.Net;
using System.Text;
using System.Text.Json;
using HappyDocker;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;

namespace HappyDocker.Web.Tests;

[TestClass]
public sealed class IngestionTests
{
    [TestMethod]
    public async Task AuthorizedSnapshotIsPersistedAndRendered()
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        AgentReport report = DashboardFactory.Report();
        using var response = await DashboardFactory.Post(client, report);
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        StringAssert.Contains(await response.Content.ReadAsStringAsync(), "accepted");
        Assert.AreEqual(report.ReportId, factory.Host().LatestReport!.ReportId);
        Assert.HasCount(1, factory.Host().Findings);
        string html = await client.GetStringAsync("/");
        foreach (string expected in new[] { "host-a", "nats", "docker.io/library/nats", "2.14.8-alpine", "2.15.0-alpine", "Minor", "Verified", "New", "Last received:" })
            StringAssert.Contains(html, expected);
        using var connection = new SqliteConnection($"Data Source={factory.DatabasePath};Pooling=False");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT count(*) FROM findings";
        Assert.AreEqual(1L, command.ExecuteScalar());
    }

    [TestMethod]
    [DataRow(null)]
    [DataRow("Bearer invalid")]
    [DataRow("Basic dGVzdA==")]
    public async Task MissingOrInvalidAuthenticationIsRejected(string? header)
    {
        using var factory = new DashboardFactory();
        using var client = factory.CreateClient();
        if (header is not null) client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", header);
        using var response = await DashboardFactory.Post(client, DashboardFactory.Report());
        Assert.AreEqual(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.IsNull(factory.Host().LatestReport);
    }

    [TestMethod]
    public async Task TokenCannotImpersonateAnotherHost()
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        using var denied = await DashboardFactory.Post(client, DashboardFactory.Report(host: "host-b"));
        Assert.AreEqual(HttpStatusCode.Forbidden, denied.StatusCode);
        using var second = factory.AuthorizedClient(factory.TokenB);
        using var accepted = await DashboardFactory.Post(second, DashboardFactory.Report(host: "host-b"));
        Assert.AreEqual(HttpStatusCode.OK, accepted.StatusCode);
        Assert.IsNull(factory.Host().LatestReport);
        Assert.IsNotNull(factory.Host("host-b").LatestReport);
    }

    [TestMethod]
    public async Task DuplicateIsIdempotentAndReusedIdConflicts()
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        var report = DashboardFactory.Report();
        using var first = await DashboardFactory.Post(client, report);
        var received = factory.Host().ReceivedAt;
        using var duplicate = await DashboardFactory.Post(client, report);
        StringAssert.Contains(await duplicate.Content.ReadAsStringAsync(), "duplicate");
        Assert.AreEqual(received, factory.Host().ReceivedAt);
        using var conflict = await DashboardFactory.Post(client, report with { Findings = [] });
        Assert.AreEqual(HttpStatusCode.Conflict, conflict.StatusCode);
        Assert.HasCount(1, factory.Host().Findings);
    }

    [TestMethod]
    public async Task OlderAndEqualTimestampReportsCannotOverwriteLatest()
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        var report = DashboardFactory.Report();
        using var first = await DashboardFactory.Post(client, report);
        using var older = await DashboardFactory.Post(client, DashboardFactory.Report(minutesAgo: 20, findings: []));
        StringAssert.Contains(await older.Content.ReadAsStringAsync(), "older");
        using var equal = await DashboardFactory.Post(client, report with { ReportId = Guid.NewGuid(), Findings = [] });
        Assert.AreEqual(HttpStatusCode.Conflict, equal.StatusCode);
        Assert.AreEqual(report.ReportId, factory.Host().LatestReport!.ReportId);
        Assert.HasCount(1, factory.Host().Findings);
    }

    [TestMethod]
    public async Task RetryOfOlderAcceptedReportRemainsDuplicateAfterNewerReport()
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        var report = DashboardFactory.Report();
        using var first = await DashboardFactory.Post(client, report);
        using var newer = await DashboardFactory.Post(client, DashboardFactory.Report(minutesAgo: 5, findings: []));
        using var duplicate = await DashboardFactory.Post(client, report);
        StringAssert.Contains(await duplicate.Content.ReadAsStringAsync(), "duplicate");
        Assert.AreEqual(FindingState.Resolved, factory.Host().Findings.Single().State);
    }

    [TestMethod]
    [DataRow(FindingRunStatus.Partial)]
    [DataRow(FindingRunStatus.Failed)]
    [DataRow(FindingRunStatus.Deferred)]
    public async Task IncompleteSnapshotDoesNotClearOutstandingFindings(FindingRunStatus status)
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        using var first = await DashboardFactory.Post(client, DashboardFactory.Report());
        using var incomplete = await DashboardFactory.Post(client, DashboardFactory.Report(status, 5, []));
        Assert.AreEqual(HttpStatusCode.OK, incomplete.StatusCode);
        Assert.AreEqual(FindingState.New, factory.Host().Findings.Single().State);
        Assert.AreEqual(status, factory.Host().LatestReport!.Status);
        StringAssert.Contains(await client.GetStringAsync("/"), "previously known findings are retained");
    }

    [TestMethod]
    [DataRow(FindingRunStatus.Partial)]
    [DataRow(FindingRunStatus.Deferred)]
    public async Task IncompleteSnapshotMergesPositivesButCannotExplicitlyResolve(FindingRunStatus status)
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        var initial = DashboardFactory.Report();
        using var first = await DashboardFactory.Post(client, initial);
        var next = DashboardFactory.Report(status, 5);
        var positive = DashboardFactory.Finding(next.ScannedAt) with { ContainerName = "second", PlatformVerified = false };
        using var partial = await DashboardFactory.Post(client, next with { Findings = [
            initial.Findings[0] with { State = FindingState.Resolved, ObservedAt = next.ScannedAt }, positive] });
        Assert.AreEqual(HttpStatusCode.OK, partial.StatusCode);
        Assert.HasCount(2, factory.Host().Findings.Where(f => f.State != FindingState.Resolved));
        Assert.IsFalse(factory.Host().Findings.Single(f => f.ContainerName == "second").PlatformVerified);
    }

    [TestMethod]
    public async Task CompleteSnapshotResolvesOmissionsAndAcceptsExplicitResolution()
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        var initial = DashboardFactory.Report();
        using var first = await DashboardFactory.Post(client, initial);
        using var resolved = await DashboardFactory.Post(client, DashboardFactory.Report(minutesAgo: 5, findings: []));
        Assert.AreEqual(FindingState.Resolved, factory.Host().Findings.Single().State);
        StringAssert.Contains(await client.GetStringAsync("/"), "No outstanding findings");
        var reactivated = DashboardFactory.Report(minutesAgo: 3);
        using var active = await DashboardFactory.Post(client, reactivated);
        var final = DashboardFactory.Report(minutesAgo: 1);
        using var explicitResolution = await DashboardFactory.Post(client, final with
        { Findings = [reactivated.Findings[0] with { State = FindingState.Resolved, ObservedAt = final.ScannedAt }] });
        Assert.AreEqual(FindingState.Resolved, factory.Host().Findings.Single().State);
    }

    [TestMethod]
    public async Task OlderFindingInsideNewerSnapshotCannotReplaceNewerObservation()
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        var initial = DashboardFactory.Report();
        using var first = await DashboardFactory.Post(client, initial);
        var next = DashboardFactory.Report(FindingRunStatus.Partial, 5);
        using var second = await DashboardFactory.Post(client, next with { Findings = [initial.Findings[0] with
        { Available = "2.14.9-alpine", Upgrade = VersionUpgrade.Patch, ObservedAt = initial.ScannedAt.AddMinutes(-1) }] });
        Assert.AreEqual("2.15.0-alpine", factory.Host().Findings.Single().Available);
    }

    [TestMethod]
    public async Task MutableTagAndUnverifiedVersionWithVerifiedAlternativeAreDistinct()
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        var report = DashboardFactory.Report(FindingRunStatus.Partial);
        var version = report.Findings[0] with { Available = "3.0.0-alpine", Upgrade = VersionUpgrade.Major,
            PlatformVerified = false, VerifiedAlternative = "2.15.0-alpine", AlternativeUpgrade = VersionUpgrade.Minor };
        var mutable = report.Findings[0] with { Kind = FindingKind.MutableTag, Upgrade = null,
            Available = "sha256:" + new string('c', 64) };
        using var response = await DashboardFactory.Post(client, report with { Findings = [version, mutable] });
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        Assert.HasCount(2, factory.Host().Findings);
        string html = await client.GetStringAsync("/");
        foreach (string expected in new[] { "Unverified candidate", "Verified alternative:", "Major", "Minor", "Tag changed" })
            StringAssert.Contains(html, expected);
    }

    [TestMethod]
    public async Task ConcurrentRetriesOnlyAcceptOneCopy()
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        var report = DashboardFactory.Report();
        var responses = await Task.WhenAll(Enumerable.Range(0, 5).Select(_ => DashboardFactory.Post(client, report)));
        var bodies = await Task.WhenAll(responses.Select(r => r.Content.ReadAsStringAsync()));
        Assert.AreEqual(1, bodies.Count(b => b.Contains("accepted")));
        Assert.AreEqual(4, bodies.Count(b => b.Contains("duplicate")));
        foreach (var response in responses) response.Dispose();
    }

    [TestMethod]
    public async Task InvalidPayloadsDoNotChangeStoredState()
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        var valid = DashboardFactory.Report();
        var finding = valid.Findings[0];
        var invalid = new List<AgentReport>
        {
            valid with { SchemaVersion = 2 }, valid with { ReportId = Guid.Empty },
            valid with { ScannedAt = DateTimeOffset.UtcNow.AddHours(1) },
            valid with { ScannedAt = valid.ScannedAt.ToOffset(TimeSpan.FromHours(1)) },
            valid with { ScannedAt = DateTimeOffset.MinValue }, valid with { Findings = null! },
            valid with { Status = FindingRunStatus.Failed }, valid with { Findings = [null!] },
            valid with { Findings = [finding, finding] },
            valid with { Findings = [finding with { ContainerName = "" }] },
            valid with { Findings = [finding with { ContainerName = new string('a', 257) }] },
            valid with { Findings = [finding with { Repository = "https://bad.example/a" }] },
            valid with { Findings = [finding with { ConfiguredImage = "image\nsecret" }] },
            valid with { Findings = [finding with { DeployedDigest = "bad-digest" }] },
            valid with { Findings = [finding with { Available = "2.14.7-alpine" }] },
            valid with { Findings = [finding with { Upgrade = VersionUpgrade.Major }] },
            valid with { Findings = [finding with { Available = "2.15.0-rc1" }] },
            valid with { Findings = [finding with { ObservedAt = valid.ScannedAt.AddSeconds(1) }] },
            valid with { Findings = [finding with { Kind = FindingKind.MutableTag }] },
            valid with { Findings = [finding with { VerifiedAlternative = "3.0.0-alpine", AlternativeUpgrade = VersionUpgrade.Major }] },
            valid with { Findings = Enumerable.Range(0, 1001).Select(i => finding with { ContainerName = $"c{i}" }).ToArray() }
        };
        foreach (var report in invalid)
        {
            using var response = await DashboardFactory.Post(client, report);
            Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode, await response.Content.ReadAsStringAsync());
        }
        Assert.IsNull(factory.Host().LatestReport);
    }

    [TestMethod]
    [DataRow("null")]
    [DataRow("{}")]
    [DataRow("{")]
    public async Task MalformedAndMissingRequiredJsonIsRejected(string json)
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        using var response = await client.PostAsync("/api/agents/reports", new StringContent(json, Encoding.UTF8, "application/json"));
        Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [TestMethod]
    public async Task UnknownPropertiesMissingFindingFieldsAndNumericEnumsAreRejected()
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        string json = JsonSerializer.Serialize(DashboardFactory.Report(), DashboardFactory.Json);
        foreach (string changed in new[] { json.Replace("\"complete\"", "3"), json.Replace("\"complete\"", "\"bogus\""),
            json.Replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"secret\":\"value\""),
            json.Replace("\"platformVerified\":true,", "") })
        {
            using var response = await client.PostAsync("/api/agents/reports", new StringContent(changed, Encoding.UTF8, "application/json"));
            Assert.AreEqual(HttpStatusCode.BadRequest, response.StatusCode);
        }
    }

    [TestMethod]
    public async Task RequestSizeAndContentTypeAreEnforced()
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        using var oversized = await client.PostAsync("/api/agents/reports", new StringContent(new string('x', 1024 * 1024 + 1), Encoding.UTF8, "application/json"));
        Assert.AreEqual(HttpStatusCode.RequestEntityTooLarge, oversized.StatusCode);
        using var text = await client.PostAsync("/api/agents/reports", new StringContent("{}"));
        Assert.AreEqual(HttpStatusCode.UnsupportedMediaType, text.StatusCode);
        Assert.IsNull(factory.Host().LatestReport);
    }
}
