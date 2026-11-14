using System.Net;
using System.Net.Http.Json;
using System.Text;
using HappyDocker;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace HappyDocker.Web.Tests;

[TestClass]
public sealed class DashboardTests
{
    [TestMethod]
    public async Task CliReportClientDeliversToTheRealIngestionEndpoint()
    {
        using var factory = new DashboardFactory();
        using var server = factory.CreateClient();
        Directory.CreateDirectory(factory.DirectoryPath);
        string tokenPath = Path.Combine(factory.DirectoryPath, "agent-token");
        File.WriteAllText(tokenPath, factory.TokenA);
        if (OperatingSystem.IsLinux()) File.SetUnixFileMode(tokenPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        using var reporter = new AgentReportClient("https://example.test/api/agents/reports", tokenPath, new IngestionHandler(server));
        using var registry = new RegistryClient();
        var run = await DockerCheck.RunObservedAsync(_ => Task.FromResult(new DockerCommandResult(0, "", "")), registry, TextWriter.Null, TextWriter.Null);
        var options = new FindingStateOptions([], Path.Combine(factory.DirectoryPath, "scanner.db"), "host-a",
            ReportUrl: "https://example.test/api/agents/reports", ReportTokenFile: tokenPath);
        Assert.AreEqual(0, await options.RecordAsync(run, _ => throw new AssertFailedException(), TextWriter.Null, reporter: reporter));
        Assert.AreEqual(FindingRunStatus.Complete, factory.Host().LatestReport!.Status);
        Assert.IsEmpty(factory.Host().Findings);
    }

    private sealed class IngestionHandler(HttpClient server) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            using var forwarded = new HttpRequestMessage(HttpMethod.Post, "/api/agents/reports");
            forwarded.Headers.Authorization = request.Headers.Authorization;
            forwarded.Content = new ByteArrayContent(await request.Content!.ReadAsByteArrayAsync(cancellationToken));
            forwarded.Content.Headers.ContentType = request.Content.Headers.ContentType;
            return await server.SendAsync(forwarded, cancellationToken);
        }
    }
    [TestMethod]
    public async Task ConstructedIncompleteSnapshotsPreserveServerFindingsUntilACompleteInventory()
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        var initial = DashboardFactory.Report();
        using var first = await DashboardFactory.Post(client, initial);
        Assert.AreEqual(HttpStatusCode.OK, first.StatusCode);
        DateTimeOffset timestamp = initial.ScannedAt;
        foreach (var evidence in new[] { FindingEvidence.Incomplete, FindingEvidence.Deferred })
        {
            timestamp = timestamp.AddMinutes(1);
            var observation = new FindingObservation(FindingKind.VersionCandidate, "nats", "id", null,
                "docker.io/library/nats", "2.14.8-alpine", null, null, null, evidence, timestamp);
            var run = new FindingRun(0, [observation]);
            var report = AgentReportBuilder.Build("host-a", run, [], timestamp);
            Assert.IsNull(ReportValidation.Validate(report, DateTimeOffset.UtcNow));
            using var response = await DashboardFactory.Post(client, report);
            Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
            Assert.AreNotEqual(FindingState.Resolved, factory.Host().Findings.Single().State);
        }
        timestamp = timestamp.AddMinutes(1);
        var failed = AgentReportBuilder.Build("host-a", new FindingRun(1, []), [], timestamp);
        using var failureResponse = await DashboardFactory.Post(client, failed);
        Assert.AreEqual(HttpStatusCode.OK, failureResponse.StatusCode);
        Assert.AreNotEqual(FindingState.Resolved, factory.Host().Findings.Single().State);

        using var registry = new RegistryClient();
        var empty = await DockerCheck.RunObservedAsync(_ => Task.FromResult(new DockerCommandResult(0, "", "")), registry, TextWriter.Null, TextWriter.Null);
        var complete = AgentReportBuilder.Build("host-a", empty, [], timestamp.AddMinutes(1));
        Assert.AreEqual(FindingRunStatus.Complete, complete.Status);
        using var last = await DashboardFactory.Post(client, complete);
        Assert.AreEqual(HttpStatusCode.OK, last.StatusCode);
        Assert.AreEqual(FindingState.Resolved, factory.Host().Findings.Single().State);
    }
    [TestMethod]
    public async Task EmptyInstallationAndRegisteredHostHaveDifferentEmptyStates()
    {
        using var empty = new DashboardFactory { RegisterAgents = false };
        using var emptyClient = empty.CreateClient();
        StringAssert.Contains(await emptyClient.GetStringAsync("/"), "No agents configured");
        using var factory = new DashboardFactory();
        using var client = factory.CreateClient();
        string html = await client.GetStringAsync("/");
        StringAssert.Contains(html, "No reports yet");
        StringAssert.Contains(html, "Awaiting report");
        StringAssert.Contains(html, "Never");
    }

    [TestMethod]
    [DataRow(FindingRunStatus.Failed)]
    [DataRow(FindingRunStatus.Partial)]
    [DataRow(FindingRunStatus.Deferred)]
    public async Task EmptyIncompleteScanDoesNotClaimAllChecksSucceeded(FindingRunStatus status)
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        using var response = await DashboardFactory.Post(client, DashboardFactory.Report(status, findings: []));
        string html = await client.GetStringAsync("/");
        StringAssert.Contains(html, "No outstanding findings known");
        StringAssert.Contains(html, "No known updates does not mean all checks succeeded.");
    }

    [TestMethod]
    public async Task HtmlIsEncodedAndNoCredentialsAreRendered()
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        var report = DashboardFactory.Report();
        using var response = await DashboardFactory.Post(client, report with { Findings = [report.Findings[0] with
        { ContainerName = "<script>alert('x')</script>" }] });
        Assert.AreEqual(HttpStatusCode.OK, response.StatusCode);
        string html = await client.GetStringAsync("/");
        StringAssert.Contains(html, "&lt;script&gt;");
        Assert.DoesNotContain("<script>", html);
        Assert.DoesNotContain(factory.TokenA, html);
        Assert.DoesNotContain(factory.TokenA, File.ReadAllText(factory.DatabasePath));
    }

    [TestMethod]
    public async Task BrowserIsIndependentOfAgentAuthenticationAndResponsesAreNotCached()
    {
        using var factory = new DashboardFactory();
        using var client = factory.CreateClient();
        using var page = await client.GetAsync("/");
        Assert.AreEqual(HttpStatusCode.OK, page.StatusCode);
        Assert.IsTrue(page.Headers.CacheControl!.NoStore);
        StringAssert.Contains(page.Headers.GetValues("Content-Security-Policy").Single(), "frame-ancestors 'none'");
        using var css = await client.GetAsync("/site.css");
        Assert.AreEqual(HttpStatusCode.OK, css.StatusCode);
        using var unauthorized = await DashboardFactory.Post(client, DashboardFactory.Report());
        Assert.AreEqual(HttpStatusCode.Unauthorized, unauthorized.StatusCode);
        using var noDocker = await client.GetAsync("/api/docker");
        Assert.AreEqual(HttpStatusCode.NotFound, noDocker.StatusCode);
    }

    [TestMethod]
    public async Task DatabaseCanBeReopenedAndReceiptsSurviveRestart()
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        var report = DashboardFactory.Report();
        using var first = await DashboardFactory.Post(client, report);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        { ["Web:DatabasePath"] = factory.DatabasePath }).Build();
        var reopened = new ReportStore(configuration, factory.Services.GetRequiredService<IWebHostEnvironment>());
        var host = reopened.ReadHosts([]).Single();
        Assert.AreEqual(report.ReportId, host.LatestReport!.ReportId);
        Assert.AreEqual(report.Findings[0], host.Findings.Single());
        Assert.AreEqual(IngestionOutcome.Duplicate, reopened.Ingest(report, DateTimeOffset.UtcNow));
        Assert.AreEqual(factory.Host().ReceivedAt, reopened.ReadHosts([]).Single().ReceivedAt);
    }

    [TestMethod]
    public async Task ForeignDatabaseIsRejectedWithoutModifyingItsSchema()
    {
        using var factory = new DashboardFactory();
        using var client = factory.CreateClient();
        string scanner = Path.Combine(factory.DirectoryPath, "scanner.db");
        using (var connection = new SqliteConnection($"Data Source={scanner};Pooling=False"))
        {
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "CREATE TABLE scanner_findings (id INTEGER); PRAGMA application_id = 1212433992; PRAGMA user_version = 4;";
            command.ExecuteNonQuery();
        }
        if (OperatingSystem.IsLinux()) File.SetUnixFileMode(scanner, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
        { ["Web:DatabasePath"] = scanner }).Build();
        Assert.ThrowsExactly<InvalidOperationException>(() => new ReportStore(configuration,
            factory.Services.GetRequiredService<IWebHostEnvironment>()));
        using var check = new SqliteConnection($"Data Source={scanner};Pooling=False");
        check.Open();
        using var query = check.CreateCommand();
        query.CommandText = "SELECT name FROM sqlite_schema WHERE type = 'table'";
        Assert.AreEqual("scanner_findings", query.ExecuteScalar());
    }

    [TestMethod]
    public async Task FailedTransactionDoesNotAdvanceLatestReportOrCreateReceipt()
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        var initial = DashboardFactory.Report();
        using var first = await DashboardFactory.Post(client, initial);
        using var connection = new SqliteConnection($"Data Source={factory.DatabasePath};Pooling=False");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "CREATE TRIGGER fail_findings BEFORE UPDATE ON findings BEGIN SELECT RAISE(ABORT, 'test failure'); END;";
        command.ExecuteNonQuery();
        var next = DashboardFactory.Report(minutesAgo: 5);
        using var failed = await DashboardFactory.Post(client, next);
        Assert.AreEqual(HttpStatusCode.ServiceUnavailable, failed.StatusCode);
        Assert.AreEqual(initial.ReportId, factory.Host().LatestReport!.ReportId);
        command.CommandText = "DROP TRIGGER fail_findings";
        command.ExecuteNonQuery();
        using var retry = await DashboardFactory.Post(client, next);
        StringAssert.Contains(await retry.Content.ReadAsStringAsync(), "accepted");
    }

    [TestMethod]
    public void InvalidAgentConfigurationFailsClosed()
    {
        string token = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32));
        foreach (var (hostA, tokenA, hostB, tokenB) in new[]
        {
            ("a", "short", "b", token), ("bad host", token, "b", token + "x"),
            ("a", token, "a", token + "x"), ("a", token, "b", token)
        })
        {
            var configuration = new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Web:Agents:0:HostId"] = hostA, ["Web:Agents:0:Token"] = tokenA,
                ["Web:Agents:1:HostId"] = hostB, ["Web:Agents:1:Token"] = tokenB
            }).Build();
            Assert.ThrowsExactly<InvalidOperationException>(() => new AgentAuthentication(configuration));
        }
    }

    [TestMethod]
    public async Task BodyWithoutContentLengthIsStillSizeLimited()
    {
        using var factory = new DashboardFactory();
        using var client = factory.AuthorizedClient();
        using var content = new UnknownLengthContent();
        using var response = await client.PostAsync("/api/agents/reports", content);
        Assert.AreEqual(HttpStatusCode.RequestEntityTooLarge, response.StatusCode);
        Assert.IsNull(factory.Host().LatestReport);
    }

    private sealed class UnknownLengthContent : HttpContent
    {
        public UnknownLengthContent() => Headers.ContentType = new("application/json");
        protected override bool TryComputeLength(out long length) { length = 0; return false; }
        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            stream.WriteAsync(new byte[ReportValidation.MaximumBytes + 1]).AsTask();
    }
}
