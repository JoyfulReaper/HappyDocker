using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace HappyDocker.Tests;

[TestClass]
public sealed class ReportDeliveryTests
{
    private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("happydocker-report-");
    private string Database => Path.Combine(directory.FullName, "state.db");
    private string TokenFile => Path.Combine(directory.FullName, "token");
    private const string Url = "https://reports.example/api/agents/reports";
    private const string Token = "0123456789abcdef0123456789abcdef";
    private readonly Clock clock = new();
    [TestInitialize]
    public void Initialize()
    {
        File.WriteAllText(TokenFile, Token + "\n");
        if (OperatingSystem.IsLinux()) File.SetUnixFileMode(TokenFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
    [TestCleanup]
    public void Cleanup() => directory.Delete(true);
    private AgentReportClient Client(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond, TimeSpan? timeout = null) =>
        new(Url, TokenFile, new Handler(respond), timeout);
    private AgentReport Report(FindingRunStatus status = FindingRunStatus.Partial) => AgentReportBuilder.Build("host", new FindingRun(0, []), [], clock.GetUtcNow(), clock) with { Status = status };
    private void Queue(AgentReportClient client, AgentReport report) => FindingHistory.WithDatabase(Database, (connection, tx) =>
    { ReportOutbox.Enqueue(connection, tx, "host", client.DestinationKey, report); return 0; });
    private static HttpResponseMessage Response(HttpStatusCode status, string content = "") => new(status) { Content = new StringContent(content, Encoding.UTF8, "application/json") };
    private static HttpResponseMessage Accepted(string outcome = "accepted") => Response(HttpStatusCode.OK, "{\"outcome\":\"" + outcome + "\"}");
    private object Scalar(string sql) => FindingHistory.WithDatabase(Database, (connection, tx) =>
    { using var command = connection.CreateCommand(); command.Transaction = tx; command.CommandText = sql; return command.ExecuteScalar()!; });
    private void Execute(string sql) => FindingHistory.WithDatabase(Database, (connection, tx) =>
    { using var command = connection.CreateCommand(); command.Transaction = tx; command.CommandText = sql; command.ExecuteNonQuery(); return 0; });

    [TestMethod]
    [DataRow("accepted", false)]
    [DataRow("duplicate", false)]
    [DataRow("older", true)]
    public async Task SuccessfulAcknowledgmentsRemoveOnlyTheAcknowledgedPayload(string outcome, bool older)
    {
        byte[]? payload = null;
        using var client = Client(async (request, _) =>
        {
            Assert.AreEqual("Bearer", request.Headers.Authorization!.Scheme);
            Assert.AreEqual(Token, request.Headers.Authorization.Parameter);
            payload = await request.Content!.ReadAsByteArrayAsync();
            return Accepted(outcome);
        });
        var report = Report();
        Queue(client, report);
        var result = await ReportOutbox.DeliverAsync(Database, "host", client, timeProvider: clock);
        Assert.AreEqual(1, result.Sent);
        Assert.AreEqual(older ? 1 : 0, result.Older);
        Assert.AreEqual(0, result.Pending);
        Assert.AreEqual(report.ReportId, JsonSerializer.Deserialize<AgentReport>(payload!, ReportJson.CreateOptions())!.ReportId);
    }

    [TestMethod]
    [DataRow(401, true)]
    [DataRow(403, true)]
    [DataRow(400, true)]
    [DataRow(409, true)]
    [DataRow(413, true)]
    [DataRow(415, true)]
    [DataRow(429, false)]
    [DataRow(503, false)]
    public async Task ErrorsRetainPayloadAndScheduleRetries(int status, bool permanent)
    {
        using var client = Client((_, _) => Task.FromResult(Response((HttpStatusCode)status)));
        Queue(client, Report());
        var result = await ReportOutbox.DeliverAsync(Database, "host", client, timeProvider: clock);
        Assert.AreEqual(1, result.Failed);
        Assert.AreEqual(1, result.Pending);
        Assert.AreEqual(clock.GetUtcNow().AddSeconds(permanent ? 86400 : 30).ToUnixTimeSeconds(), result.NextRetry!.Value.ToUnixTimeSeconds());
        var again = await ReportOutbox.DeliverAsync(Database, "host", client, timeProvider: clock);
        Assert.AreEqual(0, again.Failed);
        Assert.AreEqual($"HTTP {status}", again.Failure);
        Assert.AreEqual(1L, Scalar("SELECT attempts FROM report_outbox"));
    }

    [TestMethod]
    public async Task RestartRetryPreservesBytesIdentityAndHonorsRetryAfter()
    {
        byte[]? first = null, second = null;
        using (var client = Client(async (request, _) =>
        {
            first = await request.Content!.ReadAsByteArrayAsync();
            var response = Response(HttpStatusCode.TooManyRequests);
            response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromHours(2));
            return response;
        }))
        {
            Queue(client, Report());
            Assert.AreEqual(clock.GetUtcNow().AddHours(2).ToUnixTimeSeconds(), (await ReportOutbox.DeliverAsync(Database, "host", client, timeProvider: clock)).NextRetry!.Value.ToUnixTimeSeconds());
        }
        clock.Advance(TimeSpan.FromHours(2));
        using var restarted = Client(async (request, _) => { second = await request.Content!.ReadAsByteArrayAsync(); return Accepted("duplicate"); });
        Assert.AreEqual(1, (await ReportOutbox.DeliverAsync(Database, "host", restarted, timeProvider: clock)).Sent);
        CollectionAssert.AreEqual(first!, second!);
    }

    [TestMethod]
    public async Task TimeoutAndNetworkFailuresBackOffExponentially()
    {
        using var client = Client(async (_, token) => { await Task.Delay(Timeout.Infinite, token); return Accepted(); }, TimeSpan.FromMilliseconds(20));
        Queue(client, Report());
        var first = await ReportOutbox.DeliverAsync(Database, "host", client, timeProvider: clock);
        Assert.AreEqual("Request timed out", first.Failure);
        clock.Advance(TimeSpan.FromSeconds(30));
        var second = await ReportOutbox.DeliverAsync(Database, "host", client, timeProvider: clock);
        Assert.AreEqual(clock.GetUtcNow().AddSeconds(60).ToUnixTimeSeconds(), second.NextRetry!.Value.ToUnixTimeSeconds());
        clock.Advance(TimeSpan.FromSeconds(60));
        using var offline = Client((_, _) => throw new HttpRequestException("token detail never displayed"));
        var failure = await ReportOutbox.DeliverAsync(Database, "host", offline, timeProvider: clock);
        Assert.AreEqual("Network or response error", failure.Failure);
    }

    [TestMethod]
    public async Task ConcurrentInvocationsAndExpiredLeaseAreHandled()
    {
        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        int requests = 0;
        using var client = Client(async (_, token) => { Interlocked.Increment(ref requests); started.TrySetResult(); await release.Task.WaitAsync(token); return Accepted(); });
        Queue(client, Report());
        var first = ReportOutbox.DeliverAsync(Database, "host", client, timeProvider: clock);
        await started.Task;
        var concurrent = await ReportOutbox.DeliverAsync(Database, "host", client, timeProvider: clock);
        Assert.AreEqual(0, concurrent.Sent);
        Assert.AreEqual(1, requests);
        release.SetResult();
        Assert.AreEqual(1, (await first).Sent);
        Queue(client, Report());
        Execute($"UPDATE report_outbox SET lease_token='old', lease_until={clock.GetUtcNow().AddSeconds(-1).ToUnixTimeSeconds()}");
        Assert.AreEqual(1, (await ReportOutbox.DeliverAsync(Database, "host", client, timeProvider: clock)).Sent);
        Assert.AreEqual(2, requests);
    }

    [TestMethod]
    public async Task QueueLimitPreservesOlderReportsAndFifoBlocksNewerReports()
    {
        using var client = Client((_, _) => Task.FromResult(Response(HttpStatusCode.ServiceUnavailable)));
        for (int i = 0; i < ReportOutbox.MaximumQueuedReports; i++) Queue(client, Report());
        Assert.ThrowsExactly<InvalidOperationException>(() => Queue(client, Report()));
        Assert.AreEqual(100L, Scalar("SELECT COUNT(*) FROM report_outbox"));
        await ReportOutbox.DeliverAsync(Database, "host", client, timeProvider: clock);
        await ReportOutbox.DeliverAsync(Database, "host", client, timeProvider: clock);
        Assert.AreEqual(1L, Scalar("SELECT SUM(attempts) FROM report_outbox"));
    }

    [TestMethod]
    public void VersionFourMigrationPreservesFindingsAndNotificationOutbox()
    {
        var observation = new FindingObservation(FindingKind.MutableTag, "container", "id", null, "docker.io/library/nats",
            "latest", "sha256:" + new string('a', 64), "sha256:" + new string('b', 64), true,
            FindingEvidence.Present, DateTimeOffset.UtcNow);
        FindingHistory.Record(Database, "host", [observation], "destination");
        Execute("DROP TABLE report_outbox; PRAGMA user_version = 4");
        FindingHistory.Record(Database, "host", []);
        Assert.AreEqual(5L, Scalar("PRAGMA user_version"));
        Assert.AreEqual(1L, Scalar("SELECT COUNT(*) FROM findings"));
        Assert.AreEqual(1L, Scalar("SELECT COUNT(*) FROM notification_outbox"));
        Assert.AreEqual(0L, Scalar("SELECT COUNT(*) FROM report_outbox"));
    }

    [TestMethod]
    public async Task RedirectAndOversizedAcknowledgmentDoNotAcknowledgeReport()
    {
        int count = 0;
        using var redirect = Client((_, _) =>
        {
            count++;
            var response = Response(HttpStatusCode.Redirect);
            response.Headers.Location = new Uri("https://other.example/api/agents/reports");
            return Task.FromResult(response);
        });
        Queue(redirect, Report());
        var result = await ReportOutbox.DeliverAsync(Database, "host", redirect, timeProvider: clock);
        Assert.AreEqual(1, count);
        Assert.AreEqual(1, result.Pending);
        Assert.AreEqual("HTTP 302", result.Failure);
        clock.Advance(TimeSpan.FromDays(1));
        using var large = Client((_, _) => Task.FromResult(Response(HttpStatusCode.OK, new string('x', 4097))));
        var retry = await ReportOutbox.DeliverAsync(Database, "host", large, timeProvider: clock);
        Assert.AreEqual("Response too large", retry.Failure);
        Assert.AreEqual(1, retry.Pending);
    }

    [TestMethod]
    public async Task DisabledReportingDoesNotCreateQueueEntriesOrOutput()
    {
        var options = new FindingStateOptions([], Database, "host");
        using var output = new StringWriter();
        Assert.AreEqual(0, await options.RecordAsync(new FindingRun(0, []), _ => throw new AssertFailedException(), output));
        Assert.AreEqual(0L, Scalar("SELECT COUNT(*) FROM report_outbox"));
        Assert.DoesNotContain("Reports", output.ToString());
    }

    [TestMethod]
    public async Task ConfiguredCheckQueuesFailedAndCompleteScansWithoutChangingExitCodes()
    {
        var payloads = new List<AgentReport>();
        using var client = Client(async (request, _) => { payloads.Add(JsonSerializer.Deserialize<AgentReport>(await request.Content!.ReadAsByteArrayAsync(), ReportJson.CreateOptions())!); return Accepted(); });
        var options = new FindingStateOptions([], Database, "host", ReportUrl: Url, ReportTokenFile: TokenFile);
        using var registry = new RegistryClient();
        var empty = await DockerCheck.RunObservedAsync(_ => Task.FromResult(new DockerCommandResult(0, "", "")), registry, TextWriter.Null, TextWriter.Null);
        Assert.AreEqual(0, await options.RecordAsync(empty, _ => throw new AssertFailedException(), TextWriter.Null, reporter: client));
        Assert.AreEqual(FindingRunStatus.Complete, payloads[0].Status);
        Assert.IsEmpty(payloads[0].Findings);
        var failed = new FindingRun(7, []);
        Assert.AreEqual(7, await options.RecordAsync(failed, _ => throw new AssertFailedException(), TextWriter.Null, reporter: client));
        Assert.AreEqual(FindingRunStatus.Failed, payloads[1].Status);
        Assert.IsEmpty(payloads[1].Findings);
    }

    [TestMethod]
    public async Task ReportingAndNtfyRemainIndependentAndReportFailuresHaveTheirOwnExitCode()
    {
        int notifications = 0;
        using var notifier = new NtfyClient("https://ntfy.example/topic", handler: new Handler((_, _) =>
        { notifications++; return Task.FromResult(Response(HttpStatusCode.OK)); }));
        using var reporter = Client((_, _) => Task.FromResult(Response(HttpStatusCode.ServiceUnavailable)));
        var options = new FindingStateOptions([], Database, "host", "https://ntfy.example/topic", Url, TokenFile);
        var now = DateTimeOffset.UtcNow.AddSeconds(-1);
        var observation = new FindingObservation(FindingKind.MutableTag, "container", "id", null, "docker.io/library/nats",
            "latest", "sha256:" + new string('a', 64), "sha256:" + new string('b', 64), true, FindingEvidence.Present, now);
        using var output = new StringWriter();
        int exit = await options.RecordAsync(new FindingRun(0, [observation]) { HasFullHostCoverage = true },
            _ => throw new AssertFailedException(), output, notifier, reporter: reporter);
        Assert.AreEqual(5, exit);
        Assert.AreEqual(1, notifications);
        Assert.AreEqual(1L, Scalar("SELECT COUNT(*) FROM findings"));
        Assert.AreEqual(0L, Scalar("SELECT COUNT(*) FROM notification_outbox"));
        Assert.AreEqual(1L, Scalar("SELECT COUNT(*) FROM report_outbox"));
        StringAssert.Contains(output.ToString(), "HTTP 503");
        Assert.DoesNotContain(Token, output.ToString());
    }

    [TestMethod]
    public async Task PartialAndDeferredReportsAreDeliveredWithoutResolutionClaims()
    {
        var payloads = new List<AgentReport>();
        using var reporter = Client(async (request, _) => { payloads.Add(JsonSerializer.Deserialize<AgentReport>(await request.Content!.ReadAsByteArrayAsync(), ReportJson.CreateOptions())!); return Accepted(); });
        var options = new FindingStateOptions([], Database, "host", ReportUrl: Url, ReportTokenFile: TokenFile);
        foreach (var evidence in new[] { FindingEvidence.Incomplete, FindingEvidence.Deferred })
        {
            var now = DateTimeOffset.UtcNow.AddSeconds(-1);
            var observation = new FindingObservation(FindingKind.MutableTag, "container", "id", null, "docker.io/library/nats",
                "latest", null, null, null, evidence, now);
            var absent = observation with { ContainerName = "other", Evidence = FindingEvidence.Absent };
            var run = new FindingRun(0, [observation, absent]) { HasFullHostCoverage = true };
            int exit = await options.RecordAsync(run, _ => throw new AssertFailedException(), TextWriter.Null, reporter: reporter);
            Assert.AreEqual(evidence == FindingEvidence.Deferred ? 4 : 2, exit);
            Assert.IsEmpty(payloads.Last().Findings);
            Assert.AreEqual(evidence == FindingEvidence.Deferred ? FindingRunStatus.Deferred : FindingRunStatus.Partial, payloads.Last().Status);
        }
    }

    [TestMethod]
    public async Task StaleAbsenceCannotProduceAnAuthoritativeSnapshot()
    {
        AgentReport? sent = null;
        using var reporter = Client(async (request, _) => { sent = JsonSerializer.Deserialize<AgentReport>(await request.Content!.ReadAsByteArrayAsync(), ReportJson.CreateOptions()); return Accepted(); });
        var current = new FindingObservation(FindingKind.MutableTag, "container", "id", null, "docker.io/library/nats",
            "latest", "sha256:" + new string('a', 64), "sha256:" + new string('b', 64), true,
            FindingEvidence.Present, DateTimeOffset.UtcNow.AddMinutes(-1));
        FindingHistory.Record(Database, "host", [current]);
        var stale = current with { Evidence = FindingEvidence.Absent, Available = null, ObservedAt = current.ObservedAt.AddMinutes(-1) };
        var options = new FindingStateOptions([], Database, "host", ReportUrl: Url, ReportTokenFile: TokenFile);
        using var output = new StringWriter();
        await options.RecordAsync(new FindingRun(0, [stale]) { HasFullHostCoverage = true },
            _ => throw new AssertFailedException(), output, reporter: reporter);
        Assert.AreEqual(FindingRunStatus.Partial, sent!.Status);
        Assert.IsEmpty(sent.Findings);
        StringAssert.Contains(output.ToString(), "observations omitted");
        Assert.AreEqual("New", Scalar("SELECT state FROM findings"));
    }

    [TestMethod]
    public void ConfigurationRequiresExplicitHostStateTokenAndSafeEndpoint()
    {
        Assert.IsFalse(FindingStateOptions.TryParse(["--state", Database, "--report-url", Url, "--report-token-file", TokenFile], out _));
        Assert.IsFalse(FindingStateOptions.TryParse(["--state", Database, "--host", "host", "--report-url", Url], out _));
        Assert.IsTrue(FindingStateOptions.TryParse(["--state", Database, "--host", "host", "--report-url", "http://10.99.0.16:5080/api/agents/reports", "--report-token-file", TokenFile], out _));
        foreach (string bad in new[] { "http://example.com/api/agents/reports", "http://8.8.8.8/api/agents/reports", "https://user:pass@example.com/api/agents/reports", "https://example.com/api/agents/reports?x=1", "https://example.com/else" })
            Assert.ThrowsExactly<ReportConfigurationException>(() => AgentReportClient.ParseDestination(bad));
        Assert.ThrowsExactly<ReportConfigurationException>(() => new AgentReportClient(Url, Path.Combine(directory.FullName, "missing")));
        if (OperatingSystem.IsLinux())
        {
            File.SetUnixFileMode(TokenFile, UnixFileMode.UserRead | UnixFileMode.GroupRead);
            Assert.ThrowsExactly<ReportConfigurationException>(() => new AgentReportClient(Url, TokenFile));
        }
    }

    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken token) => send(request, token); }
    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(TimeSpan delay) => now += delay;
    }
}
