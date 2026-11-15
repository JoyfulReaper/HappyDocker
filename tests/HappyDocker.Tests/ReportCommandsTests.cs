using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace HappyDocker.Tests;

[TestClass]
public sealed class ReportCommandsTests
{
    private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("happydocker-operator-");
    private string Database => Path.Combine(directory.FullName, "state.db");
    private string TokenFile => Path.Combine(directory.FullName, "token");
    private const string DestinationA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    private const string DestinationB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    private readonly Clock clock = new();
    [TestInitialize]
    public void Initialize()
    {
        FindingHistory.Record(Database, "host-a", []);
        File.WriteAllText(TokenFile, new string('t', 32));
        if (OperatingSystem.IsLinux()) File.SetUnixFileMode(TokenFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);
    }
    [TestCleanup]
    public void Cleanup() => directory.Delete(true);
    private AgentReport Report(string host = "host-a") => new()
    { SchemaVersion = 1, HostId = host, ReportId = Guid.NewGuid(), ScannedAt = clock.GetUtcNow(), Status = FindingRunStatus.Partial, Findings = [] };
    private void Queue(AgentReport report, string destination) => FindingHistory.WithDatabase(Database, (connection, tx) =>
    { ReportOutbox.Enqueue(connection, tx, report.HostId, destination, report); return 0; });
    private int Run(out string output, out string error, params string[] args)
    {
        using var stdout = new StringWriter();
        using var stderr = new StringWriter();
        int result = ReportCommands.Run(args, stdout, stderr, clock);
        output = stdout.ToString(); error = stderr.ToString();
        return result;
    }
    private int Run(params string[] args) => Run(out _, out _, args);
    private byte[] Payload(Guid id) => FindingHistory.WithDatabase(Database, (connection, tx) =>
    {
        using var command = connection.CreateCommand(); command.Transaction = tx;
        command.CommandText = "SELECT payload FROM report_outbox";
        using var reader = command.ExecuteReader();
        while (reader.Read())
        {
            var data = (byte[])reader[0];
            if (JsonSerializer.Deserialize<AgentReport>(data, ReportJson.CreateOptions())!.ReportId == id) return data;
        }
        throw new AssertFailedException("Missing report");
    });
    private void Execute(string sql) => FindingHistory.WithDatabase(Database, (connection, tx) =>
    { using var command = connection.CreateCommand(); command.Transaction = tx; command.CommandText = sql; command.ExecuteNonQuery(); return 0; });
    private long Count() => FindingHistory.WithDatabase(Database, (connection, tx) =>
    { using var command = connection.CreateCommand(); command.Transaction = tx; command.CommandText = "SELECT COUNT(*) FROM report_outbox"; return (long)command.ExecuteScalar()!; });

    [TestMethod]
    public void StatusIsReadOnlyAndDoesNotCreateOrMigrateDatabases()
    {
        var before = SHA256.HashData(File.ReadAllBytes(Database));
        Assert.AreEqual(0, Run(out var output, out _, "status", "--state", Database));
        StringAssert.Contains(output, "empty");
        CollectionAssert.AreEqual(before, SHA256.HashData(File.ReadAllBytes(Database)));
        string missing = Path.Combine(directory.FullName, "missing.db");
        Assert.AreEqual(1, Run("status", "--state", missing));
        Assert.IsFalse(File.Exists(missing));
        Execute("PRAGMA user_version = 4");
        Assert.AreEqual(1, Run(out _, out var error, "status", "--state", Database));
        StringAssert.Contains(error, "no migration");
        using var connection = new SqliteConnection($"Data Source={Database};Mode=ReadOnly;Pooling=False");
        connection.Open();
        using var command = connection.CreateCommand(); command.CommandText = "PRAGMA user_version";
        Assert.AreEqual(4L, command.ExecuteScalar());
    }

    [TestMethod]
    public void StatusDisplaysOnlySafeMetadataForAllHostsAndDestinations()
    {
        var first = Report(); var second = Report("host-b");
        Queue(first, DestinationA); Queue(second, DestinationB);
        Execute($"UPDATE report_outbox SET attempts=3, next_attempt={clock.GetUtcNow().AddHours(1).ToUnixTimeSeconds()}, last_error='HTTP 401' WHERE host='host-a'");
        Execute($"UPDATE report_outbox SET lease_token='secret', lease_until={clock.GetUtcNow().AddMinutes(1).ToUnixTimeSeconds()} WHERE host='host-b'");
        var before = SHA256.HashData(File.ReadAllBytes(Database));
        Assert.AreEqual(0, Run(out var output, out _, "status", "--state", Database));
        foreach (string expected in new[] { first.ReportId.ToString(), second.ReportId.ToString(), "host-a", "host-b", DestinationA, DestinationB, "attempts 3", "HTTP 401", "active until", "next retry" })
            StringAssert.Contains(output, expected);
        Assert.DoesNotContain("secret", output);
        Assert.DoesNotContain("findings", output);
        CollectionAssert.AreEqual(before, SHA256.HashData(File.ReadAllBytes(Database)));
    }

    [TestMethod]
    public async Task RetryAfterAuthenticationRepairPreservesPayloadAndIdentity()
    {
        byte[]? initial = null; byte[]? retried = null;
        using var failing = Client(async (request, _) => { initial = await request.Content!.ReadAsByteArrayAsync(); return new(HttpStatusCode.Unauthorized); });
        var report = Report(); Queue(report, failing.DestinationKey);
        Assert.AreEqual(1, (await ReportOutbox.DeliverAsync(Database, "host-a", failing, timeProvider: clock)).Pending);
        Assert.AreEqual(0, Run(out var status, out _, "status", "--state", Database));
        StringAssert.Contains(status, "HTTP 401");
        byte[] persisted = Payload(report.ReportId);
        Assert.AreEqual(0, Run("retry", "--state", Database, "--id", report.ReportId.ToString()));
        CollectionAssert.AreEqual(persisted, Payload(report.ReportId));
        using var repaired = Client(async (request, _) => { retried = await request.Content!.ReadAsByteArrayAsync(); return new(HttpStatusCode.OK) { Content = new StringContent("{\"outcome\":\"duplicate\"}", Encoding.UTF8, "application/json") }; });
        Assert.AreEqual(1, (await ReportOutbox.DeliverAsync(Database, "host-a", repaired, timeProvider: clock)).Sent);
        CollectionAssert.AreEqual(initial!, retried!);
        Assert.AreEqual(report.ReportId, JsonSerializer.Deserialize<AgentReport>(retried!, ReportJson.CreateOptions())!.ReportId);
        Assert.AreEqual(0L, Count());
    }

    [TestMethod]
    public void ActiveLeasesBlockChangesButExpiredLeasesAllowThem()
    {
        var report = Report(); Queue(report, DestinationA);
        Execute($"UPDATE report_outbox SET lease_token='lease', lease_until={clock.GetUtcNow().AddMinutes(1).ToUnixTimeSeconds()}, next_attempt=1234567890");
        Assert.AreEqual(1, Run(out _, out var retryError, "retry", "--state", Database, "--id", report.ReportId.ToString()));
        StringAssert.Contains(retryError, "active delivery lease");
        Assert.AreEqual(1, Run("discard", "--state", Database, "--id", report.ReportId.ToString(), "--confirm"));
        Assert.AreEqual(1L, Count());
        clock.Advance(TimeSpan.FromMinutes(2));
        Assert.AreEqual(0, Run(out var status, out _, "status", "--state", Database));
        StringAssert.Contains(status, "lease expired");
        var data = Payload(report.ReportId);
        Assert.AreEqual(0, Run("retry", "--state", Database, "--id", report.ReportId.ToString()));
        CollectionAssert.AreEqual(data, Payload(report.ReportId));
        Assert.AreEqual(0, Run(out var warning, out _, "discard", "--state", Database, "--id", report.ReportId.ToString(), "--confirm"));
        StringAssert.Contains(warning, "may lose observations");
        Assert.AreEqual(0L, Count());
    }

    [TestMethod]
    public void ExactIdentityAndConfirmationAreRequiredAndAmbiguousIdsAreRejected()
    {
        var first = Report(); var second = Report("host-b");
        Queue(first, DestinationA); Queue(second, DestinationB);
        Assert.AreEqual(1, Run("discard", "--state", Database, "--id", first.ReportId.ToString()));
        Assert.AreEqual(1, Run("discard", "--state", Database, "--id", first.ReportId.ToString(), "--confirm", "--confirm"));
        Assert.AreEqual(1, Run("retry", "--state", Database, "--id", first.ReportId.ToString()[..8]));
        Assert.AreEqual(1, Run("retry", "--state", Database, "--id", " " + first.ReportId));
        Assert.AreEqual(1, Run("retry", "--state", Database, "--id", Guid.Empty.ToString()));
        Assert.AreEqual(1, Run("discard", "--state", Database, "--id", Guid.NewGuid().ToString(), "--confirm"));
        Assert.AreEqual(0, Run("discard", "--state", Database, "--id", first.ReportId.ToString(), "--confirm"));
        Assert.AreEqual(1L, Count());
        CollectionAssert.AreEqual(JsonSerializer.SerializeToUtf8Bytes(second, ReportJson.CreateOptions()), Payload(second.ReportId));
        Queue(second with { HostId = "host-a" }, DestinationA);
        Assert.AreEqual(1, Run(out _, out var error, "retry", "--state", Database, "--id", second.ReportId.ToString()));
        StringAssert.Contains(error, "ambiguous");
        Assert.AreEqual(1, Run("discard", "--state", Database, "--id", second.ReportId.ToString(), "--confirm"));
        Assert.AreEqual(2L, Count());
    }

    [TestMethod]
    public void DiscardRestoresQueueCapacityWithoutTouchingOtherReports()
    {
        var reports = Enumerable.Range(0, ReportOutbox.MaximumQueuedReports).Select(_ => Report()).ToArray();
        foreach (var report in reports) Queue(report, DestinationA);
        Assert.ThrowsExactly<InvalidOperationException>(() => Queue(Report(), DestinationB));
        Assert.AreEqual(0, Run("discard", "--state", Database, "--id", reports[0].ReportId.ToString(), "--confirm"));
        var replacement = Report("host-b"); Queue(replacement, DestinationB);
        Assert.AreEqual((long)ReportOutbox.MaximumQueuedReports, Count());
        CollectionAssert.AreEqual(JsonSerializer.SerializeToUtf8Bytes(reports[1], ReportJson.CreateOptions()), Payload(reports[1].ReportId));
        CollectionAssert.AreEqual(JsonSerializer.SerializeToUtf8Bytes(replacement, ReportJson.CreateOptions()), Payload(replacement.ReportId));
    }

    private AgentReportClient Client(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) =>
        new("https://reports.example/api/agents/reports", TokenFile, new Handler(send));
    private sealed class Handler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send) : HttpMessageHandler
    { protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) => send(request, cancellationToken); }
    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(TimeSpan duration) => now += duration;
    }
}
