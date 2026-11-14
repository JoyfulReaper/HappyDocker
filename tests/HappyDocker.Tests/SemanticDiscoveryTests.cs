using System.Globalization;
using System.Net;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using static HappyDocker.Tests.RegistryFixture;

namespace HappyDocker.Tests;

[TestClass]
public sealed class SemanticDiscoveryTests
{
    private const string Destination = "https://ntfy.example/versions";
    private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("happydocker-semantic-");
    private string Database => Path.Combine(directory.FullName, "findings.db");

    [TestCleanup]
    public void Cleanup()
    {
        foreach (FileInfo file in directory.GetFiles()) file.Delete();
        directory.Delete();
    }

    [TestMethod]
    [DataRow("1.2.3", "1.2.4", VersionUpgrade.Patch)]
    [DataRow("1.2.3", "1.3.0", VersionUpgrade.Minor)]
    [DataRow("1.2.3", "2.0.0", VersionUpgrade.Major)]
    [DataRow("v2.26.0", "v2.27.0", VersionUpgrade.Minor)]
    [DataRow("2.14.8-alpine", "2.15.1-alpine", VersionUpgrade.Minor)]
    [DataRow("1.9.0", "1.10.0", VersionUpgrade.Minor)]
    public async Task UnifiedCheckFindsAndClassifiesStableUpgrades(string current, string next, VersionUpgrade upgrade)
    {
        using var fixture = Fixture(current);
        fixture.SetTag(Index(Descriptor(fixture.NewManifest)), next);
        fixture.Intercept = request => IsTags(request) ? Tags(fixture.Repository, [current, next]) : null;
        var (run, output) = await Run(fixture);
        var version = Candidate(run);
        Assert.AreEqual(FindingRunStatus.Complete, run.Status);
        Assert.AreEqual(FindingEvidence.Absent, run.Observations.Single(item => item.Kind == FindingKind.MutableTag).Evidence);
        Assert.AreEqual(next, version.Available);
        Assert.AreEqual(upgrade, version.Upgrade);
        Assert.IsTrue(version.PlatformVerified ?? false);
        Assert.Contains("Upgrade " + upgrade, output);
    }

    [TestMethod]
    public async Task LatestReleaseProducesOneGroupedAlertRatherThanIntermediateAlerts()
    {
        using var fixture = Fixture();
        string[] tags = ["v2.26.1", "v2.27.0", "v3.0.0", "v4.0.0-rc1", "9.0.0", "v9.0.0-alpine"];
        foreach (string tag in tags.Take(3)) fixture.SetTag(Index(Descriptor(fixture.NewManifest)), tag);
        fixture.Intercept = request => IsTags(request) ? Tags(fixture.Repository, tags) : null;
        var second = fixture.Container with { Id = "second", Name = "/ntfy-two" };
        var result = await Run(fixture, [fixture.Container, second]);
        Assert.AreEqual(2, result.Run.Observations.Count(item => item.Kind == FindingKind.VersionCandidate));
        Assert.IsTrue(result.Run.Observations.Where(item => item.Kind == FindingKind.VersionCandidate)
            .All(item => item.Available == "v3.0.0" && item.Upgrade == VersionUpgrade.Major));
        Assert.HasCount(1, fixture.Requests.Where(item => item.Path.EndsWith("/tags/list")));
        Assert.HasCount(1, fixture.Requests.Where(item => item.Path.EndsWith("/manifests/v3.0.0")));
        Assert.IsFalse(fixture.Requests.Any(item => item.Path.EndsWith("/manifests/v2.27.0")));
        var messages = new List<string>();
        using var notifier = Notifier(messages);
        var options = new FindingStateOptions([], Database, "clanker", Destination);
        Assert.AreEqual(0, await options.RecordAsync(result.Run, NoDocker, TextWriter.Null, notifier));
        Assert.HasCount(1, messages);
        Assert.Contains("New major version candidate", messages[0]);
        Assert.Contains("ntfy, ntfy-two", messages[0]);
        Assert.AreEqual(2L, Scalar("SELECT count(*) FROM findings WHERE kind = 'VersionCandidate'"));
        Assert.AreEqual(0, await options.RecordAsync(result.Run, NoDocker, TextWriter.Null, notifier));
        Assert.HasCount(1, messages);
    }

    [TestMethod]
    public async Task UnverifiedNewestReleaseKeepsItsIdentityAndReportsAVerifiedLowerAlternative()
    {
        using var fixture = Fixture();
        SetArmOnly(fixture, "v3.0.0");
        fixture.SetTag(Index(Descriptor(fixture.NewManifest)), "v2.27.0");
        fixture.Intercept = request => IsTags(request) ? Tags(fixture.Repository, ["v2.27.0", "v3.0.0"]) : null;
        var result = await Run(fixture);
        var candidate = Candidate(result.Run);
        Assert.AreEqual("v3.0.0", candidate.Available);
        Assert.AreEqual(VersionUpgrade.Major, candidate.Upgrade);
        Assert.IsFalse(candidate.PlatformVerified ?? true);
        Assert.AreEqual("v2.27.0", candidate.VerifiedAlternative);
        Assert.AreEqual(VersionUpgrade.Minor, candidate.AlternativeUpgrade);
        Assert.AreEqual(FindingRunStatus.Partial, result.Run.Status);
        Assert.Contains("Candidate v3.0.0 (platform unverified)", result.Output);
        Assert.Contains("Verified alternative v2.27.0 (Minor; platform verified)", result.Output);
        var messages = new List<string>();
        using var notifier = Notifier(messages);
        var options = new FindingStateOptions([], Database, "clanker", Destination);
        Assert.AreEqual(2, await options.RecordAsync(result.Run, NoDocker, TextWriter.Null, notifier));
        Assert.HasCount(1, messages);
        Assert.Contains("newest platform unverified", messages[0]);
        Assert.Contains("Verified alternative v2.27.0 (minor; platform verified)", messages[0]);
        Assert.AreEqual("v3.0.0", Scalar("SELECT available FROM findings"));
        Assert.AreEqual(0L, Scalar("SELECT platform_verified FROM findings"));
        Assert.AreEqual("v2.27.0", Scalar("SELECT verified_alternative FROM findings"));
        fixture.SetTag(Index(Descriptor(fixture.NewManifest)), "v3.0.0");
        Assert.AreEqual(0, await options.RecordAsync((await Run(fixture)).Run, NoDocker, TextWriter.Null, notifier));
        Assert.HasCount(1, messages); // Improving confidence in the same newest candidate stays Known.
        Assert.AreEqual("Known", Scalar("SELECT state FROM findings"));
    }

    [TestMethod]
    public async Task DeferredEligibilityCanBeReleasedByAVerifiedAlternativeFromCachedTags()
    {
        using var fixture = Fixture();
        SetArmOnly(fixture, "v3.0.0");
        SetArmOnly(fixture, "v2.27.0");
        fixture.Intercept = request => IsTags(request) ? Tags(fixture.Repository, ["v3.0.0", "v2.27.0"]) : null;
        var cache = new VersionDiscoveryCache(Database);
        var messages = new List<string>();
        using var notifier = Notifier(messages);
        var options = new FindingStateOptions([], Database, "clanker", Destination);
        Assert.AreEqual(2, await options.RecordAsync((await Run(fixture, cache: cache)).Run, NoDocker, TextWriter.Null, notifier));
        Assert.IsEmpty(messages);
        Assert.AreEqual("New", Scalar("SELECT pending_notification_state FROM findings"));
        fixture.SetTag(Index(Descriptor(fixture.NewManifest)), "v2.27.0");
        fixture.Intercept = request => IsTags(request) ? throw new AssertFailedException("Complete tags should be cached.") : null;
        Assert.AreEqual(2, await options.RecordAsync((await Run(fixture, cache: cache)).Run, NoDocker, TextWriter.Null, notifier));
        Assert.HasCount(1, messages);
        Assert.AreEqual("Known", Scalar("SELECT state FROM findings"));
        Assert.AreEqual(DBNull.Value, Scalar("SELECT pending_notification_state FROM findings"));
    }

    [TestMethod]
    public async Task TemporaryAlternativeRequestFailurePreservesHistoricalVerificationWithoutANewAlert()
    {
        using var fixture = Fixture();
        SetArmOnly(fixture, "v3.0.0");
        fixture.SetTag(Index(Descriptor(fixture.NewManifest)), "v2.27.0");
        fixture.Intercept = request => IsTags(request) ? Tags(fixture.Repository, ["v3.0.0", "v2.27.0"]) : null;
        var messages = new List<string>();
        using var notifier = Notifier(messages);
        var options = new FindingStateOptions([], Database, "clanker", Destination);
        Assert.AreEqual(2, await options.RecordAsync((await Run(fixture)).Run, NoDocker, TextWriter.Null, notifier));
        fixture.Intercept = request => IsTags(request) ? Tags(fixture.Repository, ["v3.0.0", "v2.27.0"])
            : request.RequestUri!.AbsolutePath.EndsWith("/v2.27.0", StringComparison.Ordinal) ? Error(HttpStatusCode.ServiceUnavailable) : null;
        var failed = (await Run(fixture)).Run;
        Assert.IsNull(Candidate(failed).VerifiedAlternative);
        Assert.AreEqual(2, await options.RecordAsync(failed, NoDocker, TextWriter.Null, notifier));
        Assert.AreEqual("v2.27.0", Scalar("SELECT verified_alternative FROM findings"));
        Assert.AreEqual(0L, Scalar("SELECT platform_verified FROM findings"));
        Assert.AreEqual("Known", Scalar("SELECT state FROM findings"));
        Assert.HasCount(1, messages);
    }

    [TestMethod]
    public async Task LowerCandidateVerificationIsBoundedAndItsLimitIsVisible()
    {
        using var fixture = Fixture("1.0.0");
        string[] tags = Enumerable.Range(2, 7).Select(major => $"{major}.0.0").ToArray();
        foreach (string tag in tags) SetArmOnly(fixture, tag);
        fixture.SetTag(Index(Descriptor(fixture.NewManifest)), "3.0.0");
        fixture.Intercept = request => IsTags(request) ? Tags(fixture.Repository, tags) : null;
        var result = await Run(fixture);
        Assert.AreEqual("8.0.0", Candidate(result.Run).Available);
        Assert.IsNull(Candidate(result.Run).VerifiedAlternative);
        Assert.IsFalse(Candidate(result.Run).HasVerifiedCandidate);
        Assert.Contains("limited to five candidates", result.Output);
        Assert.HasCount(5, fixture.Requests.Where(item => tags.Any(tag => item.Path.EndsWith("/manifests/" + tag, StringComparison.Ordinal))));
        Assert.IsFalse(fixture.Requests.Any(item => item.Path.EndsWith("/manifests/3.0.0")));
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task GhcrPaginationUsesTheExistingAnonymousOrPrivateBearerExchange(bool authenticated)
    {
        const string pat = "ghp_fixture_secret";
        var credentials = authenticated ? GhcrCredentials.Load("fixture", null, pat) : null;
        using var fixture = new RegistryFixture("ghcr.io", "fixture/ntfy", "v2.26.0", credentials);
        fixture.UseContainerd(true);
        fixture.SetTag(Index(Descriptor(fixture.NewManifest)), "v3.0.0");
        fixture.Intercept = request =>
        {
            if (request.RequestUri!.AbsolutePath == "/token")
            {
                Assert.AreEqual("ghcr.io", request.RequestUri.Host);
                Assert.AreEqual("https", request.RequestUri.Scheme);
                Assert.AreEqual(authenticated ? "Basic" : null, request.Headers.Authorization?.Scheme);
                Assert.AreEqual("?service=ghcr.io&scope=repository:fixture/ntfy:pull", Uri.UnescapeDataString(request.RequestUri.Query));
                return Response(Bytes("""{"token":"fixture-bearer"}"""));
            }
            if (request.Headers.Authorization?.Parameter != "fixture-bearer")
            {
                var challenge = Error(HttpStatusCode.Unauthorized);
                challenge.Headers.WwwAuthenticate.Add(new("Bearer",
                    "realm=\"https://ghcr.io/token\",service=\"ghcr.io\",scope=\"repository:fixture/ntfy:pull\""));
                return challenge;
            }
            if (!IsTags(request)) return null;
            return request.RequestUri.Query == "?n=100"
                ? Tags(fixture.Repository, ["v2.27.0"], "</v2/fixture/ntfy/tags/list?n=2&last=v2.27.0>; rel=\"next\"")
                : Tags(fixture.Repository, ["v3.0.0"]);
        };
        var result = await Run(fixture, cache: new VersionDiscoveryCache(Database));
        Assert.AreEqual(FindingRunStatus.Complete, result.Run.Status);
        Assert.AreEqual(VersionUpgrade.Major, Candidate(result.Run).Upgrade);
        Assert.HasCount(2, fixture.Requests.Where(item => item.Path.EndsWith("/tags/list")));
        Assert.HasCount(1, fixture.Requests.Where(item => item.Path == "/token"));
        Assert.IsFalse(fixture.Requests.Any(item => item.Authorization?.StartsWith("Basic ", StringComparison.Ordinal) == true && item.Path != "/token"));
        Assert.DoesNotContain(pat, result.Output);
        Assert.DoesNotContain(pat, Encoding.UTF8.GetString(File.ReadAllBytes(Database)));
        Assert.AreEqual("ghcr.io/fixture/ntfy", Scalar("SELECT repository FROM version_discovery_cache"));
    }

    [TestMethod]
    [DataRow(401)]
    [DataRow(403)]
    [DataRow(429)]
    [DataRow(503)]
    public async Task GhcrListingFailuresStayIncomplete(int code)
    {
        using var fixture = new RegistryFixture("ghcr.io", "fixture/ntfy", "1.2.3");
        fixture.UseContainerd(false);
        fixture.Intercept = request => IsTags(request) ? Error((HttpStatusCode)code) : null;
        var result = await Run(fixture);
        Assert.AreEqual(FindingRunStatus.Partial, result.Run.Status);
        Assert.AreEqual(FindingEvidence.Incomplete, Candidate(result.Run).Evidence);
        Assert.Contains("Incomplete enumeration", result.Output);
    }

    [TestMethod]
    [DataRow("https://registry-1.docker.io/v2/fixture/ntfy/tags/list?n=2&last=1.3.0")]
    [DataRow("http://ghcr.io/v2/fixture/ntfy/tags/list?n=2&last=1.3.0")]
    public async Task GhcrRejectsUnsafePaginationDestinations(string target)
    {
        using var fixture = new RegistryFixture("ghcr.io", "fixture/ntfy", "1.2.3");
        fixture.UseContainerd(false);
        fixture.SetTag(fixture.NewManifest, "1.3.0");
        fixture.Intercept = request => IsTags(request) ? Tags(fixture.Repository, ["1.3.0"], $"<{target}>; rel=\"next\"") : null;
        var result = await Run(fixture);
        Assert.AreEqual(FindingEvidence.Incomplete, Candidate(result.Run).Evidence);
        Assert.HasCount(1, fixture.Requests.Where(item => item.Path.EndsWith("/tags/list")));
        Assert.IsTrue(fixture.Requests.All(item => item.Host == "ghcr.io"));
    }

    [TestMethod]
    public async Task IdenticalRepositoryNamesOnDifferentRegistriesHaveSeparateCachedLists()
    {
        var cache = new VersionDiscoveryCache(Database);
        using var hub = new RegistryFixture("docker.io", "fixture/ntfy", "1.2.3");
        hub.UseContainerd(false);
        hub.SetTag(hub.NewManifest, "2.0.0");
        hub.Intercept = request => IsTags(request) ? Tags(hub.Repository, ["2.0.0"]) : null;
        using var ghcr = new RegistryFixture("ghcr.io", "fixture/ntfy", "1.2.3");
        ghcr.UseContainerd(false);
        ghcr.SetTag(ghcr.NewManifest, "3.0.0");
        ghcr.Intercept = request => IsTags(request) ? Tags(ghcr.Repository, ["3.0.0"]) : null;
        Assert.AreEqual("2.0.0", Candidate((await Run(hub, cache: cache)).Run).Available);
        Assert.AreEqual("3.0.0", Candidate((await Run(ghcr, cache: cache)).Run).Available);
        Assert.AreEqual(2L, Scalar("SELECT count(*) FROM version_discovery_cache"));
    }

    [TestMethod]
    public async Task ProductionV3MigrationPreservesIdentityEligibilityOutboxAndCache()
    {
        var messages = new List<string>();
        using var notifier = Notifier(messages);
        var known = CreateV3(notifier.DestinationKey);
        var transitions = FindingHistory.Record(Database, "clanker", [known], notifier.DestinationKey);
        Assert.AreEqual(FindingState.Known, transitions.Single().State);
        Assert.AreEqual(5L, Scalar("PRAGMA user_version"));
        Assert.AreEqual(3L, Scalar("SELECT count(*) FROM findings WHERE kind = 'VersionCandidate'"));
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM findings WHERE state = 'Resolved' AND container_name != 'resolved'"));
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM notification_outbox"));
        Assert.AreEqual(7L, Scalar("SELECT attempts FROM notification_outbox"));
        Assert.AreEqual("legacy-lease", Scalar("SELECT lease_token FROM notification_outbox"));
        Assert.AreEqual(9999999999L, Scalar("SELECT lease_until FROM notification_outbox"));
        Assert.AreEqual(9999999999L, Scalar("SELECT next_attempt FROM notification_outbox"));
        Assert.AreEqual("legacy patch alert", Scalar("SELECT message FROM notification_outbox"));
        Assert.AreEqual("docker.io/library/nats", Scalar("SELECT repository FROM version_discovery_cache"));
        Assert.AreEqual(123L, Scalar("SELECT last_attempt FROM version_discovery_cache"));
        Assert.AreEqual("[\"2.14.9-alpine\",\"3.0.0-alpine\"]", Scalar("SELECT tags_json FROM version_discovery_cache"));
        var awaiting = known with { ContainerName = "awaiting", Available = "2.14.10-alpine", PlatformVerified = true };
        Assert.AreEqual(FindingState.Known, FindingHistory.Record(Database, "clanker", [awaiting], notifier.DestinationKey).Single().State);
        Assert.AreEqual(2L, Scalar("SELECT count(*) FROM notification_outbox"));
        Assert.AreEqual(DBNull.Value, Scalar("SELECT pending_notification_state FROM findings WHERE container_name = 'awaiting'"));
        Assert.AreEqual(FindingState.Known, FindingHistory.Record(Database, "clanker", [awaiting], notifier.DestinationKey).Single().State);
        Assert.AreEqual(2L, Scalar("SELECT count(*) FROM notification_outbox"));
        var major = known with { Available = "3.0.0-alpine", ObservedAt = known.ObservedAt.AddSeconds(1) };
        Assert.AreEqual(FindingState.Changed, FindingHistory.Record(Database, "clanker", [major], notifier.DestinationKey).Single().State);
        Assert.AreEqual(3L, Scalar("SELECT count(*) FROM notification_outbox"));
        Execute("UPDATE notification_outbox SET next_attempt = 0, lease_until = 0, lease_token = NULL");
        var delivered = await NotificationOutbox.DeliverAsync(Database, "clanker", notifier);
        Assert.AreEqual(3, delivered.Sent);
        Assert.Contains("legacy patch alert", messages[0]);
        Assert.IsTrue(messages.Any(message => message.Contains("Changed major version candidate", StringComparison.Ordinal)));
    }

    [TestMethod]
    public void MigrationAndEligibilityConsumptionRollBackTogetherOnEnqueueFailure()
    {
        using var notifier = Notifier([]);
        var known = CreateV3(notifier.DestinationKey);
        Execute("""
            CREATE TRIGGER fail_notice BEFORE INSERT ON notification_outbox
            BEGIN SELECT RAISE(ABORT, 'fixture failure'); END
            """);
        var verified = known with { ContainerName = "awaiting", Available = "2.14.10-alpine" };
        Assert.ThrowsExactly<FindingHistoryException>(() => FindingHistory.Record(Database, "clanker", [verified], notifier.DestinationKey));
        Assert.AreEqual(3L, Scalar("PRAGMA user_version"));
        Assert.AreEqual(3L, Scalar("SELECT count(*) FROM findings WHERE kind = 'PatchCandidate'"));
        Assert.AreEqual("Changed", Scalar("SELECT pending_notification_state FROM findings WHERE container_name = 'awaiting'"));
        Assert.AreEqual(7L, Scalar("SELECT attempts FROM notification_outbox"));
        Execute("DROP TRIGGER fail_notice");
        Assert.AreEqual(FindingState.Known, FindingHistory.Record(Database, "clanker", [verified], notifier.DestinationKey).Single().State);
        Assert.AreEqual(2L, Scalar("SELECT count(*) FROM notification_outbox"));
    }

    [TestMethod]
    public async Task MigratedDeliveryFailureContinuesTheExistingRetryHistory()
    {
        using var unavailable = new NtfyClient(Destination, handler: new FakeRegistryHandler((_, _) =>
            Task.FromResult(Error(HttpStatusCode.ServiceUnavailable))));
        CreateV3(unavailable.DestinationKey);
        FindingHistory.Record(Database, "clanker", []);
        var clock = new FixedClock(DateTimeOffset.FromUnixTimeSeconds(10000000000));
        var failed = await NotificationOutbox.DeliverAsync(Database, "clanker", unavailable, timeProvider: clock);
        Assert.AreEqual(1, failed.Failed);
        Assert.AreEqual(1, failed.Pending);
        Assert.AreEqual(8L, Scalar("SELECT attempts FROM notification_outbox"));
        Assert.AreEqual(10000003600L, Scalar("SELECT next_attempt FROM notification_outbox"));
        Assert.AreEqual(0L, Scalar("SELECT lease_until FROM notification_outbox"));
        Assert.AreEqual(5L, Scalar("PRAGMA user_version"));
        Assert.AreEqual(3L, Scalar("SELECT count(*) FROM findings"));
    }

    private FindingObservation CreateV3(string destinationKey)
    {
        FindingHistory.Record(Database, "clanker", []);
        Execute("""
            DROP TABLE findings;
            DROP TABLE version_discovery_cache;
            CREATE TABLE findings (
                host TEXT NOT NULL, container_name TEXT NOT NULL, repository TEXT NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('MutableTag','PatchCandidate')),
                container_id TEXT NOT NULL, image_id TEXT, configured_tag TEXT, deployed_digest TEXT,
                available TEXT NOT NULL, platform_verified INTEGER NOT NULL CHECK (platform_verified IN (0,1)),
                first_observed TEXT NOT NULL, last_observed TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('New','Known','Changed','Resolved')),
                pending_notification_destination TEXT,
                pending_notification_state TEXT CHECK (pending_notification_state IN ('New','Changed')),
                PRIMARY KEY(host,container_name,repository,kind)
            ) WITHOUT ROWID;
            CREATE TABLE version_discovery_cache(repository TEXT PRIMARY KEY, fetched_at TEXT, tags_json TEXT, retry_after TEXT,
                last_attempt INTEGER) WITHOUT ROWID;
            INSERT INTO version_discovery_cache VALUES ('library/nats', '2026-11-01T00:00:00.0000000Z',
                '["2.14.9-alpine","3.0.0-alpine"]', NULL, 123);
            PRAGMA user_version = 3;
            """);
        var known = new FindingObservation(FindingKind.VersionCandidate, "known", "container", "image", "docker.io/library/nats",
            "2.14.8-alpine", null, "2.14.9-alpine", true, FindingEvidence.Present, DateTimeOffset.UtcNow);
        using var connection = Open();
        foreach (string name in new[] { "known", "awaiting", "resolved" })
        {
            using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO findings VALUES ('clanker',$name,'docker.io/library/nats','PatchCandidate','container','image',
                    '2.14.8-alpine',NULL,$available,$verified,$observed,$observed,$state,$destination,$pending)
                """;
            command.Parameters.AddWithValue("$name", name);
            command.Parameters.AddWithValue("$available", name == "awaiting" ? "2.14.10-alpine" : known.Available!);
            command.Parameters.AddWithValue("$verified", name != "awaiting");
            command.Parameters.AddWithValue("$state", name == "awaiting" ? "Changed" : name == "known" ? "Known" : "Resolved");
            command.Parameters.AddWithValue("$observed", known.ObservedAt.AddMinutes(-1).UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
            command.Parameters.AddWithValue("$destination", name == "awaiting" ? destinationKey : DBNull.Value);
            command.Parameters.AddWithValue("$pending", name == "awaiting" ? "Changed" : DBNull.Value);
            command.ExecuteNonQuery();
        }
        using var pending = connection.CreateCommand();
        pending.CommandText = """
            INSERT INTO notification_outbox(id,host,destination_key,message,created_at,next_attempt,attempts,lease_token,lease_until)
            VALUES(77,'clanker',$destination,'legacy patch alert','2026-11-01T00:00:00.0000000Z',9999999999,7,'legacy-lease',9999999999)
            """;
        pending.Parameters.AddWithValue("$destination", destinationKey);
        pending.ExecuteNonQuery();
        return known;
    }

    private static RegistryFixture Fixture(string current = "v2.26.0")
    {
        var fixture = new RegistryFixture(repository: "binwiederhier/ntfy", tag: current);
        fixture.UseContainerd(true);
        fixture.Container = fixture.Container with { Name = "/ntfy", ConfiguredImage = "binwiederhier/ntfy:" + current };
        return fixture;
    }
    private static void SetArmOnly(RegistryFixture fixture, string tag)
    {
        byte[] config = Config(tag, architecture: "arm64");
        byte[] manifest = Manifest(config);
        fixture.AddConfig(config);
        fixture.AddManifest(manifest);
        fixture.SetTag(Index(Descriptor(manifest, architecture: "arm64")), tag);
    }
    private static async Task<(FindingRun Run, string Output)> Run(RegistryFixture fixture, DockerInspectRow[]? containers = null,
        VersionDiscoveryCache? cache = null)
    {
        containers ??= [fixture.Container];
        var commands = new List<string>();
        using var output = new StringWriter();
        var run = await DockerCheck.RunObservedAsync(args =>
        {
            commands.Add(args[0]);
            return Task.FromResult(new DockerCommandResult(0, args[0] switch
            {
                "ps" => Lines(containers.Select(item => new { ID = item.Id, Names = item.Name, Image = item.ConfiguredImage })),
                "inspect" when args[1] == "--type" => Lines(containers),
                "image" when args[1] == "inspect" => Lines(new[] { fixture.Image }),
                _ => throw new AssertFailedException("Unexpected Docker operation.")
            }, ""));
        }, fixture.Client, output, TextWriter.Null, discoveryCache: cache);
        CollectionAssert.AreEqual(new[] { "ps", "inspect", "image" }, commands.ToArray());
        return (run, output.ToString());
    }
    private static NtfyClient Notifier(List<string> messages) => new(Destination, handler: new FakeRegistryHandler(async (request, _) =>
    {
        messages.Add(await request.Content!.ReadAsStringAsync());
        return new(HttpStatusCode.OK);
    }));
    private static FindingObservation Candidate(FindingRun run) => run.Observations.Single(item => item.Kind == FindingKind.VersionCandidate);
    private static bool IsTags(HttpRequestMessage request) => request.RequestUri!.AbsolutePath.EndsWith("/tags/list", StringComparison.Ordinal);
    private static HttpResponseMessage Tags(string repo, string[] tags, string? link = null)
    {
        var response = Response(JsonSerializer.SerializeToUtf8Bytes(new { name = repo, tags }));
        if (link is not null) response.Headers.TryAddWithoutValidation("Link", link);
        return response;
    }
    private static Task<DockerCommandResult> NoDocker(string[] _) => throw new AssertFailedException("Explicit host needs no Docker info.");
    private object? Scalar(string sql)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }
    private void Execute(string sql)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        command.ExecuteNonQuery();
    }
    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Database, Pooling = false }.ToString());
        connection.Open();
        return connection;
    }
    private static string Lines<T>(IEnumerable<T> rows) => string.Join('\n', rows.Select(row => JsonSerializer.Serialize(row)));
    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
