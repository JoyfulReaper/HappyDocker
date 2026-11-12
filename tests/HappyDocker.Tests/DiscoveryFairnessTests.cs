using System.Globalization;
using System.Net;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using static HappyDocker.Tests.RegistryFixture;

namespace HappyDocker.Tests;

[TestClass]
public sealed class DiscoveryFairnessTests
{
    private const string Current = "1.2.3";
    private const string Candidate = "1.2.4";
    private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("happydocker-fair-");
    private readonly Clock clock = new();
    private string Database => Path.Combine(directory.FullName, "findings.db");

    [TestCleanup]
    public void Cleanup()
    {
        foreach (FileInfo file in directory.GetFiles()) file.Delete();
        directory.Delete();
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task RepeatedFailuresCannotStarveLaterRepositoriesEvenWhenClockDoesNotAdvance(bool advanceClock)
    {
        var attempted = new HashSet<string>(StringComparer.Ordinal);
        for (int scheduled = 0; scheduled < 3; scheduled++)
        {
            var result = await Run(15, repo => int.Parse(repo[^2..], CultureInfo.InvariantCulture) < 10
                ? Error(HttpStatusCode.ServiceUnavailable) : Tags(repo, []));
            Assert.IsLessThanOrEqualTo(10, result.Listed.Count);
            attempted.UnionWith(result.Listed);
            if (scheduled < 2) Assert.Contains("Discovery deferred.", result.Output);
            Assert.AreEqual(FindingRunStatus.Partial, result.Run.Status); // Genuine failures still take precedence.
            Assert.AreEqual(2, await Save(result.Run));
            if (advanceClock) clock.Advance(TimeSpan.FromHours(6));
        }
        Assert.HasCount(15, attempted);
        Assert.AreEqual(5L, Scalar("SELECT count(*) FROM version_discovery_cache WHERE fetched_at IS NOT NULL"));
        Assert.AreEqual(10L, Scalar("SELECT count(*) FROM version_discovery_cache WHERE fetched_at IS NULL AND last_attempt IS NOT NULL"));
    }

    [TestMethod]
    public async Task ASlowFailingRepositoryCannotMonopolizeSuccessiveTimeBudgets()
    {
        var attempted = new HashSet<string>(StringComparer.Ordinal);
        for (int scheduled = 0; scheduled < 12; scheduled++)
        {
            var result = await Run(12, repo =>
            {
                clock.Advance(TimeSpan.FromMinutes(1));
                return Error(HttpStatusCode.ServiceUnavailable);
            });
            Assert.HasCount(1, result.Listed);
            attempted.UnionWith(result.Listed);
            Assert.AreEqual(1, result.Run.IncompleteCount);
            Assert.AreEqual(11, result.Run.DeferredCount);
            Assert.AreEqual(FindingRunStatus.Partial, result.Run.Status);
            clock.Advance(TimeSpan.FromHours(6));
        }
        Assert.HasCount(12, attempted);
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM version_discovery_cache WHERE fetched_at IS NOT NULL"));
    }

    [TestMethod]
    public async Task BudgetDeferralHasASeparateExitStatusAndPreservesPriorFindings()
    {
        var previous = Prior("library/app-11");
        FindingHistory.Record(Database, "clanker", [previous]);
        var result = await Run(12);
        Assert.HasCount(10, result.Listed);
        Assert.AreEqual(FindingRunStatus.Deferred, result.Run.Status);
        Assert.AreEqual(0, result.Run.IncompleteCount);
        Assert.AreEqual(2, result.Run.DeferredCount);
        using var summary = new StringWriter();
        Assert.AreEqual(4, await Save(result.Run, summary));
        Assert.Contains("Finding history deferred.", summary.ToString());
        Assert.Contains("incomplete 0, deferred 2", summary.ToString());
        Assert.DoesNotContain("Incomplete enumeration.", result.Output);
        Assert.AreEqual("New", Scalar("SELECT state FROM findings"));
        Assert.AreEqual(10L, Scalar("SELECT count(*) FROM version_discovery_cache WHERE last_attempt IS NOT NULL"));
        clock.Advance(TimeSpan.FromHours(6));
        var completed = await Run(12);
        Assert.HasCount(2, completed.Listed);
        Assert.AreEqual(0, await Save(completed.Run));
        Assert.AreEqual("Resolved", Scalar("SELECT state FROM findings")); // A fresh complete listing can resolve it.
    }

    [TestMethod]
    public async Task PartialEnumerationFailureIsNotHiddenByPlatformBudgetDeferral()
    {
        FindingHistory.Record(Database, "clanker", [Prior("library/app-00")]);
        var result = await Run(2, repo =>
        {
            clock.Advance(TimeSpan.FromMinutes(1));
            var response = Tags(repo, [Candidate]);
            response.Headers.TryAddWithoutValidation("Link", "<https://other.example/list>; rel=\"next\"");
            return response;
        });
        Assert.AreEqual(1, result.Run.IncompleteCount);
        Assert.AreEqual(1, result.Run.DeferredCount);
        Assert.AreEqual(FindingRunStatus.Partial, result.Run.Status);
        Assert.AreEqual(2, await Save(result.Run));
        Assert.Contains("Incomplete enumeration.", result.Output);
        Assert.Contains("Discovery deferred.", result.Output);
        Assert.AreEqual("New", Scalar("SELECT state FROM findings"));
    }

    [TestMethod]
    public async Task CachedPlatformChecksAlsoRotateWhenVerificationExhaustsTheBudget()
    {
        FindingHistory.Record(Database, "clanker", []);
        for (int index = 0; index < 12; index++)
        {
            using var connection = Open();
            using var command = connection.CreateCommand();
            command.CommandText = """
                INSERT INTO version_discovery_cache(repository, fetched_at, tags_json) VALUES ($repo, $at, $tags)
                """;
            command.Parameters.AddWithValue("$repo", $"docker.io/library/app-{index:D2}");
            command.Parameters.AddWithValue("$at", clock.GetUtcNow().UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
            command.Parameters.AddWithValue("$tags", JsonSerializer.Serialize(new[] { Candidate }));
            command.ExecuteNonQuery();
        }
        var first = await Run(12, failCandidateAfterBudget: true);
        Assert.IsEmpty(first.Listed);
        Assert.HasCount(1, first.Candidates);
        Assert.AreEqual(11, first.Run.DeferredCount);
        clock.Advance(TimeSpan.FromHours(6));
        var next = await Run(12, failCandidateAfterBudget: true);
        Assert.IsEmpty(next.Listed);
        Assert.HasCount(1, next.Candidates);
        Assert.AreNotEqual(first.Candidates.Single(), next.Candidates.Single());
        Assert.AreEqual(12L, Scalar("SELECT count(*) FROM version_discovery_cache WHERE fetched_at IS NOT NULL"));
    }

    [TestMethod]
    public async Task ExplicitDiagnosticsKeepInventoryOrderingAndTheExistingRepositoryAllowance()
    {
        await Run(12, _ => Error(HttpStatusCode.ServiceUnavailable));
        var diagnostic = await Run(12, _ => Error(HttpStatusCode.ServiceUnavailable), diagnostic: true);
        CollectionAssert.AreEqual(Enumerable.Range(0, 12).Select(index => $"library/app-{index:D2}").ToArray(), diagnostic.Listed.ToArray());
        Assert.AreEqual(12, diagnostic.Run.IncompleteCount);
        Assert.AreEqual(0, diagnostic.Run.DeferredCount);
        Assert.DoesNotContain("Discovery deferred.", diagnostic.Output);
    }

    [TestMethod]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    public void MigrationRetainsFindingHistoryOutboxAndVersionThreeCache(int version)
    {
        var previous = Prior("library/app-00") with { Kind = FindingKind.MutableTag };
        FindingHistory.Record(Database, "clanker", [previous], version == 1 ? null : "destination");
        if (version < 3) Execute("DROP TABLE version_discovery_cache");
        else
        {
            Execute("""
                INSERT INTO version_discovery_cache (repository, fetched_at, tags_json)
                VALUES ('library/app-00', '2026-11-12T00:00:00.0000000Z', '["1.2.3"]');
                ALTER TABLE version_discovery_cache DROP COLUMN last_attempt;
                """);
        }
        if (version == 1) Execute("DROP TABLE notification_outbox");
        Execute($"PRAGMA user_version = {version}");
        FindingHistory.Record(Database, "clanker", []);
        Assert.AreEqual(4L, Scalar("PRAGMA user_version"));
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM findings WHERE state = 'New'"));
        Assert.AreEqual(version == 1 ? 0L : 1L, Scalar("SELECT count(*) FROM notification_outbox"));
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM pragma_table_info('version_discovery_cache') WHERE name = 'last_attempt'"));
        if (version == 3)
        {
            Assert.AreEqual("[\"1.2.3\"]", Scalar("SELECT tags_json FROM version_discovery_cache"));
            Assert.AreEqual(DBNull.Value, Scalar("SELECT last_attempt FROM version_discovery_cache"));
        }
    }

    private async Task<(FindingRun Run, string Output, List<string> Listed, List<string> Candidates)> Run(int count,
        Func<string, HttpResponseMessage>? listing = null, bool failCandidateAfterBudget = false, bool diagnostic = false)
    {
        var containers = new List<DockerInspectRow>();
        var images = new List<DockerImageRow>();
        var routes = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        for (int index = 0; index < count; index++)
        {
            string repo = $"library/app-{index:D2}";
            byte[] config = Config(repo);
            byte[] manifest = Manifest(config);
            string id = Digest(config);
            containers.Add(new($"container-{index}", $"/app-{index:D2}", id, $"docker.io/{repo}:{Current}", "linux"));
            images.Add(new(id, "linux", "amd64", null, [$"docker.io/{repo}@{Digest(manifest)}"],
                Identity: JsonSerializer.SerializeToElement(new { Pull = new[] { new { Repository = "docker.io/" + repo } } })));
            routes[$"/v2/{repo}/manifests/{Digest(manifest)}"] = manifest;
            routes[$"/v2/{repo}/manifests/{Current}"] = manifest;
            routes[$"/v2/{repo}/manifests/{Candidate}"] = manifest;
            routes[$"/v2/{repo}/blobs/{id}"] = config;
        }
        var listed = new List<string>();
        var candidates = new List<string>();
        using var registry = new RegistryClient(new FakeRegistryHandler((request, _) =>
        {
            string path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            string[] parts = path.Split('/', StringSplitOptions.RemoveEmptyEntries);
            string repo = parts[1] + "/" + parts[2];
            if (parts[3] == "tags")
            {
                listed.Add(repo);
                return Task.FromResult(listing?.Invoke(repo) ?? Tags(repo, []));
            }
            if (parts[3] == "manifests" && parts[4] == Candidate)
            {
                candidates.Add(repo);
                if (failCandidateAfterBudget)
                {
                    clock.Advance(TimeSpan.FromMinutes(1));
                    return Task.FromResult(Error(HttpStatusCode.ServiceUnavailable));
                }
            }
            Assert.IsTrue(routes.TryGetValue(path, out var bytes), $"Unexpected registry path {path}");
            return Task.FromResult(Response(bytes!));
        }));
        using var output = new StringWriter();
        FindingRun run = diagnostic
            ? await DockerVersions.RunObservedAsync(containers.SelectMany(container =>
                new[] { "--repo", ImageReference.Parse(container.ConfiguredImage).Repository! }).ToArray(), Docker, registry, output, TextWriter.Null)
            : await DockerCheck.RunObservedAsync(Docker, registry, output, TextWriter.Null, discoveryCache: new VersionDiscoveryCache(Database, clock));
        return (run, output.ToString(), listed, candidates);

        Task<DockerCommandResult> Docker(string[] args) => Task.FromResult(new DockerCommandResult(0, args[0] switch
        {
            "ps" => Lines(containers.Select(item => new { ID = item.Id, Names = item.Name, Image = item.ConfiguredImage })),
            "inspect" when args[1] == "--type" => Lines(containers),
            "image" when args[1] == "inspect" => Lines(images),
            _ => throw new AssertFailedException("Unexpected Docker operation.")
        }, ""));
    }

    private Task<int> Save(FindingRun run, TextWriter? output = null) =>
        new FindingStateOptions([], Database, "clanker").RecordAsync(run,
            _ => throw new AssertFailedException("Explicit host requires no Docker info."), output ?? TextWriter.Null);

    private FindingObservation Prior(string repository) => new(FindingKind.VersionCandidate, repository.Split('/')[1],
        "container", "old-image", "docker.io/" + repository, Current, null, Candidate, true,
        FindingEvidence.Present, clock.GetUtcNow().AddMinutes(-1));

    private static HttpResponseMessage Tags(string repo, string[] tags) =>
        Response(JsonSerializer.SerializeToUtf8Bytes(new { name = repo, tags }));
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
    private sealed class Clock : TimeProvider
    {
        private DateTimeOffset now = new(2026, 11, 12, 0, 0, 0, TimeSpan.Zero);
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(TimeSpan duration) => now += duration;
    }
}
