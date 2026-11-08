using System.Net;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using static HappyDocker.Tests.RegistryFixture;

namespace HappyDocker.Tests;

[TestClass]
public sealed class FindingHistoryTests
{
    private const string Repo = "docker.io/library/nats";
    private const string Current = "2.14.8-alpine";
    private const string Patch = "2.14.9-alpine";
    private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("happydocker-");
    private string Database => Path.Combine(directory.FullName, "findings.db");

    [TestCleanup]
    public void Cleanup()
    {
        File.Delete(Database);
        directory.Delete();
    }

    [TestMethod]
    public void DatabaseReopensWithoutDuplicateRowsAndIgnoresRecreatedContainerIds()
    {
        var first = new FindingObservation(FindingKind.PatchCandidate, "nats", "original", "image", Repo, Current,
            null, Patch, true, FindingEvidence.Present, new DateTimeOffset(2026, 10, 22, 4, 0, 0, TimeSpan.FromHours(-4)));
        Assert.AreEqual(FindingState.New, Record(first).State);
        var recreated = first with { ContainerId = "recreated", ObservedAt = first.ObservedAt.AddMinutes(1) };
        Assert.AreEqual(FindingState.Known, Record(recreated).State);
        Assert.AreEqual(FindingState.Known, Record(recreated).State);
        Assert.AreEqual(1L, Scalar("PRAGMA user_version"));
        Assert.AreEqual("delete", Scalar("PRAGMA journal_mode"));
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM findings"));
        Assert.AreEqual("recreated", Scalar("SELECT container_id FROM findings"));
        Assert.AreEqual("2026-10-22T08:00:00.0000000Z", Scalar("SELECT first_observed FROM findings"));
        Assert.AreEqual("2026-10-22T08:01:00.0000000Z", Scalar("SELECT last_observed FROM findings"));
        Assert.IsEmpty(FindingHistory.Record(Database, "host", [first with { Evidence = FindingEvidence.Absent }]));
        Assert.AreEqual("Known", Scalar("SELECT state FROM findings"));

        Assert.AreEqual(FindingState.New, FindingHistory.Record(Database, "other", [recreated]).Single().State);
        Assert.AreEqual(FindingState.New, Record(recreated with { Kind = FindingKind.MutableTag }).State);
        Assert.AreEqual(3L, Scalar("SELECT count(*) FROM findings"));
    }

    [TestMethod]
    public async Task MutableTag_OnlyConclusiveCheckResolvesPriorFinding()
    {
        using var changed = new RegistryFixture();
        changed.SetTag(changed.NewManifest);
        var initial = await CheckAsync(changed);
        Assert.AreEqual(FindingRunStatus.Complete, initial.Status);
        Assert.AreEqual(FindingState.New, Record(initial.Observations.Single()).State);
        Assert.AreEqual(Digest(changed.NewManifest), Scalar("SELECT available FROM findings"));
        Assert.AreEqual(Digest(changed.OldManifest), Scalar("SELECT deployed_digest FROM findings"));

        using var unavailable = new RegistryFixture();
        unavailable.Intercept = _ => Error(HttpStatusCode.Unauthorized);
        var failed = await CheckAsync(unavailable);
        Assert.AreEqual(FindingRunStatus.Failed, failed.Status);
        Assert.IsEmpty(FindingHistory.Record(Database, "host", failed.Observations));
        Assert.AreEqual("New", Scalar("SELECT state FROM findings"));

        using var unchanged = new RegistryFixture();
        var resolved = (await CheckAsync(unchanged)).Observations.Single();
        Assert.AreEqual(FindingState.Resolved, Record(resolved).State);
        Assert.IsEmpty(FindingHistory.Record(Database, "host", [resolved]));
        Assert.AreEqual("Resolved", Scalar("SELECT state FROM findings"));
        Assert.AreEqual(FindingState.New, Record(initial.Observations.Single() with { ObservedAt = resolved.ObservedAt.AddSeconds(1) }).State);
    }

    [TestMethod]
    public async Task Check_CompletesWithTwentyFourVerifiedImagesAndFiveLocalBuilds()
    {
        using var fixture = new RegistryFixture();
        var localImage = fixture.Image with { Id = Digest(fixture.NewConfig), Identity = BuildOnly() };
        DockerInspectRow[] containers = [
            .. Enumerable.Range(0, 24).Select(i => fixture.Container with { Id = $"pulled-{i}", Name = $"/pulled-{i}" }),
            .. Enumerable.Range(0, 5).Select(i => fixture.Container with { Id = $"local-{i}", Name = $"/local-{i}", ImageId = localImage.Id })
        ];
        var run = await CheckAsync(fixture, containers, [fixture.Image, localImage]);
        Assert.AreEqual(FindingRunStatus.Complete, run.Status);
        Assert.AreEqual(0, run.IncompleteCount);
        Assert.HasCount(24, run.Observations.Where(item => item.Evidence == FindingEvidence.Absent));
        Assert.HasCount(5, run.Observations.Where(item => item.Evidence == FindingEvidence.NotApplicable));

        var options = new FindingStateOptions([], Database, "host");
        using var output = new StringWriter();
        Assert.AreEqual(0, await options.RecordAsync(run, _ => throw new AssertFailedException("Explicit host requires no Docker info."), output));
        Assert.Contains("Finding history complete.", output.ToString());
        Assert.Contains("incomplete 0", output.ToString());
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM findings"));
    }

    [TestMethod]
    public async Task Check_SkippedLocalBuildLeavesPriorFindingActive()
    {
        using var fixture = new RegistryFixture();
        fixture.SetTag(fixture.NewManifest);
        Assert.AreEqual(FindingState.New, Record((await CheckAsync(fixture)).Observations.Single()).State);
        fixture.Image = fixture.Image with { Identity = BuildOnly() };
        fixture.Requests.Clear();

        var run = await CheckAsync(fixture);
        Assert.AreEqual(FindingRunStatus.Complete, run.Status);
        Assert.AreEqual(FindingEvidence.NotApplicable, run.Observations.Single().Evidence);
        Assert.IsEmpty(fixture.Requests);
        Assert.IsEmpty(FindingHistory.Record(Database, "host", run.Observations));
        Assert.AreEqual("New", Scalar("SELECT state FROM findings"));
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task Check_RegistryFailureWithSkipsRequiresAnEvaluatedCheckForPartialStatus(bool includeVerified)
    {
        using var fixture = new RegistryFixture();
        var localImage = fixture.Image with { Id = Digest(fixture.NewConfig), Identity = BuildOnly() };
        var local = fixture.Container with { Id = "local", Name = "/local", ImageId = localImage.Id };
        var denied = fixture.Container with { Id = "denied", Name = "/denied", ConfiguredImage = Repo + ":denied" };
        fixture.Intercept = request => request.RequestUri!.AbsolutePath.EndsWith("/denied", StringComparison.Ordinal)
            ? Error(HttpStatusCode.Unauthorized) : null;

        var run = await CheckAsync(fixture, includeVerified ? [local, denied, fixture.Container] : [local, denied],
            [fixture.Image, localImage]);
        Assert.AreEqual(includeVerified ? FindingRunStatus.Partial : FindingRunStatus.Failed, run.Status);
        Assert.AreEqual(1, run.IncompleteCount);
        Assert.AreEqual(FindingEvidence.NotApplicable, run.Observations[0].Evidence);
        Assert.AreEqual(FindingEvidence.Incomplete, run.Observations[1].Evidence);
    }

    [TestMethod]
    public async Task Check_AmbiguousReferenceWithMissingEvidenceIsIncomplete()
    {
        using var fixture = new RegistryFixture();
        fixture.Container = fixture.Container with { ConfiguredImage = "nats:latest" };
        var run = await CheckAsync(fixture, images: []);
        Assert.AreEqual(FindingRunStatus.Failed, run.Status);
        Assert.AreEqual(FindingEvidence.Incomplete, run.Observations.Single().Evidence);
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    public async Task PatchCandidate_SharedImageTracksContainersSeparatelyAndDetectsChanges()
    {
        using var fixture = VersionsFixture();
        var second = fixture.Container with { Id = "second", Name = "/second" };
        fixture.SetTag(fixture.NewManifest, Patch);
        fixture.Intercept = request => IsTags(request) ? Tags(fixture.Repository, [Patch]) : null;
        var run = await VersionsAsync(fixture, containers: [fixture.Container, second]);
        Assert.AreEqual(FindingRunStatus.Complete, run.Status);
        Assert.HasCount(2, FindingHistory.Record(Database, "host", run.Observations));
        Assert.HasCount(1, fixture.Requests.Where(request => request.Path.EndsWith("/tags/list")));
        Assert.AreEqual(2L, Scalar("SELECT count(*) FROM findings WHERE available = '2.14.9-alpine' AND platform_verified = 1"));

        const string higher = "2.14.10-alpine";
        fixture.Intercept = request => IsTags(request) ? Tags(fixture.Repository, [higher])
            : Error(HttpStatusCode.ServiceUnavailable);
        var unverified = await VersionsAsync(fixture);
        Assert.AreEqual(FindingRunStatus.Partial, unverified.Status);
        Assert.AreEqual(FindingState.Changed, Record(unverified.Observations.Single()).State);
        Assert.AreEqual(higher, Scalar("SELECT available FROM findings WHERE container_name = 'nats'"));
        Assert.AreEqual(0L, Scalar("SELECT platform_verified FROM findings WHERE container_name = 'nats'"));
        Assert.AreEqual(Patch, Scalar("SELECT available FROM findings WHERE container_name = 'second'"));
    }

    [TestMethod]
    [DataRow(401)]
    [DataRow(429)]
    [DataRow(503)]
    public async Task PatchCandidate_TemporaryVerificationFailureKeepsPriorVerification(int status)
    {
        using var verified = VersionsFixture();
        verified.SetTag(verified.NewManifest, Patch);
        verified.Intercept = request => IsTags(request) ? Tags(verified.Repository, [Patch]) : null;
        Assert.AreEqual(FindingState.New, Record((await VersionsAsync(verified)).Observations.Single()).State);

        using var unavailable = VersionsFixture();
        unavailable.Intercept = request => IsTags(request) ? Tags(unavailable.Repository, [Patch]) : Error((HttpStatusCode)status);
        using var output = new StringWriter();
        var run = await VersionsAsync(unavailable, output: output);
        Assert.AreEqual(FindingRunStatus.Partial, run.Status);
        Assert.Contains($"Candidate {Patch} (platform unverified)", output.ToString());
        var transition = Record(run.Observations.Single());
        Assert.AreEqual(FindingState.Known, transition.State);
        Assert.IsFalse(transition.Observation.PlatformVerified ?? true);
        Assert.AreEqual(1L, Scalar("SELECT platform_verified FROM findings"));
    }

    [TestMethod]
    public async Task PatchCandidate_NewVerificationStrengthensKnownFinding()
    {
        using var fixture = VersionsFixture();
        fixture.Intercept = request => IsTags(request) ? Tags(fixture.Repository, [Patch]) : Error(HttpStatusCode.ServiceUnavailable);
        Assert.AreEqual(FindingState.New, Record((await VersionsAsync(fixture)).Observations.Single()).State);
        Assert.AreEqual(0L, Scalar("SELECT platform_verified FROM findings"));

        fixture.SetTag(fixture.NewManifest, Patch);
        fixture.Intercept = request => IsTags(request) ? Tags(fixture.Repository, [Patch]) : null;
        var run = await VersionsAsync(fixture);
        Assert.AreEqual(FindingRunStatus.Complete, run.Status);
        Assert.AreEqual(FindingState.Known, Record(run.Observations.Single()).State);
        Assert.AreEqual(1L, Scalar("SELECT platform_verified FROM findings"));
    }

    [TestMethod]
    public async Task PatchCandidate_SameTagWithDifferentPlatformDoesNotRetainVerification()
    {
        using var fixture = VersionsFixture();
        fixture.SetTag(fixture.NewManifest, Patch);
        fixture.Intercept = request => IsTags(request) ? Tags(fixture.Repository, [Patch]) : null;
        Assert.AreEqual(FindingState.New, Record((await VersionsAsync(fixture)).Observations.Single()).State);

        byte[] armConfig = Config("candidate", architecture: "arm64");
        fixture.AddConfig(armConfig);
        fixture.SetTag(Manifest(armConfig), Patch);
        Assert.AreEqual(FindingState.Known, Record((await VersionsAsync(fixture)).Observations.Single()).State);
        Assert.AreEqual(0L, Scalar("SELECT platform_verified FROM findings"));
    }

    [TestMethod]
    [DataRow("unrecognized tag")]
    [DataRow("digest pin")]
    [DataRow("local build")]
    [DataRow("unsupported registry")]
    public async Task Versions_ExpectedSkipsAreNotApplicable(string scenario)
    {
        using var fixture = VersionsFixture();
        string repository = Repo;
        switch (scenario)
        {
            case "unrecognized tag":
                fixture.Container = fixture.Container with { ConfiguredImage = "nats:latest" };
                break;
            case "digest pin":
                fixture.Container = fixture.Container with { ConfiguredImage = Repo + "@" + Digest(fixture.OldManifest) };
                break;
            case "local build":
                fixture.Image = fixture.Image with { Identity = BuildOnly() };
                break;
            case "unsupported registry":
                repository = "ghcr.io/org/nats";
                fixture.Container = fixture.Container with { ConfiguredImage = repository + ":" + Current };
                break;
        }
        var run = await VersionsAsync(fixture, ["--repo", repository]);
        Assert.AreEqual(FindingEvidence.NotApplicable, run.Observations.Single().Evidence);
        Assert.AreEqual(FindingRunStatus.Complete, run.Status);
        Assert.AreEqual(0, run.IncompleteCount);
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    [DataRow("authentication")]
    [DataRow("rate limit")]
    [DataRow("pagination")]
    [DataRow("partial candidate")]
    [DataRow("bad JSON")]
    [DataRow("metadata")]
    [DataRow("platform")]
    [DataRow("skipped")]
    public async Task InconclusiveVersionDiscoveryLeavesPriorCandidateActive(string scenario)
    {
        using var first = VersionsFixture();
        first.SetTag(first.NewManifest, Patch);
        first.Intercept = request => IsTags(request) ? Tags(first.Repository, [Patch]) : null;
        Record((await VersionsAsync(first)).Observations.Single());

        using var later = VersionsFixture();
        later.SetTag(later.NewManifest, "2.14.10-alpine");
        later.Intercept = request => !IsTags(request) ? null : scenario switch
        {
            "authentication" => Error(HttpStatusCode.Unauthorized),
            "rate limit" => Error(HttpStatusCode.TooManyRequests),
            "pagination" => Tags(later.Repository, [], "<https://example.org/tags>; rel=\"next\""),
            "partial candidate" => Tags(later.Repository, ["2.14.10-alpine"], "<https://example.org/tags>; rel=\"next\""),
            "bad JSON" => Response(Bytes("{")),
            _ => Tags(later.Repository, [])
        };
        if (scenario == "platform") later.Image = later.Image with { Architecture = null };
        if (scenario == "skipped") later.Container = later.Container with { ConfiguredImage = "nats:latest" };
        var failed = await VersionsAsync(later, images: scenario == "metadata" ? [] : null);
        Assert.AreEqual(scenario == "skipped" ? FindingRunStatus.Complete : FindingRunStatus.Failed, failed.Status);
        Assert.IsEmpty(FindingHistory.Record(Database, "host", failed.Observations));
        Assert.AreEqual("New", Scalar("SELECT state FROM findings"));
        Assert.AreEqual(Patch, Scalar("SELECT available FROM findings"));

        using var complete = VersionsFixture();
        complete.Intercept = _ => Tags(complete.Repository, [Current]);
        Assert.AreEqual(FindingState.Resolved, Record((await VersionsAsync(complete)).Observations.Single()).State);
    }

    [TestMethod]
    public async Task IndependentSuccessIsSavedWhenAnotherRepositoryFails()
    {
        using var fixture = VersionsFixture();
        var redis = fixture.Container with { Id = "redis", Name = "/redis", ConfiguredImage = "redis:7.2.1",
            ImageId = Digest(fixture.NewConfig) };
        var redisImage = fixture.Image with { Id = redis.ImageId, Identity = Pull("docker.io/library/redis") };
        var prior = new FindingObservation(FindingKind.PatchCandidate, "redis", "redis", redis.ImageId, "docker.io/library/redis",
            "7.2.1", null, "7.2.2", true, FindingEvidence.Present, DateTimeOffset.UtcNow);
        Record(prior);
        fixture.SetTag(fixture.NewManifest, Patch);
        fixture.Intercept = request => request.RequestUri!.AbsolutePath switch
        {
            "/v2/library/nats/tags/list" => Tags(fixture.Repository, [Patch]),
            "/v2/library/redis/tags/list" => Error(HttpStatusCode.ServiceUnavailable),
            _ => null
        };
        var run = await VersionsAsync(fixture, ["--repo", "nats", "--repo", "redis"],
            [fixture.Container, redis], [fixture.Image, redisImage]);
        Assert.AreEqual(FindingRunStatus.Partial, run.Status);
        var options = new FindingStateOptions([], Database, "host");
        using var output = new StringWriter();
        Assert.AreEqual(2, await options.RecordAsync(run, _ => throw new AssertFailedException("Explicit host requires no Docker info."), output));
        Assert.Contains("New 1, known 0, changed 0, resolved 0, incomplete 1", output.ToString());
        Assert.AreEqual("New", Scalar("SELECT state FROM findings WHERE container_name = 'redis'"));
        Assert.AreEqual(Patch, Scalar("SELECT available FROM findings WHERE container_name = 'nats'"));
    }

    [TestMethod]
    public void UnsupportedSchemaAndCorruptFilesProduceControlledErrors()
    {
        FindingHistory.Record(Database, "host", []);
        using (var connection = Open())
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "PRAGMA user_version = 99";
            command.ExecuteNonQuery();
        }
        Assert.Contains("Unsupported finding history schema version 99",
            Assert.ThrowsExactly<FindingHistoryException>(() => FindingHistory.Record(Database, "host", [])).Message);
        File.WriteAllText(Database, "invalid database contents");
        Assert.Contains("SQLite error",
            Assert.ThrowsExactly<FindingHistoryException>(() => FindingHistory.Record(Database, "host", [])).Message);
        Assert.ThrowsExactly<FindingHistoryException>(() => FindingHistory.Record(Path.Combine(Database, "child.db"), "host", []));
    }

    [TestMethod]
    public void LinuxDatabaseIsPrivateAndRejectsSharedPermissions()
    {
        if (!OperatingSystem.IsLinux()) return;
        FindingHistory.Record(Database, "host", []);
        var privateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        Assert.AreEqual(privateMode, File.GetUnixFileMode(Database));
        File.SetUnixFileMode(Database, privateMode | UnixFileMode.GroupRead);
        Assert.ThrowsExactly<FindingHistoryException>(() => FindingHistory.Record(Database, "host", []));
    }

    [TestMethod]
    public async Task ImplicitHostUsesDaemonIdAndFailsClosedIfMissing()
    {
        Assert.IsTrue(FindingStateOptions.TryParse(["--state", Database, "--repo", "nats"], out var options));
        CollectionAssert.AreEqual(new[] { "--repo", "nats" }, options.CommandArguments);
        var observation = new FindingObservation(FindingKind.PatchCandidate, "nats", "container", "image", Repo,
            Current, null, Patch, true, FindingEvidence.Present, DateTimeOffset.UtcNow);
        var run = new FindingRun(0, [observation]);
        await Assert.ThrowsExactlyAsync<FindingHistoryException>(() => options.RecordAsync(run,
            _ => Task.FromResult(new DockerCommandResult(0, "null", "")), TextWriter.Null));
        Assert.IsFalse(File.Exists(Database));
        Assert.AreEqual(0, await options.RecordAsync(run, args =>
        {
            CollectionAssert.AreEqual(new[] { "info", "--format", "{{json .ID}}" }, args);
            return Task.FromResult(new DockerCommandResult(0, "\"daemon-id\"", ""));
        }, TextWriter.Null));
        Assert.AreEqual("docker:daemon-id", Scalar("SELECT host FROM findings"));
        Assert.IsFalse(FindingStateOptions.TryParse(["--host", "clanker"], out _));
        Assert.IsFalse(FindingStateOptions.TryParse(["--state", Database, "--state", Database], out _));
        Assert.IsFalse(FindingStateOptions.TryParse(["--state", Database, "--host", "docker:daemon-id"], out _));
    }

    private FindingTransition Record(FindingObservation observation) => FindingHistory.Record(Database, "host", [observation]).Single();

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = Database, Pooling = false }.ToString());
        connection.Open();
        return connection;
    }

    private object? Scalar(string sql)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar();
    }

    private static RegistryFixture VersionsFixture()
    {
        var fixture = new RegistryFixture(tag: Current);
        fixture.Image = fixture.Image with { Identity = Pull(Repo) };
        return fixture;
    }

    private static Task<FindingRun> CheckAsync(RegistryFixture fixture, DockerInspectRow[]? containers = null, DockerImageRow[]? images = null) =>
        DockerCheck.RunObservedAsync(Inventory(containers ?? [fixture.Container], images ?? [fixture.Image]),
            fixture.Checker, TextWriter.Null, TextWriter.Null);

    private static Task<FindingRun> VersionsAsync(RegistryFixture fixture, string[]? options = null,
        DockerInspectRow[]? containers = null, DockerImageRow[]? images = null, TextWriter? output = null) =>
        DockerVersions.RunObservedAsync(options ?? ["--repo", Repo], Inventory(containers ?? [fixture.Container], images ?? [fixture.Image]),
            fixture.Client, output ?? TextWriter.Null, TextWriter.Null);

    private static Func<string[], Task<DockerCommandResult>> Inventory(DockerInspectRow[] containers, DockerImageRow[] images) =>
        args => Task.FromResult(new DockerCommandResult(0, args[0] switch
        {
            "ps" => Lines(containers.Select(container => new { ID = container.Id, Names = container.Name, Image = container.ConfiguredImage })),
            "inspect" when args[1] == "--type" && args[2] == "container" => Lines(containers),
            "image" when args[1] == "inspect" => Lines(images),
            _ => throw new AssertFailedException("Unexpected Docker operation.")
        }, ""));

    private static string Lines<T>(IEnumerable<T> rows) => string.Join('\n', rows.Select(row => JsonSerializer.Serialize(row)));
    private static JsonElement Pull(string repository) =>
        JsonSerializer.SerializeToElement(new { Pull = new[] { new { Repository = repository } } });
    private static JsonElement BuildOnly() => JsonSerializer.SerializeToElement(new { Build = new[] { new { Ref = "local" } } });
    private static bool IsTags(HttpRequestMessage request) => request.RequestUri!.AbsolutePath.EndsWith("/tags/list");

    private static HttpResponseMessage Tags(string repository, string[] tags, string? link = null)
    {
        var response = Response(JsonSerializer.SerializeToUtf8Bytes(new { name = repository, tags }));
        if (link is not null) response.Headers.TryAddWithoutValidation("Link", link);
        return response;
    }
}
