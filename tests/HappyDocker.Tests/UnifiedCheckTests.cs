using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using static HappyDocker.Tests.RegistryFixture;

namespace HappyDocker.Tests;

[TestClass]
public sealed class UnifiedCheckTests
{
    private const string Current = "2.14.8-alpine";
    private const string Candidate = "2.14.9-alpine";
    private const string Next = "2.14.10-alpine";
    private const string Destination = "https://ntfy.example/updates";
    private readonly DirectoryInfo directory = Directory.CreateTempSubdirectory("happydocker-check-");
    private string Database => Path.Combine(directory.FullName, "findings.db");

    [TestCleanup]
    public void Cleanup()
    {
        foreach (FileInfo file in directory.GetFiles()) file.Delete();
        directory.Delete();
    }

    [TestMethod]
    public async Task LatestTagStillDetectsDigestChangesWithoutListingTags()
    {
        using var fixture = Fixture("latest");
        fixture.SetTag(fixture.NewManifest);
        var result = await Run(fixture);
        Assert.AreEqual(FindingEvidence.Present, OfKind(result.Run, FindingKind.MutableTag).Evidence);
        Assert.AreEqual(FindingEvidence.NotApplicable, OfKind(result.Run, FindingKind.VersionCandidate).Evidence);
        Assert.AreEqual(FindingRunStatus.Complete, result.Run.Status);
        Assert.IsFalse(fixture.Requests.Any(request => request.Path.EndsWith("/tags/list")));
        AssertInventoryOnce(result.Commands);
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task VersionedContainerSupportsBothFindingTypes(bool changedTag)
    {
        using var fixture = Fixture();
        if (changedTag) fixture.SetTag(fixture.NewManifest);
        fixture.SetTag(fixture.NewManifest, "3.14.99-alpine");
        fixture.Intercept = request => IsTags(request) ? Tags(fixture.Repository,
            [Current, Candidate, "2.14.99", "2.15.0-alpine", "3.14.99-alpine", "2.14.99-alpine-rc1"]) : null;
        var result = await Run(fixture);
        Assert.AreEqual(changedTag ? FindingEvidence.Present : FindingEvidence.Absent, OfKind(result.Run, FindingKind.MutableTag).Evidence);
        var patch = OfKind(result.Run, FindingKind.VersionCandidate);
        Assert.AreEqual(FindingEvidence.Present, patch.Evidence);
        Assert.AreEqual("3.14.99-alpine", patch.Available);
        Assert.AreEqual(VersionUpgrade.Major, patch.Upgrade);
        Assert.IsTrue(patch.PlatformVerified ?? false);
        Assert.Contains("Version discovery", result.Output);
        AssertInventoryOnce(result.Commands);
    }

    [TestMethod]
    public async Task NtfyWithLowercaseVPrefixAutomaticallyDiscoversAndVerifiesMinorUpgrade()
    {
        using var fixture = new RegistryFixture(repository: "binwiederhier/ntfy", tag: "v2.26.0");
        fixture.UseContainerd(true);
        fixture.Container = fixture.Container with { Name = "/ntfy", ConfiguredImage = "binwiederhier/ntfy:v2.26.0" };
        // The next patch is hypothetical. Only the mocked registry advertises it here.
        fixture.SetTag(Index(Descriptor(fixture.NewManifest)), "v2.26.1");
        fixture.SetTag(Index(Descriptor(fixture.NewManifest)), "v2.27.0");
        fixture.Intercept = request => IsTags(request) ? Tags(fixture.Repository,
            ["v2.26.0", "v2.26.1", "2.26.99", "v2.27.0", "v2.26.99-alpine", "v2.26.99-rc1"]) : null;
        var result = await Run(fixture);
        Assert.AreEqual(FindingRunStatus.Complete, result.Run.Status);
        Assert.AreEqual(FindingEvidence.Absent, OfKind(result.Run, FindingKind.MutableTag).Evidence);
        var patch = OfKind(result.Run, FindingKind.VersionCandidate);
        Assert.AreEqual("docker.io/binwiederhier/ntfy", patch.Repository);
        Assert.AreEqual("v2.26.0", patch.ConfiguredTag);
        Assert.AreEqual("v2.27.0", patch.Available);
        Assert.AreEqual(VersionUpgrade.Minor, patch.Upgrade);
        Assert.AreEqual(FindingEvidence.Present, patch.Evidence);
        Assert.IsTrue(patch.PlatformVerified ?? false);
        Assert.Contains("binwiederhier/ntfy:v2.26.0", result.Output);
        Assert.Contains("Candidate v2.27.0 (platform verified)", result.Output);
        AssertInventoryOnce(result.Commands);
    }

    [TestMethod]
    public async Task SharedImagesReuseRegistryRequestsAndGroupBothNotificationTypes()
    {
        using var fixture = Fixture();
        fixture.SetTag(fixture.NewManifest);
        var second = fixture.Container with { Id = "second", Name = "/nats-two" };
        var result = await Run(fixture, containers: [fixture.Container, second]);
        Assert.HasCount(4, result.Run.Observations);
        Assert.IsTrue(fixture.Requests.GroupBy(request => (request.Path, request.Query)).All(group => group.Count() == 1));
        Assert.HasCount(1, fixture.Requests.Where(request => request.Path.EndsWith("/tags/list")));
        Assert.HasCount(1, fixture.Requests.Where(request => request.Path.EndsWith("/blobs/" + Digest(fixture.NewConfig))));
        AssertInventoryOnce(result.Commands);
        var messages = new List<string>();
        using var notifier = new NtfyClient(Destination, handler: new FakeRegistryHandler(async (request, _) =>
        {
            messages.Add(await request.Content!.ReadAsStringAsync());
            return new(HttpStatusCode.OK);
        }));
        var options = new FindingStateOptions([], Database, "clanker", Destination);
        Assert.AreEqual(0, await options.RecordAsync(result.Run, NoDocker, TextWriter.Null, notifier));
        Assert.HasCount(2, messages);
        Assert.IsTrue(messages.All(message => message.Contains("nats, nats-two", StringComparison.Ordinal)));
        Assert.IsTrue(messages.Any(message => message.Contains("mutable-tag update", StringComparison.Ordinal)));
        Assert.IsTrue(messages.Any(message => message.Contains("patch version candidate", StringComparison.Ordinal)));
        Assert.AreEqual(4L, Scalar("SELECT count(*) FROM findings"));
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM notification_outbox"));
        Assert.AreEqual(0, await options.RecordAsync(result.Run, NoDocker, TextWriter.Null, notifier));
        Assert.HasCount(2, messages);
    }

    [TestMethod]
    [DataRow("latest")]
    [DataRow("dev")]
    [DataRow("2.14")]
    [DataRow("2.14.8-rc1")]
    public async Task UnsupportedVersionFormatsAreNotApplicable(string tag)
    {
        using var fixture = Fixture(tag);
        var run = (await Run(fixture)).Run;
        Assert.AreEqual(FindingEvidence.NotApplicable, OfKind(run, FindingKind.VersionCandidate).Evidence);
        Assert.AreEqual(0, run.IncompleteCount);
        Assert.IsFalse(fixture.Requests.Any(request => request.Path.EndsWith("/tags/list")));
    }

    [TestMethod]
    public async Task GhcrMutableTagsAndVersionDiscoveryWorkTogether()
    {
        using var fixture = new RegistryFixture(registry: "ghcr.io", tag: Current);
        fixture.UseContainerd(false);
        fixture.SetTag(fixture.NewManifest, "3.0.0-alpine");
        fixture.Intercept = request => IsTags(request) ? Tags(fixture.Repository, [Current, "3.0.0-alpine"]) : null;
        var run = (await Run(fixture)).Run;
        Assert.AreEqual(FindingEvidence.Absent, OfKind(run, FindingKind.MutableTag).Evidence);
        Assert.AreEqual(FindingEvidence.Present, OfKind(run, FindingKind.VersionCandidate).Evidence);
        Assert.AreEqual(VersionUpgrade.Major, OfKind(run, FindingKind.VersionCandidate).Upgrade);
        Assert.AreEqual(FindingRunStatus.Complete, run.Status);
    }

    [TestMethod]
    [DataRow("built")]
    [DataRow("imported")]
    [DataRow("pinned")]
    public async Task LocalAndPinnedImagesRemainVisibleWithoutRegistryRequests(string kind)
    {
        using var fixture = Fixture();
        if (kind == "pinned")
            fixture.Container = fixture.Container with { ConfiguredImage = "nats@" + Digest(fixture.OldManifest) };
        else if (kind == "built")
            fixture.Image = fixture.Image with { Identity = JsonSerializer.SerializeToElement(new { Build = new[] { new { Ref = "local" } } }) };
        else
        {
            fixture.UseContainerd(false);
            fixture.Container = fixture.Container with { ConfiguredImage = "nats:" + Current };
            fixture.Image = fixture.Image with { Identity = null, RepoDigests = ["nats@" + fixture.Image.Id] };
        }
        var result = await Run(fixture);
        Assert.IsTrue(result.Run.Observations.All(observation => observation.Evidence == FindingEvidence.NotApplicable));
        Assert.AreEqual(FindingRunStatus.Complete, result.Run.Status);
        Assert.Contains("nats", result.Output);
        Assert.Contains("Skipped", result.Output);
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    public async Task DiscoveryIntervalReusesTagsRechecksPlatformsAndDetectsLaterChanges()
    {
        var clock = new TestClock();
        var cache = new VersionDiscoveryCache(Database, clock);
        using var first = Fixture();
        var initial = (await Run(first, cache: cache)).Run;
        int messages = 0;
        using var notifier = new NtfyClient(Destination, handler: new FakeRegistryHandler((_, _) =>
        {
            messages++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }));
        var options = new FindingStateOptions([], Database, "clanker", Destination);
        Assert.AreEqual(0, await options.RecordAsync(initial, NoDocker, TextWriter.Null, notifier));
        Assert.AreEqual(1, messages);
        clock.Advance(TimeSpan.FromHours(6));
        using var scheduled = Fixture();
        scheduled.SetTag(scheduled.NewManifest); // The mutable tag changed during the discovery interval.
        scheduled.Intercept = request => IsTags(request) ? throw new AssertFailedException("Tag listing should be cached.") : null;
        var repeated = await Run(scheduled, cache: cache);
        Assert.Contains("Cached tag enumeration", repeated.Output);
        Assert.IsTrue(OfKind(repeated.Run, FindingKind.VersionCandidate).PlatformVerified ?? false);
        Assert.IsTrue(scheduled.Requests.Any(request => request.Path.EndsWith("/manifests/" + Candidate)));
        Assert.AreEqual(0, await options.RecordAsync(repeated.Run, NoDocker, TextWriter.Null, notifier));
        Assert.AreEqual(2, messages);
        Assert.AreEqual(Candidate, Scalar("SELECT available FROM findings WHERE kind = 'VersionCandidate'"));
        Assert.AreEqual("Known", Scalar("SELECT state FROM findings WHERE kind = 'VersionCandidate'"));
        clock.Advance(TimeSpan.FromHours(19));
        using var later = Fixture();
        later.SetTag(later.NewManifest);
        later.SetTag(later.NewManifest, Next);
        later.Intercept = request => IsTags(request) ? Tags(later.Repository, [Next]) : null;
        Assert.AreEqual(0, await options.RecordAsync((await Run(later, cache: cache)).Run, NoDocker, TextWriter.Null, notifier));
        Assert.AreEqual(3, messages);
        Assert.AreEqual(Next, Scalar("SELECT available FROM findings WHERE kind = 'VersionCandidate'"));
        Assert.AreEqual("Changed", Scalar("SELECT state FROM findings WHERE kind = 'VersionCandidate'"));
    }

    [TestMethod]
    public async Task CachedAbsenceNeverResolvesPriorFindings()
    {
        var clock = new TestClock();
        var cache = new VersionDiscoveryCache(Database, clock);
        using var fixture = Fixture();
        fixture.Intercept = request => IsTags(request) ? Tags(fixture.Repository, [Current]) : null;
        await Run(fixture, cache: cache);
        FindingHistory.Record(Database, "clanker", [PriorPatch(fixture, clock.GetUtcNow().AddMinutes(1))]);
        clock.Advance(TimeSpan.FromHours(6));
        var cached = await Run(fixture, cache: cache);
        Assert.AreEqual(FindingEvidence.NotApplicable, OfKind(cached.Run, FindingKind.VersionCandidate).Evidence);
        Assert.IsEmpty(FindingHistory.Record(Database, "clanker", cached.Run.Observations));
        Assert.AreEqual("New", Scalar("SELECT state FROM findings"));
        clock.Advance(TimeSpan.FromHours(19));
        var refreshed = (await Run(fixture, cache: cache)).Run;
        Assert.AreEqual(FindingEvidence.Absent, OfKind(refreshed, FindingKind.VersionCandidate).Evidence);
        Assert.AreEqual(FindingState.Resolved, FindingHistory.Record(Database, "clanker", refreshed.Observations).Single().State);
    }

    [TestMethod]
    public async Task OlderCachedCandidateCannotReplaceANewerDiagnosticFinding()
    {
        var clock = new TestClock();
        var cache = new VersionDiscoveryCache(Database, clock);
        using var fixture = Fixture();
        await Run(fixture, cache: cache);
        FindingHistory.Record(Database, "clanker", [PriorPatch(fixture, clock.GetUtcNow().AddHours(1)) with { Available = Next }]);
        clock.Advance(TimeSpan.FromHours(6));
        FindingHistory.Record(Database, "clanker", (await Run(fixture, cache: cache)).Run.Observations);
        Assert.AreEqual(Next, Scalar("SELECT available FROM findings"));
        Assert.AreEqual("New", Scalar("SELECT state FROM findings"));
    }

    [TestMethod]
    [DataRow("401")]
    [DataRow("429")]
    [DataRow("503")]
    [DataRow("malformed")]
    [DataRow("pagination")]
    public async Task FailedEnumerationPreservesHistoryAndRetriesWithoutWaitingADay(string scenario)
    {
        var clock = new TestClock();
        var cache = new VersionDiscoveryCache(Database, clock);
        using var fixture = Fixture();
        FindingHistory.Record(Database, "clanker", [PriorPatch(fixture, clock.GetUtcNow().AddMinutes(-1))]);
        fixture.Intercept = request => !IsTags(request) ? null : scenario switch
        {
            "malformed" => Response(Bytes("{")),
            "pagination" => Tags(fixture.Repository, [Candidate], "<https://other.example/list>; rel=\"next\""),
            _ => Error((HttpStatusCode)int.Parse(scenario, System.Globalization.CultureInfo.InvariantCulture))
        };
        var failed = (await Run(fixture, cache: cache)).Run;
        Assert.AreEqual(FindingRunStatus.Partial, failed.Status);
        Assert.AreEqual(FindingEvidence.Incomplete, OfKind(failed, FindingKind.VersionCandidate).Evidence);
        Assert.IsEmpty(FindingHistory.Record(Database, "clanker", failed.Observations));
        Assert.AreEqual("New", Scalar("SELECT state FROM findings"));
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM version_discovery_cache WHERE fetched_at IS NOT NULL"));
        clock.Advance(TimeSpan.FromMinutes(10));
        using var recovered = Fixture();
        recovered.SetTag(recovered.NewManifest, Next);
        recovered.Intercept = request => IsTags(request) ? Tags(recovered.Repository, [Next]) : null;
        var run = (await Run(recovered, cache: cache)).Run;
        Assert.AreEqual(FindingRunStatus.Complete, run.Status);
        Assert.AreEqual(FindingState.Changed, FindingHistory.Record(Database, "clanker", run.Observations).Single().State);
        Assert.AreEqual(Next, Scalar("SELECT available FROM findings"));
    }

    [TestMethod]
    public async Task DiscoveryRetryAfterPersistsAcrossInvocations()
    {
        var clock = new TestClock();
        var cache = new VersionDiscoveryCache(Database, clock);
        using var limited = Fixture();
        limited.Intercept = request => !IsTags(request) ? null : new HttpResponseMessage(HttpStatusCode.TooManyRequests)
        {
            Headers = { RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromDays(2)) }
        };
        await Run(limited, cache: cache);
        clock.Advance(TimeSpan.FromHours(6));
        using var early = Fixture();
        var waiting = (await Run(early, cache: cache)).Run;
        Assert.AreEqual(FindingEvidence.Incomplete, OfKind(waiting, FindingKind.VersionCandidate).Evidence);
        Assert.IsFalse(early.Requests.Any(request => request.Path.EndsWith("/tags/list")));
        clock.Advance(TimeSpan.FromDays(3));
        using var ready = Fixture();
        Assert.AreEqual(FindingRunStatus.Complete, (await Run(ready, cache: cache)).Run.Status);
        Assert.IsTrue(ready.Requests.Any(request => request.Path.EndsWith("/tags/list")));
    }

    [TestMethod]
    public async Task CachedCandidateVerificationRecoversAndQueuesItsDeferredNotification()
    {
        var clock = new TestClock();
        var cache = new VersionDiscoveryCache(Database, clock);
        using var unavailable = Fixture();
        unavailable.Intercept = request => IsTags(request) ? Tags(unavailable.Repository, [Candidate])
            : request.RequestUri!.AbsolutePath.EndsWith("/" + Candidate, StringComparison.Ordinal) ? Error(HttpStatusCode.ServiceUnavailable) : null;
        int sent = 0;
        using var notifier = new NtfyClient(Destination, handler: new FakeRegistryHandler((_, _) =>
        {
            sent++;
            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK));
        }));
        var options = new FindingStateOptions([], Database, "clanker", Destination);
        Assert.AreEqual(2, await options.RecordAsync((await Run(unavailable, cache: cache)).Run, NoDocker, TextWriter.Null, notifier));
        Assert.AreEqual(0, sent);
        clock.Advance(TimeSpan.FromHours(6));
        using var verified = Fixture();
        verified.Intercept = request => IsTags(request) ? throw new AssertFailedException("Tags should be cached.") : null;
        Assert.AreEqual(0, await options.RecordAsync((await Run(verified, cache: cache)).Run, NoDocker, TextWriter.Null, notifier));
        Assert.AreEqual(1, sent);
        Assert.AreEqual("Known", Scalar("SELECT state FROM findings"));
        Assert.AreEqual(1L, Scalar("SELECT platform_verified FROM findings"));
    }

    [TestMethod]
    public async Task DiscoveryDeadlinePreservesMutableTagObservationsAndCanRecover()
    {
        using var fixture = Fixture();
        using var registry = new RegistryClient(new FakeRegistryHandler(async (request, token) =>
        {
            if (IsTags(request)) await Task.Delay(Timeout.InfiniteTimeSpan, token);
            return fixture.Respond(request);
        }));
        var cache = new VersionDiscoveryCache(Database);
        var timed = await DockerCheck.RunObservedAsync(Inventory(fixture, [fixture.Container]), registry, TextWriter.Null, TextWriter.Null,
            discoveryCache: cache, discoveryBudget: TimeSpan.FromMilliseconds(25));
        Assert.AreEqual(FindingEvidence.Absent, OfKind(timed, FindingKind.MutableTag).Evidence);
        Assert.AreEqual(FindingEvidence.Deferred, OfKind(timed, FindingKind.VersionCandidate).Evidence);
        Assert.AreEqual(FindingRunStatus.Deferred, timed.Status);
        Assert.AreEqual(FindingRunStatus.Complete, (await Run(fixture, cache: cache)).Run.Status);
    }

    [TestMethod]
    public async Task RegistryOutageLeavesBothChecksIncomplete()
    {
        using var fixture = Fixture();
        fixture.Intercept = _ => Error(HttpStatusCode.ServiceUnavailable);
        var run = (await Run(fixture)).Run;
        Assert.AreEqual(FindingRunStatus.Failed, run.Status);
        Assert.AreEqual(2, run.IncompleteCount);
        Assert.IsTrue(run.Observations.All(observation => observation.Evidence == FindingEvidence.Incomplete));
    }

    [TestMethod]
    public async Task ContainerdIndexCandidateRequiresTheExactRunningPlatform()
    {
        using var fixture = Fixture();
        fixture.UseContainerd(true);
        byte[] armConfig = Config("arm candidate", architecture: "arm64");
        byte[] armManifest = Manifest(armConfig);
        fixture.AddConfig(armConfig);
        fixture.AddManifest(armManifest);
        fixture.SetTag(Index(Descriptor(armManifest, architecture: "arm64")), Candidate);
        var result = await Run(fixture);
        Assert.AreEqual(FindingEvidence.Absent, OfKind(result.Run, FindingKind.MutableTag).Evidence);
        var patch = OfKind(result.Run, FindingKind.VersionCandidate);
        Assert.AreEqual(FindingEvidence.Present, patch.Evidence);
        Assert.IsFalse(patch.PlatformVerified ?? true);
        Assert.AreEqual(FindingRunStatus.Partial, result.Run.Status);
        Assert.Contains("platform unverified", result.Output);
        Assert.IsFalse(fixture.Requests.Any(request => request.Path.EndsWith("/blobs/" + Digest(armConfig))));
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task CorruptOrOversizedCacheRowsAreRefreshedSafely(bool oversized)
    {
        var clock = new TestClock();
        var cache = new VersionDiscoveryCache(Database, clock);
        using var fixture = Fixture();
        await Run(fixture, cache: cache);
        using (var connection = Open())
        using (var command = connection.CreateCommand())
        {
            command.CommandText = "UPDATE version_discovery_cache SET tags_json = $json";
            command.Parameters.AddWithValue("$json", oversized ? new string('x', 265 * 1024) : "{");
            command.ExecuteNonQuery();
        }
        clock.Advance(TimeSpan.FromHours(6));
        using var refreshed = Fixture();
        Assert.AreEqual(FindingRunStatus.Complete, (await Run(refreshed, cache: cache)).Run.Status);
        Assert.HasCount(1, refreshed.Requests.Where(request => request.Path.EndsWith("/tags/list")));
    }

    [TestMethod]
    public async Task IntentionalCancellationPropagatesWithoutCachingAnIncompleteList()
    {
        using var fixture = Fixture();
        using var cancellation = new CancellationTokenSource();
        using var registry = new RegistryClient(new FakeRegistryHandler((request, token) =>
        {
            if (IsTags(request))
            {
                cancellation.Cancel();
                token.ThrowIfCancellationRequested();
            }
            return Task.FromResult(fixture.Respond(request));
        }));
        await Assert.ThrowsAsync<OperationCanceledException>(() => DockerCheck.RunObservedAsync(
            Inventory(fixture, [fixture.Container]), registry, TextWriter.Null, TextWriter.Null, cancellation.Token,
            new VersionDiscoveryCache(Database)));
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM version_discovery_cache WHERE last_attempt IS NOT NULL"));
        Assert.AreEqual(0L, Scalar("SELECT count(*) FROM version_discovery_cache WHERE fetched_at IS NOT NULL"));
    }

    [TestMethod]
    public async Task RepositoryBudgetMovesToUncachedRepositoriesOnSubsequentRuns()
    {
        var containers = new List<DockerInspectRow>();
        var images = new List<DockerImageRow>();
        for (int index = 0; index < 11; index++)
        {
            string repo = $"docker.io/library/app-{index}";
            string id = Digest(Config($"app-{index}"));
            containers.Add(new($"container-{index}", $"/app-{index}", id, repo + ":1.2.3", "linux"));
            images.Add(new(id, "linux", "amd64", null, [repo + "@" + id],
                Identity: JsonSerializer.SerializeToElement(new { Pull = new[] { new { Repository = repo } } })));
        }
        int lists = 0;
        using var registry = new RegistryClient(new FakeRegistryHandler((request, _) =>
        {
            if (!IsTags(request)) return Task.FromResult(Error(HttpStatusCode.ServiceUnavailable));
            lists++;
            string repo = request.RequestUri!.AbsolutePath["/v2/".Length..^"/tags/list".Length];
            return Task.FromResult(Tags(repo, []));
        }));
        var cache = new VersionDiscoveryCache(Database);
        await DockerCheck.RunObservedAsync(Docker, registry, TextWriter.Null, TextWriter.Null, discoveryCache: cache);
        Assert.AreEqual(10, lists);
        await DockerCheck.RunObservedAsync(Docker, registry, TextWriter.Null, TextWriter.Null, discoveryCache: cache);
        Assert.AreEqual(11, lists);

        Task<DockerCommandResult> Docker(string[] args) => Task.FromResult(new DockerCommandResult(0, args[0] switch
        {
            "ps" => Lines(containers.Select(item => new { ID = item.Id, Names = item.Name, Image = item.ConfiguredImage })),
            "inspect" => Lines(containers),
            "image" => Lines(images),
            _ => throw new AssertFailedException("Unexpected Docker operation.")
        }, ""));
    }

    [TestMethod]
    public async Task VersionTwoMigrationPreservesPendingNotificationsAndFindingEligibility()
    {
        var observation = new FindingObservation(FindingKind.VersionCandidate, "nats", "container", "image",
            "docker.io/library/nats", Current, null, Candidate, false, FindingEvidence.Present, DateTimeOffset.UtcNow);
        FindingHistory.Record(Database, "clanker", [observation], "destination");
        FindingHistory.Record(Database, "clanker", [observation with
        {
            Kind = FindingKind.MutableTag, PlatformVerified = true, Available = "sha256:" + new string('a', 64)
        }], "destination");
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM notification_outbox"));
        Execute("DROP TABLE version_discovery_cache; PRAGMA user_version = 2");
        using var fixture = Fixture();
        await Run(fixture, cache: new VersionDiscoveryCache(Database));
        Assert.AreEqual(4L, Scalar("PRAGMA user_version"));
        Assert.AreEqual("destination", Scalar("SELECT pending_notification_destination FROM findings WHERE kind = 'VersionCandidate'"));
        Assert.AreEqual("New", Scalar("SELECT pending_notification_state FROM findings WHERE kind = 'VersionCandidate'"));
        Assert.AreEqual(1L, Scalar("SELECT count(*) FROM notification_outbox"));
    }

    private async Task<(FindingRun Run, string Output, List<string[]> Commands)> Run(RegistryFixture fixture,
        VersionDiscoveryCache? cache = null, DockerInspectRow[]? containers = null)
    {
        var commands = new List<string[]>();
        var docker = Inventory(fixture, containers ?? [fixture.Container], commands);
        using var output = new StringWriter();
        var run = await DockerCheck.RunObservedAsync(docker, fixture.Client, output, TextWriter.Null, discoveryCache: cache);
        return (run, output.ToString(), commands);
    }

    private static Func<string[], Task<DockerCommandResult>> Inventory(RegistryFixture fixture, DockerInspectRow[] containers,
        List<string[]>? commands = null) => args =>
    {
        commands?.Add(args);
        return Task.FromResult(new DockerCommandResult(0, args[0] switch
        {
            "ps" => Lines(containers.Select(item => new { ID = item.Id, Names = item.Name, Image = item.ConfiguredImage })),
            "inspect" when args[1] == "--type" && args[2] == "container" => Lines(containers),
            "image" when args[1] == "inspect" => Lines(new[] { fixture.Image }),
            _ => throw new AssertFailedException("Unexpected Docker operation.")
        }, ""));
    };

    private static RegistryFixture Fixture(string tag = Current)
    {
        var fixture = new RegistryFixture(tag: tag);
        fixture.Image = fixture.Image with { Identity = JsonSerializer.SerializeToElement(new { Pull = new[] { new { Repository = "docker.io/library/nats" } } }) };
        fixture.SetTag(fixture.NewManifest, Candidate);
        fixture.Intercept = request => IsTags(request) ? Tags(fixture.Repository, [Current, Candidate]) : null;
        return fixture;
    }

    private static FindingObservation PriorPatch(RegistryFixture fixture, DateTimeOffset at) =>
        new(FindingKind.VersionCandidate, "nats", fixture.Container.Id, fixture.Image.Id, "docker.io/library/nats",
            Current, null, Candidate, true, FindingEvidence.Present, at);
    private static FindingObservation OfKind(FindingRun run, FindingKind kind) => run.Observations.Single(observation => observation.Kind == kind);
    private static Task<DockerCommandResult> NoDocker(string[] _) => throw new AssertFailedException("Explicit host requires no Docker info.");
    private static bool IsTags(HttpRequestMessage request) => request.RequestUri!.AbsolutePath.EndsWith("/tags/list", StringComparison.Ordinal);
    private static HttpResponseMessage Tags(string repository, string[] tags, string? link = null)
    {
        var response = Response(JsonSerializer.SerializeToUtf8Bytes(new { name = repository, tags }));
        if (link is not null) response.Headers.TryAddWithoutValidation("Link", link);
        return response;
    }
    private static void AssertInventoryOnce(List<string[]> commands)
    {
        Assert.HasCount(3, commands);
        CollectionAssert.AreEqual(new[] { "ps", "inspect", "image" }, commands.Select(command => command[0]).ToArray());
    }
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
    private sealed class TestClock : TimeProvider
    {
        private DateTimeOffset now = DateTimeOffset.UtcNow;
        public override DateTimeOffset GetUtcNow() => now;
        public void Advance(TimeSpan amount) => now += amount;
    }
}
