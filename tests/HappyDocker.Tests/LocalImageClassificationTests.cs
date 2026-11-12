using System.Net;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using static HappyDocker.Tests.RegistryFixture;

namespace HappyDocker.Tests;

[TestClass]
public sealed class LocalImageClassificationTests
{
    private const string Name = "joyful-stack-happyecho";
    private const string Repository = "docker.io/library/" + Name;

    [TestMethod]
    [DataRow(false, false)]
    [DataRow(false, true)]
    [DataRow(true, false)]
    [DataRow(true, true)]
    public async Task LocalAndTransferredImagesWithSyntheticAliasesAreSkipped(bool index, bool buildIdentity)
    {
        using var fixture = LocalFixture(index);
        fixture.Container = fixture.Container with { ConfiguredImage = Name };
        if (buildIdentity)
            fixture.Image = fixture.Image with { Identity = JsonSerializer.SerializeToElement(new { Build = new[] { new { Ref = "local-build" } } }) };
        ImageReference reference = ImageReference.Parse(fixture.Container.ConfiguredImage).WithMetadata(fixture.Image);
        Assert.AreEqual(buildIdentity ? ImageReferenceKind.LocallyBuilt : ImageReferenceKind.LocalOrImported, reference.Kind);
        Assert.AreEqual(fixture.Container.ConfiguredImage, reference.Original);
        UpdateResult result = await fixture.CheckAsync();
        Assert.AreEqual(UpdateStatus.Skipped, result.Status);
        Assert.Contains(buildIdentity ? "Build-only" : "Local/imported", result.Reason);
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    [DataRow("explicit Docker Hub")]
    [DataRow("explicit GHCR")]
    [DataRow("namespace")]
    [DataRow("canonical digest")]
    [DataRow("different digest")]
    [DataRow("missing configured alias")]
    [DataRow("missing digests")]
    [DataRow("invalid descriptor")]
    [DataRow("descriptor mismatch")]
    [DataRow("container mismatch")]
    [DataRow("empty identity")]
    [DataRow("mixed identity")]
    [DataRow("nonmatching pull")]
    public async Task InsufficientOrConflictingEvidenceDoesNotBecomeLocalProvenance(string scenario)
    {
        using var fixture = LocalFixture(false);
        switch (scenario)
        {
            case "explicit Docker Hub":
                fixture.Container = fixture.Container with { ConfiguredImage = Repository };
                break;
            case "explicit GHCR":
                fixture.Container = fixture.Container with { ConfiguredImage = "ghcr.io/joyfulreaper/happyecho:latest" };
                break;
            case "namespace":
                fixture.Container = fixture.Container with { ConfiguredImage = "team/happyecho:latest" };
                break;
            case "canonical digest":
                fixture.Image = fixture.Image with { RepoDigests = [.. fixture.Image.RepoDigests!, Repository + "@" + fixture.Image.Id] };
                break;
            case "different digest":
                fixture.Image = fixture.Image with { RepoDigests = [.. fixture.Image.RepoDigests!, "other@" + Digest(fixture.NewManifest)] };
                break;
            case "missing configured alias":
                fixture.Image = fixture.Image with { RepoDigests = ["happyecho@" + fixture.Image.Id] };
                break;
            case "missing digests":
                fixture.Image = fixture.Image with { RepoDigests = null };
                break;
            case "invalid descriptor":
                fixture.Image = fixture.Image with { Descriptor = JsonSerializer.SerializeToElement(new { digest = fixture.Image.Id }) };
                break;
            case "descriptor mismatch":
                fixture.Image = fixture.Image with { Id = Digest(fixture.NewManifest) };
                fixture.Container = fixture.Container with { ImageId = fixture.Image.Id };
                break;
            case "container mismatch":
                fixture.Container = fixture.Container with { ImageId = Digest(fixture.NewConfig) };
                break;
            case "empty identity":
                fixture.Image = fixture.Image with { Identity = JsonSerializer.Deserialize<JsonElement>("{}") };
                break;
            case "mixed identity":
                fixture.Image = fixture.Image with { Identity = JsonSerializer.SerializeToElement(new
                {
                    Pull = new[] { new { Repository } }, Build = new[] { new { Ref = "built" } }
                }) };
                break;
            case "nonmatching pull":
                fixture.Image = fixture.Image with { Identity = JsonSerializer.SerializeToElement(new
                {
                    Pull = new[] { new { Repository = "ghcr.io/other/happyecho" } }
                }) };
                break;
        }
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task MatchingPullIdentityStillAllowsVerifiedRegistryComparisons(bool index)
    {
        using var fixture = LocalFixture(index);
        fixture.Image = fixture.Image with { Identity = JsonSerializer.SerializeToElement(new { Pull = new[] { new { Repository } } }) };
        Assert.AreEqual(ImageReferenceKind.RegistryBacked, ImageReference.Parse(fixture.Container.ConfiguredImage).WithMetadata(fixture.Image).Kind);
        Assert.AreEqual(UpdateStatus.UpToDate, (await fixture.CheckAsync()).Status);
        Assert.IsNotEmpty(fixture.Requests);
    }

    [TestMethod]
    [DataRow("docker.io", 401, UpdateStatus.AuthenticationRequired)]
    [DataRow("docker.io", 429, UpdateStatus.RegistryUnavailable)]
    [DataRow("docker.io", 503, UpdateStatus.RegistryUnavailable)]
    [DataRow("ghcr.io", 401, UpdateStatus.AuthenticationRequired)]
    [DataRow("ghcr.io", 503, UpdateStatus.RegistryUnavailable)]
    public async Task PulledImagesStillReportRegistryErrors(string registry, int code, UpdateStatus expected)
    {
        using var fixture = new RegistryFixture(registry: registry);
        fixture.UseContainerd(false);
        fixture.Intercept = _ => Error((HttpStatusCode)code);
        Assert.AreEqual(expected, (await fixture.CheckAsync()).Status);
        Assert.IsNotEmpty(fixture.Requests);
    }

    [TestMethod]
    public async Task PulledImageWithMissingIdentityAndCanonicalDigestsRemainsUnknown()
    {
        using var fixture = new RegistryFixture();
        fixture.UseContainerd(false);
        fixture.Container = fixture.Container with { ConfiguredImage = "nats:2.14.3-alpine" };
        fixture.Image = fixture.Image with { Identity = null };
        Assert.AreEqual(ImageProvenanceKind.Missing,
            DockerImageIdentity.Provenance(ImageReference.Parse(fixture.Container.ConfiguredImage), fixture.Image).Kind);
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    public async Task LocalImportsRemainVisibleAndDoNotMakeRunsIncompleteOrResolveHistory()
    {
        using var fixture = LocalFixture(false);
        DirectoryInfo directory = Directory.CreateTempSubdirectory("happydocker-local-");
        string database = Path.Combine(directory.FullName, "findings.db");
        try
        {
            var previous = new FindingObservation(FindingKind.MutableTag, "joyful-stack-happyecho-1", fixture.Container.Id, fixture.Image.Id,
                Repository, "1.2.3", Digest(fixture.OldManifest), Digest(fixture.NewManifest), true, FindingEvidence.Present,
                DateTimeOffset.UtcNow.AddMinutes(-1));
            FindingHistory.Record(database, "clanker", [previous, previous with { Kind = FindingKind.VersionCandidate, Available = "1.2.4" }]);
            using var output = new StringWriter();
            var check = await DockerCheck.RunObservedAsync(Inventory, fixture.Checker, output, TextWriter.Null);
            var versions = await DockerVersions.RunObservedAsync(["--repo", Repository], Inventory, fixture.Client, output, TextWriter.Null);
            foreach (FindingRun run in new[] { check, versions })
            {
                Assert.AreEqual(FindingRunStatus.Complete, run.Status);
                Assert.AreEqual(0, run.IncompleteCount);
                Assert.AreEqual(FindingEvidence.NotApplicable, run.Observations.Single().Evidence);
                Assert.IsEmpty(FindingHistory.Record(database, "clanker", run.Observations));
                Assert.AreEqual(0, await new FindingStateOptions([], database, "clanker").RecordAsync(run, Inventory, TextWriter.Null));
            }
            Assert.Contains("joyful-stack-happyecho-1", output.ToString());
            Assert.Contains("Skipped", output.ToString());
            Assert.Contains("Local/imported", output.ToString());
            using var scan = new StringWriter();
            DockerScan.WriteReport([fixture.Container], [fixture.Image], scan, TextWriter.Null);
            Assert.Contains("LocalOrImported", scan.ToString());
            Assert.IsEmpty(fixture.Requests);
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder { DataSource = database, Pooling = false }.ToString());
            connection.Open();
            using var command = connection.CreateCommand();
            command.CommandText = "SELECT COUNT(*) FROM findings WHERE state = 'New'";
            Assert.AreEqual(2L, command.ExecuteScalar());
        }
        finally
        {
            File.Delete(database);
            directory.Delete();
        }

        Task<DockerCommandResult> Inventory(string[] arguments) => Task.FromResult(new DockerCommandResult(0, arguments[0] switch
        {
            "ps" => JsonSerializer.Serialize(new { ID = fixture.Container.Id, Names = fixture.Container.Name, Image = fixture.Container.ConfiguredImage }),
            "inspect" when arguments[1] == "--type" && arguments[2] == "container" => JsonSerializer.Serialize(fixture.Container),
            "image" when arguments[1] == "inspect" => JsonSerializer.Serialize(fixture.Image),
            _ => throw new AssertFailedException("Unexpected Docker operation.")
        }, ""));
    }

    private static RegistryFixture LocalFixture(bool index)
    {
        var fixture = new RegistryFixture(repository: "library/" + Name, tag: "1.2.3");
        fixture.UseContainerd(index);
        ImageDescriptor descriptor = DockerImageIdentity.ReadDescriptor(fixture.Image.Descriptor)!;
        fixture.Container = fixture.Container with { Name = "/joyful-stack-happyecho-1", ConfiguredImage = Name + ":1.2.3" };
        fixture.Image = fixture.Image with
        {
            Identity = null,
            RepoDigests = ["happyecho@" + fixture.Image.Id, Name + "@" + fixture.Image.Id],
            Descriptor = JsonSerializer.SerializeToElement(new
            {
                mediaType = descriptor.MediaType, digest = descriptor.Digest, size = descriptor.Size,
                annotations = new Dictionary<string, string> { ["org.opencontainers.image.ref.name"] = "docker.io/library/happyecho:net1015" }
            })
        };
        return fixture;
    }
}
