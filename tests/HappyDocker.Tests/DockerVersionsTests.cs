using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using static HappyDocker.Tests.RegistryFixture;

namespace HappyDocker.Tests;

[TestClass]
public sealed class DockerVersionsTests
{
    private const string Repo = "docker.io/library/nats";
    private const string TagPath = "/v2/library/nats/tags/list";
    private const string CurrentTag = "2.14.8-alpine";
    private const string Candidate = "2.14.10-alpine";

    [TestMethod]
    public async Task NumericVersionSelection_ConsidersMajorMinorAndExactVariant()
    {
        using var fixture = Fixture();
        fixture.SetTag(fixture.NewManifest, "3.14.0-alpine");
        fixture.Intercept = request => IsTagList(request) ? Tags(fixture.Repository,
            ["2.14.7-alpine", CurrentTag, "2.14.9-alpine", Candidate, "2.14.100-Alpine", "2.14.110",
             "2.14.120-alpine3.22", "2.15.0-alpine", "3.14.0-alpine", "2.14.999-alpine-rc1", "2.14.99-01",
             "2.14.999-alpine-dev", "2.14.99-deadbee", "2.14.010-alpine", "latest", "2.14", "dev"]) : null;
        var result = await RunAsync(fixture);
        Assert.AreEqual(0, result.ExitCode);
        Assert.Contains($"Configured tag {CurrentTag}", result.Output);
        Assert.Contains("Candidate 3.14.0-alpine (platform verified)", result.Output);
        Assert.Contains("Upgrade Major", result.Output);
        Assert.Contains("does not establish compatibility or security", result.Output);
        Assert.HasCount(3, fixture.Requests);
    }

    [TestMethod]
    [DataRow("2.14.8", "2.14.9")]
    [DataRow("2.14.8-alpine3.22", "2.14.9-alpine3.22")]
    public async Task AcceptsStableNumericVersionsWithOrWithoutOpaqueVariant(string current, string next)
    {
        using var fixture = Fixture();
        fixture.Container = fixture.Container with { ConfiguredImage = Repo + ":" + current };
        fixture.SetTag(fixture.NewManifest, next);
        fixture.Intercept = request => IsTagList(request) ? Tags(fixture.Repository, [next, current]) : null;
        Assert.Contains($"Candidate {next} (platform verified)", (await RunAsync(fixture)).Output);
    }

    [TestMethod]
    [DataRow("nats")]
    [DataRow("nats:latest")]
    [DataRow("nats:dev")]
    [DataRow("nats:2")]
    [DataRow("nats:2.14")]
    [DataRow("nats:2.14.8.1")]
    [DataRow("nats:02.14.8")]
    [DataRow("nats:2.14.999999999999")]
    [DataRow("nats:2.14.8-rc.1")]
    [DataRow("nats:2.14.8-alpine-beta1")]
    [DataRow("nats:2.14.8-1")]
    [DataRow("nats:deadbee")]
    public async Task UnrecognizedCurrentTags_DoNotQueryRegistry(string configured)
    {
        using var fixture = Fixture();
        fixture.Container = fixture.Container with { ConfiguredImage = configured };
        Assert.Contains("Skipped unrecognized version tag", (await RunAsync(fixture)).Output);
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    [DataRow("missing")]
    [DataRow("flag")]
    [DataRow("tagged")]
    [DataRow("pinned")]
    public async Task InvalidOptIn_ShowsUsageBeforeDockerOrRegistry(string scenario)
    {
        using var fixture = Fixture();
        string[] options = scenario switch
        {
            "missing" => [], "flag" => ["--repo"], "tagged" => ["--repo", Repo + ":latest"],
            _ => ["--repo", Repo + "@" + Digest(fixture.OldManifest)]
        };
        using var error = new StringWriter();
        int exit = await DockerVersions.RunAsync(options, _ => throw new AssertFailedException("Docker should not run."),
            fixture.Client, TextWriter.Null, error);
        Assert.AreEqual(1, exit);
        Assert.Contains("Usage: happydocker versions --repo", error.ToString());
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    public async Task OptIn_NormalizesAndDeduplicatesRepositoriesAndSharedImages()
    {
        using var fixture = Fixture();
        fixture.SetTag(fixture.NewManifest, Candidate);
        fixture.Intercept = request => IsTagList(request) ? Tags(fixture.Repository, [Candidate]) : null;
        var second = fixture.Container with { Id = "second", Name = "/another-nats", ConfiguredImage = "nats:" + CurrentTag };
        var unrelated = fixture.Container with { Id = "third", Name = "/unselected", ConfiguredImage = "redis:7.2.1" };
        var unsupported = fixture.Container with { Id = "fourth", Name = "/unsupported", ConfiguredImage = "registry.example/org/app:1.2.3" };
        var result = await RunAsync(fixture, ["--repo", Repo, "--repo", "nats", "--repo", "registry.example/org/app", "--repo", "library/not-running"],
            [fixture.Container, second, unrelated, unsupported]);
        Assert.Contains("another-nats", result.Output);
        Assert.Contains("Unsupported registry", result.Output);
        Assert.Contains("library/not-running has no matching running containers", result.Output);
        Assert.DoesNotContain("unselected", result.Output);
        Assert.HasCount(1, fixture.Requests.Where(request => request.Path == TagPath));
        Assert.HasCount(3, fixture.Requests);
        Assert.HasCount(3, result.Commands);
        Assert.AreEqual("ps", result.Commands[0][0]);
        CollectionAssert.AreEqual(new[] { "inspect", "--type", "container" }, result.Commands[1][..3]);
        CollectionAssert.AreEqual(new[] { "image", "inspect" }, result.Commands[2][..2]);
    }

    [TestMethod]
    public async Task RepeatedRepoFlags_QueryBothSelectedRepositories()
    {
        using var fixture = Fixture();
        string otherId = Digest(fixture.NewConfig);
        var other = fixture.Container with { Id = "redis", Name = "/redis", ImageId = otherId, ConfiguredImage = "redis:7.2.1" };
        var otherImage = fixture.Image with { Id = otherId, Identity = Pull("docker.io/library/redis") };
        fixture.Intercept = request => Tags(request.RequestUri!.AbsolutePath == TagPath ? "library/nats" : "library/redis", []);
        var result = await RunAsync(fixture, ["--repo", "nats", "--repo", "redis"], [fixture.Container, other], [fixture.Image, otherImage]);
        Assert.Contains("docker.io/library/redis", result.Output);
        CollectionAssert.AreEqual(new[] { TagPath, "/v2/library/redis/tags/list" }, fixture.Requests.Select(request => request.Path).ToArray());
    }

    [TestMethod]
    [DataRow("build", "locally built")]
    [DataRow("ambiguous", "ambiguous provenance")]
    [DataRow("mixed", "ambiguous provenance")]
    [DataRow("pinned", "digest-pinned")]
    [DataRow("missing", "metadata is missing")]
    public async Task IneligibleDeployments_AreReportedWithoutRequests(string scenario, string expected)
    {
        using var fixture = Fixture();
        switch (scenario)
        {
            case "build":
                fixture.Image = fixture.Image with { Identity = JsonSerializer.SerializeToElement(new { Build = new[] { new { Ref = "local" } } }) };
                break;
            case "ambiguous":
                fixture.Image = fixture.Image with { Identity = null };
                break;
            case "mixed":
                fixture.Image = fixture.Image with { Identity = JsonSerializer.Deserialize<JsonElement>(
                    """{"Pull":[{"Repository":"docker.io/library/nats"}],"Build":[{"Ref":"mixed"}]}""") };
                break;
            case "pinned":
                fixture.Container = fixture.Container with { ConfiguredImage = Repo + ":" + CurrentTag + "@" + Digest(fixture.OldManifest) };
                break;
        }
        var result = await RunAsync(fixture, images: scenario == "missing" ? [] : null);
        Assert.Contains(expected, result.Output);
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    public async Task Pagination_ReusesAnonymousBearerAndValidatesCursorOnShortPage()
    {
        using var fixture = Fixture();
        fixture.SetTag(fixture.NewManifest, Candidate);
        fixture.Intercept = request =>
        {
            if (request.RequestUri!.AbsolutePath == "/token")
            {
                Assert.AreEqual("auth.docker.io", request.RequestUri.Host);
                Assert.IsNull(request.Headers.Authorization);
                Assert.AreEqual("?service=registry.docker.io&scope=repository:library/nats:pull",
                    Uri.UnescapeDataString(request.RequestUri.Query));
                return Response(Bytes("""{"token":"fixture-token"}"""));
            }
            if (request.Headers.Authorization?.Parameter != "fixture-token")
            {
                var challenge = Error(HttpStatusCode.Unauthorized);
                challenge.Headers.WwwAuthenticate.Add(new("Bearer",
                    "realm=\"https://auth.docker.io/token\",service=\"registry.docker.io\",scope=\"repository:library/nats:pull\""));
                return challenge;
            }
            return IsTagList(request)
                ? request.RequestUri.Query == "?n=100"
                    ? Tags(fixture.Repository, [CurrentTag], $"<{TagPath}?n=2&last={CurrentTag}>; rel=\"next\"")
                    : Tags(fixture.Repository, [Candidate])
                : null;
        };
        var result = await RunAsync(fixture);
        Assert.Contains($"Candidate {Candidate} (platform verified)", result.Output);
        Assert.DoesNotContain("Incomplete enumeration", result.Output);
        Assert.HasCount(1, fixture.Requests.Where(request => request.Path == "/token"));
        Assert.IsTrue(fixture.Requests.Any(request => request.Query == $"?n=2&last={CurrentTag}"));
    }

    [TestMethod]
    [DataRow("<https://evil.example/v2/library/nats/tags/list?n=100&last=2.14.8-alpine>; rel=\"next\"")]
    [DataRow("<http://registry-1.docker.io/v2/library/nats/tags/list?n=100&last=2.14.8-alpine>; rel=\"next\"")]
    [DataRow("</v2/other/repo/tags/list?n=100&last=2.14.8-alpine>; rel=\"next\"")]
    [DataRow("</v2/library/nats/tags/list?n=1000&last=2.14.8-alpine>; rel=\"next\"")]
    [DataRow("</v2/library/nats/tags/list?n=100&last=other>; rel=\"next\"")]
    [DataRow("</v2/library/nats/tags/list?n=100&last=2.14.8-alpine&extra=1>; rel=\"next\"")]
    [DataRow("malformed")]
    public async Task UnsafePaginationLink_IsNeverRequested(string link)
    {
        using var fixture = Fixture();
        fixture.Intercept = _ => Tags(fixture.Repository, [CurrentTag], link);
        var result = await RunAsync(fixture);
        Assert.Contains("Incomplete enumeration", result.Output);
        Assert.Contains("pagination link", result.Output);
        Assert.HasCount(1, fixture.Requests);
    }

    [TestMethod]
    public async Task PageLimit_KeepsObservedCandidateAndReportsIncompleteEnumeration()
    {
        using var fixture = Fixture();
        fixture.SetTag(fixture.NewManifest, Candidate);
        int pages = 0;
        fixture.Intercept = request =>
        {
            if (!IsTagList(request)) return null;
            string tag = ++pages == 1 ? Candidate : $"other-{pages}";
            return Tags(fixture.Repository, [tag], $"<?n=100&last={tag}>; rel=\"next\"");
        };
        var result = await RunAsync(fixture);
        Assert.AreEqual(20, pages);
        Assert.Contains("Incomplete enumeration. Tag page limit reached.", result.Output);
        Assert.Contains($"Candidate {Candidate}", result.Output);
        Assert.DoesNotContain("latest available", result.Output);
    }

    [TestMethod]
    public async Task FullPageWithoutContinuation_IsInconclusive()
    {
        using var fixture = Fixture();
        fixture.Intercept = _ => Tags(fixture.Repository, Enumerable.Range(1, 100).Select(i => $"tag-{i}").ToArray());
        string output = (await RunAsync(fixture)).Output;
        Assert.Contains("Incomplete enumeration", output);
        Assert.Contains("no continuation link", output);
        Assert.DoesNotContain("Up to date", output);
    }

    [TestMethod]
    public async Task RepeatedCursor_StopsPagination()
    {
        using var fixture = Fixture();
        fixture.Intercept = _ => Tags(fixture.Repository, [CurrentTag], $"<?n=100&last={CurrentTag}>; rel=\"next\"");
        Assert.Contains("repeated the pagination cursor", (await RunAsync(fixture)).Output);
        Assert.HasCount(2, fixture.Requests);
    }

    [TestMethod]
    public async Task TagListingRedirect_DoesNotQueryAnotherRepository()
    {
        using var fixture = Fixture();
        fixture.Intercept = _ => new HttpResponseMessage(HttpStatusCode.TemporaryRedirect)
        {
            Headers = { Location = new Uri("https://registry-1.docker.io/v2/library/redis/tags/list") }
        };
        Assert.Contains("Incomplete enumeration", (await RunAsync(fixture)).Output);
        Assert.HasCount(1, fixture.Requests);
    }

    [TestMethod]
    public async Task RateLimitCooldown_AppliesAcrossOptedInRepositories()
    {
        using var fixture = Fixture();
        string otherId = Digest(fixture.NewConfig);
        var other = fixture.Container with { Id = "redis", Name = "/redis", ImageId = otherId, ConfiguredImage = "redis:7.2.1" };
        var otherImage = fixture.Image with { Id = otherId, Identity = Pull("docker.io/library/redis") };
        fixture.Intercept = _ =>
        {
            var response = Error(HttpStatusCode.TooManyRequests);
            response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromMinutes(5));
            return response;
        };
        var result = await RunAsync(fixture, ["--repo", "nats", "--repo", "redis"], [fixture.Container, other], [fixture.Image, otherImage]);
        Assert.Contains("docker.io/library/redis", result.Output);
        Assert.AreEqual(2, result.Output.Split("Retry after", StringSplitOptions.None).Length - 1);
        Assert.HasCount(1, fixture.Requests);
    }

    [TestMethod]
    [DataRow(401, "Authentication required")]
    [DataRow(403, "Authentication required")]
    [DataRow(429, "rate limited")]
    [DataRow(500, "Registry unavailable")]
    [DataRow(503, "Registry unavailable")]
    public async Task RegistryFailures_AreReportedWithoutBodyOrFreshnessClaims(int status, string expected)
    {
        using var fixture = Fixture();
        fixture.Intercept = _ =>
        {
            var response = Error((HttpStatusCode)status);
            if (status == 429) response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromMinutes(5));
            return response;
        };
        var second = fixture.Container with { Id = "second", Name = "/second" };
        string output = (await RunAsync(fixture, containers: [fixture.Container, second])).Output;
        Assert.Contains("Incomplete enumeration", output);
        Assert.Contains(expected, output);
        if (status == 429) Assert.Contains("Retry after", output);
        Assert.DoesNotContain("sensitive registry error", output);
        Assert.DoesNotContain("Up to date", output);
        Assert.HasCount(1, fixture.Requests);
    }

    [TestMethod]
    [DataRow("{", "malformed tag page JSON")]
    [DataRow("""{"name":"another/repo","tags":[]}""", "invalid tag page metadata")]
    [DataRow("""{"name":"library/nats","tags":[null]}""", "invalid tags")]
    public async Task MalformedPages_AreIncomplete(string body, string expected)
    {
        using var fixture = Fixture();
        fixture.Intercept = _ => Response(Bytes(body));
        Assert.Contains(expected, (await RunAsync(fixture)).Output);
        Assert.HasCount(1, fixture.Requests);
    }

    [TestMethod]
    public async Task OversizedTagPage_IsIncomplete()
    {
        using var fixture = Fixture();
        fixture.Intercept = _ => Response(new byte[64 * 1024 + 1]);
        Assert.Contains("exceeds the response size limit", (await RunAsync(fixture)).Output);
    }

    [TestMethod]
    [DataRow("wrong config")]
    [DataRow("wrong index")]
    [DataRow("missing platform")]
    [DataRow("unavailable")]
    public async Task CandidateWithoutPlatformProof_IsLabeledUnverified(string scenario)
    {
        using var fixture = Fixture();
        byte[] config = Config("candidate", architecture: "arm64");
        fixture.AddConfig(config);
        fixture.SetTag(scenario == "wrong index"
            ? Index(Descriptor(Manifest(config), architecture: "arm64"))
            : Manifest(config), Candidate);
        if (scenario == "missing platform") fixture.Image = fixture.Image with { Architecture = null };
        fixture.Intercept = request => IsTagList(request) ? Tags(fixture.Repository, [Candidate])
            : scenario == "unavailable" ? Error(HttpStatusCode.ServiceUnavailable) : null;
        Assert.Contains($"Candidate {Candidate} (platform unverified)", (await RunAsync(fixture)).Output);
        if (scenario == "missing platform") Assert.HasCount(1, fixture.Requests);
    }

    [TestMethod]
    public async Task ContainerdIndex_VerifiesRunningChildPlatformInsteadOfDaemonDefault()
    {
        using var fixture = Fixture();
        fixture.UseContainerd(true);
        byte[] armConfig = Config("arm candidate", architecture: "arm64", variant: "v8");
        byte[] armManifest = Manifest(armConfig);
        fixture.AddConfig(armConfig);
        fixture.AddManifest(armManifest);
        fixture.Container = fixture.Container with
        {
            ImageManifestDescriptor = JsonSerializer.SerializeToElement(Descriptor(fixture.OldManifest, architecture: "arm64", variant: "v8"))
        };
        fixture.SetTag(Index(Descriptor(fixture.NewManifest), Descriptor(armManifest, architecture: "arm64", variant: "v8")), Candidate);
        fixture.Intercept = request => IsTagList(request) ? Tags(fixture.Repository, [Candidate]) : null;
        Assert.Contains("platform verified). Registry metadata matches linux/arm64/v8.", (await RunAsync(fixture)).Output);
        Assert.IsFalse(fixture.Requests.Any(request => request.Path.Contains(Digest(fixture.NewManifest))));
    }

    private static RegistryFixture Fixture()
    {
        var fixture = new RegistryFixture(tag: CurrentTag);
        fixture.Image = fixture.Image with { Identity = Pull(Repo) };
        return fixture;
    }

    private static JsonElement Pull(string repository) =>
        JsonSerializer.SerializeToElement(new { Pull = new[] { new { Repository = repository } } });

    private static bool IsTagList(HttpRequestMessage request) => request.RequestUri!.AbsolutePath == TagPath;

    private static HttpResponseMessage Tags(string repository, string[] values, string? link = null)
    {
        var response = Response(JsonSerializer.SerializeToUtf8Bytes(new { name = repository, tags = values }));
        if (link is not null) response.Headers.TryAddWithoutValidation("Link", link);
        return response;
    }

    private static async Task<(int ExitCode, string Output, List<string[]> Commands)> RunAsync(RegistryFixture fixture,
        string[]? options = null, DockerInspectRow[]? containers = null, DockerImageRow[]? images = null)
    {
        containers ??= [fixture.Container];
        images ??= [fixture.Image];
        var replies = new Queue<string>([
            Lines(containers.Select(container => new { ID = container.Id, Names = container.Name, Image = container.ConfiguredImage })),
            Lines(containers), Lines(images)
        ]);
        var commands = new List<string[]>();
        using var output = new StringWriter();
        int exit = await DockerVersions.RunAsync(options ?? ["--repo", Repo], args =>
        {
            commands.Add(args);
            return Task.FromResult(new DockerCommandResult(0, replies.Dequeue(), ""));
        }, fixture.Client, output, TextWriter.Null);
        return (exit, output.ToString(), commands);
    }

    private static string Lines<T>(IEnumerable<T> items) => string.Join('\n', items.Select(item => JsonSerializer.Serialize(item)));
}
