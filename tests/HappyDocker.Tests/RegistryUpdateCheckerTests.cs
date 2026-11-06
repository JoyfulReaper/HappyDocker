using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using static HappyDocker.Tests.RegistryFixture;

namespace HappyDocker.Tests;

[TestClass]
public sealed class RegistryUpdateCheckerTests
{
    [TestMethod]
    [DataRow("docker.io")]
    [DataRow("ghcr.io")]
    public async Task UnchangedTag_ReportsUpToDate(string registry)
    {
        using var fixture = new RegistryFixture(registry);
        UpdateResult result = await fixture.CheckAsync();
        Assert.AreEqual(UpdateStatus.UpToDate, result.Status);
        Assert.AreEqual(Digest(fixture.OldManifest), result.DeployedManifest);
        Assert.AreEqual(result.DeployedManifest, result.CurrentManifest);
        Assert.AreNotEqual(fixture.Image.Id, result.DeployedManifest);
        Assert.HasCount(2, fixture.Requests);
    }

    [TestMethod]
    [DataRow("docker.io")]
    [DataRow("ghcr.io")]
    public async Task ChangedTag_ReportsDifferentPlatformManifest(string registry)
    {
        using var fixture = new RegistryFixture(registry);
        fixture.SetTag(fixture.NewManifest);
        UpdateResult result = await fixture.CheckAsync();
        Assert.AreEqual(UpdateStatus.UpdateAvailable, result.Status);
        Assert.AreEqual(Digest(fixture.OldManifest), result.DeployedManifest);
        Assert.AreEqual(Digest(fixture.NewManifest), result.CurrentManifest);
        Assert.AreNotEqual(fixture.Image.Id, result.DeployedManifest);
        Assert.HasCount(3, fixture.Requests);
        Assert.Contains("/blobs/" + Digest(fixture.NewConfig), fixture.Requests[^1].Path);
    }

    [TestMethod]
    public async Task NatsUnchangedVersionTag_DoesNotDiscoverOrCompareNewerVersions()
    {
        using var fixture = new RegistryFixture(tag: "2.14.3-alpine");
        fixture.Container = fixture.Container with { ConfiguredImage = "nats:2.14.3-alpine" };
        fixture.SetTag(fixture.NewManifest, "2.14.8-alpine");
        Assert.AreEqual(UpdateStatus.UpToDate, (await fixture.CheckAsync()).Status);
        Assert.IsFalse(fixture.Requests.Any(r => r.Path.Contains("2.14.8") || r.Path.Contains("tags/list")));
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task Index_SelectsDeployedPlatform_IgnoresChangesToOtherArchitectures(bool targetChanged)
    {
        using var fixture = new RegistryFixture();
        byte[] otherOld = Manifest(Config("arm-old", architecture: "arm64"));
        byte[] otherNew = Manifest(Config("arm-new", architecture: "arm64"));
        fixture.SetDeployed(Index(Descriptor(fixture.OldManifest), Descriptor(otherOld, architecture: "arm64")));
        fixture.SetTag(Index(Descriptor(targetChanged ? fixture.NewManifest : fixture.OldManifest),
            Descriptor(otherNew, architecture: "arm64")));
        UpdateResult result = await fixture.CheckAsync();
        Assert.AreEqual(targetChanged ? UpdateStatus.UpdateAvailable : UpdateStatus.UpToDate, result.Status);
        Assert.AreEqual(Digest(fixture.OldManifest), result.DeployedManifest);
        Assert.AreNotEqual(ImageReference.Parse(fixture.Image.RepoDigests![0]).Digest, result.DeployedManifest);
        Assert.IsFalse(fixture.Requests.Any(r => r.Path.Contains(Digest(otherOld)) || r.Path.Contains(Digest(otherNew))));
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task RepositoryDigestCanBeIndexOrChild_ComparisonResolvesBothSides(bool deployedIndex)
    {
        using var fixture = new RegistryFixture();
        if (deployedIndex) fixture.SetDeployed(Index(Descriptor(fixture.OldManifest)));
        else fixture.SetTag(Index(Descriptor(fixture.NewManifest)));
        if (deployedIndex) fixture.SetTag(fixture.NewManifest);
        Assert.AreEqual(UpdateStatus.UpdateAvailable, (await fixture.CheckAsync()).Status);
    }

    [TestMethod]
    public async Task DockerSchema2AndManifestList_AreSupported()
    {
        using var fixture = new RegistryFixture();
        byte[] old = Manifest(fixture.OldConfig, DockerManifest);
        byte[] current = Manifest(fixture.NewConfig, DockerManifest);
        fixture.SetDeployed(old);
        fixture.AddManifest(current);
        byte[] index = Bytes(System.Text.Encoding.UTF8.GetString(Index(Descriptor(current, mediaType: DockerManifest)))
            .Replace(OciIndex, DockerIndex));
        fixture.SetTag(index);
        Assert.AreEqual(UpdateStatus.UpdateAvailable, (await fixture.CheckAsync()).Status);
    }

    [TestMethod]
    [DataRow("ghcr.io/org/app@sha256:")]
    [DataRow("docker.io/library/nats:stable@sha256:")]
    public async Task DigestPins_AreSkippedWithoutHttp(string prefix)
    {
        using var fixture = new RegistryFixture();
        fixture.Container = fixture.Container with { ConfiguredImage = prefix + new string('a', 64) };
        Assert.AreEqual(UpdateStatus.Skipped, (await fixture.CheckAsync()).Status);
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    [DataRow("team/local:dev")]
    [DataRow("nats")]
    [DataRow("abcdef123456")]
    [DataRow("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    [DataRow("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]
    public async Task AmbiguousAndLocalOnlyImages_AreSkippedWithoutHttp(string configured)
    {
        using var fixture = new RegistryFixture();
        fixture.Container = fixture.Container with { ConfiguredImage = configured };
        fixture.Image = fixture.Image with { RepoDigests = null };
        Assert.AreEqual(UpdateStatus.Skipped, (await fixture.CheckAsync()).Status);
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    [DataRow("example.com/team/app:latest")]
    [DataRow("localhost:5000/app:dev")]
    [DataRow("docker.io:443/library/nats:latest")]
    [DataRow("ghcr.io.evil.example/org/app:latest")]
    public async Task UnsupportedRegistries_NeverReceiveRequests(string configured)
    {
        using var fixture = new RegistryFixture();
        fixture.Container = fixture.Container with { ConfiguredImage = configured };
        Assert.AreEqual(UpdateStatus.UnsupportedRegistry, (await fixture.CheckAsync()).Status);
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    [DataRow(2)]
    [DataRow(3)]
    [DataRow(4)]
    [DataRow(5)]
    [DataRow(6)]
    public async Task MissingOrConflictingLocalMetadata_IsUnknownBeforeHttp(int scenario)
    {
        using var fixture = new RegistryFixture();
        DockerImageRow? image = fixture.Image;
        image = scenario switch
        {
            0 => null,
            1 => image with { Os = null },
            2 => image with { Architecture = null },
            3 => image with { RepoDigests = null },
            4 => image with { Id = "invalid" },
            5 => image with { RepoDigests = ["ghcr.io/other/app@" + Digest(fixture.OldManifest)] },
            _ => image with { RepoDigests = [.. image.RepoDigests!, "docker.io/library/nats@" + Digest(fixture.NewManifest)] }
        };
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.Checker.CheckAsync(fixture.Container, image)).Status);
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    public async Task DeployedManifestMustMatchDockerConfigId()
    {
        using var fixture = new RegistryFixture();
        fixture.Image = fixture.Image with { Id = Digest(fixture.NewConfig) };
        fixture.Container = fixture.Container with { ImageId = fixture.Image.Id };
        fixture.SetTag(fixture.NewManifest);
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
        Assert.HasCount(1, fixture.Requests);
    }

    [TestMethod]
    public async Task ManifestOnlyChangeWithSameConfiguration_IsNotAnImageUpdate()
    {
        using var fixture = new RegistryFixture();
        fixture.SetTag(Manifest(fixture.OldConfig, label: "repacked"));
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
    }

    [TestMethod]
    [DataRow("arm64", null)]
    [DataRow("amd64", "v2")]
    public async Task CurrentSingleManifestMustMatchDeployedPlatform(string architecture, string? variant)
    {
        using var fixture = new RegistryFixture();
        byte[] config = Config("other platform", architecture: architecture, variant: variant);
        fixture.SetTag(Manifest(config));
        fixture.AddConfig(config);
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task IndexRequiresUniqueExactPlatformMatch(bool duplicate)
    {
        using var fixture = new RegistryFixture();
        fixture.SetTag(duplicate
            ? Index(Descriptor(fixture.NewManifest), Descriptor(fixture.OldManifest))
            : Index(Descriptor(fixture.NewManifest, architecture: "arm64", variant: "v8")));
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
    }

    [TestMethod]
    public async Task VariantIsSelectedExactly_DescriptorCanSupplyVariantMissingFromConfig()
    {
        using var fixture = new RegistryFixture();
        byte[] oldConfig = Config("arm-old", architecture: "arm64");
        byte[] newConfig = Config("arm-new", architecture: "arm64");
        byte[] oldManifest = Manifest(oldConfig);
        byte[] newManifest = Manifest(newConfig);
        fixture.Image = fixture.Image with { Id = Digest(oldConfig), Architecture = "arm64", Variant = "v8" };
        fixture.Container = fixture.Container with { ImageId = fixture.Image.Id };
        fixture.AddManifest(oldManifest);
        fixture.AddManifest(newManifest);
        fixture.AddConfig(newConfig);
        fixture.SetDeployed(Index(Descriptor(oldManifest, architecture: "arm64", variant: "v8")));
        fixture.SetTag(Index(Descriptor(newManifest, architecture: "arm64", variant: "v8"),
            Descriptor(fixture.OldManifest, architecture: "arm64", variant: "v9")));
        Assert.AreEqual(UpdateStatus.UpdateAvailable, (await fixture.CheckAsync()).Status);
    }

    [TestMethod]
    [DataRow("not json")]
    [DataRow("null")]
    [DataRow("42")]
    [DataRow("{\"schemaVersion\":\"2\"}")]
    [DataRow("{\"schemaVersion\":1}")]
    [DataRow("{\"schemaVersion\":2,\"schemaVersion\":1}")]
    [DataRow("{\"schemaVersion\":2,\"mediaType\":\"application/vnd.oci.image.index.v1+json\",\"manifests\":null}")]
    public async Task MalformedOrUnsupportedManifest_IsUnknown(string json)
    {
        using var fixture = new RegistryFixture();
        fixture.SetTag(Bytes(json));
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
    }

    [TestMethod]
    public async Task RequestedDigestMustMatchResponseBytes()
    {
        using var fixture = new RegistryFixture();
        fixture.Intercept = _ => Response(fixture.NewManifest);
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
        Assert.HasCount(1, fixture.Requests);
    }

    [TestMethod]
    public async Task AdvertisedDigestMustMatchResponseBytes()
    {
        using var fixture = new RegistryFixture();
        fixture.Intercept = _ =>
        {
            var response = Response(fixture.OldManifest);
            response.Headers.Remove("Docker-Content-Digest");
            response.Headers.Add("Docker-Content-Digest", Digest(fixture.NewManifest));
            return response;
        };
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
    }

    [TestMethod]
    public async Task MissingDigestHeader_CanUseVerifiedContentHash()
    {
        using var fixture = new RegistryFixture();
        fixture.Intercept = _ =>
        {
            var response = Response(fixture.OldManifest);
            response.Headers.Remove("Docker-Content-Digest");
            return response;
        };
        Assert.AreEqual(UpdateStatus.UpToDate, (await fixture.CheckAsync()).Status);
    }

    [TestMethod]
    [DataRow(401, UpdateStatus.AuthenticationRequired)]
    [DataRow(403, UpdateStatus.AuthenticationRequired)]
    [DataRow(404, UpdateStatus.Unknown)]
    [DataRow(408, UpdateStatus.RegistryUnavailable)]
    [DataRow(429, UpdateStatus.RegistryUnavailable)]
    [DataRow(500, UpdateStatus.RegistryUnavailable)]
    [DataRow(503, UpdateStatus.RegistryUnavailable)]
    public async Task HttpErrors_AreClassifiedWithoutPrintingResponseBodies(int status, UpdateStatus expected)
    {
        using var fixture = new RegistryFixture();
        fixture.Intercept = _ => Error((HttpStatusCode)status);
        UpdateResult result = await fixture.CheckAsync();
        Assert.AreEqual(expected, result.Status);
        Assert.DoesNotContain("sensitive", result.Reason);
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task RateLimit_RespectsRetryAfterAndSuppressesFurtherRequests(bool dateHeader)
    {
        using var fixture = new RegistryFixture();
        fixture.Intercept = _ =>
        {
            var response = Error(HttpStatusCode.TooManyRequests);
            response.Headers.RetryAfter = dateHeader ? new RetryConditionHeaderValue(DateTimeOffset.UtcNow.AddMinutes(2))
                : new RetryConditionHeaderValue(TimeSpan.FromMinutes(2));
            return response;
        };
        UpdateResult result = await fixture.CheckAsync();
        Assert.AreEqual(UpdateStatus.RegistryUnavailable, result.Status);
        Assert.IsTrue(result.RetryAfter > DateTimeOffset.UtcNow.AddSeconds(110));
        Assert.AreEqual(UpdateStatus.RegistryUnavailable, (await fixture.CheckAsync()).Status);
        Assert.HasCount(1, fixture.Requests);
    }

    [TestMethod]
    [DataRow("docker.io", "token")]
    [DataRow("ghcr.io", "access_token")]
    public async Task AnonymousBearerChallenge_UsesPullOnlyScopeAndRepositoryScopedToken(string registry, string field)
    {
        using var fixture = new RegistryFixture(registry);
        fixture.SetTag(fixture.NewManifest);
        fixture.Intercept = request =>
        {
            if (request.RequestUri!.AbsolutePath == "/token")
            {
                Assert.IsNull(request.Headers.Authorization);
                string query = Uri.UnescapeDataString(request.RequestUri.Query);
                Assert.Contains("scope=repository:library/nats:pull", query);
                Assert.DoesNotContain("push", query);
                return Response(JsonSerializer.SerializeToUtf8Bytes(new Dictionary<string, string> { [field] = "anonymous.test.token" }));
            }
            if (request.Headers.Authorization?.Parameter == "anonymous.test.token") return null;
            var response = Error(HttpStatusCode.Unauthorized);
            string realm = registry == "docker.io" ? "https://auth.docker.io/token" : "https://ghcr.io/token";
            string service = registry == "docker.io" ? "registry.docker.io" : "ghcr.io";
            response.Headers.WwwAuthenticate.Add(new AuthenticationHeaderValue("bEaReR",
                $"service=\"{service}\", scope=\"repository:library/nats:pull\", realm=\"{realm}\""));
            return response;
        };
        UpdateResult result = await fixture.CheckAsync();
        Assert.AreEqual(UpdateStatus.UpdateAvailable, result.Status);
        Assert.HasCount(1, fixture.Requests.Where(r => r.Path == "/token"));
        Assert.DoesNotContain("anonymous.test.token", result.Reason);
        Assert.IsTrue(fixture.Requests.Where(r => r.Authorization is not null).All(r => r.Host == fixture.Host));
    }

    [TestMethod]
    [DataRow("realm=\"https://evil.example/token\"")]
    [DataRow("realm=\"http://auth.docker.io/token\"")]
    [DataRow("realm=\"https://auth.docker.io/token\",service=\"evil\"")]
    [DataRow("realm=\"https://auth.docker.io/token\",scope=\"repository:other/repo:pull,push\"")]
    [DataRow("realm=\"https://auth.docker.io/token\",realm=\"https://auth.docker.io/token\"")]
    public async Task UnsafeOrAmbiguousChallenges_DoNotMakeTokenRequests(string challenge)
    {
        using var fixture = new RegistryFixture();
        fixture.Intercept = _ =>
        {
            var response = Error(HttpStatusCode.Unauthorized);
            response.Headers.WwwAuthenticate.Add(new("Bearer", challenge));
            return response;
        };
        Assert.AreEqual(UpdateStatus.AuthenticationRequired, (await fixture.CheckAsync()).Status);
        Assert.HasCount(1, fixture.Requests);
    }

    [TestMethod]
    public async Task RedirectOnSameRegistry_IsFollowed()
    {
        using var fixture = new RegistryFixture();
        fixture.Intercept = request =>
        {
            string path = Uri.UnescapeDataString(request.RequestUri!.AbsolutePath);
            if (path.EndsWith(Digest(fixture.OldManifest)))
            {
                var response = new HttpResponseMessage(HttpStatusCode.TemporaryRedirect);
                response.Headers.Location = new Uri("/redirected", UriKind.Relative);
                return response;
            }
            return path == "/redirected" ? Response(fixture.OldManifest) : null;
        };
        Assert.AreEqual(UpdateStatus.UpToDate, (await fixture.CheckAsync()).Status);
        Assert.IsTrue(fixture.Requests.Any(r => r.Path == "/redirected"));
    }

    [TestMethod]
    [DataRow("https://evil.example/manifest")]
    [DataRow("http://registry-1.docker.io/manifest")]
    [DataRow("https://registry-1.docker.io:444/manifest")]
    public async Task UnsafeRedirects_AreBlockedBeforeSendingRequests(string destination)
    {
        using var fixture = new RegistryFixture();
        fixture.Intercept = _ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.TemporaryRedirect);
            response.Headers.Location = new Uri(destination);
            return response;
        };
        Assert.AreEqual(UpdateStatus.RegistryUnavailable, (await fixture.CheckAsync()).Status);
        Assert.HasCount(1, fixture.Requests);
    }

    [TestMethod]
    public async Task RedirectLoop_IsBounded()
    {
        using var fixture = new RegistryFixture();
        fixture.Intercept = _ =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.Redirect);
            response.Headers.Location = new Uri("/loop", UriKind.Relative);
            return response;
        };
        Assert.AreEqual(UpdateStatus.RegistryUnavailable, (await fixture.CheckAsync()).Status);
        Assert.HasCount(4, fixture.Requests);
    }

    [TestMethod]
    public async Task NetworkFailure_IsUnavailableAndSanitized()
    {
        using var fixture = new RegistryFixture();
        fixture.Intercept = _ => throw new HttpRequestException("sensitive token details");
        UpdateResult result = await fixture.CheckAsync();
        Assert.AreEqual(UpdateStatus.RegistryUnavailable, result.Status);
        Assert.DoesNotContain("sensitive", result.Reason);
    }

    [TestMethod]
    public async Task RequestTimeout_IsUnavailable()
    {
        using var fixture = new RegistryFixture();
        using var client = new RegistryClient(new FakeRegistryHandler(async (_, cancellation) =>
        {
            await Task.Delay(Timeout.Infinite, cancellation);
            return new HttpResponseMessage(HttpStatusCode.OK);
        }), TimeSpan.FromMilliseconds(50));
        UpdateResult result = await new RegistryUpdateChecker(client).CheckAsync(fixture.Container, fixture.Image);
        Assert.AreEqual(UpdateStatus.RegistryUnavailable, result.Status);
        Assert.Contains("timed out", result.Reason);
    }

    [TestMethod]
    public async Task CallerCancellation_IsPropagated()
    {
        using var fixture = new RegistryFixture();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            fixture.Checker.CheckAsync(fixture.Container, fixture.Image, cancellation.Token));
    }

    [TestMethod]
    public async Task OversizedResponse_IsUnknown()
    {
        using var fixture = new RegistryFixture();
        fixture.Intercept = _ =>
        {
            var response = Response(fixture.OldManifest);
            response.Content.Headers.ContentLength = 4 * 1024 * 1024 + 1;
            return response;
        };
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
    }

    [TestMethod]
    [DataRow("docker.io", "production.cloudfront.docker.com")]
    [DataRow("ghcr.io", "pkg-containers.githubusercontent.com")]
    public async Task ConfigRedirectToAllowlistedCdn_NeverForwardsBearerToken(string registry, string cdn)
    {
        using var fixture = new RegistryFixture(registry);
        fixture.SetTag(fixture.NewManifest);
        fixture.Intercept = request =>
        {
            if (request.RequestUri!.Host == cdn)
            {
                Assert.IsNull(request.Headers.Authorization);
                return Response(fixture.NewConfig);
            }
            if (request.RequestUri.AbsolutePath == "/token")
                return Response(Bytes("{\"token\":\"anonymous.test.token\"}"));
            if (request.Headers.Authorization is null)
            {
                var unauthorized = Error(HttpStatusCode.Unauthorized);
                string realm = registry == "docker.io" ? "https://auth.docker.io/token" : "https://ghcr.io/token";
                unauthorized.Headers.WwwAuthenticate.Add(new("Bearer", $"realm=\"{realm}\""));
                return unauthorized;
            }
            if (request.RequestUri.AbsolutePath.Contains("/blobs/"))
            {
                var redirect = new HttpResponseMessage(HttpStatusCode.TemporaryRedirect);
                redirect.Headers.Location = new Uri($"https://{cdn}/config?signature=example");
                return redirect;
            }
            return null;
        };
        Assert.AreEqual(UpdateStatus.UpdateAvailable, (await fixture.CheckAsync()).Status);
        Assert.HasCount(1, fixture.Requests.Where(r => r.Host == cdn));
        Assert.IsTrue(fixture.Requests.Where(r => r.Authorization is not null).All(r => r.Host == fixture.Host));
    }

    [TestMethod]
    [DataRow("https://evil.example/config")]
    [DataRow("https://production.cloudfront.docker.com.evil.example/config")]
    [DataRow("http://production.cloudfront.docker.com/config")]
    public async Task ConfigRedirectToArbitraryHost_IsBlocked(string location)
    {
        using var fixture = new RegistryFixture();
        fixture.SetTag(fixture.NewManifest);
        fixture.Intercept = request =>
        {
            if (!request.RequestUri!.AbsolutePath.Contains("/blobs/")) return null;
            var response = new HttpResponseMessage(HttpStatusCode.TemporaryRedirect);
            response.Headers.Location = new Uri(location);
            return response;
        };
        Assert.AreEqual(UpdateStatus.RegistryUnavailable, (await fixture.CheckAsync()).Status);
        Assert.IsTrue(fixture.Requests.All(r => r.Host == fixture.Host));
    }

    [TestMethod]
    [DataRow("{}")]
    [DataRow("{\"token\":\"\"}")]
    [DataRow("{\"token\":123}")]
    [DataRow("{\"token\":\"first\",\"token\":\"second\"}")]
    [DataRow("{\"token\":\"invalid token\"}")]
    [DataRow("invalid JSON")]
    public async Task InvalidAnonymousTokenResponse_IsAuthenticationRequired(string tokenJson)
    {
        using var fixture = new RegistryFixture();
        fixture.Intercept = request =>
        {
            if (request.RequestUri!.AbsolutePath == "/token") return Response(Bytes(tokenJson));
            var response = Error(HttpStatusCode.Unauthorized);
            response.Headers.WwwAuthenticate.Add(new("Bearer", "realm=\"https://auth.docker.io/token\""));
            return response;
        };
        Assert.AreEqual(UpdateStatus.AuthenticationRequired, (await fixture.CheckAsync()).Status);
        Assert.HasCount(2, fixture.Requests);
    }

    [TestMethod]
    public async Task RejectedAnonymousToken_DoesNotLoopOrExposeToken()
    {
        using var fixture = new RegistryFixture();
        fixture.Intercept = request =>
        {
            if (request.RequestUri!.AbsolutePath == "/token") return Response(Bytes("{\"token\":\"secret.test.token\"}"));
            var response = Error(HttpStatusCode.Unauthorized);
            response.Headers.WwwAuthenticate.Add(new("Bearer", "realm=\"https://auth.docker.io/token\""));
            return response;
        };
        UpdateResult result = await fixture.CheckAsync();
        Assert.AreEqual(UpdateStatus.AuthenticationRequired, result.Status);
        Assert.HasCount(3, fixture.Requests);
        Assert.DoesNotContain("secret", result.Reason);
    }

    [TestMethod]
    public async Task BearerTokensAreNotReusedForOtherRepositories()
    {
        using var fixture = new RegistryFixture();
        fixture.Intercept = request =>
        {
            if (request.RequestUri!.AbsolutePath == "/token")
            {
                string query = Uri.UnescapeDataString(request.RequestUri.Query);
                return Response(Bytes(query.Contains("repository:other/app:pull")
                    ? "{\"token\":\"other-token\"}" : "{\"token\":\"nats-token\"}"));
            }
            bool otherRepository = request.RequestUri.AbsolutePath.Contains("/other/app/");
            if (request.Headers.Authorization is null)
            {
                var response = Error(HttpStatusCode.Unauthorized);
                response.Headers.WwwAuthenticate.Add(new("Bearer", "realm=\"https://auth.docker.io/token\""));
                return response;
            }
            Assert.AreEqual(otherRepository ? "other-token" : "nats-token", request.Headers.Authorization.Parameter);
            return Response(fixture.OldManifest);
        };
        Assert.AreEqual(UpdateStatus.UpToDate, (await fixture.CheckAsync()).Status);
        var container = fixture.Container with { ConfiguredImage = "docker.io/other/app:1" };
        var image = fixture.Image with { RepoDigests = ["docker.io/other/app@" + Digest(fixture.OldManifest)] };
        Assert.AreEqual(UpdateStatus.UpToDate, (await fixture.Checker.CheckAsync(container, image)).Status);
        Assert.HasCount(2, fixture.Requests.Where(r => r.Path == "/token"));
    }

    [TestMethod]
    public async Task ConfigContentMustMatchManifestDescriptorDigest()
    {
        using var fixture = new RegistryFixture();
        fixture.SetTag(fixture.NewManifest);
        fixture.Intercept = request => request.RequestUri!.AbsolutePath.Contains("/blobs/") ? Response(fixture.OldConfig) : null;
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
    }

    [TestMethod]
    public async Task IndexDescriptorMustAgreeWithChildMediaType()
    {
        using var fixture = new RegistryFixture();
        fixture.SetTag(Index(Descriptor(fixture.NewManifest, mediaType: DockerManifest)));
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
    }

    [TestMethod]
    public async Task PlatformConstraintsMissingFromInventory_AreUnknown()
    {
        using var fixture = new RegistryFixture();
        byte[] index = Bytes(System.Text.Encoding.UTF8.GetString(Index(Descriptor(fixture.NewManifest)))
            .Replace("\"architecture\":\"amd64\"", "\"architecture\":\"amd64\",\"os.version\":\"unrecorded\""));
        fixture.SetTag(index);
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
    }

    [TestMethod]
    public async Task DeeplyNestedIndexes_AreBounded()
    {
        using var fixture = new RegistryFixture();
        byte[] child = fixture.NewManifest;
        string childType = OciManifest;
        for (int i = 0; i < 6; i++)
        {
            child = Index(Descriptor(child, mediaType: childType));
            childType = OciIndex;
            fixture.AddManifest(child);
        }
        fixture.SetTag(child);
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
        Assert.IsLessThanOrEqualTo(7, fixture.Requests.Count);
    }
}
