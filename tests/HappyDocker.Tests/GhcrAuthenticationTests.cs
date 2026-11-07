using System.Net;
using System.Text;
using System.Text.Json;
using static HappyDocker.Tests.RegistryFixture;

namespace HappyDocker.Tests;

[TestClass]
public sealed class GhcrAuthenticationTests
{
    private const string User = "fixture-user";
    private const string Pat = "ghp_fixture_only";
    private const string Bearer = "fixture.bearer.secret";
    private const string Realm = "realm=\"https://ghcr.io/token\"";
    private static string Basic => "Basic " + Convert.ToBase64String(Encoding.ASCII.GetBytes($"{User}:{Pat}"));
    private static GhcrCredentials Credentials() => GhcrCredentials.Load(User, null, Pat)!;

    [TestMethod]
    public async Task PublicGhcr_WithCredentials_StillStartsAnonymously()
    {
        using var fixture = new RegistryFixture("ghcr.io", ghcrCredentials: Credentials());
        Assert.AreEqual(UpdateStatus.UpToDate, (await fixture.CheckAsync()).Status);
        Assert.HasCount(2, fixture.Requests);
        Assert.IsTrue(fixture.Requests.All(request => request.Authorization is null));
    }

    [TestMethod]
    public async Task PrivateGhcr_WithoutCredentials_ReportsHowToConfigureThem()
    {
        using var fixture = new RegistryFixture("ghcr.io");
        fixture.Intercept = request => request.RequestUri!.AbsolutePath == "/token"
            ? Error(HttpStatusCode.Forbidden) : Challenge(Realm);
        UpdateResult result = await fixture.CheckAsync();
        Assert.AreEqual(UpdateStatus.AuthenticationRequired, result.Status);
        Assert.Contains("HAPPYDOCKER_GHCR_TOKEN_FILE", result.Reason);
        Assert.HasCount(2, fixture.Requests);
        Assert.IsTrue(fixture.Requests.All(request => request.Authorization is null));
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task PrivateGhcr_AuthenticatesDigestTagAndConfig_IncludingContainerd(bool containerd)
    {
        using var fixture = new RegistryFixture("ghcr.io", "fixture/private", ghcrCredentials: Credentials());
        if (containerd) fixture.UseContainerd(true);
        fixture.SetTag(fixture.NewManifest);
        fixture.Intercept = request =>
        {
            if (request.RequestUri!.AbsolutePath == "/token")
            {
                Assert.AreEqual("https", request.RequestUri.Scheme);
                Assert.AreEqual("ghcr.io", request.RequestUri.Host);
                Assert.AreEqual(443, request.RequestUri.Port);
                Assert.AreEqual("?service=ghcr.io&scope=repository:fixture/private:pull", Uri.UnescapeDataString(request.RequestUri.Query));
                Assert.AreEqual(Basic, request.Headers.Authorization?.ToString());
                return Token(Bearer);
            }
            if (request.Headers.Authorization?.Parameter == Bearer) return null;
            return Challenge(Realm + ",service=\"ghcr.io\",scope=\"repository:fixture/private:pull\"");
        };
        Assert.AreEqual(UpdateStatus.UpdateAvailable, (await fixture.CheckAsync()).Status);
        Assert.AreEqual(UpdateStatus.UpdateAvailable, (await fixture.CheckAsync()).Status);
        Assert.IsNull(fixture.Requests[0].Authorization);
        Assert.HasCount(1, fixture.Requests.Where(request => request.Authorization == Basic));
        Assert.IsTrue(fixture.Requests.Any(request => request.Path.EndsWith("/" + fixture.Tag) && request.Authorization == "Bearer " + Bearer));
        Assert.IsTrue(fixture.Requests.Any(request => request.Path.Contains("/manifests/sha256:") && request.Authorization == "Bearer " + Bearer));
        Assert.IsTrue(fixture.Requests.Any(request => request.Path.Contains("/blobs/") && request.Authorization == "Bearer " + Bearer));
    }

    [TestMethod]
    public async Task PrivateGhcr_SeparatesBearerTokensByRepository()
    {
        using var fixture = new RegistryFixture("ghcr.io", "fixture/first", ghcrCredentials: Credentials());
        fixture.Intercept = request =>
        {
            Uri uri = request.RequestUri!;
            if (uri.AbsolutePath == "/token")
                return Token(Uri.UnescapeDataString(uri.Query).Contains("fixture/first:pull") ? "first-token" : "second-token");
            string expected = uri.AbsolutePath.Contains("/fixture/first/") ? "first-token" : "second-token";
            if (request.Headers.Authorization is null) return Challenge(Realm);
            Assert.AreEqual(expected, request.Headers.Authorization.Parameter);
            return Response(fixture.OldManifest);
        };
        Assert.AreEqual(UpdateStatus.UpToDate, (await fixture.CheckAsync()).Status);
        var container = fixture.Container with { ConfiguredImage = "ghcr.io/fixture/second:latest" };
        var image = fixture.Image with { RepoDigests = ["ghcr.io/fixture/second@" + Digest(fixture.OldManifest)] };
        Assert.AreEqual(UpdateStatus.UpToDate, (await fixture.Checker.CheckAsync(container, image)).Status);
        Assert.HasCount(2, fixture.Requests.Where(request => request.Path == "/token"));
        Assert.IsTrue(fixture.Requests.Any(request => request.Path.Contains("/fixture/second/") && request.Authorization is null));
    }

    [TestMethod]
    [DataRow(401, UpdateStatus.AuthenticationRequired)]
    [DataRow(403, UpdateStatus.AuthenticationRequired)]
    [DataRow(429, UpdateStatus.RegistryUnavailable)]
    [DataRow(503, UpdateStatus.RegistryUnavailable)]
    public async Task TokenEndpointFailures_AreClassifiedAndSanitized(int code, UpdateStatus expected)
    {
        using var fixture = new RegistryFixture("ghcr.io", ghcrCredentials: Credentials());
        fixture.Intercept = request => request.RequestUri!.AbsolutePath == "/token"
            ? new HttpResponseMessage((HttpStatusCode)code) { Content = new StringContent($"{User} {Pat} {Basic} {Bearer}") }
            : Challenge(Realm);
        UpdateResult result = await fixture.CheckAsync();
        Assert.AreEqual(expected, result.Status);
        Assert.HasCount(2, fixture.Requests);
        AssertRedacted(result.Reason);
        if (code is 401 or 403) Assert.Contains("configured credentials", result.Reason);
        if (code == 429)
        {
            Assert.IsNotNull(result.RetryAfter);
            Assert.AreEqual(expected, (await fixture.CheckAsync()).Status);
            Assert.HasCount(2, fixture.Requests);
        }
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task ExpiredCachedBearer_RefreshesOnceAndDoesNotCacheRejectedReplacement(bool rejectReplacement)
    {
        using var fixture = new RegistryFixture("ghcr.io", ghcrCredentials: Credentials());
        int exchanges = 0;
        bool expired = false;
        fixture.Intercept = request =>
        {
            if (request.RequestUri!.AbsolutePath == "/token") return Token(++exchanges == 1 ? "first-token" : Bearer);
            string? token = request.Headers.Authorization?.Parameter;
            if ((!expired && token == "first-token") || (!rejectReplacement && token == Bearer)) return null;
            return Challenge(Realm);
        };
        Assert.AreEqual(UpdateStatus.UpToDate, (await fixture.CheckAsync()).Status);
        expired = true;
        Assert.AreEqual(rejectReplacement ? UpdateStatus.AuthenticationRequired : UpdateStatus.UpToDate, (await fixture.CheckAsync()).Status);
        Assert.AreEqual(2, exchanges);
        if (rejectReplacement)
        {
            int before = fixture.Requests.Count;
            Assert.AreEqual(UpdateStatus.AuthenticationRequired, (await fixture.CheckAsync()).Status);
            Assert.IsNull(fixture.Requests[before].Authorization);
            Assert.AreEqual(3, exchanges);
        }
    }

    [TestMethod]
    [DataRow("realm=\"https://evil.example/token\"")]
    [DataRow("realm=\"http://ghcr.io/token\"")]
    [DataRow("realm=\"https://ghcr.io:443/token\"")]
    [DataRow("realm=\"https://ghcr.io/token?extra=1\"")]
    [DataRow(Realm + ",scope=\"repository:library/nats:pull,push\"")]
    [DataRow(Realm + ",scope=\"repository:other/image:pull\"")]
    [DataRow(Realm + ",service=\"other.example\"")]
    [DataRow(Realm + "," + Realm)]
    public async Task UnsafeChallenge_IsRejectedBeforeAnyCredentialIsSent(string challenge)
    {
        using var fixture = new RegistryFixture("ghcr.io", ghcrCredentials: Credentials());
        fixture.Intercept = _ => Challenge(challenge);
        UpdateResult result = await fixture.CheckAsync();
        Assert.AreEqual(UpdateStatus.AuthenticationRequired, result.Status);
        Assert.Contains("challenge", result.Reason);
        Assert.HasCount(1, fixture.Requests);
        Assert.IsNull(fixture.Requests[0].Authorization);
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task UnexpectedChallengeScheme_IsRejectedWithoutSendingCredentials(bool includeBearer)
    {
        using var fixture = new RegistryFixture("ghcr.io", ghcrCredentials: Credentials());
        fixture.Intercept = _ =>
        {
            var response = includeBearer ? Challenge(Realm) : Error(HttpStatusCode.Unauthorized);
            response.Headers.WwwAuthenticate.Add(new("Basic", "realm=\"unexpected\""));
            return response;
        };
        Assert.AreEqual(UpdateStatus.AuthenticationRequired, (await fixture.CheckAsync()).Status);
        Assert.HasCount(1, fixture.Requests);
        Assert.IsNull(fixture.Requests[0].Authorization);
    }

    [TestMethod]
    [DataRow("https://evil.example/token")]
    [DataRow("https://ghcr.io/other")]
    [DataRow("/token?another=1")]
    public async Task CredentialExchange_RejectsEveryRedirect(string location)
    {
        using var fixture = new RegistryFixture("ghcr.io", ghcrCredentials: Credentials());
        fixture.Intercept = request => request.RequestUri!.AbsolutePath == "/token" ? Redirect(location) : Challenge(Realm);
        UpdateResult result = await fixture.CheckAsync();
        Assert.AreEqual(UpdateStatus.AuthenticationRequired, result.Status);
        Assert.Contains("redirect", result.Reason);
        Assert.HasCount(2, fixture.Requests);
        Assert.AreEqual(Basic, fixture.Requests[1].Authorization);
    }

    [TestMethod]
    public async Task DockerHub_DoesNotReceiveConfiguredGhcrCredentials()
    {
        using var fixture = new RegistryFixture(ghcrCredentials: Credentials());
        fixture.Intercept = request => request.RequestUri!.Host == "auth.docker.io" ? Token(Bearer)
            : request.Headers.Authorization?.Parameter == Bearer ? null
            : Challenge("realm=\"https://auth.docker.io/token\"");
        Assert.AreEqual(UpdateStatus.UpToDate, (await fixture.CheckAsync()).Status);
        Assert.IsTrue(fixture.Requests.All(request => request.Authorization is null or "Bearer " + Bearer));
        Assert.IsTrue(fixture.Requests.All(request => request.Host != "ghcr.io"));
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task CdnReceivesNoAuthorization_AndCannotTriggerCredentialExchange(bool challengeOnCdn)
    {
        using var fixture = new RegistryFixture("ghcr.io", ghcrCredentials: Credentials());
        fixture.SetTag(fixture.NewManifest);
        fixture.Intercept = request =>
        {
            Uri uri = request.RequestUri!;
            if (uri.Host == "pkg-containers.githubusercontent.com")
            {
                Assert.IsNull(request.Headers.Authorization);
                return challengeOnCdn ? Challenge(Realm) : Response(fixture.NewConfig);
            }
            if (uri.AbsolutePath == "/token") return Token(Bearer);
            if (request.Headers.Authorization?.Parameter != Bearer) return Challenge(Realm);
            return uri.AbsolutePath.Contains("/blobs/") ? Redirect("https://pkg-containers.githubusercontent.com/config") : null;
        };
        Assert.AreEqual(challengeOnCdn ? UpdateStatus.AuthenticationRequired : UpdateStatus.UpdateAvailable, (await fixture.CheckAsync()).Status);
        Assert.HasCount(1, fixture.Requests.Where(request => request.Path == "/token"));
        Assert.HasCount(1, fixture.Requests.Where(request => request.Host == "pkg-containers.githubusercontent.com"));
    }

    [TestMethod]
    public async Task CliReport_DoesNotEchoSecretsFromRejectedBearerResponse()
    {
        using var fixture = new RegistryFixture("ghcr.io", ghcrCredentials: Credentials());
        fixture.Intercept = request => request.RequestUri!.AbsolutePath == "/token" ? Token(Bearer)
            : request.Headers.Authorization is null ? Challenge(Realm)
            : new HttpResponseMessage(HttpStatusCode.Forbidden) { Content = new StringContent($"{User} {Pat} {Basic} {Bearer}") };
        var responses = new Queue<DockerCommandResult>([
            new(0, """{"ID":"container","Names":"nats","Image":"nats"}""", ""),
            new(0, JsonSerializer.Serialize(fixture.Container), ""),
            new(0, JsonSerializer.Serialize(fixture.Image), "")
        ]);
        using var output = new StringWriter();
        using var error = new StringWriter();
        Assert.AreEqual(0, await DockerCheck.RunAsync(_ => Task.FromResult(responses.Dequeue()), fixture.Checker, output, error));
        Assert.Contains("Authentication required", output.ToString());
        AssertRedacted(output.ToString() + error.ToString());
        Assert.HasCount(3, fixture.Requests);
    }

    private static HttpResponseMessage Challenge(string parameters)
    {
        var response = Error(HttpStatusCode.Unauthorized);
        response.Headers.WwwAuthenticate.Add(new("Bearer", parameters));
        return response;
    }

    private static HttpResponseMessage Token(string value) => Response(JsonSerializer.SerializeToUtf8Bytes(new { token = value }));

    private static HttpResponseMessage Redirect(string location)
    {
        var response = new HttpResponseMessage(HttpStatusCode.TemporaryRedirect);
        response.Headers.Location = new Uri(location, UriKind.RelativeOrAbsolute);
        return response;
    }

    private static void AssertRedacted(string text)
    {
        Assert.DoesNotContain(User, text);
        Assert.DoesNotContain(Pat, text);
        Assert.DoesNotContain(Basic, text);
        Assert.DoesNotContain(Bearer, text);
    }
}
