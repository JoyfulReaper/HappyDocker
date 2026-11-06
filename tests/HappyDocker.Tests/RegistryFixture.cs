using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HappyDocker.Tests;

internal sealed class FakeRegistryHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> send)
    : HttpMessageHandler
{
    protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        => send(request, cancellationToken);
}

internal sealed record ObservedRequest(string Host, string Path, string Query, string? Authorization);

internal sealed class RegistryFixture : IDisposable
{
    internal const string OciManifest = "application/vnd.oci.image.manifest.v1+json";
    internal const string DockerManifest = "application/vnd.docker.distribution.manifest.v2+json";
    internal const string OciIndex = "application/vnd.oci.image.index.v1+json";
    internal const string DockerIndex = "application/vnd.docker.distribution.manifest.list.v2+json";
    internal string Registry { get; }
    internal string Repository { get; }
    internal string Host => Registry == "docker.io" ? "registry-1.docker.io" : "ghcr.io";
    internal string Tag { get; }
    internal RegistryClient Client { get; }
    internal RegistryUpdateChecker Checker { get; }
    internal byte[] OldConfig { get; } = Config("old");
    internal byte[] NewConfig { get; } = Config("new");
    internal byte[] OldManifest { get; }
    internal byte[] NewManifest { get; }
    internal DockerInspectRow Container { get; set; }
    internal DockerImageRow Image { get; set; }
    internal List<ObservedRequest> Requests { get; } = [];
    internal Func<HttpRequestMessage, HttpResponseMessage?>? Intercept { get; set; }
    private readonly Dictionary<string, byte[]> routes = new(StringComparer.Ordinal);

    internal RegistryFixture(string registry = "docker.io", string repository = "library/nats", string tag = "2.14.3-alpine")
    {
        Registry = registry; Repository = repository; Tag = tag;
        OldManifest = Manifest(OldConfig);
        NewManifest = Manifest(NewConfig);
        Container = new("container", "/nats", Digest(OldConfig), $"{registry}/{repository}:{tag}", "linux");
        Image = new(Digest(OldConfig), "linux", "amd64", null, [$"{registry}/{repository}@{Digest(OldManifest)}"]);
        AddManifest(OldManifest);
        AddManifest(NewManifest);
        AddConfig(OldConfig);
        AddConfig(NewConfig);
        SetTag(OldManifest);
        Client = new RegistryClient(new FakeRegistryHandler((request, _) =>
        {
            Assert.AreEqual(HttpMethod.Get, request.Method);
            var uri = request.RequestUri!;
            Requests.Add(new(uri.Host, Uri.UnescapeDataString(uri.AbsolutePath), uri.Query, request.Headers.Authorization?.ToString()));
            return Task.FromResult(Intercept?.Invoke(request) ?? Respond(request));
        }));
        Checker = new(Client);
    }

    internal Task<UpdateResult> CheckAsync() => Checker.CheckAsync(Container, Image);
    internal void SetTag(byte[] bytes, string? tag = null) => routes[$"/v2/{Repository}/manifests/{tag ?? Tag}"] = bytes;
    internal string AddManifest(byte[] bytes)
    {
        string digest = Digest(bytes);
        routes[$"/v2/{Repository}/manifests/{digest}"] = bytes;
        return digest;
    }
    internal void AddConfig(byte[] bytes) => routes[$"/v2/{Repository}/blobs/{Digest(bytes)}"] = bytes;
    internal void SetDeployed(byte[] bytes) => Image = Image with { RepoDigests = [$"{Registry}/{Repository}@{AddManifest(bytes)}"] };
    internal void UseContainerd(bool index)
    {
        byte[] target = index ? Index(Descriptor(OldManifest)) : OldManifest;
        SetDeployed(target);
        Image = Image with
        {
            Id = Digest(target),
            Descriptor = JsonSerializer.SerializeToElement(new
            {
                mediaType = index ? OciIndex : OciManifest, digest = Digest(target), size = target.Length
            }),
            Identity = JsonSerializer.SerializeToElement(new { Pull = new[] { new { Repository = $"{Registry}/{Repository}" } } })
        };
        Container = Container with { ImageId = Image.Id, ImageManifestDescriptor = JsonSerializer.SerializeToElement(Descriptor(OldManifest)) };
        SetTag(target);
    }
    internal HttpResponseMessage Respond(HttpRequestMessage request)
    {
        Assert.AreEqual(Host, request.RequestUri!.Host, "Unexpected registry host");
        string path = Uri.UnescapeDataString(request.RequestUri.AbsolutePath);
        Assert.IsTrue(routes.TryGetValue(path, out byte[]? bytes), $"Unexpected registry path {path}");
        return Response(bytes!);
    }

    internal static HttpResponseMessage Response(byte[] bytes)
    {
        var response = new HttpResponseMessage(HttpStatusCode.OK) { Content = new ByteArrayContent(bytes) };
        response.Headers.Add("Docker-Content-Digest", Digest(bytes));
        return response;
    }
    internal static HttpResponseMessage Error(HttpStatusCode status) =>
        new(status) { Content = new StringContent("sensitive registry error; must not appear in a report") };
    internal static byte[] Config(string label, string os = "linux", string architecture = "amd64", string? variant = null) =>
        JsonSerializer.SerializeToUtf8Bytes(new { os, architecture, variant,
            rootfs = new { type = "layers", diff_ids = Array.Empty<string>() }, config = new { Labels = new { label } } },
            new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });
    internal static byte[] Manifest(byte[] config, string mediaType = OciManifest, string label = "") =>
        JsonSerializer.SerializeToUtf8Bytes(new
        {
            schemaVersion = 2, mediaType,
            config = new { mediaType = "application/vnd.oci.image.config.v1+json", digest = Digest(config), size = config.Length },
            layers = Array.Empty<object>(), annotations = new { label }
        });
    internal static object Descriptor(byte[] manifest, string os = "linux", string architecture = "amd64", string? variant = null,
        string mediaType = OciManifest) => new
        {
            mediaType, digest = Digest(manifest), size = manifest.Length,
            platform = new { os, architecture, variant }
        };
    internal static byte[] Index(params object[] descriptors) =>
        JsonSerializer.SerializeToUtf8Bytes(new { schemaVersion = 2, mediaType = OciIndex, manifests = descriptors },
            new JsonSerializerOptions { DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull });
    internal static string Digest(byte[] bytes) => "sha256:" + Convert.ToHexStringLower(SHA256.HashData(bytes));
    internal static byte[] Bytes(string text) => Encoding.UTF8.GetBytes(text);
    public void Dispose() => Client.Dispose();
}
