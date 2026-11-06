using System.Text.Json;
using static HappyDocker.Tests.RegistryFixture;
using static HappyDocker.Tests.DockerImageIdentityTests;

namespace HappyDocker.Tests;

[TestClass]
public sealed class ContainerdRegistryTests
{
    [TestMethod]
    [DataRow(false, false)]
    [DataRow(false, true)]
    [DataRow(true, false)]
    [DataRow(true, true)]
    public async Task ContainerdIds_AnchorVerifiedIndexOrManifestInsteadOfConfig(bool index, bool changed)
    {
        using var fixture = new RegistryFixture();
        fixture.UseContainerd(index);
        fixture.Container = fixture.Container with { ConfiguredImage = "nats:2.14.3-alpine" };
        if (changed) fixture.SetTag(index ? Index(Descriptor(fixture.NewManifest)) : fixture.NewManifest);
        UpdateResult result = await fixture.CheckAsync();
        Assert.AreEqual(changed ? UpdateStatus.UpdateAvailable : UpdateStatus.UpToDate, result.Status);
        Assert.AreEqual(Digest(fixture.OldManifest), result.DeployedManifest);
        Assert.AreNotEqual(Digest(fixture.OldConfig), fixture.Image.Id);
        Assert.IsTrue(fixture.Requests.Any(r => r.Path.Contains("/blobs/" + Digest(fixture.OldConfig))));
        if (index) Assert.AreNotEqual(fixture.Image.Id, result.DeployedManifest);
        else Assert.AreEqual(fixture.Image.Id, result.DeployedManifest);
    }

    [TestMethod]
    public async Task LegacyConfigurationId_IsVerifiedWithoutClaimingPullProvenance()
    {
        using var fixture = new RegistryFixture();
        fixture.Container = fixture.Container with { ConfiguredImage = "nats:2.14.3-alpine" };
        Assert.IsNull(fixture.Image.Descriptor);
        Assert.IsNull(fixture.Image.Identity);
        Assert.AreEqual(ImageReferenceKind.Ambiguous, ImageReference.Parse(fixture.Container.ConfiguredImage).WithMetadata(fixture.Image).Kind);
        UpdateResult result = await fixture.CheckAsync();
        Assert.AreEqual(UpdateStatus.UpToDate, result.Status);
        Assert.Contains("pull provenance remains unavailable", result.Reason);
        Assert.HasCount(2, fixture.Requests);
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task BuildOnlyIdentity_SkipsEvenRegistryLookingNamesAndSyntheticDigests(bool descriptorPresent)
    {
        using var fixture = new RegistryFixture(repository: "library/joyful-stack-happyqotd");
        if (descriptorPresent) fixture.UseContainerd(true);
        fixture.Image = fixture.Image with { Identity = Json("""{"Build":[{"Ref":"local-build"}]}""") };
        Assert.AreEqual(UpdateStatus.Skipped, (await fixture.CheckAsync()).Status);
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    [DataRow("null")]
    [DataRow("{}")]
    [DataRow("{\"Pull\":[]}")]
    [DataRow("{\"Pull\":[{\"Repository\":\"ghcr.io/other/nats\"}]}")]
    [DataRow("{\"Pull\":[{\"Repository\":\"docker.io/library/nats\"}],\"Build\":[{\"Ref\":\"built\"}]}")]
    [DataRow("{\"Pull\":[{\"Repository\":\"docker.io/library/nats\"}],\"Build\":[null]}")]
    public async Task MissingOrMixedContainerdProvenance_IsUnknownBeforeHttp(string identity)
    {
        using var fixture = new RegistryFixture();
        fixture.UseContainerd(true);
        fixture.Image = fixture.Image with { Identity = Json(identity) };
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    public async Task EmptyIdentityOnLegacyStore_DoesNotTriggerMissingIdentityFallback()
    {
        using var fixture = new RegistryFixture();
        fixture.Image = fixture.Image with { Identity = Json("{}") };
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task PullIdentityAndDescriptor_CanVerifyContentWithoutRepoDigestNames(bool index)
    {
        using var fixture = new RegistryFixture();
        fixture.UseContainerd(index);
        fixture.Image = fixture.Image with { RepoDigests = null };
        Assert.AreEqual(UpdateStatus.UpToDate, (await fixture.CheckAsync()).Status);
    }

    [TestMethod]
    public async Task DescriptorAndRepoDigestMustResolveToSameDeployedPlatform()
    {
        using var fixture = new RegistryFixture();
        fixture.UseContainerd(true);
        fixture.Image = fixture.Image with { RepoDigests = ["docker.io/library/nats@" + Digest(fixture.NewManifest)] };
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
        Assert.IsFalse(fixture.Requests.Any(r => r.Path.EndsWith("/" + fixture.Tag)));
    }

    [TestMethod]
    public async Task DescriptorIndexAndChildRepoDigest_CanDescribeSameDeployedImage()
    {
        using var fixture = new RegistryFixture();
        fixture.UseContainerd(true);
        fixture.Image = fixture.Image with { RepoDigests = ["docker.io/library/nats@" + Digest(fixture.OldManifest)] };
        Assert.AreEqual(UpdateStatus.UpToDate, (await fixture.CheckAsync()).Status);
    }

    [TestMethod]
    [DataRow("{}")]
    [DataRow("\"not a descriptor\"")]
    [DataRow("{\"mediaType\":\"unknown/type\",\"digest\":\"sha256:bad\",\"size\":1}")]
    public async Task InvalidDescriptorDoesNotFallBackToConfigId(string descriptor)
    {
        using var fixture = new RegistryFixture();
        fixture.Image = fixture.Image with
        {
            Descriptor = Json(descriptor), Identity = Json("""{"Pull":[{"Repository":"docker.io/library/nats"}]}""")
        };
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    public async Task IdAndDescriptorDigestMustAgree()
    {
        using var fixture = new RegistryFixture();
        fixture.UseContainerd(true);
        fixture.Image = fixture.Image with { Id = Digest(fixture.OldConfig) };
        fixture.Container = fixture.Container with { ImageId = fixture.Image.Id };
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task IndexSelection_UsesActualContainerPlatformInsteadOfDaemonDefault(bool changed)
    {
        using var fixture = new RegistryFixture();
        fixture.UseContainerd(true);
        byte[] oldArmConfig = Config("arm-old", architecture: "arm64", variant: "v8");
        byte[] newArmConfig = Config("arm-new", architecture: "arm64", variant: "v8");
        byte[] oldArm = Manifest(oldArmConfig), newArm = Manifest(newArmConfig);
        fixture.AddManifest(oldArm); fixture.AddManifest(newArm);
        fixture.AddConfig(oldArmConfig); fixture.AddConfig(newArmConfig);
        byte[] target = Index(Descriptor(fixture.OldManifest), Descriptor(oldArm, architecture: "arm64", variant: "v8"));
        fixture.SetDeployed(target);
        fixture.Image = fixture.Image with { Id = Digest(target), Descriptor = Target(target, OciIndex) };
        fixture.Container = fixture.Container with
        {
            ImageId = fixture.Image.Id, ImageManifestDescriptor = JsonSerializer.SerializeToElement(Descriptor(oldArm, architecture: "arm64", variant: "v8"))
        };
        fixture.SetTag(Index(Descriptor(fixture.NewManifest), Descriptor(changed ? newArm : oldArm, architecture: "arm64", variant: "v8")));
        Assert.AreEqual("amd64", fixture.Image.Architecture); // Daemon default differs from this running container.
        UpdateResult result = await fixture.CheckAsync();
        Assert.AreEqual(changed ? UpdateStatus.UpdateAvailable : UpdateStatus.UpToDate, result.Status);
        Assert.AreEqual(Digest(oldArm), result.DeployedManifest);
        Assert.IsFalse(fixture.Requests.Any(r => r.Path.Contains("/manifests/" + Digest(fixture.OldManifest))));
    }

    [TestMethod]
    public async Task IndexWithoutContainerManifestDescriptor_IsUnknownInsteadOfGuessingPlatform()
    {
        using var fixture = new RegistryFixture();
        fixture.UseContainerd(true);
        fixture.Container = fixture.Container with { ImageManifestDescriptor = null };
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    public async Task IncorrectContainerManifestMatch_IsUnknown()
    {
        using var fixture = new RegistryFixture();
        fixture.UseContainerd(true);
        fixture.Container = fixture.Container with { ImageManifestDescriptor = JsonSerializer.SerializeToElement(Descriptor(fixture.NewManifest)) };
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
        Assert.IsFalse(fixture.Requests.Any(r => r.Path.EndsWith("/" + fixture.Tag)));
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task DescriptorSizeAndMediaType_AreVerifiedAgainstBytes(bool wrongSize)
    {
        using var fixture = new RegistryFixture();
        fixture.UseContainerd(true);
        ImageDescriptor descriptor = DockerImageIdentity.ReadDescriptor(fixture.Image.Descriptor)!;
        fixture.Image = fixture.Image with { Descriptor = JsonSerializer.SerializeToElement(new
        {
            mediaType = wrongSize ? OciIndex : OciManifest, digest = descriptor.Digest, size = wrongSize ? descriptor.Size + 1 : descriptor.Size
        }) };
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
    }

    [TestMethod]
    public async Task ContainerdConfigMustMatchDescriptorDigestAndPlatform()
    {
        using var fixture = new RegistryFixture();
        fixture.UseContainerd(true);
        fixture.Intercept = request => request.RequestUri!.AbsolutePath.Contains("/blobs/") ? Response(fixture.NewConfig) : null;
        Assert.AreEqual(UpdateStatus.Unknown, (await fixture.CheckAsync()).Status);
        Assert.IsFalse(fixture.Requests.Any(r => r.Path.EndsWith("/" + fixture.Tag)));
    }

    [TestMethod]
    public async Task IndexPlatformLabelMustAgreeWithDeployedConfigBytes()
    {
        using var fixture = new RegistryFixture();
        fixture.UseContainerd(true);
        byte[] target = Index(Descriptor(fixture.OldManifest, architecture: "arm64", variant: "v8"));
        fixture.SetDeployed(target);
        fixture.Image = fixture.Image with { Id = Digest(target), Descriptor = Target(target, OciIndex) };
        fixture.Container = fixture.Container with
        {
            ImageId = fixture.Image.Id,
            ImageManifestDescriptor = JsonSerializer.SerializeToElement(Descriptor(fixture.OldManifest, architecture: "arm64", variant: "v8"))
        };
        UpdateResult result = await fixture.CheckAsync();
        Assert.AreEqual(UpdateStatus.Unknown, result.Status);
        Assert.Contains("configuration platform", result.Reason);
        Assert.IsFalse(fixture.Requests.Any(r => r.Path.EndsWith("/" + fixture.Tag)));
    }

    [TestMethod]
    [DataRow("docker.io")]
    [DataRow("ghcr.io")]
    public async Task ContainerdComparisons_StillUseAnonymousBearerAuthentication(string registry)
    {
        using var fixture = new RegistryFixture(registry);
        fixture.UseContainerd(true);
        fixture.SetTag(Index(Descriptor(fixture.NewManifest)));
        fixture.Intercept = request =>
        {
            if (request.RequestUri!.AbsolutePath == "/token") return Response(Bytes("{\"token\":\"anonymous.fixture.token\"}"));
            if (request.Headers.Authorization?.Parameter == "anonymous.fixture.token") return null;
            var response = Error(System.Net.HttpStatusCode.Unauthorized);
            string realm = registry == "docker.io" ? "https://auth.docker.io/token" : "https://ghcr.io/token";
            response.Headers.WwwAuthenticate.Add(new("Bearer", $"realm=\"{realm}\""));
            return response;
        };
        UpdateResult result = await fixture.CheckAsync();
        Assert.AreEqual(UpdateStatus.UpdateAvailable, result.Status);
        Assert.DoesNotContain("anonymous.fixture.token", result.Reason);
        Assert.HasCount(1, fixture.Requests.Where(r => r.Path == "/token"));
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task CheckAndScan_ShowProvenanceAndRetainReadOnlyInventory(bool built)
    {
        using var fixture = new RegistryFixture();
        fixture.UseContainerd(true);
        if (built) fixture.Image = fixture.Image with { Identity = Json("""{"Build":[{"Ref":"private-build-ref"}]}""") };
        using var scan = new StringWriter();
        DockerScan.WriteReport([fixture.Container], [fixture.Image], scan, TextWriter.Null);
        Assert.Contains("Image ID descriptor: ImageIndex", scan.ToString());
        Assert.Contains(built ? "Reference: LocallyBuilt" : "Reference: RegistryBacked", scan.ToString());
        Assert.Contains(fixture.Container.ConfiguredImage!, scan.ToString());
        Assert.DoesNotContain("private-build-ref", scan.ToString());
        var commands = new List<string[]>();
        var responses = new Queue<DockerCommandResult>([
            new(0, """{"ID":"container","Names":"nats","Image":"nats"}""", ""),
            new(0, JsonSerializer.Serialize(fixture.Container), ""),
            new(0, JsonSerializer.Serialize(fixture.Image), "")
        ]);
        using var output = new StringWriter();
        Assert.AreEqual(0, await DockerCheck.RunAsync(args => { commands.Add(args); return Task.FromResult(responses.Dequeue()); },
            fixture.Checker, output, TextWriter.Null));
        Assert.Contains(built ? "Skipped" : "Up to date", output.ToString());
        CollectionAssert.AreEqual(new[] { "ps", "inspect", "image" }, commands.Select(args => args[0]).ToArray());
        if (built) Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task ConflictingInspectionProvenanceOrDescriptors_DoNotFallBackToLegacy(bool conflictIdentity)
    {
        using var fixture = new RegistryFixture();
        fixture.UseContainerd(true);
        DockerImageRow other = conflictIdentity
            ? fixture.Image with { Identity = Json("""{"Build":[{"Ref":"built"}]}""") }
            : fixture.Image with { Descriptor = Target(fixture.OldManifest, OciManifest) };
        var responses = new Queue<DockerCommandResult>([
            new(0, """{"ID":"container","Names":"nats","Image":"nats"}""", ""),
            new(0, JsonSerializer.Serialize(fixture.Container), ""),
            new(0, JsonSerializer.Serialize(fixture.Image) + "\n" + JsonSerializer.Serialize(other), "")
        ]);
        using var output = new StringWriter();
        using var error = new StringWriter();
        Assert.AreEqual(0, await DockerCheck.RunAsync(_ => Task.FromResult(responses.Dequeue()), fixture.Checker, output, error));
        Assert.Contains("Conflicting image metadata", error.ToString());
        Assert.Contains("Unknown / insufficient metadata", output.ToString());
        Assert.IsEmpty(fixture.Requests);
    }

    internal static JsonElement Target(byte[] bytes, string mediaType) => JsonSerializer.SerializeToElement(new
    {
        mediaType, digest = Digest(bytes), size = bytes.Length
    });
}
