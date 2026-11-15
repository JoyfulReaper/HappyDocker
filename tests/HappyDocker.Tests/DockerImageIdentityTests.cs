using System.Text.Json;
using static HappyDocker.Tests.RegistryFixture;

namespace HappyDocker.Tests;

[TestClass]
public sealed class DockerImageIdentityTests
{
    [TestMethod]
    public void ClankerPulledNatsMetadata_IsCapturedAsPullEvidence()
    {
        // Exact observed digest and identity. The descriptor fragment omits size, which was not supplied.
        const string inspect = """
            {"Id":"sha256:fce5fbf8b29ee0baa790e67bcd4abafebdd97363aa025f7d46a17489df002e30",
             "Descriptor":{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"sha256:fce5fbf8b29ee0baa790e67bcd4abafebdd97363aa025f7d46a17489df002e30"},
             "Identity":{"Pull":[{"Repository":"docker.io/library/nats"}]}}
            """;
        DockerImageRow image = DockerJsonLines.Parse<DockerImageRow>(inspect.ReplaceLineEndings("")).Single();
        Assert.AreEqual(image.Id, image.Descriptor!.Value.GetProperty("digest").GetString());
        ImageReference reference = ImageReference.Parse("nats:2.14.8-alpine").WithMetadata(image);
        Assert.AreEqual(ImageReferenceKind.RegistryBacked, reference.Kind);
        Assert.AreEqual("nats:2.14.8-alpine", reference.Original);
        Assert.IsNull(DockerImageIdentity.ReadDescriptor(image.Descriptor)); // Missing size must not become a verified descriptor.
    }

    [TestMethod]
    [DataRow("joyful-stack-happyqotd")]
    [DataRow("docker.io/library/joyful-stack-happyqotd:latest")]
    public void ClankerBuildIdentity_SyntheticRepoDigestsDoNotProveRegistryOrigin(string configured)
    {
        const string identity = """
            {"Build":[{"Ref":"zo7pyu1ddnt62xbqiduq7nqut","CreatedAt":"2026-09-28T13:30:16.381468726-04:00"}]}
            """;
        var image = new DockerImageRow(RepoDigests: ["joyful-stack-happyqotd@sha256:" + new string('a', 64)], Identity: Json(identity));
        ImageReference reference = ImageReference.Parse(configured).WithMetadata(image);
        Assert.AreEqual(ImageReferenceKind.LocallyBuilt, reference.Kind);
        Assert.DoesNotContain("zo7pyu1", reference.Reason);
        Assert.AreEqual(ImageProvenanceKind.BuildOnly, DockerImageIdentity.Provenance(reference, image).Kind);
    }

    [TestMethod]
    [DataRow("application/vnd.oci.image.index.v1+json", ImageDigestKind.ImageIndex)]
    [DataRow("application/vnd.docker.distribution.manifest.list.v2+json", ImageDigestKind.ImageIndex)]
    [DataRow("application/vnd.oci.image.manifest.v1+json", ImageDigestKind.PlatformManifest)]
    [DataRow("application/vnd.docker.distribution.manifest.v2+json", ImageDigestKind.PlatformManifest)]
    [DataRow("application/vnd.oci.image.config.v1+json", ImageDigestKind.Configuration)]
    [DataRow("application/vnd.docker.container.image.v1+json", ImageDigestKind.Configuration)]
    public void DescriptorMediaType_DistinguishesDigestRoles(string mediaType, ImageDigestKind kind)
    {
        byte[] bytes = Bytes("descriptor test bytes");
        ImageDescriptor? descriptor = DockerImageIdentity.ReadDescriptor(JsonSerializer.SerializeToElement(new
        {
            mediaType, digest = Digest(bytes), size = bytes.Length
        }));
        Assert.IsNotNull(descriptor);
        Assert.AreEqual(kind, descriptor.Kind);
        Assert.AreEqual(Digest(bytes), descriptor.Digest);
        Assert.AreEqual(bytes.Length, descriptor.Size);
    }

    [TestMethod]
    [DataRow("{}")]
    [DataRow("[]")]
    [DataRow("{\"Pull\":[]}")]
    [DataRow("{\"Pull\":{\"Repository\":\"docker.io/library/nats\"}}")]
    [DataRow("{\"Pull\":[null]}")]
    [DataRow("{\"Pull\":[{}]}")]
    [DataRow("{\"Pull\":[{\"Repository\":\"nats\"}]}")]
    [DataRow("{\"Pull\":[{\"Repository\":\"docker.io/library/nats:latest\"}]}")]
    [DataRow("{\"Pull\":[{\"Repository\":\"ghcr.io/other/nats\"}]}")]
    [DataRow("{\"Pull\":[{\"Repository\":\"docker.io/library/nats\"},{}]}")]
    [DataRow("{\"Pull\":[{\"Repository\":\"docker.io/library/nats\"}],\"Pull\":[]}")]
    [DataRow("{\"Pull\":[{\"Repository\":\"docker.io/library/nats\"}],\"Import\":[{}]}")]
    public void InconsistentOrMissingPullRecords_DoNotPromoteReferences(string identity)
    {
        var image = new DockerImageRow(Identity: Json(identity));
        ImageReference reference = ImageReference.Parse("nats").WithMetadata(image);
        Assert.AreEqual(ImageReferenceKind.Ambiguous, reference.Kind);
        Assert.AreEqual(ImageProvenanceKind.Unknown, DockerImageIdentity.Provenance(reference, image).Kind);
    }

    [TestMethod]
    public void PullRepositories_AreNormalizedAndCanContainMultipleAliases()
    {
        var image = new DockerImageRow(Identity: Json("""
            {"Pull":[{"Repository":"ghcr.io/other/nats"},{"Repository":"index.docker.io/library/nats"}],"Build":[]}
            """));
        Assert.AreEqual(ImageReferenceKind.RegistryBacked, ImageReference.Parse("nats:2").WithMetadata(image).Kind);
        Assert.AreEqual(ImageReferenceKind.Ambiguous, ImageReference.Parse("redis:7").WithMetadata(image).Kind);
    }

    [TestMethod]
    public void OptionalInspectionFields_AreAbsentOrNullOnOlderDocker()
    {
        var rows = DockerJsonLines.Parse<DockerImageRow>("""
            {"Id":"sha256:abc","Os":"linux","Architecture":"amd64"}
            {"Id":"sha256:def","Descriptor":null,"Identity":null}
            """);
        Assert.IsNull(rows[0].Descriptor);
        Assert.IsNull(rows[0].Identity);
        foreach (var image in rows)
        {
            Assert.AreEqual(ImageProvenanceKind.Missing, DockerImageIdentity.Provenance(ImageReference.Parse("nats"), image).Kind);
            Assert.IsNull(DockerImageIdentity.ReadDescriptor(image.Descriptor));
        }
    }

    internal static JsonElement Json(string json) => JsonSerializer.Deserialize<JsonElement>(json);
}
