namespace HappyDocker.Tests;

[TestClass]
public sealed class ImageReferenceTests
{
    private static readonly string Digest = "sha256:" + new string('a', 64);
    private static readonly string OtherDigest = "sha256:" + new string('b', 64);

    [TestMethod]
    [DataRow("ubuntu", "docker.io", "library/ubuntu", "latest", false)]
    [DataRow("ubuntu:24.04", "docker.io", "library/ubuntu", "24.04", false)]
    [DataRow("library/nats:2.14.8-alpine", "docker.io", "library/nats", "2.14.8-alpine", false)]
    [DataRow("team/app", "docker.io", "team/app", "latest", false)]
    [DataRow("registry/app", "docker.io", "registry/app", "latest", false)]
    [DataRow("app:5000", "docker.io", "library/app", "5000", false)]
    [DataRow("docker.io/ubuntu", "docker.io", "library/ubuntu", "latest", true)]
    [DataRow("index.docker.io/ubuntu:edge", "docker.io", "library/ubuntu", "edge", true)]
    [DataRow("DOCKER.IO/team/app:RC1", "docker.io", "team/app", "RC1", true)]
    [DataRow("ghcr.io/org/name:tag", "ghcr.io", "org/name", "tag", true)]
    [DataRow("GHCR.IO/org/name", "ghcr.io", "org/name", "latest", true)]
    [DataRow("example.com/app", "example.com", "app", "latest", true)]
    [DataRow("registry.example.com:5000/team/app:v1", "registry.example.com:5000", "team/app", "v1", true)]
    [DataRow("registry:5000/app", "registry:5000", "app", "latest", true)]
    [DataRow("Registry/app", "Registry", "app", "latest", true)]
    [DataRow("localhost/app:dev", "localhost", "app", "dev", true)]
    [DataRow("localhost:5000/app", "localhost:5000", "app", "latest", true)]
    [DataRow("127.0.0.1:5000/app:v2", "127.0.0.1:5000", "app", "v2", true)]
    [DataRow("[::1]:5000/team/app:v2", "[::1]:5000", "team/app", "v2", true)]
    [DataRow("team/a__b/c---d:v1_RC.2", "docker.io", "team/a__b/c---d", "v1_RC.2", false)]
    [DataRow("example.com", "docker.io", "library/example.com", "latest", false)]
    public void Parse_NamedReference_NormalizesWithoutChangingOriginal(
        string original, string registry, string repository, string tag, bool explicitRegistry)
    {
        ImageReference parsed = ImageReference.Parse(original);
        Assert.AreEqual(original, parsed.Original);
        Assert.AreEqual(registry, parsed.Registry);
        Assert.AreEqual(repository, parsed.Repository);
        Assert.AreEqual(tag, parsed.Tag);
        Assert.IsNull(parsed.Digest);
        Assert.IsFalse(parsed.IsDigestPinned);
        Assert.AreEqual(explicitRegistry, parsed.HasExplicitRegistry);
        Assert.AreEqual(explicitRegistry ? ImageReferenceKind.RegistryBacked : ImageReferenceKind.Ambiguous, parsed.Kind);
        Assert.AreEqual($"{registry}/{repository}:{tag}", parsed.Normalized);
        Assert.AreEqual(parsed.Normalized, ImageReference.Parse(parsed.Normalized).Normalized);
    }

    [TestMethod]
    [DataRow("ubuntu", null)]
    [DataRow("ubuntu", "24.04")]
    [DataRow("ghcr.io/org/app", null)]
    [DataRow("localhost:5000/team/app", "RC1")]
    public void Parse_DigestPinned_PreservesExplicitTagAndDoesNotDefaultTag(string name, string? tag)
    {
        string original = name + (tag is null ? "" : $":{tag}") + "@" + Digest;
        ImageReference parsed = ImageReference.Parse(original);
        Assert.AreEqual(original, parsed.Original);
        Assert.AreEqual(Digest, parsed.Digest);
        Assert.AreEqual(tag, parsed.Tag);
        Assert.IsTrue(parsed.IsDigestPinned);
        Assert.AreEqual(ImageReferenceKind.RegistryBacked, parsed.Kind);
        Assert.EndsWith("@" + Digest, parsed.Normalized!);
        Assert.AreEqual(parsed.Normalized, ImageReference.Parse(parsed.Normalized).Normalized);
    }

    [TestMethod]
    [DataRow("sha256", 64)]
    [DataRow("sha384", 96)]
    [DataRow("sha512", 128)]
    public void Parse_SupportedDigests_ValidatesLength(string algorithm, int length)
    {
        string digest = algorithm + ":" + new string('a', length);
        Assert.AreEqual(ImageReferenceKind.RegistryBacked, ImageReference.Parse("app@" + digest).Kind);
        Assert.AreEqual(ImageReferenceKind.Invalid, ImageReference.Parse("app@" + digest + "a").Kind);
        Assert.AreEqual(ImageReferenceKind.Invalid, ImageReference.Parse("app@" + digest[..^1]).Kind);
    }

    [TestMethod]
    [DataRow("https://ghcr.io/org/app")]
    [DataRow("ubuntu:")]
    [DataRow("ubuntu@")]
    [DataRow("ubuntu@sha256:abc")]
    [DataRow("ubuntu@unknown:abcdef")]
    [DataRow("ubuntu@@sha256:abc")]
    [DataRow("Ubuntu")]
    [DataRow("team/App")]
    [DataRow("ghcr.io/Org/app")]
    [DataRow("ghcr.io/")]
    [DataRow("/ubuntu")]
    [DataRow("team//app")]
    [DataRow("team/app/")]
    [DataRow("app:bad:tag")]
    [DataRow("app:-tag")]
    [DataRow("app:tag+build")]
    [DataRow("app:é")]
    [DataRow("app___name")]
    [DataRow("app..name")]
    [DataRow("-app")]
    [DataRow("app.")]
    [DataRow("registry:port/app")]
    [DataRow("bad_host:5000/app")]
    [DataRow("user:password@host/app")]
    [DataRow("ubuntu ")]
    [DataRow(" ubuntu")]
    [DataRow("ubuntu\n")]
    public void Parse_InvalidReference_PreservesOriginalAndDoesNotGuess(string original)
    {
        ImageReference parsed = ImageReference.Parse(original);
        Assert.AreEqual(ImageReferenceKind.Invalid, parsed.Kind);
        Assert.AreEqual(original, parsed.Original);
        Assert.IsNull(parsed.Normalized);
        Assert.IsFalse(parsed.IsDigestPinned);
    }

    [TestMethod]
    [DataRow(null)]
    [DataRow("")]
    [DataRow("  ")]
    public void Parse_MissingReference_IsExplicit(string? original)
    {
        ImageReference parsed = ImageReference.Parse(original);
        Assert.AreEqual(ImageReferenceKind.Missing, parsed.Kind);
        Assert.AreEqual(original, parsed.Original);
        Assert.IsNull(parsed.Normalized);
    }

    [TestMethod]
    public void Parse_LengthLimitsAndDigestEncoding_AreEnforced()
    {
        Assert.AreEqual(ImageReferenceKind.Ambiguous, ImageReference.Parse("app:" + new string('a', 128)).Kind);
        Assert.AreEqual(ImageReferenceKind.Invalid, ImageReference.Parse("app:" + new string('a', 129)).Kind);
        Assert.AreEqual(ImageReferenceKind.Invalid, ImageReference.Parse(new string('a', 256)).Kind);
        Assert.AreEqual(ImageReferenceKind.Invalid, ImageReference.Parse("app@" + Digest.ToUpperInvariant()).Kind);
        Assert.AreEqual(ImageReferenceKind.Invalid, ImageReference.Parse("app@sha256:" + new string('z', 64)).Kind);
    }

    [TestMethod]
    public void Parse_ContentIds_DoNotAcquireRepositoryFromMetadata()
    {
        foreach (string id in new[] { Digest, new string('a', 64) })
        {
            ImageReference parsed = ImageReference.Parse(id).WithMetadata(new(RepoDigests: ["ubuntu@" + Digest]));
            Assert.AreEqual(ImageReferenceKind.LocalImageId, parsed.Kind);
            Assert.IsNull(parsed.Normalized);
            Assert.AreEqual(id, parsed.Original);
        }
        Assert.AreEqual(ImageReferenceKind.Ambiguous,
            ImageReference.Parse("abc123").WithMetadata(new(RepoDigests: ["ubuntu@" + Digest])).Kind);
        Assert.AreEqual(ImageReferenceKind.Ambiguous, ImageReference.Parse("abcdef123456").Kind);
    }

    [TestMethod]
    public void WithMetadata_MatchingRepositoryDigestAlone_DoesNotProveOrigin()
    {
        ImageReference parsed = ImageReference.Parse("ubuntu:24.04")
            .WithMetadata(new(RepoDigests: [null, "invalid@digest", "index.docker.io/library/ubuntu@" + OtherDigest]));
        Assert.AreEqual(ImageReferenceKind.Ambiguous, parsed.Kind);
        Assert.AreEqual("ubuntu:24.04", parsed.Original);
        Assert.AreEqual("24.04", parsed.Tag);
        Assert.IsNull(parsed.Digest); // An image's repo digest does not change its configured pin.
        Assert.IsFalse(parsed.IsDigestPinned);
    }

    [TestMethod]
    public void WithMetadata_MissingMalformedOrUnrelatedDigests_LeaveLocalTagsAmbiguous()
    {
        foreach (string?[]? metadata in new string?[]?[] {
            null, [], [null, "", "<none>@<none>"], ["ubuntu:latest"],
            ["ghcr.io/library/ubuntu@" + Digest], ["docker.io/team/ubuntu@" + Digest] })
        {
            Assert.AreEqual(ImageReferenceKind.Ambiguous,
                ImageReference.Parse("ubuntu").WithMetadata(new(RepoDigests: metadata)).Kind);
        }
    }

    [TestMethod]
    public void WithMetadata_PinnedDigest_StaysPinnedWithoutInferringProvenance()
    {
        ImageReference parsed = ImageReference.Parse("ubuntu@" + Digest);
        ImageReference assessed = parsed.WithMetadata(new(RepoDigests: ["ubuntu@" + Digest]));
        Assert.AreEqual(ImageReferenceKind.Ambiguous, assessed.Kind);
        Assert.IsTrue(assessed.IsDigestPinned);
        Assert.AreEqual(parsed.Normalized, assessed.Normalized);
        Assert.AreEqual(parsed.Original, assessed.Original);
        Assert.AreEqual(Digest, parsed.Digest); // Image config IDs and registry manifest digests are different concepts.
    }
}
