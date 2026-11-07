using System.Text.Json;
using static HappyDocker.Tests.TrivyScannerTests;

namespace HappyDocker.Tests;

[TestClass]
public sealed class DockerVulnerabilitiesTests
{
    private static readonly string ArmId = "sha256:" + new string('b', 64);
    private static readonly string IndexId = "sha256:" + new string('c', 64);
    private const string Manifest = "application/vnd.oci.image.manifest.v1+json";
    private const string Index = "application/vnd.oci.image.index.v1+json";
    private const string Database = """{"VulnerabilityDB":{"UpdatedAt":"2026-10-01T01:00:00Z"}}""";
    private const string ClassicDriver = """{"Driver":"overlay2","DriverStatus":[["Backing Filesystem","extfs"]]}""";

    [TestMethod]
    public async Task SharedLegacyImage_ScansOnceAndReportsEveryContainerWithoutClaimingReachability()
    {
        DockerInspectRow[] containers =
        [
            new("first", "/nats", ImageId, "nats:latest", "linux"),
            new("second", "/local", ImageId, "local-build:dev", "linux"),
            new("third", "/pinned", ImageId, "ghcr.io/private/app@" + ImageId, "linux")
        ];
        var commands = new List<string[]>();
        var targets = new List<string>();
        using var output = new StringWriter();
        using var error = new StringWriter();
        int exit = await DockerVulnerabilities.RunAsync(
            Docker(containers, [new(ImageId, "linux", "amd64", Identity: JsonSerializer.SerializeToElement(new { Build = new[] { new { Ref = "local" } } }))], commands),
            Scanner(targets, id => Report(MuslTarget, id)), output, error);

        Assert.AreEqual(0, exit);
        CollectionAssert.AreEqual(new[] { ImageId }, targets);
        Assert.HasCount(4, commands);
        Assert.IsTrue(commands.All(args => args[0] is "ps" or "inspect" or "image" or "info"));
        Assert.AreEqual("inspect", commands.Single(args => args[0] == "image")[1]);
        string report = output.ToString();
        foreach (string expected in new[] { "nats:latest", "local-build:dev", "ghcr.io/private/app@", "HIGH 1", "musl 1.2.5-r0",
                     "fixed in 1.2.5-r1", "2026-10-01T01:00:00", "exploitability require separate analysis" })
            Assert.Contains(expected, report);
        Assert.DoesNotContain("NATS executes", report);
        Assert.IsEmpty(error.ToString());
    }

    [TestMethod]
    public async Task ContainerdIndex_ScansDistinctVerifiedChildrenAndIgnoresParentDefaultArchitecture()
    {
        JsonElement amd = Descriptor(ImageId, Manifest, "amd64");
        JsonElement arm = Descriptor(ArmId, Manifest, "arm64");
        DockerInspectRow[] containers =
        [
            new("amd", "/amd", IndexId, "repo:stable", "linux", amd),
            new("arm", "/arm", IndexId, "repo:stable", "linux", arm),
            new("arm2", "/arm2", IndexId, "repo:stable", "linux", arm)
        ];
        var commands = new List<string[]>();
        var targets = new List<string>();
        using var output = new StringWriter();
        int exit = await DockerVulnerabilities.RunAsync(Docker(containers,
            [new(IndexId, "linux", "amd64", Descriptor: Descriptor(IndexId, Index))], commands,
            new Dictionary<string, DockerImageRow>
            {
                [ImageId] = new(ImageId, "linux", "amd64", Descriptor: amd),
                [ArmId] = new(ArmId, "linux", "arm64", Descriptor: arm)
            }),
            Scanner(targets, id => Report(RecognizedTarget, id, arch: id == ArmId ? "arm64" : "amd64")), output, TextWriter.Null);
        Assert.AreEqual(0, exit);
        CollectionAssert.AreEqual(new[] { ImageId, ArmId }, targets);
        Assert.HasCount(1, commands.Where(args => args[^1] == ArmId));
        Assert.Contains("linux/amd64", output.ToString());
        Assert.Contains("linux/arm64", output.ToString());
        Assert.Contains("no findings reported for recognized packages", output.ToString());
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task ContainerdIndex_UnavailableOrMismatchedChildNeverScansParentOrTag(bool mismatched)
    {
        var child = Descriptor(ArmId, Manifest, "arm64");
        var container = new DockerInspectRow("arm", "/arm", IndexId, "repo:mutable", "linux", child);
        var parent = new DockerImageRow(IndexId, "linux", "amd64", Descriptor: Descriptor(IndexId, Index));
        var children = new Dictionary<string, DockerImageRow>();
        if (mismatched) children[ArmId] = new(ArmId, "linux", "amd64", Descriptor: child);
        var commands = new List<string[]>();
        var targets = new List<string>();
        using var output = new StringWriter();
        Assert.AreEqual(1, await DockerVulnerabilities.RunAsync(Docker([container], [parent], commands, children),
            Scanner(targets, _ => throw new AssertFailedException("Inconclusive target must not reach Trivy.")), output, TextWriter.Null));
        Assert.IsEmpty(targets);
        Assert.IsTrue(commands.All(args => !args.Contains("repo:mutable")));
        Assert.Contains("Scan incomplete", output.ToString());
        Assert.DoesNotContain("no findings", output.ToString());
    }

    [TestMethod]
    public async Task ContainerdManifest_CanScanDirectlyByImmutableId()
    {
        var descriptor = Descriptor(ArmId, Manifest, "arm64");
        var container = new DockerInspectRow("arm", "/arm", ArmId, "local:dev", "linux", descriptor);
        var image = new DockerImageRow(ArmId, "linux", "arm64", Descriptor: descriptor);
        var targets = new List<string>();
        var commands = new List<string[]>();
        Assert.AreEqual(0, await DockerVulnerabilities.RunAsync(Docker([container], [image], commands),
            Scanner(targets, id => Report(RecognizedTarget, id, arch: "arm64")), TextWriter.Null, TextWriter.Null));
        CollectionAssert.AreEqual(new[] { ArmId }, targets);
        Assert.HasCount(4, commands);
    }

    [TestMethod]
    public async Task DescriptorlessContainerd_DoesNotAssumeParentIdIsLegacyConfiguration()
    {
        var container = new DockerInspectRow("arm", "/arm", IndexId, "repo:stable", "linux");
        var parent = new DockerImageRow(IndexId, "linux", "amd64");
        var targets = new List<string>();
        Assert.AreEqual(1, await DockerVulnerabilities.RunAsync(
            Docker([container], [parent], [], driverInfo: """{"Driver":"overlayfs","DriverStatus":[["driver-type","io.containerd.snapshotter.v1"]]}"""),
            Scanner(targets, _ => throw new AssertFailedException("Image identity was not established.")), TextWriter.Null, TextWriter.Null));
        Assert.IsEmpty(targets);
    }

    [TestMethod]
    [DataRow("""{"Driver":"overlay2"}""")]
    [DataRow("""{"Driver":"overlay2","DriverStatus":null}""")]
    [DataRow("""{"Driver":"overlay2","DriverStatus":[]}""")]
    [DataRow("""{"Driver":"overlay2","DriverStatus":[["malformed"]]}""")]
    [DataRow("""{"Driver":"overlay2","DriverStatus":[["Other","value"]]}""")]
    [DataRow("""{"Driver":"other","DriverStatus":[["Backing Filesystem","extfs"]]}""")]
    [DataRow("""{"DriverStatus":[["Backing Filesystem","extfs"]]}""")]
    [DataRow("""{"Driver":"overlay2","DriverStatus":[["Backing Filesystem","extfs"],["DRIVER-TYPE","unexpected"]]}""")]
    [DataRow("""{"Driver":"overlay2","DriverStatus":[["driver-type","io.containerd.snapshotter.v1"],["driver-type","unexpected"]]}""")]
    [DataRow("invalid JSON")]
    public async Task UnrecognizedDriverEvidence_FailsClosed(string driverInfo)
    {
        var container = new DockerInspectRow("one", "/one", ImageId, "local:dev", "linux");
        var scanner = new TrivyScanner((_, _, _, _, _) => throw new AssertFailedException("Store is unknown."));
        using var output = new StringWriter();
        Assert.AreEqual(1, await DockerVulnerabilities.RunAsync(
            Docker([container], [new(ImageId, "linux", "amd64")], [], driverInfo: driverInfo),
            scanner, output, TextWriter.Null));
        Assert.Contains("image store is unknown", output.ToString());
    }

    [TestMethod]
    public async Task ManifestWithoutLocalFilesystemMetadata_IsIncomplete()
    {
        var descriptor = Descriptor(ArmId, Manifest, "arm64");
        var container = new DockerInspectRow("arm", "/arm", ArmId, "local:dev", "linux", descriptor);
        var image = new DockerImageRow(ArmId, "linux", "arm64", Descriptor: descriptor);
        var scanner = new TrivyScanner((_, _, _, _, _) => throw new AssertFailedException("Layer evidence is missing."));
        using var output = new StringWriter();
        Assert.AreEqual(1, await DockerVulnerabilities.RunAsync(
            Docker([container], [image], [], includeRootFs: false), scanner, output, TextWriter.Null));
        Assert.Contains("filesystem layer metadata", output.ToString());
    }

    [TestMethod]
    public async Task ScannerFailure_ExitsNonzeroAndNeverReportsNoFindings()
    {
        var container = new DockerInspectRow("one", "/one", ImageId, "local:dev", "linux");
        var scanner = new TrivyScanner((_, _, _, _, _) => Task.FromResult(new ProcessCaptureResult(ProcessOutcome.Missing)));
        using var output = new StringWriter();
        Assert.AreEqual(1, await DockerVulnerabilities.RunAsync(
            Docker([container], [new(ImageId, "linux", "amd64")], []), scanner, output, TextWriter.Null));
        Assert.Contains("Trivy was not found", output.ToString());
        Assert.DoesNotContain("no findings", output.ToString());
    }

    [TestMethod]
    public async Task EmptyInventory_DoesNotInvokeScanner()
    {
        var scanner = new TrivyScanner((_, _, _, _, _) => throw new AssertFailedException("No images to scan."));
        using var output = new StringWriter();
        Assert.AreEqual(0, await DockerVulnerabilities.RunAsync(_ => Task.FromResult(new DockerCommandResult(0, "", "")),
            scanner, output, TextWriter.Null));
        Assert.Contains("No running containers found", output.ToString());
    }

    private static TrivyScanner Scanner(List<string> targets, Func<string, string> report) => new((info, _, _, _, _) =>
    {
        if (info.ArgumentList[0] == "version") return Task.FromResult(new ProcessCaptureResult(ProcessOutcome.Exited, 0, Database));
        string target = info.ArgumentList[^1];
        targets.Add(target);
        return Task.FromResult(new ProcessCaptureResult(ProcessOutcome.Exited, 0, report(target)));
    });

    private static Func<string[], Task<DockerCommandResult>> Docker(DockerInspectRow[] containers, DockerImageRow[] images,
        List<string[]> commands, Dictionary<string, DockerImageRow>? children = null, string driverInfo = ClassicDriver, bool includeRootFs = true)
    {
        return args =>
        {
            commands.Add(args);
            DockerCommandResult result = args[0] switch
            {
                "ps" => new(0, Lines(containers.Select(c => new { ID = c.Id, Names = c.Name, Image = c.ConfiguredImage })), ""),
                "inspect" => new(0, Lines(containers), ""),
                "info" => new(0, driverInfo, ""),
                "image" when args[1] == "inspect" && commands.Count == 3 => new(0, Lines(images), ""),
                "image" when args[1] == "inspect" => InspectManifest(args[^1]),
                _ => throw new AssertFailedException("Unexpected Docker command.")
            };
            return Task.FromResult(result);
        };

        DockerCommandResult InspectManifest(string id)
        {
            DockerImageRow? image = children?.GetValueOrDefault(id) ?? images.SingleOrDefault(row => row.Id == id);
            return image is null ? new(1, "", "No such image") : new(0, JsonSerializer.Serialize(new
            {
                image.Id, image.Os, image.Architecture, image.Variant, image.Descriptor,
                RootFS = includeRootFs ? new { Type = "layers", Layers = new[] { LayerId } } : null
            }), "");
        }
    }

    private static string Lines<T>(IEnumerable<T> rows) => string.Join('\n', rows.Select(row => JsonSerializer.Serialize(row)));

    private static JsonElement Descriptor(string id, string type, string? architecture = null) => JsonSerializer.SerializeToElement(new
    {
        digest = id, mediaType = type, size = 100, platform = architecture is null ? null : new { os = "linux", architecture }
    });
}
