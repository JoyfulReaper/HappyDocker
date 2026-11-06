namespace HappyDocker.Tests;

[TestClass]
public sealed class DockerScanTests
{
    private static readonly string Digest = "sha256:" + new string('a', 64);
    private const string Ps = """{"ID":"c1","Names":"app","Image":"ubuntu"}""";

    [TestMethod]
    public async Task RunAsync_SharedImage_UsesOnlyReadOnlyCommandsAndPreservesReport()
    {
        var commands = new List<string[]>();
        var results = new Queue<DockerCommandResult>([
            new(0, Ps + "\n" + Ps.Replace("c1", "c2"), ""),
            new(0, """
                {"Id":"c1","Name":"/app","ImageId":"sha256:123","ConfiguredImage":"ubuntu:24.04","Platform":"linux"}
                {"Id":"c2","Name":"/other","ImageId":"sha256:123","ConfiguredImage":"ghcr.io/org/app:RC1","Platform":"linux"}
                """, ""),
            new(0, $$"""{"Id":"sha256:123","Os":"linux","Architecture":"arm64","Variant":"v8","RepoDigests":["ubuntu@{{Digest}}"]}""", "")
        ]);
        using var output = new StringWriter();
        using var error = new StringWriter();
        int exit = await DockerScan.RunAsync(args => { commands.Add(args); return Task.FromResult(results.Dequeue()); }, output, error);

        Assert.AreEqual(0, exit);
        Assert.AreEqual("", error.ToString());
        Assert.HasCount(3, commands);
        CollectionAssert.AreEqual(new[] { "ps", "--format", "{{json .}}" }, commands[0]);
        CollectionAssert.AreEqual(new[] { "inspect", "--type", "container", "--format" }, commands[1][..4]);
        CollectionAssert.AreEqual(new[] { "c1", "c2" }, commands[1][5..]);
        CollectionAssert.AreEqual(new[] { "image", "inspect", "--format" }, commands[2][..3]);
        CollectionAssert.AreEqual(new[] { "sha256:123" }, commands[2][4..]);
        string report = output.ToString();
        foreach (string expected in new[] { "CONTAINER", "PLATFORM", "IMAGE ID", "app", "other", "linux/arm64/v8",
            "ubuntu:24.04", "ghcr.io/org/app:RC1", "sha256:123", "Repository digests: ubuntu@" + Digest,
            "Reference: RegistryBacked", "docker.io/library/ubuntu:24.04" })
            Assert.Contains(expected, report);
        Assert.IsEmpty(results);
    }

    [TestMethod]
    public async Task RunAsync_NoContainers_DoesNotInspect()
    {
        int calls = 0;
        using var output = new StringWriter();
        int exit = await DockerScan.RunAsync(_ => { calls++; return Task.FromResult(new DockerCommandResult(0, "\n", "")); }, output, TextWriter.Null);
        Assert.AreEqual(0, exit);
        Assert.AreEqual(1, calls);
        Assert.AreEqual("No running containers found." + Environment.NewLine, output.ToString());
    }

    [TestMethod]
    [DataRow(0)]
    [DataRow(1)]
    public async Task RunAsync_CommandFailure_PreservesExitCodeAndError(int failedCommand)
    {
        var results = new Queue<DockerCommandResult>(failedCommand == 0
            ? [new(17, "", "daemon unavailable")]
            : [new(0, Ps, ""), new(17, "", "container disappeared")]);
        using var output = new StringWriter();
        using var error = new StringWriter();
        int exit = await DockerScan.RunAsync(_ => Task.FromResult(results.Dequeue()), output, error);
        Assert.AreEqual(17, exit);
        Assert.IsEmpty(output.ToString());
        Assert.Contains(failedCommand == 0 ? "daemon unavailable" : "container disappeared", error.ToString());
        Assert.IsEmpty(results);
    }

    [TestMethod]
    public async Task RunAsync_PartialImageFailure_ReportsAvailableMetadataAndUnknowns()
    {
        var results = new Queue<DockerCommandResult>([
            new(0, Ps, ""),
            new(0, """
                {"Id":"c1","Name":"/app","ImageId":"present","ConfiguredImage":"ubuntu","Platform":"linux"}
                {"Id":"c2","Name":"/other","ImageId":"gone","ConfiguredImage":"team/local","Platform":"linux"}
                """, ""),
            new(1, """{"Id":"present","Os":"linux","Architecture":"amd64"}""", "No such image: gone")
        ]);
        using var output = new StringWriter();
        using var error = new StringWriter();
        int exit = await DockerScan.RunAsync(_ => Task.FromResult(results.Dequeue()), output, error);
        Assert.AreEqual(1, exit);
        Assert.Contains("No such image: gone", error.ToString());
        foreach (string expected in new[] { "app", "other", "linux/amd64", "Repository digests: <none>",
            "Repository digests: <unknown>", "Reference: Ambiguous", "team/local" })
            Assert.Contains(expected, output.ToString());
    }

    [TestMethod]
    public async Task RunAsync_NoImageIds_SkipsImageInspectAndReportsMissingReference()
    {
        var results = new Queue<DockerCommandResult>([
            new(0, Ps, ""), new(0, """{"Id":"c1","Name":"/app"}""", "")
        ]);
        using var output = new StringWriter();
        int exit = await DockerScan.RunAsync(_ => Task.FromResult(results.Dequeue()), output, TextWriter.Null);
        Assert.AreEqual(0, exit);
        Assert.Contains("Reference: Missing", output.ToString());
        Assert.Contains("<unknown>", output.ToString());
        Assert.IsEmpty(results);
    }

    [TestMethod]
    public void WriteReport_DuplicateMetadata_UsesEquivalentRowsButRejectsConflicts()
    {
        var containers = new[] { new DockerInspectRow("a", "/app", "id", "ubuntu") };
        var first = new DockerImageRow("id", "linux", "amd64", null, ["ubuntu@" + Digest, null]);
        using var output = new StringWriter();
        using var error = new StringWriter();
        DockerScan.WriteReport(containers, [new(), first, first with { RepoDigests = ["ubuntu@" + Digest] }], output, error);
        Assert.IsEmpty(error.ToString());
        Assert.Contains("linux/amd64", output.ToString());
        Assert.Contains("Reference: RegistryBacked", output.ToString());

        output.GetStringBuilder().Clear();
        DockerScan.WriteReport(containers, [first, first with { Architecture = "arm64" }], output, error);
        Assert.Contains("Conflicting image metadata", error.ToString());
        Assert.Contains("Repository digests: <unknown>", output.ToString());
        Assert.Contains("Reference: Ambiguous", output.ToString());
    }

    [TestMethod]
    public void WriteReport_NullEmptyAndInvalidDigestMetadata_DoesNotInventProvenanceOrPlatform()
    {
        using var output = new StringWriter();
        DockerScan.WriteReport([new("a", "/app", "id", "local:dev")],
            [new("id", null, null, null, [null, "", " ", "malformed@digest"])], output, TextWriter.Null);
        Assert.Contains("<unknown>/<unknown>", output.ToString());
        Assert.Contains("Repository digests: malformed@digest", output.ToString());
        Assert.Contains("Reference: Ambiguous", output.ToString());
    }

    [TestMethod]
    public void WriteReport_ConfiguredPinAndId_AreReportedSeparately()
    {
        string configured = "ghcr.io/org/app:stable@" + Digest;
        using var output = new StringWriter();
        DockerScan.WriteReport([new("a", "/app", "sha256:local", configured)],
            [new("sha256:local", "linux", "amd64")], output, TextWriter.Null);
        Assert.Contains(configured, output.ToString());
        Assert.Contains("sha256:local", output.ToString());
        Assert.Contains("Reference: RegistryBacked (digest-pinned)", output.ToString());
    }
}
