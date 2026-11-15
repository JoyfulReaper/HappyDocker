using System.Net;
using System.Text.Json;
using static HappyDocker.Tests.RegistryFixture;

namespace HappyDocker.Tests;

[TestClass]
public sealed class DockerCheckTests
{
    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task Check_ReportsMutableTagComparisonWithoutMutatingDocker(bool changed)
    {
        using var fixture = new RegistryFixture();
        if (changed) fixture.SetTag(fixture.NewManifest);
        var commands = new List<string[]>();
        var results = Inventory(fixture);
        using var output = new StringWriter();
        using var error = new StringWriter();
        int exit = await DockerCheck.RunAsync(args =>
        {
            commands.Add(args);
            return Task.FromResult(results.Dequeue());
        }, fixture.Checker, output, error);
        Assert.AreEqual(0, exit);
        Assert.IsEmpty(error.ToString());
        Assert.Contains(changed ? "Update available" : "Up to date", output.ToString());
        Assert.Contains(fixture.Container.ConfiguredImage!, output.ToString());
        Assert.Contains("Deployed platform manifest: " + Digest(fixture.OldManifest), output.ToString());
        Assert.Contains("Current platform manifest:", output.ToString());
        Assert.HasCount(3, commands);
        Assert.AreEqual("ps", commands[0][0]);
        CollectionAssert.AreEqual(new[] { "inspect", "--type", "container" }, commands[1][..3]);
        CollectionAssert.AreEqual(new[] { "image", "inspect" }, commands[2][..2]);
        Assert.IsEmpty(results);
    }

    [TestMethod]
    [DataRow(UpdateStatus.UpToDate, "Up to date")]
    [DataRow(UpdateStatus.UpdateAvailable, "Update available")]
    [DataRow(UpdateStatus.Unknown, "Unknown / insufficient metadata")]
    [DataRow(UpdateStatus.UnsupportedRegistry, "Unsupported registry")]
    [DataRow(UpdateStatus.AuthenticationRequired, "Authentication required")]
    [DataRow(UpdateStatus.RegistryUnavailable, "Registry unavailable")]
    [DataRow(UpdateStatus.Skipped, "Skipped")]
    public void AllResultsHaveDistinctReadableLabels(UpdateStatus status, string expected) =>
        Assert.AreEqual(expected, DockerCheck.Label(status));

    [TestMethod]
    public async Task Check_ConflictingImageMetadata_IsUnknownWithoutRegistryRequests()
    {
        using var fixture = new RegistryFixture();
        string images = JsonSerializer.Serialize(fixture.Image) + "\n"
            + JsonSerializer.Serialize(fixture.Image with { Architecture = "arm64" });
        var results = Inventory(fixture, images);
        using var output = new StringWriter();
        using var error = new StringWriter();
        Assert.AreEqual(0, await DockerCheck.RunAsync(_ => Task.FromResult(results.Dequeue()), fixture.Checker, output, error));
        Assert.Contains("Unknown / insufficient metadata", output.ToString());
        Assert.Contains("Conflicting image metadata", error.ToString());
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    public async Task Check_PartialImageFailure_KeepsDockerExitCodeAndReportsUnknown()
    {
        using var fixture = new RegistryFixture();
        var results = Inventory(fixture, "", 7);
        using var output = new StringWriter();
        using var error = new StringWriter();
        Assert.AreEqual(7, await DockerCheck.RunAsync(_ => Task.FromResult(results.Dequeue()), fixture.Checker, output, error));
        Assert.Contains("Unknown / insufficient metadata", output.ToString());
        Assert.Contains("missing image", error.ToString());
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    [DataRow(0, "No running containers found.")]
    [DataRow(1, "")]
    public async Task Check_EmptyOrUnavailableDaemon_DoesNotContactRegistry(int exitCode, string expected)
    {
        using var fixture = new RegistryFixture();
        using var output = new StringWriter();
        using var error = new StringWriter();
        int exit = await DockerCheck.RunAsync(_ => Task.FromResult(new DockerCommandResult(exitCode, "", "daemon unavailable")),
            fixture.Checker, output, error);
        Assert.AreEqual(exitCode, exit);
        Assert.AreEqual(expected, output.ToString().TrimEnd());
        Assert.IsEmpty(fixture.Requests);
    }

    [TestMethod]
    public async Task Check_RegistryFailureIsReportDataAndContinuesWithOtherContainers()
    {
        using var fixture = new RegistryFixture();
        fixture.Intercept = _ => Error(HttpStatusCode.Unauthorized);
        var results = Inventory(fixture);
        DockerCommandResult ps = results.Dequeue();
        DockerCommandResult containers = results.Dequeue();
        DockerCommandResult images = results.Dequeue();
        results = new([ps, containers with
        {
            Stdout = containers.Stdout + "\n" + JsonSerializer.Serialize(fixture.Container with
            {
                Id = "other", Name = "/local", ConfiguredImage = "local:dev"
            })
        }, images]);
        using var output = new StringWriter();
        Assert.AreEqual(0, await DockerCheck.RunAsync(_ => Task.FromResult(results.Dequeue()), fixture.Checker, output, TextWriter.Null));
        Assert.Contains("Authentication required", output.ToString());
        Assert.Contains("Skipped", output.ToString());
        Assert.DoesNotContain("sensitive", output.ToString());
    }

    private static Queue<DockerCommandResult> Inventory(RegistryFixture fixture, string? images = null, int imageExit = 0) => new([
        new(0, """{"ID":"container","Names":"nats","Image":"nats"}""", ""),
        new(0, JsonSerializer.Serialize(fixture.Container), ""),
        new(imageExit, images ?? JsonSerializer.Serialize(fixture.Image), imageExit == 0 ? "" : "missing image")
    ]);
}
