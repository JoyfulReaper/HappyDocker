using System.Text.Json;

namespace HappyDocker.Tests;

[TestClass]
public sealed class AgentReportBuilderTests
{
    private readonly DateTimeOffset now = DateTimeOffset.UtcNow.AddSeconds(-2);
    private static string Digest => "sha256:" + new string('a', 64);
    private FindingObservation Finding(string name = "container") => new(FindingKind.MutableTag, name, "container-id", "image-id",
        "docker.io/library/nats", "latest", Digest, Digest, true, FindingEvidence.Present, now.AddMinutes(-1));
    private static FindingTransition Transition(FindingObservation observation, FindingState state = FindingState.New) => new(observation, state);
    private AgentReport Build(FindingRun run, params FindingTransition[] transitions) => AgentReportBuilder.Build("my-host", run, transitions, now);

    [TestMethod]
    public async Task EmptyFullHostInventoryAndInventoryFailureHaveHonestStatuses()
    {
        using var registry = new RegistryClient();
        var empty = await DockerCheck.RunObservedAsync(_ => Task.FromResult(new DockerCommandResult(0, "", "")), registry, TextWriter.Null, TextWriter.Null);
        var report = AgentReportBuilder.Build("my-host", empty, [], DateTimeOffset.UtcNow);
        Assert.AreEqual(FindingRunStatus.Complete, report.Status);
        Assert.IsEmpty(report.Findings);
        var failed = await DockerCheck.RunObservedAsync(_ => Task.FromResult(new DockerCommandResult(1, "", "error")), registry, TextWriter.Null, TextWriter.Null);
        Assert.AreEqual(FindingRunStatus.Failed, AgentReportBuilder.Build("my-host", failed, [], DateTimeOffset.UtcNow).Status);
    }

    [TestMethod]
    public async Task MissingContainerInspectionCannotBecomeACompleteSnapshot()
    {
        using var registry = new RegistryClient();
        Task<DockerCommandResult> Docker(string[] args) => Task.FromResult(args[0] == "ps"
            ? new DockerCommandResult(0, "{\"ID\":\"abc\",\"Names\":\"nats\",\"Image\":\"nats\"}", "")
            : new DockerCommandResult(0, "", ""));
        var run = await DockerCheck.RunObservedAsync(Docker, registry, TextWriter.Null, TextWriter.Null);
        Assert.AreEqual(FindingRunStatus.Complete, run.Status);
        Assert.AreEqual(FindingRunStatus.Partial, AgentReportBuilder.Build("host", run, [], DateTimeOffset.UtcNow).Status);
    }

    [TestMethod]
    public void FullCoverageNoUpdatesAndContainerRemovalOmitOldFindings()
    {
        var absent = Finding() with { Evidence = FindingEvidence.Absent, Available = null, PlatformVerified = null };
        var run = new FindingRun(0, [absent]) { HasFullHostCoverage = true };
        var report = Build(run, Transition(absent, FindingState.Resolved));
        Assert.AreEqual(FindingRunStatus.Complete, report.Status);
        Assert.IsEmpty(report.Findings);
        Assert.IsEmpty(Build(new FindingRun(0, []) { HasFullHostCoverage = true }).Findings);
    }

    [TestMethod]
    public void PartialDeferredAndTargetedRunsNeverClaimCompleteOrIncludeResolutions()
    {
        var present = Finding();
        var absent = Finding("other") with { Evidence = FindingEvidence.Absent, Available = null };
        foreach (var uncertain in new[] { FindingEvidence.Incomplete, FindingEvidence.Deferred })
        {
            var run = new FindingRun(0, [present, absent, Finding("uncertain") with { Evidence = uncertain }]) { HasFullHostCoverage = true };
            var report = Build(run, Transition(present, FindingState.Changed), Transition(absent, FindingState.Resolved));
            Assert.AreEqual(uncertain == FindingEvidence.Deferred ? FindingRunStatus.Deferred : FindingRunStatus.Partial, report.Status);
            Assert.AreEqual(FindingState.Changed, report.Findings.Single().State);
        }
        Assert.AreEqual(FindingRunStatus.Partial, Build(new FindingRun(0, [present]), Transition(present)).Status);
        var cached = new FindingRun(0, [absent with { Evidence = FindingEvidence.NotApplicable, InconclusiveForSnapshot = true }]) { HasFullHostCoverage = true };
        Assert.AreEqual(FindingRunStatus.Partial, Build(cached).Status);
    }

    [TestMethod]
    public void CarriesVersionClassificationObservationTimeAndUnverifiedEvidence()
    {
        var version = new FindingObservation(FindingKind.VersionCandidate, "nats", "id", null, "docker.io/library/nats",
            "1.2.3", null, "1.4.0", false, FindingEvidence.Present, now.AddHours(-1)) { VerifiedAlternative = "1.3.0" };
        var report = Build(new FindingRun(0, [version]) { HasFullHostCoverage = true }, Transition(version, FindingState.Known));
        Assert.AreEqual(FindingRunStatus.Partial, report.Status);
        var item = report.Findings.Single();
        Assert.AreEqual(version.ObservedAt, item.ObservedAt);
        Assert.IsFalse(item.PlatformVerified);
        Assert.AreEqual(VersionUpgrade.Minor, item.Upgrade);
        Assert.AreEqual(VersionUpgrade.Minor, item.AlternativeUpgrade);
        Assert.AreEqual(FindingState.Known, item.State);
        Assert.IsNull(item.Platform);
        Assert.IsNull(item.ConfiguredImage);
        var serialized = JsonSerializer.SerializeToUtf8Bytes(report, ReportJson.CreateOptions());
        var decoded = JsonSerializer.Deserialize<AgentReport>(serialized, ReportJson.CreateOptions())!;
        Assert.IsNull(AgentReportValidation.Validate(decoded, DateTimeOffset.UtcNow));
    }

    [TestMethod]
    public void RejectsUnrepresentableAndOversizedSnapshots()
    {
        var item = Finding();
        Assert.ThrowsExactly<ArgumentException>(() => AgentReportBuilder.Build("docker:implicit", new(0, []), [], now));
        Assert.ThrowsExactly<InvalidOperationException>(() => Build(new FindingRun(0, [item]) { HasFullHostCoverage = true }));
        var invalid = item with { Available = "not-a-digest" };
        Assert.ThrowsExactly<InvalidOperationException>(() => Build(new FindingRun(0, [invalid]), Transition(invalid)));
        var many = Enumerable.Range(0, 1001).Select(i => Finding($"container-{i}")).ToArray();
        Assert.ThrowsExactly<InvalidOperationException>(() => AgentReportBuilder.Build("host", new FindingRun(0, many) { HasFullHostCoverage = true }, many.Select(i => Transition(i)).ToArray(), now));
        var large = Enumerable.Range(0, 1000).Select(i => Finding(i.ToString("D4") + new string('n', 250)) with
        { ContainerId = new string('c', 256), ImageId = new string('i', 256), Repository = "docker.io/" + new string('r', 245) }).ToArray();
        Assert.ThrowsExactly<InvalidOperationException>(() => AgentReportBuilder.Build("host", new FindingRun(0, large) { HasFullHostCoverage = true }, large.Select(i => Transition(i)).ToArray(), now));
    }
}
