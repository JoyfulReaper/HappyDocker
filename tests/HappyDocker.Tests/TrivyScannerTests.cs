namespace HappyDocker.Tests;

[TestClass]
public sealed class TrivyScannerTests
{
    internal static readonly string ImageId = "sha256:" + new string('a', 64);
    internal static readonly string LayerId = "sha256:" + new string('d', 64);
    internal const string MuslTarget = """
        {"Target":"nats (alpine 3.22)","Class":"os-pkgs","Type":"alpine","Vulnerabilities":[
          {"VulnerabilityID":"CVE-2026-0001","PkgName":"musl","InstalledVersion":"1.2.5-r0","FixedVersion":"1.2.5-r1",
           "Severity":"HIGH","Status":"fixed","PrimaryURL":"https://example.test/advisory/musl"}]}
        """;
    internal const string RecognizedTarget = """
        {"Target":"alpine","Class":"os-pkgs","Type":"alpine","Packages":[{"Name":"musl","Version":"1.2.5-r1"}]}
        """;

    [TestMethod]
    public async Task AlpineFinding_RetainsMuslVersionFixAndAdvisory()
    {
        VulnerabilityScanResult result = await ScanAsync(Report(MuslTarget));
        Assert.AreEqual(VulnerabilityScanStatus.Findings, result.Status);
        VulnerabilityFinding finding = result.Findings.Single();
        Assert.AreEqual(new VulnerabilityFinding("CVE-2026-0001", "musl", "1.2.5-r0", "1.2.5-r1", "HIGH",
            "nats (alpine 3.22)", "alpine", "https://example.test/advisory/musl", "fixed"), finding);
    }

    [TestMethod]
    [DataRow("os-pkgs", "debian", "libssl3")]
    [DataRow("os-pkgs", "ubuntu", "openssl")]
    [DataRow("lang-pkgs", "dotnet-core", "Example.Dependency")]
    public async Task PackageFindings_IncludeUnfixedAndFallbackSource(string packageClass, string type, string package)
    {
        string entry = $$$"""
            {"Target":"application","Class":"{{{packageClass}}}","Type":"{{{type}}}","Vulnerabilities":[
                {"VulnerabilityID":"GHSA-fixture","PkgName":"{{{package}}}","InstalledVersion":"1.0","Severity":"CRITICAL",
                 "Status":"will_not_fix","DataSource":{"URL":"https://example.test/source"}}]}
            """;
        VulnerabilityFinding finding = (await ScanAsync(Report(entry))).Findings.Single();
        Assert.AreEqual(package, finding.Package);
        Assert.AreEqual(type, finding.PackageType);
        Assert.AreEqual("CRITICAL", finding.Severity);
        Assert.IsNull(finding.FixedVersion);
        Assert.AreEqual("will_not_fix", finding.Status);
        Assert.AreEqual("https://example.test/source", finding.SourceUrl);
    }

    [TestMethod]
    public async Task RecognizedPackagesWithoutVulnerabilities_ReportsNoFindings()
        => Assert.AreEqual(VulnerabilityScanStatus.NoFindings, (await ScanAsync(Report(RecognizedTarget))).Status);

    [TestMethod]
    [DataRow("")]
    [DataRow("""{"Target":"scratch","Class":"unknown"}""")]
    [DataRow("""{"Target":"distroless","Class":"os-pkgs","Type":"debian","Packages":[]}""")]
    [DataRow("""{"Target":"unknown","Class":"os-pkgs","Type":"unknown","Packages":[{"Name":"example"}]}""")]
    public async Task EmptyOrUnrecognizedPackages_DoNotReportNoFindings(string entry)
        => Assert.AreEqual(VulnerabilityScanStatus.UnsupportedPackages, (await ScanAsync(Report(entry))).Status);

    [TestMethod]
    public async Task DistrolessWithRecognizedPackages_CanReportFindings()
        => Assert.AreEqual(VulnerabilityScanStatus.Findings,
            (await ScanAsync(Report(MuslTarget.Replace("nats (alpine 3.22)", "distroless fixture")))).Status);

    [TestMethod]
    public async Task PartialPackageCoverage_RetainsKnownFindings()
    {
        VulnerabilityScanResult result = await ScanAsync(Report(MuslTarget), "WARN unsupported OS family");
        Assert.AreEqual(VulnerabilityScanStatus.Findings, result.Status);
        Assert.Contains("limited package coverage", result.Detail);
        Assert.HasCount(1, result.Findings);
    }

    [TestMethod]
    [DataRow("")]
    [DataRow("{")]
    [DataRow("""{"SchemaVersion":2,"ArtifactType":"container_image","Metadata":""")]
    [DataRow("""{"SchemaVersion":2,"ArtifactType":"container_image","Metadata":{},"Results":[]}""")]
    [DataRow("""{"SchemaVersion":2,"SchemaVersion":2}""")]
    public async Task MalformedTruncatedOrUnboundReports_AreIncomplete(string json)
        => Assert.AreEqual(VulnerabilityScanStatus.Incomplete, (await ScanAsync(json)).Status);

    [TestMethod]
    public async Task OversizedJson_IsRejectedBeforeParsing()
    {
        var scanner = new TrivyScanner((_, _, limit, _, _) => Task.FromResult(
            new ProcessCaptureResult(ProcessOutcome.Exited, 0, new string(' ', limit + 1))));
        VulnerabilityScanResult result = await scanner.ScanAsync(new(ImageId, "linux", "amd64"), default);
        Assert.AreEqual(VulnerabilityScanStatus.Incomplete, result.Status);
        Assert.Contains("output limit", result.Detail);
    }

    [TestMethod]
    [DataRow("wrong-id", "linux", "amd64", null)]
    [DataRow(null, "windows", "amd64", null)]
    [DataRow(null, "linux", "arm64", null)]
    [DataRow(null, "linux", "amd64", "v3")]
    public async Task IdentityOrPlatformMismatch_DiscardsFindings(string? id, string os, string arch, string? variant)
    {
        VulnerabilityScanResult result = await ScanAsync(Report(MuslTarget, id ?? ImageId, os, arch, variant),
            target: new(ImageId, "linux", "amd64", "v2"));
        Assert.AreEqual(VulnerabilityScanStatus.Incomplete, result.Status);
        Assert.IsEmpty(result.Findings);
    }

    [TestMethod]
    [DataRow("matching", VulnerabilityScanStatus.Findings)]
    [DataRow("configuration", VulnerabilityScanStatus.Incomplete)]
    [DataRow("layers", VulnerabilityScanStatus.Incomplete)]
    [DataRow("missing layers", VulnerabilityScanStatus.Incomplete)]
    public async Task ManifestReport_RequiresDockerManifestIdAndMatchingLayers(string scenario, VulnerabilityScanStatus expected)
    {
        var target = new DeployedScanTarget(ImageId, "linux", "amd64", IdentityKind: ImageDigestKind.PlatformManifest,
            ManifestDiffIds: [LayerId]);
        string report = Report(MuslTarget, scenario == "configuration" ? "sha256:" + new string('b', 64) : ImageId);
        if (scenario == "layers") report = report.Replace(LayerId, "sha256:" + new string('e', 64), StringComparison.Ordinal);
        if (scenario == "missing layers") report = report.Replace($"\"DiffIDs\":[\"{LayerId}\"],", "", StringComparison.Ordinal);
        var result = await ScanAsync(report, target: target);
        Assert.AreEqual(expected, result.Status);
        if (scenario == "configuration") Assert.Contains("configuration digest", result.Detail);
        if (expected == VulnerabilityScanStatus.Incomplete) Assert.IsEmpty(result.Findings);
    }

    [TestMethod]
    public async Task IndexId_CannotReachTrivyEvenWithLayerMetadata()
    {
        var scanner = new TrivyScanner((_, _, _, _, _) => throw new AssertFailedException("An index ID is not a scan target."));
        var target = new DeployedScanTarget(ImageId, "linux", "amd64", IdentityKind: ImageDigestKind.ImageIndex, ManifestDiffIds: [LayerId]);
        Assert.AreEqual(VulnerabilityScanStatus.Incomplete, (await scanner.ScanAsync(target, default)).Status);
    }

    [TestMethod]
    public async Task ScratchManifest_AllowsOmittedDiffIdsOnlyWhenDockerReportsZeroLayers()
    {
        var target = new DeployedScanTarget(ImageId, "linux", "amd64", IdentityKind: ImageDigestKind.PlatformManifest,
            ManifestDiffIds: []);
        string report = Report("").Replace($"\"DiffIDs\":[\"{LayerId}\"],", "", StringComparison.Ordinal);
        Assert.AreEqual(VulnerabilityScanStatus.UnsupportedPackages, (await ScanAsync(report, target: target)).Status);
    }

    [TestMethod]
    [DataRow(false)]
    [DataRow(true)]
    public async Task DatabaseMetadata_PrefersVersionSubcommandAndSupportsOlderCli(bool olderCli)
    {
        int calls = 0;
        var scanner = new TrivyScanner((info, _, _, _, _) =>
        {
            string[] args = info.ArgumentList.ToArray();
            CollectionAssert.AreEqual(++calls == 1
                ? new[] { "version", "--config=", "--format", "json" }
                : new[] { "--config=", "--version", "--format", "json" }, args);
            return Task.FromResult(calls == 1 && olderCli
                ? new ProcessCaptureResult(ProcessOutcome.Exited, 1, Stderr: "unknown command \"version\" for \"trivy\"")
                : new ProcessCaptureResult(ProcessOutcome.Exited, 0, """{"VulnerabilityDB":{"UpdatedAt":"2026-10-01T01:00:00Z"}}"""));
        });
        Assert.AreEqual(new DateTimeOffset(2026, 10, 1, 1, 0, 0, TimeSpan.Zero), await scanner.DatabaseUpdatedAtAsync(default));
        Assert.AreEqual(olderCli ? 2 : 1, calls);
    }

    [TestMethod]
    [DataRow(ProcessOutcome.Missing, "not found")]
    [DataRow(ProcessOutcome.TimedOut, "timed out")]
    [DataRow(ProcessOutcome.OutputLimit, "output limit")]
    [DataRow(ProcessOutcome.Failed, "capture")]
    public async Task ProcessFailures_AreIncomplete(ProcessOutcome outcome, string expected)
    {
        var scanner = new TrivyScanner((_, _, _, _, _) => Task.FromResult(new ProcessCaptureResult(outcome)));
        VulnerabilityScanResult result = await scanner.ScanAsync(new(ImageId, "linux", "amd64"), default);
        Assert.AreEqual(VulnerabilityScanStatus.Incomplete, result.Status);
        Assert.Contains(expected, result.Detail);
    }

    [TestMethod]
    [DataRow("failed to download vulnerability DB", "vulnerability databases")]
    [DataRow("database error: invalid schema", "vulnerability databases")]
    [DataRow("first run cannot skip downloading DB", "vulnerability databases")]
    [DataRow("failed to open local image", "exit 2")]
    public async Task NonzeroExit_DiscardsEvenWellFormedOutput(string diagnostic, string expected)
    {
        var scanner = new TrivyScanner((_, _, _, _, _) => Task.FromResult(
            new ProcessCaptureResult(ProcessOutcome.Exited, 2, Report(RecognizedTarget), diagnostic + " raw-private-detail")));
        VulnerabilityScanResult result = await scanner.ScanAsync(new(ImageId, "linux", "amd64"), default);
        Assert.AreEqual(VulnerabilityScanStatus.Incomplete, result.Status);
        Assert.Contains(expected, result.Detail);
        Assert.DoesNotContain("raw-private-detail", result.Detail);
    }

    [TestMethod]
    public async Task CancellationDuringScannerCall_Propagates()
    {
        using var source = new CancellationTokenSource();
        var scanner = new TrivyScanner((_, _, _, _, token) =>
        {
            Assert.AreEqual(source.Token, token);
            source.Cancel();
            return Task.FromResult(new ProcessCaptureResult(ProcessOutcome.Exited, 0, Report(RecognizedTarget)));
        });
        await Assert.ThrowsAsync<OperationCanceledException>(() => scanner.ScanAsync(new(ImageId, "linux", "amd64"), source.Token));
    }

    [TestMethod]
    [DoNotParallelize]
    public async Task ScannerInvocation_RestrictsSourcesAndIsolatesCredentials()
    {
        string[] names = ["HAPPYDOCKER_GHCR_TOKEN", "HAPPYDOCKER_GHCR_TOKEN_FILE", "HAPPYDOCKER_OTHER_SECRET",
            "GITHUB_TOKEN", "CR_PAT", "TRIVY_IMAGE_SRC", "TRIVY_SERVER"];
        string?[] original = names.Select(Environment.GetEnvironmentVariable).ToArray();
        try
        {
            foreach (string name in names) Environment.SetEnvironmentVariable(name, "fake-test-value");
            var scanner = new TrivyScanner((info, timeout, stdoutLimit, stderrLimit, _) =>
            {
                Assert.AreEqual("trivy", info.FileName);
                Assert.IsFalse(info.UseShellExecute);
                Assert.IsTrue(info.RedirectStandardOutput && info.RedirectStandardError);
                Assert.IsTrue(timeout > TimeSpan.Zero && stdoutLimit > stderrLimit && stderrLimit > 0);
                string[] args = info.ArgumentList.ToArray();
                Assert.AreEqual("image", args[0]);
                Assert.AreEqual("docker", args[Array.IndexOf(args, "--image-src") + 1]);
                Assert.AreEqual("vuln", args[Array.IndexOf(args, "--scanners") + 1]);
                Assert.AreEqual("json", args[Array.IndexOf(args, "--format") + 1]);
                Assert.AreEqual("memory", args[Array.IndexOf(args, "--cache-backend") + 1]);
                foreach (string flag in new[] { "--config=", "--offline-scan", "--disable-telemetry", "--skip-version-check", "--ignore-unfixed=false" })
                    CollectionAssert.Contains(args, flag);
                CollectionAssert.DoesNotContain(args, "--skip-db-update");
                Assert.AreEqual(ImageId, args[^1]);
                Assert.IsTrue(names.All(name => !info.Environment.ContainsKey(name)));
                Assert.DoesNotContain("fake-test-value", string.Join(" ", args));
                return Task.FromResult(new ProcessCaptureResult(ProcessOutcome.Exited, 0, Report(RecognizedTarget)));
            });
            Assert.AreEqual(VulnerabilityScanStatus.NoFindings, (await scanner.ScanAsync(new(ImageId, "linux", "amd64"), default)).Status);
        }
        finally
        {
            for (int i = 0; i < names.Length; i++) Environment.SetEnvironmentVariable(names[i], original[i]);
        }
    }

    internal static string Report(string entry, string? id = null, string os = "linux", string arch = "amd64", string? variant = null) => $$$"""
        {"SchemaVersion":2,"ArtifactType":"container_image","Metadata":{"ImageID":"{{{id ?? ImageId}}}","DiffIDs":["{{{LayerId}}}"],
         "ImageConfig":{"os":"{{{os}}}","architecture":"{{{arch}}}","variant":"{{{variant}}}"}},"Results":[{{{entry}}}]}
        """;

    private static Task<VulnerabilityScanResult> ScanAsync(string json, string stderr = "", DeployedScanTarget? target = null)
        => new TrivyScanner((_, _, _, _, _) => Task.FromResult(new ProcessCaptureResult(ProcessOutcome.Exited, 0, json, stderr)))
            .ScanAsync(target ?? new(ImageId, "linux", "amd64"), default);
}
