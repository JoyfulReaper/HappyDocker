using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace HappyDocker;

public enum VulnerabilityScanStatus { Findings, NoFindings, UnsupportedPackages, Incomplete }

public sealed record DeployedScanTarget(string ImageId, string Os, string Architecture, string? Variant = null,
    ImageDigestKind IdentityKind = ImageDigestKind.Configuration, IReadOnlyList<string>? ManifestDiffIds = null)
{
    public string Platform => string.IsNullOrEmpty(Variant) ? $"{Os}/{Architecture}" : $"{Os}/{Architecture}/{Variant}";
}

public sealed record VulnerabilityFinding(string Id, string Package, string InstalledVersion, string? FixedVersion,
    string Severity, string Target, string PackageType, string? SourceUrl, string? Status);

public sealed record VulnerabilityScanResult(VulnerabilityScanStatus Status, string Detail, IReadOnlyList<VulnerabilityFinding> Findings);

public sealed class TrivyScanner(Func<ProcessStartInfo, TimeSpan, int, int, CancellationToken, Task<ProcessCaptureResult>> run)
{
    internal const int ReportLimit = 32 * 1024 * 1024;
    internal const int DiagnosticLimit = 256 * 1024;
    private static readonly TimeSpan ScanTimeout = TimeSpan.FromMinutes(10);
    private static readonly HashSet<string> ScannerEnvironment = new(StringComparer.OrdinalIgnoreCase)
    {
        "PATH", "PATHEXT", "SystemRoot", "WINDIR",
        "HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CACHE_HOME", "XDG_CONFIG_HOME",
        "TEMP", "TMP", "TMPDIR",
        "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "DOCKER_API_VERSION",
        "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR",
        "TRIVY_CACHE_DIR"
    };
    private bool executableMissing;

    public async Task<VulnerabilityScanResult> ScanAsync(DeployedScanTarget target, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!ImageReference.IsSupportedDigest(target.ImageId)) return Incomplete("The deployed image ID is invalid.");
        if (target.IdentityKind is not (ImageDigestKind.Configuration or ImageDigestKind.PlatformManifest)
            || (target.IdentityKind == ImageDigestKind.PlatformManifest && target.ManifestDiffIds is null))
            return Incomplete("The deployed image identity could not be established for Trivy.");
        if (executableMissing) return Incomplete("Trivy was not found. Install the Trivy CLI and add it to PATH.");

        ProcessCaptureResult process = await run(CreateStartInfo([
            "image", "--config=", "--format", "json", "--scanners", "vuln", "--image-src", "docker",
            "--disable-telemetry", "--skip-version-check", "--offline-scan", "--no-progress",
            "--list-all-pkgs", "--ignore-unfixed=false", "--ignorefile=", "--cache-backend", "memory",
            "--exit-code", "0", "--timeout", "10m", "--", target.ImageId
        ]), ScanTimeout, ReportLimit, DiagnosticLimit, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (process.Outcome == ProcessOutcome.Missing)
        {
            executableMissing = true;
            return Incomplete("Trivy was not found. Install the Trivy CLI and add it to PATH.");
        }
        if (process.Outcome == ProcessOutcome.TimedOut) return Incomplete("Trivy timed out after 10 minutes.");
        if (process.Outcome == ProcessOutcome.OutputLimit) return Incomplete("Trivy exceeded the report or diagnostic output limit.");
        if (process.Outcome != ProcessOutcome.Exited) return Incomplete("Unable to run Trivy or capture its output.");
        if (process.ExitCode != 0)
        {
            return IsDatabaseError(process.Stderr)
                ? Incomplete("Trivy could not prepare or use its vulnerability databases. Check network access and the scanner cache.")
                : Incomplete($"Trivy scan failed (exit {process.ExitCode}). Check local image access and supported Trivy flags.");
        }
        return Parse(process.Stdout, target, HasPackageCoverageWarning(process.Stderr));
    }

    public async Task<DateTimeOffset?> DatabaseUpdatedAtAsync(CancellationToken cancellationToken)
    {
        // This local version display reads the cache metadata. It does not check for updates.
        ProcessCaptureResult result = await run(CreateStartInfo(["version", "--config=", "--format", "json"]),
            TimeSpan.FromSeconds(10), DiagnosticLimit, DiagnosticLimit, cancellationToken);
        cancellationToken.ThrowIfCancellationRequested();
        if (result.Outcome == ProcessOutcome.Exited && result.ExitCode != 0
            && result.Stderr.Contains("unknown command \"version\"", StringComparison.OrdinalIgnoreCase))
        {
            result = await run(CreateStartInfo(["--config=", "--version", "--format", "json"]),
                TimeSpan.FromSeconds(10), DiagnosticLimit, DiagnosticLimit, cancellationToken);
            cancellationToken.ThrowIfCancellationRequested();
        }
        if (result.Outcome != ProcessOutcome.Exited || result.ExitCode != 0 || result.Stdout.Length > DiagnosticLimit) return null;
        try
        {
            using JsonDocument json = JsonValue.Parse(System.Text.Encoding.UTF8.GetBytes(result.Stdout));
            return json.Deserialize<TrivyVersion>()?.VulnerabilityDB?.UpdatedAt is { } updated && updated != default ? updated : null;
        }
        catch (JsonException) { return null; }
    }

    private static ProcessStartInfo CreateStartInfo(string[] args)
    {
        var info = new ProcessStartInfo("trivy")
        {
            UseShellExecute = false, CreateNoWindow = true, RedirectStandardOutput = true, RedirectStandardError = true
        };
        foreach (string arg in args) info.ArgumentList.Add(arg);
        foreach (string key in info.Environment.Keys.ToArray())
        {
            // Keep only process, Docker, and database-cache settings needed by the scanner.
            if (!ScannerEnvironment.Contains(key))
                info.Environment.Remove(key);
        }
        return info;
    }

    private static VulnerabilityScanResult Parse(string json, DeployedScanTarget target, bool coverageWarning)
    {
        if (json.Length > ReportLimit) return Incomplete("Trivy exceeded the report output limit.");
        try
        {
            using JsonDocument document = JsonValue.Parse(System.Text.Encoding.UTF8.GetBytes(json));
            TrivyReport? report = document.Deserialize<TrivyReport>();
            if (report is not { SchemaVersion: 2, ArtifactType: "container_image" })
                return Incomplete("Trivy returned an unrecognized image report.");
            TrivyMetadata? metadata = report.Metadata;
            TrivyPlatform? platform = metadata?.ImageConfig;
            if (platform?.Os != target.Os || platform?.Architecture != target.Architecture
                || (!string.IsNullOrEmpty(platform.Variant) && !string.IsNullOrEmpty(target.Variant) && platform.Variant != target.Variant))
                return Incomplete("Trivy did not verify the intended deployed platform.");

            // Trivy's Docker backend exposes Docker inspect.Id as ImageID. Its kind depends on the image store.
            // A different configuration hash cannot be verified from a manifest descriptor or a list of layer diff IDs.
            if (metadata?.ImageID != target.ImageId)
                return Incomplete(target.IdentityKind == ImageDigestKind.PlatformManifest
                    ? "Trivy did not report the verified Docker manifest ID. Docker inspect does not expose its configuration digest."
                    : "Trivy did not report the deployed configuration ID.");
            if (target.IdentityKind == ImageDigestKind.PlatformManifest
                && !target.ManifestDiffIds!.SequenceEqual(metadata.DiffIDs ?? [], StringComparer.Ordinal))
                return Incomplete("Trivy's filesystem layers differ from those reported by Docker for the deployed manifest.");

            var findings = new List<VulnerabilityFinding>();
            bool recognizedPackages = false;
            foreach (TrivyTarget? entry in report.Results ?? [])
            {
                if (entry is null) return Incomplete("Trivy returned an invalid package target.");
                bool recognized = entry.Class is "os-pkgs" or "lang-pkgs" && !string.IsNullOrWhiteSpace(entry.Type) && entry.Type != "unknown";
                recognizedPackages |= recognized && (entry.Packages?.Any(p => !string.IsNullOrWhiteSpace(p?.Name)
                    && !string.IsNullOrWhiteSpace(p.Version)) == true
                    || entry.Vulnerabilities?.Length > 0);
                coverageWarning |= !recognized;
                foreach (TrivyVulnerability? finding in entry.Vulnerabilities ?? [])
                {
                    if (finding is null || string.IsNullOrWhiteSpace(finding.VulnerabilityID) || string.IsNullOrWhiteSpace(finding.PkgName)
                        || string.IsNullOrWhiteSpace(finding.InstalledVersion) || string.IsNullOrWhiteSpace(entry.Target))
                        return Incomplete("Trivy returned an incomplete vulnerability finding.");
                    findings.Add(new(finding.VulnerabilityID, finding.PkgName, finding.InstalledVersion, finding.FixedVersion,
                        Severity(finding.Severity), entry.Target, entry.Type ?? "unknown", finding.PrimaryURL ?? finding.DataSource?.URL, finding.Status));
                }
            }
            if (findings.Count > 0)
                return new(VulnerabilityScanStatus.Findings, coverageWarning
                    ? "Scan completed with findings and limited package coverage." : "Scan completed with findings.", findings);
            if (!recognizedPackages || coverageWarning)
                return new(VulnerabilityScanStatus.UnsupportedPackages, "Scan completed with unsupported or unrecognized package information.", []);
            return new(VulnerabilityScanStatus.NoFindings, "Scan completed with no findings reported for recognized packages.", []);
        }
        catch (JsonException) { return Incomplete("Trivy returned malformed or truncated JSON."); }
    }

    internal static VulnerabilityScanResult Incomplete(string reason) => new(VulnerabilityScanStatus.Incomplete, reason, []);

    private static bool IsDatabaseError(string diagnostic) =>
        new[] { "vulnerability db", "database", "db error", "download db", "downloading db", "java db", "java-db", "trivy.db" }
            .Any(value => diagnostic.Contains(value, StringComparison.OrdinalIgnoreCase));

    private static bool HasPackageCoverageWarning(string diagnostic) =>
        new[] { "unsupported os", "os is not supported", "os is not detected", "unknown os", "no package detected" }
            .Any(value => diagnostic.Contains(value, StringComparison.OrdinalIgnoreCase));

    private static string Severity(string? value) => value?.ToUpperInvariant() switch
    {
        "LOW" => "LOW", "MEDIUM" => "MEDIUM", "HIGH" => "HIGH", "CRITICAL" => "CRITICAL", _ => "UNKNOWN"
    };

    private sealed record TrivyReport(int SchemaVersion, string? ArtifactType, TrivyMetadata? Metadata, TrivyTarget?[]? Results);
    private sealed record TrivyMetadata(string? ImageID, TrivyPlatform? ImageConfig, string[]? DiffIDs);
    private sealed record TrivyPlatform([property: JsonPropertyName("os")] string? Os,
        [property: JsonPropertyName("architecture")] string? Architecture, [property: JsonPropertyName("variant")] string? Variant);
    private sealed record TrivyTarget(string? Target, string? Class, string? Type, TrivyPackage?[]? Packages, TrivyVulnerability?[]? Vulnerabilities);
    private sealed record TrivyPackage(string? Name, string? Version);
    private sealed record TrivyVulnerability(string? VulnerabilityID, string? PkgName, string? InstalledVersion, string? FixedVersion,
        string? Severity, string? PrimaryURL, string? Status, TrivySource? DataSource);
    private sealed record TrivySource(string? URL);
    private sealed record TrivyVersion(TrivyDatabase? VulnerabilityDB);
    private sealed record TrivyDatabase(DateTimeOffset? UpdatedAt);
}
