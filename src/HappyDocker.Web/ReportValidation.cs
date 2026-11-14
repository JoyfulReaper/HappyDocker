using System.Text.RegularExpressions;

namespace HappyDocker.Web;

public static class ReportValidation
{
    public const int MaximumBytes = 1024 * 1024;
    public const int MaximumFindings = 1000;

    public static string? Validate(AgentReport report, DateTimeOffset now)
    {
        if (report.SchemaVersion != 1) return "Unsupported schemaVersion; expected 1.";
        if (!AgentAuthentication.ValidHost(report.HostId) || report.ReportId == Guid.Empty
            || !ValidTimestamp(report.ScannedAt, now) || !Enum.IsDefined(report.Status)
            || report.Findings is null || report.Findings.Count > MaximumFindings)
            return "Invalid report identity, UTC timestamp, status, or findings list.";
        if (report.Status == FindingRunStatus.Failed && report.Findings.Count != 0)
            return "Failed scans must have an empty findings list; known findings are retained by the server.";
        var keys = new HashSet<(string, string, FindingKind)>();
        foreach (ReportFinding finding in report.Findings)
        {
            if (finding is null || !Enum.IsDefined(finding.Kind) || !Enum.IsDefined(finding.State)
                || !Text(finding.ContainerName, 256, required: true) || !Repository(finding.Repository)
                || !Text(finding.ContainerId, 256) || !Text(finding.ImageId, 256)
                || !Text(finding.ConfiguredImage, 1024) || !Text(finding.Platform, 128)
                || !Tag(finding.ConfiguredTag) || !Digest(finding.DeployedDigest)
                || !Text(finding.Available, 256, required: true)
                || !ValidTimestamp(finding.ObservedAt, now) || finding.ObservedAt > report.ScannedAt
                || !keys.Add((finding.ContainerName, finding.Repository, finding.Kind)))
                return "Invalid finding fields, UTC observation timestamp, or duplicate logical finding key.";
            if (finding.Kind == FindingKind.VersionCandidate)
            {
                if (finding.ExpectedUpgrade is null || finding.Upgrade != finding.ExpectedUpgrade
                    || finding.AlternativeUpgrade != finding.ExpectedAlternativeUpgrade || (finding.VerifiedAlternative is not null
                    && (finding.ExpectedAlternativeUpgrade is null || finding.VerifiedAlternative == finding.Available
                        || !IsLowerAlternative(finding))))
                    return "Version candidates require a newer stable matching tag and a valid lower verified alternative.";
            }
            else if (!Digest(finding.Available) || finding.VerifiedAlternative is not null
                || finding.ConfiguredTag is null || finding.Upgrade is not null || finding.AlternativeUpgrade is not null)
                return "Mutable-tag findings require an available digest and configured tag; no version alternative.";
        }
        return null;
    }

    private static bool IsLowerAlternative(ReportFinding finding)
    {
        // Validate ordering through the same classification rules used by the CLI.
        var alternative = finding with { ConfiguredTag = finding.VerifiedAlternative, VerifiedAlternative = null };
        return alternative.ExpectedUpgrade is not null;
    }

    private static bool ValidTimestamp(DateTimeOffset value, DateTimeOffset now) =>
        value.Offset == TimeSpan.Zero && value >= DateTimeOffset.UnixEpoch && value <= now.AddMinutes(5);

    private static bool Text(string? value, int limit, bool required = false) =>
        value is null ? !required : value.Length <= limit && !string.IsNullOrWhiteSpace(value)
            && !value.Any(char.IsControl) && value == value.Trim();

    private static bool Tag(string? value) => value is null || Regex.IsMatch(value,
        @"\A[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}\z", RegexOptions.NonBacktracking);

    private static bool Digest(string? value) => value is null || Regex.IsMatch(value,
        @"\A(?:sha256:[a-f0-9]{64}|sha384:[a-f0-9]{96}|sha512:[a-f0-9]{128})\z", RegexOptions.NonBacktracking);

    private static bool Repository(string? value) => Text(value, 255, required: true)
        && Regex.IsMatch(value!, @"\A(?:[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?|\[[a-fA-F0-9:]+\])(?::[0-9]{1,5})?/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*\z",
            RegexOptions.NonBacktracking);
}
