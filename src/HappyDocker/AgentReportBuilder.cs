using System.Text.Json;

namespace HappyDocker;

/// <summary>Constructs an immutable, validated v1 snapshot. Delivery and retry are separate.</summary>
public static class AgentReportBuilder
{
    public static AgentReport Build(string hostId, FindingRun run, IReadOnlyList<FindingTransition> transitions,
        DateTimeOffset scannedAt, TimeProvider? clock = null) => Build(hostId, run, transitions, scannedAt, out _, clock);

    public static AgentReport Build(string hostId, FindingRun run, IReadOnlyList<FindingTransition> transitions,
        DateTimeOffset scannedAt, out int unmatchedObservations, TimeProvider? clock = null)
    {
        ArgumentNullException.ThrowIfNull(run);
        ArgumentNullException.ThrowIfNull(transitions);
        if (!AgentReportValidation.ValidHost(hostId))
            throw new ArgumentException("An explicit stable --host identifier is required.", nameof(hostId));

        FindingRunStatus status = run.Status;
        if (status == FindingRunStatus.Complete && (!run.HasFullHostCoverage
            || run.Observations.Any(observation => observation.InconclusiveForSnapshot)))
            status = FindingRunStatus.Partial;

        var findings = new List<ReportFinding>();
        unmatchedObservations = 0;
        if (status != FindingRunStatus.Failed)
        {
            foreach (FindingObservation observation in run.Observations.Where(item => item.Evidence == FindingEvidence.Present))
            {
                // History may reject stale or incomplete observations. Never manufacture a state for them.
                var matches = transitions.Where(transition => transition.Observation == observation
                    && transition.State is FindingState.New or FindingState.Known or FindingState.Changed).ToArray();
                if (matches.Length != 1 || observation.Repository is null || observation.Available is null
                    || observation.PlatformVerified is null)
                {
                    unmatchedObservations++;
                    if (status == FindingRunStatus.Complete) status = FindingRunStatus.Partial;
                    continue;
                }
                findings.Add(new ReportFinding
                {
                    Kind = observation.Kind, ContainerName = observation.ContainerName,
                    ContainerId = observation.ContainerId, ImageId = observation.ImageId,
                    Repository = observation.Repository, ConfiguredTag = observation.ConfiguredTag,
                    DeployedDigest = observation.DeployedDigest, Available = observation.Available,
                    PlatformVerified = observation.PlatformVerified.Value, VerifiedAlternative = observation.VerifiedAlternative,
                    Upgrade = observation.Upgrade, AlternativeUpgrade = observation.AlternativeUpgrade,
                    State = matches[0].State, ObservedAt = observation.ObservedAt.ToUniversalTime()
                });
            }
        }
        var report = new AgentReport
        {
            SchemaVersion = 1, HostId = hostId, ReportId = Guid.NewGuid(), ScannedAt = scannedAt.ToUniversalTime(),
            Status = status, Findings = findings.ToArray()
        };
        string? error = AgentReportValidation.Validate(report, (clock ?? TimeProvider.System).GetUtcNow());
        if (error is not null) throw new InvalidOperationException($"Cannot construct a valid agent report: {error}");
        if (JsonSerializer.SerializeToUtf8Bytes(report, ReportJson.CreateOptions()).Length > AgentReportValidation.MaximumBytes)
            throw new InvalidOperationException("The agent report exceeds the 1 MiB limit.");
        return report;
    }
}
