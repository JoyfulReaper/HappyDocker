namespace HappyDocker;

public enum FindingKind { MutableTag, PatchCandidate }
public enum FindingEvidence { Present, Absent, Incomplete, NotApplicable }
public enum FindingRunStatus { Complete, Partial, Failed }

public sealed record FindingObservation(
    FindingKind Kind, string ContainerName, string ContainerId, string? ImageId, string? Repository,
    string? ConfiguredTag, string? DeployedDigest, string? Available, bool? PlatformVerified,
    FindingEvidence Evidence, DateTimeOffset ObservedAt)
{
    internal bool PlatformRequestFailed { get; init; }

    internal static FindingObservation ForContainer(DockerInspectRow container, ImageReference reference, FindingKind kind,
        DateTimeOffset observedAt, FindingEvidence evidence, string? available = null,
        bool? platformVerified = null, string? deployedDigest = null)
    {
        string name = container.Name.TrimStart('/');
        string? repository = reference.Repository is null ? null : $"{reference.Registry}/{reference.Repository}";
        if (evidence is FindingEvidence.Present or FindingEvidence.Absent
            && (string.IsNullOrWhiteSpace(name) || repository is null))
            evidence = FindingEvidence.Incomplete;
        return new(kind, name, container.Id, container.ImageId, repository, reference.Tag,
            deployedDigest, available, platformVerified, evidence, observedAt);
    }

    internal bool IsIncomplete => Evidence == FindingEvidence.Incomplete
        || (Evidence == FindingEvidence.Present && PlatformVerified != true);
}

public sealed record FindingRun(int InventoryExitCode, IReadOnlyList<FindingObservation> Observations)
{
    public int IncompleteCount => Observations.Count(observation => observation.IsIncomplete)
        + (InventoryExitCode == 0 ? 0 : 1);

    public FindingRunStatus Status => InventoryExitCode == 0 && IncompleteCount == 0 ? FindingRunStatus.Complete
        : Observations.Any(observation => observation.Evidence is FindingEvidence.Present or FindingEvidence.Absent) ? FindingRunStatus.Partial
        : FindingRunStatus.Failed;
}
