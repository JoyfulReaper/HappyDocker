namespace HappyDocker;

public enum FindingKind { MutableTag, VersionCandidate }
public enum FindingEvidence { Present, Absent, Incomplete, NotApplicable, Deferred }
public enum FindingRunStatus { Complete, Partial, Failed, Deferred }

public sealed record FindingObservation(
    FindingKind Kind, string ContainerName, string ContainerId, string? ImageId, string? Repository,
    string? ConfiguredTag, string? DeployedDigest, string? Available, bool? PlatformVerified,
    FindingEvidence Evidence, DateTimeOffset ObservedAt)
{
    internal bool PlatformRequestFailed { get; init; }
    internal IReadOnlyCollection<string> FailedPlatformRequests { get; init; } = [];
    public string? VerifiedAlternative { get; init; }
    public VersionUpgrade? Upgrade => Kind == FindingKind.VersionCandidate ? ImageVersion.Parse(ConfiguredTag)?.UpgradeTo(Available) : null;
    public VersionUpgrade? AlternativeUpgrade => Kind == FindingKind.VersionCandidate
        ? ImageVersion.Parse(ConfiguredTag)?.UpgradeTo(VerifiedAlternative) : null;
    internal bool HasVerifiedCandidate => PlatformVerified == true
        || (AlternativeUpgrade is not null && ImageVersion.Parse(Available) is { } newest
            && ImageVersion.Parse(VerifiedAlternative) is { } alternative && newest.CompareTo(alternative) > 0);

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
    public int DeferredCount => Observations.Count(observation => observation.Evidence == FindingEvidence.Deferred);

    public int IncompleteCount => Observations.Count(observation => observation.IsIncomplete)
        + (InventoryExitCode == 0 ? 0 : 1);

    public FindingRunStatus Status
    {
        get
        {
            if (InventoryExitCode == 0 && IncompleteCount == 0)
                return DeferredCount == 0 ? FindingRunStatus.Complete : FindingRunStatus.Deferred;
            return Observations.Any(observation => observation.Evidence is FindingEvidence.Present or FindingEvidence.Absent)
                ? FindingRunStatus.Partial : FindingRunStatus.Failed;
        }
    }
}
