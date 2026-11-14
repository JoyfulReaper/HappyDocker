using System.Text.Json;
using System.Text.Json.Serialization;

namespace HappyDocker;

public enum FindingKind { MutableTag, VersionCandidate }
public enum FindingRunStatus { Complete, Partial, Failed, Deferred }
public enum FindingState { New, Known, Changed, Resolved }

/// <summary>Version 1: a full host snapshot, not an event stream. See docs/WEB.md.</summary>
public sealed record AgentReport
{
    public required int SchemaVersion { get; init; }
    public required string HostId { get; init; }
    public required Guid ReportId { get; init; }
    public required DateTimeOffset ScannedAt { get; init; }
    public required FindingRunStatus Status { get; init; }
    public required IReadOnlyList<ReportFinding> Findings { get; init; }
}

public sealed record ReportFinding
{
    public required FindingKind Kind { get; init; }
    public required string ContainerName { get; init; }
    public string? ContainerId { get; init; }
    public string? ImageId { get; init; }
    public required string Repository { get; init; }
    public string? ConfiguredImage { get; init; }
    public string? ConfiguredTag { get; init; }
    public string? DeployedDigest { get; init; }
    public required string Available { get; init; }
    public required bool PlatformVerified { get; init; }
    public string? Platform { get; init; }
    public string? VerifiedAlternative { get; init; }
    public required FindingState State { get; init; }
    public required DateTimeOffset ObservedAt { get; init; }

    public VersionUpgrade? Upgrade { get; init; }
    public VersionUpgrade? AlternativeUpgrade { get; init; }

    // The server validates supplied classifications using the CLI's existing rules.
    [JsonIgnore]
    public VersionUpgrade? ExpectedUpgrade => Kind == FindingKind.VersionCandidate
        ? ImageVersion.Parse(ConfiguredTag)?.UpgradeTo(Available) : null;
    [JsonIgnore]
    public VersionUpgrade? ExpectedAlternativeUpgrade => Kind == FindingKind.VersionCandidate
        ? ImageVersion.Parse(ConfiguredTag)?.UpgradeTo(VerifiedAlternative) : null;
}

public static class ReportJson
{
    // Explicit string enums; unknown members and numeric enums are rejected in v1.
    public static JsonSerializerOptions CreateOptions() => new(JsonSerializerDefaults.Web)
    {
        PropertyNameCaseInsensitive = false,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        MaxDepth = 16,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase, allowIntegerValues: false) }
    };
}
