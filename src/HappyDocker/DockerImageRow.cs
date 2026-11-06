namespace HappyDocker;

public sealed record DockerImageRow(
    string? Id = null,
    string? Os = null,
    string? Architecture = null,
    string? Variant = null,
    string?[]? RepoDigests = null);
