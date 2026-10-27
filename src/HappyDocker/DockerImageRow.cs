namespace HappyDocker;

public sealed record DockerImageRow(
    string Id,
    string Os,
    string Architecture,
    string? Variant,
    string[]? RepoDigests);