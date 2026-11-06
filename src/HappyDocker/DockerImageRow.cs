namespace HappyDocker;

public sealed record DockerImageRow(
    string? Id = null,
    string? Os = null,
    string? Architecture = null,
    string? Variant = null,
    string?[]? RepoDigests = null,
    System.Text.Json.JsonElement? Descriptor = null,
    System.Text.Json.JsonElement? Identity = null);
