using System.Text.RegularExpressions;

namespace HappyDocker;

public enum ImageReferenceKind { Missing, Invalid, LocalImageId, Ambiguous, RegistryBacked }

/// <summary>A parsed configured reference. Normalization describes Docker naming rules, not provenance.</summary>
public sealed record ImageReference(
    string? Original,
    string? Registry,
    string? Repository,
    string? Tag,
    string? Digest,
    bool HasExplicitRegistry,
    ImageReferenceKind Kind,
    string Reason)
{
    public bool IsDigestPinned => Repository is not null && Digest is not null;
    public string? Normalized => Repository is null ? null
        : $"{Registry}/{Repository}{(Tag is null ? "" : $":{Tag}")}{(Digest is null ? "" : $"@{Digest}")}";

    // Docker distribution/reference grammar, with ASCII tags and bounded, non-backtracking matching.
    private const string Component = "[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*";
    private const string HostPart = "(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])";
    private static bool Matches(string value, string pattern) => Regex.IsMatch(
        value, $"\\A(?:{pattern})\\z", RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    public static ImageReference Parse(string? reference)
    {
        ImageReference Failure(ImageReferenceKind kind, string reason) =>
            new(reference, null, null, null, null, false, kind, reason);

        if (string.IsNullOrWhiteSpace(reference))
            return Failure(ImageReferenceKind.Missing, "No configured image reference.");

        if (Matches(reference, "[a-f0-9]{64}") || IsSupportedDigest(reference))
            return Failure(ImageReferenceKind.LocalImageId, "Content ID only; no registry repository is identified.");

        if (reference.Length > 1024 || reference.Any(char.IsWhiteSpace))
            return Failure(ImageReferenceKind.Invalid, "Invalid image reference syntax.");

        string name = reference;
        string? digest = null;
        int at = name.IndexOf('@');
        if (at >= 0)
        {
            digest = name[(at + 1)..];
            name = name[..at];
            if (!IsSupportedDigest(digest))
                return Failure(ImageReferenceKind.Invalid, "Invalid or unsupported digest (expected sha256, sha384, or sha512).");
        }

        string? tag = null;
        int colon = name.LastIndexOf(':');
        if (colon > name.LastIndexOf('/'))
        {
            tag = name[(colon + 1)..];
            name = name[..colon];
            if (!Matches(tag, "[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}"))
                return Failure(ImageReferenceKind.Invalid, "Invalid image tag.");
        }

        int slash = name.IndexOf('/');
        string first = slash < 0 ? name : name[..slash];
        bool explicitRegistry = slash >= 0 && (first == "localhost" || first.Contains('.')
            || first.Contains(':') || first.Any(char.IsUpper));
        string registry = explicitRegistry ? first.ToLowerInvariant() : "docker.io";
        string repository = explicitRegistry ? name[(slash + 1)..] : name;
        if (registry == "index.docker.io") registry = "docker.io";
        // Docker recognizes an uppercase single-label host as explicit. Lowercasing it would
        // turn the normalized reference into a Docker Hub namespace on the next parse.
        if (explicitRegistry && !first.Contains('.') && !first.Contains(':') && registry != "localhost")
            registry = first;

        if (!Matches(registry, $"(?:{HostPart}(?:\\.{HostPart})*|\\[[a-fA-F0-9:]+\\])(?::[0-9]+)?")
            || !Matches(repository, $"{Component}(?:/{Component})*"))
            return Failure(ImageReferenceKind.Invalid, "Invalid registry or repository name.");

        if (registry == "docker.io" && !repository.Contains('/')) repository = "library/" + repository;
        if ($"{registry}/{repository}".Length > 255)
            return Failure(ImageReferenceKind.Invalid, "Image repository name exceeds 255 characters.");

        // Do not invent :latest on digest-pinned references. Keep an explicitly configured tag.
        if (tag is null && digest is null) tag = "latest";
        bool identifiable = explicitRegistry || digest is not null;
        return new(reference, registry, repository, tag, digest, explicitRegistry,
            identifiable ? ImageReferenceKind.RegistryBacked : ImageReferenceKind.Ambiguous,
            identifiable ? "Reference identifies a registry repository; local availability or remote existence is not verified."
                : "Docker Hub naming default; could also be a local tag.");
    }

    /// <summary>Only metadata for the same repository (and pinned digest, if any) is evidence.</summary>
    public ImageReference WithMetadata(IEnumerable<string?>? repoDigests)
    {
        if (Repository is null || repoDigests is null) return this;
        foreach (string? value in repoDigests)
        {
            ImageReference candidate = Parse(value);
            if (candidate.IsDigestPinned && string.Equals(candidate.Registry, Registry, StringComparison.OrdinalIgnoreCase)
                && candidate.Repository == Repository
                && (Digest is null || candidate.Digest == Digest))
                return this with { Kind = ImageReferenceKind.RegistryBacked,
                    Reason = "Matching repository digest exists in the inspected image metadata." };
        }
        return this;
    }

    private static bool IsSupportedDigest(string value)
    {
        int colon = value.IndexOf(':');
        if (colon < 0) return false;
        int length = value[..colon] switch { "sha256" => 64, "sha384" => 96, "sha512" => 128, _ => 0 };
        return length > 0 && Matches(value[(colon + 1)..], $"[a-f0-9]{{{length}}}");
    }
}
