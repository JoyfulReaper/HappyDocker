using System.Text.Json;

namespace HappyDocker;

public enum ImageDigestKind { Unknown, Configuration, PlatformManifest, ImageIndex }
public enum ImageProvenanceKind { Missing, Pulled, BuildOnly, Unknown, Mixed, LocalOrImported }
public sealed record ImageProvenance(ImageProvenanceKind Kind, string Reason);
public sealed record ImageDescriptor(string Digest, string MediaType, long Size, ImageDigestKind Kind, JsonElement? Platform);

/// <summary>Local daemon evidence. Repository digest names alone establish neither store type nor origin.</summary>
public static class DockerImageIdentity
{
    public static bool Present(JsonElement? value) => value is { ValueKind: not (JsonValueKind.Null or JsonValueKind.Undefined) };

    public static ImageDescriptor? ReadDescriptor(JsonElement? value)
    {
        if (!Present(value) || value!.Value.ValueKind != JsonValueKind.Object) return null;
        JsonElement descriptor = value.Value;
        try { JsonValue.Validate(descriptor); }
        catch (JsonException) { return null; }
        string? digest = JsonValue.String(descriptor, "digest");
        string? mediaType = JsonValue.String(descriptor, "mediaType");
        ImageDigestKind kind = mediaType switch
        {
            RegistryClient.OciIndex or RegistryClient.DockerIndex => ImageDigestKind.ImageIndex,
            RegistryClient.OciManifest or RegistryClient.DockerManifest => ImageDigestKind.PlatformManifest,
            "application/vnd.oci.image.config.v1+json" or "application/vnd.docker.container.image.v1+json" => ImageDigestKind.Configuration,
            _ => ImageDigestKind.Unknown
        };
        if (kind == ImageDigestKind.Unknown || !ImageReference.IsSupportedDigest(digest ?? "")
            || !descriptor.TryGetProperty("size", out var size) || size.ValueKind != JsonValueKind.Number
            || !size.TryGetInt64(out long length) || length < 0) return null;
        JsonElement? platform = descriptor.TryGetProperty("platform", out var p) ? p : null;
        if (Present(platform) && platform!.Value.ValueKind != JsonValueKind.Object) return null;
        return new(digest!, mediaType!, length, kind, platform);
    }

    public static ImageProvenance Provenance(ImageReference reference, DockerImageRow? image)
    {
        if (!Present(image?.Identity))
        {
            if (HasLocalDescriptorAliases(reference, image))
                return new(ImageProvenanceKind.LocalOrImported,
                    "Local/imported image pattern: unqualified repository aliases match the image descriptor, but pull provenance is unavailable. Registry comparison skipped.");
            return new(ImageProvenanceKind.Missing, "Pull/build provenance is unavailable; repository digests alone do not prove registry origin.");
        }
        JsonElement identity = image!.Identity!.Value;
        if (identity.ValueKind != JsonValueKind.Object) return Unknown();
        try { JsonValue.Validate(identity); }
        catch (JsonException) { return Unknown(); }
        if (identity.EnumerateObject().Any(p => p.Name is not ("Pull" or "Build" or "Signature"))) return Unknown();
        if (!Records(identity, "Pull", out JsonElement[] pull) || !Records(identity, "Build", out JsonElement[] build))
            return Unknown();
        if (pull.Length > 0 && build.Length > 0)
            return new(ImageProvenanceKind.Mixed, "Mixed pull/build identity records; registry provenance is not inferred.");
        if (build.Length > 0)
            return new(ImageProvenanceKind.BuildOnly, "Build-only identity; repository digests may be synthetic local names.");
        if (pull.Length == 0) return Unknown();

        bool matching = false;
        foreach (JsonElement record in pull)
        {
            string? name = JsonValue.String(record, "Repository");
            ImageReference candidate = ImageReference.Parse(name);
            // Daemon pull records name canonical repositories, not tags, digests, or ambiguous local names.
            if (name is null || !candidate.HasExplicitRegistry || candidate.Repository is null || candidate.IsDigestPinned
                || name.LastIndexOf(':') > name.LastIndexOf('/')) return Unknown();
            matching |= string.Equals(candidate.Registry, reference.Registry, StringComparison.OrdinalIgnoreCase)
                && candidate.Repository == reference.Repository;
        }
        return matching
            ? new(ImageProvenanceKind.Pulled, "Matching Identity.Pull repository records provide registry-origin evidence.")
            : new(ImageProvenanceKind.Unknown, "Pull identity does not match the configured repository.");
    }

    internal static bool Equivalent(JsonElement? left, JsonElement? right) =>
        !Present(left) && !Present(right) || Present(left) && Present(right) && JsonElement.DeepEquals(left!.Value, right!.Value);

    private static bool HasLocalDescriptorAliases(ImageReference reference, DockerImageRow? image)
    {
        if (reference.Repository is null || reference.IsDigestPinned || reference.HasExplicitRegistry
            || reference.Original!.Contains('/') || image?.RepoDigests is not { Length: > 0 } digests)
            return false;
        ImageDescriptor? descriptor = ReadDescriptor(image.Descriptor);
        if (descriptor?.Kind is not (ImageDigestKind.PlatformManifest or ImageDigestKind.ImageIndex)
            || descriptor.Digest != image.Id) return false;

        bool matching = false;
        foreach (string? digest in digests)
        {
            ImageReference alias = ImageReference.Parse(digest);
            // Canonical registry names or inconsistent aliases need stronger provenance evidence.
            if (!alias.IsDigestPinned || alias.HasExplicitRegistry || alias.Tag is not null
                || alias.Original!.Contains('/') || alias.Digest != descriptor.Digest) return false;
            matching |= alias.Repository == reference.Repository;
        }
        // Descriptor name annotations are labels and cannot establish a pull or build origin.
        return matching;
    }

    private static bool Records(JsonElement identity, string name, out JsonElement[] records)
    {
        records = [];
        if (!identity.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null) return true;
        if (value.ValueKind != JsonValueKind.Array) return false;
        records = value.EnumerateArray().ToArray();
        return records.All(record => record.ValueKind == JsonValueKind.Object);
    }

    private static ImageProvenance Unknown() => new(ImageProvenanceKind.Unknown,
        "Missing or inconsistent pull/build identity records; registry provenance is unknown.");
}
