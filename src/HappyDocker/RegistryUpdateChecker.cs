using System.Text.Json;

namespace HappyDocker;

/// <summary>Compares resolved platform manifests, never image IDs against repository digests.</summary>
public sealed class RegistryUpdateChecker(RegistryClient registry)
{
    private sealed record PlatformManifest(string Digest, string ConfigDigest, long ConfigSize, int LayerCount, bool HasPlatformDescriptor);

    public async Task<UpdateResult> CheckAsync(DockerInspectRow container, DockerImageRow? image,
        CancellationToken cancellationToken = default)
    {
        ImageReference reference = ImageReference.Parse(container.ConfiguredImage).WithMetadata(image?.RepoDigests);
        if (reference.IsDigestPinned)
            return new(UpdateStatus.Skipped, "Configured image is digest-pinned.");
        if (reference.Kind is ImageReferenceKind.Ambiguous or ImageReferenceKind.LocalImageId)
            return new(UpdateStatus.Skipped, "Ambiguous or local-only reference; no registry comparison attempted.");
        if (reference.Repository is null || reference.Tag is null)
            return new(UpdateStatus.Unknown, reference.Reason);
        if (!RegistryClient.Supports(reference.Registry))
            return new(UpdateStatus.UnsupportedRegistry, "Only Docker Hub and GHCR are supported.");
        if (image is null || image.Id != container.ImageId || !ImageReference.IsSupportedDigest(image.Id ?? "")
            || string.IsNullOrWhiteSpace(image.Os) || string.IsNullOrWhiteSpace(image.Architecture)
            || (!string.IsNullOrWhiteSpace(container.Platform) && container.Platform != image.Os))
            return new(UpdateStatus.Unknown, "Missing or inconsistent deployed image identity or platform metadata.");

        string[] deployedDigests = (image.RepoDigests ?? []).Select(ImageReference.Parse)
            .Where(r => r.IsDigestPinned && r.Registry == reference.Registry && r.Repository == reference.Repository)
            .Select(r => r.Digest!).Distinct(StringComparer.Ordinal).ToArray();
        if (deployedDigests.Length != 1)
            return new(UpdateStatus.Unknown, "Need one unambiguous deployed repository digest for the configured repository.");

        try
        {
            // Resolve the immutable deployed reference first. It can be either an index or a manifest.
            var cache = new Dictionary<string, RegistryDocument>(StringComparer.Ordinal);
            PlatformManifest deployed = await ResolveAsync(reference, deployedDigests[0], image, cache, 0, false, cancellationToken);
            if (deployed.ConfigDigest != image.Id)
                return new(UpdateStatus.Unknown, "Deployed repository manifest is not tied to the local image configuration.");
            PlatformManifest current = await ResolveAsync(reference, reference.Tag, image, cache, 0, false, cancellationToken);
            if (deployed.Digest == current.Digest)
                return new(UpdateStatus.UpToDate, "Configured tag still resolves to the deployed platform manifest.", deployed.Digest, current.Digest);
            if (deployed.ConfigDigest == current.ConfigDigest)
                return new(UpdateStatus.Unknown, "Manifest changed but image configuration did not; no reliable image update inferred.", deployed.Digest, current.Digest);

            // A single manifest has no platform field. Verify its config metadata, never download layers.
            RegistryDocument config = await registry.GetAsync(reference.Registry!, reference.Repository!, current.ConfigDigest, true, cancellationToken);
            if (config.Bytes.LongLength != current.ConfigSize)
                return new(UpdateStatus.Unknown, "Image configuration size disagrees with its manifest descriptor.");
            using JsonDocument document = JsonValue.Parse(config.Bytes);
            JsonElement root = document.RootElement;
            if (!MatchesPlatform(root, image, allowMissingVariant: current.HasPlatformDescriptor))
                return new(UpdateStatus.Unknown, "Current image platform cannot be matched reliably to the deployed platform.");
            if (!root.TryGetProperty("rootfs", out var rootfs) || JsonValue.String(rootfs, "type") != "layers"
                || !rootfs.TryGetProperty("diff_ids", out var diffIds) || diffIds.ValueKind != JsonValueKind.Array
                || diffIds.GetArrayLength() != current.LayerCount
                || diffIds.EnumerateArray().Any(d => d.ValueKind != JsonValueKind.String || !ImageReference.IsSupportedDigest(d.GetString()!)))
                return new(UpdateStatus.Unknown, "Current image configuration has inconsistent filesystem metadata.");
            return new(UpdateStatus.UpdateAvailable, "Configured tag resolves to a different image for the deployed platform.", deployed.Digest, current.Digest);
        }
        catch (RegistryException exception) { return exception.Result; }
        catch (JsonException) { return new(UpdateStatus.Unknown, "Registry returned malformed image metadata."); }
    }

    private async Task<PlatformManifest> ResolveAsync(ImageReference reference, string selector, DockerImageRow image,
        Dictionary<string, RegistryDocument> cache, int depth, bool selectedPlatform, CancellationToken cancellationToken,
        string? expectedType = null, long? expectedSize = null)
    {
        if (depth > 4) throw Unknown("Nested image index exceeds the supported depth.");
        if (!cache.TryGetValue(selector, out RegistryDocument? content))
        {
            content = await registry.GetAsync(reference.Registry!, reference.Repository!, selector, false, cancellationToken);
            cache.Add(selector, content);
            // Both keys name the same verified bytes, independent of the original digest algorithm.
            cache.TryAdd(content.Digest, content);
        }
        using JsonDocument document = JsonValue.Parse(content.Bytes);
        if (expectedSize is not null && content.Bytes.LongLength != expectedSize)
            throw Unknown("Registry index descriptor disagrees with the referenced manifest size.");
        JsonElement root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("schemaVersion", out var schema)
            || schema.ValueKind != JsonValueKind.Number || !schema.TryGetInt32(out int version)
            || version != 2 || root.TryGetProperty("artifactType", out _))
            throw Unknown("Unsupported registry manifest schema or artifact.");
        string? mediaType = JsonValue.String(root, "mediaType") ?? content.MediaType;
        if (root.TryGetProperty("mediaType", out var declaredType) && declaredType.ValueKind != JsonValueKind.String)
            throw Unknown("Registry manifest media type is malformed.");
        if (expectedType is not null && mediaType != expectedType)
            throw Unknown("Registry index descriptor disagrees with the referenced manifest media type.");
        if (mediaType is RegistryClient.OciIndex or RegistryClient.DockerIndex)
        {
            if (!root.TryGetProperty("manifests", out var manifests) || manifests.ValueKind != JsonValueKind.Array)
                throw Unknown("Registry index is missing manifest descriptors.");
            JsonElement[] candidates = manifests.EnumerateArray().Where(entry =>
                entry.ValueKind == JsonValueKind.Object && entry.TryGetProperty("platform", out var platform)
                && MatchesPlatform(platform, image, allowMissingVariant: false)).ToArray();
            if (candidates.Length != 1)
                throw Unknown("Registry index has no unique exact match for the deployed platform.");
            string? digest = JsonValue.String(candidates[0], "digest");
            string? childType = JsonValue.String(candidates[0], "mediaType");
            if (!ValidDescriptor(candidates[0])
                || childType is not (RegistryClient.OciManifest or RegistryClient.DockerManifest or RegistryClient.OciIndex or RegistryClient.DockerIndex))
                throw Unknown("Registry index has an unsupported platform descriptor.");
            return await ResolveAsync(reference, digest!, image, cache, depth + 1, true, cancellationToken,
                childType, candidates[0].GetProperty("size").GetInt64());
        }
        if (mediaType is not (RegistryClient.OciManifest or RegistryClient.DockerManifest)
            || !root.TryGetProperty("config", out var config)
            || !root.TryGetProperty("layers", out var layers) || layers.ValueKind != JsonValueKind.Array)
            throw Unknown("Registry did not return a supported runnable image manifest.");
        string? configDigest = JsonValue.String(config, "digest");
        if (!ValidDescriptor(config) || layers.EnumerateArray().Any(layer => !ValidDescriptor(layer))
            || JsonValue.String(config, "mediaType") is not ("application/vnd.oci.image.config.v1+json" or "application/vnd.docker.container.image.v1+json"))
            throw Unknown("Registry manifest has an unsupported image configuration.");
        return new(content.Digest, configDigest!, config.GetProperty("size").GetInt64(), layers.GetArrayLength(), selectedPlatform);
    }

    private static bool MatchesPlatform(JsonElement platform, DockerImageRow image, bool allowMissingVariant)
    {
        if (platform.ValueKind != JsonValueKind.Object || JsonValue.String(platform, "os") != image.Os
            || JsonValue.String(platform, "architecture") != image.Architecture) return false;
        // These constraints are absent from current Docker inventory metadata. Do not guess compatibility.
        foreach (string field in new[] { "os.version", "os.features", "features" })
            if (platform.TryGetProperty(field, out var value) && value.ValueKind != JsonValueKind.Null
                && !(value.ValueKind == JsonValueKind.Array && value.GetArrayLength() == 0)
                && !(value.ValueKind == JsonValueKind.String && value.GetString() == "")) return false;
        string? variant = JsonValue.String(platform, "variant");
        if (platform.TryGetProperty("variant", out var variantValue)
            && variantValue.ValueKind is not (JsonValueKind.String or JsonValueKind.Null))
            return false;
        return (allowMissingVariant && variant is null) || (variant ?? "") == (image.Variant ?? "");
    }

    private static RegistryException Unknown(string reason) => new(UpdateStatus.Unknown, reason);

    private static bool ValidDescriptor(JsonElement descriptor) => descriptor.ValueKind == JsonValueKind.Object
        && !string.IsNullOrEmpty(JsonValue.String(descriptor, "mediaType"))
        && ImageReference.IsSupportedDigest(JsonValue.String(descriptor, "digest") ?? "")
        && descriptor.TryGetProperty("size", out var size) && size.ValueKind == JsonValueKind.Number
        && size.TryGetInt64(out long length) && length >= 0;
}
