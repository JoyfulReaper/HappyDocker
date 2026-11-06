using System.Text.Json;

namespace HappyDocker;

/// <summary>Compares resolved platform manifests, never image IDs against repository digests.</summary>
public sealed class RegistryUpdateChecker(RegistryClient registry)
{
    private sealed record PlatformManifest(string Digest, string ConfigDigest, long ConfigSize, int LayerCount, bool HasPlatformDescriptor);

    public async Task<UpdateResult> CheckAsync(DockerInspectRow container, DockerImageRow? image,
        CancellationToken cancellationToken = default)
    {
        ImageReference reference = ImageReference.Parse(container.ConfiguredImage);
        if (reference.IsDigestPinned)
            return new(UpdateStatus.Skipped, "Configured image is digest-pinned.");
        if (reference.Kind == ImageReferenceKind.LocalImageId)
            return new(UpdateStatus.Skipped, "Ambiguous or local-only reference; no registry comparison attempted.");
        if (reference.Repository is null || reference.Tag is null)
            return new(UpdateStatus.Unknown, reference.Reason);
        ImageProvenance provenance = DockerImageIdentity.Provenance(reference, image);
        if (provenance.Kind == ImageProvenanceKind.BuildOnly)
            return new(UpdateStatus.Skipped, provenance.Reason);
        if (!RegistryClient.Supports(reference.Registry))
            return new(UpdateStatus.UnsupportedRegistry, "Only Docker Hub and GHCR are supported.");
        if (provenance.Kind is ImageProvenanceKind.Unknown or ImageProvenanceKind.Mixed)
            return new(UpdateStatus.Unknown, provenance.Reason);
        bool hasDescriptor = DockerImageIdentity.Present(image?.Descriptor);
        if (hasDescriptor && provenance.Kind != ImageProvenanceKind.Pulled)
            return new(UpdateStatus.Unknown, "Image descriptor is present but matching pull provenance is unavailable.");
        if (provenance.Kind == ImageProvenanceKind.Missing && !hasDescriptor && !reference.HasExplicitRegistry
            && !(image?.RepoDigests ?? []).Select(ImageReference.Parse).Any(r => r.IsDigestPinned
                && r.Registry == reference.Registry && r.Repository == reference.Repository))
            return new(UpdateStatus.Skipped, "Ambiguous reference without pull identity or a candidate deployed repository digest.");
        if (image is null || image.Id != container.ImageId || !ImageReference.IsSupportedDigest(image.Id ?? "")
            || string.IsNullOrWhiteSpace(image.Os) || string.IsNullOrWhiteSpace(image.Architecture))
            return new(UpdateStatus.Unknown, "Missing or inconsistent deployed image identity or platform metadata.");

        ImageDescriptor? descriptor = DockerImageIdentity.ReadDescriptor(image.Descriptor);
        if (hasDescriptor && (descriptor is null || descriptor.Digest != image.Id))
            return new(UpdateStatus.Unknown, "Image ID and image descriptor are invalid or inconsistent.");
        ImageDigestKind identityKind = descriptor?.Kind ?? ImageDigestKind.Configuration;
        ImageDescriptor? containerDescriptor = DockerImageIdentity.ReadDescriptor(container.ImageManifestDescriptor);
        if (DockerImageIdentity.Present(container.ImageManifestDescriptor)
            && containerDescriptor?.Kind != ImageDigestKind.PlatformManifest)
            return new(UpdateStatus.Unknown, "Container platform manifest descriptor is invalid or unsupported.");
        if (identityKind == ImageDigestKind.ImageIndex && containerDescriptor is null)
            return new(UpdateStatus.Unknown, "Index image ID needs the container's platform manifest descriptor to identify the deployed platform.");
        if (DockerImageIdentity.Present(containerDescriptor?.Platform))
        {
            JsonElement platform = containerDescriptor!.Platform!.Value;
            var deployedPlatform = image with
            {
                Os = JsonValue.String(platform, "os"), Architecture = JsonValue.String(platform, "architecture"),
                Variant = JsonValue.String(platform, "variant")
            };
            if (string.IsNullOrWhiteSpace(deployedPlatform.Os) || string.IsNullOrWhiteSpace(deployedPlatform.Architecture)
                || !MatchesPlatform(platform, deployedPlatform, false)
                || (identityKind != ImageDigestKind.ImageIndex && !MatchesPlatform(platform, image, false)))
                return new(UpdateStatus.Unknown, "Container and image platform metadata are inconsistent or incomplete.");
            // An index's image inspection can describe the daemon's default platform, not this container.
            image = deployedPlatform;
        }
        if ((!string.IsNullOrWhiteSpace(container.Platform) && container.Platform != image.Os)
            || (DockerImageIdentity.Present(descriptor?.Platform) && !MatchesPlatform(descriptor!.Platform!.Value, image, false)))
            return new(UpdateStatus.Unknown, "Container and image descriptor platforms disagree.");

        string[] deployedDigests = (image.RepoDigests ?? []).Select(ImageReference.Parse)
            .Where(r => r.IsDigestPinned && r.Registry == reference.Registry && r.Repository == reference.Repository)
            .Select(r => r.Digest!).Distinct(StringComparer.Ordinal).ToArray();
        if (deployedDigests.Length > 1 || (deployedDigests.Length == 0 && identityKind == ImageDigestKind.Configuration))
            return new(UpdateStatus.Unknown, "Need one unambiguous deployed repository digest for the configured repository.");

        try
        {
            // Resolve the immutable deployed reference first. It can be either an index or a manifest.
            var cache = new Dictionary<string, RegistryDocument>(StringComparer.Ordinal);
            PlatformManifest deployed = descriptor is { Kind: ImageDigestKind.ImageIndex or ImageDigestKind.PlatformManifest }
                ? await ResolveAsync(reference, descriptor.Digest, image, cache, 0, DockerImageIdentity.Present(descriptor.Platform),
                    cancellationToken, descriptor.MediaType, descriptor.Size)
                : await ResolveAsync(reference, deployedDigests[0], image, cache, 0, false, cancellationToken);
            if (identityKind == ImageDigestKind.Configuration && deployed.ConfigDigest != image.Id)
                return new(UpdateStatus.Unknown, "Deployed repository manifest is not tied to the local image configuration.");
            if (descriptor is not null && identityKind != ImageDigestKind.Configuration && deployedDigests.Length == 1
                && deployedDigests[0] != descriptor.Digest)
            {
                PlatformManifest repositoryManifest = await ResolveAsync(reference, deployedDigests[0], image, cache, 0, false, cancellationToken);
                if (repositoryManifest.Digest != deployed.Digest)
                    return new(UpdateStatus.Unknown, "Repository digest conflicts with the deployed image descriptor.");
            }
            if (containerDescriptor is not null)
            {
                PlatformManifest containerManifest = await ResolveAsync(reference, containerDescriptor.Digest, image, cache, 0,
                    DockerImageIdentity.Present(containerDescriptor.Platform), cancellationToken, containerDescriptor.MediaType, containerDescriptor.Size);
                if (containerManifest.Digest != deployed.Digest)
                    return new(UpdateStatus.Unknown, "Container platform manifest is not the manifest resolved from the deployed image.");
            }
            if (descriptor is not null)
            {
                await VerifyConfigAsync(reference, deployed, image, cancellationToken);
                if (identityKind == ImageDigestKind.Configuration && descriptor.Size != deployed.ConfigSize)
                    return new(UpdateStatus.Unknown, "Configuration descriptor size disagrees with the deployed manifest.");
            }
            string provenanceNote = provenance.Kind == ImageProvenanceKind.Missing
                ? " Legacy configuration identity verified; pull provenance remains unavailable." : "";
            PlatformManifest current = await ResolveAsync(reference, reference.Tag, image, cache, 0, false, cancellationToken);
            if (deployed.Digest == current.Digest)
                return new(UpdateStatus.UpToDate, "Configured tag still resolves to the deployed platform manifest." + provenanceNote, deployed.Digest, current.Digest);
            if (deployed.ConfigDigest == current.ConfigDigest)
                return new(UpdateStatus.Unknown, "Manifest changed but image configuration did not; no reliable image update inferred.", deployed.Digest, current.Digest);

            await VerifyConfigAsync(reference, current, image, cancellationToken);
            return new(UpdateStatus.UpdateAvailable, "Configured tag resolves to a different image for the deployed platform." + provenanceNote, deployed.Digest, current.Digest);
        }
        catch (RegistryException exception) { return exception.Result; }
        catch (JsonException) { return new(UpdateStatus.Unknown, "Registry returned malformed image metadata."); }
    }

    private async Task VerifyConfigAsync(ImageReference reference, PlatformManifest manifest, DockerImageRow image,
        CancellationToken cancellationToken)
    {
        RegistryDocument config = await registry.GetAsync(reference.Registry!, reference.Repository!, manifest.ConfigDigest, true, cancellationToken);
        if (config.Bytes.LongLength != manifest.ConfigSize)
            throw Unknown("Image configuration size disagrees with its manifest descriptor.");
        using JsonDocument document = JsonValue.Parse(config.Bytes);
        JsonElement root = document.RootElement;
        if (!MatchesPlatform(root, image, allowMissingVariant: manifest.HasPlatformDescriptor))
            throw Unknown("Image configuration platform cannot be matched reliably to the deployed platform.");
        if (!root.TryGetProperty("rootfs", out var rootfs) || JsonValue.String(rootfs, "type") != "layers"
            || !rootfs.TryGetProperty("diff_ids", out var diffIds) || diffIds.ValueKind != JsonValueKind.Array
            || diffIds.GetArrayLength() != manifest.LayerCount
            || diffIds.EnumerateArray().Any(d => d.ValueKind != JsonValueKind.String || !ImageReference.IsSupportedDigest(d.GetString()!)))
            throw Unknown("Image configuration has inconsistent filesystem metadata.");
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
