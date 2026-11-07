using System.Text.Json;

namespace HappyDocker;

public static class DockerVulnerabilities
{
    private enum ImageStore { Unknown, Legacy, Containerd }

    public static async Task<int> RunAsync(Func<string[], Task<DockerCommandResult>> runDocker, TrivyScanner scanner,
        TextWriter output, TextWriter error, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        DockerInventory inventory = await DockerScan.ReadAsync(runDocker, error);
        if (inventory.Containers.Count == 0)
        {
            if (inventory.ExitCode == 0) output.WriteLine("No running containers found.");
            return inventory.ExitCode;
        }

        Dictionary<string, DockerImageRow> images = DockerScan.IndexImages(inventory.Images, error);
        var inspectedManifests = new Dictionary<string, ManifestInspection?>(StringComparer.Ordinal);
        var results = new Dictionary<(string ImageId, string Platform), VulnerabilityScanResult>();
        ImageStore? store = null;
        bool incomplete = false;
        bool completed = false;
        foreach (DockerInspectRow container in inventory.Containers)
        {
            cancellationToken.ThrowIfCancellationRequested();
            images.TryGetValue(container.ImageId ?? "", out DockerImageRow? image);
            var (target, reason) = await ResolveAsync(container, image);
            cancellationToken.ThrowIfCancellationRequested();
            VulnerabilityScanResult result;
            if (target is null)
                result = TrivyScanner.Incomplete(reason);
            else if (!results.TryGetValue((target.ImageId, target.Platform), out result!))
            {
                result = await scanner.ScanAsync(target, cancellationToken);
                results.Add((target.ImageId, target.Platform), result);
            }

            incomplete |= result.Status == VulnerabilityScanStatus.Incomplete;
            completed |= result.Status != VulnerabilityScanStatus.Incomplete;
            WriteReport(container, target, result, output);
        }

        if (completed)
        {
            DateTimeOffset? updated = await scanner.DatabaseUpdatedAtAsync(cancellationToken);
            output.WriteLine(updated is { } timestamp
                ? $"Trivy vulnerability database cache updated at {timestamp.UtcDateTime:O} (read after scanning)."
                : "Trivy vulnerability database freshness was unavailable.");
        }
        output.WriteLine("Findings describe vulnerable packages present in an image. Application reachability and exploitability require separate analysis.");
        return inventory.ExitCode != 0 ? inventory.ExitCode : incomplete ? 1 : 0;

        async Task<(DeployedScanTarget? Target, string Reason)> ResolveAsync(DockerInspectRow container, DockerImageRow? image)
        {
            if (image?.Id is not { } id || !ImageReference.IsSupportedDigest(id))
                return (null, "Docker did not provide a verified immutable image ID.");
            ImageDescriptor? root = DockerImageIdentity.ReadDescriptor(image.Descriptor);
            ImageDescriptor? child = DockerImageIdentity.ReadDescriptor(container.ImageManifestDescriptor);
            if ((DockerImageIdentity.Present(image.Descriptor) && root?.Digest != id)
                || (DockerImageIdentity.Present(container.ImageManifestDescriptor) && child?.Kind != ImageDigestKind.PlatformManifest)
                || (root?.Kind == ImageDigestKind.PlatformManifest && child is not null && child.Digest != id))
                return (null, "Docker reported inconsistent image descriptors.");

            if (root?.Kind == ImageDigestKind.ImageIndex && (child is null || child.Digest == id))
                return (null, "The image index has no verified deployed child manifest.");
            ImageDescriptor? manifest = root?.Kind == ImageDigestKind.PlatformManifest ? root
                : root?.Kind == ImageDigestKind.Configuration ? null : child;
            string[]? diffIds = null;
            if (manifest is not null)
            {
                if (!inspectedManifests.TryGetValue(manifest.Digest, out ManifestInspection? selected))
                {
                    selected = await InspectManifestAsync(runDocker, manifest.Digest);
                    inspectedManifests.Add(manifest.Digest, selected);
                }
                ImageDescriptor? selectedDescriptor = DockerImageIdentity.ReadDescriptor(selected?.Descriptor);
                if (selected?.Id != manifest.Digest || selectedDescriptor is not { Kind: ImageDigestKind.PlatformManifest }
                    || selectedDescriptor.Digest != manifest.Digest || selectedDescriptor.MediaType != manifest.MediaType
                    || selectedDescriptor.Size != manifest.Size
                    || (child is not null && (selectedDescriptor.MediaType != child.MediaType || selectedDescriptor.Size != child.Size)))
                    return (null, "Docker could not resolve the deployed platform manifest as an immutable local image.");
                if (selected.RootFS is not { Type: "layers" } filesystem
                    || (filesystem.Layers ?? []).Any(layer => layer is null || !ImageReference.IsSupportedDigest(layer)))
                    return (null, "Docker did not provide verifiable filesystem layer metadata for the deployed manifest.");
                diffIds = filesystem.Layers ?? [];
                image = new(selected.Id, selected.Os, selected.Architecture, selected.Variant);
                id = manifest.Digest;
                root = selectedDescriptor;
            }
            else if (root is null)
            {
                store ??= await DetectStoreAsync(runDocker);
                if (store != ImageStore.Legacy)
                    return (null, store == ImageStore.Containerd
                        ? "Docker uses the containerd image store but did not provide a deployed platform manifest descriptor."
                        : "Docker image store is unknown and no deployed platform manifest descriptor was available.");
            }

            string? variant = !string.IsNullOrEmpty(image.Variant) ? image.Variant
                : DescriptorVariant(child) ?? DescriptorVariant(manifest) ?? DescriptorVariant(root);
            if (string.IsNullOrWhiteSpace(image.Os) || string.IsNullOrWhiteSpace(image.Architecture)
                || (!string.IsNullOrWhiteSpace(container.Platform) && container.Platform != image.Os)
                || !MatchesPlatform(root?.Platform, image, variant) || !MatchesPlatform(manifest?.Platform, image, variant)
                || !MatchesPlatform(child?.Platform, image, variant))
                return (null, "Docker did not verify the deployed OS, architecture, and variant.");
            return (new(id, image.Os, image.Architecture, variant,
                manifest is null ? ImageDigestKind.Configuration : ImageDigestKind.PlatformManifest, diffIds), "");
        }
    }

    private static async Task<ManifestInspection?> InspectManifestAsync(Func<string[], Task<DockerCommandResult>> runDocker, string digest)
    {
        const string format = """{"Id":{{json .Id}},"Os":{{json .Os}},"Architecture":{{json .Architecture}},"Variant":{{json (index . "Variant")}},"Descriptor":{{json (index . "Descriptor")}},"RootFS":{{json (index . "RootFS")}}}""";
        DockerCommandResult result = await runDocker(["image", "inspect", "--format", format, digest]);
        if (result.ExitCode != 0) return null;
        try
        {
            List<ManifestInspection> rows = DockerJsonLines.Parse<ManifestInspection>(result.Stdout);
            return rows.Count == 1 ? rows[0] : null;
        }
        catch (JsonException) { return null; }
    }

    private static async Task<ImageStore> DetectStoreAsync(Func<string[], Task<DockerCommandResult>> runDocker)
    {
        const string format = """{"Driver":{{json .Driver}},"DriverStatus":{{json .DriverStatus}}}""";
        DockerCommandResult result = await runDocker(["info", "--format", format]);
        if (result.ExitCode != 0) return ImageStore.Unknown;
        try
        {
            using JsonDocument json = JsonValue.Parse(System.Text.Encoding.UTF8.GetBytes(result.Stdout));
            StoreInspection? info = json.Deserialize<StoreInspection>();
            if (info?.DriverStatus is not { Length: > 0 } status
                || status.Any(row => row is not { Length: 2 } || string.IsNullOrWhiteSpace(row[0]) || row[1] is null))
                return ImageStore.Unknown;

            var driverTypes = status.Where(row => string.Equals(row![0], "driver-type", StringComparison.OrdinalIgnoreCase)).ToArray();
            if (driverTypes.Length > 0)
                return driverTypes.Length == 1 && driverTypes[0]![1] == "io.containerd.snapshotter.v1"
                    ? ImageStore.Containerd : ImageStore.Unknown;

            // Require affirmative classic graph-driver evidence. Missing status also occurs with some legacy drivers.
            return info.Driver == "overlay2" && status.Any(row => row![0] == "Backing Filesystem" && !string.IsNullOrWhiteSpace(row[1]))
                ? ImageStore.Legacy : ImageStore.Unknown;
        }
        catch (JsonException) { return ImageStore.Unknown; }
    }

    private sealed record StoreInspection(string? Driver, string?[]?[]? DriverStatus);
    private sealed record ManifestInspection(string? Id, string? Os, string? Architecture, string? Variant,
        JsonElement? Descriptor, RootFilesystem? RootFS);
    private sealed record RootFilesystem(string? Type, string[]? Layers = null);

    private static string? DescriptorVariant(ImageDescriptor? descriptor) =>
        descriptor?.Platform is { } platform && JsonValue.String(platform, "variant") is { Length: > 0 } variant ? variant : null;

    private static bool MatchesPlatform(JsonElement? descriptorPlatform, DockerImageRow image, string? expectedVariant)
    {
        if (!DockerImageIdentity.Present(descriptorPlatform)) return true;
        JsonElement platform = descriptorPlatform!.Value;
        string? variant = JsonValue.String(platform, "variant");
        return JsonValue.String(platform, "os") == image.Os
            && JsonValue.String(platform, "architecture") == image.Architecture
            && (string.IsNullOrEmpty(variant) || variant == expectedVariant);
    }

    private static void WriteReport(DockerInspectRow container, DeployedScanTarget? target, VulnerabilityScanResult result, TextWriter output)
    {
        output.WriteLine($"{Display(container.Name.TrimStart('/'))}  {Display(container.ConfiguredImage ?? "<unknown>")}");
        if (target is not null) output.WriteLine($"  {Display(target.Platform)}  {target.ImageId}");
        output.WriteLine($"  {(result.Status == VulnerabilityScanStatus.Incomplete ? "Scan incomplete. " : "")}{result.Detail}");
        if (result.Status is not (VulnerabilityScanStatus.Findings or VulnerabilityScanStatus.NoFindings)) return;
        var counts = result.Findings.ToLookup(finding => finding.Severity);
        output.WriteLine($"  CRITICAL {counts["CRITICAL"].Count()}  HIGH {counts["HIGH"].Count()}  MEDIUM {counts["MEDIUM"].Count()}  LOW {counts["LOW"].Count()}  UNKNOWN {counts["UNKNOWN"].Count()}");
        foreach (VulnerabilityFinding finding in counts["CRITICAL"].Concat(counts["HIGH"]))
        {
            string fix = string.IsNullOrWhiteSpace(finding.FixedVersion) ? "no known fix" : $"fixed in {Display(finding.FixedVersion)}";
            string status = string.IsNullOrWhiteSpace(finding.Status) ? "" : $" ({Display(finding.Status)})";
            output.WriteLine($"  {finding.Severity} {Display(finding.Id)}  {Display(finding.Package)} {Display(finding.InstalledVersion)}  [{fix}]{status}");
            output.WriteLine($"    {Display(finding.Target)} ({Display(finding.PackageType)})");
            if (Uri.TryCreate(finding.SourceUrl, UriKind.Absolute, out Uri? url) && (url.Scheme is "https" or "http") && url.UserInfo.Length == 0)
                output.WriteLine($"    {Display(finding.SourceUrl!)}");
        }
    }

    private static string Display(string text) => new(text.Select(c => char.IsControl(c) ? ' ' : c).ToArray());
}
