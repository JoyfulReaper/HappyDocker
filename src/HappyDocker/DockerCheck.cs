namespace HappyDocker;

public static class DockerCheck
{
    public static async Task<int> RunAsync(Func<string[], Task<DockerCommandResult>> runDocker,
        RegistryClient registry, TextWriter output, TextWriter error, CancellationToken cancellationToken = default)
        => (await RunObservedAsync(runDocker, registry, output, error, cancellationToken)).InventoryExitCode;

    public static async Task<FindingRun> RunObservedAsync(Func<string[], Task<DockerCommandResult>> runDocker,
        RegistryClient registry, TextWriter output, TextWriter error, CancellationToken cancellationToken = default,
        VersionDiscoveryCache? discoveryCache = null, TimeSpan? discoveryBudget = null)
    {
        DateTimeOffset observedAt = DateTimeOffset.UtcNow;
        DockerInventory inventory = await DockerScan.ReadAsync(runDocker, error);
        var checker = new RegistryUpdateChecker(registry, reuseResponses: true);
        FindingRun mutable = await ObserveInventoryAsync(inventory, checker, observedAt, output, error, cancellationToken);
        if (inventory.Containers.Count == 0) return mutable with { HasFullHostCoverage = inventory.CompleteContainerInventory };
        output.WriteLine();
        output.WriteLine("Version discovery");
        FindingRun patches = await DockerVersions.ObserveInventoryAsync(inventory, registry, checker, null, observedAt,
            output, error, cancellationToken, discoveryCache, discoveryBudget);
        return new(inventory.ExitCode, [.. mutable.Observations, .. patches.Observations])
            { HasFullHostCoverage = inventory.CompleteContainerInventory };
    }

    public static async Task<int> RunAsync(Func<string[], Task<DockerCommandResult>> runDocker,
        RegistryUpdateChecker checker, TextWriter output, TextWriter error, CancellationToken cancellationToken = default)
        => (await RunObservedAsync(runDocker, checker, output, error, cancellationToken)).InventoryExitCode;

    public static async Task<FindingRun> RunObservedAsync(Func<string[], Task<DockerCommandResult>> runDocker,
        RegistryUpdateChecker checker, TextWriter output, TextWriter error, CancellationToken cancellationToken = default)
    {
        DateTimeOffset observedAt = DateTimeOffset.UtcNow;
        DockerInventory inventory = await DockerScan.ReadAsync(runDocker, error);
        return await ObserveInventoryAsync(inventory, checker, observedAt, output, error, cancellationToken);
    }

    private static async Task<FindingRun> ObserveInventoryAsync(DockerInventory inventory, RegistryUpdateChecker checker,
        DateTimeOffset observedAt, TextWriter output, TextWriter error, CancellationToken cancellationToken)
    {
        if (inventory.Containers.Count == 0)
        {
            if (inventory.ExitCode == 0) output.WriteLine("No running containers found.");
            return new(inventory.ExitCode, []);
        }
        Dictionary<string, DockerImageRow> images = DockerScan.IndexImages(inventory.Images, error);
        var observations = new List<FindingObservation>();
        var results = new Dictionary<(string? ImageId, string? Reference, string? Platform, string? Descriptor), UpdateResult>();
        output.WriteLine($"{"CONTAINER",-24} {"IMAGE",-58} RESULT");
        foreach (DockerInspectRow container in inventory.Containers)
        {
            images.TryGetValue(container.ImageId ?? "", out DockerImageRow? image);
            cancellationToken.ThrowIfCancellationRequested();
            var key = (container.ImageId, container.ConfiguredImage, container.Platform,
                DockerImageIdentity.Present(container.ImageManifestDescriptor) ? container.ImageManifestDescriptor!.Value.GetRawText() : null);
            if (!results.TryGetValue(key, out UpdateResult? result))
            {
                result = await checker.CheckAsync(container, image, cancellationToken);
                results.Add(key, result);
            }
            output.WriteLine($"{container.Name.TrimStart('/'),-24} {container.ConfiguredImage ?? "<unknown>",-58} {Label(result.Status)}");
            output.WriteLine($"  {result.Reason}");
            if (result.DeployedManifest is not null) output.WriteLine($"  Deployed platform manifest: {result.DeployedManifest}");
            if (result.CurrentManifest is not null) output.WriteLine($"  Current platform manifest:  {result.CurrentManifest}");
            if (result.RetryAfter is not null) output.WriteLine($"  Retry after: {result.RetryAfter:O}");
            FindingEvidence evidence = result.Status switch
            {
                UpdateStatus.UpdateAvailable when result.DeployedManifest is not null && result.CurrentManifest is not null => FindingEvidence.Present,
                UpdateStatus.UpToDate when result.DeployedManifest is not null => FindingEvidence.Absent,
                UpdateStatus.UnsupportedRegistry => FindingEvidence.NotApplicable,
                UpdateStatus.Skipped when !result.SkippedForInsufficientEvidence => FindingEvidence.NotApplicable,
                _ => FindingEvidence.Incomplete
            };
            observations.Add(FindingObservation.ForContainer(container, ImageReference.Parse(container.ConfiguredImage),
                FindingKind.MutableTag, observedAt, evidence, result.CurrentManifest,
                evidence is FindingEvidence.Present or FindingEvidence.Absent ? true : null, result.DeployedManifest));
        }
        // Findings are report data. Docker inventory errors retain their nonzero exit code.
        return new(inventory.ExitCode, observations);
    }

    public static string Label(UpdateStatus status) => status switch
    {
        UpdateStatus.UpToDate => "Up to date",
        UpdateStatus.UpdateAvailable => "Update available",
        UpdateStatus.Unknown => "Unknown / insufficient metadata",
        UpdateStatus.UnsupportedRegistry => "Unsupported registry",
        UpdateStatus.AuthenticationRequired => "Authentication required",
        UpdateStatus.RegistryUnavailable => "Registry unavailable",
        _ => "Skipped"
    };
}
