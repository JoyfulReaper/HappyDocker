namespace HappyDocker;

public static class DockerCheck
{
    public static async Task<int> RunAsync(Func<string[], Task<DockerCommandResult>> runDocker,
        RegistryUpdateChecker checker, TextWriter output, TextWriter error, CancellationToken cancellationToken = default)
        => (await RunObservedAsync(runDocker, checker, output, error, cancellationToken)).InventoryExitCode;

    public static async Task<FindingRun> RunObservedAsync(Func<string[], Task<DockerCommandResult>> runDocker,
        RegistryUpdateChecker checker, TextWriter output, TextWriter error, CancellationToken cancellationToken = default)
    {
        DateTimeOffset observedAt = DateTimeOffset.UtcNow;
        DockerInventory inventory = await DockerScan.ReadAsync(runDocker, error);
        if (inventory.Containers.Count == 0)
        {
            if (inventory.ExitCode == 0) output.WriteLine("No running containers found.");
            return new(inventory.ExitCode, []);
        }
        Dictionary<string, DockerImageRow> images = DockerScan.IndexImages(inventory.Images, error);
        var observations = new List<FindingObservation>();
        output.WriteLine($"{"CONTAINER",-24} {"IMAGE",-58} RESULT");
        foreach (DockerInspectRow container in inventory.Containers)
        {
            images.TryGetValue(container.ImageId ?? "", out DockerImageRow? image);
            UpdateResult result = await checker.CheckAsync(container, image, cancellationToken);
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
