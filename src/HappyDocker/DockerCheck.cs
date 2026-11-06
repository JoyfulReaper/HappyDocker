namespace HappyDocker;

public static class DockerCheck
{
    public static async Task<int> RunAsync(Func<string[], Task<DockerCommandResult>> runDocker,
        RegistryUpdateChecker checker, TextWriter output, TextWriter error, CancellationToken cancellationToken = default)
    {
        DockerInventory inventory = await DockerScan.ReadAsync(runDocker, error);
        if (inventory.Containers.Count == 0)
        {
            if (inventory.ExitCode == 0) output.WriteLine("No running containers found.");
            return inventory.ExitCode;
        }
        Dictionary<string, DockerImageRow> images = DockerScan.IndexImages(inventory.Images, error);
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
        }
        // Findings are report data. Docker inventory errors retain their nonzero exit code.
        return inventory.ExitCode;
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
