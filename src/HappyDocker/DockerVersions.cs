namespace HappyDocker;

public static class DockerVersions
{
    private const string Usage = "Usage: happydocker versions --repo <repository> [--repo <repository> ...]";

    public static async Task<int> RunAsync(string[] options, Func<string[], Task<DockerCommandResult>> runDocker,
        RegistryClient registry, TextWriter output, TextWriter error, CancellationToken cancellationToken = default)
    {
        var selected = new Dictionary<string, ImageReference>(StringComparer.Ordinal);
        for (int index = 0; index < options.Length; index += 2)
        {
            if (options[index] != "--repo" || index + 1 >= options.Length)
                return InvalidOptions(error);
            string value = options[index + 1];
            ImageReference reference = ImageReference.Parse(value);
            if (reference.Repository is null || reference.IsDigestPinned || value.LastIndexOf(':') > value.LastIndexOf('/'))
                return InvalidOptions(error);
            selected.TryAdd(RepositoryName(reference), reference);
        }
        if (selected.Count == 0) return InvalidOptions(error);

        DockerInventory inventory = await DockerScan.ReadAsync(runDocker, error);
        if (inventory.Containers.Count == 0 && inventory.ExitCode != 0) return inventory.ExitCode;
        Dictionary<string, DockerImageRow> images = DockerScan.IndexImages(inventory.Images, error);
        var checker = new RegistryUpdateChecker(registry);
        var enumerations = new Dictionary<string, TagEnumeration>(StringComparer.Ordinal);
        var platformResults = new Dictionary<(string Repository, string Tag, string? Os, string? Arch, string? Variant),
            (bool Verified, string Detail)>();
        var matched = new HashSet<string>(StringComparer.Ordinal);

        foreach (DockerInspectRow container in inventory.Containers)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ImageReference reference = ImageReference.Parse(container.ConfiguredImage);
            string repository = RepositoryName(reference);
            if (reference.Repository is null || !selected.ContainsKey(repository)) continue;
            matched.Add(repository);
            output.WriteLine($"{container.Name.TrimStart('/')}  {repository}  Configured tag {reference.Tag ?? "<none>"}");

            if (reference.Registry != "docker.io")
            {
                output.WriteLine("  Unsupported registry. Version discovery supports Docker Hub.");
                continue;
            }
            if (reference.IsDigestPinned)
            {
                output.WriteLine("  Skipped digest-pinned reference.");
                continue;
            }
            if (container.ImageId is not { } imageId || !ImageReference.IsSupportedDigest(imageId)
                || !images.TryGetValue(imageId, out DockerImageRow? image))
            {
                output.WriteLine("  Skipped because deployed image metadata is missing or inconsistent.");
                continue;
            }
            ImageProvenance provenance = DockerImageIdentity.Provenance(reference, image);
            if (provenance.Kind != ImageProvenanceKind.Pulled)
            {
                output.WriteLine(provenance.Kind == ImageProvenanceKind.BuildOnly
                    ? "  Skipped locally built image."
                    : $"  Skipped ambiguous provenance. {provenance.Reason}");
                continue;
            }
            if (PatchVersion.Parse(reference.Tag) is not { } version)
            {
                output.WriteLine("  Skipped unrecognized version tag. Expected a stable major.minor.patch tag with an optional variant.");
                continue;
            }

            if (!enumerations.TryGetValue(repository, out TagEnumeration? enumeration))
            {
                enumeration = await RegistryTagDiscovery.ListAsync(registry, reference.Repository, cancellationToken);
                enumerations.Add(repository, enumeration);
            }
            if (enumeration.IncompleteReason is { } reason)
            {
                output.WriteLine($"  Incomplete enumeration. {reason}");
                if (enumeration.RetryAfter is { } retry) output.WriteLine($"  Retry after {retry:O}.");
            }
            string? tag = version.HighestCandidate(enumeration.Tags);
            if (tag is null)
            {
                output.WriteLine("  No matching newer patch tag found in the tags examined.");
                continue;
            }

            var (deployment, platformError) = RegistryUpdateChecker.ReadDeployment(container, image);
            if (deployment?.Descriptor?.Kind == ImageDigestKind.ImageIndex
                && !DockerImageIdentity.Present(deployment.ContainerDescriptor?.Platform))
            {
                deployment = null;
                platformError = "The deployed index child lacks explicit platform metadata.";
            }
            if (deployment is { Descriptor.Kind: ImageDigestKind.PlatformManifest, ContainerDescriptor: not null }
                && deployment.Descriptor.Digest != deployment.ContainerDescriptor.Digest)
            {
                deployment = null;
                platformError = "Container and image manifest descriptors disagree.";
            }
            bool verified = false;
            string detail = platformError ?? "";
            if (deployment is not null)
            {
                DockerImageRow platform = deployment.Image;
                var key = (repository, tag, platform.Os, platform.Architecture, platform.Variant);
                if (!platformResults.TryGetValue(key, out var verification))
                {
                    verification = await checker.VerifyCandidatePlatformAsync(reference, tag, platform, cancellationToken);
                    platformResults.Add(key, verification);
                }
                (verified, detail) = verification;
            }

            output.WriteLine($"  Candidate {tag} ({(verified ? "platform verified" : "platform unverified")}). {detail}");
            output.WriteLine("  A patch candidate does not establish compatibility or security.");
        }

        foreach (var (repository, reference) in selected)
            if (!matched.Contains(repository))
                output.WriteLine(reference.Registry == "docker.io"
                    ? $"{repository} has no matching running containers."
                    : $"{repository} uses an unsupported registry. Version discovery supports Docker Hub.");
        return inventory.ExitCode;
    }

    private static string RepositoryName(ImageReference reference) => $"{reference.Registry}/{reference.Repository}";

    private static int InvalidOptions(TextWriter error)
    {
        error.WriteLine(Usage);
        error.WriteLine("Supply repository names without tags or digests, for example docker.io/library/nats.");
        return 1;
    }
}
