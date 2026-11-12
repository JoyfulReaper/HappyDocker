namespace HappyDocker;

public static class DockerVersions
{
    private const string Usage = "Usage: happydocker versions --repo <repository> [--repo <repository> ...]";

    public static async Task<int> RunAsync(string[] options, Func<string[], Task<DockerCommandResult>> runDocker,
        RegistryClient registry, TextWriter output, TextWriter error, CancellationToken cancellationToken = default)
        => (await RunObservedAsync(options, runDocker, registry, output, error, cancellationToken)).InventoryExitCode;

    public static async Task<FindingRun> RunObservedAsync(string[] options, Func<string[], Task<DockerCommandResult>> runDocker,
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

        DateTimeOffset observedAt = DateTimeOffset.UtcNow;
        DockerInventory inventory = await DockerScan.ReadAsync(runDocker, error);
        if (inventory.Containers.Count == 0 && inventory.ExitCode != 0) return new(inventory.ExitCode, []);
        return await ObserveInventoryAsync(inventory, registry, new RegistryUpdateChecker(registry, reuseResponses: true),
            selected, observedAt, output, error, cancellationToken);
    }

    internal static async Task<FindingRun> ObserveInventoryAsync(DockerInventory inventory, RegistryClient registry,
        RegistryUpdateChecker checker, Dictionary<string, ImageReference>? selected, DateTimeOffset observedAt,
        TextWriter output, TextWriter error, CancellationToken cancellationToken, VersionDiscoveryCache? discoveryCache = null,
        TimeSpan? discoveryBudget = null)
    {
        Dictionary<string, DockerImageRow> images = DockerScan.IndexImages(inventory.Images, error);
        var matched = new HashSet<string>(StringComparer.Ordinal);
        var observations = new List<FindingObservation>();
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        TimeSpan budget = discoveryBudget ?? TimeSpan.FromMinutes(1);
        deadline.CancelAfter(budget);
        DateTimeOffset started = discoveryCache?.Now ?? DateTimeOffset.UtcNow;
        bool BudgetExpired() => deadline.IsCancellationRequested
            || (discoveryCache?.Now ?? DateTimeOffset.UtcNow) - started >= budget;
        int enumeratedRepositories = 0;
        IEnumerable<IGrouping<string, DockerInspectRow>> groups =
            inventory.Containers.GroupBy(container => RepositoryName(ImageReference.Parse(container.ConfiguredImage)));
        if (selected is null && discoveryCache is not null)
        {
            var attempts = discoveryCache.ReadAttempts();
            groups = groups.OrderBy(group => attempts.GetValueOrDefault(group.Key, long.MinValue))
                .ThenBy(group => group.Key, StringComparer.Ordinal);
        }

        // Grouping keeps at most one bounded tag list in memory while still reusing it for every matching container.
        foreach (var group in groups)
        {
            TagEnumeration? enumeration = null;
            bool attemptRecorded = false;
            var platformResults = new Dictionary<(string Tag, string? Os, string? Arch, string? Variant),
                (bool Verified, string Detail, bool RequestFailed, bool Deferred)>();
            foreach (DockerInspectRow container in group)
            {
                cancellationToken.ThrowIfCancellationRequested();
                ImageReference reference = ImageReference.Parse(container.ConfiguredImage);
                string repository = RepositoryName(reference);
                if (selected is not null && (reference.Repository is null || !selected.ContainsKey(repository))) continue;
                matched.Add(repository);
                var version = PatchVersion.Parse(reference.Tag);
                FindingEvidence evidence = reference.Registry != "docker.io" || reference.IsDigestPinned || version is null
                    ? FindingEvidence.NotApplicable : FindingEvidence.Incomplete;
                if (reference.Kind is ImageReferenceKind.Missing or ImageReferenceKind.Invalid) evidence = FindingEvidence.Incomplete;
                int observationIndex = observations.Count;
                observations.Add(FindingObservation.ForContainer(container, reference, FindingKind.PatchCandidate, observedAt, evidence));
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
                    if (provenance.Kind is ImageProvenanceKind.BuildOnly or ImageProvenanceKind.LocalOrImported)
                        observations[observationIndex] = observations[observationIndex] with { Evidence = FindingEvidence.NotApplicable };
                    output.WriteLine(provenance.Kind == ImageProvenanceKind.BuildOnly
                        ? "  Skipped locally built image."
                        : provenance.Kind == ImageProvenanceKind.LocalOrImported ? $"  Skipped. {provenance.Reason}"
                        : $"  Skipped ambiguous provenance. {provenance.Reason}");
                    continue;
                }
                if (version is null)
                {
                    output.WriteLine("  Skipped unrecognized version tag. Expected a stable major.minor.patch tag with an optional variant.");
                    continue;
                }

                if (enumeration is null)
                {
                    enumeration = discoveryCache?.Read(reference.Repository!);
                    if (enumeration is null)
                    {
                        if (BudgetExpired() || (selected is null && enumeratedRepositories >= 10))
                            enumeration = selected is null
                                ? new([], DeferredReason: "Automatic discovery time or repository budget reached; retry on a later run.")
                                : new([], "Discovery time budget reached; retry on a later run.");
                        else
                        {
                            enumeratedRepositories++;
                            try
                            {
                                DateTimeOffset fetchedAt = discoveryCache?.Now ?? DateTimeOffset.UtcNow;
                                discoveryCache?.MarkAttempt(reference.Repository!, fetchedAt);
                                attemptRecorded = true;
                                enumeration = (await RegistryTagDiscovery.ListAsync(registry, reference.Repository!, deadline.Token))
                                    with { ObservedAt = fetchedAt };
                                discoveryCache?.Save(reference.Repository!, enumeration, fetchedAt);
                            }
                            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                            {
                                enumeration = selected is null
                                    ? new([], DeferredReason: "Discovery time budget reached during enumeration; retry on a later run.")
                                    : new([], "Discovery time budget reached; retry on a later run.");
                            }
                        }
                    }
                }
                if (enumeration.DeferredReason is { } deferred)
                {
                    output.WriteLine($"  Discovery deferred. {deferred}");
                    observations[observationIndex] = observations[observationIndex] with { Evidence = FindingEvidence.Deferred };
                    continue;
                }
                if (enumeration.IncompleteReason is { } reason)
                {
                    output.WriteLine($"  Incomplete enumeration. {reason}");
                    if (enumeration.RetryAfter is { } retry) output.WriteLine($"  Retry after {retry:O}.");
                }
                if (enumeration.CachedAt is { } cached)
                    output.WriteLine($"  Cached tag enumeration from {cached:O}; platform verification runs again.");
                string? tag = version.HighestCandidate(enumeration.Tags);
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
                if (tag is null)
                {
                    output.WriteLine("  No matching newer patch tag found in the tags examined.");
                    if (enumeration.CachedAt is not null)
                    {
                        output.WriteLine("  Cached absence is inconclusive; prior findings are retained until a fresh enumeration.");
                        observations[observationIndex] = observations[observationIndex] with { Evidence = FindingEvidence.NotApplicable };
                    }
                    else if (enumeration.IncompleteReason is null && deployment is not null)
                        observations[observationIndex] = FindingObservation.ForContainer(container, reference,
                            FindingKind.PatchCandidate, enumeration.ObservedAt ?? observedAt, FindingEvidence.Absent);
                    continue;
                }
                bool verified = false;
                bool requestFailed = false;
                bool platformDeferred = false;
                string detail = platformError ?? "";
                if (deployment is not null)
                {
                    DockerImageRow platform = deployment.Image;
                    var key = (tag, platform.Os, platform.Architecture, platform.Variant);
                    if (!platformResults.TryGetValue(key, out var verification))
                    {
                        try
                        {
                            if (selected is null && BudgetExpired())
                                verification = (false, "Discovery budget reached; platform verification deferred.", false, true);
                            else
                            {
                                if (!attemptRecorded)
                                {
                                    discoveryCache?.MarkAttempt(reference.Repository!, discoveryCache.Now);
                                    attemptRecorded = true;
                                }
                                var result = await checker.VerifyCandidatePlatformAsync(reference, tag, platform, deadline.Token);
                                verification = (result.Verified, result.Detail, result.RequestFailed, false);
                            }
                        }
                        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
                        {
                            verification = selected is null
                                ? (false, "Discovery time budget reached; platform verification deferred.", false, true)
                                : (false, "Discovery time budget reached; platform is unverified.", true, false);
                        }
                        platformResults.Add(key, verification);
                    }
                    (verified, detail, requestFailed, platformDeferred) = verification;
                }

                if (platformDeferred)
                {
                    output.WriteLine($"  Discovery deferred. Candidate {tag} awaits platform verification. {detail}");
                    if (enumeration.IncompleteReason is null)
                        observations[observationIndex] = observations[observationIndex] with { Evidence = FindingEvidence.Deferred };
                    continue;
                }
                output.WriteLine($"  Candidate {tag} ({(verified ? "platform verified" : "platform unverified")}). {detail}");
                output.WriteLine("  A patch candidate does not establish compatibility or security.");
                if (enumeration.IncompleteReason is null)
                    observations[observationIndex] = FindingObservation.ForContainer(container, reference, FindingKind.PatchCandidate,
                        enumeration.ObservedAt ?? observedAt, FindingEvidence.Present, tag, verified,
                        deployment?.ContainerDescriptor?.Digest ?? deployment?.Descriptor?.Digest)
                        with { PlatformRequestFailed = requestFailed };
            }
        }

        if (selected is not null)
        {
            foreach (var (repository, reference) in selected)
                if (!matched.Contains(repository))
                    output.WriteLine(reference.Registry == "docker.io"
                        ? $"{repository} has no matching running containers."
                        : $"{repository} uses an unsupported registry. Version discovery supports Docker Hub.");
        }
        return new(inventory.ExitCode, observations);
    }

    private static string RepositoryName(ImageReference reference) => $"{reference.Registry}/{reference.Repository}";

    private static FindingRun InvalidOptions(TextWriter error)
    {
        error.WriteLine(Usage);
        error.WriteLine("Supply repository names without tags or digests, for example docker.io/library/nats.");
        return new(1, []);
    }
}
