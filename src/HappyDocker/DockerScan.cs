namespace HappyDocker;

public sealed record DockerCommandResult(int ExitCode, string Stdout, string Stderr);

public static class DockerScan
{
    public static async Task<int> RunAsync(
        Func<string[], Task<DockerCommandResult>> runDocker, TextWriter output, TextWriter error)
    {
        DockerCommandResult ps = await runDocker(["ps", "--format", "{{json .}}"]);
        if (ps.ExitCode != 0) { error.WriteLine(ps.Stderr); return ps.ExitCode; }
        var containers = DockerJsonLines.Parse<DockerPsRow>(ps.Stdout);
        if (containers.Count == 0) { output.WriteLine("No running containers found."); return 0; }

        const string inspectFormat =
            """{"Id":{{json .Id}},"Name":{{json .Name}},"ImageId":{{json .Image}},"ConfiguredImage":{{json .Config.Image}},"Platform":{{json .Platform}}}""";
        DockerCommandResult inspect = await runDocker(["inspect", "--type", "container", "--format", inspectFormat,
            .. containers.Select(c => c.ID)]);
        if (inspect.ExitCode != 0) { error.WriteLine(inspect.Stderr); return inspect.ExitCode; }
        var inspected = DockerJsonLines.Parse<DockerInspectRow>(inspect.Stdout);

        const string imageFormat =
            """{"Id":{{json .Id}},"Os":{{json .Os}},"Architecture":{{json .Architecture}},"Variant":{{json (index . "Variant")}},"RepoDigests":{{json (index . "RepoDigests")}}}""";
        string[] imageIds = inspected.Select(c => c.ImageId).Where(id => !string.IsNullOrWhiteSpace(id))
            .Select(id => id!).Distinct(StringComparer.Ordinal).ToArray();
        DockerCommandResult images = imageIds.Length == 0 ? new(0, "", "")
            : await runDocker(["image", "inspect", "--format", imageFormat, .. imageIds]);
        // Docker can return partial metadata when an image disappears during the scan.
        if (images.ExitCode != 0) error.WriteLine(images.Stderr);
        WriteReport(inspected, DockerJsonLines.Parse<DockerImageRow>(images.Stdout), output, error);
        return images.ExitCode;
    }

    public static void WriteReport(IEnumerable<DockerInspectRow> containers, IEnumerable<DockerImageRow> images,
        TextWriter output, TextWriter error)
    {
        var imagesById = new Dictionary<string, DockerImageRow>(StringComparer.Ordinal);
        foreach (var group in images.Where(i => !string.IsNullOrWhiteSpace(i.Id)).GroupBy(i => i.Id!, StringComparer.Ordinal))
        {
            DockerImageRow first = group.First();
            if (group.Any(i => i.Os != first.Os || i.Architecture != first.Architecture || i.Variant != first.Variant
                || !DigestSet(i).SequenceEqual(DigestSet(first))))
            {
                error.WriteLine($"Conflicting image metadata for {group.Key}; reporting metadata as unknown.");
                continue;
            }
            imagesById.Add(group.Key, first);
        }

        output.WriteLine($"{"CONTAINER",-24} {"PLATFORM",-18} {"IMAGE",-58} IMAGE ID");
        foreach (DockerInspectRow container in containers)
        {
            imagesById.TryGetValue(container.ImageId ?? "", out DockerImageRow? image);
            string platform = image is null ? Known(container.Platform) :
                $"{Known(image.Os)}/{Known(image.Architecture)}{(string.IsNullOrWhiteSpace(image.Variant) ? "" : $"/{image.Variant}")}";
            output.WriteLine($"{container.Name.TrimStart('/'),-24} {platform,-18} {Known(container.ConfiguredImage),-58} {Known(container.ImageId)}");
            string[] digests = image is null ? [] : DigestSet(image).ToArray();
            output.WriteLine($"  Repository digests: {(image is null ? "<unknown>" : digests.Length == 0 ? "<none>" : string.Join(", ", digests))}");

            ImageReference reference = ImageReference.Parse(container.ConfiguredImage).WithMetadata(digests);
            output.WriteLine($"  Reference: {reference.Kind}{(reference.IsDigestPinned ? " (digest-pinned)" : "")}; {reference.Normalized ?? "<none>"}");
            output.WriteLine($"  {reference.Reason}");
        }
    }

    private static IEnumerable<string> DigestSet(DockerImageRow image) =>
        (image.RepoDigests ?? []).Where(d => !string.IsNullOrWhiteSpace(d)).Select(d => d!)
            .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal);

    private static string Known(string? value) => string.IsNullOrWhiteSpace(value) ? "<unknown>" : value;
}

internal sealed record DockerPsRow(string ID, string Names, string Image);

public sealed record DockerInspectRow(
    string Id,
    string Name,
    string? ImageId = null,
    string? ConfiguredImage = null,
    string? Platform = null);
