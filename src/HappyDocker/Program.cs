using HappyDocker;
using System.Diagnostics;


if (args.Length != 1 || args[0] != "scan")
{
    Console.Error.WriteLine("Usage: happydocker scan");
    return 1;
}

var (exitCode, stdout, stderr) = await RunDockerAsync("ps", "--format", "{{json .}}");

if (exitCode != 0)
{
    Console.Error.WriteLine(stderr);
    return exitCode;
}

List<DockerPsRow> containers = DockerJsonLines.Parse<DockerPsRow>(stdout);

if (containers.Count == 0)
{
    Console.WriteLine("No running containers found.");
    return 0;
}

const string inspectFormat =
    """{"Id":{{json .Id}},"Name":{{json .Name}},"ImageId":{{json .Image}},"ConfiguredImage":{{json .Config.Image}},"Platform":{{json .Platform}}}""";

var inspectArguments = new List<string>
{
    "inspect",
    "--type",
    "container",
    "--format",
    inspectFormat
};

inspectArguments.AddRange(containers.Select(container => container.ID));

var (inspectExitCode, inspectStdout, inspectStderr) = await RunDockerAsync(inspectArguments.ToArray());

if (inspectExitCode != 0)
{
    Console.Error.WriteLine(inspectStderr);
    return inspectExitCode;
}

List<DockerInspectRow> inspectedContainers = DockerJsonLines.Parse<DockerInspectRow>(inspectStdout);

const string imageInspectFormat =
    """{"Id":{{json .Id}},"Os":{{json .Os}},"Architecture":{{json .Architecture}},"Variant":{{json (index . "Variant")}},"RepoDigests":{{json (index . "RepoDigests")}}}""";

var imageInspectArguments = new List<string>
{
    "image",
    "inspect",
    "--format",
    imageInspectFormat
};

// Multiple containers may share the same image.
imageInspectArguments.AddRange(inspectedContainers.Select(c => c.ImageId).Distinct());

var (imageExitCode, imageStdout, imageStderr) = await RunDockerAsync(imageInspectArguments.ToArray());

if (imageExitCode != 0)
{
    Console.Error.WriteLine(imageStderr);
    return imageExitCode;
}

List<DockerImageRow> images = DockerJsonLines.Parse<DockerImageRow>(imageStdout);
var imagesById = images.ToDictionary(image => image.Id, StringComparer.Ordinal);

Console.WriteLine($"{"CONTAINER",-24} {"PLATFORM",-18} {"IMAGE",-58} IMAGE ID");

foreach (DockerInspectRow container in inspectedContainers)
{
    DockerImageRow image = imagesById[container.ImageId];

    string platform = $"{image.Os}/{image.Architecture}";

    if (!string.IsNullOrEmpty(image.Variant))
    {
        platform += $"/{image.Variant}";
    }

    Console.WriteLine($"{container.Name.TrimStart('/'),-24} {platform,-18} {container.ConfiguredImage,-58} {container.ImageId}");

    string digests = image.RepoDigests is { Length: > 0 }
        ? string.Join(", ", image.RepoDigests)
        : "<none>";

    Console.WriteLine($"  Repository digests: {digests}");
}

return 0;

static async Task<(int ExitCode, string Stdout, string Stderr)> RunDockerAsync(params string[] arguments)
{
    var startInfo = new ProcessStartInfo("docker")
    {
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
        CreateNoWindow = true
    };

    foreach (string argument in arguments)
    {
        startInfo.ArgumentList.Add(argument);
    }

    using var process = Process.Start(startInfo)
        ?? throw new InvalidOperationException("Failed to start Docker.");

    Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
    Task<string> stderrTask = process.StandardError.ReadToEndAsync();

    await process.WaitForExitAsync();

    return (
        process.ExitCode,
        await stdoutTask,
        await stderrTask);
}

internal sealed record DockerPsRow(
    string ID,
    string Names,
    string Image);

public sealed record DockerInspectRow(
    string Id,
    string Name,
    string ImageId,
    string ConfiguredImage,
    string Platform);