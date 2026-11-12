using HappyDocker;
using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;

if (args.Length == 0 || args[0] is not ("scan" or "check" or "versions") || (args[0] == "scan" && args.Length != 1))
{
    WriteUsage();
    return 1;
}

if (!FindingStateOptions.TryParse(args[1..], out FindingStateOptions options)
    || (args[0] == "check" && options.CommandArguments.Length != 0))
{
    WriteUsage();
    return 1;
}

try
{
    if (args[0] == "scan")
        return await DockerScan.RunAsync(arguments => RunDockerAsync(arguments), Console.Out, Console.Error);
    GhcrCredentials? credentials = GhcrCredentials.Load(
        Environment.GetEnvironmentVariable(GhcrCredentials.UsernameVariable),
        Environment.GetEnvironmentVariable(GhcrCredentials.TokenFileVariable),
        Environment.GetEnvironmentVariable(GhcrCredentials.TokenVariable));
    using var registry = new RegistryClient(ghcrCredentials: credentials);
    if (args[0] == "versions")
    {
        if (options.DatabasePath is null)
            return await DockerVersions.RunAsync(options.CommandArguments, RunDockerAsync, registry, Console.Out, Console.Error);
        FindingRun versions = await DockerVersions.RunObservedAsync(options.CommandArguments, RunDockerAsync, registry, Console.Out, Console.Error);
        return await options.RecordAsync(versions, RunDockerAsync, Console.Out);
    }
    if (options.DatabasePath is null)
        return await DockerCheck.RunAsync(RunDockerAsync, registry, Console.Out, Console.Error);
    FindingRun check = await DockerCheck.RunObservedAsync(RunDockerAsync, registry, Console.Out, Console.Error,
        discoveryCache: new VersionDiscoveryCache(options.DatabasePath));
    return await options.RecordAsync(check, RunDockerAsync, Console.Out);
}
catch (FindingHistoryException exception)
{
    Console.Error.WriteLine(exception.Message);
    return 1;
}
catch (GhcrConfigurationException exception)
{
    Console.Error.WriteLine(exception.Message);
    return 1;
}
catch (JsonException exception)
{
    Console.Error.WriteLine($"Invalid Docker inspection output: {exception.Message}");
    return 1;
}
catch (Win32Exception exception)
{
    Console.Error.WriteLine($"Unable to run Docker: {exception.Message}");
    return 1;
}

static void WriteUsage()
{
    Console.Error.WriteLine("Usage: happydocker scan");
    Console.Error.WriteLine("       happydocker check [--state <database-path> [--host <id>] [--notify-ntfy <topic-url>]]");
    Console.Error.WriteLine("       happydocker versions --repo <repository> [--repo <repository> ...] [--state <database-path> [--host <id>] [--notify-ntfy <topic-url>]]");
}

static async Task<DockerCommandResult> RunDockerAsync(params string[] arguments)
{
    ProcessStartInfo startInfo = DockerProcess.CreateStartInfo(arguments);

    using var process = Process.Start(startInfo)
        ?? throw new InvalidOperationException("Failed to start Docker.");

    Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
    Task<string> stderrTask = process.StandardError.ReadToEndAsync();

    await process.WaitForExitAsync();

    return new(
        process.ExitCode,
        await stdoutTask,
        await stderrTask);
}
