using HappyDocker;
using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;

if (args.Length != 1 || args[0] is not ("scan" or "check"))
{
    Console.Error.WriteLine("Usage: happydocker scan|check");
    return 1;
}

try
{
    if (args[0] == "scan")
        return await DockerScan.RunAsync(arguments => RunDockerAsync(arguments), Console.Out, Console.Error);
    using var registry = new RegistryClient();
    return await DockerCheck.RunAsync(arguments => RunDockerAsync(arguments), new RegistryUpdateChecker(registry), Console.Out, Console.Error);
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

static async Task<DockerCommandResult> RunDockerAsync(params string[] arguments)
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

    return new(
        process.ExitCode,
        await stdoutTask,
        await stderrTask);
}
