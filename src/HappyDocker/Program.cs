using HappyDocker;
using System.ComponentModel;
using System.Diagnostics;
using System.Text.Json;

if (args.Length != 1 || args[0] is not ("scan" or "check" or "vulnerabilities"))
{
    Console.Error.WriteLine("Usage: happydocker scan|check|vulnerabilities");
    return 1;
}

try
{
    if (args[0] == "scan")
        return await DockerScan.RunAsync(arguments => RunDockerAsync(arguments), Console.Out, Console.Error);
    if (args[0] == "vulnerabilities")
        return await RunVulnerabilitiesAsync();
    GhcrCredentials? credentials = GhcrCredentials.Load(
        Environment.GetEnvironmentVariable(GhcrCredentials.UsernameVariable),
        Environment.GetEnvironmentVariable(GhcrCredentials.TokenFileVariable),
        Environment.GetEnvironmentVariable(GhcrCredentials.TokenVariable));
    using var registry = new RegistryClient(ghcrCredentials: credentials);
    return await DockerCheck.RunAsync(arguments => RunDockerAsync(arguments), new RegistryUpdateChecker(registry), Console.Out, Console.Error);
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

static async Task<DockerCommandResult> RunDockerAsync(params string[] arguments)
{
    using var process = Process.Start(CreateDockerStartInfo(arguments))
        ?? throw new InvalidOperationException("Failed to start Docker.");

    Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
    Task<string> stderrTask = process.StandardError.ReadToEndAsync();

    await process.WaitForExitAsync();
    return new(process.ExitCode, await stdoutTask, await stderrTask);
}

static ProcessStartInfo CreateDockerStartInfo(string[] arguments)
{
    var startInfo = new ProcessStartInfo("docker")
    {
        RedirectStandardOutput = true,
        RedirectStandardError = true,
        UseShellExecute = false,
        CreateNoWindow = true
    };

    startInfo.Environment.Remove(GhcrCredentials.UsernameVariable);
    startInfo.Environment.Remove(GhcrCredentials.TokenFileVariable);
    startInfo.Environment.Remove(GhcrCredentials.TokenVariable);

    foreach (string argument in arguments)
    {
        startInfo.ArgumentList.Add(argument);
    }

    return startInfo;
}

static async Task<int> RunVulnerabilitiesAsync()
{
    using var cancellation = new CancellationTokenSource();
    ConsoleCancelEventHandler onCancel = (_, signal) => { signal.Cancel = true; cancellation.Cancel(); };
    Console.CancelKeyPress += onCancel;
    try
    {
        return await DockerVulnerabilities.RunAsync(async arguments =>
        {
            ProcessCaptureResult result = await ProcessCapture.RunAsync(CreateDockerStartInfo(arguments), TimeSpan.FromSeconds(30),
                TrivyScanner.ReportLimit, TrivyScanner.DiagnosticLimit, cancellation.Token);
            return result.Outcome == ProcessOutcome.Exited
                ? new(result.ExitCode, result.Stdout, result.Stderr)
                : new(1, "", $"Docker inventory command did not complete ({result.Outcome}).");
        }, new TrivyScanner(ProcessCapture.RunAsync), Console.Out, Console.Error, cancellation.Token);
    }
    catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
    {
        Console.Error.WriteLine("Vulnerability scan cancelled.");
        return 130;
    }
    finally { Console.CancelKeyPress -= onCancel; }
}
