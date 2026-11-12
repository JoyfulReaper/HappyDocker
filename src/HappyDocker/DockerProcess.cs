using System.Diagnostics;

namespace HappyDocker;

public static class DockerProcess
{
    public static ProcessStartInfo CreateStartInfo(string[] arguments)
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
        startInfo.Environment.Remove(NtfyClient.TokenFileVariable);
        foreach (string argument in arguments) startInfo.ArgumentList.Add(argument);
        return startInfo;
    }
}
