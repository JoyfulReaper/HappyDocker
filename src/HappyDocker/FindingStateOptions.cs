using System.Text.Json;

namespace HappyDocker;

public sealed record FindingStateOptions(string[] CommandArguments, string? DatabasePath, string? Host)
{
    public static bool TryParse(string[] arguments, out FindingStateOptions options)
    {
        options = new(arguments, null, null);
        var command = new List<string>();
        string? database = null;
        string? host = null;
        for (int index = 0; index < arguments.Length; index++)
        {
            string argument = arguments[index];
            if (argument is not ("--state" or "--host"))
            {
                command.Add(argument);
                if (argument == "--repo" && index + 1 < arguments.Length)
                {
                    if (arguments[index + 1] is "--state" or "--host") return false;
                    command.Add(arguments[++index]);
                }
                continue;
            }

            if (++index == arguments.Length || arguments[index].StartsWith("--", StringComparison.Ordinal)
                || string.IsNullOrWhiteSpace(arguments[index])) return false;
            if (argument == "--state")
            {
                if (database is not null) return false;
                database = arguments[index];
            }
            else
            {
                if (host is not null || arguments[index].Length > 128
                    || arguments[index].Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('.' or '-' or '_')))
                    return false;
                host = arguments[index];
            }
        }
        if (host is not null && database is null) return false;
        options = new(command.ToArray(), database, host);
        return true;
    }

    public async Task<int> RecordAsync(FindingRun run, Func<string[], Task<DockerCommandResult>> runDocker, TextWriter output)
    {
        IReadOnlyList<FindingTransition> transitions = [];
        if (run.InventoryExitCode == 0 || run.Observations.Count > 0)
        {
            string host = Host ?? await ReadDockerHostAsync(runDocker);
            transitions = FindingHistory.Record(DatabasePath!, host, run.Observations);
        }

        await output.WriteLineAsync($"Finding history {run.Status.ToString().ToLowerInvariant()}. "
            + $"New {Count(FindingState.New)}, known {Count(FindingState.Known)}, changed {Count(FindingState.Changed)}, "
            + $"resolved {Count(FindingState.Resolved)}, incomplete {run.IncompleteCount}.");
        if (run.InventoryExitCode != 0) return run.InventoryExitCode;
        return run.Status switch
        {
            FindingRunStatus.Complete => 0,
            FindingRunStatus.Partial => 2,
            _ => 1
        };

        int Count(FindingState state) => transitions.Count(transition => transition.State == state);
    }

    private static async Task<string> ReadDockerHostAsync(Func<string[], Task<DockerCommandResult>> runDocker)
    {
        DockerCommandResult result = await runDocker(["info", "--format", "{{json .ID}}"]);
        if (result.ExitCode == 0)
        {
            try
            {
                string? id = JsonSerializer.Deserialize<string>(result.Stdout);
                if (id is { Length: > 0 and <= 128 }
                    && id.All(character => char.IsAsciiLetterOrDigit(character) || character is '.' or ':' or '-' or '_'))
                    return $"docker:{id}";
            }
            catch (JsonException) { }
        }
        throw new FindingHistoryException("Unable to identify the Docker daemon for finding history. Supply a unique stable identifier with --host.");
    }
}
