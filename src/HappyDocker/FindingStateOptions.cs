using System.Text.Json;

namespace HappyDocker;

public sealed record FindingStateOptions(string[] CommandArguments, string? DatabasePath, string? Host, string? NotifyNtfy = null,
    string? ReportUrl = null, string? ReportTokenFile = null)
{
    public static bool TryParse(string[] arguments, out FindingStateOptions options)
    {
        options = new(arguments, null, null);
        var command = new List<string>();
        string? database = null;
        string? host = null;
        string? notify = null;
        string? reportUrl = null, reportTokenFile = null;
        for (int index = 0; index < arguments.Length; index++)
        {
            string argument = arguments[index];
            if (argument is not ("--state" or "--host" or "--notify-ntfy" or "--report-url" or "--report-token-file"))
            {
                command.Add(argument);
                if (argument == "--repo" && index + 1 < arguments.Length)
                {
                    if (arguments[index + 1] is "--state" or "--host" or "--notify-ntfy" or "--report-url" or "--report-token-file") return false;
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
            else if (argument == "--host")
            {
                if (host is not null || arguments[index].Length > 128
                    || arguments[index].Any(character => !char.IsAsciiLetterOrDigit(character) && character is not ('.' or '-' or '_')))
                    return false;
                host = arguments[index];
            }
            else if (argument == "--notify-ntfy")
            {
                if (notify is not null) return false;
                notify = arguments[index];
                try { NtfyClient.ParseDestination(notify); }
                catch (NtfyConfigurationException) { return false; }
            }
            else if (argument == "--report-url")
            {
                if (reportUrl is not null) return false;
                reportUrl = arguments[index];
                try { AgentReportClient.ParseDestination(reportUrl); }
                catch (ReportConfigurationException) { return false; }
            }
            else
            {
                if (reportTokenFile is not null) return false;
                reportTokenFile = arguments[index];
            }
        }
        if ((host is not null || notify is not null) && database is null) return false;
        if ((reportUrl is null) != (reportTokenFile is null) || reportUrl is not null && (database is null || host is null)) return false;
        options = new(command.ToArray(), database, host, notify, reportUrl, reportTokenFile);
        return true;
    }

    public async Task<int> RecordAsync(FindingRun run, Func<string[], Task<DockerCommandResult>> runDocker, TextWriter output,
        NtfyClient? notifier = null, CancellationToken cancellationToken = default, AgentReportClient? reporter = null)
    {
        IReadOnlyList<FindingTransition> transitions = [];
        string? host = null;
        string? reportError = null;
        int unmatched = 0;
        int staleAbsences = 0;
        DateTimeOffset scannedAt = DateTimeOffset.UtcNow;
        if (ReportUrl is not null && reporter is null) throw new ReportConfigurationException("Report client must be configured before the scan.");
        if (run.InventoryExitCode == 0 || run.Observations.Count > 0 || NotifyNtfy is not null || reporter is not null)
        {
            host = Host ?? await ReadDockerHostAsync(runDocker);
            string? destinationKey = NotifyNtfy is null ? null : NtfyClient.GetDestinationKey(NtfyClient.ParseDestination(NotifyNtfy));
            transitions = FindingHistory.Record(DatabasePath!, host, run.Observations, destinationKey,
                reporter is null ? null : (connection, transaction, recorded, stale) =>
                {
                    try
                    {
                        staleAbsences = stale.Count(observation => observation.Evidence == FindingEvidence.Absent);
                        FindingRun reportRun = staleAbsences == 0 ? run : run with { HasFullHostCoverage = false };
                        AgentReport report = AgentReportBuilder.Build(host, reportRun, recorded, scannedAt, out unmatched);
                        ReportOutbox.Enqueue(connection, transaction, host, reporter.DestinationKey, report);
                    }
                    catch (InvalidOperationException exception) { reportError = exception.Message; }
                });
        }

        await output.WriteLineAsync($"Finding history {run.Status.ToString().ToLowerInvariant()}. "
            + $"New {Count(FindingState.New)}, known {Count(FindingState.Known)}, changed {Count(FindingState.Changed)}, "
            + $"resolved {Count(FindingState.Resolved)}, incomplete {run.IncompleteCount}"
            + (run.DeferredCount == 0 ? "." : $", deferred {run.DeferredCount}."));
        bool notificationsPending = false;
        if (NotifyNtfy is not null)
        {
            try
            {
                // Load credentials only after observations and pending notifications have been committed.
                using NtfyClient? owned = notifier is null
                    ? new NtfyClient(NotifyNtfy, Environment.GetEnvironmentVariable(NtfyClient.TokenFileVariable)) : null;
                NtfyClient client = notifier ?? owned!;
                if (client.DestinationKey != NtfyClient.GetDestinationKey(NtfyClient.ParseDestination(NotifyNtfy)))
                    throw new NtfyConfigurationException("The notification client destination does not match --notify-ntfy.");
                NotificationDeliverySummary delivery = await NotificationOutbox.DeliverAsync(DatabasePath!, host!, client, cancellationToken);
                notificationsPending = delivery.Failed > 0 || delivery.Pending > 0;
                await output.WriteLineAsync($"Notifications sent {delivery.Sent}, failed {delivery.Failed}, pending {delivery.Pending}."
                    + (delivery.Failure is null ? "" : $" {delivery.Failure}"));
            }
            catch (Exception exception) when (exception is NtfyConfigurationException or FindingHistoryException)
            {
                notificationsPending = true;
                await output.WriteLineAsync($"Notifications unavailable. {exception.Message}");
            }
        }
        bool reportingPending = false;
        if (reporter is not null)
        {
            try
            {
                var delivery = await ReportOutbox.DeliverAsync(DatabasePath!, host!, reporter, cancellationToken);
                reportingPending = delivery.Pending > 0 || delivery.Failed > 0 || reportError is not null;
                await output.WriteLineAsync($"Reports sent {delivery.Sent}, pending {delivery.Pending}, failed {delivery.Failed + (reportError is null ? 0 : 1)}"
                    + (delivery.Older > 0 ? $", already superseded {delivery.Older}" : "")
                    + (delivery.NextRetry is { } next ? $", next retry {next:O}" : "") + "."
                    + (delivery.Failure is null ? "" : $" {delivery.Failure}.")
                    + (reportError is null ? "" : $" {reportError}")
                    + (unmatched + staleAbsences == 0 ? "" : $" {unmatched + staleAbsences} older or unmatched observations omitted; report is incomplete."));
            }
            catch (FindingHistoryException exception)
            {
                reportingPending = true;
                await output.WriteLineAsync($"Reports unavailable. {exception.Message}");
            }
        }
        if (run.InventoryExitCode != 0) return run.InventoryExitCode;
        if (notificationsPending) return 3;
        int scanExit = run.Status switch
        {
            FindingRunStatus.Complete => 0,
            FindingRunStatus.Partial => 2,
            FindingRunStatus.Deferred => 4,
            _ => 1
        };
        return scanExit != 0 ? scanExit : reportingPending ? 5 : 0;

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
