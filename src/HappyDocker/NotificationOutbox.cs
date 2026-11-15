using System.Globalization;
using System.Text;
using Microsoft.Data.Sqlite;

namespace HappyDocker;

public sealed record NotificationDeliverySummary(int Sent, int Failed, int Pending, string? Failure = null);

public static class NotificationOutbox
{
    private sealed record PendingMessage(long Id, string Message, int Attempts, string Lease);

    internal static void Enqueue(SqliteConnection connection, SqliteTransaction transaction, string host,
        string destinationKey, IReadOnlyList<FindingTransition> transitions)
    {
        var groups = transitions.Where(transition => transition.State is FindingState.New or FindingState.Changed
                && transition.Observation.Evidence == FindingEvidence.Present && transition.Observation.HasVerifiedCandidate)
            .GroupBy(transition => (transition.State, transition.Observation.Kind, transition.Observation.Repository,
                transition.Observation.ConfiguredTag, transition.Observation.ImageId, transition.Observation.DeployedDigest,
                transition.Observation.Available, transition.Observation.PlatformVerified, transition.Observation.VerifiedAlternative));
        foreach (var group in groups)
        {
            using SqliteCommand command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                INSERT INTO notification_outbox (host, destination_key, message, created_at, next_attempt)
                VALUES ($host, $destination, $message, $created,
                    MAX($now, COALESCE((SELECT MAX(next_attempt) FROM notification_outbox WHERE destination_key = $destination), $now)))
                """;
            DateTimeOffset observed = group.Min(transition => transition.Observation.ObservedAt);
            command.Parameters.AddWithValue("$host", host);
            command.Parameters.AddWithValue("$destination", destinationKey);
            command.Parameters.AddWithValue("$message", Message(host, group.ToArray()));
            command.Parameters.AddWithValue("$created", observed.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
            command.Parameters.AddWithValue("$now", DateTimeOffset.UtcNow.ToUnixTimeSeconds());
            command.ExecuteNonQuery();
        }
    }

    public static async Task<NotificationDeliverySummary> DeliverAsync(string databasePath, string host, NtfyClient client,
        CancellationToken cancellationToken = default, TimeProvider? timeProvider = null)
    {
        TimeProvider clock = timeProvider ?? TimeProvider.System;
        int sent = 0;
        int failed = 0;
        string? failure = null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        for (int attempt = 0; attempt < 10 && !deadline.IsCancellationRequested; attempt++)
        {
            PendingMessage? pending = Claim(databasePath, host, client.DestinationKey, clock.GetUtcNow());
            if (pending is null) break;
            NtfyDeliveryResult result;
            try
            {
                result = await client.SendAsync(pending.Message, clock.GetUtcNow(), deadline.Token);
            }
            catch (OperationCanceledException)
            {
                Complete(databasePath, client.DestinationKey, pending, new(false, "ntfy delivery interrupted."), clock.GetUtcNow());
                cancellationToken.ThrowIfCancellationRequested();
                failed++;
                failure = "ntfy delivery deadline reached.";
                break;
            }
            Complete(databasePath, client.DestinationKey, pending, result, clock.GetUtcNow());
            if (!result.Successful)
            {
                failed++;
                failure = result.Detail;
                break; // Defer the destination instead of repeating a failed request during this run.
            }
            sent++;
        }
        cancellationToken.ThrowIfCancellationRequested();
        int remaining = FindingHistory.WithDatabase(databasePath, (connection, transaction) =>
        {
            using SqliteCommand command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "SELECT COUNT(*) FROM notification_outbox WHERE host = $host AND destination_key = $destination";
            command.Parameters.AddWithValue("$host", host);
            command.Parameters.AddWithValue("$destination", client.DestinationKey);
            return checked((int)(long)command.ExecuteScalar()!);
        });
        return new(sent, failed, remaining, failure);
    }

    private static PendingMessage? Claim(string databasePath, string host, string destinationKey, DateTimeOffset now) =>
        FindingHistory.WithDatabase<PendingMessage?>(databasePath, (connection, transaction) =>
        {
            using SqliteCommand command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                SELECT id, message, attempts FROM notification_outbox
                WHERE host = $host AND destination_key = $destination AND next_attempt <= $now AND lease_until <= $now
                    AND NOT EXISTS (SELECT 1 FROM notification_outbox WHERE destination_key = $destination AND lease_until > $now)
                ORDER BY id LIMIT 1
                """;
            command.Parameters.AddWithValue("$host", host);
            command.Parameters.AddWithValue("$destination", destinationKey);
            command.Parameters.AddWithValue("$now", now.ToUnixTimeSeconds());
            long id;
            string message;
            int attempts;
            using (SqliteDataReader reader = command.ExecuteReader())
            {
                if (!reader.Read()) return null;
                id = reader.GetInt64(0);
                message = reader.GetString(1);
                attempts = Math.Min(reader.GetInt32(2) + 1, 30);
            }
            string lease = Guid.NewGuid().ToString("N");
            command.CommandText = """
                UPDATE notification_outbox SET lease_token = $lease, lease_until = $until, attempts = $attempts WHERE id = $id
                """;
            command.Parameters.AddWithValue("$id", id);
            command.Parameters.AddWithValue("$lease", lease);
            command.Parameters.AddWithValue("$until", now.AddSeconds(60).ToUnixTimeSeconds());
            command.Parameters.AddWithValue("$attempts", attempts);
            command.ExecuteNonQuery();
            return new(id, message, attempts, lease);
        });

    private static void Complete(string databasePath, string destinationKey, PendingMessage pending,
        NtfyDeliveryResult result, DateTimeOffset now) =>
        FindingHistory.WithDatabase(databasePath, (connection, transaction) =>
        {
            using SqliteCommand command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "SELECT COUNT(*) FROM notification_outbox WHERE id = $id AND lease_token = $lease";
            command.Parameters.AddWithValue("$id", pending.Id);
            command.Parameters.AddWithValue("$lease", pending.Lease);
            if ((long)command.ExecuteScalar()! == 0) return 0; // A newer lease owns this delivery.
            if (result.Successful)
            {
                command.CommandText = "DELETE FROM notification_outbox WHERE id = $id AND lease_token = $lease";
                return command.ExecuteNonQuery();
            }
            DateTimeOffset retry = now.AddSeconds(Math.Min(3600, 60 * Math.Pow(2, Math.Min(pending.Attempts - 1, 6))));
            if (result.RetryAfter is { } requested && requested > retry) retry = requested;
            command.CommandText = """
                UPDATE notification_outbox SET next_attempt = MAX(next_attempt, $retry) WHERE destination_key = $destination;
                UPDATE notification_outbox SET lease_token = NULL, lease_until = 0 WHERE id = $id AND lease_token = $lease;
                """;
            command.Parameters.AddWithValue("$destination", destinationKey);
            command.Parameters.AddWithValue("$retry", retry.ToUnixTimeSeconds());
            return command.ExecuteNonQuery();
        });

    private static string Message(string host, FindingTransition[] group)
    {
        FindingTransition first = group[0];
        FindingObservation observation = first.Observation;
        string[] names = group.Select(item => item.Observation.ContainerName).Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        string containers = string.Join(", ", names.Take(10).Select(name => OneLine(name, 48)));
        if (names.Length > 10) containers += $" (+{names.Length - 10} more)";
        string type = observation.Kind == FindingKind.MutableTag ? "mutable-tag update"
            : $"{observation.Upgrade?.ToString().ToLowerInvariant() ?? "unclassified"} version candidate";
        string caution = observation.Kind == FindingKind.VersionCandidate ? "\nReview compatibility and security separately." : "";
        string alternative = observation.AlternativeUpgrade is { } upgrade
            ? $"\nVerified alternative {OneLine(observation.VerifiedAlternative, 160)} ({upgrade.ToString().ToLowerInvariant()}; platform verified)" : "";
        string platform = observation.PlatformVerified == true ? "platform verified" : "newest platform unverified";
        string message = $"{first.State} {type} · {platform}{caution}\n"
            + $"Host {OneLine(host, 135)}\nRepository {OneLine(observation.Repository, 255)}\n"
            + $"Current tag {OneLine(observation.ConfiguredTag, 128)}\nAvailable {OneLine(observation.Available, 160)}{alternative}\n"
            + $"Containers {containers}\nObserved {observation.ObservedAt.UtcDateTime:yyyy-MM-dd HH:mm} UTC";
        var bounded = new StringBuilder();
        int bytes = 0;
        foreach (Rune rune in message.EnumerateRunes())
        {
            if (bytes + rune.Utf8SequenceLength > NtfyClient.MaximumMessageBytes - 3) return bounded.Append("…").ToString();
            bounded.Append(rune.ToString());
            bytes += rune.Utf8SequenceLength;
        }
        return bounded.ToString();
    }

    private static string OneLine(string? value, int limit)
    {
        if (value is null) return "<unknown>";
        int length = Math.Min(value.Length, limit);
        if (length > 0 && char.IsHighSurrogate(value[length - 1])) length--;
        string text = new(value[..length].Select(character => char.IsControl(character) ? ' ' : character).ToArray());
        return length < value.Length ? text + "…" : text;
    }
}
