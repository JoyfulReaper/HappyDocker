using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace HappyDocker;

public sealed record ReportDeliverySummary(int Sent, int Pending, int Failed, int Older, DateTimeOffset? NextRetry, string? Failure);

public static class ReportOutbox
{
    public const int MaximumQueuedReports = 100;
    private sealed record Pending(long Id, byte[] Payload, int Attempts, string Lease);

    internal static void Enqueue(SqliteConnection connection, SqliteTransaction transaction, string host, string destinationKey, AgentReport report)
    {
        byte[] payload = JsonSerializer.SerializeToUtf8Bytes(report, ReportJson.CreateOptions());
        if (payload.Length > AgentReportValidation.MaximumBytes) throw new InvalidOperationException("Report exceeds the 1 MiB limit.");
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT COUNT(*) FROM report_outbox";
        if ((long)command.ExecuteScalar()! >= MaximumQueuedReports)
            throw new InvalidOperationException("Report queue is full; existing reports are retained.");
        command.CommandText = "INSERT INTO report_outbox (host, destination_key, payload) VALUES ($host, $destination, $payload)";
        command.Parameters.AddWithValue("$host", host);
        command.Parameters.AddWithValue("$destination", destinationKey);
        command.Parameters.AddWithValue("$payload", payload);
        command.ExecuteNonQuery();
    }

    public static async Task<ReportDeliverySummary> DeliverAsync(string database, string host, AgentReportClient client,
        CancellationToken cancellationToken = default, TimeProvider? timeProvider = null)
    {
        TimeProvider clock = timeProvider ?? TimeProvider.System;
        int sent = 0, failed = 0, older = 0;
        string? failure = null;
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(TimeSpan.FromSeconds(30));
        for (int i = 0; i < 10 && !deadline.IsCancellationRequested; i++)
        {
            Pending? pending = Claim(database, host, client.DestinationKey, clock.GetUtcNow());
            if (pending is null) break;
            ReportDeliveryResult result;
            try { result = await client.SendAsync(pending.Payload, clock.GetUtcNow(), deadline.Token); }
            catch (OperationCanceledException)
            {
                Finish(database, pending, new(false, false, "Delivery interrupted"), clock.GetUtcNow());
                cancellationToken.ThrowIfCancellationRequested();
                failed++;
                failure = "Delivery deadline reached";
                break;
            }
            Finish(database, pending, result, clock.GetUtcNow());
            if (!result.Acknowledged) { failed++; failure = result.Detail; break; }
            sent++;
            if (result.Older) older++;
        }
        cancellationToken.ThrowIfCancellationRequested();
        var pendingInfo = FindingHistory.WithDatabase(database, (connection, transaction) =>
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = """
                SELECT COUNT(*),
                    (SELECT MAX(next_attempt, lease_until) FROM report_outbox WHERE host = $host AND destination_key = $destination ORDER BY id LIMIT 1),
                    (SELECT last_error FROM report_outbox WHERE host = $host AND destination_key = $destination ORDER BY id LIMIT 1)
                FROM report_outbox WHERE host = $host AND destination_key = $destination
                """;
            command.Parameters.AddWithValue("$host", host);
            command.Parameters.AddWithValue("$destination", client.DestinationKey);
            using var reader = command.ExecuteReader();
            reader.Read();
            return (Count: reader.GetInt32(0), Next: reader.IsDBNull(1) ? (long?)null : reader.GetInt64(1),
                Error: reader.IsDBNull(2) ? null : reader.GetString(2));
        });
        DateTimeOffset? next = pendingInfo.Next is { } seconds ? DateTimeOffset.FromUnixTimeSeconds(seconds) : null;
        if (next < clock.GetUtcNow()) next = clock.GetUtcNow();
        return new(sent, pendingInfo.Count, failed, older, next, failure ?? pendingInfo.Error);
    }

    private static Pending? Claim(string database, string host, string destination, DateTimeOffset now) =>
        FindingHistory.WithDatabase<Pending?>(database, (connection, transaction) =>
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = "SELECT id, payload, attempts, next_attempt, lease_until FROM report_outbox WHERE host = $host AND destination_key = $destination ORDER BY id LIMIT 1";
            command.Parameters.AddWithValue("$host", host);
            command.Parameters.AddWithValue("$destination", destination);
            long id, next, leaseUntil;
            byte[] payload;
            int attempts;
            using (var reader = command.ExecuteReader())
            {
                if (!reader.Read()) return null;
                id = reader.GetInt64(0); payload = (byte[])reader[1]; attempts = Math.Min(reader.GetInt32(2) + 1, 30);
                next = reader.GetInt64(3); leaseUntil = reader.GetInt64(4);
            }
            if (next > now.ToUnixTimeSeconds() || leaseUntil > now.ToUnixTimeSeconds()) return null;
            string lease = Guid.NewGuid().ToString("N");
            command.CommandText = "UPDATE report_outbox SET lease_token = $lease, lease_until = $until, attempts = $attempts WHERE id = $id";
            command.Parameters.AddWithValue("$lease", lease);
            command.Parameters.AddWithValue("$until", now.AddSeconds(60).ToUnixTimeSeconds());
            command.Parameters.AddWithValue("$attempts", attempts);
            command.Parameters.AddWithValue("$id", id);
            command.ExecuteNonQuery();
            return new(id, payload, attempts, lease);
        });

    private static void Finish(string database, Pending pending, ReportDeliveryResult result, DateTimeOffset now) =>
        FindingHistory.WithDatabase(database, (connection, transaction) =>
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.Parameters.AddWithValue("$id", pending.Id);
            command.Parameters.AddWithValue("$lease", pending.Lease);
            if (result.Acknowledged)
                command.CommandText = "DELETE FROM report_outbox WHERE id = $id AND lease_token = $lease";
            else
            {
                // Permanent failures are retained and retried at most once per day, allowing credential repair.
                double seconds = result.Permanent ? 86400 : Math.Min(3600, 30 * Math.Pow(2, Math.Min(pending.Attempts - 1, 7)));
                DateTimeOffset retry = now.AddSeconds(seconds);
                if (result.RetryAfter > retry) retry = result.RetryAfter.Value;
                command.CommandText = "UPDATE report_outbox SET next_attempt = $next, lease_token = NULL, lease_until = 0, last_error = $error WHERE id = $id AND lease_token = $lease";
                command.Parameters.AddWithValue("$next", retry.ToUnixTimeSeconds());
                command.Parameters.AddWithValue("$error", result.Detail);
            }
            command.ExecuteNonQuery();
            return 0;
        });
}
