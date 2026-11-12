using System.Globalization;
using System.Text.Json;

namespace HappyDocker;

/// <summary>Only complete tag lists are reused. Keys include the supported registry and repository.</summary>
public sealed class VersionDiscoveryCache(string databasePath, TimeProvider? timeProvider = null)
{
    public static TimeSpan Interval => TimeSpan.FromHours(24);
    internal DateTimeOffset Now => (timeProvider ?? TimeProvider.System).GetUtcNow();

    internal IReadOnlyDictionary<string, long> ReadAttempts() => FindingHistory.WithDatabase(databasePath, (connection, transaction) =>
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT repository, last_attempt FROM version_discovery_cache WHERE last_attempt IS NOT NULL";
        var attempts = new Dictionary<string, long>(StringComparer.Ordinal);
        using var reader = command.ExecuteReader();
        while (reader.Read()) attempts.Add(reader.GetString(0), reader.GetInt64(1));
        return attempts;
    });

    internal void MarkAttempt(string repository, DateTimeOffset attemptedAt) =>
        FindingHistory.WithDatabase(databasePath, (connection, transaction) =>
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            // The timestamp is advanced monotonically to preserve ordering even within one clock tick or after a clock rollback.
            command.CommandText = """
                INSERT INTO version_discovery_cache (repository, last_attempt)
                VALUES ($repo, MAX($now, COALESCE((SELECT MAX(last_attempt) FROM version_discovery_cache), $now - 1) + 1))
                ON CONFLICT(repository) DO UPDATE SET last_attempt = excluded.last_attempt
                """;
            command.Parameters.AddWithValue("$repo", repository);
            command.Parameters.AddWithValue("$now", attemptedAt.ToUnixTimeMilliseconds());
            return command.ExecuteNonQuery();
        });

    internal TagEnumeration? Read(string repository) => FindingHistory.WithDatabase<TagEnumeration?>(databasePath, (connection, transaction) =>
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT fetched_at, tags_json, retry_after FROM version_discovery_cache WHERE repository = $repo";
        command.Parameters.AddWithValue("$repo", repository);
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        if (!reader.IsDBNull(2) && DateTimeOffset.TryParse(reader.GetString(2), CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal, out var retry) && retry > Now)
            return new([], "Registry discovery is deferred by Retry-After.", retry);
        if (reader.IsDBNull(0) || reader.IsDBNull(1)
            || !DateTimeOffset.TryParse(reader.GetString(0), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var fetched)
            || fetched > Now || Now - fetched >= Interval)
            return null;
        string json = reader.GetString(1);
        if (json.Length > 264 * 1024) return null;
        try
        {
            string[]? tags = JsonSerializer.Deserialize<string[]>(json);
            if (tags is null || tags.Length > 2000 || tags.Any(tag => tag is null || !ImageReference.IsValidTag(tag))) return null;
            return new(tags, CachedAt: fetched, ObservedAt: fetched);
        }
        catch (JsonException) { return null; }
    });

    internal void Save(string repository, TagEnumeration enumeration, DateTimeOffset fetchedAt)
    {
        if (enumeration.IncompleteReason is not null && enumeration.RetryAfter is null) return;
        FindingHistory.WithDatabase(databasePath, (connection, transaction) =>
        {
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            if (enumeration.IncompleteReason is null)
            {
                command.CommandText = """
                    INSERT INTO version_discovery_cache (repository, fetched_at, tags_json, retry_after)
                    VALUES ($repo, $fetched, $tags, NULL)
                    ON CONFLICT(repository) DO UPDATE SET fetched_at = excluded.fetched_at, tags_json = excluded.tags_json,
                        retry_after = CASE WHEN retry_after > excluded.fetched_at THEN retry_after ELSE NULL END
                    WHERE fetched_at IS NULL OR fetched_at <= excluded.fetched_at
                    """;
                command.Parameters.AddWithValue("$fetched", fetchedAt.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
                command.Parameters.AddWithValue("$tags", JsonSerializer.Serialize(enumeration.Tags));
            }
            else
            {
                command.CommandText = """
                    INSERT INTO version_discovery_cache (repository, retry_after) VALUES ($repo, $retry)
                    ON CONFLICT(repository) DO UPDATE SET retry_after = MAX(COALESCE(retry_after, ''), excluded.retry_after)
                    """;
                command.Parameters.AddWithValue("$retry", enumeration.RetryAfter!.Value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture));
            }
            command.Parameters.AddWithValue("$repo", repository);
            return command.ExecuteNonQuery();
        });
    }
}
