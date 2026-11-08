using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Data.Sqlite;

namespace HappyDocker;

public enum FindingState { New, Known, Changed, Resolved }

public sealed record FindingTransition(FindingObservation Observation, FindingState State);

public sealed class FindingHistoryException(string message) : Exception(message);

public static class FindingHistory
{
    private const int SchemaVersion = 1;
    private const int ApplicationId = 0x48444648; // HDFH

    public static IReadOnlyList<FindingTransition> Record(string databasePath, string host, IEnumerable<FindingObservation> observations)
    {
        if (string.IsNullOrWhiteSpace(host))
            throw new FindingHistoryException("A stable host identifier is required for finding history.");
        try
        {
            string path = Path.GetFullPath(databasePath);
            if (OperatingSystem.IsLinux()) EnsurePrivateFile(path);
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = path, Mode = SqliteOpenMode.ReadWriteCreate, Pooling = false, DefaultTimeout = 5
            }.ToString());
            connection.Open();
            using var transaction = connection.BeginTransaction(deferred: false);
            EnsureSchema(connection, transaction);

            var transitions = new List<FindingTransition>();
            foreach (FindingObservation observation in observations)
            {
                if (observation.Evidence is not (FindingEvidence.Present or FindingEvidence.Absent) || observation.Repository is null
                    || string.IsNullOrWhiteSpace(observation.ContainerName)) continue;
                string timestamp = observation.ObservedAt.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);
                StoredFinding? previous = Read(connection, transaction, host, observation);
                if (previous is not null && string.CompareOrdinal(timestamp, previous.LastObserved) < 0) continue;

                if (observation.Evidence == FindingEvidence.Absent)
                {
                    if (previous is null || previous.State == FindingState.Resolved) continue;
                    using SqliteCommand resolve = SlotCommand(connection, transaction, host, observation, """
                        UPDATE findings SET state = 'Resolved', last_observed = $observed
                        WHERE host = $host AND container_name = $name AND repository = $repo AND kind = $kind
                        """);
                    resolve.Parameters.AddWithValue("$observed", timestamp);
                    resolve.ExecuteNonQuery();
                    transitions.Add(new(observation, FindingState.Resolved));
                    continue;
                }

                if (string.IsNullOrWhiteSpace(observation.Available) || observation.PlatformVerified is null) continue;
                FindingState state = previous is null || previous.State == FindingState.Resolved ? FindingState.New
                    : previous.Matches(observation) ? FindingState.Known : FindingState.Changed;
                // Keep earlier platform evidence for this candidate and deployment when the registry could not be reached or queried.
                bool platformVerified = observation.PlatformVerified.Value
                    || (state == FindingState.Known && observation.PlatformRequestFailed && previous!.PlatformVerified);
                using SqliteCommand upsert = SlotCommand(connection, transaction, host, observation, """
                    INSERT INTO findings (host, container_name, repository, kind, container_id, image_id, configured_tag,
                                          deployed_digest, available, platform_verified, first_observed, last_observed, state)
                    VALUES ($host, $name, $repo, $kind, $container, $image, $tag, $deployed, $available, $verified,
                            $observed, $observed, $state)
                    ON CONFLICT (host, container_name, repository, kind) DO UPDATE SET
                        container_id = excluded.container_id, image_id = excluded.image_id, configured_tag = excluded.configured_tag,
                        deployed_digest = excluded.deployed_digest, available = excluded.available,
                        platform_verified = excluded.platform_verified, last_observed = excluded.last_observed, state = excluded.state
                    """);
                upsert.Parameters.AddWithValue("$container", observation.ContainerId);
                upsert.Parameters.AddWithValue("$image", (object?)observation.ImageId ?? DBNull.Value);
                upsert.Parameters.AddWithValue("$tag", (object?)observation.ConfiguredTag ?? DBNull.Value);
                upsert.Parameters.AddWithValue("$deployed", (object?)observation.DeployedDigest ?? DBNull.Value);
                upsert.Parameters.AddWithValue("$available", observation.Available);
                upsert.Parameters.AddWithValue("$verified", platformVerified);
                upsert.Parameters.AddWithValue("$observed", timestamp);
                upsert.Parameters.AddWithValue("$state", state.ToString());
                upsert.ExecuteNonQuery();
                transitions.Add(new(observation, state));
            }
            transaction.Commit();
            return transitions;
        }
        catch (SqliteException exception)
        {
            throw new FindingHistoryException($"Unable to use the finding history database (SQLite error {exception.SqliteErrorCode}). Check the path, permissions, and database availability.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new FindingHistoryException("Unable to access the finding history database file. Check the path and directory permissions.");
        }
    }

    [SupportedOSPlatform("linux")]
    private static void EnsurePrivateFile(string path)
    {
        if (!File.Exists(path))
        {
            try
            {
                using var file = new FileStream(path, new FileStreamOptions
                {
                    Mode = FileMode.CreateNew, Access = FileAccess.Write,
                    UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
                });
            }
            catch (IOException) when (File.Exists(path)) { } // Another invocation created the file.
        }
        UnixFileMode shared = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
            | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
        if ((File.GetUnixFileMode(path) & shared) != 0)
            throw new FindingHistoryException("Finding history requires a private database file. Restrict it to mode 0600 and use a private directory.");
    }

    private static void EnsureSchema(SqliteConnection connection, SqliteTransaction transaction)
    {
        using SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "PRAGMA user_version";
        long version = (long)command.ExecuteScalar()!;
        if (version is not (0 or SchemaVersion))
            throw new FindingHistoryException($"Unsupported finding history schema version {version}. Expected {SchemaVersion}.");

        command.CommandText = "PRAGMA application_id";
        long applicationId = (long)command.ExecuteScalar()!;
        if (version == SchemaVersion && applicationId == ApplicationId) return;
        command.CommandText = "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'";
        if (version != 0 || applicationId != 0 || (long)command.ExecuteScalar()! != 0)
            throw new FindingHistoryException("The database is not a HappyDocker finding history database. Choose a new state path.");
        command.CommandText = $"""
            CREATE TABLE findings (
                host TEXT NOT NULL,
                container_name TEXT NOT NULL,
                repository TEXT NOT NULL,
                kind TEXT NOT NULL CHECK (kind IN ('MutableTag', 'PatchCandidate')),
                container_id TEXT NOT NULL,
                image_id TEXT,
                configured_tag TEXT,
                deployed_digest TEXT,
                available TEXT NOT NULL,
                platform_verified INTEGER NOT NULL CHECK (platform_verified IN (0, 1)),
                first_observed TEXT NOT NULL,
                last_observed TEXT NOT NULL,
                state TEXT NOT NULL CHECK (state IN ('New', 'Known', 'Changed', 'Resolved')),
                PRIMARY KEY (host, container_name, repository, kind)
            ) WITHOUT ROWID;
            PRAGMA application_id = {ApplicationId};
            PRAGMA user_version = {SchemaVersion};
            """;
        command.ExecuteNonQuery();
    }

    private static StoredFinding? Read(SqliteConnection connection, SqliteTransaction transaction, string host, FindingObservation observation)
    {
        using SqliteCommand command = SlotCommand(connection, transaction, host, observation, """
            SELECT image_id, configured_tag, deployed_digest, available, platform_verified, last_observed, state
            FROM findings WHERE host = $host AND container_name = $name AND repository = $repo AND kind = $kind
            """);
        using SqliteDataReader reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        return new(Value(0), Value(1), Value(2), reader.GetString(3), reader.GetBoolean(4), reader.GetString(5),
            Enum.Parse<FindingState>(reader.GetString(6)));

        string? Value(int column) => reader.IsDBNull(column) ? null : reader.GetString(column);
    }

    private static SqliteCommand SlotCommand(SqliteConnection connection, SqliteTransaction transaction, string host,
        FindingObservation observation, string sql)
    {
        SqliteCommand command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        command.Parameters.AddWithValue("$host", host);
        command.Parameters.AddWithValue("$name", observation.ContainerName);
        command.Parameters.AddWithValue("$repo", observation.Repository!);
        command.Parameters.AddWithValue("$kind", observation.Kind.ToString());
        return command;
    }

    private sealed record StoredFinding(string? ImageId, string? ConfiguredTag, string? DeployedDigest, string Available,
        bool PlatformVerified, string LastObserved, FindingState State)
    {
        public bool Matches(FindingObservation observation) => ImageId == observation.ImageId && ConfiguredTag == observation.ConfiguredTag
            && DeployedDigest == observation.DeployedDigest && Available == observation.Available;
    }
}
