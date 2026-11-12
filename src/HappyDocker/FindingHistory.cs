using System.Globalization;
using System.Runtime.Versioning;
using Microsoft.Data.Sqlite;

namespace HappyDocker;

public enum FindingState { New, Known, Changed, Resolved }

public sealed record FindingTransition(FindingObservation Observation, FindingState State);

public sealed class FindingHistoryException(string message) : Exception(message);

public static class FindingHistory
{
    private const int SchemaVersion = 2;
    private const int ApplicationId = 0x48444648; // HDFH

    public static IReadOnlyList<FindingTransition> Record(string databasePath, string host, IEnumerable<FindingObservation> observations,
        string? notificationDestinationKey = null)
    {
        if (string.IsNullOrWhiteSpace(host))
            throw new FindingHistoryException("A stable host identifier is required for finding history.");
        return WithDatabase(databasePath, (connection, transaction) =>
        {
            var transitions = new List<FindingTransition>();
            var notifications = new List<FindingTransition>();
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
                        UPDATE findings SET state = 'Resolved', last_observed = $observed,
                            pending_notification_destination = NULL, pending_notification_state = NULL
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
                string? pendingDestination = previous?.PendingNotificationDestination;
                FindingState? pendingState = previous?.PendingNotificationState;
                if (state is FindingState.New or FindingState.Changed)
                {
                    pendingDestination = observation.Kind == FindingKind.PatchCandidate && observation.PlatformVerified != true
                        ? notificationDestinationKey : null;
                    pendingState = pendingDestination is null ? null : state;
                }
                if (notificationDestinationKey is not null && observation.PlatformVerified == true
                    && (state is FindingState.New or FindingState.Changed
                        || (pendingDestination == notificationDestinationKey && pendingState is not null)))
                {
                    // Deferred eligibility affects the alert, while the finding transition stays Known.
                    notifications.Add(new(observation, pendingState ?? state));
                    pendingDestination = null;
                    pendingState = null;
                }
                using SqliteCommand upsert = SlotCommand(connection, transaction, host, observation, """
                    INSERT INTO findings (host, container_name, repository, kind, container_id, image_id, configured_tag,
                                          deployed_digest, available, platform_verified, first_observed, last_observed, state,
                                          pending_notification_destination, pending_notification_state)
                    VALUES ($host, $name, $repo, $kind, $container, $image, $tag, $deployed, $available, $verified,
                            $observed, $observed, $state, $pending_destination, $pending_state)
                    ON CONFLICT (host, container_name, repository, kind) DO UPDATE SET
                        container_id = excluded.container_id, image_id = excluded.image_id, configured_tag = excluded.configured_tag,
                        deployed_digest = excluded.deployed_digest, available = excluded.available,
                        platform_verified = excluded.platform_verified, last_observed = excluded.last_observed, state = excluded.state,
                        pending_notification_destination = excluded.pending_notification_destination,
                        pending_notification_state = excluded.pending_notification_state
                    """);
                upsert.Parameters.AddWithValue("$container", observation.ContainerId);
                upsert.Parameters.AddWithValue("$image", (object?)observation.ImageId ?? DBNull.Value);
                upsert.Parameters.AddWithValue("$tag", (object?)observation.ConfiguredTag ?? DBNull.Value);
                upsert.Parameters.AddWithValue("$deployed", (object?)observation.DeployedDigest ?? DBNull.Value);
                upsert.Parameters.AddWithValue("$available", observation.Available);
                upsert.Parameters.AddWithValue("$verified", platformVerified);
                upsert.Parameters.AddWithValue("$observed", timestamp);
                upsert.Parameters.AddWithValue("$state", state.ToString());
                upsert.Parameters.AddWithValue("$pending_destination", (object?)pendingDestination ?? DBNull.Value);
                upsert.Parameters.AddWithValue("$pending_state", (object?)pendingState?.ToString() ?? DBNull.Value);
                upsert.ExecuteNonQuery();
                transitions.Add(new(observation, state));
            }
            if (notificationDestinationKey is not null)
                NotificationOutbox.Enqueue(connection, transaction, host, notificationDestinationKey, notifications);
            return transitions;
        });
    }

    internal static T WithDatabase<T>(string databasePath, Func<SqliteConnection, SqliteTransaction, T> operation)
    {
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
            T result = operation(connection, transaction);
            transaction.Commit();
            return result;
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
        if (version is not (0 or 1 or SchemaVersion))
            throw new FindingHistoryException($"Unsupported finding history schema version {version}. Expected {SchemaVersion}.");

        command.CommandText = "PRAGMA application_id";
        long applicationId = (long)command.ExecuteScalar()!;
        if (applicationId == ApplicationId && version is 1 or SchemaVersion)
        {
            if (version == 1) CreateOutbox(command);
            EnsureNotificationEligibility(command);
            return;
        }
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
            PRAGMA user_version = 1;
            """;
        command.ExecuteNonQuery();
        CreateOutbox(command);
        EnsureNotificationEligibility(command);
    }

    private static void EnsureNotificationEligibility(SqliteCommand command)
    {
        // Version 2 is still under development. Existing v1 and earlier v2 files start with no retroactive eligibility.
        command.CommandText = "PRAGMA table_info(findings)";
        var columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using (SqliteDataReader reader = command.ExecuteReader())
            while (reader.Read()) columns.Add(reader.GetString(1));
        if (!columns.Contains("pending_notification_destination"))
        {
            command.CommandText = "ALTER TABLE findings ADD COLUMN pending_notification_destination TEXT";
            command.ExecuteNonQuery();
        }
        if (!columns.Contains("pending_notification_state"))
        {
            command.CommandText = """
                ALTER TABLE findings ADD COLUMN pending_notification_state TEXT
                    CHECK (pending_notification_state IN ('New', 'Changed'))
                """;
            command.ExecuteNonQuery();
        }
    }

    private static void CreateOutbox(SqliteCommand command)
    {
        command.CommandText = $"""
            CREATE TABLE notification_outbox (
                id INTEGER PRIMARY KEY,
                host TEXT NOT NULL,
                destination_key TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                next_attempt INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                lease_token TEXT,
                lease_until INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX notification_outbox_destination ON notification_outbox (destination_key, host, next_attempt);
            PRAGMA user_version = {SchemaVersion};
            """;
        command.ExecuteNonQuery();
    }

    private static StoredFinding? Read(SqliteConnection connection, SqliteTransaction transaction, string host, FindingObservation observation)
    {
        using SqliteCommand command = SlotCommand(connection, transaction, host, observation, """
            SELECT image_id, configured_tag, deployed_digest, available, platform_verified, last_observed, state,
                pending_notification_destination, pending_notification_state
            FROM findings WHERE host = $host AND container_name = $name AND repository = $repo AND kind = $kind
            """);
        using SqliteDataReader reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        return new(Value(0), Value(1), Value(2), reader.GetString(3), reader.GetBoolean(4), reader.GetString(5),
            Enum.Parse<FindingState>(reader.GetString(6)), Value(7),
            reader.IsDBNull(8) ? null : Enum.Parse<FindingState>(reader.GetString(8)));

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
        bool PlatformVerified, string LastObserved, FindingState State, string? PendingNotificationDestination,
        FindingState? PendingNotificationState)
    {
        public bool Matches(FindingObservation observation) => ImageId == observation.ImageId && ConfiguredTag == observation.ConfiguredTag
            && DeployedDigest == observation.DeployedDigest && Available == observation.Available;
    }
}
