using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace HappyDocker.Web;

public enum IngestionOutcome { Accepted, Duplicate, Older, Conflict }
public sealed record HostSnapshot(string HostId, AgentReport? LatestReport, DateTimeOffset? ReceivedAt,
    IReadOnlyList<ReportFinding> Findings);

public sealed class ReportStore
{
    private const int ApplicationId = 0x48445742; // HDWB; deliberately distinct from scanner history.
    private readonly string connectionString;
    private static readonly JsonSerializerOptions Json = ReportJson.CreateOptions();

    public ReportStore(IConfiguration configuration, IWebHostEnvironment environment)
    {
        string path = Path.GetFullPath(configuration["Web:DatabasePath"] ?? "App_Data/dashboard.db",
            environment.ContentRootPath);
        string directory = Path.GetDirectoryName(path)!;
        if (OperatingSystem.IsLinux())
        {
            Directory.CreateDirectory(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
            try
            {
                using var file = new FileStream(path, new FileStreamOptions
                {
                    Mode = FileMode.CreateNew, Access = FileAccess.Write,
                    UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite
                });
            }
            catch (IOException) when (File.Exists(path)) { }
            if ((File.GetUnixFileMode(path) & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite
                | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) != 0)
                throw new InvalidOperationException("The dashboard database must be private (mode 0600) in a private directory.");
        }
        else Directory.CreateDirectory(directory);
        connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = path, Pooling = false, DefaultTimeout = 5, ForeignKeys = true
        }.ToString();
        using var connection = Open();
        using var transaction = connection.BeginTransaction(deferred: false);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "PRAGMA application_id";
        long identity = (long)command.ExecuteScalar()!;
        command.CommandText = "PRAGMA user_version";
        long version = (long)command.ExecuteScalar()!;
        if (identity != ApplicationId || version != 1)
        {
            command.CommandText = "SELECT count(*) FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*'";
            if (identity != 0 || version != 0 || (long)command.ExecuteScalar()! != 0)
                throw new InvalidOperationException("Not a supported HappyDocker.Web database. Choose a separate new database path.");
            command.CommandText = $"""
                CREATE TABLE hosts (
                    host_id TEXT PRIMARY KEY, report_id TEXT NOT NULL, scanned_at TEXT NOT NULL,
                    received_at TEXT NOT NULL, report_json TEXT NOT NULL
                );
                CREATE TABLE findings (
                    host_id TEXT NOT NULL REFERENCES hosts(host_id), container_name TEXT NOT NULL,
                    repository TEXT NOT NULL, kind TEXT NOT NULL, finding_json TEXT NOT NULL,
                    PRIMARY KEY (host_id, container_name, repository, kind)
                );
                CREATE TABLE receipts (
                    host_id TEXT NOT NULL REFERENCES hosts(host_id), report_id TEXT NOT NULL,
                    payload_hash TEXT NOT NULL, PRIMARY KEY (host_id, report_id)
                );
                PRAGMA application_id = {ApplicationId};
                PRAGMA user_version = 1;
                """;
            command.ExecuteNonQuery();
        }
        transaction.Commit();
    }

    public IngestionOutcome Ingest(AgentReport report, DateTimeOffset receivedAt)
    {
        string payload = JsonSerializer.Serialize(report, Json);
        string hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
        using var connection = Open();
        // Immediate transaction serializes competing submissions, including the ordering/dedup checks.
        using var transaction = connection.BeginTransaction(deferred: false);
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.Parameters.AddWithValue("$host", report.HostId);
        command.Parameters.AddWithValue("$id", report.ReportId.ToString("D"));
        command.CommandText = "SELECT payload_hash FROM receipts WHERE host_id = $host AND report_id = $id";
        if (command.ExecuteScalar() is string previousHash)
            return previousHash == hash ? IngestionOutcome.Duplicate : IngestionOutcome.Conflict;
        command.CommandText = "SELECT scanned_at FROM hosts WHERE host_id = $host";
        if (command.ExecuteScalar() is string previousTime)
        {
            int comparison = string.CompareOrdinal(Timestamp(report.ScannedAt), previousTime);
            if (comparison < 0) return IngestionOutcome.Older;
            if (comparison == 0) return IngestionOutcome.Conflict;
        }

        command.CommandText = """
            INSERT INTO hosts VALUES ($host, $id, $scanned, $received, $payload)
            ON CONFLICT (host_id) DO UPDATE SET report_id = excluded.report_id, scanned_at = excluded.scanned_at,
                received_at = excluded.received_at, report_json = excluded.report_json
            """;
        command.Parameters.AddWithValue("$scanned", Timestamp(report.ScannedAt));
        command.Parameters.AddWithValue("$received", Timestamp(receivedAt));
        command.Parameters.AddWithValue("$payload", payload);
        command.ExecuteNonQuery();
        command.CommandText = "INSERT INTO receipts VALUES ($host, $id, $hash)";
        command.Parameters.AddWithValue("$hash", hash);
        command.ExecuteNonQuery();

        var current = ReadFindings(connection, transaction, report.HostId).ToDictionary(Key);
        foreach (ReportFinding finding in report.Findings)
        {
            // Only a complete scan may assert resolution. Positive observations still help partial/deferred scans.
            if (finding.State == FindingState.Resolved && report.Status != FindingRunStatus.Complete) continue;
            if (!current.TryGetValue(Key(finding), out var previous) || finding.ObservedAt >= previous.ObservedAt)
                SaveFinding(connection, transaction, report.HostId, finding);
        }
        if (report.Status == FindingRunStatus.Complete)
        {
            var supplied = report.Findings.Select(Key).ToHashSet();
            foreach (ReportFinding previous in current.Values)
                if (!supplied.Contains(Key(previous)) && previous.State != FindingState.Resolved
                    && previous.ObservedAt <= report.ScannedAt)
                    SaveFinding(connection, transaction, report.HostId,
                        previous with { State = FindingState.Resolved, ObservedAt = report.ScannedAt });
        }
        transaction.Commit();
        return IngestionOutcome.Accepted;
    }

    public IReadOnlyList<HostSnapshot> ReadHosts(IEnumerable<string> configuredHosts)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        var hosts = configuredHosts.ToDictionary(host => host,
            host => new HostSnapshot(host, null, null, []), StringComparer.Ordinal);
        using (var command = connection.CreateCommand())
        {
            command.Transaction = transaction;
            command.CommandText = "SELECT host_id, report_json, received_at FROM hosts";
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                string host = reader.GetString(0);
                hosts[host] = new(host, JsonSerializer.Deserialize<AgentReport>(reader.GetString(1), Json),
                    DateTimeOffset.Parse(reader.GetString(2), CultureInfo.InvariantCulture), []);
            }
        }
        foreach (string host in hosts.Keys.ToArray())
            hosts[host] = hosts[host] with { Findings = ReadFindings(connection, transaction, host) };
        transaction.Commit();
        return hosts.Values.OrderBy(host => host.HostId, StringComparer.Ordinal).ToArray();
    }

    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        return connection;
    }

    private static (string Container, string Repository, FindingKind Kind) Key(ReportFinding finding) =>
        (finding.ContainerName, finding.Repository, finding.Kind);

    private static string Timestamp(DateTimeOffset value) => value.UtcDateTime.ToString("O", CultureInfo.InvariantCulture);

    private static List<ReportFinding> ReadFindings(SqliteConnection connection, SqliteTransaction transaction, string host)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT finding_json FROM findings WHERE host_id = $host ORDER BY container_name, repository, kind";
        command.Parameters.AddWithValue("$host", host);
        using var reader = command.ExecuteReader();
        var findings = new List<ReportFinding>();
        while (reader.Read()) findings.Add(JsonSerializer.Deserialize<ReportFinding>(reader.GetString(0), Json)!);
        return findings;
    }

    private static void SaveFinding(SqliteConnection connection, SqliteTransaction transaction, string host, ReportFinding finding)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            INSERT INTO findings VALUES ($host, $container, $repository, $kind, $json)
            ON CONFLICT (host_id, container_name, repository, kind) DO UPDATE SET finding_json = excluded.finding_json
            """;
        command.Parameters.AddWithValue("$host", host);
        command.Parameters.AddWithValue("$container", finding.ContainerName);
        command.Parameters.AddWithValue("$repository", finding.Repository);
        command.Parameters.AddWithValue("$kind", finding.Kind.ToString());
        command.Parameters.AddWithValue("$json", JsonSerializer.Serialize(finding, Json));
        command.ExecuteNonQuery();
    }
}
