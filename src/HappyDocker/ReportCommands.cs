using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace HappyDocker;

/// <summary>Local operator inspection and recovery for the report queue.</summary>
public static class ReportCommands
{
    private const string Usage = "Usage: happydocker reports status --state <database> | reports retry --state <database> --id <report-id> | reports discard --state <database> --id <report-id> --confirm";

    public static int Run(string[] args, TextWriter output, TextWriter error, TimeProvider? clock = null)
    {
        if (!TryParse(args, out string action, out string database, out Guid id))
        {
            error.WriteLine(Usage);
            return 1;
        }
        try
        {
            if (OperatingSystem.IsLinux())
            {
                const UnixFileMode shared = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
                    | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
                if ((File.GetUnixFileMode(database) & shared) != 0)
                    throw new ReportCommandException("The state database must be private (mode 0600 on Linux).");
            }
            using var connection = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = Path.GetFullPath(database), Mode = action == "status" ? SqliteOpenMode.ReadOnly : SqliteOpenMode.ReadWrite,
                Pooling = false, DefaultTimeout = 5
            }.ToString());
            connection.Open();
            if (action == "status")
            {
                ValidateDatabase(connection, null);
                WriteStatus(connection, output, (clock ?? TimeProvider.System).GetUtcNow());
                return 0;
            }
            using var transaction = connection.BeginTransaction(deferred: false);
            ValidateDatabase(connection, transaction);
            var matches = ReadRows(connection, transaction).Where(row => row.ReportId == id).ToArray();
            if (matches.Length == 0) throw new ReportCommandException("No queued report has that report ID.");
            if (matches.Length != 1) throw new ReportCommandException("Report ID is ambiguous across queued entries; no changes were made.");
            var selected = matches[0];
            if (selected.LeaseUntil > (clock ?? TimeProvider.System).GetUtcNow().ToUnixTimeSeconds())
                throw new ReportCommandException("The report has an active delivery lease; no changes were made.");
            if (action == "discard")
                output.WriteLine("Warning: discarding an undelivered report may lose observations.");
            using var command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = action == "retry"
                ? "UPDATE report_outbox SET next_attempt = 0 WHERE id = $id"
                : "DELETE FROM report_outbox WHERE id = $id";
            command.Parameters.AddWithValue("$id", selected.RowId);
            command.ExecuteNonQuery();
            transaction.Commit();
            output.WriteLine(action == "retry"
                ? $"Report {id:D} is ready for a subsequent check to retry."
                : $"Discarded report {id:D}.");
            return 0;
        }
        catch (ReportCommandException exception) { error.WriteLine(exception.Message); return 1; }
        catch (Exception exception) when (exception is SqliteException or IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            error.WriteLine("Unable to access the existing finding history database. Check the path, permissions, and database availability.");
            return 1;
        }
    }

    private static bool TryParse(string[] args, out string action, out string database, out Guid id)
    {
        action = args.Length == 0 ? "" : args[0];
        database = "";
        id = Guid.Empty;
        string? idText = null;
        bool confirm = false;
        if (action is not ("status" or "retry" or "discard")) return false;
        for (int i = 1; i < args.Length; i++)
        {
            if (args[i] == "--confirm")
            {
                if (confirm) return false;
                confirm = true;
            }
            else if (args[i] is "--state" or "--id")
            {
                string option = args[i];
                if (++i >= args.Length || string.IsNullOrWhiteSpace(args[i]) || args[i].StartsWith("--", StringComparison.Ordinal)) return false;
                if (option == "--state") { if (database.Length != 0) return false; database = args[i]; }
                else { if (idText is not null) return false; idText = args[i]; }
            }
            else return false;
        }
        if (database.Length == 0) return false;
        if (action == "status") return idText is null && !confirm;
        return (action == "discard") == confirm && idText is { Length: 36 }
            && Guid.TryParseExact(idText, "D", out id) && id != Guid.Empty;
    }

    private static void ValidateDatabase(SqliteConnection connection, SqliteTransaction? transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "PRAGMA application_id";
        long app = (long)command.ExecuteScalar()!;
        command.CommandText = "PRAGMA user_version";
        long version = (long)command.ExecuteScalar()!;
        if (app != FindingHistory.ApplicationId || version != FindingHistory.SchemaVersion)
            throw new ReportCommandException("Expected an existing HappyDocker v5 state database; no migration was performed.");
    }

    private sealed record Row(long RowId, Guid? ReportId, string Host, string Destination, int Attempts, long Next, long LeaseUntil, string? Error);

    private static List<Row> ReadRows(SqliteConnection connection, SqliteTransaction? transaction)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT id, payload, host, destination_key, attempts, next_attempt, lease_until, last_error FROM report_outbox ORDER BY id";
        using var reader = command.ExecuteReader();
        var rows = new List<Row>();
        while (reader.Read())
        {
            Guid? reportId = null;
            try
            {
                using var json = JsonDocument.Parse((byte[])reader[1]);
                if (json.RootElement.ValueKind == JsonValueKind.Object
                    && json.RootElement.TryGetProperty("reportId", out var value) && value.TryGetGuid(out var parsed) && parsed != Guid.Empty)
                    reportId = parsed;
            }
            catch (Exception exception) when (exception is JsonException or InvalidOperationException or FormatException) { }
            rows.Add(new(reader.GetInt64(0), reportId, reader.GetString(2), reader.GetString(3), reader.GetInt32(4),
                reader.GetInt64(5), reader.GetInt64(6), reader.IsDBNull(7) ? null : reader.GetString(7)));
        }
        return rows;
    }

    private static void WriteStatus(SqliteConnection connection, TextWriter output, DateTimeOffset now)
    {
        var rows = ReadRows(connection, null);
        if (rows.Count == 0) { output.WriteLine("Report queue is empty."); return; }
        foreach (var row in rows)
        {
            string host = AgentReportValidation.ValidHost(row.Host) ? row.Host : "<invalid host>";
            string destination = Regex.IsMatch(row.Destination, @"\A[0-9a-f]{64}\z", RegexOptions.NonBacktracking) ? row.Destination : "<invalid destination>";
            string lease = row.LeaseUntil > now.ToUnixTimeSeconds() ? $"active until {Timestamp(row.LeaseUntil)}"
                : row.LeaseUntil > 0 ? "expired" : "none";
            output.WriteLine($"Report {row.ReportId?.ToString("D") ?? "<invalid report ID>"} | host {host} | destination {destination} | attempts {row.Attempts} | next retry {(row.Next <= now.ToUnixTimeSeconds() ? "ready" : Timestamp(row.Next))} | lease {lease} | last error {SafeError(row.Error)}");
        }
    }

    private static string SafeError(string? error) => error is null ? "none"
        : Regex.IsMatch(error, @"\AHTTP [1-5][0-9]{2}\z", RegexOptions.NonBacktracking) ? error
        : error is "Request timed out" or "Network or response error" or "Response too large" or "Invalid acknowledgment" or "Delivery interrupted"
            ? error : "<unrecognized error>";
    private static string Timestamp(long seconds) => seconds is >= 0 and <= 253402300799
        ? DateTimeOffset.FromUnixTimeSeconds(seconds).ToString("O") : "<invalid time>";
    private sealed class ReportCommandException(string message) : Exception(message);
}
