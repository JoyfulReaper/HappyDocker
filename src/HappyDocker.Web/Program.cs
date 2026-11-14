using System.Text.Json;
using HappyDocker;
using HappyDocker.Web;
using Microsoft.Data.Sqlite;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.ConfigureKestrel(options => options.Limits.MaxRequestBodySize = ReportValidation.MaximumBytes);
builder.Services.AddRazorPages();
builder.Services.AddSingleton<AgentAuthentication>();
builder.Services.AddSingleton<ReportStore>();
var app = builder.Build();
// Validate configuration and database ownership before accepting traffic.
_ = app.Services.GetRequiredService<AgentAuthentication>();
_ = app.Services.GetRequiredService<ReportStore>();

app.Use(async (context, next) =>
{
    context.Response.OnStarting(() =>
    {
        context.Response.Headers.CacheControl = "no-store";
        context.Response.Headers.XContentTypeOptions = "nosniff";
        context.Response.Headers["Referrer-Policy"] = "no-referrer";
        context.Response.Headers.ContentSecurityPolicy = "default-src 'self'; style-src 'self'; script-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'";
        return Task.CompletedTask;
    });
    try { await next(context); }
    catch (SqliteException)
    {
        app.Logger.LogWarning("Dashboard storage request failed.");
        context.Response.Clear();
        context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
        await context.Response.WriteAsync("Dashboard storage unavailable. Try again later.");
    }
    catch (Exception) when (!context.RequestAborted.IsCancellationRequested)
    {
        app.Logger.LogWarning("Dashboard request failed.");
        // Do not expose request bodies, authentication headers, local paths, or exception details.
        context.Response.Clear();
        context.Response.StatusCode = StatusCodes.Status500InternalServerError;
        await context.Response.WriteAsync("The dashboard could not complete the request.");
    }
});
app.UseStaticFiles();
app.MapRazorPages();
app.MapPost("/api/agents/reports", async (HttpContext context, AgentAuthentication authentication, ReportStore store) =>
{
    string? host = authentication.Authenticate(context.Request);
    if (host is null)
    {
        context.Response.Headers.WWWAuthenticate = "Bearer";
        return Results.Unauthorized();
    }
    if (!context.Request.HasJsonContentType()) return Results.StatusCode(StatusCodes.Status415UnsupportedMediaType);
    if (context.Request.ContentLength > ReportValidation.MaximumBytes)
        return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
    AgentReport? report;
    try
    {
        // Also enforce the limit without Content-Length (chunked requests and test hosts).
        using var buffer = new MemoryStream();
        byte[] chunk = new byte[8192];
        int count;
        while ((count = await context.Request.Body.ReadAsync(chunk, context.RequestAborted)) > 0)
        {
            if (buffer.Length + count > ReportValidation.MaximumBytes)
                return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
            buffer.Write(chunk, 0, count);
        }
        report = JsonSerializer.Deserialize<AgentReport>(buffer.GetBuffer().AsSpan(0, (int)buffer.Length), ReportJson.CreateOptions());
    }
    catch (BadHttpRequestException exception) when (exception.StatusCode == StatusCodes.Status413PayloadTooLarge)
    {
        return Results.StatusCode(StatusCodes.Status413PayloadTooLarge);
    }
    catch (JsonException) { return Results.BadRequest(new { error = "Invalid report JSON or missing required fields." }); }
    if (report is null) return Results.BadRequest(new { error = "A report is required." });
    if (!string.Equals(report.HostId, host, StringComparison.Ordinal)) return Results.StatusCode(StatusCodes.Status403Forbidden);
    string? error = ReportValidation.Validate(report, DateTimeOffset.UtcNow);
    if (error is not null) return Results.BadRequest(new { error });
    IngestionOutcome outcome = store.Ingest(report, DateTimeOffset.UtcNow);
    return outcome == IngestionOutcome.Conflict
        ? Results.Conflict(new { error = "Report ID reused with different content, or scan timestamp already occupied." })
        : Results.Ok(new { outcome = outcome.ToString().ToLowerInvariant() });
}).DisableAntiforgery(); // Machine-only bearer authentication; browser cookies do not authorize ingestion.
app.Run();

public partial class Program;
