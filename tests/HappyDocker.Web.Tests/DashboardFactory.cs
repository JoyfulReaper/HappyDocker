using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Cryptography;
using HappyDocker;
using HappyDocker.Web;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using HappyDocker.Web.Advisories;

[assembly: Parallelize(Scope = ExecutionScope.MethodLevel)]

namespace HappyDocker.Web.Tests;

internal sealed class DashboardFactory : WebApplicationFactory<Program>
{
    public string DirectoryPath { get; } = Path.Combine(Path.GetTempPath(), "HappyDocker.Web.Tests", Guid.NewGuid().ToString("N"));
    public string DatabasePath => Path.Combine(DirectoryPath, "dashboard.db");
    public string TokenA { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    public string TokenB { get; } = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
    public bool RegisterAgents { get; init; } = true;
    public Dictionary<string, string?> Overrides { get; } = [];
    public AdvisoryService? AdvisoryCache { get; init; }
    public static System.Text.Json.JsonSerializerOptions Json => ReportJson.CreateOptions();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseContentRoot(Path.GetFullPath("../../../../../src/HappyDocker.Web", AppContext.BaseDirectory));
        builder.ConfigureServices(services =>
        {
            // Existing and advisory HTTP tests never call live feeds.
            foreach (var worker in services.Where(service => service.ImplementationType == typeof(AdvisoryRefreshWorker)).ToArray())
                services.Remove(worker);
            if (AdvisoryCache is not null)
            {
                services.RemoveAll<AdvisoryService>();
                services.AddSingleton(AdvisoryCache);
            }
        });
        builder.ConfigureAppConfiguration((_, configuration) =>
        {
            var settings = new Dictionary<string, string?> { ["Web:DatabasePath"] = DatabasePath };
            if (RegisterAgents)
            {
                settings["Web:Agents:0:HostId"] = "host-a";
                settings["Web:Agents:0:Token"] = TokenA;
                settings["Web:Agents:1:HostId"] = "host-b";
                settings["Web:Agents:1:Token"] = TokenB;
            }
            foreach (var setting in Overrides) settings[setting.Key] = setting.Value;
            configuration.AddInMemoryCollection(settings);
        });
    }

    public HttpClient AuthorizedClient(string? token = null)
    {
        HttpClient client = CreateClient();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token ?? TokenA);
        return client;
    }

    public HostSnapshot Host(string id = "host-a") => Services.GetRequiredService<ReportStore>()
        .ReadHosts(Services.GetRequiredService<AgentAuthentication>().Hosts).Single(host => host.HostId == id);

    public static Task<HttpResponseMessage> Post(HttpClient client, AgentReport report) =>
        client.PostAsJsonAsync("/api/agents/reports", report, Json);

    public static AgentReport Report(FindingRunStatus status = FindingRunStatus.Complete, int minutesAgo = 10,
        IReadOnlyList<ReportFinding>? findings = null, string host = "host-a")
    {
        DateTimeOffset time = DateTimeOffset.UtcNow.AddMinutes(-minutesAgo);
        return new()
        {
            SchemaVersion = 1, HostId = host, ReportId = Guid.NewGuid(), ScannedAt = time,
            Status = status, Findings = findings ?? [Finding(time)]
        };
    }

    public static ReportFinding Finding(DateTimeOffset time) => new()
    {
        Kind = FindingKind.VersionCandidate, ContainerName = "nats", ContainerId = "container-id",
        ImageId = "sha256:" + new string('a', 64), Repository = "docker.io/library/nats",
        ConfiguredImage = "nats:2.14.8-alpine", ConfiguredTag = "2.14.8-alpine",
        DeployedDigest = "sha256:" + new string('b', 64), Available = "2.15.0-alpine",
        Platform = "linux/amd64", PlatformVerified = true, Upgrade = VersionUpgrade.Minor,
        State = FindingState.New, ObservedAt = time
    };

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing && Directory.Exists(DirectoryPath)) Directory.Delete(DirectoryPath, recursive: true);
    }
}
