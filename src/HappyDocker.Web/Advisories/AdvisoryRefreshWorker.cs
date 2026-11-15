namespace HappyDocker.Web.Advisories;

public sealed class AdvisoryRefreshWorker(AdvisoryService advisories, TimeProvider clock) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            await advisories.RefreshAsync(stoppingToken);
            // Per-source due times gate refreshes. Polling does not cause hourly retries to be bypassed.
            await Task.Delay(TimeSpan.FromMinutes(1), clock, stoppingToken);
        }
    }
}
