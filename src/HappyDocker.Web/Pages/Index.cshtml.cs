using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HappyDocker.Web.Pages;

public sealed class IndexModel(ReportStore store, AgentAuthentication authentication) : PageModel
{
    public IReadOnlyList<HostSnapshot> Hosts { get; private set; } = [];
    public int OutstandingCount => Hosts.Sum(host => host.Findings.Count(finding => finding.State != FindingState.Resolved));
    public void OnGet() => Hosts = store.ReadHosts(authentication.Hosts);
}
