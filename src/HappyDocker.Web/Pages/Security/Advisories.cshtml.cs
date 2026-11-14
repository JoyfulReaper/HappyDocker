using System.ComponentModel.DataAnnotations;
using HappyDocker.Web.Advisories;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace HappyDocker.Web.Pages.Security;

public sealed class AdvisoriesModel(AdvisoryService advisories) : PageModel
{
    public const int MaximumDisplayed = 100;
    [BindProperty(SupportsGet = true), StringLength(200)]
    public string? Search { get; set; }
    [BindProperty(SupportsGet = true)]
    public string? Severity { get; set; }
    [BindProperty(SupportsGet = true)]
    public string? Source { get; set; }
    [BindProperty(SupportsGet = true)]
    public DateOnly? From { get; set; }
    [BindProperty(SupportsGet = true)]
    public DateOnly? To { get; set; }
    public AdvisorySnapshot Snapshot { get; private set; } = null!;
    public IReadOnlyList<SecurityAdvisory> Results { get; private set; } = [];
    public int MatchCount { get; private set; }

    public void OnGet()
    {
        // Reading or filtering a page never fetches a feed or changes its refresh deadline.
        Snapshot = advisories.GetSnapshot();
        if (Severity is not (null or "" or "high" or "critical" or "unknown"))
            ModelState.AddModelError(nameof(Severity), "Choose a listed severity.");
        if (Source is not (null or "" or "cisa" or "github"))
            ModelState.AddModelError(nameof(Source), "Choose a listed source.");
        if (From > To) ModelState.AddModelError(nameof(From), "The start date must not follow the end date.");
        if (!ModelState.IsValid) return;

        string? search = Search?.Trim();
        var matches = Snapshot.Advisories.Where(advisory =>
            (string.IsNullOrEmpty(Severity) || (Severity == "unknown" ? advisory.Severity is null : advisory.Severity == Severity))
            && advisory.Items.Any(item => (string.IsNullOrEmpty(Source)
                || (Source == "cisa" ? item.Source == AdvisorySource.CisaKev : item.Source == AdvisorySource.GitHub))
                && (From is null || DateOnly.FromDateTime(item.PublishedAt.UtcDateTime) >= From)
                && (To is null || DateOnly.FromDateTime(item.PublishedAt.UtcDateTime) <= To))
            && (string.IsNullOrEmpty(search) || advisory.Key.Contains(search, StringComparison.OrdinalIgnoreCase)
                || advisory.Items.Any(item => item.Title.Contains(search, StringComparison.OrdinalIgnoreCase)
                    || item.Description.Contains(search, StringComparison.OrdinalIgnoreCase)
                    || item.SourceId.Contains(search, StringComparison.OrdinalIgnoreCase)
                    || item.Products.Any(product => product.Contains(search, StringComparison.OrdinalIgnoreCase)))))
            .ToArray();
        MatchCount = matches.Length;
        Results = matches.Take(MaximumDisplayed).ToArray();
    }

    public static string SourceName(AdvisorySource source) => source == AdvisorySource.CisaKev ? "CISA KEV" : "GitHub";
}
