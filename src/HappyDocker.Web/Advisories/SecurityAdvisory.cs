namespace HappyDocker.Web.Advisories;

public enum AdvisorySource { CisaKev, GitHub }

// Only normalized display fields are cached; full feed documents are discarded.
public sealed record AdvisoryItem(AdvisorySource Source, string SourceId, string? CveId,
    string Title, string Description, string? Severity, IReadOnlyList<string> Products,
    DateTimeOffset PublishedAt, Uri Link);

public sealed record SecurityAdvisory(string Key, string? CveId, IReadOnlyList<AdvisoryItem> Items)
{
    private AdvisoryItem Primary => Items.OrderByDescending(item => item.Severity == "critical" ? 2 : item.Severity == "high" ? 1 : 0)
        .ThenByDescending(item => item.PublishedAt).First();
    public string Title => Primary.Title;
    public string Description => Primary.Description;
    public string? Severity => Primary.Severity;
    public bool KnownExploited => Items.Any(item => item.Source == AdvisorySource.CisaKev);
    public DateTimeOffset LatestDate => Items.Max(item => item.PublishedAt);
    public IEnumerable<string> Products => Items.SelectMany(item => item.Products).Distinct(StringComparer.OrdinalIgnoreCase);
}

public sealed record AdvisoryFeedState(AdvisorySource Source, IReadOnlyList<AdvisoryItem> Items,
    DateTimeOffset? LastSuccess, DateTimeOffset? LastAttempt, DateTimeOffset NextAttempt,
    string? Error, bool Limited = false, int Skipped = 0, bool ViaMirror = false)
{
    public bool IsStale(DateTimeOffset now) => LastSuccess is null || Error is not null
        || now - LastSuccess >= TimeSpan.FromHours(1);
}

public sealed record AdvisorySnapshot(IReadOnlyList<SecurityAdvisory> Advisories,
    IReadOnlyList<AdvisoryFeedState> Feeds, DateTimeOffset CapturedAt);
