using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace HappyDocker.Web.Advisories;

public sealed record ParsedAdvisories(IReadOnlyList<AdvisoryItem> Items, int Skipped);

public static class AdvisoryParser
{
    public static ParsedAdvisories ParseCisa(JsonElement root, DateTimeOffset cutoff, DateTimeOffset now)
    {
        if (root.ValueKind != JsonValueKind.Object || !root.TryGetProperty("vulnerabilities", out var entries)
            || entries.ValueKind != JsonValueKind.Array || entries.GetArrayLength() > 25000)
            throw new JsonException("Invalid KEV catalog.");
        var items = new List<AdvisoryItem>();
        int skipped = 0;
        foreach (var entry in entries.EnumerateArray())
        {
            string? cve = Cve(Text(entry, "cveID", 32, truncate: false));
            string? title = Text(entry, "vulnerabilityName", 500);
            string? description = Text(entry, "shortDescription", 600);
            string? product = Text(entry, "product", 200);
            string? vendor = Text(entry, "vendorProject", 200);
            if (cve is null || title is null || description is null || product is null || vendor is null
                || !DateOnly.TryParseExact(Text(entry, "dateAdded", 10, truncate: false), "yyyy-MM-dd", CultureInfo.InvariantCulture,
                    DateTimeStyles.None, out var date))
            { skipped++; continue; }
            var added = new DateTimeOffset(date.ToDateTime(TimeOnly.MinValue, DateTimeKind.Utc));
            if (added > now.AddDays(1)) { skipped++; continue; }
            if (added < cutoff) continue;
            items.Add(new(AdvisorySource.CisaKev, cve, cve, title, description, null,
                [$"{vendor} / {product}"], added, new("https://www.cisa.gov/known-exploited-vulnerabilities-catalog")));
        }
        RejectEntirelyInvalid(entries.GetArrayLength(), skipped);
        return new(items, skipped);
    }

    public static ParsedAdvisories ParseGitHub(JsonElement root, DateTimeOffset cutoff, DateTimeOffset now)
    {
        if (root.ValueKind != JsonValueKind.Array || root.GetArrayLength() > 100)
            throw new JsonException("Invalid GitHub advisory page.");
        var items = new List<AdvisoryItem>();
        int skipped = 0;
        foreach (var entry in root.EnumerateArray())
        {
            string? id = Text(entry, "ghsa_id", 19, truncate: false);
            string? title = Text(entry, "summary", 500);
            string? severity = Text(entry, "severity", 16, truncate: false)?.ToLowerInvariant();
            string? cveText = Text(entry, "cve_id", 32, truncate: false);
            string? cve = Cve(cveText);
            if (id is null || !Regex.IsMatch(id, @"\AGHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}\z", RegexOptions.NonBacktracking)
                || title is null || severity is not ("high" or "critical")
                || (entry.TryGetProperty("cve_id", out var rawCve) && rawCve.ValueKind != JsonValueKind.Null && cve is null)
                || !DateTimeOffset.TryParse(Text(entry, "published_at", 40, truncate: false), CultureInfo.InvariantCulture,
                    DateTimeStyles.None, out var published) || published < DateTimeOffset.UnixEpoch || published > now.AddDays(1)
                || !entry.TryGetProperty("vulnerabilities", out var vulnerabilities) || vulnerabilities.ValueKind != JsonValueKind.Array)
            { skipped++; continue; }
            if (entry.TryGetProperty("withdrawn_at", out var withdrawn) && withdrawn.ValueKind != JsonValueKind.Null) continue;
            if (published < cutoff) continue;
            if (cve is null && entry.TryGetProperty("identifiers", out var identifiers) && identifiers.ValueKind == JsonValueKind.Array)
                cve = identifiers.EnumerateArray().Take(100).Where(identifier => Text(identifier, "type", 10) == "CVE")
                    .Select(identifier => Cve(Text(identifier, "value", 32, truncate: false))).FirstOrDefault(value => value is not null);
            var products = new List<string>();
            foreach (var vulnerability in vulnerabilities.EnumerateArray().Take(100))
            {
                if (vulnerability.ValueKind != JsonValueKind.Object || !vulnerability.TryGetProperty("package", out var package)) continue;
                if (Text(package, "name", 200) is { } name)
                    products.Add(Text(package, "ecosystem", 40) is { } ecosystem ? $"{ecosystem}: {name}" : name);
            }
            // Construct a canonical official link from a validated ID. Never trust html_url, references, or description URLs.
            items.Add(new(AdvisorySource.GitHub, id, cve, title,
                Text(entry, "description", 600) ?? "No description provided by GitHub.", severity,
                products.Distinct(StringComparer.Ordinal).Take(20).ToArray(), published.ToUniversalTime(),
                new($"https://github.com/advisories/{id}")));
        }
        RejectEntirelyInvalid(root.GetArrayLength(), skipped);
        return new(items, skipped);
    }

    public static IReadOnlyList<SecurityAdvisory> Merge(IEnumerable<AdvisoryItem> items) => items
        .GroupBy(item => item.CveId ?? item.SourceId, StringComparer.OrdinalIgnoreCase)
        .Select(group => new SecurityAdvisory(group.Key, group.First().CveId,
            group.GroupBy(item => (item.Source, item.SourceId)).Select(duplicates => duplicates.OrderByDescending(item => item.PublishedAt).First())
                .OrderBy(item => item.Source).ThenBy(item => item.SourceId, StringComparer.Ordinal).ToArray()))
        .OrderByDescending(item => item.LatestDate).ThenBy(item => item.Key, StringComparer.Ordinal).ToArray();

    private static string? Cve(string? value) => value is not null
        && Regex.IsMatch(value, @"\ACVE-[0-9]{4}-[0-9]{4,19}\z", RegexOptions.NonBacktracking | RegexOptions.IgnoreCase)
        ? value.ToUpperInvariant() : null;

    private static string? Text(JsonElement entry, string property, int maximum, bool truncate = true)
    {
        if (entry.ValueKind != JsonValueKind.Object || !entry.TryGetProperty(property, out var value)
            || value.ValueKind != JsonValueKind.String) return null;
        string text = value.GetString()!.Trim();
        if (string.IsNullOrWhiteSpace(text) || !truncate && text.Length > maximum) return null;
        // Keep descriptions plain text and bounded; Razor performs HTML encoding at render time.
        text = string.Concat(text.Take(maximum).Select(character => char.IsControl(character) ? ' ' : character));
        return text;
    }

    private static void RejectEntirelyInvalid(int count, int skipped)
    {
        if (count > 0 && skipped == count) throw new JsonException("Feed contains no valid records.");
    }
}
