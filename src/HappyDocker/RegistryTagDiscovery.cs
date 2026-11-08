using System.Globalization;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace HappyDocker;

internal sealed record TagEnumeration(IReadOnlyCollection<string> Tags, string? IncompleteReason = null,
    DateTimeOffset? RetryAfter = null);

internal static class RegistryTagDiscovery
{
    private const int PageSize = 100;
    private const int MaxPages = 20;
    private const int MaxTags = 2000;
    private static readonly Regex NextLink = new(@"\A\s*<([^<>\s]+)>\s*;\s*rel\s*=\s*(?:""next""|next)\s*\z",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase | RegexOptions.NonBacktracking);

    internal static async Task<TagEnumeration> ListAsync(RegistryClient registry, string repository, CancellationToken cancellationToken)
    {
        var tags = new HashSet<string>(StringComparer.Ordinal);
        var cursors = new HashSet<string>(StringComparer.Ordinal);
        int count = 0;
        string? last = null;
        int size = PageSize;
        Uri endpoint = RegistryClient.DockerHubTagEndpoint(repository);
        try
        {
            for (int page = 0; page < MaxPages; page++)
            {
                var (bytes, links) = await registry.GetTagPageAsync(repository, size, last, cancellationToken);
                using JsonDocument document = JsonValue.Parse(bytes);
                JsonElement root = document.RootElement;
                if (JsonValue.String(root, "name") != repository || !root.TryGetProperty("tags", out JsonElement values)
                    || values.ValueKind != JsonValueKind.Array || values.GetArrayLength() > size)
                    return new(tags, "Registry returned invalid tag page metadata.");

                string?[] pageTags = values.EnumerateArray()
                    .Select(value => value.ValueKind == JsonValueKind.String ? value.GetString() : null).ToArray();
                if (pageTags.Any(tag => tag is null || !ImageReference.IsValidTag(tag))
                    || (last is not null && pageTags.Contains(last, StringComparer.Ordinal)))
                    return new(tags, "Registry returned invalid tags or repeated the pagination cursor.");
                foreach (string? tag in pageTags)
                {
                    if (++count > MaxTags) return new(tags, "Tag count limit reached.");
                    tags.Add(tag!);
                }

                if (links.Length == 0)
                {
                    // Some registries omit Link even when there are further tags. Do not call a full page exhaustive.
                    return new(tags, pageTags.Length == size ? "A full tag page had no continuation link." : null);
                }
                if (!TryReadCursor(endpoint, links, pageTags.LastOrDefault(), out string? next, out size) || !cursors.Add(next!))
                    return new(tags, "Registry returned an unsafe, malformed, or repeated pagination link.");
                if (count == MaxTags) return new(tags, "Tag count limit reached.");
                last = next;
            }
            return new(tags, "Tag page limit reached.");
        }
        catch (RegistryException exception)
        {
            return new(tags, $"{DockerCheck.Label(exception.Result.Status)}. {exception.Result.Reason}", exception.Result.RetryAfter);
        }
        catch (JsonException) { return new(tags, "Registry returned malformed tag page JSON."); }
    }

    private static bool TryReadCursor(Uri endpoint, string[] links, string? expectedLast, out string? last, out int size)
    {
        last = null;
        size = PageSize;
        if (links.Length != 1 || expectedLast is null) return false;
        Match match = NextLink.Match(links[0]);
        if (!match.Success || !Uri.TryCreate(endpoint, match.Groups[1].Value, out Uri? target)
            || target.GetLeftPart(UriPartial.Path) != endpoint.AbsoluteUri || target.UserInfo.Length != 0 || target.Fragment.Length != 0)
            return false;

        bool seenSize = false;
        foreach (string field in target.Query.TrimStart('?').Split('&'))
        {
            string[] pair = field.Split('=', 2);
            if (pair.Length != 2) return false;
            string value = Uri.UnescapeDataString(pair[1]);
            if (pair[0] == "last" && last is null)
                last = value;
            else if (pair[0] == "n" && !seenSize && int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out size)
                && size is > 0 and <= PageSize)
                seenSize = true;
            else
                return false;
        }
        // Rebuild a bounded request to the fixed endpoint using only the checked cursor and page size.
        return last == expectedLast;
    }
}
