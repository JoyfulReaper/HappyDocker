using System.Globalization;
using System.Text.RegularExpressions;

namespace HappyDocker;

internal sealed record PatchVersion(int Major, int Minor, int Patch, string Variant)
{
    private static readonly Regex Pattern = new(
        @"\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[a-zA-Z][a-zA-Z0-9]*(?:[.-][a-zA-Z0-9]+)*)?\z",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex Unstable = new(
        @"\A(?:(?:alpha|beta|rc|pre|preview|prerelease|releasecandidate|candidate|dev|devel|nightly|snapshot|canary|unstable|experimental|test|edge|latest|next|main|master)(?:[0-9][a-z0-9]*)?|g?[0-9a-f]{7,64})\z",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase | RegexOptions.NonBacktracking);

    internal static PatchVersion? Parse(string? tag)
    {
        if (tag is null || !ImageReference.IsValidTag(tag)) return null;
        Match match = Pattern.Match(tag);
        if (!match.Success || !ParseNumber(match.Groups[1].Value, out int major)
            || !ParseNumber(match.Groups[2].Value, out int minor)
            || !ParseNumber(match.Groups[3].Value, out int patch))
            return null;

        string variant = match.Groups[4].Value;
        if (variant.Split(['-', '.'], StringSplitOptions.RemoveEmptyEntries).Any(part => Unstable.IsMatch(part)))
            return null;
        return new(major, minor, patch, variant);
    }

    private static bool ParseNumber(string value, out int number) =>
        int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out number);

    internal string? HighestCandidate(IEnumerable<string> tags)
    {
        int bestPatch = Patch;
        string? best = null;
        foreach (string tag in tags)
        {
            PatchVersion? candidate = Parse(tag);
            if (candidate is not null && candidate.Major == Major && candidate.Minor == Minor
                && candidate.Variant == Variant && candidate.Patch > bestPatch)
            {
                best = tag;
                bestPatch = candidate.Patch;
            }
        }
        return best;
    }
}
