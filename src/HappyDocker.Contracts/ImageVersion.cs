using System.Globalization;
using System.Text.RegularExpressions;

namespace HappyDocker;

public enum VersionUpgrade { Patch, Minor, Major }

internal sealed record ImageVersion(int Major, int Minor, int Patch, string Variant, bool HasVPrefix) : IComparable<ImageVersion>
{
    private static readonly Regex Pattern = new(
        @"\Av?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[a-zA-Z][a-zA-Z0-9]*(?:[.-][a-zA-Z0-9]+)*)?\z",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);
    private static readonly Regex Unstable = new(
        @"\A(?:(?:alpha|beta|rc|pre|preview|prerelease|releasecandidate|candidate|dev|devel|nightly|snapshot|canary|unstable|experimental|test|edge|latest|next|main|master)(?:[0-9][a-z0-9]*)?|g?[0-9a-f]{7,64})\z",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase | RegexOptions.NonBacktracking);

    internal static ImageVersion? Parse(string? tag)
    {
        if (tag is null || !Regex.IsMatch(tag, @"\A[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,127}\z",
            RegexOptions.CultureInvariant | RegexOptions.NonBacktracking)) return null;
        Match match = Pattern.Match(tag);
        if (!match.Success || !ParseNumber(match.Groups[1].Value, out int major)
            || !ParseNumber(match.Groups[2].Value, out int minor)
            || !ParseNumber(match.Groups[3].Value, out int patch))
            return null;

        string variant = match.Groups[4].Value;
        if (variant.Split(['-', '.'], StringSplitOptions.RemoveEmptyEntries).Any(part => Unstable.IsMatch(part)))
            return null;
        return new(major, minor, patch, variant, tag[0] == 'v');
    }

    private static bool ParseNumber(string value, out int number) =>
        int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out number);

    public int CompareTo(ImageVersion? other)
    {
        if (other is null) return 1;
        int major = Major.CompareTo(other.Major);
        if (major != 0) return major;
        int minor = Minor.CompareTo(other.Minor);
        return minor != 0 ? minor : Patch.CompareTo(other.Patch);
    }

    internal VersionUpgrade? UpgradeTo(string? tag)
    {
        ImageVersion? candidate = Parse(tag);
        if (candidate is null || candidate.HasVPrefix != HasVPrefix || candidate.Variant != Variant || candidate.CompareTo(this) <= 0)
            return null;
        return candidate.Major > Major ? VersionUpgrade.Major
            : candidate.Minor > Minor ? VersionUpgrade.Minor : VersionUpgrade.Patch;
    }

    internal string[] Candidates(IEnumerable<string> tags) => tags
        .Select(tag => (Tag: tag, Version: Parse(tag)))
        .Where(candidate => candidate.Version is not null && candidate.Version.HasVPrefix == HasVPrefix
            && candidate.Version.Variant == Variant && candidate.Version.CompareTo(this) > 0)
        .OrderByDescending(candidate => candidate.Version)
        .Select(candidate => candidate.Tag).ToArray();
}
