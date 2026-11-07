using System.Net.Http.Headers;
using System.Text;

namespace HappyDocker;

public sealed class GhcrConfigurationException : Exception
{
    internal GhcrConfigurationException(string message) : base(message) { }
}

public sealed class GhcrCredentials
{
    internal const string UsernameVariable = "HAPPYDOCKER_GHCR_USERNAME";
    internal const string TokenFileVariable = "HAPPYDOCKER_GHCR_TOKEN_FILE";
    internal const string TokenVariable = "HAPPYDOCKER_GHCR_TOKEN";
    internal AuthenticationHeaderValue Authorization { get; }

    private GhcrCredentials(string username, string token)
    {
        Authorization = new("Basic", Convert.ToBase64String(Encoding.ASCII.GetBytes($"{username}:{token}")));
    }

    public static GhcrCredentials? Load(string? username, string? tokenFile, string? token)
    {
        if (username is null && tokenFile is null && token is null) return null;
        if (tokenFile is not null && token is not null)
            throw new GhcrConfigurationException($"Set only one of {TokenFileVariable} and {TokenVariable}.");
        if (string.IsNullOrEmpty(username) || username.Length > 256
            || username.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_')))
            throw new GhcrConfigurationException($"Set {UsernameVariable} to a valid GitHub username.");
        if (tokenFile is null && token is null)
            throw new GhcrConfigurationException($"Set {TokenFileVariable} or {TokenVariable} to supply a GHCR classic PAT.");

        string source = tokenFile is null ? TokenVariable : TokenFileVariable;
        string value = tokenFile is null ? token! : ReadTokenFile(tokenFile);
        if (value.Length is 0 or > 4096 || value.Any(c => !char.IsAsciiLetterOrDigit(c) && c is not ('-' or '_')))
            throw new GhcrConfigurationException($"{source} must supply a nonempty classic PAT with no whitespace or invalid characters.");
        return new GhcrCredentials(username, value);
    }

    private static string ReadTokenFile(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            throw new GhcrConfigurationException($"Set {TokenFileVariable} to a nonempty file path.");
        try
        {
            using FileStream file = File.OpenRead(path);
            byte[] buffer = new byte[16 * 1024 + 1];
            int length = file.ReadAtLeast(buffer, buffer.Length, false);
            if (length == buffer.Length)
                throw new GhcrConfigurationException($"The file specified by {TokenFileVariable} exceeds 16 KiB.");
            return Encoding.UTF8.GetString(buffer, 0, length).TrimEnd('\r', '\n');
        }
        catch (Exception exception) when (exception is FileNotFoundException or DirectoryNotFoundException)
        {
            throw new GhcrConfigurationException($"The file specified by {TokenFileVariable} was not found.");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new GhcrConfigurationException($"Unable to read the file specified by {TokenFileVariable}. Check the path and read permissions.");
        }
    }
}
