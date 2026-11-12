using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;

namespace HappyDocker;

public sealed class NtfyConfigurationException(string message) : Exception(message);
public sealed record NtfyDeliveryResult(bool Successful, string Detail, DateTimeOffset? RetryAfter = null);

public sealed class NtfyClient : IDisposable
{
    public const string TokenFileVariable = "HAPPYDOCKER_NTFY_TOKEN_FILE";
    public const int MaximumMessageBytes = 3800;
    private readonly Uri destination;
    private readonly AuthenticationHeaderValue? authorization;
    private readonly HttpClient http;
    private readonly TimeSpan requestTimeout;
    public string DestinationKey { get; }

    public NtfyClient(string destination, string? tokenFile = null, HttpMessageHandler? handler = null,
        TimeSpan? requestTimeout = null)
    {
        this.destination = ParseDestination(destination);
        if (tokenFile is not null)
        {
            if (this.destination.Scheme != Uri.UriSchemeHttps)
                throw new NtfyConfigurationException("Authenticated ntfy delivery requires HTTPS.");
            authorization = new("Bearer", ReadToken(tokenFile));
        }
        DestinationKey = GetDestinationKey(this.destination);
        this.requestTimeout = requestTimeout ?? TimeSpan.FromSeconds(8);
        http = new HttpClient(handler ?? new HttpClientHandler
        {
            AllowAutoRedirect = false, UseCookies = false, MaxResponseHeadersLength = 16
        }) { Timeout = Timeout.InfiniteTimeSpan };
    }

    public static Uri ParseDestination(string destination)
    {
        if (destination.Length > 2048 || destination.Any(char.IsWhiteSpace)
            || !Uri.TryCreate(destination, UriKind.Absolute, out Uri? uri)
            || uri.Scheme is not ("https" or "http") || string.IsNullOrEmpty(uri.Host)
            || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0
            || uri.AbsolutePath == "/" || uri.AbsolutePath.EndsWith('/')
            || Uri.UnescapeDataString(uri.AbsolutePath).Any(char.IsControl))
            throw new NtfyConfigurationException("Set --notify-ntfy to an HTTP or HTTPS topic URL without credentials, query parameters, or fragments.");
        return uri;
    }

    internal static string GetDestinationKey(Uri destination) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(destination.AbsoluteUri)));

    public async Task<NtfyDeliveryResult> SendAsync(string message, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        if (string.IsNullOrWhiteSpace(message) || Encoding.UTF8.GetByteCount(message) > MaximumMessageBytes)
            return new(false, "ntfy message exceeds the supported size or is empty.");
        using var request = new HttpRequestMessage(HttpMethod.Post, destination);
        request.Headers.Authorization = authorization;
        request.Headers.Add("Title", "HappyDocker image finding");
        request.Content = new StringContent(message, Encoding.UTF8, "text/plain");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(requestTimeout);
        try
        {
            using HttpResponseMessage response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            if (response.IsSuccessStatusCode) return new(true, "ntfy accepted the message.");
            DateTimeOffset? retry = response.Headers.RetryAfter?.Date;
            if (response.Headers.RetryAfter?.Delta is { } delta)
                retry = delta < DateTimeOffset.MaxValue - now ? now + delta : DateTimeOffset.MaxValue;
            return new(false, $"ntfy returned HTTP {(int)response.StatusCode}.", retry);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return new(false, "ntfy request timed out.");
        }
        catch (Exception exception) when (exception is HttpRequestException or IOException)
        {
            return new(false, "ntfy network request failed.");
        }
    }

    private static string ReadToken(string path)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path)) throw new ArgumentException();
            using var file = File.OpenRead(path);
            byte[] buffer = new byte[4097];
            int count = file.ReadAtLeast(buffer, buffer.Length, false);
            if (count == buffer.Length) throw new ArgumentException();
            string token = new UTF8Encoding(false, true).GetString(buffer, 0, count).TrimEnd('\r', '\n');
            string value = token.TrimEnd('=');
            if (value.Length == 0 || value.Any(character => !char.IsAsciiLetterOrDigit(character)
                && character is not ('-' or '.' or '_' or '~' or '+' or '/'))) throw new ArgumentException();
            return token;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            throw new NtfyConfigurationException($"Unable to read a valid bearer token from {TokenFileVariable}. Check the file and read permissions.");
        }
    }

    public void Dispose() => http.Dispose();
}
