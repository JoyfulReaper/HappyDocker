using System.Net;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace HappyDocker;

public sealed class ReportConfigurationException(string message) : Exception(message);
public sealed record ReportDeliveryResult(bool Acknowledged, bool Permanent, string Detail, DateTimeOffset? RetryAfter = null, bool Older = false);

public sealed class AgentReportClient : IDisposable
{
    private readonly Uri destination;
    private readonly AuthenticationHeaderValue authorization;
    private readonly HttpClient http;
    private readonly TimeSpan timeout;
    public string DestinationKey { get; }
    public bool UsesInsecureHttp => destination.Scheme == Uri.UriSchemeHttp;

    public AgentReportClient(string url, string tokenFile, HttpMessageHandler? handler = null, TimeSpan? timeout = null)
    {
        destination = ParseDestination(url);
        authorization = new AuthenticationHeaderValue("Bearer", ReadToken(tokenFile));
        DestinationKey = Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(destination.AbsoluteUri)));
        this.timeout = timeout ?? TimeSpan.FromSeconds(10);
        http = new HttpClient(handler ?? new HttpClientHandler
        { AllowAutoRedirect = false, UseCookies = false, UseProxy = false, MaxResponseHeadersLength = 16 }) { Timeout = Timeout.InfiniteTimeSpan };
    }

    public static Uri ParseDestination(string url)
    {
        if (string.IsNullOrWhiteSpace(url) || url.Length > 2048 || url.Any(char.IsWhiteSpace)
            || !Uri.TryCreate(url, UriKind.Absolute, out Uri? uri) || uri.Scheme is not ("https" or "http")
            || uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0
            || uri.AbsolutePath != "/api/agents/reports" || uri.Host.Length == 0
            || uri.Scheme == "http" && !PrivateAddress(uri.Host))
            throw new ReportConfigurationException("Report URL must be an HTTPS endpoint or an HTTP private IP endpoint at /api/agents/reports, without credentials, query, or fragment.");
        return uri;
    }

    private static bool PrivateAddress(string host)
    {
        if (!IPAddress.TryParse(host.Trim('[', ']'), out var ip)) return false;
        if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
        if (IPAddress.IsLoopback(ip)) return true;
        byte[] bytes = ip.GetAddressBytes();
        return ip.AddressFamily == AddressFamily.InterNetwork
            ? bytes[0] == 10 || bytes[0] == 172 && bytes[1] is >= 16 and <= 31 || bytes[0] == 192 && bytes[1] == 168
            : ip.AddressFamily == AddressFamily.InterNetworkV6 && (bytes[0] & 0xfe) == 0xfc;
    }

    private static string ReadToken(string path)
    {
        try
        {
            if (OperatingSystem.IsLinux())
            {
                const UnixFileMode shared = UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute
                    | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute;
                if ((File.GetUnixFileMode(path) & shared) != 0) throw new UnauthorizedAccessException();
            }
            using var file = File.OpenRead(path);
            byte[] bytes = new byte[260];
            int length = file.ReadAtLeast(bytes, bytes.Length, false);
            if (length == bytes.Length) throw new ArgumentException();
            string token = new UTF8Encoding(false, true).GetString(bytes, 0, length).TrimEnd('\r', '\n');
            if (token.Length is < 32 or > 256 || token.Any(c => c < 33 || c > 126)) throw new ArgumentException();
            return token;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        { throw new ReportConfigurationException("Cannot read a valid private report token file; check its contents and permissions (0600 on Linux)."); }
    }

    public async Task<ReportDeliveryResult> SendAsync(byte[] payload, DateTimeOffset now, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, destination);
        request.Headers.Authorization = authorization;
        request.Content = new ByteArrayContent(payload);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        try
        {
            using var response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
            DateTimeOffset? retry = response.Headers.RetryAfter?.Date;
            if (response.Headers.RetryAfter?.Delta is { } delay)
                retry = delay >= DateTimeOffset.MaxValue - now ? DateTimeOffset.MaxValue : now.Add(delay);
            int status = (int)response.StatusCode;
            if (status != 200)
                return new(false, status != 408 && status != 429 && status < 500, $"HTTP {status}", retry);
            if (response.Content.Headers.ContentLength > 4096) return new(false, false, "Response too large");
            await using var stream = await response.Content.ReadAsStreamAsync(deadline.Token);
            using var buffer = new MemoryStream();
            byte[] chunk = new byte[1024];
            int count;
            while ((count = await stream.ReadAsync(chunk, deadline.Token)) > 0)
            {
                if (buffer.Length + count > 4096) return new(false, false, "Response too large");
                buffer.Write(chunk, 0, count);
            }
            using var json = JsonDocument.Parse(buffer.ToArray());
            if (json.RootElement.ValueKind != JsonValueKind.Object || !json.RootElement.TryGetProperty("outcome", out var value)
                || value.ValueKind != JsonValueKind.String) return new(false, false, "Invalid acknowledgment");
            return value.GetString() switch
            {
                "accepted" or "duplicate" => new(true, false, "Accepted"),
                "older" => new(true, false, "Server already has a newer report", Older: true),
                _ => new(false, false, "Invalid acknowledgment")
            };
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested) { return new(false, false, "Request timed out"); }
        catch (Exception exception) when (exception is HttpRequestException or IOException or JsonException)
        { return new(false, false, "Network or response error"); }
    }

    public void Dispose() => http.Dispose();
}
