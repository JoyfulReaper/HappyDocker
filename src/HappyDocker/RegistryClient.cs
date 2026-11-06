using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace HappyDocker;

public enum UpdateStatus
{
    UpToDate, UpdateAvailable, Unknown, UnsupportedRegistry, AuthenticationRequired, RegistryUnavailable, Skipped
}

public sealed record UpdateResult(UpdateStatus Status, string Reason,
    string? DeployedManifest = null, string? CurrentManifest = null, DateTimeOffset? RetryAfter = null);

internal sealed class RegistryException(UpdateStatus status, string message, DateTimeOffset? retryAfter = null)
    : Exception(message)
{
    public UpdateResult Result { get; } = new(status, message, RetryAfter: retryAfter);
}

internal sealed record RegistryDocument(byte[] Bytes, string Digest, string? MediaType);

/// <summary>Anonymous, bounded GETs to supported registries. Owns its HttpClient for the command lifetime.</summary>
public sealed class RegistryClient : IDisposable
{
    private readonly HttpClient http;
    private readonly TimeSpan timeout;
    private readonly Dictionary<string, string> tokens = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTimeOffset> rateLimits = new(StringComparer.Ordinal);
    internal const string OciManifest = "application/vnd.oci.image.manifest.v1+json";
    internal const string DockerManifest = "application/vnd.docker.distribution.manifest.v2+json";
    internal const string OciIndex = "application/vnd.oci.image.index.v1+json";
    internal const string DockerIndex = "application/vnd.docker.distribution.manifest.list.v2+json";

    // Inject a non-redirecting handler for tests. The production handler never follows redirects itself.
    public RegistryClient(HttpMessageHandler? handler = null, TimeSpan? requestTimeout = null)
    {
        http = new HttpClient(handler ?? new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            ConnectTimeout = TimeSpan.FromSeconds(10)
        }) { Timeout = Timeout.InfiniteTimeSpan };
        timeout = requestTimeout ?? TimeSpan.FromSeconds(15);
    }

    public static bool Supports(string? registry) => registry is "docker.io" or "ghcr.io";

    internal async Task<RegistryDocument> GetAsync(string registry, string repository, string reference,
        bool config, CancellationToken cancellationToken)
    {
        if (!Supports(registry)) throw new RegistryException(UpdateStatus.UnsupportedRegistry, "Registry is not supported.");
        if (rateLimits.TryGetValue(registry, out DateTimeOffset until) && until > DateTimeOffset.UtcNow)
            throw new RegistryException(UpdateStatus.RegistryUnavailable, "Registry rate limited; retry later.", until);

        using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        deadline.CancelAfter(timeout);
        try
        {
            string host = registry == "docker.io" ? "registry-1.docker.io" : "ghcr.io";
            var uri = new Uri($"https://{host}/v2/{repository}/{(config ? "blobs" : "manifests")}/{Uri.EscapeDataString(reference)}");
            string tokenKey = registry + "/" + repository;
            tokens.TryGetValue(tokenKey, out string? token);
            using HttpResponseMessage response = await GetAuthorizedAsync(uri, registry, repository, tokenKey, token, config, deadline.Token);
            CheckStatus(response, registry);
            byte[] bytes = await ReadBoundedAsync(response, 4 * 1024 * 1024, deadline.Token);
            string digest = ContentDigest.Compute(bytes);
            if (ImageReference.IsSupportedDigest(reference) && !ContentDigest.Matches(bytes, reference))
                throw new RegistryException(UpdateStatus.Unknown, "Registry content does not match the requested digest.");
            if (response.Headers.TryGetValues("Docker-Content-Digest", out var values))
            {
                string[] advertised = values.ToArray();
                if (advertised.Length != 1 || !ContentDigest.Matches(bytes, advertised[0]))
                    throw new RegistryException(UpdateStatus.Unknown, "Registry digest header is inconsistent with its content.");
            }
            return new(bytes, digest, response.Content.Headers.ContentType?.MediaType);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            throw new RegistryException(UpdateStatus.RegistryUnavailable, "Registry request timed out.");
        }
        catch (HttpRequestException)
        {
            throw new RegistryException(UpdateStatus.RegistryUnavailable, "Registry network request failed.");
        }
        catch (IOException)
        {
            throw new RegistryException(UpdateStatus.RegistryUnavailable, "Registry response could not be read.");
        }
    }

    private async Task<HttpResponseMessage> GetAuthorizedAsync(Uri uri, string registry, string repository,
        string key, string? token, bool config, CancellationToken cancellationToken)
    {
        // Only config metadata may use these documented vendor CDN endpoints; never manifests or tokens.
        string? cdnHost = !config ? null : registry == "docker.io"
            ? "production.cloudfront.docker.com" : "pkg-containers.githubusercontent.com";
        HttpResponseMessage response = await SendAsync(uri, token, cancellationToken, cdnHost);
        if (response.StatusCode != HttpStatusCode.Unauthorized) return response;
        try
        {
            AuthenticationHeaderValue[] challenges = response.Headers.WwwAuthenticate
                .Where(h => h.Scheme.Equals("Bearer", StringComparison.OrdinalIgnoreCase)).ToArray();
            if (challenges.Length != 1)
                throw new RegistryException(UpdateStatus.AuthenticationRequired, "Registry requires authentication; anonymous bearer access is unavailable.");
            Uri tokenUri = TokenUri(challenges[0].Parameter, registry, repository);
            using HttpResponseMessage tokenResponse = await SendAsync(tokenUri, null, cancellationToken);
            CheckStatus(tokenResponse, registry);
            byte[] bytes = await ReadBoundedAsync(tokenResponse, 64 * 1024, cancellationToken);
            using JsonDocument document = JsonValue.Parse(bytes);
            string? newToken = JsonValue.String(document.RootElement, "token")
                ?? JsonValue.String(document.RootElement, "access_token");
            if (string.IsNullOrEmpty(newToken) || newToken.Length > 16000
                || newToken.Any(c => !char.IsAsciiLetterOrDigit(c) && !"-._~+/=".Contains(c)))
                throw new RegistryException(UpdateStatus.AuthenticationRequired, "Anonymous token response was invalid.");
            tokens[key] = newToken;
            return await SendAsync(uri, newToken, cancellationToken, cdnHost);
        }
        catch (JsonException)
        {
            throw new RegistryException(UpdateStatus.AuthenticationRequired, "Anonymous token response was invalid.");
        }
        finally { response.Dispose(); }
    }

    private static Uri TokenUri(string? challenge, string registry, string repository)
    {
        const string parameterPattern = "\\G\\s*(?<key>[a-zA-Z_]+)\\s*=\\s*\"(?<value>[^\"\\\\\\r\\n]*)\"\\s*(?:,|$)";
        var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        int consumed = 0;
        foreach (Match match in Regex.Matches(challenge ?? "", parameterPattern, RegexOptions.CultureInvariant))
        {
            consumed += match.Length;
            if (!parameters.TryAdd(match.Groups["key"].Value, match.Groups["value"].Value))
                throw new RegistryException(UpdateStatus.AuthenticationRequired, "Registry bearer challenge is ambiguous.");
        }
        string realm = registry == "docker.io" ? "https://auth.docker.io/token" : "https://ghcr.io/token";
        string service = registry == "docker.io" ? "registry.docker.io" : "ghcr.io";
        string scope = $"repository:{repository}:pull";
        if (consumed == 0 || consumed != challenge?.Length
            || !parameters.TryGetValue("realm", out string? requestedRealm) || requestedRealm != realm
            || (parameters.TryGetValue("service", out string? requestedService) && requestedService != service)
            || (parameters.TryGetValue("scope", out string? requestedScope) && requestedScope != scope))
            throw new RegistryException(UpdateStatus.AuthenticationRequired, "Registry bearer challenge is unsupported or unsafe.");
        // Construct our own pull-only scope; never forward a challenge's arbitrary URL or scope.
        return new Uri($"{realm}?service={Uri.EscapeDataString(service)}&scope={Uri.EscapeDataString(scope)}");
    }

    private async Task<HttpResponseMessage> SendAsync(Uri uri, string? token, CancellationToken cancellationToken,
        string? cdnHost = null)
    {
        string originalHost = uri.Host;
        for (int redirects = 0; redirects <= 3; redirects++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, uri);
            request.Headers.Accept.ParseAdd($"{OciIndex}, {DockerIndex}, {OciManifest}, {DockerManifest}, application/json");
            if (token is not null) request.Headers.Authorization = new("Bearer", token);
            HttpResponseMessage response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
            if ((int)response.StatusCode is not (301 or 302 or 303 or 307 or 308)) return response;
            Uri? location = response.Headers.Location;
            response.Dispose();
            if (location is null || !Uri.TryCreate(uri, location, out Uri? next)
                || next.Scheme != "https" || next.Port != 443
                || (next.Host != uri.Host && !(uri.Host == originalHost && next.Host == cdnHost))
                || next.UserInfo.Length != 0 || next.Fragment.Length != 0 || redirects == 3)
                throw new RegistryException(UpdateStatus.RegistryUnavailable, "Registry redirect was unsafe, unsupported, or exceeded the redirect limit.");
            if (next.Host != uri.Host) token = null;
            uri = next;
        }
        throw new InvalidOperationException("Unreachable redirect state.");
    }

    private void CheckStatus(HttpResponseMessage response, string registry)
    {
        if (response.IsSuccessStatusCode) return;
        if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)
            throw new RegistryException(UpdateStatus.AuthenticationRequired, "Registry requires credentials; only anonymous access is supported.");
        if (response.StatusCode == HttpStatusCode.TooManyRequests)
        {
            DateTimeOffset now = DateTimeOffset.UtcNow;
            TimeSpan delay = response.Headers.RetryAfter?.Delta
                ?? (response.Headers.RetryAfter?.Date - now) ?? TimeSpan.FromMinutes(1);
            DateTimeOffset retry = delay > TimeSpan.FromDays(365) ? DateTimeOffset.MaxValue
                : now + TimeSpan.FromSeconds(Math.Max(delay.TotalSeconds, 1));
            rateLimits[registry] = retry;
            throw new RegistryException(UpdateStatus.RegistryUnavailable, "Registry rate limited; retry later.", retry);
        }
        if ((int)response.StatusCode >= 500 || response.StatusCode == HttpStatusCode.RequestTimeout)
            throw new RegistryException(UpdateStatus.RegistryUnavailable, "Registry is unavailable.");
        throw new RegistryException(UpdateStatus.Unknown, "Registry metadata is unavailable for this reference.");
    }

    private static async Task<byte[]> ReadBoundedAsync(HttpResponseMessage response, int limit, CancellationToken cancellationToken)
    {
        if (response.Content.Headers.ContentLength > limit)
            throw new RegistryException(UpdateStatus.Unknown, "Registry metadata exceeds the response size limit.");
        using Stream source = await response.Content.ReadAsStreamAsync(cancellationToken);
        using var buffer = new MemoryStream();
        byte[] chunk = new byte[8192];
        int read;
        while ((read = await source.ReadAsync(chunk, cancellationToken)) != 0)
        {
            if (buffer.Length + read > limit)
                throw new RegistryException(UpdateStatus.Unknown, "Registry metadata exceeds the response size limit.");
            buffer.Write(chunk, 0, read);
        }
        return buffer.ToArray();
    }

    public void Dispose() => http.Dispose();
}

internal static class ContentDigest
{
    internal static string Compute(byte[] bytes) => "sha256:" + Convert.ToHexStringLower(SHA256.HashData(bytes));
    internal static bool Matches(byte[] bytes, string digest)
    {
        if (!ImageReference.IsSupportedDigest(digest)) return false;
        byte[] hash = digest[..digest.IndexOf(':')] switch
        {
            "sha256" => SHA256.HashData(bytes), "sha384" => SHA384.HashData(bytes), _ => SHA512.HashData(bytes)
        };
        return digest[(digest.IndexOf(':') + 1)..] == Convert.ToHexStringLower(hash);
    }
}

internal static class JsonValue
{
    internal static JsonDocument Parse(byte[] bytes)
    {
        JsonDocument document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32 });
        try { Validate(document.RootElement); return document; }
        catch { document.Dispose(); throw; }
    }

    private static void Validate(JsonElement element)
    {
        if (element.ValueKind == JsonValueKind.Object)
        {
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in element.EnumerateObject())
            {
                if (!names.Add(property.Name)) throw new JsonException("Duplicate metadata property.");
                Validate(property.Value);
            }
        }
        else if (element.ValueKind == JsonValueKind.Array)
            foreach (JsonElement item in element.EnumerateArray()) Validate(item);
    }

    internal static string? String(JsonElement element, string name) =>
        element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value)
            && value.ValueKind == JsonValueKind.String ? value.GetString() : null;
}
