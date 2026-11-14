using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace HappyDocker.Web;

public sealed class AgentAuthentication
{
    private readonly (string Host, byte[] Hash)[] agents;
    public IReadOnlyList<string> Hosts => agents.Select(agent => agent.Host).ToArray();

    public AgentAuthentication(IConfiguration configuration)
    {
        var configured = configuration.GetSection("Web:Agents").GetChildren()
            .Select(section => (Host: section["HostId"], Token: section["Token"])).ToArray();
        if (configured.Any(agent => !ValidHost(agent.Host) || agent.Token is null
            || agent.Token.Length is < 32 or > 256 || agent.Token.Any(c => c < 33 || c > 126))
            || configured.Select(a => a.Host).Distinct(StringComparer.Ordinal).Count() != configured.Length
            || configured.Select(a => a.Token).Distinct(StringComparer.Ordinal).Count() != configured.Length)
            throw new InvalidOperationException("Web:Agents requires unique host IDs and unique printable tokens of 32–256 characters.");
        agents = configured.Select(agent => (agent.Host!, Hash(agent.Token!))).ToArray();
    }

    public static bool ValidHost(string? host) => host is not null && host.Length is >= 1 and <= 128
        && Regex.IsMatch(host, @"\A[a-zA-Z0-9_.-]+\z", RegexOptions.NonBacktracking);

    public string? Authenticate(HttpRequest request)
    {
        var header = request.Headers.Authorization;
        if (header.Count != 1 || header[0] is not { } value
            || !value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) return null;
        string token = value[7..];
        if (token.Length is < 32 or > 256) return null;
        byte[] hash = Hash(token);
        string? host = null;
        foreach (var agent in agents)
            if (CryptographicOperations.FixedTimeEquals(hash, agent.Hash)) host = agent.Host;
        return host;
    }

    private static byte[] Hash(string token) => SHA256.HashData(Encoding.UTF8.GetBytes(token));
}
