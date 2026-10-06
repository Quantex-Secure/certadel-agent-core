using System.Net;

namespace AcmeManager.Plugins.Contracts.Installation;

/// <summary>
/// Shared handling of the two verification options every installer exposes:
/// an explicit endpoint list and an off switch. Installers call
/// <see cref="Resolve"/> with the endpoints they would probe by default.
/// </summary>
public static class VerificationOptions
{
    /// <summary>
    /// Parses an operator-supplied endpoint list: comma- or newline-separated
    /// entries of the form <c>host</c>, <c>host:port</c>, or <c>name@host:port</c>
    /// (name = SNI to send when connecting to an address that isn't the name,
    /// e.g. <c>shop.example.com@10.0.0.5:443</c>). A bare host uses
    /// <paramref name="defaultPort"/>; an IP or <c>localhost</c> host sends
    /// <paramref name="defaultServerName"/> as SNI.
    /// </summary>
    public static IReadOnlyList<VerifyEndpoint> Parse(string? list, int defaultPort, string defaultServerName)
    {
        if (string.IsNullOrWhiteSpace(list))
        {
            return [];
        }

        var endpoints = new List<VerifyEndpoint>();
        foreach (var raw in list.Split([',', ';', '\n', '\r'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var entry = raw;
            string? serverName = null;
            var at = entry.IndexOf('@');
            if (at > 0)
            {
                serverName = entry[..at].Trim();
                entry = entry[(at + 1)..].Trim();
            }

            var host = entry;
            var port = defaultPort;
            var colon = entry.IndexOf(':');
            if (colon >= 0)
            {
                // Exactly one colon: host:port. (Bracketed IPv6 literals aren't supported here.)
                if (entry.IndexOf(':', colon + 1) >= 0 || !int.TryParse(entry[(colon + 1)..], out port))
                {
                    throw new ArgumentException($"'{raw}' is not a valid verification endpoint (expected host, host:port, or name@host:port).");
                }
                host = entry[..colon];
            }
            if (host.Length == 0 || port is < 1 or > 65535)
            {
                throw new ArgumentException($"'{raw}' is not a valid verification endpoint (expected host, host:port, or name@host:port).");
            }

            serverName ??= IsAddress(host) ? defaultServerName : host;
            endpoints.Add(new VerifyEndpoint(host, port, serverName));
        }
        return endpoints;
    }

    /// <summary>
    /// The endpoints to attach to an install result: none when verification is
    /// switched off, the operator's list when given, otherwise the installer's
    /// defaults.
    /// </summary>
    public static IReadOnlyList<VerifyEndpoint> Resolve(
        bool skipVerification,
        string? explicitList,
        int defaultPort,
        string defaultServerName,
        IReadOnlyList<VerifyEndpoint> defaults)
    {
        if (skipVerification)
        {
            return [];
        }
        var explicitEndpoints = Parse(explicitList, defaultPort, defaultServerName);
        return explicitEndpoints.Count > 0 ? explicitEndpoints : defaults;
    }

    public const string SkippedByOperator = "verification switched off in the installer options";

    private static bool IsAddress(string host) =>
        string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase) || IPAddress.TryParse(host, out _);
}