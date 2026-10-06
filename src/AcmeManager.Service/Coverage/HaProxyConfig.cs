namespace AcmeManager.Service.Coverage;

/// <summary>
/// Minimal HAProxy config reader: finds the certificate sources it loads via
/// <c>crt</c> / <c>crt-list</c> directives on <c>bind</c> lines, so we can see
/// exactly which certs HAProxy actually serves (its `crt /etc/haproxy/certs/`
/// directory loads every PEM there and matches by SNI).
/// </summary>
internal static class HaProxyConfig
{
    /// <summary>Cert sources referenced by <c>crt</c>/<c>crt-list</c> (dirs or files).</summary>
    public static IReadOnlyList<string> ParseCertSources(string configText)
    {
        var sources = new List<string>();
        foreach (var raw in configText.Split('\n'))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }
            var tokens = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
            for (var i = 0; i < tokens.Length - 1; i++)
            {
                if (tokens[i].Equals("crt", StringComparison.Ordinal)
                    || tokens[i].Equals("crt-list", StringComparison.Ordinal))
                {
                    sources.Add(tokens[i + 1]);
                }
            }
        }
        return sources.Distinct(StringComparer.Ordinal).ToList();
    }
}