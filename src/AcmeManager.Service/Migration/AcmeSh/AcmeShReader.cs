namespace AcmeManager.Service.Migration.AcmeSh;

/// <summary>An acme.sh ACME account: its key (PEM) and the CA it's registered with.</summary>
internal sealed record AcmeShAccount(string DirectoryUrl, string KeyPem, string SourcePath);

/// <summary>Azure DNS service-principal IDs acme.sh saved in <c>account.conf</c>
/// (the client SECRET is intentionally not read — that stays an agent secret).</summary>
internal sealed record AcmeShAzureConfig(string TenantId, string ClientId, string SubscriptionId);

/// <summary>Namecheap API user + source IP from <c>account.conf</c> (the API KEY is
/// not read — it stays an agent secret).</summary>
internal sealed record AcmeShNamecheapConfig(string ApiUser, string ClientIp);

/// <summary>
/// Reads acme.sh home directories: the per-domain renewal configs and the account
/// key(s) under <c>ca/&lt;server&gt;/directory/</c>. acme.sh can live under several
/// homes (root's and each user's), and stores EC certs in <c>&lt;domain&gt;_ecc</c>
/// directories — both are handled. Read-only — safe for a preview.
/// </summary>
internal static class AcmeShReader
{
    private static readonly string[] SkipDirs = ["ca", "deploy", "dnsapi", "notify"];

    /// <summary>Candidate acme.sh homes: root's, every <c>/home/*</c> user's, and the
    /// current user's. Whichever exist are scanned.</summary>
    public static IReadOnlyList<string> DefaultLocations()
    {
        var homes = new List<string> { "/root/.acme.sh" };
        try
        {
            if (Directory.Exists("/home"))
            {
                homes.AddRange(Directory.GetDirectories("/home").Select(h => Path.Combine(h, ".acme.sh")));
            }
        }
        catch
        {
            // /home not enumerable — fall through to the explicit homes.
        }
        homes.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".acme.sh"));
        return homes.Distinct(StringComparer.Ordinal).ToList();
    }

    /// <summary>The given path if it exists, else every default location present.</summary>
    public static IReadOnlyList<string> ResolveHomes(string? path)
    {
        if (!string.IsNullOrWhiteSpace(path))
        {
            return Directory.Exists(path) ? [path] : [];
        }
        return DefaultLocations().Where(Directory.Exists).ToList();
    }

    /// <summary>Every renewal across the given homes, deduped by domain (a domain with
    /// both an RSA and an EC cert collapses to one renewal — acme-manager issues one).</summary>
    public static IReadOnlyList<AcmeShRenewalConf> ReadRenewals(IEnumerable<string> homes)
    {
        var byDomain = new Dictionary<string, AcmeShRenewalConf>(StringComparer.OrdinalIgnoreCase);
        foreach (var home in homes)
        {
            foreach (var dir in Directory.GetDirectories(home))
            {
                var name = Path.GetFileName(dir);
                if (SkipDirs.Contains(name, StringComparer.OrdinalIgnoreCase))
                {
                    continue;
                }

                // Find the renewal config INSIDE the dir, by content — handles
                // <domain>/<domain>.conf and <domain>_ecc/<domain>.conf alike, and
                // ignores <domain>.csr.conf (no Le_Domain).
                foreach (var confFile in Directory.GetFiles(dir, "*.conf"))
                {
                    AcmeShRenewalConf conf;
                    try
                    {
                        conf = AcmeShConf.Parse(File.ReadAllText(confFile), confFile);
                    }
                    catch
                    {
                        continue;
                    }
                    if (!string.IsNullOrEmpty(conf.Domain))
                    {
                        byDomain.TryAdd(conf.Domain, conf);
                    }
                }
            }
        }
        return byDomain.Values.OrderBy(r => r.Domain, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>Azure SP IDs from each home's <c>account.conf</c>, keyed by home.
    /// Lets the importer pre-fill tenant/client/subscription (not the secret).</summary>
    public static IReadOnlyDictionary<string, AcmeShAzureConfig> ReadAzureConfigs(IEnumerable<string> homes)
    {
        var map = new Dictionary<string, AcmeShAzureConfig>(StringComparer.Ordinal);
        foreach (var home in homes)
        {
            var accountConf = Path.Combine(home, "account.conf");
            if (!File.Exists(accountConf))
            {
                continue;
            }
            var vars = AcmeShConf.ParseVars(File.ReadAllText(accountConf));
            var tenant = vars.GetValueOrDefault("SAVED_AZUREDNS_TENANTID", "");
            var client = vars.GetValueOrDefault("SAVED_AZUREDNS_APPID", "");
            var subscription = vars.GetValueOrDefault("SAVED_AZUREDNS_SUBSCRIPTIONID", "");
            if (tenant.Length > 0 || client.Length > 0 || subscription.Length > 0)
            {
                map[home] = new AcmeShAzureConfig(tenant, client, subscription);
            }
        }
        return map;
    }

    /// <summary>Namecheap API user + source IP from each home's <c>account.conf</c>.</summary>
    public static IReadOnlyDictionary<string, AcmeShNamecheapConfig> ReadNamecheapConfigs(IEnumerable<string> homes)
    {
        var map = new Dictionary<string, AcmeShNamecheapConfig>(StringComparer.Ordinal);
        foreach (var home in homes)
        {
            var accountConf = Path.Combine(home, "account.conf");
            if (!File.Exists(accountConf))
            {
                continue;
            }
            var vars = AcmeShConf.ParseVars(File.ReadAllText(accountConf));
            var user = vars.GetValueOrDefault("SAVED_NAMECHEAP_USERNAME", "");
            var ip = vars.GetValueOrDefault("SAVED_NAMECHEAP_SOURCEIP", "");
            if (user.Length > 0 || ip.Length > 0)
            {
                map[home] = new AcmeShNamecheapConfig(user, ip);
            }
        }
        return map;
    }

    /// <summary>The acme.sh home a renewal config belongs to (parent of its cert dir).</summary>
    public static string HomeOf(AcmeShRenewalConf conf) =>
        Path.GetDirectoryName(Path.GetDirectoryName(conf.SourcePath)) ?? "";

    /// <summary>Account key(s) across the given homes (<c>ca/&lt;server&gt;/directory/
    /// account.key</c>), deduped by the CA directory URL.</summary>
    public static IReadOnlyList<AcmeShAccount> ReadAccounts(IEnumerable<string> homes)
    {
        var byDirectory = new Dictionary<string, AcmeShAccount>(StringComparer.OrdinalIgnoreCase);
        foreach (var home in homes)
        {
            var caRoot = Path.Combine(home, "ca");
            if (!Directory.Exists(caRoot))
            {
                continue;
            }
            foreach (var serverDir in Directory.GetDirectories(caRoot))
            {
                var keyPath = Path.Combine(serverDir, "directory", "account.key");
                if (!File.Exists(keyPath))
                {
                    continue;
                }
                var url = $"https://{Path.GetFileName(serverDir)}/directory";
                byDirectory.TryAdd(url, new AcmeShAccount(url, File.ReadAllText(keyPath), keyPath));
            }
        }
        return byDirectory.Values.ToList();
    }
}