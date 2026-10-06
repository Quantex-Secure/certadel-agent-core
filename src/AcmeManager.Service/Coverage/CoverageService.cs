using System.Text.Json.Nodes;

using AcmeManager.Core.Storage;
using AcmeManager.Service.Migration.AcmeSh;
using AcmeManager.Service.Migration.WinAcme;

using Microsoft.EntityFrameworkCore;

namespace AcmeManager.Service.Coverage;

internal enum CoverageStatus
{
    Managed,    // an acme-manager renewal covers it
    OtherTool,  // only another tool (acme.sh / win-acme) renews it — migration candidate
    Unmanaged,  // nothing renews it — the gap that matters
    MissingCert,// a binding references a cert that's gone from the store — broken
    Unreadable, // not a readable certificate
}

internal sealed record CoverageEntry(
    string Path,
    IReadOnlyList<string> Domains,
    int? DaysUntilExpiry,
    CoverageStatus Status,
    string Detail,
    string? Issuer = null,
    string? Thumbprint = null,
    DateTimeOffset? NotAfter = null);

internal sealed record CoverageReport(
    string? Error,
    IReadOnlyList<string> CertSources,
    IReadOnlyList<CoverageEntry> Entries)
{
    public int Total => Entries.Count;
    public int Unmanaged => Entries.Count(e => e.Status == CoverageStatus.Unmanaged);
    public int MissingCert => Entries.Count(e => e.Status == CoverageStatus.MissingCert);
    public int OtherToolManaged => Entries.Count(e => e.Status == CoverageStatus.OtherTool);
    public int Managed => Entries.Count(e => e.Status == CoverageStatus.Managed);
    public int ExpiringSoon => Entries.Count(e => e.DaysUntilExpiry is <= 21 and >= 0);
}

/// <summary>
/// Reconciles what's actually served — HAProxy's loaded certs on Linux, IIS bindings
/// on Windows — against what's renewing those certs: acme-manager's own renewals plus
/// the platform's other tool (acme.sh on Linux, win-acme on Windows). Answers "is
/// everything we serve actually covered, and by what?" Read-only.
/// </summary>
internal sealed class CoverageService(AcmeManagerDbContext db, ILogger<CoverageService> logger)
{
    private const string DefaultHaProxyConfig = "/etc/haproxy/haproxy.cfg";

    public async Task<CoverageReport> ScanAsync(string? configPath, CancellationToken ct)
    {
        IReadOnlyList<ServedCertInfo> served;
        IReadOnlyList<string> sources;
        IReadOnlyDictionary<string, string> otherToolDomains;
        string otherToolLabel;

        if (OperatingSystem.IsWindows())
        {
            (served, sources) = WindowsServedCertReader.Read();
            otherToolDomains = WinAcmeDomains();
            otherToolLabel = "win-acme";
        }
        else
        {
            var cfgPath = string.IsNullOrWhiteSpace(configPath) ? DefaultHaProxyConfig : configPath.Trim();
            if (!File.Exists(cfgPath))
            {
                return new CoverageReport($"HAProxy config not found at {cfgPath}.", [], []);
            }
            sources = HaProxyConfig.ParseCertSources(File.ReadAllText(cfgPath));
            served = ServedCertReader.Read(sources);
            otherToolDomains = LoadAcmeShDomains();
            otherToolLabel = "acme.sh";
        }

        var agentThumbprints = await LoadAgentCertThumbprintsAsync(ct);
        var agentDomains = await LoadAgentRenewalDomainsAsync(ct);
        var now = DateTimeOffset.UtcNow;
        var entries = served.Select(s => Reconcile(s, now, agentThumbprints, agentDomains, otherToolDomains, otherToolLabel)).ToList();
        logger.LogInformation("Coverage scan: {Total} served cert(s), {Unmanaged} unmanaged",
            entries.Count, entries.Count(e => e.Status == CoverageStatus.Unmanaged));

        return new CoverageReport(null, sources, entries);
    }

    /// <summary>Pure reconciliation: classify one served cert against the supply maps.
    /// Thumbprint match is definitive (the served cert IS one acme-manager issued, no
    /// matter how the renewal names its domains); domain match is the fallback.</summary>
    internal static CoverageEntry Reconcile(
        ServedCertInfo served,
        DateTimeOffset now,
        IReadOnlyDictionary<string, string> agentThumbprints,
        IReadOnlyDictionary<string, string> agentDomains,
        IReadOnlyDictionary<string, string> otherToolDomains,
        string otherToolLabel)
    {
        var days = served.NotAfter is { } na ? (int)Math.Floor((na - now).TotalDays) : (int?)null;

        // 1. The served cert is an acme-manager-issued cert (matched by thumbprint).
        //    Works regardless of source plugin shape, and even if the cert couldn't be
        //    read back from the store.
        if (served.Thumbprint is { Length: > 0 } thumb && agentThumbprints.TryGetValue(thumb, out var byThumb))
        {
            return new CoverageEntry(served.Path, served.Domains, days, CoverageStatus.Managed,
                $"acme-manager renewal '{byThumb}'", served.Issuer, served.Thumbprint, served.NotAfter);
        }

        // 2. Not matched by thumbprint and unreadable. If a thumbprint is known the
        //    binding points at a cert that's gone from the store (broken); otherwise
        //    it's genuinely unparseable.
        if (served.Error is not null)
        {
            var status = served.Thumbprint is { Length: > 0 } ? CoverageStatus.MissingCert : CoverageStatus.Unreadable;
            return new CoverageEntry(served.Path, [], null, status, served.Error, null, served.Thumbprint, null);
        }

        // 3. A renewal covers one of the served domains (the served cert may be an older
        //    one mid-rotation, but acme-manager is keeping that domain renewed).
        foreach (var domain in served.Domains)
        {
            if (agentDomains.TryGetValue(domain, out var renewal))
            {
                return new CoverageEntry(served.Path, served.Domains, days, CoverageStatus.Managed,
                    $"acme-manager renewal '{renewal}'", served.Issuer, served.Thumbprint, served.NotAfter);
            }
        }
        foreach (var domain in served.Domains)
        {
            if (otherToolDomains.TryGetValue(domain, out var where))
            {
                return new CoverageEntry(served.Path, served.Domains, days, CoverageStatus.OtherTool,
                    $"renewed by {otherToolLabel} ({where}) — not yet imported", served.Issuer, served.Thumbprint, served.NotAfter);
            }
        }
        return new CoverageEntry(served.Path, served.Domains, days, CoverageStatus.Unmanaged,
            "no renewal found — nothing is renewing this cert", served.Issuer, served.Thumbprint, served.NotAfter);
    }

    /// <summary>Thumbprint → renewal name for every cert acme-manager has issued.
    /// The strongest "managed" signal: the served cert is literally one we produced.</summary>
    private async Task<IReadOnlyDictionary<string, string>> LoadAgentCertThumbprintsAsync(CancellationToken ct)
    {
        var renewalNames = await db.Renewals.AsNoTracking().ToDictionaryAsync(r => r.Id, r => r.Name, ct);
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var cert in await db.Certificates.AsNoTracking().ToListAsync(ct))
        {
            if (string.IsNullOrEmpty(cert.Thumbprint))
            {
                continue;
            }
            map[cert.Thumbprint] = renewalNames.GetValueOrDefault(cert.RenewalId, "(renewal removed)");
        }
        return map;
    }

    private async Task<IReadOnlyDictionary<string, string>> LoadAgentRenewalDomainsAsync(CancellationToken ct)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var r in await db.Renewals.AsNoTracking().ToListAsync(ct))
        {
            foreach (var domain in DomainsOf(r.SourceJson))
            {
                map.TryAdd(domain, r.Name);
            }
        }
        return map;
    }

    private static IReadOnlyDictionary<string, string> LoadAcmeShDomains()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var homes = AcmeShReader.ResolveHomes(null);
        foreach (var conf in AcmeShReader.ReadRenewals(homes))
        {
            var home = Path.GetDirectoryName(Path.GetDirectoryName(conf.SourcePath)) ?? "acme.sh";
            map.TryAdd(conf.Domain, home);
            foreach (var alt in conf.AltNames)
            {
                map.TryAdd(alt, home);
            }
        }
        return map;
    }

    /// <summary>Domains win-acme renews (from each renewal's target CommonName + SANs),
    /// so the Windows report can flag "managed by win-acme, not yet imported".</summary>
    private IReadOnlyDictionary<string, string> WinAcmeDomains()
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var baseDir = WinAcmeStore.ResolveBaseDir(null);
        if (baseDir is null)
        {
            return map;
        }
        try
        {
            foreach (var ca in WinAcmeStore.Read(baseDir).CaFolders)
            {
                foreach (var renewal in ca.Renewals)
                {
                    if (renewal.Root["TargetPluginOptions"] is not JsonObject target)
                    {
                        continue;
                    }
                    var cn = target["CommonName"]?.ToString();
                    if (!string.IsNullOrEmpty(cn))
                    {
                        map.TryAdd(cn, baseDir);
                    }
                    if (target["AlternativeNames"] is JsonArray alts)
                    {
                        foreach (var alt in alts)
                        {
                            var name = alt?.ToString();
                            if (!string.IsNullOrEmpty(name))
                            {
                                map.TryAdd(name, baseDir);
                            }
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            // win-acme not present / unreadable — no "other tool" supply, that's fine.
            logger.LogDebug(ex, "Coverage: could not read win-acme's managed domains.");
        }
        return map;
    }

    private static IEnumerable<string> DomainsOf(string sourceJson)
    {
        JsonNode? identifiers;
        try
        {
            identifiers = JsonNode.Parse(sourceJson)?["options"]?["identifiers"];
        }
        catch
        {
            yield break;
        }
        if (identifiers is JsonArray array)
        {
            foreach (var n in array)
            {
                if (n is not null)
                {
                    yield return n.ToString();
                }
            }
        }
    }
}