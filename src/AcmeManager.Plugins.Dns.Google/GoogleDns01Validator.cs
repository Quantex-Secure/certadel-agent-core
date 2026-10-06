using System.Collections.Concurrent;
using System.Net;

using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Validation;

using DnsClient;

using Google.Apis.Auth.OAuth2;
using Google.Apis.Dns.v1;
using Google.Apis.Dns.v1.Data;
using Google.Apis.Services;

using Microsoft.Extensions.Logging;

namespace AcmeManager.Plugins.Dns.Google;

public sealed record GoogleDns01Options : PluginOptions
{
    /// <summary>GCP project that hosts the Cloud DNS managed zone.</summary>
    public string ProjectId { get; init; } = "";

    /// <summary>Named secret holding the service-account JSON key (the whole file).
    /// The key itself is never stored in the renewal.</summary>
    [SecretReference]
    public string ServiceAccountKeySecretName { get; init; } = "";

    /// <summary>Optional. The zone's DNS name (e.g. <c>example.com</c>). Blank =
    /// auto-detect the longest managed zone that is a suffix of the identifier.</summary>
    public string ZoneName { get; init; } = "";

    public TimeSpan PropagationDelay { get; init; } = TimeSpan.FromSeconds(60);
}

/// <summary>
/// DNS-01 validator that publishes TXT records to a Google Cloud DNS managed zone
/// via the Cloud DNS API, authenticating with a service-account key resolved by
/// name from the host's secret store (never stored in the renewal). The zone is
/// auto-detected from the identifier unless <see cref="GoogleDns01Options.ZoneName"/>
/// is set.
/// </summary>
public sealed class GoogleDns01Validator(
    ISecretResolver secrets,
    ILogger<GoogleDns01Validator> logger) : IValidator
{
    private readonly ConcurrentDictionary<string, Published> _published = new();

    public PluginMetadata Metadata { get; } = new(
        Id: "validation.dns-01.google",
        Name: "Google Cloud DNS-01",
        Description: "Publishes the TXT record into a Google Cloud DNS zone via a service-account key.",
        Category: PluginCategory.Validation,
        Version: new Version(1, 0, 0));

    public ChallengeType ChallengeType => ChallengeType.Dns01;

    public async ValueTask PrepareAsync(ValidationContext ctx, CancellationToken ct)
    {
        var opts = (GoogleDns01Options)ctx.Options;
        if (string.IsNullOrWhiteSpace(opts.ProjectId) || string.IsNullOrWhiteSpace(opts.ServiceAccountKeySecretName))
        {
            throw new InvalidOperationException("GoogleDns01: ProjectId and ServiceAccountKeySecretName are required.");
        }

        var dns = await ClientAsync(opts, ct);
        var (zoneName, zoneDnsName, nameServers) = await ResolveZoneAsync(dns, opts, ctx.Identifier, ct);

        var rrset = new ResourceRecordSet
        {
            Name = ctx.Identifier.TrimEnd('.') + ".",
            Type = "TXT",
            Ttl = 60,
            Rrdatas = [QuoteTxt(ctx.KeyAuthorization)],
        };
        await dns.Changes.Create(new Change { Additions = [rrset] }, opts.ProjectId, zoneName).ExecuteAsync(ct);
        _published[ctx.Token] = new Published(zoneName, rrset);

        logger.LogInformation(
            "Google DNS-01: published TXT {Record} into zone {Zone}; checking propagation", rrset.Name, zoneDnsName);

        await WaitForPropagationAsync(nameServers, ctx.Identifier.TrimEnd('.'), ctx.KeyAuthorization, TimeSpan.FromMinutes(3), ct);
        if (opts.PropagationDelay > TimeSpan.Zero)
        {
            await Task.Delay(opts.PropagationDelay, ct);
        }
    }

    public async ValueTask CleanupAsync(ValidationContext ctx, CancellationToken ct)
    {
        if (!_published.TryRemove(ctx.Token, out var pub))
        {
            return;
        }
        try
        {
            var dns = await ClientAsync((GoogleDns01Options)ctx.Options, ct);
            await dns.Changes.Create(
                new Change { Deletions = [pub.RecordSet] }, ((GoogleDns01Options)ctx.Options).ProjectId, pub.ZoneName).ExecuteAsync(ct);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Google DNS-01 cleanup failed for {Record} in zone {Zone}", pub.RecordSet.Name, pub.ZoneName);
        }
    }

    private async Task<DnsService> ClientAsync(GoogleDns01Options opts, CancellationToken ct)
    {
        var saJson = await secrets.ResolveAsync(opts.ServiceAccountKeySecretName, ct);
        var credential = GoogleCredential.FromJson(saJson).CreateScoped(DnsService.Scope.NdevClouddnsReadwrite);
        return new DnsService(new BaseClientService.Initializer
        {
            HttpClientInitializer = credential,
            ApplicationName = "acme-manager",
        });
    }

    private async Task<(string ZoneName, string DnsName, IReadOnlyList<string> NameServers)> ResolveZoneAsync(
        DnsService dns, GoogleDns01Options opts, string identifier, CancellationToken ct)
    {
        var zones = new List<ManagedZone>();
        var request = dns.ManagedZones.List(opts.ProjectId);
        do
        {
            var resp = await request.ExecuteAsync(ct);
            if (resp.ManagedZones is not null)
            {
                zones.AddRange(resp.ManagedZones);
            }
            request.PageToken = resp.NextPageToken;
        }
        while (!string.IsNullOrEmpty(request.PageToken));

        var name = BestZoneMatch(zones.Select(z => (z.Name, z.DnsName)), identifier, opts.ZoneName);
        var zone = zones.FirstOrDefault(z => z.Name == name)
            ?? throw new InvalidOperationException(
                $"GoogleDns01: no managed zone in project '{opts.ProjectId}' matches '{identifier}' (scanned {zones.Count}).");
        return (zone.Name, zone.DnsName?.TrimEnd('.') ?? zone.Name, zone.NameServers?.ToList() ?? []);
    }

    /// <summary>Picks the managed zone Name whose DnsName is the longest suffix of the
    /// identifier (or the explicit override). Returns null if none match.</summary>
    internal static string? BestZoneMatch(IEnumerable<(string Name, string DnsName)> zones, string identifier, string? overrideDnsName = null)
    {
        var fqdn = identifier.TrimEnd('.');
        string? best = null;
        var bestLen = -1;
        foreach (var (zoneName, dnsName) in zones)
        {
            var zn = (dnsName ?? "").TrimEnd('.');
            if (zn.Length == 0)
            {
                continue;
            }
            if (!string.IsNullOrWhiteSpace(overrideDnsName))
            {
                if (zn.Equals(overrideDnsName.TrimEnd('.'), StringComparison.OrdinalIgnoreCase))
                {
                    return zoneName;
                }
                continue;
            }
            var matches = fqdn.Equals(zn, StringComparison.OrdinalIgnoreCase)
                || fqdn.EndsWith("." + zn, StringComparison.OrdinalIgnoreCase);
            if (matches && zn.Length > bestLen)
            {
                best = zoneName;
                bestLen = zn.Length;
            }
        }
        return best;
    }

    /// <summary>Cloud DNS requires TXT rrdata wrapped in double quotes.</summary>
    internal static string QuoteTxt(string value) => $"\"{value}\"";

    private async Task WaitForPropagationAsync(
        IReadOnlyList<string> nameServerHosts, string recordFqdn, string expectedValue, TimeSpan maxWait, CancellationToken ct)
    {
        var clients = new List<(string Host, LookupClient Client)>();
        foreach (var host in nameServerHosts)
        {
            var hostName = host.TrimEnd('.');
            try
            {
                var addrs = await System.Net.Dns.GetHostAddressesAsync(hostName, ct);
                var endpoints = addrs.Select(a => new IPEndPoint(a, 53)).ToArray();
                if (endpoints.Length == 0) continue;
                clients.Add((hostName, new LookupClient(new LookupClientOptions(endpoints)
                {
                    UseCache = false,
                    Timeout = TimeSpan.FromSeconds(5),
                    Retries = 1,
                })));
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "Google DNS-01: could not resolve nameserver {Ns}", hostName);
            }
        }

        if (clients.Count == 0)
        {
            logger.LogWarning("Google DNS-01: no authoritative nameservers resolved for {Record}; skipping propagation check", recordFqdn);
            return;
        }

        var deadline = DateTimeOffset.UtcNow + maxWait;
        while (true)
        {
            var allPresent = true;
            foreach (var (host, client) in clients)
            {
                try
                {
                    var resp = await client.QueryAsync(recordFqdn, QueryType.TXT, cancellationToken: ct);
                    if (!resp.Answers.TxtRecords().SelectMany(t => t.Text).Any(v => v == expectedValue))
                    {
                        allPresent = false;
                        break;
                    }
                }
                catch (Exception ex)
                {
                    logger.LogDebug(ex, "Google DNS-01: TXT query to {Ns} failed", host);
                    allPresent = false;
                    break;
                }
            }

            if (allPresent)
            {
                logger.LogInformation("Google DNS-01: TXT {Record} visible on all authoritative nameservers", recordFqdn);
                return;
            }
            if (DateTimeOffset.UtcNow >= deadline)
            {
                logger.LogWarning("Google DNS-01: TXT {Record} not visible within {MaxWait}; proceeding anyway", recordFqdn, maxWait);
                return;
            }
            await Task.Delay(TimeSpan.FromSeconds(5), ct);
        }
    }

    private sealed record Published(string ZoneName, ResourceRecordSet RecordSet);
}