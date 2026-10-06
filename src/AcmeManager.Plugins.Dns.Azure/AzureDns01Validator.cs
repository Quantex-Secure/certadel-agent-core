using System.Collections.Concurrent;
using System.Net;

using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Validation;

using Azure;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Dns;
using Azure.ResourceManager.Dns.Models;

using DnsClient;

using Microsoft.Extensions.Logging;

namespace AcmeManager.Plugins.Dns.Azure;

public sealed record AzureDns01Options : PluginOptions
{
    /// <summary>Entra tenant ID (directory).</summary>
    public string TenantId { get; init; } = "";

    /// <summary>Service principal application (client) ID.</summary>
    public string ClientId { get; init; } = "";

    /// <summary>
    /// Name of the named secret holding the service principal client secret.
    /// The secret value itself is never stored in this options blob.
    /// </summary>
    [SecretReference]
    public string ClientSecretSecretName { get; init; } = "";

    /// <summary>Azure subscription ID containing the DNS zone.</summary>
    public string SubscriptionId { get; init; } = "";

    /// <summary>
    /// Optional. Resource group containing the DNS zone. Leave blank to search
    /// every DNS zone in the subscription; set it to narrow (and speed up) the
    /// search when you have many zones.
    /// </summary>
    public string ResourceGroupName { get; init; } = "";

    /// <summary>
    /// Optional. DNS zone name as registered in Azure (e.g. <c>example.com</c>).
    /// Leave blank to auto-detect the zone by matching the longest registered
    /// zone that is a suffix of the validation identifier (the same behaviour as
    /// win-acme). Set it only to force a specific zone.
    /// </summary>
    public string ZoneName { get; init; } = "";

    /// <summary>Wait this long after creating the TXT before letting the CA validate.</summary>
    public TimeSpan PropagationDelay { get; init; } = TimeSpan.FromSeconds(30);
}

/// <summary>
/// DNS-01 validator that publishes TXT records to an Azure DNS zone via the
/// Azure Resource Manager SDK. Authenticates with a service principal
/// (ClientSecretCredential); the client secret is resolved by name from the
/// host's secret store so it never lives in the renewal's JSON. The target zone
/// is auto-detected from the identifier unless <see cref="AzureDns01Options.ZoneName"/>
/// is set explicitly.
/// </summary>
public sealed class AzureDns01Validator(
    ISecretResolver secrets,
    ILogger<AzureDns01Validator> logger) : IValidator
{
    private readonly ConcurrentDictionary<string, PublishedRecord> _published = new();

    public PluginMetadata Metadata { get; } = new(
        Id: "validation.dns-01.azure",
        Name: "Azure DNS-01",
        Description: "Publishes the TXT record into an Azure DNS zone via a service principal.",
        Category: PluginCategory.Validation,
        Version: new Version(1, 0, 0));

    public ChallengeType ChallengeType => ChallengeType.Dns01;

    public async ValueTask PrepareAsync(ValidationContext ctx, CancellationToken ct)
    {
        var opts = (AzureDns01Options)ctx.Options;
        ValidateOptions(opts);

        var zone = await ResolveZoneAsync(opts, ctx.Identifier, ct);
        var zoneName = zone.Data.Name;
        var relativeName = RelativeName(ctx.Identifier, zoneName);

        var data = new DnsTxtRecordData
        {
            TtlInSeconds = 60,
        };
        var record = new DnsTxtRecordInfo();
        record.Values.Add(ctx.KeyAuthorization);
        data.DnsTxtRecords.Add(record);

        await zone.GetDnsTxtRecords().CreateOrUpdateAsync(
            waitUntil: WaitUntil.Completed,
            txtRecordName: relativeName,
            data: data,
            cancellationToken: ct);

        _published[ctx.Token] = new PublishedRecord(zoneName, relativeName);

        var recordFqdn = relativeName == "@" ? zoneName : $"{relativeName}.{zoneName}";

        logger.LogInformation(
            "Azure DNS-01: published TXT {RecordName} into zone {Zone}; checking propagation",
            relativeName, zoneName);

        // Poll the zone's authoritative nameservers until the record is visible,
        // rather than blindly waiting — this is what lets validation succeed
        // reliably regardless of fixed-delay guesswork. zone.Data.NameServers is
        // the set Azure assigned to this zone.
        await WaitForPropagationAsync(
            zone.Data.NameServers ?? [],
            recordFqdn,
            ctx.KeyAuthorization,
            maxWait: TimeSpan.FromMinutes(3),
            ct);

        // Small post-propagation buffer for the CA's own resolver caches.
        if (opts.PropagationDelay > TimeSpan.Zero)
        {
            await Task.Delay(opts.PropagationDelay, ct);
        }
    }

    /// <summary>
    /// Polls the zone's authoritative nameservers (cache bypassed) until the
    /// expected TXT value is present on all of them, or <paramref name="maxWait"/>
    /// elapses. Best-effort: on timeout it logs and lets validation proceed.
    /// </summary>
    private async Task WaitForPropagationAsync(
        IEnumerable<string> nameServerHosts,
        string recordFqdn,
        string expectedValue,
        TimeSpan maxWait,
        CancellationToken ct)
    {
        var clients = new List<(string Host, LookupClient Client)>();
        foreach (var host in nameServerHosts)
        {
            var name = host.TrimEnd('.');
            try
            {
                var addrs = await System.Net.Dns.GetHostAddressesAsync(name, ct);
                var endpoints = addrs.Select(a => new IPEndPoint(a, 53)).ToArray();
                if (endpoints.Length == 0) continue;
                // Cache disabled so a stale NXDOMAIN can't mask the new record.
                clients.Add((name, new LookupClient(new LookupClientOptions(endpoints)
                {
                    UseCache = false,
                    Timeout = TimeSpan.FromSeconds(5),
                    Retries = 1,
                })));
            }
            catch (Exception ex)
            {
                logger.LogDebug(ex, "Azure DNS-01: could not resolve nameserver {Ns}", name);
            }
        }

        if (clients.Count == 0)
        {
            logger.LogWarning(
                "Azure DNS-01: no authoritative nameservers resolved for {Record}; skipping propagation check",
                recordFqdn);
            return;
        }

        var deadline = DateTimeOffset.UtcNow + maxWait;
        var attempt = 0;
        while (true)
        {
            attempt++;
            var allPresent = true;
            foreach (var (host, client) in clients)
            {
                bool present;
                try
                {
                    var resp = await client.QueryAsync(recordFqdn, QueryType.TXT, cancellationToken: ct);
                    present = resp.Answers.TxtRecords()
                        .SelectMany(t => t.Text)
                        .Any(v => string.Equals(v, expectedValue, StringComparison.Ordinal));
                }
                catch (Exception ex)
                {
                    logger.LogDebug(ex, "Azure DNS-01: TXT query to {Ns} failed", host);
                    present = false;
                }

                if (!present)
                {
                    allPresent = false;
                    break;
                }
            }

            if (allPresent)
            {
                logger.LogInformation(
                    "Azure DNS-01: TXT {Record} visible on all {Count} authoritative nameserver(s) after {Attempt} check(s)",
                    recordFqdn, clients.Count, attempt);
                return;
            }

            if (DateTimeOffset.UtcNow >= deadline)
            {
                logger.LogWarning(
                    "Azure DNS-01: TXT {Record} not visible on every authoritative nameserver within {MaxWait}; proceeding anyway",
                    recordFqdn, maxWait);
                return;
            }

            await Task.Delay(TimeSpan.FromSeconds(5), ct);
        }
    }

    public async ValueTask CleanupAsync(ValidationContext ctx, CancellationToken ct)
    {
        if (!_published.TryRemove(ctx.Token, out var record)) return;

        var opts = (AzureDns01Options)ctx.Options;
        try
        {
            var zone = await ResolveZoneAsync(opts, ctx.Identifier, ct);
            var txt = await zone.GetDnsTxtRecords().GetAsync(record.RelativeName, ct);
            await txt.Value.DeleteAsync(WaitUntil.Completed, cancellationToken: ct);
        }
        catch (Exception ex)
        {
            logger.LogWarning(
                ex,
                "Azure DNS-01 cleanup failed for record {Name} in zone {Zone}",
                record.RelativeName, record.ZoneName);
        }
    }

    /// <summary>
    /// Resolves the Azure DNS zone for an identifier. Uses an explicit
    /// <see cref="AzureDns01Options.ZoneName"/> when supplied; otherwise scans
    /// the subscription (or a single resource group) and selects the most
    /// specific zone whose name is a suffix of the identifier.
    /// </summary>
    private async Task<DnsZoneResource> ResolveZoneAsync(AzureDns01Options opts, string identifier, CancellationToken ct)
    {
        var secret = await secrets.ResolveAsync(opts.ClientSecretSecretName, ct);
        var credential = new ClientSecretCredential(opts.TenantId, opts.ClientId, secret);
        var arm = new ArmClient(credential, opts.SubscriptionId);
        var subscription = await arm.GetDefaultSubscriptionAsync(ct);

        var fqdn = identifier.TrimEnd('.');

        // Explicit zone wins — acts as an override / fast path.
        if (!string.IsNullOrWhiteSpace(opts.ZoneName))
        {
            var wanted = opts.ZoneName.TrimEnd('.');
            if (!string.IsNullOrWhiteSpace(opts.ResourceGroupName))
            {
                var rg = await subscription.GetResourceGroupAsync(opts.ResourceGroupName, ct);
                return (await rg.Value.GetDnsZoneAsync(wanted, ct)).Value;
            }
            await foreach (var z in subscription.GetDnsZonesAsync(cancellationToken: ct))
            {
                if (string.Equals(z.Data.Name.TrimEnd('.'), wanted, StringComparison.OrdinalIgnoreCase))
                {
                    return z;
                }
            }
            throw new InvalidOperationException(
                $"AzureDns01: zone '{opts.ZoneName}' was not found in subscription {opts.SubscriptionId}.");
        }

        // Auto-detect: pick the longest registered zone that the identifier sits under.
        AsyncPageable<DnsZoneResource> candidates;
        if (string.IsNullOrWhiteSpace(opts.ResourceGroupName))
        {
            candidates = subscription.GetDnsZonesAsync(cancellationToken: ct);
        }
        else
        {
            var rg = await subscription.GetResourceGroupAsync(opts.ResourceGroupName, ct);
            candidates = rg.Value.GetDnsZones().GetAllAsync(cancellationToken: ct);
        }

        DnsZoneResource? best = null;
        var bestLen = -1;
        var scanned = 0;
        await foreach (var z in candidates)
        {
            scanned++;
            var zn = z.Data.Name.TrimEnd('.');
            var matches = fqdn.Equals(zn, StringComparison.OrdinalIgnoreCase)
                          || fqdn.EndsWith("." + zn, StringComparison.OrdinalIgnoreCase);
            if (matches && zn.Length > bestLen)
            {
                best = z;
                bestLen = zn.Length;
            }
        }

        if (best is null)
        {
            var scope = string.IsNullOrWhiteSpace(opts.ResourceGroupName)
                ? $"subscription {opts.SubscriptionId}"
                : $"resource group '{opts.ResourceGroupName}'";
            throw new InvalidOperationException(
                $"AzureDns01: no DNS zone in {scope} matches '{identifier}' (scanned {scanned} zone(s)). " +
                "If the zone is in another resource group, clear ResourceGroupName to scan the whole subscription " +
                "or set ZoneName to that zone. A name whose DNS is not in Azure at all needs a different validator, " +
                "or exclude that host from the source.");
        }

        logger.LogInformation(
            "Azure DNS-01: auto-selected zone {Zone} for identifier {Identifier}",
            best.Data.Name, identifier);
        return best;
    }

    private static string RelativeName(string fqdn, string zoneName)
    {
        // Azure DNS expects record names relative to the zone (no trailing dot).
        var fqdnTrimmed = fqdn.TrimEnd('.');
        var zoneTrimmed = zoneName.TrimEnd('.');
        if (string.Equals(fqdnTrimmed, zoneTrimmed, StringComparison.OrdinalIgnoreCase))
        {
            return "@";
        }
        if (fqdnTrimmed.EndsWith("." + zoneTrimmed, StringComparison.OrdinalIgnoreCase))
        {
            return fqdnTrimmed[..^(zoneTrimmed.Length + 1)];
        }
        throw new InvalidOperationException(
            $"AzureDns01: identifier '{fqdn}' is not under zone '{zoneName}'. ZoneName must be the zone that contains the name; " +
            "clear it to auto-detect, or validate this name another way.");
    }

    private static void ValidateOptions(AzureDns01Options opts)
    {
        if (string.IsNullOrWhiteSpace(opts.TenantId)) throw new InvalidOperationException("AzureDns01: TenantId is required");
        if (string.IsNullOrWhiteSpace(opts.ClientId)) throw new InvalidOperationException("AzureDns01: ClientId is required");
        if (string.IsNullOrWhiteSpace(opts.ClientSecretSecretName)) throw new InvalidOperationException("AzureDns01: ClientSecretSecretName is required");
        if (string.IsNullOrWhiteSpace(opts.SubscriptionId)) throw new InvalidOperationException("AzureDns01: SubscriptionId is required");
    }

    private sealed record PublishedRecord(string ZoneName, string RelativeName);
}