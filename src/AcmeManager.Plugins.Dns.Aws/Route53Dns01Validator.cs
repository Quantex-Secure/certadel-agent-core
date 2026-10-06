using System.Collections.Concurrent;

using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Validation;

using Amazon;
using Amazon.Route53;
using Amazon.Route53.Model;
using Amazon.Runtime;

using Microsoft.Extensions.Logging;

namespace AcmeManager.Plugins.Dns.Aws;

public sealed record Route53Dns01Options : PluginOptions
{
    /// <summary>AWS access key ID for an IAM principal allowed to change records in the zone.</summary>
    public string AccessKeyId { get; init; } = "";

    /// <summary>Named secret holding the AWS secret access key (never stored in the renewal).</summary>
    [SecretReference]
    public string SecretAccessKeySecretName { get; init; } = "";

    /// <summary>Optional. Hosted zone ID (e.g. <c>Z123ABC</c>). Blank = auto-detect by
    /// the longest hosted-zone name that is a suffix of the identifier.</summary>
    public string HostedZoneId { get; init; } = "";

    public TimeSpan PropagationDelay { get; init; } = TimeSpan.FromSeconds(30);
}

/// <summary>
/// DNS-01 validator that publishes TXT records to an AWS Route 53 hosted zone via the
/// Route 53 API. Authenticates with an access key + a secret access key resolved by
/// name from the secret store (never stored in the renewal). Auto-detects the hosted
/// zone from the identifier, UPSERTs the TXT, and waits for the change to reach INSYNC.
/// </summary>
public sealed class Route53Dns01Validator(
    ISecretResolver secrets,
    ILogger<Route53Dns01Validator> logger) : IValidator
{
    private readonly ConcurrentDictionary<string, Published> _published = new();

    public PluginMetadata Metadata { get; } = new(
        Id: "validation.dns-01.route53",
        Name: "AWS Route 53 DNS-01",
        Description: "Publishes the TXT record into a Route 53 hosted zone via an AWS access key.",
        Category: PluginCategory.Validation,
        Version: new Version(1, 0, 0));

    public ChallengeType ChallengeType => ChallengeType.Dns01;

    public async ValueTask PrepareAsync(ValidationContext ctx, CancellationToken ct)
    {
        var opts = (Route53Dns01Options)ctx.Options;
        if (string.IsNullOrWhiteSpace(opts.AccessKeyId) || string.IsNullOrWhiteSpace(opts.SecretAccessKeySecretName))
        {
            throw new InvalidOperationException("Route53: AccessKeyId and SecretAccessKeySecretName are required.");
        }

        using var client = await ClientAsync(opts, ct);
        var zoneId = await ResolveZoneIdAsync(client, opts, ctx.Identifier, ct);
        var rrset = BuildRecordSet(ctx.Identifier, ctx.KeyAuthorization);

        var change = await client.ChangeResourceRecordSetsAsync(new ChangeResourceRecordSetsRequest
        {
            HostedZoneId = zoneId,
            ChangeBatch = new ChangeBatch { Changes = [new Change { Action = ChangeAction.UPSERT, ResourceRecordSet = rrset }] },
        }, ct);
        _published[ctx.Token] = new Published(zoneId, rrset);

        logger.LogInformation("Route53 DNS-01: upserted TXT {Name} in zone {Zone}; waiting for INSYNC", rrset.Name, zoneId);
        await WaitInSyncAsync(client, change.ChangeInfo.Id, TimeSpan.FromMinutes(3), ct);

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
            using var client = await ClientAsync((Route53Dns01Options)ctx.Options, ct);
            await client.ChangeResourceRecordSetsAsync(new ChangeResourceRecordSetsRequest
            {
                HostedZoneId = pub.ZoneId,
                ChangeBatch = new ChangeBatch { Changes = [new Change { Action = ChangeAction.DELETE, ResourceRecordSet = pub.RecordSet }] },
            }, ct);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Route53 DNS-01 cleanup failed for {Name} in zone {Zone}", pub.RecordSet.Name, pub.ZoneId);
        }
    }

    private async Task<AmazonRoute53Client> ClientAsync(Route53Dns01Options opts, CancellationToken ct)
    {
        var secret = await secrets.ResolveAsync(opts.SecretAccessKeySecretName, ct);
        // Route 53 is a global service; the SDK still wants a region.
        return new AmazonRoute53Client(new BasicAWSCredentials(opts.AccessKeyId, secret), RegionEndpoint.USEast1);
    }

    private static ResourceRecordSet BuildRecordSet(string identifier, string value) => new()
    {
        Name = identifier.TrimEnd('.') + ".",
        Type = RRType.TXT,
        TTL = 60,
        ResourceRecords = [new ResourceRecord { Value = $"\"{value}\"" }],
    };

    private async Task<string> ResolveZoneIdAsync(AmazonRoute53Client client, Route53Dns01Options opts, string identifier, CancellationToken ct)
    {
        if (!string.IsNullOrWhiteSpace(opts.HostedZoneId))
        {
            return opts.HostedZoneId;
        }

        var zones = new List<HostedZone>();
        string? marker = null;
        do
        {
            var resp = await client.ListHostedZonesAsync(new ListHostedZonesRequest { Marker = marker }, ct);
            zones.AddRange(resp.HostedZones);
            marker = resp.IsTruncated ? resp.NextMarker : null;
        }
        while (marker is not null);

        var id = BestZoneMatch(zones.Select(z => (z.Id, z.Name)), identifier)
            ?? throw new InvalidOperationException(
                $"Route53: no hosted zone matches '{identifier}' (scanned {zones.Count}). Set HostedZoneId to override.");
        return id;
    }

    /// <summary>Picks the hosted-zone Id whose name is the longest suffix of the identifier.</summary>
    internal static string? BestZoneMatch(IEnumerable<(string Id, string Name)> zones, string identifier)
    {
        var fqdn = identifier.TrimEnd('.');
        string? best = null;
        var bestLen = -1;
        foreach (var (id, name) in zones)
        {
            var zn = (name ?? "").TrimEnd('.');
            if (zn.Length == 0)
            {
                continue;
            }
            var matches = fqdn.Equals(zn, StringComparison.OrdinalIgnoreCase)
                || fqdn.EndsWith("." + zn, StringComparison.OrdinalIgnoreCase);
            if (matches && zn.Length > bestLen)
            {
                best = id;
                bestLen = zn.Length;
            }
        }
        return best;
    }

    private async Task WaitInSyncAsync(AmazonRoute53Client client, string changeId, TimeSpan maxWait, CancellationToken ct)
    {
        var deadline = DateTimeOffset.UtcNow + maxWait;
        while (true)
        {
            var status = (await client.GetChangeAsync(new GetChangeRequest { Id = changeId }, ct)).ChangeInfo.Status;
            if (status == ChangeStatus.INSYNC)
            {
                return;
            }
            if (DateTimeOffset.UtcNow >= deadline)
            {
                logger.LogWarning("Route53 DNS-01: change {Change} not INSYNC within {MaxWait}; proceeding anyway", changeId, maxWait);
                return;
            }
            await Task.Delay(TimeSpan.FromSeconds(5), ct);
        }
    }

    private sealed record Published(string ZoneId, ResourceRecordSet RecordSet);
}