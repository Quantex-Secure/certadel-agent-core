using System.Collections.Concurrent;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Validation;

using DnsClient;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AcmeManager.Plugins.BuiltIn.Validation;

public sealed record CloudflareDns01Options : PluginOptions
{
    /// <summary>
    /// Name of the named secret holding a Cloudflare API token (Bearer auth).
    /// The token itself is <em>never</em> stored in the renewal JSON.
    /// </summary>
    [SecretReference]
    public string ApiTokenSecretName { get; init; } = "";

    /// <summary>Wait this long after publishing the TXT before letting the CA validate.</summary>
    public TimeSpan PropagationDelay { get; init; } = TimeSpan.FromSeconds(20);
}

/// <summary>
/// DNS-01 validator that publishes TXT records via Cloudflare's REST API.
/// Walks up parent domains to find the matching zone, posts the record,
/// waits the configured propagation delay, then deletes on cleanup. State
/// is keyed by challenge token so concurrent authorizations within one
/// order are safe (though OrderRunner runs them serially today).
/// </summary>
public sealed class CloudflareDns01Validator : IValidator, IDisposable
{
    private const string CloudflareBaseUrl = "https://api.cloudflare.com/client/v4/";

    private readonly ISecretResolver _secrets;
    private readonly ILogger<CloudflareDns01Validator> _logger;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly ConcurrentDictionary<string, PublishedRecord> _published = new();

    public PluginMetadata Metadata { get; } = new(
        Id: "validation.dns-01.cloudflare",
        Name: "Cloudflare DNS-01",
        Description: "Publishes the TXT record via Cloudflare's REST API using a Bearer API token.",
        Category: PluginCategory.Validation,
        Version: new Version(1, 0, 0));

    public ChallengeType ChallengeType => ChallengeType.Dns01;

    [ActivatorUtilitiesConstructor]
    public CloudflareDns01Validator(
        ISecretResolver secrets,
        ILogger<CloudflareDns01Validator> logger)
        : this(secrets, logger, new HttpClient { BaseAddress = new Uri(CloudflareBaseUrl) }, ownsHttp: true)
    {
    }

    // Test-facing seam — supply a preconfigured client (e.g. with a mocked HttpMessageHandler).
    internal CloudflareDns01Validator(
        ISecretResolver secrets,
        ILogger<CloudflareDns01Validator> logger,
        HttpClient http,
        bool ownsHttp)
    {
        _secrets = secrets;
        _logger = logger;
        _http = http;
        _ownsHttp = ownsHttp;
        if (_http.BaseAddress is null)
        {
            _http.BaseAddress = new Uri(CloudflareBaseUrl);
        }
    }

    public async ValueTask PrepareAsync(ValidationContext ctx, CancellationToken ct)
    {
        var opts = (CloudflareDns01Options)ctx.Options;
        if (string.IsNullOrWhiteSpace(opts.ApiTokenSecretName))
        {
            throw new InvalidOperationException(
                "CloudflareDns01: ApiTokenSecretName is required");
        }

        var token = await _secrets.ResolveAsync(opts.ApiTokenSecretName, ct);
        var zone = await FindZoneAsync(ctx.Identifier, token, ct);
        var recordId = await CreateTxtRecordAsync(zone.Id, ctx.Identifier, ctx.KeyAuthorization, token, ct);

        _published[ctx.Token] = new PublishedRecord(zone.Id, recordId);

        _logger.LogInformation(
            "Cloudflare DNS-01: published {Name} (record {Record} in zone {Zone}); checking propagation",
            ctx.Identifier, recordId, zone.Id);

        // Poll the zone's authoritative nameservers until the record is visible,
        // rather than blindly waiting a fixed delay.
        await WaitForPropagationAsync(
            zone.NameServers,
            ctx.Identifier,
            ctx.KeyAuthorization,
            maxWait: TimeSpan.FromMinutes(3),
            ct);

        // Small post-propagation buffer for the CA's own resolver caches.
        if (opts.PropagationDelay > TimeSpan.Zero)
        {
            await Task.Delay(opts.PropagationDelay, ct);
        }
    }

    public async ValueTask CleanupAsync(ValidationContext ctx, CancellationToken ct)
    {
        if (!_published.TryRemove(ctx.Token, out var record))
        {
            return;
        }

        var opts = (CloudflareDns01Options)ctx.Options;
        try
        {
            var token = await _secrets.ResolveAsync(opts.ApiTokenSecretName, ct);
            await DeleteRecordAsync(record.ZoneId, record.RecordId, token, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(
                ex,
                "Cloudflare DNS-01 cleanup failed for record {Record} in zone {Zone}",
                record.RecordId, record.ZoneId);
        }
    }

    public void Dispose()
    {
        if (_ownsHttp)
        {
            _http.Dispose();
        }
    }

    private async Task<CloudflareZone> FindZoneAsync(string fqdn, string token, CancellationToken ct)
    {
        // For `_acme-challenge.www.example.com`, candidates walk upward:
        //   www.example.com, example.com, com (com won't match).
        var labels = fqdn.TrimEnd('.').Split('.');
        var tried = new List<string>();
        for (var i = 1; i < labels.Length; i++)
        {
            var candidate = string.Join('.', labels.AsSpan(i).ToArray());
            tried.Add(candidate);
            var zone = await TryGetZoneAsync(candidate, token, ct);
            if (zone is not null) return zone;
        }
        throw new InvalidOperationException(
            $"No Cloudflare zone found for '{fqdn}'. Tried: {string.Join(", ", tried)}");
    }

    private async Task<CloudflareZone?> TryGetZoneAsync(string zoneName, string token, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(
            HttpMethod.Get,
            $"zones?name={Uri.EscapeDataString(zoneName)}&status=active");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var resp = await _http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        var result = doc.RootElement.GetProperty("result");
        if (result.GetArrayLength() == 0)
        {
            return null;
        }

        var zone = result[0];
        var id = zone.GetProperty("id").GetString();
        if (id is null)
        {
            return null;
        }

        // Cloudflare returns the zone's assigned authoritative nameservers; used
        // for the propagation self-check below.
        var nameServers = new List<string>();
        if (zone.TryGetProperty("name_servers", out var ns) && ns.ValueKind == JsonValueKind.Array)
        {
            foreach (var n in ns.EnumerateArray())
            {
                var v = n.GetString();
                if (!string.IsNullOrWhiteSpace(v))
                {
                    nameServers.Add(v);
                }
            }
        }

        return new CloudflareZone(id, nameServers);
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
                _logger.LogDebug(ex, "Cloudflare DNS-01: could not resolve nameserver {Ns}", name);
            }
        }

        if (clients.Count == 0)
        {
            _logger.LogWarning(
                "Cloudflare DNS-01: no authoritative nameservers resolved for {Record}; skipping propagation check",
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
                    var r = await client.QueryAsync(recordFqdn, QueryType.TXT, cancellationToken: ct);
                    present = r.Answers.TxtRecords()
                        .SelectMany(t => t.Text)
                        .Any(v => string.Equals(v, expectedValue, StringComparison.Ordinal));
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Cloudflare DNS-01: TXT query to {Ns} failed", host);
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
                _logger.LogInformation(
                    "Cloudflare DNS-01: TXT {Record} visible on all {Count} authoritative nameserver(s) after {Attempt} check(s)",
                    recordFqdn, clients.Count, attempt);
                return;
            }

            if (DateTimeOffset.UtcNow >= deadline)
            {
                _logger.LogWarning(
                    "Cloudflare DNS-01: TXT {Record} not visible on every authoritative nameserver within {MaxWait}; proceeding anyway",
                    recordFqdn, maxWait);
                return;
            }

            await Task.Delay(TimeSpan.FromSeconds(5), ct);
        }
    }

    private async Task<string> CreateTxtRecordAsync(
        string zoneId, string name, string content, string token, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(HttpMethod.Post, $"zones/{zoneId}/dns_records")
        {
            Content = JsonContent.Create(new { type = "TXT", name, content, ttl = 60 }),
        };
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var resp = await _http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();

        using var doc = JsonDocument.Parse(await resp.Content.ReadAsStringAsync(ct));
        return doc.RootElement.GetProperty("result").GetProperty("id").GetString()
            ?? throw new InvalidOperationException("Cloudflare create-record response missing 'result.id'");
    }

    private async Task DeleteRecordAsync(string zoneId, string recordId, string token, CancellationToken ct)
    {
        using var req = new HttpRequestMessage(
            HttpMethod.Delete, $"zones/{zoneId}/dns_records/{recordId}");
        req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        using var resp = await _http.SendAsync(req, ct);
        resp.EnsureSuccessStatusCode();
    }

    private sealed record PublishedRecord(string ZoneId, string RecordId);

    private sealed record CloudflareZone(string Id, IReadOnlyList<string> NameServers);
}