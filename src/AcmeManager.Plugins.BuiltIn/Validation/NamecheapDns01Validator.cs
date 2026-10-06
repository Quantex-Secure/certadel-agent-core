using System.Collections.Concurrent;

using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Validation;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace AcmeManager.Plugins.BuiltIn.Validation;

public sealed record NamecheapDns01Options : PluginOptions
{
    /// <summary>Namecheap API user (your account username).</summary>
    public string ApiUser { get; init; } = "";

    /// <summary>Usually the same as the API user; defaults to it when blank.</summary>
    public string UserName { get; init; } = "";

    /// <summary>Named secret holding the Namecheap API key (never stored in the renewal).</summary>
    [SecretReference]
    public string ApiKeySecretName { get; init; } = "";

    /// <summary>The public IP whitelisted in Namecheap's API settings. Blank = auto-detect
    /// (Namecheap requires the calling IP be on its allowlist either way).</summary>
    public string ClientIp { get; init; } = "";

    public bool Sandbox { get; init; } = false;

    /// <summary>Namecheap DNS can be slow to propagate; wait this long before the CA checks.</summary>
    public TimeSpan PropagationDelay { get; init; } = TimeSpan.FromSeconds(120);
}

/// <summary>
/// DNS-01 validator for domains hosted at Namecheap. Publishes the
/// <c>_acme-challenge</c> TXT via Namecheap's API. Because Namecheap's setHosts
/// REPLACES every record, each change reads all hosts, edits the one TXT, and
/// writes them all back (preserving email routing). Linux/Windows agnostic.
/// </summary>
public sealed class NamecheapDns01Validator : IValidator, IDisposable
{
    private readonly ISecretResolver _secrets;
    private readonly ILogger<NamecheapDns01Validator> _logger;
    private readonly HttpClient _http;
    private readonly bool _ownsHttp;
    private readonly ConcurrentDictionary<string, PublishedTxt> _published = new();

    public PluginMetadata Metadata { get; } = new(
        Id: "validation.dns-01.namecheap",
        Name: "Namecheap DNS-01",
        Description: "Publishes the TXT record via Namecheap's API (requires a whitelisted source IP).",
        Category: PluginCategory.Validation,
        Version: new Version(1, 0, 0));

    public ChallengeType ChallengeType => ChallengeType.Dns01;

    [ActivatorUtilitiesConstructor]
    public NamecheapDns01Validator(ISecretResolver secrets, ILogger<NamecheapDns01Validator> logger)
        : this(secrets, logger, new HttpClient(), ownsHttp: true)
    {
    }

    internal NamecheapDns01Validator(
        ISecretResolver secrets, ILogger<NamecheapDns01Validator> logger, HttpClient http, bool ownsHttp)
    {
        _secrets = secrets;
        _logger = logger;
        _http = http;
        _ownsHttp = ownsHttp;
    }

    public async ValueTask PrepareAsync(ValidationContext ctx, CancellationToken ct)
    {
        var opts = (NamecheapDns01Options)ctx.Options;
        if (string.IsNullOrWhiteSpace(opts.ApiUser) || string.IsNullOrWhiteSpace(opts.ApiKeySecretName))
        {
            throw new InvalidOperationException("Namecheap DNS-01: ApiUser and ApiKeySecretName are required.");
        }

        var client = await ClientAsync(opts, ct);
        var (sld, tld, host) = SplitDomain(ctx.Identifier);

        var current = await client.GetHostsAsync(sld, tld, ct);
        var txt = new NamecheapHost(host, "TXT", ctx.KeyAuthorization, 10, 60);
        var updated = current with { Hosts = [.. current.Hosts, txt] };
        await client.SetHostsAsync(sld, tld, updated, ct);

        _published[ctx.Token] = new PublishedTxt(sld, tld, host, ctx.KeyAuthorization);
        _logger.LogInformation(
            "Namecheap DNS-01: published TXT {Host} in {Sld}.{Tld}; waiting {Delay}s for propagation",
            host, sld, tld, opts.PropagationDelay.TotalSeconds);

        if (opts.PropagationDelay > TimeSpan.Zero)
        {
            await Task.Delay(opts.PropagationDelay, ct);
        }
    }

    public async ValueTask CleanupAsync(ValidationContext ctx, CancellationToken ct)
    {
        if (!_published.TryRemove(ctx.Token, out var rec))
        {
            return;
        }
        try
        {
            var client = await ClientAsync((NamecheapDns01Options)ctx.Options, ct);
            var current = await client.GetHostsAsync(rec.Sld, rec.Tld, ct);
            var kept = current with
            {
                Hosts = current.Hosts.Where(h => !(h.Type == "TXT" && h.Name == rec.Host && h.Address == rec.Value)).ToList(),
            };
            await client.SetHostsAsync(rec.Sld, rec.Tld, kept, ct);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Namecheap DNS-01 cleanup failed for {Host} in {Sld}.{Tld}", rec.Host, rec.Sld, rec.Tld);
        }
    }

    public void Dispose()
    {
        if (_ownsHttp)
        {
            _http.Dispose();
        }
    }

    private async Task<NamecheapDnsClient> ClientAsync(NamecheapDns01Options opts, CancellationToken ct)
    {
        var apiKey = await _secrets.ResolveAsync(opts.ApiKeySecretName, ct);
        var userName = string.IsNullOrWhiteSpace(opts.UserName) ? opts.ApiUser : opts.UserName;
        var clientIp = string.IsNullOrWhiteSpace(opts.ClientIp) ? await ResolveClientIpAsync(ct) : opts.ClientIp.Trim();
        return new NamecheapDnsClient(_http, opts.ApiUser.Trim(), userName.Trim(), apiKey, clientIp, opts.Sandbox);
    }

    private async Task<string> ResolveClientIpAsync(CancellationToken ct)
    {
        // Namecheap's own IP echo service — the value must match an allowlisted IP.
        var ip = (await _http.GetStringAsync("https://dynamicdns.park-your-domain.com/getip", ct)).Trim();
        return ip;
    }

    /// <summary>Splits a challenge FQDN into Namecheap's SLD/TLD + relative host.
    /// e.g. "_acme-challenge.www.example.com" → ("example", "com", "_acme-challenge.www").</summary>
    internal static (string Sld, string Tld, string Host) SplitDomain(string fqdn)
    {
        var f = fqdn.TrimEnd('.');
        var labels = f.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length < 2)
        {
            throw new InvalidOperationException($"Cannot derive a Namecheap domain from '{fqdn}'.");
        }
        var sld = labels[^2];
        var tld = labels[^1];
        var domain = $"{sld}.{tld}";
        var host = f.Length > domain.Length ? f[..^(domain.Length + 1)] : "@";
        return (sld, tld, host);
    }

    private sealed record PublishedTxt(string Sld, string Tld, string Host, string Value);
}