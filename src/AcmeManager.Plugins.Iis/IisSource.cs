using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Sources;

using Microsoft.Extensions.Logging;
using Microsoft.Web.Administration;

namespace AcmeManager.Plugins.Iis;

public sealed record IisSourceOptions : PluginOptions
{
    /// <summary>The IIS site whose bindings supply the hostnames.</summary>
    [IisSiteReference]
    public string? SiteName { get; init; }

    /// <summary>
    /// Deliberately scrape every site on this server. Off by default — an empty
    /// SiteName used to silently mean this, which pulled unrelated (e.g.
    /// internal-only) hostnames into public certificate requests.
    /// </summary>
    public bool AllSites { get; init; }

    /// <summary>Only include these hostnames (exact, or <c>*.example.com</c>). Empty = all.</summary>
    public IReadOnlyList<string> IncludeHosts { get; init; } = [];

    /// <summary>Never include these hostnames (exact, or <c>*.example.com</c>).</summary>
    public IReadOnlyList<string> ExcludeHosts { get; init; } = [];
}

/// <summary>
/// Source plugin that scrapes IIS site bindings for HTTP/HTTPS hostnames.
/// Useful for "renew whatever IIS is serving" without maintaining a list by
/// hand. Returns identifiers in the order the bindings appear in IIS.
/// </summary>
public sealed class IisSource(ILogger<IisSource> logger) : ISource, ICapability
{
    public PluginMetadata Metadata { get; } = new(
        Id: "source.iis",
        Name: "IIS bindings",
        Description: "Scrapes an IIS site's bindings for hostnames; optional host include/exclude filters.",
        Category: PluginCategory.Source,
        Version: new Version(1, 1, 0));

    public ValueTask<CapabilityResult> CheckAsync(CancellationToken ct) =>
        ValueTask.FromResult(OperatingSystem.IsWindows()
            ? CapabilityResult.Yes
            : CapabilityResult.No("IIS source requires Windows"));

    public ValueTask<SourceResult> ResolveAsync(SourceContext ctx, CancellationToken ct)
    {
        var opts = (IisSourceOptions)ctx.Options;

        if (string.IsNullOrWhiteSpace(opts.SiteName) && !opts.AllSites)
        {
            throw new InvalidOperationException(
                "IIS source: no site name is set. Pick a site — or enable AllSites to deliberately " +
                "request a certificate covering every binding on this server.");
        }

        using var serverManager = new ServerManager();
        var sites = string.IsNullOrWhiteSpace(opts.SiteName)
            ? serverManager.Sites.ToList()
            : serverManager.Sites.Where(s =>
                string.Equals(s.Name, opts.SiteName, StringComparison.OrdinalIgnoreCase)).ToList();
        if (!string.IsNullOrWhiteSpace(opts.SiteName) && sites.Count == 0)
        {
            throw new InvalidOperationException($"IIS source: site '{opts.SiteName}' was not found on this server.");
        }

        var hostnames = sites
            .SelectMany(s => s.Bindings)
            .Where(b => (b.Protocol == "http" || b.Protocol == "https") && !string.IsNullOrWhiteSpace(b.Host))
            .Select(b => b.Host)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (hostnames.Count == 0)
        {
            throw new InvalidOperationException(
                string.IsNullOrWhiteSpace(opts.SiteName)
                    ? "IIS source: no bindings with a Host header found across any site"
                    : $"IIS source: no bindings with a Host header found for site '{opts.SiteName}'");
        }

        var filtered = FilterHosts(hostnames, opts.IncludeHosts, opts.ExcludeHosts);
        if (filtered.Count == 0)
        {
            throw new InvalidOperationException(
                $"IIS source: all {hostnames.Count} scraped hostname(s) were removed by the include/exclude filters.");
        }

        logger.LogInformation(
            "IIS source: scraped {Count} hostname(s){Filtered}",
            filtered.Count,
            filtered.Count == hostnames.Count ? "" : $" ({hostnames.Count - filtered.Count} filtered out)");
        return ValueTask.FromResult(new SourceResult(filtered, CommonName: filtered[0]));
    }

    /// <summary>Include first (empty include = everything), then exclude. Patterns are
    /// exact hostnames or <c>*.example.com</c> (any subdomain, not the apex).</summary>
    internal static List<string> FilterHosts(
        IEnumerable<string> hosts,
        IReadOnlyList<string> includeHosts,
        IReadOnlyList<string> excludeHosts)
    {
        return hosts
            .Where(h => includeHosts.Count == 0 || includeHosts.Any(p => Matches(h, p)))
            .Where(h => !excludeHosts.Any(p => Matches(h, p)))
            .ToList();

        static bool Matches(string host, string pattern)
        {
            var trimmed = pattern.Trim();
            if (trimmed.Length == 0)
            {
                return false;
            }
            return trimmed.StartsWith("*.", StringComparison.Ordinal)
                ? host.EndsWith(trimmed[1..], StringComparison.OrdinalIgnoreCase)
                : string.Equals(host, trimmed, StringComparison.OrdinalIgnoreCase);
        }
    }
}