namespace AcmeManager.Plugins.Contracts.Sources;

/// <summary>
/// Resolves a list of DNS identifiers (and optional common name) for which a
/// certificate should be issued. Examples: scrape IIS bindings, expand a
/// wildcard pattern, read a manual list.
/// </summary>
public interface ISource : IPlugin
{
    ValueTask<SourceResult> ResolveAsync(SourceContext ctx, CancellationToken ct);
}

public sealed record SourceContext(PluginOptions Options);

public sealed record SourceResult(IReadOnlyList<string> Identifiers, string? CommonName = null);