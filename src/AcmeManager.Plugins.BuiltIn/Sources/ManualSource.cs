using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Sources;

namespace AcmeManager.Plugins.BuiltIn.Sources;

public sealed record ManualSourceOptions : PluginOptions
{
    public IReadOnlyList<string> Identifiers { get; init; } = [];

    /// <summary>Optional Common Name; defaults to the first identifier.</summary>
    public string? CommonName { get; init; }
}

/// <summary>
/// Source plugin that returns whatever DNS identifiers the user typed in.
/// The lowest-common-denominator option — fits any host or platform.
/// </summary>
public sealed class ManualSource : ISource
{
    public PluginMetadata Metadata { get; } = new(
        Id: "source.manual",
        Name: "Manual",
        Description: "Use a fixed list of DNS identifiers configured per renewal.",
        Category: PluginCategory.Source,
        Version: new Version(1, 0, 0));

    public ValueTask<SourceResult> ResolveAsync(SourceContext ctx, CancellationToken ct)
    {
        var opts = (ManualSourceOptions)ctx.Options;
        if (opts.Identifiers.Count == 0)
        {
            throw new InvalidOperationException(
                "ManualSource requires at least one identifier in options.");
        }

        return ValueTask.FromResult(new SourceResult(
            Identifiers: opts.Identifiers,
            CommonName: opts.CommonName ?? opts.Identifiers[0]));
    }
}