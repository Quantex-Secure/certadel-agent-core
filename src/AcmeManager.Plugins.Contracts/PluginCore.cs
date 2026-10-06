namespace AcmeManager.Plugins.Contracts;

public enum PluginCategory
{
    Source,
    Validation,
    Store,
    Installation,
    Notification,
    Secret,
}

/// <summary>
/// Marker interface for every plugin. Concrete plugins implement one of the
/// category interfaces (<see cref="Sources.ISource"/>, <see cref="Validation.IValidator"/>, etc.)
/// which themselves extend <see cref="IPlugin"/>.
/// </summary>
public interface IPlugin
{
    PluginMetadata Metadata { get; }
}

public sealed record PluginMetadata(
    string Id,
    string Name,
    string Description,
    PluginCategory Category,
    Version Version);

/// <summary>
/// Self-check the plugin performs before it can be selected for use. Lets the
/// UI hide plugins that aren't viable on the current host (e.g. IIS plugin on
/// Linux, Azure DNS plugin without credentials configured).
/// </summary>
public interface ICapability
{
    ValueTask<CapabilityResult> CheckAsync(CancellationToken ct);
}

public sealed record CapabilityResult(bool Available, string? Reason = null)
{
    public static CapabilityResult Yes { get; } = new(true);
    public static CapabilityResult No(string reason) => new(false, reason);
}

/// <summary>
/// Base for typed plugin configuration. Each plugin defines its own derived
/// record; <see cref="SchemaVersion"/> drives forward-compatible migration.
/// </summary>
public abstract record PluginOptions
{
    public int SchemaVersion { get; init; } = 1;
}