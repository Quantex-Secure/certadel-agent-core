using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Installation;
using AcmeManager.Plugins.Contracts.Sources;
using AcmeManager.Plugins.Contracts.Storage;
using AcmeManager.Plugins.Contracts.Validation;

namespace AcmeManager.Core.Plugins;

/// <summary>
/// Fluent builder used inside <c>AddPluginCatalog(...)</c> to declare every
/// built-in (or sideloaded) plugin and its options type. The host wires keyed
/// DI from these declarations and snapshots them into a <see cref="PluginCatalog"/>.
/// </summary>
public sealed class PluginCatalogBuilder
{
    internal List<PluginRegistration> Registrations { get; } = new();

    public PluginCatalogBuilder AddSource<TPlugin, TOptions>(string id)
        where TPlugin : class, ISource
        where TOptions : PluginOptions, new()
        => AddCore(id, PluginCategory.Source, typeof(TPlugin), typeof(TOptions), () => new TOptions());

    public PluginCatalogBuilder AddValidator<TPlugin, TOptions>(string id)
        where TPlugin : class, IValidator
        where TOptions : PluginOptions, new()
        => AddCore(id, PluginCategory.Validation, typeof(TPlugin), typeof(TOptions), () => new TOptions());

    public PluginCatalogBuilder AddStore<TPlugin, TOptions>(string id)
        where TPlugin : class, IStore
        where TOptions : PluginOptions, new()
        => AddCore(id, PluginCategory.Store, typeof(TPlugin), typeof(TOptions), () => new TOptions());

    public PluginCatalogBuilder AddInstaller<TPlugin, TOptions>(string id)
        where TPlugin : class, IInstaller
        where TOptions : PluginOptions, new()
        => AddCore(id, PluginCategory.Installation, typeof(TPlugin), typeof(TOptions), () => new TOptions());

    private PluginCatalogBuilder AddCore(
        string id,
        PluginCategory category,
        Type impl,
        Type opts,
        Func<PluginOptions> factory)
    {
        if (Registrations.Any(r => r.Id == id))
        {
            throw new InvalidOperationException($"Plugin id '{id}' is already registered");
        }
        Registrations.Add(new PluginRegistration(id, category, impl, opts, factory));
        return this;
    }
}