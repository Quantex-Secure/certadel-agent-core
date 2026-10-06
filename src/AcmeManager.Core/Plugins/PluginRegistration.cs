using AcmeManager.Plugins.Contracts;

namespace AcmeManager.Core.Plugins;

/// <summary>
/// One entry in the <see cref="PluginCatalog"/>. Captures the bits the host
/// needs to instantiate the plugin via DI and (de)serialize its options.
/// </summary>
public sealed record PluginRegistration(
    string Id,
    PluginCategory Category,
    Type ImplementationType,
    Type OptionsType,
    Func<PluginOptions> DefaultOptionsFactory);