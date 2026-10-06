using AcmeManager.Core.Plugins;
using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Installation;
using AcmeManager.Plugins.Contracts.Sources;
using AcmeManager.Plugins.Contracts.Storage;
using AcmeManager.Plugins.Contracts.Validation;

// Conventional namespace so consumers don't need an extra using.
namespace Microsoft.Extensions.DependencyInjection;

public static class PluginRegistrationExtensions
{
    /// <summary>
    /// Registers a <see cref="PluginCatalog"/> singleton plus a keyed singleton
    /// per plugin so the engine can resolve them by id at runtime, e.g.
    /// <c>sp.GetRequiredKeyedService&lt;IValidator&gt;("validation.http-01.filesystem")</c>.
    /// Each plugin is also registered as its concrete type so DI can construct it.
    /// </summary>
    public static IServiceCollection AddPluginCatalog(
        this IServiceCollection services,
        Action<PluginCatalogBuilder> configure)
    {
        ArgumentNullException.ThrowIfNull(configure);

        var builder = new PluginCatalogBuilder();
        configure(builder);

        services.AddSingleton(new PluginCatalog(builder.Registrations));

        foreach (var reg in builder.Registrations)
        {
            services.AddSingleton(reg.ImplementationType);

            var categoryInterface = reg.Category switch
            {
                PluginCategory.Source => typeof(ISource),
                PluginCategory.Validation => typeof(IValidator),
                PluginCategory.Store => typeof(IStore),
                PluginCategory.Installation => typeof(IInstaller),
                _ => throw new NotSupportedException(
                    $"Plugin category {reg.Category} is not wired into DI yet"),
            };

            services.AddKeyedSingleton(
                categoryInterface,
                reg.Id,
                (sp, _) => sp.GetRequiredService(reg.ImplementationType));
        }

        return services;
    }
}