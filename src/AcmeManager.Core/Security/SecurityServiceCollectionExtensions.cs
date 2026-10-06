using AcmeManager.Core.Security;
using AcmeManager.Core.Storage;
using AcmeManager.Plugins.Contracts;

// Conventional namespace so consumers don't need an extra using.
namespace Microsoft.Extensions.DependencyInjection;

public static class SecurityServiceCollectionExtensions
{
    /// <summary>
    /// Registers an OS-appropriate <see cref="ISecretProtector"/> singleton —
    /// DPAPI on Windows, AES-GCM keyfile elsewhere.
    /// </summary>
    public static IServiceCollection AddSecretProtector(this IServiceCollection services)
    {
        services.AddSingleton(_ => SecretProtectorFactory.Create(DataPaths.SecretsKeyFile));
        return services;
    }

    /// <summary>
    /// Registers <see cref="AddSecretProtector"/> plus the secret-resolver
    /// (singleton, opens its own DI scope per call) and <see cref="SecretsService"/>
    /// (scoped) for programmatic management.
    /// </summary>
    public static IServiceCollection AddAcmeManagerSecrets(this IServiceCollection services)
    {
        services.AddSecretProtector();
        services.AddSingleton<ISecretResolver, ScopedSecretResolver>();
        services.AddScoped<SecretsService>();
        return services;
    }
}