using AcmeManager.Core.Authentication;
using AcmeManager.Plugins.Linux.Synology;
using AcmeManager.Service.Authentication;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Microsoft.Extensions.DependencyInjection;

public static class AuthServiceCollectionExtensions
{
    private const string DefaultDsmUrl = "http://127.0.0.1:5000";

    /// <summary>
    /// Registers an OS-appropriate <see cref="IAuthBackend"/> singleton —
    /// <see cref="WindowsAuthBackend"/> on Windows, <see cref="DsmAuthBackend"/> on
    /// Synology DSM (the local DSM Web API, <c>Dsm:Url</c>, default
    /// <c>http://127.0.0.1:5000</c>), <see cref="LinuxPamAuthBackend"/> on other
    /// Linux. Other platforms get a stub that always refuses.
    ///
    /// Backends authenticate and resolve group membership only. The
    /// <c>Auth:AllowedGroup</c> decision is made by <see cref="AllowedGroupAuthorizer"/>
    /// (registered separately) at the login endpoint and the management-API policy.
    /// </summary>
    public static IServiceCollection AddOsAuthBackend(this IServiceCollection services)
    {
        services.AddSingleton<IAuthBackend>(sp =>
        {
            if (OperatingSystem.IsWindows())
            {
#pragma warning disable CA1416 // guarded above
                return new WindowsAuthBackend();
#pragma warning restore CA1416
            }
            if (DsmPlatform.IsDsm)
            {
                // Validated up front: a bad Dsm:Url fails here, not silently at every login.
                var dsmUrl = DsmApiClient.ValidateEndpoint(
                    new Uri(sp.GetRequiredService<IConfiguration>()["Dsm:Url"] ?? DefaultDsmUrl));
                return new DsmAuthBackend(
                    () => new DsmApiClient(dsmUrl),
                    sp.GetRequiredService<ILogger<DsmAuthBackend>>(),
                    TimeProvider.System);
            }
            if (OperatingSystem.IsLinux())
            {
#pragma warning disable CA1416
                return new LinuxPamAuthBackend(new IdCommandGroupResolver());
#pragma warning restore CA1416
            }
            return new StubAuthBackend();
        });
        return services;
    }

    private sealed class StubAuthBackend : IAuthBackend
    {
        public ValueTask<AuthResult> AuthenticateAsync(string username, string password, CancellationToken ct) =>
            ValueTask.FromResult(AuthResult.Fail("No OS auth backend available on this platform"));
    }
}