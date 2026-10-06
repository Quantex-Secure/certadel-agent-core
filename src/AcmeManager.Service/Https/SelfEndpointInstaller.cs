using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Installation;
using AcmeManager.Plugins.Contracts.Storage;

using Microsoft.Extensions.Logging;

namespace AcmeManager.Service.Https;

/// <summary>No configurable options — applying the issued cert is the whole job.</summary>
public sealed record SelfEndpointInstallerOptions : PluginOptions;

/// <summary>
/// Installs the issued certificate as acme-manager's own HTTPS endpoint cert
/// (:9443), replacing the self-signed bootstrap cert. Add this installer to the
/// renewal that covers the management host's own FQDN to get a trusted UI cert
/// — it is then re-applied automatically on every renewal.
/// </summary>
public sealed class SelfEndpointInstaller(
    EndpointCertificateProvider endpoint,
    ILogger<SelfEndpointInstaller> logger) : IInstaller
{
    public PluginMetadata Metadata { get; } = new(
        Id: "installer.acme-manager-endpoint",
        Name: "acme-manager HTTPS endpoint",
        Description: "Serves the issued certificate on acme-manager's own web UI (:9443), replacing the self-signed cert.",
        Category: PluginCategory.Installation,
        Version: new Version(1, 0, 0));

    public ValueTask<InstallResult> InstallAsync(CertificateBundle bundle, InstallContext ctx, CancellationToken ct)
    {
        var previous = endpoint.ReadIssuedPfx();
        endpoint.ApplyPfx(bundle.PfxBytes, bundle.PfxPassword);

        logger.LogInformation(
            "Applied issued cert for {CommonName} ({Thumbprint}) to the acme-manager HTTPS endpoint on :9443.",
            bundle.CommonName, bundle.Thumbprint);

        return ValueTask.FromResult(InstallResult.Ok("applied to :9443") with
        {
            Endpoints = [new VerifyEndpoint("127.0.0.1", 9443, bundle.CommonName)],
            Rollback = _ =>
            {
                if (previous is not null)
                {
                    endpoint.ApplyPfx(previous, null);
                }
                else
                {
                    endpoint.RevertToBootstrap();
                }
                return ValueTask.CompletedTask;
            },
        });
    }
}