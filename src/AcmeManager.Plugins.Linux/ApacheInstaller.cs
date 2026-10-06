using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Installation;
using AcmeManager.Plugins.Contracts.Storage;

using Microsoft.Extensions.Logging;

namespace AcmeManager.Plugins.Linux;

public sealed record ApacheInstallerOptions : PluginOptions
{
    /// <summary>Path for the fullchain cert your vhost's <c>SSLCertificateFile</c>
    /// points at, e.g. <c>/etc/ssl/acme/example.com/fullchain.pem</c>. Required.</summary>
    [RequiredOption]
    public string CertPath { get; init; } = "";

    /// <summary>Path for the private key (<c>SSLCertificateKeyFile</c>),
    /// e.g. <c>/etc/ssl/acme/example.com/privkey.pem</c>. Required.</summary>
    [RequiredOption]
    public string KeyPath { get; init; } = "";

    /// <summary>Reload command. Default is Debian/Ubuntu's service name; on
    /// RHEL/Rocky/Alma change to <c>systemctl reload httpd</c>.</summary>
    public string ReloadCommand { get; init; } = "systemctl reload apache2";

    public TimeSpan ReloadTimeout { get; init; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Endpoints to check after install, comma-separated: <c>host</c>, <c>host:port</c>,
    /// or <c>name@host:port</c> (name = SNI). Empty = the installer's default (loopback
    /// on the service port, with the certificate's common name as SNI).
    /// </summary>
    public string VerifyEndpoints { get; init; } = "";

    /// <summary>
    /// Skips the post-install check for this step. The renewal is then recorded
    /// as unverified — use only where the agent can't reach the endpoint it serves.
    /// </summary>
    public bool SkipVerification { get; init; }
}

/// <summary>
/// Writes the fullchain cert and private key where an Apache vhost references them,
/// then gracefully reloads Apache. Linux-only.
/// </summary>
public sealed class ApacheInstaller(ICommandRunner commands, ILogger<ApacheInstaller> logger)
    : IInstaller, ICapability
{
    public PluginMetadata Metadata { get; } = new(
        Id: "installer.apache",
        Name: "Apache",
        Description: "Writes fullchain + key PEM files for an Apache vhost and reloads Apache.",
        Category: PluginCategory.Installation,
        Version: new Version(1, 0, 0));

    public ValueTask<CapabilityResult> CheckAsync(CancellationToken ct) =>
        ValueTask.FromResult(OperatingSystem.IsLinux()
            ? CapabilityResult.Yes
            : CapabilityResult.No("Apache installer requires Linux"));

    public async ValueTask<InstallResult> InstallAsync(CertificateBundle bundle, InstallContext ctx, CancellationToken ct)
    {
        var opts = (ApacheInstallerOptions)ctx.Options;
        // Validate the operator's endpoint list before writing anything.
        var explicitEndpoints = VerificationOptions.Parse(opts.VerifyEndpoints, 443, bundle.CommonName);
        if (string.IsNullOrWhiteSpace(opts.CertPath) || string.IsNullOrWhiteSpace(opts.KeyPath))
        {
            throw new InvalidOperationException("Apache installer: CertPath and KeyPath are required.");
        }

        var restoreCert = LinuxInstall.WriteFileAtomicKeepingPrevious(opts.CertPath, LinuxCertMaterial.FullChainPem(bundle), ownerOnly: false);
        var restoreKey = LinuxInstall.WriteFileAtomicKeepingPrevious(opts.KeyPath, LinuxCertMaterial.PrivateKeyPem(bundle), ownerOnly: true);
        logger.LogInformation("Wrote Apache cert to {Cert} and key to {Key}", opts.CertPath, opts.KeyPath);

        if (!string.IsNullOrWhiteSpace(opts.ReloadCommand))
        {
            await commands.RunAsync(opts.ReloadCommand, opts.ReloadTimeout, ct);
            logger.LogInformation("Reloaded Apache via '{Command}'", opts.ReloadCommand);
        }
        return InstallResult.Ok(opts.CertPath) with
        {
            Endpoints = opts.SkipVerification ? [] : explicitEndpoints.Count > 0 ? explicitEndpoints : [new VerifyEndpoint("127.0.0.1", 443, bundle.CommonName)],
            VerificationSkippedReason = opts.SkipVerification ? VerificationOptions.SkippedByOperator : null,
            Rollback = async rollbackCt =>
            {
                restoreKey();
                restoreCert();
                if (!string.IsNullOrWhiteSpace(opts.ReloadCommand))
                {
                    await commands.RunAsync(opts.ReloadCommand, opts.ReloadTimeout, rollbackCt);
                }
                logger.LogWarning("Restored the previous Apache certificate at {Path}", opts.CertPath);
            },
        };
    }
}