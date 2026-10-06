using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Installation;
using AcmeManager.Plugins.Contracts.Storage;

using Microsoft.Extensions.Logging;

namespace AcmeManager.Plugins.Linux;

public sealed record TomcatInstallerOptions : PluginOptions
{
    /// <summary>Path to the PKCS#12 keystore your <c>server.xml</c> connector
    /// references, e.g. <c>/opt/tomcat/conf/keystore.p12</c>
    /// (<c>keystoreFile</c>, <c>keystoreType="PKCS12"</c>). Required.</summary>
    [RequiredOption]
    public string KeystorePath { get; init; } = "";

    /// <summary>
    /// Name of a stored secret holding the keystore password (must match the
    /// connector's <c>keystorePass</c>). Preferred: only the secret name is
    /// persisted. Takes precedence over <see cref="KeystorePassword"/>.
    /// </summary>
    [SecretReference]
    public string KeystorePasswordSecretName { get; init; } = "";

    /// <summary>
    /// Literal keystore password. Deprecated in favour of
    /// <see cref="KeystorePasswordSecretName"/>; redacted by the management API and
    /// not accepted when creating a renewal through it. Empty (with no secret
    /// named) means Tomcat's stock <c>changeit</c>.
    /// </summary>
    [SensitiveOption]
    public string KeystorePassword { get; init; } = "";

    /// <summary>Command run after writing the keystore. Tomcat doesn't hot-reload
    /// certs, so the default restarts it.</summary>
    public string ReloadCommand { get; init; } = "systemctl restart tomcat";

    public TimeSpan ReloadTimeout { get; init; } = TimeSpan.FromSeconds(60);

    /// <summary>
    /// Endpoints to check after install, comma-separated: <c>host</c>, <c>host:port</c>,
    /// or <c>name@host:port</c> (name = SNI). Empty = the installer's default (loopback
    /// on port 8443, with the certificate's common name as SNI).
    /// </summary>
    public string VerifyEndpoints { get; init; } = "";

    /// <summary>
    /// Skips the post-install check for this step. The renewal is then recorded
    /// as unverified — use only where the agent can't reach the endpoint it serves.
    /// </summary>
    public bool SkipVerification { get; init; }
}

/// <summary>
/// Writes the certificate as a PKCS#12 keystore (re-keyed with the configured
/// password) where Tomcat's connector references it, then restarts Tomcat. PKCS#12
/// works with every Tomcat version. Linux-only.
/// </summary>
public sealed class TomcatInstaller(ICommandRunner commands, ISecretResolver secrets, ILogger<TomcatInstaller> logger)
    : IInstaller, ICapability
{
    /// <summary>Tomcat's documented default keystore password.</summary>
    public const string DefaultKeystorePassword = "changeit";

    public PluginMetadata Metadata { get; } = new(
        Id: "installer.tomcat",
        Name: "Tomcat",
        Description: "Writes a PKCS#12 keystore for a Tomcat connector and restarts Tomcat.",
        Category: PluginCategory.Installation,
        Version: new Version(1, 0, 0));

    public ValueTask<CapabilityResult> CheckAsync(CancellationToken ct) =>
        ValueTask.FromResult(OperatingSystem.IsLinux()
            ? CapabilityResult.Yes
            : CapabilityResult.No("Tomcat installer requires Linux"));

    public async ValueTask<InstallResult> InstallAsync(CertificateBundle bundle, InstallContext ctx, CancellationToken ct)
    {
        var opts = (TomcatInstallerOptions)ctx.Options;
        // Validate the operator's endpoint list before writing anything.
        var explicitEndpoints = VerificationOptions.Parse(opts.VerifyEndpoints, 8443, bundle.CommonName);
        if (string.IsNullOrWhiteSpace(opts.KeystorePath))
        {
            throw new InvalidOperationException("Tomcat installer: KeystorePath is required.");
        }

        var password = !string.IsNullOrEmpty(opts.KeystorePasswordSecretName)
            ? await secrets.ResolveAsync(opts.KeystorePasswordSecretName, ct)
            : string.IsNullOrEmpty(opts.KeystorePassword) ? DefaultKeystorePassword : opts.KeystorePassword;
        var keystore = LinuxCertMaterial.Pkcs12(bundle, password);
        var restore = LinuxInstall.WriteFileAtomicKeepingPrevious(opts.KeystorePath, keystore, ownerOnly: true);
        logger.LogInformation("Wrote Tomcat keystore to {Path}", opts.KeystorePath);

        if (!string.IsNullOrWhiteSpace(opts.ReloadCommand))
        {
            await commands.RunAsync(opts.ReloadCommand, opts.ReloadTimeout, ct);
            logger.LogInformation("Restarted Tomcat via '{Command}'", opts.ReloadCommand);
        }
        return InstallResult.Ok(opts.KeystorePath) with
        {
            Endpoints = opts.SkipVerification ? [] : explicitEndpoints.Count > 0 ? explicitEndpoints : [new VerifyEndpoint("127.0.0.1", 8443, bundle.CommonName)],
            VerificationSkippedReason = opts.SkipVerification ? VerificationOptions.SkippedByOperator : null,
            Rollback = async rollbackCt =>
            {
                restore();
                if (!string.IsNullOrWhiteSpace(opts.ReloadCommand))
                {
                    await commands.RunAsync(opts.ReloadCommand, opts.ReloadTimeout, rollbackCt);
                }
                logger.LogWarning("Restored the previous Tomcat keystore at {Path}", opts.KeystorePath);
            },
        };
    }
}