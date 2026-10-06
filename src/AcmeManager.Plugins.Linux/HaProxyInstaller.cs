using System.Text.RegularExpressions;

using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Installation;
using AcmeManager.Plugins.Contracts.Storage;

using Microsoft.Extensions.Logging;

namespace AcmeManager.Plugins.Linux;

public sealed record HaProxyInstallerOptions : PluginOptions
{
    /// <summary>Full path to the combined PEM file HAProxy's <c>crt</c> references
    /// (cert + chain + key in one file), e.g. <c>/etc/haproxy/certs/example.com.pem</c>.
    /// Required.</summary>
    [RequiredOption]
    public string PemPath { get; init; } = "";

    /// <summary>Command run after writing the cert. Default reloads HAProxy without
    /// dropping connections.</summary>
    public string ReloadCommand { get; init; } = "systemctl reload haproxy";

    /// <summary>If set, the cert file is group-owned by this group at mode 0640
    /// (e.g. <c>haproxy</c>, so HAProxy reading as that group can load it). Empty =
    /// owner-only 0600.</summary>
    public string Group { get; init; } = "";

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
/// Writes the certificate as a single combined PEM (fullchain + private key) where
/// HAProxy expects it, then reloads HAProxy. Linux-only.
/// </summary>
public sealed partial class HaProxyInstaller(ICommandRunner commands, ILogger<HaProxyInstaller> logger)
    : IInstaller, ICapability
{
    /// <summary>POSIX group names: portable characters, optionally a trailing <c>$</c>.</summary>
    internal static bool IsValidGroupName(string group) =>
        !string.IsNullOrEmpty(group) && group.Length <= 32 && GroupName().IsMatch(group);

    [GeneratedRegex(@"^[A-Za-z_][A-Za-z0-9_-]*\$?$")]
    private static partial Regex GroupName();

    public PluginMetadata Metadata { get; } = new(
        Id: "installer.haproxy",
        Name: "HAProxy",
        Description: "Writes a combined cert+chain+key PEM for HAProxy and reloads it.",
        Category: PluginCategory.Installation,
        Version: new Version(1, 0, 0));

    public ValueTask<CapabilityResult> CheckAsync(CancellationToken ct) =>
        ValueTask.FromResult(OperatingSystem.IsLinux()
            ? CapabilityResult.Yes
            : CapabilityResult.No("HAProxy installer requires Linux"));

    public async ValueTask<InstallResult> InstallAsync(CertificateBundle bundle, InstallContext ctx, CancellationToken ct)
    {
        var opts = (HaProxyInstallerOptions)ctx.Options;
        // Validate the operator's endpoint list before writing anything.
        var explicitEndpoints = VerificationOptions.Parse(opts.VerifyEndpoints, 443, bundle.CommonName);
        if (string.IsNullOrWhiteSpace(opts.PemPath))
        {
            throw new InvalidOperationException("HAProxy installer: PemPath is required.");
        }

        var groupReadable = !string.IsNullOrWhiteSpace(opts.Group);
        if (groupReadable && !IsValidGroupName(opts.Group))
        {
            throw new InvalidOperationException($"HAProxy installer: '{opts.Group}' is not a valid group name.");
        }
        var restore = LinuxInstall.WriteFileAtomicKeepingPrevious(opts.PemPath, LinuxCertMaterial.HaProxyPem(bundle), ownerOnly: !groupReadable);
        if (groupReadable && OperatingSystem.IsLinux())
        {
            File.SetUnixFileMode(opts.PemPath,
                UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead);
            // Discrete arguments, no shell: the group and path come from configuration.
            await commands.RunAsync("chgrp", [opts.Group, opts.PemPath], opts.ReloadTimeout, ct);
        }
        logger.LogInformation("Wrote HAProxy PEM to {Path}", opts.PemPath);

        if (!string.IsNullOrWhiteSpace(opts.ReloadCommand))
        {
            await commands.RunAsync(opts.ReloadCommand, opts.ReloadTimeout, ct);
            logger.LogInformation("Reloaded HAProxy via '{Command}'", opts.ReloadCommand);
        }
        return InstallResult.Ok(opts.PemPath) with
        {
            Endpoints = opts.SkipVerification ? [] : explicitEndpoints.Count > 0 ? explicitEndpoints : [new VerifyEndpoint("127.0.0.1", 443, bundle.CommonName)],
            VerificationSkippedReason = opts.SkipVerification ? VerificationOptions.SkippedByOperator : null,
            Rollback = async rollbackCt =>
            {
                restore();
                if (!string.IsNullOrWhiteSpace(opts.ReloadCommand))
                {
                    await commands.RunAsync(opts.ReloadCommand, opts.ReloadTimeout, rollbackCt);
                }
                logger.LogWarning("Restored the previous HAProxy PEM at {Path}", opts.PemPath);
            },
        };
    }
}