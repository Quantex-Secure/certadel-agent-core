namespace AcmeManager.Plugins.Contracts.Installation;

using AcmeManager.Plugins.Contracts.Storage;

/// <summary>
/// Applies a freshly-issued certificate to a deployment target (IIS bindings,
/// nginx reload, post-install script, etc.). Receives the bundle plus the
/// references returned by every store that ran, so it can pick the form it
/// needs (PFX path, cert thumbprint, KeyVault URI, …).
/// </summary>
public interface IInstaller : IPlugin
{
    /// <summary>
    /// Applies the certificate. Throw for a failure; return
    /// <see cref="InstallResult.NothingToApply"/> when the step ran but found
    /// nothing to bind (a site or binding that doesn't exist yet) — the engine
    /// records that as a warning so a certificate that was issued and stored but
    /// is not actually being served is never reported as a clean success.
    /// Populate <see cref="InstallResult.Endpoints"/> with what the engine should
    /// probe to confirm the certificate is in service, and <see cref="InstallResult.Rollback"/>
    /// with how to put the previous certificate back if it isn't.
    /// </summary>
    ValueTask<InstallResult> InstallAsync(CertificateBundle bundle, InstallContext ctx, CancellationToken ct);
}

/// <param name="StoreReferences">
/// Map of store plugin id → opaque reference returned by that store's
/// <c>StoreAsync</c>. E.g. {"store.pem": "/etc/ssl/example.com.pem",
/// "store.winstore": "A1B2C3...thumbprint"}.
/// </param>
public sealed record InstallContext(
    PluginOptions Options,
    IReadOnlyDictionary<string, string> StoreReferences);

/// <summary>
/// A TLS endpoint the engine connects to after installation to confirm the new
/// certificate is what the server actually presents.
/// </summary>
/// <param name="Host">Address to connect to (an IP or host name; loopback is fine).</param>
/// <param name="Port">TCP port.</param>
/// <param name="ServerName">Name sent as SNI, so name-based servers pick the right certificate.</param>
public sealed record VerifyEndpoint(string Host, int Port, string ServerName)
{
    public override string ToString() =>
        string.Equals(Host, ServerName, StringComparison.OrdinalIgnoreCase)
            ? $"{Host}:{Port}"
            : $"{ServerName} via {Host}:{Port}";
}

/// <summary>
/// Outcome of one installer step. <see cref="Applied"/> is true when the
/// certificate is now in use by the target; false means the step completed
/// without error but bound nothing, and <see cref="Detail"/> says why.
/// </summary>
public sealed record InstallResult(bool Applied, string? Detail = null)
{
    /// <summary>
    /// Endpoints to probe after all installers have run. Empty means this step has
    /// nothing observable to verify (a script, or verification switched off).
    /// </summary>
    public IReadOnlyList<VerifyEndpoint> Endpoints { get; init; } = [];

    /// <summary>
    /// Restores whatever this step replaced. Invoked (in reverse step order) when
    /// verification fails, so the target goes back to serving its previous
    /// certificate. Null when there is nothing to undo.
    /// </summary>
    public Func<CancellationToken, ValueTask>? Rollback { get; init; }

    /// <summary>
    /// Why verification was skipped for this step, when the operator switched it
    /// off. Recorded in history so an unverified install is never silent.
    /// </summary>
    public string? VerificationSkippedReason { get; init; }

    public static InstallResult Ok(string? detail = null) => new(true, detail);

    public static InstallResult NothingToApply(string reason) => new(false, reason);
}