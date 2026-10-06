namespace AcmeManager.Plugins.Contracts.Storage;

/// <summary>
/// Persists an issued certificate so it can be referenced later by installers.
/// Multiple stores can chain (e.g. PEM file + Windows store).
/// </summary>
public interface IStore : IPlugin
{
    ValueTask<StoreResult> StoreAsync(CertificateBundle bundle, StoreContext ctx, CancellationToken ct);

    ValueTask<CertificateBundle?> RetrieveAsync(string identifier, StoreContext ctx, CancellationToken ct);

    ValueTask DeleteAsync(string identifier, StoreContext ctx, CancellationToken ct);
}

public sealed record StoreContext(PluginOptions Options);

/// <summary>
/// Returned by <see cref="IStore.StoreAsync"/>. <see cref="Reference"/> is an
/// opaque store-specific locator (file path, thumbprint, KeyVault URI, etc.)
/// that installers can use to find the cert later.
/// </summary>
public sealed record StoreResult(string Reference);

/// <param name="PfxBytes">PKCS#12 containing the leaf cert, chain, and private key.</param>
public sealed record CertificateBundle(
    string CommonName,
    IReadOnlyList<string> SubjectAlternativeNames,
    byte[] PfxBytes,
    string PfxPassword,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string Thumbprint)
{
    /// <summary>
    /// Human-friendly label for the certificate — the renewal name, set by the
    /// engine. Stores that support naming (e.g. the Windows certificate store's
    /// Friendly Name) use it so the cert is identifiable in certlm. Optional.
    /// </summary>
    public string FriendlyName { get; init; } = "";
}