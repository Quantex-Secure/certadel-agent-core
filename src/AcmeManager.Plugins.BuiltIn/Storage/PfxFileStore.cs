using System.Security.Cryptography.X509Certificates;

using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Storage;

using Microsoft.Extensions.Logging;

namespace AcmeManager.Plugins.BuiltIn.Storage;

public sealed record PfxFileStoreOptions : PluginOptions
{
    /// <summary>Absolute path where the .pfx file will be written.</summary>
    public string FilePath { get; init; } = "";

    /// <summary>
    /// Name of a stored secret holding the PFX password. Preferred over
    /// <see cref="Password"/>: only the secret <em>name</em> is persisted in the
    /// renewal config, while the credential stays encrypted in the host's secret
    /// store. When set, it takes precedence over <see cref="Password"/>.
    /// </summary>
    [SecretReference]
    public string PasswordSecretName { get; init; } = "";

    /// <summary>
    /// Literal PFX password. Deprecated: it is stored in plaintext in the renewal
    /// config and returned by the management API — prefer
    /// <see cref="PasswordSecretName"/>. Kept for backward compatibility. If
    /// different from the bundle's existing password, the PFX is re-exported with
    /// this password before writing.
    /// </summary>
    [SensitiveOption]
    public string? Password { get; init; }
}

/// <summary>
/// Writes the issued PFX bundle (cert + chain + key) to a single file.
/// Returns the file path as the store reference for installers.
/// </summary>
public sealed class PfxFileStore(ILogger<PfxFileStore> logger, ISecretResolver secrets) : IStore
{
    public PluginMetadata Metadata { get; } = new(
        Id: "store.pfx",
        Name: "PFX file",
        Description: "Writes a single PKCS#12 .pfx file with cert chain and private key.",
        Category: PluginCategory.Store,
        Version: new Version(1, 0, 0));

    public async ValueTask<StoreResult> StoreAsync(CertificateBundle bundle, StoreContext ctx, CancellationToken ct)
    {
        var opts = (PfxFileStoreOptions)ctx.Options;
        if (string.IsNullOrWhiteSpace(opts.FilePath))
        {
            throw new InvalidOperationException("PfxFileStore: FilePath is required");
        }

        var dir = Path.GetDirectoryName(opts.FilePath);
        if (!string.IsNullOrEmpty(dir))
        {
            Directory.CreateDirectory(dir);
        }

        var password = await ResolvePasswordAsync(opts, ct);
        var bytes = bundle.PfxBytes;
        if (!string.IsNullOrEmpty(password) && password != bundle.PfxPassword)
        {
            // Ephemeral + Exportable so the key can be re-exported under the new
            // password: Windows otherwise imports the key non-exportable and the
            // Export() below fails with "Key not valid for use in specified state".
            var collection = X509CertificateLoader.LoadPkcs12Collection(
                bundle.PfxBytes,
                bundle.PfxPassword,
                X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
            try
            {
                bytes = collection.Export(X509ContentType.Pfx, password)
                    ?? throw new InvalidOperationException("PFX re-export with new password failed");
            }
            finally
            {
                foreach (var cert in collection)
                {
                    cert.Dispose();
                }
            }
        }

        File.WriteAllBytes(opts.FilePath, bytes);
        // The .pfx carries the private key — restrict it to the service account on
        // every OS (SYSTEM+Administrators on Windows, 0600 on Unix).
        SecureFileSystem.HardenFile(opts.FilePath);

        logger.LogInformation("Wrote PFX ({Bytes} bytes) to {Path}", bytes.Length, opts.FilePath);
        return new StoreResult(opts.FilePath);
    }

    public async ValueTask<CertificateBundle?> RetrieveAsync(string identifier, StoreContext ctx, CancellationToken ct)
    {
        var opts = (PfxFileStoreOptions)ctx.Options;
        if (!File.Exists(opts.FilePath))
        {
            return null;
        }

        var password = await ResolvePasswordAsync(opts, ct);
        var bytes = File.ReadAllBytes(opts.FilePath);
        var collection = X509CertificateLoader.LoadPkcs12Collection(bytes, password);
        try
        {
            var leaf = collection[0];

            var sanExt = leaf.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
            var sans = sanExt?.EnumerateDnsNames().ToList() ?? new List<string>();

            return new CertificateBundle(
                CommonName: leaf.GetNameInfo(X509NameType.DnsName, forIssuer: false),
                SubjectAlternativeNames: sans,
                PfxBytes: bytes,
                PfxPassword: password ?? "",
                NotBefore: leaf.NotBefore,
                NotAfter: leaf.NotAfter,
                Thumbprint: leaf.Thumbprint);
        }
        finally
        {
            foreach (var cert in collection)
            {
                cert.Dispose();
            }
        }
    }

    public ValueTask DeleteAsync(string identifier, StoreContext ctx, CancellationToken ct)
    {
        // The reference StoreAsync returned is the path the cert was written to AT
        // THE TIME — delete that, not the currently configured path, so cleaning up
        // an old cert can never remove the file the current config points at.
        var opts = (PfxFileStoreOptions)ctx.Options;
        var path = string.IsNullOrWhiteSpace(identifier) ? opts.FilePath : identifier;
        if (File.Exists(path))
        {
            File.Delete(path);
        }
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// Resolves the PFX password: the named secret when <see cref="PfxFileStoreOptions.PasswordSecretName"/>
    /// is set, otherwise the deprecated literal <see cref="PfxFileStoreOptions.Password"/>.
    /// </summary>
    private async ValueTask<string?> ResolvePasswordAsync(PfxFileStoreOptions opts, CancellationToken ct)
    {
        if (!string.IsNullOrEmpty(opts.PasswordSecretName))
        {
            return await secrets.ResolveAsync(opts.PasswordSecretName, ct);
        }
        return opts.Password;
    }
}