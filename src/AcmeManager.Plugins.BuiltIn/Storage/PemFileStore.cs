using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Storage;

using Microsoft.Extensions.Logging;

namespace AcmeManager.Plugins.BuiltIn.Storage;

public sealed record PemFileStoreOptions : PluginOptions
{
    /// <summary>
    /// Directory that will receive certbot-style PEM files:
    /// <c>cert.pem</c>, <c>chain.pem</c>, <c>fullchain.pem</c>, <c>privkey.pem</c>.
    /// </summary>
    public string DirectoryPath { get; init; } = "";

    /// <summary>
    /// Optional base name for the output files. Empty = the certbot names
    /// (<c>cert.pem</c> etc.). Set (e.g. <c>HAProxy</c>) to get
    /// <c>HAProxy-cert.pem</c>, <c>HAProxy-chain.pem</c>, <c>HAProxy-fullchain.pem</c>,
    /// <c>HAProxy-privkey.pem</c>.
    /// </summary>
    public string BaseName { get; init; } = "";
}

/// <summary>
/// Writes a certbot-compatible 4-file PEM layout — exactly what nginx, Apache,
/// HAProxy, and most Linux-native web servers reference in their config. The
/// private key file is chmod 0600 on Unix.
/// </summary>
public sealed class PemFileStore(ILogger<PemFileStore> logger) : IStore
{
    public PluginMetadata Metadata { get; } = new(
        Id: "store.pem",
        Name: "PEM bundle",
        Description: "Writes cert.pem / chain.pem / fullchain.pem / privkey.pem to a directory.",
        Category: PluginCategory.Store,
        Version: new Version(1, 0, 0));

    public ValueTask<StoreResult> StoreAsync(CertificateBundle bundle, StoreContext ctx, CancellationToken ct)
    {
        var opts = (PemFileStoreOptions)ctx.Options;
        if (string.IsNullOrWhiteSpace(opts.DirectoryPath))
        {
            throw new InvalidOperationException("PemFileStore: DirectoryPath is required");
        }

        Directory.CreateDirectory(opts.DirectoryPath);

        // Ephemeral + Exportable so the leaf's private key can be exported as PEM.
        // Default on Windows persists keys to CNG marked non-exportable, which
        // breaks the ExportPkcs8PrivateKeyPem() call below.
        var collection = X509CertificateLoader.LoadPkcs12Collection(
            bundle.PfxBytes,
            bundle.PfxPassword,
            X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
        try
        {
            var leaf = collection[0];
            var chain = collection.Skip(1).ToList();

            var certPath = Path.Combine(opts.DirectoryPath, FileName(opts.BaseName, "cert"));
            var chainPath = Path.Combine(opts.DirectoryPath, FileName(opts.BaseName, "chain"));
            var fullchainPath = Path.Combine(opts.DirectoryPath, FileName(opts.BaseName, "fullchain"));
            var privkeyPath = Path.Combine(opts.DirectoryPath, FileName(opts.BaseName, "privkey"));

            File.WriteAllText(certPath, leaf.ExportCertificatePem() + "\n");

            var chainPem = string.Concat(chain.Select(c => c.ExportCertificatePem() + "\n"));
            File.WriteAllText(chainPath, chainPem);

            File.WriteAllText(fullchainPath, leaf.ExportCertificatePem() + "\n" + chainPem);

            File.WriteAllText(privkeyPath, ExtractPrivateKeyPem(leaf));

            // Restrict the private key file to the service account on every OS
            // (SYSTEM+Administrators on Windows, 0600 on Unix) — not just Unix.
            SecureFileSystem.HardenFile(privkeyPath);

            logger.LogInformation(
                "Wrote PEM bundle to {Dir} ({ChainCount} intermediate cert(s))",
                opts.DirectoryPath, chain.Count);

            return ValueTask.FromResult(new StoreResult(opts.DirectoryPath));
        }
        finally
        {
            foreach (var cert in collection)
            {
                cert.Dispose();
            }
        }
    }

    public ValueTask<CertificateBundle?> RetrieveAsync(string identifier, StoreContext ctx, CancellationToken ct)
    {
        // The PEM layout drops keys/certs to known file names; no direct cert lookup
        // without re-importing. Phase 3 doesn't need this — return null and let the
        // caller fall through to "re-issue".
        return ValueTask.FromResult<CertificateBundle?>(null);
    }

    public ValueTask DeleteAsync(string identifier, StoreContext ctx, CancellationToken ct)
    {
        // The reference StoreAsync returned is the directory the cert was written
        // to AT THE TIME — clean that, not the currently configured directory, so
        // old-cert cleanup can't touch files the current config points at.
        var opts = (PemFileStoreOptions)ctx.Options;
        var directory = string.IsNullOrWhiteSpace(identifier) ? opts.DirectoryPath : identifier;
        foreach (var role in new[] { "cert", "chain", "fullchain", "privkey" })
        {
            var path = Path.Combine(directory, FileName(opts.BaseName, role));
            if (File.Exists(path)) File.Delete(path);
        }
        return ValueTask.CompletedTask;
    }

    /// <summary>certbot name when no base is set, else <c>&lt;base&gt;-&lt;role&gt;.pem</c>.</summary>
    private static string FileName(string baseName, string role) =>
        string.IsNullOrWhiteSpace(baseName) ? $"{role}.pem" : $"{baseName.Trim()}-{role}.pem";

    private static string ExtractPrivateKeyPem(X509Certificate2 cert)
    {
        if (cert.GetRSAPrivateKey() is { } rsa)
        {
            return rsa.ExportPkcs8PrivateKeyPem() + "\n";
        }
        if (cert.GetECDsaPrivateKey() is { } ec)
        {
            return ec.ExportPkcs8PrivateKeyPem() + "\n";
        }
        throw new InvalidOperationException("Leaf certificate has no supported private key (RSA or ECDSA)");
    }
}