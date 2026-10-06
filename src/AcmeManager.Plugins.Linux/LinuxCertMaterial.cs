using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using AcmeManager.Plugins.Contracts.Storage;

namespace AcmeManager.Plugins.Linux;

/// <summary>
/// Turns a <see cref="CertificateBundle"/> (a PKCS#12) into the on-disk formats
/// Linux services consume: PEM (cert/chain/key) for HAProxy and Apache, and a
/// re-keyed PKCS#12 keystore for Tomcat. Pure and OS-agnostic so it can be unit
/// tested anywhere; mirrors the extraction used by the PEM file store.
/// </summary>
internal static class LinuxCertMaterial
{
    private static (X509Certificate2 Leaf, IReadOnlyList<X509Certificate2> Chain) Load(CertificateBundle bundle)
    {
        // Ephemeral + Exportable so the leaf's private key can be exported.
        var collection = X509CertificateLoader.LoadPkcs12Collection(
            bundle.PfxBytes,
            bundle.PfxPassword,
            X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
        return (collection[0], collection.Skip(1).ToList());
    }

    /// <summary>Leaf certificate followed by the intermediate chain, PEM-encoded.</summary>
    public static string FullChainPem(CertificateBundle bundle)
    {
        var (leaf, chain) = Load(bundle);
        return leaf.ExportCertificatePem() + "\n"
            + string.Concat(chain.Select(c => c.ExportCertificatePem() + "\n"));
    }

    /// <summary>
    /// The key, the leaf alone, and the intermediates (empty if none) as separate
    /// PEMs, from a single load whose certificate and key handles are disposed —
    /// the split form appliance APIs such as Synology DSM's import expect.
    /// </summary>
    public static (string PrivateKeyPem, string LeafPem, string IntermediatesPem) SplitPem(CertificateBundle bundle)
    {
        var collection = X509CertificateLoader.LoadPkcs12Collection(
            bundle.PfxBytes,
            bundle.PfxPassword,
            X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
        try
        {
            var leaf = collection[0];
            using AsymmetricAlgorithm key = (AsymmetricAlgorithm?)leaf.GetRSAPrivateKey()
                ?? leaf.GetECDsaPrivateKey()
                ?? throw new InvalidOperationException("Leaf certificate has no supported private key (RSA or ECDSA).");
            return (
                key.ExportPkcs8PrivateKeyPem() + "\n",
                leaf.ExportCertificatePem() + "\n",
                string.Concat(collection.Skip(1).Select(c => c.ExportCertificatePem() + "\n")));
        }
        finally
        {
            foreach (var cert in collection)
            {
                cert.Dispose();
            }
        }
    }

    /// <summary>The leaf's private key as a PKCS#8 PEM.</summary>
    public static string PrivateKeyPem(CertificateBundle bundle)
    {
        var (leaf, _) = Load(bundle);
        if (leaf.GetRSAPrivateKey() is { } rsa)
        {
            return rsa.ExportPkcs8PrivateKeyPem() + "\n";
        }
        if (leaf.GetECDsaPrivateKey() is { } ec)
        {
            return ec.ExportPkcs8PrivateKeyPem() + "\n";
        }
        throw new InvalidOperationException("Leaf certificate has no supported private key (RSA or ECDSA).");
    }

    /// <summary>The single combined PEM HAProxy's <c>crt</c> reads: fullchain then key.</summary>
    public static string HaProxyPem(CertificateBundle bundle) =>
        FullChainPem(bundle) + PrivateKeyPem(bundle);

    /// <summary>A PKCS#12 keystore re-exported under <paramref name="password"/> for Tomcat.</summary>
    public static byte[] Pkcs12(CertificateBundle bundle, string password)
    {
        var collection = X509CertificateLoader.LoadPkcs12Collection(
            bundle.PfxBytes,
            bundle.PfxPassword,
            X509KeyStorageFlags.EphemeralKeySet | X509KeyStorageFlags.Exportable);
        return collection.Export(X509ContentType.Pkcs12, password)
            ?? throw new InvalidOperationException("Failed to export PKCS#12 keystore.");
    }
}