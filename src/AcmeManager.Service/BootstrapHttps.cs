using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using AcmeManager.Plugins.Contracts;

namespace AcmeManager.Service;

/// <summary>
/// Provides the TLS certificate Kestrel serves on :9443. On a freshly installed
/// server there is no ASP.NET dev cert, so the UI endpoint needs a certificate of
/// its own. This generates a self-signed certificate for the host on first run,
/// persists it (admin-only) under the data directory, and reuses it on restart.
/// It is intended as a bootstrap — once the service can issue certificates it can
/// replace this with an ACME-issued cert for its own FQDN.
/// </summary>
internal static class BootstrapHttps
{
    private const string PfxFileName = "https-9443.pfx";

    /// <summary>Returns the persisted bootstrap cert, generating it if missing or near expiry.</summary>
    public static X509Certificate2 GetOrCreate(string dataRoot)
    {
        Directory.CreateDirectory(dataRoot);
        var path = Path.Combine(dataRoot, PfxFileName);

        if (File.Exists(path))
        {
            try
            {
                var existing = Load(path);
                if (existing.NotAfter.ToUniversalTime() > DateTime.UtcNow.AddDays(30))
                {
                    return existing;
                }
                existing.Dispose();
            }
            catch
            {
                // Unreadable / corrupt — fall through and regenerate.
            }
        }

        using var generated = Generate();
        try
        {
            File.WriteAllBytes(path, generated.Export(X509ContentType.Pfx));
            Harden(path);
            // Reload so Kestrel uses the persisted key material.
            return Load(path);
        }
        catch
        {
            // Couldn't persist (e.g. read-only data dir) — run with the in-memory cert.
            return Generate();
        }
    }

    private static X509Certificate2 Load(string path) =>
        X509CertificateLoader.LoadPkcs12(
            File.ReadAllBytes(path),
            password: null,
            keyStorageFlags: X509KeyStorageFlags.MachineKeySet
                | X509KeyStorageFlags.PersistKeySet
                | X509KeyStorageFlags.Exportable);

    private static X509Certificate2 Generate()
    {
        var fqdn = ResolveFqdn();

        using var rsa = RSA.Create(2048);
        var request = new CertificateRequest(
            $"CN={fqdn}", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var san = new SubjectAlternativeNameBuilder();
        foreach (var name in DnsNames(fqdn))
        {
            san.AddDnsName(name);
        }
        san.AddIpAddress(IPAddress.Loopback);
        san.AddIpAddress(IPAddress.IPv6Loopback);
        request.CertificateExtensions.Add(san.Build());

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, critical: true));
        request.CertificateExtensions.Add(new X509KeyUsageExtension(
            X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, critical: true));
        request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
            new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") /* serverAuth */ }, critical: false));

        var now = DateTimeOffset.UtcNow;
        return request.CreateSelfSigned(now.AddDays(-1), now.AddYears(5));
    }

    private static string ResolveFqdn()
    {
        try
        {
            var host = Dns.GetHostName();
            var entry = Dns.GetHostEntry(host);
            return string.IsNullOrWhiteSpace(entry.HostName) ? host : entry.HostName;
        }
        catch
        {
            return Environment.MachineName;
        }
    }

    private static IEnumerable<string> DnsNames(string fqdn)
    {
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            fqdn,
            Environment.MachineName,
            "localhost",
        };
        return names.Where(n => !string.IsNullOrWhiteSpace(n));
    }

    /// <summary>Restricts the bootstrap cert file to SYSTEM + Administrators (Windows) / 0600 (Unix).</summary>
    internal static void Harden(string path) => SecureFileSystem.HardenFile(path);
}