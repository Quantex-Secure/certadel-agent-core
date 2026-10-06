using System.Security.Cryptography.X509Certificates;

using AcmeManager.Core.Https;

using Serilog;

namespace AcmeManager.Service.Https;

/// <summary>
/// Supplies the certificate Kestrel serves on :9443 and hot-swaps it at runtime.
/// Starts from the self-signed bootstrap cert; once a renewal issues a cert for
/// this host (via <c>installer.acme-manager-endpoint</c>) that cert is applied to
/// new TLS connections immediately and persisted so it survives a restart.
/// </summary>
public sealed class EndpointCertificateProvider : IEndpointCertificateState
{
    private const string AcmeCertFileName = "https-9443-acme.pfx";

    private const X509KeyStorageFlags KeyFlags =
        X509KeyStorageFlags.MachineKeySet
        | X509KeyStorageFlags.PersistKeySet
        | X509KeyStorageFlags.Exportable;

    private readonly string _dataRoot;
    private readonly string _acmeCertPath;
    private volatile X509Certificate2 _current;

    public EndpointCertificateProvider(string dataRoot)
    {
        _dataRoot = dataRoot;
        _acmeCertPath = Path.Combine(dataRoot, AcmeCertFileName);
        _current = LoadInitial();
    }

    /// <summary>The certificate Kestrel should present right now.</summary>
    public X509Certificate2 Current => _current;

    /// <summary>True once an ACME-issued cert (not the self-signed bootstrap) is in use.</summary>
    public bool UsingIssuedCertificate { get; private set; }

    /// <inheritdoc />
    public string Subject => _current.Subject;

    /// <inheritdoc />
    public DateTimeOffset NotAfter => _current.NotAfter;

    /// <summary>
    /// Apply a freshly-issued PKCS#12 bundle (cert + chain + key) as the endpoint
    /// certificate. New TLS connections use it immediately; it is persisted so it
    /// survives restarts.
    /// </summary>
    public void ApplyPfx(byte[] pfxBytes, string? password)
    {
        // Re-export to a password-less PFX (retaining the chain) so reloads are stable.
        var collection = X509CertificateLoader.LoadPkcs12Collection(pfxBytes, password, KeyFlags);
        var normalized = collection.Export(X509ContentType.Pfx)
            ?? throw new InvalidOperationException("Endpoint certificate PFX re-export failed.");

        File.WriteAllBytes(_acmeCertPath, normalized);
        BootstrapHttps.Harden(_acmeCertPath);

        var leaf = LoadLeaf(_acmeCertPath);
        _ = Interlocked.Exchange(ref _current, leaf);
        UsingIssuedCertificate = true;
        // The previous cert is left for the GC — in-flight handshakes may still hold it.

        Log.Information(
            "HTTPS endpoint: now serving issued certificate {Subject} on :9443.",
            leaf.Subject);
    }

    /// <summary>The persisted issued PFX currently applied, or null while serving the bootstrap cert.</summary>
    public byte[]? ReadIssuedPfx() => File.Exists(_acmeCertPath) ? File.ReadAllBytes(_acmeCertPath) : null;

    /// <summary>Drops the issued certificate and serves the self-signed bootstrap cert again.</summary>
    public void RevertToBootstrap()
    {
        if (File.Exists(_acmeCertPath))
        {
            File.Delete(_acmeCertPath);
        }
        _ = Interlocked.Exchange(ref _current, BootstrapHttps.GetOrCreate(_dataRoot));
        UsingIssuedCertificate = false;
        Log.Warning("HTTPS endpoint: reverted to the self-signed bootstrap certificate on :9443.");
    }

    private X509Certificate2 LoadInitial()
    {
        if (File.Exists(_acmeCertPath))
        {
            try
            {
                var existing = LoadLeaf(_acmeCertPath);
                if (existing.NotAfter.ToUniversalTime() > DateTime.UtcNow)
                {
                    UsingIssuedCertificate = true;
                    return existing;
                }
                existing.Dispose();
            }
            catch (Exception ex)
            {
                Log.Warning(ex,
                    "HTTPS endpoint: issued cert {Path} is unreadable; using the self-signed bootstrap cert.",
                    _acmeCertPath);
            }
        }

        return BootstrapHttps.GetOrCreate(_dataRoot);
    }

    private static X509Certificate2 LoadLeaf(string path) =>
        X509CertificateLoader.LoadPkcs12(File.ReadAllBytes(path), password: null, KeyFlags);
}