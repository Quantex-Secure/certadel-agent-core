using System.Security.Cryptography.X509Certificates;

using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Storage;

using Microsoft.Extensions.Logging;

namespace AcmeManager.Plugins.BuiltIn.Storage;

public sealed record WindowsCertStoreOptions : PluginOptions
{
    public StoreLocation Location { get; init; } = StoreLocation.LocalMachine;

    /// <summary>
    /// Windows store name (required — pick it deliberately; My and WebHosting behave
    /// very differently for IIS). A free-form string (not the <c>StoreName</c> enum) so
    /// IIS's centralized SSL store <c>WebHosting</c> — what win-acme uses for IIS
    /// bindings, and which the enum cannot express — and other custom stores work.
    /// Common values: <c>My</c> (Personal), <c>WebHosting</c>, <c>Root</c>. UIs
    /// render this as a picker of the host's stores.
    /// </summary>
    [CertStoreReference]
    [RequiredOption]
    public string StoreName { get; init; } = "";

    /// <summary>
    /// Friendly Name to stamp on the certificate in the store (shown in certlm /
    /// the IIS cert picker). Empty = use the renewal name carried on the bundle.
    /// </summary>
    public string FriendlyName { get; init; } = "";
}

/// <summary>
/// Installs the issued cert into a Windows certificate store (default:
/// LocalMachine\My) so IIS, RDS, Exchange, Schannel, and friends can find
/// it by thumbprint. The thumbprint is returned as the store reference so
/// downstream installers (e.g. IisInstaller) can wire the binding to it.
///
/// <see cref="ICapability"/> reports unavailable on non-Windows hosts —
/// X509Store technically works there but no Windows-aware consumer is.
/// </summary>
public sealed class WindowsCertStore(ILogger<WindowsCertStore> logger) : IStore, ICapability
{
    public PluginMetadata Metadata { get; } = new(
        Id: "store.winstore",
        Name: "Windows certificate store",
        Description: "Installs the cert into a Windows certificate store; returns its thumbprint.",
        Category: PluginCategory.Store,
        Version: new Version(1, 0, 0));

    public ValueTask<CapabilityResult> CheckAsync(CancellationToken ct) =>
        ValueTask.FromResult(OperatingSystem.IsWindows()
            ? CapabilityResult.Yes
            : CapabilityResult.No("Windows certificate store is Windows-only"));

    public ValueTask<StoreResult> StoreAsync(CertificateBundle bundle, StoreContext ctx, CancellationToken ct)
    {
        var opts = (WindowsCertStoreOptions)ctx.Options;
        if (string.IsNullOrWhiteSpace(opts.StoreName))
        {
            throw new InvalidOperationException(
                "WindowsCertStore: StoreName is required (e.g. 'My' or 'WebHosting'). Set the certificate store on this renewal.");
        }

        // Disposed at method end (after the thumbprint is read for the result); the
        // store keeps its own persisted copy, so releasing this handle is safe.
        using var cert = X509CertificateLoader.LoadPkcs12(
            bundle.PfxBytes,
            bundle.PfxPassword,
            X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);

        // FriendlyName is a Windows-only X509 property; this store only runs on
        // Windows (capability-gated), but guard so non-Windows test hosts don't throw.
        if (OperatingSystem.IsWindows())
        {
            var friendlyName = ResolveFriendlyName(opts, bundle);
            if (friendlyName.Length > 0)
            {
                cert.FriendlyName = friendlyName;
            }
        }

        using var store = new X509Store(opts.StoreName, opts.Location);
        store.Open(OpenFlags.ReadWrite);

        // Add the new cert FIRST, then remove old same-subject ones. The reverse
        // order is non-atomic: if Add throws after the removals, the store is left
        // with no cert for the site at all.
        store.Add(cert);

        // Remove prior certs for the SAME subject — matched EXACTLY. Do NOT use
        // X509FindType.FindBySubjectName: it's a substring match, so renewing
        // "apples.example.com" would delete the unrelated "fallingapples.example.com"
        // (and an apex "example.com" renewal would wipe every subdomain's cert).
        var subjectName = cert.GetNameInfo(X509NameType.DnsName, forIssuer: false);
        if (!string.IsNullOrEmpty(subjectName))
        {
            foreach (var old in store.Certificates.OfType<X509Certificate2>().ToArray())
            {
                using (old)
                {
                    if (!string.Equals(old.Thumbprint, cert.Thumbprint, StringComparison.OrdinalIgnoreCase)
                        && string.Equals(old.GetNameInfo(X509NameType.DnsName, forIssuer: false), subjectName, StringComparison.OrdinalIgnoreCase))
                    {
                        store.Remove(old);
                    }
                }
            }
        }

        logger.LogInformation(
            "Installed cert {Thumbprint} into {Location}\\{StoreName}",
            cert.Thumbprint, opts.Location, opts.StoreName);

        return ValueTask.FromResult(new StoreResult(cert.Thumbprint));
    }

    /// <summary>The Friendly Name to stamp: the explicit option if set, else the
    /// renewal name carried on the bundle, else empty (leave unnamed).</summary>
    internal static string ResolveFriendlyName(WindowsCertStoreOptions opts, CertificateBundle bundle) =>
        !string.IsNullOrWhiteSpace(opts.FriendlyName) ? opts.FriendlyName.Trim()
        : !string.IsNullOrWhiteSpace(bundle.FriendlyName) ? bundle.FriendlyName.Trim()
        : "";

    public ValueTask<CertificateBundle?> RetrieveAsync(string identifier, StoreContext ctx, CancellationToken ct)
    {
        var opts = (WindowsCertStoreOptions)ctx.Options;
        using var store = new X509Store(opts.StoreName, opts.Location);
        store.Open(OpenFlags.ReadOnly);

        var found = store.Certificates.Find(X509FindType.FindByThumbprint, identifier, validOnly: false);
        if (found.Count == 0)
        {
            return ValueTask.FromResult<CertificateBundle?>(null);
        }

        try
        {
            var cert = found[0];
            var sanExt = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
            var sans = sanExt?.EnumerateDnsNames().ToList() ?? new List<string>();
            var pfx = cert.Export(X509ContentType.Pfx);

            return ValueTask.FromResult<CertificateBundle?>(new CertificateBundle(
                CommonName: cert.GetNameInfo(X509NameType.DnsName, forIssuer: false),
                SubjectAlternativeNames: sans,
                PfxBytes: pfx,
                PfxPassword: string.Empty,
                NotBefore: cert.NotBefore,
                NotAfter: cert.NotAfter,
                Thumbprint: cert.Thumbprint));
        }
        finally
        {
            foreach (var c in found.OfType<X509Certificate2>())
            {
                c.Dispose();
            }
        }
    }

    public ValueTask DeleteAsync(string identifier, StoreContext ctx, CancellationToken ct)
    {
        var opts = (WindowsCertStoreOptions)ctx.Options;
        using var store = new X509Store(opts.StoreName, opts.Location);
        store.Open(OpenFlags.ReadWrite);

        var found = store.Certificates.Find(X509FindType.FindByThumbprint, identifier, validOnly: false);
        foreach (var cert in found.OfType<X509Certificate2>())
        {
            using (cert)
            {
                store.Remove(cert);
            }
        }
        return ValueTask.CompletedTask;
    }
}