using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Web.Administration;

namespace AcmeManager.Service.Coverage;

/// <summary>
/// The Windows counterpart to <see cref="ServedCertReader"/>: enumerates IIS HTTPS
/// bindings (the "what's served" demand side), resolves each binding's certificate
/// from the Windows store by thumbprint, and reports its leaf domains + expiry.
/// Deduped by thumbprint — a cert bound to several sites is one entry listing them.
/// </summary>
[SupportedOSPlatform("windows")]
internal static class WindowsServedCertReader
{
    public static (IReadOnlyList<ServedCertInfo> Served, IReadOnlyList<string> Sources) Read()
    {
        // thumbprint -> (binding descriptions, store name)
        var byThumb = new Dictionary<string, (List<string> Where, string Store)>(StringComparer.OrdinalIgnoreCase);
        try
        {
            using var server = new ServerManager();
            foreach (var site in server.Sites)
            {
                foreach (var binding in site.Bindings)
                {
                    if (!string.Equals(binding.Protocol, "https", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }
                    var hash = SafeHash(binding);
                    if (hash is null || hash.Length == 0)
                    {
                        continue;
                    }
                    var thumb = Convert.ToHexString(hash);
                    var store = string.IsNullOrEmpty(binding.CertificateStoreName) ? "My" : binding.CertificateStoreName;
                    var host = string.IsNullOrEmpty(binding.Host) ? "*" : binding.Host;
                    if (!byThumb.TryGetValue(thumb, out var entry))
                    {
                        entry = ([], store);
                        byThumb[thumb] = entry;
                    }
                    entry.Where.Add($"{site.Name} @ {host}");
                }
            }
        }
        catch (Exception ex)
        {
            return ([new ServedCertInfo("IIS", [], null, $"Could not read IIS bindings: {ex.Message}")], ["IIS"]);
        }

        var served = byThumb
            .Select(kv => ReadCert(kv.Key, kv.Value.Store, kv.Value.Where))
            .ToList();
        return (served, ["IIS HTTPS bindings"]);
    }

    private static byte[]? SafeHash(Binding binding)
    {
        try { return binding.CertificateHash; } catch { return null; }
    }

    private static ServedCertInfo ReadCert(string thumbprint, string storeName, List<string> where)
    {
        var label = $"IIS: {string.Join(", ", where)} [{storeName}]";
        var cert = FindByThumbprint(storeName, thumbprint);
        if (cert is null)
        {
            // Still carry the thumbprint — it can match an acme-manager-issued cert
            // even when the cert can't be read back from the store.
            return new ServedCertInfo(label, [], null,
                $"Bound cert {thumbprint[..Math.Min(12, thumbprint.Length)]} not found in {storeName} store", thumbprint);
        }
        return new ServedCertInfo(label, ServedCertReader.ExtractDomains(cert), new DateTimeOffset(cert.NotAfter),
            null, cert.Thumbprint, ServedCertReader.ExtractIssuer(cert));
    }

    private static X509Certificate2? FindByThumbprint(string storeName, string thumbprint)
    {
        foreach (var location in new[] { StoreLocation.LocalMachine, StoreLocation.CurrentUser })
        {
            try
            {
                using var store = new X509Store(storeName, location);
                store.Open(OpenFlags.ReadOnly);
                var found = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, validOnly: false);
                if (found.Count > 0)
                {
                    return found[0];
                }
            }
            catch
            {
                // store missing / no access — try the next location.
            }
        }
        return null;
    }
}