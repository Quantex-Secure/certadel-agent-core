using System.Security.Cryptography.X509Certificates;

namespace AcmeManager.Service.Coverage;

/// <summary>A served certificate: where it's served from, its leaf domains, expiry,
/// and SHA-1 thumbprint (the definitive key for matching against acme-manager's
/// issued certs, regardless of how the renewal names its domains).</summary>
internal sealed record ServedCertInfo(
    string Path,
    IReadOnlyList<string> Domains,
    DateTimeOffset? NotAfter,
    string? Error,
    string? Thumbprint = null,
    string? Issuer = null);

/// <summary>
/// Reads the actual certificate files behind HAProxy's <c>crt</c> sources (a
/// directory loads every PEM in it; a file is one cert) and pulls the leaf's
/// subject + SAN names and expiry — "what's really being served, and until when".
/// </summary>
internal static class ServedCertReader
{
    private static readonly string[] CertExtensions = [".pem", ".crt", ".cer"];

    public static IReadOnlyList<ServedCertInfo> Read(IEnumerable<string> sources)
    {
        var result = new List<ServedCertInfo>();
        foreach (var source in sources)
        {
            if (Directory.Exists(source))
            {
                foreach (var file in Directory.GetFiles(source).Where(IsCertFile).OrderBy(f => f, StringComparer.Ordinal))
                {
                    result.Add(ReadFile(file));
                }
            }
            else if (File.Exists(source))
            {
                result.Add(ReadFile(source));
            }
            // A missing source is simply not served — skip it.
        }
        return result;
    }

    private static bool IsCertFile(string path) =>
        CertExtensions.Contains(Path.GetExtension(path), StringComparer.OrdinalIgnoreCase);

    private static ServedCertInfo ReadFile(string path)
    {
        try
        {
            // The leaf is the first certificate in the PEM (HAProxy combined PEMs put
            // cert first, then chain, then key).
            var cert = X509Certificate2.CreateFromPem(File.ReadAllText(path));
            return new ServedCertInfo(path, ExtractDomains(cert), new DateTimeOffset(cert.NotAfter), null, cert.Thumbprint, ExtractIssuer(cert));
        }
        catch (Exception ex)
        {
            return new ServedCertInfo(path, [], null, ex.Message);
        }
    }

    /// <summary>The signing CA, for "who issued this": the issuer's organisation
    /// (e.g. "Let's Encrypt") when present, else its CN (e.g. "R11"); "self-signed"
    /// when issuer == subject.</summary>
    internal static string ExtractIssuer(X509Certificate2 cert)
    {
        if (string.Equals(cert.Issuer, cert.Subject, StringComparison.Ordinal))
        {
            return "self-signed";
        }
        foreach (var part in cert.Issuer.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (part.StartsWith("O=", StringComparison.OrdinalIgnoreCase))
            {
                return part[2..].Trim('"');
            }
        }
        var cn = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: true);
        return string.IsNullOrEmpty(cn) ? cert.Issuer : cn;
    }

    internal static IReadOnlyList<string> ExtractDomains(X509Certificate2 cert)
    {
        var domains = new List<string>();
        var cn = cert.GetNameInfo(X509NameType.DnsName, forIssuer: false);
        if (!string.IsNullOrEmpty(cn))
        {
            domains.Add(cn);
        }
        var san = cert.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
        if (san is not null)
        {
            foreach (var name in san.EnumerateDnsNames())
            {
                if (!domains.Contains(name, StringComparer.OrdinalIgnoreCase))
                {
                    domains.Add(name);
                }
            }
        }
        return domains;
    }
}