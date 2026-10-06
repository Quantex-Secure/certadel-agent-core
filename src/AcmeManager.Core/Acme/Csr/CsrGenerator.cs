using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AcmeManager.Core.Acme.Csr;

public sealed record CsrResult(byte[] CsrDer, string PrivateKeyPem);

/// <summary>
/// Generates a fresh keypair and PKCS#10 CSR with the given Common Name and
/// Subject Alternative Names. The CSR is what the ACME finalize call signs;
/// the private key is paired with the issued cert into a PFX downstream.
/// </summary>
public static class CsrGenerator
{
    public static CsrResult Generate(string commonName, IReadOnlyList<string> sans, AcmeKeyAlgorithm algorithm)
    {
        if (sans.Count == 0)
        {
            throw new ArgumentException("At least one SAN is required", nameof(sans));
        }

        var subject = new X500DistinguishedName($"CN={commonName}");

        var sanBuilder = new SubjectAlternativeNameBuilder();
        foreach (var san in sans)
        {
            sanBuilder.AddDnsName(san);
        }

        if (algorithm is AcmeKeyAlgorithm.EcP256 or AcmeKeyAlgorithm.EcP384)
        {
            var curve = algorithm == AcmeKeyAlgorithm.EcP256
                ? ECCurve.NamedCurves.nistP256
                : ECCurve.NamedCurves.nistP384;
            var hash = algorithm == AcmeKeyAlgorithm.EcP256
                ? HashAlgorithmName.SHA256
                : HashAlgorithmName.SHA384;

            using var ecdsa = ECDsa.Create(curve);
            var req = new CertificateRequest(subject, ecdsa, hash);
            req.CertificateExtensions.Add(sanBuilder.Build());

            return new CsrResult(req.CreateSigningRequest(), ecdsa.ExportPkcs8PrivateKeyPem());
        }

        using (var rsa = RSA.Create(2048))
        {
            var req = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            req.CertificateExtensions.Add(sanBuilder.Build());

            return new CsrResult(req.CreateSigningRequest(), rsa.ExportPkcs8PrivateKeyPem());
        }
    }
}