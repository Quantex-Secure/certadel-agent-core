using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using AcmeManager.Core.Acme;
using AcmeManager.Core.Acme.Csr;

namespace AcmeManager.Tests.Unit;

public sealed class CsrGeneratorTests
{
    [Theory]
    [InlineData(AcmeKeyAlgorithm.Rsa2048)]
    [InlineData(AcmeKeyAlgorithm.EcP256)]
    [InlineData(AcmeKeyAlgorithm.EcP384)]
    public void Generate_ProducesValidCsr_WithAllSans(AcmeKeyAlgorithm alg)
    {
        var sans = new[] { "example.com", "www.example.com", "api.example.com" };

        var result = CsrGenerator.Generate(commonName: sans[0], sans: sans, algorithm: alg);

        Assert.NotNull(result.CsrDer);
        Assert.NotEmpty(result.CsrDer);
        Assert.Contains("BEGIN PRIVATE KEY", result.PrivateKeyPem);

        var hash = alg == AcmeKeyAlgorithm.EcP384 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256;
        var loaded = CertificateRequest.LoadSigningRequest(
            result.CsrDer,
            hash,
            CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

        Assert.Equal($"CN={sans[0]}", loaded.SubjectName.Name);

        var sanExt = loaded.CertificateExtensions
            .OfType<X509SubjectAlternativeNameExtension>()
            .Single();

        var dnsNames = sanExt.EnumerateDnsNames().ToHashSet();
        foreach (var san in sans)
        {
            Assert.Contains(san, dnsNames);
        }
    }

    [Fact]
    public void Generate_EmptySans_Throws()
    {
        Assert.Throws<ArgumentException>(() =>
            CsrGenerator.Generate("example.com", [], AcmeKeyAlgorithm.EcP256));
    }
}