using System.Text;

using AcmeManager.Core.Security;

namespace AcmeManager.Tests.Unit;

public sealed class SecretProtectorTests : IDisposable
{
    private readonly string _keyFile = Path.Combine(Path.GetTempPath(), $"acme-test-secret-{Guid.NewGuid():N}.key");

    public void Dispose()
    {
        if (File.Exists(_keyFile))
        {
            File.Delete(_keyFile);
        }
    }

    [Fact]
    public void AesGcm_RoundTrips_Plaintext()
    {
        var protector = new AesGcmFileSecretProtector(_keyFile);
        var plaintext = Encoding.UTF8.GetBytes("the rain in Spain");

        var ct = protector.Protect(plaintext);
        var pt = protector.Unprotect(ct);

        Assert.Equal(plaintext, pt);
        Assert.NotEqual(plaintext, ct);
    }

    [Fact]
    public void AesGcm_ProducesDifferentCiphertextEachCall()
    {
        var protector = new AesGcmFileSecretProtector(_keyFile);
        var plaintext = Encoding.UTF8.GetBytes("same plaintext");

        var c1 = protector.Protect(plaintext);
        var c2 = protector.Protect(plaintext);

        Assert.NotEqual(c1, c2);
    }

    [Fact]
    public void AesGcm_PersistsKeyAcrossInstances()
    {
        var protectorA = new AesGcmFileSecretProtector(_keyFile);
        var ciphertext = protectorA.Protect(Encoding.UTF8.GetBytes("persistent"));

        var protectorB = new AesGcmFileSecretProtector(_keyFile);
        var roundtripped = protectorB.Unprotect(ciphertext);

        Assert.Equal("persistent", Encoding.UTF8.GetString(roundtripped));
    }

    [Fact]
    public void AesGcm_TamperedCiphertext_Throws()
    {
        var protector = new AesGcmFileSecretProtector(_keyFile);
        var ct = protector.Protect(Encoding.UTF8.GetBytes("secret"));

        ct[^1] ^= 0xFF; // flip a bit in the tag

        Assert.ThrowsAny<System.Security.Cryptography.CryptographicException>(
            () => protector.Unprotect(ct));
    }

    [SkippableFact]
    public void Dpapi_RoundTrips_Plaintext()
    {
        Skip.IfNot(OperatingSystem.IsWindows(), "DPAPI is Windows-only");

#pragma warning disable CA1416 // SupportedOSPlatform — guarded by Skip.IfNot above
        var protector = new DpapiSecretProtector();
        var plaintext = Encoding.UTF8.GetBytes("windows-protected secret");
        var ct = protector.Protect(plaintext);
        var pt = protector.Unprotect(ct);
#pragma warning restore CA1416

        Assert.Equal(plaintext, pt);
        Assert.NotEqual(plaintext, ct);
    }
}