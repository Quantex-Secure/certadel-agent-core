using System.Security.Cryptography;

using AcmeManager.Api.Contracts;

namespace AcmeManager.Tests.Unit;

public sealed class NodeAttestationTests
{
    private static readonly Guid NodeId = Guid.Parse("11111111-1111-1111-1111-111111111111");
    private const string CertSha256 = "AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12CD34EF56AB12";

    private static (ECDsa Key, string Spki) NewKey()
    {
        var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        return (key, Convert.ToBase64String(key.ExportSubjectPublicKeyInfo()));
    }

    private static NodeAttestationDto Signed(ECDsa key, Guid nodeId, string nonce, string sha, DateTimeOffset at) =>
        new(nodeId, nonce, sha, at, NodeAttestation.Sign(key, nodeId, nonce, sha, at));

    [Fact]
    public void SignThenVerify_RoundTrips()
    {
        var (key, spki) = NewKey();
        using (key)
        {
            var nonce = NodeAttestation.NewNonce();
            var statement = Signed(key, NodeId, nonce, CertSha256, DateTimeOffset.UtcNow);

            Assert.True(NodeAttestation.Verify(spki, statement));
        }
    }

    [Fact]
    public void Verify_IsCaseInsensitiveOnTheThumbprint()
    {
        var (key, spki) = NewKey();
        using (key)
        {
            var nonce = NodeAttestation.NewNonce();
            var statement = Signed(key, NodeId, nonce, CertSha256.ToLowerInvariant(), DateTimeOffset.UtcNow);
            Assert.True(NodeAttestation.Verify(spki, statement with { EndpointCertSha256 = CertSha256 }));
        }
    }

    [Fact]
    public void Verify_FailsWhenAnyFieldIsTampered()
    {
        var (key, spki) = NewKey();
        using (key)
        {
            var nonce = NodeAttestation.NewNonce();
            var good = Signed(key, NodeId, nonce, CertSha256, DateTimeOffset.UtcNow);

            Assert.False(NodeAttestation.Verify(spki, good with { NodeId = Guid.NewGuid() }));
            Assert.False(NodeAttestation.Verify(spki, good with { Nonce = NodeAttestation.NewNonce() }));
            Assert.False(NodeAttestation.Verify(spki, good with { EndpointCertSha256 = new string('0', 64) }));
            Assert.False(NodeAttestation.Verify(spki, good with { SignedAt = good.SignedAt.AddSeconds(1) }));
        }
    }

    [Fact]
    public void Verify_FailsWithADifferentKey()
    {
        var (signer, _) = NewKey();
        var (_, otherSpki) = NewKey();
        using (signer)
        {
            var statement = Signed(signer, NodeId, NodeAttestation.NewNonce(), CertSha256, DateTimeOffset.UtcNow);
            Assert.False(NodeAttestation.Verify(otherSpki, statement));
        }
    }

    [Fact]
    public void Verify_ToleratesGarbageInput()
    {
        var statement = new NodeAttestationDto(NodeId, "n", CertSha256, DateTimeOffset.UtcNow, "not-base64!");
        Assert.False(NodeAttestation.Verify("also-not-a-key", statement));
        Assert.False(NodeAttestation.Verify(Convert.ToBase64String([1, 2, 3]), statement));
    }

    [Fact]
    public void Nonce_Validation()
    {
        Assert.True(NodeAttestation.IsValidNonce(NodeAttestation.NewNonce()));
        Assert.False(NodeAttestation.IsValidNonce(null));
        Assert.False(NodeAttestation.IsValidNonce(""));
        Assert.False(NodeAttestation.IsValidNonce("AAAA"));               // 3 bytes: too short
        Assert.False(NodeAttestation.IsValidNonce(new string('A', 120))); // 90 bytes: too long
        Assert.False(NodeAttestation.IsValidNonce("not base64url!!"));
    }
}