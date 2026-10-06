using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;

namespace AcmeManager.Api.Contracts;

/// <summary>
/// An agent's signed proof of identity, served anonymously at
/// <see cref="NodeAttestation.Path"/>. The console uses it to decide whether a
/// changed endpoint certificate belongs to the agent it enrolled: the statement
/// binds the agent's stable node id, the console's fresh nonce, and the SHA-256
/// thumbprint of the certificate the agent is serving, all signed by the
/// agent's long-lived node identity key (whose public half was captured at
/// enrollment). A NodeId alone proves nothing — it is public — so this is what
/// stands between "the cert rotated" and "someone is on the path".
/// </summary>
/// <param name="Nonce">The caller's nonce, echoed back (replay protection).</param>
/// <param name="EndpointCertSha256">Hex SHA-256 thumbprint of the certificate the agent is serving.</param>
/// <param name="Signature">Base64 ECDSA P-256 / SHA-256 signature (IEEE P1363) over <see cref="NodeAttestation.BuildMessage"/>.</param>
public sealed record NodeAttestationDto(
    Guid NodeId,
    string Nonce,
    string EndpointCertSha256,
    DateTimeOffset SignedAt,
    string Signature);

/// <summary>
/// The attestation wire format, shared by agent (signer) and console (verifier)
/// so both build byte-identical messages.
/// </summary>
public static class NodeAttestation
{
    public const string Purpose = "acme-manager-attest-v1";

    public const string Path = "/.well-known/acme-manager/attest";

    private const int MinNonceBytes = 16;
    private const int MaxNonceBytes = 64;

    /// <summary>32 random bytes, base64url.</summary>
    public static string NewNonce() => Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));

    /// <summary>Base64url, decoding to 16–64 bytes.</summary>
    public static bool IsValidNonce(string? nonce)
    {
        if (string.IsNullOrEmpty(nonce) || nonce.Length > 128)
        {
            return false;
        }
        try
        {
            var length = Base64Url.DecodeFromChars(nonce).Length;
            return length is >= MinNonceBytes and <= MaxNonceBytes;
        }
        catch (FormatException)
        {
            return false;
        }
    }

    /// <summary>The exact bytes that are signed.</summary>
    public static byte[] BuildMessage(Guid nodeId, string nonce, string endpointCertSha256, DateTimeOffset signedAt) =>
        Encoding.UTF8.GetBytes(string.Join(
            '\n',
            Purpose,
            nodeId.ToString("D"),
            nonce,
            endpointCertSha256.ToUpperInvariant(),
            signedAt.ToUniversalTime().ToString("O")));

    /// <summary>Signs with the node identity key; returns the base64 signature.</summary>
    public static string Sign(ECDsa nodeKey, Guid nodeId, string nonce, string endpointCertSha256, DateTimeOffset signedAt) =>
        Convert.ToBase64String(nodeKey.SignData(
            BuildMessage(nodeId, nonce, endpointCertSha256, signedAt),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

    /// <summary>
    /// Verifies the signature against a base64 SubjectPublicKeyInfo captured at
    /// enrollment. Any malformed input is simply "not verified".
    /// </summary>
    public static bool Verify(string publicKeySpkiBase64, NodeAttestationDto attestation)
    {
        try
        {
            using var key = ECDsa.Create();
            key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(publicKeySpkiBase64), out _);
            return key.VerifyData(
                BuildMessage(attestation.NodeId, attestation.Nonce, attestation.EndpointCertSha256, attestation.SignedAt),
                Convert.FromBase64String(attestation.Signature),
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException or ArgumentException)
        {
            return false;
        }
    }
}