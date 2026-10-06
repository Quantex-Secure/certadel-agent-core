namespace AcmeManager.Core.Acme;

public enum AcmeKeyAlgorithm
{
    Rsa2048,
    EcP256,
    EcP384,
}

/// <summary>
/// An ACME account key in PEM form. Always stored encrypted at rest via
/// <c>ISecretProtector</c>; this DTO is the plaintext shape in memory. The
/// generating algorithm is captured at creation time only — not carried as
/// metadata, since the PEM is sufficient to reconstruct the key.
/// </summary>
public sealed record AcmeAccountKey(string Pem);

public sealed record EabCredentials(string KeyId, string HmacKeyBase64Url);

/// <summary>
/// An ACME account at a specific CA. <see cref="KeyId"/> is null until the
/// account has been registered with the CA; after that it is the CA-assigned
/// account URL used to sign every subsequent request.
/// </summary>
public sealed record AcmeAccount(
    Guid LocalId,
    Uri DirectoryUrl,
    string ContactEmail,
    AcmeAccountKey Key,
    Uri? KeyId);