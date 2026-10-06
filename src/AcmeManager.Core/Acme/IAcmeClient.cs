namespace AcmeManager.Core.Acme;

/// <summary>
/// Provider-agnostic ACME v2 (RFC 8555) operations. The default implementation
/// (<c>CertesAcmeClient</c>) wraps the Certes library; alternative
/// implementations can be plugged in for testing or to swap libraries later.
/// </summary>
public interface IAcmeClient
{
    Task<AcmeDirectory> GetDirectoryAsync(Uri directoryUrl, CancellationToken ct);

    /// <summary>
    /// Register a new account with the CA. The returned account has
    /// <see cref="AcmeAccount.KeyId"/> populated with the CA-assigned account URL.
    /// </summary>
    Task<AcmeAccount> CreateAccountAsync(
        AcmeAccount unregistered,
        EabCredentials? eab,
        CancellationToken ct);

    Task<AcmeOrder> CreateOrderAsync(
        AcmeAccount account,
        IReadOnlyList<string> identifiers,
        CancellationToken ct);

    Task<AcmeOrder> RefreshOrderAsync(AcmeAccount account, AcmeOrder order, CancellationToken ct);

    Task<AcmeAuthorization> GetAuthorizationAsync(
        AcmeAccount account,
        Uri authorizationUrl,
        CancellationToken ct);

    /// <summary>
    /// Computes the key authorization for a challenge — token + "." +
    /// base64url(SHA256(JWK thumbprint of account key)). HTTP-01 serves this
    /// raw; DNS-01 publishes base64url(SHA256(this)) as the TXT value.
    /// </summary>
    string ComputeKeyAuthorization(AcmeAccount account, AcmeChallenge challenge);

    /// <summary>
    /// Computes the DNS-01 TXT record value — base64url(SHA256(keyAuthorization)).
    /// </summary>
    string ComputeDnsTxtValue(AcmeAccount account, AcmeChallenge challenge);

    /// <summary>Tells the CA to validate the challenge — caller must have published it first.</summary>
    Task<AcmeChallenge> SubmitChallengeAsync(
        AcmeAccount account,
        AcmeChallenge challenge,
        CancellationToken ct);

    Task<AcmeOrder> FinalizeOrderAsync(
        AcmeAccount account,
        AcmeOrder order,
        byte[] csrDer,
        CancellationToken ct);

    /// <summary>Downloads the issued certificate chain as PEM.</summary>
    Task<string> DownloadCertificateAsync(
        AcmeAccount account,
        AcmeOrder order,
        CancellationToken ct);
}