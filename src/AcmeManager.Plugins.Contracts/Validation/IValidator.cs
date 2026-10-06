namespace AcmeManager.Plugins.Contracts.Validation;

public enum ChallengeType
{
    Http01,
    Dns01,
    TlsAlpn01,
}

/// <summary>
/// Handles an ACME challenge. The engine calls <see cref="PrepareAsync"/>
/// before asking the CA to validate, then <see cref="CleanupAsync"/> after —
/// always, even on failure. Implementations must be idempotent.
/// </summary>
public interface IValidator : IPlugin
{
    ChallengeType ChallengeType { get; }

    ValueTask PrepareAsync(ValidationContext ctx, CancellationToken ct);

    ValueTask CleanupAsync(ValidationContext ctx, CancellationToken ct);
}

/// <param name="Identifier">
/// For HTTP-01 / TLS-ALPN-01: the host being validated, e.g. "example.com".
/// For DNS-01: the record name to publish, e.g. "_acme-challenge.example.com".
/// </param>
/// <param name="Token">The raw ACME challenge token.</param>
/// <param name="KeyAuthorization">
/// HTTP-01: the file body to serve at /.well-known/acme-challenge/{token}.
/// DNS-01: the TXT record value (already base64url-encoded SHA-256).
/// TLS-ALPN-01: the value to embed in the validation certificate.
/// </param>
public sealed record ValidationContext(
    string Identifier,
    string Token,
    string KeyAuthorization,
    PluginOptions Options);