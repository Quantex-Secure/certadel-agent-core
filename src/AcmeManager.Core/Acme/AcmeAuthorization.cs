namespace AcmeManager.Core.Acme;

public enum AuthorizationStatus
{
    Pending,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
}

/// <summary>
/// Authorization for a single identifier within an order. Exposes the list of
/// challenges the CA will accept; the engine picks one (based on configured
/// validator) and runs it.
/// </summary>
public sealed record AcmeAuthorization(
    Uri Url,
    string Identifier,
    AuthorizationStatus Status,
    IReadOnlyList<AcmeChallenge> Challenges,
    DateTimeOffset? Expires);