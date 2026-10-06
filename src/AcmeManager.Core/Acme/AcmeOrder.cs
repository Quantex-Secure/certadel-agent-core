namespace AcmeManager.Core.Acme;

public enum OrderStatus
{
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

/// <summary>
/// An ACME order — covers a set of identifiers (DNS names) for a single
/// certificate. The order moves through OrderStatus as the engine resolves
/// authorizations and finalizes the CSR.
/// </summary>
public sealed record AcmeOrder(
    Uri Url,
    OrderStatus Status,
    IReadOnlyList<string> Identifiers,
    IReadOnlyList<Uri> AuthorizationUrls,
    Uri FinalizeUrl,
    Uri? CertificateUrl,
    DateTimeOffset? Expires);