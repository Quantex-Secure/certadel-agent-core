namespace AcmeManager.Core.Acme;

/// <summary>
/// Minimal projection of the CA's RFC 8555 directory object — just the fields
/// the engine needs to make decisions. URLs are stored on the order/account
/// objects themselves once known.
/// </summary>
public sealed record AcmeDirectory(
    Uri DirectoryUrl,
    Uri? TermsOfServiceUrl,
    bool ExternalAccountRequired);