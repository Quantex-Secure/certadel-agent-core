namespace AcmeManager.Core.Acme.Orders;

/// <summary>
/// Successful output of <see cref="OrderRunner.RunAsync"/>. Contains the
/// issued chain (PEM), the matching private key (PEM), a PFX bundle ready
/// to hand to stores/installers, and the identifiers covered.
/// </summary>
public sealed record OrderResult(
    string CertificateChainPem,
    string PrivateKeyPem,
    byte[] Pfx,
    IReadOnlyList<string> Identifiers);