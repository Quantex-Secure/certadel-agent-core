namespace AcmeManager.Core.Https;

/// <summary>
/// Read-only view of the certificate the management UI is currently serving on
/// :9443, surfaced so the UI can show whether it's still the self-signed
/// bootstrap cert or an ACME-issued one. Implemented in the host (Service) by
/// the live endpoint certificate provider.
/// </summary>
public interface IEndpointCertificateState
{
    /// <summary>Subject (e.g. <c>CN=host.example.com</c>) of the cert being served.</summary>
    string Subject { get; }

    /// <summary>Expiry of the cert being served.</summary>
    DateTimeOffset NotAfter { get; }

    /// <summary>True once an ACME-issued cert (not the self-signed bootstrap) is in use.</summary>
    bool UsingIssuedCertificate { get; }
}