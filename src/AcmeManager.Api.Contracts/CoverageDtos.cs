namespace AcmeManager.Api.Contracts;

/// <summary>
/// One certificate the agent's host is actually serving (an IIS binding, a
/// HAProxy <c>crt</c> source), reconciled against what renews it.
/// </summary>
/// <param name="Status">Managed, OtherTool, Unmanaged, MissingCert, or Unreadable.</param>
/// <param name="Thumbprint">SHA-1 hex of the served leaf, when readable — lets a console de-duplicate against its own probes.</param>
public sealed record CoverageEntryDto(
    string Path,
    IReadOnlyList<string> Domains,
    int? DaysUntilExpiry,
    string Status,
    string Detail,
    string? Issuer,
    string? Thumbprint,
    DateTimeOffset? NotAfter);

/// <summary>The agent's coverage report: what it serves, and by what it is renewed.</summary>
public sealed record CoverageReportDto(
    string? Error,
    IReadOnlyList<string> Sources,
    IReadOnlyList<CoverageEntryDto> Entries);

/// <summary>
/// A certificate issued by an internal Active Directory Certificate Services CA,
/// read from the CA database by an agent configured with <c>Coverage:AdcsCaConfig</c>.
/// </summary>
public sealed record AdcsCertificateDto(
    string SerialNumber,
    string? Thumbprint,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    string CommonName,
    string? Template,
    string? Requester);