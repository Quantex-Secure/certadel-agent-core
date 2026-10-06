namespace AcmeManager.Api.Contracts;

/// <summary>
/// One row in the fleet inventory: a managed certificate (renewal) plus the
/// facts about its latest issued certificate. <see cref="RenewalId"/> keys the
/// per-certificate actions (renew/enable/disable/edit). Node identity is added
/// by the console when merging rows across agents, not carried here.
/// </summary>
/// <param name="ConsecutiveFailures">Failed runs since the last success (0 = last run succeeded or never ran).</param>
/// <param name="Warning">
/// Set when the last successful run ended with a warning — an installer that
/// bound nothing, so the certificate is stored but may not be served.
/// </param>
/// <param name="Verified">
/// True when the agent observed the latest certificate being served by every
/// endpoint its installers reported; null when nothing could be checked.
/// </param>
public sealed record CertificateSummaryDto(
    Guid RenewalId,
    string Name,
    bool Enabled,
    string AccountName,
    string? Subject,
    IReadOnlyList<string> Sans,
    DateTimeOffset? NotBefore,
    DateTimeOffset? NotAfter,
    DateTimeOffset? LastAttemptAt,
    DateTimeOffset? LastSuccessAt,
    CertificateStatus Status,
    string? LastRunStatus,
    string? Thumbprint,
    int ConsecutiveFailures = 0,
    string? Warning = null,
    bool? Verified = null);