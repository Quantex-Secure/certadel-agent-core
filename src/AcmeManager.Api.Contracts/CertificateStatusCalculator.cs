namespace AcmeManager.Api.Contracts;

/// <summary>
/// Computes the shared <see cref="CertificateStatus"/> from primitive facts.
/// Lives in the contracts assembly so the agent (authoritative) and any client
/// derive status identically, and so it is trivially unit-testable without
/// touching storage entities.
/// </summary>
public static class CertificateStatusCalculator
{
    /// <param name="consecutiveFailures">
    /// Failed runs since the last success. Any value above zero on an enabled,
    /// unexpired renewal yields <see cref="CertificateStatus.Failing"/>.
    /// </param>
    public static CertificateStatus Compute(
        bool enabled,
        DateTimeOffset? latestNotAfter,
        int renewalWindowDays,
        DateTimeOffset now,
        int consecutiveFailures = 0)
    {
        if (!enabled)
        {
            return CertificateStatus.Disabled;
        }
        if (latestNotAfter is not null && latestNotAfter.Value <= now)
        {
            // Expired is the more urgent fact even when runs are also failing.
            return CertificateStatus.Expired;
        }
        if (consecutiveFailures > 0)
        {
            return CertificateStatus.Failing;
        }
        if (latestNotAfter is null)
        {
            return CertificateStatus.NeverIssued;
        }
        if (latestNotAfter.Value <= now.AddDays(renewalWindowDays))
        {
            return CertificateStatus.ExpiringSoon;
        }
        return CertificateStatus.Healthy;
    }
}