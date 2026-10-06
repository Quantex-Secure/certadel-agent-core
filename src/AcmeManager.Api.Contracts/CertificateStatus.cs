using System.Text.Json.Serialization;

namespace AcmeManager.Api.Contracts;

/// <summary>
/// One shared health vocabulary for a managed certificate, computed by the
/// agent (never by the client) so every certificate source — today the
/// acme-manager agent, later AD CS / external CAs — reports status the same way
/// and the console grid never reimplements expiry math per source.
/// Serialized by name for cross-version tolerance.
/// </summary>
[JsonConverter(typeof(JsonStringEnumConverter<CertificateStatus>))]
public enum CertificateStatus
{
    /// <summary>Issued and comfortably outside its renewal window.</summary>
    Healthy,

    /// <summary>Issued but inside the renewal window (renews soon).</summary>
    ExpiringSoon,

    /// <summary>Latest issued certificate is past NotAfter.</summary>
    Expired,

    /// <summary>Enabled but no certificate has been issued yet.</summary>
    NeverIssued,

    /// <summary>Renewal is disabled; not being tracked for expiry.</summary>
    Disabled,

    /// <summary>
    /// Enabled and not yet expired, but the most recent run(s) failed — the
    /// agent is trying and not succeeding. Takes precedence over Healthy /
    /// ExpiringSoon / NeverIssued so a broken renewal is never shown as fine.
    /// </summary>
    Failing,
}