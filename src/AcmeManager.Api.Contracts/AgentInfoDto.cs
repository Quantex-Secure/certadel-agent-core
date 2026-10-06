namespace AcmeManager.Api.Contracts;

/// <summary>
/// Authenticated self-description of an agent: the public discovery identity
/// (<c>/.well-known/acme-manager</c>) enriched with fleet-relevant counts. The
/// console shows these per enrolled agent and uses <see cref="NodeId"/> to
/// de-duplicate an agent discovered by both mDNS and direct probe.
/// </summary>
public sealed record AgentInfoDto(
    string Product,
    Guid NodeId,
    string Name,
    string Hostname,
    string Fqdn,
    string Version,
    string Os,
    int ApiPort,
    int RenewalCount,
    int CertificateCount,
    int ExpiringSoonCount,
    string ApiVersion);