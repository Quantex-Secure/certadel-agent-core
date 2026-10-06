namespace AcmeManager.Core.Discovery;

/// <summary>
/// Non-sensitive identity advertised for network discovery, so a central
/// management console can find and identify this node. Deliberately contains
/// nothing secret — no certificates, accounts, or secrets.
/// </summary>
public sealed record NodeInfo(
    string Product,
    Guid NodeId,
    string Name,
    string Hostname,
    string Fqdn,
    string Version,
    string Os,
    int ApiPort);

/// <summary>
/// Resolves this node's stable identity (persisted node id + friendly name) and
/// runtime facts (hostname, version, OS) used by the discovery endpoint and the
/// mDNS advertiser.
/// </summary>
public interface INodeInfoProvider
{
    Task<NodeInfo> GetAsync(CancellationToken ct = default);
}