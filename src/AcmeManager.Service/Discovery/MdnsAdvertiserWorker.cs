using AcmeManager.Core.Discovery;
using AcmeManager.Core.Storage;

using Makaretu.Dns;

using Microsoft.EntityFrameworkCore;

namespace AcmeManager.Service.Discovery;

/// <summary>
/// Advertises this node on the local network via mDNS / DNS-SD as
/// <c>_acme-manager._tcp</c>, so a management console can auto-discover it with
/// zero configuration. The TXT record carries the same non-sensitive identity
/// the HTTP discovery endpoint returns. mDNS is local-subnet only; cross-subnet
/// discovery is handled by the console probing the HTTP endpoint.
/// </summary>
public sealed class MdnsAdvertiserWorker(
    INodeInfoProvider nodeInfo,
    IDbContextFactory<AcmeManagerDbContext> dbFactory,
    IConfiguration configuration,
    ILogger<MdnsAdvertiserWorker> logger) : BackgroundService
{
    private const string ServiceName = "_acme-manager._tcp";

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!await DiscoveryEnabledAsync(stoppingToken))
        {
            logger.LogInformation("Network discovery (mDNS) is disabled by settings; not advertising.");
            return;
        }

        NodeInfo info;
        try
        {
            info = await nodeInfo.GetAsync(stoppingToken);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Network discovery: could not resolve node info; not advertising.");
            return;
        }

        ServiceDiscovery? discovery = null;
        ServiceProfile? profile = null;
        try
        {
            profile = new ServiceProfile(Sanitize(info.Name), ServiceName, (ushort)info.ApiPort);
            profile.AddProperty("product", info.Product);
            profile.AddProperty("id", info.NodeId.ToString());
            profile.AddProperty("name", info.Name);
            profile.AddProperty("fqdn", info.Fqdn);
            profile.AddProperty("version", info.Version);

            discovery = new ServiceDiscovery();
            discovery.Advertise(profile);
            discovery.Announce(profile);

            logger.LogInformation(
                "Network discovery: advertising {Service} as '{Instance}' (node {NodeId}) on :{Port}",
                ServiceName, info.Name, info.NodeId, info.ApiPort);

            // Hold the advertisement open until shutdown.
            await Task.Delay(Timeout.Infinite, stoppingToken);
        }
        catch (OperationCanceledException)
        {
            // Normal shutdown.
        }
        catch (Exception ex)
        {
            logger.LogWarning(
                ex,
                "Network discovery (mDNS) advertising failed; the HTTP discovery endpoint is unaffected.");
        }
        finally
        {
            try
            {
                if (discovery is not null && profile is not null)
                {
                    discovery.Unadvertise(profile);
                }
            }
            catch
            {
                // best effort on shutdown
            }
            discovery?.Dispose();
        }
    }

    private async Task<bool> DiscoveryEnabledAsync(CancellationToken ct)
    {
        var enabledByDefault = configuration.GetValue(DiscoverySettings.EnabledByDefaultConfigKey, defaultValue: true);
        try
        {
            await using var db = await dbFactory.CreateDbContextAsync(ct);
            var setting = await db.Settings.AsNoTracking()
                .FirstOrDefaultAsync(s => s.Key == DiscoverySettings.Key, ct);
            return DiscoverySettings.IsEnabled(setting?.Value, enabledByDefault);
        }
        catch (Exception ex)
        {
            logger.LogWarning(ex, "Network discovery: could not read '{Key}'; using the default ({Default}).",
                DiscoverySettings.Key, enabledByDefault);
            return enabledByDefault;
        }
    }

    private static string Sanitize(string name)
    {
        var trimmed = name?.Trim();
        return string.IsNullOrEmpty(trimmed) ? "acme-manager" : trimmed;
    }
}