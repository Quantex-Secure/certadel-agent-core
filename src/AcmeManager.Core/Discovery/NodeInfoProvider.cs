using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;

using AcmeManager.Core.Storage;
using AcmeManager.Core.Storage.Entities;

using Microsoft.EntityFrameworkCore;

namespace AcmeManager.Core.Discovery;

/// <summary>
/// Default <see cref="INodeInfoProvider"/>. The node id is generated once and
/// persisted in the settings table so it is stable across restarts and
/// upgrades; everything else is derived from the host at call time.
/// </summary>
public sealed class NodeInfoProvider(IDbContextFactory<AcmeManagerDbContext> dbFactory) : INodeInfoProvider
{
    /// <summary>The fixed port the web UI / API listens on.</summary>
    public const int ApiPort = 9443;

    internal const string NodeIdKey = "node.id";
    internal const string NodeNameKey = "node.name";

    private readonly SemaphoreSlim _gate = new(1, 1);
    private Guid? _cachedNodeId;

    public async Task<NodeInfo> GetAsync(CancellationToken ct = default)
    {
        await using var db = await dbFactory.CreateDbContextAsync(ct);

        var nodeId = await GetOrCreateNodeIdAsync(db, ct);

        var name = (await db.Settings.AsNoTracking()
            .FirstOrDefaultAsync(s => s.Key == NodeNameKey, ct))?.Value;
        if (string.IsNullOrWhiteSpace(name))
        {
            name = Environment.MachineName;
        }

        return new NodeInfo(
            Product: "acme-manager",
            NodeId: nodeId,
            Name: name,
            Hostname: Environment.MachineName,
            Fqdn: ResolveFqdn(),
            Version: ResolveVersion(),
            Os: ResolveOs(),
            ApiPort: ApiPort);
    }

    private async Task<Guid> GetOrCreateNodeIdAsync(AcmeManagerDbContext db, CancellationToken ct)
    {
        if (_cachedNodeId is { } cached)
        {
            return cached;
        }

        await _gate.WaitAsync(ct);
        try
        {
            if (_cachedNodeId is { } already)
            {
                return already;
            }

            var existing = await db.Settings.AsNoTracking()
                .FirstOrDefaultAsync(s => s.Key == NodeIdKey, ct);
            if (existing is not null && Guid.TryParse(existing.Value, out var parsed))
            {
                _cachedNodeId = parsed;
                return parsed;
            }

            var created = Guid.NewGuid();
            db.Settings.Add(new SettingsValue { Key = NodeIdKey, Value = created.ToString() });
            // Concurrent first-run writers: if another instance won the insert,
            // re-read the persisted value rather than failing.
            try
            {
                await db.SaveChangesAsync(ct);
                _cachedNodeId = created;
                return created;
            }
            catch (DbUpdateException)
            {
                var winner = await db.Settings.AsNoTracking()
                    .FirstOrDefaultAsync(s => s.Key == NodeIdKey, ct);
                if (winner is not null && Guid.TryParse(winner.Value, out var winnerId))
                {
                    _cachedNodeId = winnerId;
                    return winnerId;
                }
                throw;
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    private static string ResolveFqdn()
    {
        try
        {
            var host = Dns.GetHostName();
            var entry = Dns.GetHostEntry(host);
            return string.IsNullOrWhiteSpace(entry.HostName) ? host : entry.HostName;
        }
        catch
        {
            return Environment.MachineName;
        }
    }

    private static string ResolveVersion()
    {
        var informational = Assembly.GetEntryAssembly()
            ?.GetCustomAttribute<AssemblyInformationalVersionAttribute>()
            ?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(informational))
        {
            // Strip any "+<commit>" build metadata.
            var plus = informational.IndexOf('+');
            return plus >= 0 ? informational[..plus] : informational;
        }
        return Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "0.0.0";
    }

    private static string ResolveOs() =>
        OperatingSystem.IsWindows() ? "Windows"
        : OperatingSystem.IsLinux() ? "Linux"
        : OperatingSystem.IsMacOS() ? "macOS"
        : RuntimeInformation.OSDescription;
}