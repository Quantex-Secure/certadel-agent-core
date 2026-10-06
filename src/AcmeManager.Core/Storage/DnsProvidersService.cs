using AcmeManager.Core.Storage.Entities;

using Microsoft.EntityFrameworkCore;

namespace AcmeManager.Core.Storage;

/// <summary>
/// CRUD for DNS provider profiles. Names are unique; the underlying plugin
/// id + options blob are validated by the caller before persisting (the UI
/// uses <c>PluginCatalog.SerializeOptions</c> to produce canonical JSON).
/// </summary>
public sealed class DnsProvidersService(AcmeManagerDbContext db)
{
    public async Task<IReadOnlyList<DnsProvider>> ListAsync(CancellationToken ct = default) =>
        await db.DnsProviders.AsNoTracking().OrderBy(p => p.Name).ToListAsync(ct);

    public async Task<DnsProvider?> GetAsync(Guid id, CancellationToken ct = default) =>
        await db.DnsProviders.AsNoTracking().FirstOrDefaultAsync(p => p.Id == id, ct);

    public async Task<Guid> CreateAsync(string name, string pluginId, string optionsJson, CancellationToken ct = default)
    {
        var p = new DnsProvider
        {
            Name = name,
            PluginId = pluginId,
            OptionsJson = optionsJson,
            CreatedAt = DateTimeOffset.UtcNow,
            UpdatedAt = DateTimeOffset.UtcNow,
        };
        db.DnsProviders.Add(p);
        await db.SaveChangesAsync(ct);
        return p.Id;
    }

    public async Task UpdateAsync(Guid id, string name, string pluginId, string optionsJson, CancellationToken ct = default)
    {
        var existing = await db.DnsProviders.FirstAsync(p => p.Id == id, ct);
        existing.Name = name;
        existing.PluginId = pluginId;
        existing.OptionsJson = optionsJson;
        existing.UpdatedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);
    }

    public async Task<bool> DeleteAsync(Guid id, CancellationToken ct = default)
    {
        var existing = await db.DnsProviders.FirstOrDefaultAsync(p => p.Id == id, ct);
        if (existing is null) return false;
        db.DnsProviders.Remove(existing);
        await db.SaveChangesAsync(ct);
        return true;
    }
}