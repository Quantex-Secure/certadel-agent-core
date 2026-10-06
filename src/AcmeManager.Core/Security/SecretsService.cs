using System.Text;

using AcmeManager.Core.Storage;
using AcmeManager.Core.Storage.Entities;

using Microsoft.EntityFrameworkCore;

namespace AcmeManager.Core.Security;

/// <summary>
/// Programmatic management of the named-secret store used by plugins.
/// Phase 4's settings UI will sit on top of this; Phase 3.5 tests
/// use it directly to seed credentials.
/// </summary>
public sealed class SecretsService(AcmeManagerDbContext db, ISecretProtector protector)
{
    public async Task CreateOrReplaceAsync(string name, string value, CancellationToken ct = default)
    {
        var encrypted = protector.Protect(Encoding.UTF8.GetBytes(value));
        var existing = await db.Secrets.FirstOrDefaultAsync(s => s.Name == name, ct);
        if (existing is null)
        {
            db.Secrets.Add(new Secret { Name = name, EncryptedValue = encrypted });
        }
        else
        {
            existing.EncryptedValue = encrypted;
        }
        await db.SaveChangesAsync(ct);
    }

    public async Task<IReadOnlyList<string>> ListNamesAsync(CancellationToken ct = default) =>
        await db.Secrets.Select(s => s.Name).OrderBy(n => n).ToListAsync(ct);

    public async Task<bool> DeleteAsync(string name, CancellationToken ct = default)
    {
        var s = await db.Secrets.FirstOrDefaultAsync(x => x.Name == name, ct);
        if (s is null) return false;
        db.Secrets.Remove(s);
        await db.SaveChangesAsync(ct);
        return true;
    }
}