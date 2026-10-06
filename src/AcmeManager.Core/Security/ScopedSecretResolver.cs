using System.Text;

using AcmeManager.Core.Storage;
using AcmeManager.Plugins.Contracts;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AcmeManager.Core.Security;

/// <summary>
/// Singleton <see cref="ISecretResolver"/> that opens a fresh DI scope per
/// call so it can safely consume the scoped <c>AcmeManagerDbContext</c> from
/// inside singleton plugin instances (avoids the captive-dependency pitfall).
/// Updates the secret's <c>LastUsedAt</c> on each resolution.
/// </summary>
public sealed class ScopedSecretResolver(IServiceScopeFactory scopeFactory) : ISecretResolver
{
    public async Task<string> ResolveAsync(string name, CancellationToken ct)
    {
        await using var scope = scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AcmeManagerDbContext>();
        var protector = scope.ServiceProvider.GetRequiredService<ISecretProtector>();

        var secret = await db.Secrets.FirstOrDefaultAsync(s => s.Name == name, ct)
            ?? throw new KeyNotFoundException($"Secret '{name}' not found");

        secret.LastUsedAt = DateTimeOffset.UtcNow;
        await db.SaveChangesAsync(ct);

        return Encoding.UTF8.GetString(protector.Unprotect(secret.EncryptedValue));
    }
}