using System.Text.Json;

using AcmeManager.Core.Engine;
using AcmeManager.Core.Plugins;
using AcmeManager.Core.Storage;
using AcmeManager.Core.Storage.Entities;
using AcmeManager.Plugins.BuiltIn.Storage;

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AcmeManager.Tests.Integration;

/// <summary>
/// CertificateCleanupService against a real SQLite store and the real PFX file
/// store plugin: renewal deletion and post-renew superseded-cert pruning.
/// </summary>
public sealed class CertificateCleanupTests : IAsyncLifetime
{
    private SqliteConnection? _conn;
    private ServiceProvider? _sp;
    private readonly List<string> _tempFiles = [];

    private sealed class ThrowingSecretResolver : AcmeManager.Plugins.Contracts.ISecretResolver
    {
        public Task<string> ResolveAsync(string name, CancellationToken ct) =>
            throw new KeyNotFoundException(name);
    }

    public async Task InitializeAsync()
    {
        _conn = new SqliteConnection("Filename=:memory:");
        await _conn.OpenAsync();

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(NullLoggerProvider.Instance));
        services.AddDbContext<AcmeManagerDbContext>(o => o.UseSqlite(_conn));
        services.AddScoped<CertificateCleanupService>();
        // These renewals don't use a secret-backed PFX password, so a throwing stub
        // satisfies PfxFileStore's ISecretResolver dependency without a real store.
        services.AddSingleton<AcmeManager.Plugins.Contracts.ISecretResolver>(new ThrowingSecretResolver());
        services.AddPluginCatalog(c => c.AddStore<PfxFileStore, PfxFileStoreOptions>("store.pfx"));
        _sp = services.BuildServiceProvider();

        await using var scope = _sp.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AcmeManagerDbContext>();
        await db.Database.EnsureCreatedAsync();
    }

    public Task DisposeAsync()
    {
        _sp?.Dispose();
        _conn?.Dispose();
        foreach (var file in _tempFiles.Where(File.Exists))
        {
            File.Delete(file);
        }
        return Task.CompletedTask;
    }

    [Fact]
    public async Task DeleteRenewal_RemovesCertsAndStoreFiles_AndKeepsHistory()
    {
        var pfxPath = TempFile();
        await File.WriteAllBytesAsync(pfxPath, [1, 2, 3]);
        var (renewalId, _) = await SeedRenewalAsync(pfxPath, certs:
            [("THUMB-A", pfxPath)]);
        await SeedHistoryAsync(renewalId);

        bool deleted;
        await using (var scope = _sp!.CreateAsyncScope())
        {
            var cleanup = scope.ServiceProvider.GetRequiredService<CertificateCleanupService>();
            deleted = await cleanup.DeleteRenewalAsync(renewalId, default);
        }

        Assert.True(deleted);
        Assert.False(File.Exists(pfxPath));
        await using var verify = _sp!.CreateAsyncScope();
        var db = verify.ServiceProvider.GetRequiredService<AcmeManagerDbContext>();
        Assert.False(await db.Renewals.AnyAsync(r => r.Id == renewalId));
        Assert.False(await db.Certificates.AnyAsync(c => c.RenewalId == renewalId));
        var history = await db.History.AsNoTracking().ToListAsync();
        var entry = Assert.Single(history);
        Assert.Null(entry.RenewalId); // audit trail survives with a nulled FK
    }

    [Fact]
    public async Task DeleteRenewal_ReturnsFalse_WhenMissing()
    {
        await using var scope = _sp!.CreateAsyncScope();
        var cleanup = scope.ServiceProvider.GetRequiredService<CertificateCleanupService>();

        Assert.False(await cleanup.DeleteRenewalAsync(Guid.NewGuid(), default));
    }

    [Fact]
    public async Task RemoveSuperseded_DeletesOldFileAndRow_KeepsNewCert()
    {
        // Old cert was written to path A; the config later changed, so the new
        // cert lives at path B. Pruning must delete A and never touch B.
        var oldPath = TempFile();
        var newPath = TempFile();
        await File.WriteAllBytesAsync(oldPath, [1]);
        await File.WriteAllBytesAsync(newPath, [2]);
        var (renewalId, _) = await SeedRenewalAsync(newPath, certs:
            [("THUMB-OLD", oldPath), ("THUMB-NEW", newPath)]);

        int pruned;
        await using (var scope = _sp!.CreateAsyncScope())
        {
            var cleanup = scope.ServiceProvider.GetRequiredService<CertificateCleanupService>();
            pruned = await cleanup.RemoveSupersededAsync(renewalId, "THUMB-NEW", default);
        }

        Assert.Equal(1, pruned);
        Assert.False(File.Exists(oldPath));
        Assert.True(File.Exists(newPath));
        await using var verify = _sp!.CreateAsyncScope();
        var db = verify.ServiceProvider.GetRequiredService<AcmeManagerDbContext>();
        var remaining = Assert.Single(await db.Certificates.Where(c => c.RenewalId == renewalId).ToListAsync());
        Assert.Equal("THUMB-NEW", remaining.Thumbprint);
    }

    [Fact]
    public async Task RemoveSuperseded_NeverDeletesAReferenceTheKeptCertUses()
    {
        // The PFX store overwrites in place, so old and new rows share one path.
        var sharedPath = TempFile();
        await File.WriteAllBytesAsync(sharedPath, [9]);
        var (renewalId, _) = await SeedRenewalAsync(sharedPath, certs:
            [("THUMB-OLD", sharedPath), ("THUMB-NEW", sharedPath)]);

        int pruned;
        await using (var scope = _sp!.CreateAsyncScope())
        {
            var cleanup = scope.ServiceProvider.GetRequiredService<CertificateCleanupService>();
            pruned = await cleanup.RemoveSupersededAsync(renewalId, "THUMB-NEW", default);
        }

        Assert.Equal(1, pruned);
        Assert.True(File.Exists(sharedPath)); // the new cert's file must survive
    }

    private string TempFile()
    {
        var path = Path.Combine(Path.GetTempPath(), $"acme-cleanup-{Guid.NewGuid():N}.pfx");
        _tempFiles.Add(path);
        return path;
    }

    private async Task<(Guid RenewalId, Guid AccountId)> SeedRenewalAsync(
        string configuredPfxPath,
        IReadOnlyList<(string Thumbprint, string PfxReference)> certs)
    {
        await using var scope = _sp!.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AcmeManagerDbContext>();
        var catalog = scope.ServiceProvider.GetRequiredService<PluginCatalog>();

        var account = new Account { Name = "test", DirectoryUrl = "https://ca.test/dir" };
        db.Accounts.Add(account);

        var renewal = new Renewal
        {
            Name = $"cleanup-test-{Guid.NewGuid():N}",
            AccountId = account.Id,
            SourceJson = """{"pluginId":"source.manual","options":{}}""",
            ValidationJson = """{"pluginId":"validation.http-01.manual","options":{}}""",
            StoresJson = PluginStepSerializer.SerializeList(
                [("store.pfx", new PfxFileStoreOptions { FilePath = configuredPfxPath })],
                catalog),
        };
        db.Renewals.Add(renewal);

        foreach (var (thumbprint, reference) in certs)
        {
            db.Certificates.Add(new Certificate
            {
                RenewalId = renewal.Id,
                Thumbprint = thumbprint,
                Subject = "CN=cleanup.test",
                NotBefore = DateTimeOffset.UtcNow.AddDays(-1),
                NotAfter = DateTimeOffset.UtcNow.AddDays(89),
                StoreReferencesJson = JsonSerializer.Serialize(
                    new Dictionary<string, string> { ["store.pfx"] = reference }),
            });
        }

        await db.SaveChangesAsync();
        return (renewal.Id, account.Id);
    }

    private async Task SeedHistoryAsync(Guid renewalId)
    {
        await using var scope = _sp!.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AcmeManagerDbContext>();
        db.History.Add(new HistoryEntry
        {
            RenewalId = renewalId,
            At = DateTimeOffset.UtcNow,
            Status = HistoryStatus.Success,
            Message = "seeded",
        });
        await db.SaveChangesAsync();
    }
}