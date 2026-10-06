using AcmeManager.Core.Security;
using AcmeManager.Core.Storage;
using AcmeManager.Plugins.Contracts;

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace AcmeManager.Tests.Unit;

public sealed class SecretResolverTests : IAsyncLifetime
{
    private SqliteConnection _conn = null!;
    private string _keyFile = null!;
    private ServiceProvider _sp = null!;

    public async Task InitializeAsync()
    {
        _conn = new SqliteConnection("Filename=:memory:");
        await _conn.OpenAsync();
        _keyFile = Path.Combine(Path.GetTempPath(), $"acme-resolver-{Guid.NewGuid():N}.key");

        var services = new ServiceCollection();
        services.AddDbContext<AcmeManagerDbContext>(o => o.UseSqlite(_conn));
        services.AddSingleton<ISecretProtector>(new AesGcmFileSecretProtector(_keyFile));
        services.AddScoped<SecretsService>();
        services.AddSingleton<ISecretResolver, ScopedSecretResolver>();

        _sp = services.BuildServiceProvider();

        await using var scope = _sp.CreateAsyncScope();
        await scope.ServiceProvider.GetRequiredService<AcmeManagerDbContext>().Database.EnsureCreatedAsync();
    }

    public Task DisposeAsync()
    {
        _sp.Dispose();
        _conn.Dispose();
        if (File.Exists(_keyFile)) File.Delete(_keyFile);
        return Task.CompletedTask;
    }

    [Fact]
    public async Task Resolver_RoundTrips_StoredSecret()
    {
        await using (var scope = _sp.CreateAsyncScope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<SecretsService>();
            await svc.CreateOrReplaceAsync("cloudflare-token", "super-secret-token-abc123");
        }

        var resolver = _sp.GetRequiredService<ISecretResolver>();
        var value = await resolver.ResolveAsync("cloudflare-token", default);

        Assert.Equal("super-secret-token-abc123", value);
    }

    [Fact]
    public async Task Resolver_ThrowsKeyNotFound_ForMissingName()
    {
        var resolver = _sp.GetRequiredService<ISecretResolver>();

        await Assert.ThrowsAsync<KeyNotFoundException>(
            async () => await resolver.ResolveAsync("nope", default));
    }

    [Fact]
    public async Task Resolver_UpdatesLastUsedAt()
    {
        await using (var scope = _sp.CreateAsyncScope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<SecretsService>();
            await svc.CreateOrReplaceAsync("tracked", "v");
        }

        var before = DateTimeOffset.UtcNow;
        await Task.Delay(20);
        await _sp.GetRequiredService<ISecretResolver>().ResolveAsync("tracked", default);

        await using var checkScope = _sp.CreateAsyncScope();
        var db = checkScope.ServiceProvider.GetRequiredService<AcmeManagerDbContext>();
        var s = await db.Secrets.SingleAsync(x => x.Name == "tracked");
        Assert.NotNull(s.LastUsedAt);
        Assert.True(s.LastUsedAt!.Value >= before);
    }

    [Fact]
    public async Task SecretsService_Delete_RemovesSecret()
    {
        await using (var scope = _sp.CreateAsyncScope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<SecretsService>();
            await svc.CreateOrReplaceAsync("ephemeral", "x");
            Assert.True(await svc.DeleteAsync("ephemeral"));
            Assert.False(await svc.DeleteAsync("ephemeral"));
        }
    }

    [Fact]
    public async Task SecretsService_CreateOrReplace_OverwritesExisting()
    {
        await using (var scope = _sp.CreateAsyncScope())
        {
            var svc = scope.ServiceProvider.GetRequiredService<SecretsService>();
            await svc.CreateOrReplaceAsync("rotated", "v1");
            await svc.CreateOrReplaceAsync("rotated", "v2");
        }

        var resolved = await _sp.GetRequiredService<ISecretResolver>().ResolveAsync("rotated", default);
        Assert.Equal("v2", resolved);
    }
}