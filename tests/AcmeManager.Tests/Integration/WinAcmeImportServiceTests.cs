using AcmeManager.Core.Security;
using AcmeManager.Core.Storage;
using AcmeManager.Core.Storage.Entities;
using AcmeManager.Service.Migration.WinAcme;

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace AcmeManager.Tests.Integration;

/// <summary>
/// WinAcmeImportService against a synthetic win-acme config directory and a real
/// SQLite store. Account-key import isn't covered here (needs DPAPI material from
/// a real win-acme install); these renewals fall back to the existing account.
/// </summary>
public sealed class WinAcmeImportServiceTests : IAsyncLifetime
{
    private SqliteConnection? _conn;
    private AcmeManagerDbContext? _db;
    private string? _keyFile;
    private string? _winAcmeDir;

    public async Task InitializeAsync()
    {
        _conn = new SqliteConnection("Filename=:memory:");
        await _conn.OpenAsync();
        var options = new DbContextOptionsBuilder<AcmeManagerDbContext>().UseSqlite(_conn).Options;
        _db = new AcmeManagerDbContext(options);
        await _db.Database.EnsureCreatedAsync();

        _keyFile = Path.Combine(Path.GetTempPath(), $"winacme-import-test-{Guid.NewGuid():N}.key");

        // Synthetic win-acme layout: <base>/<ca-folder>/<id>.renewal.json, no
        // Registration_v2/Signer_v2 (account import falls back gracefully).
        _winAcmeDir = Path.Combine(Path.GetTempPath(), $"winacme-test-{Guid.NewGuid():N}");
        var caDir = Path.Combine(_winAcmeDir, "acme-v02.api.letsencrypt.org");
        Directory.CreateDirectory(caDir);
        await File.WriteAllTextAsync(Path.Combine(caDir, "abc123.renewal.json"), """
            {
              "Id": "abc123",
              "LastFriendlyName": "example.test",
              "TargetPluginOptions": { "CommonName": "example.test", "AlternativeNames": ["example.test"] },
              "StorePluginOptions": [],
              "InstallationPluginOptions": []
            }
            """);
    }

    public Task DisposeAsync()
    {
        _db?.Dispose();
        _conn?.Dispose();
        if (_keyFile is not null && File.Exists(_keyFile)) File.Delete(_keyFile);
        if (_winAcmeDir is not null && Directory.Exists(_winAcmeDir)) Directory.Delete(_winAcmeDir, recursive: true);
        return Task.CompletedTask;
    }

    private WinAcmeImportService CreateService() => new(
        _db!,
        new AesGcmFileSecretProtector(_keyFile!),
        NullLogger<WinAcmeImportService>.Instance);

    [Fact]
    public void Preview_NonexistentPath_ReturnsError()
    {
        var preview = CreateService().Preview(@"Z:\does\not\exist");

        Assert.NotNull(preview.Error);
        Assert.Empty(preview.CaFolders);
    }

    [Fact]
    public void Preview_MapsRenewals_WithoutTouchingTheDatabase()
    {
        var preview = CreateService().Preview(_winAcmeDir);

        Assert.Null(preview.Error);
        Assert.Equal(1, preview.RenewalCount);
        var ca = Assert.Single(preview.CaFolders);
        var renewal = Assert.Single(ca.Renewals);
        Assert.Equal("example.test", renewal.Name);
        Assert.Equal("source.manual", renewal.SourcePluginId);
        Assert.False(_db!.Renewals.Any());
    }

    [Fact]
    public async Task Apply_WithNoAccounts_ReturnsError()
    {
        var result = await CreateService().ApplyAsync(_winAcmeDir, accountName: null, noAccountImport: true, default);

        Assert.NotNull(result.Error);
        Assert.Equal(0, result.Imported);
    }

    [Fact]
    public async Task Apply_ImportsOnce_ThenSkipsExisting()
    {
        _db!.Accounts.Add(new Account { Name = "existing", DirectoryUrl = "https://ca.test/dir" });
        await _db.SaveChangesAsync();
        var service = CreateService();

        var first = await service.ApplyAsync(_winAcmeDir, accountName: null, noAccountImport: true, default);
        var second = await service.ApplyAsync(_winAcmeDir, accountName: null, noAccountImport: true, default);

        Assert.Null(first.Error);
        Assert.Equal(1, first.Imported);
        Assert.Null(second.Error);
        Assert.Equal(0, second.Imported);
        Assert.Equal(1, second.Skipped);

        var renewal = Assert.Single(await _db.Renewals.AsNoTracking().ToListAsync());
        Assert.Equal("example.test", renewal.Name);
        Assert.True(renewal.Enabled);
        Assert.Contains("source.manual", renewal.SourceJson, StringComparison.Ordinal);
    }
}