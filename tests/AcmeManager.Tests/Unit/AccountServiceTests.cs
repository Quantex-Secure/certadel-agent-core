using System.Text;

using AcmeManager.Core.Acme;
using AcmeManager.Core.Acme.Accounts;
using AcmeManager.Core.Security;
using AcmeManager.Core.Storage;
using AcmeManager.Tests.Stubs;

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;

namespace AcmeManager.Tests.Unit;

public sealed class AccountServiceTests : IAsyncLifetime
{
    private SqliteConnection _conn = null!;
    private DbContextOptions<AcmeManagerDbContext> _options = null!;
    private string _keyFile = null!;
    private AesGcmFileSecretProtector _protector = null!;

    public async Task InitializeAsync()
    {
        _conn = new SqliteConnection("Filename=:memory:");
        await _conn.OpenAsync();
        _options = new DbContextOptionsBuilder<AcmeManagerDbContext>().UseSqlite(_conn).Options;

        await using var db = new AcmeManagerDbContext(_options);
        await db.Database.EnsureCreatedAsync();

        _keyFile = Path.Combine(Path.GetTempPath(), $"acme-test-account-{Guid.NewGuid():N}.key");
        _protector = new AesGcmFileSecretProtector(_keyFile);
    }

    public Task DisposeAsync()
    {
        _conn.Dispose();
        if (File.Exists(_keyFile)) File.Delete(_keyFile);
        return Task.CompletedTask;
    }

    [Fact]
    public async Task CreateAsync_PersistsEncryptedKey_AndRoundTrips()
    {
        var stubAcme = new StubAcmeClient();

        await using (var db = new AcmeManagerDbContext(_options))
        {
            var svc = new AccountService(db, stubAcme, _protector, NullLogger<AccountService>.Instance);
            var registered = await svc.CreateAsync(
                name: "test-account",
                directoryUrl: new Uri("https://stub-ca.test/dir"),
                contactEmail: "ops@example.com",
                algorithm: AcmeKeyAlgorithm.EcP256,
                eab: null,
                ct: default);

            Assert.Equal(stubAcme.DefaultKeyId, registered.KeyId);
            Assert.Equal(1, stubAcme.CreateAccountCalls);
        }

        // Reopen the DB to prove persistence + decryption.
        await using (var db = new AcmeManagerDbContext(_options))
        {
            var stored = await db.Accounts.SingleAsync();

            // Encrypted-at-rest invariant: the raw blob must not contain PEM headers.
            var asText = Encoding.UTF8.GetString(stored.AccountKeyEncrypted);
            Assert.DoesNotContain("BEGIN", asText);
            Assert.DoesNotContain("PRIVATE KEY", asText);

            var svc = new AccountService(db, new StubAcmeClient(), _protector, NullLogger<AccountService>.Instance);
            var loaded = await svc.LoadAsync(stored.Id, default);

            Assert.NotNull(loaded);
            Assert.Equal("ops@example.com", loaded!.ContactEmail);
            Assert.Contains("BEGIN", loaded.Key.Pem); // decryption produced a valid-looking PEM
        }
    }

    [Fact]
    public async Task CreateAsync_WithEab_EncryptsEabFields()
    {
        var stubAcme = new StubAcmeClient();
        var eab = new EabCredentials(KeyId: "kid-123", HmacKeyBase64Url: "aGVsbG8td29ybGQ");

        await using var db = new AcmeManagerDbContext(_options);
        var svc = new AccountService(db, stubAcme, _protector, NullLogger<AccountService>.Instance);

        await svc.CreateAsync(
            name: "eab-account",
            directoryUrl: new Uri("https://eab-ca.test/dir"),
            contactEmail: "eab@example.com",
            algorithm: AcmeKeyAlgorithm.Rsa2048,
            eab: eab,
            ct: default);

        var stored = await db.Accounts.SingleAsync();
        Assert.NotNull(stored.EabKeyIdEncrypted);
        Assert.NotNull(stored.EabHmacEncrypted);

        Assert.DoesNotContain("kid-123", Encoding.UTF8.GetString(stored.EabKeyIdEncrypted!));
        Assert.DoesNotContain("hello", Encoding.UTF8.GetString(stored.EabHmacEncrypted!).ToLowerInvariant());
    }
}