using System.Net.Http;

using AcmeManager.Core.Acme;
using AcmeManager.Core.Acme.Accounts;
using AcmeManager.Core.Acme.Orders;
using AcmeManager.Core.Engine;
using AcmeManager.Core.Plugins;
using AcmeManager.Core.Security;
using AcmeManager.Core.Storage;
using AcmeManager.Core.Storage.Entities;
using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.BuiltIn.Sources;
using AcmeManager.Plugins.BuiltIn.Storage;

using Certes;
using Certes.Acme;

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AcmeManager.Tests.Integration;

[Collection(PebbleCollection.Name)]
public sealed class PluginDrivenRenewalTests(PebbleFixture pebble) : IAsyncLifetime
{
    private SqliteConnection? _conn;
    private ServiceProvider? _sp;
    private string? _keyFile;
    private string? _pfxPath;
    private Guid _renewalId;

    public async Task InitializeAsync()
    {
        if (!pebble.Available)
        {
            // Defer the skip to the test method so xunit reports it properly.
            return;
        }

        _conn = new SqliteConnection("Filename=:memory:");
        await _conn.OpenAsync();

        _keyFile = Path.Combine(Path.GetTempPath(), $"acme-plugin-test-{Guid.NewGuid():N}.key");
        _pfxPath = Path.Combine(Path.GetTempPath(), $"acme-plugin-test-{Guid.NewGuid():N}.pfx");

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(NullLoggerProvider.Instance));
        services.AddDbContext<AcmeManagerDbContext>(o => o.UseSqlite(_conn));
        services.AddSingleton<ISecretProtector>(new AesGcmFileSecretProtector(_keyFile));

        // Pebble-trusting ACME client.
        var httpClient = pebble.CreatePebbleTrustingHttpClient();
        services.AddSingleton<IAcmeClient>(sp => new CertesAcmeClient(
            sp.GetRequiredService<ILogger<CertesAcmeClient>>(),
            (url, key) => new AcmeContext(url, key, new AcmeHttpClient(url, httpClient))));

        // challtestsrv management HTTP client for the test validator.
        services.AddSingleton(new HttpClient { BaseAddress = pebble.ChallTestSrvMgmtUrl });

        // PfxFileStore takes an ISecretResolver; this renewal uses a literal path
        // (no password secret), so a throwing resolver satisfies DI without a store.
        services.AddSingleton<ISecretResolver>(new Stubs.ThrowingSecretResolver());

        services.AddSingleton<OrderRunner>();
        services.AddSingleton<RenewalRunGuard>();
        services.AddScoped<AccountService>();
        services.AddScoped<RenewalEngine>();
        services.AddScoped<CertificateCleanupService>();
        services.AddSingleton(Microsoft.Extensions.Options.Options.Create(new AcmeManager.Core.Notifications.NotificationOptions()));
        services.AddSingleton<RenewalAlertService>();
        services.AddSingleton(Microsoft.Extensions.Options.Options.Create(new AcmeManager.Core.Verification.TlsVerifierOptions()));
        services.AddSingleton<AcmeManager.Core.Verification.IEndpointVerifier, AcmeManager.Core.Verification.TlsEndpointVerifier>();
        services.AddSingleton<AcmeManager.Core.Verification.InstallVerificationRunner>();

        services.AddPluginCatalog(c =>
        {
            c.AddSource<ManualSource, ManualSourceOptions>("source.manual");
            c.AddValidator<ChallTestSrvHttp01Validator, ChallTestSrvHttp01Options>("validation.http-01.challtestsrv");
            c.AddStore<PfxFileStore, PfxFileStoreOptions>("store.pfx");
        });

        _sp = services.BuildServiceProvider();

        await using var setup = _sp.CreateAsyncScope();
        var db = setup.ServiceProvider.GetRequiredService<AcmeManagerDbContext>();
        await db.Database.EnsureCreatedAsync();

        var accountSvc = setup.ServiceProvider.GetRequiredService<AccountService>();
        var account = await accountSvc.CreateAsync(
            name: "pebble-plugin-test",
            directoryUrl: pebble.AcmeDirectoryUrl,
            contactEmail: "plugin-test@acme-manager.test",
            algorithm: AcmeKeyAlgorithm.EcP256,
            eab: null,
            ct: default);

        var catalog = setup.ServiceProvider.GetRequiredService<PluginCatalog>();
        var identifier = $"plugin-e2e-{Guid.NewGuid():N}.test";

        var sourceJson = PluginStepSerializer.SerializeSingle(
            "source.manual",
            new ManualSourceOptions { Identifiers = [identifier] },
            catalog);

        var validationJson = PluginStepSerializer.SerializeSingle(
            "validation.http-01.challtestsrv",
            new ChallTestSrvHttp01Options(),
            catalog);

        var storesJson = PluginStepSerializer.SerializeList(
            [("store.pfx", new PfxFileStoreOptions { FilePath = _pfxPath })],
            catalog);

        var renewal = new Renewal
        {
            Name = "plugin-driven-test",
            AccountId = account.LocalId,
            SourceJson = sourceJson,
            ValidationJson = validationJson,
            StoresJson = storesJson,
            InstallationsJson = "[]",
            Enabled = true,
        };
        db.Renewals.Add(renewal);
        await db.SaveChangesAsync();
        _renewalId = renewal.Id;
    }

    public Task DisposeAsync()
    {
        _sp?.Dispose();
        _conn?.Dispose();
        if (_keyFile is not null && File.Exists(_keyFile)) File.Delete(_keyFile);
        if (_pfxPath is not null && File.Exists(_pfxPath)) File.Delete(_pfxPath);
        return Task.CompletedTask;
    }

    [SkippableFact]
    public async Task RenewalEngine_DrivesPluginsEndToEnd_AndPersistsResults()
    {
        pebble.EnsureAvailableOrSkip();
        Assert.NotNull(_sp);
        Assert.NotNull(_pfxPath);

        await using var runScope = _sp.CreateAsyncScope();
        var engine = runScope.ServiceProvider.GetRequiredService<RenewalEngine>();

        var result = await engine.RunAsync(_renewalId, default);

        Assert.True(result.Success, $"Engine reported failure: {result.ErrorMessage}");
        Assert.NotNull(result.IssuedNotAfter);
        Assert.True(File.Exists(_pfxPath), $"PFX file was not written to {_pfxPath}");

        await using var verifyScope = _sp.CreateAsyncScope();
        var db = verifyScope.ServiceProvider.GetRequiredService<AcmeManagerDbContext>();

        var cert = await db.Certificates.AsNoTracking().SingleAsync(c => c.RenewalId == _renewalId);
        Assert.NotEmpty(cert.Thumbprint);
        Assert.True(cert.NotAfter > DateTimeOffset.UtcNow);

        // No OrderBy(h => h.At): SQLite can't translate ORDER BY over DateTimeOffset,
        // and a single history row is asserted anyway.
        var history = await db.History.AsNoTracking()
            .Where(h => h.RenewalId == _renewalId)
            .ToListAsync();
        Assert.Single(history);
        Assert.Equal(HistoryStatus.Success, history[0].Status);
        Assert.True(history[0].DurationMs > 0);

        var renewal = await db.Renewals.AsNoTracking().FirstAsync(r => r.Id == _renewalId);
        Assert.NotNull(renewal.LastSuccessAt);
        Assert.Equal(renewal.LastSuccessAt, renewal.LastAttemptAt);
    }
}