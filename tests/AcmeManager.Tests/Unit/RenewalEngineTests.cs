using AcmeManager.Core.Acme;
using AcmeManager.Core.Acme.Accounts;
using AcmeManager.Core.Acme.Orders;
using AcmeManager.Core.Engine;
using AcmeManager.Core.Plugins;
using AcmeManager.Core.Security;
using AcmeManager.Core.Storage;
using AcmeManager.Core.Storage.Entities;
using AcmeManager.Plugins.BuiltIn.Sources;
using AcmeManager.Plugins.BuiltIn.Storage;
using AcmeManager.Plugins.Contracts;
using AcmeManager.Tests.Stubs;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace AcmeManager.Tests.Unit;

/// <summary>
/// Deterministic, network-free coverage of the crown-jewel issuance path:
/// <c>RenewalEngine.RunAsync</c> → <c>OrderRunner</c> (driven by
/// <see cref="StubCaAcmeClient"/>) → build bundle → stores → persist
/// Certificate + HistoryEntry. Mirrors the Pebble-based
/// <c>PluginDrivenRenewalTests</c> but runs without Pebble so it never skips.
/// </summary>
public sealed class RenewalEngineTests
{
    private static readonly Uri StubDirectory = new("https://stub-ca.test/dir");

    [Fact]
    public async Task RunAsync_HappyPath_IssuesCertAndPersistsSuccess()
    {
        var pfxPath = TempPath("pfx");
        try
        {
            await using var h = await Harness.CreateAsync(c =>
            {
                c.AddSource<ManualSource, ManualSourceOptions>("source.manual");
                c.AddValidator<NoOpHttp01Validator, NoOpValidatorOptions>(NoOpHttp01Validator.PluginId);
                c.AddStore<PfxFileStore, PfxFileStoreOptions>("store.pfx");
            });

            var renewalId = await h.SeedRenewalAsync(
                name: "happy-path",
                source: ("source.manual", new ManualSourceOptions { Identifiers = ["happy.stub.test"] }),
                validation: (NoOpHttp01Validator.PluginId, new NoOpValidatorOptions()),
                stores: [("store.pfx", new PfxFileStoreOptions { FilePath = pfxPath })]);

            RenewalRunResult result;
            await using (var scope = h.Provider.CreateAsyncScope())
            {
                var engine = scope.ServiceProvider.GetRequiredService<RenewalEngine>();
                result = await engine.RunAsync(renewalId, default);
            }

            Assert.True(result.Success, $"Engine reported failure: {result.ErrorMessage}");
            Assert.NotNull(result.IssuedNotAfter);
            Assert.True(result.DurationMs >= 0);
            Assert.True(File.Exists(pfxPath), $"PFX file was not written to {pfxPath}");
            Assert.Equal(1, h.Ca.FinalizeCalls);

            await using var verify = h.Provider.CreateAsyncScope();
            var db = verify.ServiceProvider.GetRequiredService<AcmeManagerDbContext>();

            var cert = await db.Certificates.AsNoTracking().SingleAsync(c => c.RenewalId == renewalId);
            Assert.NotEmpty(cert.Thumbprint);
            Assert.True(cert.NotAfter > DateTimeOffset.UtcNow);
            Assert.Equal("CN=happy.stub.test", cert.Subject);

            var history = await db.History.AsNoTracking()
                .Where(hh => hh.RenewalId == renewalId)
                .ToListAsync();
            var entry = Assert.Single(history);
            Assert.Equal(HistoryStatus.Success, entry.Status);
            Assert.True(entry.DurationMs > 0);

            var renewal = await db.Renewals.AsNoTracking().FirstAsync(r => r.Id == renewalId);
            Assert.NotNull(renewal.LastSuccessAt);
            Assert.Equal(renewal.LastSuccessAt, renewal.LastAttemptAt);
            Assert.Null(renewal.RetryAfter);
        }
        finally
        {
            Delete(pfxPath);
        }
    }

    [Fact]
    public async Task RunAsync_WhenStoreThrows_ReportsFailureAndPersistsFailedHistory()
    {
        await using var h = await Harness.CreateAsync(c =>
        {
            c.AddSource<ManualSource, ManualSourceOptions>("source.manual");
            c.AddValidator<NoOpHttp01Validator, NoOpValidatorOptions>(NoOpHttp01Validator.PluginId);
            c.AddStore<ThrowingStore, ThrowingStoreOptions>(ThrowingStore.PluginId);
        });

        var renewalId = await h.SeedRenewalAsync(
            name: "store-failure",
            source: ("source.manual", new ManualSourceOptions { Identifiers = ["fail.stub.test"] }),
            validation: (NoOpHttp01Validator.PluginId, new NoOpValidatorOptions()),
            stores: [(ThrowingStore.PluginId, new ThrowingStoreOptions { FailureMessage = "boom-from-store" })]);

        RenewalRunResult result;
        await using (var scope = h.Provider.CreateAsyncScope())
        {
            var engine = scope.ServiceProvider.GetRequiredService<RenewalEngine>();
            result = await engine.RunAsync(renewalId, default);
        }

        Assert.False(result.Success);
        Assert.NotNull(result.ErrorMessage);
        Assert.Contains("boom-from-store", result.ErrorMessage);

        await using var verify = h.Provider.CreateAsyncScope();
        var db = verify.ServiceProvider.GetRequiredService<AcmeManagerDbContext>();

        // The cert never made it to a store, so no Certificate row is persisted.
        Assert.False(await db.Certificates.AnyAsync(c => c.RenewalId == renewalId));

        var history = await db.History.AsNoTracking()
            .Where(hh => hh.RenewalId == renewalId)
            .ToListAsync();
        var entry = Assert.Single(history);
        Assert.Equal(HistoryStatus.Failed, entry.Status);
        Assert.Contains("boom-from-store", entry.Message);
        Assert.NotNull(entry.ExceptionJson);

        var renewal = await db.Renewals.AsNoTracking().FirstAsync(r => r.Id == renewalId);
        Assert.NotNull(renewal.LastAttemptAt);
        Assert.Null(renewal.LastSuccessAt);
    }

    [Fact]
    public async Task RunAsync_SingleFlight_RejectsConcurrentRunForSameRenewal()
    {
        var pfxPath = TempPath("pfx");
        try
        {
            await using var h = await Harness.CreateAsync(c =>
            {
                c.AddSource<GatedSource, GatedSourceOptions>(GatedSource.PluginId);
                c.AddValidator<NoOpHttp01Validator, NoOpValidatorOptions>(NoOpHttp01Validator.PluginId);
                c.AddStore<PfxFileStore, PfxFileStoreOptions>("store.pfx");
            });

            var renewalId = await h.SeedRenewalAsync(
                name: "single-flight",
                source: (GatedSource.PluginId, new GatedSourceOptions { Identifiers = ["gated.stub.test"] }),
                validation: (NoOpHttp01Validator.PluginId, new NoOpValidatorOptions()),
                stores: [("store.pfx", new PfxFileStoreOptions { FilePath = pfxPath })]);

            var gate = h.Provider.GetRequiredService<GatedSource>();

            // First run: starts and blocks inside the gated source, holding the lock.
            var firstScope = h.Provider.CreateAsyncScope();
            var firstRun = firstScope.ServiceProvider.GetRequiredService<RenewalEngine>()
                .RunAsync(renewalId, default);

            await gate.Entered.WaitAsync(TimeSpan.FromSeconds(10));

            // Second run for the same renewal while the first is in-flight → rejected.
            RenewalRunResult second;
            await using (var secondScope = h.Provider.CreateAsyncScope())
            {
                second = await secondScope.ServiceProvider.GetRequiredService<RenewalEngine>()
                    .RunAsync(renewalId, default);
            }

            Assert.False(second.Success);
            Assert.Contains("already in progress", second.ErrorMessage);

            // Release the first run and let it finish successfully.
            gate.Release();
            var first = await firstRun.WaitAsync(TimeSpan.FromSeconds(30));
            await firstScope.DisposeAsync();

            Assert.True(first.Success, $"First run failed: {first.ErrorMessage}");

            await using var verify = h.Provider.CreateAsyncScope();
            var db = verify.ServiceProvider.GetRequiredService<AcmeManagerDbContext>();
            // Exactly one successful issuance despite the two triggers.
            var cert = await db.Certificates.AsNoTracking().SingleAsync(c => c.RenewalId == renewalId);
            Assert.NotEmpty(cert.Thumbprint);
        }
        finally
        {
            Delete(pfxPath);
        }
    }

    private static string TempPath(string ext) =>
        Path.Combine(Path.GetTempPath(), $"acme-engine-test-{Guid.NewGuid():N}.{ext}");

    private static void Delete(string path)
    {
        if (File.Exists(path)) File.Delete(path);
    }

    /// <summary>
    /// Self-contained DI harness mirroring <c>PluginDrivenRenewalTests</c>'s wiring
    /// but with the in-memory stub CA instead of Pebble. Owns the SQLite connection,
    /// the secret-protector key file, and a pre-created ACME account.
    /// </summary>
    private sealed class Harness : IAsyncDisposable
    {
        private readonly SqliteConnection _conn;
        private readonly string _keyFile;

        public ServiceProvider Provider { get; }

        public StubCaAcmeClient Ca { get; }

        public Guid AccountId { get; private set; }

        private Harness(SqliteConnection conn, ServiceProvider provider, StubCaAcmeClient ca, string keyFile)
        {
            _conn = conn;
            Provider = provider;
            Ca = ca;
            _keyFile = keyFile;
        }

        public static async Task<Harness> CreateAsync(Action<PluginCatalogBuilder> configureCatalog)
        {
            var conn = new SqliteConnection("Filename=:memory:");
            await conn.OpenAsync();

            var keyFile = TempPath("key");
            var ca = new StubCaAcmeClient();

            var services = new ServiceCollection();
            services.AddLogging(b => b.AddProvider(NullLoggerProvider.Instance));
            services.AddDbContext<AcmeManagerDbContext>(o => o.UseSqlite(conn));
            services.AddSingleton<ISecretProtector>(new AesGcmFileSecretProtector(keyFile));
            services.AddSingleton<ISecretResolver, ThrowingSecretResolver>();
            services.AddSingleton<IAcmeClient>(ca);
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
            services.AddPluginCatalog(configureCatalog);

            var provider = services.BuildServiceProvider();

            await using (var scope = provider.CreateAsyncScope())
            {
                var db = scope.ServiceProvider.GetRequiredService<AcmeManagerDbContext>();
                await db.Database.EnsureCreatedAsync();

                var accounts = scope.ServiceProvider.GetRequiredService<AccountService>();
                var account = await accounts.CreateAsync(
                    name: "stub-account",
                    directoryUrl: StubDirectory,
                    contactEmail: "engine-test@acme-manager.test",
                    algorithm: AcmeKeyAlgorithm.EcP256,
                    eab: null,
                    ct: default);

                var harness = new Harness(conn, provider, ca, keyFile) { AccountId = account.LocalId };
                return harness;
            }
        }

        public async Task<Guid> SeedRenewalAsync(
            string name,
            (string PluginId, PluginOptions Options) source,
            (string PluginId, PluginOptions Options) validation,
            IReadOnlyList<(string PluginId, PluginOptions Options)> stores)
        {
            await using var scope = Provider.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<AcmeManagerDbContext>();
            var catalog = scope.ServiceProvider.GetRequiredService<PluginCatalog>();

            var renewal = new Renewal
            {
                Name = name,
                AccountId = AccountId,
                SourceJson = PluginStepSerializer.SerializeSingle(source.PluginId, source.Options, catalog),
                ValidationJson = PluginStepSerializer.SerializeSingle(validation.PluginId, validation.Options, catalog),
                StoresJson = PluginStepSerializer.SerializeList(stores, catalog),
                InstallationsJson = "[]",
                Enabled = true,
            };
            db.Renewals.Add(renewal);
            await db.SaveChangesAsync();
            return renewal.Id;
        }

        public async ValueTask DisposeAsync()
        {
            await Provider.DisposeAsync();
            await _conn.DisposeAsync();
            Delete(_keyFile);
        }
    }
}
