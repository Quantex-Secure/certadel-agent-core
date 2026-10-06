using AcmeManager.Core.Acme;
using AcmeManager.Core.Acme.Accounts;
using AcmeManager.Core.Acme.Orders;
using AcmeManager.Core.Engine;
using AcmeManager.Core.Notifications;
using AcmeManager.Core.Plugins;
using AcmeManager.Core.Security;
using AcmeManager.Core.Storage;
using AcmeManager.Core.Storage.Entities;
using AcmeManager.Plugins.Contracts;
using AcmeManager.Plugins.Contracts.Installation;
using AcmeManager.Plugins.Contracts.Notification;
using AcmeManager.Plugins.Contracts.Sources;
using AcmeManager.Plugins.Contracts.Validation;
using AcmeManager.Tests.Stubs;

using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace AcmeManager.Tests.Unit;

/// <summary>
/// The engine's outcome bookkeeping, exercised without an ACME server by making
/// the source step fail: consecutive-failure tracking, the failure record, the
/// alert hook, and — crucially — that a failed run never commits success state.
/// The installer-warning summary is covered as a pure function.
/// </summary>
public sealed class RenewalEngineOutcomeTests : IAsyncLifetime
{
    private SqliteConnection _conn = null!;
    private ServiceProvider _sp = null!;
    private string _keyFile = null!;
    private Guid _renewalId;
    private readonly RecordingNotifier _notifier = new();

    private sealed record ThrowingSourceOptions : PluginOptions;

    private sealed class ThrowingSource : ISource
    {
        public PluginMetadata Metadata { get; } = new("source.throwing", "Throwing", "", PluginCategory.Source, new Version(1, 0));

        public ValueTask<SourceResult> ResolveAsync(SourceContext ctx, CancellationToken ct) =>
            throw new InvalidOperationException("simulated source failure");
    }

    private sealed record NoopValidatorOptions : PluginOptions;

    private sealed class NoopValidator : IValidator
    {
        public PluginMetadata Metadata { get; } = new("validation.noop", "Noop", "", PluginCategory.Validation, new Version(1, 0));

        public ChallengeType ChallengeType => ChallengeType.Http01;

        public ValueTask PrepareAsync(ValidationContext ctx, CancellationToken ct) => ValueTask.CompletedTask;

        public ValueTask CleanupAsync(ValidationContext ctx, CancellationToken ct) => ValueTask.CompletedTask;
    }

    private sealed class RecordingNotifier : INotifier
    {
        public List<NotificationEvent> Events { get; } = [];

        public PluginMetadata Metadata { get; } = new("notifier.test", "Test", "", PluginCategory.Notification, new Version(1, 0));

        public ValueTask NotifyAsync(NotificationEvent evt, CancellationToken ct)
        {
            Events.Add(evt);
            return ValueTask.CompletedTask;
        }
    }

    public async Task InitializeAsync()
    {
        _conn = new SqliteConnection("Filename=:memory:");
        await _conn.OpenAsync();
        _keyFile = Path.Combine(Path.GetTempPath(), $"acme-engine-test-{Guid.NewGuid():N}.key");

        var services = new ServiceCollection();
        services.AddLogging(b => b.AddProvider(NullLoggerProvider.Instance));
        services.AddDbContext<AcmeManagerDbContext>(o => o.UseSqlite(_conn));
        services.AddSingleton<ISecretProtector>(new AesGcmFileSecretProtector(_keyFile));
        services.AddSingleton<IAcmeClient>(new StubAcmeClient());
        services.AddSingleton<OrderRunner>();
        services.AddSingleton<RenewalRunGuard>();
        services.AddScoped<AccountService>();
        services.AddScoped<RenewalEngine>();
        services.AddScoped<CertificateCleanupService>();
        services.AddSingleton<INotifier>(_notifier);
        services.AddSingleton(Options.Create(new NotificationOptions { FailureThreshold = 2 }));
        services.AddSingleton<RenewalAlertService>();
        services.AddSingleton(Microsoft.Extensions.Options.Options.Create(new AcmeManager.Core.Verification.TlsVerifierOptions()));
        services.AddSingleton<AcmeManager.Core.Verification.IEndpointVerifier, AcmeManager.Core.Verification.TlsEndpointVerifier>();
        services.AddSingleton<AcmeManager.Core.Verification.InstallVerificationRunner>();
        services.AddPluginCatalog(c =>
        {
            c.AddSource<ThrowingSource, ThrowingSourceOptions>("source.throwing");
            c.AddValidator<NoopValidator, NoopValidatorOptions>("validation.noop");
        });
        _sp = services.BuildServiceProvider();

        await using var scope = _sp.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AcmeManagerDbContext>();
        await db.Database.EnsureCreatedAsync();

        var accounts = scope.ServiceProvider.GetRequiredService<AccountService>();
        var account = await accounts.CreateAsync(
            "test", new Uri("https://stub-ca.test/directory"), "ops@example.test", AcmeKeyAlgorithm.EcP256, eab: null, ct: default);

        var catalog = scope.ServiceProvider.GetRequiredService<PluginCatalog>();
        var renewal = new Renewal
        {
            Name = "web",
            AccountId = account.LocalId,
            SourceJson = PluginStepSerializer.SerializeSingle("source.throwing", new ThrowingSourceOptions(), catalog),
            ValidationJson = PluginStepSerializer.SerializeSingle("validation.noop", new NoopValidatorOptions(), catalog),
            StoresJson = "[]",
            InstallationsJson = "[]",
            LastSuccessAt = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            LastAttemptAt = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
        };
        db.Renewals.Add(renewal);
        await db.SaveChangesAsync();
        _renewalId = renewal.Id;
    }

    public Task DisposeAsync()
    {
        _sp.Dispose();
        _conn.Dispose();
        if (File.Exists(_keyFile)) File.Delete(_keyFile);
        return Task.CompletedTask;
    }

    private async Task<RenewalRunResult> RunOnceAsync()
    {
        await using var scope = _sp.CreateAsyncScope();
        return await scope.ServiceProvider.GetRequiredService<RenewalEngine>().RunAsync(_renewalId, default);
    }

    private async Task<Renewal> LoadRenewalAsync()
    {
        await using var scope = _sp.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AcmeManagerDbContext>();
        return await db.Renewals.AsNoTracking().SingleAsync(r => r.Id == _renewalId);
    }

    [Fact]
    public async Task FailedRun_IncrementsConsecutiveFailures_KeepsLastSuccess_AndRecordsFailedHistory()
    {
        var result = await RunOnceAsync();

        Assert.False(result.Success);
        Assert.Contains("simulated source failure", result.ErrorMessage);

        var renewal = await LoadRenewalAsync();
        Assert.Equal(1, renewal.ConsecutiveFailures);
        Assert.Equal(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), renewal.LastSuccessAt);
        Assert.NotEqual(renewal.LastSuccessAt, renewal.LastAttemptAt);

        await using var scope = _sp.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<AcmeManagerDbContext>();
        var history = await db.History.AsNoTracking().SingleAsync(h => h.RenewalId == _renewalId);
        Assert.Equal(HistoryStatus.Failed, history.Status);
        Assert.NotNull(history.ExceptionJson);
        Assert.Empty(await db.Certificates.AsNoTracking().Where(c => c.RenewalId == _renewalId).ToListAsync());
    }

    [Fact]
    public async Task RepeatedFailures_AlertAtThreshold_NotBefore()
    {
        await RunOnceAsync();
        Assert.Empty(_notifier.Events);

        await RunOnceAsync();
        var evt = Assert.Single(_notifier.Events);
        Assert.Equal(NotificationLevel.Error, evt.Level);
        Assert.Contains("2 consecutive failures", evt.Subject);

        Assert.Equal(2, (await LoadRenewalAsync()).ConsecutiveFailures);
    }

    [Fact]
    public void InstallWarning_NamesEveryInstallerThatBoundNothing()
    {
        var installs = new List<RenewalEngine.InstallOutcome>
        {
            new("installer.script", InstallResult.Ok("ran")),
            new("installer.iis", InstallResult.NothingToApply("no HTTPS binding on site 'shop' matches [shop.example.com]")),
        };

        var warning = RenewalEngine.DescribeInstallWarning(installs);

        Assert.NotNull(warning);
        Assert.Contains("installer.iis bound nothing", warning);
        Assert.Contains("shop.example.com", warning);
        Assert.DoesNotContain("installer.script", warning);

        var summary = RenewalEngine.DescribeInstalls(installs);
        Assert.Contains("installed via installer.script", summary);
        Assert.Contains("WARNING", summary);
    }

    [Fact]
    public void InstallWarning_IsNull_WhenEveryInstallerApplied()
    {
        var installs = new List<RenewalEngine.InstallOutcome> { new("installer.iis", InstallResult.Ok("2 bindings")) };
        Assert.Null(RenewalEngine.DescribeInstallWarning(installs));
        Assert.Equal("installed via installer.iis", RenewalEngine.DescribeInstalls(installs));
    }

    [Fact]
    public void NoInstallers_SaysStoredOnly()
    {
        Assert.Contains("NOT bound", RenewalEngine.DescribeInstalls([]));
        Assert.Null(RenewalEngine.DescribeInstallWarning([]));
    }
}