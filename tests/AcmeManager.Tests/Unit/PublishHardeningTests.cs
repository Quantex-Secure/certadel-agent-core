using AcmeManager.Core.Engine;
using AcmeManager.Core.Plugins;
using AcmeManager.Plugins.BuiltIn.Storage;
using AcmeManager.Plugins.BuiltIn.Validation;
using AcmeManager.Plugins.Contracts;
using AcmeManager.Service.Authentication;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;

namespace AcmeManager.Tests.Unit;

/// <summary>Unit coverage for the pre-publication hardening: challenge-token path
/// confinement, per-account auth throttling, and sensitive-option redaction.</summary>
public sealed class PublishHardeningTests
{
    // ---------------- HTTP-01 token → file path ----------------

    [Theory]
    [InlineData("evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ-PCt92wr-oA", true)]
    [InlineData("abc_DEF-123", true)]
    [InlineData("", false)]
    [InlineData("../../etc/cron.d/pwn", false)]
    [InlineData("..\\..\\windows\\system32\\x", false)]
    [InlineData("token.txt", false)]
    [InlineData("a b", false)]
    [InlineData("tok/en", false)]
    [InlineData("NUL", false)]
    [InlineData("com1", false)]
    public void ChallengeToken_MustBePlainBase64Url(string token, bool valid)
    {
        Assert.Equal(valid, FileSystemHttp01Validator.IsValidToken(token));
    }

    [Fact]
    public void ChallengeFilePath_StaysInsideTheChallengeDirectory()
    {
        var webroot = Path.Combine(Path.GetTempPath(), "wwwroot");
        var file = FileSystemHttp01Validator.ChallengeFilePath(webroot, "evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ");

        var expectedDir = Path.GetFullPath(Path.Combine(webroot, ".well-known", "acme-challenge"));
        Assert.Equal(expectedDir, Path.GetDirectoryName(file));
        Assert.Equal("evaGxfADs6pSRb2LAv9IZf17Dt3juxGJ", Path.GetFileName(file));
    }

    [Theory]
    [InlineData("../../../etc/cron.d/pwn")]
    [InlineData("..")]
    [InlineData("x/../../y")]
    public void ChallengeFilePath_RefusesTraversal(string token)
    {
        var webroot = Path.Combine(Path.GetTempPath(), "wwwroot");
        Assert.Throws<InvalidOperationException>(() => FileSystemHttp01Validator.ChallengeFilePath(webroot, token));
    }

    // ---------------- per-account throttle ----------------

    [Fact]
    public void Throttle_LocksAfterFiveFailures_AndClearsOnSuccess()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 9, 2, 12, 0, 0, TimeSpan.Zero));
        var throttle = new AuthThrottle(clock);

        for (var i = 0; i < 4; i++)
        {
            Assert.Null(throttle.RecordFailure("alice"));
            Assert.False(throttle.IsLockedOut("alice", out _));
        }
        var lockout = throttle.RecordFailure("alice");
        Assert.Equal(AuthThrottle.InitialLockout, lockout);
        Assert.True(throttle.IsLockedOut("ALICE ", out var retry)); // case/space-insensitive
        Assert.Equal(AuthThrottle.InitialLockout, retry);

        throttle.RecordSuccess("alice");
        Assert.False(throttle.IsLockedOut("alice", out _));
    }

    [Theory]
    [InlineData("alice", "ALICE")]
    [InlineData("  Alice ", "ALICE")]
    [InlineData("CORP\\alice", "ALICE")]
    [InlineData("alice@corp.example", "ALICE")]
    [InlineData("CORP\\alice@corp.example", "ALICE")]
    public void Throttle_KeysOnThePrincipal_HoweverItIsSpelled(string input, string expected)
    {
        Assert.Equal(expected, AuthThrottle.Normalize(input));
    }

    [Fact]
    public void Throttle_AdmitsOneProbePerMinute_WhileLocked()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 9, 2, 12, 0, 0, TimeSpan.Zero));
        var throttle = new AuthThrottle(clock);
        for (var i = 0; i < 5; i++) throttle.RecordFailure("erin");

        Assert.True(throttle.IsLockedOut("erin", out _));          // just locked: refused
        clock.Advance(AuthThrottle.ProbeInterval);
        Assert.False(throttle.IsLockedOut("erin", out _));         // the periodic probe gets through
        Assert.True(throttle.IsLockedOut("erin", out _));          // …but only one
        throttle.RecordSuccess("erin");                            // right password on the probe
        Assert.False(throttle.IsLockedOut("erin", out _));
    }

    [Fact]
    public async Task Throttle_SerialisesAttemptsForOneAccount()
    {
        var throttle = new AuthThrottle();
        using var first = await throttle.EnterAsync("frank", default);
        var second = throttle.EnterAsync("FRANK", default);
        await Task.Delay(50);
        Assert.False(second.IsCompleted);
        first.Dispose();
        using var lease = await second.WaitAsync(TimeSpan.FromSeconds(5));
        Assert.NotNull(lease);
    }

    [Fact]
    public void Throttle_EscalatesWhileLocked_AndCaps()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 9, 2, 12, 0, 0, TimeSpan.Zero));
        var throttle = new AuthThrottle(clock);

        for (var i = 0; i < 4; i++) Assert.Null(throttle.RecordFailure("bob"));
        Assert.Equal(TimeSpan.FromMinutes(5), throttle.RecordFailure("bob"));   // 1st lockout
        Assert.Equal(TimeSpan.FromMinutes(10), throttle.RecordFailure("bob"));  // failing (on a probe) while locked: doubled
        Assert.Equal(TimeSpan.FromMinutes(20), throttle.RecordFailure("bob"));
        Assert.Equal(TimeSpan.FromMinutes(40), throttle.RecordFailure("bob"));
        Assert.Equal(TimeSpan.FromHours(1), throttle.RecordFailure("bob"));     // 80 min → capped
        Assert.Equal(TimeSpan.FromHours(1), throttle.RecordFailure("bob"));
    }

    [Fact]
    public void Throttle_ExpiresLockout_AndForgetsOldFailures()
    {
        var clock = new FakeTimeProvider(new DateTimeOffset(2026, 9, 2, 12, 0, 0, TimeSpan.Zero));
        var throttle = new AuthThrottle(clock);

        for (var i = 0; i < 5; i++) throttle.RecordFailure("carol");
        Assert.True(throttle.IsLockedOut("carol", out _));

        clock.Advance(AuthThrottle.InitialLockout + TimeSpan.FromSeconds(1));
        Assert.False(throttle.IsLockedOut("carol", out _));

        // Failures spread over more than the window never accumulate to a lockout,
        // and stale records are pruned.
        var throttle2 = new AuthThrottle(clock);
        for (var i = 0; i < 10; i++)
        {
            Assert.Null(throttle2.RecordFailure("dave"));
            clock.Advance(TimeSpan.FromMinutes(16));
        }
        Assert.Equal(1, throttle2.Prune());
        Assert.False(throttle2.IsLockedOut("dave", out _));
    }

    // ---------------- sensitive options ----------------

    private static PluginCatalog Catalog()
    {
        var services = new ServiceCollection();
        services.AddPluginCatalog(c => c.AddStore<PfxFileStore, PfxFileStoreOptions>("store.pfx"));
        return services.BuildServiceProvider().GetRequiredService<PluginCatalog>();
    }

    [Fact]
    public void Redact_ReplacesLiteralPassword_ButNotSecretReference()
    {
        var catalog = Catalog();
        const string stores = """[{"pluginId":"store.pfx","options":{"filePath":"C:\\certs\\a.pfx","password":"hunter2","passwordSecretName":"pfx-pw"}}]""";

        var redacted = SensitiveOptions.Redact(catalog, stores);

        Assert.DoesNotContain("hunter2", redacted);
        Assert.Contains(SensitiveOptionAttribute.RedactedValue, redacted);
        Assert.Contains("pfx-pw", redacted);
        Assert.Contains("a.pfx", redacted);
    }

    [Fact]
    public void Redact_LeavesEmptyPasswordAlone()
    {
        var catalog = Catalog();
        const string stores = """[{"pluginId":"store.pfx","options":{"filePath":"x","password":""}}]""";
        Assert.Equal(stores, SensitiveOptions.Redact(catalog, stores));
    }

    [Fact]
    public void Restore_PutsTheStoredValueBehindThePlaceholder()
    {
        var catalog = Catalog();
        const string stored = """[{"pluginId":"store.pfx","options":{"filePath":"x","password":"hunter2"}}]""";
        var incoming = SensitiveOptions.Redact(catalog, stored).Replace("\"filePath\":\"x\"", "\"filePath\":\"y\"");

        var restored = SensitiveOptions.Restore(catalog, incoming, stored);

        Assert.Contains("hunter2", restored);
        Assert.Contains("\"y\"", restored);
        Assert.DoesNotContain(SensitiveOptionAttribute.RedactedValue, restored);
    }

    [Fact]
    public void Restore_MatchesByPosition_SoTwoStoresOfTheSamePluginKeepTheirOwnPasswords()
    {
        var catalog = Catalog();
        const string stored = """[{"pluginId":"store.pfx","options":{"filePath":"a.pfx","password":"alpha"}},{"pluginId":"store.pfx","options":{"filePath":"b.pfx","password":"beta"}}]""";
        var incoming = SensitiveOptions.Redact(catalog, stored);

        var restored = SensitiveOptions.Restore(catalog, incoming, stored);

        Assert.Equal(stored, restored);
    }

    [Fact]
    public void Restore_RefusesAPlaceholder_ItCannotMapToAStoredStep()
    {
        var catalog = Catalog();
        const string stored = """[{"pluginId":"store.pfx","options":{"filePath":"a.pfx","password":"alpha"}}]""";
        // Two steps sent, one stored, both redacted: the second has no source.
        const string incoming = """[{"pluginId":"store.pfx","options":{"filePath":"a.pfx","password":"********"}},{"pluginId":"store.pfx","options":{"filePath":"b.pfx","password":"********"}}]""";

        Assert.Throws<SensitiveOptionException>(() => SensitiveOptions.Restore(catalog, incoming, stored));
        Assert.Throws<SensitiveOptionException>(() => SensitiveOptions.Restore(catalog, incoming, "[]"));
    }

    [Fact]
    public void FindPlaceholder_SeesACopiedRedaction()
    {
        var catalog = Catalog();
        Assert.Equal("store.pfx.Password", SensitiveOptions.FindPlaceholder(catalog,
            """[{"pluginId":"store.pfx","options":{"filePath":"x","password":"********"}}]"""));
        Assert.Null(SensitiveOptions.FindPlaceholder(catalog,
            """[{"pluginId":"store.pfx","options":{"filePath":"x","passwordSecretName":"pw"}}]"""));
    }

    [Fact]
    public void Restore_KeepsANewLiteral_WhenTheClientActuallyChangedIt()
    {
        var catalog = Catalog();
        const string stored = """[{"pluginId":"store.pfx","options":{"filePath":"x","password":"hunter2"}}]""";
        const string incoming = """[{"pluginId":"store.pfx","options":{"filePath":"x","password":"newpw"}}]""";

        Assert.Equal(incoming, SensitiveOptions.Restore(catalog, incoming, stored));
    }

    [Fact]
    public void FindLiteral_FlagsARealPassword_NotAPlaceholderOrReference()
    {
        var catalog = Catalog();
        Assert.Equal("store.pfx.Password", SensitiveOptions.FindLiteral(catalog,
            """[{"pluginId":"store.pfx","options":{"filePath":"x","password":"hunter2"}}]"""));
        Assert.Null(SensitiveOptions.FindLiteral(catalog,
            """[{"pluginId":"store.pfx","options":{"filePath":"x","password":"********"}}]"""));
        Assert.Null(SensitiveOptions.FindLiteral(catalog,
            """[{"pluginId":"store.pfx","options":{"filePath":"x","passwordSecretName":"pfx-pw"}}]"""));
        Assert.Null(SensitiveOptions.FindLiteral(catalog, "not json"));
    }
}